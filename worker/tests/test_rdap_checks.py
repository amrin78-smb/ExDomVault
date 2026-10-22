import json

import httpx
import pytest

from app.checks import CheckContext, RateLimiter
from app.rdap_checks import (
    BOOTSTRAP_URL,
    RdapClient,
    check_rdap,
    match_bootstrap,
    parse_bootstrap,
    parse_rdap_domain,
)

TARGET = "3a1d4c1e-6b7f-4f4e-9d2e-8a9b0c1d2e3f"
BOOTSTRAP = {
    "version": "1.0",
    "services": [
        [["com", "net"], ["https://rdap.registry.test/com/v1/"]],
        [["uk"], ["http://insecure.test/", "https://rdap.uk.test/"]],
        [["co.uk"], ["https://rdap.co-uk.test/"]],
    ],
}

AVAILABLE = {
    "objectClassName": "domain",
    "ldhName": "EXAMPLE.COM",
    "status": ["client transfer prohibited"],
    "events": [
        {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00+00:00"},
        {"eventAction": "last changed", "eventDate": "2026-08-14T07:01:44Z"},
    ],
    "entities": [
        {
            "objectClassName": "entity",
            "roles": ["registrar"],
            "vcardArray": [
                "vcard",
                [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "RESERVED-Internet Assigned Numbers Authority"],
                ],
            ],
        }
    ],
    "nameservers": [{"ldhName": "B.IANA-SERVERS.NET."}, {"ldhName": "a.iana-servers.net"}],
}  # fmt: skip

REDACTED = {
    **AVAILABLE,
    "entities": [
        *AVAILABLE["entities"],
        {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", ""]]]},
    ],
    "redacted": [
        {"name": {"type": "Registrant Name"}, "method": "removal"},
        {"name": {"type": "Registrant Email"}, "method": "removal"},
    ],
}


def ctx():
    return CheckContext(
        deadline=float("inf"),
        connect_seconds=3.0,
        read_seconds=5.0,
        rate_limiter=RateLimiter(50.0, sleep=lambda _s: None),
    )


def client_for(routes: dict[str, httpx.Response | Exception], seen: list[str] | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if seen is not None:
            seen.append(url)
        result = routes.get(url)
        if result is None:
            return httpx.Response(599)
        if isinstance(result, Exception):
            raise result
        return result

    return RdapClient(transport=httpx.MockTransport(handler))


def run(client, fqdn="example.com"):
    out: list[dict] = []
    check_rdap(client, TARGET, fqdn, ctx(), out.append)
    assert len(out) == 1
    return out[0]


def test_parse_available_record():
    parsed = parse_rdap_domain(AVAILABLE)
    assert parsed["registrar"] == "RESERVED-Internet Assigned Numbers Authority"
    assert parsed["registeredAt"] == "1995-08-14T04:00:00Z"
    assert parsed["expiresAt"] == "2027-08-13T04:00:00Z"
    assert parsed["nameservers"] == ["a.iana-servers.net", "b.iana-servers.net"]
    assert parsed["dataStatus"] == "available"


def test_parse_redacted_record():
    parsed = parse_rdap_domain(REDACTED)
    assert parsed["dataStatus"] == "redacted"
    assert parsed["registrar"] == "RESERVED-Internet Assigned Numbers Authority"
    assert parsed["evidence"]["redactedFields"] == ["Registrant Email", "Registrant Name"]


def test_parse_redaction_in_remarks():
    doc = {**AVAILABLE, "remarks": [{"title": "REDACTED FOR PRIVACY", "description": []}]}
    assert parse_rdap_domain(doc)["dataStatus"] == "redacted"


def test_bootstrap_matching_prefers_longest_suffix_and_https():
    services = parse_bootstrap(BOOTSTRAP)
    assert match_bootstrap(services, "example.com") == ["https://rdap.registry.test/com/v1/"]
    assert match_bootstrap(services, "example.co.uk") == ["https://rdap.co-uk.test/"]
    assert match_bootstrap(services, "example.uk") == ["https://rdap.uk.test/"]
    assert match_bootstrap(services, "example.invalid") == []


def test_end_to_end_observation_shape_and_bootstrap_cache():
    seen: list[str] = []
    client = client_for(
        {
            BOOTSTRAP_URL: httpx.Response(200, json=BOOTSTRAP),
            "https://rdap.registry.test/com/v1/domain/example.com": httpx.Response(
                200, json=AVAILABLE
            ),
        },
        seen,
    )
    obs = run(client)
    assert set(obs) == {
        "kind", "targetId", "observedAt", "checkerVersion", "resultStatus", "evidence",
        "registrar", "registeredAt", "expiresAt", "nameservers", "dataStatus",
    }  # fmt: skip
    assert obs["kind"] == "registration"
    assert obs["resultStatus"] == "success"
    assert obs["dataStatus"] == "available"
    assert obs["evidence"]["rdapServer"] == "rdap.registry.test"
    run(client)
    assert seen.count(BOOTSTRAP_URL) == 1  # cached


def test_redacted_end_to_end():
    client = client_for(
        {
            BOOTSTRAP_URL: httpx.Response(200, json=BOOTSTRAP),
            "https://rdap.registry.test/com/v1/domain/example.com": httpx.Response(
                200, json=REDACTED
            ),
        }
    )
    assert run(client)["dataStatus"] == "redacted"


def test_not_found_is_success_unavailable():
    client = client_for(
        {
            BOOTSTRAP_URL: httpx.Response(200, json=BOOTSTRAP),
            "https://rdap.registry.test/com/v1/domain/example.com": httpx.Response(404),
        }
    )
    obs = run(client)
    assert obs["resultStatus"] == "success"
    assert obs["dataStatus"] == "unavailable"
    assert obs["registrar"] is None
    assert obs["nameservers"] == []


def test_tld_without_rdap_service_is_unavailable():
    client = client_for({BOOTSTRAP_URL: httpx.Response(200, json=BOOTSTRAP)})
    obs = run(client, "example.invalid")
    assert obs["resultStatus"] == "success"
    assert obs["dataStatus"] == "unavailable"
    assert obs["evidence"]["reason"] == "no_rdap_service"


def test_server_error_and_timeout_and_bootstrap_failure():
    client = client_for(
        {
            BOOTSTRAP_URL: httpx.Response(200, json=BOOTSTRAP),
            "https://rdap.registry.test/com/v1/domain/example.com": httpx.Response(503),
        }
    )
    obs = run(client)
    assert obs["resultStatus"] == "error"
    assert obs["dataStatus"] == "unavailable"
    assert obs["evidence"] == {"error": "http_error", "http": 503}

    client = client_for(
        {
            BOOTSTRAP_URL: httpx.Response(200, json=BOOTSTRAP),
            "https://rdap.registry.test/com/v1/domain/example.com": httpx.ReadTimeout("slow"),
        }
    )
    assert run(client)["resultStatus"] == "timeout"

    client = client_for({BOOTSTRAP_URL: httpx.ConnectError("down")})
    obs = run(client)
    assert obs["resultStatus"] == "error"
    assert obs["dataStatus"] == "unavailable"


def test_redirects_only_to_https_and_bounded():
    domain_url = "https://rdap.registry.test/com/v1/domain/example.com"
    client = client_for(
        {
            BOOTSTRAP_URL: httpx.Response(200, json=BOOTSTRAP),
            domain_url: httpx.Response(302, headers={"Location": "https://rdap.other.test/d"}),
            "https://rdap.other.test/d": httpx.Response(200, json=AVAILABLE),
        }
    )
    assert run(client)["dataStatus"] == "available"

    client = client_for(
        {
            BOOTSTRAP_URL: httpx.Response(200, json=BOOTSTRAP),
            domain_url: httpx.Response(302, headers={"Location": "http://rdap.other.test/d"}),
        }
    )
    obs = run(client)
    assert obs["resultStatus"] == "error"
    assert obs["evidence"]["error"] == "non_https_url"

    client = client_for(
        {
            BOOTSTRAP_URL: httpx.Response(200, json=BOOTSTRAP),
            domain_url: httpx.Response(302, headers={"Location": domain_url}),
        }
    )
    assert run(client)["evidence"]["error"] == "too_many_redirects"


def test_response_size_is_capped():
    big = json.dumps({**AVAILABLE, "padding": "x" * (1024 * 1024 + 10)}).encode()
    client = client_for(
        {
            BOOTSTRAP_URL: httpx.Response(200, json=BOOTSTRAP),
            "https://rdap.registry.test/com/v1/domain/example.com": httpx.Response(
                200, content=big
            ),
        }
    )
    obs = run(client)
    assert obs["resultStatus"] == "error"
    assert obs["evidence"]["error"] == "response_too_large"


@pytest.mark.parametrize("doc", [[], "x", None])
def test_invalid_documents(doc):
    client = client_for(
        {
            BOOTSTRAP_URL: httpx.Response(200, json=BOOTSTRAP),
            "https://rdap.registry.test/com/v1/domain/example.com": httpx.Response(200, json=doc),
        }
    )
    assert run(client)["resultStatus"] == "error"
