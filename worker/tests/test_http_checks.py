"""HTTP availability / header check: observation building from fake net.HttpResult values."""

import ipaddress
import json
import time

import pytest

from app import http_checks, net
from app.checks import CheckFailed, CheckStopped
from app.scope import ScopeError

from .test_tls_checks import TARGET_ID, FakePolicy, assert_http_schema, make_ctx

V4 = ipaddress.ip_address("203.0.113.10")
V4B = ipaddress.ip_address("203.0.113.20")


def hop(url, address=V4, status=200, headers=None, decision="final", error=None):
    return net.HttpHop(
        url=url, address=address, status=status, headers=headers or {}, decision=decision,
        error=error,
    )  # fmt: skip


def result(*hops):
    return net.HttpResult(hops=tuple(hops))


def build(res, include_headers=True):
    return http_checks.build_http_observation(TARGET_ID, res, include_headers=include_headers)


def test_redirect_chain_with_hsts():
    res = result(
        hop("https://example.com/", status=301, decision="followed",
            headers={"location": "https://www.example.com/"}),
        hop("https://www.example.com/", address=V4B, status=200, headers={
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
            "server": "nginx/1.25.3",
            "x-powered-by": "PHP/8.2.1",
        }),
    )  # fmt: skip
    o = build(res)
    assert_http_schema(o)
    assert o["resultStatus"] == "success"
    assert o["url"] == "https://example.com/"
    assert o["ipAddress"] == "203.0.113.10"
    assert o["statusCode"] == 200
    assert o["finalUrl"] == "https://www.example.com/"
    assert o["redirectCount"] == 1
    assert o["hstsEnabled"] is True
    ev = o["evidence"]
    assert ev["hops"] == [
        {
            "url": "https://example.com/",
            "ip": "203.0.113.10",
            "status": 301,
            "decision": "followed",
        },
        {
            "url": "https://www.example.com/",
            "ip": "203.0.113.20",
            "status": 200,
            "decision": "final",
        },
    ]
    assert ev["securityHeaders"] == {
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "x-frame-options": None,
        "referrer-policy": None,
        "permissions-policy": None,
    }
    assert ev["server"] == "nginx/1.25.3"
    assert ev["xPoweredBy"] == "PHP/8.2.1"


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ({}, False),
        ({"strict-transport-security": "max-age=0"}, False),
        ({"strict-transport-security": "includeSubDomains"}, False),
        ({"strict-transport-security": 'max-age="600"'}, True),
        ({"strict-transport-security": "MAX-AGE=1"}, True),
        ({"strict-transport-security": "max-age=abc"}, False),
    ],
)
def test_hsts_parsing(headers, expected):
    o = build(result(hop("https://www.example.com/", headers=headers)))
    assert o["hstsEnabled"] is expected


def test_hsts_is_null_when_final_response_is_plain_http():
    o = build(
        result(hop("http://www.example.com/", headers={"strict-transport-security": "max-age=600"}))
    )
    assert o["hstsEnabled"] is None


def test_refused_redirect_is_partial_and_stops_at_the_refusal():
    res = result(
        hop("https://www.example.com/", status=302, decision="followed",
            headers={"location": "https://login.other.net/"}),
        hop("https://login.other.net/", address=None, status=None,
            decision="redirect_out_of_scope"),
    )  # fmt: skip
    o = build(res)
    assert_http_schema(o)
    assert o["resultStatus"] == "partial"
    assert o["statusCode"] == 302
    assert o["finalUrl"] == "https://login.other.net/"
    assert o["redirectCount"] == 1
    assert o["evidence"]["hops"][-1] == {
        "url": "https://login.other.net/",
        "ip": None,
        "status": None,
        "decision": "redirect_out_of_scope",
    }


def test_redirect_to_private_address_is_recorded_as_refused_hop():
    res = result(
        hop("https://www.example.com/", status=301, decision="followed",
            headers={"location": "https://internal.example.com/"}),
        hop("https://internal.example.com/", address=None, status=None,
            decision="no_allowed_address"),
    )  # fmt: skip
    o = build(res)
    assert o["resultStatus"] == "partial"
    assert o["evidence"]["hops"][-1]["decision"] == "no_allowed_address"


def test_header_values_are_truncated_and_sanitised():
    long_csp = "default-src " + "a" * 2000
    o = build(
        result(
            hop("https://www.example.com/", headers={
                "content-security-policy": long_csp,
                "server": "café\x00srv",
            })
        )
    )  # fmt: skip
    assert len(o["evidence"]["securityHeaders"]["content-security-policy"]) == 512
    assert o["evidence"]["server"] == "caf??srv"


def test_cookies_and_bodies_are_never_stored():
    o = build(
        result(
            hop("https://www.example.com/", headers={
                "set-cookie": "session=SECRET-COOKIE-VALUE; HttpOnly",
                "x-frame-options": "DENY",
            })
        )
    )  # fmt: skip
    dumped = json.dumps(o)
    assert "SECRET-COOKIE-VALUE" not in dumped
    assert "set-cookie" not in dumped


def test_availability_only_omits_header_evidence():
    o = build(result(hop("https://www.example.com/", headers={"server": "x"})), False)
    assert set(o["evidence"]) == {"hops"}
    assert o["hstsEnabled"] is False


def test_connect_failure_without_response_is_error_or_timeout():
    o = build(
        result(hop("https://www.example.com/", status=None, decision="error", error="timeout"))
    )
    assert_http_schema(o)
    assert o["resultStatus"] == "timeout"
    assert o["statusCode"] is None
    assert o["hstsEnabled"] is None
    assert o["evidence"]["hops"][0]["error"] == "timeout"
    o = build(
        result(
            hop("https://www.example.com/", status=None, decision="error",
                error="connection_refused")
        )
    )  # fmt: skip
    assert o["resultStatus"] == "error"


def test_no_observation_when_first_hop_never_connected():
    assert build(result(hop("https://www.example.com/", address=None, status=None,
                            decision="prohibited_address"))) is None  # fmt: skip


def test_evidence_stays_under_the_size_cap():
    headers = {name: "\\" * 600 for name in http_checks.SECURITY_HEADERS}
    headers.update({"server": "\\" * 600, "x-powered-by": "\\" * 600})
    hops = [
        hop(f"https://www.example.com/{'x' * 1500}{i}", status=301, decision="followed")
        for i in range(5)
    ]
    hops.append(hop("https://www.example.com/end", headers=headers))
    o = build(result(*hops))
    assert_http_schema(o)


# -- check orchestration ------------------------------------------------------------------------


@pytest.fixture
def gets(monkeypatch):
    calls = []
    responses = {}

    def fake(policy, url, resolver, *, timeout, tier="web", **_kw):
        calls.append((url, tier, timeout))
        value = responses[url]
        if isinstance(value, BaseException):
            raise value
        return value

    monkeypatch.setattr(net, "http_get", fake)
    return calls, responses


def run(include_headers=True):
    out = []
    http_checks.check_http(
        FakePolicy(), None, TARGET_ID, "www.example.com", make_ctx(), out.append,
        include_headers=include_headers,
    )  # fmt: skip
    return out


def test_both_schemes_are_requested_even_when_https_answers(gets):
    calls, responses = gets
    responses["https://www.example.com/"] = result(hop("https://www.example.com/"))
    responses["http://www.example.com/"] = result(hop("http://www.example.com/"))
    out = run()
    assert [c[0] for c in calls] == ["https://www.example.com/", "http://www.example.com/"]
    assert all(c[1] == "web" for c in calls)
    assert len(out) == 2


def test_https_connect_failure_falls_back_to_http(gets):
    calls, responses = gets
    responses["https://www.example.com/"] = result(
        hop("https://www.example.com/", status=None, decision="error", error="connection_refused")
    )
    responses["http://www.example.com/"] = result(hop("http://www.example.com/"))
    out = run()
    assert [c[0] for c in calls] == ["https://www.example.com/", "http://www.example.com/"]
    assert [(o["url"], o["resultStatus"]) for o in out] == [
        ("https://www.example.com/", "error"),
        ("http://www.example.com/", "success"),
    ]
    for o in out:
        assert_http_schema(o)


def test_refusal_before_connecting_emits_nothing_and_raises_the_code(gets):
    calls, responses = gets
    responses["https://www.example.com/"] = result(
        hop("https://www.example.com/", address=None, status=None, decision="no_allowed_address")
    )
    with pytest.raises(ScopeError) as err:
        run()
    assert err.value.code == "no_allowed_address"
    assert len(calls) == 1  # plain HTTP would be refused the same way


def test_dns_failure_maps_to_resolution_failed(gets):
    _, responses = gets
    responses["https://www.example.com/"] = result(
        hop("https://www.example.com/", address=None, status=None, decision="error",
            error="nxdomain")
    )  # fmt: skip
    with pytest.raises(ScopeError) as err:
        run()
    assert err.value.code == "resolution_failed"


def test_unexpected_os_errors_are_check_failures(gets):
    _, responses = gets
    responses["https://www.example.com/"] = OSError("boom")
    responses["http://www.example.com/"] = TimeoutError()
    with pytest.raises(CheckFailed) as err:
        run()
    assert err.value.code == "http_timeout"


def test_target_budget_and_stop_signal_are_passed_to_http_get(monkeypatch):
    seen = []
    stop = {"now": False}

    def fake(policy, url, resolver, *, timeout, tier="web", deadline=None, should_stop=None):
        seen.append((deadline, should_stop))
        stop["now"] = True  # the job is cancelled while the request runs
        return result(hop(url, status=None, decision="error", error="timeout"))

    monkeypatch.setattr(net, "http_get", fake)
    before = time.monotonic()
    with pytest.raises(CheckStopped):
        http_checks.check_http(
            FakePolicy(), None, TARGET_ID, "www.example.com",
            make_ctx(remaining=30.0, should_stop=lambda: stop["now"]), [].append,
            include_headers=True,
        )  # fmt: skip
    ((deadline, should_stop),) = seen
    assert before + 29 < deadline <= time.monotonic() + 30
    assert should_stop() is True


# -- subdomain-takeover signatures (Milestone 15, DNS-008) -----------------------------------------

GH_UNCLAIMED = (
    b"<!DOCTYPE html><html><head><title>Site not found &middot; GitHub Pages</title></head>"
    b"<body><h1>404</h1><p><strong>There isn't a GitHub Pages site here.</strong></p></body></html>"
)


def body_hop(url, body, status=404, decision="final", headers=None):
    return net.HttpHop(
        url=url, address=V4, status=status, headers=headers or {}, decision=decision, body=body
    )


def test_signature_table_is_valid_and_mirrors_known_providers():
    sigs = http_checks.takeover_signatures()
    keys = {key for key, _statuses, _needles in sigs}
    assert {"github_pages", "aws_s3", "heroku", "netlify", "shopify"} <= keys
    # Providers can-i-take-over-xyz lists as "not vulnerable" are deliberately absent.
    assert not keys & {"zendesk", "fastly", "unbounce", "kinsta", "fly_io"}
    for _key, statuses, needles in sigs:
        assert needles and all(n.strip() for n in needles)
        assert all(100 <= s <= 599 for s in statuses)


@pytest.mark.parametrize(
    ("status", "body", "provider"),
    [
        (404, GH_UNCLAIMED, "github_pages"),
        (404, b"<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist"
              b"</Message></Error>", "aws_s3"),
        (404, b"<iframe src='//www.herokucdn.com/error-pages/no-such-app.html'>No such app",
         "heroku"),
        (200, b"<p>Sorry, this shop is currently unavailable.</p>", "shopify"),
        (404, b"Not Found - Request ID: 01ABCDEF", "netlify"),
    ],
)  # fmt: skip
def test_signature_match(status, body, provider):
    assert http_checks.match_takeover_signature(status, body)["provider"] == provider


@pytest.mark.parametrize(
    ("status", "body"),
    [
        (200, GH_UNCLAIMED),  # status must match where the signature lists statuses
        (404, b"<h1>Not Found</h1>"),
        (404, b""),
        (None, GH_UNCLAIMED),
        (404, b"Do you want to register this domain?"),  # every substring is required
    ],
)
def test_signature_no_match(status, body):
    assert http_checks.match_takeover_signature(status, body) is None


def test_signature_only_searches_the_bounded_body():
    padded = b"x" * net.MAX_BODY_BYTES + GH_UNCLAIMED
    assert http_checks.match_takeover_signature(404, padded) is None


def test_signature_recorded_without_the_body():
    o = build(result(body_hop("https://docs.example.com/", GH_UNCLAIMED)), False)
    assert_http_schema(o)
    assert o["evidence"]["takeoverSignature"] == {
        "provider": "github_pages",
        "signature": "There isn't a GitHub Pages site here.",
    }
    dumped = json.dumps(o)
    assert "Site not found" not in dumped and "DOCTYPE" not in dumped


def test_signature_ignored_for_another_hosts_response_or_refused_hop():
    # The unclaimed page came from a different (in-domain) host after a redirect: not evidence for
    # the requested host.
    redirected = result(
        hop("https://docs.example.com/", status=301, decision="followed",
            headers={"location": "https://www.example.com/"}),
        body_hop("https://www.example.com/", GH_UNCLAIMED),
    )  # fmt: skip
    assert "takeoverSignature" not in build(redirected)["evidence"]
    clean = build(result(body_hop("https://docs.example.com/", b"<h1>Welcome</h1>", status=200)))
    assert "takeoverSignature" not in clean["evidence"]


def test_signature_detection_makes_no_extra_requests(gets):
    calls, responses = gets
    responses["https://www.example.com/"] = result(
        body_hop("https://www.example.com/", GH_UNCLAIMED)
    )
    responses["http://www.example.com/"] = result(body_hop("http://www.example.com/", GH_UNCLAIMED))
    out = run(include_headers=False)
    assert [c[0] for c in calls] == ["https://www.example.com/", "http://www.example.com/"]
    assert [o["evidence"]["takeoverSignature"]["provider"] for o in out] == ["github_pages"] * 2
