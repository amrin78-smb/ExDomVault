"""Cert Spotter provider and multi-provider discovery (Milestone 15).

Synthetic only: Cert Spotter responses come from ``httpx.MockTransport`` fixtures shaped like the
v1 issuances API (``id``, ``dns_names``, ``not_after``, ``issuer``). The live API shape was not
verified while building this; nothing here contacts api.certspotter.com.
"""

from __future__ import annotations

import json
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from app.discovery import (
    CERTSPOTTER_MAX_PAGES,
    DISCOVERY_USER_AGENT,
    CertSpotterProvider,
    DiscoveryUnavailable,
    ProviderResult,
    Throttle,
    run_discovery,
)

from .test_discovery import (
    APEX_ID,
    NOW,
    FakeClock,
    FakeProvider,
    FakeResolver,
    discovery_job,
    make_ctx,
    names_result,
    worker_for,  # noqa: F401  (pytest fixture)
)

BASE = "https://api.certspotter.com/v1/issuances"


def issuance(id_, names, *, not_after="2027-01-01T00:00:00Z", issuer="Let's Encrypt"):
    return {
        "id": str(id_),
        "tbs_sha256": "00" * 32,
        "cert_sha256": "11" * 32,
        "dns_names": names,
        "pubkey_sha256": "22" * 32,
        "not_before": "2026-01-01T00:00:00Z",
        "not_after": not_after,
        "revoked": False,
        "issuer": {"friendly_name": issuer, "name": "C=US, O=Let's Encrypt, CN=R11"},
    }


def page(body, status=200, headers=None):
    return httpx.Response(
        status,
        content=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", **(headers or {})},
    )


class Pages:
    """Serves page N for the Nth request; records URLs."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.urls: list[str] = []
        self.requests: list[httpx.Request] = []

    def __call__(self, request):
        self.urls.append(str(request.url))
        self.requests.append(request)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def provider_for(handler, clock=None, **kwargs) -> CertSpotterProvider:
    clock = clock or FakeClock()
    return CertSpotterProvider(
        transport=httpx.MockTransport(handler),
        throttle=Throttle(2.0, monotonic=clock, sleep=clock.sleep),
        now=lambda: NOW,
        monotonic=clock,
        sleep=clock.sleep,
        **kwargs,
    )


def query(url):
    return parse_qs(urlsplit(url).query)


def test_request_is_the_fixed_api_url_with_identifying_user_agent():
    pages = Pages(page([]))
    provider_for(pages).fetch("example.com", make_ctx())
    assert pages.urls[0].startswith(BASE + "?")
    assert query(pages.urls[0]) == {
        "domain": ["example.com"],
        "include_subdomains": ["true"],
        "expand": ["dns_names", "issuer"],
    }
    assert pages.requests[0].headers["User-Agent"] == DISCOVERY_USER_AGENT


def test_client_never_follows_redirects_or_trusts_environment_proxies():
    provider = CertSpotterProvider()
    assert provider._http.follow_redirects is False
    assert provider._http.trust_env is False


def test_paginates_with_after_until_an_empty_page():
    pages = Pages(
        page([issuance(10, ["www.example.com", "*.example.com"]),
              issuance(11, ["api.example.com"])]),
        page([issuance(12, ["mail.example.com", "evil.com"])]),
        page([]),
    )  # fmt: skip
    result = provider_for(pages).fetch("example.com", make_ctx())
    assert [query(u).get("after") for u in pages.urls] == [None, ["11"], ["12"]]
    assert set(result.names) == {
        "www.example.com", "*.example.com", "api.example.com", "mail.example.com",
    }  # fmt: skip
    assert result.certificates == 3
    assert result.truncated is False and result.error is None
    assert result.names["www.example.com"].issuers == {"Let's Encrypt"}


def test_expired_and_malformed_issuances_are_skipped():
    pages = Pages(
        page([issuance(1, ["old.example.com"], not_after="2020-01-01T00:00:00Z"),
              {"id": "2", "dns_names": "not-a-list", "not_after": "2027-01-01T00:00:00Z"},
              "junk", issuance(3, ["ok.example.com"])]),
        page([]),
    )  # fmt: skip
    result = provider_for(pages).fetch("example.com", make_ctx())
    assert set(result.names) == {"ok.example.com"}
    assert result.skipped_certificates == 3


def test_page_cap_truncates():
    pages = Pages(*[page([issuance(i, [f"h{i}.example.com"])]) for i in range(5)])
    result = provider_for(pages, max_pages=3).fetch("example.com", make_ctx())
    assert len(pages.urls) == 3
    assert result.truncated is True
    assert len(result.names) == 3
    assert CERTSPOTTER_MAX_PAGES == 10


def test_429_with_short_retry_after_is_waited_for_once():
    clock = FakeClock()
    pages = Pages(
        page({}, 429, {"Retry-After": "5"}), page([issuance(1, ["a.example.com"])]), page([])
    )
    result = provider_for(pages, clock).fetch("example.com", make_ctx(clock))
    assert len(pages.urls) == 3
    assert set(result.names) == {"a.example.com"}
    assert sum(clock.slept) >= 5.0


@pytest.mark.parametrize("headers", [{}, {"Retry-After": "3600"}])
def test_429_on_the_first_page_without_short_retry_is_transient(headers):
    pages = Pages(page({}, 429, headers), page({}, 429, headers))
    with pytest.raises(DiscoveryUnavailable) as exc:
        provider_for(pages).fetch("example.com", make_ctx())
    assert exc.value.error_class == "http_429"


def test_repeated_429_after_waiting_is_transient():
    pages = Pages(page({}, 429, {"Retry-After": "1"}), page({}, 429, {"Retry-After": "1"}))
    with pytest.raises(DiscoveryUnavailable):
        provider_for(pages).fetch("example.com", make_ctx())
    assert len(pages.urls) == 2


def test_failure_on_a_later_page_keeps_earlier_names_as_truncated():
    pages = Pages(page([issuance(1, ["a.example.com"])]), page({}, 503))
    result = provider_for(pages).fetch("example.com", make_ctx())
    assert set(result.names) == {"a.example.com"}
    assert result.truncated is True


@pytest.mark.parametrize(
    ("response", "error"),
    [
        (httpx.Response(302, headers={"Location": "https://evil.example/"}), "unexpected_redirect"),
        (httpx.Response(400), "http_400"),
        (httpx.Response(200, content=b"<html>", headers={"Content-Type": "text/html"}),
         "unexpected_content_type"),
        (httpx.Response(200, content=b"{not json", headers={"Content-Type": "application/json"}),
         "invalid_json"),
        (page({"issuances": []}), "invalid_json"),
    ],
)  # fmt: skip
def test_permanent_errors_on_the_first_page(response, error):
    result = provider_for(Pages(response)).fetch("example.com", make_ctx())
    assert result.error == error
    assert result.names == {}


def test_unsafe_cursor_stops_paging():
    pages = Pages(page([issuance("1&domain=evil.com", ["a.example.com"])]))
    result = provider_for(pages).fetch("example.com", make_ctx())
    assert len(pages.urls) == 1
    assert result.truncated is True


def test_page_size_is_capped():
    big = [issuance(i, [f"h{i}.example.com"]) for i in range(200)]
    result = provider_for(Pages(page(big)), max_page_bytes=1000).fetch("example.com", make_ctx())
    assert result.truncated is True


def test_timeouts_are_transient():
    pages = Pages(httpx.ReadTimeout("slow"))
    with pytest.raises(DiscoveryUnavailable):
        provider_for(pages).fetch("example.com", make_ctx())


# -- several providers ------------------------------------------------------------------------


class Spotter(FakeProvider):
    name = "certspotter"


def test_candidates_are_merged_with_per_provider_evidence():
    crtsh = FakeProvider(names_result(["www.example.com", "a.example.com"]))
    spotter = Spotter(
        ProviderResult("certspotter", "certificate_transparency",
                       names=dict(names_result(["www.example.com", "b.example.com"]).names))
    )  # fmt: skip
    out = []
    outcome = run_discovery(
        [crtsh, spotter], FakeResolver(), APEX_ID, "example.com", make_ctx(), out.append
    )
    assert outcome.status == "success"
    disc = {o["hostname"]: o["evidence"] for o in out if o["kind"] == "discovery"}
    assert disc["www.example.com"]["provider"] == "crt.sh"
    assert disc["www.example.com"]["providers"] == ["certspotter", "crt.sh"]
    assert (
        disc["a.example.com"]["provider"] == "crt.sh" and "providers" not in disc["a.example.com"]
    )
    assert disc["b.example.com"]["provider"] == "certspotter"


def test_one_failing_provider_makes_the_run_partial():
    crtsh = FakeProvider(exc=DiscoveryUnavailable("http_503"))
    names = dict(names_result(["www.example.com"]).names)
    spotter = Spotter(ProviderResult("certspotter", "certificate_transparency", names=names))
    out = []
    outcome = run_discovery(
        [crtsh, spotter], FakeResolver(), APEX_ID, "example.com", make_ctx(), out.append
    )
    assert outcome.status == "partial"
    apex = [o for o in out if o["kind"] == "discovery" and o["hostname"] == "example.com"]
    assert len(apex) == 1 and apex[0]["resultStatus"] == "partial"
    assert apex[0]["evidence"]["failedProviders"] == [
        {"provider": "crt.sh", "errorClass": "http_503", "transient": True}
    ]
    www = [o for o in out if o["kind"] == "discovery" and o["hostname"] == "www.example.com"]
    assert www[0]["resultStatus"] == "success"


def test_permanent_error_of_one_provider_is_also_partial():
    crtsh = FakeProvider(ProviderResult("crt.sh", "certificate_transparency", error="invalid_json"))
    spotter = Spotter(names_result(["www.example.com"]))
    outcome = run_discovery(
        [crtsh, spotter], FakeResolver(), APEX_ID, "example.com", make_ctx(), lambda _o: None
    )
    assert outcome.status == "partial"


def test_all_providers_transiently_unavailable_is_retryable():
    providers = [
        FakeProvider(exc=DiscoveryUnavailable("http_503")),
        Spotter(exc=DiscoveryUnavailable("http_429")),
    ]
    out = []
    with pytest.raises(DiscoveryUnavailable):
        run_discovery(providers, FakeResolver(), APEX_ID, "example.com", make_ctx(), out.append)
    assert out == []


def test_all_providers_permanently_failing_is_one_error_observation_each():
    providers = [
        FakeProvider(ProviderResult("crt.sh", "certificate_transparency", error="invalid_json")),
        Spotter(ProviderResult("certspotter", "certificate_transparency", error="http_400")),
    ]
    out = []
    outcome = run_discovery(
        providers, FakeResolver(), APEX_ID, "example.com", make_ctx(), out.append
    )
    assert outcome.status == "error"
    assert [(o["resultStatus"], o["evidence"]) for o in out] == [
        ("error", {"provider": "crt.sh", "errorClass": "invalid_json"}),
        ("error", {"provider": "certspotter", "errorClass": "http_400"}),
    ]


def test_job_with_both_providers_survives_one_outage(worker_for):  # noqa: F811
    crtsh = FakeProvider(exc=DiscoveryUnavailable("http_502"))
    pages = Pages(page([issuance(1, ["www.example.com"])]), page([]))
    worker, api, _, _ = worker_for(discovery_job(), provider=[crtsh, provider_for(pages)])
    worker.run_once()
    assert "failures" not in [e for e, _ in api.calls]
    targets = [t for r in api.endpoint_calls("results") for t in r["targets"]]
    assert targets == [{"targetId": APEX_ID, "status": "succeeded"}]
    observations = [o for r in api.endpoint_calls("results") for o in r["observations"]]
    statuses = {o["hostname"]: o["resultStatus"] for o in observations if o["kind"] == "discovery"}
    assert statuses == {"example.com": "partial", "www.example.com": "success"}
