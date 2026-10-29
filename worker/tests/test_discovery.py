"""Passive discovery (Milestone 9): candidate pipeline, crt.sh provider, run limits, job loop.

Everything is synthetic: the provider talks to ``httpx.MockTransport`` and DNS to fake resolvers.
Nothing here contacts crt.sh, a resolver or any target.
"""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime, timedelta

import dns.resolver
import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app import discovery, net
from app.checks import CheckContext, CheckStopped, RateLimiter
from app.client import Signer, WorkerApiClient
from app.config import load_config
from app.discovery import (
    CRTSH_URL_TEMPLATE,
    DISCOVERY_USER_AGENT,
    MAX_CANDIDATES,
    MAX_RESOLVED_CANDIDATES,
    CrtShProvider,
    DiscoveryUnavailable,
    JsonArrayStream,
    NameMeta,
    ProviderResult,
    Throttle,
    absorb_certificate,
    build_candidates,
    normalise_candidate,
    run_discovery,
)
from app.dns_checks import DnsAnswer
from app.health import HealthReporter
from app.policy import tier_of
from app.queue import Worker
from app.rdap_checks import RdapClient
from app.scope import KNOWN_CHECKS, PASSIVE_CHECKS, ScopeError, assert_passive_allowed
from app.self_protection import SelfProtection

from .conftest import KEY_ID
from .test_queue import APEX_ID, JOB_ID, FakeApi, make_job

NOW = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)
CRTSH_URL = "https://crt.sh/?q=%25.example.com&output=json"


class FakeClock:
    def __init__(self, start: float = 1000.0) -> None:
        self.now = start
        self.slept: list[float] = []
        self.lock = threading.Lock()

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        with self.lock:
            self.slept.append(seconds)
            self.now += seconds


def make_ctx(clock=None, *, remaining=600.0, stop=lambda: False, rate=50.0) -> CheckContext:
    clock = clock or FakeClock()
    return CheckContext(
        deadline=clock() + remaining,
        connect_seconds=5.0,
        read_seconds=10.0,
        rate_limiter=RateLimiter(rate, monotonic=clock, sleep=clock.sleep),
        should_stop=stop,
        monotonic=clock,
    )


def cert(names, *, not_after="2027-01-01T00:00:00", cn=None, issuer="C=US, O=Test CA, CN=T1"):
    return {
        "issuer_ca_id": 1,
        "issuer_name": issuer,
        "common_name": cn,
        "name_value": "\n".join(names),
        "id": 1,
        "not_before": "2026-01-01T00:00:00",
        "not_after": not_after,
        "serial_number": "01",
    }


def provider_for(handler, clock=None, **kwargs) -> CrtShProvider:
    clock = clock or FakeClock()
    return CrtShProvider(
        transport=httpx.MockTransport(handler),
        throttle=Throttle(3.0, monotonic=clock, sleep=clock.sleep),
        now=lambda: NOW,
        **kwargs,
    )


def json_response(body, status=200, content_type="application/json"):
    content = body if isinstance(body, bytes) else json.dumps(body).encode()
    return httpx.Response(status, content=content, headers={"Content-Type": content_type})


# -- check catalogue ---------------------------------------------------------------------------


def test_discovery_is_a_known_passive_check():
    assert "discovery" in KNOWN_CHECKS
    assert "discovery" in PASSIVE_CHECKS
    assert tier_of("discovery") == "passive"
    assert_passive_allowed("discovery")  # does not raise


# -- candidate normalisation -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("www.example.com", ("www.example.com", False)),
        ("WWW.Example.COM.", ("www.example.com", False)),
        ("  api.example.com \n", ("api.example.com", False)),
        ("*.example.com", ("example.com", True)),
        ("*.Dev.Example.com.", ("dev.example.com", True)),
        ("a-b.example.com", ("a-b.example.com", False)),
        ("r3--sn-abc.example.com", ("r3--sn-abc.example.com", False)),
        # IDN: Unicode → A-label (case-folded), A-labels kept when they round-trip.
        ("bücher.example.com", ("xn--bcher-kva.example.com", False)),
        ("BÜCHER.example.com", ("xn--bcher-kva.example.com", False)),
        ("*.bücher.example.com", ("xn--bcher-kva.example.com", True)),
        ("XN--BCHER-KVA.example.com", ("xn--bcher-kva.example.com", False)),
        ("bücher。example。com", ("xn--bcher-kva.example.com", False)),  # ideographic full stop
    ],
)
def test_normalise_candidate_accepts(raw, expected):
    assert normalise_candidate(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        ".",
        "*",
        "*.",
        "*.*.example.com",
        "a.*.example.com",
        "foo*.example.com",
        "*example.com",
        "admin@example.com",
        "mailto:admin@example.com",
        "192.0.2.1",
        "2001:db8::1",
        "[2001:db8::1]",
        "a..example.com",
        ".example.com",
        "www.example.com..",
        "-a.example.com",
        "a-.example.com",
        "a_b.example.com",
        "_dmarc.example.com",
        "a b.example.com",
        "a/b.example.com",
        "a:443.example.com",
        ("a" * 64) + ".example.com",
        ".".join(["a" * 60] * 5),  # 304 characters
        "localhost",
        "xn--zzzz-.example.com",  # invalid punycode
        "xn--a.example.com",  # does not round-trip
        "a‍b.example.com",  # ZWJ outside an allowed context
        "\u0000.example.com",
        "exa\tmple.com",
    ],
)
def test_normalise_candidate_drops(raw):
    assert normalise_candidate(raw) is None


@pytest.mark.parametrize(
    ("domain", "name"),
    [
        ("example.com", "example.com.evil.com"),
        ("example.com", "www.example.com.evil.com"),
        ("example.com", "evilexample.com"),
        ("example.com", "wwwexample.com"),
        ("example.com", "example.co"),
        ("example.com", "example.com-evil.net"),
        ("example.com", "xample.com"),
        ("xample.com", "example.com"),
        ("xample.com", "www.example.com"),
        ("example.com", "*.example.com.evil.com"),
        ("example.com", "EXAMPLE.COM.evil.com."),
    ],
)
def test_label_boundary_bypasses_are_dropped(domain, name):
    found = build_candidates(domain, [name])
    assert found.candidates == ()
    assert found.dropped == 1


def test_boundary_accepts_apex_and_names_beneath_it_in_any_case():
    found = build_candidates("example.com", ["EXAMPLE.COM.", "Www.Example.Com", "a.b.example.com"])
    assert [c.hostname for c in found.candidates] == [
        "example.com",
        "www.example.com",
        "a.b.example.com",
    ]


def test_build_candidates_refuses_a_public_suffix_domain():
    with pytest.raises(ScopeError):
        build_candidates("co.uk", ["a.co.uk"])


def test_dedupe_merges_wildcards_and_metadata():
    early = datetime(2026, 1, 1, tzinfo=UTC)
    late = datetime(2027, 6, 1, tzinfo=UTC)
    names = {
        "*.a.example.com": NameMeta(2, early, {"CA One"}),
        "a.example.com.": NameMeta(1, late, {"CA Two"}),
        "*.wild.example.com": NameMeta(1, early, {"CA One"}),
        "*.WILD.example.com.": NameMeta(1, late, set()),
        "WWW.example.com": NameMeta(1, None, set()),
        "www.example.com": NameMeta(1, None, set()),
    }
    found = build_candidates("example.com", names)
    by_name = {c.hostname: c for c in found.candidates}
    assert set(by_name) == {"a.example.com", "wild.example.com", "www.example.com"}
    assert by_name["a.example.com"].wildcard is False  # seen exactly once → not wildcard-only
    assert by_name["a.example.com"].certificates == 3
    assert by_name["a.example.com"].latest_not_after == late
    assert by_name["a.example.com"].issuers == ("CA One", "CA Two")
    assert by_name["wild.example.com"].wildcard is True
    assert by_name["wild.example.com"].certificates == 2
    assert by_name["www.example.com"].wildcard is False


def test_candidate_cap_is_deterministic_and_truncates():
    names = [f"h{i:05d}.example.com" for i in range(MAX_CANDIDATES + 500)]
    names += ["example.com", "deep.h00001.example.com"]
    forward = build_candidates("example.com", names)
    backward = build_candidates("example.com", list(reversed(names)))
    assert forward.truncated is True
    assert len(forward.candidates) == MAX_CANDIDATES
    assert forward.candidates == backward.candidates
    hostnames = [c.hostname for c in forward.candidates]
    assert hostnames[0] == "example.com"  # fewest labels first, then alphabetical
    assert hostnames[1] == "h00000.example.com"
    assert "deep.h00001.example.com" not in hostnames
    assert build_candidates("example.com", names[:10]).truncated is False


# -- certificate filtering ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("not_after", "kept"),
    [
        ("2028-01-01T00:00:00", True),  # future
        ("2026-10-22T00:00:00", True),  # expired yesterday
        ("2025-10-24T12:00:00", True),  # expired 364 days ago
        ("2025-10-22T12:00:00", False),  # expired 366 days ago
        ("2019-01-01T00:00:00", False),
        ("2027-01-01T00:00:00Z", True),
        ("2027-01-01T00:00:00+02:00", True),
        ("not a date", False),
        (None, False),
        (12345, False),
    ],
)
def test_expired_certificates_are_filtered(not_after, kept):
    result = ProviderResult("crt.sh", "certificate_transparency")
    cutoff = NOW - timedelta(days=365)
    absorb_certificate(
        result, cert(["www.example.com"], not_after=not_after), "example.com", cutoff
    )
    assert ("www.example.com" in result.names) is kept
    assert result.certificates == (1 if kept else 0)
    assert result.skipped_certificates == (0 if kept else 1)


def test_name_value_lines_and_common_name_are_collected():
    result = ProviderResult("crt.sh", "certificate_transparency")
    cutoff = NOW - timedelta(days=365)
    entry = cert(
        ["www.example.com", "*.example.com", "unrelated.org", "admin@example.com"],
        cn="mail.example.com",
    )
    absorb_certificate(result, entry, "example.com", cutoff)
    absorb_certificate(result, "not an object", "example.com", cutoff)
    # unrelated.org is pre-filtered; the email is kept raw and dropped by the pipeline.
    assert set(result.names) == {
        "www.example.com",
        "*.example.com",
        "admin@example.com",
        "mail.example.com",
    }
    assert result.names["www.example.com"].issuers == {"C=US, O=Test CA, CN=T1"}
    assert result.skipped_certificates == 1
    found = build_candidates("example.com", result.names)
    assert [c.hostname for c in found.candidates] == [
        "example.com",
        "mail.example.com",
        "www.example.com",
    ]


# -- streaming JSON ----------------------------------------------------------------------------


def test_json_array_stream_yields_elements_across_chunk_boundaries():
    body = json.dumps([{"a": 1}, {"b": "x,]}"}, {"c": [1, 2]}]).encode()
    parser = JsonArrayStream()
    items = []
    for i in range(len(body)):
        items += parser.feed(body[i : i + 1])
    items += parser.close()
    assert items == [{"a": 1}, {"b": "x,]}"}, {"c": [1, 2]}]


@pytest.mark.parametrize(
    "body",
    [b"", b"{}", b"[1, 2]", b"[{}", b'[{"a": 1} {"b": 2}]', b"[{}] trailing", b"\xff\xfe", b"[{]"],
)
def test_json_array_stream_rejects_malformed(body):
    parser = JsonArrayStream()
    with pytest.raises(discovery._Malformed):
        parser.feed(body)
        parser.close()


def test_json_array_stream_bounds_a_single_element():
    parser = JsonArrayStream(max_element_bytes=100)
    with pytest.raises(discovery._Malformed):
        parser.feed(b'[{"a": "' + b"x" * 200)


# -- crt.sh provider ---------------------------------------------------------------------------


def test_provider_request_is_fixed_https_url_with_identifying_user_agent():
    seen: list[httpx.Request] = []

    def handler(request):
        seen.append(request)
        return json_response([cert(["www.example.com", "*.api.example.com"])])

    result = provider_for(handler).fetch("Example.COM.", make_ctx())
    assert len(seen) == 1
    assert str(seen[0].url) == CRTSH_URL
    assert CRTSH_URL_TEMPLATE.format(domain="example.com") == CRTSH_URL
    assert seen[0].method == "GET"
    assert seen[0].headers["User-Agent"] == DISCOVERY_USER_AGENT
    assert DISCOVERY_USER_AGENT.startswith("ExDomainVault-worker/")
    assert DISCOVERY_USER_AGENT.endswith("(passive discovery)")
    assert result.error is None and result.truncated is False
    assert set(result.names) == {"www.example.com", "*.api.example.com"}
    assert result.certificates == 1


def test_provider_client_never_follows_redirects_or_trusts_environment_proxies(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    provider = CrtShProvider()
    try:
        assert provider._http.follow_redirects is False
        assert provider._http.trust_env is False
    finally:
        provider.close()


def test_provider_refuses_a_non_registrable_domain():
    provider = provider_for(lambda r: pytest.fail("no request expected"))
    with pytest.raises(ScopeError):
        provider.fetch("co.uk", make_ctx())
    with pytest.raises(ScopeError):
        provider.fetch("com", make_ctx())


def test_redirect_is_not_followed():
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(302, headers={"Location": "https://evil.example.net/"})

    result = provider_for(handler).fetch("example.com", make_ctx())
    assert seen == [CRTSH_URL]
    assert result.error == "unexpected_redirect"
    assert result.names == {}


@pytest.mark.parametrize("status", [408, 429, 500, 502, 503, 504])
def test_rate_limits_and_server_errors_are_transient(status):
    provider = provider_for(lambda r: httpx.Response(status))
    with pytest.raises(DiscoveryUnavailable) as info:
        provider.fetch("example.com", make_ctx())
    assert info.value.error_class == f"http_{status}"
    assert info.value.code == "discovery_provider_unavailable"


@pytest.mark.parametrize(
    "exc",
    [
        httpx.ConnectTimeout("slow"),
        httpx.ReadTimeout("slow"),
        httpx.ConnectError("refused"),
        httpx.RemoteProtocolError("bad"),
    ],
)
def test_timeouts_and_connection_errors_are_transient(exc):
    def handler(request):
        raise exc

    with pytest.raises(DiscoveryUnavailable) as info:
        provider_for(handler).fetch("example.com", make_ctx())
    assert info.value.error_class == type(exc).__name__


@pytest.mark.parametrize(
    ("response", "error"),
    [
        (httpx.Response(404), "http_404"),
        (httpx.Response(400), "http_400"),
        (json_response(b"<html>busy</html>", content_type="text/html"), "unexpected_content_type"),
        (json_response(b"[]", content_type="text/plain"), "unexpected_content_type"),
        (json_response(b'[{"name_value": "www.example.com"'), "invalid_json"),
        (json_response(b'{"error": "nope"}'), "invalid_json"),
        (json_response(b"not json"), "invalid_json"),
        (json_response(b""), "invalid_json"),
    ],
)
def test_permanent_provider_errors(response, error):
    result = provider_for(lambda r: response).fetch("example.com", make_ctx())
    assert result.error == error
    assert result.names == {}


def test_content_type_parameters_are_accepted():
    response = json_response(
        [cert(["a.example.com"])], content_type="application/json; charset=utf-8"
    )
    result = provider_for(lambda r: response).fetch("example.com", make_ctx())
    assert result.error is None
    assert "a.example.com" in result.names


def test_empty_result_is_a_successful_run():
    result = provider_for(lambda r: json_response([])).fetch("example.com", make_ctx())
    assert result.error is None and result.names == {} and result.truncated is False


def test_size_cap_truncates_but_keeps_complete_elements():
    entries = [cert([f"h{i:04d}.example.com"]) for i in range(400)]
    body = json.dumps(entries).encode()
    cap = len(body) // 2
    result = provider_for(lambda r: json_response(body), max_response_bytes=cap).fetch(
        "example.com", make_ctx()
    )
    assert result.error is None
    assert result.truncated is True
    assert 150 < len(result.names) <= 200
    assert "h0000.example.com" in result.names
    assert "h0399.example.com" not in result.names


def test_default_size_cap_is_32_mib():
    assert discovery.MAX_RESPONSE_BYTES == 32 * 1024 * 1024


def test_politeness_interval_between_provider_requests():
    clock = FakeClock()
    provider = provider_for(lambda r: json_response([]), clock=clock)
    started = []
    for _ in range(3):
        provider.fetch("example.com", make_ctx(clock))
        started.append(clock())
    assert started[1] - started[0] >= 3.0
    assert started[2] - started[1] >= 3.0


def test_throttle_is_shared_across_provider_instances_by_default():
    assert provider_for.__name__  # (sanity)
    a, b = CrtShProvider(), CrtShProvider()
    try:
        assert a._throttle is b._throttle is discovery._CRTSH_THROTTLE
        assert discovery._CRTSH_THROTTLE._interval >= 3.0
    finally:
        a.close()
        b.close()


def test_throttle_wait_beyond_budget_is_transient():
    clock = FakeClock()
    provider = provider_for(lambda r: json_response([]), clock=clock)
    provider.fetch("example.com", make_ctx(clock))
    with pytest.raises(DiscoveryUnavailable) as info:
        provider.fetch("example.com", make_ctx(clock, remaining=1.0))
    assert info.value.error_class == "target_timeout"


def test_deadline_while_streaming_is_transient():
    clock = FakeClock()
    ctx = make_ctx(clock, remaining=30.0)

    class SlowStream(httpx.SyncByteStream):
        def __iter__(self):
            yield b"["
            clock.now += 60.0  # the body trickles past the target deadline
            yield b"{}]"

    def handler(request):
        return httpx.Response(
            200, headers={"Content-Type": "application/json"}, stream=SlowStream()
        )

    with pytest.raises(DiscoveryUnavailable) as info:
        provider_for(handler, clock=clock).fetch("example.com", ctx)
    assert info.value.error_class == "target_timeout"


def test_cancellation_before_and_during_the_fetch():
    seen = []
    provider = provider_for(lambda r: seen.append(r) or json_response([]))
    with pytest.raises(CheckStopped):
        provider.fetch("example.com", make_ctx(stop=lambda: True))
    assert seen == []

    stop = threading.Event()

    class Stream(httpx.SyncByteStream):
        def __iter__(self):
            yield b"["
            stop.set()
            yield b"]"

    def handler(request):
        return httpx.Response(200, headers={"Content-Type": "application/json"}, stream=Stream())

    with pytest.raises(CheckStopped):
        provider_for(handler).fetch("example.com", make_ctx(stop=stop.is_set))


def test_profile_timeouts_are_passed_to_httpx():
    seen = []

    def handler(request):
        seen.append(request.extensions["timeout"])
        return json_response([])

    provider_for(handler).fetch("example.com", make_ctx(remaining=600))
    assert seen[0]["connect"] == 5.0
    assert seen[0]["read"] == 10.0
    provider_for(handler).fetch("example.com", make_ctx(remaining=2.0))
    assert seen[1]["read"] == pytest.approx(2.0)


# -- run_discovery -----------------------------------------------------------------------------


class FakeProvider:
    name = "crt.sh"
    source = "certificate_transparency"

    def __init__(self, result=None, exc=None):
        self.result = result
        self.exc = exc
        self.calls = []

    def fetch(self, domain, budget):
        self.calls.append(domain)
        if self.exc is not None:
            raise self.exc
        return self.result


class FakeResolver:
    def __init__(self, on_query=None):
        self.queries = []
        self.on_query = on_query
        self.lock = threading.Lock()

    def query(self, name, rdtype, lifetime):
        with self.lock:
            self.queries.append((name, rdtype))
        if self.on_query:
            self.on_query(name, rdtype)
        if name.startswith("gone."):
            raise dns.resolver.NXDOMAIN
        if name.startswith("broken."):
            raise dns.resolver.NoNameservers
        if rdtype == "A":
            return DnsAnswer(300, ["198.51.100.10"], name)
        return DnsAnswer(None, [], name)


def names_result(names, **kwargs):
    return ProviderResult(
        "crt.sh", "certificate_transparency", names={n: NameMeta(1) for n in names}, **kwargs
    )


def test_run_discovery_reports_candidates_and_resolves_them():
    provider = FakeProvider(
        names_result(["example.com", "*.example.com", "www.example.com", "gone.example.com",
                      "broken.example.com", "evil.com"])
    )  # fmt: skip
    resolver = FakeResolver()
    out = []
    outcome = run_discovery(provider, resolver, APEX_ID, "example.com", make_ctx(), out.append)
    assert outcome.status == "success"
    assert outcome.candidates == 4
    disc = [o for o in out if o["kind"] == "discovery"]
    assert [(o["hostname"], o["wildcard"], o["resultStatus"]) for o in disc] == [
        ("example.com", False, "success"),
        ("broken.example.com", False, "success"),
        ("gone.example.com", False, "success"),
        ("www.example.com", False, "success"),
    ]
    for o in disc:
        assert set(o) == {
            "kind", "targetId", "observedAt", "checkerVersion", "resultStatus", "evidence",
            "hostname", "source", "wildcard",
        }  # fmt: skip
        assert o["source"] == "certificate_transparency"
        assert o["targetId"] == APEX_ID
        assert o["evidence"]["provider"] == "crt.sh"
    # The apex is not resolved again; candidates get A, AAAA and CNAME through the resolver.
    assert sorted(set(n for n, _ in resolver.queries)) == [
        "broken.example.com",
        "gone.example.com",
        "www.example.com",
    ]
    dns_obs = [o for o in out if o["kind"] == "dns"]
    assert {o["recordType"] for o in dns_obs} == {"A", "AAAA", "CNAME"}
    gone = [o for o in dns_obs if o["hostname"] == "gone.example.com"]
    assert all(o["resultStatus"] == "success" and o["values"] == [] for o in gone)
    broken = [o for o in dns_obs if o["hostname"] == "broken.example.com"]
    assert all(o["resultStatus"] == "error" for o in broken)
    # Discovery observations come first, then DNS in candidate order.
    kinds = [o["kind"] for o in out]
    assert kinds == sorted(kinds, key=lambda k: k != "discovery")


def test_run_discovery_wildcard_only_apex_is_flagged():
    out = []
    run_discovery(
        FakeProvider(names_result(["*.example.com"])), FakeResolver(), APEX_ID, "example.com",
        make_ctx(), out.append,
    )  # fmt: skip
    assert [(o["hostname"], o["wildcard"]) for o in out] == [("example.com", True)]


def test_run_discovery_permanent_error_is_one_apex_error_observation():
    resolver = FakeResolver()
    out = []
    result = ProviderResult("crt.sh", "certificate_transparency", error="invalid_json")
    outcome = run_discovery(
        FakeProvider(result), resolver, APEX_ID, "example.com", make_ctx(), out.append
    )
    assert outcome.status == "error"
    assert len(out) == 1
    assert out[0]["kind"] == "discovery"
    assert out[0]["hostname"] == "example.com"
    assert out[0]["resultStatus"] == "error"
    assert out[0]["evidence"] == {"provider": "crt.sh", "errorClass": "invalid_json"}
    assert resolver.queries == []


def test_run_discovery_transient_error_propagates():
    provider = FakeProvider(exc=DiscoveryUnavailable("http_503"))
    out = []
    with pytest.raises(DiscoveryUnavailable):
        run_discovery(provider, FakeResolver(), APEX_ID, "example.com", make_ctx(), out.append)
    assert out == []


def test_run_discovery_truncated_response_is_one_partial_apex_observation():
    result = names_result(["example.com", "www.example.com"], truncated=True, certificates=7)
    out = []
    outcome = run_discovery(
        FakeProvider(result), FakeResolver(), APEX_ID, "example.com", make_ctx(), out.append
    )
    assert outcome.status == "partial"
    apex = [o for o in out if o["kind"] == "discovery" and o["hostname"] == "example.com"]
    assert len(apex) == 1
    assert apex[0]["resultStatus"] == "partial"
    assert apex[0]["evidence"]["truncated"] is True
    assert apex[0]["evidence"]["certificates"] == 7
    www = [o for o in out if o["kind"] == "discovery" and o["hostname"] == "www.example.com"]
    assert www[0]["resultStatus"] == "success"


def test_run_discovery_candidate_cap_marks_the_run_partial():
    names = [f"h{i}.example.com" for i in range(30)]
    out = []
    outcome = run_discovery(
        FakeProvider(names_result(names)), FakeResolver(), APEX_ID, "example.com", make_ctx(),
        out.append, candidate_limit=10, resolve_limit=0,
    )  # fmt: skip
    assert outcome.status == "partial"
    disc = [o for o in out if o["kind"] == "discovery"]
    assert disc[0]["hostname"] == "example.com" and disc[0]["resultStatus"] == "partial"
    assert len(disc) == 11


def test_resolution_is_capped():
    names = [f"h{i:04d}.example.com" for i in range(MAX_RESOLVED_CANDIDATES + 50)]
    resolver = FakeResolver()
    out = []
    outcome = run_discovery(
        FakeProvider(names_result(names)), resolver, APEX_ID, "example.com", make_ctx(),
        out.append, concurrency=4,
    )  # fmt: skip
    resolved = sorted({n for n, _ in resolver.queries})
    assert len(resolved) == MAX_RESOLVED_CANDIDATES == 300
    assert resolved == sorted(names)[:300]
    assert len(resolver.queries) == 300 * 3
    assert outcome.resolved == 300
    assert len([o for o in out if o["kind"] == "discovery"]) == len(names)


def test_resolution_is_rate_limited():
    clock = FakeClock()
    ctx = make_ctx(clock, rate=5.0)
    run_discovery(
        FakeProvider(names_result([f"h{i}.example.com" for i in range(10)])), FakeResolver(),
        APEX_ID, "example.com", ctx, lambda _o: None,
    )  # fmt: skip
    # 30 queries at 5/s take at least 29 intervals of 0.2 s.
    assert sum(clock.slept) >= 29 * 0.2 - 1e-6


def test_resolution_stops_at_the_deadline_but_keeps_candidates():
    clock = FakeClock()
    ctx = make_ctx(clock, remaining=10.0)

    def slow(name, rdtype):
        clock.now += 1.0

    resolver = FakeResolver(on_query=slow)
    names = [f"h{i:02d}.example.com" for i in range(40)]
    out = []
    outcome = run_discovery(
        FakeProvider(names_result(names)), resolver, APEX_ID, "example.com", ctx, out.append
    )
    assert outcome.status == "success"
    assert len([o for o in out if o["kind"] == "discovery"]) == 40
    assert len(resolver.queries) <= 11
    assert outcome.resolved < 40


def test_resolution_cancellation_propagates():
    stop = threading.Event()
    resolver = FakeResolver(on_query=lambda n, t: stop.set())
    with pytest.raises(CheckStopped):
        run_discovery(
            FakeProvider(names_result(["a.example.com", "b.example.com"])), resolver, APEX_ID,
            "example.com", make_ctx(stop=stop.is_set), lambda _o: None,
        )  # fmt: skip
    assert len(resolver.queries) == 1


def test_resolution_queries_only_names_beneath_the_domain():
    raw = ["www.example.com", "example.com.evil.com", "evilexample.com", "1.2.3.4", "x.EXAMPLE.com"]
    resolver = FakeResolver()
    run_discovery(
        FakeProvider(names_result(raw)), resolver, APEX_ID, "example.com", make_ctx(),
        lambda _o: None,
    )  # fmt: skip
    assert {n for n, _ in resolver.queries} == {"www.example.com", "x.example.com"}


# -- job loop ----------------------------------------------------------------------------------

DISCOVERY_CONFIG = {
    "active": False,
    "checks": ["discovery"],
    "tcpPorts": [],
    "timeouts": {"connectMs": 10000, "readMs": 60000, "targetSeconds": 600},
    "concurrency": 4,
    "ratePerSecond": 50,
    "maxTargets": 1,
}
APEX_ONLY = [{"id": APEX_ID, "hostname": "example.com", "ip": None}]


def discovery_job(config=None):
    return make_job(config or DISCOVERY_CONFIG, targets=APEX_ONLY, profile="discovery")


@pytest.fixture
def worker_for(valid_env, tmp_path, monkeypatch):
    """Builds a Worker whose network primitives are all fakes. Any attempt to open a connection
    to a target (net.connect_tcp / tls / http) or to build a scope policy fails the test."""

    def forbidden(*_a, **_k):
        raise AssertionError("discovery must never connect to a target")

    monkeypatch.setattr(net, "connect_tcp", forbidden)
    monkeypatch.setattr(net, "tls_handshake", forbidden)
    monkeypatch.setattr(net, "http_get", forbidden)

    def build(job, *, crtsh=None, provider=None, resolver=None, env=None):
        key = Ed25519PrivateKey.generate()
        api = FakeApi(key, job)
        client = WorkerApiClient(
            "https://exdomainvault.example.com",
            Signer(key, KEY_ID),
            transport=httpx.MockTransport(api),
            sleep=lambda _s: None,
        )
        crtsh_seen: list[str] = []

        def crtsh_handler(request):
            crtsh_seen.append(str(request.url))
            return crtsh(request) if crtsh else json_response([])

        if provider is None:
            provider = provider_for(crtsh_handler)
        resolver = resolver or FakeResolver()
        clock = FakeClock()
        config = load_config({**valid_env, **(env or {})})
        worker = Worker(
            config,
            client,
            resolver_factory=lambda _timeout: resolver,
            rdap_client=RdapClient(transport=httpx.MockTransport(forbidden)),
            health=HealthReporter(str(tmp_path / "health.json"), "home-worker-01"),
            # Synthetic time: rate-limit waits advance the clock instead of spinning.
            monotonic=clock,
            sleep=clock.sleep,
            policy_factory=forbidden,
            self_protection=SelfProtection(
                configured_deny=(), local_reader=forbidden, egress_detector=forbidden
            ),
            discovery_provider=provider,
        )
        return worker, api, resolver, crtsh_seen

    return build


def test_default_profiles_claim_discovery_jobs(worker_for):
    worker, api, _, _ = worker_for(None)
    worker.run_once()
    assert api.endpoint_calls("claim")[0] == {"profiles": ["passive", "discovery", "brand"]}


def test_discovery_job_end_to_end_batches_observations(worker_for):
    names = [f"h{i:04d}.example.com" for i in range(1200)] + ["*.example.com", "evil.com"]
    entries = [cert(names[i : i + 50]) for i in range(0, len(names), 50)]
    worker, api, resolver, crtsh_seen = worker_for(
        discovery_job(), crtsh=lambda r: json_response(entries)
    )
    assert worker.run_once() == "job"
    assert crtsh_seen == [CRTSH_URL]
    assert "failures" not in [e for e, _ in api.calls]
    results = api.endpoint_calls("results")
    assert len(results) >= 4
    assert all(len(r["observations"]) <= 500 for r in results)
    assert [r["complete"] for r in results] == [False] * (len(results) - 1) + [True]
    assert len({r["resultId"] for r in results}) == len(results)
    targets = [t for r in results for t in r["targets"]]
    assert targets == [{"targetId": APEX_ID, "status": "succeeded"}]
    observations = [o for r in results for o in r["observations"]]
    assert {o["kind"] for o in observations} == {"discovery", "dns"}
    disc = [o for o in observations if o["kind"] == "discovery"]
    assert len(disc) == 1201  # 1200 names + the wildcard apex
    assert all(o["hostname"] == "example.com" or o["hostname"].endswith(".example.com")
               for o in observations)  # fmt: skip
    dns_names = {o["hostname"] for o in observations if o["kind"] == "dns"}
    assert len(dns_names) == MAX_RESOLVED_CANDIDATES
    assert all(n.endswith(".example.com") for n, _ in resolver.queries)


def test_discovery_job_with_no_candidates_succeeds(worker_for):
    worker, api, resolver, _ = worker_for(discovery_job())
    worker.run_once()
    results = api.endpoint_calls("results")
    assert results[-1]["complete"] is True
    assert [t for r in results for t in r["targets"]] == [
        {"targetId": APEX_ID, "status": "succeeded"}
    ]
    assert resolver.queries == []


@pytest.mark.parametrize("status", [429, 503])
def test_transient_provider_failure_is_a_retryable_job_failure(worker_for, status):
    worker, api, resolver, crtsh_seen = worker_for(
        discovery_job(), crtsh=lambda r: httpx.Response(status)
    )
    worker.run_once()
    assert crtsh_seen == [CRTSH_URL]
    failure = api.endpoint_calls("failures")[0]
    assert failure["jobId"] == JOB_ID
    assert failure["errorCode"] == "discovery_provider_unavailable"
    assert failure["retryable"] is True
    assert f"http_{status}" in failure["errorSummary"]
    assert not any(r["complete"] for r in api.endpoint_calls("results"))
    assert resolver.queries == []


def test_provider_timeout_is_a_retryable_job_failure(worker_for):
    def handler(request):
        raise httpx.ReadTimeout("slow")

    worker, api, _, _ = worker_for(discovery_job(), crtsh=handler)
    worker.run_once()
    failure = api.endpoint_calls("failures")[0]
    assert failure["errorCode"] == "discovery_provider_unavailable"
    assert failure["retryable"] is True


def test_permanent_provider_failure_completes_with_an_error_observation(worker_for):
    worker, api, resolver, _ = worker_for(
        discovery_job(), crtsh=lambda r: json_response(b"<html>", content_type="text/html")
    )
    worker.run_once()
    assert "failures" not in [e for e, _ in api.calls]
    results = api.endpoint_calls("results")
    assert results[-1]["complete"] is True
    targets = [t for r in results for t in r["targets"]]
    assert targets == [
        {"targetId": APEX_ID, "status": "failed", "errorCode": "discovery_provider_error"}
    ]
    observations = [o for r in results for o in r["observations"]]
    assert len(observations) == 1
    assert observations[0]["kind"] == "discovery"
    assert observations[0]["resultStatus"] == "error"
    assert observations[0]["evidence"]["errorClass"] == "unexpected_content_type"
    assert resolver.queries == []


def test_missing_provider_fails_the_target(worker_for):
    worker, api, _, _ = worker_for(discovery_job())
    worker._discovery = None
    worker.run_once()
    targets = [t for r in api.endpoint_calls("results") for t in r["targets"]]
    assert targets == [
        {"targetId": APEX_ID, "status": "failed", "errorCode": "discovery_unavailable"}
    ]


@pytest.mark.parametrize(
    "config",
    [
        {**DISCOVERY_CONFIG, "active": True},
        {**DISCOVERY_CONFIG, "checks": ["discovery", "tls_certificate"]},
        {**DISCOVERY_CONFIG, "active": True, "checks": ["discovery", "http_availability"]},
    ],
)
@pytest.mark.parametrize("active_enabled", ["false", "true"])
def test_discovery_never_combines_with_connecting_checks(worker_for, config, active_enabled):
    provider = FakeProvider(exc=AssertionError("provider must not run"))
    worker, api, resolver, _ = worker_for(
        discovery_job(config),
        provider=provider,
        env={"EXDV_ACTIVE_SCANNING_ENABLED": active_enabled, "EXDV_DENY_NETWORKS": "192.0.2.0/24"},
    )
    worker.run_once()
    assert [e for e, _ in api.calls] == ["claim", "failures"]
    failure = api.endpoint_calls("failures")[0]
    assert failure["errorCode"] == "invalid_profile"
    assert failure["retryable"] is False
    assert provider.calls == [] and resolver.queries == []


def test_discovery_job_never_builds_a_scope_policy_even_with_active_scanning_on(worker_for):
    # policy_factory, self-protection and every net primitive raise in this fixture.
    worker, api, _, crtsh_seen = worker_for(
        discovery_job(),
        crtsh=lambda r: json_response([cert(["www.example.com"])]),
        env={"EXDV_ACTIVE_SCANNING_ENABLED": "true", "EXDV_DENY_NETWORKS": "192.0.2.0/24"},
    )
    worker.run_once()
    assert crtsh_seen == [CRTSH_URL]
    assert "failures" not in [e for e, _ in api.calls]
    targets = [t for r in api.endpoint_calls("results") for t in r["targets"]]
    assert targets == [{"targetId": APEX_ID, "status": "succeeded"}]


def test_discovery_runs_only_for_the_apex_target(worker_for):
    www = {"id": "22222222-2222-4222-8222-222222222222", "hostname": "www.example.com", "ip": None}
    targets = [*APEX_ONLY, www]
    job = make_job({**DISCOVERY_CONFIG, "maxTargets": 5}, targets=targets, profile="discovery")
    provider = FakeProvider(names_result(["a.example.com"]))
    worker, api, _, _ = worker_for(job, provider=provider)
    worker.run_once()
    assert provider.calls == ["example.com"]
    statuses = {t["targetId"]: t["status"] for r in api.endpoint_calls("results")
                for t in r["targets"]}  # fmt: skip
    assert statuses == {APEX_ID: "succeeded", "22222222-2222-4222-8222-222222222222": "skipped"}


def test_cancellation_before_discovery_skips_the_provider(worker_for):
    provider = FakeProvider(exc=AssertionError("provider must not run"))
    worker, api, _, _ = worker_for(discovery_job(), provider=provider)
    api.heartbeat_responses.append(
        {"leaseExpiresAt": "2026-10-22T10:10:00.000Z", "cancelRequested": True}
    )
    worker.run_once()
    assert api.endpoint_calls("failures")[0]["errorCode"] == "cancelled"
    assert provider.calls == []


def test_profile_not_claimed_is_refused(worker_for):
    worker, api, _, _ = worker_for(discovery_job(), env={"EXDV_PROFILES": "passive"})
    worker.run_once()
    assert api.endpoint_calls("failures")[0]["errorCode"] == "profile_not_supported"
