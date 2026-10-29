"""Network ownership (Milestone 15): IANA IP bootstrap, RIR RDAP parsing, organisation matching,
reverse DNS of owned ranges, and the ``network`` check in the discovery job.

Everything is synthetic: RDAP goes to ``httpx.MockTransport`` with fixtures shaped like APNIC, ARIN
and RIPE responses, DNS to fake resolvers. Nothing here contacts a registry, resolver or target.
"""

from __future__ import annotations

import ipaddress
import json
import threading

import dns.resolver
import httpx
import pytest

from app.checks import CheckStopped
from app.dns_checks import DnsAnswer
from app.network_checks import (
    MAX_PTR_NETWORK_SIZE,
    NETWORK_USER_AGENT,
    NetworkContext,
    NetworkRdapError,
    RdapIpClient,
    match_ip_bootstrap,
    normalise_org,
    org_name_matches,
    parse_ip_bootstrap,
    parse_network_context,
    parse_rdap_network,
    registry_of,
    reverse_dns,
    run_network,
)
from app.policy import tier_of
from app.queue import parse_job
from app.scope import KNOWN_CHECKS, PASSIVE_CHECKS, assert_passive_allowed

from .test_discovery import (
    APEX_ID,
    APEX_ONLY,
    DISCOVERY_CONFIG,
    FakeClock,
    FakeProvider,
    make_ctx,
    names_result,
    worker_for,  # noqa: F401  (pytest fixture)
)
from .test_queue import make_job

IPV4_BOOTSTRAP = {
    "version": "1.0",
    "services": [
        [["49.0.0.0/8", "203.0.0.0/8"], ["https://rdap.apnic.net/"]],
        [["3.0.0.0/8", "52.0.0.0/8"], ["https://rdap.arin.net/registry/", "http://rdap.arin.net/registry/"]],
        [["185.0.0.0/8"], ["https://rdap.db.ripe.net/"]],
        [["100.0.0.0/8"], ["https://rdap.evil.example/"]],
        "garbage",
        [["not-a-prefix"], ["https://rdap.apnic.net/"]],
    ],
}  # fmt: skip
IPV6_BOOTSTRAP = {"services": [[["2400::/12"], ["https://rdap.apnic.net/"]]]}

APNIC_NET = {
    "objectClassName": "ip network",
    "handle": "49.231.0.0 - 49.231.3.255",
    "startAddress": "49.231.0.0",
    "endAddress": "49.231.3.255",
    "ipVersion": "v4",
    "name": "THAIUNION-TH",
    "type": "ASSIGNED PORTABLE",
    "country": "TH",
    "remarks": [
        {"title": "description",
         "description": ["Thai Union Group Public Company Limited", "Bangkok"]}
    ],
    "entities": [
        {
            "handle": "IRT-TU-TH",
            "roles": ["abuse"],
            "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "IRT-TU"]]],
        },
        {
            "handle": "TU1-AP",
            "roles": ["administrative", "technical"],
            "vcardArray": ["vcard", [["fn", {}, "text", "Network Administrator"]]],
        },
    ],
    "cidr0_cidrs": [{"v4prefix": "49.231.0.0", "length": 22}],
}  # fmt: skip

ARIN_NET = {
    "objectClassName": "ip network",
    "handle": "NET-52-0-0-0-1",
    "startAddress": "52.0.0.0",
    "endAddress": "52.79.255.255",
    "ipVersion": "v4",
    "name": "AT-88-Z",
    "type": "DIRECT ALLOCATION",
    "cidr0_cidrs": [
        {"v4prefix": "52.0.0.0", "length": 10},
        {"v4prefix": "52.64.0.0", "length": 12},
    ],
    "entities": [
        {
            "handle": "AT-88-Z",
            "roles": ["registrant"],
            "vcardArray": [
                "vcard",
                [["version", {}, "text", "4.0"], ["fn", {}, "text", "Amazon Technologies Inc."],
                 ["kind", {}, "text", "org"]],
            ],
            "entities": [{"handle": "AEA8-ARIN", "roles": ["abuse"],
                          "vcardArray": ["vcard", [["fn", {}, "text", "Amazon EC2 Abuse"]]]}],
        }
    ],
}  # fmt: skip

RIPE_NET = {
    "objectClassName": "ip network",
    "handle": "185.10.20.0 - 185.10.20.255",
    "startAddress": "185.10.20.0",
    "endAddress": "185.10.20.255",
    "name": "TU-EU-NET",
    "country": "nl",
    "entities": [
        {
            "handle": "ORG-TUE1-RIPE",
            "roles": ["registrant"],
            "vcardArray": [
                "vcard",
                [["fn", {}, "text", "THAI-UNION Europe B.V."], ["kind", {}, "text", "org"]],
            ],
        }
    ],
}  # fmt: skip

APNIC_V6 = {
    "objectClassName": "ip network",
    "handle": "2400:aa00::/32",
    "startAddress": "2400:aa00::",
    "endAddress": "2400:aa00:ffff:ffff:ffff:ffff:ffff:ffff",
    "name": "THAIUNION-V6",
    "country": "TH",
    "cidr0_cidrs": [{"v6prefix": "2400:aa00::", "length": 32}],
}


def rdap_response(body, status=200, headers=None):
    return httpx.Response(
        status,
        content=json.dumps(body).encode(),
        headers={"Content-Type": "application/rdap+json", **(headers or {})},
    )


class Registry:
    """MockTransport handler: IANA bootstrap + per-URL RDAP fixtures, recording every request."""

    def __init__(self, objects=None):
        self.objects = objects or {}
        self.seen: list[str] = []
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.seen.append(url)
        self.requests.append(request)
        if url == "https://data.iana.org/rdap/ipv4.json":
            return rdap_response(IPV4_BOOTSTRAP)
        if url == "https://data.iana.org/rdap/ipv6.json":
            return rdap_response(IPV6_BOOTSTRAP)
        handler = self.objects.get(url)
        if handler is None:
            return httpx.Response(404)
        return handler(request) if callable(handler) else rdap_response(handler)


def client_for(registry, clock=None) -> RdapIpClient:
    clock = clock or FakeClock()
    return RdapIpClient(transport=httpx.MockTransport(registry), clock=clock, sleep=clock.sleep)


class PtrResolver:
    def __init__(self, ptr=None, on_query=None):
        self.ptr = ptr or {}
        self.queries: list[tuple[str, str]] = []
        self.on_query = on_query
        self.lock = threading.Lock()

    def query(self, name, rdtype, lifetime):
        with self.lock:
            self.queries.append((name, rdtype))
        if self.on_query:
            self.on_query(name, rdtype)
        if rdtype == "PTR":
            value = self.ptr.get(name)
            if value is None:
                raise dns.resolver.NXDOMAIN
            if value == "timeout":
                raise dns.exception.Timeout
            return DnsAnswer(3600, value, name)
        if rdtype == "A":
            return DnsAnswer(300, ["49.231.0.10"], name)
        return DnsAnswer(None, [], name)


def ptr_name(ip: str) -> str:
    return ipaddress.ip_address(ip).reverse_pointer


APNIC_URL = "https://rdap.apnic.net/ip/49.231.0.10"
ARIN_URL = "https://rdap.arin.net/registry/ip/52.1.2.3"
RIPE_URL = "https://rdap.db.ripe.net/ip/185.10.20.5"
ORGS = ("Thai Union",)


# -- catalogue ---------------------------------------------------------------------------------


def test_network_is_a_known_passive_check():
    assert "network" in KNOWN_CHECKS
    assert "network" in PASSIVE_CHECKS
    assert tier_of("network") == "passive"
    assert_passive_allowed("network")


# -- organisation matching ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "candidate",
    [
        "Thai Union Group Public Company Limited",
        "THAI UNION",
        "thai-union europe b.v.",
        "Thai  Union,  Inc.",
        "THAIUNION-TH",
        "TU-THAI-UNION-NET",
        "\uff54\uff48\uff41\uff49 \uff55\uff4e\uff49\uff4f\uff4e",  # full-width (NFKC)
    ],
)
def test_org_names_match_case_and_punctuation_insensitively(candidate):
    assert org_name_matches(["Thai Union"], [candidate])


@pytest.mark.parametrize(
    "candidate",
    [
        "Thailand Unionbank",
        "Thai Unionist Party",
        "Union Thai",
        "THAIUNIONGROUP",
        "",
        None,
        "Amazon",
    ],
)
def test_org_names_do_not_match_partial_words(candidate):
    assert not org_name_matches(["Thai Union"], [candidate])


def test_names_match_on_word_boundaries_only():
    # Never a substring inside a word.
    assert not org_name_matches(["AB Co"], ["XABCOY-NET"])
    assert org_name_matches(["AB Co"], ["The AB Co. Ltd"])


def test_empty_org_list_never_matches():
    assert not org_name_matches([], ["Thai Union"])
    assert not org_name_matches(["  ", "--"], ["Thai Union"])
    assert normalise_org(" Thai--Union!! ") == "thai union"


# -- bootstrap ---------------------------------------------------------------------------------


def test_bootstrap_keeps_only_known_rir_https_bases():
    services = parse_ip_bootstrap(IPV4_BOOTSTRAP)
    bases = {base for _, base in services}
    assert bases == {
        "https://rdap.apnic.net/",
        "https://rdap.arin.net/registry/",
        "https://rdap.db.ripe.net/",
    }
    assert match_ip_bootstrap(services, ipaddress.ip_address("49.231.0.10")) == (
        "https://rdap.apnic.net/"
    )
    assert match_ip_bootstrap(services, ipaddress.ip_address("100.1.1.1")) is None
    assert match_ip_bootstrap(services, ipaddress.ip_address("8.8.8.8")) is None


def test_bootstrap_longest_prefix_wins():
    services = parse_ip_bootstrap(
        {"services": [[["49.0.0.0/8"], ["https://rdap.apnic.net/"]],
                      [["49.231.0.0/16"], ["https://rdap.ripe.net/x", "https://rdap.db.ripe.net/"]]]}
    )  # fmt: skip
    assert match_ip_bootstrap(services, ipaddress.ip_address("49.231.1.1")) == (
        "https://rdap.db.ripe.net/"
    )


def test_registry_of_requires_https_on_a_known_host():
    assert registry_of("https://rdap.apnic.net/ip/1.1.1.1") == "apnic"
    assert registry_of("http://rdap.apnic.net/") is None
    assert registry_of("https://rdap.apnic.net:8443/") is None
    assert registry_of("https://rdap.apnic.net.evil.com/") is None


def test_invalid_bootstrap_is_an_error():
    with pytest.raises(NetworkRdapError):
        parse_ip_bootstrap({"nope": 1})


# -- RDAP parsing ------------------------------------------------------------------------------


def test_parse_apnic_network_uses_description_as_organisation():
    info = parse_rdap_network(APNIC_NET, "apnic")
    assert info.registry == "apnic"
    assert info.handle == "49.231.0.0 - 49.231.3.255"
    assert info.name == "THAIUNION-TH"
    assert info.org_name == "Thai Union Group Public Company Limited"
    assert info.country == "TH"
    assert info.cidrs == ["49.231.0.0/22"]
    assert str(info.start) == "49.231.0.0" and str(info.end) == "49.231.3.255"
    assert info.size == 1024
    assert "Network Administrator" in info.entity_names
    assert "IRT-TU" not in info.entity_names  # abuse contacts are not organisation names


def test_parse_arin_network_uses_registrant_and_cidr0():
    info = parse_rdap_network(ARIN_NET, "arin")
    assert info.org_name == "Amazon Technologies Inc."
    assert info.cidrs == ["52.0.0.0/10", "52.64.0.0/12"]
    assert info.country is None
    assert info.contains(ipaddress.ip_address("52.1.2.3"))
    assert not info.contains(ipaddress.ip_address("52.80.0.1"))


def test_parse_ripe_network_without_cidr0_summarises_the_range():
    info = parse_rdap_network(RIPE_NET, "ripe")
    assert info.org_name == "THAI-UNION Europe B.V."
    assert info.cidrs == ["185.10.20.0/24"]
    assert info.country == "NL"


def test_parse_rejects_inconsistent_ranges_and_bad_values():
    info = parse_rdap_network(
        {"startAddress": "10.0.0.9", "endAddress": "10.0.0.1", "country": "Thailand",
         "cidr0_cidrs": [{"v4prefix": "x", "length": 8}, {"v4prefix": "1.0.0.0", "length": True}],
         "name": "  A   B  "},
        None,
    )  # fmt: skip
    assert info.start is None and info.end is None
    assert info.cidrs == []
    assert info.country is None
    assert info.name == "A B"
    assert info.registry is None
    with pytest.raises(NetworkRdapError):
        parse_rdap_network([], "arin")


# -- RDAP client -------------------------------------------------------------------------------


def test_lookup_uses_bootstrap_base_and_identifying_user_agent():
    registry = Registry({APNIC_URL: APNIC_NET})
    client = client_for(registry)
    name, document = client.lookup(ipaddress.ip_address("49.231.0.10"), make_ctx())
    assert name == "apnic"
    assert document["name"] == "THAIUNION-TH"
    assert registry.seen == ["https://data.iana.org/rdap/ipv4.json", APNIC_URL]
    for request in registry.requests:
        assert request.headers["User-Agent"] == NETWORK_USER_AGENT
    assert registry.requests[1].headers["Accept"] == "application/rdap+json"


def test_bootstrap_is_cached_between_lookups():
    registry = Registry({APNIC_URL: APNIC_NET, ARIN_URL: ARIN_NET})
    client = client_for(registry)
    client.lookup(ipaddress.ip_address("49.231.0.10"), make_ctx())
    client.lookup(ipaddress.ip_address("52.1.2.3"), make_ctx())
    assert registry.seen.count("https://data.iana.org/rdap/ipv4.json") == 1


def test_requests_to_one_registry_are_spaced_at_least_one_second():
    clock = FakeClock()
    other = "https://rdap.apnic.net/ip/49.231.8.1"
    registry = Registry({APNIC_URL: APNIC_NET, other: APNIC_NET})
    client = client_for(registry, clock)
    ctx = make_ctx(clock)
    start = clock.now
    client.lookup(ipaddress.ip_address("49.231.0.10"), ctx)
    client.lookup(ipaddress.ip_address("49.231.8.1"), ctx)
    assert clock.now - start >= 1.0 - 1e-9


def test_redirect_only_to_another_rir():
    moved = "https://rdap.db.ripe.net/ip/49.231.0.10"
    registry = Registry(
        {APNIC_URL: lambda r: httpx.Response(301, headers={"Location": moved}), moved: RIPE_NET}
    )
    client = client_for(registry)
    _, document = client.lookup(ipaddress.ip_address("49.231.0.10"), make_ctx())
    assert document["name"] == "TU-EU-NET"
    assert registry.seen[-1] == moved

    evil = Registry(
        {APNIC_URL: lambda r: httpx.Response(302, headers={"Location": "https://169.254.169.254/"})}
    )
    with pytest.raises(NetworkRdapError) as exc:
        client_for(evil).lookup(ipaddress.ip_address("49.231.0.10"), make_ctx())
    assert exc.value.reason == "redirect_refused"
    assert "169.254.169.254" not in " ".join(evil.seen)


def test_429_is_retried_once_after_retry_after():
    calls = []

    def limited(request):
        calls.append(1)
        if len(calls) == 1:
            return httpx.Response(429, headers={"Retry-After": "2"})
        return rdap_response(APNIC_NET)

    clock = FakeClock()
    client = client_for(Registry({APNIC_URL: limited}), clock)
    _, document = client.lookup(ipaddress.ip_address("49.231.0.10"), make_ctx(clock))
    assert document["handle"] == APNIC_NET["handle"]
    assert len(calls) == 2
    assert sum(clock.slept) >= 2.0


@pytest.mark.parametrize("retry_after", [None, "3600", "Wed, 21 Oct 2026 07:28:00 GMT"])
def test_429_without_a_short_retry_after_fails(retry_after):
    headers = {"Retry-After": retry_after} if retry_after else {}
    client = client_for(Registry({APNIC_URL: lambda r: httpx.Response(429, headers=headers)}))
    with pytest.raises(NetworkRdapError) as exc:
        client.lookup(ipaddress.ip_address("49.231.0.10"), make_ctx())
    assert exc.value.reason == "rate_limited"


def test_response_size_is_capped():
    big = {**APNIC_NET, "remarks": [{"description": ["x" * 2_000_000]}]}
    client = client_for(Registry({APNIC_URL: big}))
    with pytest.raises(NetworkRdapError) as exc:
        client.lookup(ipaddress.ip_address("49.231.0.10"), make_ctx())
    assert exc.value.reason == "response_too_large"


def test_client_never_follows_redirects_or_trusts_environment_proxies():
    client = RdapIpClient()
    assert client._http.follow_redirects is False
    assert client._http.trust_env is False


# -- reverse DNS -------------------------------------------------------------------------------


def test_reverse_dns_keeps_only_names_within_the_job_domain():
    info = parse_rdap_network(APNIC_NET, "apnic")
    resolver = PtrResolver(
        {
            ptr_name("49.231.0.1"): ["mail.example.com."],
            ptr_name("49.231.0.2"): ["vpn.EXAMPLE.com.", "other.example.net."],
            ptr_name("49.231.0.3"): ["example.com.evil.com."],
            ptr_name("49.231.0.4"): "timeout",
            ptr_name("49.231.0.5"): ["*.example.com.", "bad_name.example.com."],
        }
    )
    found, evidence = reverse_dns(resolver, info, "example.com", make_ctx(), [5000])
    assert found == {"mail.example.com": ["49.231.0.1"], "vpn.example.com": ["49.231.0.2"]}
    assert evidence["status"] == "complete"
    assert evidence["queried"] == 1024
    assert evidence["errors"] == 1
    assert evidence["namesOutsideDomain"] == 2
    assert all(t == "PTR" for _, t in resolver.queries)


def test_reverse_dns_skips_large_networks_and_ipv6():
    resolver = PtrResolver()
    large = parse_rdap_network({**APNIC_NET, "endAddress": "49.231.4.0"}, "apnic")
    assert large.size == MAX_PTR_NETWORK_SIZE + 1
    found, evidence = reverse_dns(resolver, large, "example.com", make_ctx(), [5000])
    assert found == {} and evidence == {"status": "skipped", "reason": "too_large", "size": 1025}
    v6 = parse_rdap_network(APNIC_V6, "apnic")
    assert reverse_dns(resolver, v6, "example.com", make_ctx(), [5000])[1]["reason"] == "ipv6"
    unknown = parse_rdap_network({"name": "x"}, "apnic")
    assert reverse_dns(resolver, unknown, "example.com", make_ctx(), [5000])[1]["reason"] == (
        "range_unknown"
    )
    assert resolver.queries == []


def test_reverse_dns_respects_query_cap_rate_limit_and_deadline():
    info = parse_rdap_network(RIPE_NET, "ripe")  # /24
    resolver = PtrResolver()
    budget = [10]
    _, evidence = reverse_dns(resolver, info, "example.com", make_ctx(), budget)
    assert evidence["status"] == "query_cap" and evidence["queried"] == 10 and budget == [0]

    clock = FakeClock()
    _, evidence = reverse_dns(PtrResolver(), info, "example.com", make_ctx(clock, rate=5.0), [5000])
    assert sum(clock.slept) >= 255 * 0.2 - 1e-6  # 256 queries at 5/s

    clock = FakeClock()
    slow = PtrResolver(on_query=lambda n, t: setattr(clock, "now", clock.now + 1.0))
    _, evidence = reverse_dns(slow, info, "example.com", make_ctx(clock, remaining=10.0), [5000])
    assert evidence["status"] == "time_cap"
    assert evidence["queried"] <= 11


def test_reverse_dns_cancellation_propagates():
    stop = threading.Event()
    resolver = PtrResolver(on_query=lambda n, t: stop.set())
    with pytest.raises(CheckStopped):
        reverse_dns(
            resolver, parse_rdap_network(RIPE_NET, "ripe"), "example.com",
            make_ctx(stop=stop.is_set), [5000],
        )  # fmt: skip
    assert len(resolver.queries) == 1


# -- run_network -------------------------------------------------------------------------------


def run(registry, resolver, addresses, org_names=ORGS, **kwargs):
    out = []
    outcome = run_network(
        client_for(registry), resolver, APEX_ID, "example.com",
        NetworkContext(org_names=tuple(org_names), addresses=tuple(addresses)),
        make_ctx(), out.append, **kwargs,
    )  # fmt: skip
    return outcome, out


def test_run_network_emits_one_observation_per_distinct_network():
    registry = Registry({APNIC_URL: APNIC_NET, ARIN_URL: ARIN_NET})
    resolver = PtrResolver({ptr_name("49.231.2.7"): ["portal.example.com."]})
    outcome, out = run(
        registry, resolver,
        ["49.231.0.10", "49.231.0.11", "52.1.2.3", "52.1.2.3", "10.0.0.1", "127.0.0.1", "bogus"],
    )  # fmt: skip
    # The second APNIC address is inside the first network: no second RDAP query.
    assert [u for u in registry.seen if "/ip/" in u] == [APNIC_URL, ARIN_URL]
    networks = [o for o in out if o["kind"] == "network"]
    assert len(networks) == 2
    tu, aws = networks
    assert set(tu) == {
        "kind", "targetId", "observedAt", "checkerVersion", "resultStatus", "evidence",
        "ipAddress", "startAddress", "endAddress", "cidrs", "registry", "handle", "networkName",
        "orgName", "country", "matchedOrg",
    }  # fmt: skip
    assert tu["matchedOrg"] is True and tu["registry"] == "apnic"
    assert tu["evidence"]["addresses"] == ["49.231.0.10", "49.231.0.11"]
    assert tu["evidence"]["reverseDns"]["status"] == "complete"
    assert aws["matchedOrg"] is False and aws["orgName"] == "Amazon Technologies Inc."
    assert aws["evidence"]["reverseDns"] == {"status": "skipped", "reason": "not_matched"}
    # PTR only for the matched network; the reverse name becomes a reverse_dns candidate.
    ptr = [n for n, t in resolver.queries if t == "PTR"]
    assert len(ptr) == 1024 and all(n.endswith(".231.49.in-addr.arpa") for n in ptr)
    disc = [o for o in out if o["kind"] == "discovery"]
    assert [(o["hostname"], o["source"], o["resultStatus"]) for o in disc] == [
        ("portal.example.com", "reverse_dns", "success")
    ]
    assert disc[0]["evidence"] == {
        "provider": "ptr", "addresses": ["49.231.2.7"], "network": "49.231.0.0/22",
    }  # fmt: skip
    # ... and is resolved forward like a CT candidate.
    dns_obs = [o for o in out if o["kind"] == "dns"]
    assert {o["hostname"] for o in dns_obs} == {"portal.example.com"}
    assert outcome.networks == 2 and outcome.matched == 1 and outcome.reverse_names == 1


def test_run_network_without_org_names_never_runs_reverse_dns():
    resolver = PtrResolver()
    outcome, out = run(Registry({APNIC_URL: APNIC_NET}), resolver, ["49.231.0.10"], org_names=())
    assert outcome.matched == 0
    assert [o["matchedOrg"] for o in out] == [False]
    assert resolver.queries == []


def test_run_network_reports_failed_lookups_without_inventing_data():
    registry = Registry(
        {APNIC_URL: lambda r: httpx.Response(500), ARIN_URL: lambda r: httpx.Response(404)}
    )
    outcome, out = run(registry, PtrResolver(), ["49.231.0.10", "52.1.2.3", "8.8.8.8"])
    assert outcome.failed == 3
    assert [(o["ipAddress"], o["resultStatus"], o["evidence"]["errorClass"]) for o in out] == [
        ("8.8.8.8", "error", "no_rdap_service"),
        ("49.231.0.10", "error", "http_error"),
        ("52.1.2.3", "error", "not_found"),
    ]
    for o in out:
        assert o["orgName"] is None and o["cidrs"] == [] and o["matchedOrg"] is False


def test_run_network_timeouts_are_timeout_observations():
    def slow(request):
        raise httpx.ReadTimeout("slow")

    _, out = run(Registry({APNIC_URL: slow}), PtrResolver(), ["49.231.0.10"])
    assert out[0]["resultStatus"] == "timeout"


def test_run_network_caps_rdap_queries():
    registry = Registry()
    _, out = run(registry, PtrResolver(), [f"49.231.{i}.1" for i in range(20)], max_queries=3)
    assert len([u for u in registry.seen if "/ip/" in u]) == 3
    assert len(out) == 3


def test_run_network_ipv6_network_is_not_reverse_scanned():
    v6_url = "https://rdap.apnic.net/ip/2400:aa00::10"
    resolver = PtrResolver()
    _, out = run(Registry({v6_url: APNIC_V6}), resolver, ["2400:aa00::10"])
    assert out[0]["matchedOrg"] is True
    assert out[0]["cidrs"] == ["2400:aa00::/32"]
    assert out[0]["evidence"]["reverseDns"] == {"status": "skipped", "reason": "ipv6"}
    assert resolver.queries == []


def test_parse_network_context_is_lenient_and_bounded():
    ctx = parse_network_context(
        {"orgNames": ["Thai Union", 5, "  ", "x" * 500],
         "addresses": ["1.2.3.4", None] + ["9.9.9.9"] * 300}
    )  # fmt: skip
    assert ctx.org_names == ("Thai Union", "x" * 100)
    assert len(ctx.addresses) == 256
    assert parse_network_context(None) == NetworkContext()
    assert parse_network_context({"orgNames": "Thai Union"}).org_names == ()


# -- job loop ----------------------------------------------------------------------------------

NETWORK_CONFIG = {**DISCOVERY_CONFIG, "checks": ["discovery", "network"]}


def network_job(addresses, org_names=ORGS):
    job = make_job(NETWORK_CONFIG, targets=APEX_ONLY, profile="discovery")
    job["network"] = {"orgNames": list(org_names), "addresses": list(addresses)}
    return job


def test_parse_job_reads_the_network_context():
    spec = parse_job(network_job(["49.231.0.10"]))
    assert spec.network.addresses == ("49.231.0.10",)
    assert spec.network.org_names == ORGS
    assert parse_job(make_job(NETWORK_CONFIG, targets=APEX_ONLY)).network == NetworkContext()


def test_discovery_job_runs_the_network_check_after_discovery(worker_for):  # noqa: F811
    registry = Registry({APNIC_URL: APNIC_NET})
    resolver = PtrResolver({ptr_name("49.231.0.20"): ["erp.example.com."]})
    provider = FakeProvider(names_result(["www.example.com"]))
    worker, api, _, _ = worker_for(
        network_job(["49.231.0.10"]), provider=provider, resolver=resolver
    )
    worker._network = client_for(registry)
    assert worker.run_once() == "job"
    assert "failures" not in [e for e, _ in api.calls]
    observations = [o for r in api.endpoint_calls("results") for o in r["observations"]]
    kinds = [o["kind"] for o in observations]
    assert kinds.index("network") > kinds.index("discovery")
    network = [o for o in observations if o["kind"] == "network"]
    assert len(network) == 1 and network[0]["matchedOrg"] is True
    sources = {o["hostname"]: o["source"] for o in observations if o["kind"] == "discovery"}
    assert sources == {
        "www.example.com": "certificate_transparency",
        "erp.example.com": "reverse_dns",
    }
    targets = [t for r in api.endpoint_calls("results") for t in r["targets"]]
    assert targets == [{"targetId": APEX_ID, "status": "succeeded"}]


def test_network_check_without_a_client_fails_only_that_check(worker_for):  # noqa: F811
    provider = FakeProvider(names_result(["www.example.com"]))
    worker, api, _, _ = worker_for(network_job(["49.231.0.10"]), provider=provider)
    worker.run_once()
    targets = [t for r in api.endpoint_calls("results") for t in r["targets"]]
    assert targets == [
        {"targetId": APEX_ID, "status": "succeeded", "errorCode": "network_unavailable"}
    ]


def test_network_check_never_contacts_the_addresses(worker_for):  # noqa: F811
    # worker_for patches every net primitive (connect/tls/http) to fail the test; RDAP goes to the
    # mocked registry only.
    registry = Registry({APNIC_URL: APNIC_NET})
    worker, _, _, _ = worker_for(
        network_job(["49.231.0.10"]), provider=FakeProvider(names_result([])),
        resolver=PtrResolver(),
    )  # fmt: skip
    worker._network = client_for(registry)
    worker.run_once()
    assert all(
        u.startswith(("https://data.iana.org/", "https://rdap.apnic.net/")) for u in registry.seen
    )
    assert "49.231.0.10" not in [r.url.host for r in registry.requests]
