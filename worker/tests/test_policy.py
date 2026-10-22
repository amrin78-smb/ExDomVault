"""Scope validator (Milestone 6 security gate). Pure unit tests: fake resolvers, no network."""

from __future__ import annotations

import ipaddress
import json
import logging

import dns.exception
import dns.resolver
import pytest

from app import policy as policy_module
from app.dns_checks import DnsAnswer
from app.policy import (
    ACTIVE_SCANNING_DISABLED,
    CHECK_NOT_ALLOWED,
    CNAME_CHAIN_INVALID,
    CNAME_OUT_OF_SCOPE,
    MAX_CNAME_HOPS,
    NETWORK_NOT_APPROVED,
    NO_ALLOWED_ADDRESS,
    OUT_OF_SCOPE_HOST,
    PROHIBITED_ADDRESS,
    SCOPE_REJECTED,
    AddressRefused,
    ScopeError,
    ScopePolicy,
    address_prohibited_reason,
    parse_address,
    parse_network,
    tier_of,
)

ALL_CHECKS = [
    "dns",
    "rdap",
    "tls_certificate",
    "http_availability",
    "http_headers",
    "tcp_ports",
    "service_identification",
    "tls_configuration",
]
PUBLIC_V4 = "93.184.216.34"
PUBLIC_V4_B = "8.8.8.8"
PUBLIC_V6 = "2606:4700:4700::1111"


def snapshot(*, checks=None, approved=None, targets=None, fqdn="example.com") -> dict:
    snap = {
        "domain": {"fqdn": fqdn},
        "profile": {"config": {"checks": ALL_CHECKS if checks is None else checks}},
        "approvedNetworks": approved or [],
    }
    if targets is not None:
        snap["targets"] = [{"assetId": None, "hostname": t} for t in targets]
    return snap


def make_policy(*, active=True, approved=None, deny=(), checks=None, targets=("example.com",)):
    return ScopePolicy.from_job(
        job_id="job-1",
        snapshot=snapshot(checks=checks, approved=approved),
        target_hostnames=list(targets),
        deny_networks=list(deny),
        active_scanning_enabled=active,
    )


class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.fixture
def captured():
    """Records from the ``exdv`` logger (which does not propagate to pytest's caplog)."""
    logger = logging.getLogger("exdv")
    handler = _Capture()
    old_level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        yield handler.records
    finally:
        logger.removeHandler(handler)
        logger.setLevel(old_level)


class FakeResolver:
    """Static zone: ``records[(name, rdtype)]`` = list of values, or an Exception to raise."""

    def __init__(self, records: dict[tuple[str, str], object]) -> None:
        self.records = records
        self.calls: list[tuple[str, str]] = []

    def query(self, name: str, rdtype: str, lifetime: float) -> DnsAnswer:
        self.calls.append((name, rdtype))
        value = self.records.get((name, rdtype), [])
        if isinstance(value, Exception):
            raise value
        return DnsAnswer(ttl=60, values=list(value), canonical_name=name)  # type: ignore[arg-type]


# ------------------------------------------------------------------------------------------------
# tier_of / assert_check_allowed


@pytest.mark.parametrize(
    ("check", "tier"),
    [
        ("dns", "passive"),
        ("rdap", "passive"),
        ("tls_certificate", "web"),
        ("http_availability", "web"),
        ("http_headers", "web"),
        ("tcp_ports", "network"),
        ("service_identification", "network"),
        ("tls_configuration", "network"),
    ],
)
def test_tier_of_known_checks(check, tier):
    assert tier_of(check) == tier


@pytest.mark.parametrize("check", ["", "nmap", "DNS", "exploit", "tcp_ports "])
def test_tier_of_unknown_check(check):
    with pytest.raises(ScopeError) as err:
        tier_of(check)
    assert err.value.code == CHECK_NOT_ALLOWED


def test_check_must_be_in_profile():
    policy = make_policy(checks=["dns", "http_headers"])
    assert policy.assert_check_allowed("dns") == "passive"
    assert policy.assert_check_allowed("http_headers") == "web"
    for check in ("tcp_ports", "tls_certificate", "made_up"):
        with pytest.raises(ScopeError) as err:
            policy.assert_check_allowed(check)
        assert err.value.code == CHECK_NOT_ALLOWED


@pytest.mark.parametrize("check", sorted(set(ALL_CHECKS) - {"dns", "rdap"}))
def test_active_checks_need_active_scanning(check):
    policy = make_policy(active=False)
    with pytest.raises(ScopeError) as err:
        policy.assert_check_allowed(check)
    assert err.value.code == ACTIVE_SCANNING_DISABLED
    assert make_policy(active=True).assert_check_allowed(check) in ("web", "network")


def test_passive_checks_allowed_without_active_scanning():
    policy = make_policy(active=False)
    assert policy.assert_check_allowed("dns") == "passive"
    assert policy.assert_check_allowed("rdap") == "passive"


@pytest.mark.parametrize("value", [1, "true", "yes"])
def test_active_flag_must_be_exactly_true(value):
    policy = ScopePolicy(job_id="j", domain="example.com", active_scanning_enabled=value)
    assert policy.active_scanning_enabled is (value is True)


# ------------------------------------------------------------------------------------------------
# parse_address: alternative encodings


@pytest.mark.parametrize(
    "value",
    [
        "017.0.0.1",  # octal-looking octet
        "0177.0.0.1",
        "127.000.000.001",
        "010.0.0.1",
        "0x7f.0.0.1",  # hex octet
        "0x7f000001",  # hex integer
        "0X7F.1",
        "2130706433",  # decimal integer
        "017700000001",  # octal integer
        "127.1",  # short forms
        "10.1",
        "127.0.1",
        "1",
        "127.0.0.1.",  # trailing dot
        ".127.0.0.1",
        "127.0.0.1/32",
        "127.0.0.256",
        "256.0.0.1",
        "1.2.3.4.5",
        "127.0.0.-1",
        "+127.0.0.1",
        "127.0.0.1 ",  # whitespace
        " 127.0.0.1",
        "127.0.0.1\n",
        "127.0.0.1\t",
        "127.0.0.1\x00",  # embedded NUL
        "127.0.0.1\x00.evil",
        "127.0.0.1:80",
        "\u0661\u0662\u0667.0.0.1",  # non-ASCII (Arabic-Indic) digits
        "\uff11\uff12\uff17.0.0.1",  # fullwidth digits
        "fe80::1%eth0",  # zone ids
        "fe80::1%1",
        "::1%lo",
        "[::1]",  # brackets
        "[2606:4700:4700::1111]",
        "::1 ",
        "::1\x00",
        "::ffff:017.0.0.1",  # leading zero in embedded IPv4
        "::ffff:127.1",
        "::ffff:0x7f.0.0.1",
        "2001:db8::/32",
        "1:2:3:4:5:6:7:8:9",
        "2001:db8:::1",
        "gggg::1",
        "",
        "localhost",
        "a" * 100,
    ],
)
def test_parse_address_rejects_non_canonical(value):
    with pytest.raises(ScopeError) as err:
        parse_address(value)
    assert err.value.code == PROHIBITED_ADDRESS


@pytest.mark.parametrize("value", [None, 2130706433, b"127.0.0.1"])
def test_parse_address_rejects_non_strings(value):
    with pytest.raises(ScopeError):
        parse_address(value)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("93.184.216.34", "93.184.216.34"),
        ("0.0.0.0", "0.0.0.0"),  # noqa: S104
        ("255.255.255.255", "255.255.255.255"),
        ("2606:4700:4700::1111", "2606:4700:4700::1111"),
        ("2606:4700:4700:0:0:0:0:1111", "2606:4700:4700::1111"),
        ("2606:4700:4700::1111".upper(), "2606:4700:4700::1111"),
        ("::ffff:127.0.0.1", "::ffff:7f00:1"),
        ("::ffff:7f00:1", "::ffff:7f00:1"),
    ],
)
def test_parse_address_accepts_canonical(value, expected):
    assert str(parse_address(value)) == expected


# ------------------------------------------------------------------------------------------------
# address_prohibited_reason: every range, both edges


PROHIBITED_V4 = [
    ("0.0.0.0/8", "unspecified"),
    ("10.0.0.0/8", "private"),
    ("100.64.0.0/10", "cgnat"),
    ("127.0.0.0/8", "loopback"),
    ("169.254.0.0/16", "link_local"),
    ("172.16.0.0/12", "private"),
    ("192.0.0.0/24", "reserved"),
    ("192.0.2.0/24", "documentation"),
    ("192.88.99.0/24", "6to4"),
    ("192.168.0.0/16", "private"),
    ("198.18.0.0/15", "benchmarking"),
    ("198.51.100.0/24", "documentation"),
    ("203.0.113.0/24", "documentation"),
    ("224.0.0.0/4", "multicast"),
    ("240.0.0.0/5", "reserved"),
    ("255.255.255.255/32", "broadcast"),
]

PROHIBITED_V6 = [
    ("::/128", "unspecified"),
    ("::1/128", "loopback"),
    ("::ffff:0:0/96", "ipv4_mapped"),
    ("::ffff:0:0:0/96", "ipv4_mapped"),
    ("::2/127", "ipv4_compatible"),
    ("::0.0.1.0/120", "ipv4_compatible"),
    ("::1.0.0.0/104", "ipv4_compatible"),
    ("64:ff9b::/96", "nat64"),
    ("64:ff9b:1::/48", "nat64"),
    ("100::/64", "discard"),
    ("2001::/32", "teredo"),
    ("2001:2::/48", "benchmarking"),
    ("2001:10::/28", "reserved"),
    ("2001:20::/28", "reserved"),
    ("2001:100::/24", "reserved"),
    ("2001:db8::/32", "documentation"),
    ("3fff::/20", "documentation"),
    ("2002::/16", "6to4"),
    ("fc00::/7", "ula"),
    ("fe80::/10", "link_local"),
    ("fec0::/10", "site_local"),
    ("ff00::/8", "multicast"),
    ("4000::/2", "reserved"),
    ("8000::/2", "reserved"),
    ("c000::/3", "reserved"),
    ("1000::/4", "reserved"),
    ("200::/7", "reserved"),
]


@pytest.mark.parametrize(("cidr", "reason"), PROHIBITED_V4 + PROHIBITED_V6)
def test_prohibited_ranges_both_edges(cidr, reason):
    network = ipaddress.ip_network(cidr)
    for address in (network[0], network[-1], network[network.num_addresses // 2]):
        assert address_prohibited_reason(address) == reason, (cidr, str(address))


@pytest.mark.parametrize(
    ("address", "reason"),
    [
        ("::ffff:127.0.0.1", "ipv4_mapped"),
        ("::ffff:7f00:1", "ipv4_mapped"),
        ("::ffff:10.0.0.1", "ipv4_mapped"),
        ("::ffff:8.8.8.8", "ipv4_mapped"),  # even public IPv4 is never reached via a mapped form
        ("::127.0.0.1", "ipv4_compatible"),
        ("::10.0.0.1", "ipv4_compatible"),
        ("::8.8.8.8", "ipv4_compatible"),
        ("64:ff9b::10.0.0.1", "nat64"),
        ("64:ff9b::a00:1", "nat64"),
        ("64:ff9b::127.0.0.1", "nat64"),
        ("64:ff9b::8.8.8.8", "nat64"),
        ("64:ff9b:1::10.0.0.1", "nat64"),
        ("2002:c0a8:101::1", "6to4"),  # embeds 192.168.1.1
        ("2002:7f00:1::1", "6to4"),  # embeds 127.0.0.1
        ("2002:a00:1::", "6to4"),  # embeds 10.0.0.1
        ("2002:808:808::1", "6to4"),  # embeds public 8.8.8.8: still refused
        ("2001:0:4136:e378:8000:63bf:3fff:fdd2", "teredo"),
        ("2001:0:0:0:0:0:f5ff:fffe", "teredo"),  # Teredo with obfuscated 10.0.0.1 client
        ("fe80::1", "link_local"),
        ("fd00::1", "ula"),
        ("fc00::1", "ula"),
        ("ff02::1", "multicast"),
        ("::", "unspecified"),
        ("::1", "loopback"),
    ],
)
def test_ipv6_transition_and_embedded_forms(address, reason):
    assert address_prohibited_reason(parse_address(address)) == reason


@pytest.mark.parametrize(
    "address",
    [
        "1.0.0.0",
        "8.8.8.8",
        "9.255.255.255",  # just below 10/8
        "11.0.0.0",  # just above 10/8
        "100.63.255.255",  # just below CGNAT
        "100.128.0.0",  # just above CGNAT
        "126.255.255.255",
        "128.0.0.0",
        "169.253.255.255",
        "169.255.0.0",
        "172.15.255.255",
        "172.32.0.0",
        "192.0.1.255",
        "192.0.3.0",
        "192.167.255.255",
        "192.169.0.0",
        "198.17.255.255",
        "198.20.0.0",
        "198.51.99.255",
        "198.51.101.0",
        "203.0.112.255",
        "203.0.114.0",
        "223.255.255.255",  # just below multicast
        PUBLIC_V4,
        PUBLIC_V6,
        "2001:4860:4860::8888",
        "2001:200::1",  # just above 2001::/23
        "2001:db7:ffff:ffff:ffff:ffff:ffff:ffff",  # just below documentation
        "2001:db9::",  # just above documentation
        "2003::1",  # just above 6to4
        "2a00:1450:4001::1",
    ],
)
def test_public_unicast_is_allowed(address):
    assert address_prohibited_reason(parse_address(address)) is None


def test_scoped_ipv6_object_is_refused():
    assert address_prohibited_reason(ipaddress.IPv6Address("2606:4700:4700::1111%eth0")) == (
        "reserved"
    )


def test_non_address_is_refused():
    assert address_prohibited_reason("8.8.8.8") == "reserved"  # type: ignore[arg-type]


# ------------------------------------------------------------------------------------------------
# parse_network


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("203.0.113.0/24", "203.0.113.0/24"),
        ("8.8.8.8", "8.8.8.8/32"),
        ("2001:db8::/32", "2001:db8::/32"),
        ("0.0.0.0/0", "0.0.0.0/0"),
    ],
)
def test_parse_network_valid(value, expected):
    assert str(parse_network(value)) == expected


@pytest.mark.parametrize(
    "value",
    [
        "203.0.113.1/24",  # host bits set
        "203.0.113.0/33",
        "203.0.113.0/024",
        "203.0.113.0/",
        "203.0.113.0/-1",
        "203.0.113.0/ 24",
        "0x7f.0.0.0/8",
        "127.1/8",
        "10.0.0.0/255.0.0.0",  # netmask form
        "2001:db8::/129",
        "fe80::%eth0/64",
        "",
        "example.com",
    ],
)
def test_parse_network_strict(value):
    with pytest.raises(ValueError):
        parse_network(value)


# ------------------------------------------------------------------------------------------------
# Hostnames and label boundaries


@pytest.mark.parametrize(
    "host",
    ["example.com", "EXAMPLE.COM", "example.com.", "www.example.com", "a.b.c.example.com"],
)
def test_hostname_within_domain(host):
    assert make_policy().assert_hostname(host) == host.lower().rstrip(".")


@pytest.mark.parametrize(
    "host",
    [
        "evil-example.com",
        "evilexample.com",
        "example.com.evil.net",
        "example.co",
        "xample.com",
        "com",
        "example.com.evil",
        "xn--exmple-cua.com",  # IDN lookalike
        "www.xn--exmple-cua.com",
        "ex\u0430mple.com",  # Cyrillic a
        "www.example.com\x00.evil.net",
        "www.example.com/.evil.net",
        "www.example.com:80",
        "www.example.com@evil.net",
        "*.example.com",
        "a..example.com",
        ".example.com",
        "127.0.0.1",
        "[::1]",
        "",
        "www.example.com evil.net",
    ],
)
def test_hostname_label_boundary_bypasses(host):
    with pytest.raises(ScopeError) as err:
        make_policy().assert_hostname(host)
    assert err.value.code == OUT_OF_SCOPE_HOST


def test_from_job_validates_targets_against_domain_and_snapshot():
    with pytest.raises(ScopeError) as err:
        make_policy(targets=("evil-example.com",))
    assert err.value.code == SCOPE_REJECTED
    with pytest.raises(ScopeError) as err:
        ScopePolicy.from_job(
            job_id="j",
            snapshot=snapshot(targets=["www.example.com"]),
            target_hostnames=["api.example.com"],
            deny_networks=[],
            active_scanning_enabled=True,
        )
    assert err.value.code == SCOPE_REJECTED
    policy = ScopePolicy.from_job(
        job_id="j",
        snapshot=snapshot(targets=["WWW.example.com."]),
        target_hostnames=["www.example.com"],
        deny_networks=[],
        active_scanning_enabled=True,
    )
    assert policy.target_hostnames == ("www.example.com",)
    assert policy.domain == "example.com"


@pytest.mark.parametrize(
    "snap",
    [
        {},
        {"domain": {"fqdn": "example.com"}},
        {"domain": {"fqdn": "not a domain"}, "profile": {"config": {"checks": []}}},
        {"domain": {"fqdn": "example.com"}, "profile": {"config": {"checks": "dns"}}},
    ],
)
def test_from_job_rejects_bad_snapshots(snap):
    with pytest.raises(ScopeError) as err:
        ScopePolicy.from_job(
            job_id="j",
            snapshot=snap,
            target_hostnames=[],
            deny_networks=[],
            active_scanning_enabled=True,
        )
    assert err.value.code == SCOPE_REJECTED


def test_from_job_rejects_malformed_deny_list():
    with pytest.raises(ScopeError) as err:
        make_policy(deny=["10.0.0.1/8"])
    assert err.value.code == SCOPE_REJECTED


def test_from_job_ignores_malformed_and_broad_approved_networks(captured):
    policy = make_policy(
        approved=["198.51.100.7/24", "nonsense", "0.0.0.0/0", "2000::/3", "93.184.216.0/24", 5]
    )
    assert [str(n) for n in policy.approved_networks] == ["93.184.216.0/24"]
    reasons = [r.fields["reason"] for r in captured if r.msg == "approved_network_ignored"]
    assert reasons.count("malformed") == 3
    assert reasons.count("too_broad") == 2


# ------------------------------------------------------------------------------------------------
# assert_destination: tiers, deny list, approved networks


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",  # cloud metadata
        "100.100.100.200",
        "0.0.0.0",  # noqa: S104
        "::1",
        "::ffff:127.0.0.1",
        "::ffff:7f00:1",
        "::ffff:169.254.169.254",
        "64:ff9b::a9fe:a9fe",
        "fd00:ec2::254",
        "fe80::1",
    ],
)
@pytest.mark.parametrize("tier", ["web", "network"])
def test_assert_destination_refuses_prohibited(address, tier):
    policy = make_policy(approved=["0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "fd00::/8"])
    with pytest.raises(AddressRefused) as err:
        policy.assert_destination(address, tier=tier)
    assert err.value.code == PROHIBITED_ADDRESS
    with pytest.raises(AddressRefused):
        policy.assert_destination(parse_address(address), tier=tier)


@pytest.mark.parametrize("address", ["0x7f.0.0.1", "2130706433", "127.1", "fe80::1%eth0", "[::1]"])
def test_assert_destination_refuses_encoded_strings(address):
    with pytest.raises(AddressRefused) as err:
        make_policy().assert_destination(address, tier="web")
    assert err.value.code == PROHIBITED_ADDRESS
    assert err.value.reason == "unparseable"


def test_assert_destination_refuses_non_address_objects():
    with pytest.raises(AddressRefused):
        make_policy().assert_destination(2130706433, tier="web")  # type: ignore[arg-type]


def test_assert_destination_web_tier_allows_public():
    policy = make_policy()
    assert str(policy.assert_destination(PUBLIC_V4, tier="web")) == PUBLIC_V4
    assert str(policy.assert_destination(parse_address(PUBLIC_V6), tier="web")) == PUBLIC_V6


def test_assert_destination_network_tier_requires_approved_network():
    without = make_policy()
    with pytest.raises(AddressRefused) as err:
        without.assert_destination(PUBLIC_V4, tier="network")
    assert err.value.code == NETWORK_NOT_APPROVED
    approved = make_policy(approved=["93.184.216.0/24"])
    assert str(approved.assert_destination(PUBLIC_V4, tier="network")) == PUBLIC_V4
    with pytest.raises(AddressRefused) as err:
        approved.assert_destination(PUBLIC_V4_B, tier="network")
    assert err.value.code == NETWORK_NOT_APPROVED
    # Edges of the approved network.
    approved.assert_destination("93.184.216.0", tier="network")
    approved.assert_destination("93.184.216.255", tier="network")
    with pytest.raises(AddressRefused):
        approved.assert_destination("93.184.217.0", tier="network")
    with pytest.raises(AddressRefused):
        approved.assert_destination("93.184.215.255", tier="network")


def test_approved_network_overlapping_prohibited_never_permits():
    policy = make_policy(approved=["10.0.0.0/8", "192.168.0.0/16", "100.64.0.0/10"])
    for address in ("10.1.2.3", "192.168.1.1", "100.64.0.1"):
        with pytest.raises(AddressRefused) as err:
            policy.assert_destination(address, tier="network")
        assert err.value.code == PROHIBITED_ADDRESS


@pytest.mark.parametrize("tier", ["web", "network"])
def test_deny_list_always_refused(tier):
    policy = make_policy(deny=["93.184.216.0/24", "2606:4700::/32"], approved=["93.184.216.0/24"])
    for address in (PUBLIC_V4, PUBLIC_V6):
        with pytest.raises(AddressRefused) as err:
            policy.assert_destination(address, tier=tier)
        assert err.value.code == PROHIBITED_ADDRESS
        assert err.value.reason == "deny_listed"


def test_assert_destination_refuses_when_active_scanning_disabled():
    policy = make_policy(active=False)
    for tier in ("web", "network"):
        with pytest.raises(ScopeError) as err:
            policy.assert_destination(PUBLIC_V4, tier=tier)
        assert err.value.code == ACTIVE_SCANNING_DISABLED


@pytest.mark.parametrize("tier", ["passive", "bogus"])
def test_passive_tier_never_connects(tier):
    with pytest.raises(ScopeError) as err:
        make_policy().assert_destination(PUBLIC_V4, tier=tier)  # type: ignore[arg-type]
    assert err.value.code == CHECK_NOT_ALLOWED


# ------------------------------------------------------------------------------------------------
# resolve: CNAME chains, mixed answers, network tier


def test_resolve_plain_host():
    resolver = FakeResolver(
        {("www.example.com", "A"): [PUBLIC_V4], ("www.example.com", "AAAA"): [PUBLIC_V6]}
    )
    resolved = make_policy().resolve("WWW.Example.com.", resolver, tier="web", lifetime=2)
    assert resolved.hostname == "www.example.com"
    assert [str(a) for a in resolved.addresses] == [PUBLIC_V4, PUBLIC_V6]
    assert resolved.cname_chain == ()
    assert resolved.dropped == ()


def test_resolve_refuses_out_of_scope_host_without_querying():
    resolver = FakeResolver({})
    with pytest.raises(ScopeError) as err:
        make_policy().resolve("evil-example.com", resolver, tier="web", lifetime=2)
    assert err.value.code == OUT_OF_SCOPE_HOST
    assert resolver.calls == []


def test_resolve_passive_tier_refused():
    with pytest.raises(ScopeError) as err:
        make_policy().resolve("example.com", FakeResolver({}), tier="passive", lifetime=2)
    assert err.value.code == CHECK_NOT_ALLOWED


def test_resolve_mixed_answers_keeps_only_public(captured):
    resolver = FakeResolver(
        {
            ("www.example.com", "A"): ["10.0.0.5", PUBLIC_V4, "127.0.0.1", PUBLIC_V4, "0x7f.1"],
            ("www.example.com", "AAAA"): ["::ffff:10.0.0.5", PUBLIC_V6, "fe80::1", "1.2.3.4"],
        }
    )
    resolved = make_policy().resolve("www.example.com", resolver, tier="web", lifetime=2)
    assert [str(a) for a in resolved.addresses] == [PUBLIC_V4, PUBLIC_V6]
    assert dict(resolved.dropped) == {
        "10.0.0.5": "private",
        "127.0.0.1": "loopback",
        "0x7f.1": "unparseable",
        "::ffff:a00:5": "ipv4_mapped",
        "fe80::1": "link_local",
        "1.2.3.4": "wrong_family",
    }
    decisions = [r.fields for r in captured if r.msg == "scope_decision"]
    refused = [d for d in decisions if not d["allowed"]]
    assert {d["reason"] for d in refused} >= {"private", "loopback", "ipv4_mapped", "link_local"}
    assert all(d["jobId"] == "job-1" and d["tier"] == "web" for d in refused)


def test_resolve_all_private_raises_no_allowed_address():
    resolver = FakeResolver(
        {
            ("www.example.com", "A"): ["10.0.0.5", "192.168.0.1", "169.254.169.254"],
            ("www.example.com", "AAAA"): ["fd00::1"],
        }
    )
    with pytest.raises(ScopeError) as err:
        make_policy().resolve("www.example.com", resolver, tier="web", lifetime=2)
    assert err.value.code == NO_ALLOWED_ADDRESS


def test_resolve_empty_answer_raises_no_allowed_address():
    with pytest.raises(ScopeError) as err:
        make_policy().resolve("www.example.com", FakeResolver({}), tier="web", lifetime=2)
    assert err.value.code == NO_ALLOWED_ADDRESS


def test_resolve_network_tier_filters_to_approved_networks():
    resolver = FakeResolver(
        {("www.example.com", "A"): [PUBLIC_V4, PUBLIC_V4_B], ("www.example.com", "AAAA"): []}
    )
    policy = make_policy(approved=["93.184.216.0/24"])
    resolved = policy.resolve("www.example.com", resolver, tier="network", lifetime=2)
    assert [str(a) for a in resolved.addresses] == [PUBLIC_V4]
    assert resolved.dropped == ((PUBLIC_V4_B, NETWORK_NOT_APPROVED),)
    # Web tier is not limited by approved networks.
    web = policy.resolve("www.example.com", resolver, tier="web", lifetime=2)
    assert len(web.addresses) == 2
    # Network tier without any approved network: nothing allowed.
    with pytest.raises(ScopeError) as err:
        make_policy().resolve("www.example.com", resolver, tier="network", lifetime=2)
    assert err.value.code == NO_ALLOWED_ADDRESS


def test_resolve_deny_listed_dropped():
    resolver = FakeResolver({("www.example.com", "A"): [PUBLIC_V4, PUBLIC_V4_B]})
    policy = make_policy(deny=["93.184.216.34"])
    resolved = policy.resolve("www.example.com", resolver, tier="web", lifetime=2)
    assert [str(a) for a in resolved.addresses] == [PUBLIC_V4_B]
    assert resolved.dropped == ((PUBLIC_V4, "deny_listed"),)


def test_resolve_follows_in_scope_cname_chain():
    resolver = FakeResolver(
        {
            ("www.example.com", "CNAME"): ["edge.example.com."],
            ("edge.example.com", "CNAME"): ["Origin.Example.COM."],
            ("origin.example.com", "A"): [PUBLIC_V4],
        }
    )
    resolved = make_policy().resolve("www.example.com", resolver, tier="web", lifetime=2)
    assert resolved.cname_chain == ("edge.example.com", "origin.example.com")
    assert [str(a) for a in resolved.addresses] == [PUBLIC_V4]
    assert ("origin.example.com", "A") in resolver.calls
    assert ("www.example.com", "A") not in resolver.calls


@pytest.mark.parametrize("escape_at", [1, 2, MAX_CNAME_HOPS])
@pytest.mark.parametrize(
    "outside", ["evil-example.com.", "example.com.evil.net.", "cdn.provider.net.", "com."]
)
def test_resolve_cname_leaving_domain(escape_at, outside):
    records: dict = {}
    name = "www.example.com"
    for i in range(1, escape_at):
        nxt = f"h{i}.example.com"
        records[(name, "CNAME")] = [nxt + "."]
        name = nxt
    records[(name, "CNAME")] = [outside]
    records[(outside.rstrip("."), "A")] = [PUBLIC_V4]
    resolver = FakeResolver(records)
    with pytest.raises(ScopeError) as err:
        make_policy().resolve("www.example.com", resolver, tier="web", lifetime=2)
    assert err.value.code == CNAME_OUT_OF_SCOPE
    assert all(rdtype == "CNAME" for _, rdtype in resolver.calls)


def test_resolve_cname_out_and_back_in_is_refused():
    resolver = FakeResolver(
        {
            ("www.example.com", "CNAME"): ["evil.net."],
            ("evil.net", "CNAME"): ["back.example.com."],
            ("back.example.com", "A"): [PUBLIC_V4],
        }
    )
    with pytest.raises(ScopeError) as err:
        make_policy().resolve("www.example.com", resolver, tier="web", lifetime=2)
    assert err.value.code == CNAME_OUT_OF_SCOPE


@pytest.mark.parametrize("bad", ["*.example.com.", "-bad.example.com.", "a b.example.com."])
def test_resolve_invalid_cname_target(bad):
    resolver = FakeResolver({("www.example.com", "CNAME"): [bad]})
    with pytest.raises(ScopeError) as err:
        make_policy().resolve("www.example.com", resolver, tier="web", lifetime=2)
    assert err.value.code == CNAME_OUT_OF_SCOPE


def test_resolve_cname_loop():
    resolver = FakeResolver(
        {
            ("www.example.com", "CNAME"): ["a.example.com."],
            ("a.example.com", "CNAME"): ["b.example.com."],
            ("b.example.com", "CNAME"): ["www.example.com."],
        }
    )
    with pytest.raises(ScopeError) as err:
        make_policy().resolve("www.example.com", resolver, tier="web", lifetime=2)
    assert err.value.code == CNAME_CHAIN_INVALID


def test_resolve_self_cname_loop():
    resolver = FakeResolver({("www.example.com", "CNAME"): ["www.example.com."]})
    with pytest.raises(ScopeError) as err:
        make_policy().resolve("www.example.com", resolver, tier="web", lifetime=2)
    assert err.value.code == CNAME_CHAIN_INVALID


def test_resolve_cname_chain_cap():
    def chain(length: int) -> FakeResolver:
        records: dict = {}
        for i in range(length):
            records[(f"h{i}.example.com", "CNAME")] = [f"h{i + 1}.example.com."]
        records[(f"h{length}.example.com", "A")] = [PUBLIC_V4]
        return FakeResolver(records)

    ok = make_policy().resolve("h0.example.com", chain(MAX_CNAME_HOPS), tier="web", lifetime=2)
    assert len(ok.cname_chain) == MAX_CNAME_HOPS
    with pytest.raises(ScopeError) as err:
        make_policy().resolve("h0.example.com", chain(MAX_CNAME_HOPS + 1), tier="web", lifetime=2)
    assert err.value.code == CNAME_CHAIN_INVALID


def test_resolve_multiple_cnames_refused():
    resolver = FakeResolver({("www.example.com", "CNAME"): ["a.example.com.", "b.example.com."]})
    with pytest.raises(ScopeError) as err:
        make_policy().resolve("www.example.com", resolver, tier="web", lifetime=2)
    assert err.value.code == CNAME_CHAIN_INVALID


def test_resolve_chain_changed_between_queries_refused():
    class Changing(FakeResolver):
        def query(self, name, rdtype, lifetime):
            self.calls.append((name, rdtype))
            if rdtype == "CNAME":
                return DnsAnswer(ttl=60, values=[], canonical_name=name)
            # A CNAME appeared after the walk: the A answer comes from elsewhere.
            return DnsAnswer(ttl=60, values=[PUBLIC_V4], canonical_name="attacker.net")

    with pytest.raises(ScopeError) as err:
        make_policy().resolve("www.example.com", Changing({}), tier="web", lifetime=2)
    assert err.value.code == CNAME_CHAIN_INVALID


@pytest.mark.parametrize(
    "exc", [dns.resolver.NXDOMAIN(), dns.exception.Timeout(), dns.resolver.NoNameservers()]
)
def test_resolve_propagates_dns_errors(exc):
    resolver = FakeResolver({("www.example.com", "A"): exc})
    with pytest.raises(type(exc)):
        make_policy().resolve("www.example.com", resolver, tier="web", lifetime=2)


def test_resolve_passes_lifetime():
    seen: list[float] = []

    class Recording(FakeResolver):
        def query(self, name, rdtype, lifetime):
            seen.append(lifetime)
            return super().query(name, rdtype, lifetime)

    make_policy().resolve(
        "example.com", Recording({("example.com", "A"): [PUBLIC_V4]}), tier="web", lifetime=1.5
    )
    assert seen and all(value == 1.5 for value in seen)


def test_rebinding_resolve_then_assert_destination():
    """A resolver that flips public -> private: the second resolution yields nothing allowed and the
    private address is refused by assert_destination even when passed directly."""

    class Flipping(FakeResolver):
        def __init__(self):
            super().__init__({})
            self.count = 0

        def query(self, name, rdtype, lifetime):
            if rdtype == "A":
                self.count += 1
                value = PUBLIC_V4 if self.count == 1 else "127.0.0.1"
                return DnsAnswer(ttl=0, values=[value], canonical_name=name)
            return DnsAnswer(ttl=0, values=[], canonical_name=name)

    policy = make_policy()
    resolver = Flipping()
    first = policy.resolve("www.example.com", resolver, tier="web", lifetime=2)
    assert [str(a) for a in first.addresses] == [PUBLIC_V4]
    with pytest.raises(ScopeError) as err:
        policy.resolve("www.example.com", resolver, tier="web", lifetime=2)
    assert err.value.code == NO_ALLOWED_ADDRESS
    with pytest.raises(AddressRefused):
        policy.assert_destination("127.0.0.1", tier="web")


# ------------------------------------------------------------------------------------------------
# Logging


def test_every_decision_is_logged_as_structured_json(capsys):
    from app.logging_config import configure_logging

    configure_logging("INFO")
    policy = make_policy()
    policy.assert_destination(PUBLIC_V4, tier="web")
    with pytest.raises(ScopeError):
        policy.assert_destination("10.0.0.1", tier="web")
    with pytest.raises(ScopeError):
        policy.assert_hostname("evil-example.com")
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line]
    decisions = [line for line in lines if line["message"] == "scope_decision"]
    assert len(decisions) == 3
    assert decisions[0] | {"ts": None} == {
        "ts": None,
        "level": "INFO",
        "logger": "exdv.policy",
        "message": "scope_decision",
        "jobId": "job-1",
        "subject": f"dest:{PUBLIC_V4}",
        "tier": "web",
        "allowed": True,
        "reason": "allowed",
    }
    assert decisions[1]["allowed"] is False and decisions[1]["reason"] == "private"
    assert decisions[2]["reason"] == OUT_OF_SCOPE_HOST


def test_no_flag_permits_loopback():
    """Production code has no switch that allows prohibited addresses."""
    import inspect

    source = inspect.getsource(policy_module)
    for word in ("allow_loopback", "allow_private", "EXDV_ALLOW", "os.environ", "getenv"):
        assert word not in source
