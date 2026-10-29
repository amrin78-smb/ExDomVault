import dns.exception
import dns.resolver
import pytest

from app.checks import CheckContext, CheckStopped, RateLimiter, TargetTimeout
from app.dns_checks import (
    DKIM_SELECTORS,
    DnsAnswer,
    check_dns,
    normalise_values,
    planned_queries,
    query_to_observation,
    receives_mail,
)

TARGET = "3a1d4c1e-6b7f-4f4e-9d2e-8a9b0c1d2e3f"


class FakeResolver:
    """Answers from a table keyed by (name, type); values may be exceptions."""

    def __init__(self, table=None, default=None):
        self.table = table or {}
        self.default = default
        self.queries: list[tuple[str, str, float]] = []

    def query(self, name, rdtype, lifetime):
        self.queries.append((name, rdtype, lifetime))
        result = self.table.get((name, rdtype), self.default)
        if result is None:
            raise dns.resolver.NoAnswer
        if isinstance(result, BaseException) or (
            isinstance(result, type) and issubclass(result, BaseException)
        ):
            raise result
        return result


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def ctx(clock=None, deadline=60.0, should_stop=lambda: False, rate=50.0):
    clock = clock or FakeClock()
    return CheckContext(
        deadline=clock() + deadline,
        connect_seconds=3.0,
        read_seconds=5.0,
        rate_limiter=RateLimiter(rate, monotonic=clock, sleep=clock.sleep),
        should_stop=should_stop,
        monotonic=clock,
    )


def test_success_values_sorted_and_hostname_normalised():
    resolver = FakeResolver(
        {
            ("example.com", "MX"): DnsAnswer(
                300, ["20 Mail2.Example.com.", "10 MAIL.example.com.", "10 MAIL.example.com."],
                "example.com",
            ),
        }
    )  # fmt: skip
    obs = query_to_observation(resolver, TARGET, "example.com", "MX", 5.0)
    assert obs["kind"] == "dns"
    assert obs["resultStatus"] == "success"
    assert obs["hostname"] == "example.com"
    assert obs["values"] == ["10 mail.example.com.", "20 mail2.example.com."]
    assert obs["ttl"] == 300
    assert obs["evidence"] == {"rcode": "NOERROR"}
    assert obs["observedAt"].endswith("Z")


def test_txt_case_is_preserved_and_null_mx_kept():
    assert normalise_values("TXT", ['"v=spf1 Include:X -all"']) == (
        ['"v=spf1 Include:X -all"'],
        False,
    )
    assert normalise_values("MX", ["0 ."]) == (["0 ."], False)


def test_cname_chain_recorded_as_canonical_name():
    resolver = FakeResolver(
        {
            ("www.example.com", "A"): DnsAnswer(
                60, ["192.0.2.2", "192.0.2.1"], "edge.cdn.example.net"
            )
        }
    )
    obs = query_to_observation(resolver, TARGET, "www.example.com", "A", 5.0)
    assert obs["values"] == ["192.0.2.1", "192.0.2.2"]
    assert obs["evidence"]["canonicalName"] == "edge.cdn.example.net"


def test_nxdomain_is_success_with_empty_values():
    resolver = FakeResolver(default=dns.resolver.NXDOMAIN)
    obs = query_to_observation(resolver, TARGET, "gone.example.com", "A", 5.0)
    assert obs["resultStatus"] == "success"
    assert obs["values"] == []
    assert obs["ttl"] is None
    assert obs["evidence"] == {"rcode": "NXDOMAIN"}


@pytest.mark.parametrize(
    "answer", [None, DnsAnswer(None, [], "example.com")], ids=["NoAnswer", "empty"]
)
def test_nodata_is_success_with_empty_values(answer):
    resolver = FakeResolver({("example.com", "CAA"): answer})
    obs = query_to_observation(resolver, TARGET, "example.com", "CAA", 5.0)
    assert obs["resultStatus"] == "success"
    assert obs["values"] == []
    assert obs["ttl"] is None
    assert obs["evidence"]["rcode"] == "NOERROR"
    assert obs["evidence"]["noData"] is True


def test_timeout_and_errors():
    resolver = FakeResolver(
        {
            ("example.com", "A"): dns.resolver.LifetimeTimeout(timeout=5.0, errors=[]),
            ("example.com", "AAAA"): dns.resolver.NoNameservers(),
            ("example.com", "TXT"): RuntimeError("secret detail 10.0.0.1"),
        }
    )
    t = query_to_observation(resolver, TARGET, "example.com", "A", 5.0)
    assert t["resultStatus"] == "timeout"
    assert t["evidence"] == {"error": "LifetimeTimeout"}
    e = query_to_observation(resolver, TARGET, "example.com", "AAAA", 5.0)
    assert e["resultStatus"] == "error"
    assert e["evidence"] == {"error": "NoNameservers"}
    r = query_to_observation(resolver, TARGET, "example.com", "TXT", 5.0)
    assert r["evidence"] == {"error": "RuntimeError"}
    assert "10.0.0.1" not in str(r)


def test_values_are_capped():
    values, truncated = normalise_values("TXT", [f'"{i:04d}"' for i in range(150)])
    assert len(values) == 100
    assert truncated
    resolver = FakeResolver({("example.com", "TXT"): DnsAnswer(60, ["x" * 5000], "example.com")})
    obs = query_to_observation(resolver, TARGET, "example.com", "TXT", 5.0)
    assert obs["resultStatus"] == "partial"
    assert len(obs["values"][0]) == 4096
    assert obs["evidence"]["truncated"] is True


def test_apex_plan_and_subdomain_plan():
    resolver = FakeResolver(default=DnsAnswer(60, ["192.0.2.1"], None))
    out: list[dict] = []
    check_dns(resolver, TARGET, "example.com", True, ctx(), out.append)
    assert [(o["hostname"], o["recordType"]) for o in out] == [
        ("example.com", "A"),
        ("example.com", "AAAA"),
        ("example.com", "CNAME"),
        ("example.com", "MX"),
        ("example.com", "NS"),
        ("example.com", "TXT"),
        ("example.com", "CAA"),
        ("example.com", "SOA"),
        ("example.com", "DS"),
        ("example.com", "DNSKEY"),
        ("_dmarc.example.com", "TXT"),
        *[(f"{sel}._domainkey.example.com", "TXT") for sel in DKIM_SELECTORS],
    ]  # the default answer is not a valid MX, so no receiving-side mail names
    out.clear()
    check_dns(resolver, TARGET, "www.example.com", False, ctx(), out.append)
    assert [o["recordType"] for o in out] == ["A", "AAAA", "CNAME"]


def test_rate_limit_spaces_queries():
    clock = FakeClock()
    resolver = FakeResolver(default=DnsAnswer(60, ["192.0.2.1"], None))
    out: list[dict] = []
    start = clock()
    check_dns(resolver, TARGET, "www.example.com", False, ctx(clock, rate=2.0), out.append)
    assert clock() - start == pytest.approx(1.0)  # 3 queries at 2/s: slots at 0, 0.5, 1.0


def test_deadline_raises_target_timeout_and_caps_lifetime():
    clock = FakeClock()

    class SlowResolver(FakeResolver):
        def query(self, name, rdtype, lifetime):
            clock.now += 4.0
            return super().query(name, rdtype, lifetime)

    resolver = SlowResolver(default=DnsAnswer(60, ["192.0.2.1"], None))
    out: list[dict] = []
    with pytest.raises(TargetTimeout):
        check_dns(resolver, TARGET, "example.com", True, ctx(clock, deadline=6.0), out.append)
    assert len(out) == 2
    assert resolver.queries[0][2] == 5.0
    assert resolver.queries[1][2] == pytest.approx(2.0)


def test_stop_signal_interrupts():
    resolver = FakeResolver(default=DnsAnswer(60, ["192.0.2.1"], None))
    with pytest.raises(CheckStopped):
        check_dns(resolver, TARGET, "example.com", True, ctx(should_stop=lambda: True), [].append)
    assert resolver.queries == []


def test_dnspython_resolver_uses_configured_nameservers_without_network():
    from app.dns_checks import DnspythonResolver

    r = DnspythonResolver(("192.0.2.53",), timeout=2.0)
    assert r._resolver.nameservers == ["192.0.2.53"]
    assert r._resolver.timeout == 2.0
    assert r._resolver.cache is None
    assert dns.exception.Timeout  # imported for type mapping


# -- Milestone 15: e-mail security names and takeover evidence ----------------------------------

MAIL_NAMES = [
    ("_mta-sts.example.com", "TXT"),
    ("_smtp._tls.example.com", "TXT"),
    ("default._bimi.example.com", "TXT"),
]


def run_apex(table):
    resolver = FakeResolver(table)
    out: list[dict] = []
    check_dns(resolver, TARGET, "example.com", True, ctx(), out.append)
    return resolver, out


def test_mail_names_are_queried_only_when_mx_lists_a_real_exchanger():
    resolver, out = run_apex(
        {("example.com", "MX"): DnsAnswer(300, ["10 mx1.example.com."], "example.com")}
    )
    queried = [(q[0], q[1]) for q in resolver.queries]
    assert queried[-3:] == MAIL_NAMES
    assert queried == planned_queries("example.com", True, receives_mail=True)
    assert [(o["hostname"], o["recordType"]) for o in out] == queried


@pytest.mark.parametrize(
    "mx",
    [
        DnsAnswer(300, ["0 ."], "example.com"),  # null MX (RFC 7505): no mail
        None,  # NODATA
        dns.resolver.NXDOMAIN,
        dns.exception.Timeout,  # unknown: do not guess
    ],
)
def test_no_mail_names_without_a_real_mx(mx):
    resolver, _out = run_apex({("example.com", "MX"): mx})
    queried = {(q[0], q[1]) for q in resolver.queries}
    assert not queried & set(MAIL_NAMES)
    # DKIM selectors are always queried at the apex (sending does not require an MX).
    assert ("google._domainkey.example.com", "TXT") in queried
    assert ("selector1._domainkey.example.com", "TXT") in queried


def test_subdomains_get_no_mail_or_dkim_queries():
    assert planned_queries("www.example.com", False, receives_mail=True) == [
        ("www.example.com", "A"),
        ("www.example.com", "AAAA"),
        ("www.example.com", "CNAME"),
    ]


def test_receives_mail():
    ok = {"resultStatus": "success", "values": ["10 mx.example.com."]}
    assert receives_mail(ok)
    assert not receives_mail({"resultStatus": "success", "values": ["0 ."]})
    assert not receives_mail({"resultStatus": "success", "values": []})
    assert not receives_mail({"resultStatus": "timeout", "values": []})
    assert not receives_mail({"resultStatus": "success", "values": ["garbage"]})
    assert not receives_mail(None)


def test_dkim_selector_names_pass_the_observation_contract():
    import re

    label = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
    for sel in DKIM_SELECTORS:
        assert label.match(sel), sel


def test_dkim_cname_delegation_is_followed_and_recorded():
    name = "selector1._domainkey.example.com"
    target = "selector1-example-com._domainkey.tenant.onmicrosoft.test"
    resolver = FakeResolver(
        {(name, "TXT"): DnsAnswer(3600, ['"v=DKIM1; k=rsa; p=MIIBIjAN"'], target)}
    )
    obs = query_to_observation(resolver, TARGET, name, "TXT", 5.0)
    assert obs["hostname"] == name
    assert obs["values"] == ['"v=DKIM1; k=rsa; p=MIIBIjAN"']
    assert obs["evidence"] == {"rcode": "NOERROR", "canonicalName": target}


def nxdomain_via_cname(qname: str, target: str) -> dns.resolver.NXDOMAIN:
    """A dnspython NXDOMAIN as the stub resolver raises it for qname -> CNAME target -> NXDOMAIN."""
    import dns.message
    import dns.name
    import dns.rcode
    import dns.rdata
    import dns.rdataclass
    import dns.rdatatype

    q = dns.name.from_text(qname)
    response = dns.message.make_response(dns.message.make_query(q, "A"))
    response.set_rcode(dns.rcode.NXDOMAIN)
    rrset = response.find_rrset(
        response.answer, q, dns.rdataclass.IN, dns.rdatatype.CNAME, create=True
    )
    rrset.add(dns.rdata.from_text("IN", "CNAME", target + "."), 300)
    return dns.resolver.NXDOMAIN(qnames=[q], responses={q: response})


def test_nxdomain_records_the_chain_end_as_canonical_name():
    host = "shop.example.com"
    exc = nxdomain_via_cname(host, "Old-Shop.AzureWebsites.net")
    resolver = FakeResolver({(host, "A"): exc})
    obs = query_to_observation(resolver, TARGET, host, "A", 5.0)
    assert obs["resultStatus"] == "success"
    assert obs["values"] == []
    assert obs["evidence"] == {"rcode": "NXDOMAIN", "canonicalName": "old-shop.azurewebsites.net"}


def test_nxdomain_without_a_chain_has_no_canonical_name():
    host = "gone.example.com"
    import dns.message
    import dns.name
    import dns.rcode

    q = dns.name.from_text(host)
    response = dns.message.make_response(dns.message.make_query(q, "A"))
    response.set_rcode(dns.rcode.NXDOMAIN)
    plain = dns.resolver.NXDOMAIN(qnames=[q], responses={q: response})
    for exc in (plain, dns.resolver.NXDOMAIN()):  # unparametrised: canonical_name raises
        obs = query_to_observation(FakeResolver({(host, "A"): exc}), TARGET, host, "A", 5.0)
        assert obs["evidence"] == {"rcode": "NXDOMAIN"}
