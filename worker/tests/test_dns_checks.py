import dns.exception
import dns.resolver
import pytest

from app.checks import CheckContext, CheckStopped, RateLimiter, TargetTimeout
from app.dns_checks import DnsAnswer, check_dns, normalise_values, query_to_observation

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
    ]
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
