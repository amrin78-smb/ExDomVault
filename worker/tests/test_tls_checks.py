"""TLS certificate check: certificate parsing, RFC 6125 matching and observation building.

No network: ScopePolicy and net.tls_handshake are faked; certificates are generated in-test.
Also hosts the shared fakes and schema mirrors used by the HTTP/port/queue tests.
"""

import hashlib
import ipaddress
import json
import re
import time
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app import net, tls_checks
from app.checks import CheckContext, CheckFailed
from app.policy import ResolvedHost
from app.scope import ScopeError

TARGET_ID = "11111111-1111-4111-8111-111111111111"
ISO_Z = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$")
COMMON = {"kind", "targetId", "observedAt", "checkerVersion", "resultStatus", "evidence"}


# -- shared fakes -------------------------------------------------------------------------------


class NoLimit:
    def acquire(self, should_stop=lambda: False):
        return None


def make_ctx(remaining=1000.0, should_stop=lambda: False):
    return CheckContext(
        deadline=remaining,
        connect_seconds=5.0,
        read_seconds=10.0,
        rate_limiter=NoLimit(),
        should_stop=should_stop,
        monotonic=lambda: 0.0,
    )


class FakePolicy:
    """Stands in for app.policy.ScopePolicy. ``addresses`` maps tier -> hostname -> addresses (or
    a ScopeError code to raise); ``refuse`` lists addresses assert_destination refuses."""

    def __init__(self, addresses=None, refuse=(), denied_checks=()):
        self.addresses = addresses or {}
        self.refuse = set(refuse)
        self.denied_checks = dict.fromkeys(denied_checks, "check_not_allowed")
        self.calls = []

    def resolve(self, hostname, resolver, *, tier, lifetime):
        self.calls.append(("resolve", hostname, tier))
        value = self.addresses.get(tier, {}).get(hostname, "no_allowed_address")
        if isinstance(value, str):
            raise ScopeError(value, "refused by fake policy")
        return ResolvedHost(
            hostname=hostname,
            addresses=tuple(ipaddress.ip_address(a) for a in value),
            cname_chain=(),
            dropped=(),
        )

    def assert_destination(self, address, *, tier):
        ip = ipaddress.ip_address(str(address))
        self.calls.append(("assert_destination", str(ip), tier))
        if str(ip) in self.refuse:
            raise ScopeError("prohibited_address", "refused by fake policy")
        return ip

    def assert_check_allowed(self, check):
        self.calls.append(("assert_check_allowed", check))
        if check in self.denied_checks:
            raise ScopeError(self.denied_checks[check], "refused by fake policy")
        return "web"

    def assert_hostname(self, hostname):
        return hostname


# -- schema mirrors (packages/shared/src/api/observations.ts) ----------------------------------


def _ip(value):
    ip = ipaddress.ip_address(value)
    assert str(ip) == value  # canonical text
    return ip


def assert_common(o):
    assert re.fullmatch(r"[0-9a-f-]{36}", o["targetId"])
    assert ISO_Z.match(o["observedAt"])
    assert re.fullmatch(r"[0-9A-Za-z.+-]{1,40}", o["checkerVersion"])
    assert o["resultStatus"] in {"success", "partial", "error", "timeout", "skipped"}
    assert isinstance(o["evidence"], dict)
    assert all(isinstance(k, str) and len(k) <= 64 for k in o["evidence"])
    assert len(json.dumps(o["evidence"], separators=(",", ":"))) <= 16384


def assert_tls_schema(o):
    assert set(o) == COMMON | {
        "hostname", "ipAddress", "port", "protocolVersion", "notBefore", "notAfter", "issuer",
        "subject", "subjectAltNames", "fingerprintSha256", "hostnameMatches",
    }  # fmt: skip
    assert o["kind"] == "tls"
    assert_common(o)
    assert re.fullmatch(r"[a-z0-9_.-]{1,253}", o["hostname"])
    _ip(o["ipAddress"])
    assert isinstance(o["port"], int) and 1 <= o["port"] <= 65535
    assert o["protocolVersion"] is None or len(o["protocolVersion"]) <= 20
    for key in ("notBefore", "notAfter"):
        assert o[key] is None or ISO_Z.match(o[key])
    for key in ("issuer", "subject"):
        assert o[key] is None or len(o[key]) <= 1000
    assert len(o["subjectAltNames"]) <= 200 and all(len(s) <= 253 for s in o["subjectAltNames"])
    assert o["fingerprintSha256"] is None or re.fullmatch(r"[0-9a-f]{64}", o["fingerprintSha256"])
    assert o["hostnameMatches"] in (True, False, None)


def assert_http_schema(o):
    assert set(o) == COMMON | {
        "url", "ipAddress", "statusCode", "finalUrl", "redirectCount", "hstsEnabled",
    }  # fmt: skip
    assert o["kind"] == "http"
    assert_common(o)
    assert len(o["url"]) <= 2048
    _ip(o["ipAddress"])
    assert o["statusCode"] is None or 100 <= o["statusCode"] <= 599
    assert o["finalUrl"] is None or len(o["finalUrl"]) <= 2048
    assert isinstance(o["redirectCount"], int) and 0 <= o["redirectCount"] <= 10
    assert o["hstsEnabled"] in (True, False, None)


def assert_port_schema(o):
    assert set(o) == COMMON | {"ipAddress", "port", "protocol", "state", "service"}
    assert o["kind"] == "port"
    assert_common(o)
    _ip(o["ipAddress"])
    assert isinstance(o["port"], int) and 1 <= o["port"] <= 65535
    assert o["protocol"] == "tcp"
    assert o["state"] in {"open", "closed", "filtered"}
    assert o["service"] is None or len(o["service"]) <= 100


# -- certificates -------------------------------------------------------------------------------

NOW = datetime.now(UTC).replace(microsecond=0)


def make_cert(
    *,
    sans=("www.example.com",),
    cn="www.example.com",
    not_before=None,
    not_after=None,
):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Test CA R1"),
        ]
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or NOW - timedelta(days=10))
        .not_valid_after(not_after or NOW + timedelta(days=80))
    )
    if sans is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False
        )
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


def tls_result(der, *, address="203.0.113.10", verified=True, error=None, protocol="TLSv1.3"):
    return net.TlsResult(
        address=ipaddress.ip_address(address),
        port=443,
        protocol=protocol,
        certificate_der=der,
        verified=verified,
        verify_error=error,
    )


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


# -- parsing ------------------------------------------------------------------------------------


def test_valid_certificate_observation():
    der = make_cert(sans=("www.example.com", "Example.COM"))
    o = tls_checks.build_tls_observation(
        TARGET_ID, "www.example.com", tls_result(der), ipaddress.ip_address("203.0.113.10")
    )
    assert_tls_schema(o)
    assert o["resultStatus"] == "success"
    assert o["hostname"] == "www.example.com"
    assert o["ipAddress"] == "203.0.113.10"
    assert o["port"] == 443
    assert o["protocolVersion"] == "TLSv1.3"
    assert o["notBefore"] == iso(NOW - timedelta(days=10))
    assert o["notAfter"] == iso(NOW + timedelta(days=80))
    assert o["issuer"] == "CN=Test CA R1,O=Test CA"
    assert o["subject"] == "CN=www.example.com"
    assert o["subjectAltNames"] == ["www.example.com", "example.com"]
    assert o["fingerprintSha256"] == hashlib.sha256(der).hexdigest()
    assert o["hostnameMatches"] is True
    assert o["evidence"] == {"trusted": True}  # no chainLength: net exposes only the leaf


def test_expired_untrusted_certificate_is_still_evidence():
    der = make_cert(not_before=NOW - timedelta(days=400), not_after=NOW - timedelta(days=5))
    result = tls_result(der, verified=False, error="certificate has expired")
    o = tls_checks.build_tls_observation(TARGET_ID, "www.example.com", result, result.address)
    assert_tls_schema(o)
    assert o["resultStatus"] == "success"
    assert o["notAfter"] == iso(NOW - timedelta(days=5))
    assert o["evidence"] == {"trusted": False, "verifyError": "certificate has expired"}


def test_wrong_hostname_certificate():
    der = make_cert(sans=("other.example.net",), cn="other.example.net")
    o = tls_checks.build_tls_observation(
        TARGET_ID, "www.example.com", tls_result(der, verified=False, error="Hostname mismatch"),
        ipaddress.ip_address("203.0.113.10"),
    )  # fmt: skip
    assert o["hostnameMatches"] is False
    assert o["evidence"]["trusted"] is False


def test_san_less_certificate_does_not_fall_back_to_common_name():
    der = make_cert(sans=None, cn="www.example.com")
    o = tls_checks.build_tls_observation(
        TARGET_ID, "www.example.com", tls_result(der), ipaddress.ip_address("203.0.113.10")
    )
    assert_tls_schema(o)
    assert o["subjectAltNames"] == []
    assert o["hostnameMatches"] is False
    assert o["subject"] == "CN=www.example.com"


@pytest.mark.parametrize(
    ("hostname", "sans", "expected"),
    [
        ("www.example.com", ["*.example.com"], True),
        ("WWW.Example.com", ["*.EXAMPLE.com"], True),
        ("example.com", ["*.example.com"], False),
        ("a.b.example.com", ["*.example.com"], False),
        ("www.example.com", ["w*.example.com"], False),
        ("www.example.com", ["*w.example.com"], False),
        ("www.example.com", ["www.*.com"], False),
        ("example.com", ["*.com"], False),
        ("www.example.com", ["*.*.com"], False),
        ("www.example.com", ["*"], False),
        ("www.evil-example.com", ["*.example.com"], False),
        ("www.example.com", ["example.com", "www.example.com"], True),
        ("www.example.com", ["www.example.com."], True),
        ("www.example.com", [], False),
    ],
)
def test_hostname_matching_rfc6125(hostname, sans, expected):
    assert tls_checks.hostname_matches(hostname, sans) is expected


def test_wildcard_certificate_observation():
    der = make_cert(sans=("*.example.com",), cn="*.example.com")
    for host, expected in (("www.example.com", True), ("example.com", False)):
        o = tls_checks.build_tls_observation(
            TARGET_ID, host, tls_result(der), ipaddress.ip_address("203.0.113.10")
        )
        assert o["hostnameMatches"] is expected


def test_handshake_failure_is_an_error_observation_with_nulls():
    result = net.TlsResult(
        address=ipaddress.ip_address("2001:db8::10"),
        port=443,
        protocol=None,
        certificate_der=None,
        verified=False,
        verify_error="handshake_failed: SSLV3_ALERT_HANDSHAKE_FAILURE",
    )
    o = tls_checks.build_tls_observation(TARGET_ID, "www.example.com", result, result.address)
    assert_tls_schema(o)
    assert o["resultStatus"] == "error"
    assert o["ipAddress"] == "2001:db8::10"
    assert o["protocolVersion"] is None
    assert o["notBefore"] is None and o["notAfter"] is None
    assert o["fingerprintSha256"] is None and o["hostnameMatches"] is None
    assert o["subjectAltNames"] == []
    assert o["evidence"]["trusted"] is False
    assert o["evidence"]["verifyError"].startswith("handshake_failed")


def test_unparseable_certificate_is_partial():
    o = tls_checks.build_tls_observation(
        TARGET_ID, "www.example.com", tls_result(b"\x30\x03garbage"),
        ipaddress.ip_address("203.0.113.10"),
    )  # fmt: skip
    assert_tls_schema(o)
    assert o["resultStatus"] == "partial"
    assert o["evidence"]["parseError"] == "certificate_unparseable"
    assert o["fingerprintSha256"] is None


# -- check orchestration ------------------------------------------------------------------------


@pytest.fixture
def handshakes(monkeypatch):
    calls = []
    behaviour = {}
    der = make_cert()

    def fake(policy, hostname, address, port, *, timeout, tier="web", **_kw):
        calls.append((hostname, str(address), port, tier, timeout))
        action = behaviour.get(str(address))
        if isinstance(action, BaseException):
            raise action
        return tls_result(der, address=str(address))

    monkeypatch.setattr(net, "tls_handshake", fake)
    return calls, behaviour


def test_check_uses_one_ipv4_and_one_ipv6_address(handshakes):
    calls, _ = handshakes
    policy = FakePolicy(
        {"web": {"www.example.com": ["203.0.113.10", "203.0.113.11", "2001:db8::1", "2001:db8::2"]}}
    )
    out = []
    tls_checks.check_tls_certificate(
        policy, None, TARGET_ID, "www.example.com", make_ctx(), out.append
    )
    assert [(c[1], c[2], c[3]) for c in calls] == [
        ("203.0.113.10", 443, "web"),
        ("2001:db8::1", 443, "web"),
    ]
    assert all(c[0] == "www.example.com" for c in calls)
    assert all(0 < c[4] <= 15 for c in calls)
    assert [o["ipAddress"] for o in out] == ["203.0.113.10", "2001:db8::1"]
    assert ("resolve", "www.example.com", "web") in policy.calls
    for o in out:
        assert_tls_schema(o)


def test_resolution_refusal_propagates(handshakes):
    calls, _ = handshakes
    policy = FakePolicy({"web": {"www.example.com": "cname_out_of_scope"}})
    with pytest.raises(ScopeError) as err:
        tls_checks.check_tls_certificate(
            policy, None, TARGET_ID, "www.example.com", make_ctx(), [].append
        )
    assert err.value.code == "cname_out_of_scope"
    assert calls == []


def test_connect_time_refusal_of_every_address_raises(handshakes):
    _, behaviour = handshakes
    behaviour["203.0.113.10"] = ScopeError("prohibited_address", "rebinding")
    policy = FakePolicy({"web": {"www.example.com": ["203.0.113.10"]}})
    out = []
    with pytest.raises(ScopeError) as err:
        tls_checks.check_tls_certificate(
            policy, None, TARGET_ID, "www.example.com", make_ctx(), out.append
        )
    assert err.value.code == "prohibited_address"
    assert out == []


def test_connect_time_refusal_of_one_address_keeps_the_other(handshakes):
    _, behaviour = handshakes
    behaviour["2001:db8::1"] = ScopeError("prohibited_address", "rebinding")
    policy = FakePolicy({"web": {"www.example.com": ["203.0.113.10", "2001:db8::1"]}})
    out = []
    tls_checks.check_tls_certificate(
        policy, None, TARGET_ID, "www.example.com", make_ctx(), out.append
    )
    assert [o["ipAddress"] for o in out] == ["203.0.113.10"]


def test_connection_errors_become_error_and_timeout_observations(handshakes):
    _, behaviour = handshakes
    behaviour["203.0.113.10"] = ConnectionRefusedError()
    behaviour["2001:db8::1"] = TimeoutError()
    policy = FakePolicy({"web": {"www.example.com": ["203.0.113.10", "2001:db8::1"]}})
    out = []
    tls_checks.check_tls_certificate(
        policy, None, TARGET_ID, "www.example.com", make_ctx(), out.append
    )
    assert [(o["resultStatus"], o["evidence"].get("error")) for o in out] == [
        ("error", "ConnectionRefusedError"),
        ("timeout", "timeout"),
    ]
    for o in out:
        assert_tls_schema(o)


def test_empty_address_list_fails_closed(handshakes):
    policy = FakePolicy({"web": {"www.example.com": []}})
    with pytest.raises(CheckFailed) as err:
        tls_checks.check_tls_certificate(
            policy, None, TARGET_ID, "www.example.com", make_ctx(), [].append
        )
    assert err.value.code == "no_allowed_address"


def test_tls_check_passes_the_target_budget_and_stop_signal(monkeypatch):
    seen = []

    def fake(policy, hostname, address, port, *, timeout, tier="web", deadline, should_stop):
        seen.append((deadline, should_stop))
        raise TimeoutError

    monkeypatch.setattr(net, "tls_handshake", fake)
    policy = FakePolicy({"web": {"www.example.com": ["198.51.100.7"]}})
    stop = lambda: False  # noqa: E731
    before = time.monotonic()
    tls_checks.check_tls_certificate(
        policy, None, TARGET_ID, "www.example.com", make_ctx(remaining=20.0, should_stop=stop),
        [].append,
    )  # fmt: skip
    ((deadline, should_stop),) = seen
    assert before + 19 < deadline <= time.monotonic() + 20
    assert should_stop is stop
