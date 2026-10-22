# ruff: noqa: RUF001, RUF059, RUF100, S104, F811 - intentional homoglyphs, 0.0.0.0 test data, imported fixtures
"""Red-team tests for the Milestone 6 scope validator and the connecting checks.

Every test asserts the SAFE behaviour: a passing test means the attack is defended, a failing test
is a vulnerability. No live third-party system is ever contacted: name resolution is faked, every
``socket.connect`` goes through a guard that refuses (and records) anything that is not the
throwaway 127.0.0.1 test server, and Nmap is replaced by the Python interpreter or a fake.
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
import socket
import sys
import threading
import time

import pytest

from app import net, port_checks
from app import policy as policy_module
from app.checks import CheckFailed
from app.client import Signer
from app.dns_checks import DnsAnswer
from app.logging_config import configure_logging
from app.net import FINAL, FOLLOWED, connect_tcp, http_get, tls_handshake
from app.policy import (
    AddressRefused,
    ScopeError,
    ScopePolicy,
    address_prohibited_reason,
    parse_address,
    parse_network,
)
from app.port_checks import (
    PortScanSettings,
    build_nmap_argv,
    parse_nmap_xml,
    run_nmap,
    validate_ports,
)
from app.queue import InvalidJob, parse_job

from .test_port_checks import host, nmap_xml, port
from .test_queue import (  # noqa: F401 - `setup` is a fixture
    APEX_ID,
    JOB_ID,
    PASSIVE_CONFIG,
    QUICK_CONFIG,
    STANDARD_CONFIG,
    WWW_ID,
    make_job,
    setup,
)
from .test_tls_checks import make_ctx

LOOPBACK = ipaddress.IPv4Address("127.0.0.1")
PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:4700:4700::1111"


# ================================================================================================
# Harness


def make_policy(
    *, active=True, approved=(), deny=(), checks=None, targets=("www.example.com",), domain=None
) -> ScopePolicy:
    return ScopePolicy.from_job(
        job_id="job-redteam",
        snapshot={
            "domain": {"fqdn": domain or "example.com"},
            "profile": {
                "config": {
                    "checks": checks
                    or ["http_headers", "http_availability", "tls_certificate", "tcp_ports"]
                }
            },
            "approvedNetworks": list(approved),
        },
        target_hostnames=list(targets),
        deny_networks=list(deny),
        active_scanning_enabled=active,
    )


class Resolver:
    """records[(name, rdtype)] -> list of values | Exception | callable(n) -> list (n = call #)."""

    def __init__(self, records=None, canonical=None):
        self.records = records or {}
        self.canonical = canonical or {}
        self.calls: list[tuple[str, str]] = []
        self.lock = threading.Lock()

    def query(self, name, rdtype, lifetime):
        with self.lock:
            self.calls.append((name, rdtype))
            n = sum(1 for c in self.calls if c == (name, rdtype))
        value = self.records.get((name, rdtype), [])
        if isinstance(value, Exception):
            raise value
        if callable(value):
            value = value(n)
        return DnsAnswer(60, list(value), self.canonical.get((name, rdtype), name))


@pytest.fixture
def connect_log(monkeypatch):
    """Every socket.connect is recorded; only 127.0.0.1 is actually reached."""
    original = socket.socket.connect
    log: list[tuple] = []

    def guarded(sock, address):
        log.append(address)
        if address[0] != "127.0.0.1":
            raise ConnectionRefusedError("red-team guard: non-loopback connect blocked")
        return original(sock, address)

    monkeypatch.setattr(socket.socket, "connect", guarded)
    return log


@pytest.fixture
def sockets_created(monkeypatch):
    created: list[tuple] = []
    original_init = socket.socket.__init__

    def init(self, *args, **kwargs):
        created.append(args)
        original_init(self, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "__init__", init)
    return created


@pytest.fixture
def allow_loopback(monkeypatch):
    original = policy_module.address_prohibited_reason

    def patched(address):
        if address == LOOPBACK:
            return None
        return original(address)

    monkeypatch.setattr(policy_module, "address_prohibited_reason", patched)


class Server:
    """Throwaway HTTP server on 127.0.0.1; ``handler(conn, request_bytes, index)``."""

    def __init__(self, handler):
        self.handler = handler
        self.connections = 0
        self.requests: list[bytes] = []
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self._sock.settimeout(0.05)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def url(self, path="/", hostname="www.example.com"):
        return f"http://{hostname}:{self.port}{path}"

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                continue
            index = self.connections
            self.connections += 1
            threading.Thread(target=self._handle, args=(conn, index), daemon=True).start()

    def _handle(self, conn, index):
        try:
            conn.settimeout(5)
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 65536:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            self.requests.append(data)
            self.handler(conn, data, index)
        except Exception:  # noqa: S110 - client behaviour is under test
            pass
        finally:
            with contextlib.suppress(OSError):
                conn.close()

    def close(self):
        self._stop.set()
        self._sock.close()
        self._thread.join(timeout=2)


@pytest.fixture
def servers():
    made: list[Server] = []

    def make(handler):
        server = Server(handler)
        made.append(server)
        return server

    yield make
    for server in made:
        server.close()


def redirect_to(location: bytes | str, status=302):
    raw = location.encode("latin-1") if isinstance(location, str) else location

    def handler(conn, _req, _i):
        conn.sendall(
            b"HTTP/1.1 " + str(status).encode() + b" X\r\nLocation: " + raw
            + b"\r\nContent-Length: 0\r\n\r\n"
        )  # fmt: skip

    return handler


def ok(conn, _req, _i):
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")


def www_loopback(extra=None):
    records = {("www.example.com", "A"): ["127.0.0.1"]}
    records.update(extra or {})
    return Resolver(records)


# ================================================================================================
# 1. Address encodings


BYPASS_TEXTS = [
    # IPv4 alternative encodings
    "127.1", "127.0.1", "0x7f.0.0.1", "0x7f000001", "0X7F.0.0.1", "017.0.0.1", "0177.0.0.1",
    "2130706433", "0", "0.0.0.0", "000.000.000.000", "127.000.000.001", "127.0.0.01",
    "127.0.0.1.", " 127.0.0.1", "127.0.0.1 ", "127.0.0.1\n", "127.0.0.1\x00", "127.0.0.1\t",
    "127.0.0.1:80", "127.0.0.1/32", "[127.0.0.1]", "127.0.0.1%25", "127。0。0。1",
    "１２７.0.0.1", "127.0.0.١", "۱۲۷.0.0.1", "127.0.0.𝟏", "127.0.0.1​",
    # IPv4 special ranges
    "10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1", "100.64.0.1", "100.127.255.254",
    "169.254.169.254", "192.0.0.170", "192.0.2.1", "198.18.0.1", "198.19.255.255",
    "198.51.100.1", "203.0.113.1", "192.88.99.1", "224.0.0.1", "239.255.255.250",
    "240.0.0.1", "255.255.255.255", "0.1.2.3",
    # IPv6 loopback / unspecified, all spellings
    "::1", "::", "0::1", "0:0:0:0:0:0:0:1", "0000:0000:0000:0000:0000:0000:0000:0001",
    "::0:1", "[::1]", "::1%lo", "::1%1",
    # IPv4-mapped (all spellings)
    "::ffff:127.0.0.1", "::FFFF:127.0.0.1", "::ffff:7f00:1", "::ffff:7f00:0001",
    "::FFFF:7F00:0001", "0:0:0:0:0:ffff:7f00:1", "0:0:0:0:0:FFFF:127.0.0.1",
    "::ffff:10.0.0.1", "::ffff:169.254.169.254", "::ffff:93.184.216.34", "::ffff:5db8:d822",
    # IPv4-translated (SIIT) and IPv4-compatible
    "::ffff:0:127.0.0.1", "::ffff:0:7f00:1", "::ffff:0:93.184.216.34", "::127.0.0.1",
    "::7f00:1", "::10.0.0.1", "::93.184.216.34",
    # NAT64 / 6to4 / Teredo
    "64:ff9b::7f00:1", "64:ff9b::127.0.0.1", "64:ff9b::a00:1", "64:ff9b::93.184.216.34",
    "64:ff9b:1::a00:1", "2002:7f00:1::1", "2002:a00:1::", "2002:5db8:d822::1",
    "2001:0:4136:e378:8000:63bf:80ff:fffe", "2001::1",
    # Scoped / zone ids
    "fe80::1", "fe80::1%eth0", "FE80::1", "fe80::1%25eth0", "2606:4700:4700::1111%eth0",
    "2606:4700:4700::1111%1",
    # ULA, site-local, multicast (all scopes), discard, documentation, benchmarking, ORCHID
    "fc00::1", "fd00::1", "FD12:3456:789A::1", "fec0::1", "ff01::1", "ff02::1", "ff05::2",
    "ff08::1", "ff0e::1", "FF0E::1", "ff3e::1", "100::1", "2001:db8::1", "2001:DB8::1",
    "3fff::1", "2001:2::1", "2001:10::1", "2001:20::1",
    # Outside 2000::/3
    "4000::1", "8000::1", "e000::1", "::2", "1::1",
    # Malformed / smuggling
    "", " ", "::1 ", " ::1", "::1\x00", "[2606:4700:4700::1111]", "2606:4700:4700::1111/128",
    "2606:4700:4700:::1111", "93.184.216.34\r\nHost: x", "93.184.216.34;10.0.0.1",
    "93.184.216.34,10.0.0.1", "a" * 200, "1" * 4000,
]  # fmt: skip


@pytest.mark.parametrize("text", BYPASS_TEXTS)
def test_address_text_is_refused_or_prohibited(text):
    try:
        address = parse_address(text)
    except ScopeError:
        return
    assert address_prohibited_reason(address) is not None, f"{text!r} -> {address} allowed"


@pytest.mark.parametrize("text", BYPASS_TEXTS)
def test_assert_destination_refuses_every_bypass_text(text, sockets_created):
    policy = make_policy(approved=["93.184.216.0/24", "2606:4700::/32"])
    for tier in ("web", "network"):
        with pytest.raises(ScopeError):
            policy.assert_destination(text, tier=tier)
        with pytest.raises(ScopeError):
            connect_tcp(policy, text, 443, timeout=1, tier=tier)
    assert sockets_created == []


@pytest.mark.parametrize(
    "value",
    [
        2130706433,
        b"\x7f\x00\x00\x01",
        bytearray(b"\x7f\x00\x00\x01"),
        None,
        ("127.0.0.1", 80),
        ipaddress.ip_network("93.184.216.0/24"),
        ipaddress.ip_address(2130706433),
        ipaddress.IPv6Address("::ffff:7f00:1"),
        ipaddress.IPv6Address("2606:4700:4700::1111%eth0"),
        ipaddress.IPv6Address("fe80::1%2"),
    ],
)
def test_non_text_destinations_are_refused(value, sockets_created):
    policy = make_policy()
    with pytest.raises(ScopeError):
        policy.assert_destination(value, tier="web")
    with pytest.raises(ScopeError):
        connect_tcp(policy, value, 443, timeout=1, tier="web")
    assert sockets_created == []


def test_public_addresses_are_allowed_so_the_refusals_above_are_meaningful():
    policy = make_policy()
    assert policy.assert_destination(PUBLIC_V4, tier="web") == ipaddress.ip_address(PUBLIC_V4)
    assert policy.assert_destination(PUBLIC_V6, tier="web") == ipaddress.ip_address(PUBLIC_V6)


def test_policy_has_no_hidden_allow_switch():
    # Non-bool truthy values must not enable active scanning.
    for value in ("true", 1, "yes", [1], object()):
        assert ScopePolicy(job_id="j", domain="example.com", active_scanning_enabled=value) \
            .active_scanning_enabled is False  # fmt: skip
        assert make_policy(active=value).active_scanning_enabled is False


# ================================================================================================
# 2. Values arriving from DNS answers


@pytest.mark.parametrize(
    "values",
    [
        ["127.0.0.1"],
        [" 127.0.0.1 "],
        ["127.0.0.1."],
        ["127.1"],
        ["2130706433"],
        ["0x7f.1"],
        ["93.184.216.34:80"],
        ["[93.184.216.34]"],
        ["93.184.216.34\x00"],
        ["93.184.216.34 10.0.0.1"],
        ["::ffff:93.184.216.34"],
        ["10.0.0.1", "169.254.169.254", "100.64.0.1", "0.0.0.0"],
        ["2606:4700:4700::1111"],  # IPv6 text in an A answer: wrong family
    ],
)
def test_resolve_never_returns_bad_values_from_a_answers(values):
    policy = make_policy()
    resolver = Resolver({("www.example.com", "A"): values})
    with pytest.raises(ScopeError) as err:
        policy.resolve("www.example.com", resolver, tier="web", lifetime=1)
    assert err.value.code == "no_allowed_address"


@pytest.mark.parametrize(
    "values",
    [
        ["::1"],
        ["[2606:4700:4700::1111]"],
        ["2606:4700:4700::1111%eth0"],
        ["::ffff:127.0.0.1", "::ffff:7f00:1", "64:ff9b::a00:1", "2002:a00:1::1", "fd00::1"],
        ["fe80::1"],
        ["93.184.216.34"],  # IPv4 text in an AAAA answer
    ],
)
def test_resolve_never_returns_bad_values_from_aaaa_answers(values):
    policy = make_policy()
    resolver = Resolver({("www.example.com", "AAAA"): values})
    with pytest.raises(ScopeError) as err:
        policy.resolve("www.example.com", resolver, tier="web", lifetime=1)
    assert err.value.code == "no_allowed_address"


def test_resolver_returning_non_strings_fails_closed():
    policy = make_policy()
    resolver = Resolver({("www.example.com", "A"): [2130706433]})
    with pytest.raises(Exception):  # noqa: B017 - any failure is fine, as long as nothing is allowed
        policy.resolve("www.example.com", resolver, tier="web", lifetime=1)


def test_mixed_answers_drop_every_private_address_whatever_the_order():
    policy = make_policy()
    resolver = Resolver(
        {
            ("www.example.com", "A"): ["10.0.0.1", PUBLIC_V4, "169.254.169.254", "127.0.0.1"],
            ("www.example.com", "AAAA"): ["::ffff:10.0.0.1", "fd00::1", PUBLIC_V6, "::1"],
        }
    )
    resolved = policy.resolve("www.example.com", resolver, tier="web", lifetime=1)
    assert [str(a) for a in resolved.addresses] == [PUBLIC_V4, PUBLIC_V6]


def test_http_get_with_private_first_answer_connects_only_to_the_allowed_one(
    allow_loopback, connect_log, servers
):
    server = servers(ok)
    resolver = Resolver({("www.example.com", "A"): ["10.0.0.1", "192.168.1.1", "127.0.0.1"]})
    result = http_get(make_policy(), server.url(), resolver, timeout=2)
    assert result.last.decision == FINAL
    assert connect_log == [("127.0.0.1", server.port)]


# ================================================================================================
# 3. DNS rebinding / TOCTOU / CNAME chains


def test_rebinding_after_resolution_cannot_redirect_the_pinned_connection(
    allow_loopback, connect_log, servers
):
    server = servers(ok)
    # First answer is allowed; every later answer is private. The connection must use the first.
    resolver = Resolver(
        {("www.example.com", "A"): lambda n: ["127.0.0.1"] if n == 1 else ["10.0.0.1"]}
    )  # noqa: E501
    result = http_get(make_policy(), server.url(), resolver, timeout=2)
    assert result.last.decision == FINAL
    assert connect_log == [("127.0.0.1", server.port)]
    assert resolver.calls.count(("www.example.com", "A")) == 1


def test_rebinding_on_a_same_host_redirect_is_refused(allow_loopback, connect_log, servers):
    server = servers(redirect_to("/next"))
    resolver = Resolver(
        {("www.example.com", "A"): lambda n: ["127.0.0.1"] if n == 1 else ["10.0.0.1"]}
    )  # noqa: E501
    result = http_get(make_policy(), server.url(), resolver, timeout=2)
    assert result.hops[0].decision == FOLLOWED
    assert result.last.address is None
    assert result.last.decision == "no_allowed_address"
    assert connect_log == [("127.0.0.1", server.port)]
    assert server.connections == 1


def test_tls_handshake_revalidates_and_never_resolves(sockets_created):
    policy = make_policy()
    for bad in ("10.0.0.1", "::ffff:127.0.0.1", "127.1"):
        with pytest.raises(ScopeError):
            tls_handshake(policy, "www.example.com", bad, 443, timeout=1)
    with pytest.raises(ScopeError):  # SNI must be in scope
        tls_handshake(policy, "evil.com", PUBLIC_V4, 443, timeout=1)
    assert sockets_created == []


def test_cname_chain_changing_between_walk_and_address_query_is_refused():
    policy = make_policy()
    resolver = Resolver(
        {("www.example.com", "A"): [PUBLIC_V4]},
        canonical={("www.example.com", "A"): "evil.net"},
    )
    with pytest.raises(ScopeError) as err:
        policy.resolve("www.example.com", resolver, tier="web", lifetime=1)
    assert err.value.code == "cname_chain_invalid"


def test_cname_hop_that_changes_between_queries_is_revalidated():
    policy = make_policy()
    resolver = Resolver(
        {
            ("www.example.com", "CNAME"): lambda n: ["a.example.com."] if n == 1 else ["evil.net."],
            ("a.example.com", "A"): [PUBLIC_V4],
        }
    )
    assert policy.resolve("www.example.com", resolver, tier="web", lifetime=1).addresses
    with pytest.raises(ScopeError) as err:
        policy.resolve("www.example.com", resolver, tier="web", lifetime=1)
    assert err.value.code == "cname_out_of_scope"


@pytest.mark.parametrize(
    "target",
    [
        "evil.net.", "example.com.evil.net.", "evil-example.com.", "xexample.com.", "127.0.0.1.",
        "2130706433.", "[::1].", "*.example.com.", "www.exаmple.com.", "evil.net\x00.example.com.",
        "a..example.com.", "-a.example.com.", "a" * 64 + ".example.com.", "", ".", "@",
        "evil.net/.example.com.",
    ],
)  # fmt: skip
def test_cname_targets_outside_the_domain_or_malformed_are_refused(target):
    policy = make_policy()
    resolver = Resolver(
        {("www.example.com", "CNAME"): [target], (target.rstrip("."), "A"): [PUBLIC_V4]}
    )
    with pytest.raises(ScopeError) as err:
        policy.resolve("www.example.com", resolver, tier="web", lifetime=1)
    assert err.value.code in ("cname_out_of_scope", "no_allowed_address", "cname_chain_invalid")
    assert ("evil.net", "A") not in resolver.calls


def test_cname_loops_long_chains_and_multiple_cnames_are_refused():
    policy = make_policy()
    loop = Resolver(
        {
            ("www.example.com", "CNAME"): ["a.example.com."],
            ("a.example.com", "CNAME"): ["www.example.com."],
        }  # noqa: E501
    )
    with pytest.raises(ScopeError) as err:
        policy.resolve("www.example.com", loop, tier="web", lifetime=1)
    assert err.value.code == "cname_chain_invalid"

    records = {(f"h{i}.example.com", "CNAME"): [f"h{i + 1}.example.com."] for i in range(50)}
    records[("h50.example.com", "A")] = [PUBLIC_V4]
    chain = Resolver(records)
    with pytest.raises(ScopeError) as err:
        policy.resolve("h0.example.com", chain, tier="web", lifetime=1)
    assert err.value.code == "cname_chain_invalid"
    assert len(chain.calls) <= policy_module.MAX_CNAME_HOPS + 2

    multi = Resolver({("www.example.com", "CNAME"): ["a.example.com.", "evil.net."]})
    with pytest.raises(ScopeError) as err:
        policy.resolve("www.example.com", multi, tier="web", lifetime=1)
    assert err.value.code == "cname_chain_invalid"


def test_ip_literal_looking_names_inside_the_domain_are_resolved_not_parsed():
    policy = make_policy()
    resolver = Resolver({("127.0.0.1.example.com", "A"): ["10.0.0.1"]})
    with pytest.raises(ScopeError):
        policy.resolve("127.0.0.1.example.com", resolver, tier="web", lifetime=1)


# ================================================================================================
# 4. Redirects


EVIL_LOCATIONS = [
    "http://[::1]/", "http://[::ffff:127.0.0.1]/", "http://2130706433/", "http://0x7f.1/",
    "http://127.0.0.1/", "http://127.1/", "http://017700000001/", "http://user@www.example.com/",
    "http://www.example.com@evil.com/", "http://www.example.com:0/", "http://www.example.com:65536/",
    "http://www.example.com:99999999999/", "http://www.example.com:+80/",
    "http://www.example.com:-1/", "http://evil.com\\@www.example.com/", "//evil.com/",
    "HTTPS://evil.com/", "HtTp://evil.com/", "javascript:alert(1)",
    "data:text/html,hi", "file:///etc/passwd", "gopher://www.example.com:6379/_FLUSHALL",
    "ftp://www.example.com/", "dict://www.example.com:11211/", "http://www.example.com\t.evil.com/",
    "http://evil-example.com/", "http://www.example.com.evil.net/", "http://example.com.evil.net/",
    "http://www.example.com%2eevil.com/", "http://%77ww.example.com/", "http://evil.com#@www.example.com/",
    "http://evil.com?@www.example.com/", "http://evil.com;www.example.com/",
    "http://private.example.com/", "http://mapped.example.com/", "http://nat64.example.com/",
    "http://cname.example.com/", "http://meta.example.com/",
    "http://localhost/", "http://localhost.example.com.evil.net/",
]  # fmt: skip


def redirect_resolver():
    return www_loopback(
        {
            ("private.example.com", "A"): ["10.0.0.1"],
            ("meta.example.com", "A"): ["169.254.169.254"],
            ("mapped.example.com", "AAAA"): ["::ffff:127.0.0.1"],
            ("nat64.example.com", "AAAA"): ["64:ff9b::7f00:1"],
            ("cname.example.com", "CNAME"): ["evil.net."],
            ("evil.net", "A"): ["127.0.0.1"],
            ("evil.com", "A"): ["127.0.0.1"],
            ("localhost", "A"): ["127.0.0.1"],
        }
    )


@pytest.mark.parametrize("location", EVIL_LOCATIONS)
def test_malicious_redirects_are_refused_without_connecting(
    location, allow_loopback, connect_log, servers
):
    server = servers(redirect_to(location))
    result = http_get(make_policy(), server.url(), redirect_resolver(), timeout=2)
    assert result.hops[0].decision == FOLLOWED
    assert result.last.address is None, result.last
    assert result.last.decision not in (FOLLOWED, FINAL)
    assert server.connections == 1
    assert connect_log == [("127.0.0.1", server.port)]


@pytest.mark.parametrize(
    "location", ["\\\\evil.com/", "http:evil.com", "/\\evil.com", "///evil.com/"]
)
def test_ambiguous_relative_locations_stay_on_the_same_pinned_host(
    location, allow_loopback, connect_log, servers
):
    """Browsers read some of these as another host; here they must at most be paths on the same
    in-scope host (never a new name resolved, never another address)."""
    server = servers(redirect_to(location))
    resolver = redirect_resolver()
    http_get(make_policy(), server.url(), resolver, timeout=2)
    assert {name for name, _ in resolver.calls} == {"www.example.com"}
    assert set(connect_log) == {("127.0.0.1", server.port)}


@pytest.mark.parametrize(
    "raw",
    [
        "http://www.exаmple.com/".encode(),  # Cyrillic a, sent as UTF-8
        b"http://evil.com\x00.example.com/",
        b"http://www.example.com\x0b.evil.com/",
        b"http://evil.com/\r\n x",  # obs-fold continuation
        b"http://\xef\xbc\x8e/",
    ],
)
def test_binary_and_folded_locations_are_refused(raw, allow_loopback, connect_log, servers):
    server = servers(redirect_to(raw))
    result = http_get(make_policy(), server.url(), redirect_resolver(), timeout=2)
    assert all(h.address in (None, LOOPBACK) for h in result.hops)
    assert server.connections == 1
    assert connect_log == [("127.0.0.1", server.port)]


def test_redirect_loops_and_chains_are_capped(allow_loopback, connect_log, servers):
    def handler(conn, req, i):
        conn.sendall(f"HTTP/1.1 302 X\r\nLocation: /r{i + 1}\r\n\r\n".encode())

    server = servers(handler)
    result = http_get(make_policy(), server.url(), www_loopback(), timeout=2, max_redirects=999)
    assert server.connections == net.MAX_REDIRECTS + 1
    assert result.last.decision == "too_many_redirects"

    loop = servers(redirect_to("/"))
    result = http_get(make_policy(), loop.url(), www_loopback(), timeout=2)
    assert loop.connections == 1
    assert result.last.decision == "too_many_redirects"


def test_redirect_to_a_non_web_port_is_not_followed(allow_loopback, connect_log, servers):
    """A web-tier redirect must not turn into a probe of an arbitrary port (network-tier
    capability outside the approved networks)."""
    other = servers(ok)
    server = servers(redirect_to(f"http://www.example.com:{other.port}/"))
    http_get(make_policy(), server.url(), www_loopback(), timeout=2)
    assert other.connections == 0, "redirect to an arbitrary port was followed"


def test_redirect_to_a_hostname_that_is_not_an_approved_target_is_not_followed(
    allow_loopback, connect_log, servers
):
    """Approved scope is the job's target list, not every name under the domain (CT discoveries
    stay pending until approved)."""
    server = servers(redirect_to("/"))
    first = servers(
        lambda conn, r, i: redirect_to(server.url(hostname="pending.example.com"))(conn, r, i)
    )  # noqa: E501
    resolver = www_loopback({("pending.example.com", "A"): ["127.0.0.1"]})
    policy = make_policy(targets=("www.example.com",))
    http_get(policy, first.url(), resolver, timeout=2)
    assert ("pending.example.com", "A") not in resolver.calls, "unapproved host was resolved"
    assert server.connections == 0, "unapproved host was contacted"


# ================================================================================================
# 5. Host header / SNI / request-target smuggling


@pytest.mark.parametrize(
    "url",
    [
        "http://www.example.com\r\nX-Injected: 1/",
        "http://www.example.com /",
        "http://www.example.com:80:81/",
        "http://www.example.com/ HTTP/1.1\r\nHost: evil.com\r\n\r\n",
        "http://www.example.com/\nX: y",
        "http://www.example.com/\x00",
        "http://www.example.com/ ",
        "http://www.example.com/" + "a" * 5000,
        "http://www.example.com/a b",
    ],
)
def test_request_and_host_injection_is_refused_before_resolution(url, connect_log):
    resolver = www_loopback()
    result = http_get(make_policy(), url, resolver, timeout=1)
    assert result.last.decision in ("invalid_url", "out_of_scope_host")
    assert resolver.calls == []
    assert connect_log == []


def test_request_bytes_are_exactly_the_fixed_template(allow_loopback, connect_log, servers):
    server = servers(ok)
    http_get(make_policy(), server.url("/p?q=%0d%0aX:1"), www_loopback(), timeout=2)
    (request,) = server.requests
    lines = request.split(b"\r\n")
    assert lines[0] == b"GET /p?q=%0d%0aX:1 HTTP/1.1"
    assert lines[1] == f"Host: www.example.com:{server.port}".encode()
    assert {line.split(b":")[0] for line in lines[2:] if line} == {
        b"User-Agent", b"Accept", b"Accept-Encoding", b"Connection",
    }  # fmt: skip


def test_hostnames_with_control_characters_are_normalised_or_refused():
    policy = make_policy()
    for name in ("www.example.com\r\nX: y", "www.example.com:443", "www .example.com",
                 "www.example.com/x", "www.example.com\\", "www.example.com%00"):  # fmt: skip
        with pytest.raises(ScopeError):
            policy.assert_hostname(name)


# ================================================================================================
# 6. Resource exhaustion (HTTP)


def test_slow_drip_headers_hit_the_hop_deadline(allow_loopback, connect_log, servers):
    def drip(conn, _req, _i):
        conn.sendall(b"HTTP/1.1 200 OK\r\n")
        for _ in range(200):
            conn.sendall(b"X")
            time.sleep(0.02)

    server = servers(drip)
    start = time.monotonic()
    result = http_get(make_policy(), server.url(), www_loopback(), timeout=0.3)
    assert time.monotonic() - start < 1.5
    assert result.last.decision == "error" and result.last.error == "timeout"


def test_endless_and_giant_headers_are_bounded(allow_loopback, connect_log, servers):
    def endless(conn, _req, _i):
        conn.sendall(b"HTTP/1.1 200 OK\r\n")
        with contextlib.suppress(OSError):
            for i in range(100000):
                conn.sendall(f"X-{i}: {'a' * 100}\r\n".encode())

    def giant(conn, _req, _i):
        with contextlib.suppress(OSError):
            conn.sendall(b"HTTP/1.1 200 OK\r\nX: " + b"a" * (4 * 1024 * 1024))

    for handler in (endless, giant):
        server = servers(handler)
        result = http_get(make_policy(), server.url(), www_loopback(), timeout=2)
        assert result.last.error == "header_too_large"


def test_many_headers_are_capped(allow_loopback, connect_log, servers):
    def many(conn, _req, _i):
        head = "".join(f"X-{i}: v\r\n" for i in range(1000))
        conn.sendall(f"HTTP/1.1 200 OK\r\n{head}\r\n".encode())

    server = servers(many)
    result = http_get(make_policy(), server.url(), www_loopback(), timeout=2)
    assert len(result.last.headers) <= net.MAX_HEADERS


def test_huge_and_chunked_bodies_are_capped(allow_loopback, connect_log, servers):
    def huge(conn, _req, _i):
        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
        with contextlib.suppress(OSError):
            for _ in range(2000):
                conn.sendall(b"4000\r\n" + b"a" * 0x4000 + b"\r\n")

    server = servers(huge)
    result = http_get(make_policy(), server.url(), www_loopback(), timeout=2, max_body_bytes=10**9)
    assert result.last.body_bytes <= net.MAX_BODY_BYTES


def test_http_get_total_time_is_bounded_by_one_deadline_across_redirects(
    allow_loopback, connect_log, servers
):
    """Each hop gets its own 2 x timeout deadline, so a server that answers every hop just before
    the deadline holds the worker for (MAX_REDIRECTS + 1) x 2 x timeout, beyond the per-target
    budget the caller passed as ``timeout``."""

    def slow_redirect(conn, _req, i):
        time.sleep(0.5)
        conn.sendall(f"HTTP/1.1 302 X\r\nLocation: /r{i + 1}\r\n\r\n".encode())

    server = servers(slow_redirect)
    timeout = 0.4
    start = time.monotonic()
    http_get(make_policy(), server.url(), www_loopback(), timeout=timeout)
    elapsed = time.monotonic() - start
    assert elapsed < 2 * timeout + 0.5, f"http_get ran {elapsed:.1f}s for timeout={timeout}s"


# ================================================================================================
# 7. Policy confusion: tiers, approved networks, deny list


def test_passive_tier_never_opens_a_socket(sockets_created):
    policy = make_policy()
    for tier in ("passive", "PASSIVE", "", "Web", None, "network "):
        with pytest.raises(ScopeError):
            connect_tcp(policy, PUBLIC_V4, 443, timeout=1, tier=tier)  # type: ignore[arg-type]
        with pytest.raises(ScopeError):
            policy.resolve("www.example.com", Resolver(), tier=tier, lifetime=1)  # type: ignore[arg-type]
    assert sockets_created == []


def test_active_disabled_policy_never_connects(sockets_created):
    policy = make_policy(active=False, approved=["93.184.216.0/24"])
    for tier in ("web", "network"):
        with pytest.raises(ScopeError) as err:
            connect_tcp(policy, PUBLIC_V4, 443, timeout=1, tier=tier)
        assert err.value.code == "active_scanning_disabled"
    for check in ("tls_certificate", "http_headers", "tcp_ports"):
        with pytest.raises(ScopeError):
            policy.assert_check_allowed(check)
    assert sockets_created == []


def test_network_tier_refuses_unapproved_public_addresses_through_web_helpers(
    sockets_created, connect_log
):
    policy = make_policy(approved=["198.51.100.0/24"])  # documentation: never usable
    resolver = Resolver({("www.example.com", "A"): [PUBLIC_V4]})
    with pytest.raises(AddressRefused) as err:
        connect_tcp(policy, PUBLIC_V4, 22, timeout=1, tier="network")
    assert err.value.code == "network_not_approved"
    result = http_get(policy, "http://www.example.com/", resolver, timeout=1, tier="network")
    assert result.last.decision == "no_allowed_address"
    with pytest.raises(ScopeError):
        tls_handshake(policy, "www.example.com", PUBLIC_V4, 443, timeout=1, tier="network")
    assert sockets_created == [] and connect_log == []


@pytest.mark.parametrize(
    "network,address",
    [
        ("10.0.0.0/8", "10.0.0.1"),
        ("127.0.0.0/8", "127.0.0.1"),
        ("100.64.0.0/10", "100.64.0.1"),
        ("169.254.0.0/16", "169.254.169.254"),
        ("fd00::/8", "fd00::1"),
        ("64:ff9b::/96", "64:ff9b::a00:1"),
        ("2002::/16", "2002:a00:1::1"),
        ("2001:db8::/32", "2001:db8::1"),
        ("224.0.0.0/4", "224.0.0.1"),
    ],
)
def test_approved_networks_overlapping_prohibited_ranges_grant_nothing(network, address):
    policy = make_policy(approved=[network])
    with pytest.raises(AddressRefused) as err:
        policy.assert_destination(address, tier="network")
    assert err.value.code == "prohibited_address"


@pytest.mark.parametrize(
    "network",
    [
        "0.0.0.0/0", "::/0", "0.0.0.0/1", "93.0.0.0/7", "2000::/3", "2606::/16", "93.184.216.1/24",
        "93.184.216.0/33", "93.184.216.0/-1", "93.184.216.0/ 24", "93.184.216.0/024",
        "093.184.216.0/24", "93.184.216.0/24\n", " 93.184.216.0/24", "93.184.216.0/24,10.0.0.0/8",
        "93.184.216.0/0x18", "93.184.216.0/２４", "[2606:4700::]/32", "2606:4700::%eth0/32",
        None, 42, {"cidr": "93.184.216.0/24"}, ["93.184.216.0/24"],
    ],
)  # fmt: skip
def test_malformed_or_over_broad_approved_networks_are_ignored(network):
    policy = make_policy(approved=[network])
    with pytest.raises(ScopeError):
        policy.assert_destination(PUBLIC_V4, tier="network")
    with pytest.raises(ScopeError):
        policy.assert_destination(PUBLIC_V6, tier="network")


def test_approved_networks_as_a_string_are_ignored():
    policy = ScopePolicy.from_job(
        job_id="j",
        snapshot={
            "domain": {"fqdn": "example.com"},
            "profile": {"config": {"checks": ["tcp_ports"]}},
            "approvedNetworks": "93.184.216.0/24",
        },
        target_hostnames=["www.example.com"],
        deny_networks=[],
        active_scanning_enabled=True,
    )
    assert policy.approved_networks == ()


def test_deny_list_is_enforced_by_every_path(sockets_created, connect_log, monkeypatch):
    deny = ["93.184.216.0/24", "2606:4700::/32"]
    policy = make_policy(approved=["93.184.216.0/24", "2606:4700::/32"], deny=deny)
    resolver = Resolver(
        {("www.example.com", "A"): [PUBLIC_V4], ("www.example.com", "AAAA"): [PUBLIC_V6]}
    )
    for tier in ("web", "network"):
        for address in (PUBLIC_V4, PUBLIC_V6, ipaddress.ip_address(PUBLIC_V4)):
            with pytest.raises(AddressRefused) as err:
                policy.assert_destination(address, tier=tier)
            assert err.value.reason == "deny_listed"
        with pytest.raises(ScopeError):
            policy.resolve("www.example.com", resolver, tier=tier, lifetime=1)
    assert http_get(policy, "https://www.example.com/", resolver, timeout=1).last.address is None
    nmap_calls = []
    monkeypatch.setattr(port_checks, "run_nmap", lambda *a, **k: nmap_calls.append(a))
    with pytest.raises(ScopeError):
        port_checks.check_tcp_ports(
            policy, resolver, "t", "www.example.com", make_ctx(), lambda o: None,
            PortScanSettings((22,), False, 1, 1, 60, "/usr/bin/nmap", True),
        )  # fmt: skip
    assert nmap_calls == [] and sockets_created == [] and connect_log == []


@pytest.mark.parametrize("bad", ["10.0.0.0/8 ", "10.0.0.1/8", "ten", "10.0.0.0/33", None])
def test_malformed_deny_list_fails_closed(bad):
    with pytest.raises(ScopeError) as err:
        make_policy(deny=[bad])
    assert err.value.code == "scope_rejected"


@pytest.mark.parametrize(
    "target",
    [
        "evil.com", "example.com.evil.net", "evil-example.com", "xexample.com", "www.exаmple.com",
        "*.example.com", "www.example.com\x00.evil.net", "..example.com", "www..example.com",
        "www.example.com/evil", "www.example.com:443", "127.0.0.1", "::1", "",
    ],
)  # fmt: skip
def test_snapshot_targets_outside_the_domain_are_rejected(target):
    with pytest.raises(ScopeError) as err:
        make_policy(targets=("www.example.com", target))
    assert err.value.code == "scope_rejected"


@pytest.mark.parametrize("domain", ["com", "co.uk", "localhost", "arpa", "in-addr.arpa"])
def test_public_suffix_or_single_label_job_domain_is_rejected(domain):
    """Defence in depth: the worker should not accept a job whose 'domain' is a TLD/public suffix
    (would make every name under it in scope) even if the server snapshot says so."""
    with pytest.raises(ScopeError):
        ScopePolicy.from_job(
            job_id="j",
            snapshot={
                "domain": {"fqdn": domain},
                "profile": {"config": {"checks": ["http_headers"]}},
            },
            target_hostnames=[],
            deny_networks=[],
            active_scanning_enabled=True,
        )


def test_checks_not_in_the_profile_are_refused():
    policy = make_policy(checks=["http_headers"])
    for check in ("tcp_ports", "tls_certificate", "service_identification", "exploit", "dns "):
        with pytest.raises(ScopeError):
            policy.assert_check_allowed(check)


# ================================================================================================
# 8. Nmap: argv, subprocess bounds, XML


@pytest.mark.parametrize(
    "ports",
    [["22 --script=vuln"], ["22,--script=vuln"], [-1], [0], [65536], [True], [22.0], ["22"],
     [None], [[22]], list(range(1, 1026))],
)  # fmt: skip
def test_port_injection_is_refused(ports):
    with pytest.raises(CheckFailed):
        validate_ports(ports)
    with pytest.raises((CheckFailed, ValueError, TypeError)):
        build_nmap_argv(
            "/usr/bin/nmap", [ipaddress.ip_address(PUBLIC_V4)], ports,
            service_identification=False, rate_per_second=1, concurrency=1,
            host_timeout_seconds=10,
        )  # fmt: skip


def test_argv_contains_only_template_options_whatever_the_inputs():
    argv = build_nmap_argv(
        "/usr/bin/nmap",
        [ipaddress.ip_address(PUBLIC_V6)],
        [22, 22, 443],
        service_identification=True,
        rate_per_second=10**9,
        concurrency=10**9,
        host_timeout_seconds=10,
    )
    options = {a for a in argv[1:] if a.startswith("-")}
    assert options <= {
        "-sT", "-Pn", "-n", "--unprivileged", "--max-retries", "--host-timeout", "--max-rate",
        "--max-parallelism", "-p", "-sV", "--version-light", "-6", "-oX", "-",
    }  # fmt: skip
    assert argv[argv.index("--max-rate") + 1] == "100"
    assert argv[argv.index("--max-parallelism") + 1] == "16"
    assert argv[-1] == PUBLIC_V6 and argv[argv.index("-p") + 1] == "22,443"


@pytest.mark.parametrize(
    "field,value",
    [
        ("ratePerSecond", "1 --script=vuln"),
        ("ratePerSecond", float("nan")),
        ("ratePerSecond", float("inf")),
        ("concurrency", "4; rm -rf /"),
        ("concurrency", 10**6),
        ("tcpPorts", ["22 --script=vuln"]),
        ("tcpPorts", [22, -1]),
        ("tcpPorts", [22.0]),
        ("tcpPorts", list(range(1, 1026))),
        ("tcpPorts", "22,80"),
        ("timeouts", {"connectMs": "1000 -oN /tmp/x", "readMs": 1000, "targetSeconds": 60}),
        ("timeouts", {"connectMs": 1000, "readMs": 1000, "targetSeconds": 10**9}),
        ("maxTargets", 10**9),
        ("active", "true"),
        ("checks", "tcp_ports"),
    ],
)
def test_malicious_snapshot_fields_make_the_job_invalid(field, value):
    job = make_job({**STANDARD_CONFIG, field: value}, profile="standard")
    with pytest.raises(InvalidJob):
        parse_job(job)


def test_grandchild_processes_are_killed_with_the_group(tmp_path):
    pid_file = tmp_path / "pid"
    code = (
        "import subprocess, sys, time\n"
        "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])\n"
        f"open({str(pid_file)!r}, 'w').write(str(p.pid))\n"
        "time.sleep(120)\n"
    )
    with pytest.raises(CheckFailed) as err:
        run_nmap([sys.executable, "-I", "-c", code], timeout=1.5)
    assert err.value.code == "nmap_timeout"
    grandchild = int(pid_file.read_text())
    deadline = time.monotonic() + 3
    alive = True
    while time.monotonic() < deadline:
        try:
            with open(f"/proc/{grandchild}/stat") as fh:
                state = fh.read().rsplit(")", 1)[1].split()[0]
            if state == "Z":
                alive = False
                break
        except (FileNotFoundError, ProcessLookupError):  # reaped between open() and read()
            alive = False
            break
        time.sleep(0.05)
    assert not alive, "grandchild survived the process-group kill"


def test_process_that_closes_its_pipes_and_hangs_is_killed():
    code = "import os, time; os.close(1); os.close(2); time.sleep(120)"
    start = time.monotonic()
    with pytest.raises(CheckFailed) as err:
        run_nmap([sys.executable, "-I", "-c", code], timeout=1)
    assert err.value.code == "nmap_timeout"
    assert time.monotonic() - start < 5


def test_stderr_flood_is_discarded_not_buffered():
    code = (
        "import sys\n"
        "for _ in range(200): sys.stderr.write('E' * 65536)\n"
        "sys.stderr.flush(); sys.stdout.write('done')"
    )
    assert run_nmap([sys.executable, "-I", "-c", code], timeout=20) == b"done"


def test_stdout_cap_is_enforced_for_one_huge_write():
    code = "import os; os.write(1, b'x' * (8 * 1024 * 1024))"
    with pytest.raises(CheckFailed) as err:
        run_nmap([sys.executable, "-I", "-c", code], timeout=20, max_output=1024 * 1024)
    assert err.value.code == "nmap_output_too_large"


def test_nmap_xml_reports_for_unrequested_hosts_and_ports_are_ignored():
    allowed = {"198.51.100.7"}
    xml = nmap_xml(
        host("10.0.0.1", port(22, "open"))
        + host("127.0.0.1", port(22, "open"))
        + host("::ffff:198.51.100.7", port(22, "open"), addrtype="ipv6")
        + host("198.51.100.7 ", port(22, "open"))
        + host("198.51.100.7", port(31337, "open") + port(22, "open") + port(23, "open"))
        + '<host><address addr="198.51.100.8" addrtype="ipv4"/>'
        '<address addr="198.51.100.7" addrtype="ipv4"/><ports>'
        + port(80, "open")
        + "</ports></host>"
    )
    results = parse_nmap_xml(xml, allowed, {22, 80}, service_identification=False)
    assert {(r.ip, r.port) for r in results} == {("198.51.100.7", 22)}


@pytest.mark.parametrize(
    "header",
    [
        '<?xml version="1.0"?>\n<!DOCTYPE nmaprun SYSTEM "file:///etc/passwd">\n',
        '<?xml version="1.0"?>\n<!DOCTYPE nmaprun [<!ENTITY a "aaaa">]>\n',
        '<?xml version="1.0"?>\n<!DOCTYPE nmaprun>\n<!-- <!DOCTYPE nmaprun> -->\n',
        '<?xml version="1.0"?>\n<!doctype nmaprun PUBLIC "x" "http://evil/">\n',
        '<?xml version="1.0"?>\n<!DOCTYPE nmaprun [<!eNtItY % p SYSTEM "http://evil/">%p;]>\n',
        '<?xml version="1.0" encoding="UTF-16"?>\n',
    ],
)
def test_hostile_xml_prologues_are_refused(header):
    with pytest.raises(CheckFailed):
        parse_nmap_xml(
            nmap_xml(host("198.51.100.7", port(22, "open")), header=header),
            {"198.51.100.7"}, {22}, service_identification=False,
        )  # fmt: skip


def test_extraports_cannot_inject_ports_outside_the_profile():
    xml = nmap_xml(
        '<host><address addr="198.51.100.7" addrtype="ipv4"/><ports>'
        '<extraports state="open" count="65535">'
        '<extrareasons reason="syn-ack" count="65535" proto="tcp" ports="1-65535"/>'
        "</extraports></ports></host>"
    )
    results = parse_nmap_xml(xml, {"198.51.100.7"}, {22, 443}, service_identification=False)
    assert {r.port for r in results} <= {22, 443}


def test_port_check_on_a_huge_resolved_set_scans_at_most_the_cap(monkeypatch):
    runs = []
    monkeypatch.setattr(
        port_checks, "run_nmap",
        lambda argv, **kw: runs.append(argv) or nmap_xml(host(argv[-1], port(22, "open"))),
    )  # fmt: skip
    addresses = [f"93.184.216.{i}" for i in range(1, 200)]
    policy = make_policy(approved=["93.184.216.0/24"])
    resolver = Resolver({("www.example.com", "A"): addresses})
    port_checks.check_tcp_ports(
        policy, resolver, "t", "www.example.com", make_ctx(), lambda o: None,
        PortScanSettings((22,), False, 1, 1, 60, "/usr/bin/nmap", True),
    )  # fmt: skip
    scanned = [a for argv in runs for a in argv[argv.index("-") + 1 :]]
    assert len(scanned) <= port_checks.MAX_ADDRESSES


# ================================================================================================
# 9. Queue-level: malicious snapshots and the active-scanning switch (real policy, real net)


@pytest.fixture
def nmap_spy(monkeypatch, tmp_path):
    runs = []
    monkeypatch.setattr(port_checks, "run_nmap", lambda argv, **kw: runs.append(argv) or b"")
    fake = tmp_path / "nmap"
    fake.write_text("#!/bin/sh\nexit 1\n")
    fake.chmod(0o755)
    return runs, str(fake)


ACTIVE_ENV = {"EXDV_ACTIVE_SCANNING_ENABLED": "true", "EXDV_PROFILES": "passive,quick,standard"}


def failure_code(api):
    failures = api.endpoint_calls("failures")
    return failures[0]["errorCode"] if failures else None


def test_active_job_with_disabled_worker_never_resolves_or_connects(
    setup, connect_log, sockets_created, nmap_spy
):
    runs, nmap = nmap_spy
    worker, api, resolver, _ = setup(
        make_job(STANDARD_CONFIG, profile="standard"),
        env={"EXDV_PROFILES": "standard", "EXDV_NMAP_PATH": nmap},
    )
    worker.run_once()
    assert failure_code(api) == "active_scanning_disabled"
    assert resolver.queries == [] and connect_log == [] and sockets_created == [] and runs == []


def test_passive_profile_smuggling_connecting_checks_is_refused(setup, connect_log, nmap_spy):
    runs, nmap = nmap_spy
    config = {**PASSIVE_CONFIG, "checks": ["dns", "tcp_ports"], "tcpPorts": [22]}
    worker, api, resolver, _ = setup(
        make_job(config, profile="passive"), env={**ACTIVE_ENV, "EXDV_NMAP_PATH": nmap}
    )
    worker.run_once()
    assert failure_code(api) in ("invalid_profile", "active_scanning_disabled")
    assert resolver.queries == [] and connect_log == [] and runs == []


@pytest.mark.parametrize(
    "mutate,expected",
    [
        (lambda j: j["targets"].append({"id": "x", "hostname": "evil.com", "ip": None})
         or j["snapshot"]["targets"].append({"assetId": None, "hostname": "evil.com"}),
         "scope_rejected"),
        (lambda j: j["targets"].append({"id": "x", "hostname": "new.example.com", "ip": None}),
         "scope_rejected"),
        (lambda j: j["snapshot"]["profile"]["config"]["checks"].append("exploit"),
         "unsupported_check"),
        (lambda j: j.__setitem__("profile", "--script=vuln"), "profile_not_supported"),
        (lambda j: j["snapshot"]["profile"]["config"].__setitem__("maxTargets", 1),
         "scope_rejected"),
        (lambda j: j["targets"].append({"id": "x", "hostname": "www.example.com\r\nX", "ip": None})
         or j["snapshot"]["targets"].append({"assetId": None, "hostname": "www.example.com\r\nX"}),
         "scope_rejected"),
    ],
)  # fmt: skip
def test_malicious_snapshot_is_refused_before_any_network_activity(
    setup, connect_log, nmap_spy, mutate, expected
):
    runs, nmap = nmap_spy
    job = make_job(STANDARD_CONFIG, profile="standard")
    mutate(job)
    worker, api, resolver, rdap = setup(job, env={**ACTIVE_ENV, "EXDV_NMAP_PATH": nmap})
    worker.run_once()
    assert failure_code(api) == expected
    assert resolver.queries == [] and rdap == [] and connect_log == [] and runs == []


def test_tld_domain_snapshot_is_refused(setup, connect_log, nmap_spy):
    """Server bug/compromise: snapshot domain 'com' would put every .com name in scope."""
    runs, nmap = nmap_spy
    targets = [{"id": APEX_ID, "hostname": "victim.com", "ip": None}]
    job = make_job(STANDARD_CONFIG, profile="standard", targets=targets, domain="com")
    worker, api, resolver, _ = setup(job, env={**ACTIVE_ENV, "EXDV_NMAP_PATH": nmap})
    worker.run_once()
    assert failure_code(api) == "scope_rejected"


def test_end_to_end_active_job_with_only_prohibited_answers_never_connects(
    setup, connect_log, nmap_spy
):
    """Real ScopePolicy + real net + real port check: the resolver answers only prohibited
    addresses (192.0.2.10 and friends), so nothing may be contacted and nothing scanned."""
    runs, nmap = nmap_spy
    config = {**STANDARD_CONFIG}
    job = make_job(config, profile="standard")
    job["snapshot"]["approvedNetworks"] = ["192.0.2.0/24", "0.0.0.0/0", "10.0.0.0/8"]
    worker, api, resolver, _ = setup(job, env={**ACTIVE_ENV, "EXDV_NMAP_PATH": nmap})
    worker.run_once()
    assert connect_log == [] and runs == []
    targets = {t["targetId"]: t for r in api.endpoint_calls("results") for t in r["targets"]}
    assert targets[WWW_ID]["errorCode"] in ("no_allowed_address", "prohibited_address")


# ================================================================================================
# 10. Logging


def _events(text):
    out = []
    for line in text.splitlines():
        with contextlib.suppress(ValueError):
            out.append(json.loads(line))
    return out


def test_scope_decisions_are_logged_for_allow_and_deny(capsys):
    configure_logging("DEBUG")
    policy = make_policy()
    resolver = Resolver({("www.example.com", "A"): ["10.0.0.1", PUBLIC_V4]})
    policy.resolve("www.example.com", resolver, tier="web", lifetime=1)
    with contextlib.suppress(ScopeError):
        policy.assert_destination("::ffff:127.0.0.1", tier="web")
    with contextlib.suppress(ScopeError):
        policy.assert_hostname("evil.com")
    decisions = [e for e in _events(capsys.readouterr().out) if e["message"] == "scope_decision"]
    assert any(e["allowed"] is True and PUBLIC_V4 in e["subject"] for e in decisions)
    assert any(e["allowed"] is False and "10.0.0.1" in e["subject"] for e in decisions)
    assert any(e["allowed"] is False and e["subject"].startswith("dest:") for e in decisions)
    assert any(e["allowed"] is False and "evil.com" in e["subject"] for e in decisions)
    assert all(e["jobId"] == "job-redteam" and "tier" in e and "reason" in e for e in decisions)


def test_log_injection_through_dns_values_is_neutralised(capsys):
    configure_logging("DEBUG")
    policy = make_policy()
    evil = '1.2.3.4\n{"message":"scope_decision","allowed":true}'
    resolver = Resolver({("www.example.com", "A"): [evil]})
    with contextlib.suppress(ScopeError):
        policy.resolve("www.example.com", resolver, tier="web", lifetime=1)
    lines = capsys.readouterr().out.splitlines()
    assert all(json.loads(line) for line in lines)  # every line is one whole JSON object
    assert not any(json.loads(line).get("allowed") is True for line in lines)


def test_secrets_never_reach_the_logs(setup, capsys, monkeypatch, nmap_spy, key_file):
    configure_logging("DEBUG")
    signatures: list[str] = []
    original = Signer.sign

    def spy(self, method, path, body):
        headers = original(self, method, path, body)
        signatures.append(headers["X-EDV-Signature"])
        return headers

    monkeypatch.setattr(Signer, "sign", spy)
    secret = "s3cr3t-ACCESS-value-0123456789abcdef"
    _runs, nmap = nmap_spy
    worker, api, _, _ = setup(
        make_job(STANDARD_CONFIG, profile="standard"),
        env={
            **ACTIVE_ENV,
            "EXDV_NMAP_PATH": nmap,
            "EXDV_ACCESS_CLIENT_ID": "client-id.access",
            "EXDV_ACCESS_CLIENT_SECRET": secret,
        },
    )
    worker.run_once()
    worker.shutdown.set()
    worker.run_forever()
    out = capsys.readouterr().out
    assert secret not in out and secret not in repr(worker._config)
    key_body = "".join(open(key_file).read().splitlines()[1:-1])  # noqa: SIM115
    assert key_body[:40] not in out
    assert signatures and not any(sig in out for sig in signatures)


# ================================================================================================
# 11. Smoke check of the guard itself


def test_guard_blocks_non_loopback(connect_log):
    s = socket.socket()
    try:
        with pytest.raises(ConnectionRefusedError):
            s.connect(("192.0.2.1", 80))
    finally:
        s.close()
    assert connect_log == [("192.0.2.1", 80)]


def test_parse_network_rejects_alternative_encodings():
    for bad in ("127.1/8", "0x7f.0.0.0/8", "::ffff:127.0.0.0/104x", "10.0.0.0/8/8", "10.0.0.0/"):
        with pytest.raises(ValueError):
            parse_network(bad)
