"""Pinned network primitives. No live third-party systems: name resolution is a fake resolver, and
connections go either to a mocked socket layer or to a throwaway server bound to 127.0.0.1.

Reaching that loopback server needs the scope validator to permit 127.0.0.1, which production code
never does (there is no flag for it). The ``allow_test_loopback`` fixture replaces
``app.policy.address_prohibited_reason`` via ``monkeypatch`` for this single address only, for the
duration of one test.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import ipaddress
import socket
import ssl
import threading
import time
from collections.abc import Callable

import dns.exception
import dns.resolver
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app import net
from app import policy as policy_module
from app.dns_checks import DnsAnswer
from app.net import (
    MAX_BODY_BYTES,
    MAX_HEADER_BYTES,
    MAX_REDIRECTS,
    connect_tcp,
    http_get,
    tls_handshake,
)
from app.policy import AddressRefused, ScopeError, ScopePolicy

LOOPBACK = ipaddress.IPv4Address("127.0.0.1")
PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:4700:4700::1111"


def make_policy(
    *, active: bool = True, approved=(), deny=(), targets=("www.example.com",)
) -> ScopePolicy:
    return ScopePolicy.from_job(
        job_id="job-net",
        snapshot={
            "domain": {"fqdn": "example.com"},
            "profile": {"config": {"checks": ["http_headers", "tls_certificate", "tcp_ports"]}},
            "approvedNetworks": list(approved),
        },
        target_hostnames=list(targets),
        deny_networks=list(deny),
        active_scanning_enabled=active,
    )


class FakeResolver:
    def __init__(self, records: dict[tuple[str, str], object]) -> None:
        self.records = records
        self.calls: list[tuple[str, str]] = []

    def query(self, name: str, rdtype: str, lifetime: float) -> DnsAnswer:
        self.calls.append((name, rdtype))
        value = self.records.get((name, rdtype), [])
        if isinstance(value, Exception):
            raise value
        return DnsAnswer(ttl=60, values=list(value), canonical_name=name)  # type: ignore[arg-type]


def zone(**hosts: str) -> FakeResolver:
    """zone(www="127.0.0.1") -> www.example.com A 127.0.0.1."""
    records: dict[tuple[str, str], object] = {}
    for label, address in hosts.items():
        name = "example.com" if label == "apex" else f"{label}.example.com"
        rdtype = "AAAA" if ":" in address else "A"
        records[(name, rdtype)] = [address]
    return FakeResolver(records)


@pytest.fixture
def allow_test_loopback(monkeypatch):
    original = policy_module.address_prohibited_reason

    def patched(address):
        if address == LOOPBACK:
            return None
        return original(address)

    monkeypatch.setattr(policy_module, "address_prohibited_reason", patched)


class ConnectSpy:
    """Replaces socket.socket.connect: records destinations and refuses the connection."""

    def __init__(self, monkeypatch, exc: type[OSError] = ConnectionRefusedError) -> None:
        self.addresses: list[tuple] = []
        spy = self

        def fake_connect(sock, address):
            spy.addresses.append(address)
            raise exc("refused by test")

        monkeypatch.setattr(socket.socket, "connect", fake_connect)


# ------------------------------------------------------------------------------------------------
# Local test server


Handler = Callable[[socket.socket, bytes], None]


class LocalServer:
    def __init__(
        self, handler: Handler, tls: ssl.SSLContext | None = None, *, read_request: bool = True
    ) -> None:
        self.handler = handler
        self.tls = tls
        self.read_request = read_request
        self.requests: list[bytes] = []
        self.connections = 0
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self._sock.settimeout(0.1)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def url(self, path: str = "/", host: str = "www.example.com", scheme: str = "http") -> str:
        return f"{scheme}://{host}:{self.port}{path}"

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except (TimeoutError, OSError):
                continue
            self.connections += 1
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(5)
            if self.tls is not None:
                conn = self.tls.wrap_socket(conn, server_side=True)
            data = b""
            if not self.read_request:
                self.handler(conn, data)
                return
            while b"\r\n\r\n" not in data and len(data) < 65536:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            if not data:
                return
            self.requests.append(data)
            self.handler(conn, data)
        except Exception:  # noqa: S110 - test server: client-side behaviour is under test
            pass
        finally:
            with contextlib.suppress(OSError):
                conn.close()

    def close(self) -> None:
        self._stop.set()
        self._sock.close()
        self._thread.join(timeout=2)


@pytest.fixture
def server_factory():
    servers: list[LocalServer] = []

    def make(
        handler: Handler, tls: ssl.SSLContext | None = None, *, read_request: bool = True
    ) -> LocalServer:
        server = LocalServer(handler, tls, read_request=read_request)
        servers.append(server)
        return server

    yield make
    for server in servers:
        server.close()


def respond(status: int = 200, headers: dict[str, str] | None = None, body: bytes = b"ok"):
    def handler(conn: socket.socket, _request: bytes) -> None:
        lines = [f"HTTP/1.1 {status} X"]
        for key, value in (headers or {}).items():
            lines.append(f"{key}: {value}")
        lines.append(f"Content-Length: {len(body)}")
        conn.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body)

    return handler


def request_path(request: bytes) -> str:
    return request.split(b"\r\n", 1)[0].split(b" ")[1].decode()


# ------------------------------------------------------------------------------------------------
# Certificates


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    directory = tmp_path_factory.mktemp("pki")
    now = dt.datetime.now(dt.UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(_name("ExDV Test CA"))
        .issuer_name(_name("ExDV Test CA"))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = directory / "ca.pem"
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    def leaf(dns_name: str) -> tuple[str, str, bytes]:
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (
            x509.CertificateBuilder()
            .subject_name(_name(dns_name))
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=10))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(dns_name)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        cert_path = directory / f"{dns_name}.pem"
        key_path = directory / f"{dns_name}.key"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        return str(cert_path), str(key_path), cert.public_bytes(serialization.Encoding.DER)

    return {"ca": str(ca_path), "leaf": leaf}


def server_tls(pki, dns_name: str = "www.example.com") -> tuple[ssl.SSLContext, bytes]:
    cert_path, key_path, der = pki["leaf"](dns_name)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    return ctx, der


@pytest.fixture
def trust_test_ca(monkeypatch, pki):
    def verifying() -> ssl.SSLContext:
        return ssl.create_default_context(cafile=pki["ca"])

    monkeypatch.setattr(net, "_verifying_context", verifying)


# ------------------------------------------------------------------------------------------------
# connect_tcp


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "10.0.0.1", "::1", "::ffff:127.0.0.1", "169.254.169.254", "0x7f.0.0.1", "127.1"],
)
def test_connect_tcp_refuses_before_creating_a_socket(monkeypatch, address):
    def no_socket(*_args, **_kwargs):
        raise AssertionError("socket must not be created")

    monkeypatch.setattr(socket, "socket", no_socket)
    with pytest.raises(AddressRefused):
        connect_tcp(make_policy(), address, 443, timeout=1, tier="web")


def test_connect_tcp_refuses_when_active_scanning_disabled(monkeypatch):
    spy = ConnectSpy(monkeypatch)
    with pytest.raises(ScopeError) as err:
        connect_tcp(make_policy(active=False), PUBLIC_V4, 443, timeout=1, tier="web")
    assert err.value.code == "active_scanning_disabled"
    assert spy.addresses == []


def test_connect_tcp_network_tier_needs_approved_network(monkeypatch):
    spy = ConnectSpy(monkeypatch)
    with pytest.raises(AddressRefused) as err:
        connect_tcp(make_policy(), PUBLIC_V4, 22, timeout=1, tier="network")
    assert err.value.code == "network_not_approved"
    with pytest.raises(ConnectionRefusedError):
        connect_tcp(
            make_policy(approved=["93.184.216.0/24"]), PUBLIC_V4, 22, timeout=1, tier="network"
        )
    assert spy.addresses == [(PUBLIC_V4, 22)]


@pytest.mark.parametrize("port", [0, -1, 65536, True, "443", 1.5])
def test_connect_tcp_validates_port(monkeypatch, port):
    spy = ConnectSpy(monkeypatch)
    with pytest.raises(ValueError):
        connect_tcp(make_policy(), PUBLIC_V4, port, timeout=1, tier="web")  # type: ignore[arg-type]
    assert spy.addresses == []


@pytest.mark.parametrize("timeout", [0, -1, None, True])
def test_connect_tcp_validates_timeout(monkeypatch, timeout):
    ConnectSpy(monkeypatch)
    with pytest.raises(ValueError):
        connect_tcp(make_policy(), PUBLIC_V4, 443, timeout=timeout, tier="web")  # type: ignore[arg-type]


def test_connect_tcp_connects_to_exact_literal_address(monkeypatch):
    spy = ConnectSpy(monkeypatch)
    timeouts: list[float | None] = []
    real_settimeout = socket.socket.settimeout
    monkeypatch.setattr(
        socket.socket, "settimeout", lambda s, v: (timeouts.append(v), real_settimeout(s, v))[1]
    )
    for address in (PUBLIC_V4, PUBLIC_V6, ipaddress.ip_address(PUBLIC_V4)):
        with pytest.raises(ConnectionRefusedError):
            connect_tcp(make_policy(), address, 8443, timeout=2.5, tier="web")
    assert spy.addresses == [(PUBLIC_V4, 8443), (PUBLIC_V6, 8443, 0, 0), (PUBLIC_V4, 8443)]
    assert timeouts == [2.5, 2.5, 2.5]


def test_connect_tcp_caps_timeout(monkeypatch):
    ConnectSpy(monkeypatch)
    timeouts: list[float] = []
    real_settimeout = socket.socket.settimeout
    monkeypatch.setattr(
        socket.socket, "settimeout", lambda s, v: (timeouts.append(v), real_settimeout(s, v))[1]
    )
    with pytest.raises(ConnectionRefusedError):
        connect_tcp(make_policy(), PUBLIC_V4, 443, timeout=10_000, tier="web")
    assert timeouts == [net.MAX_TIMEOUT_SECONDS]


def test_connect_tcp_does_no_name_resolution(monkeypatch):
    def no_dns(*_args, **_kwargs):
        raise AssertionError("no name resolution in net")

    monkeypatch.setattr(socket, "getaddrinfo", no_dns)
    monkeypatch.setattr(socket, "gethostbyname", no_dns)
    ConnectSpy(monkeypatch)
    with pytest.raises(ConnectionRefusedError):
        connect_tcp(make_policy(), PUBLIC_V4, 443, timeout=1, tier="web")


# ------------------------------------------------------------------------------------------------
# DNS rebinding / pinning


class FlippingResolver(FakeResolver):
    """Answers public on the first A query and private (loopback / metadata) afterwards."""

    def __init__(self, later: str = "127.0.0.1") -> None:
        super().__init__({})
        self.later = later
        self.a_queries = 0

    def query(self, name: str, rdtype: str, lifetime: float) -> DnsAnswer:
        self.calls.append((name, rdtype))
        if rdtype == "A":
            self.a_queries += 1
            value = PUBLIC_V4 if self.a_queries == 1 else self.later
            return DnsAnswer(ttl=0, values=[value], canonical_name=name)
        return DnsAnswer(ttl=0, values=[], canonical_name=name)


@pytest.mark.parametrize("later", ["127.0.0.1", "169.254.169.254", "10.0.0.1"])
def test_rebinding_connection_uses_pinned_validated_address(monkeypatch, later):
    def no_dns(*_args, **_kwargs):
        raise AssertionError("net must not re-resolve")

    monkeypatch.setattr(socket, "getaddrinfo", no_dns)
    spy = ConnectSpy(monkeypatch)
    resolver = FlippingResolver(later)
    result = http_get(make_policy(), "http://www.example.com/", resolver, timeout=1)
    # Exactly one A resolution; the connection went to the address validated by that resolution.
    assert resolver.a_queries == 1
    assert spy.addresses == [(PUBLIC_V4, 80)]
    assert result.first.address == ipaddress.ip_address(PUBLIC_V4)
    assert result.first.decision == "error"
    assert result.first.error == "connection_refused"
    # The resolver now answers private: the next resolution has nothing allowed, and passing the
    # private address straight to the primitives is refused before any socket call.
    with pytest.raises(ScopeError) as err:
        make_policy().resolve("www.example.com", resolver, tier="web", lifetime=1)
    assert err.value.code == "no_allowed_address"
    with pytest.raises(AddressRefused):
        connect_tcp(make_policy(), later, 80, timeout=1, tier="web")
    with pytest.raises(AddressRefused):
        tls_handshake(make_policy(), "www.example.com", later, 443, timeout=1)
    assert spy.addresses == [(PUBLIC_V4, 80)]


def test_https_default_port_and_pinning(monkeypatch):
    spy = ConnectSpy(monkeypatch)
    result = http_get(make_policy(), "https://www.example.com/x", zone(www=PUBLIC_V6), timeout=1)
    assert spy.addresses == [(PUBLIC_V6, 443, 0, 0)]
    assert result.first.decision == "error"


def test_redirect_hop_is_resolved_and_pinned_separately(
    monkeypatch, server_factory, allow_test_loopback
):
    """Hop 1 is served locally; hop 2 (another in-scope name) resolves to a public address and is
    connected to that pinned address only."""
    server = server_factory(respond(302, {"Location": "http://api.example.com/next"}))
    real_connect = socket.socket.connect
    seen: list[tuple] = []

    def connect(sock, address):
        seen.append(address)
        if address[0] == "127.0.0.1":
            return real_connect(sock, address)
        raise ConnectionRefusedError("test")

    monkeypatch.setattr(socket.socket, "connect", connect)
    resolver = zone(www="127.0.0.1", api=PUBLIC_V4)
    policy = make_policy(targets=("www.example.com", "api.example.com"))
    result = http_get(policy, server.url(), resolver, timeout=2)
    assert [h.decision for h in result.hops] == ["followed", "error"]
    assert seen == [("127.0.0.1", server.port), (PUBLIC_V4, 80)]
    assert result.last.address == ipaddress.ip_address(PUBLIC_V4)


# ------------------------------------------------------------------------------------------------
# http_get against the local server


def test_http_get_final_response(server_factory, allow_test_loopback):
    server = server_factory(
        respond(
            200,
            {
                "Strict-Transport-Security": "max-age=63072000",
                "X-Frame-Options": "DENY",
                "Set-Cookie": "a=1",
                "set-cookie": "b=2",
                "Server": "test\x01server",
            },
            b"hello",
        )
    )
    result = http_get(make_policy(), server.url("/path?q=1"), zone(www="127.0.0.1"), timeout=2)
    assert len(result.hops) == 1
    hop = result.first
    assert hop.decision == "final"
    assert hop.status == 200
    assert hop.address == LOOPBACK
    assert hop.headers["strict-transport-security"] == "max-age=63072000"
    assert hop.headers["x-frame-options"] == "DENY"
    assert hop.headers["set-cookie"] == "a=1, b=2"
    assert hop.headers["server"] == "testserver"  # control characters stripped
    assert hop.body_bytes == 5
    request = server.requests[0].decode()
    assert request.startswith("GET /path?q=1 HTTP/1.1\r\n")
    assert f"\r\nHost: www.example.com:{server.port}\r\n" in request
    assert "\r\nConnection: close\r\n" in request


def test_http_get_relative_redirects(server_factory, allow_test_loopback):
    def handler(conn, request):
        path = request_path(request)
        if path == "/":
            respond(301, {"Location": "/a/b"})(conn, request)
        elif path == "/a/b":
            respond(302, {"Location": "../c?x=1#frag"})(conn, request)
        else:
            respond(200)(conn, request)

    server = server_factory(handler)
    result = http_get(make_policy(), server.url("/"), zone(www="127.0.0.1"), timeout=2)
    assert [h.decision for h in result.hops] == ["followed", "followed", "final"]
    assert [h.status for h in result.hops] == [301, 302, 200]
    assert result.last.url == server.url("/c?x=1")
    assert [request_path(r) for r in server.requests] == ["/", "/a/b", "/c?x=1"]


@pytest.mark.parametrize(
    "location",
    [
        "http://10.0.0.1/",
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://169.254.169.254/latest/meta-data/",
        "http://0x7f000001/",
        "http://2130706433/",
    ],
)
def test_redirect_to_ip_literal_is_refused_without_connecting(
    server_factory, allow_test_loopback, location
):
    server = server_factory(respond(302, {"Location": location}))
    result = http_get(make_policy(), server.url(), zone(www="127.0.0.1"), timeout=2)
    assert result.first.decision == "followed"
    assert result.last.address is None
    assert result.last.decision in ("redirect_out_of_scope", "invalid_url")
    assert server.connections == 1


@pytest.mark.parametrize("private", ["10.0.0.1", "192.168.1.1", "::ffff:127.0.0.1", "fd00::1"])
def test_redirect_to_in_scope_name_resolving_private(
    server_factory, allow_test_loopback, monkeypatch, private
):
    server = server_factory(respond(302, {"Location": "http://internal.example.com/"}))
    policy = make_policy(targets=("www.example.com", "internal.example.com"))
    result = http_get(policy, server.url(), zone(www="127.0.0.1", internal=private), timeout=2)
    assert [h.decision for h in result.hops] == ["followed", "no_allowed_address"]
    assert result.last.address is None
    assert server.connections == 1


def test_redirect_to_unapproved_in_domain_host_is_not_resolved(server_factory, allow_test_loopback):
    server = server_factory(respond(302, {"Location": "http://pending.example.com/"}))
    resolver = zone(www="127.0.0.1", pending="127.0.0.1")
    result = http_get(make_policy(), server.url(), resolver, timeout=2)
    assert [h.decision for h in result.hops] == ["followed", "redirect_not_approved_target"]
    assert result.last.address is None
    assert ("pending.example.com", "A") not in resolver.calls
    assert server.connections == 1


def test_snapshot_targets_are_approved_redirect_hosts(server_factory, allow_test_loopback):
    policy = ScopePolicy.from_job(
        job_id="j",
        snapshot={
            "domain": {"fqdn": "example.com"},
            "profile": {"config": {"checks": ["http_headers"]}},
            "targets": [{"hostname": "www.example.com"}, {"hostname": "API.example.com."}],
        },
        target_hostnames=["www.example.com"],
        deny_networks=[],
        active_scanning_enabled=True,
    )
    assert policy.target_hostnames == ("www.example.com", "api.example.com")


@pytest.mark.parametrize(
    ("location", "decision"),
    [
        ("http://www.example.com:8080/", "port_not_allowed"),
        ("https://www.example.com:80/", "port_not_allowed"),
        ("http://www.example.com:443/", "port_not_allowed"),
        ("http://www.example.com:22/", "port_not_allowed"),
    ],
)
def test_redirect_to_other_ports_is_refused(
    server_factory, allow_test_loopback, location, decision
):
    server = server_factory(respond(302, {"Location": location}))
    result = http_get(make_policy(), server.url(), zone(www="127.0.0.1"), timeout=2)
    assert [h.decision for h in result.hops] == ["followed", decision]
    assert result.last.address is None
    assert server.connections == 1


def test_redirect_to_default_port_and_original_port_is_followed(
    monkeypatch, server_factory, allow_test_loopback
):
    seen: list[tuple] = []
    real_connect = socket.socket.connect

    def connect(sock, address):
        seen.append(address)
        if address[0] == "127.0.0.1" and address[1] != 443:
            return real_connect(sock, address)
        raise ConnectionRefusedError("test")

    def handler(conn, request):
        if request_path(request) == "/":
            respond(302, {"Location": f"http://www.example.com:{server.port}/same"})(conn, request)
        else:
            respond(302, {"Location": "https://www.example.com/"})(conn, request)

    server = server_factory(handler)
    monkeypatch.setattr(socket.socket, "connect", connect)
    result = http_get(make_policy(), server.url(), zone(www="127.0.0.1"), timeout=2)
    assert [h.decision for h in result.hops] == ["followed", "followed", "error"]
    assert seen[-1] == ("127.0.0.1", 443)


def test_http_get_stops_between_hops(server_factory, allow_test_loopback):
    server = server_factory(respond(302, {"Location": "/next"}))
    calls = []

    def should_stop():
        calls.append(1)
        return len(calls) > 1

    result = http_get(
        make_policy(), server.url(), zone(www="127.0.0.1"), timeout=2, should_stop=should_stop
    )
    assert [h.decision for h in result.hops] == ["followed", "stopped"]
    assert server.connections == 1


def test_http_get_respects_the_caller_deadline(server_factory, allow_test_loopback):
    server = server_factory(respond(302, {"Location": "/next"}))
    result = http_get(
        make_policy(), server.url(), zone(www="127.0.0.1"), timeout=2,
        deadline=time.monotonic() - 1,
    )  # fmt: skip
    assert result.last.decision == "error" and result.last.error == "timeout"
    assert server.connections == 0


@pytest.mark.parametrize(
    "location",
    [
        "https://evil-example.com/",
        "https://example.com.evil.net/",
        "//attacker.net/x",
        "https://www.example.com@attacker.net/",
        "https://xn--exmple-cua.com/",
    ],
)
def test_redirect_out_of_scope_host(server_factory, allow_test_loopback, location):
    server = server_factory(respond(301, {"Location": location}))
    resolver = zone(www="127.0.0.1")
    result = http_get(make_policy(), server.url(), resolver, timeout=2)
    assert result.last.address is None
    assert result.last.status is None
    assert result.last.decision in ("redirect_out_of_scope", "invalid_url")
    assert server.connections == 1
    assert all(name.endswith("example.com") for name, _ in resolver.calls)


def test_redirect_out_of_scope_records_decision(server_factory, allow_test_loopback):
    server = server_factory(respond(301, {"Location": "https://cdn.attacker.net/x"}))
    result = http_get(make_policy(), server.url(), zone(www="127.0.0.1"), timeout=2)
    assert [h.decision for h in result.hops] == ["followed", "redirect_out_of_scope"]
    assert result.last.url == "https://cdn.attacker.net/x"


@pytest.mark.parametrize(
    "location",
    [
        "ftp://www.example.com/file",
        "javascript:alert(1)",
        "file:///etc/passwd",
        "data:text/html,hi",
        "gopher://www.example.com/",
        "ws://www.example.com/",
    ],
)
def test_redirect_scheme_not_allowed(server_factory, allow_test_loopback, location):
    server = server_factory(respond(302, {"Location": location}))
    result = http_get(make_policy(), server.url(), zone(www="127.0.0.1"), timeout=2)
    assert result.last.decision == "scheme_not_allowed"
    assert result.last.address is None
    assert server.connections == 1


@pytest.mark.parametrize(
    "location",
    [
        "/a b",
        "/café",
        "http://www.example.com:0/",
        "http://www.example.com:65536/",
        "http://www.example.com:080/",
        "http://www.example.com:/",
        "http://user:pass@www.example.com/",
    ],
)
def test_redirect_invalid_url(server_factory, allow_test_loopback, location):
    def handler(conn, request):
        # Raw bytes: the Location may contain characters the helper would not encode.
        conn.sendall(
            b"HTTP/1.1 302 Found\r\nLocation: " + location.encode("utf-8") + b"\r\n"
            b"Content-Length: 0\r\n\r\n"
        )

    server = server_factory(handler)
    result = http_get(make_policy(), server.url(), zone(www="127.0.0.1"), timeout=2)
    assert result.last.address is None
    assert result.last.decision == "invalid_url"
    assert server.connections == 1


def test_redirect_loop_is_cut(server_factory, allow_test_loopback):
    server = server_factory(respond(302, {"Location": "/"}))
    result = http_get(make_policy(), server.url("/"), zone(www="127.0.0.1"), timeout=2)
    assert [h.decision for h in result.hops] == ["followed", "too_many_redirects"]
    assert server.connections == 1


def test_redirect_ping_pong_is_cut(server_factory, allow_test_loopback):
    def handler(conn, request):
        target = "/b" if request_path(request) == "/a" else "/a"
        respond(302, {"Location": target})(conn, request)

    server = server_factory(handler)
    result = http_get(make_policy(), server.url("/a"), zone(www="127.0.0.1"), timeout=2)
    assert [h.decision for h in result.hops] == ["followed", "followed", "too_many_redirects"]
    assert server.connections == 2


@pytest.mark.parametrize(("requested", "effective"), [(5, 5), (2, 2), (0, 0), (50, MAX_REDIRECTS)])
def test_redirect_cap(server_factory, allow_test_loopback, requested, effective):
    def handler(conn, request):
        n = int(request_path(request).strip("/") or 0)
        respond(302, {"Location": f"/{n + 1}"})(conn, request)

    server = server_factory(handler)
    result = http_get(
        make_policy(), server.url("/0"), zone(www="127.0.0.1"), timeout=2, max_redirects=requested
    )
    assert server.connections == effective + 1
    assert [h.decision for h in result.hops] == ["followed"] * (effective + 1) + [
        "too_many_redirects"
    ]
    assert result.last.address is None


def test_redirect_without_location_is_final(server_factory, allow_test_loopback):
    server = server_factory(respond(302, {}))
    result = http_get(make_policy(), server.url(), zone(www="127.0.0.1"), timeout=2)
    assert [h.decision for h in result.hops] == ["final"]
    assert result.first.status == 302


def test_oversized_headers_are_bounded(server_factory, allow_test_loopback):
    def handler(conn, _request):
        conn.sendall(b"HTTP/1.1 200 OK\r\n")
        filler = b"X-Fill: " + b"a" * 1000 + b"\r\n"
        try:
            for _ in range(2000):  # ~2 MB of headers, never terminated
                conn.sendall(filler)
        except OSError:
            pass

    server = server_factory(handler)
    started = time.monotonic()
    result = http_get(make_policy(), server.url(), zone(www="127.0.0.1"), timeout=2)
    assert time.monotonic() - started < 3
    assert result.first.decision == "error"
    assert result.first.error == "header_too_large"
    assert result.first.headers == {}


def test_header_block_exactly_at_limit_is_accepted(server_factory, allow_test_loopback):
    head = b"HTTP/1.1 200 OK\r\nX-Pad: "
    pad = MAX_HEADER_BYTES - len(head) - 4
    response = head + b"p" * pad + b"\r\n\r\n"

    server = server_factory(lambda conn, _r: conn.sendall(response))
    result = http_get(make_policy(), server.url(), zone(www="127.0.0.1"), timeout=2)
    assert result.first.decision == "final"
    assert len(result.first.headers["x-pad"]) == net.MAX_HEADER_VALUE


def test_header_count_is_bounded(server_factory, allow_test_loopback):
    headers = {f"X-H{i}": "v" for i in range(500)}
    server = server_factory(respond(200, headers))
    result = http_get(make_policy(), server.url(), zone(www="127.0.0.1"), timeout=2)
    assert len(result.first.headers) == net.MAX_HEADERS


@pytest.mark.parametrize(("limit", "expected"), [(1024, 1024), (10**9, MAX_BODY_BYTES), (0, 0)])
def test_body_is_bounded(server_factory, allow_test_loopback, limit, expected):
    def handler(conn, _request):
        conn.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
        try:
            for _ in range(256):  # 4 MB
                conn.sendall(b"b" * 16384)
        except OSError:
            pass

    server = server_factory(handler)
    result = http_get(
        make_policy(), server.url(), zone(www="127.0.0.1"), timeout=2, max_body_bytes=limit
    )
    assert result.first.decision == "final"
    assert result.first.body_bytes == expected


def test_no_response_times_out(server_factory, allow_test_loopback):
    def handler(_conn, _request):
        time.sleep(2)

    server = server_factory(handler)
    started = time.monotonic()
    result = http_get(make_policy(), server.url(), zone(www="127.0.0.1"), timeout=0.3)
    assert time.monotonic() - started < 1.5
    assert result.first.decision == "error"
    assert result.first.error == "timeout"


def test_slow_drip_headers_hit_the_hop_deadline(server_factory, allow_test_loopback):
    def handler(conn, _request):
        conn.sendall(b"HTTP/1.1 200 OK\r\n")
        try:
            for _ in range(100):
                conn.sendall(b"X: y\r\n")
                time.sleep(0.05)
        except OSError:
            pass

    server = server_factory(handler)
    started = time.monotonic()
    result = http_get(make_policy(), server.url(), zone(www="127.0.0.1"), timeout=0.3)
    assert time.monotonic() - started < 1.5
    assert result.first.error == "timeout"


def test_slow_drip_body_stops_at_deadline(server_factory, allow_test_loopback):
    def handler(conn, _request):
        conn.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
        try:
            for _ in range(200):
                conn.sendall(b"x")
                time.sleep(0.05)
        except OSError:
            pass

    server = server_factory(handler)
    started = time.monotonic()
    result = http_get(make_policy(), server.url(), zone(www="127.0.0.1"), timeout=0.3)
    assert time.monotonic() - started < 1.5
    assert result.first.decision == "final"
    assert 0 < result.first.body_bytes < 200


@pytest.mark.parametrize(
    "response",
    [
        b"garbage\r\n\r\n",
        b"HTTP/2 200\r\n\r\n",
        b"HTTP/1.1 99 X\r\n\r\n",
        b"HTTP/1.1 200\r\nBad\r\n\r\n",
    ],
)
def test_malformed_responses(server_factory, allow_test_loopback, response):
    server = server_factory(lambda conn, _r: conn.sendall(response))
    result = http_get(make_policy(), server.url(), zone(www="127.0.0.1"), timeout=2)
    assert result.first.decision == "error"
    assert result.first.status is None


def test_connection_closed_before_headers(server_factory, allow_test_loopback):
    server = server_factory(lambda conn, _r: conn.sendall(b"HTTP/1.1 200 OK\r\n"))
    result = http_get(make_policy(), server.url(), zone(www="127.0.0.1"), timeout=2)
    assert result.first.error == "incomplete_response"


def test_connection_refused(allow_test_loopback):
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    result = http_get(
        make_policy(), f"http://www.example.com:{port}/", zone(www="127.0.0.1"), timeout=1
    )
    assert result.first.decision == "error"
    assert result.first.error == "connection_refused"
    assert result.first.address == LOOPBACK


# ------------------------------------------------------------------------------------------------
# http_get: first-URL validation (no connection)


@pytest.mark.parametrize(
    ("url", "decision"),
    [
        ("ftp://www.example.com/", "scheme_not_allowed"),
        ("javascript:alert(1)", "scheme_not_allowed"),
        ("www.example.com/", "scheme_not_allowed"),
        ("http://evil-example.com/", "out_of_scope_host"),
        ("http://127.0.0.1/", "out_of_scope_host"),
        ("http://[::1]/", "invalid_url"),
        ("http://user@www.example.com/", "invalid_url"),
        ("http://www.example.com:0/", "invalid_url"),
        ("http://www.example.com:99999/", "invalid_url"),
        ("http://www.example.com/a b", "invalid_url"),
        ("http://www.example.com/\r\nHost: evil", "invalid_url"),
        ("http://www.example.com\x00.evil.net/", "invalid_url"),
        ("", "invalid_url"),
        ("http://www.example.com/" + "a" * 3000, "invalid_url"),
    ],
)
def test_http_get_refuses_bad_urls_without_connecting(monkeypatch, url, decision):
    spy = ConnectSpy(monkeypatch)
    resolver = zone(www=PUBLIC_V4)
    result = http_get(make_policy(), url, resolver, timeout=1)
    assert [h.decision for h in result.hops] == [decision]
    assert result.first.address is None
    assert spy.addresses == []


def test_http_get_trailing_dot_and_case_normalised(monkeypatch):
    spy = ConnectSpy(monkeypatch)
    resolver = zone(www=PUBLIC_V4)
    http_get(make_policy(), "HTTP://WWW.Example.COM./", resolver, timeout=1)
    assert spy.addresses == [(PUBLIC_V4, 80)]
    assert resolver.calls[0][0] == "www.example.com"


def test_http_get_active_scanning_disabled(monkeypatch):
    spy = ConnectSpy(monkeypatch)
    result = http_get(make_policy(active=False), "http://www.example.com/", zone(www=PUBLIC_V4),
                      timeout=1)  # fmt: skip
    assert result.first.decision == "active_scanning_disabled"
    assert spy.addresses == []


def test_http_get_deny_listed(monkeypatch):
    spy = ConnectSpy(monkeypatch)
    result = http_get(
        make_policy(deny=[PUBLIC_V4]), "http://www.example.com/", zone(www=PUBLIC_V4), timeout=1
    )
    assert result.first.decision == "no_allowed_address"
    assert spy.addresses == []


def test_http_get_cname_escape(monkeypatch):
    spy = ConnectSpy(monkeypatch)
    resolver = FakeResolver(
        {
            ("www.example.com", "CNAME"): ["victim.attacker.net."],
            ("victim.attacker.net", "A"): [PUBLIC_V4],
        }
    )
    result = http_get(make_policy(), "http://www.example.com/", resolver, timeout=1)
    assert result.first.decision == "cname_out_of_scope"
    assert spy.addresses == []


@pytest.mark.parametrize(
    ("exc", "detail"),
    [
        (dns.exception.Timeout(), "dns_timeout"),
        (dns.resolver.NXDOMAIN(), "nxdomain"),
        (dns.resolver.NoNameservers(), "dns_error: NoNameservers"),
    ],
)
def test_http_get_dns_failures(monkeypatch, exc, detail):
    spy = ConnectSpy(monkeypatch)
    resolver = FakeResolver({("www.example.com", "A"): exc})
    result = http_get(make_policy(), "http://www.example.com/", resolver, timeout=1)
    assert result.first.decision == "error"
    assert result.first.error == detail
    assert spy.addresses == []


# ------------------------------------------------------------------------------------------------
# TLS


def test_https_untrusted_certificate_is_an_error(server_factory, allow_test_loopback, pki):
    ctx, _der = server_tls(pki)
    server = server_factory(respond(200), tls=ctx)
    result = http_get(make_policy(), server.url(scheme="https"), zone(www="127.0.0.1"), timeout=2)
    assert result.first.decision == "error"
    assert result.first.address == LOOPBACK
    assert result.first.error.startswith("certificate_verify_failed")
    assert server.requests == []  # no request was sent over an unverified connection


def test_https_trusted_certificate(server_factory, allow_test_loopback, trust_test_ca, pki):
    ctx, _der = server_tls(pki)
    server = server_factory(respond(200, {"Strict-Transport-Security": "max-age=1"}), tls=ctx)
    result = http_get(make_policy(), server.url(scheme="https"), zone(www="127.0.0.1"), timeout=2)
    assert result.first.decision == "final"
    assert result.first.headers["strict-transport-security"] == "max-age=1"


def test_https_hostname_mismatch(server_factory, allow_test_loopback, trust_test_ca, pki):
    ctx, _der = server_tls(pki, "other.example.com")
    server = server_factory(respond(200), tls=ctx)
    result = http_get(make_policy(), server.url(scheme="https"), zone(www="127.0.0.1"), timeout=2)
    assert result.first.decision == "error"
    assert "certificate_verify_failed" in result.first.error


def test_tls_handshake_verified(server_factory, allow_test_loopback, trust_test_ca, pki):
    ctx, der = server_tls(pki)
    server = server_factory(respond(200), tls=ctx)
    result = tls_handshake(make_policy(), "www.example.com", "127.0.0.1", server.port, timeout=2)
    assert result.verified is True
    assert result.verify_error is None
    assert result.certificate_der == der
    assert result.protocol in ("TLSv1.2", "TLSv1.3")
    assert result.address == LOOPBACK
    assert server.requests == []  # no application data


def test_tls_handshake_untrusted_still_captures_certificate(
    server_factory, allow_test_loopback, pki, monkeypatch
):
    ctx, der = server_tls(pki)
    server = server_factory(respond(200), tls=ctx)
    real_connect = socket.socket.connect
    seen: list[tuple] = []

    def connect(sock, address):
        seen.append(address)
        return real_connect(sock, address)

    monkeypatch.setattr(socket.socket, "connect", connect)
    result = tls_handshake(make_policy(), "www.example.com", LOOPBACK, server.port, timeout=2)
    assert result.verified is False
    assert result.verify_error
    assert result.certificate_der == der
    assert result.protocol is not None
    # Both handshakes went to the same pinned address.
    assert seen == [("127.0.0.1", server.port), ("127.0.0.1", server.port)]


def test_tls_handshake_skips_the_second_handshake_when_stopped(
    server_factory, allow_test_loopback, pki
):
    ctx, _der = server_tls(pki)
    server = server_factory(respond(200), tls=ctx)
    result = tls_handshake(
        make_policy(), "www.example.com", LOOPBACK, server.port, timeout=2,
        should_stop=lambda: True,
    )  # fmt: skip
    assert result.verified is False and result.verify_error
    assert result.certificate_der is None
    assert server.connections == 1


def test_tls_handshake_hostname_mismatch(server_factory, allow_test_loopback, trust_test_ca, pki):
    ctx, der = server_tls(pki, "other.example.com")
    server = server_factory(respond(200), tls=ctx)
    result = tls_handshake(make_policy(), "www.example.com", "127.0.0.1", server.port, timeout=2)
    assert result.verified is False
    assert "mismatch" in (result.verify_error or "").lower()
    assert result.certificate_der == der


def test_tls_handshake_non_tls_server(server_factory, allow_test_loopback):
    def plain(conn, _request):
        conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")

    server = server_factory(plain, read_request=False)
    result = tls_handshake(make_policy(), "www.example.com", "127.0.0.1", server.port, timeout=2)
    assert result.verified is False
    assert result.protocol is None
    assert result.certificate_der is None
    assert result.verify_error.startswith("handshake_failed")


def test_tls_handshake_timeout(server_factory, allow_test_loopback):
    def silent(_conn, _request):
        time.sleep(2)

    server = server_factory(silent)
    with pytest.raises(OSError):
        tls_handshake(make_policy(), "www.example.com", "127.0.0.1", server.port, timeout=0.3)


@pytest.mark.parametrize("hostname", ["evil-example.com", "example.com.evil.net", "127.0.0.1"])
def test_tls_handshake_refuses_out_of_scope_sni(monkeypatch, hostname):
    spy = ConnectSpy(monkeypatch)
    with pytest.raises(ScopeError) as err:
        tls_handshake(make_policy(), hostname, PUBLIC_V4, 443, timeout=1)
    assert err.value.code == "out_of_scope_host"
    assert spy.addresses == []


def test_tls_handshake_pins_ipv6(monkeypatch):
    spy = ConnectSpy(monkeypatch, TimeoutError)
    with pytest.raises(TimeoutError):
        tls_handshake(make_policy(), "www.example.com", PUBLIC_V6, 443, timeout=1)
    assert spy.addresses == [(PUBLIC_V6, 443, 0, 0)]


def test_loopback_allowance_is_test_only():
    """Without the fixture the loopback test server address is refused."""
    with pytest.raises(AddressRefused):
        make_policy().assert_destination("127.0.0.1", tier="web")
