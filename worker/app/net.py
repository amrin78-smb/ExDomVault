"""Pinned network primitives. Every function re-validates its destination with
:meth:`ScopePolicy.assert_destination` immediately before connecting and connects to that exact
address; hostnames are only used for SNI / the Host header, never re-resolved here.

Contract (implemented by the safety core; used by tls_checks and http_checks):
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field

from app.dns_checks import DnsResolver
from app.policy import IPAddress, ScopePolicy, Tier

MAX_REDIRECTS = 5
MAX_BODY_BYTES = 64 * 1024
MAX_HEADER_BYTES = 32 * 1024


def connect_tcp(
    policy: ScopePolicy, address: IPAddress | str, port: int, *, timeout: float, tier: Tier
) -> socket.socket:
    """Opens a TCP connection to exactly ``address:port`` after re-validating it."""
    raise NotImplementedError


@dataclass(frozen=True)
class TlsResult:
    address: IPAddress
    port: int
    #: Negotiated protocol, e.g. ``TLSv1.3``; None if the handshake failed.
    protocol: str | None
    #: Leaf certificate (DER), retrieved even when verification fails.
    certificate_der: bytes | None
    #: Chain verified against the system trust store *and* the hostname.
    verified: bool
    verify_error: str | None


def tls_handshake(
    policy: ScopePolicy,
    hostname: str,
    address: IPAddress | str,
    port: int,
    *,
    timeout: float,
    tier: Tier = "web",
) -> TlsResult:
    """One TLS handshake to the pinned address with SNI = ``hostname``. Captures the leaf certificate
    even if verification fails (a second, non-verifying handshake to the same pinned address is
    acceptable for that). Sends no application data."""
    raise NotImplementedError


@dataclass(frozen=True)
class HttpHop:
    url: str
    #: Address the request was sent to (None when the hop was refused before connecting).
    address: IPAddress | None
    status: int | None
    #: Lower-cased response headers (bounded); empty when not connected.
    headers: dict[str, str] = field(default_factory=dict)
    #: ``followed``, ``final``, or a refusal code (``redirect_out_of_scope``, ``scheme_not_allowed``,
    #: ``too_many_redirects``, ``prohibited_address``, ``no_allowed_address``, ``error``).
    decision: str = "final"


@dataclass(frozen=True)
class HttpResult:
    hops: tuple[HttpHop, ...]

    @property
    def first(self) -> HttpHop:
        return self.hops[0]

    @property
    def last(self) -> HttpHop:
        return self.hops[-1]


def http_get(
    policy: ScopePolicy,
    url: str,
    resolver: DnsResolver,
    *,
    timeout: float,
    max_redirects: int = MAX_REDIRECTS,
    max_body_bytes: int = MAX_BODY_BYTES,
    tier: Tier = "web",
) -> HttpResult:
    """GET ``url`` (http/https only) without automatic redirects. For each hop: validate the host with
    ``policy.assert_hostname`` (refuse ``redirect_out_of_scope`` without connecting), resolve through
    ``policy.resolve``, connect to the first allowed address (pinned), send Host / SNI = hostname,
    read at most ``max_body_bytes`` of body, and follow ``Location`` only while within the cap."""
    raise NotImplementedError
