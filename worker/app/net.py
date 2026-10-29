"""Pinned network primitives. Every function re-validates its destination with
:meth:`ScopePolicy.assert_destination` immediately before connecting and connects to that exact
address; hostnames are only used for SNI / the Host header, never re-resolved here.

Contract (implemented by the safety core; used by tls_checks and http_checks):

* :func:`connect_tcp` — the only place a target socket is opened. Raises ScopeError when the
  address is refused (before any socket exists) and ``OSError`` (``TimeoutError``,
  ``ConnectionRefusedError``, ...) when the connection fails.
* :func:`tls_handshake` — one verifying handshake; on verification failure a second,
  non-verifying handshake to the *same pinned address* retrieves the leaf certificate. A handshake
  that fails for another TLS reason returns ``protocol=None`` with ``verify_error`` set;
  connection failures raise ``OSError``.
* :func:`http_get` — never raises for target-side problems: every hop (including refused ones) is
  recorded in :class:`HttpResult`. Requests are written by hand (HTTP/1.1, ``Connection: close``)
  on the pinned socket; response headers are bounded by :data:`MAX_HEADER_BYTES` and the body by
  ``max_body_bytes``. One overall deadline covers every hop (at most ``2 x timeout`` from the start,
  further capped by the caller's ``deadline``, i.e. the target's remaining budget) so neither a
  slow-drip server nor a chain of slow redirects can hold the worker; ``should_stop`` is checked
  between hops.
* Redirects are followed only when the new URL (a) passes ``policy.assert_hostname``
  (``redirect_out_of_scope`` otherwise), (b) names the first hop's host or one of
  ``policy.target_hostnames``, the job's approved targets (``redirect_not_approved_target``
  otherwise: unapproved names under the domain are neither resolved nor contacted), and (c) uses
  the scheme's default port (80/443) or the first URL's explicit port (``port_not_allowed``
  otherwise: a web-tier redirect must not become a probe of an arbitrary port).

Test seam: :func:`_verifying_context` builds the certificate-verifying TLS context (system trust
store). Tests replace it with ``monkeypatch`` to trust a throwaway CA; production has no switch.
"""

from __future__ import annotations

import re
import socket
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from urllib.parse import urljoin, urlsplit

from app.dns_checks import DnsResolver
from app.policy import (
    OUT_OF_SCOPE_HOST,
    IPAddress,
    ScopeError,
    ScopePolicy,
    Tier,
)

MAX_REDIRECTS = 5
MAX_BODY_BYTES = 64 * 1024
MAX_HEADER_BYTES = 32 * 1024
MAX_HEADERS = 100
MAX_HEADER_VALUE = 2048
MAX_URL_LENGTH = 2048
MAX_TIMEOUT_SECONDS = 60.0
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
USER_AGENT = "ExDomainVault-Worker/1 (+authorised external exposure monitoring)"

# Hop decisions besides the ScopeError codes.
FOLLOWED = "followed"
FINAL = "final"
REDIRECT_OUT_OF_SCOPE = "redirect_out_of_scope"
REDIRECT_NOT_APPROVED_TARGET = "redirect_not_approved_target"
PORT_NOT_ALLOWED = "port_not_allowed"
STOPPED = "stopped"
SCHEME_NOT_ALLOWED = "scheme_not_allowed"
TOO_MANY_REDIRECTS = "too_many_redirects"
INVALID_URL = "invalid_url"
ERROR = "error"

_DEFAULT_PORTS = {"http": 80, "https": 443}
# host[:port] — names only (IP literals and userinfo are refused), port 1-5 digits.
_NETLOC_RE = re.compile(r"(?P<host>[A-Za-z0-9._-]{1,253})(?::(?P<port>[0-9]{1,5}))?")
_REQUEST_TARGET_RE = re.compile(r"[\x21-\x7e]{1,2048}")
_STATUS_LINE_RE = re.compile(rb"HTTP/1\.[01] ([1-9][0-9]{2})(?: [^\r\n]*)?")
_HEADER_NAME_RE = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}")


def _check_port(port: int) -> int:
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("port must be an integer between 1 and 65535")
    return port


def _check_timeout(timeout: float) -> float:
    if isinstance(timeout, bool) or not isinstance(timeout, int | float) or not timeout > 0:
        raise ValueError("timeout must be a positive number of seconds")
    return float(min(timeout, MAX_TIMEOUT_SECONDS))


def _bounded_timeout(seconds: float, deadline: float | None) -> float:
    """``seconds`` capped by the time left until ``deadline`` (never below 10 ms)."""
    if deadline is None:
        return seconds
    return max(0.01, min(seconds, deadline - time.monotonic()))


def connect_tcp(
    policy: ScopePolicy, address: IPAddress | str, port: int, *, timeout: float, tier: Tier
) -> socket.socket:
    """Opens a TCP connection to exactly ``address:port`` after re-validating it."""
    _check_port(port)
    seconds = _check_timeout(timeout)
    ip = policy.assert_destination(address, tier=tier)
    family = socket.AF_INET if ip.version == 4 else socket.AF_INET6
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(seconds)
        # A literal address: no name resolution happens here (pinned).
        sock.connect((str(ip), port) if ip.version == 4 else (str(ip), port, 0, 0))
    except BaseException:
        sock.close()
        raise
    return sock


# ------------------------------------------------------------------------------------------------
# TLS


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


def _verifying_context() -> ssl.SSLContext:
    """System trust store, hostname checking on, TLS 1.2+ (``ssl.create_default_context``)."""
    return ssl.create_default_context()


def _non_verifying_context() -> ssl.SSLContext:
    """Only used to *read* a certificate that already failed verification; nothing is trusted."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _verify_message(exc: ssl.SSLCertVerificationError) -> str:
    message = getattr(exc, "verify_message", None) or exc.reason or type(exc).__name__
    return str(message)[:300]


def tls_handshake(
    policy: ScopePolicy,
    hostname: str,
    address: IPAddress | str,
    port: int,
    *,
    timeout: float,
    tier: Tier = "web",
    deadline: float | None = None,
    should_stop: Callable[[], bool] | None = None,
) -> TlsResult:
    """One TLS handshake to the pinned address with SNI = ``hostname``. Captures the leaf
    certificate even if verification fails (a second, non-verifying handshake to the same pinned
    address is acceptable for that). Sends no application data.

    ``deadline`` (``time.monotonic()`` value, e.g. the target's budget) bounds both handshakes;
    the second one is skipped when the deadline has passed or ``should_stop()`` is true."""
    host = policy.assert_hostname(hostname)
    ip = policy.assert_destination(address, tier=tier)
    timeout = _bounded_timeout(_check_timeout(timeout), deadline)
    sock = connect_tcp(policy, ip, port, timeout=timeout, tier=tier)
    try:
        with _verifying_context().wrap_socket(sock, server_hostname=host) as tls:
            return TlsResult(
                address=ip,
                port=port,
                protocol=tls.version(),
                certificate_der=tls.getpeercert(binary_form=True),
                verified=True,
                verify_error=None,
            )
    except ssl.SSLCertVerificationError as exc:
        verify_error = _verify_message(exc)
    except ssl.SSLError as exc:
        return TlsResult(
            address=ip,
            port=port,
            protocol=None,
            certificate_der=None,
            verified=False,
            verify_error=f"handshake_failed: {exc.reason or type(exc).__name__}"[:300],
        )
    finally:
        sock.close()

    # Verification failed: read the certificate over a second, non-verifying handshake to the same
    # pinned (and re-validated) address, if the budget allows.
    if (should_stop is not None and should_stop()) or (
        deadline is not None and deadline - time.monotonic() <= 0
    ):
        return TlsResult(ip, port, None, None, verified=False, verify_error=verify_error)
    try:
        sock = connect_tcp(policy, ip, port, timeout=_bounded_timeout(timeout, deadline), tier=tier)
    except OSError:
        return TlsResult(ip, port, None, None, verified=False, verify_error=verify_error)
    try:
        with _non_verifying_context().wrap_socket(sock, server_hostname=host) as tls:
            protocol = tls.version()
            der = tls.getpeercert(binary_form=True)
    except OSError:  # includes ssl.SSLError and timeouts
        protocol, der = None, None
    finally:
        sock.close()
    return TlsResult(
        address=ip,
        port=port,
        protocol=protocol,
        certificate_der=der,
        verified=False,
        verify_error=verify_error,
    )


# ------------------------------------------------------------------------------------------------
# HTTP


@dataclass(frozen=True)
class HttpHop:
    url: str
    #: Address the request was sent to (None when the hop was refused before connecting).
    address: IPAddress | None
    status: int | None
    #: Lower-cased response headers (bounded); empty when not connected.
    headers: dict[str, str] = field(default_factory=dict)
    #: ``followed``, ``final``, ``stopped``, or a refusal code (``redirect_out_of_scope``,
    #: ``redirect_not_approved_target``, ``port_not_allowed``, ``scheme_not_allowed``,
    #: ``too_many_redirects``, ``prohibited_address``, ``no_allowed_address``,
    #: ``cname_out_of_scope``, ``cname_chain_invalid``, ``out_of_scope_host``, ``invalid_url``,
    #: ``error``).
    decision: str = "final"
    #: Short machine-oriented detail for ``error`` hops (``timeout``, ``connection_refused``,
    #: ``certificate_verify_failed: ...``, ``dns_timeout``, ``nxdomain``, ``header_too_large``...).
    error: str | None = None
    #: Body bytes read (bounded by ``max_body_bytes``).
    body_bytes: int = 0
    #: The body bytes read (≤ ``max_body_bytes``), kept only for in-process matching of
    #: subdomain-takeover signatures (``app.http_checks``); never logged, never uploaded.
    body: bytes = field(default=b"", repr=False, compare=False)


@dataclass(frozen=True)
class HttpResult:
    hops: tuple[HttpHop, ...]

    @property
    def first(self) -> HttpHop:
        return self.hops[0]

    @property
    def last(self) -> HttpHop:
        return self.hops[-1]


class _HttpError(Exception):
    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


@dataclass(frozen=True)
class _Url:
    url: str
    scheme: str
    host: str
    port: int
    explicit_port: bool
    target: str


def _parse_url(url: str) -> _Url | str:
    """Returns the parsed URL or a refusal decision (``scheme_not_allowed`` / ``invalid_url``)."""
    if not isinstance(url, str) or not url or len(url) > MAX_URL_LENGTH:
        return INVALID_URL
    if any(ord(ch) < 0x21 or ord(ch) > 0x7E for ch in url):
        return INVALID_URL  # whitespace, control characters, non-ASCII
    try:
        parts = urlsplit(url)
    except ValueError:
        return INVALID_URL
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        return SCHEME_NOT_ALLOWED
    match = _NETLOC_RE.fullmatch(parts.netloc)
    if match is None:
        return INVALID_URL  # userinfo, IP literal in brackets, empty host, bad port...
    port_text = match.group("port")
    if port_text is not None:
        if port_text.startswith("0") or not 1 <= int(port_text) <= 65535:
            return INVALID_URL
        port = int(port_text)
    else:
        port = _DEFAULT_PORTS[scheme]
    target = parts.path or "/"
    if not target.startswith("/"):
        return INVALID_URL
    if parts.query:
        target += "?" + parts.query
    if not _REQUEST_TARGET_RE.fullmatch(target):
        return INVALID_URL
    host = match.group("host").lower()
    return _Url(
        url=url,
        scheme=scheme,
        host=host,
        port=port,
        explicit_port=port_text is not None,
        target=target,
    )


def _recv_some(sock: socket.socket, deadline: float, limit: int) -> bytes:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("deadline exceeded")
    sock.settimeout(remaining)
    return sock.recv(limit)


def _read_head(sock: socket.socket, deadline: float) -> tuple[bytes, bytes]:
    """Reads up to the end of the header block. Returns (head, already-read body bytes)."""
    buffer = b""
    while True:
        end = buffer.find(b"\r\n\r\n")
        if end != -1:
            if end + 4 > MAX_HEADER_BYTES:
                raise _HttpError("header_too_large")
            return buffer[:end], buffer[end + 4 :]
        if len(buffer) >= MAX_HEADER_BYTES:
            raise _HttpError("header_too_large")
        chunk = _recv_some(sock, deadline, min(8192, MAX_HEADER_BYTES + 4 - len(buffer)))
        if not chunk:
            raise _HttpError("incomplete_response")
        buffer += chunk


def _parse_head(head: bytes) -> tuple[int, dict[str, str]]:
    lines = head.split(b"\r\n")
    match = _STATUS_LINE_RE.fullmatch(lines[0])
    if match is None:
        raise _HttpError("malformed_status_line")
    status = int(match.group(1))
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if len(headers) >= MAX_HEADERS:
            break
        if not line or line[:1] in (b" ", b"\t"):
            continue  # obsolete line folding: ignored
        name, sep, value = line.partition(b":")
        if not sep or not _HEADER_NAME_RE.fullmatch(name):
            raise _HttpError("malformed_header")
        key = name.decode("ascii").lower()
        text = value.strip(b" \t").decode("latin-1")
        text = "".join(ch for ch in text if ch == "\t" or 0x20 <= ord(ch) != 0x7F)
        text = text[:MAX_HEADER_VALUE]
        headers[key] = f"{headers[key]}, {text}"[:MAX_HEADER_VALUE] if key in headers else text
    return status, headers


def _read_body(
    sock: socket.socket, initial: bytes, limit: int, deadline: float
) -> tuple[int, bytes]:
    """Reads at most ``limit`` body bytes; returns (count, the bytes read). Read errors after the
    header block are ignored (the status and headers are already evidence). The bytes stay in
    memory for in-process signature matching only; they are never logged or uploaded."""
    parts = [initial[:limit]]
    count = len(parts[0])
    try:
        while count < limit:
            chunk = _recv_some(sock, deadline, min(16384, limit - count))
            if not chunk:
                break
            chunk = chunk[: limit - count]
            parts.append(chunk)
            count += len(chunk)
    except (OSError, ValueError):
        pass
    return count, b"".join(parts)


def _error_detail(exc: BaseException) -> str:
    if isinstance(exc, ssl.SSLCertVerificationError):
        return f"certificate_verify_failed: {_verify_message(exc)}"[:300]
    if isinstance(exc, ssl.SSLError):
        return f"tls_error: {exc.reason or type(exc).__name__}"[:300]
    if isinstance(exc, TimeoutError | socket.timeout):
        return "timeout"
    if isinstance(exc, ConnectionRefusedError):
        return "connection_refused"
    if isinstance(exc, ConnectionResetError):
        return "connection_reset"
    return "connection_error"


def _dns_error_detail(exc: BaseException) -> str:
    import dns.exception
    import dns.resolver

    if isinstance(exc, dns.resolver.NXDOMAIN):
        return "nxdomain"
    if isinstance(exc, dns.exception.Timeout):
        return "dns_timeout"
    return f"dns_error: {type(exc).__name__}"


def _exchange(
    policy: ScopePolicy,
    target: _Url,
    address: IPAddress,
    *,
    timeout: float,
    max_body_bytes: int,
    tier: Tier,
    deadline: float,
) -> tuple[int, dict[str, str], int, bytes]:
    connect_timeout = _bounded_timeout(timeout, deadline)
    sock: socket.socket = connect_tcp(
        policy, address, target.port, timeout=connect_timeout, tier=tier
    )
    try:
        if target.scheme == "https":
            sock.settimeout(max(0.01, deadline - time.monotonic()))
            sock = _verifying_context().wrap_socket(sock, server_hostname=target.host)
        host_header = f"{target.host}:{target.port}" if target.explicit_port else target.host
        request = (
            f"GET {target.target} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"User-Agent: {USER_AGENT}\r\n"
            "Accept: */*\r\n"
            "Accept-Encoding: identity\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        sock.settimeout(max(0.01, deadline - time.monotonic()))
        sock.sendall(request)
        head, rest = _read_head(sock, deadline)
        status, headers = _parse_head(head)
        count, body = _read_body(sock, rest, max_body_bytes, deadline)
        return status, headers, count, body
    finally:
        sock.close()


def http_get(
    policy: ScopePolicy,
    url: str,
    resolver: DnsResolver,
    *,
    timeout: float,
    max_redirects: int = MAX_REDIRECTS,
    max_body_bytes: int = MAX_BODY_BYTES,
    tier: Tier = "web",
    deadline: float | None = None,
    should_stop: Callable[[], bool] | None = None,
) -> HttpResult:
    """GET ``url`` (http/https only) without automatic redirects. For each hop: validate the host
    with ``policy.assert_hostname`` (refuse ``redirect_out_of_scope`` without connecting), for a
    redirect also require an approved target host (``redirect_not_approved_target``) and an allowed
    port (``port_not_allowed``), resolve through ``policy.resolve``, connect to the first allowed
    address (pinned), send Host / SNI = hostname, read at most ``max_body_bytes`` of body, and
    follow ``Location`` only while within the cap.

    The whole call (all hops) ends by ``min(start + 2 x timeout, deadline)``; ``deadline`` is a
    ``time.monotonic()`` value (the caller's remaining target budget). ``should_stop`` is checked
    before every hop; a stop is recorded as a ``stopped`` hop."""
    seconds = _check_timeout(timeout)
    overall = time.monotonic() + 2 * seconds
    if deadline is not None:
        overall = min(overall, float(deadline))
    redirects_left = max(0, min(int(max_redirects), MAX_REDIRECTS))
    body_limit = max(0, min(int(max_body_bytes), MAX_BODY_BYTES))
    hops: list[HttpHop] = []
    visited: set[str] = set()
    current = url
    is_redirect = False
    origin: _Url | None = None

    def refused(hop_url: str, decision: str, error: str | None = None) -> HttpResult:
        hops.append(
            HttpHop(url=str(hop_url)[:MAX_URL_LENGTH], address=None, status=None,
                    decision=decision, error=error)
        )  # fmt: skip
        return HttpResult(hops=tuple(hops))

    while True:
        if should_stop is not None and should_stop():
            return refused(current, STOPPED)
        parsed = _parse_url(current)
        if isinstance(parsed, str):
            return refused(current, parsed)
        try:
            host = policy.assert_hostname(parsed.host)
        except ScopeError:
            return refused(current, REDIRECT_OUT_OF_SCOPE if is_redirect else OUT_OF_SCOPE_HOST)
        parsed = replace(parsed, host=host)  # normalised (lower-case, no trailing dot)
        if origin is None:
            origin = parsed
        else:
            if host != origin.host and host not in policy.target_hostnames:
                return refused(current, REDIRECT_NOT_APPROVED_TARGET)
            allowed_ports = {_DEFAULT_PORTS[parsed.scheme]}
            if origin.explicit_port:
                allowed_ports.add(origin.port)
            if parsed.port not in allowed_ports:
                return refused(current, PORT_NOT_ALLOWED)
        remaining = overall - time.monotonic()
        if remaining <= 0:
            return refused(current, ERROR, "timeout")
        try:
            resolved = policy.resolve(
                host, resolver, tier=tier, lifetime=max(0.01, min(seconds, remaining))
            )
        except ScopeError as exc:
            return refused(current, exc.code)
        except Exception as exc:  # DNS failures
            return refused(current, ERROR, _dns_error_detail(exc))
        address = resolved.addresses[0]
        visited.add(current)
        try:
            status, headers, body_count, body = _exchange(
                policy, parsed, address, timeout=seconds, max_body_bytes=body_limit, tier=tier,
                deadline=min(overall, time.monotonic() + 2 * seconds),
            )  # fmt: skip
        except ScopeError as exc:
            return refused(current, exc.code)
        except _HttpError as exc:
            hops.append(HttpHop(current, address, None, decision=ERROR, error=exc.detail))
            return HttpResult(hops=tuple(hops))
        except (OSError, ValueError) as exc:
            hops.append(HttpHop(current, address, None, decision=ERROR, error=_error_detail(exc)))
            return HttpResult(hops=tuple(hops))

        location = headers.get("location")
        if status not in REDIRECT_STATUSES or not location:
            hops.append(
                HttpHop(current, address, status, headers, FINAL, body_bytes=body_count, body=body)
            )
            return HttpResult(hops=tuple(hops))
        hops.append(HttpHop(current, address, status, headers, FOLLOWED, body_bytes=body_count))
        try:
            next_url = urljoin(current, location.strip())
        except ValueError:
            return refused(location, INVALID_URL)
        next_url = next_url.split("#", 1)[0]
        if redirects_left == 0 or next_url in visited:
            return refused(next_url, TOO_MANY_REDIRECTS)
        redirects_left -= 1
        current = next_url
        is_redirect = True


__all__ = [
    "MAX_BODY_BYTES",
    "MAX_HEADER_BYTES",
    "MAX_REDIRECTS",
    "PORT_NOT_ALLOWED",
    "REDIRECT_NOT_APPROVED_TARGET",
    "STOPPED",
    "HttpHop",
    "HttpResult",
    "TlsResult",
    "connect_tcp",
    "http_get",
    "tls_handshake",
]
