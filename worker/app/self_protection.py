"""Home-network self-protection for active scanning.

The worker runs on a home host. Its own addresses are not always in the prohibited ranges of
:mod:`app.policy`: a host can hold a public IPv4 address, a global IPv6 address (whose /64 is the
home LAN, every device on it globally addressable), and the home router's public IPv4 address
(NAT egress) is public by definition. A target name that resolves to any of these would turn an
external scan into a scan of the home network. While active scanning is enabled the worker therefore
adds, at start-up and every hour (:data:`REFRESH_SECONDS`), to the effective deny list of every job:

a. every address on a local interface: IPv4 addresses from ``/proc/self/net/fib_trie`` (``/32 host
   LOCAL`` entries; fallback: ``SIOCGIFADDR`` per interface), IPv6 addresses from
   ``/proc/self/net/if_inet6``, as their /64 prefix for global addresses and /128 otherwise; and
b. the public egress addresses as seen by a resolver: a single DNS query, ``whoami.cloudflare`` TXT
   in the CHAOS class, sent to Cloudflare's public resolver (``1.1.1.1`` and
   ``2606:4700:4700::1111``). This is a resolver query, never a target contact.

If no IPv4 egress address can be detected and ``EXDV_DENY_NETWORKS`` is empty, web and network
checks fail closed with error code ``egress_ip_unknown`` until a later detection succeeds (an
IPv6-only host must therefore list its prefix in ``EXDV_DENY_NETWORKS``). Detected values are
logged at INFO: they are the operator's own addresses, not secrets.
"""

from __future__ import annotations

import contextlib
import fcntl
import ipaddress
import logging
import socket
import struct
import threading
import time
from collections.abc import Callable, Iterable, Sequence

import dns.exception
import dns.message
import dns.query
import dns.rdataclass
import dns.rdatatype

from app.logging_config import get_logger, log_event
from app.policy import IPAddress, IPNetwork, parse_address
from app.scope import ScopeError

REFRESH_SECONDS = 3600.0
EGRESS_IP_UNKNOWN = "egress_ip_unknown"
EGRESS_QUERY_NAME = "whoami.cloudflare."
EGRESS_RESOLVERS: tuple[str, ...] = ("1.1.1.1", "2606:4700:4700::1111")
EGRESS_TIMEOUT_SECONDS = 3.0
GLOBAL_IPV6_PREFIX = 64
_IF_INET6_PATHS = ("/proc/self/net/if_inet6", "/proc/net/if_inet6")
_FIB_TRIE_PATHS = ("/proc/self/net/fib_trie", "/proc/net/fib_trie")
_SIOCGIFADDR = 0x8915
_MAX_TEXT = 4 * 1024 * 1024

_log = get_logger("self_protection")


# -- (a) local interface addresses ---------------------------------------------------------------


def parse_fib_trie(text: str) -> list[ipaddress.IPv4Address]:
    """IPv4 addresses the kernel considers local (``/32 host LOCAL`` leaves)."""
    found: dict[ipaddress.IPv4Address, None] = {}
    last: ipaddress.IPv4Address | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("|--"):
            try:
                last = ipaddress.IPv4Address(stripped[3:].strip())
            except ValueError:
                last = None
        elif stripped.startswith("/") and last is not None:
            if stripped.split() == ["/32", "host", "LOCAL"]:
                found[last] = None
        elif stripped.startswith("+--") or stripped.endswith(":"):
            last = None
    return list(found)


def parse_if_inet6(text: str) -> list[IPNetwork]:
    """Global IPv6 addresses as their /64, every other address as /128."""
    found: dict[IPNetwork, None] = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 6 or len(fields[0]) != 32:
            continue
        try:
            address = ipaddress.IPv6Address(int(fields[0], 16))
            scope = int(fields[3], 16)
        except ValueError:
            continue
        if scope == 0 and address in ipaddress.IPv6Network("2000::/3"):
            network = ipaddress.IPv6Network(f"{address}/{GLOBAL_IPV6_PREFIX}", strict=False)
        else:
            network = ipaddress.IPv6Network(f"{address}/128")
        found[network] = None
    return list(found)


def _read_first(paths: Iterable[str]) -> str | None:
    for path in paths:
        with contextlib.suppress(OSError), open(path, encoding="ascii", errors="replace") as fh:
            return fh.read(_MAX_TEXT)
    return None


def _ioctl_ipv4_addresses() -> list[ipaddress.IPv4Address]:
    """Fallback when fib_trie is unreadable: the primary IPv4 address of each interface."""
    found: list[ipaddress.IPv4Address] = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for _index, name in socket.if_nameindex():
            request = struct.pack("256s", name.encode()[:15])
            try:
                reply = fcntl.ioctl(sock.fileno(), _SIOCGIFADDR, request)
            except OSError:
                continue  # no IPv4 address on this interface
            found.append(ipaddress.IPv4Address(reply[20:24]))
    return found


def read_local_networks() -> list[IPNetwork]:
    """Networks covering every address on a local interface (see the module docstring)."""
    networks: list[IPNetwork] = []
    fib = _read_first(_FIB_TRIE_PATHS)
    v4 = parse_fib_trie(fib) if fib is not None else []
    if not v4:
        with contextlib.suppress(OSError):
            v4 = _ioctl_ipv4_addresses()
    networks += [ipaddress.IPv4Network(a) for a in v4]
    inet6 = _read_first(_IF_INET6_PATHS)
    if inet6 is not None:
        networks += parse_if_inet6(inet6)
    return list(dict.fromkeys(networks))


# -- (b) public egress addresses -----------------------------------------------------------------


def query_egress_address(server: str, timeout: float = EGRESS_TIMEOUT_SECONDS) -> IPAddress:
    """The source address ``server`` saw for a ``whoami.cloudflare`` CH TXT query. Raises on any
    failure (DNS error, timeout, malformed answer)."""
    query = dns.message.make_query(EGRESS_QUERY_NAME, dns.rdatatype.TXT, rdclass=dns.rdataclass.CH)
    response = dns.query.udp(query, server, timeout=timeout)
    for rrset in response.answer:
        if rrset.rdtype != dns.rdatatype.TXT:
            continue
        for rdata in rrset:
            for chunk in rdata.strings:
                return parse_address(chunk.decode("ascii", errors="replace").strip())
    raise ValueError("no TXT answer")


def detect_egress_addresses(
    query: Callable[[str], IPAddress] = query_egress_address,
    servers: Sequence[str] = EGRESS_RESOLVERS,
) -> list[IPAddress]:
    """Egress addresses from every server that answered (failures are skipped)."""
    found: dict[IPAddress, None] = {}
    for server in servers:
        try:
            found[query(server)] = None
        except (OSError, ValueError, ScopeError, dns.exception.DNSException):
            continue
    return list(found)


# -- state ---------------------------------------------------------------------------------------


class SelfProtection:
    """The extra deny list (local + egress networks) and whether egress detection succeeded.

    Thread-safe; :meth:`refresh` never raises (a failure leaves the egress unknown)."""

    def __init__(
        self,
        *,
        configured_deny: Sequence[str] = (),
        local_reader: Callable[[], Iterable[IPNetwork]] = read_local_networks,
        egress_detector: Callable[[], Iterable[IPAddress]] = detect_egress_addresses,
        monotonic: Callable[[], float] = time.monotonic,
        refresh_seconds: float = REFRESH_SECONDS,
        logger: logging.Logger | None = None,
    ) -> None:
        self._configured = tuple(configured_deny)
        self._local_reader = local_reader
        self._egress_detector = egress_detector
        self._monotonic = monotonic
        self._refresh_seconds = refresh_seconds
        self._log = logger or _log
        self._lock = threading.Lock()
        self._refreshed_at: float | None = None
        self._local: tuple[IPNetwork, ...] = ()
        self._egress: tuple[IPNetwork, ...] = ()
        self._egress_v4_known = False

    def refresh(self) -> None:
        try:
            local = tuple(dict.fromkeys(self._local_reader()))
        except Exception as exc:  # never let detection break the loop
            log_event(
                self._log, logging.WARNING, "local_addresses_failed", error=type(exc).__name__
            )
            local = self._local
        try:
            egress_addresses = list(dict.fromkeys(self._egress_detector()))
        except Exception as exc:
            log_event(
                self._log, logging.WARNING, "egress_detection_failed", error=type(exc).__name__
            )
            egress_addresses = []
        egress: list[IPNetwork] = []
        for address in egress_addresses:
            if address.version == 6:  # the home's IPv6 LAN prefix
                egress.append(
                    ipaddress.IPv6Network(f"{address}/{GLOBAL_IPV6_PREFIX}", strict=False)
                )
            else:
                egress.append(ipaddress.IPv4Network(address))
        v4_known = any(a.version == 4 for a in egress_addresses)
        with self._lock:
            self._local = local
            # A previously detected egress address stays denied after a failed detection
            # (denying more only shrinks scope); "known" reflects this detection only.
            self._egress = tuple(dict.fromkeys([*egress, *self._egress]))
            self._egress_v4_known = v4_known
            self._refreshed_at = self._monotonic()
        log_event(
            self._log, logging.INFO if v4_known else logging.WARNING, "self_protection_refreshed",
            localNetworks=[str(n) for n in local],
            egressAddresses=[str(a) for a in egress_addresses],
            egressDetected=v4_known, configuredDenyNetworks=len(self._configured),
            failClosed=self.blocking_reason() is not None,
        )  # fmt: skip

    def maybe_refresh(self) -> None:
        """Refreshes when never refreshed or older than ``refresh_seconds``."""
        with self._lock:
            due = (
                self._refreshed_at is None
                or self._monotonic() - self._refreshed_at >= self._refresh_seconds
            )
        if due:
            self.refresh()

    def deny_networks(self) -> tuple[str, ...]:
        """Configured deny list + local + egress networks, canonical CIDR text."""
        with self._lock:
            extra = [str(n) for n in (*self._local, *self._egress)]
        return tuple(dict.fromkeys([*self._configured, *extra]))

    def blocking_reason(self) -> str | None:
        """``egress_ip_unknown`` while web/network checks must fail closed, else None."""
        with self._lock:
            known = self._egress_v4_known
        if known or self._configured:
            return None
        return EGRESS_IP_UNKNOWN


__all__ = [
    "EGRESS_IP_UNKNOWN",
    "REFRESH_SECONDS",
    "SelfProtection",
    "detect_egress_addresses",
    "parse_fib_trie",
    "parse_if_inet6",
    "query_egress_address",
    "read_local_networks",
]
