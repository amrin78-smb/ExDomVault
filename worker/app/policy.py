"""Milestone 6 scope validator: the security gate for every network-connecting check.

Contract (implemented by the safety core; used by tls_checks, http_checks, port_checks):

* Every destination is resolved through :meth:`ScopePolicy.resolve`, which validates the CNAME chain
  and every returned address, and returns only allowed addresses.
* Immediately before connecting, :meth:`ScopePolicy.assert_destination` re-validates the exact
  address, and the connection is made to that address (pinned) — never by re-resolving the name.
  This closes DNS-rebinding / time-of-check-to-time-of-use gaps.
* Tiers (owner decision): ``web`` checks may reach any public address of an in-scope hostname;
  ``network`` checks only addresses inside the job's approved networks; ``passive`` checks never
  connect to targets.
* Every allow/deny decision is logged as a structured ``scope_decision`` event
  (``jobId``, ``subject``, ``tier``, ``allowed``, ``reason``).

Address policy is built from explicit tables (below) and does not rely on the
``ipaddress.is_global`` / ``is_private`` semantics, which differ between Python releases; those
properties are consulted only as an extra fail-closed backstop. There is deliberately no flag,
environment variable or argument that permits a prohibited address: tests that need a loopback
server replace :func:`address_prohibited_reason` with ``monkeypatch`` for that single address.

DNS errors raised by the resolver (``NXDOMAIN``, ``Timeout``, other ``DNSException``) propagate
from :meth:`ScopePolicy.resolve` unchanged so callers can report ``timeout`` vs ``error``;
an empty answer (NODATA) is treated as "no records".
"""

from __future__ import annotations

import ipaddress
import logging
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from app.dns_checks import DnsResolver
from app.logging_config import get_logger, log_event
from app.scope import ScopeError, normalise_hostname

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
Tier = Literal["passive", "web", "network"]

PASSIVE_TIER_CHECKS: frozenset[str] = frozenset({"dns", "rdap"})
WEB_TIER_CHECKS: frozenset[str] = frozenset(
    {"tls_certificate", "http_availability", "http_headers"}
)
NETWORK_TIER_CHECKS: frozenset[str] = frozenset(
    {"tcp_ports", "service_identification", "tls_configuration"}
)

# ScopeError codes raised by this module (also used as target errorCodes and in logs).
PROHIBITED_ADDRESS = "prohibited_address"
NETWORK_NOT_APPROVED = "network_not_approved"
OUT_OF_SCOPE_HOST = "out_of_scope_host"
CNAME_OUT_OF_SCOPE = "cname_out_of_scope"
NO_ALLOWED_ADDRESS = "no_allowed_address"
CHECK_NOT_ALLOWED = "check_not_allowed"
ACTIVE_SCANNING_DISABLED = "active_scanning_disabled"
#: CNAME loop, chain longer than :data:`MAX_CNAME_HOPS`, multiple CNAMEs at one name, or a chain
#: that changed between the hop-by-hop walk and the address query.
CNAME_CHAIN_INVALID = "cname_chain_invalid"
#: The job's scope snapshot or the operator's deny list is unusable (fail closed).
SCOPE_REJECTED = "scope_rejected"

#: Address refusal reason for operator deny-listed networks (``EXDV_DENY_NETWORKS``).
DENY_LISTED = "deny_listed"

MAX_CNAME_HOPS = 8
#: Approved networks broader than this are ignored (logged): a mistaken ``0.0.0.0/0`` must not
#: turn the network tier into "anything public".
MIN_APPROVED_PREFIX = {4: 8, 6: 20}

_LOG = get_logger("policy")

# --------------------------------------------------------------------------------------------
# Address parsing


# Dotted-quad only: each octet 0-255 in decimal without leading zeros. Rejects octal (017.0.0.1),
# hex (0x7f.0.0.1), integer (2130706433), short forms (127.1) and trailing dots.
_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])"
_IPV4_RE = re.compile(rf"{_OCTET}(?:\.{_OCTET}){{3}}")
_IPV6_CHARS_RE = re.compile(r"[0-9A-Fa-f:.]+")
_PREFIX_RE = re.compile(r"0|[1-9][0-9]{0,2}")
_MAX_ADDRESS_TEXT = 45  # longest IPv6 text form (with embedded IPv4)


def tier_of(check: str) -> Tier:
    """The tier of a known check; raises ScopeError(``check_not_allowed``) for unknown checks."""
    if check in PASSIVE_TIER_CHECKS:
        return "passive"
    if check in WEB_TIER_CHECKS:
        return "web"
    if check in NETWORK_TIER_CHECKS:
        return "network"
    raise ScopeError(CHECK_NOT_ALLOWED, "Unknown check.")


def parse_address(value: str) -> IPAddress:
    """Strictly parses a canonical IPv4/IPv6 text address. Rejects zone ids (``fe80::1%eth0``),
    non-canonical IPv4 encodings (``0x7f.1``, ``017.0.0.1``, ``2130706433``, ``127.1``), brackets
    and whitespace with ScopeError(``prohibited_address``)."""
    if not isinstance(value, str) or not value or len(value) > _MAX_ADDRESS_TEXT:
        raise ScopeError(PROHIBITED_ADDRESS, "Address is not a valid IP address text.")
    if ":" in value:
        # IPv6: hex digits, colons and (for an embedded IPv4 tail) dots only - no zone id ("%"),
        # brackets, whitespace, NUL or prefix length.
        if not _IPV6_CHARS_RE.fullmatch(value):
            raise ScopeError(PROHIBITED_ADDRESS, "Address is not a valid IPv6 address.")
        if "." in value:
            tail = value.rsplit(":", 1)[1]
            if not _IPV4_RE.fullmatch(tail):
                raise ScopeError(PROHIBITED_ADDRESS, "Address is not a valid IPv6 address.")
        try:
            return ipaddress.IPv6Address(value)
        except ValueError as exc:
            raise ScopeError(PROHIBITED_ADDRESS, "Address is not a valid IPv6 address.") from exc
    if not _IPV4_RE.fullmatch(value):
        raise ScopeError(PROHIBITED_ADDRESS, "Address is not a canonical dotted-quad IPv4 address.")
    try:
        return ipaddress.IPv4Address(value)
    except ValueError as exc:  # pragma: no cover - regex already guarantees validity
        raise ScopeError(PROHIBITED_ADDRESS, "Address is not a valid IPv4 address.") from exc


def parse_network(value: str) -> IPNetwork:
    """Strictly parses ``address/prefix`` (or a bare address = single host). The address part goes
    through :func:`parse_address`; host bits must be zero. Raises ValueError."""
    if not isinstance(value, str):
        raise ValueError("network must be a string")
    address_text, sep, prefix_text = value.partition("/")
    try:
        address = parse_address(address_text)
    except ScopeError as exc:
        raise ValueError("invalid network address") from exc
    if not sep:
        return ipaddress.ip_network(address)
    if not _PREFIX_RE.fullmatch(prefix_text) or int(prefix_text) > address.max_prefixlen:
        raise ValueError("invalid network prefix length")
    return ipaddress.ip_network(f"{address}/{prefix_text}", strict=True)


# --------------------------------------------------------------------------------------------
# Prohibited address tables. Order matters: the first match gives the reason, so more specific
# ranges come before the ranges that contain them.


def _table(entries: Iterable[tuple[str, str]]) -> tuple[tuple[IPNetwork, str], ...]:
    return tuple((ipaddress.ip_network(cidr), reason) for cidr, reason in entries)


_IPV4_PROHIBITED = _table(
    [
        ("0.0.0.0/8", "unspecified"),  # "this network" (RFC 791 / 1122)
        ("10.0.0.0/8", "private"),
        ("100.64.0.0/10", "cgnat"),  # RFC 6598 shared address space
        ("127.0.0.0/8", "loopback"),
        ("169.254.0.0/16", "link_local"),
        ("172.16.0.0/12", "private"),
        ("192.0.0.0/24", "reserved"),  # IETF protocol assignments (RFC 6890)
        ("192.0.2.0/24", "documentation"),  # TEST-NET-1
        ("192.88.99.0/24", "6to4"),  # deprecated 6to4 relay anycast (RFC 7526)
        ("192.168.0.0/16", "private"),
        ("198.18.0.0/15", "benchmarking"),  # RFC 2544
        ("198.51.100.0/24", "documentation"),  # TEST-NET-2
        ("203.0.113.0/24", "documentation"),  # TEST-NET-3
        ("224.0.0.0/4", "multicast"),
        ("255.255.255.255/32", "broadcast"),
        ("240.0.0.0/4", "reserved"),  # future use (class E)
    ]
)

_IPV6_PROHIBITED = _table(
    [
        ("::/128", "unspecified"),
        ("::1/128", "loopback"),
        ("::ffff:0:0/96", "ipv4_mapped"),
        ("::ffff:0:0:0/96", "ipv4_mapped"),  # SIIT IPv4-translated (RFC 2765)
        ("::/96", "ipv4_compatible"),  # deprecated IPv4-compatible
        ("64:ff9b::/96", "nat64"),  # RFC 6052 well-known prefix
        ("64:ff9b:1::/48", "nat64"),  # RFC 8215 local-use translation
        ("100::/64", "discard"),  # RFC 6666 discard-only
        ("2001::/32", "teredo"),
        ("2001:2::/48", "benchmarking"),  # RFC 5180
        ("2001:10::/28", "reserved"),  # ORCHID (deprecated)
        ("2001:20::/28", "reserved"),  # ORCHIDv2
        ("2001::/23", "reserved"),  # IETF protocol assignments
        ("2001:db8::/32", "documentation"),
        ("3fff::/20", "documentation"),  # RFC 9637
        ("2002::/16", "6to4"),
        ("fc00::/7", "ula"),
        ("fe80::/10", "link_local"),
        ("fec0::/10", "site_local"),
        ("ff00::/8", "multicast"),
    ]
)

#: The only IPv6 space currently allocated for global unicast. Anything else is refused.
_IPV6_GLOBAL_UNICAST = ipaddress.IPv6Network("2000::/3")


def address_prohibited_reason(address: IPAddress) -> str | None:
    """Why an address may never be contacted (e.g. ``loopback``, ``private``, ``cgnat``,
    ``link_local``, ``multicast``, ``reserved``, ``unspecified``, ``documentation``,
    ``benchmarking``, ``ipv4_mapped``, ``ipv4_compatible``, ``nat64``, ``6to4``, ``teredo``,
    ``ula``, ``site_local``, ``broadcast``, ``discard``), or None for public unicast. Embedded IPv4
    (mapped/compatible/6to4/Teredo/NAT64) is always refused — the worker never contacts IPv4 via
    an IPv6 transition form."""
    if isinstance(address, ipaddress.IPv4Address):
        table = _IPV4_PROHIBITED
    elif isinstance(address, ipaddress.IPv6Address):
        if address.scope_id is not None:
            return "reserved"
        table = _IPV6_PROHIBITED
    else:
        return "reserved"  # not an address object: fail closed
    for network, reason in table:
        if address in network:
            return reason
    if isinstance(address, ipaddress.IPv6Address) and address not in _IPV6_GLOBAL_UNICAST:
        return "reserved"
    # Backstop: if the standard library considers it special in any way, refuse it too.
    if (
        address.is_loopback
        or address.is_private
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or not address.is_global
    ):
        return "reserved"
    return None


# --------------------------------------------------------------------------------------------
# Policy


class AddressRefused(ScopeError):
    """An address failed validation. ``code`` is the ScopeError code; ``reason`` the detail
    (e.g. ``loopback``, ``deny_listed``, ``network_not_approved``)."""

    def __init__(self, code: str, reason: str, message: str) -> None:
        super().__init__(code, message)
        self.reason = reason


@dataclass(frozen=True)
class ResolvedHost:
    hostname: str
    #: Allowed addresses, de-duplicated, in resolver order (IPv4 first is fine).
    addresses: tuple[IPAddress, ...]
    #: CNAME hops followed, each validated to be within the job's domain.
    cname_chain: tuple[str, ...]
    #: Addresses refused, as (address text, reason).
    dropped: tuple[tuple[str, str], ...]


def _clean_cname(value: str) -> str:
    return value[:-1] if value.endswith(".") and value != "." else value


@dataclass(frozen=True)
class ScopePolicy:
    """Per-job scope: the job's domain, target hostnames, approved networks, the operator's deny
    list and whether active scanning is enabled. Immutable once built."""

    job_id: str
    domain: str
    checks: frozenset[str] = field(default_factory=frozenset)
    target_hostnames: tuple[str, ...] = ()
    approved_networks: tuple[IPNetwork, ...] = ()
    deny_networks: tuple[IPNetwork, ...] = ()
    active_scanning_enabled: bool = False

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "domain", normalise_hostname(self.domain))
        except ScopeError as exc:
            raise ScopeError(SCOPE_REJECTED, "The job's domain is not a valid name.") from exc
        if self.active_scanning_enabled is not True:
            object.__setattr__(self, "active_scanning_enabled", False)

    @classmethod
    def from_job(
        cls,
        *,
        job_id: str,
        snapshot: Mapping[str, Any],
        target_hostnames: Sequence[str],
        deny_networks: Sequence[str],
        active_scanning_enabled: bool,
    ) -> ScopePolicy:
        """Builds the policy from a claimed job's snapshot (``snapshot['domain']['fqdn']``,
        ``snapshot['profile']['config']['checks']``, ``snapshot['approvedNetworks']``).

        Fails closed (``scope_rejected``) on an unusable domain, a target outside the domain (or,
        when the snapshot lists ``targets``, not listed there) or a malformed deny-list entry.
        Malformed or over-broad approved networks are ignored with a logged warning (that only
        shrinks scope)."""
        try:
            fqdn = snapshot["domain"]["fqdn"]
            raw_checks = snapshot["profile"]["config"]["checks"]
        except (KeyError, TypeError) as exc:
            raise ScopeError(SCOPE_REJECTED, "The job's scope snapshot is incomplete.") from exc
        if not isinstance(raw_checks, list | tuple):
            raise ScopeError(SCOPE_REJECTED, "The job's profile checks are malformed.")
        checks = frozenset(c for c in raw_checks if isinstance(c, str))

        deny: list[IPNetwork] = []
        for raw in deny_networks:
            try:
                deny.append(parse_network(raw))
            except ValueError as exc:
                raise ScopeError(SCOPE_REJECTED, "A deny-list network is malformed.") from exc

        approved: list[IPNetwork] = []
        raw_approved = snapshot.get("approvedNetworks") or []
        if not isinstance(raw_approved, list | tuple):
            raw_approved = []
        for raw in raw_approved:
            try:
                network = parse_network(raw)
            except ValueError:
                log_event(
                    _LOG, logging.WARNING, "approved_network_ignored",
                    jobId=job_id, network=str(raw)[:64], reason="malformed",
                )  # fmt: skip
                continue
            if network.prefixlen < MIN_APPROVED_PREFIX[network.version]:
                log_event(
                    _LOG, logging.WARNING, "approved_network_ignored",
                    jobId=job_id, network=str(network), reason="too_broad",
                )  # fmt: skip
                continue
            approved.append(network)

        policy = cls(
            job_id=job_id,
            domain=fqdn,
            checks=checks,
            approved_networks=tuple(approved),
            deny_networks=tuple(deny),
            active_scanning_enabled=active_scanning_enabled is True,
        )

        snapshot_targets = snapshot.get("targets")
        listed: set[str] | None = None
        if isinstance(snapshot_targets, list):
            listed = set()
            for item in snapshot_targets:
                name = item.get("hostname") if isinstance(item, Mapping) else None
                try:
                    listed.add(normalise_hostname(name))  # type: ignore[arg-type]
                except ScopeError:
                    continue
        hosts: list[str] = []
        for raw in target_hostnames:
            try:
                host = policy.assert_hostname(raw)
            except ScopeError as exc:
                raise ScopeError(SCOPE_REJECTED, "A target is outside the job's domain.") from exc
            if listed is not None and host not in listed:
                raise ScopeError(SCOPE_REJECTED, "A target is not in the job's scope snapshot.")
            hosts.append(host)
        object.__setattr__(policy, "target_hostnames", tuple(dict.fromkeys(hosts)))
        return policy

    # ----------------------------------------------------------------------------------------

    def _log(self, subject: str, tier: str, allowed: bool, reason: str) -> None:
        log_event(
            _LOG,
            logging.INFO if allowed else logging.WARNING,
            "scope_decision",
            jobId=self.job_id,
            subject=subject[:300],
            tier=tier,
            allowed=allowed,
            reason=reason,
        )

    def assert_check_allowed(self, check: str) -> Tier:
        """Raises ScopeError when the profile does not list the check (``check_not_allowed``) or the
        check is web/network tier and active scanning is disabled (``active_scanning_disabled``)."""
        subject = f"check:{str(check)[:64]}"
        try:
            tier = tier_of(check)
        except ScopeError:
            self._log(subject, "unknown", False, CHECK_NOT_ALLOWED)
            raise
        if check not in self.checks:
            self._log(subject, tier, False, CHECK_NOT_ALLOWED)
            raise ScopeError(CHECK_NOT_ALLOWED, "The job's profile does not include this check.")
        if tier != "passive" and not self.active_scanning_enabled:
            self._log(subject, tier, False, ACTIVE_SCANNING_DISABLED)
            raise ScopeError(ACTIVE_SCANNING_DISABLED, "Active scanning is disabled.")
        self._log(subject, tier, True, "allowed")
        return tier

    def assert_hostname(self, hostname: str) -> str:
        """Normalised hostname if it is the job's domain or beneath it on a label boundary; else
        ScopeError(``out_of_scope_host``). Redirect targets use this too."""
        try:
            name = normalise_hostname(hostname)
        except ScopeError as exc:
            self._log(f"host:{str(hostname)[:253]!r}", "-", False, "invalid_hostname")
            raise ScopeError(OUT_OF_SCOPE_HOST, "Hostname is not a valid name.") from exc
        if name == self.domain or name.endswith("." + self.domain):
            return name
        self._log(f"host:{name}", "-", False, OUT_OF_SCOPE_HOST)
        raise ScopeError(OUT_OF_SCOPE_HOST, "Hostname is outside the job's domain.")

    def refusal_reason(self, address: IPAddress, tier: Tier) -> str | None:
        """Why ``address`` may not be contacted at ``tier`` (prohibited reason, ``deny_listed`` or
        ``network_not_approved``), or None. Pure: no logging."""
        reason = address_prohibited_reason(address)
        if reason is not None:
            return reason
        if any(address in network for network in self.deny_networks):
            return DENY_LISTED
        if tier == "network" and not any(address in n for n in self.approved_networks):
            return NETWORK_NOT_APPROVED
        if tier not in ("web", "network"):
            return "passive_tier"
        return None

    def resolve(
        self, hostname: str, resolver: DnsResolver, *, tier: Tier, lifetime: float
    ) -> ResolvedHost:
        """Resolves A and AAAA, following and validating each CNAME hop (``cname_out_of_scope`` if a
        hop leaves the domain), drops prohibited / deny-listed / (for ``network`` tier) unapproved
        addresses with a logged reason, and raises ``no_allowed_address`` if none remain."""
        if tier not in ("web", "network"):
            self._log(f"host:{str(hostname)[:253]}", str(tier), False, CHECK_NOT_ALLOWED)
            raise ScopeError(CHECK_NOT_ALLOWED, "Only web and network tiers resolve targets.")
        name = self.assert_hostname(hostname)

        chain: list[str] = []
        seen = {name}
        current = name
        while True:
            answer = resolver.query(current, "CNAME", lifetime)
            targets = {_clean_cname(v.strip()).lower() for v in answer.values}
            if not targets:
                break
            if len(targets) > 1:
                self._log(f"cname:{current}", tier, False, CNAME_CHAIN_INVALID)
                raise ScopeError(CNAME_CHAIN_INVALID, "Multiple CNAME records at one name.")
            (raw_target,) = targets
            try:
                target = normalise_hostname(raw_target)
            except ScopeError as exc:
                self._log(f"cname:{current}->{raw_target[:253]!r}", tier, False, CNAME_OUT_OF_SCOPE)
                raise ScopeError(CNAME_OUT_OF_SCOPE, "CNAME target is not a valid name.") from exc
            if not (target == self.domain or target.endswith("." + self.domain)):
                self._log(f"cname:{current}->{target}", tier, False, CNAME_OUT_OF_SCOPE)
                raise ScopeError(CNAME_OUT_OF_SCOPE, "CNAME target is outside the job's domain.")
            if target in seen:
                self._log(f"cname:{current}->{target}", tier, False, CNAME_CHAIN_INVALID)
                raise ScopeError(CNAME_CHAIN_INVALID, "CNAME loop.")
            if len(chain) >= MAX_CNAME_HOPS:
                self._log(f"cname:{current}->{target}", tier, False, CNAME_CHAIN_INVALID)
                raise ScopeError(CNAME_CHAIN_INVALID, "CNAME chain is too long.")
            self._log(f"cname:{current}->{target}", tier, True, "in_scope")
            chain.append(target)
            seen.add(target)
            current = target

        allowed: list[IPAddress] = []
        dropped: list[tuple[str, str]] = []
        for rdtype in ("A", "AAAA"):
            answer = resolver.query(current, rdtype, lifetime)
            canonical = answer.canonical_name
            if canonical and _clean_cname(canonical).lower() != current:
                # The chain changed between the hop-by-hop walk and this query: its intermediate
                # hops are unknown, so refuse rather than trust it.
                self._log(f"cname:{current}->{canonical[:253]}", tier, False, CNAME_CHAIN_INVALID)
                raise ScopeError(CNAME_CHAIN_INVALID, "CNAME chain changed during resolution.")
            for value in answer.values:
                text = value.strip()
                try:
                    address = parse_address(text)
                except ScopeError:
                    dropped.append((text[:64], "unparseable"))
                    self._log(f"addr:{text[:64]!r} host:{current}", tier, False, "unparseable")
                    continue
                if address.version != (4 if rdtype == "A" else 6):
                    dropped.append((str(address), "wrong_family"))
                    self._log(f"addr:{address} host:{current}", tier, False, "wrong_family")
                    continue
                if address in allowed:
                    continue
                reason = self.refusal_reason(address, tier)
                if reason is not None:
                    if (str(address), reason) not in dropped:
                        dropped.append((str(address), reason))
                    self._log(f"addr:{address} host:{current}", tier, False, reason)
                    continue
                self._log(f"addr:{address} host:{current}", tier, True, "allowed")
                allowed.append(address)

        if not allowed:
            self._log(f"host:{name}", tier, False, NO_ALLOWED_ADDRESS)
            raise ScopeError(NO_ALLOWED_ADDRESS, "The host has no address this check may contact.")
        return ResolvedHost(
            hostname=name,
            addresses=tuple(allowed),
            cname_chain=tuple(chain),
            dropped=tuple(dropped),
        )

    def assert_destination(self, address: IPAddress | str, *, tier: Tier) -> IPAddress:
        """Re-validates one address immediately before a connection is opened to it.

        Raises :class:`AddressRefused` (a ScopeError) with code ``prohibited_address`` (prohibited
        or deny-listed; ``reason`` gives the detail) or ``network_not_approved``; ScopeError
        ``active_scanning_disabled`` when active scanning is off and ``check_not_allowed`` for the
        passive tier, which never connects to targets."""
        if isinstance(address, str):
            try:
                ip = parse_address(address)
            except ScopeError:
                self._log(f"dest:{address[:64]!r}", str(tier), False, "unparseable")
                raise AddressRefused(
                    PROHIBITED_ADDRESS, "unparseable", "Destination is not a valid IP address."
                ) from None
        elif isinstance(address, ipaddress.IPv4Address | ipaddress.IPv6Address):
            ip = address
        else:
            self._log("dest:<non-address>", str(tier), False, "unparseable")
            raise AddressRefused(
                PROHIBITED_ADDRESS, "unparseable", "Destination is not an address."
            )
        subject = f"dest:{ip}"
        if tier not in ("web", "network"):
            self._log(subject, str(tier), False, CHECK_NOT_ALLOWED)
            raise ScopeError(CHECK_NOT_ALLOWED, "Passive checks never connect to targets.")
        if not self.active_scanning_enabled:
            self._log(subject, tier, False, ACTIVE_SCANNING_DISABLED)
            raise ScopeError(ACTIVE_SCANNING_DISABLED, "Active scanning is disabled.")
        reason = self.refusal_reason(ip, tier)
        if reason is not None:
            self._log(subject, tier, False, reason)
            code = NETWORK_NOT_APPROVED if reason == NETWORK_NOT_APPROVED else PROHIBITED_ADDRESS
            raise AddressRefused(code, reason, "Destination address is not allowed.")
        self._log(subject, tier, True, "allowed")
        return ip


__all__ = [
    "ACTIVE_SCANNING_DISABLED",
    "CHECK_NOT_ALLOWED",
    "CNAME_CHAIN_INVALID",
    "CNAME_OUT_OF_SCOPE",
    "DENY_LISTED",
    "MAX_CNAME_HOPS",
    "NETWORK_NOT_APPROVED",
    "NETWORK_TIER_CHECKS",
    "NO_ALLOWED_ADDRESS",
    "OUT_OF_SCOPE_HOST",
    "PASSIVE_TIER_CHECKS",
    "PROHIBITED_ADDRESS",
    "SCOPE_REJECTED",
    "WEB_TIER_CHECKS",
    "AddressRefused",
    "IPAddress",
    "IPNetwork",
    "ResolvedHost",
    "ScopeError",
    "ScopePolicy",
    "Tier",
    "address_prohibited_reason",
    "parse_address",
    "parse_network",
    "tier_of",
]
