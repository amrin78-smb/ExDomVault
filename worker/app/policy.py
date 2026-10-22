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
* Every allow/deny decision is logged as a structured ``scope_decision`` event.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from app.dns_checks import DnsResolver
from app.scope import ScopeError

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
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


def tier_of(check: str) -> Tier:
    """The tier of a known check; raises ScopeError(``check_not_allowed``) for unknown checks."""
    raise NotImplementedError


def parse_address(value: str) -> IPAddress:
    """Strictly parses a canonical IPv4/IPv6 text address. Rejects zone ids (``fe80::1%eth0``),
    non-canonical IPv4 encodings (``0x7f.1``, ``017.0.0.1``, ``2130706433``, ``127.1``), brackets and
    whitespace with ScopeError(``prohibited_address``)."""
    raise NotImplementedError


def address_prohibited_reason(address: IPAddress) -> str | None:
    """Why an address may never be contacted (e.g. ``loopback``, ``private``, ``cgnat``,
    ``link_local``, ``multicast``, ``reserved``, ``unspecified``, ``documentation``, ``benchmarking``,
    ``ipv4_mapped``, ``ipv4_compatible``, ``nat64``, ``6to4``, ``teredo``, ``ula``, ``site_local``,
    ``broadcast``), or None for public unicast. Embedded IPv4 (mapped/compatible/6to4/Teredo/NAT64)
    is always refused — the worker never contacts IPv4 via an IPv6 transition form."""
    raise NotImplementedError


@dataclass(frozen=True)
class ResolvedHost:
    hostname: str
    #: Allowed addresses, de-duplicated, in resolver order (IPv4 first is fine).
    addresses: tuple[IPAddress, ...]
    #: CNAME hops followed, each validated to be within the job's domain.
    cname_chain: tuple[str, ...]
    #: Addresses refused, as (address text, reason).
    dropped: tuple[tuple[str, str], ...]


class ScopePolicy:
    """Per-job scope: the job's domain, target hostnames, approved networks, the operator's deny
    list and whether active scanning is enabled. Immutable once built."""

    domain: str
    job_id: str

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
        ``snapshot['profile']['config']['checks']``, ``snapshot['approvedNetworks']``)."""
        raise NotImplementedError

    def assert_check_allowed(self, check: str) -> Tier:
        """Raises ScopeError when the profile does not list the check (``check_not_allowed``) or the
        check is web/network tier and active scanning is disabled (``active_scanning_disabled``)."""
        raise NotImplementedError

    def assert_hostname(self, hostname: str) -> str:
        """Normalised hostname if it is the job's domain or beneath it on a label boundary; else
        ScopeError(``out_of_scope_host``). Redirect targets use this too."""
        raise NotImplementedError

    def resolve(
        self, hostname: str, resolver: DnsResolver, *, tier: Tier, lifetime: float
    ) -> ResolvedHost:
        """Resolves A and AAAA, following and validating each CNAME hop (``cname_out_of_scope`` if a
        hop leaves the domain), drops prohibited / deny-listed / (for ``network`` tier) unapproved
        addresses with a logged reason, and raises ``no_allowed_address`` if none remain."""
        raise NotImplementedError

    def assert_destination(self, address: IPAddress | str, *, tier: Tier) -> IPAddress:
        """Re-validates one address immediately before a connection is opened to it."""
        raise NotImplementedError


__all__ = [
    "ACTIVE_SCANNING_DISABLED",
    "CHECK_NOT_ALLOWED",
    "CNAME_OUT_OF_SCOPE",
    "NETWORK_NOT_APPROVED",
    "NETWORK_TIER_CHECKS",
    "NO_ALLOWED_ADDRESS",
    "OUT_OF_SCOPE_HOST",
    "PASSIVE_TIER_CHECKS",
    "PROHIBITED_ADDRESS",
    "WEB_TIER_CHECKS",
    "IPAddress",
    "ResolvedHost",
    "ScopeError",
    "ScopePolicy",
    "Tier",
    "address_prohibited_reason",
    "parse_address",
    "tier_of",
]
