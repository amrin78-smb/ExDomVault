"""Passive DNS check: queries public/configured resolvers only, never the target's own hosts
(beyond what recursive resolution does on the resolver's side).

Per target: ``A``, ``AAAA``, ``CNAME``. At the job's apex additionally ``MX``, ``NS``, ``TXT``,
``CAA``, ``SOA``, ``DS``, ``DNSKEY`` and ``TXT`` at ``_dmarc.<apex>``. Results are normalised to
``dns`` observations (``docs/worker-protocol.md``):

- ``hostname``: lowercase, no trailing dot.
- ``values``: dnspython presentation format, sorted, at most 100. Record data that is only domain
  names (``CNAME``, ``NS``, ``MX``, ``SOA``) is lowercased so resolver case randomisation never
  looks like a change; absolute names keep their trailing dot as presentation format requires
  (e.g. a null MX is ``0 .``).
- NXDOMAIN / NODATA: ``success`` with ``values: []`` and ``evidence.rcode``.
- Resolver timeout: ``timeout``; other resolver failures: ``error`` with the exception class only.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

import dns.exception
import dns.name
import dns.resolver

from app.checks import CHECKER_VERSION, CheckContext, utc_now_iso

TARGET_RECORD_TYPES: tuple[str, ...] = ("A", "AAAA", "CNAME")
APEX_RECORD_TYPES: tuple[str, ...] = ("MX", "NS", "TXT", "CAA", "SOA", "DS", "DNSKEY")
_LOWERCASE_TYPES = frozenset({"CNAME", "NS", "MX", "SOA"})
MAX_VALUES = 100
MAX_VALUE_LENGTH = 4096


@dataclass(frozen=True)
class DnsAnswer:
    """A resolver answer reduced to what observations need. Empty ``values`` = NODATA."""

    ttl: int | None
    values: list[str]
    canonical_name: str | None = None


class DnsResolver(Protocol):
    def query(self, name: str, rdtype: str, lifetime: float) -> DnsAnswer:
        """Raises ``dns.resolver.NXDOMAIN``, ``dns.exception.Timeout`` or another
        ``dns.exception.DNSException`` on failure."""
        ...


def _strip_dot(name: str) -> str:
    return name[:-1] if name.endswith(".") and name != "." else name


class DnspythonResolver:
    """dnspython stub resolver using the configured resolvers, or the system's when none are set.

    The answer cache is off so every job observes current data.
    """

    def __init__(self, nameservers: tuple[str, ...] = (), *, timeout: float = 3.0) -> None:
        resolver = dns.resolver.Resolver(configure=not nameservers)
        if nameservers:
            resolver.nameservers = list(nameservers)
        resolver.timeout = timeout
        resolver.cache = None
        self._resolver = resolver

    def query(self, name: str, rdtype: str, lifetime: float) -> DnsAnswer:
        answer = self._resolver.resolve(
            dns.name.from_text(name),
            rdtype,
            raise_on_no_answer=False,
            lifetime=lifetime,
            search=False,
        )
        canonical = _strip_dot(answer.canonical_name.to_text()).lower()
        rrset = answer.rrset
        if rrset is None:
            return DnsAnswer(ttl=None, values=[], canonical_name=canonical)
        return DnsAnswer(
            ttl=int(rrset.ttl),
            values=[rdata.to_text() for rdata in rrset],
            canonical_name=canonical,
        )


def _observation(
    target_id: str,
    hostname: str,
    rdtype: str,
    *,
    status: str,
    ttl: int | None,
    values: list[str],
    evidence: dict[str, Any],
) -> dict[str, Any]:
    return {
        "kind": "dns",
        "targetId": target_id,
        "observedAt": utc_now_iso(),
        "checkerVersion": CHECKER_VERSION,
        "resultStatus": status,
        "evidence": evidence,
        "hostname": hostname,
        "recordType": rdtype,
        "ttl": ttl,
        "values": values,
    }


def normalise_values(rdtype: str, values: list[str]) -> tuple[list[str], bool]:
    """Sorted, de-duplicated presentation values; returns (values, truncated)."""
    out = {v.lower() if rdtype in _LOWERCASE_TYPES else v for v in values}
    truncated = False
    clipped: list[str] = []
    for value in sorted(out):
        if len(value) > MAX_VALUE_LENGTH:
            value = value[:MAX_VALUE_LENGTH]
            truncated = True
        clipped.append(value)
    if len(clipped) > MAX_VALUES:
        clipped = clipped[:MAX_VALUES]
        truncated = True
    return clipped, truncated


def query_to_observation(
    resolver: DnsResolver,
    target_id: str,
    hostname: str,
    rdtype: str,
    lifetime: float,
) -> dict[str, Any]:
    """Runs one query and maps the outcome to a ``dns`` observation (never raises DNS errors)."""
    try:
        answer = resolver.query(hostname, rdtype, lifetime)
    except dns.resolver.NXDOMAIN:
        return _observation(
            target_id, hostname, rdtype, status="success", ttl=None, values=[],
            evidence={"rcode": "NXDOMAIN"},
        )  # fmt: skip
    except dns.resolver.NoAnswer:
        return _observation(
            target_id, hostname, rdtype, status="success", ttl=None, values=[],
            evidence={"rcode": "NOERROR", "noData": True},
        )  # fmt: skip
    except dns.exception.Timeout as exc:
        return _observation(
            target_id, hostname, rdtype, status="timeout", ttl=None, values=[],
            evidence={"error": type(exc).__name__},
        )  # fmt: skip
    except Exception as exc:  # resolver failures (SERVFAIL, refused, malformed...)
        return _observation(
            target_id, hostname, rdtype, status="error", ttl=None, values=[],
            evidence={"error": type(exc).__name__},
        )  # fmt: skip

    values, truncated = normalise_values(rdtype, answer.values)
    evidence: dict[str, Any] = {"rcode": "NOERROR"}
    if not values:
        evidence["noData"] = True
    if answer.canonical_name and answer.canonical_name != hostname:
        evidence["canonicalName"] = answer.canonical_name
    if truncated:
        evidence["truncated"] = True
    ttl = answer.ttl if values else None
    if ttl is not None:
        ttl = max(0, min(int(ttl), 2_147_483_647))
    return _observation(
        target_id,
        hostname,
        rdtype,
        status="partial" if truncated else "success",
        ttl=ttl,
        values=values,
        evidence=evidence,
    )


def planned_queries(hostname: str, is_apex: bool) -> list[tuple[str, str]]:
    queries = [(hostname, rdtype) for rdtype in TARGET_RECORD_TYPES]
    if is_apex:
        queries += [(hostname, rdtype) for rdtype in APEX_RECORD_TYPES]
        queries.append((f"_dmarc.{hostname}", "TXT"))
    return queries


def check_dns(
    resolver: DnsResolver,
    target_id: str,
    hostname: str,
    is_apex: bool,
    ctx: CheckContext,
    sink: Callable[[dict[str, Any]], None],
) -> None:
    """Queries every planned record for one target, appending observations to ``sink``.

    Raises ``CheckStopped`` / ``TargetTimeout`` between queries; observations already appended
    remain valid evidence.
    """
    for name, rdtype in planned_queries(hostname, is_apex):
        ctx.before_network_call()
        lifetime = max(0.1, min(ctx.read_seconds, ctx.remaining()))
        sink(query_to_observation(resolver, target_id, name, rdtype, lifetime))
