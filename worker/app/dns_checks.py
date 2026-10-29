"""Passive DNS check: queries public/configured resolvers only, never the target's own hosts
(beyond what recursive resolution does on the resolver's side).

Per target: ``A``, ``AAAA``, ``CNAME``. At the job's apex additionally ``MX``, ``NS``, ``TXT``,
``CAA``, ``SOA``, ``DS``, ``DNSKEY``, ``TXT`` at ``_dmarc.<apex>`` and (Milestone 15) ``TXT`` at
``<selector>._domainkey.<apex>`` for each of :data:`DKIM_SELECTORS`. When the apex ``MX`` lookup
of the same run lists a real exchanger (not a null MX ``0 .``) also ``TXT`` at
``_mta-sts.<apex>``, ``_smtp._tls.<apex>`` and ``default._bimi.<apex>``
(:data:`MAIL_QUERY_PREFIXES`). Only DNS records are read: the MTA-STS policy file is never
fetched. Results are normalised to ``dns`` observations (``docs/worker-protocol.md``):

- ``hostname``: lowercase, no trailing dot.
- ``values``: dnspython presentation format, sorted, at most 100. Record data that is only domain
  names (``CNAME``, ``NS``, ``MX``, ``SOA``) is lowercased so resolver case randomisation never
  looks like a change; absolute names keep their trailing dot as presentation format requires
  (e.g. a null MX is ``0 .``).
- NXDOMAIN / NODATA: ``success`` with ``values: []`` and ``evidence.rcode``. For an aliased name the
  rcode is the chain's terminal status (a CNAME whose target does not exist is ``NXDOMAIN``), and
  ``evidence.canonicalName`` names the chain's end when it differs from the queried name — also for
  NXDOMAIN answers (subdomain-takeover evidence, rule DNS-008).
- Resolver timeout: ``timeout``; other resolver failures: ``error`` with the exception class only.
- ``geo`` (Milestone 13, A/AAAA only): ``[{ip, country}]`` for values the offline DB-IP database
  (``app.geoip``) places in a country, in ``values`` order; omitted when empty. Display-only, never
  used for scope decisions; a lookup error omits the field and never fails the query.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

import dns.exception
import dns.name
import dns.resolver

from app.checks import CHECKER_VERSION, CheckContext, utc_now_iso

#: ``ip -> ISO 3166-1 alpha-2 country`` or None (``GeoIp.country``).
GeoLookup = Callable[[str], str | None]

TARGET_RECORD_TYPES: tuple[str, ...] = ("A", "AAAA", "CNAME")
APEX_RECORD_TYPES: tuple[str, ...] = ("MX", "NS", "TXT", "CAA", "SOA", "DS", "DNSKEY")
#: Common DKIM selectors (selectors cannot be enumerated through DNS). Google Workspace, Microsoft
#: 365 (selector1/2), Mailchimp/Mandrill (k1-k3, mandrill), SendGrid (s1/s2), Mailjet, Proton,
#: Fastmail (fm1), Zoho and generic names. Dated selectors (e.g. Mimecast ``mimecast20190104``) and
#: per-tenant tokens (Amazon SES) cannot be guessed. A CNAME-delegated selector is followed by the
#: resolver (``evidence.canonicalName`` records the delegation target).
DKIM_SELECTORS: tuple[str, ...] = (
    "google", "selector1", "selector2", "k1", "k2", "k3", "s1", "s2",
    "default", "dkim", "mail", "smtp", "mandrill", "mailjet", "protonmail", "fm1", "zoho",
)  # fmt: skip
#: TXT names queried beneath the apex only when it receives mail (real MX).
MAIL_QUERY_PREFIXES: tuple[str, ...] = ("_mta-sts", "_smtp._tls", "default._bimi")
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


def geo_entries(
    lookup: Callable[[str], str | None] | None, rdtype: str, values: list[str]
) -> list[dict[str, str]]:
    """``[{ip, country}]`` for A/AAAA values with a known country, in ``values`` order (≤ 100).
    Any error yields ``[]`` — geo must never fail or alter a DNS observation."""
    if lookup is None or rdtype not in ("A", "AAAA"):
        return []
    out: list[dict[str, str]] = []
    try:
        for value in values[:100]:
            if len(value) > 45:
                continue
            country = lookup(value)
            if country and len(country) == 2 and country.isascii() and country.isupper():
                out.append({"ip": value, "country": country})
    except Exception:
        return []
    return out


def _nxdomain_canonical(exc: dns.resolver.NXDOMAIN) -> str | None:
    """The CNAME chain's end recorded in a dnspython NXDOMAIN (lowercase, no trailing dot), or None
    when the exception carries no responses (or anything about them is unusable)."""
    try:
        name = _strip_dot(exc.canonical_name.to_text()).lower()
    except Exception:
        return None
    return name if 0 < len(name) <= 253 else None


def query_to_observation(
    resolver: DnsResolver,
    target_id: str,
    hostname: str,
    rdtype: str,
    lifetime: float,
    geo: GeoLookup | None = None,
) -> dict[str, Any]:
    """Runs one query and maps the outcome to a ``dns`` observation (never raises DNS errors)."""
    try:
        answer = resolver.query(hostname, rdtype, lifetime)
    except dns.resolver.NXDOMAIN as exc:
        nx_evidence: dict[str, Any] = {"rcode": "NXDOMAIN"}
        canonical = _nxdomain_canonical(exc)
        if canonical and canonical != hostname:
            nx_evidence["canonicalName"] = canonical
        return _observation(
            target_id, hostname, rdtype, status="success", ttl=None, values=[],
            evidence=nx_evidence,
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
    observation = _observation(
        target_id,
        hostname,
        rdtype,
        status="partial" if truncated else "success",
        ttl=ttl,
        values=values,
        evidence=evidence,
    )
    entries = geo_entries(geo, rdtype, values)
    if entries:
        observation["geo"] = entries
    return observation


def planned_queries(
    hostname: str, is_apex: bool, *, receives_mail: bool = False
) -> list[tuple[str, str]]:
    """Queries for one target. ``receives_mail`` (decided from the apex MX answer of the same run)
    adds the receiving-side mail names; :func:`check_dns` runs those last."""
    queries = [(hostname, rdtype) for rdtype in TARGET_RECORD_TYPES]
    if is_apex:
        queries += [(hostname, rdtype) for rdtype in APEX_RECORD_TYPES]
        queries.append((f"_dmarc.{hostname}", "TXT"))
        queries += [(f"{sel}._domainkey.{hostname}", "TXT") for sel in DKIM_SELECTORS]
        if receives_mail:
            queries += mail_queries(hostname)
    return queries


def mail_queries(hostname: str) -> list[tuple[str, str]]:
    return [(f"{prefix}.{hostname}", "TXT") for prefix in MAIL_QUERY_PREFIXES]


def receives_mail(mx_observation: dict[str, Any] | None) -> bool:
    """True when a successful MX observation lists at least one real exchanger (``10 mx.``), i.e.
    not empty and not only a null MX (``0 .``, RFC 7505)."""
    if not mx_observation or mx_observation.get("resultStatus") != "success":
        return False
    for value in mx_observation.get("values", []):
        parts = str(value).split()
        if len(parts) >= 2 and parts[0].isdigit() and parts[1] != ".":
            return True
    return False


def check_dns(
    resolver: DnsResolver,
    target_id: str,
    hostname: str,
    is_apex: bool,
    ctx: CheckContext,
    sink: Callable[[dict[str, Any]], None],
    geo: GeoLookup | None = None,
) -> None:
    """Queries every planned record for one target, appending observations to ``sink``.

    Raises ``CheckStopped`` / ``TargetTimeout`` between queries; observations already appended
    remain valid evidence.
    """
    queries = planned_queries(hostname, is_apex)
    index = 0
    while index < len(queries):
        name, rdtype = queries[index]
        index += 1
        ctx.before_network_call()
        lifetime = max(0.1, min(ctx.read_seconds, ctx.remaining()))
        observation = query_to_observation(resolver, target_id, name, rdtype, lifetime, geo)
        sink(observation)
        # The receiving-side mail names are queried only when this run's apex MX shows mail.
        if is_apex and name == hostname and rdtype == "MX" and receives_mail(observation):
            queries += mail_queries(hostname)
