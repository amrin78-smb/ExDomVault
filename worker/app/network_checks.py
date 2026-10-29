"""Passive network ownership (Milestone 15): RDAP registration of the domain's current addresses,
and reverse DNS of IP ranges registered to the organisation.

The ``network`` check runs in the weekly discovery job, at the apex target, after ``discovery``.
It never connects to the domain's hosts or to the addresses it looks up:

1. **RDAP** (``/ip/<address>``) for each distinct public address the server sent in the claimed
   job (``job.network.addresses``: current addresses of the domain's approved assets). The registry
   comes from the IANA IP bootstrap files (``https://data.iana.org/rdap/ipv4.json`` /
   ``ipv6.json``, cached 24 h); only the five Regional Internet Registries' RDAP hosts
   (:data:`RIR_HOSTS`) are ever queried, HTTPS only with a verified certificate, no proxies from
   the environment, an identifying User-Agent, bounded timeouts, a 1 MB response cap, at most
   :data:`MAX_REDIRECTS` redirects and only to another RIR host, at least
   :data:`REGISTRY_INTERVAL_SECONDS` between requests to one registry (process-wide), and one
   bounded retry honouring ``Retry-After`` on HTTP 429. Results are cached per run: an address
   inside a network already fetched is not queried again.
2. **Organisation match**: ``matchedOrg`` is true when a configured organisation name
   (``job.network.orgNames``, server setting ``discovery_org_names``) matches the network's
   registrant/organisation names, network name or description (:func:`org_name_matches`; the server
   re-checks on ingest with the same algorithm).
3. **Reverse DNS** of matched IPv4 networks of at most :data:`MAX_PTR_NETWORK_SIZE` addresses
   (a /22): one PTR query per address through the worker's configured public resolvers, on the
   job's rate limiter, at most :data:`MAX_PTR_QUERIES` per run and within the time budget. Larger
   networks and IPv6 are skipped (the reason is recorded in the network observation's evidence).
   PTR names that lie within the **job's** domain (exact label boundary) become ``discovery``
   observations with source ``reverse_dns`` (the server stores them as ``pending`` assets with
   source ``dns``); names outside it are only counted. They are then resolved (A, AAAA, CNAME)
   like Certificate Transparency candidates.

One ``network`` observation is emitted per distinct network (``evidence.addresses`` = the job
addresses inside it); an address whose RDAP lookup failed gets one ``error``/``timeout``
observation with only ``ipAddress`` set.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import threading
import time
import unicodedata
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

import dns.exception
import dns.resolver
import httpx

from app import __version__
from app.checks import CHECKER_VERSION, CheckContext, CheckStopped, TargetTimeout, utc_now_iso
from app.discovery import Throttle, discovery_observation, normalise_candidate, resolve_candidates
from app.dns_checks import DnsResolver
from app.logging_config import get_logger, log_event
from app.policy import address_prohibited_reason, parse_address
from app.scope import ScopeError, assert_registrable_domain

SOURCE_REVERSE_DNS = "reverse_dns"
NETWORK_USER_AGENT = f"ExDomainVault-worker/{__version__} (passive network ownership)"

BOOTSTRAP_URLS = {
    4: "https://data.iana.org/rdap/ipv4.json",
    6: "https://data.iana.org/rdap/ipv6.json",
}
BOOTSTRAP_TTL_SECONDS = 24 * 3600
#: The only RDAP servers queried (host → registry key in the observation).
RIR_HOSTS: dict[str, str] = {
    "rdap.apnic.net": "apnic",
    "rdap.arin.net": "arin",
    "rdap.db.ripe.net": "ripe",
    "rdap.lacnic.net": "lacnic",
    "rdap.afrinic.net": "afrinic",
}
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_REDIRECTS = 2
REGISTRY_INTERVAL_SECONDS = 1.0
#: A ``Retry-After`` longer than this is not waited for (the lookup fails instead).
MAX_RETRY_AFTER_SECONDS = 30.0
MAX_429_RETRIES = 1
#: Distinct addresses taken from the job (the server sends at most this many).
MAX_ADDRESSES = 256
#: RDAP ``/ip`` queries per run (cache hits do not count).
MAX_RDAP_QUERIES = 100
MAX_PTR_NETWORK_SIZE = 1024
MAX_PTR_QUERIES = 2048
MAX_REVERSE_NAMES = 500
MAX_CIDRS = 32
MAX_ENTITY_NAMES = 10
MAX_NAME_LENGTH = 200
MAX_ORG_LENGTH = 300

_COUNTRY_RE = re.compile(r"^[A-Z]{2}$")
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_NON_ALNUM = re.compile(r"[^0-9a-z]+")

_LOG = get_logger("network")

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


# --------------------------------------------------------------------------------------------
# Organisation matching (mirrored by packages/shared `orgNameMatches`)


def normalise_org(text: str) -> str:
    """NFKC, lowercased, every run of characters other than ASCII letters/digits → one space,
    trimmed (so names in non-Latin scripts never match; RIR records are ASCII)."""
    folded = unicodedata.normalize("NFKC", text).lower()
    return _NON_ALNUM.sub(" ", folded).strip()


def _token_runs_equal(tokens: list[str], needle: str) -> bool:
    """True when some run of consecutive tokens, concatenated, equals ``needle``."""
    for start in range(len(tokens)):
        joined = ""
        for token in tokens[start:]:
            joined += token
            if joined == needle:
                return True
            if len(joined) >= len(needle):
                break
    return False


def org_name_matches(org_names: Iterable[str], candidates: Iterable[str | None]) -> bool:
    """True when a configured name matches a candidate text on word boundaries, ignoring case,
    punctuation and spacing: both are normalised (:func:`normalise_org`) and the name, with its
    spaces removed, must equal a run of consecutive words of the candidate joined together. So
    ``Thai Union`` matches ``Thai Union Group PCL``, ``THAI-UNION Europe`` and ``THAIUNION-TH``,
    but not ``Thai Unionist``, ``Thailand Union`` or ``THAIUNIONGROUP``."""
    needles = [
        n.replace(" ", "") for n in (normalise_org(o) for o in org_names if isinstance(o, str)) if n
    ]
    if not needles:
        return False
    for raw in candidates:
        if not isinstance(raw, str) or not raw.strip():
            continue
        tokens = normalise_org(raw).split()
        if any(_token_runs_equal(tokens, needle) for needle in needles):
            return True
    return False


# --------------------------------------------------------------------------------------------
# RDAP client


class NetworkRdapError(Exception):
    def __init__(self, reason: str, *, timeout: bool = False, http_status: int | None = None):
        super().__init__(reason)
        self.reason = reason
        self.timeout = timeout
        self.http_status = http_status


def parse_ip_bootstrap(document: Any) -> list[tuple[IPNetwork, str]]:
    """``[(prefix, base_url)]`` for entries served by a known RIR host over HTTPS."""
    if not isinstance(document, dict) or not isinstance(document.get("services"), list):
        raise NetworkRdapError("invalid_bootstrap")
    out: list[tuple[IPNetwork, str]] = []
    for entry in document["services"]:
        if not isinstance(entry, list) or len(entry) != 2:
            continue
        if not all(isinstance(part, list) for part in entry):
            continue
        base = next((u for u in entry[1] if isinstance(u, str) and registry_of(u)), None)
        if base is None:
            continue
        for prefix in entry[0]:
            if not isinstance(prefix, str):
                continue
            try:
                out.append((ipaddress.ip_network(prefix, strict=False), base))
            except ValueError:
                continue
    return out


def registry_of(url: str) -> str | None:
    """The RIR key of an ``https://`` URL on a known RIR host, else None."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme != "https" or parts.port not in (None, 443):
        return None
    return RIR_HOSTS.get((parts.hostname or "").lower())


def match_ip_bootstrap(services: Sequence[tuple[IPNetwork, str]], address: IPAddress) -> str | None:
    best: tuple[int, str] | None = None
    for network, base in services:
        if (
            network.version == address.version
            and address in network
            and (best is None or network.prefixlen > best[0])
        ):
            best = (network.prefixlen, base)
    return best[1] if best else None


class RdapIpClient:
    """Fetches IANA IP bootstrap files and RIR ``/ip`` objects (see the module docstring)."""

    def __init__(
        self,
        *,
        transport: httpx.BaseTransport | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        interval: float = REGISTRY_INTERVAL_SECONDS,
    ) -> None:
        self._http = httpx.Client(
            headers={"User-Agent": NETWORK_USER_AGENT},
            follow_redirects=False,
            verify=True,
            trust_env=False,
            transport=transport,
        )
        self._clock = clock
        self._sleep = sleep
        self._interval = interval
        self._bootstrap: dict[int, tuple[float, list[tuple[IPNetwork, str]]]] = {}
        self._throttles: dict[str, Throttle] = {}
        self._lock = threading.Lock()

    def close(self) -> None:
        self._http.close()

    def _throttle(self, host: str) -> Throttle:
        with self._lock:
            throttle = self._throttles.get(host)
            if throttle is None:
                throttle = Throttle(self._interval, monotonic=self._clock, sleep=self._sleep)
                self._throttles[host] = throttle
            return throttle

    def get_json(self, url: str, ctx: CheckContext, accept: str) -> Any:
        """GET with redirects only between allowed hosts and a bounded 429 retry."""
        retries = 0
        redirects = 0
        while True:
            parts = urlsplit(url)
            host = (parts.hostname or "").lower()
            if parts.scheme != "https" or (host != "data.iana.org" and host not in RIR_HOSTS):
                raise NetworkRdapError("host_not_allowed")
            try:
                self._throttle(host).acquire(ctx)
            except TargetTimeout:
                raise NetworkRdapError("target_timeout", timeout=True) from None
            ctx.before_network_call()
            timeout = httpx.Timeout(
                ctx.bounded(ctx.read_seconds), connect=ctx.bounded(ctx.connect_seconds)
            )
            try:
                with self._http.stream(
                    "GET", url, headers={"Accept": accept}, timeout=timeout
                ) as response:
                    status = response.status_code
                    if status in _REDIRECT_STATUSES:
                        location = response.headers.get("Location", "")
                        redirects += 1
                        if not location or redirects > MAX_REDIRECTS:
                            raise NetworkRdapError("redirect_refused", http_status=status)
                        url = urljoin(url, location)
                        if registry_of(url) is None:
                            raise NetworkRdapError("redirect_refused", http_status=status)
                        continue
                    if status == 429:
                        wait = _retry_after(response.headers.get("Retry-After"))
                        if (
                            retries >= MAX_429_RETRIES
                            or wait is None
                            or wait > MAX_RETRY_AFTER_SECONDS
                            or wait >= ctx.remaining()
                        ):
                            raise NetworkRdapError("rate_limited", http_status=429)
                        retries += 1
                        self._wait(wait, ctx)
                        continue
                    if status == 404:
                        raise NetworkRdapError("not_found", http_status=404)
                    if status != 200:
                        raise NetworkRdapError("http_error", http_status=status)
                    body = bytearray()
                    for chunk in response.iter_bytes():
                        body.extend(chunk)
                        if len(body) > MAX_RESPONSE_BYTES:
                            raise NetworkRdapError("response_too_large", http_status=status)
            except httpx.TimeoutException as exc:
                raise NetworkRdapError(type(exc).__name__, timeout=True) from None
            except httpx.HTTPError as exc:
                raise NetworkRdapError(type(exc).__name__) from None
            try:
                return json.loads(bytes(body))
            except ValueError:
                raise NetworkRdapError("invalid_json", http_status=200) from None

    def _wait(self, seconds: float, ctx: CheckContext) -> None:
        end = self._clock() + seconds
        while True:
            if ctx.should_stop():
                raise CheckStopped
            left = end - self._clock()
            if left <= 0:
                return
            self._sleep(min(left, 0.5))

    def base_url_for(self, address: IPAddress, ctx: CheckContext) -> str | None:
        version = address.version
        with self._lock:
            cached = self._bootstrap.get(version)
        if cached is None or self._clock() - cached[0] >= BOOTSTRAP_TTL_SECONDS:
            document = self.get_json(BOOTSTRAP_URLS[version], ctx, "application/json")
            services = parse_ip_bootstrap(document)
            with self._lock:
                self._bootstrap[version] = (self._clock(), services)
        else:
            services = cached[1]
        return match_ip_bootstrap(services, address)

    def lookup(self, address: IPAddress, ctx: CheckContext) -> tuple[str, Any]:
        """``(registry, document)`` for the network containing ``address``."""
        base = self.base_url_for(address, ctx)
        if base is None:
            raise NetworkRdapError("no_rdap_service")
        url = base.rstrip("/") + "/ip/" + str(address)
        document = self.get_json(url, ctx, "application/rdap+json")
        return registry_of(base) or "", document


def _retry_after(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        seconds = float(value.strip())
    except ValueError:
        return None  # HTTP-date form: not waited for
    return seconds if seconds >= 0 else None


# --------------------------------------------------------------------------------------------
# Parsing (pure)


@dataclass
class NetworkInfo:
    registry: str | None
    handle: str | None
    name: str | None
    org_name: str | None
    country: str | None
    start: IPAddress | None
    end: IPAddress | None
    cidrs: list[str]
    entity_names: list[str] = field(default_factory=list)

    def contains(self, address: IPAddress) -> bool:
        return (
            self.start is not None
            and self.end is not None
            and self.start.version == address.version
            and self.start <= address <= self.end
        )

    @property
    def size(self) -> int | None:
        if self.start is None or self.end is None or self.start.version != self.end.version:
            return None
        return int(self.end) - int(self.start) + 1


def _clip(value: Any, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    text = " ".join(value.split())
    return text[:limit] if text else None


def _vcard_names(entity: dict[str, Any]) -> list[str]:
    vcard = entity.get("vcardArray")
    if not (isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list)):
        return []
    names: list[str] = []
    for prop in vcard[1]:
        if isinstance(prop, list) and len(prop) >= 4 and prop[0] in ("fn", "org"):
            value = prop[3]
            if isinstance(value, list):  # structured `org` value
                value = " ".join(v for v in value if isinstance(v, str))
            clipped = _clip(value, MAX_ORG_LENGTH)
            if clipped:
                names.append(clipped)
    return names


def _entities(document: dict[str, Any]) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    stack = [document]
    while stack and len(found) < 100:
        node = stack.pop()
        entities = node.get("entities")
        for entity in entities if isinstance(entities, list) else []:
            if isinstance(entity, dict):
                found.append(entity)
                stack.append(entity)
    return found


def _remark_lines(document: dict[str, Any]) -> list[str]:
    """Description lines of the network's own remarks (APNIC/RIPE ``descr``)."""
    lines: list[str] = []
    remarks = document.get("remarks")
    for remark in remarks if isinstance(remarks, list) else []:
        if not isinstance(remark, dict):
            continue
        title = remark.get("title")
        if isinstance(title, str) and title.lower() not in ("description", "descr", "remarks"):
            continue
        description = remark.get("description")
        for line in description if isinstance(description, list) else []:
            clipped = _clip(line, MAX_ORG_LENGTH)
            if clipped:
                lines.append(clipped)
            if len(lines) >= 5:
                return lines
    return lines


def _address(value: Any) -> IPAddress | None:
    if not isinstance(value, str):
        return None
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def _cidrs(document: dict[str, Any], start: IPAddress | None, end: IPAddress | None) -> list[str]:
    out: list[str] = []
    raw = document.get("cidr0_cidrs")
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            continue
        prefix = item.get("v4prefix") or item.get("v6prefix")
        length = item.get("length")
        if not isinstance(prefix, str) or isinstance(length, bool) or not isinstance(length, int):
            continue
        try:
            network = ipaddress.ip_network(f"{prefix.strip()}/{length}", strict=False)
        except ValueError:
            continue
        text = str(network)
        if text not in out:
            out.append(text)
        if len(out) >= MAX_CIDRS:
            return out
    if not out and start is not None and end is not None and start.version == end.version:
        try:
            out = [str(n) for n in ipaddress.summarize_address_range(start, end)][:MAX_CIDRS]  # type: ignore[arg-type]
        except (TypeError, ValueError):
            out = []
    return out


def parse_rdap_network(document: Any, registry: str | None) -> NetworkInfo:
    """Extracts range, CIDRs, handle, name, country and organisation names from an RDAP
    ``ip network`` object (RFC 9083, ``cidr0`` extension)."""
    if not isinstance(document, dict):
        raise NetworkRdapError("invalid_response")
    start = _address(document.get("startAddress"))
    end = _address(document.get("endAddress"))
    if start is not None and end is not None and (start.version != end.version or end < start):
        start = end = None
    country = document.get("country")
    country = country.strip().upper() if isinstance(country, str) else None
    if country is not None and not _COUNTRY_RE.fullmatch(country):
        country = None

    registrant: list[str] = []
    others: list[str] = []
    for entity in _entities(document):
        roles = entity.get("roles")
        roles = [r for r in roles if isinstance(r, str)] if isinstance(roles, list) else []
        names = _vcard_names(entity)
        if "registrant" in roles:
            registrant.extend(names)
        elif "administrative" in roles:
            others.extend(names)
    remarks = _remark_lines(document)
    org_name = (registrant or remarks or others or [None])[0]
    entity_names: list[str] = []
    for name in [*registrant, *others, *remarks]:
        if name not in entity_names:
            entity_names.append(name)
    return NetworkInfo(
        registry=registry or None,
        handle=_clip(document.get("handle"), MAX_NAME_LENGTH),
        name=_clip(document.get("name"), MAX_NAME_LENGTH),
        org_name=org_name,
        country=country,
        start=start,
        end=end,
        cidrs=_cidrs(document, start, end),
        entity_names=entity_names[:MAX_ENTITY_NAMES],
    )


# --------------------------------------------------------------------------------------------
# Running the check


@dataclass(frozen=True)
class NetworkContext:
    """What the server sent with the claimed job (``job.network``)."""

    org_names: tuple[str, ...] = ()
    addresses: tuple[str, ...] = ()


def parse_network_context(raw: Any) -> NetworkContext:
    """Lenient: anything malformed is dropped (the check then has less to do, never more)."""
    if not isinstance(raw, dict):
        return NetworkContext()
    org_names = raw.get("orgNames")
    addresses = raw.get("addresses")
    names = tuple(
        n.strip()[:100] for n in (org_names if isinstance(org_names, list) else [])
        if isinstance(n, str) and n.strip()
    )[:20]  # fmt: skip
    raw_addresses = addresses if isinstance(addresses, list) else []
    addrs = tuple(a for a in raw_addresses if isinstance(a, str))
    return NetworkContext(org_names=names, addresses=addrs[:MAX_ADDRESSES])


def _public_addresses(values: Iterable[str]) -> list[IPAddress]:
    out: list[IPAddress] = []
    seen: set[IPAddress] = set()
    for value in values:
        try:
            address = parse_address(value.strip())
        except (ScopeError, AttributeError):
            continue
        if address_prohibited_reason(address) is not None or address in seen:
            continue
        seen.add(address)
        out.append(address)
        if len(out) >= MAX_ADDRESSES:
            break
    return sorted(out, key=lambda a: (a.version, int(a)))


def network_observation(
    target_id: str,
    address: IPAddress,
    *,
    status: str,
    info: NetworkInfo | None = None,
    matched: bool = False,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "kind": "network",
        "targetId": target_id,
        "observedAt": utc_now_iso(),
        "checkerVersion": CHECKER_VERSION,
        "resultStatus": status,
        "evidence": evidence or {},
        "ipAddress": str(address),
        "startAddress": str(info.start) if info and info.start else None,
        "endAddress": str(info.end) if info and info.end else None,
        "cidrs": info.cidrs if info else [],
        "registry": info.registry if info else None,
        "handle": info.handle if info else None,
        "networkName": info.name if info else None,
        "orgName": info.org_name if info else None,
        "country": info.country if info else None,
        "matchedOrg": matched,
    }


@dataclass
class _Network:
    info: NetworkInfo
    first_address: IPAddress
    addresses: list[str] = field(default_factory=list)
    matched: bool = False
    reverse: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class NetworkOutcome:
    networks: int = 0
    matched: int = 0
    failed: int = 0
    reverse_names: int = 0


def _ptr_names(answer_values: Iterable[str]) -> list[str]:
    names: list[str] = []
    for value in answer_values:
        normalised = normalise_candidate(str(value))
        if normalised is not None and not normalised[1]:
            names.append(normalised[0])
    return names


def reverse_dns(
    resolver: DnsResolver,
    network: NetworkInfo,
    apex: str,
    ctx: CheckContext,
    budget: list[int],
) -> tuple[dict[str, list[str]], dict[str, Any]]:
    """PTR for every address of an eligible network. Returns ``(names within the apex → the
    addresses that named them, evidence)``. ``budget[0]`` is the remaining query allowance."""
    size = network.size
    if network.start is None or network.end is None or size is None:
        return {}, {"status": "skipped", "reason": "range_unknown"}
    if network.start.version != 4:
        return {}, {"status": "skipped", "reason": "ipv6"}
    if size > MAX_PTR_NETWORK_SIZE:
        return {}, {"status": "skipped", "reason": "too_large", "size": size}
    found: dict[str, list[str]] = {}
    queried = errors = outside = 0
    status = "complete"
    first = int(network.start)
    for offset in range(size):
        if budget[0] <= 0:
            status = "query_cap"
            break
        address = ipaddress.IPv4Address(first + offset)
        try:
            ctx.before_network_call()
        except TargetTimeout:
            status = "time_cap"
            break
        budget[0] -= 1
        queried += 1
        try:
            answer = resolver.query(address.reverse_pointer, "PTR", ctx.bounded(ctx.read_seconds))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except dns.exception.DNSException:
            errors += 1
            continue
        for name in _ptr_names(answer.values):
            if name == apex or name.endswith("." + apex):
                addresses = found.setdefault(name, [])
                if len(addresses) < 10:
                    addresses.append(str(address))
            else:
                outside += 1
    evidence = {
        "status": status, "size": size, "queried": queried, "errors": errors,
        "namesInDomain": len(found), "namesOutsideDomain": outside,
    }  # fmt: skip
    return found, evidence


def run_network(
    client: RdapIpClient,
    resolver: DnsResolver,
    target_id: str,
    domain: str,
    context: NetworkContext,
    ctx: CheckContext,
    sink: Callable[[dict[str, Any]], None],
    *,
    concurrency: int = 1,
    max_queries: int = MAX_RDAP_QUERIES,
    max_ptr_queries: int = MAX_PTR_QUERIES,
) -> NetworkOutcome:
    """Runs RDAP ownership + reverse DNS for ``context.addresses`` (see the module docstring).
    ``CheckStopped`` propagates; the time budget ends the run quietly with what was found."""
    apex = assert_registrable_domain(domain)
    addresses = _public_addresses(context.addresses)
    networks: list[_Network] = []
    failures: list[dict[str, Any]] = []
    queries = 0
    out_of_time = False
    for address in addresses:
        known = next((n for n in networks if n.info.contains(address)), None)
        if known is not None:
            if len(known.addresses) < 64:
                known.addresses.append(str(address))
            continue
        if queries >= max_queries or out_of_time:
            continue
        queries += 1
        try:
            registry, document = client.lookup(address, ctx)
            info = parse_rdap_network(document, registry)
        except NetworkRdapError as exc:
            evidence: dict[str, Any] = {"errorClass": exc.reason}
            if exc.http_status is not None:
                evidence["http"] = exc.http_status
            failures.append(
                network_observation(
                    target_id, address, status="timeout" if exc.timeout else "error",
                    evidence=evidence,
                )
            )  # fmt: skip
            if exc.reason == "target_timeout":
                out_of_time = True
            continue
        except TargetTimeout:
            out_of_time = True
            continue
        matched = org_name_matches(
            context.org_names, [info.org_name, info.name, *info.entity_names]
        )
        networks.append(_Network(info, address, [str(address)], matched))

    reverse: dict[str, tuple[list[str], str]] = {}
    ptr_budget = [max_ptr_queries]
    for network in networks:
        if not network.matched:
            continue
        found, evidence = reverse_dns(resolver, network.info, apex, ctx, ptr_budget)
        network.reverse = evidence
        cidr = network.info.cidrs[0] if network.info.cidrs else None
        for name, addrs in found.items():
            if name not in reverse and len(reverse) < MAX_REVERSE_NAMES:
                reverse[name] = (addrs, cidr or "")

    for network in networks:
        evidence = {"addresses": network.addresses}
        if network.info.entity_names:
            evidence["entityNames"] = network.info.entity_names
        if network.reverse:
            evidence["reverseDns"] = network.reverse
        elif not network.matched:
            evidence["reverseDns"] = {"status": "skipped", "reason": "not_matched"}
        sink(
            network_observation(
                target_id, network.first_address, status="success", info=network.info,
                matched=network.matched, evidence=evidence,
            )
        )  # fmt: skip
    for failure in failures:
        sink(failure)
    for name in sorted(reverse, key=lambda h: (h.count("."), h)):
        addrs, cidr = reverse[name]
        evidence = {"provider": "ptr", "addresses": addrs}
        if cidr:
            evidence["network"] = cidr
        sink(
            discovery_observation(
                target_id, name, status="success", wildcard=False, source=SOURCE_REVERSE_DNS,
                evidence=evidence,
            )
        )  # fmt: skip
    to_resolve = [n for n in sorted(reverse) if n != apex]
    if to_resolve:
        resolve_candidates(resolver, target_id, to_resolve, ctx, sink, concurrency=concurrency)
    outcome = NetworkOutcome(
        networks=len(networks),
        matched=sum(1 for n in networks if n.matched),
        failed=len(failures),
        reverse_names=len(reverse),
    )
    log_event(
        _LOG, logging.INFO, "network_completed",
        addresses=len(addresses), queries=queries, networks=outcome.networks,
        matched=outcome.matched, failed=outcome.failed, reverseNames=outcome.reverse_names,
        outOfTime=out_of_time,
    )  # fmt: skip
    return outcome
