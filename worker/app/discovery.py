"""Passive subdomain discovery (design §7): Certificate Transparency candidates for a job's domain.

The ``discovery`` check is **passive**: it never connects to the domain's hosts. It makes HTTPS
requests to fixed provider URLs — crt.sh (one request) and, from Milestone 15, SSLMate Cert Spotter
(paginated, :class:`CertSpotterProvider`) — merges their names, and resolves candidates through the
worker's configured public resolvers (``app.dns_checks``). One failing provider marks the run
``partial`` without failing it (:func:`run_discovery`). Candidates are reported as ``discovery``
observations; the server stores them as ``pending`` assets. Discovery never adds scan targets and
never widens a job's scope (``docs/scan-safety.md``, "Passive discovery").

Pipeline (pure, :func:`normalise_candidate` / :func:`build_candidates`):

1. Lowercase, strip one trailing dot. A leading ``*.`` is stripped and flags the name as a wildcard;
   a ``*`` anywhere else drops the name.
2. Internationalised names: UTS #46 mapping, then each non-ASCII label is converted to an
   A-label and must round-trip (A-label → U-label → same A-label); ``xn--`` labels must round-trip
   as well. Uses the ``idna`` package (IDNA 2008 + UTS #46; already a pinned dependency of httpx).
3. Drop email addresses, IP literals, empty labels, labels that are not LDH (``[a-z0-9-]``, no
   leading/trailing hyphen, ≤ 63 chars; no underscores) and names longer than 253 characters.
4. Exact label boundary: the name must equal the job's domain or end with ``"." + domain``.
5. Deduplicate (a name seen both as a wildcard and exactly is ``wildcard: false``), merge per-name
   metadata, sort by (label count, name) and keep the first :data:`MAX_CANDIDATES`.

Certificates are kept only when ``not_after`` lies within the last :data:`CERT_LOOKBACK_DAYS` days
or in the future (an unparseable ``not_after`` drops the certificate), so long-dead names do not
resurface as candidates.

Provider failures:

- transient (timeout, connection error, HTTP 408/429/5xx, target deadline during the fetch) raise
  :class:`DiscoveryUnavailable`; the job loop reports a **retryable** job failure
  (``discovery_provider_unavailable``) so the server retries with backoff;
- permanent (unexpected status or redirect, unexpected content type, malformed JSON) produce
  ONE ``error`` observation for the domain and the target fails with ``discovery_provider_error``;
  the job still completes;
- a response over :data:`MAX_RESPONSE_BYTES` (or more than :data:`MAX_CANDIDATES` candidates) is
  truncated: ONE ``partial`` observation for the domain marks the run incomplete, and the names
  parsed before the cap are still reported.
"""

from __future__ import annotations

import codecs
import ipaddress
import json
import logging
import math
import re
import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

import httpx
import idna

from app import __version__
from app.checks import CHECKER_VERSION, CheckContext, CheckStopped, TargetTimeout, utc_now_iso
from app.dns_checks import DnsResolver, check_dns
from app.logging_config import get_logger, log_event
from app.scope import assert_registrable_domain

SOURCE_CT = "certificate_transparency"
CRTSH_PROVIDER = "crt.sh"
#: Fixed provider URL; ``{domain}`` is the validated, registrable job domain (``[a-z0-9.-]``).
CRTSH_URL_TEMPLATE = "https://crt.sh/?q=%25.{domain}&output=json"
DISCOVERY_USER_AGENT = f"ExDomainVault-worker/{__version__} (passive discovery)"

MAX_RESPONSE_BYTES = 32 * 1024 * 1024
#: One JSON array element larger than this is treated as malformed (bounds re-parsing work).
MAX_ELEMENT_BYTES = 1024 * 1024
#: Process-wide politeness interval between requests to one provider.
MIN_REQUEST_INTERVAL_SECONDS = 3.0
CERT_LOOKBACK_DAYS = 365
MAX_CANDIDATES = 2000
#: Only the first N candidates (sorted order, apex excluded) are resolved (A, AAAA, CNAME).
MAX_RESOLVED_CANDIDATES = 300
#: Distinct raw names tracked from one response (memory bound); beyond it the run is truncated.
MAX_TRACKED_NAMES = 50_000
MAX_RAW_NAME_LENGTH = 1024
MAX_ISSUERS = 5
MAX_ISSUER_LENGTH = 256

#: Job-level failure code (retryable) and target-level code (permanent provider error).
UNAVAILABLE_CODE = "discovery_provider_unavailable"
PROVIDER_ERROR_CODE = "discovery_provider_error"

_LDH_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_MAX_NAME_LENGTH = 253
_REDIRECT_STATUSES = range(300, 400)
_RETRYABLE_STATUSES = frozenset({408, 425, 429})

_LOG = get_logger("discovery")


# --------------------------------------------------------------------------------------------
# Provider abstraction


class DiscoveryUnavailable(Exception):
    """A transient provider failure: the job is reported as a retryable failure."""

    code = UNAVAILABLE_CODE

    def __init__(self, error_class: str) -> None:
        super().__init__(f"Discovery provider unavailable ({error_class}).")
        self.error_class = error_class


@dataclass
class NameMeta:
    """Metadata merged over every kept certificate that listed a name."""

    certificates: int = 0
    latest_not_after: datetime | None = None
    issuers: set[str] = field(default_factory=set)
    #: Providers that reported the name (filled when results of several providers are merged).
    providers: set[str] = field(default_factory=set)

    def add(self, not_after: datetime | None, issuer: str | None) -> None:
        self.certificates += 1
        if not_after is not None and (
            self.latest_not_after is None or not_after > self.latest_not_after
        ):
            self.latest_not_after = not_after
        if issuer and len(self.issuers) < MAX_ISSUERS:
            self.issuers.add(issuer)

    def merge(self, other: NameMeta) -> None:
        self.certificates += other.certificates
        if other.latest_not_after is not None and (
            self.latest_not_after is None or other.latest_not_after > self.latest_not_after
        ):
            self.latest_not_after = other.latest_not_after
        for issuer in sorted(other.issuers):
            if len(self.issuers) >= MAX_ISSUERS:
                break
            self.issuers.add(issuer)
        self.providers |= other.providers


@dataclass
class ProviderResult:
    """What one provider run produced. ``names`` maps raw (lowercased, stripped) names to their
    metadata; ``error`` is a permanent error class (``None`` when the run produced data)."""

    provider: str
    source: str
    names: dict[str, NameMeta] = field(default_factory=dict)
    certificates: int = 0
    skipped_certificates: int = 0
    truncated: bool = False
    error: str | None = None


class DiscoveryProvider(Protocol):
    name: str
    source: str

    def fetch(self, domain: str, budget: CheckContext) -> ProviderResult:
        """Raises :class:`DiscoveryUnavailable` (transient), ``CheckStopped`` (cancellation)."""
        ...


class Throttle:
    """Spaces requests at least ``min_interval`` seconds apart across all threads of the process."""

    def __init__(
        self,
        min_interval: float,
        *,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._interval = min_interval
        self._monotonic = monotonic
        self._sleep = sleep
        self._next = -math.inf
        self._lock = threading.Lock()

    def acquire(self, budget: CheckContext) -> None:
        """Waits for a slot. Raises ``CheckStopped`` on cancellation and ``TargetTimeout`` when the
        slot lies beyond the remaining budget (the slot is then not consumed)."""
        with self._lock:
            now = self._monotonic()
            slot = max(now, self._next)
            if slot - now > budget.remaining():
                raise TargetTimeout
            self._next = slot + self._interval
        while True:
            if budget.should_stop():
                raise CheckStopped
            remaining = slot - self._monotonic()
            if remaining <= 0:
                return
            self._sleep(min(remaining, 0.5))


_CRTSH_THROTTLE = Throttle(MIN_REQUEST_INTERVAL_SECONDS)


class _Malformed(Exception):
    pass


class JsonArrayStream:
    """Incremental parser for a top-level JSON array of objects (crt.sh output). Complete elements
    are returned as soon as their bytes arrive, so a response cut at the size cap still yields every
    element before the cut. Raises :class:`_Malformed` on anything else."""

    def __init__(self, max_element_bytes: int = MAX_ELEMENT_BYTES) -> None:
        self._decoder = json.JSONDecoder()
        self._utf8 = codecs.getincrementaldecoder("utf-8")("strict")
        self._buf = ""
        self._state = "start"  # start | first | item | sep | done
        self._max_element = max_element_bytes

    def feed(self, data: bytes) -> list[Any]:
        try:
            self._buf += self._utf8.decode(data)
        except UnicodeDecodeError as exc:
            raise _Malformed("invalid_utf8") from exc
        return self._drain()

    def close(self) -> list[Any]:
        try:
            self._buf += self._utf8.decode(b"", final=True)
        except UnicodeDecodeError as exc:
            raise _Malformed("invalid_utf8") from exc
        items = self._drain()
        if self._state != "done":
            raise _Malformed("incomplete")
        return items

    def _drain(self) -> list[Any]:
        out: list[Any] = []
        buf = self._buf
        pos = 0
        size = len(buf)
        while True:
            while pos < size and buf[pos] in " \t\r\n":
                pos += 1
            if pos >= size:
                break
            char = buf[pos]
            if self._state == "start":
                if char != "[":
                    raise _Malformed("not_an_array")
                pos += 1
                self._state = "first"
            elif self._state in ("first", "sep") and char == "]":
                pos += 1
                self._state = "done"
            elif self._state == "sep":
                if char != ",":
                    raise _Malformed("bad_separator")
                pos += 1
                self._state = "item"
            elif self._state in ("first", "item"):
                if char != "{":
                    raise _Malformed("element_not_object")
                try:
                    obj, end = self._decoder.raw_decode(buf, pos)
                except json.JSONDecodeError:
                    if size - pos > self._max_element:
                        raise _Malformed("element_too_large") from None
                    break  # incomplete: wait for more data
                out.append(obj)
                pos = end
                self._state = "sep"
            else:  # done: nothing may follow the array
                raise _Malformed("trailing_data")
        self._buf = buf[pos:]
        return out


def _parse_not_after(value: Any) -> datetime | None:
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _may_concern(raw: str, apex: str) -> bool:
    """Coarse, non-security pre-filter that keeps memory proportional to relevant names: ASCII
    names that cannot end with the domain are skipped early. The pipeline does the exact check."""
    if not raw.isascii():
        return True
    return raw.rstrip(".").endswith(apex)


def absorb_certificate(result: ProviderResult, entry: Any, apex: str, cutoff: datetime) -> None:
    """Adds one crt.sh certificate entry (``name_value``, ``common_name``, ``not_after``,
    ``issuer_name``) to ``result``; expired-before-``cutoff`` or malformed entries are skipped."""
    if not isinstance(entry, dict):
        result.skipped_certificates += 1
        return
    not_after = _parse_not_after(entry.get("not_after"))
    if not_after is None or not_after < cutoff:
        result.skipped_certificates += 1
        return
    issuer = entry.get("issuer_name")
    issuer = issuer[:MAX_ISSUER_LENGTH] if isinstance(issuer, str) and issuer else None
    raw_names: set[str] = set()
    name_value = entry.get("name_value")
    if isinstance(name_value, str):
        raw_names.update(name_value.split("\n"))
    common_name = entry.get("common_name")
    if isinstance(common_name, str):
        raw_names.add(common_name)
    result.certificates += 1
    for raw in raw_names:
        key = raw.strip().lower()
        if not key or len(key) > MAX_RAW_NAME_LENGTH or not _may_concern(key, apex):
            continue
        meta = result.names.get(key)
        if meta is None:
            if len(result.names) >= MAX_TRACKED_NAMES:
                result.truncated = True
                continue
            meta = result.names[key] = NameMeta()
        meta.add(not_after, issuer)


class CrtShProvider:
    """Certificate Transparency via crt.sh's JSON output.

    One GET to :data:`CRTSH_URL_TEMPLATE`: HTTPS only, certificate verified, redirects never
    followed, no proxy settings from the environment, an identifying User-Agent, connect/read
    timeouts from the profile clipped to the target budget, a streamed body capped at
    :data:`MAX_RESPONSE_BYTES`, and at most one request every
    :data:`MIN_REQUEST_INTERVAL_SECONDS` per process.
    """

    name = CRTSH_PROVIDER
    source = SOURCE_CT

    def __init__(
        self,
        *,
        transport: httpx.BaseTransport | None = None,
        throttle: Throttle | None = None,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        max_response_bytes: int = MAX_RESPONSE_BYTES,
    ) -> None:
        self._http = httpx.Client(
            headers={"User-Agent": DISCOVERY_USER_AGENT, "Accept": "application/json"},
            follow_redirects=False,
            verify=True,
            trust_env=False,
            transport=transport,
        )
        self._throttle = throttle or _CRTSH_THROTTLE
        self._now = now
        self._max_bytes = max_response_bytes

    def close(self) -> None:
        self._http.close()

    @staticmethod
    def url_for(domain: str) -> str:
        return CRTSH_URL_TEMPLATE.format(domain=assert_registrable_domain(domain))

    def fetch(self, domain: str, budget: CheckContext) -> ProviderResult:
        apex = assert_registrable_domain(domain)
        url = CRTSH_URL_TEMPLATE.format(domain=apex)
        result = ProviderResult(provider=self.name, source=self.source)
        cutoff = self._now() - timedelta(days=CERT_LOOKBACK_DAYS)
        try:
            self._throttle.acquire(budget)
            budget.before_network_call()
        except TargetTimeout:
            raise DiscoveryUnavailable("target_timeout") from None
        timeout = httpx.Timeout(
            budget.bounded(budget.read_seconds), connect=budget.bounded(budget.connect_seconds)
        )
        try:
            with self._http.stream("GET", url, timeout=timeout) as response:
                status = response.status_code
                if status in _RETRYABLE_STATUSES or status >= 500:
                    raise DiscoveryUnavailable(f"http_{status}")
                if status in _REDIRECT_STATUSES:
                    result.error = "unexpected_redirect"
                    return result
                if status != 200:
                    result.error = f"http_{status}"
                    return result
                media_type = response.headers.get("Content-Type", "").split(";")[0].strip().lower()
                if media_type != "application/json":
                    result.error = "unexpected_content_type"
                    return result
                parser = JsonArrayStream()
                received = 0
                for chunk in response.iter_bytes():
                    if budget.should_stop():
                        raise CheckStopped
                    if budget.remaining() <= 0:
                        raise DiscoveryUnavailable("target_timeout")
                    if received + len(chunk) > self._max_bytes:
                        chunk = chunk[: self._max_bytes - received]
                        result.truncated = True
                    received += len(chunk)
                    for entry in parser.feed(chunk):
                        absorb_certificate(result, entry, apex, cutoff)
                    if result.truncated:
                        break
                if not result.truncated:
                    for entry in parser.close():
                        absorb_certificate(result, entry, apex, cutoff)
        except _Malformed:
            # Names parsed before the malformed part are discarded: the response is not trusted.
            return ProviderResult(provider=self.name, source=self.source, error="invalid_json")
        except httpx.TimeoutException as exc:
            raise DiscoveryUnavailable(type(exc).__name__) from None
        except httpx.HTTPError as exc:
            raise DiscoveryUnavailable(type(exc).__name__) from None
        return result


# --------------------------------------------------------------------------------------------
# Cert Spotter (SSLMate) — second Certificate Transparency provider

CERTSPOTTER_PROVIDER = "certspotter"
#: Fixed provider URL (API v1, free unauthenticated tier). ``{domain}`` is the validated,
#: registrable job domain; ``after`` (pagination cursor) is appended as a query parameter.
CERTSPOTTER_URL_TEMPLATE = (
    "https://api.certspotter.com/v1/issuances?domain={domain}"
    "&include_subdomains=true&expand=dns_names&expand=issuer"
)
CERTSPOTTER_MAX_PAGES = 10
CERTSPOTTER_MAX_PAGE_BYTES = 8 * 1024 * 1024
#: Politeness interval between Cert Spotter requests (the free tier is rate-limited per hour).
CERTSPOTTER_INTERVAL_SECONDS = 2.0
#: A ``Retry-After`` longer than this is not waited for.
CERTSPOTTER_MAX_RETRY_AFTER = 60.0
_CURSOR_RE = re.compile(r"^[0-9A-Za-z_-]{1,64}$")

_CERTSPOTTER_THROTTLE = Throttle(CERTSPOTTER_INTERVAL_SECONDS)


def absorb_issuance(result: ProviderResult, entry: Any, apex: str, cutoff: datetime) -> None:
    """Adds one Cert Spotter issuance (``dns_names``, ``not_after``, ``issuer``) to ``result``."""
    if not isinstance(entry, dict):
        result.skipped_certificates += 1
        return
    not_after = _parse_not_after(entry.get("not_after"))
    names = entry.get("dns_names")
    if not_after is None or not_after < cutoff or not isinstance(names, list):
        result.skipped_certificates += 1
        return
    issuer_obj = entry.get("issuer")
    issuer: str | None = None
    if isinstance(issuer_obj, dict):
        for key in ("friendly_name", "name"):
            value = issuer_obj.get(key)
            if isinstance(value, str) and value:
                issuer = value[:MAX_ISSUER_LENGTH]
                break
    result.certificates += 1
    for raw in {n for n in names[:1000] if isinstance(n, str)}:
        key = raw.strip().lower()
        if not key or len(key) > MAX_RAW_NAME_LENGTH or not _may_concern(key, apex):
            continue
        meta = result.names.get(key)
        if meta is None:
            if len(result.names) >= MAX_TRACKED_NAMES:
                result.truncated = True
                continue
            meta = result.names[key] = NameMeta()
        meta.add(not_after, issuer)


class CertSpotterProvider:
    """Certificate Transparency via SSLMate Cert Spotter's issuances API (v1).

    Same transport rules as :class:`CrtShProvider` (HTTPS, verified, no redirects, no proxies,
    identifying User-Agent, profile timeouts clipped to the budget). Paginates with the ``after``
    cursor (the last issuance ``id`` of the previous page) until an empty page, at most
    :data:`CERTSPOTTER_MAX_PAGES` pages of at most :data:`CERTSPOTTER_MAX_PAGE_BYTES` each (beyond
    that the run is truncated → ``partial``). HTTP 429 with a short ``Retry-After`` is waited for
    once; otherwise a rate limit or server error on the first page is transient
    (:class:`DiscoveryUnavailable`) and on a later page truncates the run (names from earlier pages
    are kept). The API shape was not verified against the live service while building this; tests
    use recorded-shape fixtures.
    """

    name = CERTSPOTTER_PROVIDER
    source = SOURCE_CT

    def __init__(
        self,
        *,
        transport: httpx.BaseTransport | None = None,
        throttle: Throttle | None = None,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        max_pages: int = CERTSPOTTER_MAX_PAGES,
        max_page_bytes: int = CERTSPOTTER_MAX_PAGE_BYTES,
    ) -> None:
        self._http = httpx.Client(
            headers={"User-Agent": DISCOVERY_USER_AGENT, "Accept": "application/json"},
            follow_redirects=False,
            verify=True,
            trust_env=False,
            transport=transport,
        )
        self._throttle = throttle or _CERTSPOTTER_THROTTLE
        self._now = now
        self._monotonic = monotonic
        self._sleep = sleep
        self._max_pages = max_pages
        self._max_bytes = max_page_bytes

    def close(self) -> None:
        self._http.close()

    @staticmethod
    def url_for(domain: str, after: str | None = None) -> str:
        url = CERTSPOTTER_URL_TEMPLATE.format(domain=assert_registrable_domain(domain))
        return url if after is None else f"{url}&after={after}"

    def _get_page(self, url: str, budget: CheckContext) -> tuple[int, Any]:
        """``(status, parsed body or None)``; 429 after the bounded wait is returned as is."""
        waited = False
        while True:
            try:
                self._throttle.acquire(budget)
                budget.before_network_call()
            except TargetTimeout:
                raise DiscoveryUnavailable("target_timeout") from None
            timeout = httpx.Timeout(
                budget.bounded(budget.read_seconds), connect=budget.bounded(budget.connect_seconds)
            )
            try:
                with self._http.stream("GET", url, timeout=timeout) as response:
                    status = response.status_code
                    if status == 429 and not waited:
                        retry_after = response.headers.get("Retry-After", "")
                        try:
                            wait = float(retry_after.strip())
                        except ValueError:
                            wait = -1.0
                        if 0 <= wait <= CERTSPOTTER_MAX_RETRY_AFTER and wait < budget.remaining():
                            waited = True
                            self._wait(wait, budget)
                            continue
                    if status != 200:
                        return status, None
                    media = response.headers.get("Content-Type", "").split(";")[0].strip().lower()
                    if media != "application/json":
                        raise _Malformed("unexpected_content_type")
                    body = bytearray()
                    for chunk in response.iter_bytes():
                        if budget.should_stop():
                            raise CheckStopped
                        body.extend(chunk)
                        if len(body) > self._max_bytes:
                            return status, _TOO_LARGE
            except httpx.TimeoutException as exc:
                raise DiscoveryUnavailable(type(exc).__name__) from None
            except httpx.HTTPError as exc:
                raise DiscoveryUnavailable(type(exc).__name__) from None
            try:
                return status, json.loads(bytes(body))
            except ValueError:
                raise _Malformed("invalid_json") from None

    def _wait(self, seconds: float, budget: CheckContext) -> None:
        end = self._monotonic() + seconds
        while True:
            if budget.should_stop():
                raise CheckStopped
            left = end - self._monotonic()
            if left <= 0:
                return
            self._sleep(min(left, 0.5))

    def fetch(self, domain: str, budget: CheckContext) -> ProviderResult:
        apex = assert_registrable_domain(domain)
        result = ProviderResult(provider=self.name, source=self.source)
        cutoff = self._now() - timedelta(days=CERT_LOOKBACK_DAYS)
        after: str | None = None
        for page in range(self._max_pages + 1):
            if page == self._max_pages:
                result.truncated = True  # more pages may exist
                break
            url = self.url_for(apex, after)
            try:
                status, body = self._get_page(url, budget)
            except DiscoveryUnavailable:
                if page == 0:
                    raise
                result.truncated = True
                break
            except _Malformed as exc:
                if page == 0:
                    return ProviderResult(provider=self.name, source=self.source, error=str(exc))
                result.truncated = True
                break
            if status != 200:
                transient = status in _RETRYABLE_STATUSES or status >= 500
                if page == 0:
                    if transient:
                        raise DiscoveryUnavailable(f"http_{status}")
                    error = "unexpected_redirect" if status in _REDIRECT_STATUSES else None
                    return ProviderResult(
                        provider=self.name, source=self.source, error=error or f"http_{status}"
                    )
                result.truncated = True
                break
            if body is _TOO_LARGE:
                result.truncated = True
                break
            if not isinstance(body, list):
                if page == 0:
                    return ProviderResult(
                        provider=self.name, source=self.source, error="invalid_json"
                    )
                result.truncated = True
                break
            if not body:
                break
            for entry in body:
                absorb_issuance(result, entry, apex, cutoff)
            last = body[-1].get("id") if isinstance(body[-1], dict) else None
            if not isinstance(last, str) or not _CURSOR_RE.fullmatch(last):
                result.truncated = True  # cannot page further safely
                break
            if result.truncated:
                break
            after = last
        return result


_TOO_LARGE = object()


# --------------------------------------------------------------------------------------------
# Candidate pipeline (pure)


@dataclass(frozen=True)
class Candidate:
    hostname: str
    wildcard: bool
    certificates: int = 0
    latest_not_after: datetime | None = None
    issuers: tuple[str, ...] = ()
    providers: tuple[str, ...] = ()


@dataclass(frozen=True)
class CandidateSet:
    candidates: tuple[Candidate, ...]
    truncated: bool
    dropped: int


def _to_ascii_labels(name: str) -> list[str] | None:
    """Labels as lowercase A-labels, or None when the name is not a valid (round-tripping) IDN."""
    if not name.isascii():
        try:
            name = idna.uts46_remap(name, std3_rules=True, transitional=False)
        except (idna.IDNAError, UnicodeError, ValueError):
            return None
    labels: list[str] = []
    for label in name.split("."):
        if not label.isascii():
            try:
                alabel = idna.alabel(label).decode("ascii")
                if idna.ulabel(alabel) != label:
                    return None
            except (idna.IDNAError, UnicodeError, ValueError):
                return None
            label = alabel
        elif label.startswith("xn--"):
            try:
                if idna.alabel(idna.ulabel(label)).decode("ascii") != label:
                    return None
            except (idna.IDNAError, UnicodeError, ValueError):
                return None
        labels.append(label)
    return labels


def normalise_candidate(raw: str) -> tuple[str, bool] | None:
    """``(hostname, wildcard)`` as a lowercase A-label without trailing dot, or None to drop."""
    if not isinstance(raw, str):
        return None
    name = raw.strip().lower()
    if name.endswith("."):
        name = name[:-1]
    wildcard = False
    if name.startswith("*."):
        name = name[2:]
        wildcard = True
    if not name or "*" in name or "@" in name or any(c.isspace() for c in name):
        return None
    try:
        ipaddress.ip_address(name)
        return None  # IP literal
    except ValueError:
        pass
    labels = _to_ascii_labels(name)
    if labels is None or len(labels) < 2:
        return None
    if not all(_LDH_LABEL_RE.fullmatch(label) for label in labels):
        return None
    hostname = ".".join(labels)
    if len(hostname) > _MAX_NAME_LENGTH:
        return None
    return hostname, wildcard


def _sort_key(hostname: str) -> tuple[int, str]:
    return (hostname.count("."), hostname)


def build_candidates(
    domain: str, names: Mapping[str, NameMeta] | Iterable[str], limit: int = MAX_CANDIDATES
) -> CandidateSet:
    """Normalises, boundary-checks, deduplicates and caps raw names for ``domain``."""
    apex = assert_registrable_domain(domain)
    items: Iterable[tuple[str, NameMeta]] = (
        names.items() if isinstance(names, Mapping) else ((n, NameMeta()) for n in names)
    )
    merged: dict[str, tuple[bool, NameMeta]] = {}
    dropped = 0
    for raw, meta in items:
        normalised = normalise_candidate(raw)
        if normalised is None:
            dropped += 1
            continue
        hostname, wildcard = normalised
        if not (hostname == apex or hostname.endswith("." + apex)):
            dropped += 1
            continue
        current = merged.get(hostname)
        if current is None:
            combined = NameMeta()
            combined.merge(meta)
            merged[hostname] = (wildcard, combined)
        else:
            current[1].merge(meta)
            # Seen exactly at least once → not wildcard-only.
            merged[hostname] = (current[0] and wildcard, current[1])
    ordered = sorted(merged, key=_sort_key)
    truncated = len(ordered) > limit
    candidates = tuple(
        Candidate(
            hostname=h,
            wildcard=merged[h][0],
            certificates=merged[h][1].certificates,
            latest_not_after=merged[h][1].latest_not_after,
            issuers=tuple(sorted(merged[h][1].issuers))[:MAX_ISSUERS],
            providers=tuple(sorted(merged[h][1].providers)),
        )
        for h in ordered[:limit]
    )
    return CandidateSet(candidates=candidates, truncated=truncated, dropped=dropped)


# --------------------------------------------------------------------------------------------
# Running the check


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def discovery_observation(
    target_id: str,
    hostname: str,
    *,
    status: str,
    wildcard: bool,
    evidence: dict[str, Any],
    source: str = SOURCE_CT,
) -> dict[str, Any]:
    return {
        "kind": "discovery",
        "targetId": target_id,
        "observedAt": utc_now_iso(),
        "checkerVersion": CHECKER_VERSION,
        "resultStatus": status,
        "evidence": evidence,
        "hostname": hostname,
        "source": source,
        "wildcard": wildcard,
    }


def _candidate_evidence(candidate: Candidate, provider: str) -> dict[str, Any]:
    """``provider``: the first provider (in configured order) that reported the name;
    ``providers``: every provider that did, when more than one."""
    evidence: dict[str, Any] = {"provider": provider, "certificates": candidate.certificates}
    if len(candidate.providers) > 1:
        evidence["providers"] = list(candidate.providers)
    if candidate.latest_not_after is not None:
        evidence["latestNotAfter"] = _iso(candidate.latest_not_after)
    if candidate.issuers:
        evidence["issuers"] = list(candidate.issuers)
    return evidence


@dataclass(frozen=True)
class DiscoveryOutcome:
    """``status``: ``success``, ``partial`` (truncated) or ``error`` (permanent provider error)."""

    status: str
    candidates: int = 0
    resolved: int = 0
    error_class: str | None = None


def resolve_candidates(
    resolver: DnsResolver,
    target_id: str,
    hostnames: list[str],
    ctx: CheckContext,
    sink: Callable[[dict[str, Any]], None],
    *,
    concurrency: int = 1,
) -> int:
    """A, AAAA and CNAME for each name through the configured resolvers (rate-limited by ``ctx``).
    Observations are emitted in ``hostnames`` order. Stops quietly at the target deadline (names
    not yet resolved simply get no ``dns`` observation); ``CheckStopped`` propagates. Returns the
    number of names whose queries all ran."""
    per_name: list[list[dict[str, Any]]] = [[] for _ in hostnames]
    complete = [False] * len(hostnames)
    stopped: list[BaseException] = []

    def work(index: int) -> None:
        if stopped:
            return
        try:
            check_dns(resolver, target_id, hostnames[index], False, ctx, per_name[index].append)
            complete[index] = True
        except TargetTimeout:
            return
        except CheckStopped as exc:
            stopped.append(exc)

    with ThreadPoolExecutor(
        max_workers=max(1, concurrency), thread_name_prefix="discovery-dns"
    ) as pool:
        for future in [pool.submit(work, i) for i in range(len(hostnames))]:
            future.result()
    if stopped:
        raise CheckStopped
    for observations in per_name:
        for observation in observations:
            sink(observation)
    return sum(complete)


def _fetch_all(
    providers: Sequence[DiscoveryProvider], apex: str, ctx: CheckContext
) -> tuple[list[ProviderResult], list[dict[str, Any]], bool]:
    """Runs every provider. Returns (results with data, failures, any transient failure). With a
    single provider a transient failure propagates as before (retryable job failure)."""
    results: list[ProviderResult] = []
    failures: list[dict[str, Any]] = []
    transient = False
    for provider in providers:
        try:
            result = provider.fetch(apex, ctx)
        except DiscoveryUnavailable as exc:
            if len(providers) == 1:
                raise
            transient = True
            failures.append({"provider": provider.name, "errorClass": exc.error_class,
                             "transient": True})  # fmt: skip
            log_event(
                _LOG, logging.WARNING, "discovery_provider_unavailable",
                provider=provider.name, errorClass=exc.error_class,
            )  # fmt: skip
            continue
        if result.error is not None:
            failures.append({"provider": result.provider, "errorClass": result.error})
            log_event(
                _LOG, logging.WARNING, "discovery_provider_error",
                provider=result.provider, errorClass=result.error,
            )  # fmt: skip
            continue
        results.append(result)
    return results, failures, transient


def run_discovery(
    provider: DiscoveryProvider | Sequence[DiscoveryProvider],
    resolver: DnsResolver,
    target_id: str,
    domain: str,
    ctx: CheckContext,
    sink: Callable[[dict[str, Any]], None],
    *,
    concurrency: int = 1,
    resolve_limit: int = MAX_RESOLVED_CANDIDATES,
    candidate_limit: int = MAX_CANDIDATES,
) -> DiscoveryOutcome:
    """Runs the provider(s) for the job's apex, merges their names and appends ``discovery`` and
    ``dns`` observations to ``sink``.

    Several providers (crt.sh, Cert Spotter): one failing provider does not fail the run — the run
    is reported ``partial`` (ONE ``partial`` apex observation whose ``evidence.failedProviders``
    names it) and the other providers' candidates are kept. When no provider produced data: if any
    failure was transient, :class:`DiscoveryUnavailable` is raised (retryable job failure);
    otherwise ONE ``error`` observation per provider and the outcome is ``error``. Raises
    ``CheckStopped`` on cancellation."""
    providers: list[DiscoveryProvider] = (
        list(provider) if isinstance(provider, list | tuple) else [provider]
    )
    apex = assert_registrable_domain(domain)
    results, failures, transient = _fetch_all(providers, apex, ctx)
    if not results:
        if transient:
            raise DiscoveryUnavailable("all_providers_unavailable")
        for failure in failures:
            sink(
                discovery_observation(
                    target_id, apex, status="error", wildcard=False, source=SOURCE_CT,
                    evidence={"provider": failure["provider"], "errorClass": failure["errorClass"]},
                )
            )  # fmt: skip
        first = failures[0]["errorClass"] if failures else "no_provider"
        return DiscoveryOutcome("error", error_class=first)

    order = {r.provider: i for i, r in enumerate(results)}
    names: dict[str, NameMeta] = {}
    for result in results:
        for raw, meta in result.names.items():
            merged = names.get(raw)
            if merged is None:
                merged = names[raw] = NameMeta()
            merged.merge(meta)
            merged.providers.add(result.provider)
    certificates = sum(r.certificates for r in results)
    truncated = any(r.truncated for r in results)
    provider_label = "+".join(r.provider for r in results)

    found = build_candidates(apex, names, candidate_limit)
    incomplete = truncated or found.truncated or bool(failures)
    apex_candidate = next((c for c in found.candidates if c.hostname == apex), None)
    if incomplete:
        # ONE partial observation for the domain: absence of a name proves nothing for this run.
        evidence: dict[str, Any] = {
            "provider": provider_label,
            "truncated": truncated or found.truncated,
            "certificates": certificates,
        }
        if failures:
            evidence["failedProviders"] = failures
        if apex_candidate is not None and apex_candidate.latest_not_after is not None:
            evidence["latestNotAfter"] = _iso(apex_candidate.latest_not_after)
        sink(
            discovery_observation(
                target_id, apex, status="partial", source=SOURCE_CT, evidence=evidence,
                wildcard=apex_candidate.wildcard if apex_candidate is not None else False,
            )
        )  # fmt: skip
    for candidate in found.candidates:
        if incomplete and candidate.hostname == apex:
            continue  # already reported by the partial run observation
        first = min(candidate.providers, key=lambda p: order.get(p, 99), default=provider_label)
        sink(
            discovery_observation(
                target_id, candidate.hostname, status="success", wildcard=candidate.wildcard,
                source=SOURCE_CT, evidence=_candidate_evidence(candidate, first),
            )
        )  # fmt: skip

    to_resolve = [c.hostname for c in found.candidates if c.hostname != apex][:resolve_limit]
    resolved = resolve_candidates(
        resolver, target_id, to_resolve, ctx, sink, concurrency=concurrency
    )
    log_event(
        _LOG, logging.INFO, "discovery_completed",
        provider=provider_label, certificates=certificates,
        skippedCertificates=sum(r.skipped_certificates for r in results),
        candidates=len(found.candidates), dropped=found.dropped, truncated=incomplete,
        failedProviders=len(failures), resolved=resolved, resolutionPlanned=len(to_resolve),
    )  # fmt: skip
    return DiscoveryOutcome(
        "partial" if incomplete else "success",
        candidates=len(found.candidates),
        resolved=resolved,
    )
