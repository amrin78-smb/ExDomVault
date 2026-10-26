"""Offline IP-to-country lookup for DNS observations (Milestone 13). Display-only data.

Source: DB-IP "IP to Country Lite" (https://db-ip.com/db/download/ip-to-country-lite), licensed
CC BY 4.0 — attribution "IP geolocation by DB-IP" is shown wherever the data is displayed. The
monthly file is a gzip-compressed CSV without a header, one range per row::

    1.0.0.0,1.0.0.255,AU
    2001:200::,2001:200:ffff:ffff:ffff:ffff:ffff:ffff,JP

IPv4 and IPv6 rows are each in ascending, non-overlapping order (IPv4 block first). ``ZZ`` marks
unallocated/unknown space.

Safety properties:

- The country is **never** used for scope, policy or severity decisions; it only annotates ``dns``
  observations (``geo``). Prohibited (private, loopback, reserved...) addresses are never looked up.
- Download: one GET to a fixed HTTPS URL built in code (``download.db-ip.com``, current month,
  then the previous month when the current file is not published yet). TLS verified, redirects
  never followed (a 3xx is a failed attempt), no proxy settings from the environment, an
  identifying User-Agent, connect/read timeouts and an overall deadline, the body streamed into
  the cache directory and capped at :data:`MAX_COMPRESSED_BYTES`.
- The new file is fully parsed (decompressed size capped at :data:`MAX_DECOMPRESSED_BYTES`, at
  least ``min_ranges`` valid ranges) **before** it atomically replaces the cached copy
  (temp file + ``fsync`` + ``os.replace``). On any failure the previous file stays in use; with no
  file at all geo is omitted. Failed refreshes back off for :data:`RETRY_BACKOFF_SECONDS`.
- Refresh and load happen between jobs (``GeoIp.maybe_refresh``), never inside a DNS check;
  :meth:`GeoIp.country` only reads the in-memory tables and never raises.

Memory: IPv4 ranges as two ``array("I")`` + one ``array("B")`` country index (9 bytes/range); IPv6
ranges as four ``array("Q")`` halves + one ``array("B")`` (33 bytes/range). Measured with a
synthetic 600k-row file (350k IPv4 + 250k IPv6): ~13 MB RSS, ~1.6 s to load, ~1 us per lookup.
"""

from __future__ import annotations

import contextlib
import csv
import gzip
import io
import ipaddress
import json
import logging
import os
import socket
import tempfile
import threading
import time
from array import array
from bisect import bisect_right
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx

from app import __version__
from app.logging_config import get_logger, log_event
from app.policy import address_prohibited_reason

DBIP_URL_TEMPLATE = "https://download.db-ip.com/free/dbip-country-lite-{month}.csv.gz"
GEOIP_USER_AGENT = f"ExDomainVault-worker/{__version__} (geoip download)"
CACHE_FILENAME = "dbip-country-lite.csv.gz"
META_FILENAME = "dbip-country-lite.json"
ATTRIBUTION = "IP geolocation by DB-IP"

MAX_COMPRESSED_BYTES = 64 * 1024 * 1024
MAX_DECOMPRESSED_BYTES = 512 * 1024 * 1024
MAX_RANGES = 5_000_000
#: The real file has ~600k ranges; anything far smaller is truncated or not the expected file.
DEFAULT_MIN_RANGES = 100_000
MAX_AGE_SECONDS = 35 * 86400
#: A cached previous-month file is re-checked for the current month at most once a day.
NEWER_MONTH_CHECK_SECONDS = 86400
RETRY_BACKOFF_SECONDS = 6 * 3600
CONNECT_TIMEOUT_SECONDS = 10.0
READ_TIMEOUT_SECONDS = 30.0
DOWNLOAD_DEADLINE_SECONDS = 300.0
_MAX_FIELD_CHARS = 64
_MAX_COUNTRIES = 255  # index 0..254 fits array('B')

_MASK64 = (1 << 64) - 1


def _default_transport() -> httpx.BaseTransport | None:
    """httpx's real transport in production; tests replace this so nothing reaches db-ip.com."""
    return None


class GeoIpUnavailable(Exception):
    """A download or load failed; ``code`` is a short error class (logged, never raised past
    :meth:`GeoIp.maybe_refresh`)."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class _JoinedU128:
    """Read-only sequence of 128-bit ints stored as two ``array('Q')`` halves (for ``bisect``)."""

    __slots__ = ("_hi", "_lo")

    def __init__(self, hi: array, lo: array) -> None:
        self._hi = hi
        self._lo = lo

    def __len__(self) -> int:
        return len(self._hi)

    def __getitem__(self, index: int) -> int:
        return (self._hi[index] << 64) | self._lo[index]


@dataclass(frozen=True)
class LoadStats:
    ipv4_ranges: int
    ipv6_ranges: int
    skipped_rows: int


class GeoDatabase:
    """Sorted, non-overlapping ranges per address family with interned country codes."""

    def __init__(self) -> None:
        self.countries: list[str] = []
        self._country_index: dict[str, int] = {}
        self._v4_start = array("I")
        self._v4_end = array("I")
        self._v4_cc = array("B")
        self._v6_start_hi = array("Q")
        self._v6_start_lo = array("Q")
        self._v6_end_hi = array("Q")
        self._v6_end_lo = array("Q")
        self._v6_cc = array("B")
        self._v6_last_end = -1
        self.skipped_rows = 0

    # -- building -------------------------------------------------------------------------------

    def _cc(self, code: str) -> int | None:
        index = self._country_index.get(code)
        if index is None:
            if len(self.countries) >= _MAX_COUNTRIES:
                return None
            index = len(self.countries)
            self.countries.append(code)
            self._country_index[code] = index
        return index

    def add_row(self, row: list[str]) -> bool:
        """Adds one CSV row; returns False (and counts it skipped) when it is malformed, unknown
        (``ZZ``), inverted, mixes families, or overlaps/precedes the previous range."""
        if len(row) != 3:
            self.skipped_rows += 1
            return False
        start_text, end_text, code = (field.strip() for field in row)
        if (
            len(code) != 2
            or not ("A" <= code[0] <= "Z" and "A" <= code[1] <= "Z")
            or code == "ZZ"
            or len(start_text) > _MAX_FIELD_CHARS
            or len(end_text) > _MAX_FIELD_CHARS
        ):
            self.skipped_rows += 1
            return False
        try:
            if ":" in start_text:
                family = socket.AF_INET6
                start = int.from_bytes(socket.inet_pton(family, start_text))
                end = int.from_bytes(socket.inet_pton(family, end_text))
            else:
                family = socket.AF_INET
                start = int.from_bytes(socket.inet_pton(family, start_text))
                end = int.from_bytes(socket.inet_pton(family, end_text))
        except (OSError, ValueError):
            self.skipped_rows += 1
            return False
        if start > end:
            self.skipped_rows += 1
            return False
        if family == socket.AF_INET:
            if self._v4_end and start <= self._v4_end[-1]:
                self.skipped_rows += 1
                return False
            cc = self._cc(code)
            if cc is None:
                self.skipped_rows += 1
                return False
            self._v4_start.append(start)
            self._v4_end.append(end)
            self._v4_cc.append(cc)
            return True
        if start <= self._v6_last_end:
            self.skipped_rows += 1
            return False
        cc = self._cc(code)
        if cc is None:
            self.skipped_rows += 1
            return False
        self._v6_start_hi.append(start >> 64)
        self._v6_start_lo.append(start & _MASK64)
        self._v6_end_hi.append(end >> 64)
        self._v6_end_lo.append(end & _MASK64)
        self._v6_cc.append(cc)
        self._v6_last_end = end
        return True

    @property
    def ranges(self) -> int:
        return len(self._v4_start) + len(self._v6_start_hi)

    def stats(self) -> LoadStats:
        return LoadStats(len(self._v4_start), len(self._v6_start_hi), self.skipped_rows)

    # -- lookup ---------------------------------------------------------------------------------

    def lookup(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
        value = int(address)
        if isinstance(address, ipaddress.IPv4Address):
            i = bisect_right(self._v4_start, value) - 1
            if i >= 0 and value <= self._v4_end[i]:
                return self.countries[self._v4_cc[i]]
            return None
        starts = _JoinedU128(self._v6_start_hi, self._v6_start_lo)
        i = bisect_right(starts, value) - 1
        if i >= 0 and value <= ((self._v6_end_hi[i] << 64) | self._v6_end_lo[i]):
            return self.countries[self._v6_cc[i]]
        return None


class _CappedReader(io.RawIOBase):
    """Raises once more than ``limit`` bytes have been read from ``inner``."""

    def __init__(self, inner: Any, limit: int) -> None:
        self._inner = inner
        self._limit = limit
        self._read = 0

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        data = self._inner.read(len(buffer))
        self._read += len(data)
        if self._read > self._limit:
            raise GeoIpUnavailable("decompressed_too_large")
        buffer[: len(data)] = data
        return len(data)


def load_database(
    path: str,
    *,
    max_decompressed_bytes: int = MAX_DECOMPRESSED_BYTES,
    max_ranges: int = MAX_RANGES,
    min_ranges: int = 1,
) -> GeoDatabase:
    """Streams a DB-IP country CSV.gz into a :class:`GeoDatabase`. Raises GeoIpUnavailable."""
    db = GeoDatabase()
    try:
        with gzip.open(path, "rb") as compressed:
            raw = io.BufferedReader(_CappedReader(compressed, max_decompressed_bytes), 1 << 20)
            text = io.TextIOWrapper(raw, encoding="ascii", errors="replace", newline="")
            for row in csv.reader(text):
                if not row:
                    continue
                db.add_row(row)
                if db.ranges > max_ranges:
                    raise GeoIpUnavailable("too_many_ranges")
    except GeoIpUnavailable:
        raise
    except (OSError, EOFError, csv.Error, UnicodeError, ValueError) as exc:
        raise GeoIpUnavailable(f"invalid_file:{type(exc).__name__}") from None
    if db.ranges < min_ranges:
        raise GeoIpUnavailable("too_few_ranges")
    return db


def candidate_months(now: datetime) -> list[str]:
    """Current month, then the previous one (DB-IP publishes early in each month)."""
    year, month = now.year, now.month
    prev_year, prev_month = (year - 1, 12) if month == 1 else (year, month - 1)
    return [f"{year:04d}-{month:02d}", f"{prev_year:04d}-{prev_month:02d}"]


class GeoIp:
    """Cache manager + lookup. Thread-safe: lookups read an immutable reference that refreshes
    swap atomically."""

    def __init__(
        self,
        cache_dir: str,
        *,
        enabled: bool = True,
        transport: httpx.BaseTransport | None = None,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        monotonic: Callable[[], float] = time.monotonic,
        max_compressed_bytes: int = MAX_COMPRESSED_BYTES,
        max_decompressed_bytes: int = MAX_DECOMPRESSED_BYTES,
        min_ranges: int = DEFAULT_MIN_RANGES,
        logger: logging.Logger | None = None,
    ) -> None:
        self.enabled = enabled
        self.cache_dir = cache_dir
        self._transport = transport
        self._now = now
        self._monotonic = monotonic
        self._max_compressed = max_compressed_bytes
        self._max_decompressed = max_decompressed_bytes
        self._min_ranges = min_ranges
        self._log = logger or get_logger("geoip")
        self._db: GeoDatabase | None = None
        self._loaded_mtime: float | None = None
        self._next_attempt = 0.0
        self._unavailable_logged = False
        self._lock = threading.Lock()

    @property
    def path(self) -> str:
        return os.path.join(self.cache_dir, CACHE_FILENAME)

    @property
    def meta_path(self) -> str:
        return os.path.join(self.cache_dir, META_FILENAME)

    @property
    def loaded(self) -> bool:
        return self._db is not None

    # -- lookup ---------------------------------------------------------------------------------

    def country(self, ip: str) -> str | None:
        """ISO 3166-1 alpha-2 code for a public address, else None. Never raises."""
        db = self._db
        if db is None or not self.enabled:
            return None
        try:
            address = ipaddress.ip_address(ip)
            if address_prohibited_reason(address) is not None:
                return None
            return db.lookup(address)
        except Exception:
            return None

    # -- refresh --------------------------------------------------------------------------------

    def _meta(self) -> dict[str, Any]:
        try:
            with open(self.meta_path, encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _cached_mtime(self) -> float | None:
        try:
            return os.stat(self.path).st_mtime
        except OSError:
            return None

    def _needs_download(self, mtime: float | None) -> bool:
        if mtime is None:
            return True
        age = self._now().timestamp() - mtime
        if age > MAX_AGE_SECONDS:
            return True
        current = candidate_months(self._now())[0]
        meta_month = self._meta().get("month")
        return meta_month != current and age > NEWER_MONTH_CHECK_SECONDS

    def maybe_refresh(self) -> None:
        """Downloads a newer file when due and (re)loads the cache. Never raises."""
        if not self.enabled:
            return
        with self._lock:
            try:
                self._refresh_locked()
            except Exception as exc:  # never let geo break the worker loop
                log_event(self._log, logging.WARNING, "geoip_error", error=type(exc).__name__)

    def _refresh_locked(self) -> None:
        mtime = self._cached_mtime()
        if self._needs_download(mtime) and self._monotonic() >= self._next_attempt:
            try:
                changed = self._download(have_month=self._meta().get("month") if mtime else None)
                # No newer month yet: look again after NEWER_MONTH_CHECK_SECONDS, not every loop.
                self._next_attempt = (
                    0.0 if changed else self._monotonic() + NEWER_MONTH_CHECK_SECONDS
                )
            except GeoIpUnavailable as exc:
                self._next_attempt = self._monotonic() + RETRY_BACKOFF_SECONDS
                log_event(
                    self._log, logging.WARNING, "geoip_download_failed",
                    error=exc.code, keptExisting=mtime is not None,
                )  # fmt: skip
            mtime = self._cached_mtime()
        if mtime is not None and (self._db is None or mtime != self._loaded_mtime):
            try:
                db = load_database(self.path, max_decompressed_bytes=self._max_decompressed)
            except GeoIpUnavailable as exc:
                log_event(self._log, logging.WARNING, "geoip_load_failed", error=exc.code)
            else:
                self._db = db
                self._loaded_mtime = mtime
                self._unavailable_logged = False
                stats = db.stats()
                log_event(
                    self._log, logging.INFO, "geoip_loaded",
                    ipv4Ranges=stats.ipv4_ranges, ipv6Ranges=stats.ipv6_ranges,
                    skippedRows=stats.skipped_rows, month=self._meta().get("month"),
                )  # fmt: skip
        if self._db is None and not self._unavailable_logged:
            self._unavailable_logged = True
            log_event(self._log, logging.WARNING, "geoip_unavailable", cacheDir=self.cache_dir)

    def _download(self, have_month: str | None = None) -> bool:
        """Fetches the newest published month. Returns False when that month is already cached
        (``have_month``), True after replacing the cache; raises GeoIpUnavailable."""
        os.makedirs(self.cache_dir, mode=0o700, exist_ok=True)
        last = GeoIpUnavailable("no_attempt")
        with httpx.Client(
            headers={"User-Agent": GEOIP_USER_AGENT, "Accept": "application/gzip, */*"},
            follow_redirects=False,
            verify=True,
            trust_env=False,
            transport=self._transport or _default_transport(),
            timeout=httpx.Timeout(READ_TIMEOUT_SECONDS, connect=CONNECT_TIMEOUT_SECONDS),
        ) as http:
            for month in candidate_months(self._now()):
                if month == have_month:
                    return False
                try:
                    self._download_month(http, month)
                    return True
                except GeoIpUnavailable as exc:
                    last = exc
                    if exc.code != "http_404":
                        break  # only "not published yet" falls back to the previous month
        raise last

    def _download_month(self, http: httpx.Client, month: str) -> None:
        url = DBIP_URL_TEMPLATE.format(month=month)
        fd, tmp = tempfile.mkstemp(prefix=".geoip-", suffix=".part", dir=self.cache_dir)
        try:
            with os.fdopen(fd, "wb") as out:
                for chunk in self._stream(http, url):
                    out.write(chunk)
                out.flush()
                os.fsync(out.fileno())
            # Validate completely before replacing the working copy.
            db = load_database(
                tmp, max_decompressed_bytes=self._max_decompressed, min_ranges=self._min_ranges
            )
            del db
            os.replace(tmp, self.path)
            tmp = ""
            self._write_meta(month)
            self._fsync_dir()
            log_event(self._log, logging.INFO, "geoip_downloaded", month=month)
        finally:
            if tmp:
                with contextlib.suppress(OSError):
                    os.unlink(tmp)

    def _stream(self, http: httpx.Client, url: str) -> Iterator[bytes]:
        deadline = self._monotonic() + DOWNLOAD_DEADLINE_SECONDS
        try:
            with http.stream("GET", url) as response:
                status = response.status_code
                if 300 <= status < 400:
                    raise GeoIpUnavailable("unexpected_redirect")
                if status != 200:
                    raise GeoIpUnavailable(f"http_{status}")
                received = 0
                first = True
                for chunk in response.iter_bytes():
                    if not chunk:
                        continue
                    if first:
                        if chunk[:2] != b"\x1f\x8b" and len(chunk) >= 2:
                            raise GeoIpUnavailable("not_gzip")
                        first = False
                    received += len(chunk)
                    if received > self._max_compressed:
                        raise GeoIpUnavailable("download_too_large")
                    if self._monotonic() > deadline:
                        raise GeoIpUnavailable("download_deadline")
                    yield chunk
                if received == 0:
                    raise GeoIpUnavailable("empty_body")
        except httpx.HTTPError as exc:
            raise GeoIpUnavailable(type(exc).__name__) from None

    def _write_meta(self, month: str) -> None:
        payload = {
            "source": "db-ip.com country lite",
            "license": "CC BY 4.0",
            "attribution": ATTRIBUTION,
            "month": month,
            "downloadedAt": self._now().isoformat(),
        }
        fd, tmp = tempfile.mkstemp(prefix=".geoip-meta-", suffix=".part", dir=self.cache_dir)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as out:
                json.dump(payload, out)
                out.flush()
                os.fsync(out.fileno())
            os.replace(tmp, self.meta_path)
        except OSError:
            with contextlib.suppress(OSError):
                os.unlink(tmp)

    def _fsync_dir(self) -> None:
        with contextlib.suppress(OSError):
            fd = os.open(self.cache_dir, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
