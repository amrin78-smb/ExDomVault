"""Passive registration (RDAP) check for the job's apex domain.

Only the IANA bootstrap service and the registry's RDAP server are contacted, never the target.
The registry base URL comes from the IANA DNS bootstrap file
(``https://data.iana.org/rdap/dns.json``), cached in memory for 24 hours. Requests use HTTPS only,
bounded timeouts, a 1 MB response cap, and follow at most 3 redirects, each of which must stay on
HTTPS. The result is one ``registration`` observation (``docs/worker-protocol.md``).
"""

from __future__ import annotations

import json
import re
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from app.checks import CHECKER_VERSION, CheckContext, utc_now_iso
from app.client import USER_AGENT

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
BOOTSTRAP_TTL_SECONDS = 24 * 3600
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_REDIRECTS = 3
MAX_NAMESERVERS = 20
_HOST_RE = re.compile(r"^[a-z0-9_.-]{1,253}$")
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


class RdapError(Exception):
    """RDAP data could not be obtained. ``reason`` is a short machine-readable token."""

    def __init__(self, reason: str, *, timeout: bool = False, http_status: int | None = None):
        super().__init__(reason)
        self.reason = reason
        self.timeout = timeout
        self.http_status = http_status


class RdapNotFound(Exception):
    pass


class RdapClient:
    """HTTPS GETs with size cap and HTTPS-only redirect handling, plus the bootstrap cache."""

    def __init__(
        self,
        *,
        transport: httpx.BaseTransport | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._http = httpx.Client(
            headers={"User-Agent": USER_AGENT},
            follow_redirects=False,
            verify=True,
            trust_env=False,
            transport=transport,
        )
        self._clock = clock
        self._bootstrap: list[tuple[list[str], list[str]]] | None = None
        self._bootstrap_at = 0.0
        self._lock = threading.Lock()

    def close(self) -> None:
        self._http.close()

    def get_json(self, url: str, ctx: CheckContext, accept: str) -> Any:
        timeout = httpx.Timeout(
            max(0.1, min(ctx.read_seconds, ctx.remaining())),
            connect=max(0.1, min(ctx.connect_seconds, ctx.remaining())),
        )
        for _ in range(MAX_REDIRECTS + 1):
            if urlsplit(url).scheme != "https":
                raise RdapError("non_https_url")
            ctx.before_network_call()
            try:
                with self._http.stream(
                    "GET", url, headers={"Accept": accept}, timeout=timeout
                ) as response:
                    status = response.status_code
                    if status in _REDIRECT_STATUSES:
                        location = response.headers.get("Location", "")
                        if not location:
                            raise RdapError("redirect_without_location", http_status=status)
                        url = urljoin(url, location)
                        continue
                    if status == 404:
                        raise RdapNotFound
                    if status != 200:
                        raise RdapError("http_error", http_status=status)
                    body = bytearray()
                    for chunk in response.iter_bytes():
                        body.extend(chunk)
                        if len(body) > MAX_RESPONSE_BYTES:
                            raise RdapError("response_too_large", http_status=status)
            except httpx.TimeoutException as exc:
                raise RdapError(type(exc).__name__, timeout=True) from None
            except httpx.HTTPError as exc:
                raise RdapError(type(exc).__name__) from None
            try:
                return json.loads(bytes(body))
            except ValueError:
                raise RdapError("invalid_json", http_status=200) from None
        raise RdapError("too_many_redirects")

    def base_urls_for(self, fqdn: str, ctx: CheckContext) -> list[str]:
        """Registry RDAP base URLs (HTTPS only) for the longest matching TLD/suffix entry."""
        with self._lock:
            fresh = (
                self._bootstrap is not None
                and self._clock() - self._bootstrap_at < BOOTSTRAP_TTL_SECONDS
            )
            if not fresh:
                try:
                    document = self.get_json(BOOTSTRAP_URL, ctx, "application/json")
                except RdapNotFound:
                    raise RdapError("bootstrap_unavailable", http_status=404) from None
                self._bootstrap = parse_bootstrap(document)
                self._bootstrap_at = self._clock()
            services = self._bootstrap or []
        return match_bootstrap(services, fqdn)


def parse_bootstrap(document: Any) -> list[tuple[list[str], list[str]]]:
    if not isinstance(document, dict) or not isinstance(document.get("services"), list):
        raise RdapError("invalid_bootstrap")
    services: list[tuple[list[str], list[str]]] = []
    for entry in document["services"]:
        if (
            isinstance(entry, list)
            and len(entry) == 2
            and all(isinstance(part, list) for part in entry)
        ):
            suffixes = [s.lower().strip(".") for s in entry[0] if isinstance(s, str)]
            urls = [u for u in entry[1] if isinstance(u, str) and u.startswith("https://")]
            if suffixes and urls:
                services.append((suffixes, urls))
    return services


def match_bootstrap(services: list[tuple[list[str], list[str]]], fqdn: str) -> list[str]:
    labels = fqdn.lower().split(".")
    best: list[str] = []
    best_len = 0
    for suffixes, urls in services:
        for suffix in suffixes:
            n = suffix.count(".") + 1
            if n > best_len and n <= len(labels) and ".".join(labels[-n:]) == suffix:
                best, best_len = urls, n
    return best


# --- Parsing ---------------------------------------------------------------------------------


def _iso(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("z", "Z"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _vcard_fn(entity: dict[str, Any]) -> str | None:
    vcard = entity.get("vcardArray")
    if not (isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list)):
        return None
    for prop in vcard[1]:
        if (
            isinstance(prop, list)
            and len(prop) >= 4
            and prop[0] == "fn"
            and isinstance(prop[3], str)
            and prop[3].strip()
        ):
            return prop[3].strip()[:300]
    return None


def _text_mentions_redacted(notices: Any) -> bool:
    if not isinstance(notices, list):
        return False
    for notice in notices:
        if not isinstance(notice, dict):
            continue
        texts = [notice.get("title")]
        description = notice.get("description")
        if isinstance(description, list):
            texts.extend(description)
        if any(isinstance(t, str) and "redacted" in t.lower() for t in texts):
            return True
    return False


def _entities(document: dict[str, Any]) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    stack = [document]
    while stack and len(found) < 100:
        node = stack.pop()
        for entity in node.get("entities", []) if isinstance(node.get("entities"), list) else []:
            if isinstance(entity, dict):
                found.append(entity)
                stack.append(entity)
    return found


def parse_rdap_domain(document: Any) -> dict[str, Any]:
    """Extracts registrar, registration/expiry dates, nameservers and redaction status."""
    if not isinstance(document, dict):
        raise RdapError("invalid_response")

    registrar: str | None = None
    entities = _entities(document)
    for entity in entities:
        roles = entity.get("roles")
        if isinstance(roles, list) and "registrar" in roles:
            registrar = _vcard_fn(entity)
            if registrar:
                break

    registered_at = expires_at = None
    events = document.get("events")
    for event in events if isinstance(events, list) else []:
        if not isinstance(event, dict):
            continue
        action = event.get("eventAction")
        if action == "registration" and registered_at is None:
            registered_at = _iso(event.get("eventDate"))
        elif action == "expiration" and expires_at is None:
            expires_at = _iso(event.get("eventDate"))

    nameservers: set[str] = set()
    raw_ns = document.get("nameservers")
    for ns in raw_ns if isinstance(raw_ns, list) else []:
        if isinstance(ns, dict) and isinstance(ns.get("ldhName"), str):
            name = ns["ldhName"].strip().lower().rstrip(".")
            if _HOST_RE.fullmatch(name):
                nameservers.add(name)

    redacted_fields: list[str] = []
    redacted = document.get("redacted")
    if isinstance(redacted, list):
        for item in redacted:
            if isinstance(item, dict) and isinstance(item.get("name"), dict):
                label = item["name"].get("type") or item["name"].get("description")
                if isinstance(label, str):
                    redacted_fields.append(label[:64])
    is_redacted = (
        (isinstance(redacted, list) and len(redacted) > 0)
        or _text_mentions_redacted(document.get("remarks"))
        or _text_mentions_redacted(document.get("notices"))
        or any(_text_mentions_redacted(e.get("remarks")) for e in entities)
    )

    status = document.get("status")
    evidence: dict[str, Any] = {}
    if isinstance(status, list):
        evidence["domainStatus"] = [s[:64] for s in status if isinstance(s, str)][:20]
    if redacted_fields:
        evidence["redactedFields"] = sorted(set(redacted_fields))[:20]

    return {
        "registrar": registrar,
        "registeredAt": registered_at,
        "expiresAt": expires_at,
        "nameservers": sorted(nameservers)[:MAX_NAMESERVERS],
        "dataStatus": "redacted" if is_redacted else "available",
        "evidence": evidence,
    }


def _observation(
    target_id: str,
    status: str,
    *,
    parsed: dict[str, Any] | None = None,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    parsed = parsed or {}
    return {
        "kind": "registration",
        "targetId": target_id,
        "observedAt": utc_now_iso(),
        "checkerVersion": CHECKER_VERSION,
        "resultStatus": status,
        "evidence": {**parsed.get("evidence", {}), **(evidence or {})},
        "registrar": parsed.get("registrar"),
        "registeredAt": parsed.get("registeredAt"),
        "expiresAt": parsed.get("expiresAt"),
        "nameservers": parsed.get("nameservers", []),
        "dataStatus": parsed.get("dataStatus", "unavailable"),
    }


def check_rdap(
    client: RdapClient,
    target_id: str,
    fqdn: str,
    ctx: CheckContext,
    sink: Callable[[dict[str, Any]], None],
) -> None:
    """Appends one ``registration`` observation for the apex ``fqdn``.

    Not found (404) → ``success`` + ``unavailable``; TLD without an RDAP service → ``success`` +
    ``unavailable``; any failure → ``error``/``timeout`` + ``unavailable``. Stop/deadline signals
    propagate.
    """
    try:
        bases = client.base_urls_for(fqdn, ctx)
        if not bases:
            sink(_observation(target_id, "success", evidence={"reason": "no_rdap_service"}))
            return
        base = bases[0]
        url = base.rstrip("/") + "/domain/" + fqdn
        document = client.get_json(url, ctx, "application/rdap+json")
        parsed = parse_rdap_domain(document)
    except RdapNotFound:
        sink(_observation(target_id, "success", evidence={"reason": "not_found", "http": 404}))
        return
    except RdapError as exc:
        evidence: dict[str, Any] = {"error": exc.reason}
        if exc.http_status is not None:
            evidence["http"] = exc.http_status
        sink(_observation(target_id, "timeout" if exc.timeout else "error", evidence=evidence))
        return
    parsed["evidence"]["rdapServer"] = urlsplit(base).hostname or ""
    sink(_observation(target_id, "success", parsed=parsed))
