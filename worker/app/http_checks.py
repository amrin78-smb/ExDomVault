"""HTTP availability and security-header checks (web tier) — Milestone 6.

Two :func:`app.net.http_get` calls per target, as a visitor typing the name would make:
``https://<hostname>/`` and ``http://<hostname>/`` (the latter shows whether plain HTTP redirects
to HTTPS). ``net.http_get``
re-validates and pins every hop and never follows a redirect it has not validated. Each attempt
that reached an address becomes one ``http`` observation (``docs/worker-protocol.md``):

- ``url``: the URL requested; ``ipAddress``: the first hop's pinned address.
- ``statusCode``: the status of the last hop that returned a response.
- ``finalUrl``: the last hop's URL (the stopping point when a redirect was refused).
- ``redirectCount``: redirects actually followed.
- ``hstsEnabled``: ``Strict-Transport-Security`` with ``max-age > 0`` on the final HTTPS response;
  null when the final response is not HTTPS (HSTS is ignored over plain HTTP) or none arrived.
- ``resultStatus``: ``success`` when the chain ended in a response, ``partial`` when a redirect was
  refused after a response, ``error``/``timeout`` when no response arrived.
- Evidence: ``hops`` ``[{url, ip, status, decision, error?}]`` always; with ``http_headers`` also
  ``securityHeaders`` (the six headers, value or null), ``server`` and ``xPoweredBy`` taken from the
  last response, values truncated to 512 printable ASCII characters. Cookies and bodies are never
  read into observations.

If no attempt reached an address (e.g. resolution refused), no observation is emitted and the
refusal is raised for the queue to record as the target's error code.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from typing import Any

from app import net
from app.checks import CHECKER_VERSION, CheckContext, CheckFailed, CheckStopped, utc_now_iso
from app.dns_checks import DnsResolver
from app.policy import ScopePolicy
from app.scope import ScopeError

SECURITY_HEADERS: tuple[str, ...] = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
)
MAX_HEADER_VALUE = 512
MAX_URL_LENGTH = 2048
MAX_EVIDENCE_URL = 512
MAX_EVIDENCE_BYTES = 16_000
MAX_REDIRECT_COUNT = 10
_NON_PRINTABLE = re.compile(r"[^\x20-\x7e]")
_MAX_AGE = re.compile(r"(?:^|;)\s*max-age\s*=\s*\"?(\d+)\"?\s*(?:;|$)", re.IGNORECASE)


def _clean(value: str, limit: int) -> str:
    """Printable ASCII only (bounded JSON size), truncated."""
    return _NON_PRINTABLE.sub("?", value[:limit])


def hsts_enabled(value: str | None) -> bool:
    if not value:
        return False
    match = _MAX_AGE.search(value)
    return bool(match and int(match.group(1)) > 0)


def _responded(hop: net.HttpHop) -> bool:
    return hop.address is not None and hop.status is not None


def build_http_observation(
    target_id: str, result: net.HttpResult, *, include_headers: bool
) -> dict[str, Any] | None:
    """Maps one ``http_get`` result to an ``http`` observation; None if no hop reached an
    address (the schema requires ``ipAddress``)."""
    if not result.hops or result.first.address is None:
        return None
    responded = [h for h in result.hops if _responded(h)]
    last_response = responded[-1] if responded else None
    last = result.last
    if last_response is None:
        status = "timeout" if (last.error or "").startswith("timeout") else "error"
    elif last is last_response and last.decision in ("final", "followed"):
        status = "success"
    else:
        status = "partial"

    hsts: bool | None = None
    if last_response is not None and last_response.url.lower().startswith("https://"):
        hsts = hsts_enabled(last_response.headers.get("strict-transport-security"))

    evidence: dict[str, Any] = {
        "hops": [
            {
                "url": _clean(h.url, MAX_EVIDENCE_URL),
                "ip": str(h.address) if h.address is not None else None,
                "status": h.status,
                "decision": _clean(h.decision, 64),
                **({"error": _clean(h.error, 100)} if h.error else {}),
            }
            for h in result.hops
        ]
    }
    if include_headers and last_response is not None:
        headers = last_response.headers
        evidence["securityHeaders"] = {
            name: _clean(headers[name], MAX_HEADER_VALUE) if name in headers else None
            for name in SECURITY_HEADERS
        }
        for key, name in (("server", "server"), ("xPoweredBy", "x-powered-by")):
            evidence[key] = _clean(headers[name], MAX_HEADER_VALUE) if name in headers else None
    if len(json.dumps(evidence)) > MAX_EVIDENCE_BYTES:  # defensive: keep within the 16 KB cap
        evidence["hops"] = evidence["hops"][:2]
        evidence["truncated"] = True

    return {
        "kind": "http",
        "targetId": target_id,
        "observedAt": utc_now_iso(),
        "checkerVersion": CHECKER_VERSION,
        "resultStatus": status,
        "evidence": evidence,
        "url": result.first.url[:MAX_URL_LENGTH],
        "ipAddress": str(result.first.address),
        "statusCode": last_response.status if last_response is not None else None,
        "finalUrl": last.url[:MAX_URL_LENGTH],
        "redirectCount": min(
            sum(1 for h in result.hops if h.decision == "followed"), MAX_REDIRECT_COUNT
        ),
        "hstsEnabled": hsts,
    }


def _refusal_code(result: net.HttpResult) -> str:
    """Target error code when no hop reached an address: the policy refusal code, or
    ``resolution_failed`` for DNS errors."""
    decision = result.last.decision if result.hops else "error"
    if decision == "error" or not re.fullmatch(r"[a-z0-9_]{1,64}", decision):
        return "resolution_failed"
    return decision


def check_http(
    policy: ScopePolicy,
    resolver: DnsResolver,
    target_id: str,
    hostname: str,
    ctx: CheckContext,
    sink: Callable[[dict[str, Any]], None],
    *,
    include_headers: bool,
) -> None:
    """Runs ``http_availability`` / ``http_headers`` for one target (one shared observation per
    attempted URL). Raises ScopeError / CheckFailed when no observation could be produced."""
    emitted = 0
    failure: Exception | None = None
    for url in (f"https://{hostname}/", f"http://{hostname}/"):
        ctx.before_network_call()
        timeout = ctx.bounded(ctx.connect_seconds + ctx.read_seconds)
        try:
            # One deadline for every hop, capped by the target's remaining budget; the job's stop
            # signal is checked between hops.
            result = net.http_get(
                policy, url, resolver, timeout=timeout, tier="web",
                deadline=time.monotonic() + max(0.0, ctx.remaining()),
                should_stop=ctx.should_stop,
            )  # fmt: skip
        except ScopeError as exc:  # defensive: net reports refusals as hops
            failure = exc
            break
        except TimeoutError:
            failure = CheckFailed("http_timeout")
            continue
        except OSError as exc:
            failure = CheckFailed("http_error", type(exc).__name__)
            continue
        if ctx.should_stop():
            raise CheckStopped
        observation = build_http_observation(target_id, result, include_headers=include_headers)
        if observation is None:
            # Refused before connecting (policy or DNS): plain HTTP would be refused the same way.
            failure = ScopeError(_refusal_code(result), "No HTTP hop reached an address.")
            break
        sink(observation)
        emitted += 1
    if emitted == 0:
        raise failure or CheckFailed("http_error")
