"""Lookalike-domain check (Milestone 15, ``brand`` profile): passive, public resolvers only.

The server generates the lookalike candidates of the job's domain (typos, homoglyphs, other TLDs;
``generateLookalikes`` in ``packages/shared``) and freezes them into the job's scope snapshot as
``snapshot.lookalike.candidates`` (``[{candidate, technique}]``). This module resolves exactly those
names through the worker's configured resolvers and NEVER connects to them: no HTTP, no TLS, no
port probes — a lookalike is somebody else's name, so it is never a target.

Per candidate (each query waits for a rate-limit slot and respects the target deadline):

* ``NS`` at the candidate (it is a registrable domain). NXDOMAIN → not registered. NOERROR without
  NS → ``SOA`` fallback: an SOA answer means the name is a zone apex (registered); otherwise not
  registered. A wildcard ``A`` record in some TLDs therefore never counts as a registration.
* ``subdomain_dot`` candidates (``thai.union.com``: a name beneath somebody else's domain) are not
  zone apexes: they "exist" when ``A``/``AAAA``/``MX`` has an answer. NXDOMAIN on ``A`` stops early.
* Registered → ``A``, ``AAAA``, ``MX`` for the records. A failed record lookup makes the
  observation ``partial`` (still registered).
* ``SERVFAIL``/refused/other resolver failure on the deciding query → ``error`` observation
  (``registered: false``); a resolver timeout → ``timeout``. Never treated as "not registered".

Volume: only registered candidates and failures produce observations. A run that checked every
candidate (no target deadline hit) completes the target ``succeeded`` even with no observation, so
the server can tell "checked and not registered" (absent in a complete run) from "not checked"
(failed/incomplete target). If EVERY candidate failed (resolver outage) the check fails with
``lookalike_resolution_failed``.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

import dns.exception
import dns.resolver

from app.checks import (
    CHECKER_VERSION,
    CheckContext,
    CheckFailed,
    CheckStopped,
    TargetTimeout,
    utc_now_iso,
)
from app.dns_checks import DnsResolver, normalise_values
from app.scope import name_within_domain

#: ``LOOKALIKE_TECHNIQUES`` in ``packages/shared/src/api/observations.ts``.
LOOKALIKE_TECHNIQUES: frozenset[str] = frozenset(
    {
        "omission",
        "repetition",
        "transposition",
        "replacement",
        "insertion",
        "homoglyph",
        "hyphenation",
        "bitsquatting",
        "vowel_swap",
        "tld_swap",
        "subdomain_dot",
    }
)
#: ``MAX_LOOKALIKE_CANDIDATES`` in ``packages/shared/src/domain/lookalike.ts``.
MAX_CANDIDATES = 1500
#: Server schema limits for ``records`` (per type).
MAX_RECORDS = 20
MAX_RECORD_LENGTH = 512
RECORD_TYPES: tuple[str, ...] = ("A", "AAAA", "MX")

_LDH_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


@dataclass(frozen=True)
class Candidate:
    name: str
    technique: str


@dataclass
class LookalikeOutcome:
    checked: int = 0
    registered: int = 0
    failed: int = 0


def _valid_name(name: str) -> bool:
    if not 1 <= len(name) <= 253:
        return False
    labels = name.split(".")
    return len(labels) >= 2 and all(_LDH_LABEL.fullmatch(label) for label in labels)


def parse_candidates(snapshot: Any, domain: str) -> list[Candidate]:
    """The job's candidate list, validated. Raises ``CheckFailed('lookalike_candidates_invalid')``
    when it is missing or malformed: nothing is resolved from an untrusted list. Names equal to or
    beneath the job's own domain are refused the same way (they are ours, not lookalikes)."""
    try:
        raw = snapshot["lookalike"]["candidates"]
        if not isinstance(raw, list) or len(raw) > MAX_CANDIDATES:
            raise ValueError("candidates")
        out: list[Candidate] = []
        seen: set[str] = set()
        for item in raw:
            name, technique = item["candidate"], item["technique"]
            if not isinstance(name, str) or not isinstance(technique, str):
                raise ValueError("types")
            if name != name.lower() or not _valid_name(name):
                raise ValueError("name")
            if technique not in LOOKALIKE_TECHNIQUES:
                raise ValueError("technique")
            if name_within_domain(name, domain):
                raise ValueError("own domain")
            if name in seen:
                continue
            seen.add(name)
            out.append(Candidate(name, technique))
        return out
    except (KeyError, TypeError, ValueError) as exc:
        raise CheckFailed(
            "lookalike_candidates_invalid", "The job's lookalike candidate list is invalid."
        ) from exc


def _records(rdtype: str, values: Iterable[str]) -> list[str]:
    clipped, _ = normalise_values(rdtype, list(values))
    return [v[:MAX_RECORD_LENGTH] for v in clipped[:MAX_RECORDS]]


def _observation(
    target_id: str,
    candidate: Candidate,
    *,
    status: str,
    registered: bool,
    records: dict[str, list[str]],
    evidence: dict[str, Any],
) -> dict[str, Any]:
    return {
        "kind": "lookalike",
        "targetId": target_id,
        "observedAt": utc_now_iso(),
        "checkerVersion": CHECKER_VERSION,
        "resultStatus": status,
        "evidence": evidence,
        "candidate": candidate.name,
        "technique": candidate.technique,
        "registered": registered,
        "records": records,
    }


class _Query:
    """One candidate's lookups: rate limit + deadline before every query."""

    def __init__(self, resolver: DnsResolver, name: str, ctx: CheckContext) -> None:
        self.resolver = resolver
        self.name = name
        self.ctx = ctx
        self.count = 0

    def __call__(self, rdtype: str) -> list[str]:
        """Values (``[]`` for NODATA). Raises NXDOMAIN / Timeout / other DNSException."""
        self.ctx.before_network_call()
        self.count += 1
        lifetime = max(0.1, min(self.ctx.read_seconds, self.ctx.remaining()))
        try:
            answer = self.resolver.query(self.name, rdtype, lifetime)
        except dns.resolver.NoAnswer:
            return []
        return list(answer.values)


def _failure(target_id: str, candidate: Candidate, rdtype: str, exc: Exception) -> dict[str, Any]:
    status = "timeout" if isinstance(exc, dns.exception.Timeout) else "error"
    return _observation(
        target_id, candidate, status=status, registered=False, records={},
        evidence={"query": rdtype, "error": type(exc).__name__},
    )  # fmt: skip


def check_candidate(
    resolver: DnsResolver, target_id: str, candidate: Candidate, ctx: CheckContext
) -> dict[str, Any] | None:
    """Resolves one candidate. ``None`` = checked and not registered. Raises only
    ``CheckStopped``/``TargetTimeout`` (between queries)."""
    query = _Query(resolver, candidate.name, ctx)
    records: dict[str, list[str]] = {}
    errors: dict[str, str] = {}
    evidence: dict[str, Any] = {}

    if candidate.technique != "subdomain_dot":
        try:
            ns = query("NS")
        except dns.resolver.NXDOMAIN:
            return None
        except dns.exception.DNSException as exc:
            return _failure(target_id, candidate, "NS", exc)
        if ns:
            records["NS"] = _records("NS", ns)
        else:
            try:
                soa = query("SOA")
            except dns.resolver.NXDOMAIN:
                return None
            except dns.exception.DNSException as exc:
                return _failure(target_id, candidate, "SOA", exc)
            if not soa:
                return None  # the name exists but is no zone apex: not a registration
            evidence["soa"] = True
            records["NS"] = []
        for rdtype in RECORD_TYPES:
            try:
                values = query(rdtype)
            except dns.resolver.NXDOMAIN:
                values = []
            except dns.exception.DNSException as exc:
                errors[rdtype] = type(exc).__name__
                continue
            if values:
                records[rdtype] = _records(rdtype, values)
    else:
        for rdtype in RECORD_TYPES:
            try:
                values = query(rdtype)
            except dns.resolver.NXDOMAIN:
                if rdtype == "A":
                    return None  # the name does not exist at all
                values = []
            except dns.exception.DNSException as exc:
                errors[rdtype] = type(exc).__name__
                continue
            if values:
                records[rdtype] = _records(rdtype, values)
        if not records:
            if errors:
                first = next(iter(errors))
                status = "timeout" if errors[first] == "Timeout" else "error"
                return _observation(
                    target_id, candidate, status=status, registered=False, records={},
                    evidence={"query": first, "error": errors[first]},
                )  # fmt: skip
            return None

    evidence["queries"] = query.count
    if errors:
        evidence["errors"] = errors
    return _observation(
        target_id,
        candidate,
        status="partial" if errors else "success",
        registered=True,
        records=records,
        evidence=evidence,
    )


def run_lookalikes(
    resolver: DnsResolver,
    target_id: str,
    candidates: list[Candidate],
    ctx: CheckContext,
    sink: Callable[[dict[str, Any]], None],
    *,
    concurrency: int = 8,
) -> LookalikeOutcome:
    """Checks every candidate with up to ``concurrency`` threads sharing the job's rate limiter and
    the target deadline. Raises ``TargetTimeout``/``CheckStopped`` when the run could not finish
    (observations already appended stay valid evidence), ``CheckFailed`` when every candidate
    failed."""
    outcome = LookalikeOutcome()
    lock = threading.Lock()
    stop: list[BaseException] = []

    def one(candidate: Candidate) -> None:
        if stop:
            return
        try:
            observation = check_candidate(resolver, target_id, candidate, ctx)
        except (TargetTimeout, CheckStopped) as exc:
            with lock:
                stop.append(exc)
            return
        with lock:
            outcome.checked += 1
            if observation is not None:
                if observation["registered"]:
                    outcome.registered += 1
                else:
                    outcome.failed += 1
                sink(observation)

    with ThreadPoolExecutor(
        max_workers=max(1, min(concurrency, 16)), thread_name_prefix="lookalike"
    ) as pool:
        for future in [pool.submit(one, c) for c in candidates]:
            future.result()
    if stop:
        raise stop[0]
    if outcome.checked > 0 and outcome.failed == outcome.checked:
        raise CheckFailed(
            "lookalike_resolution_failed", "No lookalike candidate could be resolved."
        )
    return outcome
