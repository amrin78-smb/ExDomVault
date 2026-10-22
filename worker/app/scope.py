"""Milestone 5 scope guard.

Active scanning is disabled (``WorkerConfig.active_scanning_enabled`` is hard-coded False), so the
only checks this worker may run are the passive ones: ``dns`` (queries public resolvers) and
``rdap`` (queries the registry's RDAP service). Neither contacts a target host. Every
network-connecting check is refused here with :class:`ScopeError`.

This module also enforces exact DNS label boundaries: every target of a job must be the job's
domain or a name beneath it. Full scope validation for active checks (resolving and validating
every destination address against prohibited ranges, pinning it, and revalidating every redirect
and CNAME hop) is the Milestone 6 scope validator and is intentionally not implemented here;
until it exists no code path in the worker connects to a target.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

PASSIVE_CHECKS: frozenset[str] = frozenset({"dns", "rdap"})
NETWORK_CHECKS: frozenset[str] = frozenset(
    {
        "tls_certificate",
        "http_availability",
        "http_headers",
        "tcp_ports",
        "service_identification",
        "tls_configuration",
    }
)
KNOWN_CHECKS: frozenset[str] = PASSIVE_CHECKS | NETWORK_CHECKS

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
_MAX_NAME_LENGTH = 253


class ScopeError(Exception):
    """A check or target is outside what this worker may do. ``code`` is the API error code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def assert_passive_allowed(check: str) -> None:
    """Permits only passive checks. Network-connecting checks raise ``active_scanning_disabled``;
    unknown checks raise ``unsupported_check``."""
    if check in PASSIVE_CHECKS:
        return
    if check in NETWORK_CHECKS:
        raise ScopeError(
            "active_scanning_disabled",
            f"Check '{check}' connects to target hosts; active scanning is disabled.",
        )
    raise ScopeError("unsupported_check", "The profile lists a check this worker does not know.")


def normalise_hostname(name: str) -> str:
    """Lowercase A-label without a trailing dot; raises ScopeError(``invalid_hostname``)."""
    if not isinstance(name, str):
        raise ScopeError("invalid_hostname", "Hostname must be a string.")
    value = name.strip().lower()
    if value.endswith("."):
        value = value[:-1]
    if not value or len(value) > _MAX_NAME_LENGTH:
        raise ScopeError("invalid_hostname", "Hostname is empty or too long.")
    if not all(_LABEL_RE.fullmatch(label) for label in value.split(".")):
        raise ScopeError("invalid_hostname", "Hostname is not a valid A-label name.")
    return value


def name_within_domain(name: str, domain: str) -> bool:
    """True when ``name`` equals ``domain`` or lies beneath it at a label boundary.

    ``evil-example.com`` and ``example.com.evil.net`` are *not* within ``example.com``.
    """
    try:
        n = normalise_hostname(name)
        d = normalise_hostname(domain)
    except ScopeError:
        return False
    return n == d or n.endswith("." + d)


def validate_job_targets(
    domain: str,
    target_hostnames: Iterable[str],
    snapshot_hostnames: Iterable[str],
) -> None:
    """Refuses a job (``scope_rejected``) unless every claimed target is a valid name within the
    job's domain and is listed in the job's immutable scope snapshot."""
    try:
        apex = normalise_hostname(domain)
    except ScopeError as exc:
        raise ScopeError("scope_rejected", "The job's domain is not a valid name.") from exc
    allowed: set[str] = set()
    for raw in snapshot_hostnames:
        try:
            allowed.add(normalise_hostname(raw))
        except ScopeError:
            continue
    for raw in target_hostnames:
        try:
            host = normalise_hostname(raw)
        except ScopeError as exc:
            raise ScopeError("scope_rejected", "A target hostname is not a valid name.") from exc
        if not name_within_domain(host, apex):
            raise ScopeError("scope_rejected", "A target is outside the job's domain.")
        if host not in allowed:
            raise ScopeError("scope_rejected", "A target is not in the job's scope snapshot.")
