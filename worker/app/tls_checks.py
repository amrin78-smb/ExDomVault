"""TLS certificate check (web tier) — Milestone 6.

Per target: resolve through :meth:`ScopePolicy.resolve` (tier ``web``), take at most one IPv4 and
one IPv6 allowed address, and perform one TLS handshake to each on port 443 through
:func:`app.net.tls_handshake` (which re-validates and pins the address; SNI = the hostname). The
leaf certificate is parsed locally into a ``tls`` observation (``docs/worker-protocol.md``):

- ``notBefore`` / ``notAfter``: UTC ISO 8601 with ``Z``.
- ``issuer`` / ``subject``: RFC 4514 strings (≤ 1000 chars).
- ``subjectAltNames``: dNSName entries only, lowercased, de-duplicated (≤ 200).
- ``fingerprintSha256``: lowercase hex of the DER leaf.
- ``hostnameMatches``: RFC 6125 matching against the dNSName SANs only (no Common Name fallback,
  as browsers do); a wildcard is accepted only as the entire left-most label and matches exactly
  one label (``*.example.com`` matches ``www.example.com``, not ``example.com`` or
  ``a.b.example.com``); partial-label wildcards (``w*.example.com``) never match.
- Evidence: ``{ trusted, verifyError? }``. ``chainLength`` is omitted: ``net.TlsResult`` exposes
  only the leaf.

A failed handshake produces an ``error`` observation with the certificate fields null.

``tls_configuration`` (network tier, deep profile) is **not run**: protocol-version enumeration
needs a version-pinned handshake primitive that ``app.net`` does not provide. The queue records it
as not applicable; the negotiated (highest mutually supported) version is still captured in
``protocolVersion`` by ``tls_certificate``.
"""

from __future__ import annotations

import ipaddress
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from app import net
from app.checks import CHECKER_VERSION, CheckContext, CheckFailed, utc_now_iso
from app.dns_checks import DnsResolver
from app.policy import IPAddress, ScopePolicy
from app.scope import ScopeError

TLS_PORT = 443
MAX_SANS = 200
MAX_NAME_LENGTH = 253
MAX_DN_LENGTH = 1000
MAX_VERIFY_ERROR_LENGTH = 300


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def select_addresses(addresses: tuple[IPAddress, ...]) -> list[IPAddress]:
    """The first IPv4 and the first IPv6 address (resolver order), at most two in total."""
    chosen: list[IPAddress] = []
    for version in (4, 6):
        first = next((a for a in addresses if a.version == version), None)
        if first is not None:
            chosen.append(first)
    return chosen


def hostname_matches(hostname: str, san_names: list[str]) -> bool:
    """RFC 6125 §6.4 DNS-ID matching (single, full left-most label wildcard only)."""
    host = hostname.lower().rstrip(".")
    host_labels = host.split(".")
    for raw in san_names:
        name = raw.lower().rstrip(".")
        if not name:
            continue
        if "*" not in name:
            if name == host:
                return True
            continue
        labels = name.split(".")
        # Wildcard only as the whole left-most label, with at least two labels after it.
        if labels[0] != "*" or any("*" in label for label in labels[1:]) or len(labels) < 3:
            continue
        if len(host_labels) != len(labels):
            continue
        if host_labels[0] and host_labels[1:] == labels[1:]:
            return True
    return False


def parse_certificate(der: bytes, hostname: str) -> dict[str, Any]:
    """Certificate fields of a ``tls`` observation. Raises ValueError on an unparseable DER."""
    cert = x509.load_der_x509_certificate(der)
    sans: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for value in ext.value.get_values_for_type(x509.DNSName):
            name = value.lower()
            if name not in sans and len(name) <= MAX_NAME_LENGTH:
                sans.append(name)
    except x509.ExtensionNotFound:
        pass
    return {
        "notBefore": _iso(cert.not_valid_before_utc),
        "notAfter": _iso(cert.not_valid_after_utc),
        "issuer": cert.issuer.rfc4514_string()[:MAX_DN_LENGTH],
        "subject": cert.subject.rfc4514_string()[:MAX_DN_LENGTH],
        "subjectAltNames": sans[:MAX_SANS],
        "fingerprintSha256": cert.fingerprint(hashes.SHA256()).hex(),
        "hostnameMatches": hostname_matches(hostname, sans),
    }


def _empty_cert_fields() -> dict[str, Any]:
    return {
        "notBefore": None,
        "notAfter": None,
        "issuer": None,
        "subject": None,
        "subjectAltNames": [],
        "fingerprintSha256": None,
        "hostnameMatches": None,
    }


def build_tls_observation(
    target_id: str, hostname: str, result: net.TlsResult | None, address: IPAddress, *,
    status_override: str | None = None, error: str | None = None,
) -> dict[str, Any]:  # fmt: skip
    """Maps a handshake result (or a local failure, ``result=None``) to a ``tls`` observation."""
    evidence: dict[str, Any] = {"trusted": bool(result and result.verified)}
    fields = _empty_cert_fields()
    status = "error"
    if result is not None:
        if result.verify_error:
            evidence["verifyError"] = str(result.verify_error)[:MAX_VERIFY_ERROR_LENGTH]
        if result.certificate_der:
            try:
                fields = parse_certificate(result.certificate_der, hostname)
                status = "success"
            except ValueError:
                evidence["parseError"] = "certificate_unparseable"
                status = "partial" if result.protocol else "error"
    if error:
        evidence["error"] = error
    protocol = result.protocol if result is not None else None
    return {
        "kind": "tls",
        "targetId": target_id,
        "observedAt": utc_now_iso(),
        "checkerVersion": CHECKER_VERSION,
        "resultStatus": status_override or status,
        "evidence": evidence,
        "hostname": hostname,
        "ipAddress": str(ipaddress.ip_address(address)),
        "port": result.port if result is not None else TLS_PORT,
        "protocolVersion": protocol[:20] if protocol else None,
        **fields,
    }


def check_tls_certificate(
    policy: ScopePolicy,
    resolver: DnsResolver,
    target_id: str,
    hostname: str,
    ctx: CheckContext,
    sink: Callable[[dict[str, Any]], None],
) -> None:
    """Appends one ``tls`` observation per selected address. Raises ScopeError when no address may
    be contacted (resolution refused or every pinned connection refused)."""
    ctx.before_network_call()
    lifetime = ctx.bounded(ctx.read_seconds)
    resolved = policy.resolve(hostname, resolver, tier="web", lifetime=lifetime)
    refused: ScopeError | None = None
    emitted = 0
    for address in select_addresses(resolved.addresses):
        ctx.before_network_call()
        timeout = ctx.bounded(ctx.connect_seconds + ctx.read_seconds)
        try:
            result = net.tls_handshake(
                policy, hostname, address, TLS_PORT, timeout=timeout,
                deadline=time.monotonic() + max(0.0, ctx.remaining()),
                should_stop=ctx.should_stop,
            )  # fmt: skip
        except ScopeError as exc:  # refused at connect time (e.g. the address changed category)
            refused = exc
            continue
        except TimeoutError:
            sink(build_tls_observation(target_id, hostname, None, address,
                                       status_override="timeout", error="timeout"))  # fmt: skip
        except OSError as exc:
            sink(build_tls_observation(target_id, hostname, None, address,
                                       error=type(exc).__name__))  # fmt: skip
        else:
            sink(build_tls_observation(target_id, hostname, result, address))
        emitted += 1
    if emitted == 0:
        if refused is not None:
            raise refused
        raise CheckFailed("no_allowed_address", "No address selected for the TLS check.")
