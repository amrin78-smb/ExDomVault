"""TCP port check and limited service identification (network tier) — Milestone 6.

Only addresses that survive :meth:`ScopePolicy.resolve` with tier ``network`` (inside the job's
admin-approved networks, never prohibited or deny-listed) are scanned, and each is re-validated
with :meth:`ScopePolicy.assert_destination` immediately before Nmap starts; one refusal aborts the
run before any process is started.

Nmap is run with a **fixed argv template** built only from the server-defined profile (validated
integers) and validated IP addresses — never user input, never a shell::

    [nmap, -sT, -Pn, -n, --unprivileged, --max-retries, 1, --host-timeout, <T>s,
     --max-rate, <R>, --max-parallelism, <P>, -p, <ports>, (-sV --version-light), (-6),
     -oX, -, <ip>...]

- ``-sT --unprivileged``: TCP connect scan, no raw packets even if run as root.
- ``<R>`` = clamp(round(ratePerSecond * 10), 1, 100) probes/second (standard 10, deep 5).
- ``<P>`` = clamp(concurrency * 4, 1, 16) parallel probes (standard 8, deep 4).
- ``<T>`` = min(targetSeconds, remaining target budget), at least 5 s.
- ``-sV --version-light`` only when the profile lists ``service_identification``. No ``--script``,
  ``-O``, ``-sS``, ``-A`` or any other option exists in the template.
- IPv4 and IPv6 addresses are scanned in separate runs (Nmap needs ``-6`` and cannot mix them);
  at most :data:`MAX_ADDRESSES` addresses per target.

The process runs with ``shell=False``, ``stdin`` closed, ``env`` = ``PATH`` only, its own process
group (``process_group=0``; the whole group is killed on timeout, overflow or cancellation), stdout
capped at 2 MB, stderr capped at 64 KB, a wall-clock timeout of ``<T> + 30`` s, and rlimits
(address space 512 MB, CPU seconds = the wall-clock timeout, 1024 file descriptors, no core dumps).
The rlimits are applied without ``preexec_fn`` (unsafe in this multi-threaded worker: the forked
child could deadlock on a lock held by another thread): a fixed, isolated Python stub
(``python -I -S -c <constant code>``) calls ``setrlimit`` with integer values computed in the
parent and then ``execv``s the Nmap argv unchanged, so the limits are in force before Nmap's first
instruction and no shell is involved.

Service identification (``-sV --version-light``): besides Nmap's probe database (light intensity),
``-sV`` also runs the NSE scripts of the ``version`` category; no other category can run because the
template has no ``--script``/``-sC``/``-A``. With the installed Nmap 7.94 that is 46 scripts
(``nmap --script-help version``); none is in the ``intrusive``, ``exploit``, ``brute``, ``dos``,
``malware`` or ``external`` categories. They are protocol-specific version/banner probes (e.g.
``http-server-header``, ``fingerprint-strings``, ``rpc-grind``); the only one also tagged ``vuln``
(``wdb-version``) has a UDP-only port rule and cannot run under this TCP connect scan.

The XML report is parsed with ``xml.etree.ElementTree`` after refusing any entity declaration and
any document type other than Nmap's own bare ``<!DOCTYPE nmaprun>`` (no internal subset, no
external identifier). Only ports listed in the profile on validated addresses become ``port``
observations; anything else Nmap reports is ignored. States: ``open``, ``closed``, ``filtered``;
``open|filtered`` and ``closed|filtered`` map to ``filtered``; ``unfiltered`` (impossible with a
connect scan) is ignored. Ports Nmap folds into ``<extraports>`` are expanded from
``<extrareasons ports=…>`` (Nmap ≥ 7.90); without that attribute they are attributed only when the
host has a single ``extraports`` group.
"""

from __future__ import annotations

import contextlib
import ipaddress
import logging
import os
import re
import resource
import selectors
import signal
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from app.checks import (
    CHECKER_VERSION,
    CheckContext,
    CheckFailed,
    CheckStopped,
    TargetTimeout,
    utc_now_iso,
)
from app.dns_checks import DnsResolver
from app.logging_config import get_logger, log_event
from app.policy import IPAddress, ScopePolicy

MAX_PORTS = 1024
MAX_ADDRESSES = 4
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_STDERR_BYTES = 64 * 1024
SUBPROCESS_GRACE_SECONDS = 30
MIN_HOST_TIMEOUT_SECONDS = 5
RLIMIT_AS_BYTES = 512 * 1024 * 1024
RLIMIT_NOFILE_COUNT = 1024
NMAP_ENV = {"PATH": "/usr/bin:/bin"}
_STATE_MAP = {
    "open": "open",
    "closed": "closed",
    "filtered": "filtered",
    "open|filtered": "filtered",
    "closed|filtered": "filtered",
}
_MAX_TEXT = 200

_log = get_logger("port_checks")


def max_rate(rate_per_second: float) -> int:
    return max(1, min(100, round(rate_per_second * 10)))


def max_parallelism(concurrency: int) -> int:
    return max(1, min(16, int(concurrency) * 4))


def validate_ports(ports: Iterable[Any]) -> list[int]:
    """Sorted unique ports 1-65535; raises CheckFailed(``invalid_profile``) on anything else."""
    out: set[int] = set()
    for port in ports:
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise CheckFailed("invalid_profile", "tcpPorts contains an invalid port.")
        out.add(port)
    if len(out) > MAX_PORTS:
        raise CheckFailed("invalid_profile", "tcpPorts lists too many ports.")
    return sorted(out)


def build_nmap_argv(
    nmap_path: str,
    addresses: list[IPAddress],
    ports: list[int],
    *,
    service_identification: bool,
    rate_per_second: float,
    concurrency: int,
    host_timeout_seconds: int,
) -> list[str]:
    """The fixed Nmap template. ``addresses`` must be validated and of one IP version."""
    if not addresses or len({a.version for a in addresses}) != 1:
        raise ValueError("addresses must be non-empty and of one IP version")
    ips = [str(ipaddress.ip_address(a)) for a in addresses]  # canonical text, never starts '-'
    port_list = ",".join(str(p) for p in validate_ports(ports))
    argv = [
        nmap_path,
        "-sT",
        "-Pn",
        "-n",
        "--unprivileged",
        "--max-retries", "1",
        "--host-timeout", f"{int(host_timeout_seconds)}s",
        "--max-rate", str(max_rate(rate_per_second)),
        "--max-parallelism", str(max_parallelism(concurrency)),
        "-p", port_list,
    ]  # fmt: skip
    if service_identification:
        argv += ["-sV", "--version-light"]
    if addresses[0].version == 6:
        argv.append("-6")
    argv += ["-oX", "-", *ips]
    return argv


# -- subprocess ---------------------------------------------------------------------------------


def _clamped_limit(which: int, wanted: int) -> tuple[int, int]:
    _soft, hard = resource.getrlimit(which)
    value = wanted if hard == resource.RLIM_INFINITY else min(wanted, hard)
    return (value, value)


def _rlimit_values(cpu_seconds: int) -> list[tuple[int, int, int]]:
    """(resource, soft, hard) integers, computed in the parent."""
    limits = [
        (resource.RLIMIT_AS, _clamped_limit(resource.RLIMIT_AS, RLIMIT_AS_BYTES)),
        (resource.RLIMIT_CPU, _clamped_limit(resource.RLIMIT_CPU, cpu_seconds)),
        (resource.RLIMIT_NOFILE, _clamped_limit(resource.RLIMIT_NOFILE, RLIMIT_NOFILE_COUNT)),
        (resource.RLIMIT_CORE, (0, 0)),
    ]
    return [(int(which), int(soft), int(hard)) for which, (soft, hard) in limits]


# Constant stub; only integers are interpolated into it. The target argv follows as sys.argv[1:].
_RLIMIT_STUB = (
    "import os, resource, sys\n"
    "for which, soft, hard in {limits!r}:\n"
    "    resource.setrlimit(which, (soft, hard))\n"
    "os.execv(sys.argv[1], sys.argv[1:])\n"
)


def limited_argv(argv: list[str], cpu_seconds: int) -> list[str]:
    """``argv`` wrapped so it starts with the rlimits in force (see the module docstring).
    ``argv[0]`` must be an absolute path (``execv`` does no PATH search)."""
    if not argv or not os.path.isabs(argv[0]):
        raise ValueError("argv[0] must be an absolute path")
    code = _RLIMIT_STUB.format(limits=_rlimit_values(cpu_seconds))
    return [sys.executable, "-I", "-S", "-c", code, *argv]


def _kill_group(proc: subprocess.Popen[bytes]) -> None:
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(proc.pid, signal.SIGKILL)


def run_nmap(
    argv: list[str],
    *,
    timeout: float,
    should_stop: Callable[[], bool] = lambda: False,
    max_output: int = MAX_OUTPUT_BYTES,
    monotonic: Callable[[], float] = time.monotonic,
) -> bytes:
    """Runs ``argv`` (never through a shell) and returns its stdout. Raises CheckFailed
    (``nmap_timeout``, ``nmap_output_too_large``, ``nmap_failed``) or CheckStopped."""
    proc = subprocess.Popen(  # noqa: S603 - fixed argv template, shell=False
        limited_argv(argv, int(timeout) + 1),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        env=dict(NMAP_ENV),
        close_fds=True,
        process_group=0,  # own process group: killpg reaches every descendant
    )
    assert proc.stdout is not None and proc.stderr is not None  # noqa: S101 - PIPE requested
    out = bytearray()
    err_len = 0
    deadline = monotonic() + timeout
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ)
    selector.register(proc.stderr, selectors.EVENT_READ)
    try:
        while selector.get_map():
            if should_stop():
                _kill_group(proc)
                raise CheckStopped
            remaining = deadline - monotonic()
            if remaining <= 0:
                _kill_group(proc)
                raise CheckFailed("nmap_timeout", "Nmap exceeded its time limit.")
            for key, _events in selector.select(min(0.5, remaining)):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.fileobj is proc.stdout:
                    out += chunk
                    if len(out) > max_output:
                        _kill_group(proc)
                        raise CheckFailed("nmap_output_too_large", "Nmap output exceeded the cap.")
                else:
                    err_len = min(err_len + len(chunk), MAX_STDERR_BYTES)  # discarded
        try:
            proc.wait(timeout=max(0.1, deadline - monotonic()))
        except subprocess.TimeoutExpired as exc:
            _kill_group(proc)
            raise CheckFailed("nmap_timeout", "Nmap exceeded its time limit.") from exc
    finally:
        selector.close()
        proc.stdout.close()
        proc.stderr.close()
        if proc.poll() is None:
            _kill_group(proc)
            proc.wait()
    if proc.returncode != 0:
        log_event(
            _log, logging.WARNING, "nmap_failed", returncode=proc.returncode, stderrBytes=err_len
        )
        raise CheckFailed("nmap_failed", "Nmap exited with an error.")
    return bytes(out)


# -- XML parsing --------------------------------------------------------------------------------


@dataclass(frozen=True)
class PortResult:
    ip: str
    port: int
    state: str
    reason: str | None = None
    service: str | None = None
    product: str | None = None
    version: str | None = None
    service_method: str | None = None


_DOCTYPE_RE = re.compile(rb"<!doctype", re.IGNORECASE)
_ENTITY_RE = re.compile(rb"<!entity", re.IGNORECASE)
NMAP_DOCTYPE = b"<!DOCTYPE nmaprun>"


def _screen_xml(data: bytes) -> None:
    if _ENTITY_RE.search(data):
        raise CheckFailed("nmap_output_invalid", "Nmap output declares entities.")
    doctypes = len(_DOCTYPE_RE.findall(data))
    if doctypes > 1 or (doctypes == 1 and data.count(NMAP_DOCTYPE) != 1):
        raise CheckFailed("nmap_output_invalid", "Nmap output has an unexpected DOCTYPE.")


def _expand_ports(spec: str) -> set[int]:
    out: set[int] = set()
    for part in spec.split(","):
        lo, _, hi = part.strip().partition("-")
        if not lo.isdigit() or (hi and not hi.isdigit()):
            continue
        start, end = int(lo), int(hi or lo)
        if 1 <= start <= end <= 65535 and end - start <= 65535:
            out.update(range(start, end + 1))
    return out


def _text(value: str | None) -> str | None:
    return value[:_MAX_TEXT] if value else None


def _canonical(addr: str | None) -> str | None:
    try:
        return str(ipaddress.ip_address(addr or ""))
    except ValueError:
        return None


def parse_nmap_xml(
    data: bytes, allowed_ips: set[str], ports: set[int], *, service_identification: bool
) -> list[PortResult]:
    """Port results for ``allowed_ips`` x ``ports`` only. Raises CheckFailed on unsafe or
    malformed XML."""
    _screen_xml(data)
    try:
        root = ET.fromstring(data)  # noqa: S314 - DTD/entity-free (screened above)
    except ET.ParseError as exc:
        raise CheckFailed("nmap_output_invalid", "Nmap output is not valid XML.") from exc
    if root.tag != "nmaprun":
        raise CheckFailed("nmap_output_invalid", "Nmap output is not an nmaprun document.")

    results: dict[tuple[str, int], PortResult] = {}
    for host in root.iter("host"):
        ip = None
        for address in host.findall("address"):
            if address.get("addrtype") in ("ipv4", "ipv6"):
                ip = _canonical(address.get("addr"))
                break
        if ip is None or ip not in allowed_ips:
            continue
        ports_el = host.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            portid = port_el.get("portid", "")
            if port_el.get("protocol") != "tcp" or not portid.isdigit():
                continue
            number = int(portid)
            state_el = port_el.find("state")
            state = _STATE_MAP.get(state_el.get("state", "") if state_el is not None else "")
            if number not in ports or state is None:
                continue
            service_el = port_el.find("service")
            svc = service_el if service_identification and state == "open" else None
            results[(ip, number)] = PortResult(
                ip=ip,
                port=number,
                state=state,
                reason=_text(state_el.get("reason") if state_el is not None else None),
                service=_text(svc.get("name")) if svc is not None else None,
                product=_text(svc.get("product")) if svc is not None else None,
                version=_text(svc.get("version")) if svc is not None else None,
                service_method=_text(svc.get("method")) if svc is not None else None,
            )
        extras = ports_el.findall("extraports")
        for extra in extras:
            state = _STATE_MAP.get(extra.get("state", ""))
            if state is None:
                continue
            listed: set[int] = set()
            reason: str | None = None
            for reasons in extra.findall("extrareasons"):
                if reasons.get("proto", "tcp") == "tcp" and reasons.get("ports"):
                    listed |= _expand_ports(reasons.get("ports", ""))
                    reason = reason or _text(reasons.get("reason"))
            if not listed and len(extras) == 1:
                listed = set(ports)  # the only folded group: every unlisted port has this state
            for number in sorted(listed & ports):
                results.setdefault((ip, number), PortResult(ip, number, state, reason))
    return sorted(results.values(), key=lambda r: (r.ip, r.port))


# -- check --------------------------------------------------------------------------------------


def build_port_observation(target_id: str, result: PortResult) -> dict[str, Any]:
    evidence: dict[str, Any] = {"method": "nmap-sT"}
    if result.reason:
        evidence["reason"] = result.reason
    if result.product:
        evidence["product"] = result.product
    if result.version:
        evidence["version"] = result.version
    if result.service_method:
        evidence["serviceMethod"] = result.service_method
    return {
        "kind": "port",
        "targetId": target_id,
        "observedAt": utc_now_iso(),
        "checkerVersion": CHECKER_VERSION,
        "resultStatus": "success",
        "evidence": evidence,
        "ipAddress": result.ip,
        "port": result.port,
        "protocol": "tcp",
        "state": result.state,
        "service": result.service[:100] if result.service else None,
    }


@dataclass(frozen=True)
class PortScanSettings:
    """Profile-derived settings; nothing here comes from users."""

    ports: tuple[int, ...]
    service_identification: bool
    rate_per_second: float
    concurrency: int
    target_seconds: float
    nmap_path: str
    nmap_available: bool


def check_tcp_ports(
    policy: ScopePolicy,
    resolver: DnsResolver,
    target_id: str,
    hostname: str,
    ctx: CheckContext,
    sink: Callable[[dict[str, Any]], None],
    settings: PortScanSettings,
) -> None:
    """``tcp_ports`` (+ ``service_identification``) for one target. Raises ScopeError (refused),
    CheckFailed (Nmap missing/failed), CheckStopped or TargetTimeout."""
    if not settings.nmap_available:
        raise CheckFailed("nmap_unavailable", "Nmap is not installed on this worker.")
    ports = validate_ports(settings.ports)
    if not ports:
        return
    ctx.before_network_call()
    resolved = policy.resolve(
        hostname, resolver, tier="network", lifetime=ctx.bounded(ctx.read_seconds)
    )
    candidates = list(resolved.addresses)[:MAX_ADDRESSES]
    # Every address is validated before any scan starts; one refusal aborts the whole check.
    validated = [policy.assert_destination(a, tier="network") for a in candidates]
    emitted = 0
    for family in (4, 6):
        group = [a for a in validated if a.version == family]
        if not group:
            continue
        ctx.before_network_call()
        remaining = ctx.remaining()
        if remaining < MIN_HOST_TIMEOUT_SECONDS:
            raise TargetTimeout
        host_timeout = int(max(MIN_HOST_TIMEOUT_SECONDS, min(settings.target_seconds, remaining)))
        group = [policy.assert_destination(a, tier="network") for a in group]  # just before start
        argv = build_nmap_argv(
            settings.nmap_path,
            group,
            ports,
            service_identification=settings.service_identification,
            rate_per_second=settings.rate_per_second,
            concurrency=settings.concurrency,
            host_timeout_seconds=host_timeout,
        )
        log_event(
            _log, logging.INFO, "nmap_started",
            targetId=target_id, addresses=[str(a) for a in group], ports=len(ports),
        )  # fmt: skip
        stdout = run_nmap(
            argv, timeout=host_timeout + SUBPROCESS_GRACE_SECONDS, should_stop=ctx.should_stop
        )
        for result in parse_nmap_xml(
            stdout,
            {str(a) for a in group},
            set(ports),
            service_identification=settings.service_identification,
        ):
            sink(build_port_observation(target_id, result))
            emitted += 1
    if emitted == 0:
        raise CheckFailed("nmap_no_results", "Nmap reported no results for the target.")
