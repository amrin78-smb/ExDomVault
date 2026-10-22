"""The worker loop: claim → revalidate → check → heartbeat → upload → complete.

PostgreSQL (behind the API) is the source of truth for job state; this loop only acts on a job
while it holds the lease (``attempt`` is the fencing token). A ``409`` stops work immediately and
nothing further is reported for that job. Failed or incomplete work is never reported as success:
targets that could not be checked are reported ``failed`` with an error code.

Milestone 5 runs passive checks only (``dns``, ``rdap``). A job whose profile is active or lists
a network-connecting check is refused with ``active_scanning_disabled`` before any check runs.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any

from app.checks import CheckContext, CheckStopped, RateLimiter, TargetTimeout
from app.client import ApiError, AuthError, LeaseLost, WorkerApiClient
from app.config import WorkerConfig
from app.dns_checks import DnsResolver, check_dns
from app.health import HealthReporter
from app.logging_config import get_logger, log_event
from app.rdap_checks import RdapClient, check_rdap
from app.result_upload import ResultUploader
from app.scope import ScopeError, assert_passive_allowed, normalise_hostname, validate_job_targets

AUTH_BACKOFF_SECONDS = 300
_FAILED_STATUSES = frozenset({"error", "timeout"})


class InvalidJob(Exception):
    def __init__(self, message: str, job_id: str | None = None, attempt: int | None = None):
        super().__init__(message)
        self.job_id = job_id
        self.attempt = attempt


@dataclass(frozen=True)
class JobTarget:
    id: str
    hostname: str


@dataclass(frozen=True)
class JobSpec:
    id: str
    attempt: int
    profile: str
    heartbeat_seconds: int
    lease_seconds: int
    domain: str
    active: bool
    checks: tuple[str, ...]
    connect_seconds: float
    read_seconds: float
    target_seconds: float
    concurrency: int
    rate_per_second: float
    max_targets: int
    targets: tuple[JobTarget, ...]
    snapshot_hostnames: tuple[str, ...]


def _get(obj: Any, *path: str) -> Any:
    for key in path:
        if not isinstance(obj, dict) or key not in obj:
            raise KeyError(".".join(path))
        obj = obj[key]
    return obj


def _num(value: Any, lo: float, hi: float, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float) or not lo <= value <= hi:
        raise ValueError(name)
    return value


def parse_job(raw: dict[str, Any]) -> JobSpec:
    """Structurally validates a claimed job. Raises InvalidJob (with id/attempt when known)."""
    job_id = raw.get("id") if isinstance(raw.get("id"), str) else None
    attempt = raw.get("attempt")
    attempt = attempt if isinstance(attempt, int) and not isinstance(attempt, bool) else None
    try:
        if job_id is None or attempt is None or attempt < 1:
            raise ValueError("id/attempt")
        config = _get(raw, "snapshot", "profile", "config")
        checks = _get(config, "checks")
        if not isinstance(checks, list) or not all(isinstance(c, str) for c in checks):
            raise ValueError("checks")
        timeouts = _get(config, "timeouts")
        raw_targets = _get(raw, "targets")
        if not isinstance(raw_targets, list):
            raise ValueError("targets")
        targets = tuple(
            JobTarget(id=str(_get(t, "id")), hostname=str(_get(t, "hostname"))) for t in raw_targets
        )
        snapshot_targets = _get(raw, "snapshot", "targets")
        if not isinstance(snapshot_targets, list):
            raise ValueError("snapshot.targets")
        active = _get(config, "active")
        if not isinstance(active, bool):
            raise ValueError("active")
        return JobSpec(
            id=job_id,
            attempt=attempt,
            profile=str(_get(raw, "profile")),
            heartbeat_seconds=int(_num(raw.get("heartbeatSeconds", 60), 1, 3600, "hb")),
            lease_seconds=int(_num(raw.get("leaseSeconds", 300), 1, 86_400, "lease")),
            domain=str(_get(raw, "snapshot", "domain", "fqdn")),
            active=active,
            checks=tuple(checks),
            connect_seconds=_num(_get(timeouts, "connectMs"), 100, 30_000, "connectMs") / 1000,
            read_seconds=_num(_get(timeouts, "readMs"), 100, 60_000, "readMs") / 1000,
            target_seconds=_num(_get(timeouts, "targetSeconds"), 5, 3600, "targetSeconds"),
            concurrency=int(_num(_get(config, "concurrency"), 1, 16, "concurrency")),
            rate_per_second=_num(_get(config, "ratePerSecond"), 0.1, 50, "ratePerSecond"),
            max_targets=int(_num(_get(config, "maxTargets"), 1, 1000, "maxTargets")),
            targets=targets,
            snapshot_hostnames=tuple(str(_get(t, "hostname")) for t in snapshot_targets),
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise InvalidJob("The claimed job is malformed.", job_id, attempt) from exc


@dataclass
class TargetResult:
    target_id: str
    status: str
    error_code: str | None = None
    observations: list[dict[str, Any]] = field(default_factory=list)


class JobControl:
    """Stop signals for one job: user cancellation, lost lease, or worker shutdown."""

    def __init__(self, shutdown: threading.Event) -> None:
        self.shutdown = shutdown
        self.cancelled = threading.Event()
        self.lease_lost = threading.Event()
        self.aborted = threading.Event()
        self.done = threading.Event()

    def should_stop(self) -> bool:
        return (
            self.shutdown.is_set()
            or self.cancelled.is_set()
            or self.lease_lost.is_set()
            or self.aborted.is_set()
        )


class Worker:
    def __init__(
        self,
        config: WorkerConfig,
        api: WorkerApiClient,
        *,
        resolver_factory: Callable[[float], DnsResolver],
        rdap_client: RdapClient,
        health: HealthReporter,
        shutdown: threading.Event | None = None,
        heartbeat_interval: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        logger: logging.Logger | None = None,
    ) -> None:
        self._config = config
        self._api = api
        self._resolver_factory = resolver_factory
        self._rdap = rdap_client
        self._health = health
        self.shutdown = shutdown or threading.Event()
        self._heartbeat_interval = heartbeat_interval
        self._monotonic = monotonic
        self._sleep = sleep
        self._log = logger or get_logger("queue")
        self._completed = 0
        self._total = 0

    # -- loop ---------------------------------------------------------------------------------

    def run_forever(self) -> int:
        log_event(
            self._log, logging.INFO, "worker_started",
            workerId=self._config.worker_id, profiles=list(self._config.profiles),
            activeScanningEnabled=self._config.active_scanning_enabled,
        )  # fmt: skip
        while not self.shutdown.is_set():
            try:
                outcome = self.run_once()
            except Exception as exc:  # never let the loop die on a bug
                log_event(self._log, logging.ERROR, "loop_error", error=type(exc).__name__)
                outcome = "error"
            if outcome == "job":
                continue
            wait = self._config.poll_interval_seconds
            if outcome == "auth_error":
                wait = max(AUTH_BACKOFF_SECONDS, wait)
            self.shutdown.wait(wait)
        self._health.update(status="stopped")
        log_event(self._log, logging.INFO, "worker_stopped")
        return 0

    def run_once(self) -> str:
        """One claim cycle. Returns ``idle``, ``job``, ``error`` or ``auth_error``."""
        if self.shutdown.is_set():
            return "idle"
        try:
            raw = self._api.claim(self._config.profiles)
        except AuthError:
            log_event(self._log, logging.ERROR, "claim_auth_failed")
            self._health.update(status="error", last_error="auth_failed")
            return "auth_error"
        except ApiError as exc:
            log_event(self._log, logging.WARNING, "claim_failed", error=type(exc).__name__)
            self._health.update(status="error", last_error=f"claim_{type(exc).__name__}")
            return "error"
        self._health.update(status="ok", polled=True, last_error=None)
        if raw is None:
            return "idle"
        self.process_job(raw)
        return "job"

    # -- job ----------------------------------------------------------------------------------

    def _report_failure(
        self, job_id: str, attempt: int, code: str, summary: str, retryable: bool
    ) -> None:
        log_event(
            self._log, logging.WARNING, "job_failed",
            jobId=job_id, attempt=attempt, errorCode=code, retryable=retryable,
        )  # fmt: skip
        try:
            self._api.failures(job_id, attempt, code, summary, retryable)
        except LeaseLost:
            log_event(self._log, logging.WARNING, "lease_lost", jobId=job_id)
        except ApiError as exc:
            log_event(
                self._log, logging.ERROR, "failure_report_failed",
                jobId=job_id, error=type(exc).__name__,
            )  # fmt: skip
        self._health.update(last_error=code)

    def _refusal(self, spec: JobSpec) -> tuple[str, str, bool] | None:
        """Why this worker must not run the job, as (errorCode, summary, retryable)."""
        if spec.profile not in self._config.profiles:
            return ("profile_not_supported", "This worker is not configured for the profile.", True)
        if spec.active or self._config.active_scanning_enabled is not False:
            return (
                "active_scanning_disabled",
                "The profile is active; active scanning is disabled on this worker.",
                False,
            )
        for check in spec.checks:
            try:
                assert_passive_allowed(check)
            except ScopeError as exc:
                return (exc.code, str(exc), False)
        if len(spec.targets) > spec.max_targets:
            return ("scope_rejected", "The job has more targets than the profile allows.", False)
        try:
            validate_job_targets(
                spec.domain, [t.hostname for t in spec.targets], spec.snapshot_hostnames
            )
        except ScopeError as exc:
            return (exc.code, str(exc), False)
        return None

    def process_job(self, raw: dict[str, Any]) -> None:
        try:
            spec = parse_job(raw)
        except InvalidJob as exc:
            log_event(self._log, logging.ERROR, "invalid_job", jobId=exc.job_id)
            if exc.job_id is not None and exc.attempt is not None:
                self._report_failure(exc.job_id, exc.attempt, "invalid_job", str(exc), False)
            return
        self._health.update(last_job_id=spec.id)
        log_event(
            self._log, logging.INFO, "job_claimed",
            jobId=spec.id, attempt=spec.attempt, profile=spec.profile, targets=len(spec.targets),
        )  # fmt: skip

        refusal = self._refusal(spec)
        if refusal is not None:
            self._report_failure(spec.id, spec.attempt, *refusal)
            return

        control = JobControl(self.shutdown)
        try:
            self._run_job(spec, control)
        except LeaseLost:
            control.lease_lost.set()
            log_event(self._log, logging.WARNING, "lease_lost", jobId=spec.id)
        except AuthError:
            log_event(self._log, logging.ERROR, "job_auth_failed", jobId=spec.id)
            self._health.update(last_error="auth_failed")
        except Exception as exc:
            self._report_failure(
                spec.id,
                spec.attempt,
                "worker_error",
                f"Unexpected worker error ({type(exc).__name__}).",
                True,
            )

    def _heartbeat(self, spec: JobSpec, control: JobControl) -> None:
        progress = {"completedTargets": self._completed, "totalTargets": self._total}
        try:
            response = self._api.heartbeat(spec.id, spec.attempt, progress)
        except LeaseLost:
            control.lease_lost.set()
            log_event(self._log, logging.WARNING, "lease_lost", jobId=spec.id)
            return
        except ApiError as exc:
            log_event(
                self._log, logging.WARNING, "heartbeat_failed",
                jobId=spec.id, error=type(exc).__name__,
            )  # fmt: skip
            return
        self._health.update(polled=True)
        if response.get("cancelRequested") is True and not control.cancelled.is_set():
            log_event(self._log, logging.INFO, "job_cancel_requested", jobId=spec.id)
            control.cancelled.set()

    def _heartbeat_loop(self, spec: JobSpec, control: JobControl) -> None:
        interval = self._heartbeat_interval
        if interval is None:
            interval = max(5.0, min(float(spec.heartbeat_seconds), spec.lease_seconds / 2))
        while not control.done.wait(interval):
            self._heartbeat(spec, control)
            if control.lease_lost.is_set():
                return

    def _run_job(self, spec: JobSpec, control: JobControl) -> None:
        self._completed = 0
        self._total = len(spec.targets)
        uploader = ResultUploader(self._api, spec.id, spec.attempt)

        # Immediate heartbeat: marks the job running and picks up an early cancellation.
        self._heartbeat(spec, control)
        heartbeater = threading.Thread(
            target=self._heartbeat_loop, args=(spec, control), name="heartbeat", daemon=True
        )
        if not control.should_stop():
            heartbeater.start()
        try:
            if not control.should_stop():
                self._run_targets(spec, control, uploader)
        finally:
            control.done.set()
            if heartbeater.is_alive():
                heartbeater.join(timeout=35)

        if control.lease_lost.is_set():
            return  # someone else owns the job now: report nothing
        if control.cancelled.is_set():
            self._report_failure(
                spec.id, spec.attempt, "cancelled", "The job was cancelled by a user.", False
            )
            return
        if self.shutdown.is_set():
            self._report_failure(
                spec.id,
                spec.attempt,
                "worker_shutdown",
                "The worker shut down before the job finished.",
                True,
            )
            return
        uploader.finish()
        log_event(
            self._log, logging.INFO, "job_completed",
            jobId=spec.id, attempt=spec.attempt, batches=uploader.batches_sent,
        )  # fmt: skip

    def _run_targets(self, spec: JobSpec, control: JobControl, uploader: ResultUploader) -> None:
        limiter = RateLimiter(spec.rate_per_second, monotonic=self._monotonic, sleep=self._sleep)
        resolver = self._resolver_factory(spec.connect_seconds)
        apex = normalise_hostname(spec.domain)
        executor = ThreadPoolExecutor(max_workers=spec.concurrency, thread_name_prefix="check")
        try:
            futures = [
                executor.submit(self._check_target, spec, t, apex, limiter, resolver, control)
                for t in spec.targets
            ]
            for future in as_completed(futures):
                result = future.result()
                if control.should_stop():
                    break
                if result is None:
                    continue
                uploader.add_target_result(
                    result.target_id, result.status, result.observations, result.error_code
                )
                self._completed += 1
        except LeaseLost:
            control.lease_lost.set()
            raise
        except BaseException:
            control.aborted.set()
            raise
        finally:
            # Running checks observe should_stop() between queries; queued ones are cancelled.
            executor.shutdown(wait=True, cancel_futures=True)

    def _check_target(
        self,
        spec: JobSpec,
        target: JobTarget,
        apex: str,
        limiter: RateLimiter,
        resolver: DnsResolver,
        control: JobControl,
    ) -> TargetResult | None:
        if control.should_stop():
            return None
        hostname = normalise_hostname(target.hostname)
        is_apex = hostname == apex
        observations: list[dict[str, Any]] = []
        ctx = CheckContext(
            deadline=self._monotonic() + spec.target_seconds,
            connect_seconds=spec.connect_seconds,
            read_seconds=spec.read_seconds,
            rate_limiter=limiter,
            should_stop=control.should_stop,
            monotonic=self._monotonic,
        )
        try:
            if "dns" in spec.checks:
                check_dns(resolver, target.id, hostname, is_apex, ctx, observations.append)
            if "rdap" in spec.checks and is_apex:
                check_rdap(self._rdap, target.id, hostname, ctx, observations.append)
        except CheckStopped:
            return None
        except TargetTimeout:
            return TargetResult(target.id, "failed", "target_timeout", observations)
        except Exception as exc:
            log_event(
                self._log, logging.ERROR, "check_error",
                jobId=spec.id, targetId=target.id, error=type(exc).__name__,
            )  # fmt: skip
            return TargetResult(target.id, "failed", "check_error", observations)
        if not observations:
            return TargetResult(target.id, "skipped", None, observations)
        if all(o["resultStatus"] in _FAILED_STATUSES for o in observations):
            return TargetResult(target.id, "failed", "checks_failed", observations)
        return TargetResult(target.id, "succeeded", None, observations)
