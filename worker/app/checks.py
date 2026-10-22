"""Shared plumbing for checks: per-target deadline, cooperative stop, and a rate limiter."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from app import __version__

CHECKER_VERSION = __version__


def utc_now_iso() -> str:
    """ISO 8601 UTC with millisecond precision and a ``Z`` suffix (accepted by the API)."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class CheckStopped(Exception):
    """The job was cancelled, lost its lease, or the worker is shutting down."""


class TargetTimeout(Exception):
    """The per-target time budget (``profile.timeouts.targetSeconds``) is exhausted."""


class CheckFailed(Exception):
    """A check could not produce any observation. ``code`` becomes the target's ``errorCode``
    (``^[a-z0-9_]{1,64}$``); the message is for logs only and never contains target data."""

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code


class RateLimiter:
    """Spaces operations at most ``rate_per_second`` apart across all threads of a job."""

    def __init__(
        self,
        rate_per_second: float,
        *,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if rate_per_second <= 0:
            raise ValueError("rate_per_second must be positive")
        self._interval = 1.0 / rate_per_second
        self._monotonic = monotonic
        self._sleep = sleep
        self._next = 0.0
        self._lock = threading.Lock()

    def acquire(self, should_stop: Callable[[], bool] = lambda: False) -> None:
        with self._lock:
            now = self._monotonic()
            slot = max(now, self._next)
            self._next = slot + self._interval
        while True:
            if should_stop():
                raise CheckStopped
            remaining = slot - self._monotonic()
            if remaining <= 0:
                return
            self._sleep(min(remaining, 0.5))


@dataclass
class CheckContext:
    """Limits for checking one target."""

    deadline: float
    connect_seconds: float
    read_seconds: float
    rate_limiter: RateLimiter
    should_stop: Callable[[], bool] = lambda: False
    monotonic: Callable[[], float] = field(default=time.monotonic)

    def remaining(self) -> float:
        return self.deadline - self.monotonic()

    def bounded(self, seconds: float) -> float:
        """``seconds`` clipped to the remaining budget (never below 0.1 s)."""
        return max(0.1, min(seconds, self.remaining()))

    def before_network_call(self) -> None:
        """Checks stop/deadline and waits for a rate-limit slot."""
        if self.should_stop():
            raise CheckStopped
        if self.remaining() <= 0:
            raise TargetTimeout
        self.rate_limiter.acquire(self.should_stop)
        if self.remaining() <= 0:
            raise TargetTimeout
