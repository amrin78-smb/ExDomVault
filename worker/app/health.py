"""Health file: a small JSON status document written atomically after each poll.

``exdomainvault-worker --health`` (used by systemd/Docker health checks) reads it and succeeds
when the last successful API contact is recent (within 3 x the poll interval).
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app import __version__


def _iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class HealthReporter:
    def __init__(
        self, path: str, worker_id: str, *, clock: Callable[[], float] = time.time
    ) -> None:
        self._path = Path(path)
        self._worker_id = worker_id
        self._clock = clock
        self._lock = threading.Lock()
        self.status = "starting"
        self.last_poll_at: float | None = None
        self.last_job_id: str | None = None
        self.last_error: str | None = None
        self.write_failed = False

    def snapshot(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "version": __version__,
            "workerId": self._worker_id,
            "lastPollAt": _iso(self.last_poll_at),
            "lastJobId": self.last_job_id,
            "lastError": self.last_error,
            "activeScanningEnabled": False,
        }

    def update(self, **changes: Any) -> None:
        """Applies changes (``status``, ``polled=True``, ``last_job_id``, ``last_error``) and
        rewrites the file. Write failures are remembered, never raised."""
        with self._lock:
            if changes.pop("polled", False):
                self.last_poll_at = self._clock()
            for key, value in changes.items():
                setattr(self, key, value)
            self._write(self.snapshot())

    def _write(self, data: dict[str, Any]) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix=".health-", dir=self._path.parent)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(data, fh, separators=(",", ":"))
                os.replace(tmp, self._path)
            except BaseException:
                Path(tmp).unlink(missing_ok=True)
                raise
            self.write_failed = False
        except OSError:
            self.write_failed = True


def check_health(path: str, poll_interval_seconds: int, *, now: float | None = None) -> bool:
    """True when the health file shows a successful API contact within 3 x poll interval."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        last = data.get("lastPollAt")
        if not isinstance(last, str):
            return False
        last_ts = datetime.fromisoformat(last).timestamp()
    except (OSError, ValueError, AttributeError):
        return False
    current = time.time() if now is None else now
    return 0 <= current - last_ts <= 3 * poll_interval_seconds or (
        # tolerate small clock adjustments
        -60 <= current - last_ts < 0
    )
