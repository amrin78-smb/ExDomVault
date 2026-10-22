"""Batches target updates and observations into ``results`` submissions.

Limits per batch (``docs/worker-protocol.md``): at most 500 observations, at most 1000 target
updates, and a serialised body comfortably under the 1 MB request cap. Each batch gets a stable
``resultId`` (``<jobId>-<attempt>-<batchNo>``) generated once and reused on every retry, so a
duplicate delivery is a no-op on the server. The final batch carries ``complete: true``.
"""

from __future__ import annotations

import json
import re
from typing import Any, Protocol

MAX_OBSERVATIONS_PER_BATCH = 500
MAX_TARGETS_PER_BATCH = 1000
MAX_BATCH_BYTES = 900_000  # leaves headroom under the 1 MB request limit for the envelope
_RESULT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")


class ResultsApi(Protocol):
    def results(
        self,
        job_id: str,
        attempt: int,
        result_id: str,
        targets: list[dict[str, Any]],
        observations: list[dict[str, Any]],
        complete: bool,
    ) -> dict[str, Any]: ...


def make_result_id(job_id: str, attempt: int, batch_no: int) -> str:
    safe_job = re.sub(r"[^A-Za-z0-9_-]", "", job_id)[:80]
    result_id = f"{safe_job}-{attempt}-{batch_no:04d}"
    if not _RESULT_ID_RE.fullmatch(result_id):
        raise ValueError("cannot build a valid resultId")
    return result_id


def _size(item: dict[str, Any]) -> int:
    return len(json.dumps(item, separators=(",", ":"))) + 1


class ResultUploader:
    def __init__(self, api: ResultsApi, job_id: str, attempt: int) -> None:
        self._api = api
        self._job_id = job_id
        self._attempt = attempt
        self._batch_no = 0
        self._targets: list[dict[str, Any]] = []
        self._observations: list[dict[str, Any]] = []
        self._bytes = 0
        self.batches_sent = 0
        self.completed = False

    def _would_overflow(self, *, observations: int = 0, targets: int = 0, size: int = 0) -> bool:
        return (
            len(self._observations) + observations > MAX_OBSERVATIONS_PER_BATCH
            or len(self._targets) + targets > MAX_TARGETS_PER_BATCH
            or self._bytes + size > MAX_BATCH_BYTES
        )

    def add_observation(self, observation: dict[str, Any]) -> None:
        size = _size(observation)
        if self._would_overflow(observations=1, size=size):
            self.flush()
        self._observations.append(observation)
        self._bytes += size

    def add_target(self, target_id: str, status: str, error_code: str | None = None) -> None:
        update: dict[str, Any] = {"targetId": target_id, "status": status}
        if error_code:
            update["errorCode"] = error_code
        size = _size(update)
        if self._would_overflow(targets=1, size=size):
            self.flush()
        self._targets.append(update)
        self._bytes += size

    def add_target_result(
        self,
        target_id: str,
        status: str,
        observations: list[dict[str, Any]],
        error_code: str | None = None,
    ) -> None:
        for observation in observations:
            self.add_observation(observation)
        self.add_target(target_id, status, error_code)

    def flush(self, *, complete: bool = False) -> None:
        """Sends the pending batch (if any, or always when ``complete``)."""
        if self.completed:
            raise RuntimeError("results already completed")
        if not complete and not self._targets and not self._observations:
            return
        result_id = make_result_id(self._job_id, self._attempt, self._batch_no)
        self._api.results(
            self._job_id,
            self._attempt,
            result_id,
            self._targets,
            self._observations,
            complete,
        )
        self._batch_no += 1
        self.batches_sent += 1
        self._targets = []
        self._observations = []
        self._bytes = 0
        if complete:
            self.completed = True

    def finish(self) -> None:
        """Sends everything still pending as the final batch with ``complete: true``."""
        self.flush(complete=True)
