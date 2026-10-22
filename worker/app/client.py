"""Signed HTTPS client for the application's internal worker API (``docs/worker-protocol.md``).

Every request is a ``POST`` of compact JSON, signed with the worker's Ed25519 key over
``EDV1 / method / path / timestamp / nonce / sha256(body)``. Each attempt (including every retry)
gets a fresh timestamp and nonce, because the server consumes a nonce as soon as it authenticates.
Redirects are never followed: a redirect means Cloudflare Access or the base URL is misconfigured.
"""

from __future__ import annotations

import base64
import hashlib
import json
import random
import re
import secrets
import time
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app import __version__

SIGNATURE_VERSION = "EDV1"
API_PREFIX = "/api/v1/internal/worker/"
USER_AGENT = f"exdomainvault-worker/{__version__}"
MAX_REQUEST_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
CONNECT_TIMEOUT_SECONDS = 10.0
TOTAL_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_RETRIES = 5
BACKOFF_BASE_SECONDS = 1.0
BACKOFF_CAP_SECONDS = 30.0
_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
_ENDPOINTS = frozenset({"claim", "heartbeat", "results", "failures"})


# --- Errors ----------------------------------------------------------------------------------


class ApiError(Exception):
    """A call to the worker API failed. Messages never contain secrets or response bodies."""

    def __init__(self, message: str, *, status: int | None = None, code: str | None = None):
        super().__init__(message)
        self.status = status
        self.code = code


class LeaseLost(ApiError):
    """409: this worker attempt no longer holds the job. Stop work and report nothing further."""


class AuthError(ApiError):
    """401/403: the worker is not authenticated (key revoked/expired, clock skew, Access token)."""


class TransientError(ApiError):
    """Network failure, timeout, 429 or 5xx that persisted through all retries."""


class RequestRejected(ApiError):
    """Any other non-success response (400, 404, 413, unexpected redirect...). Not retried."""


# --- Signing ---------------------------------------------------------------------------------


def body_bytes(payload: Mapping[str, Any]) -> bytes:
    """Compact JSON exactly as sent and hashed."""
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def default_nonce() -> str:
    return secrets.token_urlsafe(24)  # 32 chars of A-Z a-z 0-9 _ -


def signing_string(method: str, path: str, timestamp: str, nonce: str, body: bytes) -> str:
    return "\n".join(
        [
            SIGNATURE_VERSION,
            method.upper(),
            path,
            timestamp,
            nonce,
            hashlib.sha256(body).hexdigest(),
        ]
    )


class Signer:
    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        key_id: str,
        *,
        clock: Callable[[], float] = time.time,
        nonce_factory: Callable[[], str] = default_nonce,
    ) -> None:
        self._key = private_key
        self._key_id = key_id
        self._clock = clock
        self._nonce_factory = nonce_factory

    def sign(self, method: str, path: str, body: bytes) -> dict[str, str]:
        timestamp = str(int(self._clock()))
        nonce = self._nonce_factory()
        if not _NONCE_RE.fullmatch(nonce):
            raise ValueError("nonce must be 16-64 chars of A-Z a-z 0-9 _ -")
        message = signing_string(method, path, timestamp, nonce, body)
        signature = base64.b64encode(self._key.sign(message.encode("utf-8"))).decode("ascii")
        return {
            "X-EDV-Key-Id": self._key_id,
            "X-EDV-Timestamp": timestamp,
            "X-EDV-Nonce": nonce,
            "X-EDV-Signature": signature,
            "X-EDV-Worker-Version": __version__[:40],
        }


# --- Client ----------------------------------------------------------------------------------


def _retry_after_seconds(response: httpx.Response) -> float | None:
    value = response.headers.get("Retry-After", "").strip()
    if value.isdigit():
        return min(float(value), 60.0)
    return None


def _error_code(content: bytes) -> str | None:
    try:
        parsed = json.loads(content)
    except ValueError:
        return None
    if isinstance(parsed, dict) and isinstance(parsed.get("error"), dict):
        code = parsed["error"].get("code")
        if isinstance(code, str) and len(code) <= 64:
            return code
    return None


class WorkerApiClient:
    """Typed, signed calls to ``claim``, ``heartbeat``, ``results`` and ``failures``."""

    def __init__(
        self,
        base_url: str,
        signer: Signer,
        *,
        access_client_id: str | None = None,
        access_client_secret: str | None = None,
        transport: httpx.BaseTransport | None = None,
        max_retries: int = DEFAULT_MAX_RETRIES,
        sleep: Callable[[float], None] = time.sleep,
        rng: random.Random | None = None,
    ) -> None:
        parts = urlsplit(base_url.rstrip("/"))
        self._base_url = base_url.rstrip("/")
        self._path_prefix = parts.path.rstrip("/") + API_PREFIX
        self._signer = signer
        self._max_retries = max_retries
        self._sleep = sleep
        self._rng = rng or random.Random()  # noqa: S311 - jitter, not security
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if access_client_id and access_client_secret:
            headers["CF-Access-Client-Id"] = access_client_id
            headers["CF-Access-Client-Secret"] = access_client_secret
        self._http = httpx.Client(
            headers=headers,
            timeout=httpx.Timeout(TOTAL_TIMEOUT_SECONDS, connect=CONNECT_TIMEOUT_SECONDS),
            follow_redirects=False,
            verify=True,
            trust_env=False,
            transport=transport,
        )

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> WorkerApiClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- typed endpoints --

    def claim(self, profiles: list[str] | tuple[str, ...]) -> dict[str, Any] | None:
        response = self._post("claim", {"profiles": list(profiles)})
        job = response.get("job")
        if job is not None and not isinstance(job, dict):
            raise RequestRejected("claim response has an invalid job")
        return job

    def heartbeat(
        self,
        job_id: str,
        attempt: int,
        progress: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"jobId": job_id, "attempt": attempt}
        if progress is not None:
            payload["progress"] = dict(progress)
        return self._post("heartbeat", payload)

    def results(
        self,
        job_id: str,
        attempt: int,
        result_id: str,
        targets: list[dict[str, Any]],
        observations: list[dict[str, Any]],
        complete: bool,
    ) -> dict[str, Any]:
        # The same resultId is reused on every retry of this batch (idempotency key).
        return self._post(
            "results",
            {
                "jobId": job_id,
                "attempt": attempt,
                "resultId": result_id,
                "targets": targets,
                "observations": observations,
                "complete": complete,
            },
        )

    def failures(
        self,
        job_id: str,
        attempt: int,
        error_code: str,
        error_summary: str,
        retryable: bool,
    ) -> dict[str, Any]:
        return self._post(
            "failures",
            {
                "jobId": job_id,
                "attempt": attempt,
                "errorCode": error_code,
                "errorSummary": error_summary[:500],
                "retryable": retryable,
            },
        )

    # -- transport --

    def _backoff(self, retry: int, response: httpx.Response | None) -> float:
        delay = min(BACKOFF_CAP_SECONDS, BACKOFF_BASE_SECONDS * (2**retry))
        delay *= self._rng.uniform(0.5, 1.0)
        if response is not None:
            retry_after = _retry_after_seconds(response)
            if retry_after is not None:
                delay = max(delay, retry_after)
        return delay

    def _post(self, endpoint: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        if endpoint not in _ENDPOINTS:
            raise ValueError(f"unknown endpoint {endpoint!r}")
        body = body_bytes(payload)
        if len(body) > MAX_REQUEST_BYTES:
            raise RequestRejected("request body exceeds 1 MB", code="body_too_large")
        path = self._path_prefix + endpoint
        url = self._base_url + API_PREFIX + endpoint

        last_error = "unknown"
        for attempt in range(self._max_retries + 1):
            response: httpx.Response | None = None
            try:
                # Fresh timestamp + nonce for every attempt: nonces are single use.
                headers = self._signer.sign("POST", path, body)
                status, content, response = self._send(url, body, headers)
            except httpx.TransportError as exc:
                last_error = type(exc).__name__
            except _ResponseTooLarge:
                raise RequestRejected("response exceeds 1 MB", code="response_too_large") from None
            else:
                if 200 <= status < 300:
                    try:
                        parsed = json.loads(content)
                    except ValueError:
                        raise RequestRejected(
                            "response is not JSON", status=status, code="invalid_response"
                        ) from None
                    if not isinstance(parsed, dict):
                        raise RequestRejected(
                            "response is not an object", status=status, code="invalid_response"
                        )
                    return parsed
                code = _error_code(content)
                if status == 409:
                    raise LeaseLost("job lease lost", status=status, code=code)
                if status in (401, 403):
                    raise AuthError("worker authentication failed", status=status, code=code)
                if 300 <= status < 400:
                    raise RequestRejected(
                        "unexpected redirect (check EXDV_API_BASE_URL and Cloudflare Access)",
                        status=status,
                        code="unexpected_redirect",
                    )
                if status not in (408, 429) and status < 500:
                    raise RequestRejected(
                        f"request rejected with HTTP {status}", status=status, code=code
                    )
                last_error = f"http_{status}"
            if attempt < self._max_retries:
                self._sleep(self._backoff(attempt, response))
        raise TransientError(
            f"{endpoint} failed after {self._max_retries + 1} attempts ({last_error})",
            code=last_error,
        )

    def _send(
        self, url: str, body: bytes, headers: dict[str, str]
    ) -> tuple[int, bytes, httpx.Response]:
        deadline = time.monotonic() + TOTAL_TIMEOUT_SECONDS
        with self._http.stream("POST", url, content=body, headers=headers) as response:
            chunks: list[bytes] = []
            size = 0
            for chunk in response.iter_bytes():
                size += len(chunk)
                if size > MAX_RESPONSE_BYTES:
                    raise _ResponseTooLarge
                if time.monotonic() > deadline:
                    raise httpx.ReadTimeout("total request time exceeded")
                chunks.append(chunk)
            return response.status_code, b"".join(chunks), response


class _ResponseTooLarge(Exception):
    pass
