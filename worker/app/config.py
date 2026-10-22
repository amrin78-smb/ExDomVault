"""Worker configuration loaded from environment variables.

Configuration is validated at start-up and invalid values stop the worker (fail closed).
Active network scanning is not configurable yet: it stays disabled until the scope validator
(Milestone 6) is implemented and tested.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

Environment = Literal["development", "production"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR"]

_WORKER_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
_LOG_LEVELS: tuple[LogLevel, ...] = ("DEBUG", "INFO", "WARNING", "ERROR")
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


class ConfigError(ValueError):
    """Raised when worker configuration is missing or invalid."""


@dataclass(frozen=True, slots=True)
class WorkerConfig:
    api_base_url: str
    worker_id: str
    environment: Environment
    poll_interval_seconds: int
    log_level: LogLevel
    # Hard-coded off until Milestone 6 passes its security gate. Not read from the environment.
    active_scanning_enabled: bool = False


def load_config(env: Mapping[str, str] | None = None) -> WorkerConfig:
    """Builds a validated WorkerConfig from ``env`` (defaults to ``os.environ``)."""
    source = os.environ if env is None else env

    def required(name: str) -> str:
        value = source.get(name, "").strip()
        if not value:
            raise ConfigError(f"{name} is required")
        return value

    environment = source.get("EXDV_ENVIRONMENT", "production").strip()
    if environment not in ("development", "production"):
        raise ConfigError("EXDV_ENVIRONMENT must be 'development' or 'production'")

    api_base_url = required("EXDV_API_BASE_URL").rstrip("/")
    parts = urlsplit(api_base_url)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise ConfigError("EXDV_API_BASE_URL must be an absolute http(s) URL")
    if parts.username or parts.password:
        raise ConfigError("EXDV_API_BASE_URL must not contain credentials")
    if parts.scheme == "http" and not (
        environment == "development" and parts.hostname in _LOCAL_HOSTS
    ):
        raise ConfigError("EXDV_API_BASE_URL must use https outside local development")

    worker_id = required("EXDV_WORKER_ID")
    if not _WORKER_ID_RE.fullmatch(worker_id):
        raise ConfigError("EXDV_WORKER_ID must be 2-63 lowercase letters, digits or hyphens")

    raw_interval = source.get("EXDV_POLL_INTERVAL_SECONDS", "30").strip()
    try:
        poll_interval = int(raw_interval)
    except ValueError as exc:
        raise ConfigError("EXDV_POLL_INTERVAL_SECONDS must be an integer") from exc
    if not 5 <= poll_interval <= 3600:
        raise ConfigError("EXDV_POLL_INTERVAL_SECONDS must be between 5 and 3600")

    log_level = source.get("EXDV_LOG_LEVEL", "INFO").strip().upper()
    if log_level not in _LOG_LEVELS:
        raise ConfigError(f"EXDV_LOG_LEVEL must be one of {', '.join(_LOG_LEVELS)}")

    return WorkerConfig(
        api_base_url=api_base_url,
        worker_id=worker_id,
        environment=environment,  # type: ignore[arg-type]  # validated above
        poll_interval_seconds=poll_interval,
        log_level=log_level,  # type: ignore[arg-type]  # validated above
    )
