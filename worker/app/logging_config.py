"""Structured JSON logging to stdout (one object per line, read by journald).

Use :func:`log_event` with an event name and keyword fields. A redaction guard replaces the
value of any field whose name looks secret (secret, token, signature, authorization, password,
private key, cookie), at any nesting depth, so a mistake elsewhere cannot leak credentials.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import UTC, datetime
from typing import Any

LOGGER_NAME = "exdv"
REDACTED = "[REDACTED]"
_SENSITIVE_KEY = re.compile(
    r"secret|token|signature|authori[sz]ation|password|passwd|private|cookie|cf-access-client",
    re.IGNORECASE,
)
_MAX_DEPTH = 6


def redact(value: Any, depth: int = 0) -> Any:
    """Returns ``value`` with sensitive-looking keys' values replaced."""
    if depth > _MAX_DEPTH:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        return {
            str(k): REDACTED if _SENSITIVE_KEY.search(str(k)) else redact(v, depth + 1)
            for k, v in value.items()
        }
    if isinstance(value, list | tuple):
        return [redact(v, depth + 1) for v in value]
    return value


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            for key, value in redact(fields).items():
                if key not in payload:
                    payload[key] = value
        if record.exc_info and record.exc_info[0] is not None:
            # Exception class only: messages and stack traces may carry sensitive data.
            payload["exception"] = record.exc_info[0].__name__
        return json.dumps(payload, default=str, separators=(",", ":"))


class _StdoutHandler(logging.Handler):
    """Writes to the *current* ``sys.stdout`` (so test capture and re-configuration work)."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            sys.stdout.write(self.format(record) + "\n")
            sys.stdout.flush()
        except Exception:  # pragma: no cover - logging must never crash the worker
            self.handleError(record)


def configure_logging(level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger(LOGGER_NAME)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    handler = _StdoutHandler()
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    return logging.getLogger(LOGGER_NAME if name is None else f"{LOGGER_NAME}.{name}")


def log_event(logger: logging.Logger, level: int, event: str, **fields: Any) -> None:
    logger.log(level, event, extra={"fields": fields})
