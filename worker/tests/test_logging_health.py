import json
import logging
import os

from app.health import HealthReporter, check_health
from app.logging_config import configure_logging, log_event, redact


def test_redaction_guard():
    data = {
        "ok": 1,
        "accessClientSecret": "s",
        "nested": {"Authorization": "Bearer x", "list": [{"token": "t"}]},
        "X-EDV-Signature": "sig",
        "password": "p",
    }
    out = redact(data)
    assert out["ok"] == 1
    assert out["accessClientSecret"] == "[REDACTED]"
    assert out["nested"]["Authorization"] == "[REDACTED]"
    assert out["nested"]["list"][0]["token"] == "[REDACTED]"
    assert out["X-EDV-Signature"] == "[REDACTED]"
    assert out["password"] == "[REDACTED]"


def test_json_logs_one_object_per_line(capsys):
    logger = configure_logging("INFO")
    log_event(logger, logging.INFO, "hello", jobId="j1", secret="nope")
    log_event(logger, logging.DEBUG, "hidden")
    try:
        raise ValueError("sensitive message")
    except ValueError:
        logger.exception("boom")
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["message"] == "hello"
    assert first["jobId"] == "j1"
    assert first["secret"] == "[REDACTED]"
    assert first["level"] == "INFO"
    second = json.loads(lines[1])
    assert second["exception"] == "ValueError"
    assert "sensitive message" not in lines[1]


def test_health_file_is_written_atomically(tmp_path):
    path = tmp_path / "sub" / "health.json"
    reporter = HealthReporter(str(path), "home-worker-01", clock=lambda: 1_792_656_000)
    reporter.update(status="ok", polled=True, last_job_id="j1")
    data = json.loads(path.read_text())
    assert data == {
        "status": "ok",
        "version": data["version"],
        "workerId": "home-worker-01",
        "lastPollAt": "2026-10-22T08:00:00Z",
        "lastJobId": "j1",
        "lastError": None,
        "activeScanningEnabled": False,
    }
    assert [p.name for p in path.parent.iterdir()] == ["health.json"]
    assert check_health(str(path), 30, now=1_792_656_000 + 89)
    assert not check_health(str(path), 30, now=1_792_656_000 + 91)


def test_health_write_failure_is_not_fatal(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    reporter = HealthReporter(str(blocker / "health.json"), "w1")
    reporter.update(status="ok")
    assert reporter.write_failed
    assert not check_health(str(blocker / "health.json"), 30)
    assert not os.path.exists(blocker / "health.json")


def test_health_rejects_garbage(tmp_path):
    path = tmp_path / "health.json"
    path.write_text("{not json")
    assert not check_health(str(path), 30)
    path.write_text(json.dumps({"lastPollAt": None}))
    assert not check_health(str(path), 30)
