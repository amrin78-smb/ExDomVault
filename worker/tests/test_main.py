import json
import os
import time
from pathlib import Path

import httpx
import pytest

from app import main as main_module
from app.health import HealthReporter
from app.main import main


@pytest.fixture
def env(monkeypatch, valid_env):
    for key in list(os.environ):
        if key.startswith("EXDV_"):
            monkeypatch.delenv(key)
    for key, value in valid_env.items():
        monkeypatch.setenv(key, value)
    return valid_env


def test_check_config_succeeds(env, capsys):
    assert main(["--check-config"]) == 0
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert out["message"] == "config_ok"
    assert out["active_scanning_enabled"] is False
    assert out["activeScanningEnabled"] is False
    assert isinstance(out["nmapAvailable"], bool)
    assert out["api_host"] == "exdomainvault.example.com"


def test_check_config_reports_active_scanning_and_nmap(env, monkeypatch, tmp_path, capsys):
    nmap = tmp_path / "nmap"
    nmap.write_text("#!/bin/sh\nexit 0\n")  # never executed
    nmap.chmod(0o755)
    monkeypatch.setenv("EXDV_ACTIVE_SCANNING_ENABLED", "true")
    monkeypatch.setenv("EXDV_NMAP_PATH", str(nmap))
    assert main(["--check-config"]) == 0
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert out["activeScanningEnabled"] is True
    assert out["nmapAvailable"] is True

    monkeypatch.setenv("EXDV_NMAP_PATH", str(tmp_path / "missing-nmap"))
    assert main(["--check-config"]) == 0
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert out["nmapAvailable"] is False


def test_invalid_config_exits_non_zero(env, monkeypatch, capsys):
    monkeypatch.delenv("EXDV_API_BASE_URL")
    assert main(["--check-config"]) == 2
    assert "invalid_config" in capsys.readouterr().out


def test_check_config_rejects_a_non_ed25519_key(env, key_file, capsys):
    with open(key_file, "w") as fh:
        fh.write("-----BEGIN PRIVATE KEY-----\nnot a key\n-----END PRIVATE KEY-----\n")
    assert main(["--check-config"]) == 2
    out = capsys.readouterr().out
    assert "invalid_config" in out
    assert "not a key" not in out


def test_check_config_never_logs_the_access_secret(env, monkeypatch, capsys):
    monkeypatch.setenv("EXDV_ACCESS_CLIENT_ID", "abc.access")
    monkeypatch.setenv("EXDV_ACCESS_CLIENT_SECRET", "super-secret-access-value")
    assert main(["--check-config"]) == 0
    out = capsys.readouterr().out
    assert "super-secret-access-value" not in out
    assert json.loads(out.strip().splitlines()[-1])["cf_access_configured"] is True


def test_health_fails_without_file(env):
    assert main(["--health"]) == 1


def test_health_passes_after_recent_poll_and_fails_when_stale(env):
    reporter = HealthReporter(env["EXDV_HEALTH_FILE"], "home-worker-01")
    reporter.update(status="ok", polled=True)
    assert main(["--health"]) == 0
    stale = HealthReporter(
        env["EXDV_HEALTH_FILE"], "home-worker-01", clock=lambda: time.time() - 3 * 30 - 5
    )
    stale.update(status="ok", polled=True)
    assert main(["--health"]) == 1


def test_once_runs_a_single_idle_claim_cycle(env, monkeypatch):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(200, json={"job": None})

    original = main_module.WorkerApiClient

    def client_with_mock(*args, **kwargs):
        return original(*args, transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(main_module, "WorkerApiClient", client_with_mock)
    assert main(["--once"]) == 0
    assert calls == ["/api/v1/internal/worker/claim"]
    health = json.loads(Path(env["EXDV_HEALTH_FILE"]).read_text())
    assert health["status"] == "ok"
    assert health["activeScanningEnabled"] is False
    assert health["lastPollAt"] is not None
