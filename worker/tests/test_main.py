import json

from app.main import main


def test_check_config_succeeds(monkeypatch, capsys):
    monkeypatch.setenv("EXDV_API_BASE_URL", "https://exdomainvault.example.com")
    monkeypatch.setenv("EXDV_WORKER_ID", "home-worker-01")
    assert main(["--check-config"]) == 0
    out = json.loads(capsys.readouterr().out.strip())
    assert out["message"] == "config_ok"
    assert out["active_scanning_enabled"] is False


def test_invalid_config_exits_non_zero(monkeypatch, capsys):
    monkeypatch.delenv("EXDV_API_BASE_URL", raising=False)
    monkeypatch.setenv("EXDV_WORKER_ID", "home-worker-01")
    assert main(["--check-config"]) == 2
    assert "invalid_config" in capsys.readouterr().out
