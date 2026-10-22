import pytest

from app.config import ConfigError, load_config

VALID = {
    "EXDV_API_BASE_URL": "https://exdomainvault.example.com/",
    "EXDV_WORKER_ID": "home-worker-01",
}


def test_valid_config_applies_defaults():
    config = load_config(VALID)
    assert config.api_base_url == "https://exdomainvault.example.com"
    assert config.environment == "production"
    assert config.poll_interval_seconds == 30
    assert config.log_level == "INFO"


def test_active_scanning_is_always_disabled():
    assert (
        load_config({**VALID, "EXDV_ACTIVE_SCANNING_ENABLED": "true"}).active_scanning_enabled
        is False
    )


@pytest.mark.parametrize("missing", ["EXDV_API_BASE_URL", "EXDV_WORKER_ID"])
def test_required_values(missing):
    env = {k: v for k, v in VALID.items() if k != missing}
    with pytest.raises(ConfigError, match=missing):
        load_config(env)


@pytest.mark.parametrize(
    ("url", "environment"),
    [
        ("http://exdomainvault.example.com", "production"),
        ("http://exdomainvault.example.com", "development"),
        ("http://localhost:5173", "production"),
        ("https://user:pass@exdomainvault.example.com", "production"),
        ("ftp://exdomainvault.example.com", "production"),
        ("exdomainvault.example.com", "production"),
    ],
)
def test_rejects_unsafe_api_urls(url, environment):
    with pytest.raises(ConfigError):
        load_config({**VALID, "EXDV_API_BASE_URL": url, "EXDV_ENVIRONMENT": environment})


def test_allows_plain_http_only_for_local_development():
    config = load_config(
        {**VALID, "EXDV_API_BASE_URL": "http://localhost:5173", "EXDV_ENVIRONMENT": "development"}
    )
    assert config.api_base_url == "http://localhost:5173"


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("EXDV_WORKER_ID", "Bad ID!"),
        ("EXDV_POLL_INTERVAL_SECONDS", "1"),
        ("EXDV_POLL_INTERVAL_SECONDS", "abc"),
        ("EXDV_LOG_LEVEL", "TRACE"),
        ("EXDV_ENVIRONMENT", "staging"),
    ],
)
def test_rejects_invalid_values(name, value):
    with pytest.raises(ConfigError):
        load_config({**VALID, name: value})
