import os

import pytest

from app.config import DEFAULT_HEALTH_FILE, ConfigError, load_config


def test_valid_config_applies_defaults(valid_env):
    env = {k: v for k, v in valid_env.items() if k != "EXDV_HEALTH_FILE"}
    config = load_config(env)
    assert config.api_base_url == "https://exdomainvault.example.com"
    assert config.environment == "production"
    assert config.poll_interval_seconds == 30
    assert config.log_level == "INFO"
    assert config.profiles == ("passive",)
    assert config.dns_resolvers == ("1.1.1.1", "9.9.9.9", "2606:4700:4700::1111", "2620:fe::fe")
    assert config.health_file == DEFAULT_HEALTH_FILE
    assert config.access_client_id is None
    assert config.access_client_secret is None
    assert config.api_host == "exdomainvault.example.com"


def test_active_scanning_is_always_disabled(valid_env):
    config = load_config({**valid_env, "EXDV_ACTIVE_SCANNING_ENABLED": "true"})
    assert config.active_scanning_enabled is False


@pytest.mark.parametrize(
    "missing",
    ["EXDV_API_BASE_URL", "EXDV_WORKER_ID", "EXDV_KEY_ID", "EXDV_PRIVATE_KEY_FILE"],
)
def test_required_values(valid_env, missing):
    env = {k: v for k, v in valid_env.items() if k != missing}
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
        ("https://exdomainvault.example.com/?x=1", "production"),
    ],
)
def test_rejects_unsafe_api_urls(valid_env, url, environment):
    with pytest.raises(ConfigError):
        load_config({**valid_env, "EXDV_API_BASE_URL": url, "EXDV_ENVIRONMENT": environment})


def test_allows_plain_http_only_for_local_development(valid_env):
    config = load_config(
        {
            **valid_env,
            "EXDV_API_BASE_URL": "http://localhost:5173",
            "EXDV_ENVIRONMENT": "development",
        }
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
        ("EXDV_KEY_ID", "not-a-uuid"),
        ("EXDV_PROFILES", "passive,BAD PROFILE"),
        ("EXDV_PROFILES", " , "),
        ("EXDV_DNS_RESOLVERS", "1.1.1.1,resolver.example"),
        ("EXDV_DNS_RESOLVERS", "999.1.1.1"),
        ("EXDV_HEALTH_FILE", "relative/health.json"),
    ],
)
def test_rejects_invalid_values(valid_env, name, value):
    with pytest.raises(ConfigError):
        load_config({**valid_env, name: value})


def test_parses_lists(valid_env):
    config = load_config(
        {
            **valid_env,
            "EXDV_PROFILES": "passive, quick,passive",
            "EXDV_DNS_RESOLVERS": "192.0.2.53, 2001:db8::53",
            "EXDV_KEY_ID": valid_env["EXDV_KEY_ID"].upper(),
        }
    )
    assert config.profiles == ("passive", "quick")
    assert config.dns_resolvers == ("192.0.2.53", "2001:db8::53")
    assert config.key_id == valid_env["EXDV_KEY_ID"]


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o660, 0o644, 0o700 | 0o010])
def test_rejects_group_or_world_accessible_key(valid_env, key_file, mode):
    os.chmod(key_file, mode)
    with pytest.raises(ConfigError, match="group or others"):
        load_config(valid_env)


def test_accepts_owner_only_key(valid_env, key_file):
    os.chmod(key_file, 0o400)
    assert load_config(valid_env).private_key_file == key_file


def test_rejects_missing_or_non_file_key(valid_env, tmp_path):
    with pytest.raises(ConfigError):
        load_config({**valid_env, "EXDV_PRIVATE_KEY_FILE": str(tmp_path / "missing.key")})
    os.chmod(tmp_path, 0o700)
    with pytest.raises(ConfigError):
        load_config({**valid_env, "EXDV_PRIVATE_KEY_FILE": str(tmp_path)})


@pytest.mark.parametrize(
    "extra",
    [{"EXDV_ACCESS_CLIENT_ID": "abc.access"}, {"EXDV_ACCESS_CLIENT_SECRET": "s3cr3t-value"}],
)
def test_access_token_both_or_neither(valid_env, extra):
    with pytest.raises(ConfigError, match="together"):
        load_config({**valid_env, **extra})


def test_access_secret_is_not_in_repr(valid_env):
    config = load_config(
        {
            **valid_env,
            "EXDV_ACCESS_CLIENT_ID": "abc.access",
            "EXDV_ACCESS_CLIENT_SECRET": "very-secret-value-123",
        }
    )
    assert config.access_client_secret == "very-secret-value-123"
    assert "very-secret-value-123" not in repr(config)
    assert "abc.access" in repr(config)


def test_system_resolvers_opt_in(valid_env):
    config = load_config({**valid_env, "EXDV_DNS_RESOLVERS": "system"})
    assert config.dns_resolvers == ()
