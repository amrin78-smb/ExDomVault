import os
from pathlib import Path

import pytest

from app.config import DEFAULT_HEALTH_FILE, DEFAULT_NMAP_PATH, ConfigError, load_config


def test_valid_config_applies_defaults(valid_env):
    env = {k: v for k, v in valid_env.items() if k != "EXDV_HEALTH_FILE"}
    config = load_config(env)
    assert config.api_base_url == "https://exdomainvault.example.com"
    assert config.environment == "production"
    assert config.poll_interval_seconds == 30
    assert config.log_level == "INFO"
    assert config.profiles == ("passive", "discovery", "brand")
    assert config.dns_resolvers == ("1.1.1.1", "9.9.9.9", "2606:4700:4700::1111", "2620:fe::fe")
    assert config.health_file == DEFAULT_HEALTH_FILE
    assert config.access_client_id is None
    assert config.access_client_secret is None
    assert config.api_host == "exdomainvault.example.com"


def test_active_scanning_defaults_off(valid_env):
    config = load_config(valid_env)
    assert config.active_scanning_enabled is False
    assert load_config(
        {**valid_env, "EXDV_ACTIVE_SCANNING_ENABLED": ""}
    ).active_scanning_enabled is (False)
    assert load_config(
        {**valid_env, "EXDV_ACTIVE_SCANNING_ENABLED": "false"}
    ).active_scanning_enabled is (False)


def test_active_scanning_explicit_true(valid_env):
    config = load_config({**valid_env, "EXDV_ACTIVE_SCANNING_ENABLED": " true "})
    assert config.active_scanning_enabled is True


@pytest.mark.parametrize(
    "value", ["TRUE", "True", "1", "yes", "on", "enabled", "truee", "false,true"]
)
def test_active_scanning_accepts_only_true_or_false(valid_env, value):
    with pytest.raises(ConfigError, match="EXDV_ACTIVE_SCANNING_ENABLED"):
        load_config({**valid_env, "EXDV_ACTIVE_SCANNING_ENABLED": value})


def test_deny_networks_parsed_and_canonical(valid_env):
    config = load_config(
        {
            **valid_env,
            "EXDV_DENY_NETWORKS": " 203.0.113.0/24, 198.51.100.7 ,2001:DB8::/32,203.0.113.0/24",
        }
    )
    assert config.deny_networks == ("203.0.113.0/24", "198.51.100.7/32", "2001:db8::/32")
    assert load_config(valid_env).deny_networks == ()


@pytest.mark.parametrize(
    "value",
    [
        "203.0.113.1/24",  # host bits set
        "203.0.113.0/33",
        "203.0.113.0/024",
        "10.0.0.0/255.0.0.0",
        "0x7f.0.0.0/8",
        "127.1",
        "2130706433",
        "fe80::%eth0/64",
        "home.example.com",
        "203.0.113.0/24;rm -rf /",
    ],
)
def test_deny_networks_strict(valid_env, value):
    with pytest.raises(ConfigError, match="EXDV_DENY_NETWORKS"):
        load_config({**valid_env, "EXDV_DENY_NETWORKS": value})


def test_deny_networks_count_capped(valid_env):
    many = ",".join(f"203.0.{i}.0/24" for i in range(101))
    with pytest.raises(ConfigError, match="at most"):
        load_config({**valid_env, "EXDV_DENY_NETWORKS": many})


def test_nmap_path_default_and_availability(valid_env, tmp_path):
    config = load_config(valid_env)
    assert config.nmap_path == DEFAULT_NMAP_PATH
    fake = tmp_path / "nmap"
    custom = load_config({**valid_env, "EXDV_NMAP_PATH": str(fake)})
    assert custom.nmap_path == str(fake)
    assert custom.nmap_available is False  # missing file is not a config error
    fake.write_text("#!/bin/sh\n")
    os.chmod(fake, 0o644)
    assert custom.nmap_available is False  # not executable
    os.chmod(fake, 0o700)
    assert custom.nmap_available is True
    assert load_config({**valid_env, "EXDV_NMAP_PATH": str(tmp_path)}).nmap_available is False


@pytest.mark.parametrize(
    "value", ["nmap", "bin/nmap", "/usr/bin/nmap --script x", "/usr/bin/nm\tap"]
)
def test_nmap_path_must_be_absolute_without_whitespace(valid_env, value):
    with pytest.raises(ConfigError, match="EXDV_NMAP_PATH"):
        load_config({**valid_env, "EXDV_NMAP_PATH": value})


def test_nmap_path_is_normalised(valid_env):
    config = load_config({**valid_env, "EXDV_NMAP_PATH": "/usr/local/../bin//nmap"})
    assert config.nmap_path == "/usr/bin/nmap"


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


def test_accepts_group_readable_key_inside_systemd_credentials_dir(valid_env, key_file, tmp_path):
    creds = tmp_path / "credentials"
    creds.mkdir(mode=0o750)
    key = creds / "worker.key"
    key.write_bytes(Path(key_file).read_bytes())
    os.chmod(key, 0o440)
    env = {**valid_env, "EXDV_PRIVATE_KEY_FILE": str(key), "CREDENTIALS_DIRECTORY": str(creds)}
    assert load_config(env).private_key_file == str(key)


@pytest.mark.parametrize(("dir_mode", "file_mode"), [(0o755, 0o440), (0o750, 0o444)])
def test_rejects_credentials_open_to_others(valid_env, key_file, tmp_path, dir_mode, file_mode):
    creds = tmp_path / "credentials"
    creds.mkdir()
    key = creds / "worker.key"
    key.write_bytes(Path(key_file).read_bytes())
    os.chmod(key, file_mode)
    os.chmod(creds, dir_mode)
    env = {**valid_env, "EXDV_PRIVATE_KEY_FILE": str(key), "CREDENTIALS_DIRECTORY": str(creds)}
    with pytest.raises(ConfigError, match="accessible by others"):
        load_config(env)


def test_group_readable_key_outside_credentials_dir_still_rejected(valid_env, key_file, tmp_path):
    os.chmod(key_file, 0o440)
    env = {**valid_env, "CREDENTIALS_DIRECTORY": str(tmp_path / "elsewhere")}
    with pytest.raises(ConfigError, match="group or others"):
        load_config(env)
