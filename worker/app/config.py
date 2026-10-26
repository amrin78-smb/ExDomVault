"""Worker configuration loaded from environment variables (see ``docs/worker-protocol.md``).

Configuration is validated at start-up and invalid values stop the worker (fail closed).
Active (target-connecting) checks run only when ``EXDV_ACTIVE_SCANNING_ENABLED=true``; the default
is off, and every connection still passes the Milestone 6 scope validator (``app.policy``).
"""

from __future__ import annotations

import ipaddress
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import urlsplit

from app.policy import parse_network

Environment = Literal["development", "production"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR"]

DEFAULT_HEALTH_FILE = "/var/lib/exdomainvault-worker/health.json"
DEFAULT_DNS_RESOLVERS = "1.1.1.1,9.9.9.9,2606:4700:4700::1111,2620:fe::fe"
DEFAULT_NMAP_PATH = "/usr/bin/nmap"
#: Both passive: DNS/RDAP monitoring and Certificate Transparency discovery.
DEFAULT_PROFILES = "passive,discovery"

_WORKER_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_PROFILE_RE = re.compile(r"^[a-z0-9_-]{1,40}$")
_ACCESS_VALUE_RE = re.compile(r"^[\x21-\x7e]{1,512}$")
_LOG_LEVELS: tuple[LogLevel, ...] = ("DEBUG", "INFO", "WARNING", "ERROR")
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
_MAX_PROFILES = 10
_MAX_RESOLVERS = 10
_MAX_DENY_NETWORKS = 100


class ConfigError(ValueError):
    """Raised when worker configuration is missing or invalid."""


@dataclass(frozen=True, slots=True)
class WorkerConfig:
    api_base_url: str
    worker_id: str
    key_id: str
    private_key_file: str
    environment: Environment
    poll_interval_seconds: int
    log_level: LogLevel
    profiles: tuple[str, ...] = ("passive", "discovery")
    dns_resolvers: tuple[str, ...] = ()
    health_file: str = DEFAULT_HEALTH_FILE
    access_client_id: str | None = None
    # Secret: never shown in repr() or logs.
    access_client_secret: str | None = field(default=None, repr=False)
    # EXDV_ACTIVE_SCANNING_ENABLED; off unless explicitly "true".
    active_scanning_enabled: bool = False
    # EXDV_DENY_NETWORKS: canonical CIDRs never contacted, on top of the built-in prohibited ranges.
    deny_networks: tuple[str, ...] = ()
    nmap_path: str = DEFAULT_NMAP_PATH
    # EXDV_GEOIP_ENABLED (default true): offline DB-IP country lookup for DNS observations.
    geoip_enabled: bool = True
    # EXDV_GEOIP_DIR: cache directory; default "geoip" next to the health file (state directory).
    geoip_dir: str = os.path.join(os.path.dirname(DEFAULT_HEALTH_FILE), "geoip")

    @property
    def api_host(self) -> str:
        return urlsplit(self.api_base_url).hostname or ""

    @property
    def nmap_available(self) -> bool:
        """True when ``nmap_path`` is an executable regular file (checked on each call)."""
        return os.path.isfile(self.nmap_path) and os.access(self.nmap_path, os.X_OK)


def _in_credentials_dir(path: str, credentials_dir: str | None) -> bool:
    """True when ``path`` is inside systemd's per-service credentials directory."""
    if not credentials_dir:
        return False
    base = os.path.realpath(credentials_dir)
    return os.path.commonpath([os.path.realpath(path), base]) == base


def _check_private_key_file(path: str, credentials_dir: str | None = None) -> None:
    try:
        info = os.stat(path)
    except OSError as exc:
        raise ConfigError("EXDV_PRIVATE_KEY_FILE does not exist or cannot be accessed") from exc
    if not stat.S_ISREG(info.st_mode):
        raise ConfigError("EXDV_PRIVATE_KEY_FILE must be a regular file")
    if _in_credentials_dir(path, credentials_dir):
        # systemd LoadCredential= copies are group-readable (0440) inside a per-service directory
        # that only the service can enter. Accept that, but require the directory itself and the
        # file to be closed to others.
        dir_mode = os.stat(os.path.realpath(credentials_dir or "")).st_mode
        if dir_mode & 0o007 or info.st_mode & 0o007:
            raise ConfigError("EXDV_PRIVATE_KEY_FILE credential must not be accessible by others")
    elif info.st_mode & 0o077:
        raise ConfigError(
            "EXDV_PRIVATE_KEY_FILE must not be readable or writable by group or others (chmod 600)"
        )
    if not os.access(path, os.R_OK):
        raise ConfigError("EXDV_PRIVATE_KEY_FILE is not readable by the worker user")


def _csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


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
    if parts.query or parts.fragment:
        raise ConfigError("EXDV_API_BASE_URL must not contain a query or fragment")
    if parts.scheme == "http" and not (
        environment == "development" and parts.hostname in _LOCAL_HOSTS
    ):
        raise ConfigError("EXDV_API_BASE_URL must use https outside local development")

    worker_id = required("EXDV_WORKER_ID")
    if not _WORKER_ID_RE.fullmatch(worker_id):
        raise ConfigError("EXDV_WORKER_ID must be 2-63 lowercase letters, digits or hyphens")

    key_id = required("EXDV_KEY_ID").lower()
    if not _UUID_RE.fullmatch(key_id):
        raise ConfigError("EXDV_KEY_ID must be the credential UUID shown at registration")

    private_key_file = required("EXDV_PRIVATE_KEY_FILE")
    _check_private_key_file(private_key_file, source.get("CREDENTIALS_DIRECTORY"))

    access_id = source.get("EXDV_ACCESS_CLIENT_ID", "").strip() or None
    access_secret = source.get("EXDV_ACCESS_CLIENT_SECRET", "").strip() or None
    if (access_id is None) != (access_secret is None):
        raise ConfigError(
            "EXDV_ACCESS_CLIENT_ID and EXDV_ACCESS_CLIENT_SECRET must be set together"
        )
    for name, value in (
        ("EXDV_ACCESS_CLIENT_ID", access_id),
        ("EXDV_ACCESS_CLIENT_SECRET", access_secret),
    ):
        if value is not None and not _ACCESS_VALUE_RE.fullmatch(value):
            raise ConfigError(f"{name} contains invalid characters")

    raw_interval = source.get("EXDV_POLL_INTERVAL_SECONDS", "30").strip()
    try:
        poll_interval = int(raw_interval)
    except ValueError as exc:
        raise ConfigError("EXDV_POLL_INTERVAL_SECONDS must be an integer") from exc
    if not 5 <= poll_interval <= 3600:
        raise ConfigError("EXDV_POLL_INTERVAL_SECONDS must be between 5 and 3600")

    profiles = tuple(dict.fromkeys(_csv(source.get("EXDV_PROFILES", DEFAULT_PROFILES))))
    if not profiles:
        raise ConfigError("EXDV_PROFILES must list at least one profile")
    if len(profiles) > _MAX_PROFILES:
        raise ConfigError(f"EXDV_PROFILES may list at most {_MAX_PROFILES} profiles")
    for profile in profiles:
        if not _PROFILE_RE.fullmatch(profile):
            raise ConfigError("EXDV_PROFILES entries must be 1-40 of a-z 0-9 _ -")

    # Default: public resolvers (Cloudflare, Quad9) so records are seen as the internet sees
    # them and DNSSEC record types work; local stubs such as systemd-resolved answer DS
    # queries with SERVFAIL. "system" opts back in to the host's resolver configuration.
    raw_resolvers = source.get("EXDV_DNS_RESOLVERS", "").strip() or DEFAULT_DNS_RESOLVERS
    resolvers: list[str] = []
    for raw in [] if raw_resolvers == "system" else _csv(raw_resolvers):
        try:
            resolvers.append(str(ipaddress.ip_address(raw)))
        except ValueError as exc:
            raise ConfigError("EXDV_DNS_RESOLVERS must be a comma-separated IP list") from exc
    if len(resolvers) > _MAX_RESOLVERS:
        raise ConfigError(f"EXDV_DNS_RESOLVERS may list at most {_MAX_RESOLVERS} resolvers")

    health_file = source.get("EXDV_HEALTH_FILE", "").strip() or DEFAULT_HEALTH_FILE
    if not os.path.isabs(health_file):
        raise ConfigError("EXDV_HEALTH_FILE must be an absolute path")

    raw_active = source.get("EXDV_ACTIVE_SCANNING_ENABLED", "").strip() or "false"
    if raw_active not in ("true", "false"):
        raise ConfigError("EXDV_ACTIVE_SCANNING_ENABLED must be 'true' or 'false'")

    deny: list[str] = []
    for raw in _csv(source.get("EXDV_DENY_NETWORKS", "")):
        try:
            deny.append(str(parse_network(raw)))
        except ValueError as exc:
            raise ConfigError(
                "EXDV_DENY_NETWORKS must be comma-separated canonical CIDRs (host bits zero) "
                "or addresses"
            ) from exc
    deny = list(dict.fromkeys(deny))
    if len(deny) > _MAX_DENY_NETWORKS:
        raise ConfigError(f"EXDV_DENY_NETWORKS may list at most {_MAX_DENY_NETWORKS} networks")

    nmap_path = source.get("EXDV_NMAP_PATH", "").strip() or DEFAULT_NMAP_PATH
    if not os.path.isabs(nmap_path) or "\x00" in nmap_path or any(c.isspace() for c in nmap_path):
        raise ConfigError("EXDV_NMAP_PATH must be an absolute path without whitespace")
    nmap_path = os.path.normpath(nmap_path)

    raw_geoip = source.get("EXDV_GEOIP_ENABLED", "").strip() or "true"
    if raw_geoip not in ("true", "false"):
        raise ConfigError("EXDV_GEOIP_ENABLED must be 'true' or 'false'")
    geoip_dir = source.get("EXDV_GEOIP_DIR", "").strip() or os.path.join(
        os.path.dirname(health_file), "geoip"
    )
    if not os.path.isabs(geoip_dir) or "\x00" in geoip_dir:
        raise ConfigError("EXDV_GEOIP_DIR must be an absolute path")
    geoip_dir = os.path.normpath(geoip_dir)

    log_level = source.get("EXDV_LOG_LEVEL", "INFO").strip().upper()
    if log_level not in _LOG_LEVELS:
        raise ConfigError(f"EXDV_LOG_LEVEL must be one of {', '.join(_LOG_LEVELS)}")

    return WorkerConfig(
        api_base_url=api_base_url,
        worker_id=worker_id,
        key_id=key_id,
        private_key_file=private_key_file,
        environment=environment,  # type: ignore[arg-type]  # validated above
        poll_interval_seconds=poll_interval,
        log_level=log_level,  # type: ignore[arg-type]  # validated above
        profiles=profiles,
        dns_resolvers=tuple(resolvers),
        health_file=health_file,
        access_client_id=access_id,
        access_client_secret=access_secret,
        active_scanning_enabled=raw_active == "true",
        deny_networks=tuple(deny),
        nmap_path=nmap_path,
        geoip_enabled=raw_geoip == "true",
        geoip_dir=geoip_dir,
    )
