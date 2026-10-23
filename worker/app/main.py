"""Worker entry point.

- ``--check-config``: validate configuration and the private key, then exit.
- ``--health``: exit 0 when the health file shows a recent successful poll, else 1.
- ``--once``: run a single claim cycle (and the job, if one is claimed), then exit.
- default: run the claim loop until SIGTERM/SIGINT (graceful: in-flight jobs are reported as
  ``worker_shutdown`` so they are retried), then exit 0.
"""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import threading
from typing import Any

from app import __version__
from app.client import Signer, WorkerApiClient
from app.config import ConfigError, WorkerConfig, load_config
from app.discovery import CrtShProvider
from app.dns_checks import DnspythonResolver
from app.health import HealthReporter, check_health
from app.identity import load_private_key
from app.logging_config import configure_logging, log_event
from app.queue import Worker
from app.rdap_checks import RdapClient


def _print(level: str, message: str, **fields: Any) -> None:
    print(json.dumps({"level": level, "message": message, **fields}))


def build_worker(config: WorkerConfig, shutdown: threading.Event) -> Worker:
    key = load_private_key(config.private_key_file)
    api = WorkerApiClient(
        config.api_base_url,
        Signer(key, config.key_id),
        access_client_id=config.access_client_id,
        access_client_secret=config.access_client_secret,
    )
    resolvers = config.dns_resolvers

    def resolver_factory(timeout: float) -> DnspythonResolver:
        return DnspythonResolver(resolvers, timeout=timeout)

    return Worker(
        config,
        api,
        resolver_factory=resolver_factory,
        # The resolver vets RDAP redirect targets (never loopback/LAN/metadata addresses).
        rdap_client=RdapClient(resolver=resolver_factory(5.0)),
        health=HealthReporter(config.health_file, config.worker_id),
        shutdown=shutdown,
        # Passive discovery: fixed Certificate Transparency provider (crt.sh), never a target.
        discovery_provider=CrtShProvider(),
    )


def install_signal_handlers(shutdown: threading.Event) -> None:
    def handler(signum: int, _frame: object) -> None:
        log_event(logging.getLogger("exdv"), logging.INFO, "shutdown_requested", signal=signum)
        shutdown.set()

    signal.signal(signal.SIGTERM, handler)
    signal.signal(signal.SIGINT, handler)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="exdomainvault-worker")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check-config", action="store_true", help="validate configuration")
    mode.add_argument("--health", action="store_true", help="check the health file")
    mode.add_argument("--once", action="store_true", help="run one claim cycle and exit")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)

    try:
        config = load_config()
        if args.health:
            return 0 if check_health(config.health_file, config.poll_interval_seconds) else 1
        load_private_key(config.private_key_file)
    except ConfigError as exc:
        _print("ERROR", "invalid_config", detail=str(exc))
        return 2

    logger = configure_logging(config.log_level)
    log_event(
        logger, logging.INFO, "config_ok",
        worker_id=config.worker_id, environment=config.environment, api_host=config.api_host,
        profiles=list(config.profiles), cf_access_configured=config.access_client_id is not None,
        active_scanning_enabled=config.active_scanning_enabled, version=__version__,
        activeScanningEnabled=config.active_scanning_enabled, nmapAvailable=config.nmap_available,
    )  # fmt: skip
    if args.check_config:
        return 0

    shutdown = threading.Event()
    worker = build_worker(config, shutdown)
    if args.once:
        outcome = worker.run_once()
        return 0 if outcome in ("idle", "job") else 1
    install_signal_handlers(shutdown)
    return worker.run_forever()


if __name__ == "__main__":
    sys.exit(main())
