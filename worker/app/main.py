"""Worker entry point.

Milestone 1 only validates configuration. Job claiming, checks and result submission are
implemented in Milestones 4-6.
"""

from __future__ import annotations

import argparse
import json
import sys

from app import __version__
from app.config import ConfigError, load_config


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="exdomainvault-worker")
    parser.add_argument(
        "--check-config", action="store_true", help="validate configuration and exit"
    )
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)

    try:
        config = load_config()
    except ConfigError as exc:
        print(json.dumps({"level": "ERROR", "message": "invalid_config", "detail": str(exc)}))
        return 2

    summary = {
        "level": "INFO",
        "message": "config_ok",
        "worker_id": config.worker_id,
        "environment": config.environment,
        "api_host": config.api_base_url.split("/")[2],
        "active_scanning_enabled": config.active_scanning_enabled,
    }
    print(json.dumps(summary))
    if args.check_config:
        return 0

    print(json.dumps({"level": "WARNING", "message": "job_processing_not_implemented"}))
    return 1


if __name__ == "__main__":
    sys.exit(main())
