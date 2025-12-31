from __future__ import annotations

import argparse

from .config import load_config
from .logging_utils import Logger
from .daemon import Daemon


def main() -> None:
    logger = Logger.from_env()
    logger.install_exception_logging()

    parser = argparse.ArgumentParser(prog="rp-sync")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("sync", help="Run one sync and exit")
    sub.add_parser("daemon", help="Run continuously and re-sync on changes")

    args = parser.parse_args()

    command = args.command or "sync"
    daemon_mode = command == "daemon"

    config = load_config()
    proc = Daemon.from_core_config(logger, config)

    if daemon_mode:
        logger.info("Starting in daemon mode.")
        proc.watch()
    else:
        logger.info("Starting single run.")
        proc.sync_once()
