from __future__ import annotations

import sys
from .config import load_config
from .logging_utils import Logger
from .watcher import Watcher


def main() -> None:
    logger = Logger.from_env()
    logger.install_exception_logging()

    config = load_config()
    watcher = Watcher.from_core_config(logger, config)

    if "--watch" in sys.argv:
        logger.info("Starting in watcher mode.")
        watcher.watch()
    else:
        logger.info("Starting single run.")
        watcher.run_sync()
