from __future__ import annotations

from .config import load_config
from .logging_utils import Logger

import sys

from .watcher import Watcher


def main() -> None:
    logger = Logger.from_env()
    config = load_config()
    watcher = Watcher.from_core_config(logger, config)

    if "--watch" in sys.argv:
        logger.info("Starting in watcher mode.")
        watcher.watch()
    else:
        logger.info("Starting single run.")
        watcher.run_sync()
