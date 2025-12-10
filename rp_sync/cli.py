from __future__ import annotations

from .config import load_config
from .logging_utils import Logger


import sys

from .watcher import Watcher


def main() -> None:
    cfg = load_config()
    logger = Logger.from_config(cfg.logging)
    watcher = Watcher(logger)

    if "--watch" in sys.argv:
        watcher.watch()
    else:
        watcher.run_sync()
