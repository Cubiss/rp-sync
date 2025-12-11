from __future__ import annotations

import logging

import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict

from rp_sync.config import (
    LOG_LEVEL,
    APP_NAME,
    LOG_KEEP,
    LOG_DIR,
    DEFAULT_LOG_LEVEL,
    DEFAULT_LOG_DIR,
    DEFAULT_LOG_KEEP,
)


class Logger:
    _instances: Dict[str, Logger] = {}

    def __init__(
        self,
        app_name: str = APP_NAME,
        log_level: str = "INFO",
        keep: int = 10,
        log_dir: Optional[Path] = "./logs",
    ):
        self.app_name = app_name
        self.keep = keep
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        pid = os.getpid()
        self.file_path = self.log_dir / f"{self.app_name}_{ts}_{pid}.log"
        self.latest_path = self.log_dir / "latest.log"

        self.logger = logging.getLogger(self.app_name)
        self.logger.setLevel(log_level or logging.INFO)
        self.logger.propagate = False

        self._base_fmt = logging.Formatter(
            fmt="%(asctime)s.%(msecs)03d [%(levelname)s]: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        # Idempotent: only add our file handlers once per process
        if not any(
            isinstance(h, logging.FileHandler) and getattr(h, "_app_file", False)
            for h in self.logger.handlers
        ):
            self._add_file_handlers()

        self._prune_old_logs()

        self.logger.debug(f"Logging initialized -> {self.file_path}")

    # ---------- public helpers ----------

    @classmethod
    def from_env(cls) -> Logger:
        key = f"{APP_NAME}"
        if key in cls._instances:
            inst = cls._instances[key]
            inst.set_level(os.environ.get(LOG_LEVEL, DEFAULT_LOG_LEVEL))
            return inst
        inst = cls(
            app_name=APP_NAME,
            log_level=os.environ.get(LOG_LEVEL, DEFAULT_LOG_LEVEL),
            keep=int(os.environ.get(LOG_KEEP, DEFAULT_LOG_KEEP)),
            log_dir=os.environ.get(LOG_DIR, DEFAULT_LOG_DIR),
        )
        cls._instances[key] = inst
        inst.add_console(os.environ.get(LOG_LEVEL, DEFAULT_LOG_LEVEL))
        return inst

    def set_level(self, level: str | int) -> None:
        lvl = getattr(logging, str(level).upper(), level)
        self.logger.setLevel(lvl)
        for h in self.logger.handlers:
            h.setLevel(logging.DEBUG if isinstance(h, logging.FileHandler) else lvl)

    def add_console(self, level: str | int = "INFO") -> None:
        if not any(
            isinstance(h, logging.StreamHandler) and getattr(h, "_app_console", False)
            for h in self.logger.handlers
        ):
            ch = logging.StreamHandler(stream=sys.stdout)
            ch.setFormatter(self._base_fmt)
            ch.setLevel(getattr(logging, str(level).upper(), level))
            ch._app_console = True
            self.logger.addHandler(ch)

    # ---------- internals ----------
    def _add_file_handlers(self) -> None:
        """
        Two file handlers:
          • append to the per-run file
          • overwrite 'latest.log'
        """
        for path, mode in [(self.file_path, "a"), (self.latest_path, "w")]:
            fh = logging.FileHandler(path, encoding="utf-8", mode=mode)
            fh.setFormatter(self._base_fmt)
            fh.setLevel(logging.DEBUG)  # capture everything to disk
            fh._app_file = True  # marker to avoid duplicates
            self.logger.addHandler(fh)

    def _prune_old_logs(self) -> None:
        """
        Keep the newest `keep` matching '{APP_NAME}_*.log' in the same directory.
        """
        if self.keep <= 0:
            return
        pattern = f"{self.app_name}_*.log"
        files = sorted(self.log_dir.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)
        for old in files[self.keep :]:
            # noinspection PyBroadException
            try:
                old.unlink(missing_ok=True)
            except Exception:
                # Best-effort; ignore locked files
                pass

    # Delegate logging methods to the wrapped logger
    def debug(self, msg, *args, **kwargs):
        self.logger.debug(msg, *args, **kwargs)

    def info(self, msg, *args, **kwargs):
        self.logger.info(msg, *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        self.logger.warning(msg, *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        self.logger.error(msg, *args, **kwargs)

    def critical(self, msg, *args, **kwargs):
        self.logger.critical(msg, *args, **kwargs)

    def exception(self, msg, *args, **kwargs):
        self.logger.exception(msg, *args, **kwargs)

    def log(self, level, msg, *args, **kwargs):
        self.logger.log(level, msg, *args, **kwargs)
