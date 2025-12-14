from __future__ import annotations

import logging

import os
import sys
import threading
import traceback
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
        log_dir: Optional[Path|str] = "./logs",
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

        if not self._has_app_file_handlers():
            self._add_file_handlers()

        self._prune_old_logs()

        self.logger.debug(f"Logging initialized -> {self.file_path}")

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


    def _has_app_file_handlers(self) -> bool:
        return any(
            isinstance(h, logging.FileHandler) and getattr(h, "_app_file", False)
            for h in self.logger.handlers
        )

    def _add_file_handlers(self) -> None:
        """
        Two file handlers:
          • append to the per-run file
          • overwrite 'latest.log'
        """
        for path, mode in [(self.file_path, "a"), (self.latest_path, "w")]:
            fh = logging.FileHandler(path, encoding="utf-8", mode=mode)
            fh.setFormatter(self._base_fmt)
            # TODO: Let's introduce latest.debug.log that will always capture DEBUG, make current/latest follow the configured log level
            fh.setLevel(logging.DEBUG)
            fh._app_file = True
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
            try:
                old.unlink(missing_ok=True)
            except Exception:
                pass

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

    def install_exception_logging(self: Logger) -> None:
        def _log(exc_type, exc, tb, where: str = "") -> None:
            # TODO: any other common "non-error" exceptions I might want to ignore?
            if exc_type in (KeyboardInterrupt, SystemExit):
                return

            log_exception = getattr(self, "exception", None)
            if callable(log_exception):
                log_exception(
                    f"Unhandled exception{where}",
                    exc_info=(exc_type, exc, tb),
                )
            else:
                formatted = "".join(traceback.format_exception(exc_type, exc, tb))

                # TODO: any reason to guard this given this class implements error?
                log_error = getattr(self, "error", None)
                if callable(log_error):
                    log_error(f"Unhandled exception{where}\n{formatted}")
                else:
                    sys.stderr.write(f"Unhandled exception{where}\n{formatted}\n")

        def _sys_excepthook(exc_type, exc, tb) -> None:
            _log(exc_type, exc, tb)
            sys.__excepthook__(exc_type, exc, tb)

        sys.excepthook = _sys_excepthook

        if hasattr(threading, "excepthook"):
            # TODO: Any reason to guard this given requires-python = ">=3.11"?
            default_thread_excepthook = getattr(threading, "__excepthook__", None)
            def _thread_excepthook(args) -> None:
                _log(
                    args.exc_type,
                    args.exc_value,
                    args.exc_traceback,
                    where=f" in thread {args.thread.name!r}",
                )
                if callable(default_thread_excepthook):
                    default_thread_excepthook(args)

            threading.excepthook = _thread_excepthook
