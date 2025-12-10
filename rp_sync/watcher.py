from __future__ import annotations

import os
import time
import traceback
from typing import Optional
from .config import load_config
from .dns_updater import DnsUpdater
from .logging_utils import Logger
from .step_ca import StepCAClient
from .dsm import DsmSession, DsmCertificateClient, _read_secret, DsmReverseProxyClient
from .orchestrator import SyncContext, SyncOrchestrator


# Env vars / defaults
_CONFIG_ENV = "RP_SYNC_CONFIG_PATH"
_DEFAULT_CONFIG_PATH = "./config.yaml"

_HEALTH_ENV = "RP_SYNC_HEALTH_FILE"
_DEFAULT_HEALTH_PATH = "/tmp/rp-sync-health"

_POLL_ENV = "RP_SYNC_WATCH_INTERVAL_SEC"
_DEFAULT_POLL_SECONDS = 5.0


class Watcher:
    def __init__(self, logger: Logger):
        self.logger = logger

    def _get_config_path(self) -> str:
        return os.environ.get(_CONFIG_ENV, _DEFAULT_CONFIG_PATH)

    def _get_health_path(self) -> str:
        return os.environ.get(_HEALTH_ENV, _DEFAULT_HEALTH_PATH)

    def _write_health(self, ok: bool, error_text: Optional[str] = None) -> None:
        """
        Write a tiny status file the Docker healthcheck can read.

        Content:
          - "healthy"      (on success)
          - "unhealthy\n<last error snippet>" (on failure)
        """
        path = self._get_health_path()
        try:
            directory = os.path.dirname(path)
            if directory:
                os.makedirs(directory, exist_ok=True)
        except Exception:
            # If we can't create the dir, there's not much we can do.
            return

        try:
            with open(path, "w", encoding="utf-8") as f:
                if ok:
                    f.write("healthy\n")
                else:
                    f.write("unhealthy\n")
                    if error_text:
                        # Keep it short-ish so the file doesn't explode
                        f.write(error_text.strip()[:1000] + "\n")
        except Exception:
            # Don't crash the watcher just because health file failed
            pass

    def _get_mtime(self, path: str) -> Optional[float]:
        try:
            return os.path.getmtime(path)
        except FileNotFoundError:
            return None

    def watch(self) -> None:
        """
        Watch the config file for changes and run sync on change.

        Semantics:
          - On startup:
              * If config exists -> run sync once.
              * If missing/invalid -> mark unhealthy, keep polling.
          - On every mtime change:
              * Try sync; mark healthy on success, unhealthy on failure.
        """
        config_path = self._get_config_path()
        poll_seconds = float(os.environ.get(_POLL_ENV, str(_DEFAULT_POLL_SECONDS)))

        last_mtime: Optional[float] = None

        self.logger.info(f"[watcher] Watching config: {config_path}")
        self.logger.info(f"[watcher] Health file: {self._get_health_path()}")
        self.logger.info(f"[watcher] Poll interval: {poll_seconds}s")

        while True:
            mtime = self._get_mtime(config_path)

            if mtime is None:
                # Config file missing
                msg = f"Config file not found: {config_path}"
                self.logger.info(f"[watcher] {msg}")
                self._write_health(False, msg)
                time.sleep(poll_seconds)
                continue

            if last_mtime is None or mtime != last_mtime:
                # New or changed config
                last_mtime = mtime
                self.logger.info(f"[watcher] Detected config change, running sync...")

                try:
                    self.run_sync()
                except Exception:
                    tb = traceback.format_exc()
                    self.logger.error("[watcher] Sync failed:\n" + tb)
                    self._write_health(False, tb)
                else:
                    self.logger.info("[watcher] Sync succeeded")
                    self._write_health(True)

            time.sleep(poll_seconds)

    def run_sync(self) -> None:
        """
        Perform a single sync run using the current config.
        This is the core logic used both by the CLI and the file watcher.
        """
        cfg = load_config()

        logger = Logger.from_config(cfg.logging)

        # DSM login
        dsm_session = DsmSession(cfg.dsm, logger)
        username = _read_secret(cfg.dsm.username_file)
        password = _read_secret(cfg.dsm.password_file)
        dsm_session.login(username, password)

        dns_updater = DnsUpdater(cfg.dns, logger)
        step_ca = StepCAClient(cfg.certs, logger)
        dsm_certs = DsmCertificateClient(dsm_session, logger)
        dsm_rp = DsmReverseProxyClient(dsm_session, logger)

        ctx = SyncContext(
            cfg=cfg,
            dsm_session=dsm_session,
            dns_updater=dns_updater,
            step_ca=step_ca,
            dsm_certs=dsm_certs,
            dsm_rp=dsm_rp,
        )

        logger.info("Starting sync run")
        SyncOrchestrator(ctx, logger).sync()
        logger.info("Sync run completed successfully")
