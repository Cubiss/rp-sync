from __future__ import annotations

import os
import signal
import threading
import traceback
from typing import Optional, Tuple, List

from .config import (
    load_root_config,
    HEALTH_ENV,
    DEFAULT_HEALTH_PATH,
    POLL_ENV,
    DEFAULT_POLL_SECONDS,
)
from .dns_updater import DnsUpdater
from .logging_utils import Logger
from .models import RootConfig
from .step_ca import StepCAClient
from .dsm import DsmSession, DsmCertificateClient, _read_secret, DsmReverseProxyClient
from .orchestrator import SyncContext
from .http_redirect_server import start_redirect_server, RedirectServer
from .service import get_services_path, load_services, SERVICE_FILE_SUFFIX
from .orchestrator import SyncOrchestrator


class Daemon:
    """Long-running rp-sync process.

    In this mode, rp-sync:
      - performs an initial sync
      - keeps running
      - polls service configuration and re-syncs on changes
      - (optionally) hosts a tiny HTTP->HTTPS redirect backend

    The "root" config (DSM/DNS/certs) is loaded once at startup and is not
    reloaded on changes.
    """

    def __init__(
        self,
        logger: Logger,
        core_config: RootConfig,
        dsm_session: DsmSession,
        dns_updater: DnsUpdater,
        step_ca: StepCAClient,
        dsm_certs: DsmCertificateClient,
        dsm_rp: DsmReverseProxyClient,
        daemon_mode: bool,
    ) -> None:
        self.logger = logger

        self.core_config = core_config

        self.ctx = SyncContext(
            cfg=core_config,
            dsm_session=dsm_session,
            dns_updater=dns_updater,
            step_ca=step_ca,
            dsm_certs=dsm_certs,
            dsm_rp=dsm_rp,
            services=[],
        )

        self._stop_event = threading.Event()
        self._redirect_server: RedirectServer | None = None
        self._register_signal_handlers()

        # Optionally start builtin HTTP->HTTPS redirect backend.
        hr = getattr(core_config, "http_redirect", None)
        if hr and hr.enabled and hr.builtin_backend.enabled:
            if not daemon_mode:
                raise RuntimeError(
                    "http_redirect.builtin_backend is enabled, but rp-sync is not running in daemon mode. "
                    "The builtin redirect backend must stay running to handle redirects. "
                    "Run `rp-sync daemon`, or disable builtin_backend and point backend_url to an external "
                    "redirect service."
                )
            self._redirect_server = start_redirect_server(logger, hr)

    # ----- static construction helpers ---------------------------------- #

    @staticmethod
    def _init_connectors(
        logger: Logger,
        cfg: RootConfig,
    ) -> tuple[DsmSession, DnsUpdater, StepCAClient, DsmCertificateClient, DsmReverseProxyClient]:
        """Initialize all external connectors from a *core* RootConfig."""
        dsm_session = DsmSession(cfg.dsm, logger)
        username = _read_secret(cfg.dsm.username_file)
        password = _read_secret(cfg.dsm.password_file)
        dsm_session.login(username, password)

        dns_updater = DnsUpdater(cfg.dns, logger)
        step_ca = StepCAClient(cfg.certs, logger)
        dsm_certs = DsmCertificateClient(dsm_session, logger)
        dsm_rp = DsmReverseProxyClient(dsm_session, logger)

        return dsm_session, dns_updater, step_ca, dsm_certs, dsm_rp

    @staticmethod
    def from_core_config(logger: Logger, core_config: RootConfig, daemon_mode: bool) -> "Daemon":
        """Build a Daemon from an already loaded root config."""
        dsm_session, dns_updater, step_ca, dsm_certs, dsm_rp = Daemon._init_connectors(logger, core_config)
        return Daemon(
            logger=logger,
            core_config=core_config,
            dsm_session=dsm_session,
            dns_updater=dns_updater,
            step_ca=step_ca,
            dsm_certs=dsm_certs,
            dsm_rp=dsm_rp,
            daemon_mode=daemon_mode,
        )

    @staticmethod
    def from_env(logger: Logger, daemon_mode: bool) -> "Daemon":
        core_cfg = load_root_config()
        return Daemon.from_core_config(logger, core_cfg, daemon_mode=daemon_mode)

    # ----- internals ----------------------------------------------------- #

    def _register_signal_handlers(self) -> None:
        signal.signal(signal.SIGTERM, self._handle_stop)
        signal.signal(signal.SIGINT, self._handle_stop)
        self.logger.debug(
            "[daemon] Registered signal handlers for SIGTERM and SIGINT (Docker stop and Ctrl+C)"
        )

    def _handle_stop(self, signum, frame) -> None:  # type: ignore[override]
        self._stop_event.set()
        if self._redirect_server is not None:
            try:
                self._redirect_server.stop(self.logger)
            except Exception as ex:
                self.logger.debug(ex)

    def _get_health_path(self) -> str:
        return os.environ.get(HEALTH_ENV, DEFAULT_HEALTH_PATH)

    def _write_health(self, ok: bool, error_text: Optional[str] = None) -> None:
        """Write a tiny status file for the Docker healthcheck."""
        path = self._get_health_path()
        self.logger.debug(f"Writing OK: {ok}, error_text{error_text} into {path}")
        try:
            directory = os.path.dirname(path)
            if directory:
                os.makedirs(directory, exist_ok=True)
        except Exception as ex:
            self.logger.debug(ex)
            return

        try:
            with open(path, "w", encoding="utf-8") as f:
                if ok:
                    f.write("healthy\n")
                else:
                    f.write("unhealthy\n")
                    if error_text:
                        f.write(error_text.strip()[:1000] + "\n")
        except Exception as ex:
            self.logger.debug(ex)
            pass

    def _get_services_mtime(self, services_path: str) -> Optional[float]:
        """Return a composite mtime representing all service config."""
        if os.path.isdir(services_path):
            try:
                mtimes = [os.path.getmtime(services_path)]
                with os.scandir(services_path) as it:
                    for entry in it:
                        if entry.is_file() and entry.name.endswith(SERVICE_FILE_SUFFIX):
                            mtimes.append(entry.stat().st_mtime)
                return max(mtimes) if mtimes else None
            except FileNotFoundError:
                return None

        try:
            return os.path.getmtime(services_path)
        except FileNotFoundError:
            return None

    # ----- public API ---------------------------------------------------- #

    def run(self) -> None:
        """Run forever: poll services config and sync on change."""
        services_path = get_services_path()
        poll_seconds = float(os.environ.get(POLL_ENV, str(DEFAULT_POLL_SECONDS)))

        last_services_mtime: Optional[float] = None

        self.logger.info(f"[daemon] Services path:  {services_path}")
        self.logger.info(f"[daemon] Health file:    {self._get_health_path()}")
        self.logger.info(f"[daemon] Poll interval:  {poll_seconds}s")

        # Run at least once, even if the files already exist
        force_first_run = True

        while not self._stop_event.is_set():
            mtime = self._get_services_mtime(services_path)

            if mtime is None:
                msg = f"Service config not found: {services_path}"
                self.logger.info(f"[daemon] {msg}")
                self._write_health(False, msg)
            else:
                if force_first_run or last_services_mtime is None or mtime != last_services_mtime:
                    force_first_run = False
                    last_services_mtime = mtime
                    self.logger.info("[daemon] Detected services change, running sync...")
                    try:
                        ok, failed_services = self.sync_once()
                    except Exception:
                        tb = traceback.format_exc()
                        self.logger.error("[daemon] Sync failed:\n" + tb)
                        self._write_health(False, tb)
                    else:
                        if ok:
                            self.logger.info("[daemon] Sync succeeded")
                            self._write_health(True)
                        else:
                            if failed_services:
                                services_str = ", ".join(sorted(failed_services))
                                msg = "Sync completed with errors for services: " + services_str
                            else:
                                msg = "Sync completed with errors (some services failed)"

                            self.logger.warning("[daemon] " + msg)
                            self._write_health(False, msg)

            self._stop_event.wait(poll_seconds)

        self.logger.info("[daemon] Stop signal received – shutting down gracefully")

        if self._redirect_server:
            self._redirect_server.stop(self.logger)

    def sync_once(self) -> Tuple[bool, List[str]]:
        """Perform a single sync run using the current services view."""
        self.ctx.services = load_services()

        self.logger.info("Starting sync run")
        ok, failed_services = SyncOrchestrator(self.ctx, self.logger).sync()

        if ok:
            self.logger.info("Sync run completed successfully")
        else:
            if failed_services:
                services_str = ", ".join(sorted(failed_services))
                self.logger.warning("Sync run completed with errors for services: " + services_str)
            else:
                self.logger.warning("Sync run completed with errors (some services failed)")

        return ok, failed_services
