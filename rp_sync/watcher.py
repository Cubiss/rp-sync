from __future__ import annotations

import os
import signal
import threading
import traceback
from types import FrameType
from typing import Optional, Tuple, List, Dict

from .config import (
    load_root_config,
    HEALTH_ENV,
    DEFAULT_HEALTH_PATH,
    POLL_ENV,
    DEFAULT_POLL_SECONDS,
)
from .dns_updater import DnsUpdater
from .logging_utils import Logger
from .models import RootConfig, ServiceConfig
from .step_ca import StepCAClient
from .dsm import DsmSession, DsmCertificateClient, _read_secret, DsmReverseProxyClient
from .orchestrator import SyncContext, SyncOrchestrator
from .service import (
    get_services_path,
    load_services,
    SERVICE_FILE_SUFFIX,
)


class Watcher:
    """Watch only service configuration and trigger syncs.

    The "root" config (DSM/DNS/certs) is loaded once up-front and is not
    reloaded on changes. If you change those, restart the process/container.

    All external connectors are mandatory constructor parameters. Use
    `Watcher.from_env(logger)` as the default entrypoint.
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
        self._register_signal_handlers()

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
    def from_core_config(logger: Logger, core_config: RootConfig) -> "Watcher":
        """Build a Watcher from an already loaded root config."""
        dsm_session, dns_updater, step_ca, dsm_certs, dsm_rp = Watcher._init_connectors(
            logger, core_config
        )
        return Watcher(
            logger=logger,
            core_config=core_config,
            dsm_session=dsm_session,
            dns_updater=dns_updater,
            step_ca=step_ca,
            dsm_certs=dsm_certs,
            dsm_rp=dsm_rp,
        )

    @staticmethod
    def from_env(logger: Logger) -> "Watcher":
        core_cfg = load_root_config()
        return Watcher.from_core_config(logger, core_cfg)

    def _register_signal_handlers(self) -> None:
        signal.signal(signal.SIGTERM, self._handle_stop)
        signal.signal(signal.SIGINT, self._handle_stop)
        self.logger.debug(
            "[watcher] Registered signal handlers for SIGTERM and SIGINT " "(Docker stop and Ctrl+C)"
        )

    def _handle_stop(self, signum: int, frame: FrameType | None) -> None:
        self._stop_event.set()

    def _get_health_path(self) -> str:
        return os.environ.get(HEALTH_ENV, DEFAULT_HEALTH_PATH)

    def _write_health(self, ok: bool, error_text: Optional[str] = None) -> None:
        """Write a tiny status file for the Docker healthcheck."""
        path = self._get_health_path()
        self.logger.debug(f'Writing OK: {ok}, error_text{error_text} into {path}')
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
        """Return a composite mtime representing all service config.

        - If *services_path* is a file, return its mtime.
        - If it's a directory, return max(mtime(directory), mtimes of all
          *.service files inside).
        """
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

    def _list_service_files(self, services_path: str) -> List[str]:
        """Return an ordered list of service config files.

        - If *services_path* is a directory, returns all '*.service' files inside.
        - If it's a file, returns just that file.
        """
        if os.path.isdir(services_path):
            try:
                with os.scandir(services_path) as it:
                    files = [
                        e.path
                        for e in it
                        if e.is_file() and e.name.endswith(SERVICE_FILE_SUFFIX)
                    ]
                return sorted(files)
            except FileNotFoundError:
                return []

        if os.path.isfile(services_path):
            return [services_path]

        return []

    def _get_service_file_state(self, services_path: str) -> Dict[str, float]:
        """Map each service file path -> mtime (seconds)."""
        state: Dict[str, float] = {}
        for path in self._list_service_files(services_path):
            try:
                state[path] = os.path.getmtime(path)
            except FileNotFoundError:
                continue
        return state

    def _load_services_from_files(self, files: List[str]) -> List[ServiceConfig]:
        """Load + merge services from a set of service config files.

        If the same service name appears multiple times, the last occurrence wins
        (deterministic because *files* is expected to be sorted).
        """
        services_by_name: Dict[str, ServiceConfig] = {}
        for fpath in files:
            for svc in load_services(fpath):
                services_by_name[svc.name] = svc
        return list(services_by_name.values())

    def _handle_no_service_files(
        self,
        services_path: str,
        force_first_run: bool,
    ) -> tuple[bool, Dict[str, float]]:
        if os.path.isdir(services_path):
            msg = f"No '{SERVICE_FILE_SUFFIX}' files found in: {services_path}"
            self.logger.info(f"[watcher] {msg}")
            self._write_health(True)
            return False, {}

        msg = f"Service config not found: {services_path}"
        self.logger.info(f"[watcher] {msg}")
        self._write_health(False, msg)
        return force_first_run, {}

    def _plan_sync(
        self,
        changed_files: List[str],
        removed_files: List[str],
    ) -> tuple[Optional[List[ServiceConfig]], str]:
        if removed_files:
            removed = ", ".join(os.path.basename(p) for p in removed_files)
            self.logger.warning(f"[watcher] Service file(s) removed ({removed}); running full sync")
            return None, "full (file removal)"

        touched = ", ".join(os.path.basename(p) for p in changed_files)
        self.logger.info(f"[watcher] Detected change in: {touched}; running incremental sync")
        services = self._load_services_from_files(changed_files)
        return services, f"incremental ({len(changed_files)} file(s))"

    def _execute_sync(self, services: Optional[List[ServiceConfig]], source: str) -> None:
        try:
            failed_services = self.run_sync(services=services, source=source)
        except Exception:
            tb = traceback.format_exc()
            self.logger.error("[watcher] Sync failed:\n" + tb)
            self._write_health(False, tb)
            return

        if not failed_services:
            self.logger.info("[watcher] Sync succeeded")
            self._write_health(True)
            return
        else:
            services_str = ", ".join(sorted(failed_services))
            msg = "Sync completed with errors for services: " + services_str

        self.logger.warning("[watcher] " + msg)
        self._write_health(False, msg)

    def watch(self) -> None:
        """Watch only the service configuration and run syncs on change.

        Root config is NOT watched. Changing DSM/DNS/certs => restart.
        """
        services_path = get_services_path()
        poll_seconds = float(os.environ.get(POLL_ENV, str(DEFAULT_POLL_SECONDS)))

        last_state: Dict[str, float] = {}

        self.logger.info(f"[watcher] Services path:  {services_path}")
        self.logger.info(f"[watcher] Health file:    {self._get_health_path()}")
        self.logger.info(f"[watcher] Poll interval:  {poll_seconds}s")

        force_first_run = True

        while not self._stop_event.is_set():
            state = self._get_service_file_state(services_path)

            if not state:
                force_first_run, last_state = self._handle_no_service_files(
                    services_path,
                    force_first_run,
                )
            else:
                changed_files = sorted(
                    [p for p, mt in state.items() if force_first_run or last_state.get(p) != mt]
                )
                removed_files = sorted([p for p in last_state.keys() if p not in state])

                if force_first_run or changed_files or removed_files:
                    force_first_run = False
                    last_state = state

                    run_services, source = self._plan_sync(changed_files, removed_files)
                    self._execute_sync(run_services, source)

            self._stop_event.wait(poll_seconds)

        self.logger.info("[watcher] Stop signal received – shutting down gracefully")

    def run_sync(
        self,
        services: Optional[List[ServiceConfig]] = None,
        source: str = "full",
    ) -> List[str]:
        # TODO: Analyze the need for duplicate of Watcher._execute_sync / Watcher.run_sync / SyncOrchestrator.sync and their logging.

        """Perform a single sync run using the current services view.

        - If *services* is None, reloads all services from the service path.
        - If *services* is provided, syncs only those services.
        - Reuses the already initialized connectors.

        Returns:
            (ok, failed_services)
        """
        if services is None:
            self.ctx.services = load_services()
        else:
            self.ctx.services = services

        self.logger.info(f"Starting sync run [{source}] ({len(self.ctx.services)} service(s))")
        failed_services = SyncOrchestrator(self.ctx, self.logger).sync()

        if not failed_services:
            self.logger.info("Sync run completed successfully")
        else:
            services_str = ", ".join(sorted(failed_services))
            self.logger.warning("Sync run completed with errors for services: " + services_str)

        return failed_services
