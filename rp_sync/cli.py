from __future__ import annotations

from .config import load_config
from .dns_updater import DnsUpdater
from .logging_utils import Logger
from .step_ca import StepCAClient
from .dsm import DsmSession, DsmCertificateClient, _read_secret, DsmReverseProxyClient
from .orchestrator import SyncContext, SyncOrchestrator


def main() -> None:
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

    SyncOrchestrator(ctx, logger).sync()
