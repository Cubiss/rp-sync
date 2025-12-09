from __future__ import annotations

from .config import load_config
from .dns_updater import DnsUpdater
from .step_ca import StepCAClient
from .dsm import DsmSession, DsmCertificateClient, _read_secret, DsmReverseProxyClient
from .orchestrator import SyncContext, SyncOrchestrator


def main() -> None:
    cfg = load_config()

    # DSM login
    dsm_session = DsmSession(cfg.dsm)
    username = _read_secret(cfg.dsm.username_file)
    password = _read_secret(cfg.dsm.password_file)
    dsm_session.login(username, password)

    dns_updater = DnsUpdater(cfg.dns)
    step_ca = StepCAClient(cfg.certs)
    dsm_certs = DsmCertificateClient(dsm_session)
    dsm_rp = DsmReverseProxyClient(dsm_session)

    ctx = SyncContext(
        cfg=cfg,
        dsm_session=dsm_session,
        dns_updater=dns_updater,
        step_ca=step_ca,
        dsm_certs=dsm_certs,
        dsm_rp=dsm_rp,
    )

    SyncOrchestrator(ctx).sync()
