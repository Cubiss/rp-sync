from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import traceback

from .logging_utils import Logger
from .models import AccessControlProfile, RootConfig, ServiceConfig, Protocol
from .dns_updater import DnsUpdater
from .step_ca import StepCAClient, read_cert_expiry
from .nginx_writer import NginxConfigWriter
from urllib.parse import urlparse


@dataclass
class SyncContext:
    cfg: RootConfig
    dns_updater: DnsUpdater
    step_ca: StepCAClient
    nginx_writer: NginxConfigWriter
    services: List[ServiceConfig]


class SyncOrchestrator:
    def __init__(self, ctx: SyncContext, logger: Logger):
        self.ctx = ctx
        self.logger = logger

    def sync(self) -> Tuple[List[str], Optional[datetime]]:
        errors: List[str] = []
        next_checks: List[datetime] = []

        profiles: Dict[str, AccessControlProfile] = {
            p.name: p for p in self.ctx.cfg.access_control_profiles
        }

        for svc in self.ctx.services:
            try:
                next_check = self._sync_service(svc)
                if next_check is not None:
                    next_checks.append(next_check)
            except Exception:
                errors.append(svc.name)
                tb = traceback.format_exc()
                self.logger.error(f"\n[orchestrator] Failed to sync service '{svc.name}':\n{tb}")

        # Write nginx config after all certs are in place
        try:
            self.ctx.nginx_writer.write(
                self.ctx.services,
                profiles,
                self.ctx.cfg.default_access_control_profile,
            )
            self.logger.info(f"[nginx] Config written to {self.ctx.cfg.nginx.conf_dir}")
        except Exception:
            tb = traceback.format_exc()
            self.logger.error("\n[orchestrator] Failed to write nginx config:\n" + tb)
            errors.append("__nginx_config__")

        earliest = min(next_checks) if next_checks else None

        if errors:
            self.logger.error("\nSome services failed to sync: " + ", ".join(sorted(errors)))
            return errors, earliest

        self.logger.info("\nAll services processed successfully.")
        return errors, earliest

    def _sync_service(self, svc: ServiceConfig) -> Optional[datetime]:
        all_hosts: List[str] = [svc.host, *svc.aliases]

        self.logger.info(f"\n=== Service: {svc.name} ===")
        if svc.loaded_from:
            self.logger.info(f"Config: {svc.loaded_from}")
        self.logger.info(f"Hosts: {', '.join(all_hosts)}")
        self.logger.info(f"Backend: {svc.dest_url}")

        if svc.dns_a:
            for hostname in all_hosts:
                self.ctx.dns_updater.ensure_a_record(hostname, svc.dns_a)

        if not self.ctx.step_ca.enabled or svc.source_protocol != "https":
            return None

        cert_dir = Path(self.ctx.cfg.nginx.certs_dir) / svc.name
        cert_path = cert_dir / "cert.pem"
        key_path = cert_dir / "key.pem"
        renew_before_h = int(self.ctx.cfg.certs.renew_before_hours)

        if cert_path.exists():
            expiry = read_cert_expiry(cert_path)
            if expiry is not None:
                now = datetime.now(timezone.utc)
                renew_after = expiry - timedelta(hours=renew_before_h)
                if now < renew_after:
                    self.logger.info(
                        f"[TLS] '{svc.name}' cert valid until {expiry}; "
                        f"next renewal at {renew_after}"
                    )
                    return renew_after
                self.logger.info(
                    f"[TLS] '{svc.name}' cert expiring soon ({expiry}); renewing"
                )
            else:
                self.logger.warning(f"[TLS] Could not read expiry for '{svc.name}'; renewing")
        else:
            self.logger.info(f"[TLS] No cert found for '{svc.name}'; issuing")

        cert_dir.mkdir(parents=True, exist_ok=True)
        self.ctx.step_ca.obtain_certificate(svc.host, all_hosts, cert_path, key_path)

        expiry = read_cert_expiry(cert_path)
        return (expiry - timedelta(hours=renew_before_h)) if expiry else None


def parse_dest_url(url: str) -> Tuple[Protocol, str, int]:
    p = urlparse(url)
    scheme = (p.scheme or "http").lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"Unsupported dest_url scheme: {scheme!r} in {url!r}")
    protocol: Protocol = scheme
    host = p.hostname or "localhost"

    if p.port is not None:
        port = p.port
    else:
        port = 443 if protocol == "https" else 80

    return protocol, host, port
