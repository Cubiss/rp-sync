from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple
from urllib.parse import urlparse
import traceback

from .logging_utils import Logger
from .models import RootConfig, ServiceConfig, ReverseProxyRule, Protocol
from .dns_updater import DnsUpdater
from .step_ca import StepCAClient
from .dsm import DsmSession, DsmCertificateClient, DsmReverseProxyClient


@dataclass
class SyncContext:
    cfg: RootConfig
    dsm_session: DsmSession
    dns_updater: DnsUpdater
    step_ca: StepCAClient
    dsm_certs: DsmCertificateClient
    dsm_rp: DsmReverseProxyClient
    services: List[ServiceConfig]


class SyncOrchestrator:
    def __init__(self, ctx: SyncContext, logger: Logger):
        self.ctx = ctx
        self.logger = logger

    def sync(self) -> List[str]:
        errors: List[str] = []

        for svc in self.ctx.services:
            try:
                self._sync_service(svc)
            except Exception:
                errors.append(svc.name)
                tb = traceback.format_exc()
                self.logger.error(f"\n[orchestrator] Failed to sync service '{svc.name}':\n{tb}")

        if errors:
            self.logger.error("\nSome services failed to sync: " + ", ".join(sorted(errors)))
            return errors

        self.logger.info("\nAll services processed successfully.")
        return errors

    def _sync_service(self, svc: ServiceConfig) -> None:
        # TODO: Improve behavior of aliases. I already have a simple http->https redirect service, use it to redirect aliases to main hostname (instead of duplicate reverse proxy rules)
        hostnames: List[str] = [svc.host, *svc.aliases]

        self.logger.info(f"\n=== Service: {svc.name} ===")
        self.logger.info(f"Hosts: {', '.join(hostnames)}")
        self.logger.info(f"Backend: {svc.dest_url}")

        if svc.dns_a:
            for hostname in hostnames:
                self.ctx.dns_updater.ensure_a_record(hostname, svc.dns_a)

        protocol, host, port = parse_dest_url(svc.dest_url)
        for hostname in hostnames:
            rp_rule = ReverseProxyRule(
                description=f"{svc.name} ({hostname})",
                src_host=hostname,
                src_port=svc.source_port,
                src_protocol=svc.source_protocol,
                dst_host=host,
                dst_port=port,
                dst_protocol=protocol,
            )
            self.ctx.dsm_rp.upsert_rule(rp_rule)

        if self.ctx.step_ca.enabled and svc.source_protocol == "https":
            cn = svc.host
            sans = hostnames
            dsm_cert_name = f"rp-sync-{svc.name}"

            existing = self.ctx.dsm_certs.find_certificate_by_name(dsm_cert_name)
            renew_window_h = int(getattr(self.ctx.cfg.certs, "renew_before_hours", 168))

            if existing:
                assigned = self.ctx.dsm_certs.is_assigned_to_reverse_proxy_hosts(
                    dsm_cert_name, hostnames=hostnames
                )
                expiring = self.ctx.dsm_certs.expires_within_hours(existing, hours=renew_window_h)

                if (not expiring) and assigned:
                    self.logger.info(
                        f"[TLS] '{dsm_cert_name}' already valid and assigned to all hosts; "
                        f"skipping issuance/import"
                    )
                    return

                if (not expiring) and (not assigned):
                    self.logger.info(
                        f"[TLS] '{dsm_cert_name}' valid but not assigned everywhere; "
                        f"assigning only (no re-issue)"
                    )
                    self.ctx.dsm_certs.assign_to_reverse_proxy_hosts(
                        dsm_cert_name,
                        hostnames=hostnames,
                    )
                    return

                self.logger.info(
                    f"[TLS] '{dsm_cert_name}' exists but expiring soon (<= {renew_window_h}h); renewing"
                )

            tmp_dir = Path("/tmp")
            cert_path = tmp_dir / f"{svc.name}.crt"
            key_path = tmp_dir / f"{svc.name}.key"

            self.ctx.step_ca.obtain_certificate(cn, sans, cert_path, key_path)

            cert_pem = cert_path.read_text(encoding="utf-8")
            key_pem = key_path.read_text(encoding="utf-8")

            self.ctx.dsm_certs.import_or_replace_certificate(dsm_cert_name, cert_pem, key_pem)

            self.ctx.dsm_certs.assign_to_reverse_proxy_hosts(
                dsm_cert_name,
                hostnames=hostnames,
            )


def parse_dest_url(url: str) -> Tuple[Protocol, str, int]:
    p = urlparse(url)
    # TODO: guard to ensure Protocol (Literal["http", "https"])
    protocol: Protocol = p.scheme or "http"
    host = p.hostname or "localhost"

    if p.port is not None:
        port = p.port
    else:
        port = 443 if protocol == "https" else 80

    return protocol, host, port
