from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple
from urllib.parse import urlparse

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


class SyncOrchestrator:
    def __init__(self, ctx: SyncContext):
        self.ctx = ctx

    def sync(self) -> None:
        for svc in self.ctx.cfg.services:
            self._sync_service(svc)
        print("\nAll services processed.")

    def _sync_service(self, svc: ServiceConfig) -> None:
        all_hosts: List[str] = [svc.host] + svc.aliases

        print(f"\n=== Service: {svc.name} ===")
        print(f"Hosts: {', '.join(all_hosts)}")
        print(f"Backend: {svc.dest_url}")

        # 1) DNS
        if svc.dns_a:
            for hostname in all_hosts:
                self.ctx.dns_updater.ensure_a_record(hostname, svc.dns_a)

        # 2) Reverse Proxy
        all_hosts = [svc.host, *svc.aliases]
        for hostname in all_hosts:
            protocol, host, port = parse_dest_url(svc.dest_url)
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

        # 3) TLS via step-ca + DSM certs
        if svc.tls and svc.tls.use_step_ca and self.ctx.step_ca.enabled:
            cn = svc.tls.common_name or svc.host
            sans = svc.tls.sans or all_hosts
            dsm_cert_name = svc.tls.dsm_cert_name or f"rp-sync-{svc.name}"

            tmp_dir = Path("/tmp")
            cert_path = tmp_dir / f"{svc.name}.crt"
            key_path = tmp_dir / f"{svc.name}.key"

            self.ctx.step_ca.obtain_certificate(cn, sans, cert_path, key_path)

            cert_pem = cert_path.read_text(encoding="utf-8")
            key_pem = key_path.read_text(encoding="utf-8")

            self.ctx.dsm_certs.import_or_replace_certificate(dsm_cert_name, cert_pem, key_pem)

            self.ctx.dsm_certs.assign_to_reverse_proxy_hosts(
                dsm_cert_name, hostnames=[svc.host] + svc.aliases
            )


def parse_dest_url(url: str) -> Tuple[Protocol, str, int]:
    p = urlparse(url)
    protocol: Protocol = p.scheme or "http"
    host = p.hostname or "localhost"

    if p.port is not None:
        port = p.port
    else:
        port = 443 if protocol == "https" else 80

    return protocol, host, port
