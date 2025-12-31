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
from .redirect_backend import RedirectBackend


@dataclass
class SyncContext:
    cfg: RootConfig
    dsm_session: DsmSession
    dns_updater: DnsUpdater
    step_ca: StepCAClient
    dsm_certs: DsmCertificateClient
    dsm_rp: DsmReverseProxyClient
    services: List[ServiceConfig]
    redirect_backend: RedirectBackend


class SyncOrchestrator:
    def __init__(self, ctx: SyncContext, logger: Logger):
        self.ctx = ctx
        self.logger = logger

    def sync(self) -> List[str]:
        errors: List[str] = []

        # 0) Optional: global HTTP->HTTPS redirect rules
        try:
            self._sync_http_redirect()
        except Exception:
            tb = traceback.format_exc()
            self.logger.error("\n[orchestrator] Failed to sync http_redirect:\n" + tb)
            return False, ["__http_redirect__"]

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

    def _sync_http_redirect(self) -> None:
        hr = getattr(self.ctx.cfg, "http_redirect", None)
        if not hr or not hr.enabled:
            return

        proto, host, port = parse_dest_url(hr.backend_url)
        if proto != "http":
            raise ValueError(
                f"http_redirect.backend_url must be http://..., got '{hr.backend_url}'"
            )

        if hr.mode == "catch_all":
            rp_rule = ReverseProxyRule(
                description="rp-sync http->https redirect (catch-all)",
                src_host="*",
                src_port=int(hr.source_port),
                src_protocol="http",
                dst_host=host,
                dst_port=int(port),
                dst_protocol="http",
            )
            self.ctx.dsm_rp.upsert_rule(rp_rule)
            self.logger.info(
                f"[http_redirect] Installed catch-all HTTP:{hr.source_port} redirect rule"
            )
            return

        if hr.mode == "per_host":
            # Create one http rule per HTTPS hostname. This allows opt-outs.
            for svc in self.ctx.services:
                if svc.source_protocol != "https":
                    continue
                if getattr(svc, "allow_http", False):
                    continue
                for hostname in [svc.host, *svc.aliases]:
                    rp_rule = ReverseProxyRule(
                        description=f"{svc.name} ({hostname}) http->https",
                        src_host=hostname,
                        src_port=int(hr.source_port),
                        src_protocol="http",
                        dst_host=host,
                        dst_port=int(port),
                        dst_protocol="http",
                    )
                    self.ctx.dsm_rp.upsert_rule(rp_rule)
            self.logger.info(
                f"[http_redirect] Installed per-host HTTP:{hr.source_port} redirect rules"
            )
            return

        raise ValueError(
            f"Unknown http_redirect.mode '{hr.mode}'. Expected 'catch_all' or 'per_host'."
        )

    def _sync_service(self, svc: ServiceConfig) -> None:
        canonical = svc.host
        aliases = list(svc.aliases)
        all_hosts: List[str] = [canonical, *aliases]

        self.logger.info(f"\n=== Service: {svc.name} ===")
        if svc.loaded_from:
            self.logger.info(f"Config: {svc.loaded_from}")
        self.logger.info(f"Hosts: {', '.join(all_hosts)}")
        self.logger.info(f"Backend: {svc.dest_url}")

        if svc.dns_a:
            for hostname in all_hosts:
                self.ctx.dns_updater.ensure_a_record(hostname, svc.dns_a)

        dst_protocol, dst_host, dst_port = parse_dest_url(svc.dest_url)

        self.ctx.dsm_rp.upsert_rule(
            ReverseProxyRule(
                description=f"{svc.name} ({canonical})",
                src_host=canonical,
                src_port=svc.source_port,
                src_protocol=svc.source_protocol,
                dst_host=dst_host,
                dst_port=dst_port,
                dst_protocol=dst_protocol,
            )
        )

        if self.ctx.redirect_backend.enabled:
            rb_host, rb_port, rb_proto = self.ctx.redirect_backend.destination()
            if aliases:
                for a in aliases:
                    self.ctx.dsm_rp.upsert_rule(
                        ReverseProxyRule(
                            description=f"{svc.name} (redirect {a} -> {canonical})",
                            src_host=a,
                            src_port=svc.source_port,
                            src_protocol=svc.source_protocol,
                            dst_host=rb_host,
                            dst_port=rb_port,
                            dst_protocol=rb_proto,
                        )
                    )

            if svc.source_protocol == "https":
                for h in all_hosts:
                    self.ctx.dsm_rp.upsert_rule(
                        ReverseProxyRule(
                            description=f"{svc.name} (redirect http -> https {h})",
                            src_host=h,
                            src_port=80,
                            src_protocol="http",
                            dst_host=rb_host,
                            dst_port=rb_port,
                            dst_protocol=rb_proto,
                        )
                    )

        if self.ctx.step_ca.enabled and svc.source_protocol == "https":
            cn = svc.host
            sans = all_hosts
            dsm_cert_name = f"rp-sync-{svc.name}"

            existing = self.ctx.dsm_certs.find_certificate_by_name(dsm_cert_name)
            renew_window_h = int(getattr(self.ctx.cfg.certs, "renew_before_hours", 168))

            if existing:
                assigned = self.ctx.dsm_certs.is_assigned_to_reverse_proxy_hosts(
                    dsm_cert_name, hostnames=all_hosts
                )
                expiring = self.ctx.dsm_certs.expires_within_hours(existing, hours=renew_window_h)

                if (not expiring) and assigned:
                    self.logger.info(
                        f"[TLS] '{dsm_cert_name}' already valid and assigned to all hosts; skipping issuance/import"
                    )
                    return

                if (not expiring) and (not assigned):
                    self.logger.info(
                        f"[TLS] '{dsm_cert_name}' valid but not assigned everywhere; assigning only (no re-issue)"
                    )
                    self.ctx.dsm_certs.assign_to_reverse_proxy_hosts(dsm_cert_name, hostnames=all_hosts)
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
            self.ctx.dsm_certs.assign_to_reverse_proxy_hosts(dsm_cert_name, hostnames=all_hosts)


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
