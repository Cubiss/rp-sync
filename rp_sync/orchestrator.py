from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import traceback

from typing import Protocol as TypingProtocol

from .logging_utils import Logger
from .models import AccessControlProfile, RootConfig, ServiceConfig, Protocol
from .dns_updater import DnsUpdater
from .step_ca import read_cert_expiry, cert_covers_hosts
from .nginx_writer import NginxConfigWriter
from urllib.parse import urlparse


class CertProvider(TypingProtocol):
    @property
    def enabled(self) -> bool: ...

    @property
    def name(self) -> Optional[str]: ...

    def group_hosts(self, host: str, aliases: List[str]) -> list: ...

    def filter_sans(self, common_name: str, sans: List[str]) -> List[str]: ...

    def renew_before_hours(self, hostname: str) -> int: ...

    def obtain_certificate(
        self, common_name: str, sans: List[str], out_crt: Path, out_key: Path
    ) -> None: ...


@dataclass
class SyncContext:
    cfg: RootConfig
    dns_updater: DnsUpdater
    cert_provider: CertProvider
    nginx_writer: NginxConfigWriter
    services: List[ServiceConfig]


class SyncOrchestrator:
    def __init__(self, ctx: SyncContext, logger: Logger):
        self.ctx = ctx
        self.logger = logger

    # cert_map type: {hostname: (nginx_cert_path, nginx_key_path)}
    _CertMap = Dict[str, Tuple[str, str]]

    def sync(self) -> Tuple[List[str], Optional[datetime]]:
        errors: List[str] = []
        next_checks: List[datetime] = []

        profiles: Dict[str, AccessControlProfile] = {
            p.name: p for p in self.ctx.cfg.access_control_profiles
        }
        default_profile = self.ctx.cfg.default_access_control_profile

        # Pre-issuance write: HTTPS blocks only for certs that already exist.
        # This ensures ACME challenge locations are served on port 80 before
        # we ask Let's Encrypt to validate.
        pre_maps = {svc.name: self._existing_cert_map(svc) for svc in self.ctx.services}
        self.ctx.nginx_writer.write(self.ctx.services, profiles, default_profile, pre_maps)

        post_maps: Dict[str, "SyncOrchestrator._CertMap"] = dict(pre_maps)
        for svc in self.ctx.services:
            try:
                next_check, cert_map = self._sync_service(svc)
                post_maps[svc.name] = cert_map
                if next_check is not None:
                    next_checks.append(next_check)
            except Exception:
                errors.append(svc.name)
                tb = traceback.format_exc()
                self.logger.error(f"\n[orchestrator] Failed to sync service '{svc.name}':\n{tb}")

        # Post-issuance write: all certs now in place.
        try:
            self.ctx.nginx_writer.write(self.ctx.services, profiles, default_profile, post_maps)
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

    def _group_paths(
        self, svc: ServiceConfig, group_idx: int, provider_name: Optional[str] = None
    ) -> Tuple[Path, Path, str, str]:
        """Return (write_cert, write_key, nginx_cert, nginx_key) for one cert group."""
        write_base = Path(self.ctx.cfg.nginx.certs_write_dir) / svc.name
        nginx_base = self.ctx.cfg.nginx.certs_nginx_dir + "/" + svc.name
        if group_idx == 0:
            return (
                write_base / "cert.pem",
                write_base / "key.pem",
                f"{nginx_base}/cert.pem",
                f"{nginx_base}/key.pem",
            )
        sub = provider_name or f"group-{group_idx}"
        return (
            write_base / sub / "cert.pem",
            write_base / sub / "key.pem",
            f"{nginx_base}/{sub}/cert.pem",
            f"{nginx_base}/{sub}/key.pem",
        )

    def _existing_cert_map(self, svc: ServiceConfig) -> "_CertMap":
        """Build cert_map from cert files that already exist on disk (pre-issuance)."""
        cert_map: SyncOrchestrator._CertMap = {}
        if svc.source_protocol != "https" or not self.ctx.cert_provider.enabled:
            return cert_map
        for i, (provider, hosts) in enumerate(
            self.ctx.cert_provider.group_hosts(svc.host, svc.aliases)
        ):
            if not provider.enabled:
                continue
            write_cert, _, nginx_cert, nginx_key = self._group_paths(svc, i, provider.name)
            if write_cert.exists():
                for h in hosts:
                    cert_map[h] = (nginx_cert, nginx_key)
        return cert_map

    def _sync_service(self, svc: ServiceConfig) -> Tuple[Optional[datetime], "_CertMap"]:
        all_hosts: List[str] = [svc.host, *svc.aliases]

        self.logger.info(f"\n=== Service: {svc.name} ===")
        if svc.loaded_from:
            self.logger.info(f"Config: {svc.loaded_from}")
        self.logger.info(f"Hosts: {', '.join(all_hosts)}")
        self.logger.info(f"Backend: {svc.dest_url}")

        if svc.dns_a:
            for hostname in all_hosts:
                self.ctx.dns_updater.ensure_a_record(hostname, svc.dns_a)

        cert_map: SyncOrchestrator._CertMap = {}
        if not self.ctx.cert_provider.enabled or svc.source_protocol != "https":
            return None, cert_map

        groups = self.ctx.cert_provider.group_hosts(svc.host, svc.aliases)
        next_checks: List[datetime] = []

        for i, (provider, hosts) in enumerate(groups):
            if not provider.enabled:
                continue

            write_cert, write_key, nginx_cert, nginx_key = self._group_paths(svc, i, provider.name)
            common_name = svc.host if i == 0 else hosts[0]
            effective = provider.filter_sans(common_name, hosts)
            renew_before_h = provider.renew_before_hours()

            next_check = self._ensure_cert(
                provider, common_name, effective, write_cert, write_key, renew_before_h
            )
            if next_check is not None:
                next_checks.append(next_check)

            if write_cert.exists():
                for h in hosts:
                    cert_map[h] = (nginx_cert, nginx_key)

        earliest = min(next_checks) if next_checks else None
        return earliest, cert_map

    def _ensure_cert(
        self,
        provider,
        common_name: str,
        effective_hosts: List[str],
        cert_path: Path,
        key_path: Path,
        renew_before_h: int,
    ) -> Optional[datetime]:
        if cert_path.exists():
            expiry = read_cert_expiry(cert_path)
            if expiry is not None:
                now = datetime.now(timezone.utc)
                renew_after = expiry - timedelta(hours=renew_before_h)
                if now < renew_after:
                    if cert_covers_hosts(cert_path, effective_hosts):
                        self.logger.info(
                            f"[TLS] '{common_name}' cert valid until {expiry}; "
                            f"next renewal at {renew_after}"
                        )
                        return renew_after
                    self.logger.info(
                        f"[TLS] '{common_name}' cert SANs do not cover all hosts; renewing"
                    )
                else:
                    self.logger.info(
                        f"[TLS] '{common_name}' cert expiring soon ({expiry}); renewing"
                    )
            else:
                self.logger.warning(f"[TLS] Could not read expiry for '{common_name}'; renewing")
        else:
            self.logger.info(f"[TLS] No cert found for '{common_name}'; issuing")

        cert_path.parent.mkdir(parents=True, exist_ok=True)
        provider.obtain_certificate(common_name, effective_hosts, cert_path, key_path)

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
