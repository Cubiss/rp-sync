from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Tuple

from dns import name as dnsname

from .acme_client import AcmeClient
from .logging_utils import Logger
from .models import CertsConfig, NginxConfig
from .step_ca import StepCAClient


class CertDispatcher:
    """Routes certificate requests to the appropriate provider based on hostname zone."""

    def __init__(self, zones: List[CertsConfig], nginx_cfg: NginxConfig, logger: Logger):
        # Build list of (zone_name_or_None, provider) sorted most-specific first
        self._entries: List[Tuple[Optional[dnsname.Name], object]] = []
        for cfg in zones:
            zone_name = dnsname.from_text(cfg.zone) if cfg.zone else None
            if cfg.provider == "letsencrypt":
                provider = AcmeClient(cfg, nginx_cfg, logger)
            else:
                provider = StepCAClient(cfg, logger)
            self._entries.append((zone_name, provider))

    @property
    def enabled(self) -> bool:
        return any(p.enabled for _, p in self._entries)

    @property
    def name(self) -> Optional[str]:
        return None

    def _select(self, hostname: str) -> object:
        fqdn = dnsname.from_text(hostname)
        best_len = -1
        best_provider = None
        default_provider = None

        for zone_name, provider in self._entries:
            if zone_name is None:
                if default_provider is None:
                    default_provider = provider
            elif fqdn.is_subdomain(zone_name):
                if len(zone_name.labels) > best_len:
                    best_len = len(zone_name.labels)
                    best_provider = provider

        return best_provider or default_provider

    def group_hosts(self, host: str, aliases: List[str]) -> list:
        """
        Split host+aliases into groups by matched provider.
        The first group always contains *host*. Returns [(provider, [hosts]), ...].
        """
        groups: dict = {}   # id(provider) → (provider, [hosts])
        order: list = []
        for h in [host] + aliases:
            p = self._select(h)
            pid = id(p)
            if pid not in groups:
                groups[pid] = (p, [])
                order.append(pid)
            groups[pid][1].append(h)
        return [groups[pid] for pid in order]

    def filter_sans(self, common_name: str, sans: List[str]) -> List[str]:
        provider = self._select(common_name)
        if provider is None:
            return sans
        return provider.filter_sans(common_name, sans)

    def renew_before_hours(self, hostname: str) -> int:
        provider = self._select(hostname)
        if provider is None:
            return 168
        return provider.renew_before_hours()

    def obtain_certificate(
        self, common_name: str, sans: List[str], out_crt: Path, out_key: Path
    ) -> None:
        provider = self._select(common_name)
        if provider is None:
            raise RuntimeError(
                f"[certs] No cert provider configured for hostname '{common_name}'"
            )
        provider.obtain_certificate(common_name, sans, out_crt, out_key)
