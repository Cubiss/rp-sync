from __future__ import annotations

import os
from typing import Any, Dict, List

import yaml

from .models import (
    RootConfig,
    DsmConfig,
    DnsConfig,
    CertsConfig,
    ServiceConfig,
    TLSServiceConfig,
)


def _load_yaml(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_config(path: str | None = None) -> RootConfig:
    config_path = path or os.environ.get("RP_SYNC_CONFIG_PATH", "./config.yaml")
    raw = _load_yaml(config_path)

    dsm_raw = raw["dsm"]
    dns_raw = raw["dns"]
    certs_raw = raw.get("certs", {})
    services_raw: List[Dict[str, Any]] = raw.get("services", [])

    dsm = DsmConfig(
        host=dsm_raw["host"],
        port=dsm_raw.get("port", 5001),
        https=dsm_raw.get("https", True),
        verify_ssl=dsm_raw.get("verify_ssl", True),
        username_file=dsm_raw["username_file"],
        password_file=dsm_raw["password_file"],
    )

    dns = DnsConfig(
        server=dns_raw["server"],
        zone=dns_raw["zone"],
        port=dns_raw.get("port", 53),
        tsig_key_file=dns_raw["tsig_key_file"],
    )

    certs = CertsConfig(
        enabled=certs_raw.get("enabled", False),
        ca_url=certs_raw.get("ca_url", ""),
        ca_fingerprint=certs_raw.get("ca_fingerprint", ""),
        provisioner=certs_raw.get("provisioner", ""),
        provisioner_password_file=certs_raw.get("provisioner_password_file"),
        default_ltl_hours=int(certs_raw.get("default_ltl_hours", 2160)),
        ca_root_file=certs_raw.get("ca_root_file"),
    )

    services: List[ServiceConfig] = []
    for s in services_raw:
        tls_raw = s.get("tls")
        tls = None
        if tls_raw:
            tls = TLSServiceConfig(
                use_step_ca=tls_raw.get("use_step_ca", False),
                common_name=tls_raw.get("common_name"),
                sans=tls_raw.get("sans", []),
                dsm_cert_name=tls_raw.get("dsm_cert_name"),
            )

        svc = ServiceConfig(
            name=s["name"],
            host=s["host"],
            dest_url=s["dest_url"],
            source_port=int(s["source_port"]),
            source_protocol=s["source_protocol"],
            dns_a=s.get("dns_a"),
            aliases=s.get("aliases", []),
            tls=tls,
        )
        services.append(svc)

    return RootConfig(dsm=dsm, dns=dns, certs=certs, services=services)
