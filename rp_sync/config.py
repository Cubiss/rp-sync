from __future__ import annotations

import os
from typing import Any, Dict, List

import yaml

from .models import RootConfig, DsmConfig, DnsConfig, CertsConfig, ServiceConfig, LoggingConfig


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
    logging_raw = raw["logging"]

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
        disabled=certs_raw.get("disabled", False),
        ca_url=certs_raw.get("ca_url", ""),
        ca_fingerprint=certs_raw.get("ca_fingerprint", ""),
        provisioner=certs_raw.get("provisioner", ""),
        provisioner_password_file=certs_raw.get("provisioner_password_file"),
        default_ltl_hours=int(certs_raw.get("default_ltl_hours", 2160)),
        root_ca=certs_raw.get("root_ca"),
    )

    logging = LoggingConfig(
        log_dir=logging_raw.get("log_dir", "./logs/"), log_keep=int(logging_raw.get("log_keep", 10))
    )

    services: List[ServiceConfig] = []
    for s in services_raw:
        svc = ServiceConfig(
            name=s["name"],
            host=s["host"],
            dest_url=s["dest_url"],
            source_port=int(s["source_port"]),
            source_protocol=s["source_protocol"],
            dns_a=s.get("dns_a"),
            aliases=s.get("aliases", []),
        )
        services.append(svc)

    return RootConfig(dsm=dsm, dns=dns, certs=certs, services=services, logging=logging)
