from __future__ import annotations

import os
from typing import Any, Dict

import yaml

from .models import RootConfig, DsmConfig, DnsConfig, CertsConfig

APP_NAME = "rp-sync"

LOG_DIR = "RP_SYNC_LOG_DIR"
DEFAULT_LOG_DIR = "./logs/"

LOG_KEEP = "RP_SYNC_LOG_KEEP"
DEFAULT_LOG_KEEP = 10

LOG_LEVEL = "RP_SYNC_LOG_LEVEL"
DEFAULT_LOG_LEVEL = "INFO"

CONFIG_ENV = "RP_SYNC_CONFIG_PATH"
DEFAULT_CONFIG_PATH = "./config.yaml"

HEALTH_ENV = "RP_SYNC_HEALTH_FILE"
DEFAULT_HEALTH_PATH = "/tmp/rp-sync-health"

POLL_ENV = "RP_SYNC_WATCH_INTERVAL_SEC"
DEFAULT_POLL_SECONDS = 5.0


def _load_yaml(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _load_core_raw(path: str | None = None) -> Dict[str, Any]:
    config_path = path or os.environ.get(CONFIG_ENV, DEFAULT_CONFIG_PATH)
    raw = _load_yaml(config_path)
    if not isinstance(raw, dict):
        raise ValueError(f"Top-level structure of {config_path} must be a mapping")
    return raw


def load_root_config(path: str | None = None) -> RootConfig:
    """Load only the 'root' config (dsm/dns/certs), no services."""
    raw = _load_core_raw(path)

    dsm_raw = raw["dsm"]
    dns_raw = raw["dns"]
    certs_raw = raw.get("certs", {})

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

    return RootConfig(dsm=dsm, dns=dns, certs=certs)


def load_config(path: str | None = None) -> RootConfig:
    """Backwards-compatible loader: root config + services.

    - Root config always comes from RP_SYNC_CONFIG_PATH / *path*.
    - Services come from:
        * *path* if explicitly provided (treat it as the service file), or
        * service_config.get_services_path() otherwise (supporting directories).
    """
    core = load_root_config(path=path)

    return RootConfig(
        dsm=core.dsm,
        dns=core.dns,
        certs=core.certs
    )
