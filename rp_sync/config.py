from __future__ import annotations

import os
from typing import Any, Dict

import yaml

from .models import AccessControlProfile, AccessControlRule, RootConfig, DnsZone, CertsConfig, NginxConfig

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
    raw = _load_core_raw(path)

    dns_raw = raw["dns"]
    certs_raw = raw.get("certs", {})
    nginx_raw = raw.get("nginx", {})
    ac_profiles_raw = raw.get("access_control_profiles", [])
    default_ac_profile = raw.get("default_access_control_profile")

    dns_zones: list[DnsZone] = []
    for z_raw in dns_raw:
        dns_zones.append(
            DnsZone(
                zone=z_raw["zone"],
                server=z_raw["server"],
                tsig_key_file=z_raw.get("tsig_key_file"),
            )
        )

    certs = CertsConfig(
        disabled=certs_raw.get("disabled", False),
        ca_url=certs_raw.get("ca_url", ""),
        ca_fingerprint=certs_raw.get("ca_fingerprint", ""),
        provisioner=certs_raw.get("provisioner", ""),
        provisioner_password_file=certs_raw.get("provisioner_password_file"),
        default_ltl_hours=int(certs_raw.get("default_ltl_hours", 2160)),
        renew_before_hours=int(certs_raw.get("renew_before_hours", 168)),
        root_ca=certs_raw.get("root_ca"),
    )

    nginx = NginxConfig(
        conf_path=nginx_raw.get("conf_path", "/etc/nginx/conf.d/rp-sync.conf"),
        certs_dir=nginx_raw.get("certs_dir", "/certs"),
    )

    ac_profiles: list[AccessControlProfile] = []
    for p in ac_profiles_raw:
        rules = [
            AccessControlRule(address=r["address"], allow=r.get("allow", True))
            for r in p.get("rules", [])
        ]
        ac_profiles.append(AccessControlProfile(name=p["name"], rules=rules))

    return RootConfig(
        dns=dns_zones,
        certs=certs,
        nginx=nginx,
        access_control_profiles=ac_profiles,
        default_access_control_profile=default_ac_profile,
    )


def load_config(path: str | None = None) -> RootConfig:
    return load_root_config(path=path)
