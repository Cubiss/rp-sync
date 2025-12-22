from __future__ import annotations

import os
from typing import Any, Dict, cast

import yaml

from .models import (
    RootConfig,
    DsmConfig,
    DnsZone,
    CertsConfig,
    HttpRedirectConfig,
    BuiltinRedirectBackendConfig,
    HttpRedirectMode,
)

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

POLL_ENV = "RP_SYNC_POLL_SECONDS"
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

    dsm_raw = raw["dsm"]
    dns_raw = raw["dns"]
    certs_raw = raw.get("certs", {})
    http_redirect_raw = raw.get("http_redirect", {})

    dsm = DsmConfig(
        host=dsm_raw["host"],
        port=dsm_raw.get("port", 5001),
        https=dsm_raw.get("https", True),
        verify_ssl=dsm_raw.get("verify_ssl", True),
        username_file=dsm_raw["username_file"],
        password_file=dsm_raw["password_file"],
    )

    dns_zones: list[DnsZone] = []

    for z_raw in dns_raw:
        server = z_raw["server"]
        dns_zones.append(
            DnsZone(
                zone=z_raw["zone"],
                server=server,
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

    builtin_raw = http_redirect_raw.get("builtin_backend", {}) or {}
    builtin_backend = BuiltinRedirectBackendConfig(
        enabled=bool(builtin_raw.get("enabled", True)),
        listen_host=str(builtin_raw.get("listen_host", "127.0.0.1")),
        listen_port=int(builtin_raw.get("listen_port", 18080)),
        code=int(builtin_raw.get("code", 308)),
    )

    mode_raw = http_redirect_raw.get("mode", "catch_all")
    if mode_raw not in ("catch_all", "per_host"):
        raise ValueError(
            f"http_redirect.mode must be 'catch_all' or 'per_host' (got: {mode_raw!r})"
        )
    mode: HttpRedirectMode = cast(HttpRedirectMode, mode_raw)

    http_redirect = HttpRedirectConfig(
        enabled=bool(http_redirect_raw.get("enabled", False)),
        mode=mode,
        source_port=int(http_redirect_raw.get("source_port", 80)),
        backend_url=str(http_redirect_raw.get("backend_url", "http://127.0.0.1:18080")),
        canonical_host=http_redirect_raw.get("canonical_host"),
        builtin_backend=builtin_backend,
    )

    return RootConfig(dsm=dsm, dns=dns_zones, certs=certs, http_redirect=http_redirect)


def load_config(path: str | None = None) -> RootConfig:
    """Backwards-compatible loader: root config + services.

    - Root config always comes from RP_SYNC_CONFIG_PATH / *path*.
    - Services come from:
        * *path* if explicitly provided (treat it as the service file), or
        * service_config.get_services_path() otherwise (supporting directories).
    """
    core = load_root_config(path=path)

    return RootConfig(dsm=core.dsm, dns=core.dns, certs=core.certs, http_redirect=core.http_redirect)
