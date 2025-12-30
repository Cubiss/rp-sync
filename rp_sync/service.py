from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import yaml

from .models import ServiceConfig

SERVICES_ENV = "RP_SYNC_SERVICES_PATH"
DEFAULT_SERVICES_PATH = "./services/"

SERVICE_FILE_SUFFIX = ".service"


def get_services_path() -> str:
    return os.environ.get(SERVICES_ENV, DEFAULT_SERVICES_PATH)


def _load_yaml(path: str) -> Dict[str, Any] | List[Dict[str, Any]] | None:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _services_from_raw(raw: Dict[str, Any] | List[Dict[str, Any]] | None) -> List[Dict[str, Any]]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        v = raw.get("services")
        if isinstance(v, list):
            return v
    return []


def _load_services_from_file(path: str) -> List[Dict[str, Any]]:
    raw = _load_yaml(path)
    return _services_from_raw(raw)


def _iter_service_files_recursive(path: str) -> List[str]:
    if not os.path.isdir(path):
        return []

    files: List[str] = []
    for root, _dirs, names in os.walk(path):
        for name in names:
            if name.endswith(SERVICE_FILE_SUFFIX):
                files.append(os.path.join(root, name))
    return sorted(files)


def _service_from_dict(s: Dict[str, Any], loaded_from: str) -> ServiceConfig:
    return ServiceConfig(
        name=s["name"],
        host=s["host"],
        dest_url=s["dest_url"],
        source_port=int(s["source_port"]),
        source_protocol=s["source_protocol"],
        dns_a=s.get("dns_a"),
        aliases=s.get("aliases", []),
        loaded_from=loaded_from,
    )


def load_services(path: Optional[str] = None) -> List[ServiceConfig]:
    services_path = path or get_services_path()

    out: List[ServiceConfig] = []

    if os.path.isdir(services_path):
        for fpath in _iter_service_files_recursive(services_path):
            for s in _load_services_from_file(fpath):
                out.append(_service_from_dict(s, loaded_from=fpath))
        return out

    for s in _load_services_from_file(services_path):
        out.append(_service_from_dict(s, loaded_from=services_path))

    return out
