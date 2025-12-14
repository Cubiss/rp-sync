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


def _services_from_raw(
    raw: Dict[str, Any] | List[Dict[str, Any]] | None,
) -> List[Dict[str, Any]]:
    if raw is None:
        return []

    if isinstance(raw, list):
        return raw

    return []


def _load_services_from_file(path: str) -> List[Dict[str, Any]]:
    raw = _load_yaml(path)
    return _services_from_raw(raw)

# TODO: make this search for .service files in subdirectories recursively.
# TODO: capture the path where service config was loaded from and utilize it in logs
def _load_services_from_directory(path: str) -> List[Dict[str, Any]]:
    """Load services from all *.service files in a directory."""
    services: List[Dict[str, Any]] = []

    try:
        with os.scandir(path) as it:
            entries = sorted(
                [e for e in it if e.is_file() and e.name.endswith(SERVICE_FILE_SUFFIX)],
                key=lambda e: e.name,
            )
    except FileNotFoundError:
        return []

    for entry in entries:
        services.extend(_load_services_from_file(entry.path))

    return services


def load_services(path: Optional[str] = None) -> List[ServiceConfig]:
    """Load all ServiceConfig objects from a path (file or directory).

    If *path* is None, it is resolved using get_services_path().

    - If path is a directory, all *.service files are loaded and merged.
    - Each file may contain:
        * services: [ {...}, {...} ]
        * [ {...}, {...} ]
    """
    services_path = path or get_services_path()

    if os.path.isdir(services_path):
        raw_services = _load_services_from_directory(services_path)
    else:
        raw_services = _load_services_from_file(services_path)

    result: List[ServiceConfig] = []
    for s in raw_services:
        svc = ServiceConfig(
            name=s["name"],
            host=s["host"],
            dest_url=s["dest_url"],
            source_port=int(s["source_port"]),
            source_protocol=s["source_protocol"],
            dns_a=s.get("dns_a"),
            aliases=s.get("aliases", []),
        )
        result.append(svc)

    return result
