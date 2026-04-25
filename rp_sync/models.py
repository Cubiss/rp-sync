from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Literal

Protocol = Literal["http", "https"]


@dataclass
class AccessControlRule:
    address: str
    allow: bool = True


@dataclass
class AccessControlProfile:
    name: str
    rules: List[AccessControlRule] = field(default_factory=list)


@dataclass
class DnsZone:
    zone: str
    server: str
    tsig_key_file: Optional[str] = None


@dataclass
class CertsConfig:
    disabled: bool = False
    ca_url: str = ""
    ca_fingerprint: str = ""
    provisioner: str = ""
    provisioner_password_file: Optional[str] = None
    default_ltl_hours: int = 2160
    renew_before_hours: int = 168
    root_ca: Optional[str] = None

    @property
    def enabled(self) -> bool:
        return not self.disabled


@dataclass
class NginxConfig:
    conf_path: str = "/etc/nginx/conf.d/rp-sync.conf"
    certs_dir: str = "/certs"


@dataclass
class ServiceConfig:
    name: str
    host: str
    dest_url: str
    source_port: int
    source_protocol: Protocol
    dns_a: Optional[str] = None
    aliases: List[str] = field(default_factory=list)
    custom_headers: Dict[str, str] = field(default_factory=dict)
    access_control_profile: Optional[str] = None
    loaded_from: Optional[str] = None


@dataclass
class RootConfig:
    dns: list[DnsZone]
    certs: CertsConfig
    nginx: NginxConfig = field(default_factory=NginxConfig)
    access_control_profiles: List[AccessControlProfile] = field(default_factory=list)
    default_access_control_profile: Optional[str] = None
