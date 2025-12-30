from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Literal

Protocol = Literal["http", "https"]


@dataclass
class DsmConfig:
    host: str
    port: int = 5001
    https: bool = True
    verify_ssl: bool = True
    username_file: str = ""
    password_file: str = ""


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
class RedirectConfig:
    enabled: bool = True
    bind_host: str = "127.0.0.1"
    backend_host: Optional[str] = None
    port: int = 9179


@dataclass
class ServiceConfig:
    name: str
    host: str
    dest_url: str
    source_port: int
    source_protocol: Protocol
    dns_a: Optional[str] = None
    aliases: List[str] = field(default_factory=list)
    loaded_from: Optional[str] = None


@dataclass
class RootConfig:
    dsm: DsmConfig
    dns: list[DnsZone]
    certs: CertsConfig
    redirect: RedirectConfig = field(default_factory=RedirectConfig)


@dataclass
class ReverseProxyRule:
    description: str
    src_host: str
    src_port: int
    src_protocol: Protocol

    dst_host: str
    dst_port: int
    dst_protocol: Protocol

    enabled: bool = True
