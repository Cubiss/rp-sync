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
class DnsConfig:
    server: str
    zone: str
    port: int = 53

    tsig_key_file: str | None = None


@dataclass
class LoggingConfig:
    log_dir: str = "./logs/"
    log_keep: int = 10


@dataclass
class CertsConfig:
    disabled: bool = False
    ca_url: str = ""
    ca_fingerprint: str = ""
    provisioner: str = ""
    provisioner_password_file: Optional[str] = None
    default_ltl_hours: int = 2160
    root_ca: Optional[str] = None

    @property
    def enabled(self) -> bool:
        return not self.disabled


@dataclass
class ServiceConfig:
    name: str
    host: str
    dest_url: str
    source_port: int
    source_protocol: Protocol
    dns_a: Optional[str] = None
    aliases: List[str] = field(default_factory=list)


@dataclass
class RootConfig:
    dsm: DsmConfig
    dns: DnsConfig
    certs: CertsConfig
    services: List[ServiceConfig]
    logging: LoggingConfig


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
