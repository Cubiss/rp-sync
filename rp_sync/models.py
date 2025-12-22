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
class ServiceConfig:
    name: str
    host: str
    dest_url: str
    source_port: int
    source_protocol: Protocol
    dns_a: Optional[str] = None
    aliases: List[str] = field(default_factory=list)
    # If True, rp-sync will NOT generate HTTP->HTTPS redirect rules for this
    # service hostnames when http_redirect.mode == "per_host".
    #
    # This is useful for endpoints that must remain reachable over plain HTTP.
    allow_http: bool = False


HttpRedirectMode = Literal["catch_all", "per_host"]


@dataclass
class BuiltinRedirectBackendConfig:
    enabled: bool = True
    listen_host: str = "127.0.0.1"
    listen_port: int = 18080
    # 308 preserves method/body; 301 is the classic browser redirect.
    code: int = 308


@dataclass
class HttpRedirectConfig:
    enabled: bool = False
    mode: HttpRedirectMode = "catch_all"
    # Frontend that should be redirected. Typically 80.
    source_port: int = 80
    # Where DSM Reverse Proxy will forward HTTP requests.
    backend_url: str = "http://127.0.0.1:18080"
    # Optional: force redirects to a single canonical host.
    # If unset, Host / X-Forwarded-Host is used.
    canonical_host: Optional[str] = None
    builtin_backend: BuiltinRedirectBackendConfig = field(
        default_factory=BuiltinRedirectBackendConfig
    )


@dataclass
class RootConfig:
    dsm: DsmConfig
    dns: list[DnsZone]
    certs: CertsConfig
    http_redirect: HttpRedirectConfig = field(default_factory=HttpRedirectConfig)


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
