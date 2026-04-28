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
    provider: str = "step-ca"  # "step-ca", "letsencrypt", or "none"
    name: Optional[str] = None  # used as subdirectory name for alias cert groups
    zone: Optional[str] = None  # zone this entry applies to; None = catch-all
    email: Optional[str] = None  # required for letsencrypt
    ca_url: str = ""
    ca_fingerprint: str = ""
    provisioner: str = ""
    provisioner_password_file: Optional[str] = None
    default_ltl_hours: int = 2160
    renew_before_hours: int = 168
    root_ca: Optional[str] = None

    @property
    def enabled(self) -> bool:
        return self.provider != "none"


@dataclass
class NginxConfig:
    conf_dir: str = "/etc/nginx/conf.d"
    certs_dir: str = "/certs"
    cleanup: bool = True
    prefix: str = "rp-sync"
    acme_webroot: Optional[str] = None  # "write_path" or "write_path;nginx_path"
    ipv6: bool = True

    @property
    def certs_write_dir(self) -> str:
        """Local filesystem path where rp-sync writes cert files."""
        return self.certs_dir.split(";", 1)[0]

    @property
    def certs_nginx_dir(self) -> str:
        """Path used in nginx ssl_certificate directives (container-side). Defaults to certs_dir."""
        parts = self.certs_dir.split(";", 1)
        return parts[1] if len(parts) > 1 else self.certs_dir

    @property
    def acme_write_path(self) -> Optional[str]:
        """Filesystem path where rp-sync writes ACME challenge tokens."""
        if not self.acme_webroot:
            return None
        return self.acme_webroot.split(";", 1)[0]

    @property
    def acme_nginx_path(self) -> str:
        """Path used in the nginx root directive (container-side). Defaults to /var/www/acme."""
        if not self.acme_webroot:
            return "/var/www/acme"
        parts = self.acme_webroot.split(";", 1)
        return parts[1] if len(parts) > 1 else "/var/www/acme"


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
    certs: List[CertsConfig]
    nginx: NginxConfig = field(default_factory=NginxConfig)
    access_control_profiles: List[AccessControlProfile] = field(default_factory=list)
    default_access_control_profile: Optional[str] = None
