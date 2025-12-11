# rp_sync/dns_updater.py

from __future__ import annotations

import re
import socket
from dataclasses import dataclass

from dns import update as dns_update
from dns import query as dns_query
from dns import tsigkeyring
from dns import rdatatype
from dns import name as dnsname

from .logging_utils import Logger
from .models import DnsZone


def _normalize_tsig_algorithm(alg: str) -> str:
    """
    Map BIND-style algorithm names (HMAC-MD5, HMAC-SHA256, ...) to the
    DNS names dnspython expects.
    """
    a = alg.strip().lower()
    if a in {"hmac-md5", "md5"}:
        return "hmac-md5.sig-alg.reg.int."
    if a in {"hmac-sha256", "sha256"}:
        return "hmac-sha256."
    if a in {"hmac-sha512", "sha512"}:
        return "hmac-sha512."

    return alg


def _parse_bind_tsig_file(path: str) -> tuple[str, str, str]:
    name = None
    algorithm = None
    secret = None

    with open(path, "r", encoding="utf-8") as f:
        text = f.read()

    m = re.search(r'key\s+"([^"]+)"', text)
    if m:
        name = m.group(1)

    m = re.search(r"algorithm\s+([A-Za-z0-9_-]+)\s*;", text)
    if m:
        algorithm = m.group(1)

    m = re.search(r'secret\s+"([^"]+)"', text)
    if m:
        secret = m.group(1)

    if not (name and algorithm and secret):
        raise ValueError(f"Could not parse TSIG key file: {path}")

    return name, algorithm, secret


def _split_host_port(server: str, default_port: int = 53) -> tuple[str, int]:
    """
    Parse "host:port" or just "host" into (host, port).

    Supports IPv6 in the form "[2001:db8::1]:53".
    """
    value = server.strip()
    if not value:
        raise ValueError("Empty DNS server value")

    # IPv6 literal like "[2001:db8::1]:53"
    if value.startswith("["):
        end = value.find("]")
        if end == -1:
            raise ValueError(f"Invalid server format (missing ']'): {server!r}")
        host = value[1:end]
        rest = value[end + 1 :]
        if rest.startswith(":"):
            port_str = rest[1:]
        else:
            port_str = ""
    else:
        if ":" in value:
            host, port_str = value.rsplit(":", 1)
        else:
            host, port_str = value, ""

    port = default_port if not port_str else int(port_str)
    return host, port


@dataclass
class _ZoneContext:
    zone: dnsname.Name
    server_host: str
    server_port: int
    key_name: str
    key_algorithm: str
    key_secret: str


class DnsUpdater:
    def __init__(self, zones: list[DnsZone], logger: Logger):
        self.cfg = zones
        self.logger = logger

        self._zones: list[_ZoneContext] = []

        if not zones:
            raise ValueError("No DNS zones configured")

        # Build per-zone contexts (server + TSIG)
        for z in zones:
            if not z.tsig_key_file:
                raise ValueError(f"TSIG key file is required for zone {z.zone}")

            name, alg, secret = _parse_bind_tsig_file(z.tsig_key_file)
            key_name = name if name.endswith(".") else name + "."
            key_algorithm = _normalize_tsig_algorithm(alg)

            server_host, server_port = _split_host_port(z.server)
            zone_name = dnsname.from_text(z.zone)

            self._zones.append(
                _ZoneContext(
                    zone=zone_name,
                    server_host=server_host,
                    server_port=server_port,
                    key_name=key_name,
                    key_algorithm=key_algorithm,
                    key_secret=secret,
                )
            )

    def _resolve_server_ip(self, host: str, port: int) -> str:
        info = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
        return info[0][4][0]

    def _select_zone_for_hostname(self, hostname: str) -> _ZoneContext:
        """Pick the most specific configured zone that contains the hostname."""
        fqdn = dnsname.from_text(hostname)

        best: _ZoneContext | None = None
        for z in self._zones:
            if fqdn.is_subdomain(z.zone):
                if best is None or len(z.zone.labels) > len(best.zone.labels):
                    best = z

        return best

    def ensure_a_record(self, hostname: str, ip: str, ttl: int = 300) -> None:
        zone_ctx = self._select_zone_for_hostname(hostname)

        if zone_ctx is None:
            self.logger.warning(f"No DNS zone configured for hostname {hostname}")
            return

        keyring = tsigkeyring.from_text({zone_ctx.key_name: zone_ctx.key_secret})

        fqdn = dnsname.from_text(hostname)

        upd = dns_update.Update(
            zone_ctx.zone,
            keyring=keyring,
            keyalgorithm=zone_ctx.key_algorithm,
        )
        upd.replace(fqdn, ttl, rdatatype.A, ip)

        server_ip = self._resolve_server_ip(zone_ctx.server_host, zone_ctx.server_port)
        self.logger.info(
            f"[DNS] Updating A {hostname} -> {ip} via {server_ip}:{zone_ctx.server_port}"
        )
        resp = dns_query.tcp(upd, server_ip, port=zone_ctx.server_port)
        rcode = resp.rcode()
        if rcode != 0:
            self.logger.debug(f"[DNS] Failed request: {upd}")
            self.logger.debug(f"[DNS] Failed response: {resp}")
            raise RuntimeError(f"DNS update failed for {hostname}: rcode={rcode}")
