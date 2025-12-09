# rp_sync/dns_updater.py

from __future__ import annotations

import re
import socket

from dns import update as dns_update
from dns import query as dns_query
from dns import tsigkeyring
from dns import rdatatype
from dns import name as dnsname

from .models import DnsConfig


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


class DnsUpdater:
    def __init__(self, cfg: DnsConfig):
        self.cfg = cfg

        name, alg, secret = _parse_bind_tsig_file(cfg.tsig_key_file)
        # normalize into what dnspython expects
        self.key_name = name if name.endswith(".") else name + "."
        self.key_algorithm = _normalize_tsig_algorithm(alg)
        self.key_secret = secret

    def _resolve_server_ip(self) -> str:
        info = socket.getaddrinfo(self.cfg.server, self.cfg.port, 0, socket.SOCK_STREAM)
        return info[0][4][0]

    def ensure_a_record(self, hostname: str, ip: str, ttl: int = 300) -> None:
        keyring = tsigkeyring.from_text({self.key_name: self.key_secret})

        zone = dnsname.from_text(self.cfg.zone)
        fqdn = dnsname.from_text(hostname)

        upd = dns_update.Update(
            zone,
            keyring=keyring,
            keyalgorithm=self.key_algorithm,
        )
        upd.replace(fqdn, ttl, rdatatype.A, ip)

        server_ip = self._resolve_server_ip()
        print(f"[DNS] Updating A {hostname} -> {ip} via {server_ip}:{self.cfg.port}")
        resp = dns_query.tcp(upd, server_ip, port=self.cfg.port)
        rcode = resp.rcode()
        if rcode != 0:
            raise RuntimeError(f"DNS update failed for {hostname}: rcode={rcode}")
