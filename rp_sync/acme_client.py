from __future__ import annotations

import ipaddress
import socket
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import List

import josepy as jose
import requests
from acme import client as acme_lib
from acme import challenges, errors as acme_errors, messages
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .logging_utils import Logger
from .models import CertsConfig, NginxConfig

_LETS_ENCRYPT_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"

# TLDs that are never publicly resolvable and cannot be validated by Let's Encrypt.
_LOCAL_TLDS = {"local", "localhost", "internal", "lan", "home", "invalid", "test", "example"}


def _is_public_hostname(name: str) -> bool:
    """Return True if name can be validated by Let's Encrypt (HTTP-01)."""
    try:
        ipaddress.ip_address(name)
        return False  # IP addresses not supported
    except ValueError:
        pass
    if "." not in name:
        return False  # single-label names (e.g. "jellyfin")
    tld = name.rsplit(".", 1)[-1].lower()
    return tld not in _LOCAL_TLDS


class AcmeClient:
    def __init__(self, cfg: CertsConfig, nginx_cfg: NginxConfig, logger: Logger):
        self.cfg = cfg
        self.nginx_cfg = nginx_cfg
        self.logger = logger
        self._state_dir = Path(nginx_cfg.certs_write_dir) / ".acme"

    @property
    def enabled(self) -> bool:
        return self.cfg.enabled and self.cfg.provider == "letsencrypt"

    @property
    def name(self) -> Optional[str]:
        return self.cfg.name

    def filter_sans(self, common_name: str, sans: List[str]) -> List[str]:
        return [s for s in sans if _is_public_hostname(s)]

    def group_hosts(self, host: str, aliases: List[str]) -> list:
        return [(self, [host] + aliases)]

    def renew_before_hours(self) -> int:
        return self.cfg.renew_before_hours

    # ------------------------------------------------------------------
    # Account key
    # ------------------------------------------------------------------

    def _account_key(self) -> jose.JWKRSA:
        key_path = self._state_dir / "account.key"
        if key_path.exists():
            raw = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
            return jose.JWKRSA(key=raw)

        self._state_dir.mkdir(parents=True, exist_ok=True)
        raw = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key_path.write_bytes(
            raw.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        self.logger.info("[acme] Generated new account key")
        return jose.JWKRSA(key=raw)

    # ------------------------------------------------------------------
    # ACME client + account registration
    # ------------------------------------------------------------------

    def _build_client(self, account_key: jose.JWKRSA) -> acme_lib.ClientV2:
        directory_url = self.cfg.ca_url or _LETS_ENCRYPT_DIRECTORY
        net = acme_lib.ClientNetwork(account_key, user_agent="rp-sync")
        directory = messages.Directory.from_json(net.get(directory_url).json())
        return acme_lib.ClientV2(directory, net)

    def _ensure_account(self, client: acme_lib.ClientV2) -> None:
        reg = messages.NewRegistration.from_data(
            email=self.cfg.email,
            terms_of_service_agreed=True,
        )
        try:
            regr = client.new_account(reg)
            self.logger.info(f"[acme] Registered new account: {regr.uri}")
        except acme_errors.ConflictError as e:
            # Account with this key already exists; the library raises ConflictError
            # on a 200 response and provides the account URI in e.location.
            client.net.account = messages.RegistrationResource(
                uri=e.location,
                body=messages.Registration(),
            )
            self.logger.info(f"[acme] Using existing account: {e.location}")

    # ------------------------------------------------------------------
    # CSR generation
    # ------------------------------------------------------------------

    def _make_csr(self, common_name: str, sans: List[str]) -> tuple[bytes, bytes]:
        """Return (key_pem, csr_pem) for a fresh RSA 2048 key."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        csr_pem = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
            .public_bytes(serialization.Encoding.PEM)
        )
        return key_pem, csr_pem

    # ------------------------------------------------------------------
    # HTTP-01 challenge handling
    # ------------------------------------------------------------------

    def _check_challenge_ipv6(self, domain: str, token_name: str, validation: str) -> bool:
        """Return True if the challenge token is served correctly over IPv6."""
        try:
            addrs = socket.getaddrinfo(domain, 80, family=socket.AF_INET6, type=socket.SOCK_STREAM)
        except socket.gaierror:
            return True  # No AAAA records — skip IPv6 check
        if not addrs:
            return True
        ipv6_addr = addrs[0][4][0]
        try:
            with socket.create_connection((ipv6_addr, 80), timeout=5) as s:
                req = (
                    f"GET /.well-known/acme-challenge/{token_name} HTTP/1.0\r\n"
                    f"Host: {domain}\r\n"
                    f"Connection: close\r\n\r\n"
                )
                s.sendall(req.encode())
                buf = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
            text = buf.decode("utf-8", errors="replace")
            body = text.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in text else text
            return body.strip() == validation.strip()
        except Exception:
            return False

    def _wait_for_challenge(self, domain: str, token_name: str, validation: str, timeout: int = 30) -> None:
        url = f"http://{domain}/.well-known/acme-challenge/{token_name}"
        # Determine once whether the domain has AAAA records.
        try:
            has_ipv6 = bool(socket.getaddrinfo(domain, 80, family=socket.AF_INET6))
        except socket.gaierror:
            has_ipv6 = False

        deadline = time.monotonic() + timeout
        ipv4_ok = False
        ipv6_ok = not has_ipv6  # skip if no AAAA records

        while time.monotonic() < deadline:
            if not ipv4_ok:
                try:
                    resp = requests.get(url, timeout=5, allow_redirects=False)
                    if resp.status_code == 200 and resp.text.strip() == validation.strip():
                        self.logger.info(f"[acme] Challenge reachable via IPv4: {url}")
                        ipv4_ok = True
                except Exception:
                    pass
            if not ipv6_ok:
                if self._check_challenge_ipv6(domain, token_name, validation):
                    self.logger.info(f"[acme] Challenge reachable via IPv6: {url}")
                    ipv6_ok = True
            if ipv4_ok and ipv6_ok:
                return
            time.sleep(1)

        if not ipv4_ok:
            raise TimeoutError(f"[acme] Challenge URL not reachable via IPv4 within {timeout}s: {url}")
        raise TimeoutError(f"[acme] Challenge URL not reachable via IPv6 within {timeout}s: {url}")

    def _answer_challenges(
        self,
        client: acme_lib.ClientV2,
        account_key: jose.JWKRSA,
        order,
    ) -> List[Path]:
        webroot = Path(self.nginx_cfg.acme_write_path)
        challenge_dir = webroot / ".well-known" / "acme-challenge"
        challenge_dir.mkdir(parents=True, exist_ok=True)

        token_paths: List[Path] = []
        for auth in order.authorizations:
            domain = auth.body.identifier.value
            http01 = next(
                (c for c in auth.body.challenges if isinstance(c.chall, challenges.HTTP01)),
                None,
            )
            if http01 is None:
                raise ValueError(f"[acme] No HTTP-01 challenge available for {domain}")

            response, validation = http01.chall.response_and_validation(account_key)
            token_name = http01.chall.encode("token")
            token_path = challenge_dir / token_name
            token_path.write_text(validation)
            token_paths.append(token_path)

            self._wait_for_challenge(domain, token_name, validation)
            self.logger.info(f"[acme] Answering HTTP-01 challenge for {domain}")
            client.answer_challenge(http01, response)

        return token_paths

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def obtain_certificate(
        self,
        common_name: str,
        sans: List[str],
        out_crt: Path,
        out_key: Path,
    ) -> None:
        if not self.enabled:
            self.logger.info("[acme] Disabled; skipping certificate issuance")
            return

        if not self.nginx_cfg.acme_write_path:
            raise ValueError("[acme] nginx.acme_webroot must be set to use the letsencrypt provider")
        if not self.cfg.email:
            raise ValueError("[acme] certs.email must be set to use the letsencrypt provider")

        if not _is_public_hostname(common_name):
            raise ValueError(
                f"[acme] '{common_name}' is not a publicly resolvable hostname; "
                "cannot issue a Let's Encrypt certificate"
            )

        public_sans = [s for s in sans if _is_public_hostname(s)]
        skipped = [s for s in sans if s not in public_sans]
        if skipped:
            self.logger.warning(
                f"[acme] Skipping SANs not supported by Let's Encrypt: {', '.join(skipped)}"
            )

        self.logger.info(f"[acme] Issuing certificate for {common_name} ({', '.join(public_sans)})")

        account_key = self._account_key()
        client = self._build_client(account_key)
        self._ensure_account(client)

        key_pem, csr_pem = self._make_csr(common_name, public_sans)
        order = client.new_order(csr_pem)

        token_paths = self._answer_challenges(client, account_key, order)
        try:
            deadline = datetime.now() + timedelta(seconds=90)
            order = client.poll_and_finalize(order, deadline=deadline)
        finally:
            for p in token_paths:
                p.unlink(missing_ok=True)

        out_key.write_bytes(key_pem)
        out_crt.write_text(order.fullchain_pem)
        self.logger.info(f"[acme] Wrote cert: {out_crt}, key: {out_key}")
