from __future__ import annotations

import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from cryptography import x509

from .logging_utils import Logger
from .models import CertsConfig


def read_cert_expiry(cert_path: Path) -> Optional[datetime]:
    """Return the notAfter datetime (UTC) of the first cert in a PEM file, or None if unreadable."""
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        return cert.not_valid_after_utc
    except Exception:
        return None


def cert_covers_hosts(cert_path: Path, hosts: List[str]) -> bool:
    """Return True if the cert's SANs cover all requested hosts."""
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        cert_dns_names = {name.lower() for name in san_ext.value.get_values_for_type(x509.DNSName)}
        return all(h.lower() in cert_dns_names for h in hosts)
    except Exception:
        return False


class StepCAClient:
    def __init__(self, cfg: CertsConfig, logger: Logger):
        self.cfg = cfg
        self.logger = logger
        self.step_bin = os.environ.get("STEP_BIN", "step")

    @property
    def enabled(self) -> bool:
        return self.cfg.enabled

    @property
    def name(self) -> Optional[str]:
        return self.cfg.name

    def filter_sans(self, common_name: str, sans: List[str]) -> List[str]:
        return sans

    def group_hosts(self, host: str, aliases: List[str]) -> list:
        return [(self, [host] + aliases)]

    def renew_before_hours(self) -> int:
        return self.cfg.renew_before_hours

    def obtain_certificate(
        self,
        common_name: str,
        sans: List[str],
        out_crt: Path,
        out_key: Path,
    ) -> None:
        if not self.enabled:
            self.logger.info("[step-ca] Disabled; skipping certificate issuance")
            return

        cmd = [
            self.step_bin,
            "ca",
            "certificate",
            common_name,
            str(out_crt),
            str(out_key),
            "--force",
            "--ca-url",
            self.cfg.ca_url,
            "--provisioner",
            self.cfg.provisioner,
            f"--not-after={self.cfg.default_ltl_hours}h",
        ]

        if self.cfg.root_ca:
            cmd.extend(["--root", self.cfg.root_ca])

        for san in sans:
            cmd.extend(["--san", san])

        if self.cfg.provisioner_password_file:
            cmd.extend(["--password-file", self.cfg.provisioner_password_file])

        self.logger.info(f"[step-ca] Issuing certificate for {common_name} ({', '.join(sans)})")
        subprocess.run(cmd, check=True)
        self.logger.info(f"[step-ca] Wrote cert: {out_crt}, key: {out_key}")
