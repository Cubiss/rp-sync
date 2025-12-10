from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import List

from .logging_utils import Logger
from .models import CertsConfig


class StepCAClient:
    def __init__(self, cfg: CertsConfig, logger: Logger):
        self.cfg = cfg
        self.logger = logger
        self.step_bin = os.environ.get("STEP_BIN", "step")

    @property
    def enabled(self) -> bool:
        return self.cfg.enabled

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

        # add --root if configured
        if self.cfg.root_ca:
            cmd.extend(["--root", self.cfg.root_ca])

        for san in sans:
            cmd.extend(["--san", san])

        if self.cfg.provisioner_password_file:
            cmd.extend(["--password-file", self.cfg.provisioner_password_file])

        self.logger.info(f"[step-ca] Issuing certificate for {common_name} ({', '.join(sans)})")
        subprocess.run(cmd, check=True)
        self.logger.info(f"[step-ca] Wrote cert: {out_crt}, key: {out_key}")
