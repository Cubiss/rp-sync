from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import List

from .models import CertsConfig


class StepCAClient:
    def __init__(self, cfg: CertsConfig):
        self.cfg = cfg
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
            print("[step-ca] Disabled; skipping certificate issuance")
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
        if self.cfg.ca_root_file:
            cmd.extend(["--root", self.cfg.ca_root_file])

        for san in sans:
            cmd.extend(["--san", san])

        if self.cfg.provisioner_password_file:
            cmd.extend(["--password-file", self.cfg.provisioner_password_file])

        print(f"[step-ca] Issuing certificate for {common_name} ({', '.join(sans)})")
        subprocess.run(cmd, check=True)
        print(f"[step-ca] Wrote cert: {out_crt}, key: {out_key}")
