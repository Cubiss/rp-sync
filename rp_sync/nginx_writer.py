from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Optional

from .models import AccessControlProfile, NginxConfig, ServiceConfig


_MANAGED_MARKER = "# managed by rp-sync\n"

_PROXY_HEADERS = """\
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $http_connection;\
"""


class NginxConfigWriter:
    def __init__(self, cfg: NginxConfig) -> None:
        self.cfg = cfg

    def _listen_lines(self, port: int | str, ssl: bool = False, default_server: bool = False) -> List[str]:
        flags = (["ssl"] if ssl else []) + (["default_server"] if default_server else [])
        flags_str = (" " + " ".join(flags)) if flags else ""
        lines = [f"    listen {port}{flags_str};"]
        if self.cfg.ipv6:
            v6_flags = (["ssl"] if ssl else []) + ["ipv6only=on"] + (["default_server"] if default_server else [])
            lines.append(f"    listen [::]:{port} {' '.join(v6_flags)};")
        return lines

    def cert_paths(self, svc_name: str) -> tuple[str, str]:
        """Paths used in nginx ssl_certificate directives (container-side)."""
        base = os.path.join(self.cfg.certs_nginx_dir, svc_name)
        return f"{base}/cert.pem", f"{base}/key.pem"

    def cert_write_paths(self, svc_name: str) -> tuple[str, str]:
        """Local filesystem paths used to check whether a cert exists."""
        base = os.path.join(self.cfg.certs_write_dir, svc_name)
        return f"{base}/cert.pem", f"{base}/key.pem"

    def _global_conf(self) -> str:
        acme = self.cfg.acme_webroot
        port80_block_lines = ["server {"] + self._listen_lines(80, default_server=True) + [
            "    server_name _;",
        ]
        if acme:
            port80_block_lines += [
                "",
                "    location /.well-known/acme-challenge/ {",
                f"        root {self.cfg.acme_nginx_path};",
                "    }",
            ]
        # return at server level fires before location matching; use location /
        # so the ACME challenge location takes precedence.
        port80_block_lines += [
            "",
            "    location / {",
            "        return 444;",
            "    }",
            "}",
        ]
        port80_block = "\n".join(port80_block_lines)
        listen_443_default = "\n".join(self._listen_lines(443, ssl=True, default_server=True))

        return _MANAGED_MARKER + f"""\
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers off;
ssl_session_timeout 1d;
ssl_session_cache shared:MozSSL:10m;

{port80_block}

server {{
{listen_443_default}
    server_name _;
    ssl_reject_handshake on;
}}
"""

    def write_global(self) -> None:
        conf_dir = Path(self.cfg.conf_dir)
        conf_dir.mkdir(parents=True, exist_ok=True)
        self._write_file(conf_dir / f"{self.cfg.prefix}-global.conf", self._global_conf())

    def write(
        self,
        services: List[ServiceConfig],
        profiles: Dict[str, AccessControlProfile],
        default_profile: Optional[str],
    ) -> None:
        conf_dir = Path(self.cfg.conf_dir)
        conf_dir.mkdir(parents=True, exist_ok=True)

        p = self.cfg.prefix
        self._write_file(conf_dir / f"{p}-global.conf", self._global_conf())

        managed_files = {f"{p}-global.conf"}
        for svc in services:
            profile_name = svc.access_control_profile or default_profile
            profile = profiles.get(profile_name) if profile_name else None
            content = _MANAGED_MARKER + "\n".join(self._service_blocks(svc, profile)) + "\n"
            filename = f"{p}-{svc.name}.conf"
            self._write_file(conf_dir / filename, content)
            managed_files.add(filename)

        if self.cfg.cleanup:
            for existing in conf_dir.glob(f"{p}-*.conf"):
                if existing.name not in managed_files:
                    existing.unlink()

    def _write_file(self, path: Path, content: str) -> None:
        tmp = path.with_suffix(".conf.tmp")
        tmp.write_text(content, encoding="utf-8")
        tmp.replace(path)

    def _acl_lines(self, profile: Optional[AccessControlProfile]) -> List[str]:
        if not profile or not profile.rules:
            return []
        lines = []
        for rule in profile.rules:
            action = "allow" if rule.allow else "deny"
            lines.append(f"    {action} {rule.address};")
        lines.append("    deny all;")
        return lines

    def _proxy_location(self, dest_url: str, custom_headers: Dict[str, str]) -> List[str]:
        lines = [
            "    location / {",
            f"        proxy_pass {dest_url};",
            _PROXY_HEADERS,
        ]
        for name, value in custom_headers.items():
            lines.append(f"        proxy_set_header {name} {value};")
        lines.append("    }")
        return lines

    @staticmethod
    def _error_page_lines() -> List[str]:
        return [
            "    error_page 400 401 403 404 429 500 502 503 504 /rp-sync-error.html;",
            "    location = /rp-sync-error.html {",
            "        internal;",
            "        ssi on;",
            "        root /usr/share/nginx/html;",
            "    }",
        ]

    def _service_blocks(
        self, svc: ServiceConfig, profile: Optional[AccessControlProfile]
    ) -> List[str]:
        blocks: List[str] = []
        acl = self._acl_lines(profile)

        if svc.source_protocol == "https":
            cert_pem, key_pem = self.cert_paths(svc.name)
            write_crt, _ = self.cert_write_paths(svc.name)

            if Path(write_crt).exists():
                # Main HTTPS server block
                lines = [f"server {{"] + self._listen_lines(svc.source_port, ssl=True) + [
                    f"    server_name {svc.host};",
                    f"",
                    f"    ssl_certificate {cert_pem};",
                    f"    ssl_certificate_key {key_pem};",
                ]
                if acl:
                    lines.append("")
                    lines.extend(acl)
                lines.append("")
                lines.extend(self._proxy_location(svc.dest_url, svc.custom_headers))
                lines.append("")
                lines.extend(self._error_page_lines())
                lines.append("}")
                blocks.append("\n".join(lines))

                # Alias redirect block (HTTPS → canonical)
                if svc.aliases:
                    lines = [f"server {{"] + self._listen_lines(svc.source_port, ssl=True) + [
                        f"    server_name {' '.join(svc.aliases)};",
                        f"",
                        f"    ssl_certificate {cert_pem};",
                        f"    ssl_certificate_key {key_pem};",
                        f"",
                        f"    return 308 https://{svc.host}$request_uri;",
                        f"}}",
                    ]
                    blocks.append("\n".join(lines))

            # HTTP → HTTPS redirect block (always written so ACME challenges are served)
            all_hosts = " ".join([svc.host] + svc.aliases)
            lines = [f"server {{"] + self._listen_lines(80) + [
                f"    server_name {all_hosts};",
            ]
            if self.cfg.acme_webroot:
                lines += [
                    f"",
                    f"    location /.well-known/acme-challenge/ {{",
                    f"        root {self.cfg.acme_nginx_path};",
                    f"    }}",
                ]
            # return at server level fires before location matching, so use
            # location / to let the ACME challenge location take precedence.
            lines += [
                f"",
                f"    location / {{",
                f"        return 308 https://{svc.host}$request_uri;",
                f"    }}",
                f"}}",
            ]
            blocks.append("\n".join(lines))

        else:
            # Plain HTTP service
            lines = [f"server {{"] + self._listen_lines(svc.source_port) + [
                f"    server_name {svc.host};",
            ]
            if acl:
                lines.append("")
                lines.extend(acl)
            lines.append("")
            lines.extend(self._proxy_location(svc.dest_url, svc.custom_headers))
            lines.append("")
            lines.extend(self._error_page_lines())
            lines.append("}")
            blocks.append("\n".join(lines))

            # Alias redirect block (HTTP → canonical)
            if svc.aliases:
                lines = [f"server {{"] + self._listen_lines(svc.source_port) + [
                    f"    server_name {' '.join(svc.aliases)};",
                    f"",
                    f"    return 308 http://{svc.host}$request_uri;",
                    f"}}",
                ]
                blocks.append("\n".join(lines))

        return blocks
