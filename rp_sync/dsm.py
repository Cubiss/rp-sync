from __future__ import annotations

import logging
from logging import debug

from .logging_utils import Logger
from .models import DsmConfig, ReverseProxyRule
from typing import List, Optional, Dict, Any

import json
import requests
from datetime import datetime, timezone
import re


def _read_secret(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()


class DsmSession:
    def __init__(self, cfg: DsmConfig, logger: Logger):
        self.cfg = cfg
        self.logger = logger
        scheme = "https" if cfg.https else "http"
        self.base = f"{scheme}://{cfg.host}:{cfg.port}"
        self.session = requests.Session()
        self.verify_ssl = cfg.verify_ssl
        self.sid: Optional[str] = None
        self.synotoken: str | None = None

    def url(self, path: str) -> str:
        return f"{self.base}{path}"

    def login(self, username: str, password: str) -> None:
        # Discover auth path
        info_resp = self.session.get(
            self.url("/webapi/query.cgi"),
            params={
                "api": "SYNO.API.Info",
                "version": "1",
                "method": "query",
                "query": "SYNO.API.Auth",
            },
            verify=self.verify_ssl,
        )
        info_resp.raise_for_status()
        auth_info = info_resp.json()["data"]["SYNO.API.Auth"]
        auth_path = auth_info["path"]
        auth_ver = auth_info.get("maxVersion", auth_info.get("version", 1))

        # Login and request synotoken
        login_resp = self.session.get(
            self.url(f"/webapi/{auth_path}"),
            params={
                "api": "SYNO.API.Auth",
                "version": auth_ver,
                "method": "login",
                "account": username,
                "passwd": password,
                "session": "core",
                "format": "sid",
                "enable_syno_token": "yes",
            },
            verify=self.verify_ssl,
        )
        login_resp.raise_for_status()
        data = login_resp.json()
        if not data.get("success"):
            raise RuntimeError(f"DSM login failed: {data}")

        d = data["data"]
        self.sid = d["sid"]
        # token field name can vary a bit by build
        self.synotoken = d.get("synotoken") or d.get("SynoToken")

        if not self.synotoken:
            raise RuntimeError("DSM login did not return synotoken; cannot call core APIs")

        # Attach as header like the DSM UI does
        self.session.headers.update(
            {
                "X-SYNO-TOKEN": self.synotoken,
                # optional but matches UI
                "X-Requested-With": "XMLHttpRequest",
            }
        )

    def _auth_params(self) -> dict[str, str]:
        params: dict[str, str] = {}
        if self.sid:
            params["_sid"] = self.sid
        # some builds also expect SynoToken in body; harmless to send both
        if self.synotoken:
            params["SynoToken"] = self.synotoken
        return params

    def get(self, path: str, params: dict[str, Any]) -> dict[str, Any]:
        all_params = {**params, **self._auth_params()}
        resp = self.session.get(self.url(path), params=all_params, verify=self.verify_ssl)
        resp.raise_for_status()
        return resp.json()

    def post(self, path: str, data: dict[str, Any]) -> dict[str, Any]:
        all_data = {**data, **self._auth_params()}
        resp = self.session.post(self.url(path), data=all_data, verify=self.verify_ssl)
        resp.raise_for_status()
        return resp.json()


class DsmCertificateClient:
    def __init__(self, dsm: DsmSession, logger: Logger):
        self.dsm = dsm
        self.logger = logger

    # --- helpers for "don't renew unless needed" ---

    @staticmethod
    def _parse_expiry_dt(cert: Dict[str, Any]) -> Optional[datetime]:
        """
        Best-effort parse of expiry from various DSM builds.
        Returns an aware UTC datetime if possible, else None.
        """
        for key in (
            "valid_till",
            "valid_to",
            "valid_until",
            "not_after",
            "notAfter",
            "expire_time",
            "expiry",
        ):
            if key not in cert:
                continue
            v = cert.get(key)
            if v is None:
                continue

            # epoch seconds or ms
            if isinstance(v, (int, float)):
                ts = float(v)
                if ts > 10_000_000_000:  # likely ms
                    ts = ts / 1000.0
                return datetime.fromtimestamp(ts, tz=timezone.utc)

            if isinstance(v, str):
                s = v.strip()
                if not s:
                    continue
                # common cases: "YYYY-MM-DD HH:MM:SS", ISO, or includes "Z"
                s = s.replace("Z", "+00:00")
                # If it's "YYYY-MM-DD HH:MM:SS" (no T), make it ISO-ish
                if re.match(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", s):
                    s = s.replace(" ", "T", 1)
                try:
                    dt = datetime.fromisoformat(s)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt.astimezone(timezone.utc)
                except Exception:
                    continue

        return None

    def expires_within_hours(self, cert: Dict[str, Any], hours: int) -> bool:
        # Some DSM responses include a validity flag
        if cert.get("is_valid") is False:
            return True

        dt = self._parse_expiry_dt(cert)
        if dt is None:
            # Can't safely prove it's not expiring; treat as "needs attention"
            return True

        now = datetime.now(timezone.utc)
        return dt <= (now + timedelta(hours=hours))

    def is_assigned_to_reverse_proxy_hosts(self, cert_name: str, hostnames: list[str]) -> bool:
        """
        True if the certificate is currently bound (via ReverseProxy services)
        to *all* requested hostnames.
        """
        target = self.find_certificate_by_name(cert_name)
        if not target:
            return False

        wanted = set(hostnames)
        found: set[str] = set()
        for svc in target.get("services", []):
            if svc.get("subscriber") != "ReverseProxy":
                continue
            dn = svc.get("display_name")
            if dn in wanted:
                found.add(dn)

        return wanted.issubset(found)

    def list_certificates(self) -> List[Dict[str, Any]]:
        # Use POST, DSM behaves like the UI: /webapi/entry.cgi with form data
        data = self.dsm.post(
            "/webapi/entry.cgi",
            {
                "api": "SYNO.Core.Certificate.CRT",
                "version": "1",
                "method": "list",
            },
        )
        if not data.get("success"):
            raise RuntimeError(f"DSM cert list failed: {data}")
        inner = data.get("data", {})
        return inner.get("certificates", inner.get("items", []))

    def find_certificate_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        for cert in self.list_certificates():
            desc = cert.get("desc") or cert.get("display_name") or cert.get("name")
            if desc == name:
                return cert
        return None

    def import_or_replace_certificate(self, name: str, full_cert_pem: str, key_pem: str) -> None:
        """
        Import or replace a certificate in DSM.

        - `name` is the description you see in DSM UI.
        - `full_cert_pem` may contain a chain; we split it into leaf + intermediates.
        """
        # 1) Split leaf vs chain
        leaf_pem, chain_pem = _split_cert_and_chain(full_cert_pem)
        if chain_pem is None:
            raise RuntimeError(
                "Certificate PEM does not contain an intermediate chain; "
                "DSM expects an 'inter_cert' payload."
            )

        # 2) Find existing cert (if any)
        existing = self.find_certificate_by_name(name)
        existing_id = existing["id"] if existing else None

        # 3) Build multipart form
        params = {
            "api": "SYNO.Core.Certificate",
            "method": "import",
            "version": "1",
        }
        if self.dsm.sid:
            params["_sid"] = self.dsm.sid
        if self.dsm.synotoken:
            params["SynoToken"] = self.dsm.synotoken

        data = {
            "desc": name,
        }

        if existing_id:
            data["id"] = existing_id

        files = {
            "key": ("key.pem", key_pem),
            "cert": ("cert.pem", leaf_pem),
            "inter_cert": ("chain.pem", chain_pem),
        }

        resp = self.dsm.session.post(
            self.dsm.url("/webapi/entry.cgi"),
            params=params,
            data=data,
            files=files,
            verify=self.dsm.verify_ssl,
        )
        resp.raise_for_status()
        body = resp.json()

        if not body.get("success"):
            raise RuntimeError(f"DSM cert import failed: {body}")

        action = "Updated" if existing_id else "Created"
        self.logger.info(f"[DSM] {action} certificate '{name}'")

    def assign_to_reverse_proxy_hosts(self, cert_name: str, hostnames: list[str]) -> None:
        """
        Assign the certificate `cert_name` to all ReverseProxy services whose
        display_name matches any of `hostnames`.

        This mirrors what the DSM UI does with SYNO.Core.Certificate.Service/set.
        """
        if not hostnames:
            return

        # 1) Find the target certificate
        target = self.find_certificate_by_name(cert_name)
        if not target:
            raise RuntimeError(f"Certificate '{cert_name}' not found in DSM")
        target_id = target["id"]

        # 2) Build settings by scanning all certs' services
        all_certs = self.list_certificates()
        wanted = set(hostnames)
        settings: list[dict[str, Any]] = []

        for cert in all_certs:
            cert_id = cert["id"]
            for svc in cert.get("services", []):
                if svc.get("subscriber") != "ReverseProxy":
                    continue
                display_name = svc.get("display_name")
                if display_name not in wanted:
                    continue

                # If already bound to the target cert, nothing to do for this one
                if cert_id == target_id:
                    continue

                settings.append(
                    {
                        "service": svc,
                        "old_id": cert_id,
                        "id": target_id,
                    }
                )

        if not settings:
            self.logger.info(f"[DSM] No ReverseProxy service mappings changed for cert '{cert_name}'")
            return

        # 3) Call SYNO.Core.Certificate.Service/set with JSON-encoded settings
        payload = {
            "api": "SYNO.Core.Certificate.Service",
            "method": "set",
            "version": "1",
            "settings": json.dumps(settings),
        }
        resp = self.dsm.post("/webapi/entry.cgi", payload)
        if not resp.get("success"):
            raise RuntimeError(f"DSM Certificate.Service/set failed: {resp}")

        data = resp.get("data", {})
        if data.get("restart_httpd"):
            self.logger.info(
                f"[DSM] Certificate '{cert_name}' assigned to ReverseProxy hosts "
                f"{', '.join(hostnames)} (HTTPD restart requested)"
            )
        else:
            self.logger.info(
                f"[DSM] Certificate '{cert_name}' assigned to ReverseProxy hosts "
                f"{', '.join(hostnames)}"
            )


def _split_cert_and_chain(pem: str) -> tuple[str, str | None]:
    """
    Given a PEM that may contain a full chain, return:
      - leaf cert PEM (first certificate block)
      - chain PEM (all remaining cert blocks) or None if there is no chain.
    """
    blocks: list[list[str]] = []
    current: list[str] = []
    in_block = False

    for line in pem.splitlines():
        if "BEGIN CERTIFICATE" in line:
            in_block = True
            current = [line]
        elif "END CERTIFICATE" in line and in_block:
            current.append(line)
            blocks.append(current)
            in_block = False
            current = []
        elif in_block:
            current.append(line)

    if not blocks:
        # Just return as-is; DSM will error if it really needed a chain
        return pem, None

    def join_block(block: list[str]) -> str:
        # Ensure trailing newline – DSM is picky but tolerant.
        return "\n".join(block) + "\n"

    leaf = join_block(blocks[0])
    rest_blocks = blocks[1:]
    if not rest_blocks:
        return leaf, None

    chain = "".join(join_block(b) for b in rest_blocks)
    return leaf, chain


class DsmReverseProxyClient:
    """
    Minimal wrapper around SYNO.Core.AppPortal.ReverseProxy.

    This mirrors what the DSM UI does:
      POST /webapi/entry.cgi/SYNO.Core.AppPortal.ReverseProxy
      Content-Type: application/x-www-form-urlencoded; charset=UTF-8
    """

    API = "SYNO.Core.AppPortal.ReverseProxy"
    VERSION = 1
    PATH = "/webapi/entry.cgi/SYNO.Core.AppPortal.ReverseProxy"

    def __init__(self, session: "DsmSession", logger: Logger) -> None:
        self.session = session
        self.logger = logger

    # ---------- helpers ----------

    @staticmethod
    def _scheme_to_proto(s: str) -> int:
        # DSM uses 0 = http, 1 = https
        return 1 if s.lower() == "https" else 0

    # ---------- low-level calls ----------

    def _call(self, method: str, **params) -> dict:
        data = {
            "api": self.API,
            "version": self.VERSION,
            "method": method,
            **params,
        }
        self.logger.debug(f"[DSM] Calling {method} with params: {params}")
        resp = self.session.post(self.PATH, data)
        self.logger.debug(f"[DSM] Response: {resp}")
        return resp

    # ---------- public API ----------

    def list_rules(self) -> list[dict]:
        """
        Return raw rule objects as DSM sends them.
        Shape is roughly:

            {
              "UUID": "...",
              "description": "Jellyfin",
              "backend": {"fqdn": "localhost", "port": 8096, "protocol": 0},
              "frontend": {
                  "fqdn": "jellyfin.home.cubiss.cz",
                  "port": 443,
                  "protocol": 1,
                  "https": {"hsts": false},
                  "acl": null
              },
              "customize_headers": [],
              "proxy_connect_timeout": 60,
              "proxy_read_timeout": 60,
              "proxy_send_timeout": 60,
              "proxy_http_version": 1,
              ...
            }
        """
        resp = self._call("list")
        # DSM sometimes uses "entries" or "items" in different builds
        data = resp.get("data", resp)
        return data.get("entries") or data.get("items") or data.get("rules") or []

    def upsert_rule(self, rule: ReverseProxyRule) -> None:
        """
        Create or update a reverse-proxy rule for one hostname.

        Matching criteria: same frontend fqdn, port and protocol.
        """
        existing = None
        for r in self.list_rules():
            try:
                front = r["frontend"]
            except KeyError:
                continue

            if (
                front.get("fqdn") == rule.src_host
                and int(front.get("port", 0)) == int(rule.src_port)
                and int(front.get("protocol", -1)) == self._scheme_to_proto(rule.src_protocol)
            ):
                existing = r
                break

        # Build an "entry" object in the same shape DSM returns.
        entry = {
            # description appears as the name in the UI
            "description": rule.description,
            "backend": {
                "fqdn": rule.dst_host,
                "port": int(rule.dst_port),
                "protocol": self._scheme_to_proto(rule.dst_protocol),
            },
            "frontend": {
                "acl": None,
                "fqdn": rule.src_host,
                "port": int(rule.src_port),
                "protocol": self._scheme_to_proto(rule.src_protocol),
                # DSM stores HTTPS-specific flags here.
                # For plain HTTP frontends DSM just ignores this.
                "https": {
                    "hsts": False,
                },
            },
            "customize_headers": [],
            "enable": bool(rule.enabled),
            # Reasonable timeouts / defaults; tweak if you like.
            "proxy_http_version": 1,
            "proxy_connect_timeout": 60,
            "proxy_read_timeout": 60,
            "proxy_send_timeout": 60,
            "proxy_intercept_errors": False,
        }

        if existing is None:
            # Create new
            payload = {"entry": json.dumps(entry)}
            self._call("create", **payload)
            self.logger.info(f"[DSM] Created reverse-proxy rule for {rule.src_host}:{rule.src_port}")
        else:
            # Update existing – DSM expects UUID to identify the rule
            entry["UUID"] = existing.get("UUID") or existing.get("_key")
            payload = {"entry": json.dumps(entry)}
            self._call("set", **payload)
            self.logger.info(f"[DSM] Updated reverse-proxy rule for {rule.src_host}:{rule.src_port}")
