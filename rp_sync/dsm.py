from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import requests

from .logging_utils import Logger
from .models import DsmConfig, ReverseProxyRule


def _read_secret(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()


def _to_utc_datetime_from_unix_timestamp(ts: float) -> datetime:
    """Convert seconds (or milliseconds) since epoch to an aware UTC datetime."""
    if ts > 10_000_000_000:
        ts = ts / 1000.0
    return datetime.fromtimestamp(ts, tz=timezone.utc)


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
        self.synotoken = d.get("synotoken") or d.get("SynoToken")

        if not self.synotoken:
            raise RuntimeError("DSM login did not return synotoken; cannot call core APIs")

        self.session.headers.update(
            {
                "X-SYNO-TOKEN": self.synotoken,
                "X-Requested-With": "XMLHttpRequest",
            }
        )

    def _auth_params(self) -> dict[str, str]:
        params: dict[str, str] = {}
        if self.sid:
            params["_sid"] = self.sid
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

    def _parse_expiry_dt(self, cert: Dict[str, Any]) -> Optional[datetime]:
        keys = (
            "valid_till",
            "valid_to",
            "valid_until",
            "not_after",
            "notAfter",
            "expire_time",
            "expiry",
        )
        desc = (
            cert.get("desc") or cert.get("display_name") or cert.get("name") or cert.get("id") or "unknown"
        )

        for key in keys:
            v = cert.get(key)
            if v is None:
                continue

            if isinstance(v, (int, float)):
                return _to_utc_datetime_from_unix_timestamp(float(v))

            if isinstance(v, str):
                s = v.strip()
                if not s:
                    continue

                if re.fullmatch(r"\d+", s):
                    return _to_utc_datetime_from_unix_timestamp(float(s))

                s_iso = s.replace("Z", "+00:00")
                if re.match(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", s_iso):
                    s_iso = s_iso.replace(" ", "T", 1)

                try:
                    dt = datetime.fromisoformat(s_iso)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt.astimezone(timezone.utc)
                except Exception:
                    pass

                m = re.match(
                    r"^(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<hms>\d{2}:\d{2}:\d{2})\s+(?P<year>\d{4})(?:\s+(?P<tz>[A-Za-z]{3,4}))?$",
                    s,
                )
                if m:
                    tz = (m.group("tz") or "").upper()
                    base = f"{m.group('mon')} {m.group('day')} {m.group('hms')} {m.group('year')}"
                    try:
                        dt = datetime.strptime(base, "%b %d %H:%M:%S %Y")
                        if tz in ("GMT", "UTC", ""):
                            return dt.replace(tzinfo=timezone.utc)
                    except Exception:
                        pass

                self.logger.debug(f"[DSM] Failed to parse cert expiry for {desc}: {key}={s!r}")

        return None

    def expires_within_hours(self, cert: Dict[str, Any], hours: int) -> bool:
        if cert.get("is_valid") is False:
            return True

        dt = self._parse_expiry_dt(cert)
        if dt is None:
            self.logger.warning(f"No expiry date for cert {cert}")
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
        leaf_pem, chain_pem = _split_cert_and_chain(full_cert_pem)
        if chain_pem is None:
            raise RuntimeError(
                "Certificate PEM does not contain an intermediate chain; "
                "DSM expects an 'inter_cert' payload."
            )

        existing = self.find_certificate_by_name(name)
        existing_id = existing["id"] if existing else None

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

        target = self.find_certificate_by_name(cert_name)
        if not target:
            raise RuntimeError(f"Certificate '{cert_name}' not found in DSM")
        target_id = target["id"]

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
        return pem, None

    def join_block(block: list[str]) -> str:
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

    @staticmethod
    def _scheme_to_proto(s: str) -> int:
        v = s.lower()
        if v == "http":
            return 0
        if v == "https":
            return 1
        raise ValueError(f"Unsupported protocol: {s!r}")

    def _call(self, method: str, **params) -> dict:
        data = {
            "api": self.API,
            "version": self.VERSION,
            "method": method,
            **params,
        }
        self.logger.debug(f"[DSM] Calling {self.PATH}/{method} with params: {params}")
        resp = self.session.post(self.PATH, data)
        self.logger.debug(f"[DSM] Response: {json.dumps(resp)}")
        return resp

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
        data = resp.get("data") or resp
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

        entry = {
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
                "https": {
                    "hsts": False,
                },
            },
            "customize_headers": [],
            "enable": bool(rule.enabled),
            "proxy_http_version": 1,
            "proxy_connect_timeout": 60,
            "proxy_read_timeout": 60,
            "proxy_send_timeout": 60,
            "proxy_intercept_errors": False,
        }

        if existing is None:
            payload = {"entry": json.dumps(entry)}
            resp = self._call("create", **payload)
            action = "Created"
        else:
            entry["UUID"] = existing.get("UUID") or existing.get("_key")
            payload = {"entry": json.dumps(entry)}
            resp = self._call("update", **payload)
            action = "Updated"

        if not resp.get("success"):
            raise RuntimeError(f"DSM ReverseProxy/set failed: {resp}")
        self.logger.info(f"[DSM] {action} reverse-proxy rule for {rule.src_host}:{rule.src_port}")
