import os
import yaml
import requests
from urllib.parse import urljoin
from dns import update, query, tsigkeyring, rdatatype, rdataclass, name as dnsname

CONFIG_PATH = os.environ.get("CONFIG_PATH", "/config/config.yaml")


class DSMClient:
    def __init__(self, host, port, username, password, https=True, verify_ssl=True):
        self.base = f"{'https' if https else 'http'}://{host}:{port}"
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.sid = None

    def api(self, api, method="get", version=1, **params):
        """Generic DSM WebAPI call via /webapi/entry.cgi"""
        url = urljoin(self.base, "/webapi/entry.cgi")
        payload = {
            "api": api,
            "version": version,
            "method": method,
            **params,
        }
        # SID is passed in cookies after login
        resp = self.session.get(url, params=payload, verify=self.verify_ssl)
        resp.raise_for_status()
        data = resp.json()
        if not data.get("success", False):
            raise RuntimeError(f"DSM API error for {api}/{method}: {data}")
        return data.get("data", {})

    def login(self):
        info = self.session.get(
            urljoin(self.base, "/webapi/query.cgi"),
            params={
                "api": "SYNO.API.Info",
                "version": "1",
                "method": "query",
                "query": "SYNO.API.Auth",
            },
            verify=self.verify_ssl,
        ).json()
        auth_path = info["data"]["SYNO.API.Auth"]["path"]

        resp = self.session.get(
            urljoin(self.base, f"/webapi/{auth_path}"),
            params={
                "api": "SYNO.API.Auth",
                "version": "7",
                "method": "login",
                "account": self.username,
                "passwd": self.password,
                "session": "core",
                "format": "sid",
            },
            verify=self.verify_ssl,
        )
        resp.raise_for_status()
        data = resp.json()
        if not data.get("success"):
            raise RuntimeError(f"DSM login failed: {data}")
        self.sid = data["data"]["sid"]
        # cookie is stored in session automatically

    # --- Reverse proxy helpers ---

    def list_reverse_proxy(self):
        # API name comes from DSM API list: SYNO.Core.AppPortal.ReverseProxy :contentReference[oaicite:2]{index=2}
        data = self.api("SYNO.Core.AppPortal.ReverseProxy", "list", version=1)
        # Structure depends on DSM; typically something like data["rules"]
        return data.get("rules", data)

    def create_or_update_reverse_proxy(self, svc):
        """
        svc: dict with keys:
          name, host, source_port, source_protocol, dest_url
        """
        current = self.list_reverse_proxy()

        # Find existing rule by hostname+port (adjust if you want to match by name)
        existing = None
        for rule in current:
            if (
                rule.get("host") == svc["host"]
                and rule.get("src_port") == svc["source_port"]
                and rule.get("src_protocol").lower()
                == svc["source_protocol"].lower()
            ):
                existing = rule
                break

        params = {
            "description": svc["name"],
            "host": svc["host"],
            "src_port": svc["source_port"],
            "src_protocol": svc["source_protocol"].upper(),
            "dst_host": svc["dest_host"],
            "dst_port": svc["dest_port"],
            "dst_protocol": svc["dest_protocol"].upper(),
            "enable": True,
        }

        if existing:
            params["id"] = existing["id"]
            self.api("SYNO.Core.AppPortal.ReverseProxy", "set", version=1, **params)
            print(f"Updated reverse proxy rule for {svc['host']}")
        else:
            self.api("SYNO.Core.AppPortal.ReverseProxy", "create", version=1, **params)
            print(f"Created reverse proxy rule for {svc['host']}")


def parse_dest_url(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        raise ValueError("dest_url must start with http:// or https://")
    proto, rest = url.split("://", 1)
    if ":" in rest:
        host, port_str = rest.rsplit(":", 1)
        port = int(port_str)
    else:
        host = rest
        port = 443 if proto == "https" else 80
    return proto, host, port


def ensure_dns_a_record(cfg_dns, hostname, ip):
    # Build TSIG keyring for RFC2136 updates
    keyring = tsigkeyring.from_text(
        {cfg_dns["tsig_key_name"]: cfg_dns["tsig_key_secret"]}
    )

    zone = dnsname.from_text(cfg_dns["zone"])
    fqdn = dnsname.from_text(hostname)

    update_msg = update.Update(zone, keyring=keyring, keyalgorithm=cfg_dns["tsig_key_algorithm"])
    # Delete any existing A records for this name, then add the one we want
    update_msg.replace(fqdn, 300, rdatatype.A, ip)

    response = query.tcp(update_msg, cfg_dns["server"], port=cfg_dns.get("port", 53))
    rcode = response.rcode()
    if rcode != 0:
        raise RuntimeError(f"DNS update failed for {hostname}: rcode={rcode}")
    print(f"DNS A {hostname} -> {ip} ensured")


def main():
    with open(CONFIG_PATH, "r") as f:
        cfg = yaml.safe_load(f)

    dsm_cfg = cfg["dsm"]
    dns_cfg = cfg["dns"]
    services = cfg["services"]

    dsm = DSMClient(
        dsm_cfg["host"],
        dsm_cfg.get("port", 5001),
        dsm_cfg["username"],
        dsm_cfg["password"],
        https=dsm_cfg.get("https", True),
        verify_ssl=dsm_cfg.get("verify_ssl", True),
    )
    dsm.login()

    for svc in services:
        proto, dst_host, dst_port = parse_dest_url(svc["dest_url"])

        all_hosts = [svc["host"]] + svc.get("aliases", [])

        for hostname in all_hosts:
            svc_internal = {
                "name": f"{svc['name']} ({hostname})",
                "host": hostname,
                "source_port": svc["source_port"],
                "source_protocol": svc["source_protocol"],
                "dest_host": dst_host,
                "dest_port": dst_port,
                "dest_protocol": proto,
            }

            # 1) one RP rule per hostname
            dsm.create_or_update_reverse_proxy(svc_internal)

            # 2) one A record per hostname
            if "dns_a" in svc:
                ensure_dns_a_record(dns_cfg, hostname, svc["dns_a"])

if __name__ == "__main__":
    main()
