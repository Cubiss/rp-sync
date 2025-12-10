# rp-sync

Config-driven sync tool for a home lab with a Synology NAS.

`rp-sync` keeps these things in sync:

- **Synology DSM reverse proxy rules**  
  (DSM Control Panel → Login Portal → Reverse Proxy)
- **Internal DNS A records**  
  (via RFC2136 / TSIG updates)
- **TLS certificates from step-ca**
- **Certificate bindings for reverse proxies**  
  (DSM Control Panel → Security → Certificates)

---

## What it does

For every service in `config.yaml`:

1. **DNS**
   - Ensures `A` records for `host` and all `aliases` exist in your internal zone
     using RFC2136 dynamic updates (TSIG-signed).

2. **Reverse Proxy (DSM)**
   - Creates or updates DSM reverse-proxy rules pointing  
     `https://<host>:<port>` → `dest_url`  
     e.g. `https://vpn.home.example.net:443` → `http://localhost:51821`.

3. **TLS via step-ca (optional, global)**
   - If certificates are enabled *and* `source_protocol: https`:
     - Calls `step ca certificate` to issue a certificate with:
       - **Common name:** `service.host`
       - **SANs:** `service.host` + all `aliases`
     - Imports or updates that certificate in DSM as  
       `rp-sync-<service-name>`.
   - The global default DSM certificate is **never** changed.

4. **Bind cert to reverse proxies**
   - Rebinds the relevant `ReverseProxy` services in DSM so that each
     `host` / `alias` uses the matching `rp-sync-<service-name>` cert.

---

## Configuration

Config path is taken from the `RP_SYNC_CONFIG_PATH` environment variable.  
If not set, the watcher uses `./config.yaml` by default; the Docker image
is usually run with `/config/config.yaml`.

### Example config

```yaml
# /config/config.yaml

dsm:
  # Hostname (or IP) of your Synology NAS
  host: nas.internal.example.net
  port: 5001
  https: true

  # Can be:
  #   - true/false (use system CAs / disable verification)
  #   - a path to a CA bundle (e.g. your step-ca root)
  verify_ssl: /certs/ca-root.crt

  # These are read from files so you don't bake secrets into the image
  username_file: /secrets/dsm_username
  password_file: /secrets/dsm_password

dns:
  # Authoritative DNS server for your internal zone
  server: 10.0.0.10
  port: 53
  zone: home.example.net.          # note the trailing dot

  # BIND-style TSIG key file, e.g.:
  #   key "rp-sync." {
  #     algorithm hmac-sha256;
  #     secret "base64...";
  #   };
  #
  # Synology DNS exports keys in this format
  tsig_key_file: /secrets/rp-sync.key

certs:
  # Global on/off switch. When disabled:
  #   - No calls to step-ca are made
  #   - No certificates are imported/bound in DSM
  disabled: false

  # step-ca URL (your internal CA)
  ca_url: https://ca.internal.example.net:8443

  # Optional fingerprint (can be left empty if you just trust root_ca)
  ca_fingerprint: ""

  # JWK provisioner used to issue certs
  provisioner: admin@example.net
  provisioner_password_file: /secrets/step_provisioner_password

  # Lifetime of issued certs in hours (90 days here)
  default_ltl_hours: 2160

  # Root or intermediate CA used to verify the CA (and for DSM trust)
  root_ca: /certs/ca-root.crt

logging:
  # Where rotated logs are stored inside the container
  log_dir: /logs/

  # How many old log files to keep
  log_keep: 10

services:
  - name: vpn-ui
    host: vpn.home.example.net
    aliases:
      - wg.home.example.net
      - wireguard.home.example.net

    # Reverse proxy frontend (what DSM listens on)
    source_port: 443
    source_protocol: https

    # Reverse proxy backend (where the app actually runs)
    dest_url: http://localhost:51821

    # DNS A record to create/update
    dns_a: 10.0.0.5   # IP of your NAS or reverse-proxy host

  - name: media
    host: media.home.example.net
    aliases:
      - jellyfin.home.example.net
      - tv.home.example.net

    source_port: 443
    source_protocol: https

    # Example: Jellyfin running on the same NAS
    dest_url: http://localhost:8096
    dns_a: 10.0.0.5
