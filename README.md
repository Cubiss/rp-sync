# rp-sync

Config-driven sync tool for a home lab with a Synology NAS.

`rp-sync` keeps these things in sync:

- **Synology DSM reverse proxy rules** (DSM Control Panel → Login Portal → Reverse Proxy)
- **Internal DNS A records** (via RFC2136 / TSIG updates)
- **TLS certificates from step-ca**
- **Certificate bindings for reverse proxies** (DSM Control Panel → Security → Certificates)

---

## What it does

For every service in `config.yaml`:

1. **DNS**
   - Ensures `A` records for `host` and `aliases` in your internal zone
     (via RFC2136 updates to your DNS server).

2. **Reverse Proxy (DSM)**
   - Creates or updates DSM reverse-proxy rules pointing
     `https://<host>:<port>` → `dest_url` (e.g. `http://localhost:51821`).

3. **TLS via step-ca (optional)**
   - Uses `step ca certificate` to issue a cert for the service
     (with SANs from your config).
   - Imports or updates that cert in DSM (without changing the global default).

4. **Bind cert to reverse proxies**
   - Rebinds the corresponding `ReverseProxy` services in DSM so that
     your `host`/`aliases` use the service’s own certificate.

---

## Configuration

Config path: Taken from (`RP_SYNC_CONFIG_PATH` environment variable).

Example:

```yaml
# /config/config.yaml

dsm:
  # Hostname (or IP) of your Synology NAS
  host: nas.internal.example.com
  port: 5001
  https: true
  # Can be true/false or a path to a CA bundle.
  # In a step-ca setup, this is typically your root CA cert:
  verify_ssl: /certs/ca-root.crt
  username_file: /secrets/dsm_username
  password_file: /secrets/dsm_password

dns:
  # Authoritative DNS server for your internal zone
  server: 10.0.0.10
  port: 53
  zone: home.example.com.
  tsig_key_name: rp-sync.
  tsig_key_secret_file: /secrets/dns_tsig_secret
  tsig_key_algorithm: hmac-sha256

step_ca:
  enabled: true
  ca_url: https://ca.internal.example.com:8443
  root_ca: /certs/ca-root.crt
  provisioner: admin@example.com
  provisioner_password_file: /secrets/step_provisioner_password
  # Lifetime of issued certs in hours (90 days here)
  default_ltl_hours: 2160

services:
  - name: vpn-ui
    host: vpn.home.example.com
    aliases:
      - wg.home.example.com

    # Reverse proxy frontend (what DSM listens on)
    source_port: 443
    source_protocol: https

    # Reverse proxy backend (where the app actually runs)
    dest_url: http://localhost:51821

    # DNS A record to create/update
    dns_a: 10.0.0.5   # IP of your NAS or reverse-proxy host

    # Optional TLS / step-ca integration
    tls:
      use_step_ca: true
      common_name: vpn.home.example.com
      sans:
        - vpn.home.example.com
        - wg.home.example.com
      dsm_cert_name: rp-sync-vpn

  - name: media
    host: media.home.example.com
    aliases: []

    source_port: 443
    source_protocol: https

    # Example: Jellyfin running on the same NAS
    dest_url: http://localhost:8096

    dns_a: 10.0.0.5

    tls:
      use_step_ca: true
      common_name: media.home.example.com
      sans:
        - media.home.example.com
      dsm_cert_name: rp-sync-media
```