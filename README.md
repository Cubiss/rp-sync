# rp-sync

Keeps a Synology DSM reverse proxy, DNS A records, and step-ca TLS certificates in sync from a single declarative config. Run it once or as a daemon — it watches for config changes and re-syncs automatically.

## Requirements

- Python 3.11+
- [step CLI](https://smallstep.com/docs/step-cli/) in `PATH` (only required if cert management is enabled)
- A Synology NAS with DSM 7+ and the reverse proxy feature enabled
- A step-ca instance (optional, for automatic TLS certificates)
- A DNS server supporting RFC 2136 dynamic updates (optional, for automatic A records)

## Installation

```sh
pip install .
```

## Usage

```sh
# Run a single sync and exit
rp-sync sync

# Run as a daemon — re-syncs when config or service files change,
# and again before each certificate expires
rp-sync daemon
```

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `RP_SYNC_CONFIG_PATH` | `./config.yaml` | Path to the root config file |
| `RP_SYNC_SERVICES_PATH` | `./services/` | Path to service files (file or directory) |
| `RP_SYNC_WATCH_INTERVAL_SEC` | `5` | How often the daemon polls for config changes |
| `RP_SYNC_LOG_DIR` | `./logs/` | Directory for log files |
| `RP_SYNC_LOG_KEEP` | `10` | Number of log files to keep |
| `RP_SYNC_LOG_LEVEL` | `INFO` | Log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `RP_SYNC_HEALTH_FILE` | `/tmp/rp-sync-health` | Touched on each successful sync (useful for health checks) |

---

## Configuration

### `config.yaml`

```yaml
# ---------------------------------------------------------------------------
# DSM connection (required)
# ---------------------------------------------------------------------------
dsm:
  host: nas.example.com     # DSM hostname or IP
  port: 5001                # DSM API port; default: 5001
  https: true               # use HTTPS; default: true
  verify_ssl: true          # true/false, or path to a CA cert file to trust
  username_file: ./secrets/dsm_username   # file containing the DSM username
  password_file: ./secrets/dsm_password   # file containing the DSM password

# ---------------------------------------------------------------------------
# DNS zones (required)
# Supports multiple zones. rp-sync picks the most specific matching zone
# when creating A records for a service hostname.
# ---------------------------------------------------------------------------
dns:
  - zone: example.com.              # zone name — trailing dot required
    server: 10.0.0.1:53             # DNS server; port is optional (default: 53)
    tsig_key_file: ./secrets/rp-sync.key  # TSIG key for authenticated updates (optional)

  - zone: internal.example.com.
    server: 10.0.0.2

# ---------------------------------------------------------------------------
# TLS certificate management via step-ca (optional)
# When enabled, rp-sync issues and renews certificates automatically and
# assigns them to the matching reverse proxy rules in DSM.
# ---------------------------------------------------------------------------
certs:
  disabled: false           # set true to disable all cert management; default: false

  ca_url: https://ca.example.com:8443   # step-ca server URL
  root_ca: ./secrets/root_ca.crt        # CA trust anchor passed to the step CLI (optional)
  ca_fingerprint: ""                    # root CA fingerprint; alternative to root_ca (optional)

  provisioner: admin@example.com        # JWK provisioner name
  provisioner_password_file: ./secrets/step_provisioner_password

  default_ltl_hours: 2160   # requested certificate lifetime in hours; default: 2160 (90 days)
  renew_before_hours: 168   # renew when expiry is within this many hours; default: 168 (7 days)

# ---------------------------------------------------------------------------
# Internal redirect backend (optional)
# A lightweight HTTP server that rp-sync runs locally. DSM forwards alias
# hostnames and plain-HTTP traffic to it; it responds with 301 redirects
# to the canonical HTTPS hostname.
# ---------------------------------------------------------------------------
redirect:
  enabled: true           # default: true
  bind_host: 127.0.0.1   # address the redirect server binds to
  port: 18080             # port the redirect server listens on; default: 18080
  backend_host:           # address DSM uses to reach the redirect server;
                          # defaults to bind_host if omitted
```

---

### Service files (`services/*.service`)

Service files are YAML files with a `.service` extension placed in the
`./services/` directory (override with `RP_SYNC_SERVICES_PATH`). The directory
is scanned recursively. Each file contains a list of service definitions.

```yaml
- name: myapp               # unique service name; used in cert names (rp-sync-<name>) and logs
                            # (required)

  host: myapp.example.com   # canonical FQDN (required)
                            # traffic hitting this hostname is proxied directly to dest_url

  aliases:                  # additional FQDNs (optional)
    - myapp                 # each alias redirects (HTTP 301) to `host` rather than proxying directly
    - myapp.internal        # useful for short names or legacy hostnames

  dest_url: http://localhost:8080   # backend URL to proxy to (required)
                                    # supports http:// and https://

  source_port: 443          # port DSM listens on for this service (required)
  source_protocol: https    # protocol DSM listens on: https or http (required)

  dns_a: 10.0.0.5           # if set, an A record is created for `host` and every alias (optional)

  custom_headers:           # headers injected by DSM into requests to the backend (optional)
    X-Forwarded-Proto: https
    X-Custom-Header: value
```

#### `host` vs `aliases`

`host` is the **canonical hostname** — DSM proxies traffic directly to `dest_url`.

`aliases` are **redirect hostnames** — DSM forwards them to the internal redirect backend, which issues a 301 to `host`. The client ends up at the canonical URL before reaching the backend.

Both `host` and all `aliases` receive the same treatment for DNS, TLS, and HTTP→HTTPS redirects:

| | `host` | `aliases` |
|---|---|---|
| DSM reverse proxy rule | proxies directly to `dest_url` | 301 redirect to `host` |
| TLS certificate | used as CN | included as SANs |
| DNS A record | created (if `dns_a` set) | created (if `dns_a` set) |
| HTTP→HTTPS redirect rule | created (if `source_protocol: https`) | created (if `source_protocol: https`) |

#### Full example

```yaml
- name: zitadel
  host: zitadel.example.com  # canonical — DSM proxies :443 directly to localhost:8080
  aliases:
    - zitadel                 # short name — DSM redirects :443 → 301 to zitadel.example.com
  source_port: 443
  source_protocol: https
  dest_url: http://localhost:8080
  dns_a: 10.23.0.5            # creates A records: zitadel.example.com → 10.23.0.5
                              #                     zitadel            → 10.23.0.5
  custom_headers:
    X-Forwarded-Proto: https  # tell the backend it was reached over HTTPS

- name: grafana
  host: grafana.example.com
  source_port: 443
  source_protocol: https
  dest_url: http://localhost:3000
  dns_a: 10.23.0.5
```
