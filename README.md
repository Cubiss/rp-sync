# rp-sync

Keeps nginx reverse proxy rules, DNS A records, and step-ca TLS certificates in sync from a single declarative config. Run it once or as a daemon — it watches for config changes and re-syncs automatically.

## Architecture

Two containers share a named volume for nginx config; certificates use a bind mount:

```
rp-sync container          nginx container
─────────────────          ───────────────
reads service files  ───►  serves traffic on :80 / :443
writes nginx.conf    ───►  inotifywait detects change → nginx -s reload
writes certs/        ───►  reads certs directly
updates DNS records
renews TLS certs
```

rp-sync runs on a normal bridge network (outbound only). Only the nginx container uses `network_mode: host` to bind ports 80 and 443.

## Requirements

- Docker with Compose
- [step CLI](https://smallstep.com/docs/step-cli/) in `PATH` inside the rp-sync container (only required if cert management is enabled)
- A step-ca instance (optional, for automatic TLS certificates)
- A DNS server supporting RFC 2136 dynamic updates (optional, for automatic A records)

## Usage

```sh
docker compose up -d
```

### Commands

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
| `RP_SYNC_HEALTH_FILE` | `/tmp/rp-sync-health` | Written on each sync (`healthy` / `unhealthy`) |

---

## Configuration

### `config.yaml`

```yaml
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
# writes them to the certs volume for nginx to read.
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
# Nginx config output (optional — shown with defaults)
# Both paths must match the volumes mounted in docker-compose.yml.
# ---------------------------------------------------------------------------
nginx:
  conf_dir: /etc/nginx/conf.d   # directory where nginx configs are written
  certs_dir: /certs             # root dir for certs; each service gets a subdir
  cleanup: true                 # delete orphaned managed configs on sync;
                                # set false to preserve all configs (useful for testing)
  prefix: rp-sync              # filename prefix for generated configs ({prefix}-{service}.conf);
                                # change when running multiple instances against the same conf_dir

# ---------------------------------------------------------------------------
# Access control profiles (optional)
# Define named IP allowlists. Profiles are referenced by services and applied
# as nginx allow/deny directives.
# ---------------------------------------------------------------------------
access_control_profiles:
  - name: local-only
    rules:
      - address: 10.0.0.0/8
        allow: true

# Apply a profile to all services that don't specify one explicitly (optional)
default_access_control_profile: local-only
```

---

### Service files (`services/*.service`)

Service files are YAML files with a `.service` extension placed in the
`./services/` directory (override with `RP_SYNC_SERVICES_PATH`). The directory
is scanned recursively. Each file contains a list of service definitions.

```yaml
- name: myapp               # unique service name; used in cert paths and logs (required)

  host: myapp.example.com   # canonical FQDN (required)
                            # traffic hitting this hostname is proxied to dest_url

  aliases:                  # additional FQDNs (optional)
    - myapp                 # each alias redirects (308) to `host`
    - myapp.internal        # useful for short names or legacy hostnames

  dest_url: http://localhost:8080   # backend URL to proxy to (required)
                                    # supports http:// and https://

  source_port: 443          # port nginx listens on for this service (required)
  source_protocol: https    # protocol: https or http (required)

  dns_a: 10.0.0.5           # if set, an A record is created for `host` and every alias (optional)

  access_control_profile: local-only   # override the default profile for this service (optional)

  custom_headers:           # extra headers injected into requests to the backend (optional)
    X-Forwarded-Proto: https
    X-Custom-Header: value
```

#### `host` vs `aliases`

`host` is the **canonical hostname** — nginx proxies traffic directly to `dest_url`.

`aliases` are **redirect hostnames** — nginx issues a 308 redirect to `host`. The client ends up at the canonical URL before reaching the backend.

| | `host` | `aliases` |
|---|---|---|
| nginx rule | proxies to `dest_url` | 308 redirect to `host` |
| TLS certificate | used as CN | included as SANs |
| DNS A record | created (if `dns_a` set) | created (if `dns_a` set) |
| HTTP→HTTPS redirect | created (if `source_protocol: https`) | created (if `source_protocol: https`) |
| Access control | applied | not applied (redirect only) |

#### Full example

```yaml
- name: zitadel
  host: zitadel.example.com
  aliases:
    - zitadel
  source_port: 443
  source_protocol: https
  dest_url: http://localhost:8080
  dns_a: 10.23.0.5
  custom_headers:
    X-Forwarded-Proto: https

- name: grafana
  host: grafana.example.com
  source_port: 443
  source_protocol: https
  dest_url: http://localhost:3000
  dns_a: 10.23.0.5
  access_control_profile: local-only   # explicit override
```

---

## Certificates

Certificates are stored at `{certs_dir}/{service_name}/cert.pem` and `key.pem`. They are issued by step-ca and renewed automatically within `renew_before_hours` of expiry and on alias changes.

## nginx config

rp-sync writes one config file per service into `nginx.conf_dir`:

```
rp-sync-global.conf       ← SSL session settings, always present
rp-sync-jellyfin.conf     ← managed by rp-sync
rp-sync-wireguard-ui.conf ← managed by rp-sync
extra.conf                ← manually placed, never touched by rp-sync
```

When `cleanup: true`, rp-sync deletes any `{prefix}-*.conf` file in `conf_dir` that no longer corresponds to a known service. Files outside the prefix are never touched, so multiple instances can safely share the same `conf_dir` with distinct prefixes.

Files are written atomically (temp file + rename) so nginx never reads a partial config. nginx reloads automatically via `inotifywait` in the nginx container's entrypoint on each write.

A failed `nginx -t` check keeps the previous config in place and logs an error.

## nginx logs

Access and error logs are written to `/var/log/nginx/` inside the nginx container, bind-mounted to `/volume1/docker/rp-sync/logs/nginx/` on the host.
