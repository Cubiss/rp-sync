#!/bin/sh
set -e

CONF_D="${NGINX_CONF_DIR:-/etc/nginx/conf.d}"

nginx

inotifywait -m -e close_write,moved_to "$CONF_D" | while read -r _ _ _; do
    echo "[entrypoint] Config change detected — testing..."
    if nginx -t 2>&1; then
        echo "[entrypoint] Config OK — reloading nginx"
        nginx -s reload
    else
        echo "[entrypoint] Config test FAILED — keeping current config"
    fi
done
