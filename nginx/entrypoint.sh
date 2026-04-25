#!/bin/sh
set -e

NGINX_DIR="${NGINX_CONF_DIR:-/etc/nginx}"
CONF_FILE="$NGINX_DIR/nginx.conf"
CONF_D="$NGINX_DIR/conf.d"

mkdir -p "$CONF_D"

if [ ! -f "$NGINX_DIR/mime.types" ]; then
    echo "[entrypoint] mime.types not found — copying default"
    cp /mime.types.default "$NGINX_DIR/mime.types"
fi

if [ ! -f "$CONF_FILE" ]; then
    echo "[entrypoint] nginx.conf not found — writing default"
    cat > "$CONF_FILE" <<'EOF'
worker_processes auto;

events {
    worker_connections 1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;
    sendfile      on;

    access_log /var/log/nginx/access.log;
    error_log  /var/log/nginx/error.log warn;

    include /etc/nginx/conf.d/*.conf;
}
EOF
fi

nginx -c "$CONF_FILE"

inotifywait -m -e close_write,moved_to "$CONF_D" | while read -r _ _ _; do
    echo "[entrypoint] Config change detected — testing..."
    if nginx -t 2>&1; then
        echo "[entrypoint] Config OK — reloading nginx"
        nginx -s reload
    else
        echo "[entrypoint] Config test FAILED — keeping current config"
    fi
done
