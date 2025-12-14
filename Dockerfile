FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1


ENV RP_SYNC_LOG_DIR=/logs/ \
    RP_SYNC_LOG_KEEP=10 \
    RP_SYNC_LOG_LEVEL=INFO \
    RP_SYNC_CONFIG_PATH=/config/config.yaml \
    RP_SYNC_SERVICES_PATH=/services/ \
    RP_SYNC_HEALTH_FILE=/tmp/rp-sync-health \
    RP_SYNC_WATCH_INTERVAL_SEC=5.0

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        gnupg && \
    curl -fsSL https://packages.smallstep.com/keys/apt/repo-signing-key.gpg \
        -o /etc/apt/trusted.gpg.d/smallstep.asc && \
    echo "deb [signed-by=/etc/apt/trusted.gpg.d/smallstep.asc] https://packages.smallstep.com/stable/debian debs main" \
        > /etc/apt/sources.list.d/smallstep.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends step-cli && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml ./
COPY rp_sync ./rp_sync
RUN pip install --no-cache-dir .


VOLUME ["/config", "/secrets", "/certs", "/logs"]

CMD ["rp-sync", "--watch"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD test -f "$RP_SYNC_HEALTH_FILE" \
   && head -n1 "$RP_SYNC_HEALTH_FILE" | grep -qx "healthy"
