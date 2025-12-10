# Dockerfile for rp-sync

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Default config path inside the container
ENV RP_SYNC_CONFIG_PATH=/config/config.yaml

# Install step-cli and minimal tooling
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

# Run the installed module's CLI
CMD ["rp-sync"]
