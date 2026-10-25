# syntax=docker/dockerfile:1
# =============================================================================
# Stage 1: Build & Test daviante-doh (by Daviante - https://daviante.org)
# =============================================================================
FROM rust@sha256:931c2c0531a8b143e044f0f3914dfe802f15bb3d1955f0b657e9359327ac2ffc AS builder

ARG BUILD_TLS=true
ARG RUN_TESTS=true

RUN apk add --no-cache musl-dev pkgconfig

WORKDIR /build

COPY Cargo.toml Cargo.lock LICENSE ./
COPY src ./src
COPY tests ./tests

RUN if [ "$RUN_TESTS" = "true" ]; then \
        cargo test --release --locked; \
    fi && \
    if [ "$BUILD_TLS" = "true" ]; then \
        cargo build --release --locked --bin daviante-doh; \
    else \
        cargo build --release --locked --no-default-features --features cli --bin daviante-doh; \
    fi

# =============================================================================
# Stage 2: Hardened Alpine 3.24 Runtime (Docker / Podman / K8s / OpenShift)
# =============================================================================
FROM alpine@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS runtime

LABEL org.opencontainers.image.title="daviante-doh" \
      org.opencontainers.image.description="Lightweight, 100% configurable DoH (RFC 8484), ODoH (RFC 9230), and JSON DoH server by Daviante (daviante.org)" \
      org.opencontainers.image.vendor="Daviante" \
      org.opencontainers.image.url="https://daviante.org" \
      org.opencontainers.image.source="https://github.com/daviante-org/daviante-doh" \
      org.opencontainers.image.licenses="Apache-2.0"

RUN apk add --no-cache ca-certificates && \
    adduser -D -u 10001 -G root -h /etc/daviante-doh -s /sbin/nologin daviante-doh && \
    mkdir -p /etc/daviante-doh/certs

COPY --from=builder /build/target/release/daviante-doh /usr/local/bin/daviante-doh

# Set compatibility symlinks and GID 0 (g=u) permissions required by
# Red Hat OpenShift restricted-v2 SCC arbitrary UIDs.
RUN chmod 0755 /usr/local/bin/daviante-doh && \
    ln -s /usr/local/bin/daviante-doh /usr/local/bin/doh-server && \
    ln -s /usr/local/bin/daviante-doh /usr/local/bin/doh-proxy && \
    chgrp -R 0 /etc/daviante-doh /usr/local/bin/daviante-doh && \
    chmod -R g=u /etc/daviante-doh

ENV DOH_LISTEN_ADDRESS="0.0.0.0:3000" \
    DOH_SERVER_ADDRESS="9.9.9.9:53" \
    DOH_PATH="/dns-query" \
    DOH_ODOH_CONFIGS_PATH="/.well-known/odohconfigs" \
    DOH_HEALTH_PATH="/healthz" \
    DOH_ENABLE_METRICS="false" \
    DOH_METRICS_PATH="/metrics" \
    DOH_MAX_CLIENTS="512" \
    DOH_MAX_CONCURRENT="16" \
    DOH_MAX_CONNS_PER_IP="0" \
    DOH_TIMEOUT="10" \
    DOH_SHUTDOWN_GRACE_SECS="25" \
    DOH_MIN_TTL="0" \
    DOH_MAX_TTL="604800" \
    DOH_ERR_TTL="2" \
    DOH_STALE_IF_ERROR="86400" \
    DOH_STALE_WHILE_REVALIDATE="60" \
    DOH_CACHE_SIZE="0" \
    DOH_SERVE_STALE_TTL="0" \
    DOH_CACHE_PREFETCH="false" \
    DOH_DISABLE_COALESCING="false" \
    DOH_UPSTREAM_STRATEGY="failover" \
    DOH_DISABLE_ANY="false" \
    DOH_ECS_PREFIX_V4="24" \
    DOH_ECS_PREFIX_V6="56" \
    DOH_ODOH_ROTATION_SECS="86400" \
    DOH_BLOCK_ACTION="nxdomain" \
    DOH_BLOCK_PRIVATE_REBINDING="false" \
    DOH_RATE_LIMIT_RPS="0" \
    DOH_RATE_LIMIT_BURST="20" \
    DOH_RATE_LIMIT_V6_PREFIX="64" \
    DOH_CORS_ALLOW_ORIGIN="*" \
    DOH_LOG_QUERIES="false" \
    DOH_LOG_CLIENT_IP="false" \
    DOH_LOG_FORMAT="json" \
    DOH_LOG_LEVEL="info" \
    DOH_TLS_MIN_VERSION="1.2"

EXPOSE 3000/tcp

USER 10001:0
WORKDIR /etc/daviante-doh

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/daviante-doh", "--healthcheck"]

ENTRYPOINT ["/usr/local/bin/daviante-doh"]
