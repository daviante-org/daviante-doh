# daviante-doh — Lightweight DoH, ODoH & Enterprise Protective DNS Library and Server

Developed and maintained by **Daviante** (<https://daviante.org> | <https://github.com/daviante-org/daviante-doh>).

`daviante-doh` is a clean-room, ultra-lightweight, zero-telemetry Rust library (`src/lib.rs`) and server (`src/main.rs`) implementing **DNS-over-HTTPS (RFC 8484)**, **Oblivious DoH (RFC 9230)**, **EDNS0 Padding & Client Subnet (RFC 6891, RFC 7830, RFC 7871, RFC 8467)**, **Extended DNS Errors (RFC 8914)**, **Protective DNS Enterprise Policy**, and the **DNS JSON API (`application/dns-json`, RFC 3597)**.

It is packaged as a hardened, rootless `alpine:3.21` container image (`~10 MiB`, zero shell/curl runtime dependencies) and a unified **Helm Chart (`charts/daviante-doh/`)** compatible out-of-the-box with **Docker**, **Podman**, **Kubernetes**, and **Red Hat OpenShift (`restricted-v2` SCC)**.

---

## Package Layout

- **[`src/`](src/)**: Pure production Rust library (`src/lib.rs`, `#![forbid(unsafe_code)]`, `#![deny(clippy::unwrap_used)]`) and binary entrypoint (`src/main.rs` + `src/cli.rs` behind the `cli` feature).
- **[`tests/`](tests/)**: Segregated integration tests (`tests/integration.rs`) and module-by-module unit tests (`tests/unit/`).
- **[`charts/daviante-doh/`](charts/daviante-doh/)**: Unified Kubernetes & Red Hat OpenShift Helm chart with `ServiceAccount`, `NetworkPolicy`, `ServiceMonitor`, mountable policy `ConfigMap`, and `values.schema.json`.
- **[`scripts/e2e/`](scripts/e2e/)**: Automated container and Helm ConfigMap end-to-end verification suite.

---

## Features & World Standards Compliance

- **RFC 8484 & RFC 9111 (Strict DoH Wire, Header & Cache-Control Compliance)**:
  - Supports `GET` (`?dns=<base64url-unpadded>`), `POST` (`application/dns-message`), and `HEAD` (`414 URI Too Long` when URI exceeds `2048` bytes).
  - Enforces `QR == 0` (Query), `OPCODE == 0`, `QDCOUNT == 1`, `ANCOUNT == 0`, `NSCOUNT == 0`, and rejects `AXFR`/`IXFR` zone-transfer meta-queries.
  - Strict `Cache-Control` and `Age` alignment where HTTP freshness (`s-maxage` / `max-age`) never exceeds Answer RR TTL (`min_ttl` defaults to `0`), `TTL == 0` responses emit `max-age=0, no-cache, no-store`, and header-dependent errors (`405`/`406`/`415`) emit `Cache-Control: no-store` + `Vary: Accept, Content-Type`.
- **RFC 5452, RFC 7766 & Multi-Upstream Circuit Breaker**:
  - Randomizes outbound 16-bit DNS transaction IDs (`TXID`) on a connected UDP socket, verifies `TXID`, `QR == 1`, and Question section match in a bounded read loop (ignoring spoofed datagrams), and restores the client's original ID and `0x20` Question casing.
  - Supports comma-separated multiple upstream resolvers (`9.9.9.9:53,1.1.1.1:53`) with a 30-second per-upstream circuit breaker, persistent RFC 7766 §6.2.1 TCP connection pool (`65,535`-byte buffer), and UDP-to-TCP fallback on `TC=1` (Truncated).
- **RFC 7830, RFC 8467 & RFC 6891 (EDNS0 Hygiene & 468-Byte Block Padding)**:
  - Never injects `OPT` records into responses for non-EDNS (`DO=0`, no client `OPT`) clients.
  - Pads DNS responses with EDNS0 Option Code 12 (`0x00` octets) to **468-byte** block multiples per RFC 8467 §4.1 when the client sent an EDNS Padding option.
- **RFC 7871 (EDNS Client Subnet & Trusted Proxy Verification)**:
  - Evaluates `X-Forwarded-For` and `Forwarded` **right-to-left** only when the TCP peer is inside `--trusted-proxies` (`DOH_TRUSTED_PROXIES`), preserves client-supplied ECS options (`Cache-Control: private, no-store`), enforces §7.1.2 non-leakage of private addresses, and masks IPv4 (`/24` default) and IPv6 (`/56` default) prefixes.
- **RFC 9230 (Oblivious DoH - ODoH)**:
  - Enforces `POST`-only (`405 Method Not Allowed` on `GET`/`HEAD`), pads ODoH plaintext responses to 468-byte blocks, emits `Cache-Control: no-store` on all success and error responses, and serves `GET /.well-known/odohconfigs` with `max-age = rotation / 2` and a lock-free 2-key rotation grace ring (`[current, previous]`).
- **RFC 8914 (Extended DNS Errors) & Protective DNS Policy**:
  - Fail-closed startup loader for `--allowlist-file` and `--blocklist-file` (`nxdomain` + `EDE 15`, `refused` + `EDE 18`, or `zero-ip` + `EDE 17`), inspecting both QNAME and upstream Answer CNAME/DNAME target chains.

---

## Configuration Reference (100% Configurable via Env or CLI)

All optional enterprise features are **off by default** unless explicitly enabled:

| Environment Variable | CLI Flag | Default | Description |
| :--- | :--- | :--- | :--- |
| `DOH_LISTEN_ADDRESS` | `-l, --listen-address` | `0.0.0.0:3000` | Socket address to listen on (`IP:port`) |
| `DOH_ADMIN_LISTEN_ADDRESS` | `--admin-listen-address` | *(disabled)* | Optional isolated listener for `/metrics`, `/livez`, `/readyz`, `/healthz` |
| `DOH_SERVER_ADDRESS` | `-u, --server-address` | `9.9.9.9:53` | Upstream UDP/TCP DNS resolver(s), comma-separated for failover |
| `DOH_LOCAL_BIND_ADDRESS` | `-b, --local-bind-address` | *(auto)* | Local outbound bind address (`0.0.0.0:0` or `[::]:0`) |
| `DOH_HOSTNAME` | `-H, --hostname` | *(optional)* | Public hostname (generates DoH & ODoH DNS stamps on startup) |
| `DOH_PUBLIC_ADDRESS` | `-g, --public-address` | *(optional)* | Comma/space-separated list of public IPs for DNS stamps |
| `DOH_PUBLIC_PORT` | `-j, --public-port` | *(optional)* | External public port if not `443` |
| `DOH_PATH` | `-p, --path` | `/dns-query` | DoH endpoint URI path |
| `DOH_ODOH_CONFIGS_PATH` | `--odoh-configs-path` | `/.well-known/odohconfigs` | RFC 9230 ODoH key configuration URI path |
| `DOH_HEALTH_PATH` | `--health-path` | `/healthz` | Liveness / readiness probe URI path (`/livez` & `/readyz` always active) |
| `DOH_ENABLE_METRICS` | `--enable-metrics` | `false` | Set `true`/`1`/`yes`/`on` to enable Prometheus `/metrics` endpoint |
| `DOH_METRICS_PATH` | `--metrics-path` | `/metrics` | Prometheus / OpenMetrics URI path |
| `DOH_MAX_CLIENTS` | `-c, --max-clients` | `512` | Max simultaneous client connections |
| `DOH_MAX_CONCURRENT` | `-C, --max-concurrent` | `16` | Max concurrent HTTP/2 streams per client |
| `DOH_MAX_CONNS_PER_IP` | `--max-conns-per-ip` | `0` | Max concurrent TCP connections per peer IP (`0` = disabled) |
| `DOH_TIMEOUT` | `-t, --timeout` | `10` | Per-request timeout in seconds (`1`–`3600`) |
| `DOH_SHUTDOWN_GRACE_PERIOD` | `--shutdown-grace-period` | `15` | Graceful `SIGTERM` / `Ctrl-C` connection drain timeout in seconds |
| `DOH_MIN_TTL` | `-T, --min-ttl` | `0` | Minimum DNS cache TTL floor in seconds (`0` per RFC 8484 §5.1) |
| `DOH_MAX_TTL` | `-X, --max-ttl` | `604800` | Maximum caching TTL in seconds |
| `DOH_ERR_TTL` | `-E, --err-ttl` | `2` | Error response TTL in seconds |
| `DOH_STALE_IF_ERROR_SECS` | `--stale-if-error-secs` | `0` | Optional RFC 5861 `stale-if-error` directive (`0` = disabled) |
| `DOH_STALE_WHILE_REVALIDATE_SECS` | `--stale-while-revalidate-secs` | `0` | Optional RFC 5861 `stale-while-revalidate` directive (`0` = disabled) |
| `DOH_CACHE_SIZE` | `--cache-size` | `0` | In-memory DNS cache capacity (`0` = disabled by default) |
| `DOH_DISABLE_KEEPALIVE` | `-K, --disable-keepalive` | `false` | Disable HTTP keepalive |
| `DOH_DISABLE_POST` | `-P, --disable-post` | `false` | Disable standard DoH `POST` queries |
| `DOH_ALLOW_ODOH_POST` | `-O, --allow-odoh-post` | `false` | Allow ODoH `POST` when `--disable-post` is set |
| `DOH_DISABLE_ANY` | `--disable-any` | `false` | Refuse `QTYPE=ANY` queries per RFC 8482 (`EDE 21`) |
| `DOH_ENABLE_ECS` | `--enable-ecs` | `false` | Enable RFC 7871 EDNS Client Subnet |
| `DOH_TRUSTED_PROXIES` | `--trusted-proxies` | *(empty)* | Comma-separated trusted proxy CIDRs for `X-Forwarded-For` / `Forwarded` |
| `DOH_ECS_PREFIX_V4` | `--ecs-prefix-v4` | `24` | IPv4 prefix length for ECS (`0`–`32`) |
| `DOH_ECS_PREFIX_V6` | `--ecs-prefix-v6` | `56` | IPv6 prefix length for ECS (`0`–`128`) |
| `DOH_ODOH_ROTATION_SECS` | `--odoh-rotation-secs` | `86400` | ODoH HPKE key rotation interval in seconds (`60`–`604800`) |
| `DOH_ALLOWLIST_FILE` | `--allowlist-file` | *(optional)* | Path to Protective DNS domain allowlist file (fails closed if missing) |
| `DOH_BLOCKLIST_FILE` | `--blocklist-file` | *(optional)* | Path to Protective DNS domain blocklist file (fails closed if missing) |
| `DOH_BLOCK_ACTION` | `--block-action` | `nxdomain` | Block action: `nxdomain` (`EDE 15`), `refused` (`EDE 18`), or `zero-ip` (`EDE 17`) |
| `DOH_RATE_LIMIT_RPS` | `--rate-limit-rps` | `0` | Per-IP rate limit in requests/sec (`0` = disabled by default) |
| `DOH_RATE_LIMIT_BURST` | `--rate-limit-burst` | `20` | Per-IP token-bucket burst capacity |
| `DOH_RATE_LIMIT_V6_PREFIX` | `--rate-limit-v6-prefix` | `64` | IPv6 prefix length aggregated into a single rate-limit bucket |
| `DOH_CORS_ALLOW_ORIGIN` | `--cors-allow-origin` | `*` | Value for `Access-Control-Allow-Origin` header |
| `DOH_LOG_QUERIES` | `--log-queries` | `false` | Emit structured JSON query audit logs |
| `DOH_LOG_CLIENT_IP` | `--log-client-ip` | `false` | Client IP audit mode: `false`, `truncated` (`/24` & `/48`), or `full` |
| `DOH_LOG_FORMAT` | `--log-format` | `json` | Log format: `json` or `text` |
| `DOH_LOG_LEVEL` | `--log-level` | `info` | Log level: `error`, `warn`, `info`, `debug`, `trace` |
| `DOH_TLS_CERT_PATH` | `-i, --tls-cert-path` | *(optional)* | Path to PEM certificate chain (enables built-in HTTPS) |
| `DOH_TLS_CERT_KEY_PATH` | `-I, --tls-cert-key-path` | *(optional)* | Path to PEM/PKCS#8 private key |
| `DOH_TLS_MIN_VERSION` | `--tls-min-version` | `1.2` | Minimum TLS protocol version (`1.2` or `1.3`; 0-RTT always disabled) |

---

## Quick Start

### Podman / Docker

```bash
podman run -d --name daviante-doh \
  --read-only --cap-drop=ALL \
  -p 3000:3000 \
  -e DOH_HOSTNAME="doh.example.com" \
  -e DOH_SERVER_ADDRESS="9.9.9.9:53,1.1.1.1:53" \
  -e DOH_CACHE_SIZE="10000" \
  -e DOH_ENABLE_METRICS="true" \
  ghcr.io/daviante-org/daviante-doh:latest
```

### Kubernetes & Red Hat OpenShift (Unified Helm Chart)

```bash
# Standard Kubernetes
helm install daviante-doh ./charts/daviante-doh \
  --set config.serverAddress="9.9.9.9:53\,1.1.1.1:53" \
  --set config.hostname="doh.example.com"

# Red Hat OpenShift (restricted-v2 SCC compatible by default + OpenShift Route enabled)
helm install daviante-doh ./charts/daviante-doh \
  --set route.enabled=true \
  --set route.host="doh.example.com"
```

---

## License

MIT License — Copyright (c) 2026 **Daviante** (<https://daviante.org>).
