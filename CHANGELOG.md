# Changelog

All notable changes to **`daviante-doh`** (by **Daviante** — [daviante.org](https://daviante.org)) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-18

### Added
- **Multi-Protocol DoH Engine (`src/`)**:
  - **RFC 8484** DNS-over-HTTPS (`GET` with `base64url` `?dns=` and `POST` with `application/dns-message`).
  - **RFC 9230** Oblivious DoH (`POST` with `application/oblivious-dns-message` and HPKE key publishing at `/.well-known/odohconfigs`).
  - **JSON DoH API** (`GET` with `Accept: application/dns-json` or `?name=...&type=...&do=...&cd=...`).
- **RFC & IETF Compliance**:
  - **RFC 8484 §5.1 / RFC 9111** HTTP `Cache-Control` and `Age` alignment where HTTP freshness never exceeds Answer RR TTL and zero-TTL responses emit `max-age=0, no-cache, no-store`.
  - **RFC 7871 §7.2.2 / §11.2** EDNS Client Subnet (ECS) forwarding with trusted-proxy CIDR verification (`--trusted-proxies` / `DOH_TRUSTED_PROXIES`), client-supplied ECS preservation, and scope-0 uncached fallback.
  - **RFC 8467 §4.1 & RFC 9230 §4.3 / §7** 468-byte response block padding for padded DoH and ODoH responses.
  - **RFC 5452 §9.1 & RFC 7766 §6.2.1** Upstream DNS resilience with TXID + Question verification, UDP-to-TCP `TC=1` fallback, 30s circuit breaker across multiple upstreams, and persistent TCP connection pooling.
  - **RFC 8914** Extended DNS Errors (`EDE 15 Blocked`, `EDE 21 Not Supported`, `EDE 22 No Reachable Authority`, `EDE 23 Network Error`).
- **Enterprise & Security Hardening**:
  - Fail-closed Protective DNS allowlist/blocklist loader (`nxdomain`, `refused`, `zero-ip`) with CNAME/DNAME answer-chain inspection.
  - Bounded per-IP token-bucket rate limiter with IPv6 `/64` subnet aggregation and per-IP TCP connection limits.
  - Dedicated admin listener (`--admin-listen-address` / `DOH_ADMIN_LISTEN_ADDRESS`) isolating `/metrics`, `/livez`, `/readyz`, and `/healthz`.
  - Built-in `--healthcheck` (HTTP & leaf-pinned HTTPS) and `--print-config` CLI sub-modes.
  - Graceful `SIGTERM` / `Ctrl-C` connection draining (`--shutdown-grace-period`).
  - Unified Kubernetes & Red Hat OpenShift (`restricted-v2` SCC) Helm chart (`charts/daviante-doh`) with `ServiceAccount`, `NetworkPolicy`, `ServiceMonitor`, `values.schema.json`, and mountable policy ConfigMaps.
