# Changelog

All notable changes to **`daviante-doh`** (developed by **Daviante** — <https://daviante.org>) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-10-18

### Summary
Initial enterprise production release of **`daviante-doh`** — a clean-room, zero-telemetry, 100% safe Rust (`#![forbid(unsafe_code)]`) DNS-over-HTTPS (`RFC 8484`), Oblivious DoH (`RFC 9230`), and JSON DoH (`RFC 3597` / Google & Cloudflare spec) library crate (`daviante_doh`) and standalone server binary (`daviante-doh`), shipped with a rootless Alpine 3.24 container image and unified Kubernetes / Red Hat OpenShift (`restricted-v2` SCC) Helm chart.

### Added
- **Protocol & Codec Engine (`src/dns/`, `src/http/`)**:
  - **RFC 8484 Wireformat DoH**: Full support for `GET (?dns=<base64url>)`, `POST (application/dns-message)`, and `HEAD` over HTTP/1.1 and HTTP/2 (`h2`) with strict `Accept`/`Content-Type` negotiation (`400`/`406`/`413`/`414`/`415`).
  - **RFC 9230 Oblivious DoH (ODoH)**: HPKE (`X25519HkdfSha256` / `HkdfSha256` / `Aes128Gcm`) encrypted `POST (application/oblivious-dns-message)`, lock-free 2-key rotation grace ring (`[current, previous]`), 468-byte plaintext block padding, and public key configuration discovery at `/.well-known/odohconfigs`.
  - **JSON DoH API**: `GET /dns-query?name=...&type=...&do=...&cd=...` (`Accept: application/dns-json`) with `RFC 3597` fallback formatting for unknown RR types.
- **EDNS0 Hygiene, Privacy Padding & Client Subnet (`src/dns/edns.rs`, `src/http/handler.rs`)**:
  - **RFC 6891 / RFC 7830 / RFC 8467**: Automatic upstream `OPT` stripping for non-EDNS clients and **468-byte block multiple** EDNS0 response padding (`Option Code 12`).
  - **RFC 7871 / RFC 7239 Client Subnet (ECS)**: Right-to-left `X-Forwarded-For` / `Forwarded` evaluation strictly gated by `--trusted-proxies` CIDR verification, private/loopback IP filtering, and automatic `/24` (IPv4) / `/56` (IPv6) prefix truncation.
- **Protective DNS Policy & Extended DNS Errors (`src/policy/mod.rs`)**:
  - **RFC 8914 Extended DNS Errors (EDE)**: Synthesizes `EDE 15 (Blocked)`, `EDE 17 (Filtered)`, `EDE 18 (Prohibited)`, `EDE 21 (Not Supported)`, `EDE 22 (No Reachable Authority)`, and `EDE 23 (Network Error)`.
  - **Domain Allowlist & Blocklist**: Suffix-trie policy engine inspecting both the query `QNAME` and upstream `CNAME`/`DNAME` answer chains to prevent CNAME-cloaking bypasses, with `nxdomain`, `refused`, and `zero-ip` actions.
  - **RFC 8482 `QTYPE=ANY` Mitigation**: Configurable refusal (`REFUSED + EDE 21`) to prevent DNS amplification.
- **Caching, Upstream Resilience & Rate Limiting (`src/cache/`, `src/upstream/`, `src/ratelimit/`)**:
  - **16-Shard Lock-Minimal In-Memory Cache**: `RFC 9111` HTTP `Cache-Control` / `Age` alignment (`RFC 8484 §5.1`), negative caching (`RFC 2308`), and `RFC 5861` `stale-while-revalidate` / `stale-if-error` directives.
  - **RFC 5452 & RFC 7766 Upstream Resolver Pool**: CSPRNG TXID randomization, `0x20` QNAME case-preservation verification, bounded anti-spoofing UDP receive loop, 30-second per-upstream circuit breaker, multi-upstream failover, and persistent TCP `:53` connection pooling on `TC=1` truncation.
  - **Per-IP Connection Caps & Token-Bucket Rate Limiter**: IPv4 `/32` and IPv6 `/64` subnet-aggregated token buckets returning `429 Too Many Requests` with `Retry-After: 1`.
- **Observability, Security & Cloud-Native Packaging**:
  - **Isolated Admin Listener & OpenMetrics (`src/metrics/`)**: Dedicated `--admin-listen-address` for `/metrics`, `/livez`, `/readyz`, and `/healthz` (`daviante_doh_*` counters).
  - **Built-In TLS 1.2 / 1.3 (`src/tls.rs`)**: `tokio-rustls` acceptor with 0-RTT disabled and 60-second background certificate/key mtime hot-reloading.
  - **Hardened Container & Unified Helm Chart (`Dockerfile`, `charts/daviante-doh/`)**: `~10 MiB` Alpine 3.24 rootless image (`USER 10001:0`, `g=u` permissions, built-in `--healthcheck`) and unified Kubernetes / Red Hat OpenShift (`restricted-v2` SCC + `route.openshift.io/v1`) Helm chart.
