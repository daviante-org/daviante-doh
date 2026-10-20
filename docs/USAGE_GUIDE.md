# `daviante-doh` Complete Usage Guide, Recipes & SDK Examples

<div align="center">

**[Project Home](../README.md)** • **[Architecture & UML](ARCHITECTURE.md)** • **[Global Standards & Security](STANDARDS_AND_SECURITY.md)** • **[Usage Guide & Examples](USAGE_GUIDE.md)** • **[OpenAPI 3.1 Spec](openapi.yaml)** • **[Deployment Guide](DEPLOYMENT.md)** • **[Helm Chart](../charts/daviante-doh/README.md)**

</div>

---

## Table of Contents

1. [CLI Usage, Sub-Modes & Environment Variables](#1-cli-usage-sub-modes--environment-variables)
2. [Querying `daviante-doh`: Client Examples](#2-querying-daviante-doh-client-examples)
   - [2.1 RFC 8484 Wireformat (`GET` & `POST`) via `curl` & `kdig`](#21-rfc-8484-wireformat-get--post-via-curl--kdig)
   - [2.2 JSON DoH API (`application/dns-json`)](#22-json-doh-api-applicationdns-json)
   - [2.3 Oblivious DoH (`RFC 9230` ODoH) End-to-End Example](#23-oblivious-doh-rfc-9230-odoh-end-to-end-example)
   - [2.4 Node.js HTTP/2 Client Example](#24-nodejs-http2-client-example)
   - [2.5 Python (`httpx` + `dnspython`) Client Example](#25-python-httpx--dnspython-client-example)
3. [Enterprise Configuration Recipes](#3-enterprise-configuration-recipes)
   - [3.1 Protective DNS Domain Allowlist & Blocklist](#31-protective-dns-domain-allowlist--blocklist)
   - [3.2 High-Performance 16-Shard In-Memory DNS Cache, RFC 8767 Serve-Stale & Prefetching](#32-high-performance-16-shard-in-memory-dns-cache-rfc-8767-serve-stale--prefetching)
   - [3.2b Multi-Strategy Upstream Load Balancing & Encrypted Upstream DoT (`RFC 7858`)](#32b-multi-strategy-upstream-load-balancing--encrypted-upstream-dot-rfc-7858)
   - [3.2c DNS Rebinding Protection, Split-Horizon Hosts & Lock-Free Policy Hot-Reload](#32c-dns-rebinding-protection-split-horizon-hosts--lock-free-policy-hot-reload)
   - [3.3 Per-IP Token-Bucket Rate Limiting & Connection Caps](#33-per-ip-token-bucket-rate-limiting--connection-caps)
   - [3.4 Trusted Reverse Proxies & RFC 7871 EDNS Client Subnet (ECS)](#34-trusted-reverse-proxies--rfc-7871-edns-client-subnet-ecs)
   - [3.5 Isolated Admin Listener & Prometheus / OpenMetrics Telemetry](#35-isolated-admin-listener--prometheus--openmetrics-telemetry)
   - [3.6 Built-In TLS 1.2 / 1.3 with Zero-Downtime Certificate Hot-Reload](#36-built-in-tls-12--13-with-zero-downtime-certificate-hot-reload)
4. [Embedding `daviante_doh` as a Rust Library Crate](#4-embedding-daviante_doh-as-a-rust-library-crate)

---

## 1. CLI Usage, Sub-Modes & Environment Variables

Every setting in `daviante-doh` can be configured via **CLI flags** or **`DOH_*` environment variables** (CLI flags take precedence when both are provided).

> [!TIP]
> **Flexible Boolean & Empty Environment Parsing**: All boolean `DOH_*` environment variables accept `true`, `false`, `1`, `0`, `yes`, `no`, `on`, or `off` (case-insensitive), and empty strings (`DOH_ADMIN_LISTEN_ADDRESS=""`) are automatically sanitized as unset so Docker Compose and Kubernetes ConfigMaps work seamlessly.

### 1.1 Starting the Server
```bash
# Minimal startup (listens on 0.0.0.0:3000, forwards to 9.9.9.9:53)
daviante-doh

# Production startup with multi-upstream failover, 10k cache, metrics, and DNS stamps
daviante-doh \
  --listen-address 0.0.0.0:3000 \
  --admin-listen-address 127.0.0.1:9090 \
  --server-address 9.9.9.9:53,1.1.1.1:53,8.8.8.8:53 \
  --hostname doh.daviante.org \
  --cache-size 10000 \
  --enable-metrics
```

### 1.2 Inspecting Resolved Configuration (`--print-config`)
Validate all CLI flags and `DOH_*` environment variables and print the resolved configuration as JSON without binding sockets:
```bash
DOH_CACHE_SIZE=4096 DOH_ENABLE_METRICS=true daviante-doh --print-config
```
Output:
```json
{
  "listen_address": "0.0.0.0:3000",
  "admin_listen_address": null,
  "server_address": "9.9.9.9:53",
  "upstream_addresses": ["9.9.9.9:53"],
  "path": "/dns-query",
  "odoh_configs_path": "/.well-known/odohconfigs",
  "health_path": "/healthz",
  "enable_metrics": true,
  "metrics_path": "/metrics",
  "cache_size": 4096
}
```

### 1.3 Native Zero-Dependency Health Probe (`--healthcheck`)
`daviante-doh --healthcheck` probes `/healthz` over HTTP (or leaf-pinned HTTPS when `DOH_TLS_CERT_PATH` is set) and exits `0` on `200 OK` or non-zero on failure:
```bash
# Probe local instance (automatically reads DOH_LISTEN_ADDRESS, DOH_HEALTH_PATH, and DOH_TLS_CERT_PATH)
daviante-doh --healthcheck
```

---

## 2. Querying `daviante-doh`: Client Examples

### 2.1 RFC 8484 Wireformat (`GET` & `POST`) via `curl` & `kdig`

```bash
# 1. RFC 8484 GET with unpadded base64url (?dns= for example.com IN A)
curl -i -H "Accept: application/dns-message" \
  "http://127.0.0.1:3000/dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE" \
  --output - | xxd

# 2. RFC 8484 POST with binary DNS wireformat via kdig (Knot DNS)
kdig @127.0.0.1 +https=/dns-query +tls-ca=certs/tls.crt example.com AAAA

# 3. CORS Preflight (W3C Fetch OPTIONS)
curl -i -X OPTIONS "http://127.0.0.1:3000/dns-query"
```

### 2.2 JSON DoH API (`application/dns-json`)

`daviante-doh` natively supports the Google / Cloudflare JSON DoH specification on `GET /dns-query`:

```bash
# Query A record with DNSSEC (do=1) enabled
curl -sS -H "Accept: application/dns-json" \
  "http://127.0.0.1:3000/dns-query?name=example.com&type=A&do=1&cd=0" | jq .
```
Sample response:
```json
{
  "Status": 0,
  "TC": false,
  "RD": true,
  "RA": true,
  "AD": true,
  "CD": false,
  "Question": [
    {
      "name": "example.com.",
      "type": 1
    }
  ],
  "Answer": [
    {
      "name": "example.com.",
      "type": 1,
      "TTL": 300,
      "data": "93.184.215.14"
    }
  ]
}
```

### 2.3 Oblivious DoH (`RFC 9230` ODoH) End-to-End Example

```bash
# Step 1: Fetch the active HPKE ObliviousDoHConfigs from the Target
curl -fsS "http://127.0.0.1:3000/.well-known/odohconfigs" -o odohconfigs.bin
```

In Rust (using `odoh-rs` to encrypt a query against `odohconfigs.bin` and decrypt the sealed response):
```rust
use bytes::Bytes;
use odoh_rs::{
    decrypt_response, encrypt_query, Deserialize, ObliviousDoHConfigs,
    ObliviousDoHMessage, ObliviousDoHMessagePlaintext, Serialize,
};

fn build_and_verify_odoh(configs_raw: Vec<u8>, dns_wire_query: &[u8]) {
    let configs = ObliviousDoHConfigs::deserialize(&mut Bytes::from(configs_raw)).unwrap();
    let target_config = configs.into_iter().next().unwrap().into();

    // 1. Encrypt DNS query with HPKE
    let plain_query = ObliviousDoHMessagePlaintext::new(dns_wire_query, 0);
    let mut rng = rand::rng();
    let (encrypted_query, client_secret) =
        encrypt_query(&plain_query, &target_config, &mut rng).unwrap();

    let mut request_body = Vec::new();
    encrypted_query.serialize(&mut request_body).unwrap();

    // 2. POST `request_body` to `/dns-query` with:
    //    Content-Type: application/oblivious-dns-message
    //    Accept: application/oblivious-dns-message
    // 3. Decrypt response:
    // let enc_resp = ObliviousDoHMessage::deserialize(&mut Bytes::from(response_bytes)).unwrap();
    // let plain_resp = decrypt_response(&plain_query, &enc_resp, client_secret).unwrap();
}
```

### 2.4 Node.js HTTP/2 Client Example

```javascript
import http2 from 'node:http2';

const client = http2.connect('https://localhost:8443', {
  rejectUnauthorized: false, // Use CA cert in production
});

// DNS wire query for example.com IN A (unpadded base64url)
const dnsParam = 'AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE';

const req = client.request({
  ':method': 'GET',
  ':path': `/dns-query?dns=${dnsParam}`,
  accept: 'application/dns-message',
});

const chunks = [];
req.on('response', (headers) => {
  console.log('HTTP/2 Status:', headers[':status']);
  console.log('Cache-Control:', headers['cache-control']);
});
req.on('data', (chunk) => chunks.push(chunk));
req.on('end', () => {
  const wireResp = Buffer.concat(chunks);
  console.log(`Received ${wireResp.length}-byte DNS wire response`);
  client.close();
});
req.end();
```

### 2.5 Python (`httpx` + `dnspython`) Client Example

```python
import dns.message
import httpx

query = dns.message.make_query("example.com", dns.rdatatype.A, use_edns=0, payload=1232)
wire_bytes = query.to_wire()

with httpx.Client(http2=True) as client:
    resp = client.post(
        "http://127.0.0.1:3000/dns-query",
        content=wire_bytes,
        headers={
            "Content-Type": "application/dns-message",
            "Accept": "application/dns-message",
        },
    )
    resp.raise_for_status()
    answer = dns.message.from_wire(resp.content)
    print(answer)
```

---

## 3. Enterprise Configuration Recipes

### 3.1 Protective DNS Domain Allowlist & Blocklist

`daviante-doh` includes a fail-closed Protective DNS policy engine (`src/policy/mod.rs`) that inspects both the incoming **QNAME** and upstream Answer **CNAME / DNAME target chains**.

Create `blocklist.txt`:
```text
# Exact match + all subdomains (e.g., ads.example.com and sub.ads.example.com)
ads.example.com
*.telemetry.example.org
malware-c2.invalid
```

Run with `--blocklist-file` and choose a `--block-action`:
- `nxdomain` *(default)*: Returns `RCODE=3 (NXDOMAIN)` with **RFC 8914 `EDE 15 (Blocked)`**.
- `refused`: Returns `RCODE=5 (REFUSED)` with **RFC 8914 `EDE 18 (Prohibited)`**.
- `zero-ip`: Synthesizes `0.0.0.0` (for `A`) or `::` (for `AAAA`) with **RFC 8914 `EDE 17 (Filtered)`**.

```bash
daviante-doh \
  --blocklist-file /etc/daviante-doh/policy/blocklist.txt \
  --block-action nxdomain
```

### 3.2 High-Performance 16-Shard In-Memory DNS Cache, RFC 8767 Serve-Stale & Prefetching

Enable the 16-shard in-memory cache (`--cache-size`), **RFC 8767 Serve-Stale** (`--serve-stale-ttl`), proactive 10% TTL **Cache Prefetching** (`--cache-prefetch`), and optional **RFC 5861** HTTP cache directives:
```bash
daviante-doh \
  --cache-size 65536 \
  --serve-stale-ttl 86400 \
  --cache-prefetch \
  --min-ttl 0 \
  --max-ttl 86400 \
  --err-ttl 5 \
  --stale-while-revalidate 60 \
  --stale-if-error 86400
```

### 3.2b Multi-Strategy Upstream Load Balancing & Encrypted Upstream DoT (`RFC 7858`)

Choose between `failover` (default sequential priority), `round-robin`, or `parallel` (fastest-wins concurrent query race), and optionally encrypt upstream queries over **DNS-over-TLS (`DoT`, RFC 7858 `:853`)**:
```bash
daviante-doh \
  --server-address 9.9.9.9:853,1.1.1.1:853 \
  --upstream-strategy parallel \
  --upstream-dot-sni dns.quad9.net
```

### 3.2c DNS Rebinding Protection, Split-Horizon Hosts & Lock-Free Policy Hot-Reload

Block upstream responses that resolve public domains to RFC 1918 / loopback / link-local IPs (`--block-private-rebinding`) while serving local split-horizon `A`, `AAAA`, and `PTR` records from `--hosts-file` (automatically hot-reloaded on file modification alongside `--allowlist-file` and `--blocklist-file`):
```bash
daviante-doh \
  --hosts-file /etc/daviante-doh/policy/hosts.txt \
  --blocklist-file /etc/daviante-doh/policy/blocklist.txt \
  --block-private-rebinding
```

### 3.3 Per-IP Token-Bucket Rate Limiting & Connection Caps

Protect against volumetric DoH floods and slowloris connection exhaustion:
```bash
daviante-doh \
  --rate-limit-rps 100 \
  --rate-limit-burst 200 \
  --rate-limit-v6-prefix 64 \
  --max-clients 2048 \
  --max-conns-per-ip 32 \
  --max-concurrent 128
```
When a client exceeds `--rate-limit-rps` / `--rate-limit-burst`, `daviante-doh` immediately returns `HTTP 429 Too Many Requests` with `Retry-After: 1` and `Cache-Control: no-store`.

### 3.4 Trusted Reverse Proxies & RFC 7871 EDNS Client Subnet (ECS)

When running behind NGINX, HAProxy, Envoy, or Cloudflare, specify the proxy CIDRs in `--trusted-proxies` so `daviante-doh` safely extracts the real client IP for rate limiting and optional ECS forwarding:
```bash
daviante-doh \
  --enable-ecs \
  --trusted-proxies "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16" \
  --ecs-prefix-v4 24 \
  --ecs-prefix-v6 56
```

### 3.5 Isolated Admin Listener & Prometheus / OpenMetrics Telemetry

Bind `/metrics`, `/livez`, `/readyz`, and `/healthz` to an internal-only admin port (`--admin-listen-address`) so `/metrics` is never exposed on the public ingress:
```bash
daviante-doh \
  --listen-address 0.0.0.0:3000 \
  --admin-listen-address 0.0.0.0:9090 \
  --enable-metrics
```

#### Exported Prometheus Metrics Reference (`GET /metrics`)

| Metric Name | Type | Labels | Description |
| :--- | :---: | :---: | :--- |
| `daviante_doh_requests_total` | `counter` | `flavor="wire" \| "json" \| "odoh"` | Total DoH requests received by protocol flavor |
| `daviante_doh_responses_total` | `counter` | `status="2xx" \| "4xx" \| "5xx"` | Total HTTP responses sent by HTTP status class |
| `daviante_doh_responses_by_rcode_total` | `counter` | `rcode="NOERROR" \| "FORMERR" \| "SERVFAIL" \| "NXDOMAIN" \| "NOTIMP" \| "REFUSED" \| "OTHER"` | Total DNS responses sent by DNS RCODE |
| `daviante_doh_cache_hits_total` | `counter` | — | Total queries served directly from the 16-shard `DnsCache` |
| `daviante_doh_cache_misses_total` | `counter` | — | Total cache misses forwarded to upstream resolvers |
| `daviante_doh_cache_stale_hits_total` | `counter` | — | Total expired cache entries served during upstream outages per RFC 8767 (`EDE 3`) |
| `daviante_doh_cache_prefetch_total` | `counter` | — | Total proactive background cache refreshes triggered in the final 10% of TTL |
| `daviante_doh_coalesced_queries_total` | `counter` | — | Total concurrent cache-miss queries deduplicated via Singleflight coalescing |
| `daviante_doh_policy_blocked_total` | `counter` | — | Total queries or CNAME chains blocked by `DomainPolicy` |
| `daviante_doh_rebinding_blocked_total` | `counter` | — | Total upstream responses blocked by DNS rebinding protection (`EDE 17`) |
| `daviante_doh_hosts_hits_total` | `counter` | — | Total queries answered locally from `--hosts-file` (`A`, `AAAA`, `PTR`) |
| `daviante_doh_rate_limited_total` | `counter` | — | Total requests rejected with `HTTP 429` by `IpRateLimiter` |
| `daviante_doh_upstream_queries_total` | `counter` | `transport="udp" \| "tcp" \| "dot"`, `upstream`, `result="ok" \| "error" \| "timeout"` | Total queries sent to upstream DNS resolvers by transport and target |
| `daviante_doh_upstream_failures_total` | `counter` | — | Total upstream UDP/TCP/DoT timeouts or socket errors |
| `daviante_doh_connections_active` | `gauge` | — | Currently active client TCP/TLS connections |
| `daviante_doh_request_duration_seconds` | `histogram` | `flavor="wire" \| "json" \| "odoh"`, `le="0.001".."10.0" \| "+Inf"` | End-to-end request latency histogram (12 buckets + `+Inf`) |

### 3.6 Built-In TLS 1.2 / 1.3 with Zero-Downtime Certificate Hot-Reload

```bash
daviante-doh \
  --listen-address 0.0.0.0:8443 \
  --tls-cert-path /etc/daviante-doh/certs/tls.crt \
  --tls-cert-key-path /etc/daviante-doh/certs/tls.key \
  --tls-min-version 1.3
```
`ReloadableTlsAcceptor` polls the certificate and key modification timestamps every 60 seconds and atomically swaps the `TlsAcceptor` when `cert-manager` or OpenShift rotates the secret.

---

## 4. Embedding `daviante_doh` as a Rust Library Crate

Add `daviante-doh` to your `Cargo.toml` with `default-features = false` for a pure library dependency tree:

```toml
[dependencies]
daviante-doh = { version = "0.1.0", default-features = false, features = ["tls"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "net", "signal"] }
```

Embed the engine inside your own Rust application:

```rust
use std::time::Duration;
use tokio::net::TcpListener;
use daviante_doh::{
    serve_with_shutdown, DohConfig, DohEngine, OdohKeyManager,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:3000").await?;

    let config = DohConfig {
        listen_address: listener.local_addr()?,
        server_address: "9.9.9.9:53".parse()?,
        upstream_addresses: vec!["9.9.9.9:53".parse()?, "1.1.1.1:53".parse()?],
        cache_size: 8192,
        enable_metrics: true,
        ..DohConfig::default()
    };

    let odoh_keys = OdohKeyManager::spawn(
        tokio::runtime::Handle::current(),
        Duration::from_secs(config.odoh_rotation_secs as u64),
    )?;

    let engine = DohEngine::new(config, odoh_keys)?;

    serve_with_shutdown(engine, listener, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;

    Ok(())
}
```
