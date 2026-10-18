# `daviante-doh` Unified Kubernetes & Red Hat OpenShift Helm Chart

<div align="center">

**[Project Home](../../README.md)** • **[Architecture & UML](../../docs/ARCHITECTURE.md)** • **[Global Standards & Security](../../docs/STANDARDS_AND_SECURITY.md)** • **[Usage Guide](../../docs/USAGE_GUIDE.md)** • **[Deployment Guide](../../docs/DEPLOYMENT.md)**

</div>

---

## Overview

This directory contains the official Helm chart for **`daviante-doh`** (`0.1.0`), designed to deploy seamlessly on both **standard Kubernetes (`v1.26+`)** and **Red Hat OpenShift (`4.12+` with `restricted-v2` SCC)** without chart modifications.

### Included Kubernetes & OpenShift Resources
- [`templates/deployment.yaml`](templates/deployment.yaml) — Rootless `Deployment` with pod anti-affinity, `/livez` & `/readyz` HTTP/HTTPS probes, and automatic ConfigMap checksum rollouts.
- [`templates/configmap.yaml`](templates/configmap.yaml) — Maps all `values.config.*` settings to `DOH_*` environment variables.
- [`templates/policy-configmap.yaml`](templates/policy-configmap.yaml) — Mounts inline `policy.allowlist` / `policy.blocklist` domain rules at `/etc/daviante-doh/policy`.
- [`templates/service.yaml`](templates/service.yaml) — Exposes the primary DoH port (`3000`) and optional dedicated `http-admin` port (`9090`).
- [`templates/ingress.yaml`](templates/ingress.yaml) — Standard `networking.k8s.io/v1` `Ingress`.
- [`templates/route.yaml`](templates/route.yaml) — Red Hat OpenShift `route.openshift.io/v1` `Route` (`edge`, `reencrypt`, or `passthrough`).
- [`templates/networkpolicy.yaml`](templates/networkpolicy.yaml) — Zero-trust ingress/egress `NetworkPolicy` (permits DNS `:53` UDP/TCP egress to upstream resolvers).
- [`templates/servicemonitor.yaml`](templates/servicemonitor.yaml) — Prometheus Operator `monitoring.coreos.com/v1` `ServiceMonitor`.
- [`templates/hpa.yaml`](templates/hpa.yaml) & [`templates/pdb.yaml`](templates/pdb.yaml) — `HorizontalPodAutoscaler` (`autoscaling/v2`) and `PodDisruptionBudget` (`policy/v1`).
- [`templates/tests/test-connection.yaml`](templates/tests/test-connection.yaml) — `helm test` hook Pod executing `/usr/local/bin/daviante-doh --healthcheck`.
- [`values.schema.json`](values.schema.json) — JSON Schema validating `values.yaml` at `helm lint` / `helm install` time.

---

## Quick Start

### 1. Standard Kubernetes
```bash
helm upgrade --install daviante-doh ./charts/daviante-doh \
  --namespace daviante-doh --create-namespace \
  --set config.serverAddress="9.9.9.9:53\,1.1.1.1:53" \
  --set config.cacheSize=10000 \
  --set config.enableMetrics=true
```

### 2. Red Hat OpenShift (`restricted-v2` SCC + `Route`)
```bash
helm upgrade --install daviante-doh ./charts/daviante-doh \
  --namespace daviante-doh \
  --set route.enabled=true \
  --set route.host="doh.apps.cluster.example.com" \
  --set route.tls.termination="edge"
```

### 3. Inline Protective DNS Blocklist via Helm Values
```bash
helm upgrade --install daviante-doh ./charts/daviante-doh \
  --namespace daviante-doh \
  --set policy.blocklist[0]="ads.example.com" \
  --set policy.blocklist[1]="*.tracker.example.org" \
  --set config.blockAction="nxdomain"
```

---

## Complete Helm Values Reference (`values.yaml`)

| Key | Type | Default | Description |
| :--- | :---: | :--- | :--- |
| `replicaCount` | `int` | `2` | Number of `daviante-doh` Pod replicas |
| `image.repository` | `string` | `"ghcr.io/daviante-org/daviante-doh"` | Container image repository |
| `image.pullPolicy` | `string` | `"IfNotPresent"` | Image pull policy (`IfNotPresent`, `Always`, `Never`) |
| `image.tag` | `string` | `"0.1.0"` | Container image tag |
| `serviceAccount.create` | `bool` | `true` | Create dedicated `ServiceAccount` (`automountServiceAccountToken: false`) |
| `config.listenAddress` | `string` | `"0.0.0.0:3000"` | Primary DoH/ODoH/JSON socket bind address (`DOH_LISTEN_ADDRESS`) |
| `config.adminListenAddress` | `string` | `""` | Optional isolated admin listener for `/metrics` & probes (`DOH_ADMIN_LISTEN_ADDRESS`) |
| `config.serverAddress` | `string` | `"9.9.9.9:53"` | Comma-separated upstream DNS resolver(s) (`DOH_SERVER_ADDRESS`) |
| `config.localBindAddress` | `string` | `""` | Optional local outbound UDP/TCP bind address (`DOH_LOCAL_BIND_ADDRESS`) |
| `config.hostname` | `string` | `""` | Public hostname for `sdns://` stamp generation (`DOH_HOSTNAME`) |
| `config.path` | `string` | `"/dns-query"` | DoH endpoint URI path (`DOH_PATH`) |
| `config.odohConfigsPath` | `string` | `"/.well-known/odohconfigs"` | RFC 9230 ODoH config URI path (`DOH_ODOH_CONFIGS_PATH`) |
| `config.healthPath` | `string` | `"/healthz"` | Health probe URI path (`DOH_HEALTH_PATH`) |
| `config.enableMetrics` | `bool` | `false` | Enable Prometheus `/metrics` endpoint (`DOH_ENABLE_METRICS`) |
| `config.metricsPath` | `string` | `"/metrics"` | Prometheus metrics URI path (`DOH_METRICS_PATH`) |
| `config.maxClients` | `int` | `512` | Max concurrent client connections (`DOH_MAX_CLIENTS`) |
| `config.maxConcurrent` | `int` | `16` | Max concurrent HTTP/2 streams per connection (`DOH_MAX_CONCURRENT`) |
| `config.maxConnsPerIp` | `int` | `0` | Per-IP TCP connection limit (`0` = disabled) (`DOH_MAX_CONNS_PER_IP`) |
| `config.timeout` | `int` | `10` | Per-request timeout in seconds (`DOH_TIMEOUT`) |
| `config.shutdownGracePeriod` | `int` | `15` | Graceful `SIGTERM` drain timeout in seconds (`DOH_SHUTDOWN_GRACE_PERIOD`) |
| `config.minTtl` | `int` | `0` | Minimum caching TTL floor in seconds (`DOH_MIN_TTL`) |
| `config.maxTtl` | `int` | `604800` | Maximum caching TTL ceiling in seconds (`DOH_MAX_TTL`) |
| `config.errTtl` | `int` | `2` | Error response caching TTL in seconds (`DOH_ERR_TTL`) |
| `config.staleIfErrorSecs` | `int` | `0` | RFC 5861 `stale-if-error` directive (`0` = disabled) |
| `config.staleWhileRevalidateSecs` | `int` | `0` | RFC 5861 `stale-while-revalidate` directive (`0` = disabled) |
| `config.cacheSize` | `int` | `0` | In-memory 16-shard DNS cache capacity (`0` = disabled) (`DOH_CACHE_SIZE`) |
| `config.disableKeepalive` | `bool` | `false` | Disable HTTP keepalive (`DOH_DISABLE_KEEPALIVE`) |
| `config.disablePost` | `bool` | `false` | Disable standard DoH `POST` queries (`DOH_DISABLE_POST`) |
| `config.allowOdohPost` | `bool` | `false` | Allow ODoH `POST` when `disablePost=true` (`DOH_ALLOW_ODOH_POST`) |
| `config.disableAny` | `bool` | `false` | Refuse `QTYPE=ANY` per RFC 8482 with `EDE 21` (`DOH_DISABLE_ANY`) |
| `config.enableEcs` | `bool` | `false` | Enable RFC 7871 EDNS Client Subnet (`DOH_ENABLE_ECS`) |
| `config.trustedProxies` | `string` | `""` | Trusted reverse proxy CIDRs (`DOH_TRUSTED_PROXIES`) |
| `config.ecsPrefixV4` | `int` | `24` | ECS IPv4 prefix length (`DOH_ECS_PREFIX_V4`) |
| `config.ecsPrefixV6` | `int` | `56` | ECS IPv6 prefix length (`DOH_ECS_PREFIX_V6`) |
| `config.odohRotationSecs` | `int` | `86400` | ODoH HPKE key rotation interval in seconds (`DOH_ODOH_ROTATION_SECS`) |
| `config.blockAction` | `string` | `"nxdomain"` | Policy block action: `nxdomain`, `refused`, or `zero-ip` (`DOH_BLOCK_ACTION`) |
| `config.rateLimitRps` | `int` | `0` | Per-IP token-bucket rate limit in req/s (`0` = disabled) (`DOH_RATE_LIMIT_RPS`) |
| `config.rateLimitBurst` | `int` | `20` | Per-IP token-bucket burst size (`DOH_RATE_LIMIT_BURST`) |
| `config.rateLimitV6Prefix` | `int` | `64` | IPv6 subnet aggregation prefix for rate limiting (`DOH_RATE_LIMIT_V6_PREFIX`) |
| `config.corsAllowOrigin` | `string` | `"*"` | `Access-Control-Allow-Origin` header value (`DOH_CORS_ALLOW_ORIGIN`) |
| `config.logQueries` | `bool` | `false` | Emit structured query audit logs (`DOH_LOG_QUERIES`) |
| `config.logClientIp` | `string` | `"false"` | Client IP audit mode: `"false"`, `"truncated"`, or `"full"` (`DOH_LOG_CLIENT_IP`) |
| `config.logFormat` | `string` | `"json"` | Log format: `"json"` or `"text"` (`DOH_LOG_FORMAT`) |
| `config.logLevel` | `string` | `"info"` | Log level: `"error"`, `"warn"`, `"info"`, `"debug"`, `"trace"` (`DOH_LOG_LEVEL`) |
| `config.tlsMinVersion` | `string` | `"1.2"` | Minimum TLS version (`"1.2"` or `"1.3"`) (`DOH_TLS_MIN_VERSION`) |
| `policy.allowlist` | `list` | `[]` | Inline domain allowlist entries mounted via `ConfigMap` |
| `policy.blocklist` | `list` | `[]` | Inline domain blocklist entries mounted via `ConfigMap` |
| `tls.enabled` | `bool` | `false` | Enable built-in HTTPS using a Kubernetes TLS `Secret` |
| `tls.secretName` | `string` | `""` | Name of the Kubernetes TLS `Secret` containing `tls.crt` and `tls.key` |
| `service.type` | `string` | `"ClusterIP"` | Kubernetes `Service` type (`ClusterIP`, `NodePort`, `LoadBalancer`) |
| `service.port` | `int` | `3000` | Service port for DoH traffic |
| `service.adminPort` | `int` | `9090` | Service port for isolated admin/metrics listener |
| `ingress.enabled` | `bool` | `false` | Enable Kubernetes `Ingress` |
| `route.enabled` | `bool` | `false` | Enable Red Hat OpenShift `Route` (`route.openshift.io/v1`) |
| `networkPolicy.enabled` | `bool` | `false` | Enable Kubernetes `NetworkPolicy` |
| `serviceMonitor.enabled` | `bool` | `false` | Enable Prometheus Operator `ServiceMonitor` |
| `autoscaling.enabled` | `bool` | `false` | Enable `HorizontalPodAutoscaler` |
| `pdb.enabled` | `bool` | `true` | Enable `PodDisruptionBudget` (`minAvailable: 1`) |
