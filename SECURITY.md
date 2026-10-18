# Security Policy (`daviante-doh`)

<div align="center">

**[Project Home](README.md)** • **[Architecture & UML](docs/ARCHITECTURE.md)** • **[Global Standards & Security](docs/STANDARDS_AND_SECURITY.md)** • **[Usage Guide](docs/USAGE_GUIDE.md)** • **[Deployment Guide](docs/DEPLOYMENT.md)**

</div>

---

## Supported Versions

Daviante maintains security updates for the latest minor release series of **`daviante-doh`**:

| Version | Supported |
| :--- | :---: |
| `0.1.x` | :white_check_mark: |

## Built-In Security Guarantees

- **Compile-Time Memory & Panic Safety**: `#![forbid(unsafe_code)]` and `#![deny(clippy::unwrap_used)]` enforced across all production crates.
- **Cryptographic & Transport Hardening**: `tokio-rustls` TLS 1.2/1.3 with `0-RTT` unconditionally disabled (`max_early_data_size = 0`) per **RFC 8446 §8**, and **RFC 9230** Oblivious DoH HPKE (`X25519HkdfSha256` / `Aes128Gcm`).
- **DNS Forgery Resilience**: CSPRNG TXID randomization, `0x20` Question verification, bounded UDP spoof rejection loop (**RFC 5452**), and trusted-proxy CIDR verification (**RFC 7871**).
- **Container & Cluster Hardening**: Rootless UID `10001:0`, `readOnlyRootFilesystem: true`, `cap-drop=ALL`, and native **Red Hat OpenShift `restricted-v2` SCC** compatibility.

See **[`docs/STANDARDS_AND_SECURITY.md`](docs/STANDARDS_AND_SECURITY.md)** for the full security specification.

## Reporting a Vulnerability

Please **do not** report security vulnerabilities through public GitHub issues.

Instead, report vulnerabilities privately via:
- **GitHub Private Vulnerability Reporting**: <https://github.com/daviante-org/daviante-doh/security/advisories/new>
- **Email**: `security@daviante.org`

Please include:
1. A description of the vulnerability and its potential impact (e.g., RFC violation, memory exhaustion, cache poisoning, ACL bypass).
2. Minimal reproduction steps, DNS wire-format payload, or HTTP request parameters.
3. Affected `daviante-doh` configuration flags or deployment topology (standalone binary, Docker/Podman, Kubernetes, or OpenShift).

## Response Timeline

- **Initial acknowledgment**: Within **48 hours**.
- **Triage & severity assessment**: Within **5 business days**.
- **Coordinated patch & advisory release**: Within **14–30 days**, depending on complexity.
