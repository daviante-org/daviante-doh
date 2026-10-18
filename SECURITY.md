# Security Policy

## Supported Versions

Daviante maintains security updates for the latest minor release series of **`daviante-doh`**:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

Please **do not** report security vulnerabilities through public GitHub issues.

Instead, report vulnerabilities privately via:
- **GitHub Private Vulnerability Reporting**: [https://github.com/daviante-org/daviante-doh/security/advisories/new](https://github.com/daviante-org/daviante-doh/security/advisories/new)
- **Email**: `security@daviante.org`

Please include:
1. A description of the vulnerability and its potential impact (e.g., RFC violation, memory exhaustion, cache poisoning, ACL bypass).
2. Minimal reproduction steps, DNS wire-format payload, or HTTP request parameters.
3. Affected `daviante-doh` configuration flags or deployment topology (standalone binary, Docker/Podman, Kubernetes, or OpenShift).

## Response Timeline

- **Initial acknowledgment**: Within **48 hours**.
- **Triage & severity assessment**: Within **5 business days**.
- **Coordinated patch & advisory release**: Within **14–30 days**, depending on complexity.
