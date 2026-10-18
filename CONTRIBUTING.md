# Contributing to `daviante-doh`

<div align="center">

**[Project Home](README.md)** • **[Architecture & UML](docs/ARCHITECTURE.md)** • **[Global Standards & Security](docs/STANDARDS_AND_SECURITY.md)** • **[Usage Guide](docs/USAGE_GUIDE.md)** • **[Deployment Guide](docs/DEPLOYMENT.md)**

</div>

---

Thank you for contributing to **`daviante-doh`** by **Daviante** ([daviante.org](https://daviante.org))!

## Repository Layout

- [`src/`](src): Pure production library (`src/lib.rs`) and server binary (`src/main.rs` + `src/cli.rs`) with `#![forbid(unsafe_code)]` and `#![deny(clippy::unwrap_used)]`.
- [`tests/`](tests): Segregated integration (`tests/integration.rs`) and unit (`tests/unit/`) test suites.
- [`charts/daviante-doh/`](charts/daviante-doh): Unified Helm chart for Kubernetes and Red Hat OpenShift (`restricted-v2` SCC).
- [`docs/`](docs): Architecture UML diagrams, IETF/OWASP standards specification, usage recipes, and deployment guides.
- [`scripts/e2e/`](scripts/e2e): Automated container, Kubernetes (`kind` + MetalLB + Ingress), and OpenShift (`Route` + HAProxy Router) black-box test runners.

## Pre-PR Verification Checklist

Every pull request must pass the following gates cleanly with zero warnings:

```bash
# 1. Formatting
cargo fmt --all -- --check

# 2. Strict Clippy (with and without default TLS feature)
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo clippy --workspace --all-targets --no-default-features -- -D warnings

# 3. Unit, integration, and security regression tests
cargo test --workspace --all-features --release --locked
cargo test --workspace --no-default-features --release --locked

# 4. Pure library dependency verification (no CLI leakage)
cargo tree --no-default-features --features tls | grep -E "clap|mimalloc|dnsstamps" && exit 1 || true

# 5. Helm chart lint & render validation
helm lint ./charts/daviante-doh --strict

# 6. Live Container & 73-Case Black-Box API & Protocol Suite
sh ./scripts/e2e/test-container.sh
sh ./scripts/e2e/run-blackbox-ci.sh
```

## Design Principles

1. **Standards-Mandated Rules ON by Default**: Protocol rules required by RFC 8484, RFC 9230, RFC 7871, RFC 8467, RFC 8914, RFC 8932, and OWASP are always enforced by default (see [`docs/STANDARDS_AND_SECURITY.md`](docs/STANDARDS_AND_SECURITY.md)).
2. **Optional Enterprise Controls OFF by Default**: Stateful or environment-specific features (in-memory DNS cache, Prometheus `/metrics`, dedicated admin listener, domain allow/blocklists, `ANY` blocking, rate limiting, ECS injection) default to disabled (`false` / `0`) and are 100% configurable via CLI flags, `DOH_*` environment variables, and Helm `values.yaml`.

## License

By contributing to `daviante-doh`, you agree that your contributions will be licensed under the **Apache License, Version 2.0** (see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE)).
