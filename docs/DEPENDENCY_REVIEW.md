# Dependency review — 2026-11-03

Reviewed the main/v0.2.0 codebase against crates.io stable releases, upstream GitHub releases, Docker Hub image indexes, and the RustSec advisory database. No Rust source, resolver logic, public APIs, or Cargo feature selections were changed.

## Rust updates

Checked 135 distinct registry package names and updated 11 compatible packages through Cargo. All 19 direct dependencies now resolve to their latest stable release. Cargo.toml already permits those versions; Cargo.lock records the exact versions and checksums.

| Package | Previous lock | Updated lock | Latest stable |
| --- | --- | --- | --- |
| [aes](https://crates.io/crates/aes) | 0.9.3 | 0.9.4 | 0.9.4 |
| [arc-swap](https://crates.io/crates/arc-swap) | 1.9.2 | 1.9.3 | 1.9.3 |
| [cc](https://crates.io/crates/cc) | 1.8.0 | 1.11.0 | 1.11.0 |
| [ctutils](https://crates.io/crates/ctutils) | 0.4.3 | 0.4.7 | 0.4.7 |
| [find-msvc-tools](https://crates.io/crates/find-msvc-tools) | 0.1.14 | 0.1.15 | 0.1.15 |
| [inout](https://crates.io/crates/inout) | 0.2.4 | 0.2.5 | 0.2.5 |
| [log](https://crates.io/crates/log) | 0.4.34 | 0.4.35 | 0.4.35 |
| [rustix](https://crates.io/crates/rustix) | 1.1.5 | 1.1.6 | 1.1.6 |
| [rustls-webpki](https://crates.io/crates/rustls-webpki) | 0.103.15 | 0.103.16 | 0.103.16 |
| [smallvec](https://crates.io/crates/smallvec) | 1.16.3 | 1.16.4 | 1.16.4 |
| [tokio](https://crates.io/crates/tokio) | 1.53.3 | 1.54.1 | 1.54.1 |

The update fixes [RUSTSEC-2026-0382](https://rustsec.org/advisories/RUSTSEC-2026-0382.html) in rustls-webpki and [RUSTSEC-2026-0385](https://rustsec.org/advisories/RUSTSEC-2026-0385.html) in ctutils. The updated cargo-deny check passes advisories, licenses, bans, and sources. Existing duplicate-version warnings come from upstream dependency requirements; they are not suppressed.

## Versions constrained by upstream libraries

These newer releases cannot be substituted within the parent libraries' declared compatible ranges. No forced cryptography or platform dependency replacement was introduced.

| Package | Selected | Latest stable | Parent requirements |
| --- | --- | --- | --- |
| hpke | 0.14.1 | 0.15.1 | odoh-rs 1.0.5: `^0.14` |
| r-efi | 6.0.0 | 7.1.0 | getrandom 0.4.3: `^6` |
| wasi | 0.11.1+wasi-snapshot-preview1 | 0.14.7+wasi-0.2.4 | getrandom 0.2.17: `^0.11`; mio 1.2.4: `^0.11.0` |
| windows_aarch64_gnullvm | 0.52.6 | 0.53.1 | windows-targets 0.52.6: `^0.52.6` |
| windows_aarch64_msvc | 0.52.6 | 0.53.1 | windows-targets 0.52.6: `^0.52.6` |
| windows_i686_gnu | 0.52.6 | 0.53.1 | windows-targets 0.52.6: `^0.52.6` |
| windows_i686_gnullvm | 0.52.6 | 0.53.1 | windows-targets 0.52.6: `^0.52.6` |
| windows_i686_msvc | 0.52.6 | 0.53.1 | windows-targets 0.52.6: `^0.52.6` |
| windows_x86_64_gnu | 0.52.6 | 0.53.1 | windows-targets 0.52.6: `^0.52.6` |
| windows_x86_64_gnullvm | 0.52.6 | 0.53.1 | windows-targets 0.52.6: `^0.52.6` |
| windows_x86_64_msvc | 0.52.6 | 0.53.1 | windows-targets 0.52.6: `^0.52.6` |
| windows-link | 0.2.1 | 0.100.0 | windows-sys 0.61.2: `^0.2.1` |
| windows-targets | 0.52.6 | 0.53.5 | windows-sys 0.52.0: `^0.52.0` |

Multiple versions of getrandom, syn, thiserror, thiserror-impl, and windows-sys also remain where required by different parents; see the full inventory below.

## Container and build tooling

- Rust Alpine builder: refreshed to the current multi-architecture index, Rust 1.99.1, digest `sha256:7e9e2d068a107a2adafd19930011178d14a78326053cd4c3a9f7ad3fd049557d`.
- Alpine runtime: refreshed to 3.24.3, multi-architecture index digest `sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a`.
- QEMU/binfmt release helper: refreshed and pinned by multi-architecture digest `sha256:400a4873b838d1b89194d982c45e5fb3cda4593fbfd7e08a02e76b03b21166f0`.
- Cross-build script: same pinned Rust builder, cargo-zigbuild 0.24.0 with locked installation, and Cargo.lock copied and honored for application builds.
- Integration harness: kind 0.27.0 → 0.33.0; MetalLB 0.14.9 → 0.16.1; HAProxy 3.1-alpine → 3.4-alpine.

## CI actions and scanner

All actions remain pinned to verified commit SHAs. The SonarQube action changed from v8.3.0 to v8.4.0; Trivy changed from v0.76.0 to v0.76.1.

| Upstream | Latest checked release | Pinned commit |
| --- | --- | --- |
| [actions/checkout](https://github.com/actions/checkout/releases/tag/v7.0.1) | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| [actions/cache](https://github.com/actions/cache/releases/tag/v6.1.0) | v6.1.0 | `55cc8345863c7cc4c66a329aec7e433d2d1c52a9` |
| [actions/upload-artifact](https://github.com/actions/upload-artifact/releases/tag/v7.0.2) | v7.0.2 | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` |
| [SonarSource/sonarqube-scan-action](https://github.com/SonarSource/sonarqube-scan-action/releases/tag/v8.4.0) | v8.4.0 | `4d1dc0c91ee400dcf8a6dddf2f705ac36542e304` |
| [EmbarkStudios/cargo-deny-action](https://github.com/EmbarkStudios/cargo-deny-action/releases/tag/v2.1.1) | v2.1.1 | `3c6349835b2b7b196a839186cb8b78e02f7b5f25` |
| [aquasecurity/trivy-action](https://github.com/aquasecurity/trivy-action/releases/tag/v0.36.0) | v0.36.0 | `ed142fd0673e97e23eac54620cfb913e5ce36c25` |
| [aquasecurity/trivy](https://github.com/aquasecurity/trivy/releases/tag/v0.76.1) | v0.76.1 | `e713f67f7d54decdcd9b3132c9751833dcced698` |
| [dtolnay/rust-toolchain](https://github.com/dtolnay/rust-toolchain) | stable | `b725eda525362e7cf34af9a7243cac1e3f01a7ec` |

## Validation

- Original release suite, all features: 85 passed.
- Updated release suite, all features: 85 passed.
- Updated release suite, no default features: 76 passed.
- Rust 1.89.0 minimum-version check, all targets/all features: passed.
- Strict Clippy, all targets with all features and no default features: passed.
- CLI without TLS, all-target compilation check: passed.
- Formatting: passed.
- Library dependency isolation: passed; no clap, mimalloc, or dnsstamps in the TLS-only library dependency tree.
- cargo-deny 0.20.2, all features: advisories, bans, licenses, and sources passed.
- Workflow/Compose YAML, PowerShell syntax, shell syntax, and both HAProxy configurations on HAProxy 3.4: passed.
- Production container build, using the updated Dockerfile and lockfile: passed (linux/amd64).
- Existing container smoke suite: passed, including arbitrary UID 20001:0, read-only rootfs, CLI/environment handling, real upstream DNS resolution, health checks, and metrics.
- Existing live HTTPS/HTTP2 protocol suite: 73/73 passed. The 500-request flood returned 152 successful responses and 348 rate-limit responses, with no dropped requests; recovery passed.
- Trivy 0.76.1 image scan: zero fixable HIGH/CRITICAL OS vulnerabilities. Rust dependencies are covered by cargo-deny; Trivy did not identify language package metadata in the compiled binary.
- Helm strict lint: passed for default, OpenShift Route, and Kubernetes LoadBalancer/Ingress configurations.
- Full Kubernetes/OpenShift provisioning, Windows cross-build, and multi-architecture publishing: not executed locally; remain CI/release checks.

## Complete Rust package inventory

Latest means the newest stable, non-yanked release reported by crates.io at review time, rather than a prerelease. Older platform versions and major-version duplicates can be intentional upstream requirements. The discarded UI is not part of main and its leftover node_modules/dist directories were excluded from this review and container build context.

| Package | Previous lock | Updated lock | Latest stable |
| --- | --- | --- | --- |
| [aead](https://crates.io/crates/aead) | 0.6.1 | 0.6.1 | 0.6.1 |
| [aes](https://crates.io/crates/aes) | 0.9.3 | 0.9.4 | 0.9.4 |
| [aes-gcm](https://crates.io/crates/aes-gcm) | 0.11.1 | 0.11.1 | 0.11.1 |
| [anstream](https://crates.io/crates/anstream) | 1.0.0 | 1.0.0 | 1.0.0 |
| [anstyle](https://crates.io/crates/anstyle) | 1.0.14 | 1.0.14 | 1.0.14 |
| [anstyle-parse](https://crates.io/crates/anstyle-parse) | 1.0.0 | 1.0.0 | 1.0.0 |
| [anstyle-query](https://crates.io/crates/anstyle-query) | 1.1.5 | 1.1.5 | 1.1.5 |
| [anstyle-wincon](https://crates.io/crates/anstyle-wincon) | 3.0.11 | 3.0.11 | 3.0.11 |
| [arc-swap](https://crates.io/crates/arc-swap) | 1.9.2 | 1.9.3 | 1.9.3 |
| [atomic-waker](https://crates.io/crates/atomic-waker) | 1.1.2 | 1.1.2 | 1.1.2 |
| [base64](https://crates.io/crates/base64) | 0.23.1 | 0.23.1 | 0.23.1 |
| [bitflags](https://crates.io/crates/bitflags) | 2.13.2 | 2.13.2 | 2.13.2 |
| [block-buffer](https://crates.io/crates/block-buffer) | 0.12.1 | 0.12.1 | 0.12.1 |
| [byteorder](https://crates.io/crates/byteorder) | 1.5.0 | 1.5.0 | 1.5.0 |
| [bytes](https://crates.io/crates/bytes) | 1.12.1 | 1.12.1 | 1.12.1 |
| [cc](https://crates.io/crates/cc) | 1.8.0 | 1.11.0 | 1.11.0 |
| [cfg-if](https://crates.io/crates/cfg-if) | 1.0.5 | 1.0.5 | 1.0.5 |
| [chacha20](https://crates.io/crates/chacha20) | 0.10.2 | 0.10.2 | 0.10.2 |
| [cipher](https://crates.io/crates/cipher) | 0.5.2 | 0.5.2 | 0.5.2 |
| [clap](https://crates.io/crates/clap) | 4.6.7 | 4.6.7 | 4.6.7 |
| [clap_builder](https://crates.io/crates/clap_builder) | 4.6.7 | 4.6.7 | 4.6.7 |
| [clap_lex](https://crates.io/crates/clap_lex) | 1.1.1 | 1.1.1 | 1.1.1 |
| [cmov](https://crates.io/crates/cmov) | 0.5.4 | 0.5.4 | 0.5.4 |
| [colorchoice](https://crates.io/crates/colorchoice) | 1.0.5 | 1.0.5 | 1.0.5 |
| [const-oid](https://crates.io/crates/const-oid) | 0.10.2 | 0.10.2 | 0.10.2 |
| [cpubits](https://crates.io/crates/cpubits) | 0.1.1 | 0.1.1 | 0.1.1 |
| [cpufeatures](https://crates.io/crates/cpufeatures) | 0.3.1 | 0.3.1 | 0.3.1 |
| [crypto-common](https://crates.io/crates/crypto-common) | 0.2.2 | 0.2.2 | 0.2.2 |
| [ct-codecs](https://crates.io/crates/ct-codecs) | 1.1.8 | 1.1.8 | 1.1.8 |
| [ctr](https://crates.io/crates/ctr) | 0.10.1 | 0.10.1 | 0.10.1 |
| [ctutils](https://crates.io/crates/ctutils) | 0.4.3 | 0.4.7 | 0.4.7 |
| [curve25519-dalek](https://crates.io/crates/curve25519-dalek) | 5.0.0 | 5.0.0 | 5.0.0 |
| [curve25519-dalek-derive](https://crates.io/crates/curve25519-dalek-derive) | 0.1.1 | 0.1.1 | 0.1.1 |
| [digest](https://crates.io/crates/digest) | 0.11.3 | 0.11.3 | 0.11.3 |
| [dnsstamps](https://crates.io/crates/dnsstamps) | 0.1.11 | 0.1.11 | 0.1.11 |
| [equivalent](https://crates.io/crates/equivalent) | 1.0.3 | 1.0.3 | 1.0.3 |
| [errno](https://crates.io/crates/errno) | 0.3.14 | 0.3.14 | 0.3.14 |
| [fiat-crypto](https://crates.io/crates/fiat-crypto) | 0.3.0 | 0.3.0 | 0.3.0 |
| [find-msvc-tools](https://crates.io/crates/find-msvc-tools) | 0.1.14 | 0.1.15 | 0.1.15 |
| [fnv](https://crates.io/crates/fnv) | 1.0.7 | 1.0.7 | 1.0.7 |
| [futures-channel](https://crates.io/crates/futures-channel) | 0.3.34 | 0.3.34 | 0.3.34 |
| [futures-core](https://crates.io/crates/futures-core) | 0.3.34 | 0.3.34 | 0.3.34 |
| [futures-sink](https://crates.io/crates/futures-sink) | 0.3.34 | 0.3.34 | 0.3.34 |
| [getrandom](https://crates.io/crates/getrandom) | 0.2.17, 0.4.3 | 0.2.17, 0.4.3 | 0.4.3 |
| [ghash](https://crates.io/crates/ghash) | 0.6.0 | 0.6.0 | 0.6.0 |
| [h2](https://crates.io/crates/h2) | 0.4.20 | 0.4.20 | 0.4.20 |
| [hashbrown](https://crates.io/crates/hashbrown) | 0.17.1 | 0.17.1 | 0.17.1 |
| [hkdf](https://crates.io/crates/hkdf) | 0.13.0 | 0.13.0 | 0.13.0 |
| [hmac](https://crates.io/crates/hmac) | 0.13.0 | 0.13.0 | 0.13.0 |
| [hpke](https://crates.io/crates/hpke) | 0.14.1 | 0.14.1 | 0.15.1 |
| [http](https://crates.io/crates/http) | 1.5.0 | 1.5.0 | 1.5.0 |
| [http-body](https://crates.io/crates/http-body) | 1.1.0 | 1.1.0 | 1.1.0 |
| [http-body-util](https://crates.io/crates/http-body-util) | 0.1.5 | 0.1.5 | 0.1.5 |
| [httparse](https://crates.io/crates/httparse) | 1.10.1 | 1.10.1 | 1.10.1 |
| [httpdate](https://crates.io/crates/httpdate) | 1.0.3 | 1.0.3 | 1.0.3 |
| [hybrid-array](https://crates.io/crates/hybrid-array) | 0.4.15 | 0.4.15 | 0.4.15 |
| [hyper](https://crates.io/crates/hyper) | 1.12.0 | 1.12.0 | 1.12.0 |
| [hyper-util](https://crates.io/crates/hyper-util) | 0.1.21 | 0.1.21 | 0.1.21 |
| [indexmap](https://crates.io/crates/indexmap) | 2.14.2 | 2.14.2 | 2.14.2 |
| [inout](https://crates.io/crates/inout) | 0.2.4 | 0.2.5 | 0.2.5 |
| [is_terminal_polyfill](https://crates.io/crates/is_terminal_polyfill) | 1.70.2 | 1.70.2 | 1.70.2 |
| [itoa](https://crates.io/crates/itoa) | 1.0.18 | 1.0.18 | 1.0.18 |
| [libc](https://crates.io/crates/libc) | 0.2.191 | 0.2.191 | 0.2.191 |
| [libmimalloc-sys](https://crates.io/crates/libmimalloc-sys) | 0.1.49 | 0.1.49 | 0.1.49 |
| [linux-raw-sys](https://crates.io/crates/linux-raw-sys) | 0.12.1 | 0.12.1 | 0.12.1 |
| [log](https://crates.io/crates/log) | 0.4.34 | 0.4.35 | 0.4.35 |
| [memchr](https://crates.io/crates/memchr) | 2.8.3 | 2.8.3 | 2.8.3 |
| [mimalloc](https://crates.io/crates/mimalloc) | 0.1.52 | 0.1.52 | 0.1.52 |
| [mio](https://crates.io/crates/mio) | 1.2.4 | 1.2.4 | 1.2.4 |
| [odoh-rs](https://crates.io/crates/odoh-rs) | 1.0.5 | 1.0.5 | 1.0.5 |
| [once_cell](https://crates.io/crates/once_cell) | 1.21.4 | 1.21.4 | 1.21.4 |
| [once_cell_polyfill](https://crates.io/crates/once_cell_polyfill) | 1.70.2 | 1.70.2 | 1.70.2 |
| [pin-project-lite](https://crates.io/crates/pin-project-lite) | 0.2.17 | 0.2.17 | 0.2.17 |
| [polyval](https://crates.io/crates/polyval) | 0.7.3 | 0.7.3 | 0.7.3 |
| [proc-macro2](https://crates.io/crates/proc-macro2) | 1.0.107 | 1.0.107 | 1.0.107 |
| [quote](https://crates.io/crates/quote) | 1.0.47 | 1.0.47 | 1.0.47 |
| [r-efi](https://crates.io/crates/r-efi) | 6.0.0 | 6.0.0 | 7.1.0 |
| [rand](https://crates.io/crates/rand) | 0.10.3 | 0.10.3 | 0.10.3 |
| [rand_core](https://crates.io/crates/rand_core) | 0.10.1 | 0.10.1 | 0.10.1 |
| [ring](https://crates.io/crates/ring) | 0.17.14 | 0.17.14 | 0.17.14 |
| [rustc_version](https://crates.io/crates/rustc_version) | 0.4.1 | 0.4.1 | 0.4.1 |
| [rustix](https://crates.io/crates/rustix) | 1.1.5 | 1.1.6 | 1.1.6 |
| [rustls](https://crates.io/crates/rustls) | 0.23.46 | 0.23.46 | 0.23.46 |
| [rustls-pki-types](https://crates.io/crates/rustls-pki-types) | 1.15.1 | 1.15.1 | 1.15.1 |
| [rustls-webpki](https://crates.io/crates/rustls-webpki) | 0.103.15 | 0.103.16 | 0.103.16 |
| [rustversion](https://crates.io/crates/rustversion) | 1.0.23 | 1.0.23 | 1.0.23 |
| [semver](https://crates.io/crates/semver) | 1.0.28 | 1.0.28 | 1.0.28 |
| [serde](https://crates.io/crates/serde) | 1.0.229 | 1.0.229 | 1.0.229 |
| [serde_core](https://crates.io/crates/serde_core) | 1.0.229 | 1.0.229 | 1.0.229 |
| [serde_derive](https://crates.io/crates/serde_derive) | 1.0.229 | 1.0.229 | 1.0.229 |
| [serde_json](https://crates.io/crates/serde_json) | 1.0.154 | 1.0.154 | 1.0.154 |
| [sha2](https://crates.io/crates/sha2) | 0.11.1 | 0.11.1 | 0.11.1 |
| [shlex](https://crates.io/crates/shlex) | 2.0.1 | 2.0.1 | 2.0.1 |
| [signal-hook-registry](https://crates.io/crates/signal-hook-registry) | 1.4.8 | 1.4.8 | 1.4.8 |
| [slab](https://crates.io/crates/slab) | 0.4.12 | 0.4.12 | 0.4.12 |
| [smallvec](https://crates.io/crates/smallvec) | 1.16.3 | 1.16.4 | 1.16.4 |
| [socket2](https://crates.io/crates/socket2) | 0.6.5 | 0.6.5 | 0.6.5 |
| [strsim](https://crates.io/crates/strsim) | 0.11.1 | 0.11.1 | 0.11.1 |
| [subtle](https://crates.io/crates/subtle) | 2.6.1 | 2.6.1 | 2.6.1 |
| [syn](https://crates.io/crates/syn) | 2.0.119, 3.0.9 | 2.0.119, 3.0.9 | 3.0.9 |
| [terminal_size](https://crates.io/crates/terminal_size) | 0.4.4 | 0.4.4 | 0.4.4 |
| [thiserror](https://crates.io/crates/thiserror) | 1.0.69, 2.0.21 | 1.0.69, 2.0.21 | 2.0.21 |
| [thiserror-impl](https://crates.io/crates/thiserror-impl) | 1.0.69, 2.0.21 | 1.0.69, 2.0.21 | 2.0.21 |
| [tokio](https://crates.io/crates/tokio) | 1.53.3 | 1.54.1 | 1.54.1 |
| [tokio-macros](https://crates.io/crates/tokio-macros) | 2.7.2 | 2.7.2 | 2.7.2 |
| [tokio-rustls](https://crates.io/crates/tokio-rustls) | 0.26.6 | 0.26.6 | 0.26.6 |
| [tokio-util](https://crates.io/crates/tokio-util) | 0.7.20 | 0.7.20 | 0.7.20 |
| [tracing](https://crates.io/crates/tracing) | 0.1.44 | 0.1.44 | 0.1.44 |
| [tracing-attributes](https://crates.io/crates/tracing-attributes) | 0.1.31 | 0.1.31 | 0.1.31 |
| [tracing-core](https://crates.io/crates/tracing-core) | 0.1.36 | 0.1.36 | 0.1.36 |
| [try-lock](https://crates.io/crates/try-lock) | 0.2.5 | 0.2.5 | 0.2.5 |
| [typenum](https://crates.io/crates/typenum) | 1.20.1 | 1.20.1 | 1.20.1 |
| [unicode-ident](https://crates.io/crates/unicode-ident) | 1.0.27 | 1.0.27 | 1.0.27 |
| [universal-hash](https://crates.io/crates/universal-hash) | 0.6.1 | 0.6.1 | 0.6.1 |
| [untrusted](https://crates.io/crates/untrusted) | 0.9.0 | 0.9.0 | 0.9.0 |
| [urlencoding](https://crates.io/crates/urlencoding) | 2.1.3 | 2.1.3 | 2.1.3 |
| [utf8parse](https://crates.io/crates/utf8parse) | 0.2.2 | 0.2.2 | 0.2.2 |
| [valuable](https://crates.io/crates/valuable) | 0.1.1 | 0.1.1 | 0.1.1 |
| [want](https://crates.io/crates/want) | 0.3.2 | 0.3.2 | 0.3.2 |
| [wasi](https://crates.io/crates/wasi) | 0.11.1+wasi-snapshot-preview1 | 0.11.1+wasi-snapshot-preview1 | 0.14.7+wasi-0.2.4 |
| [windows_aarch64_gnullvm](https://crates.io/crates/windows_aarch64_gnullvm) | 0.52.6 | 0.52.6 | 0.53.1 |
| [windows_aarch64_msvc](https://crates.io/crates/windows_aarch64_msvc) | 0.52.6 | 0.52.6 | 0.53.1 |
| [windows_i686_gnu](https://crates.io/crates/windows_i686_gnu) | 0.52.6 | 0.52.6 | 0.53.1 |
| [windows_i686_gnullvm](https://crates.io/crates/windows_i686_gnullvm) | 0.52.6 | 0.52.6 | 0.53.1 |
| [windows_i686_msvc](https://crates.io/crates/windows_i686_msvc) | 0.52.6 | 0.52.6 | 0.53.1 |
| [windows_x86_64_gnu](https://crates.io/crates/windows_x86_64_gnu) | 0.52.6 | 0.52.6 | 0.53.1 |
| [windows_x86_64_gnullvm](https://crates.io/crates/windows_x86_64_gnullvm) | 0.52.6 | 0.52.6 | 0.53.1 |
| [windows_x86_64_msvc](https://crates.io/crates/windows_x86_64_msvc) | 0.52.6 | 0.52.6 | 0.53.1 |
| [windows-link](https://crates.io/crates/windows-link) | 0.2.1 | 0.2.1 | 0.100.0 |
| [windows-sys](https://crates.io/crates/windows-sys) | 0.52.0, 0.61.2 | 0.52.0, 0.61.2 | 0.61.2 |
| [windows-targets](https://crates.io/crates/windows-targets) | 0.52.6 | 0.52.6 | 0.53.5 |
| [x25519-dalek](https://crates.io/crates/x25519-dalek) | 3.0.0 | 3.0.0 | 3.0.0 |
| [zeroize](https://crates.io/crates/zeroize) | 1.9.1 | 1.9.1 | 1.9.1 |
| [zeroize_derive](https://crates.io/crates/zeroize_derive) | 1.5.0 | 1.5.0 | 1.5.0 |
| [zmij](https://crates.io/crates/zmij) | 1.0.23 | 1.0.23 | 1.0.23 |
