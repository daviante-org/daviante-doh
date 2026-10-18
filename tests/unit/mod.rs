//! Segregated unit tests for all `daviante-doh` modules (`src/**`).
//! Mounted inside `tests/integration.rs` so `src/` remains 100% pure production code
//! and `cargo llvm-cov --test integration --all-features` produces a single unified coverage report.

#[cfg(feature = "cli")]
mod cli_tests;
mod core_tests;
mod dns_tests;
mod http_tests;
