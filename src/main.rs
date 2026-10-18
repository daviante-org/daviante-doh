//! `daviante-doh` standalone binary entrypoint by Daviante (<https://daviante.org>).

#![forbid(unsafe_code)]

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    if let Err(err) = daviante_doh::cli::run_from_env() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
