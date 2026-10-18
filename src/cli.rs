//! `daviante-doh` CLI argument parser, structured tracing subscriber, DNS Stamp generator,
//! self-contained healthcheck probe, and server runtime bootstrap.

#![cfg(feature = "cli")]
#![allow(clippy::unwrap_used)]

use std::ffi::OsString;
use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::mpsc::{self, SyncSender};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::builder::BoolishValueParser;
use clap::{Arg, ArgAction, ArgMatches, Command};
use serde_json::{json, Map, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::Level;
use tracing_core::field::{Field, Visit};
use tracing_core::{Event, Interest, Metadata, Subscriber};

use crate::{
    serve_with_admin_and_shutdown, BlockAction, ClientIpLogMode, DohConfig, DohEngine, IpNet,
    OdohKeyManager,
};

/// Removes any `DOH_*` environment variables whose values are empty or whitespace-only.
///
/// Must be called at the start of synchronous `fn main()` before starting the multi-threaded
/// Tokio runtime or invoking `clap` (fixes C-3 where Kubernetes ConfigMaps / Compose files
/// inject `DOH_PUBLIC_PORT=""`).
pub fn sanitize_empty_doh_env_vars() {
    let empty_keys: Vec<OsString> = std::env::vars_os()
        .filter_map(|(k, v)| {
            let k_str = k.to_string_lossy();
            if k_str.starts_with("DOH_") && v.to_string_lossy().trim().is_empty() {
                Some(k)
            } else {
                None
            }
        })
        .collect();
    for key in empty_keys {
        std::env::remove_var(key);
    }
}

fn bool_flag_arg(
    id: &'static str,
    long: &'static str,
    short: Option<char>,
    env_var: &'static str,
    help: &'static str,
) -> Arg {
    let mut arg = Arg::new(id)
        .long(long)
        .env(env_var)
        .num_args(0..=1)
        .require_equals(true)
        .default_value("false")
        .default_missing_value("true")
        .value_parser(BoolishValueParser::new())
        .action(ArgAction::Set)
        .help(help);
    if let Some(ch) = short {
        arg = arg.short(ch);
    }
    arg
}

fn u32_opt_arg(
    id: &'static str,
    long: &'static str,
    short: Option<char>,
    env_var: &'static str,
    default_val: &'static str,
    help: &'static str,
) -> Arg {
    let mut arg = Arg::new(id)
        .long(long)
        .env(env_var)
        .default_value(default_val)
        .value_parser(clap::value_parser!(u32))
        .help(help);
    if let Some(ch) = short {
        arg = arg.short(ch);
    }
    arg
}

fn usize_opt_arg(
    id: &'static str,
    long: &'static str,
    short: Option<char>,
    env_var: &'static str,
    default_val: &'static str,
    help: &'static str,
) -> Arg {
    let mut arg = Arg::new(id)
        .long(long)
        .env(env_var)
        .default_value(default_val)
        .value_parser(clap::value_parser!(usize))
        .help(help);
    if let Some(ch) = short {
        arg = arg.short(ch);
    }
    arg
}

pub fn build_cli() -> Command {
    Command::new("daviante-doh")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Daviante <https://daviante.org>")
        .about("Lightweight, standards-compliant DoH (RFC 8484), ODoH (RFC 9230), and JSON DoH server by Daviante (daviante.org)")
        .arg(
            Arg::new("listen_address")
                .short('l')
                .long("listen-address")
                .env("DOH_LISTEN_ADDRESS")
                .default_value("0.0.0.0:3000")
                .help("Socket address to listen on (IP:port or :port)"),
        )
        .arg(
            Arg::new("admin_listen_address")
                .long("admin-listen-address")
                .env("DOH_ADMIN_LISTEN_ADDRESS")
                .help("Dedicated admin socket address for /livez, /readyz, /healthz, and /metrics (off by default)"),
        )
        .arg(
            Arg::new("server_address")
                .short('u')
                .long("server-address")
                .env("DOH_SERVER_ADDRESS")
                .default_value("9.9.9.9:53")
                .help("Upstream DNS resolver address(es), comma-separated for automatic failover (e.g. 9.9.9.9:53,1.1.1.1:53)"),
        )
        .arg(
            Arg::new("local_bind_address")
                .short('b')
                .long("local-bind-address")
                .env("DOH_LOCAL_BIND_ADDRESS")
                .help("Local outbound socket address to bind when querying upstream"),
        )
        .arg(
            Arg::new("trusted_proxies")
                .long("trusted-proxies")
                .env("DOH_TRUSTED_PROXIES")
                .value_delimiter(',')
                .action(ArgAction::Append)
                .help("Trusted reverse-proxy CIDRs/IPs permitted to supply X-Forwarded-For / Forwarded headers (default empty)"),
        )
        .arg(
            Arg::new("hostname")
                .short('H')
                .long("hostname")
                .env("DOH_HOSTNAME")
                .help("Public hostname clients use to connect (prints DoH & ODoH DNS stamps)"),
        )
        .arg(
            Arg::new("public_address")
                .short('g')
                .long("public-address")
                .env("DOH_PUBLIC_ADDRESS")
                .value_delimiter(',')
                .action(ArgAction::Append)
                .help("External IP address(es) clients connect to (can be repeated or comma-separated)"),
        )
        .arg(
            Arg::new("public_port")
                .short('j')
                .long("public-port")
                .env("DOH_PUBLIC_PORT")
                .value_parser(clap::value_parser!(u16))
                .help("External port clients connect to if not 443"),
        )
        .arg(
            Arg::new("path")
                .short('p')
                .long("path")
                .env("DOH_PATH")
                .default_value("/dns-query")
                .help("DoH URI path"),
        )
        .arg(
            Arg::new("odoh_configs_path")
                .long("odoh-configs-path")
                .env("DOH_ODOH_CONFIGS_PATH")
                .default_value("/.well-known/odohconfigs")
                .help("Oblivious DoH key configuration URI path (RFC 9230)"),
        )
        .arg(
            Arg::new("health_path")
                .long("health-path")
                .env("DOH_HEALTH_PATH")
                .default_value("/healthz")
                .help("Health check URI path alias for container/Kubernetes probes"),
        )
        .arg(bool_flag_arg(
            "enable_metrics",
            "enable-metrics",
            None,
            "DOH_ENABLE_METRICS",
            "Enable first-party Prometheus / OpenMetrics endpoint (off by default)",
        ))
        .arg(
            Arg::new("metrics_path")
                .long("metrics-path")
                .env("DOH_METRICS_PATH")
                .default_value("/metrics")
                .help("Prometheus / OpenMetrics URI path when --enable-metrics is set"),
        )
        .arg(usize_opt_arg(
            "max_clients",
            "max-clients",
            Some('c'),
            "DOH_MAX_CLIENTS",
            "512",
            "Maximum simultaneous client connections",
        ))
        .arg(usize_opt_arg(
            "max_conns_per_ip",
            "max-conns-per-ip",
            None,
            "DOH_MAX_CONNS_PER_IP",
            "0",
            "Maximum simultaneous connections per client IP / IPv6 prefix (0 = disabled by default)",
        ))
        .arg(u32_opt_arg(
            "max_concurrent",
            "max-concurrent",
            Some('C'),
            "DOH_MAX_CONCURRENT",
            "16",
            "Maximum concurrent HTTP/2 streams per client connection",
        ))
        .arg(
            Arg::new("timeout")
                .short('t')
                .long("timeout")
                .env("DOH_TIMEOUT")
                .default_value("10")
                .value_parser(clap::value_parser!(u64).range(1..=3600))
                .help("Request time budget in seconds (1..=3600)"),
        )
        .arg(
            Arg::new("shutdown_grace_secs")
                .long("shutdown-grace-secs")
                .env("DOH_SHUTDOWN_GRACE_SECS")
                .default_value("25")
                .value_parser(clap::value_parser!(u64).range(1..=600))
                .help("Graceful shutdown connection drain period in seconds"),
        )
        .arg(u32_opt_arg(
            "min_ttl",
            "min-ttl",
            Some('T'),
            "DOH_MIN_TTL",
            "0",
            "Minimum internal cache retention TTL in seconds (0 = disabled per RFC 8484 §5.1)",
        ))
        .arg(u32_opt_arg(
            "max_ttl",
            "max-ttl",
            Some('X'),
            "DOH_MAX_TTL",
            "604800",
            "Maximum caching TTL in seconds",
        ))
        .arg(u32_opt_arg(
            "err_ttl",
            "err-ttl",
            Some('E'),
            "DOH_ERR_TTL",
            "2",
            "TTL for error responses in seconds",
        ))
        .arg(u32_opt_arg(
            "stale_if_error",
            "stale-if-error",
            None,
            "DOH_STALE_IF_ERROR",
            "86400",
            "HTTP Cache-Control stale-if-error directive in seconds (0 = omit)",
        ))
        .arg(u32_opt_arg(
            "stale_while_revalidate",
            "stale-while-revalidate",
            None,
            "DOH_STALE_WHILE_REVALIDATE",
            "60",
            "HTTP Cache-Control stale-while-revalidate directive in seconds (0 = omit)",
        ))
        .arg(usize_opt_arg(
            "cache_size",
            "cache-size",
            None,
            "DOH_CACHE_SIZE",
            "0",
            "In-memory DNS cache capacity in entries (0 = disabled by default)",
        ))
        .arg(bool_flag_arg(
            "disable_keepalive",
            "disable-keepalive",
            Some('K'),
            "DOH_DISABLE_KEEPALIVE",
            "Disable HTTP keepalive",
        ))
        .arg(bool_flag_arg(
            "disable_post",
            "disable-post",
            Some('P'),
            "DOH_DISABLE_POST",
            "Disable HTTP POST queries for standard DoH",
        ))
        .arg(bool_flag_arg(
            "allow_odoh_post",
            "allow-odoh-post",
            Some('O'),
            "DOH_ALLOW_ODOH_POST",
            "Allow HTTP POST queries for Oblivious DoH even when --disable-post is set",
        ))
        .arg(bool_flag_arg(
            "disable_any",
            "disable-any",
            None,
            "DOH_DISABLE_ANY",
            "Refuse QTYPE=ANY queries per RFC 8482 with EDE 21 (off by default)",
        ))
        .arg(bool_flag_arg(
            "enable_ecs",
            "enable-ecs",
            None,
            "DOH_ENABLE_ECS",
            "Enable RFC 7871 EDNS Client Subnet forwarding (off by default)",
        ))
        .arg(
            Arg::new("ecs_prefix_v4")
                .long("ecs-prefix-v4")
                .env("DOH_ECS_PREFIX_V4")
                .default_value("24")
                .value_parser(clap::value_parser!(u8).range(0..=32))
                .help("IPv4 prefix length for EDNS Client Subnet (0..=32)"),
        )
        .arg(
            Arg::new("ecs_prefix_v6")
                .long("ecs-prefix-v6")
                .env("DOH_ECS_PREFIX_V6")
                .default_value("56")
                .value_parser(clap::value_parser!(u8).range(0..=128))
                .help("IPv6 prefix length for EDNS Client Subnet (0..=128)"),
        )
        .arg(
            Arg::new("odoh_rotation_secs")
                .long("odoh-rotation-secs")
                .env("DOH_ODOH_ROTATION_SECS")
                .default_value("86400")
                .value_parser(clap::value_parser!(u32).range(60..=604800))
                .help("Oblivious DoH HPKE key rotation interval in seconds"),
        )
        .arg(
            Arg::new("allowlist_file")
                .long("allowlist-file")
                .env("DOH_ALLOWLIST_FILE")
                .help("Path to Protective DNS domain allowlist file (off by default)"),
        )
        .arg(
            Arg::new("blocklist_file")
                .long("blocklist-file")
                .env("DOH_BLOCKLIST_FILE")
                .help("Path to Protective DNS domain blocklist file (off by default)"),
        )
        .arg(
            Arg::new("block_action")
                .long("block-action")
                .env("DOH_BLOCK_ACTION")
                .default_value("nxdomain")
                .help("Action when a domain is blocked: nxdomain (EDE 15), refused (EDE 18), or null (EDE 17)"),
        )
        .arg(u32_opt_arg(
            "rate_limit_rps",
            "rate-limit-rps",
            None,
            "DOH_RATE_LIMIT_RPS",
            "0",
            "Per-client IP rate limit in requests/sec (0 = disabled by default)",
        ))
        .arg(u32_opt_arg(
            "rate_limit_burst",
            "rate-limit-burst",
            None,
            "DOH_RATE_LIMIT_BURST",
            "20",
            "Per-client IP token-bucket burst capacity when --rate-limit-rps > 0",
        ))
        .arg(
            Arg::new("rate_limit_v6_prefix")
                .long("rate-limit-v6-prefix")
                .env("DOH_RATE_LIMIT_V6_PREFIX")
                .default_value("64")
                .value_parser(clap::value_parser!(u8).range(0..=128))
                .help("IPv6 prefix length used to aggregate rate-limit buckets (default 64)"),
        )
        .arg(
            Arg::new("cors_allow_origin")
                .long("cors-allow-origin")
                .env("DOH_CORS_ALLOW_ORIGIN")
                .default_value("*")
                .help("Value for Access-Control-Allow-Origin header"),
        )
        .arg(bool_flag_arg(
            "log_queries",
            "log-queries",
            None,
            "DOH_LOG_QUERIES",
            "Emit structured DNS query audit logs to stdout (off by default)",
        ))
        .arg(
            Arg::new("log_client_ip")
                .long("log-client-ip")
                .env("DOH_LOG_CLIENT_IP")
                .default_value("none")
                .help("Client IP logging mode in query audit logs: none (default, RFC 8932), truncated, or full"),
        )
        .arg(
            Arg::new("log_format")
                .long("log-format")
                .env("DOH_LOG_FORMAT")
                .default_value("json")
                .help("Structured log output format: json (default) or text"),
        )
        .arg(
            Arg::new("log_level")
                .long("log-level")
                .env("DOH_LOG")
                .default_value("info")
                .help("Minimum log level: error, warn, info, debug, or trace"),
        )
        .arg(
            Arg::new("tls_cert_path")
                .short('i')
                .long("tls-cert-path")
                .env("DOH_TLS_CERT_PATH")
                .help("Path to PEM-encoded TLS certificate chain (enables built-in HTTPS)"),
        )
        .arg(
            Arg::new("tls_cert_key_path")
                .short('I')
                .long("tls-cert-key-path")
                .env("DOH_TLS_CERT_KEY_PATH")
                .help("Path to PEM/PKCS#8-encoded TLS private key"),
        )
        .arg(
            Arg::new("tls_min_version")
                .long("tls-min-version")
                .env("DOH_TLS_MIN_VERSION")
                .default_value("1.2")
                .help("Minimum TLS protocol version when built-in HTTPS is enabled: 1.2 (default) or 1.3"),
        )
        .arg(
            Arg::new("print_config")
                .long("print-config")
                .action(ArgAction::SetTrue)
                .help("Validate and print effective configuration and exit 0"),
        )
        .arg(
            Arg::new("healthcheck")
                .long("healthcheck")
                .action(ArgAction::SetTrue)
                .help("Execute a self-contained liveness probe against the local listener and exit"),
        )
}

pub fn parse_socket_addr_flexible(raw: &str) -> Result<SocketAddr, String> {
    let trimmed = raw.trim();
    if let Some(port_str) = trimmed.strip_prefix(':') {
        let port: u16 = port_str
            .parse()
            .map_err(|e| format!("invalid port '{port_str}': {e}"))?;
        return Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port));
    }
    trimmed
        .parse::<SocketAddr>()
        .map_err(|e| format!("invalid socket address '{trimmed}': {e}"))
}

pub struct ParsedCli {
    pub config: DohConfig,
    pub hostname: Option<String>,
    pub public_ips: Vec<String>,
    pub public_port: Option<u16>,
    pub log_format: String,
    pub log_level: Level,
    pub print_config: bool,
    pub healthcheck: bool,
}

pub fn parse_from_matches(m: &ArgMatches) -> Result<ParsedCli, String> {
    let listen_str = m.get_one::<String>("listen_address").unwrap();
    let listen_address = parse_socket_addr_flexible(listen_str)?;

    let admin_listen_address = match m
        .get_one::<String>("admin_listen_address")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        Some(adm_str) => Some(parse_socket_addr_flexible(adm_str)?),
        None => None,
    };

    let server_str = m.get_one::<String>("server_address").unwrap();
    let mut upstream_addresses = Vec::new();
    for item in server_str.split(',') {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }
        let resolved = trimmed
            .to_socket_addrs()
            .map_err(|e| format!("invalid upstream server address '{trimmed}': {e}"))?
            .next()
            .ok_or_else(|| format!("could not resolve upstream server address '{trimmed}'"))?;
        upstream_addresses.push(resolved);
    }

    if upstream_addresses.is_empty() {
        return Err("at least one upstream server address must be specified".into());
    }
    let server_address = upstream_addresses[0];

    let local_bind_address: SocketAddr = match m.get_one::<String>("local_bind_address") {
        Some(s) if !s.trim().is_empty() => parse_socket_addr_flexible(s)?,
        _ => DohConfig::default_local_bind_for(server_address),
    };

    let mut trusted_proxies = Vec::new();
    if let Some(vals) = m.get_many::<String>("trusted_proxies") {
        for raw_cidr in vals {
            let trimmed = raw_cidr.trim();
            if trimmed.is_empty() {
                continue;
            }
            let net: IpNet = trimmed
                .parse()
                .map_err(|e: crate::DohError| e.to_string())?;
            trusted_proxies.push(net);
        }
    }

    let allowlist_file = m
        .get_one::<String>("allowlist_file")
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from);
    let blocklist_file = m
        .get_one::<String>("blocklist_file")
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from);
    let block_action_str = m.get_one::<String>("block_action").unwrap();
    let block_action = BlockAction::from_str_name(block_action_str).map_err(|e| e.to_string())?;

    let log_client_ip_str = m.get_one::<String>("log_client_ip").unwrap();
    let log_client_ip =
        ClientIpLogMode::from_str_name(log_client_ip_str).map_err(|e| e.to_string())?;

    let tls_cert_path = m
        .get_one::<String>("tls_cert_path")
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from);
    let tls_cert_key_path = m
        .get_one::<String>("tls_cert_key_path")
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .or_else(|| tls_cert_path.clone());

    #[cfg(feature = "tls")]
    let tls_min_version = {
        let ver_str = m.get_one::<String>("tls_min_version").unwrap();
        crate::TlsMinVersion::from_str_name(ver_str).map_err(|e| e.to_string())?
    };

    let cfg = DohConfig {
        listen_address,
        admin_listen_address,
        local_bind_address,
        server_address,
        upstream_addresses,
        trusted_proxies,
        path: m.get_one::<String>("path").unwrap().clone(),
        odoh_configs_path: m.get_one::<String>("odoh_configs_path").unwrap().clone(),
        health_path: m.get_one::<String>("health_path").unwrap().clone(),
        enable_metrics: m
            .get_one::<bool>("enable_metrics")
            .copied()
            .unwrap_or(false),
        metrics_path: m.get_one::<String>("metrics_path").unwrap().clone(),
        max_clients: *m.get_one::<usize>("max_clients").unwrap(),
        max_conns_per_ip: *m.get_one::<usize>("max_conns_per_ip").unwrap(),
        max_concurrent_streams: *m.get_one::<u32>("max_concurrent").unwrap(),
        timeout: Duration::from_secs(*m.get_one::<u64>("timeout").unwrap()),
        shutdown_grace_period: Duration::from_secs(
            *m.get_one::<u64>("shutdown_grace_secs").unwrap(),
        ),
        min_ttl: *m.get_one::<u32>("min_ttl").unwrap(),
        max_ttl: *m.get_one::<u32>("max_ttl").unwrap(),
        err_ttl: *m.get_one::<u32>("err_ttl").unwrap(),
        stale_if_error_secs: *m.get_one::<u32>("stale_if_error").unwrap(),
        stale_while_revalidate_secs: *m.get_one::<u32>("stale_while_revalidate").unwrap(),
        cache_size: *m.get_one::<usize>("cache_size").unwrap(),
        keepalive: !m
            .get_one::<bool>("disable_keepalive")
            .copied()
            .unwrap_or(false),
        disable_post: m.get_one::<bool>("disable_post").copied().unwrap_or(false),
        allow_odoh_post: m
            .get_one::<bool>("allow_odoh_post")
            .copied()
            .unwrap_or(false),
        disable_any: m.get_one::<bool>("disable_any").copied().unwrap_or(false),
        enable_ecs: m.get_one::<bool>("enable_ecs").copied().unwrap_or(false),
        ecs_prefix_v4: *m.get_one::<u8>("ecs_prefix_v4").unwrap(),
        ecs_prefix_v6: *m.get_one::<u8>("ecs_prefix_v6").unwrap(),
        odoh_rotation_secs: *m.get_one::<u32>("odoh_rotation_secs").unwrap(),
        allowlist_file,
        blocklist_file,
        block_action,
        rate_limit_rps: *m.get_one::<u32>("rate_limit_rps").unwrap(),
        rate_limit_burst: *m.get_one::<u32>("rate_limit_burst").unwrap(),
        rate_limit_v6_prefix: *m.get_one::<u8>("rate_limit_v6_prefix").unwrap(),
        cors_allow_origin: m.get_one::<String>("cors_allow_origin").unwrap().clone(),
        log_queries: m.get_one::<bool>("log_queries").copied().unwrap_or(false),
        log_client_ip,
        tls_cert_path,
        tls_cert_key_path,
        #[cfg(feature = "tls")]
        tls_min_version,
    };

    cfg.validate().map_err(|e| e.to_string())?;

    let hostname = m
        .get_one::<String>("hostname")
        .filter(|s| !s.trim().is_empty())
        .cloned();
    let public_ips: Vec<String> = m
        .get_many::<String>("public_address")
        .map(|vals| {
            vals.filter(|s| !s.trim().is_empty())
                .map(|s| s.trim().to_string())
                .collect()
        })
        .unwrap_or_default();
    let public_port = m.get_one::<u16>("public_port").copied();

    let log_format = m
        .get_one::<String>("log_format")
        .unwrap()
        .trim()
        .to_ascii_lowercase();
    let log_level = match m
        .get_one::<String>("log_level")
        .unwrap()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "error" => Level::ERROR,
        "warn" | "warning" => Level::WARN,
        "debug" => Level::DEBUG,
        "trace" => Level::TRACE,
        _ => Level::INFO,
    };

    Ok(ParsedCli {
        config: cfg,
        hostname,
        public_ips,
        public_port,
        log_format,
        log_level,
        print_config: m.get_flag("print_config"),
        healthcheck: m.get_flag("healthcheck"),
    })
}

pub fn format_config_summary(parsed: &ParsedCli) -> String {
    let c = &parsed.config;
    let upstreams_str = c
        .effective_upstreams()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let mut flags = vec![
        format!("--listen-address {}", c.listen_address),
        format!("--server-address {upstreams_str}"),
        format!("--local-bind-address {}", c.local_bind_address),
        format!("--path {}", c.path),
        format!("--odoh-configs-path {}", c.odoh_configs_path),
        format!("--health-path {}", c.health_path),
        format!("--metrics-path {}", c.metrics_path),
        format!("--max-clients {}", c.max_clients),
        format!("--max-conns-per-ip {}", c.max_conns_per_ip),
        format!("--max-concurrent {}", c.max_concurrent_streams),
        format!("--timeout {}", c.timeout.as_secs()),
        format!(
            "--shutdown-grace-secs {}",
            c.shutdown_grace_period.as_secs()
        ),
        format!("--min-ttl {}", c.min_ttl),
        format!("--max-ttl {}", c.max_ttl),
        format!("--err-ttl {}", c.err_ttl),
        format!("--stale-if-error {}", c.stale_if_error_secs),
        format!("--stale-while-revalidate {}", c.stale_while_revalidate_secs),
        format!("--cache-size {}", c.cache_size),
        format!("--ecs-prefix-v4 {}", c.ecs_prefix_v4),
        format!("--ecs-prefix-v6 {}", c.ecs_prefix_v6),
        format!("--odoh-rotation-secs {}", c.odoh_rotation_secs),
        format!("--block-action {}", c.block_action.as_str()),
        format!("--rate-limit-rps {}", c.rate_limit_rps),
        format!("--rate-limit-burst {}", c.rate_limit_burst),
        format!("--rate-limit-v6-prefix {}", c.rate_limit_v6_prefix),
        format!("--cors-allow-origin {}", c.cors_allow_origin),
        format!("--log-client-ip {}", c.log_client_ip.as_str()),
    ];
    if let Some(adm) = c.admin_listen_address {
        flags.push(format!("--admin-listen-address {adm}"));
    }
    if !c.trusted_proxies.is_empty() {
        let joined = c
            .trusted_proxies
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        flags.push(format!("--trusted-proxies {joined}"));
    }
    if let Some(ref host) = parsed.hostname {
        flags.push(format!("--hostname {host}"));
    }
    for ip in &parsed.public_ips {
        flags.push(format!("--public-address {ip}"));
    }
    if let Some(port) = parsed.public_port {
        flags.push(format!("--public-port {port}"));
    }
    if c.enable_metrics {
        flags.push("--enable-metrics".into());
    }
    if !c.keepalive {
        flags.push("--disable-keepalive".into());
    }
    if c.disable_post {
        flags.push("--disable-post".into());
    }
    if c.allow_odoh_post {
        flags.push("--allow-odoh-post".into());
    }
    if c.disable_any {
        flags.push("--disable-any".into());
    }
    if c.enable_ecs {
        flags.push("--enable-ecs".into());
    }
    if let Some(ref p) = c.allowlist_file {
        flags.push(format!("--allowlist-file {}", p.display()));
    }
    if let Some(ref p) = c.blocklist_file {
        flags.push(format!("--blocklist-file {}", p.display()));
    }
    if c.log_queries {
        flags.push("--log-queries".into());
    }
    if let Some(ref p) = c.tls_cert_path {
        flags.push(format!("--tls-cert-path {}", p.display()));
    }
    if let Some(ref p) = c.tls_cert_key_path {
        flags.push(format!("--tls-cert-key-path {}", p.display()));
    }
    #[cfg(feature = "tls")]
    flags.push(format!("--tls-min-version {}", c.tls_min_version.as_str()));

    format!("daviante-doh {}", flags.join(" "))
}

pub fn print_dns_stamps(
    hostname: &str,
    path: &str,
    public_ips: &[String],
    public_port: Option<u16>,
) {
    if public_ips.is_empty() {
        let mut doh_builder = dnsstamps::DoHBuilder::new(hostname.to_string(), path.to_string());
        if let Some(port) = public_port {
            doh_builder = doh_builder.with_port(port);
        }
        if let Ok(doh_stamp) = doh_builder.serialize() {
            println!("DoH DNS stamp for [{hostname}]: {doh_stamp}");
        }

        let mut odoh_builder =
            dnsstamps::ODoHTargetBuilder::new(hostname.to_string(), path.to_string());
        if let Some(port) = public_port {
            odoh_builder = odoh_builder.with_port(port);
        }
        if let Ok(odoh_stamp) = odoh_builder.serialize() {
            println!("ODoH Target DNS stamp for [{hostname}]: {odoh_stamp}");
        }
    } else {
        for ip in public_ips {
            let mut doh_builder =
                dnsstamps::DoHBuilder::new(hostname.to_string(), path.to_string())
                    .with_address(ip.clone());
            if let Some(port) = public_port {
                doh_builder = doh_builder.with_port(port);
            }
            if let Ok(doh_stamp) = doh_builder.serialize() {
                println!("DoH DNS stamp for [{ip}] ({hostname}): {doh_stamp}");
            }
        }
    }
}

/// Non-blocking structured JSON / text `tracing` subscriber (M-4).
pub struct DohTracingSubscriber {
    pub max_level: Level,
    pub json_format: bool,
    pub sender: SyncSender<String>,
}

struct JsonFieldVisitor {
    fields: Map<String, Value>,
}

impl Visit for JsonFieldVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.fields.insert(
            field.name().to_string(),
            Value::String(format!("{value:?}")),
        );
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.fields
            .insert(field.name().to_string(), Value::String(value.to_string()));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields
            .insert(field.name().to_string(), Value::Number(value.into()));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.fields
            .insert(field.name().to_string(), Value::Number(value.into()));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.fields
            .insert(field.name().to_string(), Value::Bool(value));
    }
}

impl Subscriber for DohTracingSubscriber {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= &self.max_level
    }

    fn register_callsite(&self, metadata: &'static Metadata<'static>) -> Interest {
        if self.enabled(metadata) {
            Interest::always()
        } else {
            Interest::never()
        }
    }

    fn new_span(&self, _span: &tracing_core::span::Attributes<'_>) -> tracing_core::span::Id {
        tracing_core::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing_core::span::Id, _values: &tracing_core::span::Record<'_>) {}

    fn record_follows_from(
        &self,
        _span: &tracing_core::span::Id,
        _follows: &tracing_core::span::Id,
    ) {
    }

    fn event(&self, event: &Event<'_>) {
        if !self.enabled(event.metadata()) {
            return;
        }
        let mut visitor = JsonFieldVisitor { fields: Map::new() };
        event.record(&mut visitor);

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let level_str = event.metadata().level().as_str();
        let target_str = event.metadata().target();

        let line = if self.json_format {
            let mut obj = Map::new();
            obj.insert("ts".into(), json!(ts));
            obj.insert("level".into(), json!(level_str));
            obj.insert("target".into(), json!(target_str));
            obj.insert("service".into(), json!("daviante-doh"));
            for (k, v) in visitor.fields {
                obj.insert(k, v);
            }
            format!("{}\n", Value::Object(obj))
        } else {
            let msg = visitor
                .fields
                .remove("message")
                .and_then(|v| v.as_str().map(ToString::to_string))
                .unwrap_or_default();
            format!(
                "{ts} [{level_str}] {target_str}: {msg} {:?}\n",
                visitor.fields
            )
        };

        let _ = self.sender.try_send(line);
    }

    fn enter(&self, _span: &tracing_core::span::Id) {}
    fn exit(&self, _span: &tracing_core::span::Id) {}
}

pub fn init_tracing(max_level: Level, log_format: &str) {
    let (tx, rx) = mpsc::sync_channel::<String>(4096);
    std::thread::Builder::new()
        .name("daviante-doh-log-writer".into())
        .spawn(move || {
            let mut stdout = std::io::stdout();
            while let Ok(line) = rx.recv() {
                let _ = stdout.write_all(line.as_bytes());
                let _ = stdout.flush();
            }
        })
        .ok();

    let sub = DohTracingSubscriber {
        max_level,
        json_format: log_format != "text",
        sender: tx,
    };
    let _ = tracing::subscriber::set_global_default(sub);
}

pub fn loopback_probe_target(listen: SocketAddr) -> SocketAddr {
    let ip = match listen.ip() {
        IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(v6) if v6.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        other => other,
    };
    SocketAddr::new(ip, listen.port())
}

/// Executes a self-contained healthcheck probe (`daviante-doh --healthcheck`) against the local admin or public listener (M-11).
pub async fn execute_self_healthcheck(config: &DohConfig) -> Result<(), String> {
    let (target_addr, use_tls) = match config.admin_listen_address {
        Some(adm) => (loopback_probe_target(adm), false),
        None => (
            loopback_probe_target(config.listen_address),
            config.tls_cert_path.is_some(),
        ),
    };

    let req_bytes = format!(
        "GET {} HTTP/1.1\r\nHost: localhost\r\nUser-Agent: daviante-doh-healthcheck\r\nConnection: close\r\n\r\n",
        config.health_path
    );

    let probe_fut = async {
        let tcp = TcpStream::connect(target_addr)
            .await
            .map_err(|e| format!("failed to connect to {target_addr}: {e}"))?;

        let mut resp_buf = vec![0u8; 512];
        let n = if use_tls {
            #[cfg(feature = "tls")]
            {
                let cert_path = config
                    .tls_cert_path
                    .as_deref()
                    .ok_or_else(|| "missing TLS cert path".to_string())?;
                let connector = crate::tls::build_pinned_healthcheck_connector(cert_path)
                    .map_err(|e| e.to_string())?;
                let server_name =
                    tokio_rustls::rustls::pki_types::ServerName::try_from("localhost")
                        .map_err(|e| e.to_string())?;
                let mut tls_stream = connector
                    .connect(server_name, tcp)
                    .await
                    .map_err(|e| format!("TLS healthcheck handshake failed: {e}"))?;
                tls_stream
                    .write_all(req_bytes.as_bytes())
                    .await
                    .map_err(|e| format!("TLS write failed: {e}"))?;
                tls_stream
                    .read(&mut resp_buf)
                    .await
                    .map_err(|e| format!("TLS read failed: {e}"))?
            }
            #[cfg(not(feature = "tls"))]
            {
                return Err(
                    "TLS healthcheck requested on binary built without 'tls' feature".into(),
                );
            }
        } else {
            let mut stream = tcp;
            stream
                .write_all(req_bytes.as_bytes())
                .await
                .map_err(|e| format!("HTTP write failed: {e}"))?;
            stream
                .read(&mut resp_buf)
                .await
                .map_err(|e| format!("HTTP read failed: {e}"))?
        };

        let status_line = String::from_utf8_lossy(&resp_buf[..n]);
        if status_line.starts_with("HTTP/1.1 200") || status_line.starts_with("HTTP/1.0 200") {
            Ok(())
        } else {
            Err(format!(
                "unexpected healthcheck status from {target_addr}: {}",
                status_line.lines().next().unwrap_or("")
            ))
        }
    };

    tokio::time::timeout(Duration::from_secs(4), probe_fut)
        .await
        .map_err(|_| format!("healthcheck timed out connecting to {target_addr}"))?
}

pub async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("failed to register SIGTERM");
        let mut sigint = signal(SignalKind::interrupt()).expect("failed to register SIGINT");
        tokio::select! {
            _ = sigterm.recv() => {},
            _ = sigint.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

pub async fn run_server_async<F>(config: DohConfig, shutdown: F) -> Result<(), String>
where
    F: std::future::Future<Output = ()> + Send,
{
    let odoh_keys = OdohKeyManager::spawn(
        tokio::runtime::Handle::current(),
        Duration::from_secs(config.odoh_rotation_secs as u64),
    )
    .map_err(|e| format!("Failed to initialize Oblivious DoH key manager: {e}"))?;

    let listener = TcpListener::bind(config.listen_address)
        .await
        .map_err(|e| {
            format!(
                "Failed to bind listening socket {}: {e}",
                config.listen_address
            )
        })?;

    let admin_listener = match config.admin_listen_address {
        Some(adm_addr) => Some(
            TcpListener::bind(adm_addr)
                .await
                .map_err(|e| format!("Failed to bind admin listening socket {adm_addr}: {e}"))?,
        ),
        None => None,
    };

    let scheme = if config.tls_cert_path.is_some() {
        "https"
    } else {
        "http"
    };
    let metrics_label = if config.enable_metrics {
        &config.metrics_path
    } else {
        "disabled"
    };
    println!(
        "daviante-doh v{} (daviante.org) listening on {}://{}{} (upstreams: {:?}, admin: {:?}, health: {}, cache_size: {}, metrics: {})",
        env!("CARGO_PKG_VERSION"),
        scheme,
        config.listen_address,
        config.path,
        config.effective_upstreams(),
        config.admin_listen_address,
        config.health_path,
        config.cache_size,
        metrics_label
    );

    let engine = DohEngine::new(config, odoh_keys)
        .map_err(|e| format!("Failed to initialize DohEngine: {e}"))?;

    serve_with_admin_and_shutdown(engine, listener, admin_listener, shutdown)
        .await
        .map_err(|e| format!("Server error: {e}"))
}

pub fn execute_parsed_cli<F>(parsed: ParsedCli, shutdown: F) -> Result<(), String>
where
    F: std::future::Future<Output = ()> + Send,
{
    if parsed.print_config {
        println!("{}", format_config_summary(&parsed));
        return Ok(());
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Failed to initialize Tokio runtime: {e}"))?;

    if parsed.healthcheck {
        return runtime
            .block_on(execute_self_healthcheck(&parsed.config))
            .map_err(|e| format!("Healthcheck failed: {e}"));
    }

    init_tracing(parsed.log_level, &parsed.log_format);

    if let Some(ref host) = parsed.hostname {
        print_dns_stamps(
            host,
            &parsed.config.path,
            &parsed.public_ips,
            parsed.public_port,
        );
    }

    runtime.block_on(run_server_async(parsed.config, shutdown))
}

pub fn run_from_env() -> Result<(), String> {
    sanitize_empty_doh_env_vars();
    let matches = build_cli().get_matches();
    parse_from_matches(&matches)
        .map_err(|e| format!("Configuration error: {e}"))
        .and_then(|parsed| execute_parsed_cli(parsed, wait_for_shutdown_signal()))
}
