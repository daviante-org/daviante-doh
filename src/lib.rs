//! # daviante-doh
//!
//! Lightweight, standards-compliant DNS-over-HTTPS (RFC 8484), Oblivious DoH (RFC 9230),
//! EDNS0 Padding/ECS (RFC 6891, RFC 7830, RFC 7871, RFC 8467), Extended DNS Errors (RFC 8914),
//! Protective DNS Enterprise Policy, and JSON DoH (`application/dns-json`) library and server
//! by Daviante (<https://daviante.org>).

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]

pub mod admin;
pub mod cache;
#[cfg(feature = "cli")]
#[doc(hidden)]
pub mod cli;
pub mod dns;
pub mod error;
pub mod http;
pub mod metrics;
pub mod policy;
#[cfg(feature = "tls")]
pub mod tls;
pub mod upstream;

pub use crate::cache::{CacheHit, CacheKey, DnsCache, MAX_CACHE_ENTRY_BYTES};
pub use crate::dns::ecs::{self, IpNet};
pub use crate::dns::json;
pub use crate::dns::odoh::{self, OdohActiveKey, OdohKeyManager, OdohKeyRing};
pub use crate::dns::wire;
pub use crate::error::DohError;
pub use crate::http::handler::{self, DohEngine, HttpBody, RequestFlavor};
pub use crate::metrics::DohMetrics;
pub use crate::policy::{BlockAction, DomainPolicy, IpRateLimiter};
#[cfg(feature = "tls")]
pub use crate::tls::TlsMinVersion;
pub use crate::upstream::{UpstreamSet, UpstreamStrategy, CIRCUIT_BREAKER_COOLDOWN};

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyper::body::Incoming;
use hyper::header::HeaderValue;
use hyper::service::Service;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as AutoConnBuilder;
use hyper_util::server::graceful::{GracefulShutdown, Watcher as GracefulWatcher};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Privacy-preserving client IP logging policy for query audit logs (RFC 8932, M-4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClientIpLogMode {
    /// Do not log client IP addresses (default, RFC 8932 §5.1).
    #[default]
    None,
    /// Log client IP truncated to `ecs_prefix_v4` / `ecs_prefix_v6` (e.g. `/24` and `/56`).
    Truncated,
    /// Log full client IP address (explicit enterprise opt-in).
    Full,
}

impl ClientIpLogMode {
    pub fn from_str_name(s: &str) -> Result<Self, DohError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "none" | "off" | "false" | "0" => Ok(Self::None),
            "truncated" | "subnet" | "masked" => Ok(Self::Truncated),
            "full" | "all" | "true" | "1" => Ok(Self::Full),
            other => Err(DohError::InvalidConfig(format!(
                "invalid client IP log mode '{other}' (expected none, truncated, or full)"
            ))),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Truncated => "truncated",
            Self::Full => "full",
        }
    }
}

/// Complete configuration for a `daviante-doh` server instance.
///
/// All optional enterprise features (caching, Prometheus `/metrics`, dedicated admin listener,
/// Protective DNS domain filtering, `ANY` blocking, rate limiting, per-IP connection limits,
/// trusted proxy headers, and query audit logging) are **disabled by default** unless explicitly enabled.
#[derive(Clone)]
pub struct DohConfig {
    pub listen_address: SocketAddr,
    pub admin_listen_address: Option<SocketAddr>,
    pub local_bind_address: SocketAddr,
    pub server_address: SocketAddr,
    pub upstream_addresses: Vec<SocketAddr>,
    pub trusted_proxies: Vec<IpNet>,
    pub path: String,
    pub odoh_configs_path: String,
    pub health_path: String,
    pub enable_metrics: bool,
    pub metrics_path: String,
    pub max_clients: usize,
    pub max_conns_per_ip: usize,
    pub max_concurrent_streams: u32,
    pub timeout: Duration,
    pub shutdown_grace_period: Duration,
    pub min_ttl: u32,
    pub max_ttl: u32,
    pub err_ttl: u32,
    pub stale_if_error_secs: u32,
    pub stale_while_revalidate_secs: u32,
    pub cache_size: usize,
    pub serve_stale_ttl: u32,
    pub cache_prefetch: bool,
    pub coalesce_queries: bool,
    pub upstream_strategy: UpstreamStrategy,
    pub upstream_dot_sni: Option<String>,
    pub keepalive: bool,
    pub disable_post: bool,
    pub allow_odoh_post: bool,
    pub disable_any: bool,
    pub enable_ecs: bool,
    pub ecs_prefix_v4: u8,
    pub ecs_prefix_v6: u8,
    pub odoh_rotation_secs: u32,
    pub allowlist_file: Option<PathBuf>,
    pub blocklist_file: Option<PathBuf>,
    pub hosts_file: Option<PathBuf>,
    pub dns_store_file: Option<PathBuf>,
    pub block_action: BlockAction,
    pub block_private_rebinding: bool,
    pub rate_limit_rps: u32,
    pub rate_limit_burst: u32,
    pub rate_limit_v6_prefix: u8,
    pub cors_allow_origin: String,
    pub log_queries: bool,
    pub log_client_ip: ClientIpLogMode,
    pub enable_admin_ui: bool,
    pub admin_ui_dir: Option<PathBuf>,
    pub admin_username: Option<String>,
    pub admin_password_hash: Option<String>,
    pub oidc_issuer_url: Option<String>,
    pub oidc_client_id: Option<String>,
    pub oidc_client_secret: Option<String>,
    pub oidc_redirect_uri: Option<String>,
    pub oidc_admin_role: String,
    pub oidc_viewer_role: String,
    pub tls_cert_path: Option<PathBuf>,
    pub tls_cert_key_path: Option<PathBuf>,
    #[cfg(feature = "tls")]
    pub tls_min_version: TlsMinVersion,
}

impl std::fmt::Debug for DohConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("DohConfig");
        s.field("listen_address", &self.listen_address)
            .field("admin_listen_address", &self.admin_listen_address)
            .field("local_bind_address", &self.local_bind_address)
            .field("server_address", &self.server_address)
            .field("upstream_addresses", &self.upstream_addresses)
            .field("trusted_proxies", &self.trusted_proxies)
            .field("path", &self.path)
            .field("odoh_configs_path", &self.odoh_configs_path)
            .field("health_path", &self.health_path)
            .field("enable_metrics", &self.enable_metrics)
            .field("metrics_path", &self.metrics_path)
            .field("max_clients", &self.max_clients)
            .field("max_conns_per_ip", &self.max_conns_per_ip)
            .field("max_concurrent_streams", &self.max_concurrent_streams)
            .field("timeout", &self.timeout)
            .field("shutdown_grace_period", &self.shutdown_grace_period)
            .field("min_ttl", &self.min_ttl)
            .field("max_ttl", &self.max_ttl)
            .field("err_ttl", &self.err_ttl)
            .field("stale_if_error_secs", &self.stale_if_error_secs)
            .field(
                "stale_while_revalidate_secs",
                &self.stale_while_revalidate_secs,
            )
            .field("cache_size", &self.cache_size)
            .field("serve_stale_ttl", &self.serve_stale_ttl)
            .field("cache_prefetch", &self.cache_prefetch)
            .field("coalesce_queries", &self.coalesce_queries)
            .field("upstream_strategy", &self.upstream_strategy)
            .field("upstream_dot_sni", &self.upstream_dot_sni)
            .field("keepalive", &self.keepalive)
            .field("disable_post", &self.disable_post)
            .field("allow_odoh_post", &self.allow_odoh_post)
            .field("disable_any", &self.disable_any)
            .field("enable_ecs", &self.enable_ecs)
            .field("ecs_prefix_v4", &self.ecs_prefix_v4)
            .field("ecs_prefix_v6", &self.ecs_prefix_v6)
            .field("odoh_rotation_secs", &self.odoh_rotation_secs)
            .field("allowlist_file", &self.allowlist_file)
            .field("blocklist_file", &self.blocklist_file)
            .field("hosts_file", &self.hosts_file)
            .field("dns_store_file", &self.dns_store_file)
            .field("block_action", &self.block_action)
            .field("block_private_rebinding", &self.block_private_rebinding)
            .field("rate_limit_rps", &self.rate_limit_rps)
            .field("rate_limit_burst", &self.rate_limit_burst)
            .field("rate_limit_v6_prefix", &self.rate_limit_v6_prefix)
            .field("cors_allow_origin", &self.cors_allow_origin)
            .field("log_queries", &self.log_queries)
            .field("log_client_ip", &self.log_client_ip)
            .field("enable_admin_ui", &self.enable_admin_ui)
            .field("admin_ui_dir", &self.admin_ui_dir)
            .field("admin_username", &self.admin_username)
            .field(
                "admin_password_hash",
                &self.admin_password_hash.as_ref().map(|_| "[REDACTED]"),
            )
            .field("oidc_issuer_url", &self.oidc_issuer_url)
            .field("oidc_client_id", &self.oidc_client_id)
            .field(
                "oidc_client_secret",
                &self.oidc_client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("oidc_redirect_uri", &self.oidc_redirect_uri)
            .field("oidc_admin_role", &self.oidc_admin_role)
            .field("oidc_viewer_role", &self.oidc_viewer_role)
            .field("tls_cert_path", &self.tls_cert_path)
            .field("tls_cert_key_path", &self.tls_cert_key_path);
        #[cfg(feature = "tls")]
        s.field("tls_min_version", &self.tls_min_version);
        s.finish()
    }
}

impl Default for DohConfig {
    fn default() -> Self {
        Self {
            listen_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 3000),
            admin_listen_address: None,
            local_bind_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            server_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 53),
            upstream_addresses: Vec::new(),
            trusted_proxies: Vec::new(),
            path: "/dns-query".to_string(),
            odoh_configs_path: "/.well-known/odohconfigs".to_string(),
            health_path: "/healthz".to_string(),
            enable_metrics: false,
            metrics_path: "/metrics".to_string(),
            max_clients: 512,
            max_conns_per_ip: 0,
            max_concurrent_streams: 16,
            timeout: Duration::from_secs(10),
            shutdown_grace_period: Duration::from_secs(25),
            min_ttl: 0,
            max_ttl: 604_800,
            err_ttl: 2,
            stale_if_error_secs: 86_400,
            stale_while_revalidate_secs: 60,
            cache_size: 0,
            serve_stale_ttl: 0,
            cache_prefetch: false,
            coalesce_queries: true,
            upstream_strategy: UpstreamStrategy::Failover,
            upstream_dot_sni: None,
            keepalive: true,
            disable_post: false,
            allow_odoh_post: false,
            disable_any: false,
            enable_ecs: false,
            ecs_prefix_v4: 24,
            ecs_prefix_v6: 56,
            odoh_rotation_secs: 86_400,
            allowlist_file: None,
            blocklist_file: None,
            hosts_file: None,
            dns_store_file: None,
            block_action: BlockAction::Nxdomain,
            block_private_rebinding: false,
            rate_limit_rps: 0,
            rate_limit_burst: 20,
            rate_limit_v6_prefix: 64,
            cors_allow_origin: "*".to_string(),
            log_queries: false,
            log_client_ip: ClientIpLogMode::None,
            enable_admin_ui: false,
            admin_ui_dir: None,
            admin_username: None,
            admin_password_hash: None,
            oidc_issuer_url: None,
            oidc_client_id: None,
            oidc_client_secret: None,
            oidc_redirect_uri: None,
            oidc_admin_role: "doh-admin".to_string(),
            oidc_viewer_role: "doh-viewer".to_string(),
            tls_cert_path: None,
            tls_cert_key_path: None,
            #[cfg(feature = "tls")]
            tls_min_version: TlsMinVersion::Tls12,
        }
    }
}

impl DohConfig {
    /// Returns the ordered list of upstream DNS resolvers to query (with failover).
    pub fn effective_upstreams(&self) -> Vec<SocketAddr> {
        if self.upstream_addresses.is_empty() {
            vec![self.server_address]
        } else {
            self.upstream_addresses.clone()
        }
    }

    /// Validates configuration bounds and header values before binding sockets (H-6).
    pub fn validate(&self) -> Result<(), DohError> {
        if self.max_clients == 0 {
            return Err(DohError::InvalidConfig(
                "max_clients must be at least 1".into(),
            ));
        }
        if self.max_concurrent_streams == 0 {
            return Err(DohError::InvalidConfig(
                "max_concurrent_streams must be at least 1".into(),
            ));
        }
        if self.timeout < Duration::from_secs(1) || self.timeout > Duration::from_secs(3600) {
            return Err(DohError::InvalidConfig(
                "timeout must be between 1 and 3600 seconds".into(),
            ));
        }
        if !self.path.starts_with('/') {
            return Err(DohError::InvalidConfig("path must start with '/'".into()));
        }
        if !self.odoh_configs_path.starts_with('/') {
            return Err(DohError::InvalidConfig(
                "odoh_configs_path must start with '/'".into(),
            ));
        }
        if !self.health_path.starts_with('/') {
            return Err(DohError::InvalidConfig(
                "health_path must start with '/'".into(),
            ));
        }
        if !self.metrics_path.starts_with('/') {
            return Err(DohError::InvalidConfig(
                "metrics_path must start with '/'".into(),
            ));
        }
        if self.ecs_prefix_v4 > 32 {
            return Err(DohError::InvalidConfig(
                "ecs_prefix_v4 must be <= 32".into(),
            ));
        }
        if self.ecs_prefix_v6 > 128 {
            return Err(DohError::InvalidConfig(
                "ecs_prefix_v6 must be <= 128".into(),
            ));
        }
        if self.rate_limit_v6_prefix > 128 {
            return Err(DohError::InvalidConfig(
                "rate_limit_v6_prefix must be <= 128".into(),
            ));
        }
        if self.cors_allow_origin.trim().is_empty()
            || HeaderValue::from_str(&self.cors_allow_origin).is_err()
        {
            return Err(DohError::InvalidConfig(format!(
                "cors_allow_origin '{}' is not a valid HTTP header value",
                self.cors_allow_origin
            )));
        }
        if self.enable_admin_ui {
            let has_local = self
                .admin_username
                .as_ref()
                .is_some_and(|u| !u.trim().is_empty())
                && self
                    .admin_password_hash
                    .as_ref()
                    .is_some_and(|h| !h.trim().is_empty());
            let has_oidc = self
                .oidc_issuer_url
                .as_ref()
                .is_some_and(|u| !u.trim().is_empty())
                && self
                    .oidc_client_id
                    .as_ref()
                    .is_some_and(|c| !c.trim().is_empty())
                && self
                    .oidc_redirect_uri
                    .as_ref()
                    .is_some_and(|r| !r.trim().is_empty());
            if !has_local && !has_oidc {
                return Err(DohError::InvalidConfig(
                    "enable_admin_ui requires either (--admin-username and --admin-password-hash) or (--oidc-issuer-url, --oidc-client-id, and --oidc-redirect-uri)".into(),
                ));
            }
            if let Some(ref phc) = self.admin_password_hash {
                if !phc.trim().is_empty() && !phc.trim().starts_with("$argon2id$v=19$") {
                    return Err(DohError::InvalidConfig(
                        "admin_password_hash must be an Argon2id v19 PHC string ($argon2id$v=19$...)".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Computes the matching unspecified local bind address (`0.0.0.0:0` or `[::]:0`) for `server_address`.
    pub fn default_local_bind_for(server_address: SocketAddr) -> SocketAddr {
        match server_address {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        }
    }
}

#[derive(Clone)]
struct ConnectionHandler {
    engine: DohEngine,
    peer_addr: Option<SocketAddr>,
    admin_only: bool,
}

impl Service<Request<Incoming>> for ConnectionHandler {
    type Response = Response<HttpBody>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let engine = self.engine.clone();
        let peer_addr = self.peer_addr;
        let admin_only = self.admin_only;
        Box::pin(async move {
            if admin_only {
                engine.handle_admin_request_with_peer(req, peer_addr).await
            } else {
                engine.handle_request(req, peer_addr).await
            }
        })
    }
}

/// Per-IP concurrent connection limiter (M-7). Disabled when `max_per_ip == 0`.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct PerIpConnLimiter {
    max_per_ip: usize,
    v6_prefix: u8,
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

#[doc(hidden)]
pub struct ActiveConnGuard {
    metrics: DohMetrics,
    ip_key: Option<IpAddr>,
    counts: Option<Arc<Mutex<HashMap<IpAddr, usize>>>>,
}

impl Drop for ActiveConnGuard {
    fn drop(&mut self) {
        self.metrics.dec_active_connections();
        if let (Some(key), Some(counts)) = (self.ip_key, &self.counts) {
            if let Ok(mut map) = counts.lock() {
                if let Some(c) = map.get_mut(&key) {
                    *c = c.saturating_sub(1);
                    if *c == 0 {
                        map.remove(&key);
                    }
                }
            }
        }
    }
}

impl PerIpConnLimiter {
    pub fn new(max_per_ip: usize, v6_prefix: u8) -> Self {
        Self {
            max_per_ip,
            v6_prefix: v6_prefix.min(128),
            counts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn normalize(&self, ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V4(v4) => IpAddr::V4(v4),
            IpAddr::V6(v6) => IpAddr::V6(ecs::mask_ipv6(v6, self.v6_prefix)),
        }
    }

    pub fn try_acquire(&self, peer_ip: IpAddr, metrics: DohMetrics) -> Option<ActiveConnGuard> {
        if self.max_per_ip == 0 {
            metrics.inc_active_connections();
            return Some(ActiveConnGuard {
                metrics,
                ip_key: None,
                counts: None,
            });
        }
        let key = self.normalize(peer_ip);
        let mut map = self.counts.lock().ok()?;
        let cur = map.get(&key).copied().unwrap_or(0);
        if cur >= self.max_per_ip {
            return None;
        }
        map.insert(key, cur + 1);
        drop(map);
        metrics.inc_active_connections();
        Some(ActiveConnGuard {
            metrics,
            ip_key: Some(key),
            counts: Some(Arc::clone(&self.counts)),
        })
    }
}

fn build_shared_http_builder(config: &DohConfig) -> Arc<AutoConnBuilder<TokioExecutor>> {
    let mut http_builder = AutoConnBuilder::new(TokioExecutor::new());
    http_builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(config.timeout)
        .keep_alive(config.keepalive)
        .pipeline_flush(true)
        .max_buf_size(64 * 1024);
    http_builder
        .http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(config.max_concurrent_streams)
        .max_pending_accept_reset_streams(Some(20))
        .max_local_error_reset_streams(Some(1024))
        .max_header_list_size(16 * 1024)
        .keep_alive_interval(Some(Duration::from_secs(30)))
        .keep_alive_timeout(Duration::from_secs(10));
    Arc::new(http_builder)
}

/// Runs the `daviante-doh` HTTP/1.1 & HTTP/2 server on `listener` until `shutdown` resolves,
/// then drains in-flight requests up to `config.shutdown_grace_period`.
pub async fn serve_with_shutdown<F>(
    engine: DohEngine,
    listener: TcpListener,
    shutdown: F,
) -> Result<(), DohError>
where
    F: Future<Output = ()> + Send,
{
    serve_with_admin_and_shutdown(engine, listener, None, shutdown).await
}

/// Runs the `daviante-doh` server on `listener` and an optional dedicated `admin_listener` (M-5)
/// until `shutdown` resolves, then sets `/readyz` to `503` and drains in-flight requests (H-8).
pub async fn serve_with_admin_and_shutdown<F>(
    engine: DohEngine,
    listener: TcpListener,
    admin_listener: Option<TcpListener>,
    shutdown: F,
) -> Result<(), DohError>
where
    F: Future<Output = ()> + Send,
{
    engine.config.validate()?;
    engine.policy.spawn_reload_watcher(
        engine.config.allowlist_file.clone(),
        engine.config.blocklist_file.clone(),
        engine.config.hosts_file.clone(),
        engine.config.block_action,
        engine.config.block_private_rebinding,
        Duration::from_secs(30),
    );
    let client_limiter = Arc::new(Semaphore::new(engine.config.max_clients));
    let ip_limiter = PerIpConnLimiter::new(
        engine.config.max_conns_per_ip,
        engine.config.rate_limit_v6_prefix,
    );
    let http_builder = build_shared_http_builder(&engine.config);
    let graceful = GracefulShutdown::new();

    #[cfg(feature = "tls")]
    let tls_acceptor = match (
        &engine.config.tls_cert_path,
        &engine.config.tls_cert_key_path,
    ) {
        (Some(cert), Some(key)) => Some(tls::ReloadableTlsAcceptor::spawn_with_version(
            cert.clone(),
            key.clone(),
            engine.config.tls_min_version,
        )?),
        (Some(cert), None) => Some(tls::ReloadableTlsAcceptor::spawn_with_version(
            cert.clone(),
            cert.clone(),
            engine.config.tls_min_version,
        )?),
        _ => None,
    };

    // If a dedicated admin listener is provided, spawn its accept loop in the background so
    // `/readyz` continues to respond (returning 503) during the graceful drain window.
    let (admin_stop_tx, mut admin_stop_rx) = tokio::sync::oneshot::channel::<()>();
    let admin_task = admin_listener.map(|adm_listener| {
        let adm_engine = engine.clone();
        let adm_builder = build_shared_http_builder(&engine.config);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = &mut admin_stop_rx => break,
                    res = adm_listener.accept() => {
                        if let Ok((stream, peer_addr)) = res {
                            let _ = stream.set_nodelay(true);
                            let svc = ConnectionHandler {
                                engine: adm_engine.clone(),
                                peer_addr: Some(peer_addr),
                                admin_only: true,
                            };
                            let b = Arc::clone(&adm_builder);
                            tokio::spawn(async move {
                                let conn = b.serve_connection(TokioIo::new(stream), svc);
                                let _ = conn.await;
                            });
                        }
                    }
                }
            }
        })
    });

    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => {
                engine.set_draining(true);
                tracing::info!(
                    grace_secs = engine.config.shutdown_grace_period.as_secs(),
                    "shutdown signal received; draining in-flight connections"
                );
                break;
            }
            accept_res = listener.accept() => {
                let (stream, peer_addr) = match accept_res {
                    Ok(pair) => pair,
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        continue;
                    }
                };
                let _ = stream.set_nodelay(true);

                // Non-blocking global admission control: drop immediately if at max_clients capacity
                let Ok(permit) = Arc::clone(&client_limiter).try_acquire_owned() else {
                    drop(stream);
                    continue;
                };

                // Optional per-IP concurrent connection cap (M-7)
                let Some(active_guard) = ip_limiter.try_acquire(peer_addr.ip(), engine.metrics.clone()) else {
                    drop(stream);
                    continue;
                };

                let engine_clone = engine.clone();
                let builder_clone = Arc::clone(&http_builder);
                let watcher = graceful.watcher();

                #[cfg(feature = "tls")]
                if let Some(ref reloadable_tls) = tls_acceptor {
                    let acceptor = reloadable_tls.get();
                    let hs_timeout = engine_clone.config.timeout;
                    tokio::spawn(async move {
                        if let Ok(Ok(tls_stream)) = tokio::time::timeout(hs_timeout, acceptor.accept(stream)).await {
                            serve_io_connection(
                                tls_stream,
                                peer_addr,
                                engine_clone,
                                builder_clone,
                                watcher,
                                permit,
                                active_guard,
                            ).await;
                        }
                    });
                    continue;
                }

                tokio::spawn(async move {
                    serve_io_connection(
                        stream,
                        peer_addr,
                        engine_clone,
                        builder_clone,
                        watcher,
                        permit,
                        active_guard,
                    ).await;
                });
            }
        }
    }

    // Drain in-flight HTTP/1.1 & HTTP/2 connections up to `shutdown_grace_period` (H-8)
    let _ = tokio::time::timeout(engine.config.shutdown_grace_period, graceful.shutdown()).await;
    let _ = admin_stop_tx.send(());
    if let Some(handle) = admin_task {
        let _ = handle.await;
    }

    Ok(())
}

async fn serve_io_connection<I>(
    io: I,
    peer_addr: SocketAddr,
    engine: DohEngine,
    http_builder: Arc<AutoConnBuilder<TokioExecutor>>,
    watcher: GracefulWatcher,
    _permit: OwnedSemaphorePermit,
    _active_guard: ActiveConnGuard,
) where
    I: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let service = ConnectionHandler {
        engine,
        peer_addr: Some(peer_addr),
        admin_only: false,
    };

    let conn = http_builder.serve_connection(TokioIo::new(io), service);
    let watched = watcher.watch(conn);
    let _ = watched.await;
}
