//! Clean-room upstream DNS resolver client with Circuit-Breaker Failover (`UpstreamSet`),
//! Load-Balancing Strategies (`failover`, `round-robin`, `parallel`), Singleflight In-Flight
//! Query Coalescing, Upstream DNS-over-TLS (`DoT`, RFC 7858), RFC 5452 §9.1 spoof-resistant
//! UDP verification, DNS Flag Day 2020 `1232`-byte EDNS0 UDP size, and RFC 7766 §6.2.1
//! persistent TCP connection pooling.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant as StdInstant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;
use tokio::time::Instant;

use crate::cache::CacheKey;
use crate::dns::ecs::attach_ecs_to_query;
use crate::dns::wire::{
    compute_response_ttl_with_floor, ensure_edns0_max_payload, finalize_wire_response_for_client,
    is_recoverable_error, is_truncated, matches_response_question, rewrite_question_from_client,
    validate_and_parse_query, MAX_DNS_MESSAGE_LEN, MIN_DNS_PACKET_LEN, UPSTREAM_EDNS_UDP_SIZE,
};
use crate::error::DohError;
use crate::metrics::DohMetrics;
use crate::DohConfig;

/// Default circuit-breaker cooldown duration when an upstream resolver fails (30 seconds).
pub const CIRCUIT_BREAKER_COOLDOWN: Duration = Duration::from_secs(30);
/// Maximum idle TCP connections retained per upstream resolver (RFC 7766 §6.2.1).
#[doc(hidden)]
pub const MAX_IDLE_TCP_PER_UPSTREAM: usize = 8;
/// Maximum idle lifetime of a pooled upstream TCP connection.
const TCP_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Upstream resolver selection and load-balancing strategy (`--upstream-strategy` / `DOH_UPSTREAM_STRATEGY`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UpstreamStrategy {
    /// Query healthy upstreams in configured priority order with circuit-breaker failover (default).
    #[default]
    Failover,
    /// Distribute queries evenly across healthy upstreams in round-robin rotation.
    RoundRobin,
    /// Race healthy upstreams concurrently and return the fastest valid response.
    Parallel,
}

impl UpstreamStrategy {
    pub fn from_str_name(s: &str) -> Result<Self, DohError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "failover" | "sequential" | "default" => Ok(Self::Failover),
            "round-robin" | "round_robin" | "roundrobin" | "rr" => Ok(Self::RoundRobin),
            "parallel" | "fastest" | "race" => Ok(Self::Parallel),
            other => Err(DohError::InvalidConfig(format!(
                "invalid upstream strategy '{other}' (expected failover, round-robin, or parallel)"
            ))),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Failover => "failover",
            Self::RoundRobin => "round-robin",
            Self::Parallel => "parallel",
        }
    }
}

/// Result of an upstream DNS exchange, containing both client-finalized and unpadded wire bytes and caching metadata.
#[derive(Debug, Clone)]
pub struct ResolvedDnsPacket {
    /// Wire-format DNS response finalized for the requesting client (468-byte padded if EDNS0, or OPT-stripped if non-EDNS0).
    pub wire_bytes: Vec<u8>,
    /// Unpadded wire-format DNS response (with OPT/EDE intact for cache storage and JSON decoding).
    pub unpadded_wire_bytes: Vec<u8>,
    /// RFC 8484 §5.1 HTTP freshness lifetime (`<= min(Answer RR TTLs)`).
    pub cache_ttl: u32,
    /// Internal cache retention TTL (`>= cache_ttl` when `min_ttl > 0` floor is configured).
    pub internal_cache_ttl: u32,
    pub age_secs: u32,
    pub ecs_attached: bool,
    pub cacheable: bool,
}

#[derive(Debug, Clone)]
enum CoalescedOutcome {
    Ok(ResolvedDnsPacket),
    Timeout,
    NetworkError(String),
}

type InflightReceiver = watch::Receiver<Option<CoalescedOutcome>>;
type InflightMap = HashMap<CacheKey, InflightReceiver>;

#[derive(Debug, Default)]
struct UpstreamCircuit {
    consecutive_failures: AtomicU32,
    open_until_ms: AtomicU64,
}

type TcpPoolMap = HashMap<SocketAddr, VecDeque<(TcpStream, StdInstant)>>;

/// Manages per-upstream circuit-breaker health state, load-balancing state, Singleflight
/// in-flight query coalescing, and a persistent RFC 7766 §6.2.1 TCP connection pool.
#[derive(Clone)]
pub struct UpstreamSet {
    epoch: StdInstant,
    cooldown_ms: u64,
    rr_counter: Arc<AtomicUsize>,
    circuits: Arc<Mutex<HashMap<SocketAddr, Arc<UpstreamCircuit>>>>,
    tcp_pool: Arc<Mutex<TcpPoolMap>>,
    inflight: Arc<Mutex<InflightMap>>,
    #[cfg(feature = "tls")]
    dot_connector: Arc<Mutex<Option<tokio_rustls::TlsConnector>>>,
}

impl std::fmt::Debug for UpstreamSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamSet")
            .field("cooldown_ms", &self.cooldown_ms)
            .finish()
    }
}

impl Default for UpstreamSet {
    fn default() -> Self {
        Self::new(CIRCUIT_BREAKER_COOLDOWN)
    }
}

struct InflightLeaderGuard {
    key: CacheKey,
    inflight: Arc<Mutex<InflightMap>>,
    tx: Option<watch::Sender<Option<CoalescedOutcome>>>,
}

impl InflightLeaderGuard {
    fn complete(mut self, outcome: CoalescedOutcome) {
        if let Ok(mut map) = self.inflight.lock() {
            map.remove(&self.key);
        }
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(Some(outcome));
        }
    }
}

impl Drop for InflightLeaderGuard {
    fn drop(&mut self) {
        if let Some(tx) = self.tx.take() {
            if let Ok(mut map) = self.inflight.lock() {
                map.remove(&self.key);
            }
            let _ = tx.send(Some(CoalescedOutcome::Timeout));
        }
    }
}

impl UpstreamSet {
    pub fn new(cooldown: Duration) -> Self {
        Self {
            epoch: StdInstant::now(),
            cooldown_ms: cooldown.as_millis().min(u64::MAX as u128) as u64,
            rr_counter: Arc::new(AtomicUsize::new(0)),
            circuits: Arc::new(Mutex::new(HashMap::new())),
            tcp_pool: Arc::new(Mutex::new(HashMap::new())),
            inflight: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(feature = "tls")]
            dot_connector: Arc::new(Mutex::new(None)),
        }
    }

    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis().min(u64::MAX as u128) as u64
    }

    fn circuit_for(&self, addr: SocketAddr) -> Arc<UpstreamCircuit> {
        let mut guard = self
            .circuits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(
            guard
                .entry(addr)
                .or_insert_with(|| Arc::new(UpstreamCircuit::default())),
        )
    }

    /// Marks `addr` as healthy and closes its circuit breaker.
    pub fn record_success(&self, addr: SocketAddr) {
        let circuit = self.circuit_for(addr);
        circuit.consecutive_failures.store(0, Ordering::Relaxed);
        circuit.open_until_ms.store(0, Ordering::Relaxed);
    }

    /// Records a failure for `addr` and opens its circuit breaker for `cooldown_ms`.
    pub fn record_failure(&self, addr: SocketAddr) {
        let circuit = self.circuit_for(addr);
        circuit.consecutive_failures.fetch_add(1, Ordering::Relaxed);
        let until = self.now_ms().saturating_add(self.cooldown_ms);
        circuit.open_until_ms.store(until, Ordering::Relaxed);
    }

    /// Returns `true` if `addr`'s circuit breaker is currently closed (or half-open after cooldown).
    pub fn is_healthy(&self, addr: SocketAddr) -> bool {
        let circuit = self.circuit_for(addr);
        circuit.open_until_ms.load(Ordering::Relaxed) <= self.now_ms()
    }

    /// Returns `true` if at least one upstream in `upstreams` has a closed/half-open circuit breaker.
    pub fn has_healthy_upstream(&self, upstreams: &[SocketAddr]) -> bool {
        upstreams.iter().copied().any(|addr| self.is_healthy(addr))
    }

    /// Partitions `upstreams` so healthy resolvers are tried first, followed by circuit-open resolvers as fallback.
    pub fn prioritized_upstreams(&self, upstreams: &[SocketAddr]) -> Vec<SocketAddr> {
        self.select_upstreams(upstreams, UpstreamStrategy::Failover)
    }

    /// Selects and orders `upstreams` according to `strategy` (`Failover`, `RoundRobin`, or `Parallel`),
    /// always keeping healthy resolvers ahead of circuit-open fallback resolvers.
    pub fn select_upstreams(
        &self,
        upstreams: &[SocketAddr],
        strategy: UpstreamStrategy,
    ) -> Vec<SocketAddr> {
        let now = self.now_ms();
        let mut healthy = Vec::with_capacity(upstreams.len());
        let mut open = Vec::new();
        for &addr in upstreams {
            let circuit = self.circuit_for(addr);
            if circuit.open_until_ms.load(Ordering::Relaxed) <= now {
                healthy.push(addr);
            } else {
                open.push(addr);
            }
        }
        if strategy == UpstreamStrategy::RoundRobin && healthy.len() > 1 {
            let rot = self.rr_counter.fetch_add(1, Ordering::Relaxed) % healthy.len();
            healthy.rotate_left(rot);
        }
        healthy.extend(open);
        healthy
    }

    fn take_pooled_tcp(&self, addr: SocketAddr) -> Option<TcpStream> {
        let mut guard = self.tcp_pool.lock().ok()?;
        let queue = guard.get_mut(&addr)?;
        let now = StdInstant::now();
        while let Some((stream, idle_since)) = queue.pop_front() {
            if now.duration_since(idle_since) < TCP_POOL_IDLE_TIMEOUT {
                return Some(stream);
            }
        }
        None
    }

    #[doc(hidden)]
    pub fn return_pooled_tcp(&self, addr: SocketAddr, stream: TcpStream) {
        if let Ok(mut guard) = self.tcp_pool.lock() {
            let queue = guard.entry(addr).or_default();
            if queue.len() >= MAX_IDLE_TCP_PER_UPSTREAM {
                queue.pop_front();
            }
            queue.push_back((stream, StdInstant::now()));
        }
    }

    #[cfg(feature = "tls")]
    fn get_or_init_dot_connector(
        &self,
        extra_ca: Option<&std::path::Path>,
    ) -> Result<tokio_rustls::TlsConnector, DohError> {
        let mut guard = self
            .dot_connector
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(ref conn) = *guard {
            return Ok(conn.clone());
        }
        let conn = crate::tls::build_upstream_dot_connector(extra_ca)?;
        *guard = Some(conn.clone());
        Ok(conn)
    }
}

/// Stateless wrapper around `resolve_upstream_with_set` using a default `UpstreamSet`.
pub async fn resolve_upstream(
    query: Vec<u8>,
    client_ip: Option<IpAddr>,
    config: &DohConfig,
    tcp_limiter: &Arc<Semaphore>,
    metrics: &DohMetrics,
    deadline: Instant,
) -> Result<ResolvedDnsPacket, DohError> {
    let default_set = UpstreamSet::default();
    resolve_upstream_with_set(
        query,
        client_ip,
        config,
        &default_set,
        tcp_limiter,
        metrics,
        deadline,
    )
    .await
}

/// Executes an upstream DNS lookup with Singleflight In-Flight Query Coalescing when `coalesce_key` is `Some`.
/// Concurrent identical cache-miss queries share a single upstream resolution and restore each client's
/// individual `TXID`, Question `0x20` casing, and EDNS0 padding on completion.
#[allow(clippy::too_many_arguments)]
pub async fn resolve_upstream_coalesced(
    query: Vec<u8>,
    coalesce_key: Option<&CacheKey>,
    client_ip: Option<IpAddr>,
    config: &DohConfig,
    upstream_set: &UpstreamSet,
    tcp_limiter: &Arc<Semaphore>,
    metrics: &DohMetrics,
    deadline: Instant,
) -> Result<ResolvedDnsPacket, DohError> {
    let Some(key) = coalesce_key else {
        return resolve_upstream_with_set(
            query,
            client_ip,
            config,
            upstream_set,
            tcp_limiter,
            metrics,
            deadline,
        )
        .await;
    };

    let parsed = validate_and_parse_query(&query)?;
    enum Role {
        Leader(InflightLeaderGuard),
        Follower(InflightReceiver),
    }

    let role = {
        let mut map = upstream_set
            .inflight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(rx) = map.get(key) {
            Role::Follower(rx.clone())
        } else {
            let (tx, rx) = watch::channel(None);
            map.insert(key.clone(), rx);
            Role::Leader(InflightLeaderGuard {
                key: key.clone(),
                inflight: Arc::clone(&upstream_set.inflight),
                tx: Some(tx),
            })
        }
    };

    match role {
        Role::Leader(guard) => {
            let res = resolve_upstream_with_set(
                query,
                client_ip,
                config,
                upstream_set,
                tcp_limiter,
                metrics,
                deadline,
            )
            .await;
            match &res {
                Ok(pkt) => guard.complete(CoalescedOutcome::Ok(pkt.clone())),
                Err(DohError::UpstreamTimeout) => guard.complete(CoalescedOutcome::Timeout),
                Err(e) => guard.complete(CoalescedOutcome::NetworkError(e.to_string())),
            }
            res
        }
        Role::Follower(mut rx) => {
            metrics.inc_coalesced_query();
            let wait_fut = async {
                loop {
                    if let Some(outcome) = rx.borrow_and_update().clone() {
                        return Ok(outcome);
                    }
                    if rx.changed().await.is_err() {
                        return Err(DohError::UpstreamTimeout);
                    }
                }
            };
            let outcome = tokio::time::timeout_at(deadline, wait_fut)
                .await
                .map_err(|_| DohError::UpstreamTimeout)??;

            match outcome {
                CoalescedOutcome::Ok(mut pkt) => {
                    let mut waiter_buf = pkt.unpadded_wire_bytes;
                    rewrite_question_from_client(
                        &mut waiter_buf,
                        &query,
                        parsed.question_end_offset,
                    );
                    pkt.unpadded_wire_bytes = waiter_buf.clone();
                    finalize_wire_response_for_client(&mut waiter_buf, parsed.has_edns0);
                    pkt.wire_bytes = waiter_buf;
                    Ok(pkt)
                }
                CoalescedOutcome::Timeout => Err(DohError::UpstreamTimeout),
                CoalescedOutcome::NetworkError(msg) => Err(DohError::UpstreamError(msg)),
            }
        }
    }
}

/// Executes an upstream DNS lookup across configured upstream resolvers using `upstream_set`
/// for circuit-breaker failover, load balancing, and persistent TCP connection pooling.
pub async fn resolve_upstream_with_set(
    mut query: Vec<u8>,
    client_ip: Option<IpAddr>,
    config: &DohConfig,
    upstream_set: &UpstreamSet,
    tcp_limiter: &Arc<Semaphore>,
    metrics: &DohMetrics,
    deadline: Instant,
) -> Result<ResolvedDnsPacket, DohError> {
    tokio::time::timeout_at(
        deadline,
        resolve_upstream_inner(
            &mut query,
            client_ip,
            config,
            upstream_set,
            tcp_limiter,
            metrics,
            deadline,
        ),
    )
    .await
    .map_err(|_| {
        metrics.inc_upstream_failure();
        DohError::UpstreamTimeout
    })?
}

async fn resolve_upstream_inner(
    query: &mut Vec<u8>,
    client_ip: Option<IpAddr>,
    config: &DohConfig,
    upstream_set: &UpstreamSet,
    tcp_limiter: &Arc<Semaphore>,
    metrics: &DohMetrics,
    deadline: Instant,
) -> Result<ResolvedDnsPacket, DohError> {
    let parsed = validate_and_parse_query(query)?;
    let original_client_query = query.clone();

    let upstream_txid: [u8; 2] = rand::random();
    query[0] = upstream_txid[0];
    query[1] = upstream_txid[1];

    // Advertise 1232-byte EDNS0 UDP payload size to upstream (DNS Flag Day 2020, M-3)
    if let Err(e) = ensure_edns0_max_payload(query, UPSTREAM_EDNS_UDP_SIZE) {
        tracing::warn!("failed to set upstream EDNS0 payload size: {e}");
    }

    // Attach RFC 7871 EDNS Client Subnet if enabled (or if client supplied ECS)
    let mut ecs_attached = parsed.has_client_ecs;
    if config.enable_ecs && !parsed.has_client_ecs {
        if let Some(ip) = client_ip {
            ecs_attached =
                attach_ecs_to_query(query, ip, config.ecs_prefix_v4, config.ecs_prefix_v6)
                    .unwrap_or(false);
        }
    }

    let configured_upstreams = config.effective_upstreams();
    let upstreams = upstream_set.select_upstreams(&configured_upstreams, config.upstream_strategy);
    let total_upstreams = upstreams.len().max(1);
    let now = Instant::now();
    let remaining_budget = deadline.saturating_duration_since(now);
    let per_try_timeout =
        (remaining_budget / (total_upstreams as u32)).max(Duration::from_millis(250));

    let response_buf =
        if config.upstream_strategy == UpstreamStrategy::Parallel && upstreams.len() > 1 {
            query_upstreams_parallel(
                query,
                upstream_txid,
                &parsed.qname,
                parsed.qtype,
                parsed.qclass,
                &upstreams,
                config,
                upstream_set,
                tcp_limiter,
                metrics,
            )
            .await?
        } else {
            let mut last_err = DohError::UpstreamTimeout;
            let mut buf_out = Vec::new();
            for (idx, &upstream_addr) in upstreams.iter().enumerate() {
                let try_fut = query_single_upstream(
                    query,
                    upstream_txid,
                    &parsed.qname,
                    parsed.qtype,
                    parsed.qclass,
                    upstream_addr,
                    config,
                    upstream_set,
                    tcp_limiter,
                    metrics,
                );
                let result = if idx + 1 < total_upstreams {
                    match tokio::time::timeout(per_try_timeout, try_fut).await {
                        Ok(r) => r,
                        Err(_) => {
                            let transport = if config
                                .upstream_dot_sni
                                .as_deref()
                                .is_some_and(|s| !s.trim().is_empty())
                            {
                                "dot"
                            } else {
                                "udp"
                            };
                            metrics.record_upstream_target(upstream_addr, transport, "timeout");
                            Err(DohError::UpstreamTimeout)
                        }
                    }
                } else {
                    try_fut.await
                };

                match result {
                    Ok(buf) => {
                        upstream_set.record_success(upstream_addr);
                        buf_out = buf;
                        break;
                    }
                    Err(e) => {
                        upstream_set.record_failure(upstream_addr);
                        metrics.inc_upstream_failure();
                        last_err = e;
                    }
                }
            }
            if buf_out.is_empty() {
                return Err(last_err);
            }
            buf_out
        };

    let mut response_buf = response_buf;

    // Restore client's original DNS ID and exact Question section casing (RFC 8484 §4.1, L-7)
    rewrite_question_from_client(
        &mut response_buf,
        &original_client_query,
        parsed.question_end_offset,
    );

    let recoverable_err = is_recoverable_error(&response_buf);
    let (http_ttl, internal_cache_ttl) = if recoverable_err {
        let err = config.err_ttl.min(config.max_ttl);
        (err, err)
    } else {
        compute_response_ttl_with_floor(
            &response_buf,
            config.min_ttl,
            config.max_ttl,
            config.err_ttl,
        )?
    };

    let unpadded_wire_bytes = response_buf.clone();

    // Per-client EDNS0 OPT/padding post-processing (RFC 6891 §7, RFC 7830 §4, RFC 8467 §4.1, M-1)
    finalize_wire_response_for_client(&mut response_buf, parsed.has_edns0);

    Ok(ResolvedDnsPacket {
        wire_bytes: response_buf,
        unpadded_wire_bytes,
        cache_ttl: http_ttl,
        internal_cache_ttl,
        age_secs: 0,
        ecs_attached,
        cacheable: !recoverable_err && !ecs_attached && http_ttl > 0,
    })
}

#[allow(clippy::too_many_arguments)]
async fn query_upstreams_parallel(
    query: &[u8],
    upstream_txid: [u8; 2],
    expected_qname_lower: &str,
    expected_qtype: u16,
    expected_qclass: u16,
    upstreams: &[SocketAddr],
    config: &DohConfig,
    upstream_set: &UpstreamSet,
    tcp_limiter: &Arc<Semaphore>,
    metrics: &DohMetrics,
) -> Result<Vec<u8>, DohError> {
    let mut set = JoinSet::new();
    for &upstream_addr in upstreams {
        let q_bytes = query.to_vec();
        let qname = expected_qname_lower.to_string();
        let cfg = config.clone();
        let u_set = upstream_set.clone();
        let limiter = Arc::clone(tcp_limiter);
        let m = metrics.clone();
        set.spawn(async move {
            let res = query_single_upstream(
                &q_bytes,
                upstream_txid,
                &qname,
                expected_qtype,
                expected_qclass,
                upstream_addr,
                &cfg,
                &u_set,
                &limiter,
                &m,
            )
            .await;
            (upstream_addr, res)
        });
    }

    let mut last_err = DohError::UpstreamTimeout;
    while let Some(join_res) = set.join_next().await {
        if let Ok((addr, res)) = join_res {
            match res {
                Ok(buf) => {
                    upstream_set.record_success(addr);
                    // Dropping `set` automatically aborts remaining slower upstream tasks
                    return Ok(buf);
                }
                Err(e) => {
                    upstream_set.record_failure(addr);
                    metrics.inc_upstream_failure();
                    last_err = e;
                }
            }
        }
    }
    Err(last_err)
}

#[allow(clippy::too_many_arguments)]
async fn query_single_upstream(
    query: &[u8],
    upstream_txid: [u8; 2],
    expected_qname_lower: &str,
    expected_qtype: u16,
    expected_qclass: u16,
    upstream_addr: SocketAddr,
    config: &DohConfig,
    upstream_set: &UpstreamSet,
    tcp_limiter: &Arc<Semaphore>,
    metrics: &DohMetrics,
) -> Result<Vec<u8>, DohError> {
    if let Some(sni) = config
        .upstream_dot_sni
        .as_ref()
        .filter(|s| !s.trim().is_empty())
    {
        return query_upstream_dot(
            query,
            upstream_txid,
            expected_qname_lower,
            expected_qtype,
            expected_qclass,
            upstream_addr,
            sni.trim(),
            config,
            upstream_set,
            tcp_limiter,
            metrics,
        )
        .await;
    }

    let local_bind = config.local_bind_address;
    let bind_addr = if local_bind.ip().is_unspecified() {
        DohConfig::default_local_bind_for(upstream_addr)
    } else {
        local_bind
    };

    // Step 1: Query upstream over connected UDP socket with RFC 5452 §9.1 validation loop (H-4)
    metrics.inc_upstream_udp();
    let mut response_buf = vec![0u8; 4096];
    {
        let udp_sock = UdpSocket::bind(bind_addr).await.map_err(|e| {
            metrics.record_upstream_target(upstream_addr, "udp", "error");
            DohError::Io(e)
        })?;
        udp_sock.connect(upstream_addr).await.map_err(|e| {
            metrics.record_upstream_target(upstream_addr, "udp", "error");
            DohError::Io(e)
        })?;
        udp_sock.send(query).await.map_err(|e| {
            metrics.record_upstream_target(upstream_addr, "udp", "error");
            DohError::Io(e)
        })?;

        loop {
            let n = udp_sock.recv(&mut response_buf).await.map_err(|e| {
                metrics.record_upstream_target(upstream_addr, "udp", "error");
                DohError::Io(e)
            })?;
            if n < MIN_DNS_PACKET_LEN {
                tracing::warn!("ignoring short UDP datagram ({n} bytes) from {upstream_addr}");
                continue;
            }
            if response_buf[0] != upstream_txid[0] || response_buf[1] != upstream_txid[1] {
                tracing::warn!("ignoring UDP datagram with mismatched TXID from {upstream_addr}");
                continue;
            }
            if !matches_response_question(
                &response_buf[..n],
                expected_qname_lower,
                expected_qtype,
                expected_qclass,
            ) {
                tracing::warn!(
                    "ignoring UDP datagram with mismatched Question or QR=0 from {upstream_addr}"
                );
                continue;
            }
            response_buf.truncate(n);
            metrics.record_upstream_target(upstream_addr, "udp", "ok");
            break;
        }
    }

    // Step 2: RFC 7766 TCP fallback if UDP response had TC=1 (Truncated)
    if is_truncated(&response_buf) {
        metrics.inc_upstream_tcp();
        let _permit = tcp_limiter
            .acquire()
            .await
            .map_err(|_| DohError::UpstreamError("TCP concurrency semaphore closed".into()))?;

        let tcp_res = query_upstream_tcp(
            query,
            upstream_txid,
            expected_qname_lower,
            expected_qtype,
            expected_qclass,
            upstream_addr,
            upstream_set,
        )
        .await;
        match tcp_res {
            Ok(buf) => {
                metrics.record_upstream_target(upstream_addr, "tcp", "ok");
                response_buf = buf;
            }
            Err(e) => {
                metrics.record_upstream_target(upstream_addr, "tcp", "error");
                return Err(e);
            }
        }
    }

    Ok(response_buf)
}

#[allow(clippy::too_many_arguments)]
async fn query_upstream_dot(
    query: &[u8],
    upstream_txid: [u8; 2],
    expected_qname_lower: &str,
    expected_qtype: u16,
    expected_qclass: u16,
    upstream_addr: SocketAddr,
    sni: &str,
    config: &DohConfig,
    upstream_set: &UpstreamSet,
    tcp_limiter: &Arc<Semaphore>,
    metrics: &DohMetrics,
) -> Result<Vec<u8>, DohError> {
    #[cfg(feature = "tls")]
    {
        metrics.inc_upstream_dot();
        let _permit = tcp_limiter
            .acquire()
            .await
            .map_err(|_| DohError::UpstreamError("DoT concurrency semaphore closed".into()))?;

        let do_dot = async {
            let connector =
                upstream_set.get_or_init_dot_connector(config.tls_cert_path.as_deref())?;
            let server_name =
                tokio_rustls::rustls::pki_types::ServerName::try_from(sni.to_string()).map_err(
                    |e| DohError::InvalidConfig(format!("invalid upstream DoT SNI '{sni}': {e}")),
                )?;
            let tcp_sock = match upstream_addr {
                SocketAddr::V4(_) => TcpSocket::new_v4()?,
                SocketAddr::V6(_) => TcpSocket::new_v6()?,
            };
            let stream = tcp_sock.connect(upstream_addr).await?;
            stream.set_nodelay(true)?;
            let mut tls_stream = connector.connect(server_name, stream).await?;
            exchange_dns_over_stream(
                &mut tls_stream,
                query,
                upstream_txid,
                expected_qname_lower,
                expected_qtype,
                expected_qclass,
            )
            .await
        };

        match do_dot.await {
            Ok(buf) => {
                metrics.record_upstream_target(upstream_addr, "dot", "ok");
                Ok(buf)
            }
            Err(e) => {
                metrics.record_upstream_target(upstream_addr, "dot", "error");
                Err(e)
            }
        }
    }
    #[cfg(not(feature = "tls"))]
    {
        let _ = (
            query,
            upstream_txid,
            expected_qname_lower,
            expected_qtype,
            expected_qclass,
            upstream_addr,
            sni,
            config,
            upstream_set,
            tcp_limiter,
            metrics,
        );
        Err(DohError::InvalidConfig(
            "upstream DoT requires the 'tls' crate feature".into(),
        ))
    }
}

#[doc(hidden)]
pub async fn query_upstream_tcp(
    query: &[u8],
    upstream_txid: [u8; 2],
    expected_qname_lower: &str,
    expected_qtype: u16,
    expected_qclass: u16,
    upstream_addr: SocketAddr,
    upstream_set: &UpstreamSet,
) -> Result<Vec<u8>, DohError> {
    // Try pooled TCP connection first (RFC 7766 §6.2.1)
    if let Some(mut pooled_stream) = upstream_set.take_pooled_tcp(upstream_addr) {
        if let Ok(resp) = exchange_dns_over_tcp_stream(
            &mut pooled_stream,
            query,
            upstream_txid,
            expected_qname_lower,
            expected_qtype,
            expected_qclass,
        )
        .await
        {
            upstream_set.return_pooled_tcp(upstream_addr, pooled_stream);
            return Ok(resp);
        }
    }

    // Connect a fresh TCP socket if no pooled connection was available or if the pooled stream closed
    let tcp_sock = match upstream_addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    let mut stream = tcp_sock.connect(upstream_addr).await?;
    stream.set_nodelay(true)?;

    let resp = exchange_dns_over_tcp_stream(
        &mut stream,
        query,
        upstream_txid,
        expected_qname_lower,
        expected_qtype,
        expected_qclass,
    )
    .await?;
    upstream_set.return_pooled_tcp(upstream_addr, stream);
    Ok(resp)
}

#[doc(hidden)]
pub async fn exchange_dns_over_tcp_stream(
    stream: &mut TcpStream,
    query: &[u8],
    upstream_txid: [u8; 2],
    expected_qname_lower: &str,
    expected_qtype: u16,
    expected_qclass: u16,
) -> Result<Vec<u8>, DohError> {
    exchange_dns_over_stream(
        stream,
        query,
        upstream_txid,
        expected_qname_lower,
        expected_qtype,
        expected_qclass,
    )
    .await
}

async fn exchange_dns_over_stream<S>(
    stream: &mut S,
    query: &[u8],
    upstream_txid: [u8; 2],
    expected_qname_lower: &str,
    expected_qtype: u16,
    expected_qclass: u16,
) -> Result<Vec<u8>, DohError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let qlen_bytes = (query.len() as u16).to_be_bytes();
    stream.write_all(&qlen_bytes).await?;
    stream.write_all(query).await?;
    stream.flush().await?;

    let mut rlen_bytes = [0u8; 2];
    stream.read_exact(&mut rlen_bytes).await?;
    let rlen = u16::from_be_bytes(rlen_bytes) as usize;
    if !(MIN_DNS_PACKET_LEN..=MAX_DNS_MESSAGE_LEN).contains(&rlen) {
        return Err(DohError::UpstreamError(
            "upstream TCP packet size out of range".into(),
        ));
    }
    let mut response_buf = vec![0u8; rlen];
    stream.read_exact(&mut response_buf).await?;

    if response_buf[0] != upstream_txid[0] || response_buf[1] != upstream_txid[1] {
        return Err(DohError::UpstreamError(
            "upstream TCP transaction ID mismatch".into(),
        ));
    }
    if !matches_response_question(
        &response_buf,
        expected_qname_lower,
        expected_qtype,
        expected_qclass,
    ) {
        return Err(DohError::UpstreamError(
            "upstream TCP response question mismatch".into(),
        ));
    }
    Ok(response_buf)
}
