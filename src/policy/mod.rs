//! Clean-room Enterprise Protective DNS Domain Policy Engine (Allowlist / Blocklist + CNAME chain +
//! DNS Rebinding Protection + Custom Split-Horizon Hosts + Lock-Free Hot-Reload + RFC 8914 EDE)
//! and Per-IP / IPv6-Prefix Token-Bucket Rate Limiter.

use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::hash::BuildHasher;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use arc_swap::ArcSwap;

use crate::dns::ecs::mask_ipv6;
use crate::dns::wire::{
    build_hosts_response, build_policy_response, extract_answer_domain_names, extract_answer_ips,
    EDE_BLOCKED, EDE_FILTERED, EDE_PROHIBITED, RCODE_NOERROR, RCODE_NXDOMAIN, RCODE_REFUSED,
    RR_TYPE_A, RR_TYPE_AAAA, RR_TYPE_PTR,
};
use crate::error::DohError;

/// Action to take when a domain matches the enterprise blocklist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BlockAction {
    /// Return `RCODE 3 (NXDOMAIN)` with RFC 8914 `EDE 15 (Blocked)`.
    #[default]
    Nxdomain,
    /// Return `RCODE 5 (REFUSED)` with RFC 8914 `EDE 18 (Prohibited)`.
    Refused,
    /// Return `RCODE 0 (NOERROR)` with `0.0.0.0` (`A`) or `::` (`AAAA`) and RFC 8914 `EDE 17 (Filtered)`.
    NullIp,
}

impl BlockAction {
    pub fn from_str_name(s: &str) -> Result<Self, DohError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "nxdomain" => Ok(Self::Nxdomain),
            "refused" => Ok(Self::Refused),
            "null" | "nullip" | "sinkhole" | "0.0.0.0" => Ok(Self::NullIp),
            other => Err(DohError::InvalidConfig(format!(
                "invalid block action '{other}' (expected nxdomain, refused, or null)"
            ))),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Nxdomain => "nxdomain",
            Self::Refused => "refused",
            Self::NullIp => "null",
        }
    }
}

/// Returns `true` if `ip` is a private, loopback, link-local, CGNAT, ULA, or unspecified address
/// that must not be returned by a public authoritative DNS server when DNS rebinding protection is enabled.
pub fn is_private_or_special_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                // RFC 6598 Shared CGNAT space (100.64.0.0/10)
                || (octets[0] == 100 && (octets[1] & 0b1100_0000) == 64)
        }
        IpAddr::V6(v6) => {
            if let Some(mapped_v4) = v6.to_ipv4_mapped() {
                return is_private_or_special_ip(IpAddr::V4(mapped_v4));
            }
            let seg0 = v6.segments()[0];
            v6.is_unspecified()
                || v6.is_loopback()
                // RFC 4193 Unique Local Addresses (fc00::/7)
                || (seg0 & 0xfe00) == 0xfc00
                // Link-local unicast (fe80::/10)
                || (seg0 & 0xffc0) == 0xfe80
        }
    }
}

/// Formats an `IpAddr` into its reverse DNS lookup name (`in-addr.arpa` or `ip6.arpa`).
pub fn reverse_ptr_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{d}.{c}.{b}.{a}.in-addr.arpa")
        }
        IpAddr::V6(v6) => {
            let mut nibbles = String::with_capacity(72);
            for byte in v6.octets().iter().rev() {
                let lo = byte & 0x0f;
                let hi = (byte >> 4) & 0x0f;
                nibbles.push_str(&format!("{lo:x}.{hi:x}."));
            }
            nibbles.push_str("ip6.arpa");
            nibbles
        }
    }
}

#[derive(Debug, Clone, Default)]
struct DomainPolicyInner {
    allow_domains: HashSet<String>,
    block_domains: HashSet<String>,
    hosts_forward: HashMap<String, Vec<IpAddr>>,
    hosts_reverse: HashMap<String, String>,
    action: BlockAction,
    block_private_rebinding: bool,
}

/// Enterprise Protective DNS domain filtering policy, split-horizon hosts table, and DNS rebinding guard.
/// Supports lock-free hot-reloading via `ArcSwap` when policy or hosts files are updated on disk.
#[derive(Debug, Clone, Default)]
pub struct DomainPolicy {
    inner: Arc<ArcSwap<DomainPolicyInner>>,
}

impl DomainPolicy {
    /// Loads optional allowlist and blocklist files (supports plain domain lists, `*.domain` wildcards, and `/etc/hosts` format).
    /// Fails closed if a configured policy file cannot be read (C-2).
    pub fn from_files(
        allowlist_path: Option<&Path>,
        blocklist_path: Option<&Path>,
        action: BlockAction,
    ) -> Result<Self, DohError> {
        Self::from_files_full(allowlist_path, blocklist_path, None, action, false)
    }

    /// Loads optional allowlist, blocklist, and split-horizon custom hosts files, plus DNS rebinding protection setting.
    pub fn from_files_full(
        allowlist_path: Option<&Path>,
        blocklist_path: Option<&Path>,
        hosts_path: Option<&Path>,
        action: BlockAction,
        block_private_rebinding: bool,
    ) -> Result<Self, DohError> {
        let inner = Self::load_inner(
            allowlist_path,
            blocklist_path,
            hosts_path,
            action,
            block_private_rebinding,
        )?;
        Ok(Self {
            inner: Arc::new(ArcSwap::from_pointee(inner)),
        })
    }

    fn load_inner(
        allowlist_path: Option<&Path>,
        blocklist_path: Option<&Path>,
        hosts_path: Option<&Path>,
        action: BlockAction,
        block_private_rebinding: bool,
    ) -> Result<DomainPolicyInner, DohError> {
        let allow_domains = match allowlist_path {
            Some(p) => Self::parse_domain_file(p)?,
            None => HashSet::new(),
        };
        let block_domains = match blocklist_path {
            Some(p) => Self::parse_domain_file(p)?,
            None => HashSet::new(),
        };
        let (hosts_forward, hosts_reverse) = match hosts_path {
            Some(p) => Self::parse_hosts_file(p)?,
            None => (HashMap::new(), HashMap::new()),
        };
        Ok(DomainPolicyInner {
            allow_domains,
            block_domains,
            hosts_forward,
            hosts_reverse,
            action,
            block_private_rebinding,
        })
    }

    /// Creates an in-memory `DomainPolicy` directly from domain iterators (useful for embedding or testing).
    pub fn from_lists<I, J, S1, S2>(allow: I, block: J, action: BlockAction) -> Self
    where
        I: IntoIterator<Item = S1>,
        J: IntoIterator<Item = S2>,
        S1: AsRef<str>,
        S2: AsRef<str>,
    {
        Self::from_lists_with_options(
            allow,
            block,
            std::iter::empty::<(IpAddr, &str)>(),
            action,
            false,
        )
    }

    /// Creates an in-memory `DomainPolicy` with custom hosts entries and DNS rebinding protection setting.
    pub fn from_lists_with_options<I, J, H, S1, S2, S3>(
        allow: I,
        block: J,
        hosts: H,
        action: BlockAction,
        block_private_rebinding: bool,
    ) -> Self
    where
        I: IntoIterator<Item = S1>,
        J: IntoIterator<Item = S2>,
        H: IntoIterator<Item = (IpAddr, S3)>,
        S1: AsRef<str>,
        S2: AsRef<str>,
        S3: AsRef<str>,
    {
        let allow_set = allow
            .into_iter()
            .filter_map(|s| Self::normalize_rule(s.as_ref()))
            .collect();
        let block_set = block
            .into_iter()
            .filter_map(|s| Self::normalize_rule(s.as_ref()))
            .collect();
        let mut hosts_forward: HashMap<String, Vec<IpAddr>> = HashMap::new();
        let mut hosts_reverse: HashMap<String, String> = HashMap::new();
        for (ip, host) in hosts {
            let clean = host.as_ref().trim_matches('.').to_ascii_lowercase();
            if !clean.is_empty() {
                hosts_forward.entry(clean.clone()).or_default().push(ip);
                hosts_reverse.entry(reverse_ptr_name(ip)).or_insert(clean);
            }
        }
        Self {
            inner: Arc::new(ArcSwap::from_pointee(DomainPolicyInner {
                allow_domains: allow_set,
                block_domains: block_set,
                hosts_forward,
                hosts_reverse,
                action,
                block_private_rebinding,
            })),
        }
    }

    /// Atomically reloads `allowlist_path`, `blocklist_path`, and `hosts_path` from disk via `ArcSwap`.
    pub fn reload_from_files(
        &self,
        allowlist_path: Option<&Path>,
        blocklist_path: Option<&Path>,
        hosts_path: Option<&Path>,
        action: BlockAction,
        block_private_rebinding: bool,
    ) -> Result<(), DohError> {
        let new_inner = Self::load_inner(
            allowlist_path,
            blocklist_path,
            hosts_path,
            action,
            block_private_rebinding,
        )?;
        self.inner.store(Arc::new(new_inner));
        Ok(())
    }

    /// Spawns a background hot-reload task that checks `mtime` on `allowlist_file`, `blocklist_file`,
    /// and `hosts_file` every `interval` (default 60s) and atomically swaps the policy on change.
    pub fn spawn_reload_watcher(
        &self,
        allowlist_path: Option<PathBuf>,
        blocklist_path: Option<PathBuf>,
        hosts_path: Option<PathBuf>,
        action: BlockAction,
        block_private_rebinding: bool,
        interval: Duration,
    ) {
        if allowlist_path.is_none() && blocklist_path.is_none() && hosts_path.is_none() {
            return;
        }
        let policy_clone = self.clone();
        let file_mtimes = |a: &Option<PathBuf>,
                           b: &Option<PathBuf>,
                           h: &Option<PathBuf>|
         -> (Option<SystemTime>, Option<SystemTime>, Option<SystemTime>) {
            let ma = a
                .as_ref()
                .and_then(|p| fs::metadata(p).ok())
                .and_then(|m| m.modified().ok());
            let mb = b
                .as_ref()
                .and_then(|p| fs::metadata(p).ok())
                .and_then(|m| m.modified().ok());
            let mh = h
                .as_ref()
                .and_then(|p| fs::metadata(p).ok())
                .and_then(|m| m.modified().ok());
            (ma, mb, mh)
        };
        let mut last_mtimes = file_mtimes(&allowlist_path, &blocklist_path, &hosts_path);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval.max(Duration::from_millis(100)));
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let cur_mtimes = file_mtimes(&allowlist_path, &blocklist_path, &hosts_path);
                if cur_mtimes != last_mtimes {
                    match Self::load_inner(
                        allowlist_path.as_deref(),
                        blocklist_path.as_deref(),
                        hosts_path.as_deref(),
                        action,
                        block_private_rebinding,
                    ) {
                        Ok(new_inner) => {
                            policy_clone.inner.store(Arc::new(new_inner));
                            last_mtimes = cur_mtimes;
                            tracing::info!("hot-reloaded Protective DNS policy / hosts files");
                        }
                        Err(e) => {
                            tracing::warn!(
                                "keeping previous Protective DNS policy after reload error: {e}"
                            );
                        }
                    }
                }
            }
        });
    }

    #[inline]
    pub fn is_enabled(&self) -> bool {
        let guard = self.inner.load();
        !guard.block_domains.is_empty() || guard.block_private_rebinding
    }

    #[inline]
    pub fn has_hosts(&self) -> bool {
        let guard = self.inner.load();
        !guard.hosts_forward.is_empty() || !guard.hosts_reverse.is_empty()
    }

    fn parse_domain_file(path: &Path) -> Result<HashSet<String>, DohError> {
        let content = fs::read_to_string(path).map_err(|e| {
            DohError::InvalidConfig(format!(
                "failed to read domain list {}: {e}",
                path.display()
            ))
        })?;
        let mut set = HashSet::new();
        for raw_line in content.lines() {
            if let Some(domain) = Self::normalize_rule(raw_line) {
                set.insert(domain);
            }
        }
        Ok(set)
    }

    #[allow(clippy::type_complexity)]
    fn parse_hosts_file(
        path: &Path,
    ) -> Result<(HashMap<String, Vec<IpAddr>>, HashMap<String, String>), DohError> {
        let content = fs::read_to_string(path).map_err(|e| {
            DohError::InvalidConfig(format!("failed to read hosts file {}: {e}", path.display()))
        })?;
        let mut forward: HashMap<String, Vec<IpAddr>> = HashMap::new();
        let mut reverse: HashMap<String, String> = HashMap::new();
        for raw_line in content.lines() {
            let without_comment = raw_line.split('#').next().unwrap_or("").trim();
            if without_comment.is_empty() {
                continue;
            }
            let mut parts = without_comment.split_whitespace();
            let Some(ip_str) = parts.next() else {
                continue;
            };
            let ip: IpAddr = ip_str.parse().map_err(|e| {
                DohError::InvalidConfig(format!(
                    "invalid IP address '{ip_str}' in hosts file {}: {e}",
                    path.display()
                ))
            })?;
            for host_token in parts {
                let clean = host_token.trim_matches('.').to_ascii_lowercase();
                if !clean.is_empty() {
                    forward.entry(clean.clone()).or_default().push(ip);
                    reverse.entry(reverse_ptr_name(ip)).or_insert(clean);
                }
            }
        }
        Ok((forward, reverse))
    }

    fn normalize_rule(line: &str) -> Option<String> {
        let without_comment = line.split('#').next().unwrap_or("").trim();
        if without_comment.is_empty() {
            return None;
        }
        // Support `/etc/hosts` format (`0.0.0.0 ads.example.com` or `127.0.0.1 ads.example.com`)
        let mut parts = without_comment.split_whitespace();
        let first = parts.next()?;
        let token = if matches!(first, "0.0.0.0" | "127.0.0.1" | "::" | "::1") {
            parts.next()?
        } else {
            first
        };
        let cleaned = token
            .trim_start_matches("*.")
            .trim_matches('.')
            .to_ascii_lowercase();
        if cleaned.is_empty() || cleaned == "localhost" {
            return None;
        }
        Some(cleaned)
    }

    /// Returns `true` if `qname` or any of its parent domain suffixes is present in `set`.
    fn matches_hierarchy(qname: &str, set: &HashSet<String>) -> bool {
        if set.is_empty() {
            return false;
        }
        let mut cursor = qname.trim_matches('.');
        loop {
            if set.contains(cursor) {
                return true;
            }
            match cursor.split_once('.') {
                Some((_, parent)) => cursor = parent,
                None => return false,
            }
        }
    }

    /// Checks whether `qname_lower` matches a local split-horizon host override for `A`, `AAAA`, or `PTR`
    /// and returns a synthesized `NOERROR` wire response if matched.
    pub fn try_resolve_hosts(
        &self,
        query: &[u8],
        qname_lower: &str,
        qtype: u16,
        ttl: u32,
    ) -> Result<Option<Vec<u8>>, DohError> {
        let guard = self.inner.load();
        if guard.hosts_forward.is_empty() && guard.hosts_reverse.is_empty() {
            return Ok(None);
        }
        let clean = qname_lower.trim_matches('.');
        match qtype {
            RR_TYPE_A | RR_TYPE_AAAA => {
                if let Some(ips) = guard.hosts_forward.get(clean) {
                    let has_matching_family = ips.iter().any(|ip| {
                        (qtype == RR_TYPE_A && ip.is_ipv4())
                            || (qtype == RR_TYPE_AAAA && ip.is_ipv6())
                    });
                    if has_matching_family {
                        let wire = build_hosts_response(query, ips, None, ttl)?;
                        return Ok(Some(wire));
                    }
                }
            }
            RR_TYPE_PTR => {
                if let Some(target) = guard.hosts_reverse.get(clean) {
                    let wire = build_hosts_response(query, &[], Some(target), ttl)?;
                    return Ok(Some(wire));
                }
            }
            _ => {}
        }
        Ok(None)
    }

    /// Returns `true` if `qname` (already lowercase) is blocked by this policy.
    /// Allowlist entries always take precedence over blocklist entries.
    pub fn is_blocked(&self, qname_lower: &str) -> bool {
        let guard = self.inner.load();
        if guard.block_domains.is_empty() {
            return false;
        }
        if Self::matches_hierarchy(qname_lower, &guard.allow_domains) {
            return false;
        }
        Self::matches_hierarchy(qname_lower, &guard.block_domains)
    }

    fn is_blocked_with_guard(guard: &DomainPolicyInner, qname_lower: &str) -> bool {
        if guard.block_domains.is_empty() {
            return false;
        }
        if Self::matches_hierarchy(qname_lower, &guard.allow_domains) {
            return false;
        }
        Self::matches_hierarchy(qname_lower, &guard.block_domains)
    }

    /// Inspects all owner names and CNAME/DNAME targets in the Answer section of `response_packet`
    /// and returns `true` if any name in the answer chain is blocked by this policy (N-4).
    pub fn is_answer_blocked(&self, response_packet: &[u8]) -> bool {
        let guard = self.inner.load();
        if guard.block_domains.is_empty() {
            return false;
        }
        extract_answer_domain_names(response_packet)
            .iter()
            .any(|name| Self::is_blocked_with_guard(&guard, name))
    }

    /// Inspects resolved `A` and `AAAA` records in `response_packet` and returns `true` if DNS Rebinding
    /// Protection is enabled (`block_private_rebinding == true`), the queried domain is not allowlisted,
    /// and any resolved IP is private, loopback, link-local, CGNAT, or ULA.
    pub fn is_rebinding_blocked(&self, qname_lower: &str, response_packet: &[u8]) -> bool {
        let guard = self.inner.load();
        if !guard.block_private_rebinding {
            return false;
        }
        let clean = qname_lower.trim_matches('.');
        if Self::matches_hierarchy(clean, &guard.allow_domains)
            || guard.hosts_forward.contains_key(clean)
        {
            return false;
        }
        extract_answer_ips(response_packet)
            .into_iter()
            .any(is_private_or_special_ip)
    }

    /// Builds a synthetic blocked DNS wire response with RFC 8914 Extended DNS Error (`EDE`) metadata.
    pub fn build_blocked_response(&self, query: &[u8], ttl: u32) -> Result<Vec<u8>, DohError> {
        let guard = self.inner.load();
        match guard.action {
            BlockAction::Nxdomain => build_policy_response(
                query,
                RCODE_NXDOMAIN,
                false,
                Some((EDE_BLOCKED, "Blocked by Protective DNS policy")),
                ttl,
            ),
            BlockAction::Refused => build_policy_response(
                query,
                RCODE_REFUSED,
                false,
                Some((EDE_PROHIBITED, "Prohibited by Protective DNS policy")),
                ttl,
            ),
            BlockAction::NullIp => build_policy_response(
                query,
                RCODE_NOERROR,
                true,
                Some((EDE_FILTERED, "Filtered by Protective DNS policy")),
                ttl,
            ),
        }
    }

    /// Builds a synthetic DNS rebinding blocked response (`RCODE_REFUSED` or configured action + `EDE 15`).
    pub fn build_rebinding_blocked_response(
        &self,
        query: &[u8],
        ttl: u32,
    ) -> Result<Vec<u8>, DohError> {
        let guard = self.inner.load();
        let rcode_val = match guard.action {
            BlockAction::Refused => RCODE_REFUSED,
            _ => RCODE_NXDOMAIN,
        };
        build_policy_response(
            query,
            rcode_val,
            false,
            Some((
                EDE_BLOCKED,
                "Blocked by DNS Rebinding Protection (private IP in public answer)",
            )),
            ttl,
        )
    }
}

const RATE_SHARDS: usize = 16;
const MAX_BUCKETS_PER_SHARD: usize = 4096;

#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

/// Sharded per-IP / IPv6-prefix token-bucket rate limiter. Disabled by default (`rps == 0`).
#[derive(Clone, Debug)]
pub struct IpRateLimiter {
    rps: f64,
    burst: f64,
    v6_prefix: u8,
    max_buckets_per_shard: usize,
    hasher_builder: RandomState,
    shards: Arc<[Mutex<HashMap<IpAddr, TokenBucket>>; RATE_SHARDS]>,
}

impl IpRateLimiter {
    /// Creates a new `IpRateLimiter` with default IPv6 `/64` bucket aggregation.
    /// Set `rps = 0` to disable rate limiting.
    pub fn new(rps: u32, burst: u32) -> Self {
        Self::with_v6_prefix(rps, burst, 64)
    }

    /// Creates a new `IpRateLimiter` aggregating IPv6 addresses by `v6_prefix` bits (default `64`, M-8).
    pub fn with_v6_prefix(rps: u32, burst: u32, v6_prefix: u8) -> Self {
        Self::with_capacity_and_v6_prefix(rps, burst, v6_prefix, MAX_BUCKETS_PER_SHARD)
    }

    /// Creates a new `IpRateLimiter` with custom per-shard capacity (used in eviction tests).
    pub fn with_capacity_and_v6_prefix(
        rps: u32,
        burst: u32,
        v6_prefix: u8,
        max_buckets_per_shard: usize,
    ) -> Self {
        let shards = std::array::from_fn(|_| Mutex::new(HashMap::new()));
        let effective_burst = burst.max(rps).max(1) as f64;
        Self {
            rps: rps as f64,
            burst: effective_burst,
            v6_prefix: v6_prefix.min(128),
            max_buckets_per_shard: max_buckets_per_shard.max(1),
            hasher_builder: RandomState::new(),
            shards: Arc::new(shards),
        }
    }

    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.rps > 0.0
    }

    /// Normalizes `ip` to its rate-limiting bucket key (IPv4 `/32`, IPv6 `/v6_prefix`).
    #[inline]
    pub fn normalize_key(&self, ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V4(v4) => IpAddr::V4(v4),
            IpAddr::V6(v6) => IpAddr::V6(mask_ipv6(v6, self.v6_prefix)),
        }
    }

    /// Returns `true` if `client_ip` is allowed to proceed, or `false` if rate-limited (`HTTP 429`).
    pub fn check_and_consume(&self, client_ip: Option<IpAddr>) -> bool {
        if !self.is_enabled() {
            return true;
        }
        let Some(raw_ip) = client_ip else {
            return true;
        };
        let key_ip = self.normalize_key(raw_ip);
        let idx = (self.hasher_builder.hash_one(key_ip) as usize) % RATE_SHARDS;

        let now = Instant::now();
        let Ok(mut guard) = self.shards[idx].lock() else {
            return true;
        };

        if guard.len() >= self.max_buckets_per_shard && !guard.contains_key(&key_ip) {
            // Evict the most idle bucket (oldest last_refill timestamp) (M-8)
            if let Some(victim) = guard
                .iter()
                .min_by_key(|(_, b)| b.last_refill)
                .map(|(k, _)| *k)
            {
                guard.remove(&victim);
            }
        }

        let bucket = guard.entry(key_ip).or_insert(TokenBucket {
            tokens: self.burst,
            last_refill: now,
        });

        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        if elapsed > 0.0 {
            bucket.tokens = (bucket.tokens + elapsed * self.rps).min(self.burst);
            bucket.last_refill = now;
        }

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}
