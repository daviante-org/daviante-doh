//! Clean-room Enterprise Protective DNS Domain Policy Engine (Allowlist / Blocklist + CNAME chain + RFC 8914 EDE)
//! and Per-IP / IPv6-Prefix Token-Bucket Rate Limiter.

use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::hash::BuildHasher;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::dns::ecs::mask_ipv6;
use crate::dns::wire::{
    build_policy_response, extract_answer_domain_names, EDE_BLOCKED, EDE_FILTERED, EDE_PROHIBITED,
    RCODE_NOERROR, RCODE_NXDOMAIN, RCODE_REFUSED,
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

/// Enterprise Protective DNS domain filtering policy (disabled by default until lists are provided).
#[derive(Debug, Clone, Default)]
pub struct DomainPolicy {
    allow_domains: Arc<HashSet<String>>,
    block_domains: Arc<HashSet<String>>,
    action: BlockAction,
}

impl DomainPolicy {
    /// Loads optional allowlist and blocklist files (supports plain domain lists, `*.domain` wildcards, and `/etc/hosts` format).
    /// Fails closed if a configured policy file cannot be read (C-2).
    pub fn from_files(
        allowlist_path: Option<&Path>,
        blocklist_path: Option<&Path>,
        action: BlockAction,
    ) -> Result<Self, DohError> {
        let allow_domains = match allowlist_path {
            Some(p) => Self::parse_domain_file(p)?,
            None => HashSet::new(),
        };
        let block_domains = match blocklist_path {
            Some(p) => Self::parse_domain_file(p)?,
            None => HashSet::new(),
        };
        Ok(Self {
            allow_domains: Arc::new(allow_domains),
            block_domains: Arc::new(block_domains),
            action,
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
        let allow_set = allow
            .into_iter()
            .filter_map(|s| Self::normalize_rule(s.as_ref()))
            .collect();
        let block_set = block
            .into_iter()
            .filter_map(|s| Self::normalize_rule(s.as_ref()))
            .collect();
        Self {
            allow_domains: Arc::new(allow_set),
            block_domains: Arc::new(block_set),
            action,
        }
    }

    #[inline]
    pub fn is_enabled(&self) -> bool {
        !self.block_domains.is_empty()
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

    /// Returns `true` if `qname` (already lowercase) is blocked by this policy.
    /// Allowlist entries always take precedence over blocklist entries.
    pub fn is_blocked(&self, qname_lower: &str) -> bool {
        if self.block_domains.is_empty() {
            return false;
        }
        if Self::matches_hierarchy(qname_lower, &self.allow_domains) {
            return false;
        }
        Self::matches_hierarchy(qname_lower, &self.block_domains)
    }

    /// Inspects all owner names and CNAME/DNAME targets in the Answer section of `response_packet`
    /// and returns `true` if any name in the answer chain is blocked by this policy (N-4).
    pub fn is_answer_blocked(&self, response_packet: &[u8]) -> bool {
        if !self.is_enabled() {
            return false;
        }
        extract_answer_domain_names(response_packet)
            .iter()
            .any(|name| self.is_blocked(name))
    }

    /// Builds a synthetic blocked DNS wire response with RFC 8914 Extended DNS Error (`EDE`) metadata.
    pub fn build_blocked_response(&self, query: &[u8], ttl: u32) -> Result<Vec<u8>, DohError> {
        match self.action {
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
