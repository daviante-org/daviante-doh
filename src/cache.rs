//! Clean-room sharded in-memory DNS response cache with RFC 1035 §6.2 wire TTL decrementing,
//! `RandomState` SipHash shard selection, 4 KiB entry size bound, and `0x20` question-case preservation.

use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::hash::{BuildHasher, Hash};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::dns::wire::{
    decrement_wire_ttls, finalize_wire_response_for_client, rewrite_question_from_client,
};

const SHARD_COUNT: usize = 16;
/// Maximum size in bytes of a single wire response eligible for in-memory caching (M-9).
pub const MAX_CACHE_ENTRY_BYTES: usize = 4096;

/// Composite lookup key isolating DNS questions by name, type, class, and DNSSEC bits.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
    pub do_bit: bool,
    pub cd_bit: bool,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    /// Unpadded wire-format DNS response with original upstream RR TTLs.
    raw_wire: Vec<u8>,
    /// Original RFC 8484 §5.1 HTTP freshness TTL (`<= min(Answer RR TTLs)`).
    http_ttl: u32,
    /// Retention TTL in the internal cache (`>= http_ttl` if `min_ttl` floor is configured).
    cache_ttl: u32,
    inserted_at: Instant,
    expires_at: Instant,
}

/// Result of a successful in-memory DNS cache hit.
#[derive(Debug, Clone)]
pub struct CacheHit {
    /// Wire-format DNS response finalized for the requesting client (padded or OPT-stripped).
    pub wire_bytes: Vec<u8>,
    /// Unpadded wire-format DNS response (with OPT/EDE intact for JSON decoding).
    pub unpadded_wire_bytes: Vec<u8>,
    /// Remaining RFC 8484 §5.1 HTTP freshness lifetime in seconds.
    pub remaining_ttl: u32,
    /// Elapsed seconds in cache.
    pub age_secs: u32,
}

/// Thread-safe, sharded in-memory DNS response cache.
/// Disabled (`max_entries == 0`) by default unless configured.
#[derive(Clone, Debug)]
pub struct DnsCache {
    max_entries: usize,
    hasher_builder: RandomState,
    shards: Arc<[RwLock<HashMap<CacheKey, CacheEntry>>; SHARD_COUNT]>,
}

impl DnsCache {
    /// Creates a new `DnsCache` bounded to `max_entries` total cached responses (`0` disables caching).
    pub fn new(max_entries: usize) -> Self {
        let shards = std::array::from_fn(|_| RwLock::new(HashMap::new()));
        Self {
            max_entries,
            hasher_builder: RandomState::new(),
            shards: Arc::new(shards),
        }
    }

    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.max_entries > 0
    }

    fn shard_index(&self, key: &CacheKey) -> usize {
        (self.hasher_builder.hash_one(key) as usize) % SHARD_COUNT
    }

    /// Looks up `key` in the cache, rewrites the client's 2-byte `txid` and `0x20` Question casing,
    /// decrements wire RR TTLs by elapsed seconds (RFC 1035 §6.2), and applies per-client EDNS0
    /// post-processing (468-byte padding when `client_has_edns0`, or OPT stripping when `!client_has_edns0`).
    pub fn get_for_query(
        &self,
        key: &CacheKey,
        client_query: &[u8],
        question_end_offset: usize,
        client_has_edns0: bool,
    ) -> Option<CacheHit> {
        if !self.is_enabled() {
            return None;
        }
        let now = Instant::now();
        let idx = self.shard_index(key);
        let entry = {
            let guard = self.shards[idx].read().ok()?;
            let found = guard.get(key)?;
            if now >= found.expires_at {
                return None;
            }
            found.clone()
        };

        let elapsed_secs = now.duration_since(entry.inserted_at).as_secs() as u32;
        if elapsed_secs >= entry.cache_ttl {
            return None;
        }
        let remaining_ttl = entry.http_ttl.saturating_sub(elapsed_secs);

        let mut unpadded_wire = entry.raw_wire;
        rewrite_question_from_client(&mut unpadded_wire, client_query, question_end_offset);
        if let Err(e) = decrement_wire_ttls(&mut unpadded_wire, elapsed_secs) {
            tracing::warn!("failed to decrement cached wire TTLs: {e}");
            return None;
        }

        let mut wire_bytes = unpadded_wire.clone();
        finalize_wire_response_for_client(&mut wire_bytes, client_has_edns0);

        Some(CacheHit {
            wire_bytes,
            unpadded_wire_bytes: unpadded_wire,
            remaining_ttl,
            age_secs: elapsed_secs,
        })
    }

    /// Convenience lookup method taking a 2-byte `client_txid` (assumes EDNS0 client).
    pub fn get(&self, key: &CacheKey, client_txid: [u8; 2]) -> Option<CacheHit> {
        self.get_for_query(key, &client_txid, 0, true)
    }

    /// Inserts an unpadded DNS wire response into the cache when `http_ttl > 0`, `cache_ttl > 0`,
    /// and `raw_wire.len() <= MAX_CACHE_ENTRY_BYTES` (4 KiB).
    pub fn insert_with_floor(
        &self,
        key: CacheKey,
        raw_wire: Vec<u8>,
        http_ttl: u32,
        cache_ttl: u32,
    ) {
        if !self.is_enabled()
            || http_ttl == 0
            || cache_ttl == 0
            || raw_wire.len() > MAX_CACHE_ENTRY_BYTES
        {
            return;
        }
        let now = Instant::now();
        let expires_at = now + Duration::from_secs(cache_ttl as u64);
        let idx = self.shard_index(&key);
        let shard_cap = (self.max_entries / SHARD_COUNT).max(1);

        if let Ok(mut guard) = self.shards[idx].write() {
            if guard.len() >= shard_cap && !guard.contains_key(&key) {
                // First evict any expired entries
                guard.retain(|_, v| now < v.expires_at);
                // If still at capacity, evict the entry closest to expiration
                if guard.len() >= shard_cap {
                    if let Some(victim) = guard
                        .iter()
                        .min_by_key(|(_, v)| v.expires_at)
                        .map(|(k, _)| k.clone())
                    {
                        guard.remove(&victim);
                    }
                }
            }
            guard.insert(
                key,
                CacheEntry {
                    raw_wire,
                    http_ttl,
                    cache_ttl,
                    inserted_at: now,
                    expires_at,
                },
            );
        }
    }

    /// Inserts an unpadded DNS wire response with `http_ttl == cache_ttl == ttl`.
    pub fn insert(&self, key: CacheKey, raw_wire: Vec<u8>, ttl: u32) {
        self.insert_with_floor(key, raw_wire, ttl, ttl);
    }
}
