//! Clean-room Enterprise Protective DNS Domain Policy Engine (Allowlist / Blocklist + CNAME chain +
//! DNS Rebinding Protection + Custom Split-Horizon Hosts + Lock-Free Hot-Reload + RFC 8914 EDE)
//! and Per-IP / IPv6-Prefix Token-Bucket Rate Limiter.

pub mod records;

use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::hash::BuildHasher;
use std::io::Write as _;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;

use crate::dns::ecs::mask_ipv6;
use crate::dns::wire::{
    build_hosts_response, build_local_authoritative_response, build_local_records_response,
    build_policy_response, extract_answer_domain_names, extract_answer_ips, EDE_BLOCKED,
    EDE_FILTERED, EDE_PROHIBITED, RCODE_NOERROR, RCODE_NXDOMAIN, RCODE_REFUSED, RR_TYPE_A,
    RR_TYPE_AAAA, RR_TYPE_ANY, RR_TYPE_CNAME, RR_TYPE_DNAME, RR_TYPE_NS, RR_TYPE_PTR, RR_TYPE_SOA,
};
use crate::error::DohError;

pub use records::{
    encode_domain_wire, export_zone_to_bind, format_bind_preview, parse_bind_zone_text,
    resolve_record_owner_in_zone, validate_general_domain_name, validate_record_against_store,
    CompiledDnsZone, CompiledLocalRecord, DnsStoreDocument, DnsZone, LocalDnsRecord,
    LocalRecordData, PolicyRuleEntry, PolicyRuleKind, RecordValidationError, ZoneMode,
};

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
    file_allow_domains: HashSet<String>,
    file_block_domains: HashSet<String>,
    hosts_forward: HashMap<String, Vec<IpAddr>>,
    hosts_reverse: HashMap<String, String>,
    action: BlockAction,
    block_private_rebinding: bool,
    store_path: Option<PathBuf>,
    zones: Vec<DnsZone>,
    compiled_zones: HashMap<String, CompiledDnsZone>,
    local_records: Vec<LocalDnsRecord>,
    compiled_by_domain: HashMap<String, Vec<CompiledLocalRecord>>,
    auto_ptr_by_reverse: HashMap<String, (u32, Vec<u8>)>,
    policy_rules: Vec<PolicyRuleEntry>,
}

impl DomainPolicyInner {
    fn rebuild_compiled_maps(&mut self) {
        let mut compiled_zones: HashMap<String, CompiledDnsZone> = HashMap::new();
        for z in &self.zones {
            if !z.enabled {
                continue;
            }
            if let Ok(cz) = z.validate_and_compile() {
                compiled_zones.insert(cz.zone.domain.clone(), cz);
            }
        }

        let mut compiled_by_domain: HashMap<String, Vec<CompiledLocalRecord>> = HashMap::new();
        let mut auto_ptr_by_reverse: HashMap<String, (u32, Vec<u8>)> = HashMap::new();

        for rec in &self.local_records {
            if !rec.enabled {
                continue;
            }
            // If the record belongs to a zone that is currently disabled, skip serving it
            if let Some(ref zid) = rec.zone_id {
                if let Some(z) = self.zones.iter().find(|z| &z.id == zid) {
                    if !z.enabled {
                        continue;
                    }
                }
            }
            let Ok(compiled) = rec.validate_and_compile() else {
                continue;
            };
            let clean_domain = compiled.domain.clone();
            let ttl = compiled.ttl;
            if let Some((ref rev_name, ref ptr_wire)) = compiled.auto_ptr_reverse {
                if !clean_domain.starts_with("*.") {
                    auto_ptr_by_reverse
                        .entry(rev_name.clone())
                        .or_insert((ttl, ptr_wire.clone()));
                }
            }
            compiled_by_domain
                .entry(clean_domain)
                .or_default()
                .push(compiled);
        }

        let mut allow_domains = self.file_allow_domains.clone();
        let mut block_domains = self.file_block_domains.clone();
        for rule in &self.policy_rules {
            if !rule.enabled {
                continue;
            }
            if let Some(norm) = DomainPolicy::normalize_rule(&rule.domain) {
                match rule.kind {
                    PolicyRuleKind::Allow => {
                        allow_domains.insert(norm);
                    }
                    PolicyRuleKind::Block => {
                        block_domains.insert(norm);
                    }
                }
            }
        }

        self.compiled_zones = compiled_zones;
        self.compiled_by_domain = compiled_by_domain;
        self.auto_ptr_by_reverse = auto_ptr_by_reverse;
        self.allow_domains = allow_domains;
        self.block_domains = block_domains;
    }

    fn lookup_domain_records(&self, qname_clean: &str) -> Option<&Vec<CompiledLocalRecord>> {
        if let Some(exact) = self.compiled_by_domain.get(qname_clean) {
            return Some(exact);
        }
        let mut cursor = qname_clean;
        while let Some((_, parent)) = cursor.split_once('.') {
            let wildcard_key = format!("*.{parent}");
            if let Some(wc) = self.compiled_by_domain.get(&wildcard_key) {
                return Some(wc);
            }
            cursor = parent;
        }
        None
    }

    /// Finds the closest ancestor `DNAME` record for `qname_clean` per RFC 6672.
    /// Returns `Some((dname_owner, dname_rec, relative_prefix))` when `qname_clean` is `<relative_prefix>.<dname_owner>`.
    fn find_ancestor_dname<'a>(
        &'a self,
        qname_clean: &'a str,
    ) -> Option<(&'a str, &'a CompiledLocalRecord, String)> {
        let mut cursor = qname_clean;
        while let Some((_, parent)) = cursor.split_once('.') {
            if let Some(recs) = self.compiled_by_domain.get(parent) {
                if let Some(dname_rec) = recs.iter().find(|r| r.rr_type == RR_TYPE_DNAME) {
                    let prefix_len = qname_clean.len().saturating_sub(parent.len() + 1);
                    let prefix = qname_clean[..prefix_len].to_string();
                    return Some((parent, dname_rec, prefix));
                }
            }
            cursor = parent;
        }
        None
    }

    /// Finds the longest-matching enabled `CompiledDnsZone` enclosing `qname_clean`.
    fn find_enclosing_zone(&self, qname_clean: &str) -> Option<&CompiledDnsZone> {
        let mut cursor = qname_clean;
        loop {
            if let Some(z) = self.compiled_zones.get(cursor) {
                return Some(z);
            }
            match cursor.split_once('.') {
                Some((_, parent)) => cursor = parent,
                None => return None,
            }
        }
    }

    /// Collects in-bailiwick local `A` and `AAAA` glue records for `glue_targets`.
    fn collect_glue_records(
        &self,
        glue_targets: &[String],
        primary_qname: &str,
    ) -> Vec<(String, u16, u32, Vec<u8>)> {
        let mut additional = Vec::new();
        let mut seen = HashSet::new();
        for target in glue_targets {
            if target.eq_ignore_ascii_case(primary_qname) || !seen.insert(target.clone()) {
                continue;
            }
            if let Some(recs) = self.compiled_by_domain.get(target) {
                for r in recs {
                    if matches!(r.rr_type, RR_TYPE_A | RR_TYPE_AAAA) {
                        additional.push((target.clone(), r.rr_type, r.ttl, r.rdata.clone()));
                    }
                }
            }
        }
        additional
    }
}

/// Enterprise Protective DNS domain filtering policy, split-horizon local DNS record store, and DNS rebinding guard.
/// Supports lock-free hot-reloading via `ArcSwap` when policy, hosts, or JSON store files are updated.
#[derive(Debug, Clone, Default)]
pub struct DomainPolicy {
    inner: Arc<ArcSwap<DomainPolicyInner>>,
    store_lock: Arc<Mutex<()>>,
    rr_cursor: Arc<AtomicUsize>,
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
        Self::from_files_with_store(
            allowlist_path,
            blocklist_path,
            hosts_path,
            None,
            action,
            block_private_rebinding,
        )
    }

    /// Loads optional allowlist, blocklist, custom hosts file, and persistent JSON store file (`--dns-store-file`).
    pub fn from_files_with_store(
        allowlist_path: Option<&Path>,
        blocklist_path: Option<&Path>,
        hosts_path: Option<&Path>,
        store_path: Option<&Path>,
        action: BlockAction,
        block_private_rebinding: bool,
    ) -> Result<Self, DohError> {
        let inner = Self::load_inner_with_store(
            allowlist_path,
            blocklist_path,
            hosts_path,
            store_path,
            action,
            block_private_rebinding,
        )?;
        Ok(Self {
            inner: Arc::new(ArcSwap::from_pointee(inner)),
            store_lock: Arc::new(Mutex::new(())),
            rr_cursor: Arc::new(AtomicUsize::new(0)),
        })
    }

    fn load_inner_with_store(
        allowlist_path: Option<&Path>,
        blocklist_path: Option<&Path>,
        hosts_path: Option<&Path>,
        store_path: Option<&Path>,
        mut action: BlockAction,
        mut block_private_rebinding: bool,
    ) -> Result<DomainPolicyInner, DohError> {
        let file_allow_domains = match allowlist_path {
            Some(p) => Self::parse_domain_file(p)?,
            None => HashSet::new(),
        };
        let file_block_domains = match blocklist_path {
            Some(p) => Self::parse_domain_file(p)?,
            None => HashSet::new(),
        };
        let (hosts_forward, hosts_reverse) = match hosts_path {
            Some(p) => Self::parse_hosts_file(p)?,
            None => (HashMap::new(), HashMap::new()),
        };

        let mut zones = Vec::new();
        let mut local_records = Vec::new();
        let mut policy_rules = Vec::new();
        if let Some(sp) = store_path {
            if sp.exists() {
                let raw = fs::read_to_string(sp).map_err(|e| {
                    DohError::InvalidConfig(format!(
                        "failed to read DNS store file {}: {e}",
                        sp.display()
                    ))
                })?;
                let doc: DnsStoreDocument = serde_json::from_str(&raw).map_err(|e| {
                    DohError::InvalidConfig(format!(
                        "invalid JSON in DNS store file {}: {e}",
                        sp.display()
                    ))
                })?;
                if let Some(ref act_str) = doc.block_action {
                    if let Ok(parsed_action) = BlockAction::from_str_name(act_str) {
                        action = parsed_action;
                    }
                }
                if let Some(reb) = doc.block_private_rebinding {
                    block_private_rebinding = reb;
                }
                zones = doc.zones;
                local_records = doc.records;
                policy_rules = doc.policy_rules;
            }
        }

        let mut inner = DomainPolicyInner {
            allow_domains: HashSet::new(),
            block_domains: HashSet::new(),
            file_allow_domains,
            file_block_domains,
            hosts_forward,
            hosts_reverse,
            action,
            block_private_rebinding,
            store_path: store_path.map(Path::to_path_buf),
            zones,
            compiled_zones: HashMap::new(),
            local_records,
            compiled_by_domain: HashMap::new(),
            auto_ptr_by_reverse: HashMap::new(),
            policy_rules,
        };
        inner.rebuild_compiled_maps();
        Ok(inner)
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
        let allow_set: HashSet<String> = allow
            .into_iter()
            .filter_map(|s| Self::normalize_rule(s.as_ref()))
            .collect();
        let block_set: HashSet<String> = block
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
        let mut inner = DomainPolicyInner {
            allow_domains: allow_set.clone(),
            block_domains: block_set.clone(),
            file_allow_domains: allow_set,
            file_block_domains: block_set,
            hosts_forward,
            hosts_reverse,
            action,
            block_private_rebinding,
            store_path: None,
            zones: Vec::new(),
            compiled_zones: HashMap::new(),
            local_records: Vec::new(),
            compiled_by_domain: HashMap::new(),
            auto_ptr_by_reverse: HashMap::new(),
            policy_rules: Vec::new(),
        };
        inner.rebuild_compiled_maps();
        Self {
            inner: Arc::new(ArcSwap::from_pointee(inner)),
            store_lock: Arc::new(Mutex::new(())),
            rr_cursor: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Atomically reloads `allowlist_path`, `blocklist_path`, and `hosts_path` from disk via `ArcSwap`,
    /// preserving any in-memory/store records and rules.
    pub fn reload_from_files(
        &self,
        allowlist_path: Option<&Path>,
        blocklist_path: Option<&Path>,
        hosts_path: Option<&Path>,
        action: BlockAction,
        block_private_rebinding: bool,
    ) -> Result<(), DohError> {
        let _guard = self.store_lock.lock().ok();
        let cur = self.inner.load_full();
        let mut new_inner = Self::load_inner_with_store(
            allowlist_path,
            blocklist_path,
            hosts_path,
            cur.store_path.as_deref(),
            action,
            block_private_rebinding,
        )?;
        if cur.store_path.is_none() {
            new_inner.zones = cur.zones.clone();
            new_inner.local_records = cur.local_records.clone();
            new_inner.policy_rules = cur.policy_rules.clone();
            new_inner.rebuild_compiled_maps();
        }
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
                    match policy_clone.reload_from_files(
                        allowlist_path.as_deref(),
                        blocklist_path.as_deref(),
                        hosts_path.as_deref(),
                        action,
                        block_private_rebinding,
                    ) {
                        Ok(()) => {
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
        !guard.compiled_zones.is_empty()
            || !guard.compiled_by_domain.is_empty()
            || !guard.auto_ptr_by_reverse.is_empty()
            || !guard.hosts_forward.is_empty()
            || !guard.hosts_reverse.is_empty()
    }

    /// Returns a snapshot of all managed DNS zones.
    pub fn list_zones(&self) -> Vec<DnsZone> {
        self.inner.load().zones.clone()
    }

    /// Returns a snapshot of all structured local DNS records.
    pub fn list_local_records(&self) -> Vec<LocalDnsRecord> {
        self.inner.load().local_records.clone()
    }

    /// Returns a snapshot of all structured Protective DNS policy rules.
    pub fn list_policy_rules(&self) -> Vec<PolicyRuleEntry> {
        self.inner.load().policy_rules.clone()
    }

    /// Returns `(block_action, block_private_rebinding, allow_count, block_count, local_record_count)`.
    pub fn policy_summary(&self) -> (BlockAction, bool, usize, usize, usize) {
        let guard = self.inner.load();
        (
            guard.action,
            guard.block_private_rebinding,
            guard.allow_domains.len(),
            guard.block_domains.len(),
            guard.local_records.len(),
        )
    }

    /// Validates, upserts (creates or updates), and persists a `DnsZone`.
    /// Returns `(saved_zone, previous_domain_if_changed)`.
    pub fn upsert_zone(
        &self,
        mut zone: DnsZone,
    ) -> Result<(DnsZone, Option<String>), RecordValidationError> {
        let _lock = self.store_lock.lock().map_err(|_| {
            RecordValidationError::InvalidRecordData("Policy store lock is poisoned.".to_string())
        })?;
        let mut next = (*self.inner.load_full()).clone();

        let compiled = zone.validate_and_compile()?;
        zone = compiled.zone;
        zone.updated_at_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if next
            .zones
            .iter()
            .any(|z| z.id != zone.id && z.domain.eq_ignore_ascii_case(&zone.domain))
        {
            return Err(RecordValidationError::DuplicateRecord(format!(
                "A DNS zone for '{}' already exists.",
                zone.domain
            )));
        }

        let mut prev_domain = None;
        if let Some(existing) = next.zones.iter_mut().find(|z| z.id == zone.id) {
            if existing.domain != zone.domain {
                prev_domain = Some(existing.domain.clone());
            }
            if zone.serial <= existing.serial {
                zone.serial = existing.serial.saturating_add(1);
            }
            *existing = zone.clone();
        } else {
            if zone.serial == 0 {
                zone.serial = 2026102401;
            }
            next.zones.push(zone.clone());
        }

        next.rebuild_compiled_maps();
        Self::save_store_if_configured(&next)?;
        self.inner.store(Arc::new(next));
        Ok((zone, prev_domain))
    }

    /// Deletes a `DnsZone` by `id` and optionally deletes all records belonging to that zone.
    pub fn delete_zone(
        &self,
        id: &str,
        delete_records: bool,
    ) -> Result<Option<(DnsZone, usize)>, RecordValidationError> {
        let _lock = self.store_lock.lock().map_err(|_| {
            RecordValidationError::InvalidRecordData("Policy store lock is poisoned.".to_string())
        })?;
        let mut next = (*self.inner.load_full()).clone();
        let Some(pos) = next.zones.iter().position(|z| z.id == id) else {
            return Ok(None);
        };
        let removed_zone = next.zones.remove(pos);
        let mut deleted_records_count = 0usize;
        if delete_records {
            let before = next.local_records.len();
            let zone_suffix = format!(".{}", removed_zone.domain);
            next.local_records.retain(|r| {
                let in_zone = r.zone_id.as_deref() == Some(id)
                    || r.domain == removed_zone.domain
                    || r.domain.ends_with(&zone_suffix);
                !in_zone
            });
            deleted_records_count = before.saturating_sub(next.local_records.len());
        } else {
            for r in &mut next.local_records {
                if r.zone_id.as_deref() == Some(id) {
                    r.zone_id = None;
                }
            }
        }

        next.rebuild_compiled_maps();
        Self::save_store_if_configured(&next)?;
        self.inner.store(Arc::new(next));
        Ok(Some((removed_zone, deleted_records_count)))
    }

    /// Validates, upserts (creates or updates), and persists a `LocalDnsRecord`.
    /// Returns `(saved_record, previous_domain_if_changed)`.
    pub fn upsert_local_record(
        &self,
        mut record: LocalDnsRecord,
    ) -> Result<(LocalDnsRecord, Option<String>), RecordValidationError> {
        let _lock = self.store_lock.lock().map_err(|_| {
            RecordValidationError::InvalidRecordData("Policy store lock is poisoned.".to_string())
        })?;
        let mut next = (*self.inner.load_full()).clone();

        // If `zone_id` is specified, expand relative names (`@`, `sub`) against the zone's domain
        if let Some(ref zid) = record.zone_id {
            let Some(zone) = next.zones.iter().find(|z| &z.id == zid) else {
                return Err(RecordValidationError::NotFound(
                    "The specified DNS zone does not exist.".to_string(),
                ));
            };
            record.domain = resolve_record_owner_in_zone(&record.domain, &zone.domain, &record.data)?;
        }

        let compiled = validate_record_against_store(&record, &next.local_records)?;
        record.domain = compiled.domain;
        // Auto-associate with longest matching zone if zone_id was not explicitly set
        if record.zone_id.is_none() {
            if let Some(matched_zone) = next
                .zones
                .iter()
                .filter(|z| {
                    record.domain == z.domain
                        || record.domain.ends_with(&format!(".{}", z.domain))
                })
                .max_by_key(|z| z.domain.len())
            {
                record.zone_id = Some(matched_zone.id.clone());
            }
        }
        record.updated_at_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut prev_domain = None;
        if let Some(existing) = next.local_records.iter_mut().find(|r| r.id == record.id) {
            if existing.domain != record.domain {
                prev_domain = Some(existing.domain.clone());
            }
            *existing = record.clone();
        } else {
            next.local_records.push(record.clone());
        }

        // Bump enclosing zone SOA serial
        if let Some(ref zid) = record.zone_id {
            if let Some(z) = next.zones.iter_mut().find(|z| &z.id == zid) {
                z.serial = z.serial.saturating_add(1);
                z.updated_at_epoch = record.updated_at_epoch;
            }
        }

        next.rebuild_compiled_maps();
        Self::save_store_if_configured(&next)?;
        self.inner.store(Arc::new(next));
        Ok((record, prev_domain))
    }

    /// Deletes a `LocalDnsRecord` by `id` and persists the store. Returns the deleted record if found.
    pub fn delete_local_record(
        &self,
        id: &str,
    ) -> Result<Option<LocalDnsRecord>, RecordValidationError> {
        let _lock = self.store_lock.lock().map_err(|_| {
            RecordValidationError::InvalidRecordData("Policy store lock is poisoned.".to_string())
        })?;
        let mut next = (*self.inner.load_full()).clone();
        let Some(pos) = next.local_records.iter().position(|r| r.id == id) else {
            return Ok(None);
        };
        let removed = next.local_records.remove(pos);
        if let Some(ref zid) = removed.zone_id {
            if let Some(z) = next.zones.iter_mut().find(|z| &z.id == zid) {
                z.serial = z.serial.saturating_add(1);
            }
        }
        next.rebuild_compiled_maps();
        Self::save_store_if_configured(&next)?;
        self.inner.store(Arc::new(next));
        Ok(Some(removed))
    }

    /// Bulk-deletes multiple `LocalDnsRecord` IDs in a single atomic transaction.
    /// Returns the list of deleted records.
    pub fn bulk_delete_local_records(
        &self,
        ids: &[String],
    ) -> Result<Vec<LocalDnsRecord>, RecordValidationError> {
        let _lock = self.store_lock.lock().map_err(|_| {
            RecordValidationError::InvalidRecordData("Policy store lock is poisoned.".to_string())
        })?;
        let id_set: HashSet<&str> = ids.iter().map(String::as_str).collect();
        let mut next = (*self.inner.load_full()).clone();
        let mut removed = Vec::new();
        next.local_records.retain(|r| {
            if id_set.contains(r.id.as_str()) {
                removed.push(r.clone());
                false
            } else {
                true
            }
        });
        if !removed.is_empty() {
            next.rebuild_compiled_maps();
            Self::save_store_if_configured(&next)?;
            self.inner.store(Arc::new(next));
        }
        Ok(removed)
    }

    /// Validates and imports a batch of `LocalDnsRecord`s (or performs a dry-run preview when `dry_run == true`).
    pub fn import_local_records(
        &self,
        candidates: Vec<LocalDnsRecord>,
        dry_run: bool,
    ) -> Result<Vec<LocalDnsRecord>, RecordValidationError> {
        let _lock = self.store_lock.lock().map_err(|_| {
            RecordValidationError::InvalidRecordData("Policy store lock is poisoned.".to_string())
        })?;
        let mut next = (*self.inner.load_full()).clone();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut imported = Vec::with_capacity(candidates.len());

        for mut rec in candidates {
            if let Some(ref zid) = rec.zone_id {
                let Some(zone) = next.zones.iter().find(|z| &z.id == zid) else {
                    return Err(RecordValidationError::NotFound(
                        "The specified DNS zone does not exist.".to_string(),
                    ));
                };
                rec.domain = resolve_record_owner_in_zone(&rec.domain, &zone.domain, &rec.data)?;
            }
            let compiled = validate_record_against_store(&rec, &next.local_records)?;
            rec.domain = compiled.domain;
            if rec.zone_id.is_none() {
                if let Some(matched_zone) = next
                    .zones
                    .iter()
                    .filter(|z| {
                        rec.domain == z.domain
                            || rec.domain.ends_with(&format!(".{}", z.domain))
                    })
                    .max_by_key(|z| z.domain.len())
                {
                    rec.zone_id = Some(matched_zone.id.clone());
                }
            }
            rec.updated_at_epoch = now;
            next.local_records.push(rec.clone());
            imported.push(rec);
        }

        if !dry_run {
            next.rebuild_compiled_maps();
            Self::save_store_if_configured(&next)?;
            self.inner.store(Arc::new(next));
        }
        Ok(imported)
    }

    /// Validates, upserts, and persists a `PolicyRuleEntry`.
    pub fn upsert_policy_rule(
        &self,
        mut rule: PolicyRuleEntry,
    ) -> Result<PolicyRuleEntry, RecordValidationError> {
        let _lock = self.store_lock.lock().map_err(|_| {
            RecordValidationError::InvalidRecordData("Policy store lock is poisoned.".to_string())
        })?;
        let mut next = (*self.inner.load_full()).clone();

        if rule.id.trim().is_empty() || rule.id.len() > 64 {
            return Err(RecordValidationError::InvalidRecordData(
                "Rule ID must be between 1 and 64 characters.".to_string(),
            ));
        }
        if rule.comment.len() > 256 {
            return Err(RecordValidationError::InvalidRecordData(
                "Rule comment must not exceed 256 characters.".to_string(),
            ));
        }
        let cleaned_domain = validate_general_domain_name(&rule.domain, true)?;
        if cleaned_domain == "localhost" {
            return Err(RecordValidationError::InvalidDomain(
                "'localhost' cannot be added as a policy filter rule.".to_string(),
            ));
        }
        rule.domain = cleaned_domain;
        rule.updated_at_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Prevent duplicate rule for same (kind, domain) with different id
        if next.policy_rules.iter().any(|r| {
            r.id != rule.id && r.kind == rule.kind && r.domain.eq_ignore_ascii_case(&rule.domain)
        }) {
            return Err(RecordValidationError::DuplicateRecord(format!(
                "Domain '{}' already exists in this policy list.",
                rule.domain
            )));
        }

        if let Some(existing) = next.policy_rules.iter_mut().find(|r| r.id == rule.id) {
            *existing = rule.clone();
        } else {
            next.policy_rules.push(rule.clone());
        }

        next.rebuild_compiled_maps();
        Self::save_store_if_configured(&next)?;
        self.inner.store(Arc::new(next));
        Ok(rule)
    }

    /// Deletes a `PolicyRuleEntry` by `id`.
    pub fn delete_policy_rule(
        &self,
        id: &str,
    ) -> Result<Option<PolicyRuleEntry>, RecordValidationError> {
        let _lock = self.store_lock.lock().map_err(|_| {
            RecordValidationError::InvalidRecordData("Policy store lock is poisoned.".to_string())
        })?;
        let mut next = (*self.inner.load_full()).clone();
        let Some(pos) = next.policy_rules.iter().position(|r| r.id == id) else {
            return Ok(None);
        };
        let removed = next.policy_rules.remove(pos);
        next.rebuild_compiled_maps();
        Self::save_store_if_configured(&next)?;
        self.inner.store(Arc::new(next));
        Ok(Some(removed))
    }

    /// Updates global Protective DNS settings (`block_action` and `block_private_rebinding`) and persists the store.
    pub fn update_policy_settings(
        &self,
        action: BlockAction,
        block_private_rebinding: bool,
    ) -> Result<(), RecordValidationError> {
        let _lock = self.store_lock.lock().map_err(|_| {
            RecordValidationError::InvalidRecordData("Policy store lock is poisoned.".to_string())
        })?;
        let mut next = (*self.inner.load_full()).clone();
        next.action = action;
        next.block_private_rebinding = block_private_rebinding;
        Self::save_store_if_configured(&next)?;
        self.inner.store(Arc::new(next));
        Ok(())
    }

    fn save_store_if_configured(inner: &DomainPolicyInner) -> Result<(), RecordValidationError> {
        let Some(ref path) = inner.store_path else {
            return Ok(());
        };
        let doc = DnsStoreDocument {
            version: 1,
            zones: inner.zones.clone(),
            records: inner.local_records.clone(),
            policy_rules: inner.policy_rules.clone(),
            block_action: Some(inner.action.as_str().to_string()),
            block_private_rebinding: Some(inner.block_private_rebinding),
        };
        let serialized = serde_json::to_vec_pretty(&doc).map_err(|e| {
            RecordValidationError::InvalidRecordData(format!("Failed to serialize DNS store: {e}"))
        })?;

        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                fs::create_dir_all(parent).map_err(|e| {
                    RecordValidationError::InvalidRecordData(format!(
                        "Failed to create store directory: {e}"
                    ))
                })?;
            }
        }

        let tmp_path = path.with_extension("json.tmp");
        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|e| {
                RecordValidationError::InvalidRecordData(format!(
                    "Failed to open temporary store file: {e}"
                ))
            })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
        }

        file.write_all(&serialized)
            .and_then(|()| file.sync_all())
            .map_err(|e| {
                RecordValidationError::InvalidRecordData(format!(
                    "Failed to write temporary store file: {e}"
                ))
            })?;
        drop(file);

        fs::rename(&tmp_path, path).map_err(|e| {
            RecordValidationError::InvalidRecordData(format!(
                "Failed to atomically rename store file: {e}"
            ))
        })?;
        Ok(())
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

    /// Resolves local DNS records (all 29 RR types, local CNAME chains, RFC 6672 DNAME subtree aliases,
    /// `auto_ptr` reverse records, zone-apex SOA/NS, RFC 2308 `NODATA`/`NXDOMAIN` with SOA Authority,
    /// in-bailiwick `A`/`AAAA` glue, and legacy hosts).
    /// Returns `Ok(Some((wire_response, effective_ttl)))` if matched locally.
    pub fn try_resolve_local_records(
        &self,
        query: &[u8],
        qname_lower: &str,
        qtype: u16,
        default_ttl: u32,
    ) -> Result<Option<(Vec<u8>, u32)>, DohError> {
        let guard = self.inner.load();
        if guard.compiled_zones.is_empty()
            && guard.compiled_by_domain.is_empty()
            && guard.auto_ptr_by_reverse.is_empty()
            && guard.hosts_forward.is_empty()
            && guard.hosts_reverse.is_empty()
        {
            return Ok(None);
        }

        let clean = qname_lower.trim_matches('.');
        let enclosing_zone = guard.find_enclosing_zone(clean);
        let zone_soa_authority = |cz: Option<&CompiledDnsZone>| -> Vec<(String, u16, u32, Vec<u8>)> {
            match cz {
                Some(z) => {
                    let neg_ttl = z.zone.minimum.min(z.zone.default_ttl).max(1);
                    vec![(
                        z.zone.domain.clone(),
                        RR_TYPE_SOA,
                        neg_ttl,
                        z.soa_rdata.clone(),
                    )]
                }
                None => Vec::new(),
            }
        };

        // 0. Check RFC 6672 DNAME subtree redirection (`<prefix>.<dname_owner>` -> `<prefix>.<dname_target>`)
        if let Some((dname_owner, dname_rec, prefix)) = guard.find_ancestor_dname(clean) {
            if let Some(ref dname_target) = dname_rec.dname_target {
                let synth_target = format!("{prefix}.{dname_target}");
                let mut synth_cname_rdata = Vec::with_capacity(synth_target.len() + 2);
                if encode_domain_wire(&synth_target, &mut synth_cname_rdata).is_ok() {
                    let mut answer_rrs = vec![
                        (
                            dname_owner.to_string(),
                            RR_TYPE_DNAME,
                            dname_rec.ttl,
                            dname_rec.rdata.clone(),
                        ),
                        (
                            clean.to_string(),
                            RR_TYPE_CNAME,
                            dname_rec.ttl,
                            synth_cname_rdata,
                        ),
                    ];
                    let mut min_ttl = dname_rec.ttl;
                    let mut glue_targets = Vec::new();
                    if qtype != RR_TYPE_CNAME {
                        if let Some(target_recs) = guard.lookup_domain_records(&synth_target) {
                            for rec in target_recs
                                .iter()
                                .filter(|r| qtype == RR_TYPE_ANY || r.rr_type == qtype)
                            {
                                min_ttl = min_ttl.min(rec.ttl);
                                if let Some(ref gt) = rec.glue_target {
                                    glue_targets.push(gt.clone());
                                }
                                answer_rrs.push((
                                    synth_target.clone(),
                                    rec.rr_type,
                                    rec.ttl,
                                    rec.rdata.clone(),
                                ));
                            }
                        }
                    }
                    let additional_rrs = guard.collect_glue_records(&glue_targets, clean);
                    let wire = build_local_authoritative_response(
                        query,
                        RCODE_NOERROR,
                        &answer_rrs,
                        &[],
                        &additional_rrs,
                    )?;
                    return Ok(Some((wire, min_ttl)));
                }
            }
        }

        // 1. Check structured local DNS records (exact match or `*.zone` wildcard)
        if let Some(domain_records) = guard.lookup_domain_records(clean) {
            let mut answer_rrs: Vec<(String, u16, u32, Vec<u8>)> = Vec::new();
            let mut glue_targets: Vec<String> = Vec::new();
            let mut min_ttl: Option<u32> = None;

            if qtype == RR_TYPE_CNAME {
                for rec in domain_records.iter().filter(|r| r.rr_type == RR_TYPE_CNAME) {
                    min_ttl = Some(min_ttl.map_or(rec.ttl, |cur| cur.min(rec.ttl)));
                    answer_rrs.push((clean.to_string(), rec.rr_type, rec.ttl, rec.rdata.clone()));
                }
                if !answer_rrs.is_empty() {
                    let wire = build_local_records_response(query, &answer_rrs)?;
                    return Ok(Some((wire, min_ttl.unwrap_or(default_ttl))));
                }
            }

            if let Some(first_cname) = domain_records.iter().find(|r| r.rr_type == RR_TYPE_CNAME) {
                // Follow local CNAME chain up to 8 hops
                let mut current_owner = clean.to_string();
                let mut current_cname = first_cname;
                for _ in 0..8 {
                    min_ttl = Some(
                        min_ttl.map_or(current_cname.ttl, |cur| cur.min(current_cname.ttl)),
                    );
                    answer_rrs.push((
                        current_owner.clone(),
                        RR_TYPE_CNAME,
                        current_cname.ttl,
                        current_cname.rdata.clone(),
                    ));
                    let Some(ref target) = current_cname.cname_target else {
                        break;
                    };
                    current_owner = target.clone();
                    let Some(target_records) = guard.lookup_domain_records(&current_owner) else {
                        break;
                    };
                    let mut matched_terminal = false;
                    for rec in target_records
                        .iter()
                        .filter(|r| qtype == RR_TYPE_ANY || r.rr_type == qtype)
                    {
                        min_ttl = Some(min_ttl.map_or(rec.ttl, |cur| cur.min(rec.ttl)));
                        if let Some(ref gt) = rec.glue_target {
                            glue_targets.push(gt.clone());
                        }
                        answer_rrs.push((
                            current_owner.clone(),
                            rec.rr_type,
                            rec.ttl,
                            rec.rdata.clone(),
                        ));
                        matched_terminal = true;
                    }
                    if matched_terminal {
                        break;
                    }
                    if let Some(next_cname) =
                        target_records.iter().find(|r| r.rr_type == RR_TYPE_CNAME)
                    {
                        current_cname = next_cname;
                    } else {
                        break;
                    }
                }
                let additional_rrs = guard.collect_glue_records(&glue_targets, clean);
                let wire = build_local_authoritative_response(
                    query,
                    RCODE_NOERROR,
                    &answer_rrs,
                    &[],
                    &additional_rrs,
                )?;
                return Ok(Some((wire, min_ttl.unwrap_or(default_ttl))));
            }

            let matching: Vec<&CompiledLocalRecord> = domain_records
                .iter()
                .filter(|r| qtype == RR_TYPE_ANY || r.rr_type == qtype)
                .collect();

            if !matching.is_empty() {
                let len = matching.len();
                let offset = if len > 1 && matches!(qtype, RR_TYPE_A | RR_TYPE_AAAA) {
                    self.rr_cursor.fetch_add(1, Ordering::Relaxed) % len
                } else {
                    0
                };
                for idx in 0..len {
                    let rec = matching[(offset + idx) % len];
                    min_ttl = Some(min_ttl.map_or(rec.ttl, |cur| cur.min(rec.ttl)));
                    if let Some(ref gt) = rec.glue_target {
                        glue_targets.push(gt.clone());
                    }
                    answer_rrs.push((clean.to_string(), rec.rr_type, rec.ttl, rec.rdata.clone()));
                }
                let additional_rrs = guard.collect_glue_records(&glue_targets, clean);
                let wire = build_local_authoritative_response(
                    query,
                    RCODE_NOERROR,
                    &answer_rrs,
                    &[],
                    &additional_rrs,
                )?;
                return Ok(Some((wire, min_ttl.unwrap_or(default_ttl))));
            }

            // If querying SOA or NS at the zone apex and no explicit SOA/NS record was in `domain_records`,
            // serve the zone's synthesized SOA/NS record!
            if let Some(cz) = enclosing_zone {
                if cz.zone.domain == clean {
                    if qtype == RR_TYPE_SOA {
                        let ans = vec![(
                            clean.to_string(),
                            RR_TYPE_SOA,
                            cz.zone.default_ttl,
                            cz.soa_rdata.clone(),
                        )];
                        let wire = build_local_authoritative_response(
                            query,
                            RCODE_NOERROR,
                            &ans,
                            &[],
                            &[],
                        )?;
                        return Ok(Some((wire, cz.zone.default_ttl)));
                    } else if qtype == RR_TYPE_NS {
                        let ans = vec![(
                            clean.to_string(),
                            RR_TYPE_NS,
                            cz.zone.default_ttl,
                            cz.ns_rdata.clone(),
                        )];
                        let glue =
                            guard.collect_glue_records(std::slice::from_ref(&cz.zone.mname), clean);
                        let wire = build_local_authoritative_response(
                            query,
                            RCODE_NOERROR,
                            &ans,
                            &[],
                            &glue,
                        )?;
                        return Ok(Some((wire, cz.zone.default_ttl)));
                    }
                }
            }

            // RFC 2308 §2.2: Domain owns enabled local records of another RR type -> synthesize NODATA with SOA Authority
            let nodata_ttl = enclosing_zone
                .map(|z| z.zone.minimum.min(z.zone.default_ttl).max(1))
                .unwrap_or_else(|| {
                    domain_records
                        .iter()
                        .map(|r| r.ttl)
                        .min()
                        .unwrap_or(default_ttl)
                });
            let authority_rrs = zone_soa_authority(enclosing_zone);
            let wire = build_local_authoritative_response(
                query,
                RCODE_NOERROR,
                &[],
                &authority_rrs,
                &[],
            )?;
            return Ok(Some((wire, nodata_ttl)));
        }

        // 1b. Check zone-apex synthesized SOA / NS / NODATA when a zone has no explicit apex records in `compiled_by_domain`
        if let Some(cz) = enclosing_zone {
            if cz.zone.domain == clean {
                if qtype == RR_TYPE_SOA || qtype == RR_TYPE_ANY {
                    let mut ans = vec![(
                        clean.to_string(),
                        RR_TYPE_SOA,
                        cz.zone.default_ttl,
                        cz.soa_rdata.clone(),
                    )];
                    if qtype == RR_TYPE_ANY {
                        ans.push((
                            clean.to_string(),
                            RR_TYPE_NS,
                            cz.zone.default_ttl,
                            cz.ns_rdata.clone(),
                        ));
                    }
                    let wire =
                        build_local_authoritative_response(query, RCODE_NOERROR, &ans, &[], &[])?;
                    return Ok(Some((wire, cz.zone.default_ttl)));
                } else if qtype == RR_TYPE_NS {
                    let ans = vec![(
                        clean.to_string(),
                        RR_TYPE_NS,
                        cz.zone.default_ttl,
                        cz.ns_rdata.clone(),
                    )];
                    let glue =
                        guard.collect_glue_records(std::slice::from_ref(&cz.zone.mname), clean);
                    let wire =
                        build_local_authoritative_response(query, RCODE_NOERROR, &ans, &[], &glue)?;
                    return Ok(Some((wire, cz.zone.default_ttl)));
                } else {
                    let neg_ttl = cz.zone.minimum.min(cz.zone.default_ttl).max(1);
                    let authority_rrs = zone_soa_authority(Some(cz));
                    let wire = build_local_authoritative_response(
                        query,
                        RCODE_NOERROR,
                        &[],
                        &authority_rrs,
                        &[],
                    )?;
                    return Ok(Some((wire, neg_ttl)));
                }
            }
        }

        // 2. Check synthesized `auto_ptr` reverse records for `PTR` queries
        if qtype == RR_TYPE_PTR {
            if let Some((ptr_ttl, ptr_rdata)) = guard.auto_ptr_by_reverse.get(clean) {
                let answer_rrs = vec![(
                    clean.to_string(),
                    RR_TYPE_PTR,
                    *ptr_ttl,
                    ptr_rdata.clone(),
                )];
                let wire = build_local_records_response(query, &answer_rrs)?;
                return Ok(Some((wire, *ptr_ttl)));
            }
        }

        // 3. Fallback to legacy `--hosts-file` table if configured
        match qtype {
            RR_TYPE_A | RR_TYPE_AAAA => {
                if let Some(ips) = guard.hosts_forward.get(clean) {
                    let has_matching_family = ips.iter().any(|ip| {
                        (qtype == RR_TYPE_A && ip.is_ipv4())
                            || (qtype == RR_TYPE_AAAA && ip.is_ipv6())
                    });
                    if has_matching_family {
                        let wire = build_hosts_response(query, ips, None, default_ttl)?;
                        return Ok(Some((wire, default_ttl)));
                    }
                    // Domain exists in hosts_forward for the other IP family -> synthesize NODATA
                    let wire = build_local_records_response(query, &[])?;
                    return Ok(Some((wire, default_ttl)));
                }
            }
            RR_TYPE_PTR => {
                if let Some(target) = guard.hosts_reverse.get(clean) {
                    let wire = build_hosts_response(query, &[], Some(target), default_ttl)?;
                    return Ok(Some((wire, default_ttl)));
                }
            }
            _ => {
                if guard.hosts_forward.contains_key(clean) {
                    let wire = build_local_records_response(query, &[])?;
                    return Ok(Some((wire, default_ttl)));
                }
            }
        }

        // 4. Authoritative Zone NXDOMAIN (Zero Upstream Leak):
        // If `clean` falls under an enabled `Authoritative` zone and did not match any record above,
        // return a local authoritative `NXDOMAIN` (RCODE 3) with the zone's SOA in the Authority section!
        if let Some(cz) = enclosing_zone {
            if cz.zone.mode == ZoneMode::Authoritative {
                let neg_ttl = cz.zone.minimum.min(cz.zone.default_ttl).max(1);
                let authority_rrs = zone_soa_authority(Some(cz));
                let wire = build_local_authoritative_response(
                    query,
                    RCODE_NXDOMAIN,
                    &[],
                    &authority_rrs,
                    &[],
                )?;
                return Ok(Some((wire, neg_ttl)));
            }
        }

        Ok(None)
    }

    /// Checks whether `qname_lower` matches a local split-horizon host override or structured local record
    /// and returns a synthesized `NOERROR` wire response if matched.
    pub fn try_resolve_hosts(
        &self,
        query: &[u8],
        qname_lower: &str,
        qtype: u16,
        ttl: u32,
    ) -> Result<Option<Vec<u8>>, DohError> {
        Ok(self
            .try_resolve_local_records(query, qname_lower, qtype, ttl)?
            .map(|(wire, _)| wire))
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
            || guard.lookup_domain_records(clean).is_some()
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
