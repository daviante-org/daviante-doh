//! Cloudflare-grade Local DNS Record Engine supporting all standard IANA DNS Resource Record types,
//! strict RFC wire-format RDATA encoding, CNAME exclusivity & cycle detection, and BIND zone previewing.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::dns::wire::{
    RR_TYPE_A, RR_TYPE_AAAA, RR_TYPE_ANY, RR_TYPE_AXFR, RR_TYPE_CNAME, RR_TYPE_DNAME,
    RR_TYPE_IXFR, RR_TYPE_OPT, RR_TYPE_PTR, RR_TYPE_SOA,
};
use crate::policy::reverse_ptr_name;

/// Maximum allowed local DNS record TTL (7 days = 604,800 seconds).
pub const MAX_LOCAL_RECORD_TTL: u32 = 604_800;
/// Minimum allowed local DNS record TTL (1 second).
pub const MIN_LOCAL_RECORD_TTL: u32 = 1;
/// Maximum CNAME chain hops followed within the local DNS store.
pub const MAX_CNAME_CHAIN_HOPS: usize = 8;

/// Validation or conflict error returned when creating or updating a local DNS record or policy rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordValidationError {
    /// RFC 9457 `INVALID_DOMAIN` (HTTP 400).
    InvalidDomain(String),
    /// RFC 9457 `INVALID_RECORD_DATA` (HTTP 400).
    InvalidRecordData(String),
    /// RFC 9457 `INVALID_TTL` (HTTP 400).
    InvalidTtl(String),
    /// RFC 9457 `CNAME_CONFLICT` (HTTP 409).
    CnameConflict(String),
    /// RFC 9457 `CNAME_LOOP` (HTTP 400).
    CnameLoop(String),
    /// RFC 9457 `DUPLICATE_RECORD` (HTTP 409).
    DuplicateRecord(String),
    /// RFC 9457 `RECORD_NOT_FOUND` (HTTP 404).
    NotFound(String),
}

impl RecordValidationError {
    /// Returns the stable machine-readable error code for RFC 9457 Problem Details responses.
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidDomain(_) => "INVALID_DOMAIN",
            Self::InvalidRecordData(_) => "INVALID_RECORD_DATA",
            Self::InvalidTtl(_) => "INVALID_TTL",
            Self::CnameConflict(_) => "CNAME_CONFLICT",
            Self::CnameLoop(_) => "CNAME_LOOP",
            Self::DuplicateRecord(_) => "DUPLICATE_RECORD",
            Self::NotFound(_) => "RECORD_NOT_FOUND",
        }
    }

    /// Returns the human-readable detail message.
    pub fn message(&self) -> &str {
        match self {
            Self::InvalidDomain(m)
            | Self::InvalidRecordData(m)
            | Self::InvalidTtl(m)
            | Self::CnameConflict(m)
            | Self::CnameLoop(m)
            | Self::DuplicateRecord(m)
            | Self::NotFound(m) => m,
        }
    }
}

impl std::fmt::Display for RecordValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.error_code(), self.message())
    }
}

/// Type-specific structured data for a local DNS record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "UPPERCASE")]
pub enum LocalRecordData {
    /// IPv4 Address record (`TYPE 1`).
    A {
        ip: String,
        #[serde(default)]
        auto_ptr: bool,
    },
    /// IPv6 Address record (`TYPE 28`).
    AAAA {
        ip: String,
        #[serde(default)]
        auto_ptr: bool,
    },
    /// Canonical Name alias record (`TYPE 5`).
    CNAME { target: String },
    /// Delegation Name subtree alias record (`TYPE 39`).
    DNAME { target: String },
    /// Mail Exchange record (`TYPE 15`).
    MX { priority: u16, target: String },
    /// Text record (`TYPE 16`).
    TXT { content: String },
    /// Legacy Sender Policy Framework record (`TYPE 99`).
    SPF { content: String },
    /// Service Locator record (`TYPE 33`, RFC 2782).
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    /// Certification Authority Authorization record (`TYPE 257`, RFC 8659).
    CAA {
        flags: u8,
        tag: String,
        value: String,
    },
    /// HTTPS Service Binding record (`TYPE 65`, RFC 9460).
    HTTPS {
        priority: u16,
        target: String,
        #[serde(default)]
        svc_params: String,
    },
    /// Generic Service Binding record (`TYPE 64`, RFC 9460).
    SVCB {
        priority: u16,
        target: String,
        #[serde(default)]
        svc_params: String,
    },
    /// Authoritative Name Server record (`TYPE 2`).
    NS { target: String },
    /// Domain Name Pointer record (`TYPE 12`).
    PTR { target: String },
    /// Start of Authority record (`TYPE 6`).
    SOA {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    /// DANE TLS Authentication record (`TYPE 52`, RFC 6698).
    TLSA {
        usage: u8,
        selector: u8,
        matching_type: u8,
        cert_data: String,
    },
    /// S/MIME Certificate Association record (`TYPE 53`, RFC 8162).
    SMIMEA {
        usage: u8,
        selector: u8,
        matching_type: u8,
        cert_data: String,
    },
    /// SSH Public Key Fingerprint record (`TYPE 44`, RFC 4255).
    SSHFP {
        algorithm: u8,
        fp_type: u8,
        fingerprint: String,
    },
    /// Delegation Signer record (`TYPE 43`, RFC 4034).
    DS {
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: String,
    },
    /// Child DS record (`TYPE 59`, RFC 7344).
    CDS {
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: String,
    },
    /// DNSSEC Public Key record (`TYPE 48`, RFC 4034).
    DNSKEY {
        flags: u16,
        protocol: u8,
        algorithm: u8,
        public_key: String,
    },
    /// Child DNSKEY record (`TYPE 60`, RFC 7344).
    CDNSKEY {
        flags: u16,
        protocol: u8,
        algorithm: u8,
        public_key: String,
    },
    /// Naming Authority Pointer record (`TYPE 35`, RFC 3403).
    NAPTR {
        order: u16,
        preference: u16,
        flags: String,
        service: String,
        regexp: String,
        replacement: String,
    },
    /// Uniform Resource Identifier record (`TYPE 256`, RFC 7553).
    URI {
        priority: u16,
        weight: u16,
        target: String,
    },
    /// Host Information record (`TYPE 13`, RFC 1035).
    HINFO { cpu: String, os: String },
    /// Responsible Person record (`TYPE 17`, RFC 1183).
    RP { mbox: String, txt: String },
    /// Geographical Location record (`TYPE 29`, RFC 1876).
    LOC { coordinates: String },
    /// Certificate record (`TYPE 37`, RFC 4398).
    CERT {
        cert_type: u16,
        key_tag: u16,
        algorithm: u8,
        cert_data: String,
    },
    /// OpenPGP Public Key record (`TYPE 61`, RFC 7929).
    OPENPGPKEY { public_key: String },
    /// Arbitrary IANA RR Type with RFC 3597 hexadecimal RDATA.
    RAW { rr_type: u16, rdata_hex: String },
}

impl LocalRecordData {
    /// Returns the numeric IANA DNS Resource Record `TYPE` code (`u16`).
    pub fn rr_type_code(&self) -> u16 {
        match self {
            Self::A { .. } => RR_TYPE_A,
            Self::NS { .. } => 2,
            Self::CNAME { .. } => RR_TYPE_CNAME,
            Self::SOA { .. } => RR_TYPE_SOA,
            Self::PTR { .. } => RR_TYPE_PTR,
            Self::HINFO { .. } => 13,
            Self::MX { .. } => 15,
            Self::TXT { .. } => 16,
            Self::RP { .. } => 17,
            Self::AAAA { .. } => RR_TYPE_AAAA,
            Self::LOC { .. } => 29,
            Self::SRV { .. } => 33,
            Self::NAPTR { .. } => 35,
            Self::CERT { .. } => 37,
            Self::DNAME { .. } => RR_TYPE_DNAME,
            Self::DS { .. } => 43,
            Self::SSHFP { .. } => 44,
            Self::DNSKEY { .. } => 48,
            Self::TLSA { .. } => 52,
            Self::SMIMEA { .. } => 53,
            Self::CDS { .. } => 59,
            Self::CDNSKEY { .. } => 60,
            Self::OPENPGPKEY { .. } => 61,
            Self::SVCB { .. } => 64,
            Self::HTTPS { .. } => 65,
            Self::SPF { .. } => 99,
            Self::URI { .. } => 256,
            Self::CAA { .. } => 257,
            Self::RAW { rr_type, .. } => *rr_type,
        }
    }

    /// Returns the canonical uppercase type mnemonic (e.g. `"A"`, `"HTTPS"`, `"SRV"`).
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::A { .. } => "A",
            Self::AAAA { .. } => "AAAA",
            Self::CNAME { .. } => "CNAME",
            Self::DNAME { .. } => "DNAME",
            Self::MX { .. } => "MX",
            Self::TXT { .. } => "TXT",
            Self::SPF { .. } => "SPF",
            Self::SRV { .. } => "SRV",
            Self::CAA { .. } => "CAA",
            Self::HTTPS { .. } => "HTTPS",
            Self::SVCB { .. } => "SVCB",
            Self::NS { .. } => "NS",
            Self::PTR { .. } => "PTR",
            Self::SOA { .. } => "SOA",
            Self::TLSA { .. } => "TLSA",
            Self::SMIMEA { .. } => "SMIMEA",
            Self::SSHFP { .. } => "SSHFP",
            Self::DS { .. } => "DS",
            Self::CDS { .. } => "CDS",
            Self::DNSKEY { .. } => "DNSKEY",
            Self::CDNSKEY { .. } => "CDNSKEY",
            Self::NAPTR { .. } => "NAPTR",
            Self::URI { .. } => "URI",
            Self::HINFO { .. } => "HINFO",
            Self::RP { .. } => "RP",
            Self::LOC { .. } => "LOC",
            Self::CERT { .. } => "CERT",
            Self::OPENPGPKEY { .. } => "OPENPGPKEY",
            Self::RAW { .. } => "RAW",
        }
    }

    /// Formats a concise human-readable summary of the record's RDATA (BIND presentation style).
    pub fn display_summary(&self) -> String {
        match self {
            Self::A { ip, .. } | Self::AAAA { ip, .. } => ip.clone(),
            Self::CNAME { target }
            | Self::DNAME { target }
            | Self::NS { target }
            | Self::PTR { target } => target.clone(),
            Self::MX { priority, target } => format!("{priority} {target}"),
            Self::TXT { content } | Self::SPF { content } => format!("\"{content}\""),
            Self::SRV {
                priority,
                weight,
                port,
                target,
            } => format!("{priority} {weight} {port} {target}"),
            Self::CAA { flags, tag, value } => format!("{flags} {tag} \"{value}\""),
            Self::HTTPS {
                priority,
                target,
                svc_params,
            }
            | Self::SVCB {
                priority,
                target,
                svc_params,
            } => {
                if svc_params.trim().is_empty() {
                    format!("{priority} {target}")
                } else {
                    format!("{priority} {target} {}", svc_params.trim())
                }
            }
            Self::SOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => format!("{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"),
            Self::TLSA {
                usage,
                selector,
                matching_type,
                cert_data,
            }
            | Self::SMIMEA {
                usage,
                selector,
                matching_type,
                cert_data,
            } => format!("{usage} {selector} {matching_type} {cert_data}"),
            Self::SSHFP {
                algorithm,
                fp_type,
                fingerprint,
            } => format!("{algorithm} {fp_type} {fingerprint}"),
            Self::DS {
                key_tag,
                algorithm,
                digest_type,
                digest,
            }
            | Self::CDS {
                key_tag,
                algorithm,
                digest_type,
                digest,
            } => format!("{key_tag} {algorithm} {digest_type} {digest}"),
            Self::DNSKEY {
                flags,
                protocol,
                algorithm,
                public_key,
            }
            | Self::CDNSKEY {
                flags,
                protocol,
                algorithm,
                public_key,
            } => format!("{flags} {protocol} {algorithm} {public_key}"),
            Self::NAPTR {
                order,
                preference,
                flags,
                service,
                regexp,
                replacement,
            } => format!(
                "{order} {preference} \"{flags}\" \"{service}\" \"{regexp}\" {replacement}"
            ),
            Self::URI {
                priority,
                weight,
                target,
            } => format!("{priority} {weight} \"{target}\""),
            Self::HINFO { cpu, os } => format!("\"{cpu}\" \"{os}\""),
            Self::RP { mbox, txt } => format!("{mbox} {txt}"),
            Self::LOC { coordinates } => coordinates.clone(),
            Self::CERT {
                cert_type,
                key_tag,
                algorithm,
                cert_data,
            } => format!("{cert_type} {key_tag} {algorithm} {cert_data}"),
            Self::OPENPGPKEY { public_key } => public_key.clone(),
            Self::RAW { rr_type, rdata_hex } => {
                let byte_len = rdata_hex.trim().len() / 2;
                format!("TYPE{rr_type} \\# {byte_len} {rdata_hex}")
            }
        }
    }
}

/// Resolution mode for a managed [`DnsZone`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ZoneMode {
    /// Authoritative local zone: unmatched names under this zone return a local `NXDOMAIN`
    /// with the zone's `SOA` in the `Authority` section and NEVER leak to upstream resolvers.
    #[default]
    Authoritative,
    /// Split-horizon overlay: matched records resolve locally; unmatched names fall through
    /// to upstream DNS resolvers.
    SplitHorizon,
}

impl ZoneMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Authoritative => "authoritative",
            Self::SplitHorizon => "split_horizon",
        }
    }
}

/// A first-class managed DNS Zone (Domain) persisted in `--dns-store-file`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsZone {
    pub id: String,
    /// Canonical lowercase zone apex domain (e.g. `internal.corp` or `20.10.10.in-addr.arpa`).
    pub domain: String,
    #[serde(default)]
    pub mode: ZoneMode,
    pub default_ttl: u32,
    pub enabled: bool,
    pub mname: String,
    pub rname: String,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
    #[serde(default)]
    pub comment: String,
    #[serde(default)]
    pub updated_at_epoch: u64,
}

/// Pre-validated and wire-compiled DNS Zone stored inside `DomainPolicyInner`.
#[derive(Debug, Clone)]
pub struct CompiledDnsZone {
    pub zone: DnsZone,
    /// Wire-encoded `SOA` RDATA for RFC 2308 negative responses (`NXDOMAIN` / `NODATA` Authority section)
    /// and zone-apex `SOA` queries.
    pub soa_rdata: Vec<u8>,
    /// Wire-encoded `NS` RDATA (`mname`) for zone-apex `NS` queries.
    pub ns_rdata: Vec<u8>,
}

/// A structured local DNS record persisted in `--dns-store-file` and served by [`crate::policy::DomainPolicy`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalDnsRecord {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone_id: Option<String>,
    pub domain: String,
    pub data: LocalRecordData,
    pub ttl: u32,
    pub enabled: bool,
    #[serde(default)]
    pub comment: String,
    #[serde(default)]
    pub updated_at_epoch: u64,
}

/// Kind of Protective DNS domain policy rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyRuleKind {
    Allow,
    Block,
}

/// A structured Protective DNS allowlist or blocklist rule managed via the Admin UI / API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRuleEntry {
    pub id: String,
    pub domain: String,
    pub kind: PolicyRuleKind,
    pub enabled: bool,
    #[serde(default)]
    pub comment: String,
    #[serde(default)]
    pub updated_at_epoch: u64,
}

/// Complete JSON schema persisted in `--dns-store-file` (`DOH_DNS_STORE_FILE`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsStoreDocument {
    #[serde(default = "default_store_version")]
    pub version: u32,
    #[serde(default)]
    pub zones: Vec<DnsZone>,
    #[serde(default)]
    pub records: Vec<LocalDnsRecord>,
    #[serde(default)]
    pub policy_rules: Vec<PolicyRuleEntry>,
    #[serde(default)]
    pub block_action: Option<String>,
    #[serde(default)]
    pub block_private_rebinding: Option<bool>,
}

fn default_store_version() -> u32 {
    1
}

/// Pre-validated and wire-encoded local DNS record stored inside `DomainPolicyInner` for zero-allocation query serving.
#[derive(Debug, Clone)]
pub struct CompiledLocalRecord {
    pub id: String,
    pub zone_id: Option<String>,
    pub domain: String,
    pub rr_type: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
    pub cname_target: Option<String>,
    pub dname_target: Option<String>,
    pub glue_target: Option<String>,
    pub auto_ptr_reverse: Option<(String, Vec<u8>)>,
}

/// Validates and normalizes an owner domain name according to RFC 1035 / RFC 1123 and the record's type rules.
pub fn validate_and_normalize_owner_domain(
    raw_domain: &str,
    data: &LocalRecordData,
) -> Result<String, RecordValidationError> {
    let trimmed = raw_domain.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return Err(RecordValidationError::InvalidDomain(
            "Domain name is required.".into(),
        ));
    }

    // Convenience for PTR records: if the user entered an IPv4 or IPv6 address directly, convert to in-addr.arpa / ip6.arpa
    if matches!(data, LocalRecordData::PTR { .. }) {
        if let Ok(ip) = trimmed.parse::<IpAddr>() {
            return Ok(reverse_ptr_name(ip));
        }
    }

    let lower = trimmed.to_ascii_lowercase();
    if lower.len() > 253 {
        return Err(RecordValidationError::InvalidDomain(
            "Domain name exceeds maximum length of 253 characters (RFC 1035).".into(),
        ));
    }

    let allow_underscore = matches!(
        data,
        LocalRecordData::CNAME { .. }
            | LocalRecordData::DNAME { .. }
            | LocalRecordData::TXT { .. }
            | LocalRecordData::SPF { .. }
            | LocalRecordData::SRV { .. }
            | LocalRecordData::CAA { .. }
            | LocalRecordData::HTTPS { .. }
            | LocalRecordData::SVCB { .. }
            | LocalRecordData::TLSA { .. }
            | LocalRecordData::SMIMEA { .. }
            | LocalRecordData::URI { .. }
            | LocalRecordData::NAPTR { .. }
            | LocalRecordData::OPENPGPKEY { .. }
            | LocalRecordData::RAW { .. }
    );

    let labels: Vec<&str> = lower.split('.').collect();
    for (idx, &label) in labels.iter().enumerate() {
        if label.is_empty() || label.len() > 63 {
            return Err(RecordValidationError::InvalidDomain(
                "Each domain label must be between 1 and 63 characters.".into(),
            ));
        }
        if idx == 0 && label == "*" {
            if labels.len() < 2 {
                return Err(RecordValidationError::InvalidDomain(
                    "Wildcard '*' requires a parent domain (e.g. '*.internal.lan').".into(),
                ));
            }
            continue;
        }
        validate_domain_label(label, allow_underscore)?;
    }

    if matches!(data, LocalRecordData::SRV { .. }) {
        // RFC 2782: SRV owner names begin with `_service._proto.` (unless leftmost is `*`)
        let check_start = usize::from(labels.first() == Some(&"*"));
        if labels.len() < check_start + 3
            || !labels[check_start].starts_with('_')
            || !labels[check_start + 1].starts_with('_')
        {
            return Err(RecordValidationError::InvalidDomain(
                "SRV record owner name must follow '_service._proto.domain' format (RFC 2782)."
                    .into(),
            ));
        }
    }

    if matches!(data, LocalRecordData::PTR { .. })
        && !lower.ends_with(".in-addr.arpa")
        && !lower.ends_with(".ip6.arpa")
    {
        return Err(RecordValidationError::InvalidDomain(
            "PTR record owner must be an IPv4/IPv6 address or end with '.in-addr.arpa' / '.ip6.arpa'."
                .into(),
        ));
    }

    Ok(lower)
}

/// Validates and normalizes a general DNS domain name (allowing leading `*.` when `allow_wildcard == true`).
pub fn validate_general_domain_name(
    raw_domain: &str,
    allow_wildcard: bool,
) -> Result<String, RecordValidationError> {
    let trimmed = raw_domain.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return Err(RecordValidationError::InvalidDomain(
            "Domain name is required.".into(),
        ));
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.len() > 253 {
        return Err(RecordValidationError::InvalidDomain(
            "Domain name exceeds maximum length of 253 characters (RFC 1035).".into(),
        ));
    }
    let labels: Vec<&str> = lower.split('.').collect();
    for (idx, &label) in labels.iter().enumerate() {
        if label.is_empty() || label.len() > 63 {
            return Err(RecordValidationError::InvalidDomain(
                "Each domain label must be between 1 and 63 characters.".into(),
            ));
        }
        if idx == 0 && label == "*" {
            if !allow_wildcard || labels.len() < 2 {
                return Err(RecordValidationError::InvalidDomain(
                    "Wildcard '*' requires a parent domain and is only permitted where wildcards are supported.".into(),
                ));
            }
            continue;
        }
        validate_domain_label(label, true)?;
    }
    Ok(lower)
}

fn validate_domain_label(label: &str, allow_underscore: bool) -> Result<(), RecordValidationError> {
    let bytes = label.as_bytes();
    if bytes.first() == Some(&b'-') || bytes.last() == Some(&b'-') {
        return Err(RecordValidationError::InvalidDomain(format!(
            "Domain label '{label}' must not start or end with a hyphen."
        )));
    }
    for &b in bytes {
        let valid_char = b.is_ascii_lowercase()
            || b.is_ascii_digit()
            || b == b'-'
            || (allow_underscore && b == b'_');
        if !valid_char {
            return Err(RecordValidationError::InvalidDomain(format!(
                "Domain label '{label}' contains invalid characters."
            )));
        }
    }
    Ok(())
}

/// Validates a target hostname (allowing `"."` only when `allow_root_dot == true`) and returns normalized lowercase domain.
pub fn validate_target_hostname(
    raw_target: &str,
    field_name: &str,
    allow_root_dot: bool,
    allow_underscore: bool,
) -> Result<String, RecordValidationError> {
    let trimmed = raw_target.trim();
    if trimmed == "." {
        if allow_root_dot {
            return Ok(".".to_string());
        }
        return Err(RecordValidationError::InvalidRecordData(format!(
            "{field_name} cannot be the root '.' for this record type."
        )));
    }
    let clean = trimmed.trim_end_matches('.').to_ascii_lowercase();
    if clean.is_empty() || clean.len() > 253 {
        return Err(RecordValidationError::InvalidRecordData(format!(
            "{field_name} must be a valid domain name (1..=253 characters)."
        )));
    }
    if clean.parse::<IpAddr>().is_ok() {
        return Err(RecordValidationError::InvalidRecordData(format!(
            "{field_name} must be a hostname, not an IP address."
        )));
    }
    for label in clean.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(RecordValidationError::InvalidRecordData(format!(
                "{field_name} contains an empty or oversized label."
            )));
        }
        validate_domain_label(label, allow_underscore).map_err(|e| {
            RecordValidationError::InvalidRecordData(format!("{field_name}: {}", e.message()))
        })?;
    }
    Ok(clean)
}

/// Encodes a validated domain name into uncompressed DNS wire format (`[len, bytes..., 0]`).
pub fn encode_domain_wire(domain: &str, out: &mut Vec<u8>) -> Result<(), RecordValidationError> {
    let clean = domain.trim().trim_end_matches('.');
    if clean.is_empty() {
        out.push(0);
        return Ok(());
    }
    for label in clean.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(RecordValidationError::InvalidRecordData(
                "Invalid domain label length in RDATA.".into(),
            ));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

fn encode_character_string(
    text: &str,
    field_name: &str,
    out: &mut Vec<u8>,
) -> Result<(), RecordValidationError> {
    let bytes = text.as_bytes();
    if bytes.len() > 255 {
        return Err(RecordValidationError::InvalidRecordData(format!(
            "{field_name} exceeds 255 bytes."
        )));
    }
    out.push(bytes.len() as u8);
    out.extend_from_slice(bytes);
    Ok(())
}

fn decode_hex_strict(
    raw_hex: &str,
    field_name: &str,
    expected_byte_len: Option<usize>,
) -> Result<Vec<u8>, RecordValidationError> {
    let cleaned: String = raw_hex.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() || !cleaned.len().is_multiple_of(2) {
        return Err(RecordValidationError::InvalidRecordData(format!(
            "{field_name} must be a non-empty, even-length hexadecimal string."
        )));
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let bytes = cleaned.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16).ok_or_else(|| {
            RecordValidationError::InvalidRecordData(format!(
                "{field_name} contains non-hexadecimal characters."
            ))
        })?;
        let lo = (bytes[i + 1] as char).to_digit(16).ok_or_else(|| {
            RecordValidationError::InvalidRecordData(format!(
                "{field_name} contains non-hexadecimal characters."
            ))
        })?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    if let Some(exp) = expected_byte_len {
        if out.len() != exp {
            return Err(RecordValidationError::InvalidRecordData(format!(
                "{field_name} must be exactly {} bytes ({} hex characters) for the selected hash type.",
                exp,
                exp * 2
            )));
        }
    }
    Ok(out)
}

/// Validates and encodes RFC 9460 `SvcParams` (`mandatory`, `alpn`, `no-default-alpn`, `port`, `ipv4hint`, `ech`, `ipv6hint`)
/// in strictly ascending SvcParamKey order.
fn encode_rfc9460_svc_params(
    priority: u16,
    target: &str,
    raw_params: &str,
    out: &mut Vec<u8>,
) -> Result<(), RecordValidationError> {
    let trimmed = raw_params.trim();
    if priority == 0 {
        if target == "." {
            return Err(RecordValidationError::InvalidRecordData(
                "AliasMode (priority 0) HTTPS/SVCB record cannot have '.' as target (RFC 9460 §2.4.2)."
                    .into(),
            ));
        }
        if !trimmed.is_empty() {
            return Err(RecordValidationError::InvalidRecordData(
                "AliasMode (priority 0) HTTPS/SVCB record must not contain SvcParams (RFC 9460 §2.4.2)."
                    .into(),
            ));
        }
        return Ok(());
    }

    if trimmed.is_empty() {
        return Ok(());
    }

    let mut params_by_key: HashMap<u16, Vec<u8>> = HashMap::new();
    let mut mandatory_keys: Vec<u16> = Vec::new();

    for token in trimmed.split_whitespace() {
        if token == "no-default-alpn" {
            if params_by_key.insert(2, Vec::new()).is_some() {
                return Err(RecordValidationError::InvalidRecordData(
                    "Duplicate 'no-default-alpn' SvcParam.".into(),
                ));
            }
            continue;
        }
        let Some((k, v)) = token.split_once('=') else {
            return Err(RecordValidationError::InvalidRecordData(format!(
                "Invalid SvcParam token '{token}' (expected key=value or no-default-alpn)."
            )));
        };
        let v = v.trim_matches('"');
        match k {
            "mandatory" => {
                let mut keys = Vec::new();
                for name in v.split(',') {
                    let key_id = match name.trim() {
                        "alpn" => 1u16,
                        "no-default-alpn" => 2u16,
                        "port" => 3u16,
                        "ipv4hint" => 4u16,
                        "ech" => 5u16,
                        "ipv6hint" => 6u16,
                        other => {
                            return Err(RecordValidationError::InvalidRecordData(format!(
                                "Unknown mandatory SvcParam key '{other}'."
                            )))
                        }
                    };
                    if !keys.contains(&key_id) {
                        keys.push(key_id);
                    }
                }
                if keys.is_empty() {
                    return Err(RecordValidationError::InvalidRecordData(
                        "'mandatory' SvcParam cannot be empty.".into(),
                    ));
                }
                keys.sort_unstable();
                mandatory_keys.clone_from(&keys);
                let mut buf = Vec::with_capacity(keys.len() * 2);
                for kid in keys {
                    buf.extend_from_slice(&kid.to_be_bytes());
                }
                params_by_key.insert(0, buf);
            }
            "alpn" => {
                let mut buf = Vec::new();
                for proto in v.split(',') {
                    let p = proto.trim().as_bytes();
                    if p.is_empty() || p.len() > 255 {
                        return Err(RecordValidationError::InvalidRecordData(
                            "Invalid ALPN protocol ID in 'alpn' SvcParam.".into(),
                        ));
                    }
                    buf.push(p.len() as u8);
                    buf.extend_from_slice(p);
                }
                params_by_key.insert(1, buf);
            }
            "port" => {
                let port: u16 = v.parse().map_err(|_| {
                    RecordValidationError::InvalidRecordData(
                        "'port' SvcParam must be an integer 0..=65535.".into(),
                    )
                })?;
                params_by_key.insert(3, port.to_be_bytes().to_vec());
            }
            "ipv4hint" => {
                let mut buf = Vec::new();
                for ip_s in v.split(',') {
                    let v4: Ipv4Addr = ip_s.trim().parse().map_err(|_| {
                        RecordValidationError::InvalidRecordData(format!(
                            "Invalid IPv4 address '{ip_s}' in 'ipv4hint'."
                        ))
                    })?;
                    buf.extend_from_slice(&v4.octets());
                }
                params_by_key.insert(4, buf);
            }
            "ech" => {
                let decoded = BASE64_STANDARD.decode(v.trim()).map_err(|_| {
                    RecordValidationError::InvalidRecordData(
                        "'ech' SvcParam must be valid standard Base64.".into(),
                    )
                })?;
                if decoded.is_empty() {
                    return Err(RecordValidationError::InvalidRecordData(
                        "'ech' SvcParam cannot be empty.".into(),
                    ));
                }
                params_by_key.insert(5, decoded);
            }
            "ipv6hint" => {
                let mut buf = Vec::new();
                for ip_s in v.split(',') {
                    let v6: Ipv6Addr = ip_s.trim().parse().map_err(|_| {
                        RecordValidationError::InvalidRecordData(format!(
                            "Invalid IPv6 address '{ip_s}' in 'ipv6hint'."
                        ))
                    })?;
                    buf.extend_from_slice(&v6.octets());
                }
                params_by_key.insert(6, buf);
            }
            other => {
                return Err(RecordValidationError::InvalidRecordData(format!(
                    "Unsupported SvcParam key '{other}' (expected mandatory, alpn, no-default-alpn, port, ipv4hint, ech, or ipv6hint)."
                )));
            }
        }
    }

    for req_key in &mandatory_keys {
        if !params_by_key.contains_key(req_key) {
            return Err(RecordValidationError::InvalidRecordData(
                "Every SvcParam listed in 'mandatory' must also be present in SvcParams (RFC 9460 §8)."
                    .into(),
            ));
        }
    }
    if params_by_key.contains_key(&2) && !params_by_key.contains_key(&1) {
        return Err(RecordValidationError::InvalidRecordData(
            "'no-default-alpn' requires an explicit 'alpn=...' SvcParam (RFC 9460 §7.1.2).".into(),
        ));
    }

    let mut sorted_keys: Vec<u16> = params_by_key.keys().copied().collect();
    sorted_keys.sort_unstable();
    for key in sorted_keys {
        if let Some(val) = params_by_key.get(&key) {
            out.extend_from_slice(&key.to_be_bytes());
            out.extend_from_slice(&(val.len() as u16).to_be_bytes());
            out.extend_from_slice(val);
        }
    }
    Ok(())
}

/// Parses an RFC 1876 `LOC` presentation string (e.g. `37 46 30.000 N 122 25 09.840 W 10.00m 1.00m 10000.00m 10.00m`)
/// into the 16-byte binary `LOC` RDATA format.
fn encode_rfc1876_loc(coords: &str) -> Result<Vec<u8>, RecordValidationError> {
    let tokens: Vec<&str> = coords.split_whitespace().collect();
    let mut idx = 0usize;

    let parse_dms = |tokens: &[&str],
                     idx: &mut usize,
                     pos_hem: char,
                     neg_hem: char,
                     max_deg: u32|
     -> Result<u32, RecordValidationError> {
        let deg_str = *tokens.get(*idx).ok_or_else(|| {
            RecordValidationError::InvalidRecordData(
                "Incomplete LOC coordinates (expected 'd [m [s]] N|S d [m [s]] E|W altm').".into(),
            )
        })?;
        let deg: u32 = deg_str.parse().map_err(|_| {
            RecordValidationError::InvalidRecordData(format!("Invalid LOC degrees '{deg_str}'."))
        })?;
        if deg > max_deg {
            return Err(RecordValidationError::InvalidRecordData(format!(
                "LOC degrees {deg} exceeds maximum {max_deg}."
            )));
        }
        *idx += 1;

        let mut mins: u32 = 0;
        let mut secs_millis: u32 = 0;

        if let Some(&next) = tokens.get(*idx) {
            if !next.eq_ignore_ascii_case(&pos_hem.to_string())
                && !next.eq_ignore_ascii_case(&neg_hem.to_string())
            {
                mins = next.parse().map_err(|_| {
                    RecordValidationError::InvalidRecordData(format!(
                        "Invalid LOC minutes '{next}'."
                    ))
                })?;
                if mins > 59 {
                    return Err(RecordValidationError::InvalidRecordData(
                        "LOC minutes must be 0..=59.".into(),
                    ));
                }
                *idx += 1;
            }
        }

        if let Some(&next) = tokens.get(*idx) {
            if !next.eq_ignore_ascii_case(&pos_hem.to_string())
                && !next.eq_ignore_ascii_case(&neg_hem.to_string())
            {
                let secs_f: f64 = next.parse().map_err(|_| {
                    RecordValidationError::InvalidRecordData(format!(
                        "Invalid LOC seconds '{next}'."
                    ))
                })?;
                if !(0.0..60.0).contains(&secs_f) {
                    return Err(RecordValidationError::InvalidRecordData(
                        "LOC seconds must be between 0 and 59.999.".into(),
                    ));
                }
                secs_millis = (secs_f * 1000.0).round() as u32;
                *idx += 1;
            }
        }

        let hem = *tokens.get(*idx).ok_or_else(|| {
            RecordValidationError::InvalidRecordData("Missing LOC hemisphere (N/S/E/W).".into())
        })?;
        *idx += 1;

        let total_millis = deg * 3_600_000 + mins * 60_000 + secs_millis;
        let equator = 1u32 << 31;
        if hem.eq_ignore_ascii_case(&pos_hem.to_string()) {
            Ok(equator.saturating_add(total_millis))
        } else if hem.eq_ignore_ascii_case(&neg_hem.to_string()) {
            Ok(equator.saturating_sub(total_millis))
        } else {
            Err(RecordValidationError::InvalidRecordData(format!(
                "Invalid LOC hemisphere '{hem}' (expected {pos_hem} or {neg_hem})."
            )))
        }
    };

    let lat = parse_dms(&tokens, &mut idx, 'N', 'S', 90)?;
    let lon = parse_dms(&tokens, &mut idx, 'E', 'W', 180)?;

    let alt_str = tokens
        .get(idx)
        .ok_or_else(|| RecordValidationError::InvalidRecordData("Missing LOC altitude.".into()))?
        .trim_end_matches(['m', 'M']);
    let alt_meters: f64 = alt_str.parse().map_err(|_| {
        RecordValidationError::InvalidRecordData(format!("Invalid LOC altitude '{alt_str}'."))
    })?;
    let alt_cm = ((alt_meters + 100_000.0) * 100.0).round();
    if !(0.0..=(u32::MAX as f64)).contains(&alt_cm) {
        return Err(RecordValidationError::InvalidRecordData(
            "LOC altitude out of RFC 1876 range.".into(),
        ));
    }
    let alt_u32 = alt_cm as u32;
    idx += 1;

    let encode_precision = |raw: &str, label: &str| -> Result<u8, RecordValidationError> {
        let num_str = raw.trim().trim_end_matches(['m', 'M']);
        let meters: f64 = num_str.parse().map_err(|_| {
            RecordValidationError::InvalidRecordData(format!("Invalid LOC {label} '{raw}'."))
        })?;
        if !(0.0..=90_000_000.0).contains(&meters) {
            return Err(RecordValidationError::InvalidRecordData(format!(
                "LOC {label} '{raw}' is out of RFC 1876 range (0m..=90000000m)."
            )));
        }
        let mut cm = (meters * 100.0).round() as u64;
        if cm == 0 {
            return Ok(0);
        }
        let mut exp: u8 = 0;
        while cm >= 10 && exp < 9 {
            cm /= 10;
            exp += 1;
        }
        let mantissa = (cm.min(9)) as u8;
        Ok((mantissa << 4) | exp)
    };

    let size_byte = match tokens.get(idx) {
        Some(&s) => {
            idx += 1;
            encode_precision(s, "size")?
        }
        None => 0x12, // default 1m
    };
    let horiz_byte = match tokens.get(idx) {
        Some(&s) => {
            idx += 1;
            encode_precision(s, "horizontal precision")?
        }
        None => 0x16, // default 10000m
    };
    let vert_byte = match tokens.get(idx) {
        Some(&s) => {
            idx += 1;
            encode_precision(s, "vertical precision")?
        }
        None => 0x13, // default 10m
    };
    if idx < tokens.len() {
        return Err(RecordValidationError::InvalidRecordData(
            "Unexpected trailing tokens in LOC coordinates.".into(),
        ));
    }

    let mut out = Vec::with_capacity(16);
    out.push(0); // version = 0
    out.push(size_byte);
    out.push(horiz_byte);
    out.push(vert_byte);
    out.extend_from_slice(&lat.to_be_bytes());
    out.extend_from_slice(&lon.to_be_bytes());
    out.extend_from_slice(&alt_u32.to_be_bytes());
    Ok(out)
}

impl DnsZone {
    /// Validates the `DnsZone` configuration and compiles its wire-format `SOA` and `NS` RDATA.
    pub fn validate_and_compile(&self) -> Result<CompiledDnsZone, RecordValidationError> {
        if self.id.trim().is_empty() || self.id.len() > 64 {
            return Err(RecordValidationError::InvalidRecordData(
                "Zone ID must be between 1 and 64 characters.".into(),
            ));
        }
        if !(MIN_LOCAL_RECORD_TTL..=MAX_LOCAL_RECORD_TTL).contains(&self.default_ttl) {
            return Err(RecordValidationError::InvalidTtl(format!(
                "Zone default TTL must be between {MIN_LOCAL_RECORD_TTL} and {MAX_LOCAL_RECORD_TTL} seconds."
            )));
        }
        if self.comment.len() > 256 {
            return Err(RecordValidationError::InvalidRecordData(
                "Zone comment must not exceed 256 characters.".into(),
            ));
        }
        let norm_domain = validate_general_domain_name(&self.domain, false)?;
        let norm_mname = validate_target_hostname(&self.mname, "Zone SOA primary NS", false, false)?;
        let norm_rname =
            validate_target_hostname(&self.rname, "Zone SOA admin mailbox", false, true)?;
        if self.refresh == 0 || self.retry == 0 || self.expire == 0 || self.minimum == 0 {
            return Err(RecordValidationError::InvalidRecordData(
                "Zone SOA timers (refresh, retry, expire, minimum) must be > 0.".into(),
            ));
        }

        let mut soa_rdata = Vec::with_capacity(64);
        encode_domain_wire(&norm_mname, &mut soa_rdata)?;
        encode_domain_wire(&norm_rname, &mut soa_rdata)?;
        soa_rdata.extend_from_slice(&self.serial.to_be_bytes());
        soa_rdata.extend_from_slice(&self.refresh.to_be_bytes());
        soa_rdata.extend_from_slice(&self.retry.to_be_bytes());
        soa_rdata.extend_from_slice(&self.expire.to_be_bytes());
        soa_rdata.extend_from_slice(&self.minimum.to_be_bytes());

        let mut ns_rdata = Vec::with_capacity(32);
        encode_domain_wire(&norm_mname, &mut ns_rdata)?;

        let mut normalized_zone = self.clone();
        normalized_zone.domain = norm_domain;
        normalized_zone.mname = norm_mname;
        normalized_zone.rname = norm_rname;

        Ok(CompiledDnsZone {
            zone: normalized_zone,
            soa_rdata,
            ns_rdata,
        })
    }
}

/// Expands a relative record owner name (`@`, `api`, `*.app`, or an IP for `PTR`) against `zone_domain`
/// and verifies that the resulting canonical domain belongs to `zone_domain`.
pub fn resolve_record_owner_in_zone(
    raw_domain: &str,
    zone_domain: &str,
    data: &LocalRecordData,
) -> Result<String, RecordValidationError> {
    let clean_zone = validate_general_domain_name(zone_domain, false)?;
    let trimmed = raw_domain.trim().trim_end_matches('.');

    // Expand `@` or empty owner to zone apex
    let expanded = if trimmed.is_empty() || trimmed == "@" {
        clean_zone.clone()
    } else if matches!(data, LocalRecordData::PTR { .. }) && trimmed.parse::<IpAddr>().is_ok() {
        trimmed.to_string()
    } else {
        let lower = trimmed.to_ascii_lowercase();
        let zone_suffix = format!(".{clean_zone}");
        if lower == clean_zone || lower.ends_with(&zone_suffix) {
            lower
        } else {
            format!("{lower}.{clean_zone}")
        }
    };

    let norm = validate_and_normalize_owner_domain(&expanded, data)?;
    let zone_suffix = format!(".{clean_zone}");
    if norm != clean_zone && !norm.ends_with(&zone_suffix) {
        return Err(RecordValidationError::InvalidDomain(format!(
            "Record owner '{norm}' does not belong to zone '{clean_zone}'."
        )));
    }
    Ok(norm)
}

impl LocalDnsRecord {
    /// Validates `self` (domain syntax, TTL bounds, type-specific fields) and compiles it into [`CompiledLocalRecord`].
    pub fn validate_and_compile(&self) -> Result<CompiledLocalRecord, RecordValidationError> {
        if !(MIN_LOCAL_RECORD_TTL..=MAX_LOCAL_RECORD_TTL).contains(&self.ttl) {
            return Err(RecordValidationError::InvalidTtl(format!(
                "TTL must be between {MIN_LOCAL_RECORD_TTL} and {MAX_LOCAL_RECORD_TTL} seconds."
            )));
        }
        if self.comment.len() > 256 {
            return Err(RecordValidationError::InvalidRecordData(
                "Comment must not exceed 256 characters.".into(),
            ));
        }

        let norm_domain = validate_and_normalize_owner_domain(&self.domain, &self.data)?;
        let rr_type = self.data.rr_type_code();
        let mut rdata = Vec::new();
        let mut cname_target = None;
        let mut dname_target = None;
        let mut glue_target = None;
        let mut auto_ptr_reverse = None;

        match &self.data {
            LocalRecordData::A { ip, auto_ptr } => {
                let v4: Ipv4Addr = ip.trim().parse().map_err(|_| {
                    RecordValidationError::InvalidRecordData(format!(
                        "'{ip}' is not a valid IPv4 address."
                    ))
                })?;
                rdata.extend_from_slice(&v4.octets());
                if *auto_ptr && !norm_domain.starts_with("*.") {
                    let mut ptr_rdata = Vec::new();
                    encode_domain_wire(&norm_domain, &mut ptr_rdata)?;
                    auto_ptr_reverse = Some((reverse_ptr_name(IpAddr::V4(v4)), ptr_rdata));
                }
            }
            LocalRecordData::AAAA { ip, auto_ptr } => {
                let v6: Ipv6Addr = ip.trim().parse().map_err(|_| {
                    RecordValidationError::InvalidRecordData(format!(
                        "'{ip}' is not a valid IPv6 address."
                    ))
                })?;
                rdata.extend_from_slice(&v6.octets());
                if *auto_ptr && !norm_domain.starts_with("*.") {
                    let mut ptr_rdata = Vec::new();
                    encode_domain_wire(&norm_domain, &mut ptr_rdata)?;
                    auto_ptr_reverse = Some((reverse_ptr_name(IpAddr::V6(v6)), ptr_rdata));
                }
            }
            LocalRecordData::CNAME { target } => {
                let norm_target = validate_target_hostname(target, "CNAME target", false, true)?;
                if norm_target == norm_domain {
                    return Err(RecordValidationError::CnameLoop(
                        "CNAME record cannot point to its own owner domain.".into(),
                    ));
                }
                encode_domain_wire(&norm_target, &mut rdata)?;
                cname_target = Some(norm_target);
            }
            LocalRecordData::DNAME { target } => {
                let norm_target = validate_target_hostname(target, "DNAME target", false, true)?;
                if norm_target == norm_domain
                    || norm_target.ends_with(&format!(".{norm_domain}"))
                {
                    return Err(RecordValidationError::CnameLoop(
                        "DNAME record cannot redirect to itself or a subdomain of itself.".into(),
                    ));
                }
                encode_domain_wire(&norm_target, &mut rdata)?;
                dname_target = Some(norm_target);
            }
            LocalRecordData::MX { priority, target } => {
                let allow_null_mx = *priority == 0;
                let norm_target =
                    validate_target_hostname(target, "MX mail server", allow_null_mx, false)?;
                rdata.extend_from_slice(&priority.to_be_bytes());
                encode_domain_wire(&norm_target, &mut rdata)?;
                if norm_target != "." {
                    glue_target = Some(norm_target);
                }
            }
            LocalRecordData::TXT { content } | LocalRecordData::SPF { content } => {
                let bytes = content.as_bytes();
                if bytes.is_empty() || bytes.len() > 4096 {
                    return Err(RecordValidationError::InvalidRecordData(
                        "TXT/SPF content must be between 1 and 4096 bytes.".into(),
                    ));
                }
                // RFC 1035 §3.3.14: Split strings > 255 bytes into 255-byte <character-string> chunks
                for chunk in bytes.chunks(255) {
                    rdata.push(chunk.len() as u8);
                    rdata.extend_from_slice(chunk);
                }
            }
            LocalRecordData::SRV {
                priority,
                weight,
                port,
                target,
            } => {
                let norm_target = validate_target_hostname(target, "SRV target", true, true)?;
                rdata.extend_from_slice(&priority.to_be_bytes());
                rdata.extend_from_slice(&weight.to_be_bytes());
                rdata.extend_from_slice(&port.to_be_bytes());
                encode_domain_wire(&norm_target, &mut rdata)?;
                if norm_target != "." {
                    glue_target = Some(norm_target);
                }
            }
            LocalRecordData::CAA { flags, tag, value } => {
                let clean_tag = tag.trim().to_ascii_lowercase();
                if clean_tag.is_empty()
                    || clean_tag.len() > 15
                    || !clean_tag
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                {
                    return Err(RecordValidationError::InvalidRecordData(
                        "CAA tag must be 1..=15 lowercase alphanumeric characters (e.g. issue, issuewild, iodef)."
                            .into(),
                    ));
                }
                let clean_val = value.trim();
                if clean_val.is_empty() || clean_val.len() > 512 {
                    return Err(RecordValidationError::InvalidRecordData(
                        "CAA value must be between 1 and 512 characters.".into(),
                    ));
                }
                rdata.push(*flags);
                rdata.push(clean_tag.len() as u8);
                rdata.extend_from_slice(clean_tag.as_bytes());
                rdata.extend_from_slice(clean_val.as_bytes());
            }
            LocalRecordData::HTTPS {
                priority,
                target,
                svc_params,
            }
            | LocalRecordData::SVCB {
                priority,
                target,
                svc_params,
            } => {
                let norm_target =
                    validate_target_hostname(target, "HTTPS/SVCB target", true, true)?;
                rdata.extend_from_slice(&priority.to_be_bytes());
                encode_domain_wire(&norm_target, &mut rdata)?;
                encode_rfc9460_svc_params(*priority, &norm_target, svc_params, &mut rdata)?;
                if norm_target != "." {
                    glue_target = Some(norm_target);
                }
            }
            LocalRecordData::NS { target } => {
                let norm_target =
                    validate_target_hostname(target, "Nameserver target", false, false)?;
                encode_domain_wire(&norm_target, &mut rdata)?;
                glue_target = Some(norm_target);
            }
            LocalRecordData::PTR { target } => {
                let norm_target = validate_target_hostname(target, "PTR target", false, true)?;
                encode_domain_wire(&norm_target, &mut rdata)?;
            }
            LocalRecordData::SOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                let norm_mname = validate_target_hostname(mname, "SOA primary NS", false, false)?;
                let norm_rname =
                    validate_target_hostname(rname, "SOA admin mailbox", false, true)?;
                encode_domain_wire(&norm_mname, &mut rdata)?;
                encode_domain_wire(&norm_rname, &mut rdata)?;
                rdata.extend_from_slice(&serial.to_be_bytes());
                rdata.extend_from_slice(&refresh.to_be_bytes());
                rdata.extend_from_slice(&retry.to_be_bytes());
                rdata.extend_from_slice(&expire.to_be_bytes());
                rdata.extend_from_slice(&minimum.to_be_bytes());
            }
            LocalRecordData::TLSA {
                usage,
                selector,
                matching_type,
                cert_data,
            }
            | LocalRecordData::SMIMEA {
                usage,
                selector,
                matching_type,
                cert_data,
            } => {
                if *usage > 3 {
                    return Err(RecordValidationError::InvalidRecordData(
                        "TLSA/SMIMEA usage must be 0..=3.".into(),
                    ));
                }
                if *selector > 1 {
                    return Err(RecordValidationError::InvalidRecordData(
                        "TLSA/SMIMEA selector must be 0 or 1.".into(),
                    ));
                }
                let expected_len = match *matching_type {
                    0 => None,
                    1 => Some(32),
                    2 => Some(64),
                    _ => {
                        return Err(RecordValidationError::InvalidRecordData(
                            "TLSA/SMIMEA matching_type must be 0 (Exact), 1 (SHA-256), or 2 (SHA-512)."
                                .into(),
                        ))
                    }
                };
                let cert_bytes =
                    decode_hex_strict(cert_data, "Certificate association data", expected_len)?;
                rdata.push(*usage);
                rdata.push(*selector);
                rdata.push(*matching_type);
                rdata.extend_from_slice(&cert_bytes);
            }
            LocalRecordData::SSHFP {
                algorithm,
                fp_type,
                fingerprint,
            } => {
                if !matches!(*algorithm, 1 | 2 | 3 | 4 | 6) {
                    return Err(RecordValidationError::InvalidRecordData(
                        "SSHFP algorithm must be 1 (RSA), 2 (DSA), 3 (ECDSA), 4 (Ed25519), or 6 (Ed448)."
                            .into(),
                    ));
                }
                let expected_len = match *fp_type {
                    1 => Some(20),
                    2 => Some(32),
                    _ => {
                        return Err(RecordValidationError::InvalidRecordData(
                            "SSHFP fp_type must be 1 (SHA-1) or 2 (SHA-256).".into(),
                        ))
                    }
                };
                let fp_bytes = decode_hex_strict(fingerprint, "SSHFP fingerprint", expected_len)?;
                rdata.push(*algorithm);
                rdata.push(*fp_type);
                rdata.extend_from_slice(&fp_bytes);
            }
            LocalRecordData::DS {
                key_tag,
                algorithm,
                digest_type,
                digest,
            }
            | LocalRecordData::CDS {
                key_tag,
                algorithm,
                digest_type,
                digest,
            } => {
                if *algorithm == 0 {
                    return Err(RecordValidationError::InvalidRecordData(
                        "DS/CDS algorithm must be between 1 and 255.".into(),
                    ));
                }
                let expected_len = match *digest_type {
                    1 => Some(20),
                    2 => Some(32),
                    4 => Some(48),
                    _ => {
                        return Err(RecordValidationError::InvalidRecordData(
                            "DS/CDS digest_type must be 1 (SHA-1), 2 (SHA-256), or 4 (SHA-384)."
                                .into(),
                        ))
                    }
                };
                let digest_bytes = decode_hex_strict(digest, "DS/CDS digest", expected_len)?;
                rdata.extend_from_slice(&key_tag.to_be_bytes());
                rdata.push(*algorithm);
                rdata.push(*digest_type);
                rdata.extend_from_slice(&digest_bytes);
            }
            LocalRecordData::DNSKEY {
                flags,
                protocol,
                algorithm,
                public_key,
            }
            | LocalRecordData::CDNSKEY {
                flags,
                protocol,
                algorithm,
                public_key,
            } => {
                if *protocol != 3 {
                    return Err(RecordValidationError::InvalidRecordData(
                        "DNSKEY/CDNSKEY protocol must be 3 (RFC 4034 §2.1.2).".into(),
                    ));
                }
                if *algorithm == 0 {
                    return Err(RecordValidationError::InvalidRecordData(
                        "DNSKEY/CDNSKEY algorithm must be between 1 and 255.".into(),
                    ));
                }
                let key_bytes = BASE64_STANDARD.decode(public_key.trim()).map_err(|_| {
                    RecordValidationError::InvalidRecordData(
                        "DNSKEY/CDNSKEY public_key must be valid Base64.".into(),
                    )
                })?;
                if key_bytes.is_empty() {
                    return Err(RecordValidationError::InvalidRecordData(
                        "DNSKEY/CDNSKEY public_key cannot be empty.".into(),
                    ));
                }
                rdata.extend_from_slice(&flags.to_be_bytes());
                rdata.push(*protocol);
                rdata.push(*algorithm);
                rdata.extend_from_slice(&key_bytes);
            }
            LocalRecordData::NAPTR {
                order,
                preference,
                flags,
                service,
                regexp,
                replacement,
            } => {
                let clean_flags = flags.trim();
                if !clean_flags
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric())
                {
                    return Err(RecordValidationError::InvalidRecordData(
                        "NAPTR flags must be alphanumeric (e.g. 'S', 'A', 'U', 'P', or empty)."
                            .into(),
                    ));
                }
                let norm_rep =
                    validate_target_hostname(replacement, "NAPTR replacement", true, true)?;
                rdata.extend_from_slice(&order.to_be_bytes());
                rdata.extend_from_slice(&preference.to_be_bytes());
                encode_character_string(clean_flags, "NAPTR flags", &mut rdata)?;
                encode_character_string(service.trim(), "NAPTR service", &mut rdata)?;
                encode_character_string(regexp.trim(), "NAPTR regexp", &mut rdata)?;
                encode_domain_wire(&norm_rep, &mut rdata)?;
            }
            LocalRecordData::URI {
                priority,
                weight,
                target,
            } => {
                let clean_uri = target.trim();
                if clean_uri.is_empty() || clean_uri.len() > 2048 || !clean_uri.contains(':') {
                    return Err(RecordValidationError::InvalidRecordData(
                        "URI target must be a valid RFC 3986 URI (1..=2048 bytes).".into(),
                    ));
                }
                rdata.extend_from_slice(&priority.to_be_bytes());
                rdata.extend_from_slice(&weight.to_be_bytes());
                rdata.extend_from_slice(clean_uri.as_bytes());
            }
            LocalRecordData::HINFO { cpu, os } => {
                if cpu.trim().is_empty() || os.trim().is_empty() {
                    return Err(RecordValidationError::InvalidRecordData(
                        "HINFO CPU and OS strings are required.".into(),
                    ));
                }
                encode_character_string(cpu.trim(), "HINFO CPU", &mut rdata)?;
                encode_character_string(os.trim(), "HINFO OS", &mut rdata)?;
            }
            LocalRecordData::RP { mbox, txt } => {
                let norm_mbox = validate_target_hostname(mbox, "RP mailbox domain", true, true)?;
                let norm_txt = validate_target_hostname(txt, "RP TXT domain", true, true)?;
                encode_domain_wire(&norm_mbox, &mut rdata)?;
                encode_domain_wire(&norm_txt, &mut rdata)?;
            }
            LocalRecordData::LOC { coordinates } => {
                rdata = encode_rfc1876_loc(coordinates)?;
            }
            LocalRecordData::CERT {
                cert_type,
                key_tag,
                algorithm,
                cert_data,
            } => {
                if *cert_type == 0 {
                    return Err(RecordValidationError::InvalidRecordData(
                        "CERT cert_type must be > 0.".into(),
                    ));
                }
                let cert_bytes = BASE64_STANDARD.decode(cert_data.trim()).map_err(|_| {
                    RecordValidationError::InvalidRecordData(
                        "CERT cert_data must be valid Base64.".into(),
                    )
                })?;
                if cert_bytes.is_empty() {
                    return Err(RecordValidationError::InvalidRecordData(
                        "CERT cert_data cannot be empty.".into(),
                    ));
                }
                rdata.extend_from_slice(&cert_type.to_be_bytes());
                rdata.extend_from_slice(&key_tag.to_be_bytes());
                rdata.push(*algorithm);
                rdata.extend_from_slice(&cert_bytes);
            }
            LocalRecordData::OPENPGPKEY { public_key } => {
                let key_bytes = BASE64_STANDARD.decode(public_key.trim()).map_err(|_| {
                    RecordValidationError::InvalidRecordData(
                        "OPENPGPKEY public_key must be valid Base64.".into(),
                    )
                })?;
                if key_bytes.is_empty() {
                    return Err(RecordValidationError::InvalidRecordData(
                        "OPENPGPKEY public_key cannot be empty.".into(),
                    ));
                }
                rdata.extend_from_slice(&key_bytes);
            }
            LocalRecordData::RAW { rr_type, rdata_hex } => {
                if matches!(
                    *rr_type,
                    0 | RR_TYPE_OPT | RR_TYPE_IXFR | RR_TYPE_AXFR | RR_TYPE_ANY
                ) {
                    return Err(RecordValidationError::InvalidRecordData(format!(
                        "RR type {rr_type} is a meta-query type and cannot be stored as a resource record."
                    )));
                }
                rdata = decode_hex_strict(rdata_hex, "RAW RDATA hex", None)?;
            }
        }

        Ok(CompiledLocalRecord {
            id: self.id.clone(),
            zone_id: self.zone_id.clone(),
            domain: norm_domain,
            rr_type,
            ttl: self.ttl,
            rdata,
            cname_target,
            dname_target,
            glue_target,
            auto_ptr_reverse,
        })
    }
}

/// Validates a candidate `LocalDnsRecord` against the existing set of records, enforcing:
/// 1. Field & wire-encoding validity.
/// 2. **CNAME Exclusivity** (RFC 1034 §3.6.2 / RFC 2181 §10.1): a CNAME cannot share an owner name with any other record.
/// 3. **DNAME Uniqueness** (RFC 6672): at most one DNAME record per owner name.
/// 4. **Duplicate Record Rejection**: no two records may have identical `(domain, rr_type, rdata)`.
/// 5. **CNAME Cycle Detection**: prevents multi-hop CNAME loops up to `MAX_CNAME_CHAIN_HOPS`.
pub fn validate_record_against_store(
    candidate: &LocalDnsRecord,
    existing: &[LocalDnsRecord],
) -> Result<CompiledLocalRecord, RecordValidationError> {
    let compiled = candidate.validate_and_compile()?;

    let mut cname_graph: HashMap<String, String> = HashMap::new();
    if let Some(ref target) = compiled.cname_target {
        cname_graph.insert(compiled.domain.clone(), target.clone());
    }

    for other in existing {
        if other.id == candidate.id {
            continue;
        }
        let Ok(other_compiled) = other.validate_and_compile() else {
            continue;
        };
        if let Some(ref t) = other_compiled.cname_target {
            cname_graph.insert(other_compiled.domain.clone(), t.clone());
        }

        if other_compiled.domain == compiled.domain {
            if compiled.rr_type == RR_TYPE_CNAME {
                return Err(RecordValidationError::CnameConflict(format!(
                    "CNAME record for '{}' conflicts with an existing {} record at the same name (RFC 2181 §10.1).",
                    compiled.domain,
                    other.data.type_name()
                )));
            }
            if other_compiled.rr_type == RR_TYPE_CNAME {
                return Err(RecordValidationError::CnameConflict(format!(
                    "Cannot add {} record for '{}' because a CNAME record already exists at that name (RFC 2181 §10.1).",
                    candidate.data.type_name(),
                    compiled.domain
                )));
            }
            if compiled.rr_type == RR_TYPE_DNAME && other_compiled.rr_type == RR_TYPE_DNAME {
                return Err(RecordValidationError::CnameConflict(format!(
                    "Only one DNAME record is permitted at '{}'.",
                    compiled.domain
                )));
            }
            if other_compiled.rr_type == compiled.rr_type && other_compiled.rdata == compiled.rdata
            {
                return Err(RecordValidationError::DuplicateRecord(format!(
                    "An identical {} record for '{}' already exists.",
                    candidate.data.type_name(),
                    compiled.domain
                )));
            }
        }
    }

    // Check CNAME cycles
    if compiled.rr_type == RR_TYPE_CNAME {
        let mut visited = HashSet::new();
        let mut cursor = compiled.domain.as_str();
        for _ in 0..=MAX_CNAME_CHAIN_HOPS {
            if !visited.insert(cursor.to_string()) {
                return Err(RecordValidationError::CnameLoop(format!(
                    "CNAME chain starting at '{}' creates a circular loop.",
                    compiled.domain
                )));
            }
            match cname_graph.get(cursor) {
                Some(next) => cursor = next.as_str(),
                None => break,
            }
        }
    }

    Ok(compiled)
}

/// Formats a canonical BIND zone-file line preview for a `LocalDnsRecord`.
pub fn format_bind_preview(record: &LocalDnsRecord) -> String {
    let mut out = String::new();
    let owner = record.domain.trim().trim_end_matches('.');
    let _ = write!(
        out,
        "{owner}. {} IN {} {}",
        record.ttl,
        record.data.type_name(),
        record.data.display_summary()
    );
    out
}

/// Exports a [`DnsZone`] and its associated [`LocalDnsRecord`]s to an RFC 1035 BIND zone file.
pub fn export_zone_to_bind(zone: &DnsZone, records: &[LocalDnsRecord]) -> String {
    let mut out = String::with_capacity(1024);
    let _ = writeln!(
        out,
        "; BIND Zone File exported by Daviante DoH for zone '{}.'",
        zone.domain
    );
    let _ = writeln!(out, "; Resolution Mode: {}", zone.mode.as_str());
    let _ = writeln!(out, "$ORIGIN {}.", zone.domain);
    let _ = writeln!(out, "$TTL {}", zone.default_ttl);
    let _ = writeln!(
        out,
        "@ {} IN SOA {}. {}. ({} {} {} {} {})",
        zone.default_ttl,
        zone.mname,
        zone.rname,
        zone.serial,
        zone.refresh,
        zone.retry,
        zone.expire,
        zone.minimum
    );
    let _ = writeln!(out, "@ {} IN NS {}.", zone.default_ttl, zone.mname);

    for rec in records {
        if !rec.enabled {
            out.push_str("; [DISABLED] ");
        }
        let _ = writeln!(out, "{}", format_bind_preview(rec));
    }
    out
}

/// Parses bulk BIND zone lines or `/etc/hosts` entries into candidate [`LocalDnsRecord`]s.
/// Supports `$ORIGIN`, `$TTL`, `@`, relative names, and standard RR types (`A`, `AAAA`, `CNAME`, `DNAME`, `MX`, `TXT`, `SPF`, `SRV`, `CAA`, `HTTPS`, `SVCB`, `NS`, `PTR`).
pub fn parse_bind_zone_text(
    zone: Option<&DnsZone>,
    fallback_ttl: u32,
    text: &str,
) -> Result<Vec<LocalDnsRecord>, RecordValidationError> {
    let mut origin = zone.map(|z| z.domain.clone());
    let mut current_ttl = zone.map(|z| z.default_ttl).unwrap_or(fallback_ttl);
    let zone_id = zone.map(|z| z.id.clone());
    let mut out = Vec::new();

    for (line_idx, raw_line) in text.lines().enumerate() {
        let line_no = line_idx + 1;
        let line = raw_line
            .split([';', '#'])
            .next()
            .unwrap_or("")
            .trim();
        if line.is_empty() {
            continue;
        }

        if let Some(rest) = line.strip_prefix("$ORIGIN") {
            let clean_orig = validate_general_domain_name(rest.trim(), false)?;
            origin = Some(clean_orig);
            continue;
        }
        if let Some(rest) = line.strip_prefix("$TTL") {
            let parsed_ttl: u32 = rest.trim().parse().map_err(|_| {
                RecordValidationError::InvalidTtl(format!("Line {line_no}: invalid $TTL value."))
            })?;
            current_ttl = parsed_ttl;
            continue;
        }

        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 2 {
            return Err(RecordValidationError::InvalidRecordData(format!(
                "Line {line_no}: incomplete record line '{line}'."
            )));
        }

        // Check if this is an `/etc/hosts` style line (`<IP> <host1> [host2...]`)
        if let Ok(ip) = tokens[0].parse::<IpAddr>() {
            let is_in = tokens
                .get(1)
                .is_some_and(|t| t.eq_ignore_ascii_case("IN") || t.parse::<u32>().is_ok());
            if !is_in {
                for &host_tok in &tokens[1..] {
                    let data = match ip {
                        IpAddr::V4(v4) => LocalRecordData::A {
                            ip: v4.to_string(),
                            auto_ptr: true,
                        },
                        IpAddr::V6(v6) => LocalRecordData::AAAA {
                            ip: v6.to_string(),
                            auto_ptr: true,
                        },
                    };
                    let domain = match origin.as_deref() {
                        Some(orig) => resolve_record_owner_in_zone(host_tok, orig, &data)?,
                        None => validate_and_normalize_owner_domain(host_tok, &data)?,
                    };
                    out.push(LocalDnsRecord {
                        id: format!("import-{line_no}-{}", out.len()),
                        zone_id: zone_id.clone(),
                        domain,
                        data,
                        ttl: current_ttl,
                        enabled: true,
                        comment: String::new(),
                        updated_at_epoch: 0,
                    });
                }
                continue;
            }
        }

        // Parse standard BIND record line: `<owner> [ttl] [IN] <TYPE> <rdata...>`
        let raw_owner = tokens[0];
        let mut cursor = 1usize;
        let mut rec_ttl = current_ttl;

        if let Some(&tok) = tokens.get(cursor) {
            if let Ok(t) = tok.parse::<u32>() {
                rec_ttl = t;
                cursor += 1;
            }
        }
        if let Some(&tok) = tokens.get(cursor) {
            if tok.eq_ignore_ascii_case("IN") {
                cursor += 1;
                if let Some(&next_tok) = tokens.get(cursor) {
                    if let Ok(t) = next_tok.parse::<u32>() {
                        rec_ttl = t;
                        cursor += 1;
                    }
                }
            }
        }

        let Some(&type_tok) = tokens.get(cursor) else {
            return Err(RecordValidationError::InvalidRecordData(format!(
                "Line {line_no}: missing record type in '{line}'."
            )));
        };
        cursor += 1;
        let rdata_tokens = &tokens[cursor..];
        if rdata_tokens.is_empty() {
            return Err(RecordValidationError::InvalidRecordData(format!(
                "Line {line_no}: missing RDATA for {} record.",
                type_tok
            )));
        }

        let rtype = type_tok.to_ascii_uppercase();
        // Skip zone-apex SOA if pasting an exported zone file
        if rtype == "SOA" && (raw_owner == "@" || origin.as_deref() == Some(raw_owner.trim_end_matches('.'))) {
            continue;
        }

        let data = match rtype.as_str() {
            "A" => LocalRecordData::A {
                ip: rdata_tokens[0].to_string(),
                auto_ptr: false,
            },
            "AAAA" => LocalRecordData::AAAA {
                ip: rdata_tokens[0].to_string(),
                auto_ptr: false,
            },
            "CNAME" => LocalRecordData::CNAME {
                target: rdata_tokens[0].trim_end_matches('.').to_string(),
            },
            "DNAME" => LocalRecordData::DNAME {
                target: rdata_tokens[0].trim_end_matches('.').to_string(),
            },
            "NS" => LocalRecordData::NS {
                target: rdata_tokens[0].trim_end_matches('.').to_string(),
            },
            "PTR" => LocalRecordData::PTR {
                target: rdata_tokens[0].trim_end_matches('.').to_string(),
            },
            "MX" => {
                if rdata_tokens.len() < 2 {
                    return Err(RecordValidationError::InvalidRecordData(format!(
                        "Line {line_no}: MX requires '<priority> <target>'."
                    )));
                }
                let prio: u16 = rdata_tokens[0].parse().map_err(|_| {
                    RecordValidationError::InvalidRecordData(format!(
                        "Line {line_no}: invalid MX priority."
                    ))
                })?;
                LocalRecordData::MX {
                    priority: prio,
                    target: rdata_tokens[1].trim_end_matches('.').to_string(),
                }
            }
            "TXT" => LocalRecordData::TXT {
                content: rdata_tokens.join(" ").trim_matches('"').to_string(),
            },
            "SPF" => LocalRecordData::SPF {
                content: rdata_tokens.join(" ").trim_matches('"').to_string(),
            },
            "SRV" => {
                if rdata_tokens.len() < 4 {
                    return Err(RecordValidationError::InvalidRecordData(format!(
                        "Line {line_no}: SRV requires '<priority> <weight> <port> <target>'."
                    )));
                }
                let priority: u16 = rdata_tokens[0].parse().map_err(|_| {
                    RecordValidationError::InvalidRecordData(format!(
                        "Line {line_no}: invalid SRV priority."
                    ))
                })?;
                let weight: u16 = rdata_tokens[1].parse().map_err(|_| {
                    RecordValidationError::InvalidRecordData(format!(
                        "Line {line_no}: invalid SRV weight."
                    ))
                })?;
                let port: u16 = rdata_tokens[2].parse().map_err(|_| {
                    RecordValidationError::InvalidRecordData(format!(
                        "Line {line_no}: invalid SRV port."
                    ))
                })?;
                LocalRecordData::SRV {
                    priority,
                    weight,
                    port,
                    target: rdata_tokens[3].trim_end_matches('.').to_string(),
                }
            }
            "CAA" => {
                if rdata_tokens.len() < 3 {
                    return Err(RecordValidationError::InvalidRecordData(format!(
                        "Line {line_no}: CAA requires '<flags> <tag> <value>'."
                    )));
                }
                let flags: u8 = rdata_tokens[0].parse().map_err(|_| {
                    RecordValidationError::InvalidRecordData(format!(
                        "Line {line_no}: invalid CAA flags."
                    ))
                })?;
                LocalRecordData::CAA {
                    flags,
                    tag: rdata_tokens[1].to_string(),
                    value: rdata_tokens[2..].join(" ").trim_matches('"').to_string(),
                }
            }
            "HTTPS" | "SVCB" => {
                if rdata_tokens.len() < 2 {
                    return Err(RecordValidationError::InvalidRecordData(format!(
                        "Line {line_no}: {rtype} requires '<priority> <target> [svc_params...]'."
                    )));
                }
                let priority: u16 = rdata_tokens[0].parse().map_err(|_| {
                    RecordValidationError::InvalidRecordData(format!(
                        "Line {line_no}: invalid {rtype} priority."
                    ))
                })?;
                let target = if rdata_tokens[1] == "." {
                    ".".to_string()
                } else {
                    rdata_tokens[1].trim_end_matches('.').to_string()
                };
                let svc_params = rdata_tokens[2..].join(" ");
                if rtype == "HTTPS" {
                    LocalRecordData::HTTPS {
                        priority,
                        target,
                        svc_params,
                    }
                } else {
                    LocalRecordData::SVCB {
                        priority,
                        target,
                        svc_params,
                    }
                }
            }
            other => {
                return Err(RecordValidationError::InvalidRecordData(format!(
                    "Line {line_no}: unsupported BIND bulk import record type '{other}'."
                )))
            }
        };

        let domain = match origin.as_deref() {
            Some(orig) => resolve_record_owner_in_zone(raw_owner, orig, &data)?,
            None => validate_and_normalize_owner_domain(raw_owner, &data)?,
        };

        let candidate = LocalDnsRecord {
            id: format!("import-{line_no}-{}", out.len()),
            zone_id: zone_id.clone(),
            domain,
            data,
            ttl: rec_ttl,
            enabled: true,
            comment: String::new(),
            updated_at_epoch: 0,
        };
        let _ = candidate.validate_and_compile()?;
        out.push(candidate);
    }

    if out.is_empty() {
        return Err(RecordValidationError::InvalidRecordData(
            "No valid DNS records were found in the import input.".into(),
        ));
    }
    Ok(out)
}
