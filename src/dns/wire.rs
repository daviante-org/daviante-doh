//! Clean-room DNS wire-format inspection, validation, TTL management, and RFC 8914 EDE synthesis
//! (RFC 1035, RFC 2308, RFC 5452, RFC 6891, RFC 7830, RFC 8467, RFC 8482, RFC 8484, RFC 8914).

use std::fmt::Write as _;

use crate::error::DohError;

/// Fixed 12-byte DNS header length (RFC 1035 §4.1.1).
pub const DNS_HEADER_LEN: usize = 12;
/// Minimum valid DNS query length (12-byte header + 1-byte root name + 4-byte QTYPE/QCLASS).
pub const MIN_DNS_PACKET_LEN: usize = 17;
/// Maximum DNS message size supported over DoH and TCP (RFC 8484 §6).
pub const MAX_DNS_MESSAGE_LEN: usize = 65_535;
/// Alias for backward compatibility with callers referencing `MAX_DNS_PACKET_LEN`.
pub const MAX_DNS_PACKET_LEN: usize = MAX_DNS_MESSAGE_LEN;
/// Safe EDNS0 UDP payload size advertised to upstream resolvers (DNS Flag Day 2020).
pub const UPSTREAM_EDNS_UDP_SIZE: u16 = 1232;
/// Maximum raw DNS query message accepted from a client (4096 bytes).
pub const MAX_DNS_QUERY_LEN: usize = 4096;
/// RFC 8467 §4.1 recommended EDNS0 response padding block multiple (468 octets).
pub const RESPONSE_PADDING_BLOCK_SIZE: usize = 468;

/// Resource Record Type codes.
pub const RR_TYPE_A: u16 = 1;
pub const RR_TYPE_CNAME: u16 = 5;
pub const RR_TYPE_SOA: u16 = 6;
pub const RR_TYPE_AAAA: u16 = 28;
pub const RR_TYPE_DNAME: u16 = 39;
pub const RR_TYPE_OPT: u16 = 41;
pub const RR_TYPE_IXFR: u16 = 251;
pub const RR_TYPE_AXFR: u16 = 252;
pub const RR_TYPE_ANY: u16 = 255;

/// DNS CLASS codes.
pub const DNS_CLASS_IN: u16 = 1;

/// EDNS0 Option codes (RFC 7871, RFC 7830, RFC 8914).
pub const EDNS_OPT_CLIENT_SUBNET: u16 = 8;
pub const EDNS_OPT_PADDING: u16 = 12;
pub const EDNS_OPT_EDE: u16 = 15;

/// RFC 8914 Extended DNS Error (`INFO-CODE`) constants.
pub const EDE_BLOCKED: u16 = 15;
pub const EDE_CENSORED: u16 = 16;
pub const EDE_FILTERED: u16 = 17;
pub const EDE_PROHIBITED: u16 = 18;
pub const EDE_NOT_SUPPORTED: u16 = 21;
pub const EDE_NO_REACHABLE_AUTHORITY: u16 = 22;
pub const EDE_NETWORK_ERROR: u16 = 23;

/// DNS RCODE values (RFC 1035 §4.1.1).
pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_FORMERR: u8 = 1;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_NOTIMP: u8 = 4;
pub const RCODE_REFUSED: u8 = 5;

/// Parsed and validated metadata from an incoming DNS query packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedQuestion {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
    pub has_edns0: bool,
    pub has_padding: bool,
    pub has_client_ecs: bool,
    pub do_bit: bool,
    pub cd_bit: bool,
    pub question_end_offset: usize,
}

#[inline]
pub fn read_u16_be(buf: &[u8], offset: usize) -> Result<u16, DohError> {
    let slice = buf
        .get(offset..offset + 2)
        .ok_or(DohError::MalformedDnsPacket(
            "unexpected end of packet reading u16",
        ))?;
    Ok(u16::from_be_bytes([slice[0], slice[1]]))
}

#[inline]
pub fn read_u32_be(buf: &[u8], offset: usize) -> Result<u32, DohError> {
    let slice = buf
        .get(offset..offset + 4)
        .ok_or(DohError::MalformedDnsPacket(
            "unexpected end of packet reading u32",
        ))?;
    Ok(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

#[inline]
pub fn write_u16_be(buf: &mut [u8], offset: usize, val: u16) -> Result<(), DohError> {
    let slice = buf
        .get_mut(offset..offset + 2)
        .ok_or(DohError::MalformedDnsPacket(
            "unexpected end of packet writing u16",
        ))?;
    slice.copy_from_slice(&val.to_be_bytes());
    Ok(())
}

#[inline]
pub fn write_u32_be(buf: &mut [u8], offset: usize, val: u32) -> Result<(), DohError> {
    let slice = buf
        .get_mut(offset..offset + 4)
        .ok_or(DohError::MalformedDnsPacket(
            "unexpected end of packet writing u32",
        ))?;
    slice.copy_from_slice(&val.to_be_bytes());
    Ok(())
}

#[inline]
pub fn qdcount(packet: &[u8]) -> u16 {
    read_u16_be(packet, 4).unwrap_or(0)
}

#[inline]
pub fn ancount(packet: &[u8]) -> u16 {
    read_u16_be(packet, 6).unwrap_or(0)
}

#[inline]
pub fn nscount(packet: &[u8]) -> u16 {
    read_u16_be(packet, 8).unwrap_or(0)
}

#[inline]
pub fn arcount(packet: &[u8]) -> u16 {
    read_u16_be(packet, 10).unwrap_or(0)
}

#[inline]
pub fn rcode(packet: &[u8]) -> u8 {
    packet.get(3).map(|b| b & 0x0f).unwrap_or(RCODE_SERVFAIL)
}

#[inline]
pub fn is_truncated(packet: &[u8]) -> bool {
    packet.get(2).map(|b| (b & 0x02) != 0).unwrap_or(false)
}

#[inline]
pub fn is_response(packet: &[u8]) -> bool {
    packet.get(2).map(|b| (b & 0x80) != 0).unwrap_or(false)
}

#[inline]
pub fn is_recoverable_error(packet: &[u8]) -> bool {
    matches!(rcode(packet), RCODE_SERVFAIL | RCODE_REFUSED)
}

/// Validates an incoming DNS query packet against RFC 1035 §4.1.1 and RFC 8484 §4.1 rules,
/// and extracts normalized question and EDNS0 metadata (including client ECS and padding presence).
pub fn validate_and_parse_query(packet: &[u8]) -> Result<ParsedQuestion, DohError> {
    if packet.len() < MIN_DNS_PACKET_LEN {
        return Err(DohError::MalformedDnsPacket(
            "packet shorter than minimum DNS length",
        ));
    }
    if packet.len() > MAX_DNS_QUERY_LEN {
        return Err(DohError::PayloadTooLarge);
    }

    // RFC 1035 §4.1.1: QR bit (bit 7 of byte 2) MUST be 0 (Query), OPCODE (bits 3..6) MUST be 0 (QUERY)
    if (packet[2] & 0x80) != 0 {
        return Err(DohError::MalformedDnsPacket(
            "DNS packet has QR=1 (response packet sent as query)",
        ));
    }
    if (packet[2] & 0x78) != 0 {
        return Err(DohError::MalformedDnsPacket("unsupported DNS query OPCODE"));
    }

    // Standard DNS query must have QDCOUNT=1, ANCOUNT=0, NSCOUNT=0
    if qdcount(packet) != 1 || ancount(packet) != 0 || nscount(packet) != 0 {
        return Err(DohError::MalformedDnsPacket(
            "DNS query must have QDCOUNT=1, ANCOUNT=0, NSCOUNT=0",
        ));
    }

    let (raw_name, after_name) = decode_name(packet, DNS_HEADER_LEN)?;
    if after_name + 4 > packet.len() {
        return Err(DohError::MalformedDnsPacket(
            "truncated question QTYPE/QCLASS",
        ));
    }
    let qtype = read_u16_be(packet, after_name)?;
    let qclass = read_u16_be(packet, after_name + 2)?;
    let question_end_offset = after_name + 4;

    // Reject zone transfer and pseudo-RR query types
    if matches!(qtype, 0 | RR_TYPE_OPT | RR_TYPE_IXFR | RR_TYPE_AXFR) {
        return Err(DohError::MalformedDnsPacket(
            "disallowed meta/zone-transfer QTYPE",
        ));
    }

    let cd_bit = (packet[3] & 0x10) != 0;
    let mut has_edns0 = false;
    let mut has_padding = false;
    let mut has_client_ecs = false;
    let mut do_bit = false;

    let ar = arcount(packet);
    let mut offset = question_end_offset;
    for _ in 0..ar {
        offset = skip_name(packet, offset)?;
        if offset + 10 > packet.len() {
            return Err(DohError::MalformedDnsPacket("truncated additional record"));
        }
        let rr_type = read_u16_be(packet, offset)?;
        let edns_flags = read_u16_be(packet, offset + 6)?;
        let rdlen = read_u16_be(packet, offset + 8)? as usize;
        let rdata_start = offset + 10;
        let rdata_end = rdata_start + rdlen;
        if rdata_end > packet.len() {
            return Err(DohError::MalformedDnsPacket(
                "additional record RDATA out of bounds",
            ));
        }

        if rr_type == RR_TYPE_OPT {
            if has_edns0 {
                return Err(DohError::MalformedDnsPacket("duplicate EDNS0 OPT record"));
            }
            has_edns0 = true;
            do_bit = (edns_flags & 0x8000) != 0;
            let (ecs, pad) = parse_edns0_opt_flags(packet, rdata_start, rdata_end)?;
            has_client_ecs |= ecs;
            has_padding |= pad;
        }
        offset = rdata_end;
    }

    Ok(ParsedQuestion {
        qname: raw_name.trim_end_matches('.').to_ascii_lowercase(),
        qtype,
        qclass,
        has_edns0,
        has_padding,
        has_client_ecs,
        do_bit,
        cd_bit,
        question_end_offset,
    })
}

fn parse_edns0_opt_flags(
    packet: &[u8],
    rdata_start: usize,
    rdata_end: usize,
) -> Result<(bool, bool), DohError> {
    let mut has_client_ecs = false;
    let mut has_padding = false;
    let mut pos = rdata_start;
    while pos < rdata_end {
        if pos + 4 > rdata_end {
            return Err(DohError::MalformedDnsPacket("truncated EDNS0 option"));
        }
        let opt_code = read_u16_be(packet, pos)?;
        let opt_len = read_u16_be(packet, pos + 2)? as usize;
        pos += 4;
        if pos + opt_len > rdata_end {
            return Err(DohError::MalformedDnsPacket(
                "EDNS0 option length exceeds RDLENGTH",
            ));
        }
        match opt_code {
            EDNS_OPT_CLIENT_SUBNET => has_client_ecs = true,
            EDNS_OPT_PADDING => has_padding = true,
            _ => {}
        }
        pos += opt_len;
    }
    Ok((has_client_ecs, has_padding))
}

/// Verifies per RFC 5452 §9.1 that an upstream DNS response has `QR == 1`, `QDCOUNT == 1`,
/// and matches the expected `(qname_lower, qtype, qclass)` question tuple.
pub fn matches_response_question(
    response: &[u8],
    expected_qname_lower: &str,
    expected_qtype: u16,
    expected_qclass: u16,
) -> bool {
    if response.len() < MIN_DNS_PACKET_LEN || !is_response(response) || qdcount(response) != 1 {
        return false;
    }
    let Ok((raw_name, after_name)) = decode_name(response, DNS_HEADER_LEN) else {
        return false;
    };
    let Ok(qtype) = read_u16_be(response, after_name) else {
        return false;
    };
    let Ok(qclass) = read_u16_be(response, after_name + 2) else {
        return false;
    };
    raw_name
        .trim_end_matches('.')
        .eq_ignore_ascii_case(expected_qname_lower)
        && qtype == expected_qtype
        && qclass == expected_qclass
}

/// Rewrites the 2-byte Transaction ID and (when lengths match) the client's original Question
/// section bytes into `response` to preserve `0x20` bit-case encoding (L-7).
pub fn rewrite_question_from_client(
    response: &mut [u8],
    client_query: &[u8],
    question_end_offset: usize,
) {
    if response.len() >= 2 && client_query.len() >= 2 {
        response[0] = client_query[0];
        response[1] = client_query[1];
    }
    if let Ok(resp_q_end) = skip_questions(response) {
        if resp_q_end == question_end_offset
            && client_query.len() >= question_end_offset
            && response.len() >= question_end_offset
        {
            response[DNS_HEADER_LEN..question_end_offset]
                .copy_from_slice(&client_query[DNS_HEADER_LEN..question_end_offset]);
        }
    }
}

/// Advances `offset` past a wire-encoded DNS domain name (supporting RFC 1035 §4.1.4 compression pointers).
pub fn skip_name(packet: &[u8], mut offset: usize) -> Result<usize, DohError> {
    let len = packet.len();
    let mut jumps = 0usize;
    loop {
        let label_len = *packet
            .get(offset)
            .ok_or(DohError::MalformedDnsPacket("truncated domain label"))?;
        if label_len == 0 {
            return Ok(offset + 1);
        }
        match label_len & 0xc0 {
            0xc0 => {
                if offset + 2 > len {
                    return Err(DohError::MalformedDnsPacket(
                        "truncated compression pointer",
                    ));
                }
                return Ok(offset + 2);
            }
            0x00 => {
                let step = (label_len as usize) + 1;
                if offset + step >= len {
                    return Err(DohError::MalformedDnsPacket("domain label out of bounds"));
                }
                offset += step;
                jumps += 1;
                if jumps > 128 {
                    return Err(DohError::MalformedDnsPacket("too many domain labels"));
                }
            }
            _ => {
                return Err(DohError::MalformedDnsPacket(
                    "invalid label compression bits",
                ));
            }
        }
    }
}

/// Decodes a wire-encoded DNS name into a raw dotted string and returns `(name, next_offset)`.
pub fn decode_name(packet: &[u8], offset: usize) -> Result<(String, usize), DohError> {
    decode_name_inner(packet, offset, false)
}

/// Decodes a wire-encoded DNS name into RFC 1035 §5.1 presentation format (`\.`, `\\`, `\DDD` escaped)
/// for unambiguous JSON output (N-7).
pub fn decode_name_escaped(packet: &[u8], offset: usize) -> Result<(String, usize), DohError> {
    decode_name_inner(packet, offset, true)
}

fn decode_name_inner(
    packet: &[u8],
    mut offset: usize,
    escape_presentation: bool,
) -> Result<(String, usize), DohError> {
    let packet_len = packet.len();
    let mut name = String::new();
    let mut post_jump_offset = None;
    let mut jumps = 0usize;

    loop {
        let b = *packet
            .get(offset)
            .ok_or(DohError::MalformedDnsPacket("name extends past packet"))?;
        if b == 0 {
            offset += 1;
            break;
        }
        if (b & 0xc0) == 0xc0 {
            let b2 = *packet.get(offset + 1).ok_or(DohError::MalformedDnsPacket(
                "incomplete compression pointer",
            ))?;
            if post_jump_offset.is_none() {
                post_jump_offset = Some(offset + 2);
            }
            jumps += 1;
            if jumps > 64 {
                return Err(DohError::MalformedDnsPacket(
                    "compression pointer loop detected",
                ));
            }
            let target = (((b & 0x3f) as usize) << 8) | (b2 as usize);
            if target >= packet_len {
                return Err(DohError::MalformedDnsPacket(
                    "compression pointer out of bounds",
                ));
            }
            offset = target;
            continue;
        }
        if (b & 0xc0) != 0 {
            return Err(DohError::MalformedDnsPacket("reserved label type bits"));
        }
        let label_len = b as usize;
        offset += 1;
        let label_bytes = packet
            .get(offset..offset + label_len)
            .ok_or(DohError::MalformedDnsPacket("label content out of bounds"))?;
        if !name.is_empty() {
            name.push('.');
        }
        if escape_presentation {
            escape_presentation_label(label_bytes, &mut name);
        } else {
            name.push_str(&String::from_utf8_lossy(label_bytes));
        }
        offset += label_len;
    }

    Ok((name, post_jump_offset.unwrap_or(offset)))
}

/// Escapes a single DNS label according to RFC 1035 §5.1 presentation rules (`\.`, `\\`, `\DDD`).
pub fn escape_presentation_label(label_bytes: &[u8], out: &mut String) {
    for &b in label_bytes {
        if b == b'.' || b == b'\\' {
            out.push('\\');
            out.push(b as char);
        } else if (0x21..=0x7e).contains(&b) {
            out.push(b as char);
        } else {
            let _ = write!(out, "\\{b:03}");
        }
    }
}

/// Extracts all lowercased owner names and CNAME/DNAME target domain names from the Answer section (N-4).
pub fn extract_answer_domain_names(packet: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    let Ok(mut offset) = skip_questions(packet) else {
        return names;
    };
    let an = ancount(packet) as usize;
    for _ in 0..an {
        let Ok((owner, after_name)) = decode_name(packet, offset) else {
            break;
        };
        let clean_owner = owner.trim_end_matches('.').to_ascii_lowercase();
        if !clean_owner.is_empty() {
            names.push(clean_owner);
        }
        if after_name + 10 > packet.len() {
            break;
        }
        let Ok(rr_type) = read_u16_be(packet, after_name) else {
            break;
        };
        let Ok(rdlen) = read_u16_be(packet, after_name + 8) else {
            break;
        };
        let rdata_start = after_name + 10;
        let rdata_end = rdata_start + (rdlen as usize);
        if rdata_end > packet.len() {
            break;
        }
        if matches!(rr_type, RR_TYPE_CNAME | RR_TYPE_DNAME) {
            if let Ok((target, _)) = decode_name(packet, rdata_start) {
                let clean_target = target.trim_end_matches('.').to_ascii_lowercase();
                if !clean_target.is_empty() {
                    names.push(clean_target);
                }
            }
        }
        offset = rdata_end;
    }
    names
}

/// Returns the byte offset immediately following the Question section.
pub fn skip_questions(packet: &[u8]) -> Result<usize, DohError> {
    if packet.len() < MIN_DNS_PACKET_LEN {
        return Err(DohError::MalformedDnsPacket(
            "packet shorter than minimum DNS length",
        ));
    }
    let q_count = qdcount(packet);
    if q_count != 1 {
        return Err(DohError::MalformedDnsPacket(
            "DNS packet must contain exactly 1 question",
        ));
    }
    let mut offset = skip_name(packet, DNS_HEADER_LEN)?;
    if offset + 4 > packet.len() {
        return Err(DohError::MalformedDnsPacket(
            "truncated question QTYPE/QCLASS",
        ));
    }
    offset += 4;
    Ok(offset)
}

/// Computes both `(http_freshness_ttl, internal_cache_ttl)` per RFC 8484 §5.1 and RFC 2308 §5.
///
/// - `http_freshness_ttl` is **never** raised above the smallest non-OPT RR TTL (`raw_ttl.min(max_ttl)`).
/// - If any RR has TTL `0`, both returned TTLs are `0` so zero-TTL records are never cached.
/// - `min_ttl` (default `0`) only acts as an opt-in floor for `internal_cache_ttl` when `raw_ttl > 0`.
pub fn compute_response_ttl_with_floor(
    packet: &[u8],
    min_ttl: u32,
    max_ttl: u32,
    err_ttl: u32,
) -> Result<(u32, u32), DohError> {
    if packet.len() > MAX_DNS_MESSAGE_LEN {
        return Err(DohError::PayloadTooLarge);
    }
    let mut offset = skip_questions(packet)?;
    let (an, ns, ar) = (ancount(packet), nscount(packet), arcount(packet));
    let total_rrs = (an as usize) + (ns as usize) + (ar as usize);

    if rcode(packet) != RCODE_NOERROR && rcode(packet) != RCODE_NXDOMAIN {
        let bounded_err = err_ttl.min(max_ttl);
        return Ok((bounded_err, bounded_err));
    }

    let mut found_ttl: Option<u32> = None;

    for i in 0..total_rrs {
        offset = skip_name(packet, offset)?;
        if offset + 10 > packet.len() {
            return Err(DohError::MalformedDnsPacket(
                "truncated resource record header",
            ));
        }
        let rr_type = read_u16_be(packet, offset)?;
        let _rr_class = read_u16_be(packet, offset + 2)?;
        let rr_ttl = read_u32_be(packet, offset + 4)?;
        let rdlen = read_u16_be(packet, offset + 8)? as usize;
        offset += 10;

        if offset + rdlen > packet.len() {
            return Err(DohError::MalformedDnsPacket(
                "truncated resource record RDATA",
            ));
        }

        if rr_type != RR_TYPE_OPT {
            let mut effective_rr_ttl = rr_ttl;
            // RFC 2308 §5 & RFC 8484 §5.1: For negative responses, SOA MINIMUM field bounds TTL.
            if i >= (an as usize) && rr_type == RR_TYPE_SOA {
                if let Some(soa_min) = extract_soa_minimum_ttl(packet, offset, rdlen) {
                    effective_rr_ttl = effective_rr_ttl.min(soa_min);
                }
            }
            found_ttl = Some(found_ttl.map_or(effective_rr_ttl, |cur| cur.min(effective_rr_ttl)));
        }

        offset += rdlen;
    }

    Ok(finalize_computed_ttls(found_ttl, min_ttl, max_ttl, err_ttl))
}

fn extract_soa_minimum_ttl(packet: &[u8], offset: usize, rdlen: usize) -> Option<u32> {
    let after_mname = skip_name(packet, offset).ok()?;
    let after_rname = skip_name(packet, after_mname).ok()?;
    if after_rname + 20 <= offset + rdlen {
        read_u32_be(packet, after_rname + 16).ok()
    } else {
        None
    }
}

fn finalize_computed_ttls(
    found_ttl: Option<u32>,
    min_ttl: u32,
    max_ttl: u32,
    err_ttl: u32,
) -> (u32, u32) {
    match found_ttl {
        Some(0) => (0, 0),
        Some(t) => (t.min(max_ttl), t.max(min_ttl).min(max_ttl)),
        None => {
            let bounded_err = err_ttl.min(max_ttl);
            (bounded_err, bounded_err)
        }
    }
}

/// Computes the RFC 8484 §5.1 HTTP caching TTL (`http_freshness_ttl`, never exceeding the wire TTL).
pub fn compute_response_ttl(
    packet: &[u8],
    min_ttl: u32,
    max_ttl: u32,
    err_ttl: u32,
) -> Result<u32, DohError> {
    let (http_ttl, _) = compute_response_ttl_with_floor(packet, min_ttl, max_ttl, err_ttl)?;
    Ok(http_ttl)
}

/// Decrements the 32-bit TTL of all non-OPT Resource Records in `packet` by `elapsed_secs` (RFC 1035 §6.2).
pub fn decrement_wire_ttls(packet: &mut [u8], elapsed_secs: u32) -> Result<(), DohError> {
    if elapsed_secs == 0 {
        return Ok(());
    }
    let mut offset = skip_questions(packet)?;
    let total_rrs =
        (ancount(packet) as usize) + (nscount(packet) as usize) + (arcount(packet) as usize);

    for _ in 0..total_rrs {
        offset = skip_name(packet, offset)?;
        if offset + 10 > packet.len() {
            return Err(DohError::MalformedDnsPacket(
                "truncated resource record header",
            ));
        }
        let rr_type = read_u16_be(packet, offset)?;
        let rr_ttl = read_u32_be(packet, offset + 4)?;
        let rdlen = read_u16_be(packet, offset + 8)? as usize;

        if rr_type != RR_TYPE_OPT {
            let new_ttl = rr_ttl.saturating_sub(elapsed_secs);
            write_u32_be(packet, offset + 4, new_ttl)?;
        }
        offset += 10 + rdlen;
        if offset > packet.len() {
            return Err(DohError::MalformedDnsPacket(
                "truncated resource record RDATA",
            ));
        }
    }
    Ok(())
}

/// Extracts all RFC 8914 Extended DNS Error (`EDE`, Option Code 15) entries from the `OPT` record in `packet`.
pub fn extract_ede_options(packet: &[u8]) -> Vec<(u16, String)> {
    let mut out = Vec::new();
    let Ok(mut offset) = skip_questions(packet) else {
        return out;
    };
    let (an, ns, ar) = (ancount(packet), nscount(packet), arcount(packet));

    for _ in 0..((an as usize) + (ns as usize)) {
        let Ok(next_name) = skip_name(packet, offset) else {
            return out;
        };
        let Ok(rdlen) = read_u16_be(packet, next_name + 8) else {
            return out;
        };
        offset = next_name + 10 + (rdlen as usize);
    }

    for _ in 0..(ar as usize) {
        let Ok(next_name) = skip_name(packet, offset) else {
            return out;
        };
        if next_name + 10 > packet.len() {
            return out;
        }
        let rr_type = read_u16_be(packet, next_name).unwrap_or(0);
        let rdlen = read_u16_be(packet, next_name + 8).unwrap_or(0) as usize;
        let rdata_start = next_name + 10;
        let rdata_end = rdata_start + rdlen;
        if rdata_end > packet.len() {
            return out;
        }

        if rr_type == RR_TYPE_OPT {
            let mut pos = rdata_start;
            while pos + 4 <= rdata_end {
                let opt_code = read_u16_be(packet, pos).unwrap_or(0);
                let opt_len = read_u16_be(packet, pos + 2).unwrap_or(0) as usize;
                pos += 4;
                if pos + opt_len > rdata_end {
                    break;
                }
                if opt_code == EDNS_OPT_EDE && opt_len >= 2 {
                    let info_code = read_u16_be(packet, pos).unwrap_or(0);
                    let extra_text = String::from_utf8_lossy(&packet[pos + 2..pos + opt_len])
                        .trim_end_matches('\0')
                        .to_string();
                    out.push((info_code, extra_text));
                }
                pos += opt_len;
            }
        }
        offset = rdata_end;
    }

    out
}

///Synthesizes a DNS wire response for Protective DNS policy enforcement (NXDOMAIN, REFUSED, NOTIMP, SERVFAIL, or Null IP sinkhole)
/// and attaches an optional RFC 8914 Extended DNS Error (`EDE`, Option Code 15) when the client supports EDNS0.
pub fn build_policy_response(
    query: &[u8],
    response_rcode: u8,
    null_sinkhole: bool,
    ede: Option<(u16, &str)>,
    ttl: u32,
) -> Result<Vec<u8>, DohError> {
    let parsed = validate_and_parse_query(query)?;
    let mut resp = Vec::with_capacity(128);

    // Copy 12-byte header and Question section from client query
    resp.extend_from_slice(&query[..parsed.question_end_offset]);

    // Set QR=1 (Response), RD preserved, RA=1, and target RCODE
    let rd_bit = query[2] & 0x01;
    let cd_bit = query[3] & 0x10;
    resp[2] = 0x80 | rd_bit;
    resp[3] = 0x80 | cd_bit | (response_rcode & 0x0f);

    // Reset ANCOUNT, NSCOUNT, ARCOUNT
    write_u16_be(&mut resp, 6, 0)?;
    write_u16_be(&mut resp, 8, 0)?;
    write_u16_be(&mut resp, 10, 0)?;

    // If null_sinkhole is requested and QTYPE is A (1) or AAAA (28), synthesize 0.0.0.0 or ::
    if null_sinkhole && parsed.qclass == DNS_CLASS_IN {
        match parsed.qtype {
            RR_TYPE_A => {
                write_u16_be(&mut resp, 6, 1)?; // ANCOUNT = 1
                resp.extend_from_slice(&[0xc0, 0x0c]); // Name pointer to QNAME at offset 12
                resp.extend_from_slice(&RR_TYPE_A.to_be_bytes());
                resp.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
                resp.extend_from_slice(&ttl.to_be_bytes());
                resp.extend_from_slice(&4u16.to_be_bytes());
                resp.extend_from_slice(&[0, 0, 0, 0]);
            }
            RR_TYPE_AAAA => {
                write_u16_be(&mut resp, 6, 1)?; // ANCOUNT = 1
                resp.extend_from_slice(&[0xc0, 0x0c]); // Name pointer to QNAME at offset 12
                resp.extend_from_slice(&RR_TYPE_AAAA.to_be_bytes());
                resp.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
                resp.extend_from_slice(&ttl.to_be_bytes());
                resp.extend_from_slice(&16u16.to_be_bytes());
                resp.extend_from_slice(&[0u8; 16]);
            }
            _ => {}
        }
    }

    if let Some((info_code, extra_text)) = ede {
        let opt_offset = append_empty_opt_record(&mut resp, UPSTREAM_EDNS_UDP_SIZE)?;
        let text_bytes = extra_text.as_bytes();
        let ede_opt_len = (2 + text_bytes.len()) as u16;
        let rdlen_offset = opt_offset + 8;
        let cur_rdlen = read_u16_be(&resp, rdlen_offset)?;
        write_u16_be(&mut resp, rdlen_offset, cur_rdlen + 4 + ede_opt_len)?;
        resp.extend_from_slice(&EDNS_OPT_EDE.to_be_bytes());
        resp.extend_from_slice(&ede_opt_len.to_be_bytes());
        resp.extend_from_slice(&info_code.to_be_bytes());
        resp.extend_from_slice(text_bytes);
    }

    Ok(resp)
}

/// Strips any EDNS0 `OPT` record from the Additional section of `packet` and updates `ARCOUNT`.
/// Required by RFC 6891 §7 when responding to a client query that did not contain an `OPT` record (M-1).
pub fn strip_opt_record(packet: &mut Vec<u8>) -> Result<(), DohError> {
    let mut offset = skip_questions(packet)?;
    let (an, ns, ar) = (ancount(packet), nscount(packet), arcount(packet));
    if ar == 0 {
        return Ok(());
    }

    for _ in 0..((an as usize) + (ns as usize)) {
        offset = skip_name(packet, offset)?;
        if offset + 10 > packet.len() {
            return Err(DohError::MalformedDnsPacket(
                "record header exceeds packet boundary",
            ));
        }
        let rdlen = read_u16_be(packet, offset + 8)? as usize;
        offset += 10 + rdlen;
        if offset > packet.len() {
            return Err(DohError::MalformedDnsPacket(
                "record RDATA exceeds packet boundary",
            ));
        }
    }

    let mut removed_count = 0u16;
    let mut idx = 0usize;
    while idx < (ar as usize) {
        let rr_start = offset;
        let after_name = skip_name(packet, offset)?;
        if after_name + 10 > packet.len() {
            return Err(DohError::MalformedDnsPacket("truncated additional record"));
        }
        let rr_type = read_u16_be(packet, after_name)?;
        let rdlen = read_u16_be(packet, after_name + 8)? as usize;
        let rr_end = after_name + 10 + rdlen;
        if rr_end > packet.len() {
            return Err(DohError::MalformedDnsPacket(
                "additional record RDATA out of bounds",
            ));
        }
        if rr_type == RR_TYPE_OPT {
            packet.drain(rr_start..rr_end);
            removed_count += 1;
        } else {
            offset = rr_end;
        }
        idx += 1;
    }

    if removed_count > 0 {
        write_u16_be(packet, 10, ar.saturating_sub(removed_count))?;
    }
    Ok(())
}

/// Finalizes a wire-format DNS response for the requesting client per RFC 6891 §7, RFC 7830 §4, and RFC 8467 §4.1:
/// - If `client_has_edns0 == false`: strips any `OPT` record and applies **no** padding.
/// - If `client_has_edns0 == true`: pads the response to a 468-byte block multiple.
pub fn finalize_wire_response_for_client(packet: &mut Vec<u8>, client_has_edns0: bool) {
    if client_has_edns0 {
        if let Err(e) = apply_edns0_padding(packet) {
            tracing::warn!("failed to apply RFC 8467 EDNS0 response padding: {e}");
        }
    } else if let Err(e) = strip_opt_record(packet) {
        tracing::warn!("failed to strip OPT record for non-EDNS0 client: {e}");
    }
}

/// Ensures an EDNS0 OPT record (RFC 6891) exists on the packet and advertises `max_payload` bytes.
pub fn ensure_edns0_max_payload(packet: &mut Vec<u8>, max_payload: u16) -> Result<(), DohError> {
    if packet.len() > MAX_DNS_MESSAGE_LEN {
        return Err(DohError::PayloadTooLarge);
    }
    let mut offset = skip_questions(packet)?;
    let (an, ns, ar) = (ancount(packet), nscount(packet), arcount(packet));

    // Skip Answer and Authority sections
    for _ in 0..((an as usize) + (ns as usize)) {
        offset = skip_name(packet, offset)?;
        let rdlen = read_u16_be(packet, offset + 8)? as usize;
        offset += 10 + rdlen;
        if offset > packet.len() {
            return Err(DohError::MalformedDnsPacket(
                "record exceeds packet boundary",
            ));
        }
    }

    // Search Additional section for an existing OPT RR
    let mut opt_found = false;
    for _ in 0..(ar as usize) {
        offset = skip_name(packet, offset)?;
        if offset + 10 > packet.len() {
            return Err(DohError::MalformedDnsPacket("truncated additional record"));
        }
        let rr_type = read_u16_be(packet, offset)?;
        let rdlen = read_u16_be(packet, offset + 8)? as usize;
        if rr_type == RR_TYPE_OPT {
            if opt_found {
                return Err(DohError::MalformedDnsPacket("duplicate EDNS0 OPT record"));
            }
            write_u16_be(packet, offset + 2, max_payload)?;
            opt_found = true;
        }
        offset += 10 + rdlen;
        if offset > packet.len() {
            return Err(DohError::MalformedDnsPacket(
                "additional record RDATA out of bounds",
            ));
        }
    }

    if !opt_found {
        append_empty_opt_record(packet, max_payload)?;
    }
    Ok(())
}

/// Appends a fresh EDNS0 OPT record at the end of `packet`.
pub fn append_empty_opt_record(packet: &mut Vec<u8>, max_payload: u16) -> Result<usize, DohError> {
    let ar = arcount(packet);
    if ar == u16::MAX || packet.len() + 11 > MAX_DNS_MESSAGE_LEN {
        return Err(DohError::PayloadTooLarge);
    }
    let opt_type_offset = packet.len() + 1;
    write_u16_be(packet, 10, ar + 1)?;
    packet.push(0); // Root domain '.'
    packet.extend_from_slice(&RR_TYPE_OPT.to_be_bytes());
    packet.extend_from_slice(&max_payload.to_be_bytes());
    packet.extend_from_slice(&0u32.to_be_bytes()); // ext RCODE + version + flags
    packet.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH = 0
    Ok(opt_type_offset)
}

/// Pads the DNS message using EDNS0 Option Code 12 (`PADDING`, RFC 7830) to a 468-byte block multiple (RFC 8467 §4.1).
pub fn apply_edns0_padding(packet: &mut Vec<u8>) -> Result<(), DohError> {
    let mut offset = skip_questions(packet)?;
    let (an, ns, ar) = (ancount(packet), nscount(packet), arcount(packet));

    for _ in 0..((an as usize) + (ns as usize)) {
        offset = skip_name(packet, offset)?;
        let rdlen = read_u16_be(packet, offset + 8)? as usize;
        offset += 10 + rdlen;
        if offset > packet.len() {
            return Err(DohError::MalformedDnsPacket("record out of bounds"));
        }
    }

    let mut opt_type_offset: Option<usize> = None;
    for _ in 0..(ar as usize) {
        offset = skip_name(packet, offset)?;
        if offset + 10 > packet.len() {
            return Err(DohError::MalformedDnsPacket("truncated additional record"));
        }
        let rr_type = read_u16_be(packet, offset)?;
        let rdlen = read_u16_be(packet, offset + 8)? as usize;
        if rr_type == RR_TYPE_OPT {
            opt_type_offset = Some(offset);
        }
        offset += 10 + rdlen;
    }

    let opt_offset = match opt_type_offset {
        Some(off) => off,
        None => append_empty_opt_record(packet, UPSTREAM_EDNS_UDP_SIZE)?,
    };

    // RFC 8467 §4.1: Pad response to a multiple of 468 octets (including the 4-byte option header).
    let base_with_opt_header = packet.len() + 4;
    let target_len = base_with_opt_header
        .div_ceil(RESPONSE_PADDING_BLOCK_SIZE)
        .saturating_mul(RESPONSE_PADDING_BLOCK_SIZE)
        .min(MAX_DNS_MESSAGE_LEN);
    let pad_bytes_len = target_len.saturating_sub(base_with_opt_header);

    let rdlen_offset = opt_offset + 8;
    let current_rdlen = read_u16_be(packet, rdlen_offset)? as usize;
    let extra_len = 4 + pad_bytes_len;

    if packet.len() + extra_len > MAX_DNS_MESSAGE_LEN
        || current_rdlen + extra_len > u16::MAX as usize
    {
        return Ok(());
    }

    write_u16_be(packet, rdlen_offset, (current_rdlen + extra_len) as u16)?;
    packet.extend_from_slice(&EDNS_OPT_PADDING.to_be_bytes());
    packet.extend_from_slice(&(pad_bytes_len as u16).to_be_bytes());
    // RFC 7830 §3: PADDING octets MUST be set to 0x00.
    packet.resize(packet.len() + pad_bytes_len, 0x00);

    Ok(())
}
