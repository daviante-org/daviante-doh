//! Clean-room implementation of the DNS-over-HTTPS JSON API (`application/dns-json`),
//! RFC 8914 Extended DNS Error (`EDE`) reporting, RFC 1035 §5.1 presentation escaping, and RFC 3597 formatting.

use std::fmt::Write as _;
use std::net::IpAddr;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::dns::ecs::encode_ecs_option;
use crate::dns::wire::{
    ancount, arcount, decode_name_escaped, extract_ede_options, nscount, qdcount, rcode,
    read_u16_be, read_u32_be, write_u16_be, DNS_CLASS_IN, DNS_HEADER_LEN, RR_TYPE_OPT, RR_TYPE_SOA,
    UPSTREAM_EDNS_UDP_SIZE,
};
use crate::error::DohError;

/// Standard Google / Cloudflare DoH JSON response structure with RFC 8914 Extended DNS Error support.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonDnsResponse {
    #[serde(rename = "Status")]
    pub status: u16,
    #[serde(rename = "TC")]
    pub tc: bool,
    #[serde(rename = "RD")]
    pub rd: bool,
    #[serde(rename = "RA")]
    pub ra: bool,
    #[serde(rename = "AD")]
    pub ad: bool,
    #[serde(rename = "CD")]
    pub cd: bool,
    #[serde(rename = "Question", skip_serializing_if = "Option::is_none")]
    pub question: Option<Vec<JsonDnsQuestion>>,
    #[serde(rename = "Answer", skip_serializing_if = "Option::is_none")]
    pub answer: Option<Vec<JsonDnsRecord>>,
    #[serde(rename = "Authority", skip_serializing_if = "Option::is_none")]
    pub authority: Option<Vec<JsonDnsRecord>>,
    #[serde(rename = "Additional", skip_serializing_if = "Option::is_none")]
    pub additional: Option<Vec<JsonDnsRecord>>,
    #[serde(rename = "Comment", skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(rename = "EDE", skip_serializing_if = "Option::is_none")]
    pub ede: Option<Vec<JsonExtendedDnsError>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonExtendedDnsError {
    pub info_code: u16,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub extra_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonDnsQuestion {
    pub name: String,
    #[serde(rename = "type")]
    pub qtype: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonDnsRecord {
    pub name: String,
    #[serde(rename = "type")]
    pub rtype: u16,
    #[serde(rename = "TTL")]
    pub ttl: u32,
    pub data: String,
}

#[derive(Debug, Clone, Default)]
pub struct JsonDnsQueryParams {
    pub name: String,
    pub qtype: Option<u16>,
    pub cd: bool,
    pub do_bit: bool,
    pub edns_client_subnet: Option<String>,
}

/// Resolves a numeric (`1`..`65535`) or symbolic (`"A"`, `"AAAA"`, `"HTTPS"`, `"SVCB"`, etc.) DNS record type.
pub fn resolve_rr_type(input: &str) -> Option<u16> {
    if let Ok(num) = input.parse::<u16>() {
        return (num > 0).then_some(num);
    }
    match input.trim().to_ascii_uppercase().as_str() {
        "A" => Some(1),
        "NS" => Some(2),
        "CNAME" => Some(5),
        "SOA" => Some(6),
        "PTR" => Some(12),
        "HINFO" => Some(13),
        "MX" => Some(15),
        "TXT" => Some(16),
        "RP" => Some(17),
        "AFSDB" => Some(18),
        "SIG" => Some(24),
        "KEY" => Some(25),
        "AAAA" => Some(28),
        "LOC" => Some(29),
        "SRV" => Some(33),
        "NAPTR" => Some(35),
        "KX" => Some(36),
        "CERT" => Some(37),
        "DNAME" => Some(39),
        "OPT" => Some(41),
        "APL" => Some(42),
        "DS" => Some(43),
        "SSHFP" => Some(44),
        "IPSECKEY" => Some(45),
        "RRSIG" => Some(46),
        "NSEC" => Some(47),
        "DNSKEY" => Some(48),
        "DHCID" => Some(49),
        "NSEC3" => Some(50),
        "NSEC3PARAM" => Some(51),
        "TLSA" => Some(52),
        "SMIMEA" => Some(53),
        "HIP" => Some(55),
        "CDS" => Some(59),
        "CDNSKEY" => Some(60),
        "OPENPGPKEY" => Some(61),
        "CSYNC" => Some(62),
        "ZONEMD" => Some(63),
        "SVCB" => Some(64),
        "HTTPS" => Some(65),
        "SPF" => Some(99),
        "EUI48" => Some(108),
        "EUI64" => Some(109),
        "TKEY" => Some(249),
        "TSIG" => Some(250),
        "ANY" | "*" => Some(255),
        "URI" => Some(256),
        "CAA" => Some(257),
        _ => None,
    }
}

/// Formats binary RDATA according to RFC 3597 (`\# <length> <hex>`).
pub fn format_rfc3597_rdata(rdata: &[u8]) -> String {
    if rdata.is_empty() {
        return "\\# 0".to_string();
    }
    let mut hex_str = String::with_capacity(rdata.len() * 2);
    for byte in rdata {
        let _ = write!(&mut hex_str, "{byte:02x}");
    }
    format!("\\# {} {}", rdata.len(), hex_str)
}

fn format_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

/// Builds a wire-format DNS query packet from JSON API query parameters.
pub fn encode_json_query_to_wire(params: &JsonDnsQueryParams) -> Result<Vec<u8>, DohError> {
    let clean_name = params.name.trim_end_matches('.');
    if clean_name.is_empty() {
        return Err(DohError::BadRequest("missing 'name' parameter".into()));
    }
    if clean_name.len() > 253 {
        return Err(DohError::BadRequest(
            "domain name exceeds 253 characters (RFC 1035)".into(),
        ));
    }

    let qtype = params.qtype.unwrap_or(1);
    let mut packet = vec![0u8; DNS_HEADER_LEN];

    // Random 16-bit Transaction ID
    let txid: [u8; 2] = rand::random();
    packet[0] = txid[0];
    packet[1] = txid[1];

    // Standard recursive query with RD=1 (0x0100) and AD=1 (0x0020)
    packet[2] = 0x01;
    packet[3] = 0x20 | if params.cd { 0x10 } else { 0x00 };

    // QDCOUNT = 1
    write_u16_be(&mut packet, 4, 1)?;

    for label in clean_name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(DohError::BadRequest(
                "invalid DNS label length (must be 1..=63 bytes)".into(),
            ));
        }
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0); // Root terminator

    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

    // Always include EDNS0 OPT on JSON queries so upstream resolvers can attach EDE (RFC 8914)
    write_u16_be(&mut packet, 10, 1)?; // ARCOUNT = 1
    packet.push(0); // Root domain
    packet.extend_from_slice(&RR_TYPE_OPT.to_be_bytes());
    packet.extend_from_slice(&UPSTREAM_EDNS_UDP_SIZE.to_be_bytes());
    packet.push(0); // Extended RCODE
    packet.push(0); // EDNS version 0
    let edns_flags: u16 = if params.do_bit { 0x8000 } else { 0x0000 };
    packet.extend_from_slice(&edns_flags.to_be_bytes());

    let rdlen_pos = packet.len();
    packet.extend_from_slice(&0u16.to_be_bytes());

    if let Some(subnet_str) = &params.edns_client_subnet {
        let (ip_str, prefix_opt) = match subnet_str.split_once('/') {
            Some((i, p)) => (
                i,
                Some(
                    p.parse::<u8>()
                        .map_err(|_| DohError::BadRequest("invalid ECS prefix".into()))?,
                ),
            ),
            None => (subnet_str.as_str(), None),
        };
        let ip: IpAddr = ip_str
            .parse()
            .map_err(|_| DohError::BadRequest("invalid ECS IP address".into()))?;
        let (v4_p, v6_p) = match ip {
            IpAddr::V4(_) => (prefix_opt.unwrap_or(24), 56),
            IpAddr::V6(_) => (24, prefix_opt.unwrap_or(56)),
        };
        let ecs_opt = encode_ecs_option(ip, v4_p, v6_p)?;
        write_u16_be(&mut packet, rdlen_pos, ecs_opt.len() as u16)?;
        packet.extend_from_slice(&ecs_opt);
    }

    Ok(packet)
}

/// Decodes a wire-format DNS response packet into `JsonDnsResponse` with RFC 1035 §5.1 escaped domain names.
pub fn decode_wire_to_json(packet: &[u8]) -> Result<JsonDnsResponse, DohError> {
    if packet.len() < DNS_HEADER_LEN {
        return Err(DohError::MalformedDnsPacket(
            "packet shorter than 12-byte header",
        ));
    }

    let flags = read_u16_be(packet, 2)?;
    let qd = qdcount(packet);
    let an = ancount(packet);
    let ns = nscount(packet);
    let ar = arcount(packet);

    let mut offset = DNS_HEADER_LEN;
    let mut questions = Vec::new();
    for _ in 0..qd {
        let (name, next_off) = decode_name_escaped(packet, offset)?;
        let qtype = read_u16_be(packet, next_off)?;
        offset = next_off + 4;
        questions.push(JsonDnsQuestion { name, qtype });
    }

    let (answers, next_off) = decode_rr_section(packet, offset, an)?;
    offset = next_off;
    let (authority, next_off) = decode_rr_section(packet, offset, ns)?;
    offset = next_off;
    let (additional, _) = decode_rr_section(packet, offset, ar)?;

    let raw_edes = extract_ede_options(packet);
    let (comment, ede) = if raw_edes.is_empty() {
        (None, None)
    } else {
        let comment_str = raw_edes
            .iter()
            .map(|(code, text)| {
                if text.is_empty() {
                    format!("EDE {code}")
                } else {
                    format!("EDE {code}: {text}")
                }
            })
            .collect::<Vec<_>>()
            .join("; ");
        let ede_list = raw_edes
            .into_iter()
            .map(|(info_code, extra_text)| JsonExtendedDnsError {
                info_code,
                extra_text,
            })
            .collect();
        (Some(comment_str), Some(ede_list))
    };

    Ok(JsonDnsResponse {
        status: rcode(packet) as u16,
        tc: (flags & 0x0200) != 0,
        rd: (flags & 0x0100) != 0,
        ra: (flags & 0x0080) != 0,
        ad: (flags & 0x0020) != 0,
        cd: (flags & 0x0010) != 0,
        question: (!questions.is_empty()).then_some(questions),
        answer: (!answers.is_empty()).then_some(answers),
        authority: (!authority.is_empty()).then_some(authority),
        additional: (!additional.is_empty()).then_some(additional),
        comment,
        ede,
    })
}

fn decode_rr_section(
    packet: &[u8],
    mut offset: usize,
    count: u16,
) -> Result<(Vec<JsonDnsRecord>, usize), DohError> {
    let mut records = Vec::new();
    for _ in 0..count {
        let (name, after_name) = decode_name_escaped(packet, offset)?;
        offset = after_name;
        if offset + 10 > packet.len() {
            return Err(DohError::MalformedDnsPacket("truncated resource record"));
        }
        let rtype = read_u16_be(packet, offset)?;
        let rclass = read_u16_be(packet, offset + 2)?;
        let ttl = read_u32_be(packet, offset + 4)?;
        let rdlen = read_u16_be(packet, offset + 8)? as usize;
        offset += 10;

        let rdata_end = offset + rdlen;
        if rdata_end > packet.len() {
            return Err(DohError::MalformedDnsPacket(
                "RDATA exceeds packet boundary",
            ));
        }

        if rclass != DNS_CLASS_IN || rtype == RR_TYPE_OPT {
            offset = rdata_end;
            continue;
        }

        let data = match rtype {
            1 if rdlen == 4 => format!(
                "{}.{}.{}.{}",
                packet[offset],
                packet[offset + 1],
                packet[offset + 2],
                packet[offset + 3]
            ),
            28 if rdlen == 16 => {
                let mut v6_octets = [0u8; 16];
                v6_octets.copy_from_slice(&packet[offset..offset + 16]);
                std::net::Ipv6Addr::from(v6_octets).to_string()
            }
            2 | 5 | 12 | 39 => decode_name_escaped(packet, offset)?.0,
            15 if rdlen >= 2 => {
                let pref = read_u16_be(packet, offset)?;
                let (exchange, _) = decode_name_escaped(packet, offset + 2)?;
                format!("{pref} {exchange}")
            }
            16 | 99 => decode_txt_rdata(packet, offset, rdata_end),
            RR_TYPE_SOA => decode_soa_rdata(packet, offset, rdata_end)?,
            33 if rdlen >= 6 => {
                let prio = read_u16_be(packet, offset)?;
                let weight = read_u16_be(packet, offset + 2)?;
                let port = read_u16_be(packet, offset + 4)?;
                let (target, _) = decode_name_escaped(packet, offset + 6)?;
                format!("{prio} {weight} {port} {target}")
            }
            43 if rdlen >= 4 => {
                let key_tag = read_u16_be(packet, offset)?;
                let alg = packet[offset + 2];
                let digest_type = packet[offset + 3];
                let digest_hex = format_hex(&packet[offset + 4..rdata_end]);
                format!("{key_tag} {alg} {digest_type} {digest_hex}")
            }
            44 if rdlen >= 2 => {
                let alg = packet[offset];
                let fp_type = packet[offset + 1];
                let fp_hex = format_hex(&packet[offset + 2..rdata_end]);
                format!("{alg} {fp_type} {fp_hex}")
            }
            48 if rdlen >= 4 => {
                let flags = read_u16_be(packet, offset)?;
                let proto = packet[offset + 2];
                let alg = packet[offset + 3];
                let pk_b64 = BASE64_STANDARD.encode(&packet[offset + 4..rdata_end]);
                format!("{flags} {proto} {alg} {pk_b64}")
            }
            52 if rdlen >= 3 => {
                let usage = packet[offset];
                let selector = packet[offset + 1];
                let mtype = packet[offset + 2];
                let cert_hex = format_hex(&packet[offset + 3..rdata_end]);
                format!("{usage} {selector} {mtype} {cert_hex}")
            }
            257 if rdlen >= 2 => decode_caa_rdata(packet, offset, rdata_end),
            _ => format_rfc3597_rdata(&packet[offset..rdata_end]),
        };

        offset = rdata_end;
        records.push(JsonDnsRecord {
            name,
            rtype,
            ttl,
            data,
        });
    }
    Ok((records, offset))
}

fn decode_txt_rdata(packet: &[u8], offset: usize, rdata_end: usize) -> String {
    let mut out = String::new();
    let mut pos = offset;
    while pos < rdata_end {
        let slen = packet[pos] as usize;
        pos += 1;
        if pos + slen > rdata_end {
            break;
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&String::from_utf8_lossy(&packet[pos..pos + slen]));
        pos += slen;
    }
    out
}

fn decode_soa_rdata(packet: &[u8], offset: usize, rdata_end: usize) -> Result<String, DohError> {
    let (mname, p1) = decode_name_escaped(packet, offset)?;
    let (rname, p2) = decode_name_escaped(packet, p1)?;
    if p2 + 20 <= rdata_end {
        let serial = read_u32_be(packet, p2)?;
        let refresh = read_u32_be(packet, p2 + 4)?;
        let retry = read_u32_be(packet, p2 + 8)?;
        let expire = read_u32_be(packet, p2 + 12)?;
        let minimum = read_u32_be(packet, p2 + 16)?;
        Ok(format!(
            "{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
        ))
    } else {
        Ok(format_rfc3597_rdata(&packet[offset..rdata_end]))
    }
}

fn decode_caa_rdata(packet: &[u8], offset: usize, rdata_end: usize) -> String {
    let flags = packet[offset];
    let tag_len = packet[offset + 1] as usize;
    if offset + 2 + tag_len <= rdata_end {
        let tag = String::from_utf8_lossy(&packet[offset + 2..offset + 2 + tag_len]);
        let val = String::from_utf8_lossy(&packet[offset + 2 + tag_len..rdata_end]);
        format!("{flags} {tag} \"{val}\"")
    } else {
        format_rfc3597_rdata(&packet[offset..rdata_end])
    }
}
