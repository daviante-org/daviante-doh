//! Clean-room implementation of RFC 7871 (Client Subnet in DNS Queries - EDNS0 Option Code 8)
//! and OWASP-compliant reverse-proxy client IP extraction (`DOH_TRUSTED_PROXIES`).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use hyper::HeaderMap;

use crate::dns::wire::{
    ancount, append_empty_opt_record, arcount, nscount, read_u16_be, skip_name, skip_questions,
    write_u16_be, EDNS_OPT_CLIENT_SUBNET, MAX_DNS_MESSAGE_LEN, RR_TYPE_OPT, UPSTREAM_EDNS_UDP_SIZE,
};
use crate::error::DohError;

const FAMILY_IPV4: u16 = 1;
const FAMILY_IPV6: u16 = 2;

/// IPv4 or IPv6 CIDR network prefix (e.g. `10.0.0.0/8`, `192.168.1.1/32`, `fd00::/8`) used for
/// trusted proxy verification (`DOH_TRUSTED_PROXIES`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpNet {
    network: IpAddr,
    prefix_len: u8,
}

impl IpNet {
    /// Creates a new `IpNet` from an IP address and prefix length, masking host bits to zero.
    pub fn new(addr: IpAddr, prefix_len: u8) -> Result<Self, DohError> {
        match addr {
            IpAddr::V4(v4) => {
                if prefix_len > 32 {
                    return Err(DohError::InvalidConfig(format!(
                        "IPv4 CIDR prefix length {prefix_len} exceeds 32"
                    )));
                }
                let masked = mask_ipv4(v4, prefix_len);
                Ok(Self {
                    network: IpAddr::V4(masked),
                    prefix_len,
                })
            }
            IpAddr::V6(v6) => {
                if prefix_len > 128 {
                    return Err(DohError::InvalidConfig(format!(
                        "IPv6 CIDR prefix length {prefix_len} exceeds 128"
                    )));
                }
                let masked = mask_ipv6(v6, prefix_len);
                Ok(Self {
                    network: IpAddr::V6(masked),
                    prefix_len,
                })
            }
        }
    }

    /// Returns `true` if `ip` belongs to this CIDR block.
    #[inline]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(candidate)) => {
                mask_ipv4(candidate, self.prefix_len) == net
            }
            (IpAddr::V6(net), IpAddr::V6(candidate)) => {
                mask_ipv6(candidate, self.prefix_len) == net
            }
            _ => false,
        }
    }

    #[inline]
    pub fn network(&self) -> IpAddr {
        self.network
    }

    #[inline]
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }
}

impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

impl FromStr for IpNet {
    type Err = DohError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if let Some((ip_part, prefix_part)) = trimmed.split_once('/') {
            let ip: IpAddr = ip_part.trim().parse().map_err(|e| {
                DohError::InvalidConfig(format!("invalid CIDR IP '{ip_part}': {e}"))
            })?;
            let prefix_len: u8 = prefix_part.trim().parse().map_err(|e| {
                DohError::InvalidConfig(format!("invalid CIDR prefix '{prefix_part}': {e}"))
            })?;
            Self::new(ip, prefix_len)
        } else {
            let ip: IpAddr = trimmed.parse().map_err(|e| {
                DohError::InvalidConfig(format!("invalid proxy IP/CIDR '{trimmed}': {e}"))
            })?;
            let max_prefix = match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            Self::new(ip, max_prefix)
        }
    }
}

/// Masks an IPv4 address to its top `prefix_len` bits (`0..=32`).
#[inline]
pub fn mask_ipv4(ip: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    let bits = u32::from(ip);
    let mask = if prefix_len == 0 {
        0
    } else if prefix_len >= 32 {
        u32::MAX
    } else {
        !0u32 << (32 - prefix_len)
    };
    Ipv4Addr::from(bits & mask)
}

/// Masks an IPv6 address to its top `prefix_len` bits (`0..=128`).
#[inline]
pub fn mask_ipv6(ip: Ipv6Addr, prefix_len: u8) -> Ipv6Addr {
    let bits = u128::from(ip);
    let mask = if prefix_len == 0 {
        0
    } else if prefix_len >= 128 {
        u128::MAX
    } else {
        !0u128 << (128 - prefix_len)
    };
    Ipv6Addr::from(bits & mask)
}

/// Truncates `ip` to `v4_prefix` (for IPv4) or `v6_prefix` (for IPv6) for RFC 8932 privacy-preserving logging.
#[inline]
pub fn truncate_ip(ip: IpAddr, v4_prefix: u8, v6_prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(mask_ipv4(v4, v4_prefix.min(32))),
        IpAddr::V6(v6) => IpAddr::V6(mask_ipv6(v6, v6_prefix.min(128))),
    }
}

/// Returns `true` if `ip` is contained in at least one configured `trusted_proxies` CIDR.
#[inline]
pub fn is_trusted_proxy_ip(ip: IpAddr, trusted_proxies: &[IpNet]) -> bool {
    trusted_proxies.iter().any(|net| net.contains(ip))
}

/// Extracts the originating client IP address from reverse-proxy headers (`X-Forwarded-For`,
/// `Forwarded`, `X-Real-IP`) **only** when the direct TCP `peer_addr` is inside `trusted_proxies` (C-1).
///
/// When `peer_addr` is trusted:
/// - `X-Forwarded-For` is walked **right-to-left** (`rsplit(',')`), returning the first hop that is
///   not in `trusted_proxies`. If a hop is malformed, chain traversal stops immediately and returns
///   the last validated hop so an attacker cannot inject garbage to bypass proxy validation.
/// - `Forwarded` (RFC 7239) is walked right-to-left with the same trust boundary rules.
/// - `X-Real-IP` is checked if neither `X-Forwarded-For` nor `Forwarded` was present.
pub fn resolve_client_ip(
    headers: &HeaderMap,
    peer_addr: Option<SocketAddr>,
    trusted_proxies: &[IpNet],
) -> Option<IpAddr> {
    let peer_ip = peer_addr?.ip();
    if !is_trusted_proxy_ip(peer_ip, trusted_proxies) {
        return Some(peer_ip);
    }

    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        let mut last_valid = peer_ip;
        for hop in xff.rsplit(',') {
            let trimmed = hop.trim();
            let Ok(hop_ip) = trimmed.parse::<IpAddr>() else {
                // Malformed hop: stop immediately and return the last verified hop
                return Some(last_valid);
            };
            if !is_trusted_proxy_ip(hop_ip, trusted_proxies) {
                return Some(hop_ip);
            }
            last_valid = hop_ip;
        }
        return Some(last_valid);
    }

    if let Some(fwd) = headers.get("forwarded").and_then(|v| v.to_str().ok()) {
        let mut last_valid = peer_ip;
        for element in fwd.rsplit(',') {
            let mut found_for = None;
            for directive in element.split(';') {
                let trimmed = directive.trim();
                if let Some(val) = trimmed
                    .strip_prefix("for=")
                    .or_else(|| trimmed.strip_prefix("FOR="))
                {
                    found_for = Some(parse_forwarded_for_value(val));
                    break;
                }
            }
            match found_for {
                Some(Some(hop_ip)) => {
                    if !is_trusted_proxy_ip(hop_ip, trusted_proxies) {
                        return Some(hop_ip);
                    }
                    last_valid = hop_ip;
                }
                Some(None) => return Some(last_valid),
                None => {}
            }
        }
        return Some(last_valid);
    }

    if let Some(xri) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        if let Ok(ip) = xri.trim().parse::<IpAddr>() {
            return Some(ip);
        }
    }

    Some(peer_ip)
}

fn parse_forwarded_for_value(val: &str) -> Option<IpAddr> {
    let unquoted = val.trim().trim_matches('"');
    if let Some(bracketed) = unquoted.strip_prefix('[') {
        let v6_str = bracketed.split(']').next()?;
        v6_str.parse::<IpAddr>().ok()
    } else if let Ok(ip) = unquoted.parse::<IpAddr>() {
        Some(ip)
    } else if let Some((ip_part, _port)) = unquoted.rsplit_once(':') {
        ip_part.parse::<IpAddr>().ok()
    } else {
        None
    }
}

/// Encodes an RFC 7871 EDNS0 Client Subnet option payload (`code=8`, `length`, `family`, `source_prefix`, `scope=0`, `truncated_addr`).
pub fn encode_ecs_option(
    client_ip: IpAddr,
    v4_prefix: u8,
    v6_prefix: u8,
) -> Result<Vec<u8>, DohError> {
    let (family, octets, prefix_len): (u16, Vec<u8>, u8) = match client_ip {
        IpAddr::V4(v4) => {
            if v4_prefix > 32 {
                return Err(DohError::InvalidConfig("IPv4 ECS prefix > 32".into()));
            }
            (FAMILY_IPV4, v4.octets().to_vec(), v4_prefix)
        }
        IpAddr::V6(v6) => {
            if v6_prefix > 128 {
                return Err(DohError::InvalidConfig("IPv6 ECS prefix > 128".into()));
            }
            (FAMILY_IPV6, v6.octets().to_vec(), v6_prefix)
        }
    };

    let byte_count = (prefix_len as usize).div_ceil(8);
    let mut addr_bytes = octets[..byte_count].to_vec();
    let trailing_bits = prefix_len % 8;
    if trailing_bits != 0 {
        if let Some(last) = addr_bytes.last_mut() {
            *last &= !0u8 << (8 - trailing_bits);
        }
    }

    let opt_data_len = (4 + addr_bytes.len()) as u16;
    let mut buf = Vec::with_capacity(4 + opt_data_len as usize);
    buf.extend_from_slice(&EDNS_OPT_CLIENT_SUBNET.to_be_bytes());
    buf.extend_from_slice(&opt_data_len.to_be_bytes());
    buf.extend_from_slice(&family.to_be_bytes());
    buf.push(prefix_len);
    buf.push(0); // Scope prefix-length = 0 in queries
    buf.extend_from_slice(&addr_bytes);
    Ok(buf)
}

/// Returns `true` if `ip` is a globally routable unicast address permitted in an RFC 7871 §7.1.2 ECS option.
pub fn is_globally_routable_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            let is_cgnat = octets[0] == 100 && (octets[1] & 0b1100_0000) == 64;
            !v4.is_private()
                && !v4.is_loopback()
                && !v4.is_link_local()
                && !v4.is_broadcast()
                && !v4.is_documentation()
                && !v4.is_unspecified()
                && !v4.is_multicast()
                && !is_cgnat
        }
        IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            let is_ula = (seg0 & 0xfe00) == 0xfc00; // fc00::/7 (RFC 4193)
            let is_ll = (seg0 & 0xffc0) == 0xfe80; // fe80::/10 (RFC 4291)
            let is_doc = seg0 == 0x2001 && v6.segments()[1] == 0x0db8; // 2001:db8::/32
            !v6.is_loopback()
                && !v6.is_unspecified()
                && !v6.is_multicast()
                && !is_ula
                && !is_ll
                && !is_doc
        }
    }
}

/// Attaches an RFC 7871 Client Subnet option to a DNS query packet unless the client already included one.
/// Returns `Ok(true)` if an ECS option is present/attached on the outgoing query.
pub fn attach_ecs_to_query(
    packet: &mut Vec<u8>,
    client_ip: IpAddr,
    v4_prefix: u8,
    v6_prefix: u8,
) -> Result<bool, DohError> {
    // RFC 7871 §7.1.2: Never leak non-globally-routable addresses to upstream resolvers.
    if !is_globally_routable_ip(client_ip) {
        return Ok(false);
    }

    let mut offset = skip_questions(packet)?;
    let (an, ns, ar) = (ancount(packet), nscount(packet), arcount(packet));

    for _ in 0..((an as usize) + (ns as usize)) {
        offset = skip_name(packet, offset)?;
        let rdlen = read_u16_be(packet, offset + 8)? as usize;
        offset += 10 + rdlen;
    }

    let mut opt_type_offset: Option<usize> = None;
    for _ in 0..(ar as usize) {
        offset = skip_name(packet, offset)?;
        let rr_type = read_u16_be(packet, offset)?;
        let rdlen = read_u16_be(packet, offset + 8)? as usize;
        if rr_type == RR_TYPE_OPT {
            let rdata_start = offset + 10;
            let rdata_end = rdata_start + rdlen;
            let mut pos = rdata_start;
            while pos + 4 <= rdata_end {
                let code = read_u16_be(packet, pos)?;
                let len = read_u16_be(packet, pos + 2)? as usize;
                if code == EDNS_OPT_CLIENT_SUBNET {
                    return Ok(true);
                }
                pos += 4 + len;
            }
            opt_type_offset = Some(offset);
        }
        offset += 10 + rdlen;
    }

    let opt_offset = match opt_type_offset {
        Some(off) => off,
        None => append_empty_opt_record(packet, UPSTREAM_EDNS_UDP_SIZE)?,
    };

    let ecs_bytes = encode_ecs_option(client_ip, v4_prefix, v6_prefix)?;
    let rdlen_offset = opt_offset + 8;
    let cur_rdlen = read_u16_be(packet, rdlen_offset)? as usize;

    if packet.len() + ecs_bytes.len() > MAX_DNS_MESSAGE_LEN {
        return Err(DohError::PayloadTooLarge);
    }

    write_u16_be(packet, rdlen_offset, (cur_rdlen + ecs_bytes.len()) as u16)?;
    packet.extend_from_slice(&ecs_bytes);
    Ok(true)
}
