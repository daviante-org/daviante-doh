//! Unit tests for `src/dns/ecs.rs`, `src/dns/json.rs`, `src/dns/odoh.rs`, and `src/dns/wire.rs`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::Bytes;
use daviante_doh::ecs::{
    attach_ecs_to_query, encode_ecs_option, is_globally_routable_ip, mask_ipv4, mask_ipv6,
    resolve_client_ip, IpNet,
};
use daviante_doh::error::DohError;
use daviante_doh::json::{
    decode_wire_to_json, encode_json_query_to_wire, format_rfc3597_rdata, resolve_rr_type,
    JsonDnsQueryParams,
};
use daviante_doh::odoh::{OdohActiveKey, OdohKeyRing};
use daviante_doh::wire::{
    ancount, append_empty_opt_record, apply_edns0_padding, arcount, build_policy_response,
    compute_response_ttl, decrement_wire_ttls, ensure_edns0_max_payload, extract_ede_options,
    finalize_wire_response_for_client, matches_response_question, rcode, skip_name,
    strip_opt_record, validate_and_parse_query, write_u16_be, EDE_BLOCKED, MAX_DNS_QUERY_LEN,
    RCODE_NOERROR, RCODE_NXDOMAIN, RESPONSE_PADDING_BLOCK_SIZE,
};
use hyper::header::HeaderMap;
use odoh_rs::{
    Deserialize as _, ObliviousDoHConfigs, ObliviousDoHMessagePlaintext, Serialize as _,
};

// =============================================================================
// Unit tests for src/dns/ecs.rs
// =============================================================================
#[test]
fn ipv4_and_ipv6_ecs_bit_masking() {
    let ip4: IpAddr = "198.51.100.255".parse().unwrap();
    let opt4 = encode_ecs_option(ip4, 24, 56).unwrap();
    assert_eq!(opt4.len(), 11);
    assert_eq!(&opt4[8..11], &[198, 51, 100]);

    let ip4_20: IpAddr = "198.51.255.255".parse().unwrap();
    let opt4_20 = encode_ecs_option(ip4_20, 20, 56).unwrap();
    assert_eq!(&opt4_20[8..11], &[198, 51, 240]);
}

#[test]
fn rfc7871_private_ips_are_not_leaked() {
    assert!(!is_globally_routable_ip("10.88.0.1".parse().unwrap()));
    assert!(!is_globally_routable_ip("172.17.0.1".parse().unwrap()));
    assert!(!is_globally_routable_ip("192.168.1.1".parse().unwrap()));
    assert!(!is_globally_routable_ip("100.64.0.1".parse().unwrap()));
    assert!(!is_globally_routable_ip("127.0.0.1".parse().unwrap()));
    assert!(!is_globally_routable_ip("fd00::1".parse().unwrap()));
    assert!(is_globally_routable_ip("8.8.8.8".parse().unwrap()));
    assert!(is_globally_routable_ip(
        "2606:4700:4700::1111".parse().unwrap()
    ));
    assert!(!is_globally_routable_ip("::1".parse().unwrap()));
    assert!(!is_globally_routable_ip("fe80::1".parse().unwrap()));
    assert!(!is_globally_routable_ip("2001:db8::1".parse().unwrap()));
}

#[test]
fn ipnet_parsing_matching_and_display() {
    let net4: IpNet = "10.1.2.3/8".parse().unwrap();
    assert_eq!(net4.network(), "10.0.0.0".parse::<IpAddr>().unwrap());
    assert_eq!(net4.prefix_len(), 8);
    assert_eq!(net4.to_string(), "10.0.0.0/8");
    assert!(net4.contains("10.99.88.77".parse().unwrap()));
    assert!(!net4.contains("11.0.0.1".parse().unwrap()));
    assert!(!net4.contains("2001:4860:4860::8888".parse().unwrap()));

    let net6: IpNet = "2001:4860:4860::8888/48".parse().unwrap();
    assert_eq!(net6.prefix_len(), 48);
    assert!(net6.contains("2001:4860:4860::1234".parse().unwrap()));
    assert!(!net6.contains("2001:4860:4861::1".parse().unwrap()));

    let host4: IpNet = "192.0.2.9".parse().unwrap();
    assert_eq!(host4.prefix_len(), 32);
    let host6: IpNet = "2606:4700::1".parse().unwrap();
    assert_eq!(host6.prefix_len(), 128);

    assert!("10.0.0.1/33".parse::<IpNet>().is_err());
    assert!("2001:db8::/129".parse::<IpNet>().is_err());
    assert!("not-an-ip/24".parse::<IpNet>().is_err());
    assert!("10.0.0.1/not-a-num".parse::<IpNet>().is_err());
    assert!("not-an-ip".parse::<IpNet>().is_err());
}

#[test]
fn forwarded_and_x_real_ip_extraction() {
    let trusted = vec![
        "10.0.0.0/8".parse::<IpNet>().unwrap(),
        "fd00::/8".parse::<IpNet>().unwrap(),
    ];
    let peer: SocketAddr = "10.0.0.5:443".parse().unwrap();

    let mut h_fwd = HeaderMap::new();
    h_fwd.insert(
        "forwarded",
        "for=\"[2606:4700:4700::1111]:8080\";proto=https, for=10.0.0.9:1234"
            .parse()
            .unwrap(),
    );
    assert_eq!(
        resolve_client_ip(&h_fwd, Some(peer), &trusted),
        Some("2606:4700:4700::1111".parse().unwrap())
    );

    let mut h_xri = HeaderMap::new();
    h_xri.insert("x-real-ip", "198.51.100.42".parse().unwrap());
    assert_eq!(
        resolve_client_ip(&h_xri, Some(peer), &trusted),
        Some("198.51.100.42".parse().unwrap())
    );
}

#[test]
fn attach_ecs_ipv4_and_ipv6_queries() {
    let mut query = vec![
        0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    query.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
    let mut q_priv = query.clone();

    let ip6: IpAddr = "2606:4700:4700:1234::1".parse().unwrap();
    assert!(attach_ecs_to_query(&mut query, ip6, 24, 56).unwrap());
    // Calling a second time recognizes the existing ECS option without duplicating it
    assert!(attach_ecs_to_query(&mut query, ip6, 24, 56).unwrap());

    let priv_ip: IpAddr = "192.168.1.50".parse().unwrap();
    assert!(!attach_ecs_to_query(&mut q_priv, priv_ip, 24, 56).unwrap());

    // Prefix 0 masking and invalid ECS prefix bounds
    assert_eq!(
        mask_ipv4("198.51.100.1".parse().unwrap(), 0),
        Ipv4Addr::UNSPECIFIED
    );
    assert_eq!(
        mask_ipv6("2606:4700::1".parse().unwrap(), 0),
        Ipv6Addr::UNSPECIFIED
    );
    assert!(encode_ecs_option("198.51.100.1".parse().unwrap(), 33, 56).is_err());
    assert!(encode_ecs_option("2606:4700::1".parse().unwrap(), 24, 129).is_err());

    // Forwarded with unbracketed IPv4:port, malformed Forwarded, and empty headers fallback
    let trusted = vec!["10.0.0.0/8".parse::<IpNet>().unwrap()];
    let peer: SocketAddr = "10.0.0.5:443".parse().unwrap();
    let mut h_port = HeaderMap::new();
    h_port.insert("forwarded", "for=198.51.100.7:8443".parse().unwrap());
    assert_eq!(
        resolve_client_ip(&h_port, Some(peer), &trusted),
        Some("198.51.100.7".parse().unwrap())
    );

    let mut h_bad = HeaderMap::new();
    h_bad.insert("forwarded", "proto=https, for=not_an_ip".parse().unwrap());
    assert_eq!(
        resolve_client_ip(&h_bad, Some(peer), &trusted),
        Some(peer.ip())
    );
    assert_eq!(
        resolve_client_ip(&HeaderMap::new(), Some(peer), &trusted),
        Some(peer.ip())
    );

    // Attach ECS to query that already has an empty EDNS0 OPT record
    let mut q_opt = q_priv;
    append_empty_opt_record(&mut q_opt, 1232).unwrap();
    assert!(attach_ecs_to_query(&mut q_opt, "8.8.8.8".parse().unwrap(), 24, 56).unwrap());
}

// =============================================================================
// Unit tests for src/dns/json.rs
// =============================================================================
#[test]
fn resolves_symbolic_and_numeric_rr_types() {
    assert_eq!(resolve_rr_type("A"), Some(1));
    assert_eq!(resolve_rr_type("aaaa"), Some(28));
    assert_eq!(resolve_rr_type("HTTPS"), Some(65));
    assert_eq!(resolve_rr_type("SVCB"), Some(64));
    assert_eq!(resolve_rr_type("CAA"), Some(257));
    assert_eq!(resolve_rr_type("65"), Some(65));
    assert_eq!(resolve_rr_type("0"), None);
}

#[test]
fn encodes_and_decodes_rfc3597_unknown_record() {
    let mut pkt = vec![
        0x12, 0x34, 0x81, 0xa0, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    ];
    pkt.extend_from_slice(b"\x07example\x03com\x00\x00\x41\x00\x01");
    pkt.extend_from_slice(b"\xc0\x0c\x00\x41\x00\x01\x00\x00\x00\x3c\x00\x04\xde\xad\xbe\xef");
    let decoded = decode_wire_to_json(&pkt).unwrap();
    assert!(decoded.ad);
    assert_eq!(decoded.answer.unwrap()[0].data, "\\# 4 deadbeef");
}

#[test]
fn decodes_standard_rr_types_to_json() {
    for sym in [
        "NS",
        "CNAME",
        "SOA",
        "PTR",
        "HINFO",
        "MX",
        "TXT",
        "RP",
        "AFSDB",
        "SIG",
        "KEY",
        "LOC",
        "SRV",
        "NAPTR",
        "KX",
        "CERT",
        "DNAME",
        "OPT",
        "APL",
        "DS",
        "SSHFP",
        "IPSECKEY",
        "RRSIG",
        "NSEC",
        "DNSKEY",
        "DHCID",
        "NSEC3",
        "NSEC3PARAM",
        "TLSA",
        "SMIMEA",
        "HIP",
        "CDS",
        "CDNSKEY",
        "OPENPGPKEY",
        "CSYNC",
        "ZONEMD",
        "SPF",
        "EUI48",
        "EUI64",
        "TKEY",
        "TSIG",
        "ANY",
        "*",
        "URI",
        "CAA",
    ] {
        assert!(resolve_rr_type(sym).is_some(), "missing {sym}");
    }

    // ANCOUNT = 7 (AAAA=28, MX=15, TXT=16, SRV=33, DS=43, TLSA=52, CAA=257)
    let mut pkt = vec![
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00,
    ];
    pkt.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
    // 1. AAAA (28)
    pkt.extend_from_slice(b"\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x3c\x00\x10");
    pkt.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    // 2. MX (15)
    pkt.extend_from_slice(b"\xc0\x0c\x00\x0f\x00\x01\x00\x00\x00\x3c\x00\x04\x00\x0a\xc0\x0c");
    // 3. TXT (16)
    pkt.extend_from_slice(b"\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x3c\x00\x08\x03v=1\x03abc");
    // 4. SRV (33)
    pkt.extend_from_slice(
        b"\xc0\x0c\x00\x21\x00\x01\x00\x00\x00\x3c\x00\x08\x00\x01\x00\x02\x01\xbb\xc0\x0c",
    );
    // 5. DS (43)
    pkt.extend_from_slice(
        b"\xc0\x0c\x00\x2b\x00\x01\x00\x00\x00\x3c\x00\x06\x30\x39\x08\x02\xab\xcd",
    );
    // 6. TLSA (52)
    pkt.extend_from_slice(b"\xc0\x0c\x00\x34\x00\x01\x00\x00\x00\x3c\x00\x05\x03\x01\x01\xff\x00");
    // 7. CAA (257)
    pkt.extend_from_slice(
        b"\xc0\x0c\x01\x01\x00\x01\x00\x00\x00\x3c\x00\x12\x00\x05issueletsencrypt",
    );

    let decoded = decode_wire_to_json(&pkt).unwrap();
    let ans = decoded.answer.unwrap();
    assert_eq!(ans.len(), 7);
    assert_eq!(ans[0].data, "2001:db8::1");
    assert_eq!(ans[1].data, "10 example.com");
    assert_eq!(ans[2].data, "v=1 abc");
    assert_eq!(ans[3].data, "1 2 443 example.com");
    assert_eq!(ans[4].data, "12345 8 2 abcd");
    assert_eq!(ans[5].data, "3 1 1 ff00");
    assert_eq!(ans[6].data, "0 issue \"letsencrypt\"");
}

#[test]
fn encodes_json_query_params_and_decodes_soa_sshfp_dnskey() {
    assert_eq!(format_rfc3597_rdata(&[]), "\\# 0");
    assert!(decode_wire_to_json(&[0u8; 5]).is_err());

    // Error branches of encode_json_query_to_wire
    assert!(encode_json_query_to_wire(&JsonDnsQueryParams::default()).is_err());
    let long_name = format!("{}.com", "a".repeat(251));
    assert!(encode_json_query_to_wire(&JsonDnsQueryParams {
        name: long_name,
        ..Default::default()
    })
    .is_err());
    assert!(encode_json_query_to_wire(&JsonDnsQueryParams {
        name: "a..b.com".into(),
        ..Default::default()
    })
    .is_err());

    // Valid IPv4 and IPv6 ECS in encode_json_query_to_wire
    let q_v4 = encode_json_query_to_wire(&JsonDnsQueryParams {
        name: "example.com.".into(),
        qtype: Some(1),
        cd: true,
        do_bit: true,
        edns_client_subnet: Some("198.51.100.0/24".into()),
    })
    .unwrap();
    assert!(q_v4.len() > 29);

    let q_v6 = encode_json_query_to_wire(&JsonDnsQueryParams {
        name: "example.com".into(),
        qtype: Some(28),
        cd: false,
        do_bit: false,
        edns_client_subnet: Some("2606:4700::".into()),
    })
    .unwrap();
    assert!(q_v6.len() > 29);

    // Decode CNAME (5), SOA (6), SSHFP (44), DNSKEY (48), and truncated SOA/CAA fallback
    let mut pkt = vec![
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00,
    ];
    pkt.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
    // 1. CNAME (5)
    pkt.extend_from_slice(b"\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x3c\x00\x02\xc0\x0c");
    // 2. SOA (6) valid (mname=\xc0\x0c, rname=\xc0\x0c, + 20 bytes)
    pkt.extend_from_slice(b"\xc0\x0c\x00\x06\x00\x01\x00\x00\x00\x3c\x00\x18\xc0\x0c\xc0\x0c");
    pkt.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5]);
    // 3. SOA (6) short fallback
    pkt.extend_from_slice(b"\xc0\x0c\x00\x06\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x0c\xc0\x0c");
    // 4. SSHFP (44)
    pkt.extend_from_slice(b"\xc0\x0c\x00\x2c\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x02\xaa\xbb");
    // 5. DNSKEY (48)
    pkt.extend_from_slice(
        b"\xc0\x0c\x00\x30\x00\x01\x00\x00\x00\x3c\x00\x06\x01\x01\x03\x0d\xff\xff",
    );
    // 6. CAA (257) invalid tag_len fallback
    pkt.extend_from_slice(b"\xc0\x0c\x01\x01\x00\x01\x00\x00\x00\x3c\x00\x03\x00\x09x");

    let decoded = decode_wire_to_json(&pkt).unwrap();
    let ans = decoded.answer.unwrap();
    assert_eq!(ans.len(), 6);
    assert_eq!(ans[0].data, "example.com");
    assert_eq!(ans[1].data, "example.com example.com 1 2 3 4 5");
    assert!(ans[2].data.starts_with("\\# 4"));
    assert_eq!(ans[3].data, "1 2 aabb");
    assert!(ans[4].data.starts_with("257 3 13 "));
    assert!(ans[5].data.starts_with("\\# 3"));
}

// =============================================================================
// Unit tests for src/dns/odoh.rs
// =============================================================================
#[test]
fn odoh_key_ring_previous_key_grace_and_stale_key_rejection() {
    let key1 = OdohActiveKey::generate().unwrap();
    let key2 = OdohActiveKey::generate().unwrap();
    let key3 = OdohActiveKey::generate().unwrap();
    assert!(format!("{key1:?}").contains("OdohActiveKey"));

    // Encrypt a query using key1 (which will become `previous` after rotation)
    let mut configs_bytes = Bytes::from(key1.serialized_configs());
    let configs = ObliviousDoHConfigs::deserialize(&mut configs_bytes).unwrap();
    let client_cfg = configs.into_iter().next().unwrap().into();
    let plain_q = ObliviousDoHMessagePlaintext::new(b"\x12\x34query", 0);
    let mut rng = rand::rng();
    let (enc_q, _cli_secret) = odoh_rs::encrypt_query(&plain_q, &client_cfg, &mut rng).unwrap();
    let mut wire_q = Vec::new();
    enc_q.serialize(&mut wire_q).unwrap();

    // Ring where `current` is key2 and `previous` is key1: should decrypt via `previous`!
    let ring = OdohKeyRing {
        current: key2,
        previous: Some(key1),
    };
    let (decrypted, session) = ring.open_query(wire_q.clone()).unwrap();
    assert_eq!(decrypted, b"\x12\x34query");
    let sealed = session.seal_response(vec![0u8; 32]).unwrap();
    assert!(!sealed.is_empty());

    // Ring with only key3 rejects query encrypted for key1 with OdohStaleKey
    let stale_ring = OdohKeyRing {
        current: key3.clone(),
        previous: None,
    };
    assert!(matches!(
        stale_ring.open_query(wire_q.clone()),
        Err(DohError::OdohStaleKey)
    ));
    assert!(matches!(
        key3.open_query(wire_q),
        Err(DohError::OdohStaleKey)
    ));
    assert!(key3.open_query(vec![0xff, 0x00]).is_err());
}

// =============================================================================
// Unit tests for src/dns/wire.rs
// =============================================================================
fn sample_wire_query() -> Vec<u8> {
    let mut pkt = vec![
        0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    pkt.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
    pkt
}

#[test]
fn edns0_padding_aligns_to_468_bytes_with_zero_octets() {
    let mut pkt = sample_wire_query();
    apply_edns0_padding(&mut pkt).unwrap();
    assert_eq!(pkt.len() % RESPONSE_PADDING_BLOCK_SIZE, 0);
    assert_eq!(arcount(&pkt), 1);
    assert_eq!(*pkt.last().unwrap(), 0x00);
}

#[test]
fn rejects_response_packet_or_axfr_as_query() {
    let mut qr1 = sample_wire_query();
    qr1[2] |= 0x80; // Set QR=1
    assert!(validate_and_parse_query(&qr1).is_err());

    let mut axfr = vec![
        0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    axfr.extend_from_slice(b"\x07example\x03com\x00\x00\xfc\x00\x01"); // QTYPE 252 (AXFR)
    assert!(validate_and_parse_query(&axfr).is_err());
}

#[test]
fn synthesizes_and_parses_rfc8914_ede_response() {
    let q = sample_wire_query();
    let resp = build_policy_response(
        &q,
        RCODE_NXDOMAIN,
        false,
        Some((EDE_BLOCKED, "Blocked by Daviante Enterprise Policy")),
        60,
    )
    .unwrap();
    assert_eq!(rcode(&resp), RCODE_NXDOMAIN);
    let edes = extract_ede_options(&resp);
    assert_eq!(
        edes,
        vec![(
            EDE_BLOCKED,
            "Blocked by Daviante Enterprise Policy".to_string()
        )]
    );
}

#[test]
fn wire_validation_ttl_opt_and_null_ip_edge_cases() {
    // Short packet and QDCOUNT=0
    assert!(validate_and_parse_query(&[0u8; 8]).is_err());
    let mut qd0 = sample_wire_query();
    qd0[5] = 0;
    assert!(validate_and_parse_query(&qd0).is_err());

    // Compression pointer loop detection
    let mut loop_pkt = vec![
        0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x0c, 0x00,
        0x01, 0x00, 0x01,
    ];
    assert!(validate_and_parse_query(&loop_pkt).is_err());
    loop_pkt[13] = 0x50; // Out-of-bounds pointer
    assert!(validate_and_parse_query(&loop_pkt).is_err());

    // NullIp policy responses for A and AAAA
    let q_a = sample_wire_query();
    let null_a = build_policy_response(&q_a, RCODE_NOERROR, true, None, 120).unwrap();
    assert_eq!(ancount(&null_a), 1);
    assert_eq!(compute_response_ttl(&null_a, 10, 3600, 60).unwrap(), 120);

    let mut q_aaaa = vec![
        0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    q_aaaa.extend_from_slice(b"\x07example\x03com\x00\x00\x1c\x00\x01");
    let null_aaaa = build_policy_response(&q_aaaa, RCODE_NOERROR, true, None, 90).unwrap();
    assert_eq!(ancount(&null_aaaa), 1);

    // ensure_edns0_max_payload and strip_opt_record
    let mut pkt = sample_wire_query();
    ensure_edns0_max_payload(&mut pkt, 1232).unwrap();
    // Second call updates existing OPT record
    ensure_edns0_max_payload(&mut pkt, 1400).unwrap();
    assert_eq!(arcount(&pkt), 1);
    finalize_wire_response_for_client(&mut pkt, false);
    assert_eq!(arcount(&pkt), 0);

    // matches_response_question checks
    let mut resp = null_a;
    assert!(matches_response_question(&resp, "example.com", 1, 1));
    assert!(!matches_response_question(&resp, "other.com", 1, 1));
    assert!(!matches_response_question(&resp, "example.com", 28, 1));
    resp[2] &= 0x7f; // Clear QR bit
    assert!(!matches_response_question(&resp, "example.com", 1, 1));
}

#[test]
fn wire_malformed_packets_edns_options_and_ttl_decrement_errors() {
    // Oversized query > MAX_DNS_QUERY_LEN and non-zero OPCODE
    assert!(validate_and_parse_query(&vec![0u8; MAX_DNS_QUERY_LEN + 1]).is_err());
    let mut bad_op = sample_wire_query();
    bad_op[2] |= 0x08; // OPCODE=1
    assert!(validate_and_parse_query(&bad_op).is_err());

    // Truncated question QTYPE/QCLASS (name ends right at packet boundary)
    let trunc_q = vec![
        0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    assert!(validate_and_parse_query(&trunc_q).is_err());

    // Invalid label compression bits (0x40) in decode_name & skip_name
    let mut bad_bits = sample_wire_query();
    bad_bits[12] = 0x40;
    assert!(validate_and_parse_query(&bad_bits).is_err());
    assert!(skip_name(&bad_bits, 12).is_err());
    assert!(skip_name(&[0xc0], 0).is_err());

    // Query with EDNS0 PADDING option + unknown option, then duplicate OPT record
    let mut q_pad = sample_wire_query();
    apply_edns0_padding(&mut q_pad).unwrap();
    let parsed = validate_and_parse_query(&q_pad).unwrap();
    assert!(parsed.has_edns0 && parsed.has_padding);

    // Append a second OPT record -> duplicate OPT error in both validate_and_parse_query and ensure_edns0_max_payload
    append_empty_opt_record(&mut q_pad, 1232).unwrap();
    assert!(validate_and_parse_query(&q_pad).is_err());
    assert!(ensure_edns0_max_payload(&mut q_pad, 1232).is_err());

    // Truncated EDNS0 option & option length exceeding RDLENGTH
    let mut bad_opt = sample_wire_query();
    let off = append_empty_opt_record(&mut bad_opt, 1232).unwrap();
    write_u16_be(&mut bad_opt, off + 8, 2).unwrap();
    bad_opt.extend_from_slice(&[0x00, 0x0c]); // Only 2 bytes in RDATA (< 4)
    assert!(validate_and_parse_query(&bad_opt).is_err());
    write_u16_be(&mut bad_opt, off + 8, 4).unwrap();
    bad_opt.extend_from_slice(&[0x00, 0x10]); // opt_len = 16 > remaining 0
    assert!(validate_and_parse_query(&bad_opt).is_err());

    // decrement_wire_ttls, ensure_edns0_max_payload, and strip_opt_record on response with Answer RR
    let q_a = sample_wire_query();
    let mut ans = build_policy_response(&q_a, RCODE_NOERROR, true, None, 120).unwrap();
    ensure_edns0_max_payload(&mut ans, 1232).unwrap();
    decrement_wire_ttls(&mut ans, 20).unwrap();
    assert_eq!(compute_response_ttl(&ans, 0, 3600, 10).unwrap(), 100);
    strip_opt_record(&mut ans).unwrap();
    assert_eq!(arcount(&ans), 0);

    // decrement_wire_ttls error branches on truncated RR header and truncated RDATA
    let mut trunc_rr = ans.clone();
    trunc_rr.truncate(33); // Inside Answer RR header
    assert!(decrement_wire_ttls(&mut trunc_rr, 5).is_err());
    let mut trunc_rdata = ans;
    trunc_rdata.pop(); // Inside Answer RR RDATA
    assert!(decrement_wire_ttls(&mut trunc_rdata, 5).is_err());
}
