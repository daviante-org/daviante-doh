//! Unit tests for `src/lib.rs`, `src/cache.rs`, `src/error.rs`, `src/metrics.rs`,
//! `src/tls.rs`, `src/policy/mod.rs`, and `src/upstream/mod.rs`.

use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use daviante_doh::cache::{CacheKey, DnsCache};
use daviante_doh::error::DohError;
use daviante_doh::metrics::DohMetrics;
use daviante_doh::policy::{BlockAction, DomainPolicy, IpRateLimiter};
use daviante_doh::upstream::{
    exchange_dns_over_tcp_stream, query_upstream_tcp, resolve_upstream, UpstreamSet,
    MAX_IDLE_TCP_PER_UPSTREAM,
};
use daviante_doh::wire::{
    rcode, read_u32_be, write_u16_be, RCODE_FORMERR, RCODE_NOERROR, RCODE_NOTIMP, RCODE_NXDOMAIN,
    RCODE_REFUSED, RCODE_SERVFAIL, RESPONSE_PADDING_BLOCK_SIZE,
};
use daviante_doh::{ClientIpLogMode, DohConfig, PerIpConnLimiter};
use hyper::StatusCode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::time::Instant;

// =============================================================================
// Unit tests for src/lib.rs
// =============================================================================
#[test]
fn client_ip_log_mode_and_config_validation() {
    assert_eq!(
        ClientIpLogMode::from_str_name("none").unwrap(),
        ClientIpLogMode::None
    );
    assert_eq!(
        ClientIpLogMode::from_str_name("truncated").unwrap(),
        ClientIpLogMode::Truncated
    );
    assert_eq!(
        ClientIpLogMode::from_str_name("full").unwrap(),
        ClientIpLogMode::Full
    );
    assert!(ClientIpLogMode::from_str_name("invalid").is_err());
    assert_eq!(ClientIpLogMode::None.as_str(), "none");
    assert_eq!(ClientIpLogMode::Truncated.as_str(), "truncated");
    assert_eq!(ClientIpLogMode::Full.as_str(), "full");

    let v4_bind = DohConfig::default_local_bind_for("9.9.9.9:53".parse().unwrap());
    assert!(v4_bind.is_ipv4());
    let v6_bind = DohConfig::default_local_bind_for("[2620:fe::fe]:53".parse().unwrap());
    assert!(v6_bind.is_ipv6());

    let base = DohConfig::default();
    assert!(base.validate().is_ok());

    let mut c = base.clone();
    c.upstream_addresses = vec!["1.1.1.1:53".parse().unwrap()];
    assert_eq!(c.effective_upstreams().len(), 1);

    for invalid in [
        DohConfig {
            max_clients: 0,
            ..base.clone()
        },
        DohConfig {
            max_concurrent_streams: 0,
            ..base.clone()
        },
        DohConfig {
            timeout: Duration::from_millis(100),
            ..base.clone()
        },
        DohConfig {
            path: "dns-query".into(),
            ..base.clone()
        },
        DohConfig {
            odoh_configs_path: "well-known".into(),
            ..base.clone()
        },
        DohConfig {
            health_path: "healthz".into(),
            ..base.clone()
        },
        DohConfig {
            metrics_path: "metrics".into(),
            ..base.clone()
        },
        DohConfig {
            ecs_prefix_v4: 33,
            ..base.clone()
        },
        DohConfig {
            ecs_prefix_v6: 129,
            ..base.clone()
        },
        DohConfig {
            rate_limit_v6_prefix: 129,
            ..base.clone()
        },
        DohConfig {
            cors_allow_origin: "   ".into(),
            ..base
        },
    ] {
        assert!(invalid.validate().is_err());
    }
}

#[test]
fn per_ip_conn_limiter_ipv6_prefix_and_drop() {
    let limiter = PerIpConnLimiter::new(1, 64);
    let metrics = DohMetrics::new();
    let ip1: IpAddr = "2001:db8:1234:5678::1".parse().unwrap();
    let ip2: IpAddr = "2001:db8:1234:5678::99".parse().unwrap();

    let g1 = limiter.try_acquire(ip1, metrics.clone());
    assert!(g1.is_some());
    // Same /64 subnet -> rejected while g1 is held
    assert!(limiter.try_acquire(ip2, metrics.clone()).is_none());
    drop(g1);
    // After dropping g1, acquisition succeeds again
    assert!(limiter.try_acquire(ip2, metrics).is_some());
}

// =============================================================================
// Unit tests for src/cache.rs
// =============================================================================
#[test]
fn cache_hit_restores_txid_and_pads_response() {
    let cache = DnsCache::new(1024);
    let key = CacheKey {
        qname: "example.com".into(),
        qtype: 1,
        qclass: 1,
        do_bit: false,
        cd_bit: false,
    };

    let mut resp = vec![
        0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    ];
    resp.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
    resp.extend_from_slice(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x5d\xb8\xd8\x22");
    write_u16_be(&mut resp, 0, 0x1111).unwrap();

    cache.insert(key.clone(), resp, 60);
    let hit = cache.get(&key, [0xab, 0xcd]).expect("expected cache hit");
    assert_eq!(&hit.wire_bytes[0..2], &[0xab, 0xcd]);
    assert_eq!(hit.wire_bytes.len() % RESPONSE_PADDING_BLOCK_SIZE, 0);
    let rr_ttl = read_u32_be(&hit.wire_bytes, 29 + 6).unwrap();
    assert!((59..=60).contains(&rr_ttl));
}

#[test]
fn disabled_cache_and_shard_eviction() {
    let disabled = DnsCache::new(0);
    assert!(!disabled.is_enabled());
    let base_key = CacheKey {
        qname: "example.com".into(),
        qtype: 1,
        qclass: 1,
        do_bit: false,
        cd_bit: false,
    };
    disabled.insert(base_key.clone(), vec![0u8; 32], 60);
    assert!(disabled.get(&base_key, [0, 1]).is_none());

    // Tiny cache (max_entries = 1 => shard_cap = 1 per shard) to trigger shard capacity eviction
    let tiny = DnsCache::new(1);
    let mut resp = vec![
        0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    ];
    resp.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
    resp.extend_from_slice(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x5d\xb8\xd8\x22");

    for i in 0..40u16 {
        let k = CacheKey {
            qname: format!("host-{i}.example.com"),
            qtype: 1,
            qclass: 1,
            do_bit: false,
            cd_bit: false,
        };
        tiny.insert(k, resp.clone(), 60 + (i as u32));
    }

    // Inserting with ttl=0 is a no-op
    let zero_key = CacheKey {
        qname: "zero.example.com".into(),
        qtype: 1,
        qclass: 1,
        do_bit: false,
        cd_bit: false,
    };
    tiny.insert(zero_key.clone(), resp, 0);
    assert!(tiny.get(&zero_key, [0, 1]).is_none());
}

// =============================================================================
// Unit tests for src/error.rs
// =============================================================================
#[test]
fn all_error_variants_map_to_expected_http_status() {
    let cases = [
        (DohError::BadRequest("x".into()), StatusCode::BAD_REQUEST),
        (DohError::MalformedDnsPacket("x"), StatusCode::BAD_REQUEST),
        (
            DohError::OdohCryptoError("x".into()),
            StatusCode::BAD_REQUEST,
        ),
        (DohError::PayloadTooLarge, StatusCode::PAYLOAD_TOO_LARGE),
        (DohError::UriTooLong, StatusCode::URI_TOO_LONG),
        (DohError::MethodNotAllowed, StatusCode::METHOD_NOT_ALLOWED),
        (DohError::NotAcceptable, StatusCode::NOT_ACCEPTABLE),
        (
            DohError::UnsupportedMediaType,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (DohError::RateLimited, StatusCode::TOO_MANY_REQUESTS),
        (DohError::RequestTimeout, StatusCode::REQUEST_TIMEOUT),
        (DohError::UpstreamTimeout, StatusCode::GATEWAY_TIMEOUT),
        (DohError::UpstreamError("x".into()), StatusCode::BAD_GATEWAY),
        (
            DohError::Io(io::Error::other("io")),
            StatusCode::BAD_GATEWAY,
        ),
        (DohError::OdohStaleKey, StatusCode::UNAUTHORIZED),
        (
            DohError::InvalidConfig("x".into()),
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
    ];

    for (err, expected) in cases {
        assert_eq!(err.status_code(), expected);
        assert!(!err.to_string().is_empty());
    }
}

// =============================================================================
// Unit tests for src/metrics.rs
// =============================================================================
#[test]
fn records_all_status_classes_rcodes_and_counters() {
    let m = DohMetrics::new();
    m.record_status(100);
    m.record_status(200);
    m.record_status(429);
    m.record_status(502);

    m.record_rcode(RCODE_NOERROR);
    m.record_rcode(RCODE_FORMERR);
    m.record_rcode(RCODE_SERVFAIL);
    m.record_rcode(RCODE_NXDOMAIN);
    m.record_rcode(RCODE_NOTIMP);
    m.record_rcode(RCODE_REFUSED);
    m.record_rcode(99);

    m.inc_cache_hit();
    m.inc_cache_miss();
    m.inc_policy_blocked();
    m.inc_rate_limited();
    m.inc_upstream_udp();
    m.inc_upstream_tcp();
    m.inc_upstream_failure();
    m.inc_active_connections();
    m.dec_active_connections();

    let text = m.render_prometheus();
    assert!(text.contains("daviante_doh_responses_total{status=\"5xx\"} 1"));
    assert!(text.contains("daviante_doh_responses_by_rcode_total{rcode=\"FORMERR\"} 1"));
    assert!(text.contains("daviante_doh_responses_by_rcode_total{rcode=\"NOTIMP\"} 1"));
    assert!(text.contains("daviante_doh_responses_by_rcode_total{rcode=\"REFUSED\"} 1"));
    assert!(text.contains("daviante_doh_responses_by_rcode_total{rcode=\"OTHER\"} 1"));
    assert!(text.contains("daviante_doh_rate_limited_total 1"));
}

// =============================================================================
// Unit tests for src/tls.rs
// =============================================================================
#[cfg(feature = "tls")]
#[tokio::test]
async fn tls_min_version_and_pinned_verifier_methods() {
    use daviante_doh::tls::{
        build_pinned_healthcheck_connector, build_tls_acceptor, load_certs, load_private_key,
        PinnedLeafCertVerifier, TlsMinVersion,
    };
    use tokio::net::TcpListener;
    use tokio_rustls::rustls::client::danger::ServerCertVerifier;
    use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use tokio_rustls::rustls::{ClientConfig, ServerConfig};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    assert_eq!(
        TlsMinVersion::from_str_name("1.2").unwrap(),
        TlsMinVersion::Tls12
    );
    assert_eq!(
        TlsMinVersion::from_str_name("tls1.3").unwrap(),
        TlsMinVersion::Tls13
    );
    assert!(TlsMinVersion::from_str_name("1.0").is_err());
    assert_eq!(TlsMinVersion::Tls12.as_str(), "1.2");
    assert_eq!(TlsMinVersion::Tls13.as_str(), "1.3");

    let (cert_path, key_path) = crate::tls::write_temp_cert_and_key("unit-tls");
    let dir = std::env::temp_dir();
    let empty_path = dir.join(format!(
        "daviante-doh-test-empty-{}.pem",
        std::process::id()
    ));
    std::fs::write(&empty_path, b"").unwrap();

    assert!(build_tls_acceptor(&cert_path, &key_path).is_ok());
    assert!(build_pinned_healthcheck_connector(&cert_path).is_ok());
    assert!(load_certs(&empty_path).is_err());
    assert!(load_private_key(&empty_path).is_err());
    assert!(load_certs(&dir.join("daviante-doh-missing-cert-999999.pem")).is_err());
    assert!(load_private_key(&dir.join("daviante-doh-missing-key-999999.pem")).is_err());

    let mut certs = load_certs(&cert_path).unwrap();
    let leaf = certs.remove(0);
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let verifier = Arc::new(PinnedLeafCertVerifier {
        pinned_leaf: leaf.clone(),
        provider: Arc::clone(&provider),
    });
    assert!(format!("{verifier:?}").contains("PinnedLeafCertVerifier"));
    assert!(!verifier.supported_verify_schemes().is_empty());

    let sname = ServerName::try_from("localhost").unwrap();
    assert!(verifier
        .verify_server_cert(&leaf, &[], &sname, &[], UnixTime::now())
        .is_ok());
    let wrong_leaf = CertificateDer::from(vec![9, 9, 9, 9]);
    assert!(verifier
        .verify_server_cert(&wrong_leaf, &[], &sname, &[], UnixTime::now())
        .is_err());

    // Exercise verify_tls13_signature via build_pinned_healthcheck_connector against a TLS 1.3 acceptor
    let acceptor_13 = build_tls_acceptor(&cert_path, &key_path).unwrap();
    let connector_13 = build_pinned_healthcheck_connector(&cert_path).unwrap();
    let listener_13 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_13 = listener_13.local_addr().unwrap();
    let srv_13 = tokio::spawn(async move {
        let (stream, _) = listener_13.accept().await.unwrap();
        let _ = acceptor_13.accept(stream).await.unwrap();
    });
    let cli_stream_13 = tokio::net::TcpStream::connect(addr_13).await.unwrap();
    let _ = connector_13
        .connect(ServerName::try_from("localhost").unwrap(), cli_stream_13)
        .await
        .unwrap();
    srv_13.await.unwrap();

    // Exercise verify_tls12_signature via a TLS 1.2 client config with PinnedLeafCertVerifier
    let server_cfg_12 = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![leaf], load_private_key(&key_path).unwrap())
        .unwrap();
    let acceptor_12 = TlsAcceptor::from(Arc::new(server_cfg_12));
    let client_cfg_12 = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS12])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let connector_12 = TlsConnector::from(Arc::new(client_cfg_12));
    let listener_12 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_12 = listener_12.local_addr().unwrap();
    let srv_12 = tokio::spawn(async move {
        let (stream, _) = listener_12.accept().await.unwrap();
        let _ = acceptor_12.accept(stream).await.unwrap();
    });
    let cli_stream_12 = tokio::net::TcpStream::connect(addr_12).await.unwrap();
    let _ = connector_12
        .connect(ServerName::try_from("localhost").unwrap(), cli_stream_12)
        .await
        .unwrap();
    srv_12.await.unwrap();

    let _ = std::fs::remove_file(cert_path);
    let _ = std::fs::remove_file(key_path);
    let _ = std::fs::remove_file(empty_path);
}

// =============================================================================
// Unit tests for src/policy/mod.rs
// =============================================================================
#[test]
fn domain_policy_allowlist_overrides_blocklist_and_matches_subdomains() {
    let policy = DomainPolicy::from_lists(
        ["safe.ads.example.com"],
        ["0.0.0.0 ads.example.com", "*.Telemetry.Bad.org"],
        BlockAction::Nxdomain,
    );
    assert!(policy.is_blocked("ads.example.com"));
    assert!(policy.is_blocked("tracker.ads.example.com"));
    assert!(!policy.is_blocked("safe.ads.example.com"));
    assert!(policy.is_blocked("sub.telemetry.bad.org"));
    assert!(!policy.is_blocked("example.com"));
}

#[test]
fn per_ip_rate_limiter_enforces_burst_bound() {
    let limiter = IpRateLimiter::new(1, 2);
    let ip: Option<IpAddr> = Some("198.51.100.42".parse().unwrap());
    assert!(limiter.check_and_consume(ip));
    assert!(limiter.check_and_consume(ip));
    assert!(!limiter.check_and_consume(ip));
}

#[test]
fn block_actions_file_loading_and_response_synthesis() {
    assert_eq!(
        BlockAction::from_str_name("refused").unwrap(),
        BlockAction::Refused
    );
    assert_eq!(
        BlockAction::from_str_name("null").unwrap(),
        BlockAction::NullIp
    );
    assert_eq!(
        BlockAction::from_str_name("sinkhole").unwrap(),
        BlockAction::NullIp
    );
    assert_eq!(BlockAction::Nxdomain.as_str(), "nxdomain");
    assert_eq!(BlockAction::Refused.as_str(), "refused");
    assert_eq!(BlockAction::NullIp.as_str(), "null");
    assert!(BlockAction::from_str_name("invalid").is_err());

    let tmp_allow = std::env::temp_dir().join("daviante_doh_test_allow.txt");
    let tmp_block = std::env::temp_dir().join("daviante_doh_test_block.txt");
    std::fs::write(
        &tmp_allow,
        "# comment\n127.0.0.1 localhost\nallowed.bad.example.com\n",
    )
    .unwrap();
    std::fs::write(
        &tmp_block,
        "# blocklist\n0.0.0.0 bad.example.com\n*.wild.example.com\n",
    )
    .unwrap();

    let pol_refused =
        DomainPolicy::from_files(Some(&tmp_allow), Some(&tmp_block), BlockAction::Refused).unwrap();
    assert!(pol_refused.is_blocked("bad.example.com"));
    assert!(!pol_refused.is_blocked("allowed.bad.example.com"));

    let mut q_a = vec![
        0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    q_a.extend_from_slice(b"\x03bad\x07example\x03com\x00\x00\x01\x00\x01");
    let r_ref = pol_refused.build_blocked_response(&q_a, 60).unwrap();
    assert_eq!(rcode(&r_ref), RCODE_REFUSED);

    let pol_null = DomainPolicy::from_lists(
        std::iter::empty::<&str>(),
        ["bad.example.com"],
        BlockAction::NullIp,
    );
    let r_null_a = pol_null.build_blocked_response(&q_a, 60).unwrap();
    assert_eq!(rcode(&r_null_a), RCODE_NOERROR);

    let mut q_aaaa = vec![
        0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    q_aaaa.extend_from_slice(b"\x03bad\x07example\x03com\x00\x00\x1c\x00\x01");
    let r_null_aaaa = pol_null.build_blocked_response(&q_aaaa, 60).unwrap();
    assert_eq!(rcode(&r_null_aaaa), RCODE_NOERROR);

    let _ = std::fs::remove_file(&tmp_allow);
    let _ = std::fs::remove_file(&tmp_block);
}

// =============================================================================
// Unit tests for src/upstream/mod.rs
// =============================================================================
fn sample_upstream_query() -> Vec<u8> {
    let mut q = vec![
        0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    q.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
    q
}

#[tokio::test]
async fn resolve_upstream_servfail_and_pooled_tcp_reuse() {
    // 1. UDP upstream that returns SERVFAIL (RCODE=2) -> exercises resolve_upstream & recoverable_err branch
    let udp_servfail = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sf_addr = udp_servfail.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        if let Ok((n, peer)) = udp_servfail.recv_from(&mut buf).await {
            let mut resp = buf[..n].to_vec();
            resp[2] = 0x81;
            resp[3] = 0x82; // QR=1, RCODE=2 (SERVFAIL)
            resp[10] = 0;
            resp[11] = 0; // ARCOUNT=0
            resp.truncate(29);
            let _ = udp_servfail.send_to(&resp, peer).await;
        }
    });

    let cfg = DohConfig {
        server_address: sf_addr,
        local_bind_address: "127.0.0.1:0".parse().unwrap(),
        err_ttl: 5,
        ..DohConfig::default()
    };
    let sem = Arc::new(Semaphore::new(8));
    let metrics = DohMetrics::new();
    let res = resolve_upstream(
        sample_upstream_query(),
        Some("198.51.100.9".parse().unwrap()),
        &cfg,
        &sem,
        &metrics,
        Instant::now() + Duration::from_secs(3),
    )
    .await
    .unwrap();
    assert!(!res.cacheable);
    assert_eq!(res.cache_ttl, 5);

    // 2. TCP connection pool overflow eviction & pooled stream reuse in query_upstream_tcp
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = tcp_listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut srv, _)) = tcp_listener.accept().await {
            tokio::spawn(async move {
                let mut len_buf = [0u8; 2];
                while srv.read_exact(&mut len_buf).await.is_ok() {
                    let qlen = u16::from_be_bytes(len_buf) as usize;
                    let mut qbuf = vec![0u8; qlen];
                    if srv.read_exact(&mut qbuf).await.is_err() {
                        break;
                    }
                    qbuf[2] = 0x81;
                    qbuf[3] = 0x80;
                    let rlen = (qbuf.len() as u16).to_be_bytes();
                    let _ = srv.write_all(&rlen).await;
                    let _ = srv.write_all(&qbuf).await;
                }
            });
        }
    });

    let set = UpstreamSet::default();
    for _ in 0..=MAX_IDLE_TCP_PER_UPSTREAM {
        let s = TcpStream::connect(tcp_addr).await.unwrap();
        set.return_pooled_tcp(tcp_addr, s);
    }
    let q = sample_upstream_query();
    let r1 = query_upstream_tcp(&q, [0xab, 0xcd], "example.com", 1, 1, tcp_addr, &set)
        .await
        .unwrap();
    assert_eq!(&r1[0..2], &[0xab, 0xcd]);
    // Second call reuses the pooled connection returned by the first call
    let r2 = query_upstream_tcp(&q, [0xab, 0xcd], "example.com", 1, 1, tcp_addr, &set)
        .await
        .unwrap();
    assert_eq!(&r2[0..2], &[0xab, 0xcd]);
}

#[tokio::test]
async fn tcp_exchange_rejects_short_txid_and_question_mismatch() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        // Connection 1: send short 4-byte frame (< MIN_DNS_PACKET_LEN)
        if let Ok((mut s1, _)) = listener.accept().await {
            let mut hdr = [0u8; 2];
            let _ = s1.read_exact(&mut hdr).await;
            let mut q = vec![0u8; u16::from_be_bytes(hdr) as usize];
            let _ = s1.read_exact(&mut q).await;
            let _ = s1.write_all(&4u16.to_be_bytes()).await;
            let _ = s1.write_all(&[1, 2, 3, 4]).await;
        }
        // Connection 2: send mismatched TXID
        if let Ok((mut s2, _)) = listener.accept().await {
            let mut hdr = [0u8; 2];
            let _ = s2.read_exact(&mut hdr).await;
            let mut q = vec![0u8; u16::from_be_bytes(hdr) as usize];
            let _ = s2.read_exact(&mut q).await;
            q[0] ^= 0xff;
            q[2] = 0x81;
            let _ = s2.write_all(&(q.len() as u16).to_be_bytes()).await;
            let _ = s2.write_all(&q).await;
        }
        // Connection 3: send matching TXID but QR=0 (fails matches_response_question)
        if let Ok((mut s3, _)) = listener.accept().await {
            let mut hdr = [0u8; 2];
            let _ = s3.read_exact(&mut hdr).await;
            let mut q = vec![0u8; u16::from_be_bytes(hdr) as usize];
            let _ = s3.read_exact(&mut q).await;
            q[2] = 0x01; // QR=0
            let _ = s3.write_all(&(q.len() as u16).to_be_bytes()).await;
            let _ = s3.write_all(&q).await;
        }
    });

    let q = sample_upstream_query();
    let mut c1 = TcpStream::connect(addr).await.unwrap();
    assert!(
        exchange_dns_over_tcp_stream(&mut c1, &q, [0xab, 0xcd], "example.com", 1, 1)
            .await
            .is_err()
    );
    let mut c2 = TcpStream::connect(addr).await.unwrap();
    assert!(
        exchange_dns_over_tcp_stream(&mut c2, &q, [0xab, 0xcd], "example.com", 1, 1)
            .await
            .is_err()
    );
    let mut c3 = TcpStream::connect(addr).await.unwrap();
    assert!(
        exchange_dns_over_tcp_stream(&mut c3, &q, [0xab, 0xcd], "example.com", 1, 1)
            .await
            .is_err()
    );
}
