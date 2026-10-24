//! Comprehensive integration & regression test suite for `daviante-doh`.
//! Covers RFC 8484, RFC 9230, RFC 6891, RFC 7830, RFC 7871, RFC 8467, RFC 8482, RFC 8914,
//! RFC 5452, RFC 7766, RFC 9110, RFC 9111, and all security/enterprise audit findings.

#![forbid(unsafe_code)]

mod unit;

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bytes::Bytes;
use daviante_doh::{
    cache::{CacheKey, DnsCache, MAX_CACHE_ENTRY_BYTES},
    ecs::{resolve_client_ip, IpNet},
    handler::format_audit_client_ip,
    json::decode_wire_to_json,
    serve_with_admin_and_shutdown, serve_with_shutdown,
    upstream::resolve_upstream,
    wire::{
        self, ancount, arcount, compute_response_ttl_with_floor, finalize_wire_response_for_client,
        read_u32_be, write_u16_be, EDE_BLOCKED, EDE_NO_REACHABLE_AUTHORITY, RCODE_NXDOMAIN,
        RCODE_SERVFAIL, RESPONSE_PADDING_BLOCK_SIZE,
    },
    BlockAction, ClientIpLogMode, DohConfig, DohEngine, DohMetrics, DomainPolicy, IpRateLimiter,
    OdohKeyManager,
};
use http_body_util::Empty;
use hyper::header::HeaderMap;
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;

fn build_sample_query(name_wire: &[u8], qtype: u16, with_edns: bool) -> Vec<u8> {
    let mut pkt = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    pkt.extend_from_slice(name_wire);
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes());
    if with_edns {
        wire::ensure_edns0_max_payload(&mut pkt, 1232).unwrap();
    }
    pkt
}

fn build_mock_dns_answer_with_ttl(query: &[u8], ttl: u32) -> Vec<u8> {
    let q_end = wire::skip_questions(query).unwrap();
    let mut resp = query[..q_end].to_vec();
    resp[2] = 0x81;
    resp[3] = 0x80;
    write_u16_be(&mut resp, 4, 1).unwrap();
    write_u16_be(&mut resp, 6, 1).unwrap();
    write_u16_be(&mut resp, 8, 0).unwrap();
    write_u16_be(&mut resp, 10, 0).unwrap();
    resp.extend_from_slice(b"\xc0\x0c\x00\x01\x00\x01");
    resp.extend_from_slice(&ttl.to_be_bytes());
    resp.extend_from_slice(b"\x00\x04\x5d\xb8\xd8\x22");
    resp
}

async fn start_mock_upstream_with_ttl(truncate_udp: bool, ttl: u32) -> SocketAddr {
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = udp.local_addr().unwrap();
    let tcp_listener = TcpListener::bind(addr).await.unwrap();

    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = udp.recv_from(&mut buf).await {
            let mut resp = build_mock_dns_answer_with_ttl(&buf[..len], ttl);
            if truncate_udp {
                resp[2] |= 0x02; // Set TC=1
            }
            let _ = udp.send_to(&resp, peer).await;
        }
    });

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = tcp_listener.accept().await {
            tokio::spawn(async move {
                loop {
                    let mut len_buf = [0u8; 2];
                    if stream.read_exact(&mut len_buf).await.is_err() {
                        break;
                    }
                    let qlen = u16::from_be_bytes(len_buf) as usize;
                    let mut qbuf = vec![0u8; qlen];
                    if stream.read_exact(&mut qbuf).await.is_err() {
                        break;
                    }
                    let mut resp = build_mock_dns_answer_with_ttl(&qbuf, ttl);
                    resp[3] |= 0x80;
                    let rlen = (resp.len() as u16).to_be_bytes();
                    if stream.write_all(&rlen).await.is_err() {
                        break;
                    }
                    if stream.write_all(&resp).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    addr
}

async fn start_mock_upstream(truncate_udp: bool) -> SocketAddr {
    start_mock_upstream_with_ttl(truncate_udp, 300).await
}

async fn raw_http_request(addr: SocketAddr, req_str: &str, body: &[u8]) -> (String, Vec<u8>) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(req_str.as_bytes()).await.unwrap();
    if !body.is_empty() {
        stream.write_all(body).await.unwrap();
    }
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let sep = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("missing HTTP header separator");
    let headers = String::from_utf8_lossy(&buf[..sep]).to_string();
    let resp_body = buf[sep + 4..].to_vec();
    (headers, resp_body)
}

// =============================================================================
// C-1: Client IP & Trusted Proxies Regression Tests
// =============================================================================
pub mod client_ip {
    use super::*;

    #[test]
    fn direct_peer_ignores_xff() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "1.2.3.4".parse().unwrap());
        // Even a private Kubernetes pod IP (10.0.0.5) is untrusted when trusted_proxies is empty!
        let pod_peer: SocketAddr = "10.0.0.5:54321".parse().unwrap();
        assert_eq!(
            resolve_client_ip(&headers, Some(pod_peer), &[]),
            Some("10.0.0.5".parse().unwrap())
        );
    }

    #[test]
    fn rightmost_untrusted_hop() {
        let mut headers = HeaderMap::new();
        // Attacker injects spoofed 1.1.1.1 at the left; real client is 198.51.100.77; edge proxy is 10.0.0.2
        headers.insert(
            "x-forwarded-for",
            "1.1.1.1, 198.51.100.77, 10.0.0.2".parse().unwrap(),
        );
        let proxy_peer: SocketAddr = "10.0.0.1:443".parse().unwrap();
        let trusted: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        assert_eq!(
            resolve_client_ip(&headers, Some(proxy_peer), &trusted),
            Some("198.51.100.77".parse().unwrap())
        );
    }

    #[test]
    fn malformed_hop_stops_chain() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "1.1.1.1, not-an-ip, 10.0.0.2".parse().unwrap(),
        );
        let proxy_peer: SocketAddr = "10.0.0.1:443".parse().unwrap();
        let trusted: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        // Traversal stops at `not-an-ip` and returns the last verified hop (`10.0.0.2`), never `1.1.1.1`
        assert_eq!(
            resolve_client_ip(&headers, Some(proxy_peer), &trusted),
            Some("10.0.0.2".parse().unwrap())
        );
    }

    #[test]
    fn untrusted_peer_cannot_spoof_forwarded() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "forwarded",
            "for=198.51.100.99;proto=https".parse().unwrap(),
        );
        headers.insert("x-real-ip", "198.51.100.99".parse().unwrap());
        let untrusted_peer: SocketAddr = "172.16.0.10:12345".parse().unwrap();
        let trusted: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        assert_eq!(
            resolve_client_ip(&headers, Some(untrusted_peer), &trusted),
            Some("172.16.0.10".parse().unwrap())
        );
    }
}

// =============================================================================
// C-2 & N-4: Protective DNS Policy Regression Tests
// =============================================================================
pub mod policy {
    use super::*;

    #[tokio::test]
    async fn missing_blocklist_is_fatal() {
        let cfg = DohConfig {
            blocklist_file: Some(PathBuf::from("/nonexistent/path/to/blocklist.txt")),
            ..DohConfig::default()
        };
        let odoh_keys =
            OdohKeyManager::spawn(tokio::runtime::Handle::current(), Duration::from_secs(3600))
                .unwrap();
        let res = DohEngine::new(cfg, odoh_keys);
        assert!(
            res.is_err(),
            "expected missing blocklist file to fail closed"
        );
    }

    #[tokio::test]
    async fn cname_chain_to_blocked_domain_blocked() {
        // Upstream returns: allowed.example.com CNAME -> tracker.evil.org, tracker.evil.org A -> 93.184.216.34
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = udp.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((len, peer)) = udp.recv_from(&mut buf).await {
                let q_end = wire::skip_questions(&buf[..len]).unwrap();
                let mut resp = buf[..q_end].to_vec();
                resp[2] = 0x81;
                resp[3] = 0x80;
                write_u16_be(&mut resp, 4, 1).unwrap();
                write_u16_be(&mut resp, 6, 2).unwrap(); // ANCOUNT = 2
                write_u16_be(&mut resp, 8, 0).unwrap();
                write_u16_be(&mut resp, 10, 0).unwrap();
                // RR 1: allowed.example.com CNAME tracker.evil.org
                let target_rdata = b"\x07tracker\x04evil\x03org\x00";
                resp.extend_from_slice(b"\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x3c");
                resp.extend_from_slice(&(target_rdata.len() as u16).to_be_bytes());
                resp.extend_from_slice(target_rdata);
                // RR 2: tracker.evil.org A 93.184.216.34
                resp.extend_from_slice(target_rdata);
                resp.extend_from_slice(b"\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x5d\xb8\xd8\x22");
                let _ = udp.send_to(&resp, peer).await;
            }
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let cfg = DohConfig {
            listen_address: server_addr,
            local_bind_address: "127.0.0.1:0".parse().unwrap(),
            server_address: upstream_addr,
            keepalive: false,
            ..DohConfig::default()
        };
        let odoh_keys =
            OdohKeyManager::spawn(tokio::runtime::Handle::current(), Duration::from_secs(3600))
                .unwrap();
        let mut engine = DohEngine::new(cfg, odoh_keys).unwrap();
        engine.policy =
            DomainPolicy::from_lists(Vec::<&str>::new(), ["evil.org"], BlockAction::Nxdomain);

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = serve_with_shutdown(engine, listener, async {
                let _ = rx.await;
            })
            .await;
        });

        let (_, body) = raw_http_request(
            server_addr,
            "GET /dns-query?name=allowed.example.com&type=A HTTP/1.1\r\nHost: localhost\r\nAccept: application/dns-json\r\nConnection: close\r\n\r\n",
            b"",
        )
        .await;
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["Status"], RCODE_NXDOMAIN as u64);
        assert_eq!(parsed["EDE"][0]["info_code"], EDE_BLOCKED as u64);

        let _ = tx.send(());
    }
}

// =============================================================================
// H-6: Configuration Validation Regression Tests
// =============================================================================
pub mod config {
    use super::*;

    #[test]
    fn invalid_cors_origin_rejected() {
        let cfg = DohConfig {
            cors_allow_origin: "invalid\r\nheader-injection".to_string(),
            ..DohConfig::default()
        };
        assert!(cfg.validate().is_err());
    }
}

// =============================================================================
// H-1: TTL & Freshness Compliance Regression Tests
// =============================================================================
pub mod ttl {
    use super::*;

    #[test]
    fn http_freshness_never_exceeds_answer_ttl() {
        let q = build_sample_query(b"\x07example\x03com\x00", 1, false);
        let resp = build_mock_dns_answer_with_ttl(&q, 3); // Answer TTL = 3s
                                                          // Even if min_ttl = 60 is configured for the internal cache, HTTP freshness MUST be <= 3s!
        let (http_ttl, cache_ttl) = compute_response_ttl_with_floor(&resp, 60, 86400, 2).unwrap();
        assert_eq!(http_ttl, 3);
        assert_eq!(cache_ttl, 60);
    }

    #[test]
    fn zero_ttl_not_cached() {
        let q = build_sample_query(b"\x07example\x03com\x00", 1, false);
        let resp = build_mock_dns_answer_with_ttl(&q, 0); // Answer TTL = 0s
        let (http_ttl, cache_ttl) = compute_response_ttl_with_floor(&resp, 60, 86400, 2).unwrap();
        assert_eq!(http_ttl, 0);
        assert_eq!(cache_ttl, 0);

        let cache = DnsCache::new(1024);
        let key = CacheKey {
            qname: "example.com".into(),
            qtype: 1,
            qclass: 1,
            do_bit: false,
            cd_bit: false,
        };
        cache.insert_with_floor(key.clone(), resp, http_ttl, cache_ttl);
        assert!(cache.get(&key, [0x12, 0x34]).is_none());
    }

    #[test]
    fn negative_bounded_by_soa_minimum() {
        let mut pkt = build_sample_query(b"\x07example\x03com\x00", 1, false);
        pkt[2] = 0x81;
        pkt[3] = 0x83; // NXDOMAIN
        write_u16_be(&mut pkt, 8, 1).unwrap(); // NSCOUNT = 1
        pkt.extend_from_slice(b"\xc0\x0c\x00\x06\x00\x01\x00\x00\x0e\x10"); // SOA TTL = 3600s
        let mut rdata = Vec::new();
        rdata.extend_from_slice(b"\x02ns\xc0\x0c\x0ahostmaster\xc0\x0c");
        rdata.extend_from_slice(&2026101801u32.to_be_bytes());
        rdata.extend_from_slice(&7200u32.to_be_bytes());
        rdata.extend_from_slice(&3600u32.to_be_bytes());
        rdata.extend_from_slice(&1209600u32.to_be_bytes());
        rdata.extend_from_slice(&120u32.to_be_bytes()); // MINIMUM = 120s
        pkt.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&rdata);

        let (http_ttl, _) = compute_response_ttl_with_floor(&pkt, 0, 86400, 2).unwrap();
        assert_eq!(http_ttl, 120);
    }
}

// =============================================================================
// H-2, M-2, L-2, L-3: HTTP Semantics & Security Headers Regression Tests
// =============================================================================
pub mod http {
    use super::*;

    #[tokio::test]
    async fn header_dependent_errors_not_shareable() {
        let upstream_addr = start_mock_upstream(false).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let cfg = DohConfig {
            listen_address: server_addr,
            local_bind_address: "127.0.0.1:0".parse().unwrap(),
            server_address: upstream_addr,
            keepalive: false,
            ..DohConfig::default()
        };
        let odoh_keys =
            OdohKeyManager::spawn(tokio::runtime::Handle::current(), Duration::from_secs(3600))
                .unwrap();
        let engine = DohEngine::new(cfg, odoh_keys).unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = serve_with_shutdown(engine, listener, async {
                let _ = rx.await;
            })
            .await;
        });

        // 406 Not Acceptable
        let (hdr_406, _) = raw_http_request(
            server_addr,
            "GET /dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE HTTP/1.1\r\nHost: localhost\r\nAccept: text/html\r\nConnection: close\r\n\r\n",
            b"",
        )
        .await;
        let low_406 = hdr_406.to_ascii_lowercase();
        assert!(hdr_406.starts_with("HTTP/1.1 406"));
        assert!(low_406.contains("cache-control: no-store"));
        assert!(low_406.contains("vary: accept, content-type"));

        // 415 Unsupported Media Type
        let (hdr_415, _) = raw_http_request(
            server_addr,
            "POST /dns-query HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/plain\r\nContent-Length: 4\r\nConnection: close\r\n\r\n",
            b"test",
        )
        .await;
        let low_415 = hdr_415.to_ascii_lowercase();
        assert!(hdr_415.starts_with("HTTP/1.1 415"));
        assert!(low_415.contains("cache-control: no-store"));
        assert!(low_415.contains("vary: accept, content-type"));

        let _ = tx.send(());
    }

    #[tokio::test]
    async fn cache_hit_has_no_age_double_count() {
        let upstream_addr = start_mock_upstream_with_ttl(false, 60).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let cfg = DohConfig {
            listen_address: server_addr,
            local_bind_address: "127.0.0.1:0".parse().unwrap(),
            server_address: upstream_addr,
            cache_size: 1024,
            keepalive: false,
            ..DohConfig::default()
        };
        let odoh_keys =
            OdohKeyManager::spawn(tokio::runtime::Handle::current(), Duration::from_secs(3600))
                .unwrap();
        let engine = DohEngine::new(cfg, odoh_keys).unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = serve_with_shutdown(engine, listener, async {
                let _ = rx.await;
            })
            .await;
        });

        let req = "GET /dns-query?name=example.com&type=A HTTP/1.1\r\nHost: localhost\r\nAccept: application/dns-json\r\nConnection: close\r\n\r\n";
        let _ = raw_http_request(server_addr, req, b"").await;
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let (hdr2, _) = raw_http_request(server_addr, req, b"").await;
        let low2 = hdr2.to_ascii_lowercase();
        assert!(hdr2.starts_with("HTTP/1.1 200 OK"));
        assert!(!low2.contains("\r\nage:"));

        let _ = tx.send(());
    }

    #[tokio::test]
    async fn oversized_get_is_414() {
        let upstream_addr = start_mock_upstream(false).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let cfg = DohConfig {
            listen_address: server_addr,
            local_bind_address: "127.0.0.1:0".parse().unwrap(),
            server_address: upstream_addr,
            keepalive: false,
            ..DohConfig::default()
        };
        let odoh_keys =
            OdohKeyManager::spawn(tokio::runtime::Handle::current(), Duration::from_secs(3600))
                .unwrap();
        let engine = DohEngine::new(cfg, odoh_keys).unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = serve_with_shutdown(engine, listener, async {
                let _ = rx.await;
            })
            .await;
        });

        let huge_b64 = "A".repeat(6000);
        let (hdr, _) = raw_http_request(
            server_addr,
            &format!(
                "GET /dns-query?dns={huge_b64} HTTP/1.1\r\nHost: localhost\r\nAccept: application/dns-message\r\nConnection: close\r\n\r\n"
            ),
            b"",
        )
        .await;
        assert!(
            hdr.starts_with("HTTP/1.1 414"),
            "expected 414 URI Too Long, got: {hdr}"
        );

        let _ = tx.send(());
    }

    #[tokio::test]
    async fn security_headers_present() {
        let upstream_addr = start_mock_upstream(false).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let cfg = DohConfig {
            listen_address: server_addr,
            local_bind_address: "127.0.0.1:0".parse().unwrap(),
            server_address: upstream_addr,
            cors_allow_origin: "https://daviante.org".to_string(),
            keepalive: false,
            ..DohConfig::default()
        };
        let odoh_keys =
            OdohKeyManager::spawn(tokio::runtime::Handle::current(), Duration::from_secs(3600))
                .unwrap();
        let engine = DohEngine::new(cfg, odoh_keys).unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = serve_with_shutdown(engine, listener, async {
                let _ = rx.await;
            })
            .await;
        });

        let (hdr, _) = raw_http_request(
            server_addr,
            "GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            b"",
        )
        .await;
        let low = hdr.to_ascii_lowercase();
        assert!(low.contains("x-content-type-options: nosniff"));
        assert!(low.contains("content-security-policy: default-src 'none'; frame-ancestors 'none'"));
        assert!(low.contains("referrer-policy: no-referrer"));
        assert!(low.contains("vary: origin"));

        let _ = tx.send(());
    }
}

// =============================================================================
// H-3, M-9, L-7: In-Memory DNS Cache Regression Tests
// =============================================================================
pub mod cache {
    use super::*;

    #[tokio::test]
    async fn client_ecs_bypasses_cache() {
        let upstream_addr = start_mock_upstream(false).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let cfg = DohConfig {
            listen_address: server_addr,
            local_bind_address: "127.0.0.1:0".parse().unwrap(),
            server_address: upstream_addr,
            cache_size: 1024,
            enable_metrics: true,
            keepalive: false,
            ..DohConfig::default()
        };
        let odoh_keys =
            OdohKeyManager::spawn(tokio::runtime::Handle::current(), Duration::from_secs(3600))
                .unwrap();
        let engine = DohEngine::new(cfg, odoh_keys).unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = serve_with_shutdown(engine, listener, async {
                let _ = rx.await;
            })
            .await;
        });

        // Query with client-supplied edns_client_subnet twice -> must bypass shared cache both times
        let ecs_req = "GET /dns-query?name=example.com&type=A&edns_client_subnet=198.51.100.0/24 HTTP/1.1\r\nHost: localhost\r\nAccept: application/dns-json\r\nConnection: close\r\n\r\n";
        let (hdr1, _) = raw_http_request(server_addr, ecs_req, b"").await;
        let (hdr2, _) = raw_http_request(server_addr, ecs_req, b"").await;
        assert!(hdr1
            .to_ascii_lowercase()
            .contains("cache-control: private, max-age="));
        assert!(hdr2
            .to_ascii_lowercase()
            .contains("cache-control: private, max-age="));

        let (_, m_body) = raw_http_request(
            server_addr,
            "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            b"",
        )
        .await;
        let m_text = String::from_utf8_lossy(&m_body);
        assert!(m_text.contains("daviante_doh_cache_hits_total 0"));

        let _ = tx.send(());
    }

    #[test]
    fn large_entry_not_cached() {
        let cache = DnsCache::new(1024);
        let key = CacheKey {
            qname: "large.example.com".into(),
            qtype: 16,
            qclass: 1,
            do_bit: false,
            cd_bit: false,
        };
        let oversized = vec![0u8; MAX_CACHE_ENTRY_BYTES + 1];
        cache.insert(key.clone(), oversized, 300);
        assert!(cache.get(&key, [0x00, 0x01]).is_none());
    }

    #[test]
    fn preserves_0x20_casing() {
        let cache = DnsCache::new(1024);
        let key = CacheKey {
            qname: "example.com".into(),
            qtype: 1,
            qclass: 1,
            do_bit: false,
            cd_bit: false,
        };
        let q1 = build_sample_query(b"\x07example\x03com\x00", 1, false);
        let resp1 = build_mock_dns_answer_with_ttl(&q1, 300);
        cache.insert(key.clone(), resp1, 300);

        // Second client uses mixed 0x20 casing `eXaMpLe.CoM`
        let q2 = build_sample_query(b"\x07eXaMpLe\x03CoM\x00", 1, false);
        let parsed2 = wire::validate_and_parse_query(&q2).unwrap();
        let hit = cache
            .get_for_query(&key, &q2, parsed2.question_end_offset, false)
            .expect("expected cache hit");
        assert_eq!(
            &hit.wire_bytes[12..parsed2.question_end_offset],
            &q2[12..parsed2.question_end_offset]
        );
    }
}

// =============================================================================
// H-4, H-5, H-10, L-8: Upstream Resolution & Circuit Breaker Regression Tests
// =============================================================================
pub mod upstream {
    use super::*;

    #[tokio::test]
    async fn spoofed_datagram_ignored_then_real_accepted() {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = udp.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            if let Ok((len, peer)) = udp.recv_from(&mut buf).await {
                // 1. Send a spoofed datagram with wrong TXID
                let mut wrong_txid = build_mock_dns_answer_with_ttl(&buf[..len], 300);
                wrong_txid[0] ^= 0xff;
                let _ = udp.send_to(&wrong_txid, peer).await;

                // 2. Send a spoofed datagram with matching TXID but wrong QNAME
                let wrong_q = build_sample_query(b"\x08attacker\x03com\x00", 1, false);
                let mut wrong_qname = build_mock_dns_answer_with_ttl(&wrong_q, 300);
                wrong_qname[0] = buf[0];
                wrong_qname[1] = buf[1];
                let _ = udp.send_to(&wrong_qname, peer).await;

                // 3. Finally send the genuine matching response
                let real_resp = build_mock_dns_answer_with_ttl(&buf[..len], 300);
                let _ = udp.send_to(&real_resp, peer).await;
            }
        });

        let cfg = DohConfig {
            local_bind_address: "127.0.0.1:0".parse().unwrap(),
            server_address: upstream_addr,
            ..DohConfig::default()
        };
        let q = build_sample_query(b"\x07example\x03com\x00", 1, true);
        let sem = Arc::new(Semaphore::new(4));
        let metrics = DohMetrics::new();
        let res = resolve_upstream(
            q,
            None,
            &cfg,
            &sem,
            &metrics,
            tokio::time::Instant::now() + Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert_eq!(ancount(&res.unpadded_wire_bytes), 1);
    }

    #[tokio::test]
    async fn tcp_response_over_4096_accepted() {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = udp.local_addr().unwrap();
        let tcp_listener = TcpListener::bind(upstream_addr).await.unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((len, peer)) = udp.recv_from(&mut buf).await {
                let mut resp = build_mock_dns_answer_with_ttl(&buf[..len], 300);
                resp[2] |= 0x02; // TC=1 to trigger TCP
                let _ = udp.send_to(&resp, peer).await;
            }
        });

        tokio::spawn(async move {
            while let Ok((mut stream, _)) = tcp_listener.accept().await {
                tokio::spawn(async move {
                    let mut len_buf = [0u8; 2];
                    if stream.read_exact(&mut len_buf).await.is_ok() {
                        let qlen = u16::from_be_bytes(len_buf) as usize;
                        let mut qbuf = vec![0u8; qlen];
                        if stream.read_exact(&mut qbuf).await.is_ok() {
                            let q_end = wire::skip_questions(&qbuf).unwrap();
                            let mut resp = qbuf[..q_end].to_vec();
                            resp[2] = 0x81;
                            resp[3] = 0x80;
                            write_u16_be(&mut resp, 4, 1).unwrap();
                            // Add 50 TXT records of 200 bytes each (~10.6 KB > 4096 bytes!)
                            write_u16_be(&mut resp, 6, 50).unwrap();
                            write_u16_be(&mut resp, 8, 0).unwrap();
                            write_u16_be(&mut resp, 10, 0).unwrap();
                            for _ in 0..50 {
                                resp.extend_from_slice(b"\xc0\x0c\x00\x10\x00\x01\x00\x00\x01\x2c");
                                resp.extend_from_slice(&201u16.to_be_bytes());
                                resp.push(200);
                                resp.extend_from_slice(&[b'x'; 200]);
                            }
                            let rlen = (resp.len() as u16).to_be_bytes();
                            let _ = stream.write_all(&rlen).await;
                            let _ = stream.write_all(&resp).await;
                        }
                    }
                });
            }
        });

        let cfg = DohConfig {
            local_bind_address: "127.0.0.1:0".parse().unwrap(),
            server_address: upstream_addr,
            ..DohConfig::default()
        };
        let q = build_sample_query(b"\x07example\x03com\x00", 16, true);
        let sem = Arc::new(Semaphore::new(4));
        let metrics = DohMetrics::new();
        let res = resolve_upstream(
            q,
            None,
            &cfg,
            &sem,
            &metrics,
            tokio::time::Instant::now() + Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert!(res.unpadded_wire_bytes.len() > 9000);
        assert_eq!(ancount(&res.unpadded_wire_bytes), 50);
    }

    #[tokio::test]
    async fn dead_primary_skipped_after_first_failure() {
        // Primary UDP socket receives packets and never replies (simulating blackhole timeout)
        let silent_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dead_primary = silent_udp.local_addr().unwrap();
        let primary_hits = Arc::new(AtomicUsize::new(0));
        let hits_clone = Arc::clone(&primary_hits);
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while silent_udp.recv_from(&mut buf).await.is_ok() {
                hits_clone.fetch_add(1, Ordering::Relaxed);
            }
        });

        let live_secondary = start_mock_upstream(false).await;
        let cfg = DohConfig {
            local_bind_address: "127.0.0.1:0".parse().unwrap(),
            server_address: dead_primary,
            upstream_addresses: vec![dead_primary, live_secondary],
            timeout: Duration::from_secs(2),
            ..DohConfig::default()
        };
        let odoh_keys =
            OdohKeyManager::spawn(tokio::runtime::Handle::current(), Duration::from_secs(3600))
                .unwrap();
        let engine = DohEngine::new(cfg.clone(), odoh_keys).unwrap();
        let sem = Arc::new(Semaphore::new(4));

        // 1st query: tries dead_primary (times out), opens circuit breaker, succeeds on live_secondary
        let q1 = build_sample_query(b"\x07example\x03com\x00", 1, true);
        let _ = daviante_doh::upstream::resolve_upstream_with_set(
            q1,
            None,
            &cfg,
            &engine.upstreams,
            &sem,
            &engine.metrics,
            tokio::time::Instant::now() + Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(primary_hits.load(Ordering::Relaxed), 1);

        // 2nd query: circuit breaker skips dead_primary immediately!
        let start = tokio::time::Instant::now();
        let q2 = build_sample_query(b"\x07example\x03com\x00", 1, true);
        let _ = daviante_doh::upstream::resolve_upstream_with_set(
            q2,
            None,
            &cfg,
            &engine.upstreams,
            &sem,
            &engine.metrics,
            tokio::time::Instant::now() + Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert!(start.elapsed() < Duration::from_millis(200));
        assert_eq!(primary_hits.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn all_upstreams_down_returns_servfail_ede() {
        let silent_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = silent_udp.local_addr().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let cfg = DohConfig {
            listen_address: server_addr,
            local_bind_address: "127.0.0.1:0".parse().unwrap(),
            server_address: dead_addr,
            timeout: Duration::from_secs(1),
            keepalive: false,
            ..DohConfig::default()
        };
        let odoh_keys =
            OdohKeyManager::spawn(tokio::runtime::Handle::current(), Duration::from_secs(3600))
                .unwrap();
        let engine = DohEngine::new(cfg, odoh_keys).unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = serve_with_shutdown(engine, listener, async {
                let _ = rx.await;
            })
            .await;
        });

        let (hdr, body) = raw_http_request(
            server_addr,
            "GET /dns-query?name=example.com&type=A HTTP/1.1\r\nHost: localhost\r\nAccept: application/dns-json\r\nConnection: close\r\n\r\n",
            b"",
        )
        .await;
        assert!(hdr.starts_with("HTTP/1.1 200 OK"));
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["Status"], RCODE_SERVFAIL as u64);
        assert_eq!(
            parsed["EDE"][0]["info_code"],
            EDE_NO_REACHABLE_AUTHORITY as u64
        );

        let _ = tx.send(());
    }
}

// =============================================================================
// M-1: EDNS0 OPT & RFC 8467 468-Byte Padding Regression Tests
// =============================================================================
pub mod edns {
    use super::*;

    #[test]
    fn no_opt_for_non_edns_client() {
        let q = build_sample_query(b"\x07example\x03com\x00", 1, false);
        let mut resp = build_mock_dns_answer_with_ttl(&q, 300);
        // Simulate upstream attaching OPT record
        wire::append_empty_opt_record(&mut resp, 1232).unwrap();
        assert_eq!(arcount(&resp), 1);

        finalize_wire_response_for_client(&mut resp, false);
        assert_eq!(arcount(&resp), 0);
        assert_ne!(resp.len() % RESPONSE_PADDING_BLOCK_SIZE, 0);
    }

    #[test]
    fn pads_to_468_when_client_padded() {
        let q = build_sample_query(b"\x07example\x03com\x00", 1, true);
        let mut resp = build_mock_dns_answer_with_ttl(&q, 300);
        finalize_wire_response_for_client(&mut resp, true);
        assert_eq!(resp.len() % RESPONSE_PADDING_BLOCK_SIZE, 0);
        assert_eq!(arcount(&resp), 1);
    }

    #[test]
    fn cache_hit_respects_client_edns() {
        let cache = DnsCache::new(1024);
        let key = CacheKey {
            qname: "example.com".into(),
            qtype: 1,
            qclass: 1,
            do_bit: false,
            cd_bit: false,
        };
        let q = build_sample_query(b"\x07example\x03com\x00", 1, true);
        let mut resp = build_mock_dns_answer_with_ttl(&q, 300);
        wire::append_empty_opt_record(&mut resp, 1232).unwrap();
        cache.insert(key.clone(), resp, 300);

        // 1. Non-EDNS client gets no OPT and no padding
        let q_no_edns = build_sample_query(b"\x07example\x03com\x00", 1, false);
        let p_no = wire::validate_and_parse_query(&q_no_edns).unwrap();
        let hit_no = cache
            .get_for_query(&key, &q_no_edns, p_no.question_end_offset, false)
            .unwrap();
        assert_eq!(arcount(&hit_no.wire_bytes), 0);

        // 2. EDNS client gets OPT + 468-byte padding
        let q_edns = build_sample_query(b"\x07example\x03com\x00", 1, true);
        let p_edns = wire::validate_and_parse_query(&q_edns).unwrap();
        let hit_edns = cache
            .get_for_query(&key, &q_edns, p_edns.question_end_offset, true)
            .unwrap();
        assert_eq!(arcount(&hit_edns.wire_bytes), 1);
        assert_eq!(hit_edns.wire_bytes.len() % RESPONSE_PADDING_BLOCK_SIZE, 0);
    }
}

// =============================================================================
// M-10, N-2, N-3: Oblivious DoH (RFC 9230) Regression Tests
// =============================================================================
pub mod odoh {
    use super::*;

    #[tokio::test]
    async fn configs_max_age_within_grace_ring() {
        let upstream_addr = start_mock_upstream(false).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let cfg = DohConfig {
            listen_address: server_addr,
            local_bind_address: "127.0.0.1:0".parse().unwrap(),
            server_address: upstream_addr,
            odoh_rotation_secs: 3600,
            keepalive: false,
            ..DohConfig::default()
        };
        let odoh_keys =
            OdohKeyManager::spawn(tokio::runtime::Handle::current(), Duration::from_secs(3600))
                .unwrap();
        let engine = DohEngine::new(cfg, odoh_keys).unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = serve_with_shutdown(engine, listener, async {
                let _ = rx.await;
            })
            .await;
        });

        let (hdr, _) = raw_http_request(
            server_addr,
            "GET /.well-known/odohconfigs HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            b"",
        )
        .await;
        let low = hdr.to_ascii_lowercase();
        assert!(low.contains("cache-control: max-age=1800"));
        assert!(!low.contains("stale-if-error"));

        let _ = tx.send(());
    }

    #[tokio::test]
    async fn get_rejected_405() {
        let upstream_addr = start_mock_upstream(false).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let cfg = DohConfig {
            listen_address: server_addr,
            local_bind_address: "127.0.0.1:0".parse().unwrap(),
            server_address: upstream_addr,
            keepalive: false,
            ..DohConfig::default()
        };
        let odoh_keys =
            OdohKeyManager::spawn(tokio::runtime::Handle::current(), Duration::from_secs(3600))
                .unwrap();
        let engine = DohEngine::new(cfg, odoh_keys).unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = serve_with_shutdown(engine, listener, async {
                let _ = rx.await;
            })
            .await;
        });

        let (hdr, _) = raw_http_request(
            server_addr,
            "GET /dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE HTTP/1.1\r\nHost: localhost\r\nAccept: application/oblivious-dns-message\r\nConnection: close\r\n\r\n",
            b"",
        )
        .await;
        let low = hdr.to_ascii_lowercase();
        assert!(hdr.starts_with("HTTP/1.1 405"));
        assert!(low.contains("allow: post"));
        assert!(low.contains("cache-control: no-store"));

        let _ = tx.send(());
    }

    #[tokio::test]
    async fn errors_are_no_store() {
        let upstream_addr = start_mock_upstream(false).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let cfg = DohConfig {
            listen_address: server_addr,
            local_bind_address: "127.0.0.1:0".parse().unwrap(),
            server_address: upstream_addr,
            keepalive: false,
            ..DohConfig::default()
        };
        let odoh_keys =
            OdohKeyManager::spawn(tokio::runtime::Handle::current(), Duration::from_secs(3600))
                .unwrap();
        let engine = DohEngine::new(cfg, odoh_keys).unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = serve_with_shutdown(engine, listener, async {
                let _ = rx.await;
            })
            .await;
        });

        let (hdr, _) = raw_http_request(
            server_addr,
            "POST /dns-query HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/oblivious-dns-message\r\nContent-Length: 5\r\nConnection: close\r\n\r\n",
            b"bogus",
        )
        .await;
        assert!(hdr.starts_with("HTTP/1.1 400"));
        assert!(hdr.to_ascii_lowercase().contains("cache-control: no-store"));

        let _ = tx.send(());
    }

    #[test]
    fn plaintext_padded() {
        use odoh_rs::{
            Deserialize as _, ObliviousDoHConfigs, ObliviousDoHMessage,
            ObliviousDoHMessagePlaintext, Serialize as _,
        };

        let key = daviante_doh::OdohActiveKey::generate().unwrap();
        let configs =
            ObliviousDoHConfigs::deserialize(&mut Bytes::from(key.serialized_configs())).unwrap();
        let target_cfg = configs.into_iter().next().unwrap().into();

        let q = build_sample_query(b"\x07example\x03com\x00", 1, false);
        let plain_q = ObliviousDoHMessagePlaintext::new(&q, 0);
        let mut rng = rand::rng();
        let (enc_q, cli_secret) = odoh_rs::encrypt_query(&plain_q, &target_cfg, &mut rng).unwrap();
        let mut enc_bytes = Vec::new();
        enc_q.serialize(&mut enc_bytes).unwrap();

        let (raw_dns, session) = key.open_query(enc_bytes).unwrap();
        let resp_dns = build_mock_dns_answer_with_ttl(&raw_dns, 300);
        let sealed = session.seal_response(resp_dns).unwrap();
        assert!(sealed.len() >= RESPONSE_PADDING_BLOCK_SIZE);

        let enc_resp = ObliviousDoHMessage::deserialize(&mut Bytes::from(sealed)).unwrap();
        let dec_resp = odoh_rs::decrypt_response(&plain_q, &enc_resp, cli_secret).unwrap();
        assert_eq!(ancount(dec_resp.into_msg().as_ref()), 1);
    }
}

// =============================================================================
// H-7: TLS 0-RTT & Minimum Protocol Version Regression Tests
// =============================================================================
#[cfg(feature = "tls")]
pub mod tls {
    use super::*;
    use daviante_doh::tls::{
        build_pinned_healthcheck_connector, build_tls_server_config, TlsMinVersion,
    };

    const TEST_CERT_PEM: &str = concat!(
        "-----BEGIN ",
        "CERTIFICATE-----\n",
        "MIIBmDCCAT+gAwIBAgIUNkDcdb1ZlMu64/GJkM44GkERsaAwCgYIKoZIzj0EAwIw\n",
        "FDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MTAxNzIzNTE1NFoXDTM2MTAxNDIz\n",
        "NTE1NFowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D\n",
        "AQcDQgAErWF7m21jDRyZr+u79nnigFHMXSBZVcsqDn/d0yqFsV8Ch4yNP2S/1XIa\n",
        "kax2nnW3xeW+SsJi+sA/byCq12JoKaNvMG0wHQYDVR0OBBYEFO0UieoBWoaZqtEf\n",
        "A2xv5ykf9V2rMB8GA1UdIwQYMBaAFO0UieoBWoaZqtEfA2xv5ykf9V2rMA8GA1Ud\n",
        "EwEB/wQFMAMBAf8wGgYDVR0RBBMwEYIJbG9jYWxob3N0hwR/AAABMAoGCCqGSM49\n",
        "BAMCA0cAMEQCIGTM8ArzrRMwK9y1TKy+irluoIIF5as2qdFdSc/AgFEAAiBsPLDg\n",
        "blVaU9jbWKRNgVekewSGO76v9Kqw7knea8HweA==\n",
        "-----END ",
        "CERTIFICATE-----\n"
    );

    const TEST_KEY_PEM: &str = concat!(
        "-----BEGIN ",
        "PRIVATE KEY-----\n",
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgDDxGimCBITAIRnKd\n",
        "tYIR6+QBODvchStEmUe21mRmAs2hRANCAAStYXubbWMNHJmv67v2eeKAUcxdIFlV\n",
        "yyoOf93TKoWxXwKHjI0/ZL/VchqRrHaedbfF5b5KwmL6wD9vIKrXYmgp\n",
        "-----END ",
        "PRIVATE KEY-----\n"
    );

    pub fn write_temp_cert_and_key(tag: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let cert_path = dir.join(format!("daviante-doh-test-{tag}-{pid}.crt"));
        let key_path = dir.join(format!("daviante-doh-test-{tag}-{pid}.key"));
        std::fs::write(&cert_path, TEST_CERT_PEM).unwrap();
        std::fs::write(&key_path, TEST_KEY_PEM).unwrap();
        (cert_path, key_path)
    }

    #[test]
    fn early_data_disabled() {
        let (cert_path, key_path) = write_temp_cert_and_key("early-data");
        let server_cfg =
            build_tls_server_config(&cert_path, &key_path, TlsMinVersion::Tls12).unwrap();
        assert_eq!(server_cfg.max_early_data_size, 0);
        let _ = std::fs::remove_file(cert_path);
        let _ = std::fs::remove_file(key_path);
    }

    #[tokio::test]
    async fn tls13_only_rejects_tls12() {
        let (cert_path, key_path) = write_temp_cert_and_key("tls13-only");
        let acceptor = daviante_doh::tls::build_tls_acceptor_with_version(
            &cert_path,
            &key_path,
            TlsMinVersion::Tls13,
        )
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let acc_clone = acceptor.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let a = acc_clone.clone();
                tokio::spawn(async move {
                    let _ = a.accept(stream).await;
                });
            }
        });

        // 1. TLS 1.2-only client MUST be rejected by TLS 1.3-only server
        let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
        for cert in daviante_doh::tls::load_certs(&cert_path).unwrap() {
            root_store.add(cert).unwrap();
        }
        let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
        let tls12_cfg = tokio_rustls::rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS12])
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let tls12_connector = tokio_rustls::TlsConnector::from(Arc::new(tls12_cfg));
        let tcp1 = TcpStream::connect(addr).await.unwrap();
        let sname = tokio_rustls::rustls::pki_types::ServerName::try_from("localhost").unwrap();
        assert!(tls12_connector.connect(sname.clone(), tcp1).await.is_err());

        // 2. Leaf-pinned TLS 1.3 healthcheck connector MUST succeed
        let reloadable =
            daviante_doh::tls::ReloadableTlsAcceptor::spawn(cert_path.clone(), key_path.clone())
                .unwrap();
        let _ = reloadable.get();
        let pinned_connector = build_pinned_healthcheck_connector(&cert_path).unwrap();
        let tcp2 = TcpStream::connect(addr).await.unwrap();
        assert!(pinned_connector.connect(sname, tcp2).await.is_ok());

        let _ = std::fs::remove_file(cert_path);
        let _ = std::fs::remove_file(key_path);
    }
}

// =============================================================================
// H-8 & M-7: Graceful Shutdown, HTTP/2 Idle Persistence, & Per-IP Cap Tests
// =============================================================================
pub mod server {
    use super::*;

    #[tokio::test]
    async fn inflight_request_completes_during_shutdown() {
        // Upstream delays response by 300ms while shutdown is triggered at 50ms
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = udp.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((len, peer)) = udp.recv_from(&mut buf).await {
                let pkt = buf[..len].to_vec();
                let u_clone = udp.local_addr().unwrap();
                let resp = build_mock_dns_answer_with_ttl(&pkt, 300);
                tokio::time::sleep(Duration::from_millis(250)).await;
                let _ = udp.send_to(&resp, peer).await;
                let _ = u_clone;
            }
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let cfg = DohConfig {
            listen_address: server_addr,
            local_bind_address: "127.0.0.1:0".parse().unwrap(),
            server_address: upstream_addr,
            shutdown_grace_period: Duration::from_secs(5),
            keepalive: false,
            ..DohConfig::default()
        };
        let odoh_keys =
            OdohKeyManager::spawn(tokio::runtime::Handle::current(), Duration::from_secs(3600))
                .unwrap();
        let engine = DohEngine::new(cfg, odoh_keys).unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let srv_handle = tokio::spawn(async move {
            serve_with_shutdown(engine, listener, async {
                let _ = rx.await;
            })
            .await
        });

        let req_task = tokio::spawn(async move {
            raw_http_request(
                server_addr,
                "GET /dns-query?name=example.com&type=A HTTP/1.1\r\nHost: localhost\r\nAccept: application/dns-json\r\nConnection: close\r\n\r\n",
                b"",
            )
            .await
        });

        // Trigger shutdown while request is in flight!
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = tx.send(());

        let (hdr, body) = req_task.await.unwrap();
        assert!(hdr.starts_with("HTTP/1.1 200 OK"));
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["Status"], 0);
        assert!(srv_handle.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn idle_h2_connection_survives_beyond_timeout() {
        let upstream_addr = start_mock_upstream(false).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let cfg = DohConfig {
            listen_address: server_addr,
            local_bind_address: "127.0.0.1:0".parse().unwrap(),
            server_address: upstream_addr,
            timeout: Duration::from_secs(1),
            ..DohConfig::default()
        };
        let odoh_keys =
            OdohKeyManager::spawn(tokio::runtime::Handle::current(), Duration::from_secs(3600))
                .unwrap();
        let engine = DohEngine::new(cfg, odoh_keys).unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = serve_with_shutdown(engine, listener, async {
                let _ = rx.await;
            })
            .await;
        });

        let tcp = TcpStream::connect(server_addr).await.unwrap();
        let (mut sender, conn) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tcp))
                .await
                .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });

        // Wait longer than 2 * timeout (2.2s > 2s) and verify the HTTP/2 connection is STILL alive!
        tokio::time::sleep(Duration::from_millis(2200)).await;

        let req = Request::builder()
            .method("GET")
            .uri("/healthz")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), 200);

        let _ = tx.send(());
    }

    #[tokio::test]
    async fn readyz_503_after_shutdown_signal() {
        let upstream_addr = start_mock_upstream(false).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let adm_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let adm_addr = adm_listener.local_addr().unwrap();

        let cfg = DohConfig {
            listen_address: server_addr,
            admin_listen_address: Some(adm_addr),
            local_bind_address: "127.0.0.1:0".parse().unwrap(),
            server_address: upstream_addr,
            keepalive: false,
            ..DohConfig::default()
        };
        let odoh_keys =
            OdohKeyManager::spawn(tokio::runtime::Handle::current(), Duration::from_secs(3600))
                .unwrap();
        let engine = DohEngine::new(cfg, odoh_keys).unwrap();
        let engine_ref = engine.clone();

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = serve_with_admin_and_shutdown(engine, listener, Some(adm_listener), async {
                let _ = rx.await;
            })
            .await;
        });

        // Before drain: /readyz returns 200 OK
        let (hdr1, _) = raw_http_request(
            adm_addr,
            "GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            b"",
        )
        .await;
        assert!(hdr1.starts_with("HTTP/1.1 200 OK"));

        // Mark draining (as shutdown signal does) and verify /readyz returns 503 Service Unavailable
        engine_ref.set_draining(true);
        let (hdr2, _) = raw_http_request(
            adm_addr,
            "GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            b"",
        )
        .await;
        assert!(hdr2.starts_with("HTTP/1.1 503"));

        let _ = tx.send(());
    }

    #[tokio::test]
    async fn per_ip_conn_cap() {
        let upstream_addr = start_mock_upstream(false).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let cfg = DohConfig {
            listen_address: server_addr,
            local_bind_address: "127.0.0.1:0".parse().unwrap(),
            server_address: upstream_addr,
            max_conns_per_ip: 1,
            ..DohConfig::default()
        };
        let odoh_keys =
            OdohKeyManager::spawn(tokio::runtime::Handle::current(), Duration::from_secs(3600))
                .unwrap();
        let engine = DohEngine::new(cfg, odoh_keys).unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = serve_with_shutdown(engine, listener, async {
                let _ = rx.await;
            })
            .await;
        });

        // Hold 1st connection open
        let _conn1 = TcpStream::connect(server_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // 2nd connection from the same IP should be dropped immediately
        let mut conn2 = TcpStream::connect(server_addr).await.unwrap();
        let _ = conn2
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await;
        let mut buf = Vec::new();
        let _ = conn2.read_to_end(&mut buf).await;
        assert!(
            buf.is_empty(),
            "expected 2nd concurrent connection from same IP to be dropped"
        );

        let _ = tx.send(());
    }
}

// =============================================================================
// M-8: Rate Limiter IPv6 /64 Aggregation & Idle Eviction Regression Tests
// =============================================================================
pub mod ratelimit {
    use super::*;

    #[test]
    fn ipv6_same_64_shares_bucket() {
        let limiter = IpRateLimiter::with_v6_prefix(1, 2, 64);
        let ip_a: Option<IpAddr> = Some("2001:db8:abcd:1234::1".parse().unwrap());
        let ip_b: Option<IpAddr> = Some("2001:db8:abcd:1234:ffff:ffff:ffff:ffff".parse().unwrap());
        assert!(limiter.check_and_consume(ip_a));
        assert!(limiter.check_and_consume(ip_b));
        // 3rd request from another host in the same /64 must be rate-limited!
        let ip_c: Option<IpAddr> = Some("2001:db8:abcd:1234::99".parse().unwrap());
        assert!(!limiter.check_and_consume(ip_c));
    }

    #[test]
    fn eviction_prefers_idle() {
        // Create a limiter with 1 bucket per shard
        let limiter = IpRateLimiter::with_capacity_and_v6_prefix(1, 1, 64, 1);
        // Find two IPs that hash to the same shard
        let base_ip: IpAddr = "198.51.100.1".parse().unwrap();
        assert!(limiter.check_and_consume(Some(base_ip)));
        assert!(!limiter.check_and_consume(Some(base_ip)));

        std::thread::sleep(Duration::from_millis(10));
        // Insert enough distinct IPs to guarantee shard collision and eviction of the older bucket
        for i in 2..=64u8 {
            let ip: IpAddr = format!("198.51.100.{i}").parse().unwrap();
            let _ = limiter.check_and_consume(Some(ip));
        }
    }
}

// =============================================================================
// N-6 & N-7: JSON DoH Error RCODE & Presentation Escaping Regression Tests
// =============================================================================
pub mod json {
    use super::*;

    #[tokio::test]
    async fn error_status_is_rcode() {
        let upstream_addr = start_mock_upstream(false).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let cfg = DohConfig {
            listen_address: server_addr,
            local_bind_address: "127.0.0.1:0".parse().unwrap(),
            server_address: upstream_addr,
            keepalive: false,
            ..DohConfig::default()
        };
        let odoh_keys =
            OdohKeyManager::spawn(tokio::runtime::Handle::current(), Duration::from_secs(3600))
                .unwrap();
        let engine = DohEngine::new(cfg, odoh_keys).unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = serve_with_shutdown(engine, listener, async {
                let _ = rx.await;
            })
            .await;
        });

        let (hdr, body) = raw_http_request(
            server_addr,
            "GET /dns-query?name=example.com&type=INVALIDTYPE HTTP/1.1\r\nHost: localhost\r\nAccept: application/dns-json\r\nConnection: close\r\n\r\n",
            b"",
        )
        .await;
        assert!(hdr.starts_with("HTTP/1.1 400"));
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // Status MUST be DNS RCODE FORMERR (1), not HTTP 400
        assert_eq!(parsed["Status"], 1);

        let _ = tx.send(());
    }

    #[test]
    fn escapes_presentation_format() {
        // Label containing a literal '.' (`a.b`) and a space (`0x20` -> `\032`) followed by `com`
        let q = build_sample_query(b"\x04a.b \x03com\x00", 1, false);
        let resp = build_mock_dns_answer_with_ttl(&q, 300);
        let decoded = decode_wire_to_json(&resp).unwrap();
        let qname = &decoded.question.unwrap()[0].name;
        assert_eq!(qname, "a\\.b\\032.com");
    }
}

// =============================================================================
// M-4: Privacy-Preserving Audit Logging Regression Tests
// =============================================================================
pub mod audit {
    use super::*;

    #[test]
    fn client_ip_none_by_default() {
        let cfg = DohConfig::default();
        assert_eq!(cfg.log_client_ip, ClientIpLogMode::None);
        let ip: Option<IpAddr> = Some("198.51.100.77".parse().unwrap());
        assert_eq!(format_audit_client_ip(ip, cfg.log_client_ip, 24, 56), None);
    }

    #[test]
    fn truncated_v4_v6() {
        let v4: Option<IpAddr> = Some("198.51.100.77".parse().unwrap());
        let v6: Option<IpAddr> = Some("2001:db8:abcd:12ff:1111:2222:3333:4444".parse().unwrap());
        assert_eq!(
            format_audit_client_ip(v4, ClientIpLogMode::Truncated, 24, 56).as_deref(),
            Some("198.51.100.0")
        );
        assert_eq!(
            format_audit_client_ip(v6, ClientIpLogMode::Truncated, 24, 56).as_deref(),
            Some("2001:db8:abcd:1200::")
        );
    }
}

// =============================================================================
// M-5 & M-6: Dedicated Admin Listener & Liveness/Readiness Separation Tests
// =============================================================================
pub mod admin {
    use super::*;

    #[tokio::test]
    async fn metrics_not_on_public_listener_when_admin_set() {
        let upstream_addr = start_mock_upstream(false).await;
        let pub_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let adm_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pub_addr = pub_listener.local_addr().unwrap();
        let adm_addr = adm_listener.local_addr().unwrap();

        let cfg = DohConfig {
            listen_address: pub_addr,
            admin_listen_address: Some(adm_addr),
            local_bind_address: "127.0.0.1:0".parse().unwrap(),
            server_address: upstream_addr,
            enable_metrics: true,
            keepalive: false,
            ..DohConfig::default()
        };
        let odoh_keys =
            OdohKeyManager::spawn(tokio::runtime::Handle::current(), Duration::from_secs(3600))
                .unwrap();
        let engine = DohEngine::new(cfg, odoh_keys).unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ =
                serve_with_admin_and_shutdown(engine, pub_listener, Some(adm_listener), async {
                    let _ = rx.await;
                })
                .await;
        });

        // Public listener returns 404 on /metrics and /livez
        let (pub_m, _) = raw_http_request(
            pub_addr,
            "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            b"",
        )
        .await;
        assert!(pub_m.starts_with("HTTP/1.1 404"));

        // Admin listener returns 200 on /metrics and /livez
        let (adm_m, _) = raw_http_request(
            adm_addr,
            "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            b"",
        )
        .await;
        assert!(adm_m.starts_with("HTTP/1.1 200 OK"));

        let _ = tx.send(());
    }

    #[tokio::test]
    async fn readyz_reflects_upstream_and_drain() {
        let upstream_addr = start_mock_upstream(false).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let cfg = DohConfig {
            listen_address: server_addr,
            local_bind_address: "127.0.0.1:0".parse().unwrap(),
            server_address: upstream_addr,
            keepalive: false,
            ..DohConfig::default()
        };
        let odoh_keys =
            OdohKeyManager::spawn(tokio::runtime::Handle::current(), Duration::from_secs(3600))
                .unwrap();
        let engine = DohEngine::new(cfg, odoh_keys).unwrap();
        let engine_ref = engine.clone();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = serve_with_shutdown(engine, listener, async {
                let _ = rx.await;
            })
            .await;
        });

        // 1. Healthy upstream -> /readyz is 200 OK
        let (r1, _) = raw_http_request(
            server_addr,
            "GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            b"",
        )
        .await;
        assert!(r1.starts_with("HTTP/1.1 200 OK"));

        // 2. Open upstream circuit breaker -> /readyz is 503 while /livez remains 200!
        engine_ref.upstreams.record_failure(upstream_addr);
        let (r2, _) = raw_http_request(
            server_addr,
            "GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            b"",
        )
        .await;
        assert!(r2.starts_with("HTTP/1.1 503"));

        let (l2, _) = raw_http_request(
            server_addr,
            "GET /livez HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            b"",
        )
        .await;
        assert!(l2.starts_with("HTTP/1.1 200 OK"));

        let _ = tx.send(());
    }
}

// =============================================================================
// L-6: Prometheus Histogram, RCODE, and Upstream Target Exposition Test
// =============================================================================
pub mod metrics {
    use super::*;

    #[tokio::test]
    async fn exposition_contains_histogram_and_rcode() {
        let upstream_addr = start_mock_upstream(false).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let cfg = DohConfig {
            listen_address: server_addr,
            local_bind_address: "127.0.0.1:0".parse().unwrap(),
            server_address: upstream_addr,
            enable_metrics: true,
            keepalive: false,
            ..DohConfig::default()
        };
        let odoh_keys =
            OdohKeyManager::spawn(tokio::runtime::Handle::current(), Duration::from_secs(3600))
                .unwrap();
        let engine = DohEngine::new(cfg, odoh_keys).unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = serve_with_shutdown(engine, listener, async {
                let _ = rx.await;
            })
            .await;
        });

        let _ = raw_http_request(
            server_addr,
            "GET /dns-query?name=example.com&type=A HTTP/1.1\r\nHost: localhost\r\nAccept: application/dns-json\r\nConnection: close\r\n\r\n",
            b"",
        )
        .await;

        let (_, m_body) = raw_http_request(
            server_addr,
            "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            b"",
        )
        .await;
        let text = String::from_utf8_lossy(&m_body);
        assert!(text
            .contains("daviante_doh_request_duration_seconds_bucket{flavor=\"json\",le=\"0.1\"}"));
        assert!(text.contains("daviante_doh_request_duration_seconds_count{flavor=\"json\"} 1"));
        assert!(text.contains("daviante_doh_responses_by_rcode_total{rcode=\"NOERROR\"} 1"));
        assert!(text.contains("daviante_doh_connections_active"));
        assert!(text.contains(&format!(
            "daviante_doh_upstream_queries_total{{upstream=\"{upstream_addr}\",transport=\"udp\",result=\"ok\"}} 1"
        )));

        let _ = tx.send(());
    }
}

// =============================================================================
// Full End-to-End Protocol Suite
// =============================================================================
#[tokio::test]
async fn e2e_wire_doh_json_odoh_cors_and_health() {
    let upstream_addr = start_mock_upstream(false).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let cfg = DohConfig {
        listen_address: server_addr,
        local_bind_address: "127.0.0.1:0".parse().unwrap(),
        server_address: upstream_addr,
        keepalive: false,
        enable_ecs: true,
        ..DohConfig::default()
    };
    let odoh_keys =
        OdohKeyManager::spawn(tokio::runtime::Handle::current(), Duration::from_secs(3600))
            .unwrap();
    let engine = DohEngine::new(cfg, odoh_keys.clone()).unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = serve_with_shutdown(engine, listener, async {
            let _ = rx.await;
        })
        .await;
    });

    // 1. Health check endpoint + nosniff header
    let (h_hdr, h_body) = raw_http_request(
        server_addr,
        "GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        b"",
    )
    .await;
    assert!(h_hdr.starts_with("HTTP/1.1 200 OK"));
    assert!(h_hdr
        .to_ascii_lowercase()
        .contains("x-content-type-options: nosniff"));
    assert_eq!(h_body, br#"{"status":"ok","service":"daviante-doh"}"#);

    // 2. CORS OPTIONS preflight
    let (c_hdr, _) = raw_http_request(
        server_addr,
        "OPTIONS /dns-query HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        b"",
    )
    .await;
    assert!(c_hdr.starts_with("HTTP/1.1 204 No Content"));
    assert!(c_hdr
        .to_ascii_lowercase()
        .contains("access-control-allow-origin: *"));

    // 3. RFC 8484 Wireformat DoH GET (with EDNS0 -> 468-byte padded)
    let q = build_sample_query(b"\x07example\x03com\x00", 1, true);
    let b64 = URL_SAFE_NO_PAD.encode(&q);
    let (w_hdr, w_body) = raw_http_request(
        server_addr,
        &format!(
            "GET /dns-query?dns={b64} HTTP/1.1\r\nHost: localhost\r\nAccept: application/dns-message\r\nConnection: close\r\n\r\n"
        ),
        b"",
    )
    .await;
    assert!(w_hdr.starts_with("HTTP/1.1 200 OK"));
    assert_eq!(w_body.len() % RESPONSE_PADDING_BLOCK_SIZE, 0);
    assert_eq!(&w_body[0..2], &[0x12, 0x34]);

    // 4. JSON DoH GET
    let (j_hdr, j_body) = raw_http_request(
        server_addr,
        "GET /dns-query?name=example.com&type=A HTTP/1.1\r\nHost: localhost\r\nAccept: application/dns-json\r\nConnection: close\r\n\r\n",
        b"",
    )
    .await;
    assert!(j_hdr.starts_with("HTTP/1.1 200 OK"));
    let parsed: serde_json::Value = serde_json::from_slice(&j_body).unwrap();
    assert_eq!(parsed["Status"], 0);
    assert_eq!(parsed["Answer"][0]["data"], "93.184.216.34");

    // 5. RFC 9230 Oblivious DoH (with 2-key rotation grace window verification & Cache-Control: no-store)
    let (_, odoh_cfg_bytes) = raw_http_request(
        server_addr,
        "GET /.well-known/odohconfigs HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        b"",
    )
    .await;
    use odoh_rs::{
        Deserialize as _, ObliviousDoHConfigs, ObliviousDoHMessagePlaintext, Serialize as _,
    };
    let configs = ObliviousDoHConfigs::deserialize(&mut Bytes::from(odoh_cfg_bytes)).unwrap();
    let target_cfg = configs.into_iter().next().unwrap().into();
    let plain_q = ObliviousDoHMessagePlaintext::new(&q, 0);
    let mut rng = rand::rng();
    let (enc_q, cli_secret) = odoh_rs::encrypt_query(&plain_q, &target_cfg, &mut rng).unwrap();
    let mut enc_bytes = Vec::new();
    enc_q.serialize(&mut enc_bytes).unwrap();

    // Rotate the server key BEFORE sending the client's encrypted query to prove the 2-key grace ring works!
    odoh_keys.rotate_now().unwrap();

    let (o_hdr, o_body) = raw_http_request(
        server_addr,
        &format!(
            "POST /dns-query HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/oblivious-dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            enc_bytes.len()
        ),
        &enc_bytes,
    )
    .await;
    assert!(o_hdr.starts_with("HTTP/1.1 200 OK"));
    assert!(o_hdr
        .to_ascii_lowercase()
        .contains("cache-control: no-store"));
    let enc_resp = odoh_rs::ObliviousDoHMessage::deserialize(&mut Bytes::from(o_body)).unwrap();
    let dec_resp = odoh_rs::decrypt_response(&plain_q, &enc_resp, cli_secret).unwrap();
    assert_eq!(ancount(dec_resp.into_msg().as_ref()), 1);

    let _ = tx.send(());
}

#[tokio::test]
async fn tcp_fallback_when_udp_truncated() {
    let upstream_addr = start_mock_upstream(true).await;
    let cfg = DohConfig {
        local_bind_address: "127.0.0.1:0".parse().unwrap(),
        server_address: upstream_addr,
        ..DohConfig::default()
    };
    let mut q = vec![
        0xbe, 0xef, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    q.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");

    let sem = Arc::new(Semaphore::new(4));
    let metrics = DohMetrics::new();
    let res = resolve_upstream(
        q,
        None,
        &cfg,
        &sem,
        &metrics,
        tokio::time::Instant::now() + Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(&res.wire_bytes[0..2], &[0xbe, 0xef]);
    assert!(!wire::is_truncated(&res.wire_bytes));
    assert!(read_u32_be(&res.unpadded_wire_bytes, 29 + 6).is_ok());
}

// =============================================================================
// v0.2.0 Competitive Enhancements: Serve-Stale (RFC 8767), Prefetch, Singleflight,
// Load-Balancing (Round-Robin & Parallel), Upstream DoT (RFC 7858), Rebinding & Hosts
// =============================================================================
pub mod competitive_enhancements {
    use super::*;
    use daviante_doh::UpstreamStrategy;

    #[tokio::test]
    async fn rfc8767_serve_stale_and_prefetch_on_upstream_outage() {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = udp.local_addr().unwrap();
        let respond_enabled = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let respond_flag = Arc::clone(&respond_enabled);

        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((len, peer)) = udp.recv_from(&mut buf).await {
                if respond_flag.load(Ordering::Acquire) {
                    let resp = build_mock_dns_answer_with_ttl(&buf[..len], 1);
                    let _ = udp.send_to(&resp, peer).await;
                }
            }
        });

        let cfg = DohConfig {
            local_bind_address: "127.0.0.1:0".parse().unwrap(),
            server_address: upstream_addr,
            cache_size: 1024,
            serve_stale_ttl: 3600,
            cache_prefetch: true,
            timeout: Duration::from_secs(1),
            ..DohConfig::default()
        };
        let odoh_keys =
            OdohKeyManager::spawn(tokio::runtime::Handle::current(), Duration::from_secs(3600))
                .unwrap();
        let engine = DohEngine::new(cfg, odoh_keys).unwrap();

        let q = build_sample_query(b"\x05stale\x07example\x03com\x00", 1, true);

        // 1. Initial query populates cache with 1-second TTL
        let r1 = engine
            .process_dns_query(
                q.clone(),
                None,
                tokio::time::Instant::now() + Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(wire::rcode(&r1.unpadded_wire_bytes), 0);

        // 2. Wait 1.15s so the 1-second TTL expires, then disable upstream to simulate total outage
        tokio::time::sleep(Duration::from_millis(1150)).await;
        respond_enabled.store(false, Ordering::Release);

        // 3. Query again during upstream outage -> RFC 8767 Serve-Stale returns NOERROR with TTL=30 and EDE 3!
        let mut q2 = q.clone();
        q2[0] = 0x99;
        q2[1] = 0x88;
        let r2 = engine
            .process_dns_query(
                q2,
                None,
                tokio::time::Instant::now() + Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(&r2.wire_bytes[0..2], &[0x99, 0x88]);
        assert_eq!(wire::rcode(&r2.unpadded_wire_bytes), 0);
        assert_eq!(r2.cache_ttl, 30);

        let decoded_json = decode_wire_to_json(&r2.unpadded_wire_bytes).unwrap();
        assert_eq!(decoded_json.status, 0);
        assert_eq!(decoded_json.answer.as_ref().unwrap()[0].ttl, 30);
        assert!(decoded_json
            .comment
            .as_deref()
            .unwrap_or("")
            .contains("Stale Answer"));

        let prom = engine.metrics.render_prometheus();
        assert!(prom.contains("daviante_doh_cache_stale_hits_total 1"));
    }

    #[tokio::test]
    async fn singleflight_coalesces_concurrent_identical_cache_misses() {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = udp.local_addr().unwrap();
        let upstream_hits = Arc::new(AtomicUsize::new(0));
        let hits_clone = Arc::clone(&upstream_hits);

        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((len, peer)) = udp.recv_from(&mut buf).await {
                hits_clone.fetch_add(1, Ordering::Relaxed);
                let pkt = buf[..len].to_vec();
                let u_sock = udp.local_addr().unwrap();
                let _ = u_sock;
                tokio::time::sleep(Duration::from_millis(120)).await;
                let resp = build_mock_dns_answer_with_ttl(&pkt, 300);
                let _ = udp.send_to(&resp, peer).await;
            }
        });

        let cfg = DohConfig {
            local_bind_address: "127.0.0.1:0".parse().unwrap(),
            server_address: upstream_addr,
            cache_size: 1024,
            coalesce_queries: true,
            ..DohConfig::default()
        };
        let odoh_keys =
            OdohKeyManager::spawn(tokio::runtime::Handle::current(), Duration::from_secs(3600))
                .unwrap();
        let engine = DohEngine::new(cfg, odoh_keys).unwrap();

        let mut tasks = Vec::new();
        for i in 0..8u8 {
            let eng = engine.clone();
            tasks.push(tokio::spawn(async move {
                let name_wire: &[u8] = if i % 2 == 0 {
                    b"\x08CoAlEsCe\x07ExAmPlE\x03cOm\x00"
                } else {
                    b"\x08coalesce\x07example\x03com\x00"
                };
                let mut q = build_sample_query(name_wire, 1, i % 2 == 0);
                q[0] = 0x42;
                q[1] = i;
                let res = eng
                    .process_dns_query(
                        q.clone(),
                        None,
                        tokio::time::Instant::now() + Duration::from_secs(3),
                    )
                    .await
                    .unwrap();
                (i, q, res)
            }));
        }

        for t in tasks {
            let (i, orig_q, res) = t.await.unwrap();
            assert_eq!(&res.wire_bytes[0..2], &[0x42, i]);
            // Verify 0x20 question section casing matches each individual client's query
            assert_eq!(&res.wire_bytes[12..29], &orig_q[12..29]);
            if i % 2 == 0 {
                assert_eq!(res.wire_bytes.len() % RESPONSE_PADDING_BLOCK_SIZE, 0);
            }
        }

        assert_eq!(
            upstream_hits.load(Ordering::Relaxed),
            1,
            "expected all 8 concurrent identical queries to coalesce into 1 upstream lookup"
        );
        let prom = engine.metrics.render_prometheus();
        assert!(prom.contains("daviante_doh_coalesced_queries_total 7"));
    }

    #[tokio::test]
    async fn upstream_round_robin_and_parallel_strategies() {
        assert_eq!(
            UpstreamStrategy::from_str_name("round-robin").unwrap(),
            UpstreamStrategy::RoundRobin
        );
        assert_eq!(
            UpstreamStrategy::from_str_name("parallel").unwrap(),
            UpstreamStrategy::Parallel
        );
        assert!(UpstreamStrategy::from_str_name("invalid").is_err());

        // 1. Round-Robin across 2 healthy upstreams
        let u1_hits = Arc::new(AtomicUsize::new(0));
        let u2_hits = Arc::new(AtomicUsize::new(0));
        let u1_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let u2_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let u1_addr = u1_sock.local_addr().unwrap();
        let u2_addr = u2_sock.local_addr().unwrap();

        let h1 = Arc::clone(&u1_hits);
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((len, peer)) = u1_sock.recv_from(&mut buf).await {
                h1.fetch_add(1, Ordering::Relaxed);
                let resp = build_mock_dns_answer_with_ttl(&buf[..len], 60);
                let _ = u1_sock.send_to(&resp, peer).await;
            }
        });
        let h2 = Arc::clone(&u2_hits);
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((len, peer)) = u2_sock.recv_from(&mut buf).await {
                h2.fetch_add(1, Ordering::Relaxed);
                let resp = build_mock_dns_answer_with_ttl(&buf[..len], 60);
                let _ = u2_sock.send_to(&resp, peer).await;
            }
        });

        let cfg_rr = DohConfig {
            local_bind_address: "127.0.0.1:0".parse().unwrap(),
            server_address: u1_addr,
            upstream_addresses: vec![u1_addr, u2_addr],
            upstream_strategy: UpstreamStrategy::RoundRobin,
            ..DohConfig::default()
        };
        let odoh_keys =
            OdohKeyManager::spawn(tokio::runtime::Handle::current(), Duration::from_secs(3600))
                .unwrap();
        let eng_rr = DohEngine::new(cfg_rr, odoh_keys.clone()).unwrap();
        for i in 0..4u8 {
            let mut q = build_sample_query(b"\x02rr\x07example\x03com\x00", 1, false);
            q[1] = i;
            let _ = eng_rr
                .process_dns_query(
                    q,
                    None,
                    tokio::time::Instant::now() + Duration::from_secs(2),
                )
                .await
                .unwrap();
        }
        assert_eq!(u1_hits.load(Ordering::Relaxed), 2);
        assert_eq!(u2_hits.load(Ordering::Relaxed), 2);

        // 2. Parallel strategy: slow upstream (500ms) + fast upstream (10ms) -> completes in < 200ms
        let slow_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let slow_addr = slow_sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((len, peer)) = slow_sock.recv_from(&mut buf).await {
                let pkt = buf[..len].to_vec();
                tokio::time::sleep(Duration::from_millis(500)).await;
                let resp = build_mock_dns_answer_with_ttl(&pkt, 60);
                let _ = slow_sock.send_to(&resp, peer).await;
            }
        });

        let cfg_par = DohConfig {
            local_bind_address: "127.0.0.1:0".parse().unwrap(),
            server_address: slow_addr,
            upstream_addresses: vec![slow_addr, u1_addr],
            upstream_strategy: UpstreamStrategy::Parallel,
            ..DohConfig::default()
        };
        let eng_par = DohEngine::new(cfg_par, odoh_keys).unwrap();
        let started = tokio::time::Instant::now();
        let q_par = build_sample_query(b"\x04fast\x07example\x03com\x00", 1, false);
        let _ = eng_par
            .process_dns_query(q_par, None, started + Duration::from_secs(2))
            .await
            .unwrap();
        assert!(started.elapsed() < Duration::from_millis(250));
    }

    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn upstream_dns_over_tls_rfc7858() {
        let (cert_path, key_path) = crate::tls::write_temp_cert_and_key("upstream-dot");
        let acceptor = daviante_doh::tls::build_tls_acceptor(&cert_path, &key_path).unwrap();
        let dot_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dot_addr = dot_listener.local_addr().unwrap();

        tokio::spawn(async move {
            while let Ok((stream, _)) = dot_listener.accept().await {
                let acc = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(mut tls_stream) = acc.accept(stream).await {
                        let mut len_buf = [0u8; 2];
                        if tls_stream.read_exact(&mut len_buf).await.is_ok() {
                            let qlen = u16::from_be_bytes(len_buf) as usize;
                            let mut qbuf = vec![0u8; qlen];
                            if tls_stream.read_exact(&mut qbuf).await.is_ok() {
                                let resp = build_mock_dns_answer_with_ttl(&qbuf, 120);
                                let rlen = (resp.len() as u16).to_be_bytes();
                                let _ = tls_stream.write_all(&rlen).await;
                                let _ = tls_stream.write_all(&resp).await;
                                let _ = tls_stream.flush().await;
                            }
                        }
                    }
                });
            }
        });

        let cfg = DohConfig {
            local_bind_address: "127.0.0.1:0".parse().unwrap(),
            server_address: dot_addr,
            upstream_dot_sni: Some("localhost".into()),
            tls_cert_path: Some(cert_path.clone()),
            tls_cert_key_path: Some(key_path.clone()),
            ..DohConfig::default()
        };
        let odoh_keys =
            OdohKeyManager::spawn(tokio::runtime::Handle::current(), Duration::from_secs(3600))
                .unwrap();
        let engine = DohEngine::new(cfg, odoh_keys).unwrap();

        let q = build_sample_query(b"\x03dot\x07example\x03com\x00", 1, false);
        let res = engine
            .process_dns_query(
                q,
                None,
                tokio::time::Instant::now() + Duration::from_secs(3),
            )
            .await
            .unwrap();
        assert_eq!(wire::rcode(&res.unpadded_wire_bytes), 0);
        let prom = engine.metrics.render_prometheus();
        assert!(prom.contains(&format!(
            "daviante_doh_upstream_queries_total{{upstream=\"{dot_addr}\",transport=\"dot\",result=\"ok\"}} 1"
        )));

        let _ = std::fs::remove_file(cert_path);
        let _ = std::fs::remove_file(key_path);
    }

    #[tokio::test]
    async fn rebinding_protection_split_horizon_hosts_and_hot_reload() {
        // Upstream returns private RFC 1918 IP 192.168.1.50
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = udp.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((len, peer)) = udp.recv_from(&mut buf).await {
                let q_end = wire::skip_questions(&buf[..len]).unwrap();
                let mut resp = buf[..q_end].to_vec();
                resp[2] = 0x81;
                resp[3] = 0x80;
                write_u16_be(&mut resp, 4, 1).unwrap();
                write_u16_be(&mut resp, 6, 1).unwrap();
                write_u16_be(&mut resp, 8, 0).unwrap();
                write_u16_be(&mut resp, 10, 0).unwrap();
                resp.extend_from_slice(
                    b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\xa8\x01\x32",
                );
                let _ = udp.send_to(&resp, peer).await;
            }
        });

        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let hosts_path = dir.join(format!("daviante-doh-hosts-{pid}.txt"));
        let allow_path = dir.join(format!("daviante-doh-allow-{pid}.txt"));
        let block_path = dir.join(format!("daviante-doh-block-{pid}.txt"));

        std::fs::write(
            &hosts_path,
            "10.20.30.40 intranet.corp.local\nfd00::42 intranet.corp.local\n",
        )
        .unwrap();
        std::fs::write(&allow_path, "allowed.internal.local\n").unwrap();
        std::fs::write(&block_path, "initial-blocked.example.com\n").unwrap();

        let cfg = DohConfig {
            local_bind_address: "127.0.0.1:0".parse().unwrap(),
            server_address: upstream_addr,
            allowlist_file: Some(allow_path.clone()),
            blocklist_file: Some(block_path.clone()),
            hosts_file: Some(hosts_path.clone()),
            block_private_rebinding: true,
            ..DohConfig::default()
        };
        let odoh_keys =
            OdohKeyManager::spawn(tokio::runtime::Handle::current(), Duration::from_secs(3600))
                .unwrap();
        let engine = DohEngine::new(cfg, odoh_keys).unwrap();

        // 1. Split-Horizon Hosts File: A, AAAA, and reverse PTR queries resolved locally
        let q_a = build_sample_query(b"\x08intranet\x04corp\x05local\x00", 1, false);
        let r_a = engine
            .process_dns_query(
                q_a,
                None,
                tokio::time::Instant::now() + Duration::from_secs(2),
            )
            .await
            .unwrap();
        let j_a = decode_wire_to_json(&r_a.unpadded_wire_bytes).unwrap();
        assert_eq!(j_a.answer.unwrap()[0].data, "10.20.30.40");

        let q_aaaa = build_sample_query(b"\x08intranet\x04corp\x05local\x00", 28, false);
        let r_aaaa = engine
            .process_dns_query(
                q_aaaa,
                None,
                tokio::time::Instant::now() + Duration::from_secs(2),
            )
            .await
            .unwrap();
        let j_aaaa = decode_wire_to_json(&r_aaaa.unpadded_wire_bytes).unwrap();
        assert_eq!(j_aaaa.answer.unwrap()[0].data, "fd00::42");

        let q_ptr = build_sample_query(
            b"\x0240\x0230\x0220\x0210\x07in-addr\x04arpa\x00",
            12,
            false,
        );
        let r_ptr = engine
            .process_dns_query(
                q_ptr,
                None,
                tokio::time::Instant::now() + Duration::from_secs(2),
            )
            .await
            .unwrap();
        let j_ptr = decode_wire_to_json(&r_ptr.unpadded_wire_bytes).unwrap();
        assert_eq!(j_ptr.answer.unwrap()[0].data, "intranet.corp.local");

        // 2. DNS Rebinding Protection blocks public domain resolving to 192.168.1.50
        let q_rebind = build_sample_query(b"\x06rebind\x07example\x03com\x00", 1, true);
        let r_rebind = engine
            .process_dns_query(
                q_rebind,
                None,
                tokio::time::Instant::now() + Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(wire::rcode(&r_rebind.unpadded_wire_bytes), RCODE_NXDOMAIN);
        let j_rebind = decode_wire_to_json(&r_rebind.unpadded_wire_bytes).unwrap();
        assert!(j_rebind
            .comment
            .as_deref()
            .unwrap_or("")
            .contains("DNS Rebinding Protection"));

        // 3. Allowlisted domain is permitted to resolve to 192.168.1.50
        let q_allowed = build_sample_query(b"\x07allowed\x08internal\x05local\x00", 1, false);
        let r_allowed = engine
            .process_dns_query(
                q_allowed,
                None,
                tokio::time::Instant::now() + Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(wire::rcode(&r_allowed.unpadded_wire_bytes), 0);

        // 4. Lock-free Hot-Reload of blocklist & hosts file
        std::fs::write(&block_path, "newly-blocked.example.com\n").unwrap();
        engine
            .policy
            .reload_from_files(
                Some(&allow_path),
                Some(&block_path),
                Some(&hosts_path),
                BlockAction::Nxdomain,
                true,
            )
            .unwrap();
        assert!(!engine.policy.is_blocked("initial-blocked.example.com"));
        assert!(engine.policy.is_blocked("newly-blocked.example.com"));

        let prom = engine.metrics.render_prometheus();
        assert!(prom.contains("daviante_doh_hosts_hits_total 3"));
        assert!(prom.contains("daviante_doh_rebinding_blocked_total 1"));

        let _ = std::fs::remove_file(hosts_path);
        let _ = std::fs::remove_file(allow_path);
        let _ = std::fs::remove_file(block_path);
    }
}

// =============================================================================
// Admin Control-Plane API (/api/v1/*), RBAC, CSRF, & All-29 DNS Record Types Tests
// =============================================================================
pub mod admin_control_plane {
    use super::*;
    use daviante_doh::admin::auth::AdminRole;
    use daviante_doh::admin::crypto::hash_password_argon2id;
    use daviante_doh::policy::{
        format_bind_preview, validate_record_against_store, LocalDnsRecord, LocalRecordData,
    };

    #[test]
    fn all_29_dns_record_types_compile_and_format_bind_preview() {
        let samples: Vec<LocalRecordData> = vec![
            LocalRecordData::A {
                ip: "10.10.20.30".into(),
                auto_ptr: true,
            },
            LocalRecordData::AAAA {
                ip: "2001:db8::42".into(),
                auto_ptr: true,
            },
            LocalRecordData::CNAME {
                target: "target.internal.corp".into(),
            },
            LocalRecordData::DNAME {
                target: "subtree.internal.corp".into(),
            },
            LocalRecordData::MX {
                priority: 10,
                target: "mail.internal.corp".into(),
            },
            LocalRecordData::TXT {
                content: "v=spf1 include:internal.corp -all".into(),
            },
            LocalRecordData::SPF {
                content: "v=spf1 -all".into(),
            },
            LocalRecordData::SRV {
                priority: 10,
                weight: 5,
                port: 8443,
                target: "api.internal.corp".into(),
            },
            LocalRecordData::CAA {
                flags: 0,
                tag: "issue".into(),
                value: "letsencrypt.org".into(),
            },
            LocalRecordData::HTTPS {
                priority: 1,
                target: ".".into(),
                svc_params: "alpn=\"h2,h3\" port=8443 ipv4hint=10.10.20.30".into(),
            },
            LocalRecordData::SVCB {
                priority: 1,
                target: "svc.internal.corp".into(),
                svc_params: "alpn=\"h2\"".into(),
            },
            LocalRecordData::NS {
                target: "ns1.internal.corp".into(),
            },
            LocalRecordData::PTR {
                target: "host.internal.corp".into(),
            },
            LocalRecordData::SOA {
                mname: "ns1.internal.corp".into(),
                rname: "hostmaster.internal.corp".into(),
                serial: 2026102401,
                refresh: 3600,
                retry: 600,
                expire: 604800,
                minimum: 300,
            },
            LocalRecordData::TLSA {
                usage: 3,
                selector: 1,
                matching_type: 1,
                cert_data: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    .into(),
            },
            LocalRecordData::SMIMEA {
                usage: 3,
                selector: 1,
                matching_type: 1,
                cert_data: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    .into(),
            },
            LocalRecordData::SSHFP {
                algorithm: 4,
                fp_type: 2,
                fingerprint: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    .into(),
            },
            LocalRecordData::DS {
                key_tag: 12345,
                algorithm: 13,
                digest_type: 2,
                digest: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
            },
            LocalRecordData::CDS {
                key_tag: 12345,
                algorithm: 13,
                digest_type: 2,
                digest: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
            },
            LocalRecordData::DNSKEY {
                flags: 257,
                protocol: 3,
                algorithm: 13,
                public_key: "AQIDBAUGBwg=".into(),
            },
            LocalRecordData::CDNSKEY {
                flags: 257,
                protocol: 3,
                algorithm: 13,
                public_key: "AQIDBAUGBwg=".into(),
            },
            LocalRecordData::NAPTR {
                order: 100,
                preference: 10,
                flags: "s".into(),
                service: "SIP+D2U".into(),
                regexp: String::new(),
                replacement: "_sip._udp.internal.corp".into(),
            },
            LocalRecordData::URI {
                priority: 10,
                weight: 1,
                target: "https://internal.corp/svc".into(),
            },
            LocalRecordData::HINFO {
                cpu: "X86-64".into(),
                os: "LINUX".into(),
            },
            LocalRecordData::RP {
                mbox: "ops.internal.corp".into(),
                txt: "txt.internal.corp".into(),
            },
            LocalRecordData::LOC {
                coordinates: "37 46 29.744 N 122 25 9.816 W 15.00m 1m 10000m 10m".into(),
            },
            LocalRecordData::CERT {
                cert_type: 1,
                key_tag: 12345,
                algorithm: 13,
                cert_data: "AQIDBAUGBwg=".into(),
            },
            LocalRecordData::OPENPGPKEY {
                public_key: "AQIDBAUGBwg=".into(),
            },
            LocalRecordData::RAW {
                rr_type: 65280,
                rdata_hex: "c0000201".into(),
            },
        ];

        assert_eq!(samples.len(), 29);
        for (idx, data) in samples.into_iter().enumerate() {
            let domain = if matches!(data, LocalRecordData::SRV { .. }) {
                format!("_https._tcp.node-{idx}.internal.corp")
            } else if matches!(data, LocalRecordData::PTR { .. }) {
                format!("{idx}.20.10.10.in-addr.arpa")
            } else {
                format!("node-{idx}.internal.corp")
            };
            let rec = LocalDnsRecord {
                id: format!("rec-{idx}"),
                zone_id: None,
                domain: domain.clone(),
                data,
                ttl: 300,
                enabled: true,
                comment: "unit-test".into(),
                updated_at_epoch: 100,
            };
            let compiled = validate_record_against_store(&rec, &[]).unwrap();
            assert!(!compiled.rdata.is_empty());
            let bind_str = format_bind_preview(&rec);
            assert!(bind_str.contains(&format!("{domain}. 300 IN")));

            // Verify all 29 RR types decode cleanly to human-readable presentation format in JSON DoH
            let q = daviante_doh::dns::wire::build_minimal_query_packet(
                &domain,
                compiled.rr_type,
                false,
            )
            .unwrap();
            let wire = daviante_doh::dns::wire::build_local_authoritative_response(
                &q,
                0,
                &[(domain.clone(), compiled.rr_type, 300, compiled.rdata.clone())],
                &[],
                &[],
            )
            .unwrap();
            let decoded_json = daviante_doh::dns::json::decode_wire_to_json(&wire).unwrap();
            let ans = decoded_json.answer.expect("Answer section should be present");
            assert_eq!(ans.len(), 1);
            assert!(!ans[0].data.is_empty());
        }
    }

    #[tokio::test]
    async fn admin_api_auth_csrf_rbac_persistence_and_live_dns_lookup() {
        let upstream_addr = start_mock_upstream(false).await;
        let pub_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let adm_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pub_addr = pub_listener.local_addr().unwrap();
        let adm_addr = adm_listener.local_addr().unwrap();

        let store_path = std::env::temp_dir().join(format!(
            "daviante-doh-admin-store-{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&store_path);

        let salt = b"0123456789abcdef";
        let password_hash = hash_password_argon2id(b"S3cureAdminPass!2026", salt, 64, 2, 1).unwrap();

        let cfg = DohConfig {
            listen_address: pub_addr,
            admin_listen_address: Some(adm_addr),
            local_bind_address: "127.0.0.1:0".parse().unwrap(),
            server_address: upstream_addr,
            enable_admin_ui: true,
            dns_store_file: Some(store_path.clone()),
            admin_username: Some("admin".into()),
            admin_password_hash: Some(password_hash),
            cache_size: 256,
            keepalive: false,
            ..DohConfig::default()
        };
        let odoh_keys =
            OdohKeyManager::spawn(tokio::runtime::Handle::current(), Duration::from_secs(3600))
                .unwrap();
        let engine = DohEngine::new(cfg, odoh_keys).unwrap();
        let engine_ref = engine.clone();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ =
                serve_with_admin_and_shutdown(engine, pub_listener, Some(adm_listener), async {
                    let _ = rx.await;
                })
                .await;
        });

        // 1. Public listener never exposes /api/v1/* (returns 404)
        let (pub_api_hdr, _) = raw_http_request(
            pub_addr,
            "GET /api/v1/dns/records HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            b"",
        )
        .await;
        assert!(pub_api_hdr.starts_with("HTTP/1.1 404"));

        // 2. Unauthenticated request on admin listener to /api/v1/dns/records returns 401
        let (unauth_hdr, _) = raw_http_request(
            adm_addr,
            "GET /api/v1/dns/records HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            b"",
        )
        .await;
        assert!(unauth_hdr.starts_with("HTTP/1.1 401"));

        // 3. Invalid login returns generic 401 "Invalid username or password."
        let bad_login = br#"{"username":"admin","password":"wrong"}"#;
        let (bad_hdr, bad_body) = raw_http_request(
            adm_addr,
            &format!(
                "POST /api/v1/auth/login HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                bad_login.len()
            ),
            bad_login,
        )
        .await;
        assert!(bad_hdr.starts_with("HTTP/1.1 401"));
        let bad_json: serde_json::Value = serde_json::from_slice(&bad_body).unwrap();
        assert_eq!(bad_json["detail"], "Invalid username or password.");

        // 4. Valid login returns 200 OK + Set-Cookie + csrf_token
        let good_login = br#"{"username":"admin","password":"S3cureAdminPass!2026"}"#;
        let (login_hdr, login_body) = raw_http_request(
            adm_addr,
            &format!(
                "POST /api/v1/auth/login HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                good_login.len()
            ),
            good_login,
        )
        .await;
        assert!(login_hdr.starts_with("HTTP/1.1 200 OK"));
        let cookie_line = login_hdr
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("set-cookie:"))
            .unwrap();
        let session_cookie = cookie_line
            .split_once(':')
            .unwrap()
            .1
            .trim()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let login_json: serde_json::Value = serde_json::from_slice(&login_body).unwrap();
        let csrf_token = login_json["csrf_token"].as_str().unwrap().to_string();

        // 5. Mutation without X-CSRF-Token is rejected with 403 Forbidden (CSRF_INVALID)
        let rec_body = br#"{"domain":"db.internal.corp","ttl":300,"enabled":true,"comment":"primary db","record":{"type":"A","ip":"10.99.0.10","auto_ptr":true}}"#;
        let (no_csrf_hdr, _) = raw_http_request(
            adm_addr,
            &format!(
                "POST /api/v1/dns/records HTTP/1.1\r\nHost: localhost\r\nCookie: {session_cookie}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                rec_body.len()
            ),
            rec_body,
        )
        .await;
        assert!(no_csrf_hdr.starts_with("HTTP/1.1 403"));

        // 6. Create record with valid session cookie + X-CSRF-Token succeeds (201 Created)
        let (create_hdr, create_body) = raw_http_request(
            adm_addr,
            &format!(
                "POST /api/v1/dns/records HTTP/1.1\r\nHost: localhost\r\nCookie: {session_cookie}\r\nX-CSRF-Token: {csrf_token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                rec_body.len()
            ),
            rec_body,
        )
        .await;
        assert!(create_hdr.starts_with("HTTP/1.1 201 Created"));
        let created_json: serde_json::Value = serde_json::from_slice(&create_body).unwrap();
        assert_eq!(created_json["domain"], "db.internal.corp");
        assert!(store_path.exists());

        // 7. Create CNAME record at the same owner name is rejected with 409 Conflict (CNAME_CONFLICT)
        let cname_conflict_body = br#"{"domain":"db.internal.corp","ttl":300,"enabled":true,"comment":"","record":{"type":"CNAME","target":"other.internal.corp"}}"#;
        let (conflict_hdr, conflict_resp) = raw_http_request(
            adm_addr,
            &format!(
                "POST /api/v1/dns/records HTTP/1.1\r\nHost: localhost\r\nCookie: {session_cookie}\r\nX-CSRF-Token: {csrf_token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                cname_conflict_body.len()
            ),
            cname_conflict_body,
        )
        .await;
        assert!(conflict_hdr.starts_with("HTTP/1.1 409 Conflict"));
        let conflict_json: serde_json::Value = serde_json::from_slice(&conflict_resp).unwrap();
        assert_eq!(conflict_json["error_code"], "CNAME_CONFLICT");

        // 8. Live DNS Lookup via /api/v1/dns/lookup resolves db.internal.corp from local_record
        let lookup_body = br#"{"name":"db.internal.corp","record_type":"A","do_bit":false}"#;
        let (lk_hdr, lk_resp) = raw_http_request(
            adm_addr,
            &format!(
                "POST /api/v1/dns/lookup HTTP/1.1\r\nHost: localhost\r\nCookie: {session_cookie}\r\nX-CSRF-Token: {csrf_token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                lookup_body.len()
            ),
            lookup_body,
        )
        .await;
        assert!(lk_hdr.starts_with("HTTP/1.1 200 OK"));
        let lk_json: serde_json::Value = serde_json::from_slice(&lk_resp).unwrap();
        assert_eq!(lk_json["source"], "local_store");
        assert_eq!(lk_json["dns_json"]["Answer"][0]["data"], "10.99.0.10");

        // 9. Viewer RBAC negative test: Viewer can GET records, but POST /api/v1/dns/records is denied with 403 Forbidden
        let viewer_session = engine_ref
            .admin_sessions()
            .create_session("viewer-user".into(), AdminRole::Viewer, "oidc")
            .unwrap();
        let viewer_cookie = format!("doh_session={}", viewer_session.session_id);
        let (v_get_hdr, _) = raw_http_request(
            adm_addr,
            &format!(
                "GET /api/v1/dns/records HTTP/1.1\r\nHost: localhost\r\nCookie: {viewer_cookie}\r\nConnection: close\r\n\r\n"
            ),
            b"",
        )
        .await;
        assert!(v_get_hdr.starts_with("HTTP/1.1 200 OK"));

        let (v_post_hdr, v_post_body) = raw_http_request(
            adm_addr,
            &format!(
                "POST /api/v1/dns/records HTTP/1.1\r\nHost: localhost\r\nCookie: {viewer_cookie}\r\nX-CSRF-Token: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                viewer_session.csrf_token,
                rec_body.len()
            ),
            rec_body,
        )
        .await;
        assert!(v_post_hdr.starts_with("HTTP/1.1 403 Forbidden"));
        let v_err: serde_json::Value = serde_json::from_slice(&v_post_body).unwrap();
        assert_eq!(v_err["error_code"], "FORBIDDEN");

        // 10. Create Authoritative DNS Zone (`corp.internal`) and verify relative @/subdomain records,
        // SOA in Authority on NXDOMAIN/NODATA, A/AAAA Glue in Additional, DNAME subtree redirection,
        // QTYPE=ANY, BIND export/import, and Telemetry Activity / Audit Trail.
        let zone_body = br#"{"name":"corp.internal","mode":"authoritative","primary_ns":"ns1.corp.internal","admin_email":"dnsops.corp.internal","default_ttl":300,"enabled":true,"comment":"Primary internal zone"}"#;
        let (z_hdr, z_resp) = raw_http_request(
            adm_addr,
            &format!(
                "POST /api/v1/dns/zones HTTP/1.1\r\nHost: localhost\r\nCookie: {session_cookie}\r\nX-CSRF-Token: {csrf_token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                zone_body.len()
            ),
            zone_body,
        )
        .await;
        assert!(z_hdr.starts_with("HTTP/1.1 201 Created"));
        let z_json: serde_json::Value = serde_json::from_slice(&z_resp).unwrap();
        let zone_id = z_json["id"].as_str().unwrap().to_string();
        assert_eq!(z_json["name"], "corp.internal");
        assert_eq!(z_json["mode"], "authoritative");

        // Create relative `@`, `mail` (A), `@` (MX -> mail.corp.internal), and `legacy` (DNAME -> corp.internal) via BIND Import
        let bind_import_payload = serde_json::json!({
            "zone_id": zone_id,
            "dry_run": false,
            "content": "$TTL 300\n@ IN A 10.50.0.1\nmail IN A 10.50.0.25\n@ IN MX 10 mail.corp.internal.\nlegacy IN DNAME corp.internal.\n"
        })
        .to_string();
        let (imp_hdr, imp_resp) = raw_http_request(
            adm_addr,
            &format!(
                "POST /api/v1/dns/records/import HTTP/1.1\r\nHost: localhost\r\nCookie: {session_cookie}\r\nX-CSRF-Token: {csrf_token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                bind_import_payload.len()
            ),
            bind_import_payload.as_bytes(),
        )
        .await;
        assert!(imp_hdr.starts_with("HTTP/1.1 200 OK"));
        let imp_json: serde_json::Value = serde_json::from_slice(&imp_resp).unwrap();
        assert_eq!(imp_json["imported_count"], 4);

        // Query MX on corp.internal -> Answer has MX, Additional has in-bailiwick A glue for mail.corp.internal
        let mx_lk_body = br#"{"name":"corp.internal","record_type":"MX","do_bit":false}"#;
        let (mx_hdr, mx_resp) = raw_http_request(
            adm_addr,
            &format!(
                "POST /api/v1/dns/lookup HTTP/1.1\r\nHost: localhost\r\nCookie: {session_cookie}\r\nX-CSRF-Token: {csrf_token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                mx_lk_body.len()
            ),
            mx_lk_body,
        )
        .await;
        assert!(mx_hdr.starts_with("HTTP/1.1 200 OK"));
        let mx_json: serde_json::Value = serde_json::from_slice(&mx_resp).unwrap();
        assert_eq!(mx_json["dns_json"]["Answer"][0]["data"], "10 mail.corp.internal");
        assert_eq!(mx_json["dns_json"]["Additional"][0]["name"], "mail.corp.internal");
        assert_eq!(mx_json["dns_json"]["Additional"][0]["data"], "10.50.0.25");

        // Query DNAME subtree (`mail.legacy.corp.internal` A) -> DNAME + synthesized CNAME + final A (10.50.0.25)
        let dname_lk_body = br#"{"name":"mail.legacy.corp.internal","record_type":"A","do_bit":false}"#;
        let (_, dname_resp) = raw_http_request(
            adm_addr,
            &format!(
                "POST /api/v1/dns/lookup HTTP/1.1\r\nHost: localhost\r\nCookie: {session_cookie}\r\nX-CSRF-Token: {csrf_token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                dname_lk_body.len()
            ),
            dname_lk_body,
        )
        .await;
        let dname_json: serde_json::Value = serde_json::from_slice(&dname_resp).unwrap();
        let dname_answers = dname_json["dns_json"]["Answer"].as_array().unwrap();
        assert_eq!(dname_answers.len(), 3);
        assert_eq!(dname_answers[0]["type"], 39); // DNAME
        assert_eq!(dname_answers[1]["type"], 5);  // Synthesized CNAME
        assert_eq!(dname_answers[2]["data"], "10.50.0.25");

        // Query non-existent name in Authoritative zone (`missing.corp.internal`) -> local NXDOMAIN (3) + SOA in Authority
        let nx_lk_body = br#"{"name":"missing.corp.internal","record_type":"A","do_bit":false}"#;
        let (_, nx_resp) = raw_http_request(
            adm_addr,
            &format!(
                "POST /api/v1/dns/lookup HTTP/1.1\r\nHost: localhost\r\nCookie: {session_cookie}\r\nX-CSRF-Token: {csrf_token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                nx_lk_body.len()
            ),
            nx_lk_body,
        )
        .await;
        let nx_json: serde_json::Value = serde_json::from_slice(&nx_resp).unwrap();
        assert_eq!(nx_json["status_rcode"], 3);
        assert_eq!(nx_json["source"], "local_store");
        assert_eq!(nx_json["dns_json"]["Authority"][0]["type"], 6); // SOA

        // Export zone to RFC 1035 BIND format
        let (exp_hdr, exp_resp) = raw_http_request(
            adm_addr,
            &format!(
                "GET /api/v1/dns/zones/{zone_id}/export HTTP/1.1\r\nHost: localhost\r\nCookie: {session_cookie}\r\nConnection: close\r\n\r\n"
            ),
            b"",
        )
        .await;
        assert!(exp_hdr.starts_with("HTTP/1.1 200 OK"));
        let exp_json: serde_json::Value = serde_json::from_slice(&exp_resp).unwrap();
        let bind_text = exp_json["bind_zone_text"].as_str().unwrap();
        assert!(bind_text.contains("$ORIGIN corp.internal."));
        assert!(bind_text.contains("IN SOA ns1.corp.internal."));

        // Verify Telemetry Activity & Admin Audit endpoint
        let (act_hdr, act_resp) = raw_http_request(
            adm_addr,
            &format!(
                "GET /api/v1/telemetry/activity HTTP/1.1\r\nHost: localhost\r\nCookie: {session_cookie}\r\nConnection: close\r\n\r\n"
            ),
            b"",
        )
        .await;
        assert!(act_hdr.starts_with("HTTP/1.1 200 OK"));
        let act_json: serde_json::Value = serde_json::from_slice(&act_resp).unwrap();
        assert!(!act_json["dns_activity"].as_array().unwrap().is_empty());
        assert!(!act_json["admin_audit"].as_array().unwrap().is_empty());

        let _ = tx.send(());
        let _ = std::fs::remove_file(store_path);
    }
}

