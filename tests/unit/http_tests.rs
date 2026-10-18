//! Unit tests for `src/http/handler.rs`.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use bytes::Bytes;
use daviante_doh::cache::CacheKey;
use daviante_doh::error::DohError;
use daviante_doh::handler::{
    format_audit_client_ip, DohEngine, RequestFlavor, MIME_DNS_JSON, MIME_DNS_MESSAGE,
    MIME_ODOH_MESSAGE,
};
use daviante_doh::odoh::OdohKeyManager;
use daviante_doh::policy::{BlockAction, DomainPolicy};
use daviante_doh::wire::{rcode, RCODE_NOTIMP, RCODE_SERVFAIL, RR_TYPE_ANY};
use daviante_doh::{ClientIpLogMode, DohConfig};
use http_body_util::{Empty, Full};
use hyper::body::Incoming;
use hyper::header::{STRICT_TRANSPORT_SECURITY, VARY};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::time::Instant;

fn build_query(labels: &[u8], qtype: u16) -> Vec<u8> {
    let mut q = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    q.extend_from_slice(labels);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    q
}

async fn send_test_req(
    engine: DohEngine,
    admin: bool,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: &'static [u8],
) -> Response<Incoming> {
    let (c_io, s_io) = tokio::io::duplex(16 * 1024);
    let peer: Option<SocketAddr> = Some("198.51.100.42:54321".parse().unwrap());
    tokio::spawn(async move {
        let svc = hyper::service::service_fn(move |req| {
            let eng = engine.clone();
            async move {
                if admin {
                    eng.handle_admin_request(req).await
                } else {
                    eng.handle_request(req, peer).await
                }
            }
        });
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(s_io), svc)
            .await;
    });

    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(c_io))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut builder = Request::builder().method(method).uri(uri);
    for &(k, v) in headers {
        builder = builder.header(k, v);
    }
    let req = builder.body(Full::new(Bytes::from_static(body))).unwrap();
    sender.send_request(req).await.unwrap()
}

#[test]
fn helpers_negotiation_headers_and_audit_ip() {
    let ip: Option<IpAddr> = Some("198.51.100.88".parse().unwrap());
    assert_eq!(
        format_audit_client_ip(ip, ClientIpLogMode::Full, 24, 56).as_deref(),
        Some("198.51.100.88")
    );

    assert!(DohEngine::extract_base64_dns_param(None).is_err());
    assert!(DohEngine::extract_base64_dns_param(Some("foo=bar")).is_err());
    assert!(DohEngine::extract_base64_dns_param(Some("dns=")).is_err());
    assert!(DohEngine::extract_base64_dns_param(Some("dns=***")).is_err());
    let oversized = format!("dns={}", "A".repeat(6000));
    assert!(matches!(
        DohEngine::extract_base64_dns_param(Some(&oversized)),
        Err(DohError::UriTooLong)
    ));

    assert_eq!(
        DohEngine::infer_flavor_from_query("dns=AAAB"),
        Some(RequestFlavor::WireDoh)
    );
    assert_eq!(
        DohEngine::infer_flavor_from_query("name=example.com"),
        Some(RequestFlavor::JsonDoh)
    );
    assert_eq!(DohEngine::infer_flavor_from_query("other=1"), None);
}

#[tokio::test]
async fn handler_formatting_security_headers_and_pipeline_branches() {
    let odoh_keys =
        OdohKeyManager::spawn(tokio::runtime::Handle::current(), Duration::from_secs(3600))
            .unwrap();
    let cfg = DohConfig {
        server_address: "127.0.0.1:0".parse().unwrap(),
        local_bind_address: "127.0.0.1:0".parse().unwrap(),
        enable_metrics: true,
        disable_any: true,
        disable_post: true,
        allow_odoh_post: false,
        cache_size: 64,
        log_queries: true,
        log_client_ip: ClientIpLogMode::Full,
        cors_allow_origin: "https://dns.example.com".into(),
        tls_cert_path: Some(PathBuf::from("/tmp/cert.pem")),
        ..DohConfig::default()
    };
    let mut engine = DohEngine::new(cfg, odoh_keys).unwrap();
    engine.policy = DomainPolicy::from_lists(
        ["allowed.example.com"],
        ["blocked-target.example.com"],
        BlockAction::Nxdomain,
    );

    // Cache-Control branches: no_store, private_cache, ttl=0, and standard with stale-*
    assert_eq!(engine.format_cache_control(60, true, false), "no-store");
    assert_eq!(
        engine.format_cache_control(60, false, true),
        "private, max-age=60"
    );
    assert_eq!(
        engine.format_cache_control(0, false, false),
        "max-age=0, no-cache"
    );
    assert!(engine
        .format_cache_control(120, false, false)
        .contains("stale-if-error="));

    // Security headers with TLS HSTS + custom CORS Origin Vary
    let mut sample_resp = engine.bad_request_response();
    engine.apply_security_headers(&mut sample_resp);
    assert!(sample_resp
        .headers()
        .contains_key(STRICT_TRANSPORT_SECURITY));
    let vary_str = sample_resp.headers().get(VARY).unwrap().to_str().unwrap();
    assert!(vary_str.contains("Origin"));

    // Explicit MIME & ct= negotiation branches
    assert_eq!(
        engine
            .negotiate_from_ct_param("ct=application%2Fdns-json")
            .unwrap()
            .unwrap(),
        RequestFlavor::JsonDoh
    );
    assert!(engine
        .classify_explicit_mime(MIME_ODOH_MESSAGE, false)
        .is_err());
    assert!(engine.classify_explicit_mime("text/plain", true).is_err());

    // 1. QTYPE=ANY blocked per RFC 8482, and direct QNAME blocked by DomainPolicy
    let any_q = build_query(b"\x07example\x03com\x00", RR_TYPE_ANY);
    let any_res = engine
        .process_dns_query(
            any_q,
            Some("198.51.100.1".parse().unwrap()),
            Instant::now() + Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(rcode(&any_res.unpadded_wire_bytes), RCODE_NOTIMP);

    let blocked_q = build_query(b"\x0eblocked-target\x07example\x03com\x00", 1);
    let blocked_res = engine
        .process_dns_query(blocked_q, None, Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(rcode(&blocked_res.unpadded_wire_bytes), 3); // NXDOMAIN

    // 2. Cache hit with blocked CNAME target in answer section
    let cname_q = build_query(b"\x05alias\x07example\x03com\x00", 1);
    let mut cached_resp = cname_q.clone();
    cached_resp[2] = 0x81;
    cached_resp[3] = 0x80;
    cached_resp[6] = 0x00;
    cached_resp[7] = 0x01; // ANCOUNT=1
    cached_resp.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c]);
    let rdata = b"\x0eblocked-target\x07example\x03com\x00";
    cached_resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    cached_resp.extend_from_slice(rdata);
    let key = CacheKey {
        qname: "alias.example.com".into(),
        qtype: 1,
        qclass: 1,
        do_bit: false,
        cd_bit: false,
    };
    engine.cache.insert(key, cached_resp, 60);
    let cname_hit = engine
        .process_dns_query(cname_q, None, Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(rcode(&cname_hit.unpadded_wire_bytes), 3); // NXDOMAIN

    // 3. Upstream Io error -> synthesize_upstream_servfail with EDE_NETWORK_ERROR
    let norm_q = build_query(b"\x07example\x03com\x00", 1);
    let sf_res = engine
        .process_dns_query(norm_q, None, Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(rcode(&sf_res.unpadded_wire_bytes), RCODE_SERVFAIL);
}

#[tokio::test]
async fn http_router_admin_and_public_edge_cases() {
    let odoh_keys =
        OdohKeyManager::spawn(tokio::runtime::Handle::current(), Duration::from_secs(3600))
            .unwrap();
    let cfg = DohConfig {
        enable_metrics: true,
        disable_post: true,
        allow_odoh_post: false,
        ..DohConfig::default()
    };
    let engine = DohEngine::new(cfg, odoh_keys).unwrap();

    // Admin listener: POST -> 405, unknown path -> 404, HEAD /livez, HEAD /readyz, HEAD /metrics -> 200
    assert_eq!(
        send_test_req(engine.clone(), true, "POST", "/livez", &[], b"")
            .await
            .status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_eq!(
        send_test_req(engine.clone(), true, "GET", "/unknown", &[], b"")
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send_test_req(engine.clone(), true, "HEAD", "/livez", &[], b"")
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        send_test_req(engine.clone(), true, "HEAD", "/readyz", &[], b"")
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        send_test_req(engine.clone(), true, "HEAD", "/metrics", &[], b"")
            .await
            .status(),
        StatusCode::OK
    );

    // Public listener: odohconfigs OPTIONS -> 204, POST -> 405, HEAD -> 200
    assert_eq!(
        send_test_req(
            engine.clone(),
            false,
            "OPTIONS",
            "/.well-known/odohconfigs",
            &[],
            b""
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        send_test_req(
            engine.clone(),
            false,
            "POST",
            "/.well-known/odohconfigs",
            &[],
            b""
        )
        .await
        .status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_eq!(
        send_test_req(
            engine.clone(),
            false,
            "HEAD",
            "/.well-known/odohconfigs",
            &[],
            b""
        )
        .await
        .status(),
        StatusCode::OK
    );

    // Public listener: /dns-query PUT -> 405, POST without Content-Type -> 415, POST with disable_post -> 405
    assert_eq!(
        send_test_req(engine.clone(), false, "PUT", "/dns-query", &[], b"")
            .await
            .status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_eq!(
        send_test_req(engine.clone(), false, "POST", "/dns-query", &[], b"")
            .await
            .status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    for mime in [MIME_DNS_MESSAGE, MIME_ODOH_MESSAGE, MIME_DNS_JSON] {
        assert_eq!(
            send_test_req(
                engine.clone(),
                false,
                "POST",
                "/dns-query",
                &[("content-type", mime)],
                b"123"
            )
            .await
            .status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
    }

    // GET with Accept: */* and ?name=example.com&cd=1&do=1&edns_client_subnet=198.51.100.0/24
    let json_r = send_test_req(
        engine.clone(),
        false,
        "HEAD",
        "/dns-query?name=example.com&type=A&cd=1&do=1&edns_client_subnet=198.51.100.0/24",
        &[("accept", "*/*")],
        b"",
    )
    .await;
    assert_eq!(json_r.status(), StatusCode::OK);

    // GET with ?ct= override, invalid dns= base64, and empty JSON name=
    assert_eq!(
        send_test_req(
            engine.clone(),
            false,
            "GET",
            "/dns-query?ct=application/oblivious-dns-message",
            &[],
            b""
        )
        .await
        .status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_eq!(
        send_test_req(
            engine.clone(),
            false,
            "GET",
            "/dns-query?dns=***",
            &[("accept", MIME_DNS_MESSAGE)],
            b""
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        send_test_req(
            engine.clone(),
            false,
            "GET",
            "/dns-query?name=",
            &[("accept", MIME_DNS_JSON)],
            b""
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );

    // GET with Accept: */* and no query params -> 406 Not Acceptable
    assert_eq!(
        send_test_req(
            engine,
            false,
            "GET",
            "/dns-query",
            &[("accept", "*/*")],
            b""
        )
        .await
        .status(),
        StatusCode::NOT_ACCEPTABLE
    );

    // Rate-limited engine (429 Too Many Requests) + Wire POST enabled
    let rl_keys =
        OdohKeyManager::spawn(tokio::runtime::Handle::current(), Duration::from_secs(3600))
            .unwrap();
    let rl_engine = DohEngine::new(
        DohConfig {
            rate_limit_rps: 1,
            rate_limit_burst: 1,
            ..DohConfig::default()
        },
        rl_keys,
    )
    .unwrap();
    assert_eq!(
        send_test_req(
            rl_engine.clone(),
            false,
            "POST",
            "/dns-query",
            &[("content-type", MIME_DNS_MESSAGE)],
            b"short"
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        send_test_req(rl_engine, false, "GET", "/dns-query", &[], b"")
            .await
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    let _ = Empty::<Bytes>::new();
}
