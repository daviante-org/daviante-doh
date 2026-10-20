//! Unit tests for `src/cli.rs`.

use std::sync::{mpsc, Mutex};

use daviante_doh::cli::{
    build_cli, execute_parsed_cli, execute_self_healthcheck, format_config_summary,
    loopback_probe_target, parse_from_matches, parse_socket_addr_flexible, print_dns_stamps,
    sanitize_empty_doh_env_vars, DohTracingSubscriber,
};
use daviante_doh::DohConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::Level;

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn empty_env_is_unset() {
    let _guard = ENV_LOCK.lock().unwrap();
    std::env::set_var("DOH_PUBLIC_PORT", "");
    std::env::set_var("DOH_LOCAL_BIND_ADDRESS", "   ");
    std::env::set_var("DOH_ENABLE_ECS", "");
    std::env::set_var("DOH_ALLOWLIST_FILE", "");
    std::env::set_var("DOH_BLOCKLIST_FILE", "");

    sanitize_empty_doh_env_vars();

    assert!(std::env::var("DOH_PUBLIC_PORT").is_err());
    assert!(std::env::var("DOH_LOCAL_BIND_ADDRESS").is_err());
    assert!(std::env::var("DOH_ENABLE_ECS").is_err());

    let m = build_cli().try_get_matches_from(["daviante-doh"]).unwrap();
    let parsed = parse_from_matches(&m).unwrap();
    assert_eq!(parsed.public_port, None);
    assert!(!parsed.config.enable_ecs);
}

#[test]
fn boolish_env_values() {
    let _guard = ENV_LOCK.lock().unwrap();
    let cases = [
        ("1", true),
        ("0", false),
        ("true", true),
        ("false", false),
        ("TRUE", true),
        ("FALSE", false),
        ("yes", true),
        ("no", false),
        ("YES", true),
        ("NO", false),
        ("on", true),
        ("off", false),
        ("ON", true),
        ("OFF", false),
    ];

    for (raw, expected) in cases {
        std::env::set_var("DOH_ENABLE_ECS", raw);
        std::env::set_var("DOH_ENABLE_METRICS", raw);
        let m = build_cli().try_get_matches_from(["daviante-doh"]).unwrap();
        let parsed = parse_from_matches(&m)
            .unwrap_or_else(|e| panic!("failed to parse boolish value '{raw}': {e}"));
        assert_eq!(
            parsed.config.enable_ecs, expected,
            "mismatch for DOH_ENABLE_ECS={raw}"
        );
        assert_eq!(
            parsed.config.enable_metrics, expected,
            "mismatch for DOH_ENABLE_METRICS={raw}"
        );
    }
    std::env::remove_var("DOH_ENABLE_ECS");
    std::env::remove_var("DOH_ENABLE_METRICS");
}

#[test]
fn full_cli_flags_summary_and_stamps() {
    let _guard = ENV_LOCK.lock().unwrap();
    let m = build_cli()
        .try_get_matches_from([
            "daviante-doh",
            "-l",
            ":8080",
            "--admin-listen-address",
            "127.0.0.1:9090",
            "-u",
            "9.9.9.9:53, ,1.1.1.1:53",
            "-b",
            "0.0.0.0:0",
            "--trusted-proxies",
            "10.0.0.0/8, ,fd00::/8",
            "-H",
            "doh.daviante.org",
            "-g",
            "203.0.113.10,203.0.113.11",
            "-j",
            "443",
            "--enable-metrics",
            "--disable-keepalive",
            "--disable-post",
            "--allow-odoh-post",
            "--disable-any",
            "--enable-ecs",
            "--log-queries",
            "--allowlist-file",
            "/tmp/allow.txt",
            "--blocklist-file",
            "/tmp/block.txt",
            "--hosts-file",
            "/tmp/hosts.txt",
            "--block-private-rebinding",
            "--serve-stale-ttl",
            "3600",
            "--cache-prefetch",
            "--disable-coalescing",
            "--upstream-strategy",
            "parallel",
            "--upstream-dot-sni",
            "dns.quad9.net",
            "--tls-cert-path",
            "/tmp/cert.pem",
            "--tls-cert-key-path",
            "/tmp/key.pem",
            "--tls-min-version",
            "1.3",
            "--log-level",
            "debug",
            "--log-format",
            "text",
            "--print-config",
        ])
        .unwrap();
    let parsed = parse_from_matches(&m).unwrap();
    assert!(parsed.print_config);
    assert_eq!(parsed.log_level, Level::DEBUG);
    assert_eq!(parsed.log_format, "text");

    let summary = format_config_summary(&parsed);
    assert!(summary.contains("--admin-listen-address 127.0.0.1:9090"));
    assert!(summary.contains("--trusted-proxies 10.0.0.0/8,fd00::/8"));
    assert!(summary.contains("--hostname doh.daviante.org"));
    assert!(summary.contains("--enable-metrics"));
    assert!(summary.contains("--disable-keepalive"));
    assert!(summary.contains("--disable-post"));
    assert!(summary.contains("--allow-odoh-post"));
    assert!(summary.contains("--disable-any"));
    assert!(summary.contains("--enable-ecs"));
    assert!(summary.contains("--log-queries"));
    assert!(summary.contains("--hosts-file /tmp/hosts.txt"));
    assert!(summary.contains("--block-private-rebinding"));
    assert!(summary.contains("--serve-stale-ttl 3600"));
    assert!(summary.contains("--cache-prefetch"));
    assert!(summary.contains("--disable-coalescing"));
    assert!(summary.contains("--upstream-strategy parallel"));
    assert!(summary.contains("--upstream-dot-sni dns.quad9.net"));

    // Verify empty upstream list error and remaining log_level variants
    let empty_u = build_cli()
        .try_get_matches_from(["daviante-doh", "-u", " , "])
        .unwrap();
    assert!(parse_from_matches(&empty_u).is_err());

    for (lvl_str, lvl_val) in [
        ("error", Level::ERROR),
        ("warn", Level::WARN),
        ("trace", Level::TRACE),
    ] {
        let lm = build_cli()
            .try_get_matches_from(["daviante-doh", "--log-level", lvl_str])
            .unwrap();
        assert_eq!(parse_from_matches(&lm).unwrap().log_level, lvl_val);
    }

    print_dns_stamps("doh.daviante.org", "/dns-query", &[], Some(443));
    print_dns_stamps(
        "doh.daviante.org",
        "/dns-query",
        &["203.0.113.10".to_string()],
        Some(443),
    );

    assert_eq!(
        loopback_probe_target("0.0.0.0:3000".parse().unwrap()),
        "127.0.0.1:3000".parse().unwrap()
    );
    assert_eq!(
        loopback_probe_target("[::]:3000".parse().unwrap()),
        "[::1]:3000".parse().unwrap()
    );
    assert!(parse_socket_addr_flexible(":notaport").is_err());
    assert!(parse_socket_addr_flexible("notanaddr").is_err());
}

#[test]
fn tracing_subscriber_json_and_text_visitors_and_cli_runner() {
    let (tx, rx) = mpsc::sync_channel::<String>(64);
    let json_sub = DohTracingSubscriber {
        max_level: Level::INFO,
        json_format: true,
        sender: tx.clone(),
    };
    tracing::subscriber::with_default(json_sub, || {
        let span = tracing::info_span!("test_span", id = 1u64);
        let _enter = span.enter();
        tracing::info!(
            count_u = 42u64,
            offset_i = -7i64,
            flag = true,
            text = "hello",
            dbg = ?(1, 2),
            "structured json event"
        );
        tracing::debug!("filtered debug event");
    });
    let emitted_json = rx.try_recv().unwrap();
    assert!(emitted_json.contains("\"service\":\"daviante-doh\""));
    assert!(emitted_json.contains("\"count_u\":42"));
    assert!(emitted_json.contains("\"offset_i\":-7"));
    assert!(emitted_json.contains("\"flag\":true"));

    let text_sub = DohTracingSubscriber {
        max_level: Level::DEBUG,
        json_format: false,
        sender: tx,
    };
    tracing::subscriber::with_default(text_sub, || {
        tracing::info!(key = "val", "human text event");
    });
    let emitted_text = rx.try_recv().unwrap();
    assert!(emitted_text.contains("[INFO]"));
    assert!(emitted_text.contains("human text event"));

    // Exercise execute_parsed_cli for --print-config and full startup + immediate shutdown
    let _guard = ENV_LOCK.lock().unwrap();
    let m_print = build_cli()
        .try_get_matches_from(["daviante-doh", "--print-config"])
        .unwrap();
    let p_print = parse_from_matches(&m_print).unwrap();
    assert!(execute_parsed_cli(p_print, std::future::ready(())).is_ok());

    let m_serve = build_cli()
        .try_get_matches_from([
            "daviante-doh",
            "-l",
            "127.0.0.1:0",
            "--admin-listen-address",
            "127.0.0.1:0",
            "-H",
            "doh.example.com",
            "--enable-metrics",
        ])
        .unwrap();
    let p_serve = parse_from_matches(&m_serve).unwrap();
    assert!(execute_parsed_cli(p_serve, std::future::ready(())).is_ok());
}

#[test]
fn self_healthcheck_probe_http_ok_and_fail() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                let mut buf = [0u8; 256];
                let _ = s.read(&mut buf).await;
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await;
            }
            if let Ok((mut s, _)) = listener.accept().await {
                let mut buf = [0u8; 256];
                let _ = s.read(&mut buf).await;
                let _ = s
                    .write_all(b"HTTP/1.1 503 Service Unavailable\r\n\r\n")
                    .await;
            }
        });

        let mut cfg = DohConfig {
            listen_address: addr,
            ..DohConfig::default()
        };
        assert!(execute_self_healthcheck(&cfg).await.is_ok());
        cfg.admin_listen_address = Some(addr);
        assert!(execute_self_healthcheck(&cfg).await.is_err());
    });
}
