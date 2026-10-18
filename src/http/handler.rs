//! Clean-room HTTP/1.1 & HTTP/2 request router for RFC 8484 DoH, RFC 9230 ODoH, JSON DoH,
//! W3C CORS preflight, Prometheus `/metrics`, Protective DNS policy, and `/livez` + `/readyz` + `/healthz` probes.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{
    HeaderName, HeaderValue, ACCEPT, ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS,
    ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_MAX_AGE, ALLOW, CACHE_CONTROL, CONTENT_LENGTH,
    CONTENT_SECURITY_POLICY, CONTENT_TYPE, REFERRER_POLICY, RETRY_AFTER, STRICT_TRANSPORT_SECURITY,
    VARY, X_CONTENT_TYPE_OPTIONS,
};
use hyper::{Method, Request, Response, StatusCode};
use serde_json::json;
use tokio::sync::Semaphore;
use tokio::time::Instant;

use crate::cache::{CacheKey, DnsCache};
use crate::dns::ecs::{resolve_client_ip, truncate_ip};
use crate::dns::json::{
    decode_wire_to_json, encode_json_query_to_wire, resolve_rr_type, JsonDnsQueryParams,
};
use crate::dns::odoh::OdohKeyManager;
use crate::dns::wire::{
    build_policy_response, finalize_wire_response_for_client, rcode, validate_and_parse_query,
    EDE_NETWORK_ERROR, EDE_NOT_SUPPORTED, EDE_NO_REACHABLE_AUTHORITY, MAX_DNS_QUERY_LEN,
    RCODE_FORMERR, RCODE_NOTIMP, RCODE_SERVFAIL, RR_TYPE_ANY,
};
use crate::error::DohError;
use crate::metrics::DohMetrics;
use crate::policy::{DomainPolicy, IpRateLimiter};
use crate::upstream::{resolve_upstream_with_set, ResolvedDnsPacket, UpstreamSet};
use crate::{ClientIpLogMode, DohConfig};

pub const MIME_DNS_MESSAGE: &str = "application/dns-message";
pub const MIME_ODOH_MESSAGE: &str = "application/oblivious-dns-message";
pub const MIME_DNS_JSON: &str = "application/dns-json";
pub const MIME_JSON: &str = "application/json";
pub const MIME_PROMETHEUS: &str = "text/plain; version=0.0.4; charset=utf-8";

pub type HttpBody = Full<Bytes>;

/// Negotiated protocol flavor for an incoming HTTP request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestFlavor {
    /// RFC 8484 binary wireformat (`application/dns-message`).
    WireDoh,
    /// RFC 9230 Oblivious DoH (`application/oblivious-dns-message`).
    ObliviousDoh,
    /// Google/Cloudflare JSON DoH (`application/dns-json`).
    JsonDoh,
}

/// Shared execution state for the `daviante-doh` HTTP/2 & HTTP/1.1 service.
#[derive(Clone, Debug)]
pub struct DohEngine {
    pub config: Arc<DohConfig>,
    pub odoh_keys: OdohKeyManager,
    pub tcp_limiter: Arc<Semaphore>,
    pub cache: DnsCache,
    pub policy: DomainPolicy,
    pub rate_limiter: IpRateLimiter,
    pub metrics: DohMetrics,
    pub upstreams: UpstreamSet,
    draining: Arc<AtomicBool>,
    cors_origin_header: HeaderValue,
}

impl DohEngine {
    /// Constructs and validates a new `DohEngine` from `DohConfig` and an active `OdohKeyManager`.
    /// Fails closed if `config` is invalid or if any configured Protective DNS policy file cannot be loaded (C-2).
    pub fn new(config: DohConfig, odoh_keys: OdohKeyManager) -> Result<Self, DohError> {
        config.validate()?;
        let cors_origin_header = HeaderValue::from_str(&config.cors_allow_origin).map_err(|e| {
            DohError::InvalidConfig(format!("invalid cors_allow_origin header: {e}"))
        })?;
        let tcp_slots = (config.max_clients / 4).max(8);
        let cache = DnsCache::new(config.cache_size);
        let policy = DomainPolicy::from_files(
            config.allowlist_file.as_deref(),
            config.blocklist_file.as_deref(),
            config.block_action,
        )?;
        let rate_limiter = IpRateLimiter::with_v6_prefix(
            config.rate_limit_rps,
            config.rate_limit_burst,
            config.rate_limit_v6_prefix,
        );

        Ok(Self {
            config: Arc::new(config),
            odoh_keys,
            tcp_limiter: Arc::new(Semaphore::new(tcp_slots)),
            cache,
            policy,
            rate_limiter,
            metrics: DohMetrics::new(),
            upstreams: UpstreamSet::default(),
            draining: Arc::new(AtomicBool::new(false)),
            cors_origin_header,
        })
    }

    /// Sets the graceful shutdown draining state (causes `/readyz` to return `503 Service Unavailable`).
    #[inline]
    pub fn set_draining(&self, draining: bool) {
        self.draining.store(draining, Ordering::Release);
    }

    /// Returns `true` if the server has entered graceful shutdown drain.
    #[inline]
    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }

    /// Handles an incoming HTTP request on the dedicated admin listener (`/livez`, `/readyz`, `/healthz`, `/metrics`).
    pub async fn handle_admin_request(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<HttpBody>, hyper::Error> {
        let path = req.uri().path();
        let method = req.method().clone();
        let is_head = method == Method::HEAD;

        if !matches!(method, Method::GET | Method::HEAD) {
            let mut resp = self.empty_status(StatusCode::METHOD_NOT_ALLOWED);
            self.apply_security_headers(&mut resp);
            return Ok(resp);
        }

        if let Some(resp) = self.try_handle_admin_path(path, is_head) {
            return Ok(resp);
        }

        let mut resp = self.empty_status(StatusCode::NOT_FOUND);
        self.apply_security_headers(&mut resp);
        Ok(resp)
    }

    fn try_handle_admin_path(&self, path: &str, is_head: bool) -> Option<Response<HttpBody>> {
        let mut resp = if path == "/livez" || path == self.config.health_path {
            self.handle_livez(is_head)
        } else if path == "/readyz" {
            self.handle_readyz(is_head)
        } else if self.config.enable_metrics && path == self.config.metrics_path {
            self.handle_metrics(is_head)
        } else {
            return None;
        };
        self.apply_security_headers(&mut resp);
        Some(resp)
    }

    /// Handles an incoming HTTP request on the public listener from `peer_addr`.
    pub async fn handle_request(
        &self,
        req: Request<Incoming>,
        peer_addr: Option<SocketAddr>,
    ) -> Result<Response<HttpBody>, hyper::Error> {
        let path = req.uri().path();
        let method = req.method().clone();
        let is_head = method == Method::HEAD;

        // M-5: Operational endpoints are served on the public listener ONLY when no dedicated admin listener is configured.
        if self.config.admin_listen_address.is_none() {
            if let Some(resp) = self.try_handle_admin_path(path, is_head) {
                return Ok(resp);
            }
        }

        // Per-IP / IPv6-prefix Token-Bucket Rate Limiting (when enabled via DOH_RATE_LIMIT_RPS > 0)
        if self.rate_limiter.is_enabled() {
            let client_ip =
                resolve_client_ip(req.headers(), peer_addr, &self.config.trusted_proxies);
            if !self.rate_limiter.check_and_consume(client_ip) {
                self.metrics.inc_rate_limited();
                self.metrics.record_status(429);
                return Ok(self.rate_limited_response());
            }
        }

        // RFC 9230 Oblivious DoH configuration endpoint (`/.well-known/odohconfigs`)
        if path == self.config.odoh_configs_path {
            let mut resp = match method {
                Method::GET | Method::HEAD => self.handle_odoh_configs(),
                Method::OPTIONS => self.handle_cors_preflight(),
                _ => self.method_not_allowed("GET, HEAD, OPTIONS"),
            };
            if is_head {
                *resp.body_mut() = Full::new(Bytes::new());
            }
            self.apply_security_headers(&mut resp);
            self.metrics.record_status(resp.status().as_u16());
            return Ok(resp);
        }

        // Primary DoH / ODoH / JSON endpoint (`/dns-query`)
        if path != self.config.path {
            let mut resp = self.empty_status(StatusCode::NOT_FOUND);
            self.apply_security_headers(&mut resp);
            self.metrics.record_status(404);
            return Ok(resp);
        }

        if method == Method::OPTIONS {
            let mut resp = self.handle_cors_preflight();
            self.apply_security_headers(&mut resp);
            self.metrics.record_status(204);
            return Ok(resp);
        }

        let started_at = Instant::now();
        let deadline = started_at + self.config.timeout;
        let mut response = match method {
            Method::GET | Method::HEAD => {
                self.handle_get(req, peer_addr, started_at, deadline).await
            }
            Method::POST => self.handle_post(req, peer_addr, started_at, deadline).await,
            _ => self.method_not_allowed("GET, HEAD, POST, OPTIONS"),
        };

        if is_head {
            *response.body_mut() = Full::new(Bytes::new());
        }
        self.apply_security_headers(&mut response);
        self.metrics.record_status(response.status().as_u16());
        Ok(response)
    }

    fn handle_livez(&self, is_head: bool) -> Response<HttpBody> {
        let payload = br#"{"status":"ok","service":"daviante-doh"}"#;
        let body = if is_head {
            Bytes::new()
        } else {
            Bytes::from_static(payload)
        };
        Self::build_response(
            StatusCode::OK,
            &[
                (CONTENT_TYPE, HeaderValue::from_static(MIME_JSON)),
                (CONTENT_LENGTH, HeaderValue::from(payload.len())),
                (CACHE_CONTROL, HeaderValue::from_static("no-store")),
            ],
            body,
        )
    }

    fn handle_readyz(&self, is_head: bool) -> Response<HttpBody> {
        let is_ready = !self.is_draining()
            && self
                .upstreams
                .has_healthy_upstream(&self.config.effective_upstreams());
        let (status, payload): (StatusCode, &'static [u8]) = if is_ready {
            (
                StatusCode::OK,
                br#"{"status":"ready","service":"daviante-doh"}"#,
            )
        } else {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                br#"{"status":"not_ready","service":"daviante-doh"}"#,
            )
        };
        let body = if is_head {
            Bytes::new()
        } else {
            Bytes::from_static(payload)
        };
        Self::build_response(
            status,
            &[
                (CONTENT_TYPE, HeaderValue::from_static(MIME_JSON)),
                (CONTENT_LENGTH, HeaderValue::from(payload.len())),
                (CACHE_CONTROL, HeaderValue::from_static("no-store")),
            ],
            body,
        )
    }

    fn handle_metrics(&self, is_head: bool) -> Response<HttpBody> {
        let text = self.metrics.render_prometheus();
        let len = text.len();
        let body = if is_head {
            Bytes::new()
        } else {
            Bytes::from(text)
        };
        Self::build_response(
            StatusCode::OK,
            &[
                (CONTENT_TYPE, HeaderValue::from_static(MIME_PROMETHEUS)),
                (CONTENT_LENGTH, HeaderValue::from(len)),
                (CACHE_CONTROL, HeaderValue::from_static("no-store")),
            ],
            body,
        )
    }

    fn handle_cors_preflight(&self) -> Response<HttpBody> {
        Self::build_response(
            StatusCode::NO_CONTENT,
            &[
                (ACCESS_CONTROL_ALLOW_ORIGIN, self.cors_origin_header.clone()),
                (
                    ACCESS_CONTROL_ALLOW_METHODS,
                    HeaderValue::from_static("GET, HEAD, POST, OPTIONS"),
                ),
                (
                    ACCESS_CONTROL_ALLOW_HEADERS,
                    HeaderValue::from_static("Content-Type, Accept"),
                ),
                (ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("86400")),
            ],
            Bytes::new(),
        )
    }

    fn handle_odoh_configs(&self) -> Response<HttpBody> {
        let key = self.odoh_keys.snapshot();
        let bytes = key.serialized_configs();
        // M-10: Bound Cache-Control max-age to half the rotation period without stale-* directives
        // so clients never cache a key past the 2-key rotation grace window.
        let max_age = (self.config.odoh_rotation_secs / 2).max(1);
        let cc_val = HeaderValue::from_str(&format!("max-age={max_age}"))
            .unwrap_or_else(|_| HeaderValue::from_static("max-age=60"));
        Self::build_response(
            StatusCode::OK,
            &[
                (
                    CONTENT_TYPE,
                    HeaderValue::from_static("application/octet-stream"),
                ),
                (CONTENT_LENGTH, HeaderValue::from(bytes.len())),
                (CACHE_CONTROL, cc_val),
                (ACCESS_CONTROL_ALLOW_ORIGIN, self.cors_origin_header.clone()),
            ],
            Bytes::from(bytes),
        )
    }

    async fn handle_get(
        &self,
        req: Request<Incoming>,
        peer_addr: Option<SocketAddr>,
        started_at: Instant,
        deadline: Instant,
    ) -> Response<HttpBody> {
        let flavor = match self.negotiate_flavor(&req, false) {
            Ok(f) => f,
            Err(resp) => return *resp,
        };

        let mut resp = match flavor {
            RequestFlavor::WireDoh => {
                self.metrics.inc_wire_req();
                let r = self.handle_wire_get(req, peer_addr, deadline).await;
                self.metrics.observe_wire_duration(started_at.elapsed());
                r
            }
            RequestFlavor::ObliviousDoh => {
                // N-2: RFC 9230 §4.1 MUST reject ODoH over GET
                self.metrics.inc_odoh_req();
                self.odoh_method_not_allowed()
            }
            RequestFlavor::JsonDoh => {
                self.metrics.inc_json_req();
                let r = self.handle_json_get(req, peer_addr, deadline).await;
                self.metrics.observe_json_duration(started_at.elapsed());
                r
            }
        };

        resp.headers_mut()
            .insert(VARY, HeaderValue::from_static("Accept, Content-Type"));
        resp
    }

    async fn handle_post(
        &self,
        req: Request<Incoming>,
        peer_addr: Option<SocketAddr>,
        started_at: Instant,
        deadline: Instant,
    ) -> Response<HttpBody> {
        let flavor = match self.negotiate_flavor(&req, true) {
            Ok(f) => f,
            Err(resp) => return *resp,
        };

        match flavor {
            RequestFlavor::WireDoh => {
                self.metrics.inc_wire_req();
                if self.config.disable_post {
                    return self.method_not_allowed("GET, HEAD, OPTIONS");
                }
                let client_ip =
                    resolve_client_ip(req.headers(), peer_addr, &self.config.trusted_proxies);
                let body = match Self::collect_body(req.into_body(), deadline).await {
                    Ok(b) => b,
                    Err(e) => return self.error_status_response(e.status_code(), false),
                };
                let r = self.execute_wire_query(body, client_ip, deadline).await;
                self.metrics.observe_wire_duration(started_at.elapsed());
                r
            }
            RequestFlavor::ObliviousDoh => {
                self.metrics.inc_odoh_req();
                if self.config.disable_post && !self.config.allow_odoh_post {
                    return self.odoh_method_not_allowed();
                }
                let body = match Self::collect_body(req.into_body(), deadline).await {
                    Ok(b) => b,
                    Err(e) => return self.error_status_response(e.status_code(), true),
                };
                let r = self.execute_odoh_query(body, deadline).await;
                self.metrics.observe_odoh_duration(started_at.elapsed());
                r
            }
            RequestFlavor::JsonDoh => {
                self.metrics.inc_json_req();
                self.method_not_allowed("GET, HEAD, OPTIONS")
            }
        }
    }

    async fn handle_wire_get(
        &self,
        req: Request<Incoming>,
        peer_addr: Option<SocketAddr>,
        deadline: Instant,
    ) -> Response<HttpBody> {
        let client_ip = resolve_client_ip(req.headers(), peer_addr, &self.config.trusted_proxies);
        let query_bytes = match Self::extract_base64_dns_param(req.uri().query()) {
            Ok(bytes) => bytes,
            Err(DohError::UriTooLong) => {
                return self.error_status_response(StatusCode::URI_TOO_LONG, false)
            }
            Err(_) => return self.bad_request_response(),
        };

        self.execute_wire_query(query_bytes, client_ip, deadline)
            .await
    }

    async fn handle_json_get(
        &self,
        req: Request<Incoming>,
        peer_addr: Option<SocketAddr>,
        deadline: Instant,
    ) -> Response<HttpBody> {
        let raw_qs = req.uri().query().unwrap_or("");
        let mut params = JsonDnsQueryParams::default();

        for pair in raw_qs.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                match k {
                    "name" => {
                        params.name = urlencoding::decode(v).unwrap_or_default().into_owned();
                    }
                    "type" => {
                        let decoded = urlencoding::decode(v).unwrap_or_default();
                        params.qtype = resolve_rr_type(&decoded);
                        if params.qtype.is_none() {
                            return self.json_error(
                                StatusCode::BAD_REQUEST,
                                RCODE_FORMERR,
                                "Invalid DNS record type",
                            );
                        }
                    }
                    "cd" => params.cd = v == "1" || v.eq_ignore_ascii_case("true"),
                    "do" => params.do_bit = v == "1" || v.eq_ignore_ascii_case("true"),
                    "edns_client_subnet" => {
                        params.edns_client_subnet =
                            Some(urlencoding::decode(v).unwrap_or_default().into_owned());
                    }
                    _ => {}
                }
            }
        }

        let wire_query = match encode_json_query_to_wire(&params) {
            Ok(q) => q,
            Err(e) => {
                return self.json_error(StatusCode::BAD_REQUEST, RCODE_FORMERR, &e.to_string())
            }
        };

        let client_ip = resolve_client_ip(req.headers(), peer_addr, &self.config.trusted_proxies);
        let resolved = match self
            .process_dns_query(wire_query, client_ip, deadline)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                return self.json_error(e.status_code(), RCODE_FORMERR, &e.to_string());
            }
        };

        match decode_wire_to_json(&resolved.unpadded_wire_bytes) {
            Ok(json_struct) => {
                let body_str = serde_json::to_string(&json_struct).unwrap_or_else(|_| "{}".into());
                let cc =
                    self.format_cache_control(resolved.cache_ttl, false, resolved.ecs_attached);
                let cc_hdr = HeaderValue::from_str(&cc)
                    .unwrap_or_else(|_| HeaderValue::from_static("no-store"));
                Self::build_response(
                    StatusCode::OK,
                    &[
                        (CONTENT_TYPE, HeaderValue::from_static(MIME_DNS_JSON)),
                        (CONTENT_LENGTH, HeaderValue::from(body_str.len())),
                        (CACHE_CONTROL, cc_hdr),
                        (ACCESS_CONTROL_ALLOW_ORIGIN, self.cors_origin_header.clone()),
                    ],
                    Bytes::from(body_str),
                )
            }
            Err(e) => self.json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                RCODE_SERVFAIL,
                &e.to_string(),
            ),
        }
    }

    /// Core DNS query pipeline shared across Wire DoH, JSON DoH, and Oblivious DoH:
    /// 1. Validates query header & Question section (RFC 1035 / RFC 8484).
    /// 2. Enforces RFC 8482 `ANY` blocking (if enabled) and Enterprise Protective DNS policy (if enabled).
    /// 3. Checks in-memory `DnsCache` (if enabled and no client/server ECS) and decrements wire TTLs on hit.
    /// 4. Queries upstream resolver(s) with circuit-breaker failover, or synthesizes SERVFAIL + EDE 22/23 if all fail.
    /// 5. Inspects Answer section CNAME/DNAME chain against Protective DNS policy (N-4).
    /// 6. Records RCODE metrics and emits structured `tracing` audit log (if enabled).
    #[doc(hidden)]
    pub async fn process_dns_query(
        &self,
        query: Vec<u8>,
        client_ip: Option<IpAddr>,
        deadline: Instant,
    ) -> Result<ResolvedDnsPacket, DohError> {
        let parsed = validate_and_parse_query(&query)?;

        // 1. Optional RFC 8482 QTYPE=ANY blocking
        if self.config.disable_any && parsed.qtype == RR_TYPE_ANY {
            let unpadded = build_policy_response(
                &query,
                RCODE_NOTIMP,
                false,
                Some((EDE_NOT_SUPPORTED, "QTYPE ANY disabled per RFC 8482 policy")),
                self.config.err_ttl,
            )?;
            let mut client_wire = unpadded.clone();
            finalize_wire_response_for_client(&mut client_wire, parsed.has_edns0);
            self.metrics.record_rcode(RCODE_NOTIMP);
            self.emit_audit_log(
                &parsed.qname,
                parsed.qtype,
                RCODE_NOTIMP,
                "blocked_any",
                client_ip,
            );
            return Ok(ResolvedDnsPacket {
                wire_bytes: client_wire,
                unpadded_wire_bytes: unpadded,
                cache_ttl: self.config.err_ttl,
                internal_cache_ttl: self.config.err_ttl,
                age_secs: 0,
                ecs_attached: false,
                cacheable: false,
            });
        }

        // 2. Enterprise Protective DNS Domain Policy on QNAME
        if self.policy.is_blocked(&parsed.qname) {
            return self.synthesize_policy_blocked(
                &query,
                &parsed.qname,
                parsed.qtype,
                parsed.has_edns0,
                "policy_blocked",
                client_ip,
            );
        }

        // 3. In-memory DNS Response Cache lookup (when enabled and neither server ECS nor client ECS is active, H-3)
        let cache_key = CacheKey {
            qname: parsed.qname.clone(),
            qtype: parsed.qtype,
            qclass: parsed.qclass,
            do_bit: parsed.do_bit,
            cd_bit: parsed.cd_bit,
        };
        let bypass_cache_for_ecs = self.config.enable_ecs || parsed.has_client_ecs;
        if self.cache.is_enabled() && !bypass_cache_for_ecs {
            if let Some(hit) = self.cache.get_for_query(
                &cache_key,
                &query,
                parsed.question_end_offset,
                parsed.has_edns0,
            ) {
                if self.policy.is_answer_blocked(&hit.unpadded_wire_bytes) {
                    return self.synthesize_policy_blocked(
                        &query,
                        &parsed.qname,
                        parsed.qtype,
                        parsed.has_edns0,
                        "policy_blocked_cname",
                        client_ip,
                    );
                }
                self.metrics.inc_cache_hit();
                let rc = rcode(&hit.unpadded_wire_bytes);
                self.metrics.record_rcode(rc);
                self.emit_audit_log(&parsed.qname, parsed.qtype, rc, "cache_hit", client_ip);
                return Ok(ResolvedDnsPacket {
                    wire_bytes: hit.wire_bytes,
                    unpadded_wire_bytes: hit.unpadded_wire_bytes,
                    cache_ttl: hit.remaining_ttl,
                    internal_cache_ttl: hit.remaining_ttl,
                    age_secs: hit.age_secs,
                    ecs_attached: false,
                    cacheable: true,
                });
            }
            self.metrics.inc_cache_miss();
        }

        // 4. Upstream UDP/TCP resolution with circuit-breaker failover
        let ecs_ip = self.config.enable_ecs.then_some(client_ip).flatten();
        let resolved = match resolve_upstream_with_set(
            query.clone(),
            ecs_ip,
            &self.config,
            &self.upstreams,
            &self.tcp_limiter,
            &self.metrics,
            deadline,
        )
        .await
        {
            Ok(r) => r,
            Err(DohError::UpstreamTimeout) => {
                return self.synthesize_upstream_servfail(
                    &query,
                    &parsed.qname,
                    parsed.qtype,
                    parsed.has_edns0,
                    EDE_NO_REACHABLE_AUTHORITY,
                    "Upstream DNS resolver timed out",
                    client_ip,
                );
            }
            Err(DohError::UpstreamError(_)) | Err(DohError::Io(_)) => {
                return self.synthesize_upstream_servfail(
                    &query,
                    &parsed.qname,
                    parsed.qtype,
                    parsed.has_edns0,
                    EDE_NETWORK_ERROR,
                    "Upstream DNS resolver network error",
                    client_ip,
                );
            }
            Err(other) => return Err(other),
        };

        // 5. N-4: Protective DNS CNAME / DNAME answer chain inspection
        if self.policy.is_answer_blocked(&resolved.unpadded_wire_bytes) {
            return self.synthesize_policy_blocked(
                &query,
                &parsed.qname,
                parsed.qtype,
                parsed.has_edns0,
                "policy_blocked_cname",
                client_ip,
            );
        }

        if self.cache.is_enabled() && resolved.cacheable && !bypass_cache_for_ecs {
            self.cache.insert_with_floor(
                cache_key,
                resolved.unpadded_wire_bytes.clone(),
                resolved.cache_ttl,
                resolved.internal_cache_ttl,
            );
        }

        let rc = rcode(&resolved.unpadded_wire_bytes);
        self.metrics.record_rcode(rc);
        self.emit_audit_log(&parsed.qname, parsed.qtype, rc, "upstream", client_ip);
        Ok(resolved)
    }

    fn synthesize_policy_blocked(
        &self,
        query: &[u8],
        qname: &str,
        qtype: u16,
        client_has_edns0: bool,
        audit_source: &str,
        client_ip: Option<IpAddr>,
    ) -> Result<ResolvedDnsPacket, DohError> {
        self.metrics.inc_policy_blocked();
        let ttl = self.config.err_ttl.max(self.config.min_ttl);
        let unpadded = self.policy.build_blocked_response(query, ttl)?;
        let mut client_wire = unpadded.clone();
        finalize_wire_response_for_client(&mut client_wire, client_has_edns0);
        let rc = rcode(&unpadded);
        self.metrics.record_rcode(rc);
        self.emit_audit_log(qname, qtype, rc, audit_source, client_ip);
        Ok(ResolvedDnsPacket {
            wire_bytes: client_wire,
            unpadded_wire_bytes: unpadded,
            cache_ttl: ttl,
            internal_cache_ttl: ttl,
            age_secs: 0,
            ecs_attached: false,
            cacheable: false,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn synthesize_upstream_servfail(
        &self,
        query: &[u8],
        qname: &str,
        qtype: u16,
        client_has_edns0: bool,
        ede_code: u16,
        ede_text: &'static str,
        client_ip: Option<IpAddr>,
    ) -> Result<ResolvedDnsPacket, DohError> {
        let ttl = self.config.err_ttl;
        let unpadded = build_policy_response(
            query,
            RCODE_SERVFAIL,
            false,
            Some((ede_code, ede_text)),
            ttl,
        )?;
        let mut client_wire = unpadded.clone();
        finalize_wire_response_for_client(&mut client_wire, client_has_edns0);
        self.metrics.record_rcode(RCODE_SERVFAIL);
        self.emit_audit_log(qname, qtype, RCODE_SERVFAIL, "upstream_servfail", client_ip);
        Ok(ResolvedDnsPacket {
            wire_bytes: client_wire,
            unpadded_wire_bytes: unpadded,
            cache_ttl: ttl,
            internal_cache_ttl: ttl,
            age_secs: 0,
            ecs_attached: false,
            cacheable: false,
        })
    }

    async fn execute_wire_query(
        &self,
        query: Vec<u8>,
        client_ip: Option<IpAddr>,
        deadline: Instant,
    ) -> Response<HttpBody> {
        match self.process_dns_query(query, client_ip, deadline).await {
            Ok(resolved) => self.binary_response(
                resolved.wire_bytes,
                resolved.cache_ttl,
                MIME_DNS_MESSAGE,
                false,
                resolved.ecs_attached,
            ),
            Err(DohError::BadRequest(_)) | Err(DohError::MalformedDnsPacket(_)) => {
                self.bad_request_response()
            }
            Err(e) => self.error_status_response(e.status_code(), false),
        }
    }

    async fn execute_odoh_query(
        &self,
        ciphertext: Vec<u8>,
        deadline: Instant,
    ) -> Response<HttpBody> {
        let active_ring = self.odoh_keys.snapshot();
        let (plaintext_query, session) = match active_ring.open_query(ciphertext) {
            Ok(res) => res,
            Err(e) => return self.error_status_response(e.status_code(), true),
        };

        let resolved = match self
            .process_dns_query(plaintext_query, None, deadline)
            .await
        {
            Ok(r) => r,
            Err(e) => return self.error_status_response(e.status_code(), true),
        };

        match session.seal_response(resolved.wire_bytes) {
            Ok(encrypted_resp) => {
                // RFC 9230 §4.3: Oblivious DoH responses MUST carry `Cache-Control: no-store`
                self.binary_response(encrypted_resp, 0, MIME_ODOH_MESSAGE, true, false)
            }
            Err(e) => self.error_status_response(e.status_code(), true),
        }
    }

    fn emit_audit_log(
        &self,
        qname: &str,
        qtype: u16,
        rcode_val: u8,
        source: &str,
        client_ip: Option<IpAddr>,
    ) {
        if !self.config.log_queries {
            return;
        }
        let logged_ip = format_audit_client_ip(
            client_ip,
            self.config.log_client_ip,
            self.config.ecs_prefix_v4,
            self.config.ecs_prefix_v6,
        );
        tracing::info!(
            target: "daviante_doh::audit",
            qname = %qname,
            qtype = qtype,
            rcode = rcode_val,
            source = %source,
            client_ip = ?logged_ip,
            "dns_query_audit"
        );
    }

    /// Negotiates the request flavor (`WireDoh`, `ObliviousDoh`, or `JsonDoh`) per RFC 8484 §4.1, RFC 9110, and RFC 9230 §4.1.
    pub fn negotiate_flavor(
        &self,
        req: &Request<Incoming>,
        is_post: bool,
    ) -> Result<RequestFlavor, Box<Response<HttpBody>>> {
        let query_str = req.uri().query().unwrap_or("");

        // 1. Check explicit `?ct=` query parameter override (supported on GET/HEAD)
        if !is_post {
            if let Some(res) = self.negotiate_from_ct_param(query_str) {
                return res;
            }
        }

        // 2. Check Content-Type header if present
        if let Some(ct_header) = req.headers().get(CONTENT_TYPE) {
            let Ok(ct_str) = ct_header.to_str() else {
                return Err(Box::new(self.bad_request_response()));
            };
            return self.classify_explicit_mime(ct_str, is_post);
        }

        if is_post {
            return Err(Box::new(
                self.header_negotiation_error(StatusCode::UNSUPPORTED_MEDIA_TYPE),
            ));
        }

        // 3. For GET/HEAD without Content-Type, inspect Accept header or infer from query parameters
        self.negotiate_get_flavor(req, query_str)
    }

    #[doc(hidden)]
    pub fn negotiate_from_ct_param(
        &self,
        query_str: &str,
    ) -> Option<Result<RequestFlavor, Box<Response<HttpBody>>>> {
        for pair in query_str.split('&') {
            if let Some(("ct", val)) = pair.split_once('=') {
                let decoded = urlencoding::decode(val).unwrap_or_default();
                return Some(self.classify_explicit_mime(&decoded, false));
            }
        }
        None
    }

    #[doc(hidden)]
    pub fn classify_explicit_mime(
        &self,
        raw_mime: &str,
        is_post: bool,
    ) -> Result<RequestFlavor, Box<Response<HttpBody>>> {
        let base_mime = raw_mime
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        match base_mime.as_str() {
            MIME_DNS_MESSAGE => Ok(RequestFlavor::WireDoh),
            MIME_ODOH_MESSAGE if is_post => Ok(RequestFlavor::ObliviousDoh),
            MIME_ODOH_MESSAGE => Err(Box::new(self.odoh_method_not_allowed())),
            MIME_DNS_JSON | MIME_JSON => Ok(RequestFlavor::JsonDoh),
            _ => Err(Box::new(
                self.header_negotiation_error(StatusCode::UNSUPPORTED_MEDIA_TYPE),
            )),
        }
    }

    fn negotiate_get_flavor(
        &self,
        req: &Request<Incoming>,
        query_str: &str,
    ) -> Result<RequestFlavor, Box<Response<HttpBody>>> {
        let inferred = Self::infer_flavor_from_query(query_str);

        if let Some(accept_str) = req.headers().get(ACCEPT).and_then(|h| h.to_str().ok()) {
            let mut wildcard = false;
            for item in accept_str.split(',') {
                let media = item
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase();
                match media.as_str() {
                    MIME_DNS_MESSAGE => return Ok(RequestFlavor::WireDoh),
                    MIME_ODOH_MESSAGE => return Err(Box::new(self.odoh_method_not_allowed())),
                    MIME_DNS_JSON | MIME_JSON => return Ok(RequestFlavor::JsonDoh),
                    "*/*" | "application/*" => wildcard = true,
                    _ => {}
                }
            }
            if wildcard {
                if let Some(flavor) = inferred {
                    return Ok(flavor);
                }
            }
            return Err(Box::new(
                self.header_negotiation_error(StatusCode::NOT_ACCEPTABLE),
            ));
        }

        inferred.ok_or_else(|| Box::new(self.header_negotiation_error(StatusCode::NOT_ACCEPTABLE)))
    }

    #[doc(hidden)]
    pub fn infer_flavor_from_query(query_str: &str) -> Option<RequestFlavor> {
        if query_str.split('&').any(|p| p.starts_with("dns=")) {
            Some(RequestFlavor::WireDoh)
        } else if query_str.split('&').any(|p| p.starts_with("name=")) {
            Some(RequestFlavor::JsonDoh)
        } else {
            None
        }
    }

    #[doc(hidden)]
    pub fn extract_base64_dns_param(query_str: Option<&str>) -> Result<Vec<u8>, DohError> {
        let qs = query_str.ok_or_else(|| DohError::BadRequest("missing query string".into()))?;
        let mut raw_b64 = None;
        for part in qs.split('&') {
            if let Some(("dns", val)) = part.split_once('=') {
                raw_b64 = Some(val.trim_end_matches('='));
                break;
            }
        }
        let b64 = raw_b64.ok_or_else(|| DohError::BadRequest("missing dns parameter".into()))?;
        if b64.is_empty() {
            return Err(DohError::BadRequest("empty dns parameter".into()));
        }
        // L-2: Return HTTP 414 URI Too Long (RFC 9110 §15.5.15) when base64url query exceeds maximum DNS query size
        if b64.len() > (MAX_DNS_QUERY_LEN * 4 / 3) + 4 {
            return Err(DohError::UriTooLong);
        }
        URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|_| DohError::BadRequest("invalid base64url dns parameter".into()))
    }

    async fn collect_body(mut body: Incoming, deadline: Instant) -> Result<Vec<u8>, DohError> {
        let read_fut = async {
            let mut buf = Vec::new();
            while let Some(frame_res) = body.frame().await {
                let frame = frame_res.map_err(|_| DohError::PayloadTooLarge)?;
                if let Some(chunk) = frame.data_ref() {
                    if buf.len() + chunk.len() > MAX_DNS_QUERY_LEN {
                        return Err(DohError::PayloadTooLarge);
                    }
                    buf.extend_from_slice(chunk);
                }
            }
            Ok(buf)
        };
        tokio::time::timeout_at(deadline, read_fut)
            .await
            .map_err(|_| DohError::RequestTimeout)?
    }

    #[doc(hidden)]
    pub fn apply_security_headers(&self, resp: &mut Response<HttpBody>) {
        let headers = resp.headers_mut();
        headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
        headers.insert(
            CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
        );
        headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
        if self.config.tls_cert_path.is_some() {
            headers.insert(
                STRICT_TRANSPORT_SECURITY,
                HeaderValue::from_static("max-age=31536000; includeSubDomains"),
            );
        }
        if self.config.cors_allow_origin != "*" {
            if let Some(existing_vary) = headers.get(VARY).and_then(|v| v.to_str().ok()) {
                if !existing_vary.to_ascii_lowercase().contains("origin") {
                    let combined = format!("{existing_vary}, Origin");
                    if let Ok(hv) = HeaderValue::from_str(&combined) {
                        headers.insert(VARY, hv);
                    }
                }
            } else {
                headers.insert(VARY, HeaderValue::from_static("Origin"));
            }
        }
    }

    #[doc(hidden)]
    pub fn format_cache_control(&self, ttl: u32, no_store: bool, private_cache: bool) -> String {
        if no_store {
            "no-store".to_string()
        } else if private_cache {
            format!("private, max-age={ttl}")
        } else if ttl == 0 {
            "max-age=0, no-cache".to_string()
        } else {
            let mut cc = format!("max-age={ttl}");
            if self.config.stale_if_error_secs > 0 {
                cc.push_str(&format!(
                    ", stale-if-error={}",
                    self.config.stale_if_error_secs
                ));
            }
            if self.config.stale_while_revalidate_secs > 0 {
                cc.push_str(&format!(
                    ", stale-while-revalidate={}",
                    self.config.stale_while_revalidate_secs
                ));
            }
            cc
        }
    }

    fn binary_response(
        &self,
        payload: Vec<u8>,
        ttl: u32,
        content_type: &'static str,
        no_store: bool,
        private_cache: bool,
    ) -> Response<HttpBody> {
        let cc = self.format_cache_control(ttl, no_store, private_cache);
        let cc_hdr =
            HeaderValue::from_str(&cc).unwrap_or_else(|_| HeaderValue::from_static("no-store"));

        // M-2: Do NOT emit an `Age` header alongside a decremented `max-age` (avoids double-counting age per RFC 9111 §4.2.3).
        Self::build_response(
            StatusCode::OK,
            &[
                (CONTENT_TYPE, HeaderValue::from_static(content_type)),
                (CONTENT_LENGTH, HeaderValue::from(payload.len())),
                (CACHE_CONTROL, cc_hdr),
                (ACCESS_CONTROL_ALLOW_ORIGIN, self.cors_origin_header.clone()),
            ],
            Bytes::from(payload),
        )
    }

    fn rate_limited_response(&self) -> Response<HttpBody> {
        let mut resp = Self::build_response(
            StatusCode::TOO_MANY_REQUESTS,
            &[
                (CONTENT_LENGTH, HeaderValue::from_static("0")),
                (RETRY_AFTER, HeaderValue::from_static("1")),
                (CACHE_CONTROL, HeaderValue::from_static("no-store")),
                (ACCESS_CONTROL_ALLOW_ORIGIN, self.cors_origin_header.clone()),
            ],
            Bytes::new(),
        );
        self.apply_security_headers(&mut resp);
        resp
    }

    fn json_error(
        &self,
        http_status: StatusCode,
        dns_rcode: u8,
        comment: &str,
    ) -> Response<HttpBody> {
        // N-6: Put the DNS RCODE (e.g. FORMERR = 1) in `"Status"`, not the HTTP status code.
        let body = json!({
            "Status": dns_rcode,
            "Comment": comment,
        })
        .to_string();
        Self::build_response(
            http_status,
            &[
                (CONTENT_TYPE, HeaderValue::from_static(MIME_DNS_JSON)),
                (CONTENT_LENGTH, HeaderValue::from(body.len())),
                (CACHE_CONTROL, HeaderValue::from_static("no-store")),
                (VARY, HeaderValue::from_static("Accept, Content-Type")),
                (ACCESS_CONTROL_ALLOW_ORIGIN, self.cors_origin_header.clone()),
            ],
            Bytes::from(body),
        )
    }

    fn empty_status(&self, status: StatusCode) -> Response<HttpBody> {
        Self::build_response(
            status,
            &[
                (CONTENT_LENGTH, HeaderValue::from_static("0")),
                (CACHE_CONTROL, HeaderValue::from_static("no-store")),
                (ACCESS_CONTROL_ALLOW_ORIGIN, self.cors_origin_header.clone()),
            ],
            Bytes::new(),
        )
    }

    fn error_status_response(&self, status: StatusCode, _is_odoh: bool) -> Response<HttpBody> {
        // N-2 & H-2: All error responses on POST / ODoH / oversized URI carry Cache-Control: no-store
        Self::build_response(
            status,
            &[
                (CONTENT_LENGTH, HeaderValue::from_static("0")),
                (CACHE_CONTROL, HeaderValue::from_static("no-store")),
                (VARY, HeaderValue::from_static("Accept, Content-Type")),
                (ACCESS_CONTROL_ALLOW_ORIGIN, self.cors_origin_header.clone()),
            ],
            Bytes::new(),
        )
    }

    #[doc(hidden)]
    pub fn bad_request_response(&self) -> Response<HttpBody> {
        // H-2: 400 Bad Request on GET has bounded max-age=3600 + Vary: Accept, Content-Type
        Self::build_response(
            StatusCode::BAD_REQUEST,
            &[
                (CONTENT_LENGTH, HeaderValue::from_static("0")),
                (CACHE_CONTROL, HeaderValue::from_static("max-age=3600")),
                (VARY, HeaderValue::from_static("Accept, Content-Type")),
                (ACCESS_CONTROL_ALLOW_ORIGIN, self.cors_origin_header.clone()),
            ],
            Bytes::new(),
        )
    }

    fn header_negotiation_error(&self, status: StatusCode) -> Response<HttpBody> {
        // H-2: 406 / 415 responses depend on Accept / Content-Type headers and MUST NOT be shared-cached
        Self::build_response(
            status,
            &[
                (CONTENT_LENGTH, HeaderValue::from_static("0")),
                (CACHE_CONTROL, HeaderValue::from_static("no-store")),
                (VARY, HeaderValue::from_static("Accept, Content-Type")),
                (ACCESS_CONTROL_ALLOW_ORIGIN, self.cors_origin_header.clone()),
            ],
            Bytes::new(),
        )
    }

    fn method_not_allowed(&self, allow: &'static str) -> Response<HttpBody> {
        Self::build_response(
            StatusCode::METHOD_NOT_ALLOWED,
            &[
                (ALLOW, HeaderValue::from_static(allow)),
                (CONTENT_LENGTH, HeaderValue::from_static("0")),
                (CACHE_CONTROL, HeaderValue::from_static("no-store")),
                (VARY, HeaderValue::from_static("Accept, Content-Type")),
                (ACCESS_CONTROL_ALLOW_ORIGIN, self.cors_origin_header.clone()),
            ],
            Bytes::new(),
        )
    }

    fn odoh_method_not_allowed(&self) -> Response<HttpBody> {
        // N-2: RFC 9230 §4.1 requires ODoH targets to accept POST only
        self.method_not_allowed("POST")
    }

    /// Infallible HTTP response constructor that never calls `.unwrap()` on request paths (H-6).
    fn build_response(
        status: StatusCode,
        headers: &[(HeaderName, HeaderValue)],
        body: Bytes,
    ) -> Response<HttpBody> {
        let mut resp = Response::new(Full::new(body));
        *resp.status_mut() = status;
        let map = resp.headers_mut();
        for (k, v) in headers {
            map.insert(k.clone(), v.clone());
        }
        resp
    }
}

/// Formats `client_ip` according to `ClientIpLogMode` (`none` default per RFC 8932, `truncated`, or `full`).
pub fn format_audit_client_ip(
    client_ip: Option<IpAddr>,
    mode: ClientIpLogMode,
    v4_prefix: u8,
    v6_prefix: u8,
) -> Option<String> {
    let ip = client_ip?;
    match mode {
        ClientIpLogMode::None => None,
        ClientIpLogMode::Truncated => Some(truncate_ip(ip, v4_prefix, v6_prefix).to_string()),
        ClientIpLogMode::Full => Some(ip.to_string()),
    }
}
