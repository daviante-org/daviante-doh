//! Admin Control-Plane HTTP Router, RFC 9457 Problem Details Responder,
//! Local DNS Record & Policy CRUD Endpoints, Live DNS Lookup Tester,
//! Telemetry Summary Endpoint, and Hardened Static SPA Asset Server.

use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::header::{
    HeaderName, HeaderValue, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_SECURITY_POLICY, CONTENT_TYPE,
    LOCATION, SET_COOKIE, STRICT_TRANSPORT_SECURITY, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use hyper::{Method, Request, Response, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::admin::auth::{
    extract_session_cookie, format_session_clear_cookie, format_session_set_cookie,
    verify_csrf_request, verify_local_credentials, verify_oidc_id_token, AdminRole, AdminSession,
    JwksDocument,
};
use crate::admin::crypto::generate_uuid_v4;
use crate::dns::json::decode_wire_to_json;
use crate::dns::wire::{build_minimal_query_packet, rcode};
use crate::http::handler::{DohEngine, HttpBody};
use crate::metrics::{AdminAuditEntry, RecentDnsActivityEntry};
use crate::policy::{
    export_zone_to_bind, format_bind_preview, resolve_record_owner_in_zone,
    validate_general_domain_name, validate_record_against_store, BlockAction, DnsZone,
    LocalDnsRecord, LocalRecordData, PolicyRuleEntry, PolicyRuleKind, RecordValidationError,
    ZoneMode,
};

/// Maximum JSON request body accepted by any `/api/v1/*` endpoint (64 KiB).
pub const MAX_ADMIN_JSON_BODY: usize = 65_536;

const MIME_JSON: &str = "application/json; charset=utf-8";
const MIME_PROBLEM_JSON: &str = "application/problem+json; charset=utf-8";

/// Content-Security-Policy for the PatternFly 6 Admin SPA:
/// - `script-src 'self'` strictly forbids `'unsafe-inline'` and `'unsafe-eval'`.
/// - `style-src 'self' 'unsafe-inline'` permits PatternFly 6 runtime layout inline style attributes.
const ADMIN_UI_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'";

/// RFC 9457 Problem Details payload returned on all Admin API errors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProblemDetails {
    #[serde(rename = "type")]
    pub problem_type: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
    pub error_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

/// Builds an RFC 9457 `application/problem+json` response with `Cache-Control: no-store`.
pub fn problem_response(
    status: StatusCode,
    error_code: &str,
    title: &str,
    detail: &str,
    field: Option<&str>,
) -> Response<HttpBody> {
    let payload = ProblemDetails {
        problem_type: format!("urn:daviante-doh:error:{error_code}"),
        title: title.to_string(),
        status: status.as_u16(),
        detail: detail.to_string(),
        error_code: error_code.to_string(),
        field: field.map(str::to_string),
    };
    let bytes = serde_json::to_vec(&payload).unwrap_or_else(|_| {
        br#"{"type":"urn:daviante-doh:error:INTERNAL_ERROR","title":"Internal Server Error","status":500,"detail":"Internal error.","error_code":"INTERNAL_ERROR"}"#.to_vec()
    });
    build_json_response_raw(status, MIME_PROBLEM_JSON, bytes, None)
}

fn validation_error_to_response(err: RecordValidationError) -> Response<HttpBody> {
    let status = match err {
        RecordValidationError::CnameConflict(_) | RecordValidationError::DuplicateRecord(_) => {
            StatusCode::CONFLICT
        }
        RecordValidationError::NotFound(_) => StatusCode::NOT_FOUND,
        RecordValidationError::InvalidDomain(_)
        | RecordValidationError::InvalidRecordData(_)
        | RecordValidationError::InvalidTtl(_)
        | RecordValidationError::CnameLoop(_) => StatusCode::UNPROCESSABLE_ENTITY,
    };
    let field = match err {
        RecordValidationError::InvalidDomain(_) => Some("domain"),
        RecordValidationError::InvalidTtl(_) => Some("ttl"),
        RecordValidationError::InvalidRecordData(_)
        | RecordValidationError::CnameConflict(_)
        | RecordValidationError::CnameLoop(_)
        | RecordValidationError::DuplicateRecord(_) => Some("record"),
        RecordValidationError::NotFound(_) => None,
    };
    problem_response(
        status,
        err.error_code(),
        "DNS Record Validation Failed",
        err.message(),
        field,
    )
}

fn json_ok_response<T: Serialize>(
    status: StatusCode,
    value: &T,
    set_cookie: Option<String>,
) -> Response<HttpBody> {
    match serde_json::to_vec(value) {
        Ok(bytes) => build_json_response_raw(status, MIME_JSON, bytes, set_cookie),
        Err(_) => problem_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Internal Server Error",
            "Failed to serialize response payload.",
            None,
        ),
    }
}

fn build_json_response_raw(
    status: StatusCode,
    content_type: &'static str,
    body_bytes: Vec<u8>,
    set_cookie: Option<String>,
) -> Response<HttpBody> {
    let len = body_bytes.len();
    let mut resp = Response::new(Full::new(Bytes::from(body_bytes)));
    *resp.status_mut() = status;
    let headers = resp.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(CONTENT_LENGTH, HeaderValue::from(len));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Some(cookie_str) = set_cookie {
        if let Ok(hv) = HeaderValue::from_str(&cookie_str) {
            headers.insert(SET_COOKIE, hv);
        }
    }
    resp
}

/// Applies strict security headers to all Admin Listener HTTP responses.
pub fn apply_admin_security_headers(resp: &mut Response<HttpBody>, is_tls: bool) {
    let h = resp.headers_mut();
    h.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(ADMIN_UI_CSP),
    );
    h.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    h.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=()"),
    );
    h.insert(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    if is_tls {
        h.insert(
            STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=63072000; includeSubDomains"),
        );
    }
}

async fn read_bounded_json_body<T: DeserializeOwned>(
    req: Request<Incoming>,
) -> Result<T, Box<Response<HttpBody>>> {
    let limited = Limited::new(req.into_body(), MAX_ADMIN_JSON_BODY);
    let collected = match limited.collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) => {
            let msg = format!("{e}");
            if msg.contains("length limit exceeded") {
                return Err(Box::new(problem_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "BODY_TOO_LARGE",
                    "Payload Too Large",
                    "Request JSON body exceeds the 64 KiB limit.",
                    None,
                )));
            }
            return Err(Box::new(problem_response(
                StatusCode::BAD_REQUEST,
                "INVALID_JSON_BODY",
                "Bad Request",
                "Failed to read request body.",
                None,
            )));
        }
    };

    serde_json::from_slice::<T>(&collected).map_err(|_| {
        Box::new(problem_response(
            StatusCode::BAD_REQUEST,
            "INVALID_JSON_BODY",
            "Invalid Request Payload",
            "Request body is not valid JSON or contains unknown fields.",
            None,
        ))
    })
}

fn parse_query_params(query: Option<&str>) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let Some(q) = query else {
        return map;
    };
    for pair in q.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        map.insert(percent_decode(k), percent_decode(v));
    }
    map
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            ) {
                out.push(((hi << 4) | lo) as u8);
                i += 3;
                continue;
            }
            out.push(bytes[i]);
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 2);
    for &b in input.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

// ============================================================================
// Request & Response DTOs
// ============================================================================

#[derive(Debug, Serialize)]
pub struct SessionStatusResponse {
    pub authenticated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<AdminRole>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub csrf_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<String>,
    pub local_auth_enabled: bool,
    pub oidc_enabled: bool,
    pub oidc_provider_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalLoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LocalDnsRecordView {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone_id: Option<String>,
    pub domain: String,
    pub ttl: u32,
    pub enabled: bool,
    pub comment: String,
    pub updated_at: String,
    pub updated_at_epoch: u64,
    pub record: LocalRecordData,
    pub rr_type_code: u16,
    pub bind_preview: String,
}

impl LocalDnsRecordView {
    pub fn from_record(rec: LocalDnsRecord) -> Self {
        let rr_type_code = rec.data.rr_type_code();
        let bind_preview = format_bind_preview(&rec);
        let updated_at = rec.updated_at_epoch.to_string();
        Self {
            id: rec.id,
            zone_id: rec.zone_id,
            domain: rec.domain,
            ttl: rec.ttl,
            enabled: rec.enabled,
            comment: rec.comment,
            updated_at,
            updated_at_epoch: rec.updated_at_epoch,
            record: rec.data,
            rr_type_code,
            bind_preview,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct DnsZoneView {
    pub id: String,
    pub name: String,
    pub mode: ZoneMode,
    pub serial: u32,
    pub primary_ns: String,
    pub admin_email: String,
    pub default_ttl: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
    pub enabled: bool,
    pub comment: String,
    pub updated_at_epoch: u64,
    pub record_count: usize,
}

impl DnsZoneView {
    pub fn from_zone(zone: DnsZone, record_count: usize) -> Self {
        Self {
            id: zone.id,
            name: zone.domain,
            mode: zone.mode,
            serial: zone.serial,
            primary_ns: zone.mname,
            admin_email: zone.rname,
            default_ttl: zone.default_ttl,
            refresh: zone.refresh,
            retry: zone.retry,
            expire: zone.expire,
            minimum: zone.minimum,
            enabled: zone.enabled,
            comment: zone.comment,
            updated_at_epoch: zone.updated_at_epoch,
            record_count,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpsertZoneRequest {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(alias = "domain")]
    pub name: String,
    #[serde(default)]
    pub mode: ZoneMode,
    #[serde(default, alias = "mname")]
    pub primary_ns: String,
    #[serde(default, alias = "rname")]
    pub admin_email: String,
    #[serde(default = "default_ttl")]
    pub default_ttl: u32,
    #[serde(default = "default_refresh")]
    pub refresh: u32,
    #[serde(default = "default_retry")]
    pub retry: u32,
    #[serde(default = "default_expire")]
    pub expire: u32,
    #[serde(default = "default_ttl")]
    pub minimum: u32,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub comment: String,
}

fn default_refresh() -> u32 {
    3600
}
fn default_retry() -> u32 {
    600
}
fn default_expire() -> u32 {
    86400
}

#[derive(Debug, Serialize)]
pub struct ZoneExportResponse {
    pub zone_id: String,
    pub zone_name: String,
    pub bind_zone_text: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportRecordsRequest {
    #[serde(default)]
    pub zone_id: Option<String>,
    pub content: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Serialize)]
pub struct ImportRecordsResponse {
    pub dry_run: bool,
    pub imported_count: usize,
    pub records: Vec<LocalDnsRecordView>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BulkDeleteRecordsRequest {
    pub ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct BulkDeleteRecordsResponse {
    pub deleted_count: usize,
    pub deleted_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct TelemetryActivityResponse {
    pub dns_activity: Vec<RecentDnsActivityEntry>,
    pub admin_audit: Vec<AdminAuditEntry>,
}

#[derive(Debug, Serialize)]
pub struct PaginatedListResponse<T> {
    pub items: Vec<T>,
    pub total: usize,
    pub page: usize,
    pub per_page: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpsertRecordRequest {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub zone_id: Option<String>,
    pub domain: String,
    #[serde(default = "default_ttl")]
    pub ttl: u32,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub comment: String,
    #[serde(alias = "data")]
    pub record: LocalRecordData,
}

fn default_ttl() -> u32 {
    300
}
fn default_enabled() -> bool {
    true
}

#[derive(Debug, Serialize)]
pub struct RecordPreviewResponse {
    pub valid: bool,
    pub bind_preview: String,
    pub rr_type_code: u16,
    pub wire_rdata_len: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpsertPolicyRuleRequest {
    pub kind: PolicyRuleKind,
    pub domain: String,
    #[serde(default)]
    pub comment: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct PolicySettingsResponse {
    pub block_action: String,
    pub block_private_rebinding: bool,
    pub allow_rules_count: usize,
    pub block_rules_count: usize,
    pub local_records_count: usize,
    pub zones_count: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdatePolicySettingsRequest {
    pub block_action: String,
    pub block_private_rebinding: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsLookupRequest {
    pub name: String,
    pub record_type: String,
    #[serde(default)]
    pub do_bit: bool,
}

#[derive(Debug, Serialize)]
pub struct DnsLookupResponse {
    pub qname: String,
    pub qtype: u16,
    pub record_type: String,
    pub status_rcode: u8,
    pub rcode_name: String,
    pub source: String,
    pub latency_ms: f64,
    pub cache_ttl: u32,
    pub dns_json: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct UpstreamHealthItem {
    pub address: String,
    pub healthy: bool,
}

#[derive(Debug, Serialize)]
pub struct TelemetrySummaryResponse {
    pub requests_wire_total: u64,
    pub requests_json_total: u64,
    pub requests_odoh_total: u64,
    pub responses_2xx_total: u64,
    pub responses_4xx_total: u64,
    pub responses_5xx_total: u64,
    pub rcode_noerror_total: u64,
    pub rcode_nxdomain_total: u64,
    pub rcode_servfail_total: u64,
    pub rcode_refused_total: u64,
    pub cache_enabled: bool,
    pub cache_entries: usize,
    pub cache_hits_total: u64,
    pub cache_misses_total: u64,
    pub cache_stale_hits_total: u64,
    pub hosts_hits_total: u64,
    pub policy_blocked_total: u64,
    pub rebinding_blocked_total: u64,
    pub rate_limited_total: u64,
    pub upstream_udp_total: u64,
    pub upstream_tcp_total: u64,
    pub upstream_dot_total: u64,
    pub upstream_failures_total: u64,
    pub connections_active: u64,
    pub local_records_count: usize,
    pub zones_count: usize,
    pub allow_rules_count: usize,
    pub block_rules_count: usize,
    pub block_action: String,
    pub block_private_rebinding: bool,
    pub upstreams: Vec<UpstreamHealthItem>,
}

// ============================================================================
// Main Router Entrypoint for `/api/v1/*` and Static UI Assets
// ============================================================================

/// Dispatches an Admin Control-Plane `/api/v1/*` or Static SPA request.
pub async fn handle_admin_ui_or_api(
    engine: &DohEngine,
    req: Request<Incoming>,
    peer_addr: Option<SocketAddr>,
) -> Response<HttpBody> {
    let method = req.method().clone();
    let is_head = method == Method::HEAD;
    let path = req.uri().path().to_string();
    let query_str = req.uri().query().map(str::to_string);
    let is_tls = engine.config().tls_cert_path.is_some();

    let mut resp = if path.starts_with("/api/v1/") {
        dispatch_api_v1(
            engine,
            req,
            &method,
            &path,
            query_str.as_deref(),
            peer_addr,
            is_tls,
        )
        .await
    } else {
        if method != Method::GET && method != Method::HEAD {
            problem_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "METHOD_NOT_ALLOWED",
                "Method Not Allowed",
                "Only GET and HEAD are allowed for UI assets.",
                None,
            )
        } else {
            serve_admin_ui_asset(engine.config().admin_ui_dir.as_deref(), &path, is_head)
        }
    };

    if is_head {
        *resp.body_mut() = Full::new(Bytes::new());
    }
    apply_admin_security_headers(&mut resp, is_tls);
    resp
}

async fn dispatch_api_v1(
    engine: &DohEngine,
    req: Request<Incoming>,
    method: &Method,
    path: &str,
    query_str: Option<&str>,
    peer_addr: Option<SocketAddr>,
    is_tls: bool,
) -> Response<HttpBody> {
    let client_ip = peer_addr.map(|a| a.ip());
    let cfg = engine.config();
    let local_auth_enabled = cfg
        .admin_username
        .as_ref()
        .is_some_and(|u| !u.trim().is_empty())
        && cfg
            .admin_password_hash
            .as_ref()
            .is_some_and(|h| !h.trim().is_empty());
    let oidc_enabled = cfg
        .oidc_issuer_url
        .as_ref()
        .is_some_and(|u| !u.trim().is_empty())
        && cfg
            .oidc_client_id
            .as_ref()
            .is_some_and(|c| !c.trim().is_empty());

    // 1. Public / Auth Bootstrap Endpoints
    match (method, path) {
        (&Method::GET, "/api/v1/auth/session") | (&Method::HEAD, "/api/v1/auth/session") => {
            let session = extract_session_cookie(req.headers())
                .and_then(|sid| engine.admin_sessions().get_and_touch(&sid));
            let body = match session {
                Some(s) => SessionStatusResponse {
                    authenticated: true,
                    username: Some(s.username),
                    role: Some(s.role),
                    csrf_token: Some(s.csrf_token),
                    auth_method: Some(s.auth_method),
                    local_auth_enabled,
                    oidc_enabled,
                    oidc_provider_name: "Keycloak OIDC".to_string(),
                },
                None => SessionStatusResponse {
                    authenticated: false,
                    username: None,
                    role: None,
                    csrf_token: None,
                    auth_method: None,
                    local_auth_enabled,
                    oidc_enabled,
                    oidc_provider_name: "Keycloak OIDC".to_string(),
                },
            };
            return json_ok_response(StatusCode::OK, &body, None);
        }
        (&Method::POST, "/api/v1/auth/login") => {
            if !local_auth_enabled {
                return problem_response(
                    StatusCode::FORBIDDEN,
                    "LOCAL_AUTH_DISABLED",
                    "Local Authentication Disabled",
                    "Local username/password sign-in is not configured on this server.",
                    None,
                );
            }
            if engine
                .admin_sessions()
                .login_limiter
                .is_locked_out(client_ip)
            {
                tracing::warn!(
                    event = "admin_login_rate_limited",
                    client_ip = ?client_ip,
                    "admin login rejected due to brute-force rate limit"
                );
                return problem_response(
                    StatusCode::TOO_MANY_REQUESTS,
                    "RATE_LIMITED",
                    "Too Many Login Attempts",
                    "Too many failed sign-in attempts. Please wait 60 seconds and try again.",
                    None,
                );
            }
            let payload: LocalLoginRequest = match read_bounded_json_body(req).await {
                Ok(p) => p,
                Err(resp) => return *resp,
            };
            if verify_local_credentials(
                cfg.admin_username.as_deref(),
                cfg.admin_password_hash.as_deref(),
                &payload.username,
                &payload.password,
            ) {
                engine.admin_sessions().login_limiter.clear_ip(client_ip);
                let session = match engine.admin_sessions().create_session(
                    payload.username.trim().to_string(),
                    AdminRole::Admin,
                    "local",
                ) {
                    Ok(s) => s,
                    Err(_) => {
                        return problem_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "INTERNAL_ERROR",
                            "Session Creation Error",
                            "Failed to initialize session.",
                            None,
                        )
                    }
                };
                tracing::info!(
                    event = "admin_login_success",
                    auth_method = "local",
                    username = %session.username,
                    client_ip = ?client_ip,
                    "admin session established"
                );
                engine.metrics().record_admin_audit(
                    &session.username,
                    session.role.as_str(),
                    "auth.login",
                    &session.username,
                    "Signed in via local credentials",
                );
                let cookie = format_session_set_cookie(&session.session_id, is_tls);
                let body = SessionStatusResponse {
                    authenticated: true,
                    username: Some(session.username),
                    role: Some(session.role),
                    csrf_token: Some(session.csrf_token),
                    auth_method: Some(session.auth_method),
                    local_auth_enabled,
                    oidc_enabled,
                    oidc_provider_name: "Keycloak OIDC".to_string(),
                };
                return json_ok_response(StatusCode::OK, &body, Some(cookie));
            }

            engine
                .admin_sessions()
                .login_limiter
                .record_failure(client_ip);
            tracing::warn!(
                event = "admin_login_failed",
                auth_method = "local",
                client_ip = ?client_ip,
                "invalid local admin credentials"
            );
            // Rule 4.2 / OWASP A07: Generic login failure message
            return problem_response(
                StatusCode::UNAUTHORIZED,
                "INVALID_CREDENTIALS",
                "Authentication Failed",
                "Invalid username or password.",
                None,
            );
        }
        (&Method::GET, "/api/v1/auth/oidc/login") => {
            return handle_oidc_login(engine, oidc_enabled);
        }
        (&Method::GET, "/api/v1/auth/oidc/callback") => {
            return handle_oidc_callback(engine, query_str, is_tls, client_ip).await;
        }
        _ => {}
    }

    // 2. Require active authenticated session for all remaining `/api/v1/*` endpoints
    let Some(session_id) = extract_session_cookie(req.headers()) else {
        return problem_response(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "Authentication Required",
            "Please sign in to access the Admin Control-Plane.",
            None,
        );
    };
    let Some(session) = engine.admin_sessions().get_and_touch(&session_id) else {
        return problem_response(
            StatusCode::UNAUTHORIZED,
            "SESSION_EXPIRED",
            "Session Expired",
            "Your session has expired or is invalid. Please sign in again.",
            None,
        );
    };

    // 3. Enforce CSRF verification on all state-changing HTTP methods
    if matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    ) {
        if let Err(csrf_err) = verify_csrf_request(req.headers(), &session) {
            tracing::warn!(
                event = "admin_csrf_rejected",
                username = %session.username,
                client_ip = ?client_ip,
                reason = csrf_err,
                "rejected admin mutation due to CSRF validation failure"
            );
            return problem_response(
                StatusCode::FORBIDDEN,
                "CSRF_INVALID",
                "CSRF Verification Failed",
                csrf_err,
                None,
            );
        }
    }

    // 4. Logout endpoint (accessible to any authenticated role)
    if *method == Method::POST && path == "/api/v1/auth/logout" {
        engine.admin_sessions().revoke_session(&session.session_id);
        tracing::info!(
            event = "admin_logout",
            username = %session.username,
            client_ip = ?client_ip,
            "admin session revoked"
        );
        let clear_cookie = format_session_clear_cookie(is_tls);
        return json_ok_response(
            StatusCode::OK,
            &serde_json::json!({ "status": "logged_out" }),
            Some(clear_cookie),
        );
    }

    // 5. Dispatch Authenticated Resource Endpoints
    match (method, path) {
        (&Method::GET, "/api/v1/dns/zones") => handle_list_zones(engine),
        (&Method::POST, "/api/v1/dns/zones") => {
            if let Some(resp) = require_admin_role(&session, client_ip, path) {
                return resp;
            }
            handle_create_zone(engine, req, &session, client_ip).await
        }
        (&Method::GET, p) if p.starts_with("/api/v1/dns/zones/") && p.ends_with("/export") => {
            let id = p
                .trim_start_matches("/api/v1/dns/zones/")
                .trim_end_matches("/export")
                .trim_end_matches('/')
                .trim();
            handle_export_zone(engine, id)
        }
        (&Method::PUT, p) if p.starts_with("/api/v1/dns/zones/") => {
            if let Some(resp) = require_admin_role(&session, client_ip, path) {
                return resp;
            }
            let id = p.trim_start_matches("/api/v1/dns/zones/").trim();
            handle_update_zone(engine, id, req, &session, client_ip).await
        }
        (&Method::DELETE, p) if p.starts_with("/api/v1/dns/zones/") => {
            if let Some(resp) = require_admin_role(&session, client_ip, path) {
                return resp;
            }
            let id = p.trim_start_matches("/api/v1/dns/zones/").trim();
            handle_delete_zone(engine, id, query_str, &session, client_ip)
        }
        (&Method::GET, "/api/v1/dns/records") => handle_list_records(engine, query_str),
        (&Method::POST, "/api/v1/dns/records") => {
            if let Some(resp) = require_admin_role(&session, client_ip, path) {
                return resp;
            }
            handle_create_record(engine, req, &session, client_ip).await
        }
        (&Method::POST, "/api/v1/dns/records/preview") => handle_preview_record(engine, req).await,
        (&Method::POST, "/api/v1/dns/records/import") => {
            if let Some(resp) = require_admin_role(&session, client_ip, path) {
                return resp;
            }
            handle_import_records(engine, req, &session, client_ip).await
        }
        (&Method::POST, "/api/v1/dns/records/bulk-delete") => {
            if let Some(resp) = require_admin_role(&session, client_ip, path) {
                return resp;
            }
            handle_bulk_delete_records(engine, req, &session, client_ip).await
        }
        (&Method::PUT, p) if p.starts_with("/api/v1/dns/records/") => {
            if let Some(resp) = require_admin_role(&session, client_ip, path) {
                return resp;
            }
            let id = p.trim_start_matches("/api/v1/dns/records/").trim();
            handle_update_record(engine, id, req, &session, client_ip).await
        }
        (&Method::DELETE, p) if p.starts_with("/api/v1/dns/records/") => {
            if let Some(resp) = require_admin_role(&session, client_ip, path) {
                return resp;
            }
            let id = p.trim_start_matches("/api/v1/dns/records/").trim();
            handle_delete_record(engine, id, &session, client_ip)
        }
        (&Method::GET, "/api/v1/policy/rules") => handle_list_policy_rules(engine, query_str),
        (&Method::POST, "/api/v1/policy/rules") => {
            if let Some(resp) = require_admin_role(&session, client_ip, path) {
                return resp;
            }
            handle_create_policy_rule(engine, req, &session, client_ip).await
        }
        (&Method::PUT, p) if p.starts_with("/api/v1/policy/rules/") => {
            if let Some(resp) = require_admin_role(&session, client_ip, path) {
                return resp;
            }
            let id = p.trim_start_matches("/api/v1/policy/rules/").trim();
            handle_update_policy_rule(engine, id, req, &session, client_ip).await
        }
        (&Method::DELETE, p) if p.starts_with("/api/v1/policy/rules/") => {
            if let Some(resp) = require_admin_role(&session, client_ip, path) {
                return resp;
            }
            let id = p.trim_start_matches("/api/v1/policy/rules/").trim();
            handle_delete_policy_rule(engine, id, &session, client_ip)
        }
        (&Method::GET, "/api/v1/policy/settings") => handle_get_policy_settings(engine),
        (&Method::PUT, "/api/v1/policy/settings") => {
            if let Some(resp) = require_admin_role(&session, client_ip, path) {
                return resp;
            }
            handle_update_policy_settings(engine, req, &session, client_ip).await
        }
        (&Method::POST, "/api/v1/dns/lookup") => handle_dns_lookup(engine, req, client_ip).await,
        (&Method::GET, "/api/v1/telemetry/summary") => handle_telemetry_summary(engine),
        (&Method::GET, "/api/v1/telemetry/activity") => handle_telemetry_activity(engine),
        _ => problem_response(
            StatusCode::NOT_FOUND,
            "ENDPOINT_NOT_FOUND",
            "Not Found",
            "The requested Admin API endpoint does not exist.",
            None,
        ),
    }
}

fn require_admin_role(
    session: &AdminSession,
    client_ip: Option<std::net::IpAddr>,
    path: &str,
) -> Option<Response<HttpBody>> {
    if session.role.can_write() {
        None
    } else {
        tracing::warn!(
            event = "admin_rbac_denied",
            username = %session.username,
            role = %session.role.as_str(),
            path = path,
            client_ip = ?client_ip,
            "viewer role attempted write operation"
        );
        Some(problem_response(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "Insufficient Permissions",
            "Your account has Viewer (read-only) permissions and cannot modify DNS records or policies.",
            None,
        ))
    }
}

// ============================================================================
// DNS Zones & Local DNS Records Handlers
// ============================================================================

fn handle_list_zones(engine: &DohEngine) -> Response<HttpBody> {
    let zones = engine.policy().list_zones();
    let records = engine.policy().list_local_records();
    let mut views: Vec<DnsZoneView> = zones
        .into_iter()
        .map(|z| {
            let count = records
                .iter()
                .filter(|r| r.zone_id.as_deref() == Some(z.id.as_str()))
                .count();
            DnsZoneView::from_zone(z, count)
        })
        .collect();
    views.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.id.cmp(&b.id)));
    json_ok_response(StatusCode::OK, &views, None)
}

async fn handle_create_zone(
    engine: &DohEngine,
    req: Request<Incoming>,
    session: &AdminSession,
    client_ip: Option<std::net::IpAddr>,
) -> Response<HttpBody> {
    let payload: UpsertZoneRequest = match read_bounded_json_body(req).await {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let id = match generate_uuid_v4() {
        Ok(u) => u,
        Err(_) => {
            return problem_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "ID Generation Error",
                "Failed to generate zone UUID.",
                None,
            )
        }
    };
    let candidate = DnsZone {
        id,
        domain: payload.name,
        mode: payload.mode,
        serial: 0,
        mname: payload.primary_ns,
        rname: payload.admin_email,
        default_ttl: payload.default_ttl,
        refresh: payload.refresh,
        retry: payload.retry,
        expire: payload.expire,
        minimum: payload.minimum,
        enabled: payload.enabled,
        comment: payload.comment,
        updated_at_epoch: 0,
    };

    match engine.policy().upsert_zone(candidate) {
        Ok((saved, prev_domain)) => {
            if let Some(ref prev) = prev_domain {
                engine.cache().invalidate_domain_or_subtree(prev);
            }
            engine.cache().invalidate_domain_or_subtree(&saved.domain);
            tracing::info!(
                event = "admin_zone_created",
                username = %session.username,
                zone_id = %saved.id,
                zone_name = %saved.domain,
                mode = %saved.mode.as_str(),
                client_ip = ?client_ip,
                "created DNS zone"
            );
            engine.metrics().record_admin_audit(
                &session.username,
                session.role.as_str(),
                "zone.create",
                &saved.domain,
                &format!(
                    "Created {} zone (TTL {})",
                    saved.mode.as_str(),
                    saved.default_ttl
                ),
            );
            let view = DnsZoneView::from_zone(saved, 0);
            json_ok_response(StatusCode::CREATED, &view, None)
        }
        Err(e) => validation_error_to_response(e),
    }
}

async fn handle_update_zone(
    engine: &DohEngine,
    id: &str,
    req: Request<Incoming>,
    session: &AdminSession,
    client_ip: Option<std::net::IpAddr>,
) -> Response<HttpBody> {
    if id.is_empty() || id.len() > 64 {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "INVALID_ZONE_ID",
            "Invalid Zone ID",
            "Zone ID is invalid.",
            Some("id"),
        );
    }
    let existing_zones = engine.policy().list_zones();
    let Some(old_zone) = existing_zones.iter().find(|z| z.id == id).cloned() else {
        return problem_response(
            StatusCode::NOT_FOUND,
            "ZONE_NOT_FOUND",
            "Zone Not Found",
            "The specified DNS zone does not exist.",
            None,
        );
    };
    let payload: UpsertZoneRequest = match read_bounded_json_body(req).await {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let candidate = DnsZone {
        id: id.to_string(),
        domain: payload.name,
        mode: payload.mode,
        serial: old_zone.serial,
        mname: payload.primary_ns,
        rname: payload.admin_email,
        default_ttl: payload.default_ttl,
        refresh: payload.refresh,
        retry: payload.retry,
        expire: payload.expire,
        minimum: payload.minimum,
        enabled: payload.enabled,
        comment: payload.comment,
        updated_at_epoch: 0,
    };

    match engine.policy().upsert_zone(candidate) {
        Ok((saved, prev_domain)) => {
            if let Some(ref prev) = prev_domain {
                engine.cache().invalidate_domain_or_subtree(prev);
            }
            engine
                .cache()
                .invalidate_domain_or_subtree(&old_zone.domain);
            engine.cache().invalidate_domain_or_subtree(&saved.domain);
            let record_count = engine
                .policy()
                .list_local_records()
                .iter()
                .filter(|r| r.zone_id.as_deref() == Some(saved.id.as_str()))
                .count();
            tracing::info!(
                event = "admin_zone_updated",
                username = %session.username,
                zone_id = %saved.id,
                zone_name = %saved.domain,
                mode = %saved.mode.as_str(),
                client_ip = ?client_ip,
                "updated DNS zone"
            );
            engine.metrics().record_admin_audit(
                &session.username,
                session.role.as_str(),
                "zone.update",
                &saved.domain,
                &format!(
                    "Updated zone mode={} serial={}",
                    saved.mode.as_str(),
                    saved.serial
                ),
            );
            let view = DnsZoneView::from_zone(saved, record_count);
            json_ok_response(StatusCode::OK, &view, None)
        }
        Err(e) => validation_error_to_response(e),
    }
}

fn handle_delete_zone(
    engine: &DohEngine,
    id: &str,
    query_str: Option<&str>,
    session: &AdminSession,
    client_ip: Option<std::net::IpAddr>,
) -> Response<HttpBody> {
    let params = parse_query_params(query_str);
    let delete_records = params
        .get("delete_records")
        .is_some_and(|v| v == "true" || v == "1");
    match engine.policy().delete_zone(id, delete_records) {
        Ok(Some((removed, deleted_records_count))) => {
            engine.cache().invalidate_domain_or_subtree(&removed.domain);
            tracing::info!(
                event = "admin_zone_deleted",
                username = %session.username,
                zone_id = %removed.id,
                zone_name = %removed.domain,
                delete_records = delete_records,
                deleted_records_count = deleted_records_count,
                client_ip = ?client_ip,
                "deleted DNS zone"
            );
            engine.metrics().record_admin_audit(
                &session.username,
                session.role.as_str(),
                "zone.delete",
                &removed.domain,
                if delete_records {
                    "Deleted zone and all member records"
                } else {
                    "Deleted zone (records unassigned)"
                },
            );
            json_ok_response(
                StatusCode::OK,
                &serde_json::json!({
                    "deleted_id": removed.id,
                    "deleted_records": delete_records,
                    "deleted_records_count": deleted_records_count,
                }),
                None,
            )
        }
        Ok(None) => problem_response(
            StatusCode::NOT_FOUND,
            "ZONE_NOT_FOUND",
            "Zone Not Found",
            "The specified DNS zone does not exist.",
            None,
        ),
        Err(e) => validation_error_to_response(e),
    }
}

fn handle_export_zone(engine: &DohEngine, id: &str) -> Response<HttpBody> {
    let zones = engine.policy().list_zones();
    let Some(zone) = zones.into_iter().find(|z| z.id == id) else {
        return problem_response(
            StatusCode::NOT_FOUND,
            "ZONE_NOT_FOUND",
            "Zone Not Found",
            "The specified DNS zone does not exist.",
            None,
        );
    };
    let records = engine.policy().list_local_records();
    let bind_zone_text = export_zone_to_bind(&zone, &records);
    json_ok_response(
        StatusCode::OK,
        &ZoneExportResponse {
            zone_id: zone.id,
            zone_name: zone.domain,
            bind_zone_text,
        },
        None,
    )
}

fn handle_list_records(engine: &DohEngine, query_str: Option<&str>) -> Response<HttpBody> {
    let params = parse_query_params(query_str);
    let search = params
        .get("search")
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();
    let zone_filter = params
        .get("zone_id")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("ALL"));
    let record_type_filter = params
        .get("record_type")
        .map(|s| s.trim().to_ascii_uppercase())
        .filter(|s| !s.is_empty() && s != "ALL");
    let sort_by = params
        .get("sort_by")
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_else(|| "domain".to_string());
    let sort_desc = params
        .get("sort_dir")
        .is_some_and(|s| s.trim().eq_ignore_ascii_case("desc"));
    let page = params
        .get("page")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1)
        .max(1);
    // Rule 2.3 & 4.2: Hard maximum page size of 100
    let per_page = params
        .get("per_page")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(20)
        .clamp(1, 100);

    let all_records = engine.policy().list_local_records();
    let mut filtered: Vec<LocalDnsRecordView> = all_records
        .into_iter()
        .map(LocalDnsRecordView::from_record)
        .filter(|item| {
            if let Some(ref zf) = zone_filter {
                if zf.eq_ignore_ascii_case("unassigned") {
                    if item.zone_id.is_some() {
                        return false;
                    }
                } else if item.zone_id.as_deref() != Some(zf.as_str()) {
                    return false;
                }
            }
            if let Some(ref rt) = record_type_filter {
                if !item.record.type_name().eq_ignore_ascii_case(rt) {
                    return false;
                }
            }
            if !search.is_empty() {
                let in_domain = item.domain.to_ascii_lowercase().contains(&search);
                let in_comment = item.comment.to_ascii_lowercase().contains(&search);
                let in_preview = item.bind_preview.to_ascii_lowercase().contains(&search);
                if !in_domain && !in_comment && !in_preview {
                    return false;
                }
            }
            true
        })
        .collect();

    filtered.sort_by(|a, b| {
        let ord = match sort_by.as_str() {
            "type" => a
                .record
                .type_name()
                .cmp(b.record.type_name())
                .then_with(|| a.domain.cmp(&b.domain)),
            "ttl" => a.ttl.cmp(&b.ttl).then_with(|| a.domain.cmp(&b.domain)),
            "updated" => a
                .updated_at_epoch
                .cmp(&b.updated_at_epoch)
                .then_with(|| a.domain.cmp(&b.domain)),
            _ => a
                .domain
                .cmp(&b.domain)
                .then_with(|| a.rr_type_code.cmp(&b.rr_type_code)),
        }
        .then_with(|| a.id.cmp(&b.id));
        if sort_desc {
            ord.reverse()
        } else {
            ord
        }
    });

    let total = filtered.len();
    let offset = (page - 1).saturating_mul(per_page);
    let items: Vec<LocalDnsRecordView> = filtered.into_iter().skip(offset).take(per_page).collect();

    json_ok_response(
        StatusCode::OK,
        &PaginatedListResponse {
            items,
            total,
            page,
            per_page,
        },
        None,
    )
}

async fn handle_create_record(
    engine: &DohEngine,
    req: Request<Incoming>,
    session: &AdminSession,
    client_ip: Option<std::net::IpAddr>,
) -> Response<HttpBody> {
    let payload: UpsertRecordRequest = match read_bounded_json_body(req).await {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let id = match generate_uuid_v4() {
        Ok(u) => u,
        Err(_) => {
            return problem_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "ID Generation Error",
                "Failed to generate record UUID.",
                None,
            )
        }
    };
    let candidate = LocalDnsRecord {
        id,
        zone_id: payload.zone_id.filter(|s| !s.trim().is_empty()),
        domain: payload.domain,
        ttl: payload.ttl,
        enabled: payload.enabled,
        comment: payload.comment,
        updated_at_epoch: 0,
        data: payload.record,
    };

    match engine.policy().upsert_local_record(candidate) {
        Ok((saved, _)) => {
            engine.cache().invalidate_domain_or_subtree(&saved.domain);
            tracing::info!(
                event = "admin_record_created",
                username = %session.username,
                record_id = %saved.id,
                domain = %saved.domain,
                rr_type = %saved.data.type_name(),
                client_ip = ?client_ip,
                "created local DNS record"
            );
            engine.metrics().record_admin_audit(
                &session.username,
                session.role.as_str(),
                "record.create",
                &saved.domain,
                &format!(
                    "Created {} record (TTL {})",
                    saved.data.type_name(),
                    saved.ttl
                ),
            );
            let view = LocalDnsRecordView::from_record(saved);
            json_ok_response(StatusCode::CREATED, &view, None)
        }
        Err(e) => validation_error_to_response(e),
    }
}

async fn handle_update_record(
    engine: &DohEngine,
    id: &str,
    req: Request<Incoming>,
    session: &AdminSession,
    client_ip: Option<std::net::IpAddr>,
) -> Response<HttpBody> {
    if id.is_empty() || id.len() > 64 {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "INVALID_RECORD_ID",
            "Invalid Record ID",
            "Record ID is invalid.",
            Some("id"),
        );
    }
    if !engine
        .policy()
        .list_local_records()
        .iter()
        .any(|r| r.id == id)
    {
        return problem_response(
            StatusCode::NOT_FOUND,
            "RECORD_NOT_FOUND",
            "Record Not Found",
            "The specified DNS record does not exist.",
            None,
        );
    }
    let payload: UpsertRecordRequest = match read_bounded_json_body(req).await {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let candidate = LocalDnsRecord {
        id: id.to_string(),
        zone_id: payload.zone_id.filter(|s| !s.trim().is_empty()),
        domain: payload.domain,
        ttl: payload.ttl,
        enabled: payload.enabled,
        comment: payload.comment,
        updated_at_epoch: 0,
        data: payload.record,
    };

    match engine.policy().upsert_local_record(candidate) {
        Ok((saved, prev_domain)) => {
            if let Some(old_dom) = prev_domain {
                engine.cache().invalidate_domain_or_subtree(&old_dom);
            }
            engine.cache().invalidate_domain_or_subtree(&saved.domain);
            tracing::info!(
                event = "admin_record_updated",
                username = %session.username,
                record_id = %saved.id,
                domain = %saved.domain,
                rr_type = %saved.data.type_name(),
                client_ip = ?client_ip,
                "updated local DNS record"
            );
            engine.metrics().record_admin_audit(
                &session.username,
                session.role.as_str(),
                "record.update",
                &saved.domain,
                &format!(
                    "Updated {} record (enabled={})",
                    saved.data.type_name(),
                    saved.enabled
                ),
            );
            let view = LocalDnsRecordView::from_record(saved);
            json_ok_response(StatusCode::OK, &view, None)
        }
        Err(e) => validation_error_to_response(e),
    }
}

fn handle_delete_record(
    engine: &DohEngine,
    id: &str,
    session: &AdminSession,
    client_ip: Option<std::net::IpAddr>,
) -> Response<HttpBody> {
    match engine.policy().delete_local_record(id) {
        Ok(Some(removed)) => {
            engine.cache().invalidate_domain_or_subtree(&removed.domain);
            tracing::info!(
                event = "admin_record_deleted",
                username = %session.username,
                record_id = %removed.id,
                domain = %removed.domain,
                client_ip = ?client_ip,
                "deleted local DNS record"
            );
            engine.metrics().record_admin_audit(
                &session.username,
                session.role.as_str(),
                "record.delete",
                &removed.domain,
                &format!("Deleted {} record", removed.data.type_name()),
            );
            json_ok_response(
                StatusCode::OK,
                &serde_json::json!({ "deleted_id": removed.id }),
                None,
            )
        }
        Ok(None) => problem_response(
            StatusCode::NOT_FOUND,
            "RECORD_NOT_FOUND",
            "Record Not Found",
            "The specified DNS record does not exist.",
            None,
        ),
        Err(e) => validation_error_to_response(e),
    }
}

async fn handle_bulk_delete_records(
    engine: &DohEngine,
    req: Request<Incoming>,
    session: &AdminSession,
    client_ip: Option<std::net::IpAddr>,
) -> Response<HttpBody> {
    let payload: BulkDeleteRecordsRequest = match read_bounded_json_body(req).await {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    if payload.ids.is_empty() || payload.ids.len() > 500 {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "INVALID_BULK_DELETE",
            "Invalid Bulk Delete Request",
            "Bulk delete requires between 1 and 500 record IDs.",
            Some("ids"),
        );
    }
    match engine.policy().bulk_delete_local_records(&payload.ids) {
        Ok(removed) => {
            let mut deleted_ids = Vec::with_capacity(removed.len());
            for r in &removed {
                engine.cache().invalidate_domain_or_subtree(&r.domain);
                deleted_ids.push(r.id.clone());
            }
            tracing::info!(
                event = "admin_records_bulk_deleted",
                username = %session.username,
                count = deleted_ids.len(),
                client_ip = ?client_ip,
                "bulk deleted local DNS records"
            );
            engine.metrics().record_admin_audit(
                &session.username,
                session.role.as_str(),
                "record.bulk_delete",
                "local_records",
                &format!("Bulk deleted {} DNS records", deleted_ids.len()),
            );
            json_ok_response(
                StatusCode::OK,
                &BulkDeleteRecordsResponse {
                    deleted_count: deleted_ids.len(),
                    deleted_ids,
                },
                None,
            )
        }
        Err(e) => validation_error_to_response(e),
    }
}

async fn handle_import_records(
    engine: &DohEngine,
    req: Request<Incoming>,
    session: &AdminSession,
    client_ip: Option<std::net::IpAddr>,
) -> Response<HttpBody> {
    let payload: ImportRecordsRequest = match read_bounded_json_body(req).await {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let zone_id = payload.zone_id.filter(|s| !s.trim().is_empty());
    let target_zone = if let Some(ref zid) = zone_id {
        let zones = engine.policy().list_zones();
        let Some(z) = zones.into_iter().find(|z| &z.id == zid) else {
            return validation_error_to_response(RecordValidationError::NotFound(format!(
                "DNS Zone '{zid}' does not exist."
            )));
        };
        Some(z)
    } else {
        None
    };

    let mut candidates =
        match crate::policy::parse_bind_zone_text(target_zone.as_ref(), 300, &payload.content) {
            Ok(c) => c,
            Err(e) => return validation_error_to_response(e),
        };
    for candidate in &mut candidates {
        let Ok(uid) = generate_uuid_v4() else {
            return problem_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "ID Generation Error",
                "Failed to generate record UUID.",
                None,
            );
        };
        candidate.id = uid;
    }

    match engine
        .policy()
        .import_local_records(candidates, payload.dry_run)
    {
        Ok(records) => {
            if !payload.dry_run {
                for r in &records {
                    engine.cache().invalidate_domain_or_subtree(&r.domain);
                }
                tracing::info!(
                    event = "admin_records_imported",
                    username = %session.username,
                    count = records.len(),
                    zone_id = ?zone_id,
                    client_ip = ?client_ip,
                    "imported local DNS records"
                );
                engine.metrics().record_admin_audit(
                    &session.username,
                    session.role.as_str(),
                    "record.import",
                    zone_id.as_deref().unwrap_or("global"),
                    &format!("Imported {} DNS records", records.len()),
                );
            }
            let views: Vec<LocalDnsRecordView> = records
                .into_iter()
                .map(LocalDnsRecordView::from_record)
                .collect();
            json_ok_response(
                StatusCode::OK,
                &ImportRecordsResponse {
                    dry_run: payload.dry_run,
                    imported_count: views.len(),
                    records: views,
                    warnings: Vec::new(),
                },
                None,
            )
        }
        Err(e) => validation_error_to_response(e),
    }
}

async fn handle_preview_record(engine: &DohEngine, req: Request<Incoming>) -> Response<HttpBody> {
    let payload: UpsertRecordRequest = match read_bounded_json_body(req).await {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let clean_zid = payload.zone_id.filter(|s| !s.trim().is_empty());
    let resolved_domain = if let Some(ref zid) = clean_zid {
        let zones = engine.policy().list_zones();
        let Some(zone) = zones.iter().find(|z| &z.id == zid) else {
            return validation_error_to_response(RecordValidationError::NotFound(format!(
                "DNS Zone '{zid}' does not exist."
            )));
        };
        match resolve_record_owner_in_zone(&payload.domain, &zone.domain, &payload.record) {
            Ok(d) => d,
            Err(e) => return validation_error_to_response(e),
        }
    } else {
        payload.domain
    };

    let candidate = LocalDnsRecord {
        id: payload.id.unwrap_or_else(|| "preview-record".to_string()),
        zone_id: clean_zid,
        domain: resolved_domain,
        ttl: payload.ttl,
        enabled: payload.enabled,
        comment: payload.comment,
        updated_at_epoch: 0,
        data: payload.record,
    };
    let existing = engine.policy().list_local_records();
    let compiled = match validate_record_against_store(&candidate, &existing) {
        Ok(c) => c,
        Err(e) => return validation_error_to_response(e),
    };
    let bind_preview = format_bind_preview(&candidate);
    json_ok_response(
        StatusCode::OK,
        &RecordPreviewResponse {
            valid: true,
            bind_preview,
            rr_type_code: compiled.rr_type,
            wire_rdata_len: compiled.rdata.len(),
        },
        None,
    )
}

// ============================================================================
// Protective DNS Policy Rules & Settings Handlers
// ============================================================================

fn handle_list_policy_rules(engine: &DohEngine, query_str: Option<&str>) -> Response<HttpBody> {
    let params = parse_query_params(query_str);
    let kind_filter = params.get("kind").and_then(|s| match s.as_str() {
        "allow" => Some(PolicyRuleKind::Allow),
        "block" => Some(PolicyRuleKind::Block),
        _ => None,
    });
    let search = params
        .get("search")
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();
    let page = params
        .get("page")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1)
        .max(1);
    let per_page = params
        .get("per_page")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(20)
        .clamp(1, 100);

    let mut rules: Vec<PolicyRuleEntry> = engine
        .policy()
        .list_policy_rules()
        .into_iter()
        .filter(|r| {
            if let Some(k) = kind_filter {
                if r.kind != k {
                    return false;
                }
            }
            if !search.is_empty()
                && !r.domain.to_ascii_lowercase().contains(&search)
                && !r.comment.to_ascii_lowercase().contains(&search)
            {
                return false;
            }
            true
        })
        .collect();

    rules.sort_by(|a, b| a.domain.cmp(&b.domain).then_with(|| a.id.cmp(&b.id)));
    let total = rules.len();
    let offset = (page - 1).saturating_mul(per_page);
    let items: Vec<PolicyRuleEntry> = rules.into_iter().skip(offset).take(per_page).collect();

    json_ok_response(
        StatusCode::OK,
        &PaginatedListResponse {
            items,
            total,
            page,
            per_page,
        },
        None,
    )
}

async fn handle_create_policy_rule(
    engine: &DohEngine,
    req: Request<Incoming>,
    session: &AdminSession,
    client_ip: Option<std::net::IpAddr>,
) -> Response<HttpBody> {
    let payload: UpsertPolicyRuleRequest = match read_bounded_json_body(req).await {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let id = match generate_uuid_v4() {
        Ok(u) => u,
        Err(_) => {
            return problem_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "ID Generation Error",
                "Failed to generate rule UUID.",
                None,
            )
        }
    };
    let entry = PolicyRuleEntry {
        id,
        kind: payload.kind,
        domain: payload.domain,
        comment: payload.comment,
        enabled: payload.enabled,
        updated_at_epoch: 0,
    };
    match engine.policy().upsert_policy_rule(entry) {
        Ok(saved) => {
            engine.cache().invalidate_domain_or_subtree(&saved.domain);
            tracing::info!(
                event = "admin_policy_rule_created",
                username = %session.username,
                rule_id = %saved.id,
                domain = %saved.domain,
                kind = ?saved.kind,
                client_ip = ?client_ip,
                "created protective DNS policy rule"
            );
            engine.metrics().record_admin_audit(
                &session.username,
                session.role.as_str(),
                "policy.rule_create",
                &saved.domain,
                &format!("Added {:?} policy rule", saved.kind),
            );
            json_ok_response(StatusCode::CREATED, &saved, None)
        }
        Err(e) => validation_error_to_response(e),
    }
}

async fn handle_update_policy_rule(
    engine: &DohEngine,
    id: &str,
    req: Request<Incoming>,
    session: &AdminSession,
    client_ip: Option<std::net::IpAddr>,
) -> Response<HttpBody> {
    if !engine
        .policy()
        .list_policy_rules()
        .iter()
        .any(|r| r.id == id)
    {
        return problem_response(
            StatusCode::NOT_FOUND,
            "RULE_NOT_FOUND",
            "Policy Rule Not Found",
            "The specified policy rule does not exist.",
            None,
        );
    }
    let payload: UpsertPolicyRuleRequest = match read_bounded_json_body(req).await {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let entry = PolicyRuleEntry {
        id: id.to_string(),
        kind: payload.kind,
        domain: payload.domain,
        comment: payload.comment,
        enabled: payload.enabled,
        updated_at_epoch: 0,
    };
    match engine.policy().upsert_policy_rule(entry) {
        Ok(saved) => {
            engine.cache().invalidate_domain_or_subtree(&saved.domain);
            tracing::info!(
                event = "admin_policy_rule_updated",
                username = %session.username,
                rule_id = %saved.id,
                domain = %saved.domain,
                client_ip = ?client_ip,
                "updated protective DNS policy rule"
            );
            engine.metrics().record_admin_audit(
                &session.username,
                session.role.as_str(),
                "policy.rule_update",
                &saved.domain,
                &format!("Updated {:?} rule (enabled={})", saved.kind, saved.enabled),
            );
            json_ok_response(StatusCode::OK, &saved, None)
        }
        Err(e) => validation_error_to_response(e),
    }
}

fn handle_delete_policy_rule(
    engine: &DohEngine,
    id: &str,
    session: &AdminSession,
    client_ip: Option<std::net::IpAddr>,
) -> Response<HttpBody> {
    match engine.policy().delete_policy_rule(id) {
        Ok(Some(removed)) => {
            engine.cache().invalidate_domain_or_subtree(&removed.domain);
            tracing::info!(
                event = "admin_policy_rule_deleted",
                username = %session.username,
                rule_id = %removed.id,
                domain = %removed.domain,
                client_ip = ?client_ip,
                "deleted protective DNS policy rule"
            );
            engine.metrics().record_admin_audit(
                &session.username,
                session.role.as_str(),
                "policy.rule_delete",
                &removed.domain,
                &format!("Deleted {:?} policy rule", removed.kind),
            );
            json_ok_response(
                StatusCode::OK,
                &serde_json::json!({ "deleted_id": removed.id }),
                None,
            )
        }
        Ok(None) => problem_response(
            StatusCode::NOT_FOUND,
            "RULE_NOT_FOUND",
            "Policy Rule Not Found",
            "The specified policy rule does not exist.",
            None,
        ),
        Err(e) => validation_error_to_response(e),
    }
}

fn handle_get_policy_settings(engine: &DohEngine) -> Response<HttpBody> {
    let (action, rebinding, allow_cnt, block_cnt, rec_cnt) = engine.policy().policy_summary();
    let zones_count = engine.policy().list_zones().len();
    json_ok_response(
        StatusCode::OK,
        &PolicySettingsResponse {
            block_action: action.as_str().to_string(),
            block_private_rebinding: rebinding,
            allow_rules_count: allow_cnt,
            block_rules_count: block_cnt,
            local_records_count: rec_cnt,
            zones_count,
        },
        None,
    )
}

async fn handle_update_policy_settings(
    engine: &DohEngine,
    req: Request<Incoming>,
    session: &AdminSession,
    client_ip: Option<std::net::IpAddr>,
) -> Response<HttpBody> {
    let payload: UpdatePolicySettingsRequest = match read_bounded_json_body(req).await {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let Ok(action) = BlockAction::from_str_name(&payload.block_action) else {
        return problem_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "INVALID_BLOCK_ACTION",
            "Invalid Block Action",
            "Block action must be one of 'nxdomain', 'refused', or 'null'.",
            Some("block_action"),
        );
    };
    if let Err(e) = engine
        .policy()
        .update_policy_settings(action, payload.block_private_rebinding)
    {
        return validation_error_to_response(e);
    }
    engine.cache().clear();
    tracing::info!(
        event = "admin_policy_settings_updated",
        username = %session.username,
        block_action = action.as_str(),
        block_private_rebinding = payload.block_private_rebinding,
        client_ip = ?client_ip,
        "updated protective DNS policy settings"
    );
    engine.metrics().record_admin_audit(
        &session.username,
        session.role.as_str(),
        "policy.settings_update",
        "global_policy",
        &format!(
            "Set block_action={} rebinding_protection={}",
            action.as_str(),
            payload.block_private_rebinding
        ),
    );
    handle_get_policy_settings(engine)
}

// ============================================================================
// Live DNS Resolution Tester (`/api/v1/dns/lookup`) & Telemetry Summary
// ============================================================================

pub fn parse_qtype_from_str(s: &str) -> Result<u16, RecordValidationError> {
    let up = s.trim().to_ascii_uppercase();
    let code = match up.as_str() {
        "A" => 1,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "HINFO" => 13,
        "MX" => 15,
        "TXT" => 16,
        "RP" => 17,
        "AAAA" => 28,
        "LOC" => 29,
        "SRV" => 33,
        "NAPTR" => 35,
        "CERT" => 37,
        "DNAME" => 39,
        "DS" => 43,
        "SSHFP" => 44,
        "DNSKEY" => 48,
        "TLSA" => 52,
        "SMIMEA" => 53,
        "CDS" => 59,
        "CDNSKEY" => 60,
        "OPENPGPKEY" => 61,
        "SVCB" => 64,
        "HTTPS" => 65,
        "SPF" => 99,
        "ANY" => 255,
        "URI" => 256,
        "CAA" => 257,
        other => {
            let num_str = other.strip_prefix("TYPE").unwrap_or(other);
            let parsed = num_str.parse::<u16>().map_err(|_| {
                RecordValidationError::InvalidRecordData(format!(
                    "Unsupported DNS record type '{s}'."
                ))
            })?;
            if parsed == 0 || matches!(parsed, 41 | 251 | 252) {
                return Err(RecordValidationError::InvalidRecordData(
                    "Meta or zone-transfer query types are not permitted.".to_string(),
                ));
            }
            parsed
        }
    };
    Ok(code)
}

async fn handle_dns_lookup(
    engine: &DohEngine,
    req: Request<Incoming>,
    client_ip: Option<std::net::IpAddr>,
) -> Response<HttpBody> {
    let payload: DnsLookupRequest = match read_bounded_json_body(req).await {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let clean_name = match validate_general_domain_name(&payload.name, false) {
        Ok(n) => n,
        Err(e) => return validation_error_to_response(e),
    };
    let qtype = match parse_qtype_from_str(&payload.record_type) {
        Ok(qt) => qt,
        Err(e) => return validation_error_to_response(e),
    };
    let query_wire = match build_minimal_query_packet(&clean_name, qtype, payload.do_bit) {
        Ok(q) => q,
        Err(_) => {
            return problem_response(
                StatusCode::BAD_REQUEST,
                "INVALID_DNS_QUERY",
                "Invalid DNS Query",
                "Could not encode DNS wire query for the provided domain.",
                Some("name"),
            )
        }
    };

    let started = Instant::now();
    let (resolved, source) = match engine.resolve_for_admin_lookup(query_wire, client_ip).await {
        Ok(res) => res,
        Err(_) => {
            return problem_response(
                StatusCode::BAD_GATEWAY,
                "LOOKUP_FAILED",
                "DNS Resolution Failed",
                "Failed to resolve the DNS query against local store and upstream resolvers.",
                None,
            )
        }
    };
    let latency_ms = started.elapsed().as_secs_f64() * 1000.0;
    let rc = rcode(&resolved.unpadded_wire_bytes);
    let rcode_name = match rc {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "OTHER",
    }
    .to_string();

    let dns_json: serde_json::Value = decode_wire_to_json(&resolved.unpadded_wire_bytes)
        .ok()
        .and_then(|resp| serde_json::to_value(resp).ok())
        .unwrap_or(serde_json::Value::Null);

    json_ok_response(
        StatusCode::OK,
        &DnsLookupResponse {
            qname: clean_name,
            qtype,
            record_type: payload.record_type.trim().to_ascii_uppercase(),
            status_rcode: rc,
            rcode_name,
            source: source.to_string(),
            latency_ms,
            cache_ttl: resolved.cache_ttl,
            dns_json,
        },
        None,
    )
}

fn handle_telemetry_summary(engine: &DohEngine) -> Response<HttpBody> {
    let m = engine.metrics().snapshot();
    let (action, rebinding, allow_cnt, block_cnt, rec_cnt) = engine.policy().policy_summary();
    let zones_count = engine.policy().list_zones().len();
    let upstreams = engine
        .upstream_health_list()
        .into_iter()
        .map(|(addr, healthy)| UpstreamHealthItem {
            address: addr.to_string(),
            healthy,
        })
        .collect();

    let summary = TelemetrySummaryResponse {
        requests_wire_total: m.requests_wire_total.load(Ordering::Relaxed),
        requests_json_total: m.requests_json_total.load(Ordering::Relaxed),
        requests_odoh_total: m.requests_odoh_total.load(Ordering::Relaxed),
        responses_2xx_total: m.responses_2xx_total.load(Ordering::Relaxed),
        responses_4xx_total: m.responses_4xx_total.load(Ordering::Relaxed),
        responses_5xx_total: m.responses_5xx_total.load(Ordering::Relaxed),
        rcode_noerror_total: m.rcode_noerror_total.load(Ordering::Relaxed),
        rcode_nxdomain_total: m.rcode_nxdomain_total.load(Ordering::Relaxed),
        rcode_servfail_total: m.rcode_servfail_total.load(Ordering::Relaxed),
        rcode_refused_total: m.rcode_refused_total.load(Ordering::Relaxed),
        cache_enabled: engine.cache().is_enabled(),
        cache_entries: engine.cache().entry_count(),
        cache_hits_total: m.cache_hits_total.load(Ordering::Relaxed),
        cache_misses_total: m.cache_misses_total.load(Ordering::Relaxed),
        cache_stale_hits_total: m.cache_stale_hits_total.load(Ordering::Relaxed),
        hosts_hits_total: m.hosts_hits_total.load(Ordering::Relaxed),
        policy_blocked_total: m.policy_blocked_total.load(Ordering::Relaxed),
        rebinding_blocked_total: m.rebinding_blocked_total.load(Ordering::Relaxed),
        rate_limited_total: m.rate_limited_total.load(Ordering::Relaxed),
        upstream_udp_total: m.upstream_udp_total.load(Ordering::Relaxed),
        upstream_tcp_total: m.upstream_tcp_total.load(Ordering::Relaxed),
        upstream_dot_total: m.upstream_dot_total.load(Ordering::Relaxed),
        upstream_failures_total: m.upstream_failures_total.load(Ordering::Relaxed),
        connections_active: m.connections_active.load(Ordering::Relaxed),
        local_records_count: rec_cnt,
        zones_count,
        allow_rules_count: allow_cnt,
        block_rules_count: block_cnt,
        block_action: action.as_str().to_string(),
        block_private_rebinding: rebinding,
        upstreams,
    };

    json_ok_response(StatusCode::OK, &summary, None)
}

fn handle_telemetry_activity(engine: &DohEngine) -> Response<HttpBody> {
    let dns_activity = engine.metrics().recent_dns_activity();
    let admin_audit = engine.metrics().recent_admin_audit();
    json_ok_response(
        StatusCode::OK,
        &TelemetryActivityResponse {
            dns_activity,
            admin_audit,
        },
        None,
    )
}

// ============================================================================
// Keycloak OIDC Authorization Code + PKCE (`S256`) Handlers
// ============================================================================

fn handle_oidc_login(engine: &DohEngine, oidc_enabled: bool) -> Response<HttpBody> {
    if !oidc_enabled {
        return problem_response(
            StatusCode::FORBIDDEN,
            "OIDC_DISABLED",
            "OIDC Authentication Disabled",
            "Keycloak OIDC authentication is not configured on this server.",
            None,
        );
    }
    let cfg = engine.config();
    let issuer = cfg
        .oidc_issuer_url
        .as_deref()
        .unwrap_or("")
        .trim_end_matches('/');
    let client_id = cfg.oidc_client_id.as_deref().unwrap_or("");
    let redirect_uri = cfg.oidc_redirect_uri.as_deref().unwrap_or("");

    let (flow, code_challenge) = match engine.admin_sessions().create_oidc_flow() {
        Ok(res) => res,
        Err(_) => {
            return problem_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "OIDC Flow Initialization Failed",
                "Failed to initialize OIDC PKCE state.",
                None,
            )
        }
    };

    let auth_url = format!(
        "{issuer}/protocol/openid-connect/auth?response_type=code&client_id={}&redirect_uri={}&scope=openid%20profile%20roles&state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
        percent_encode(client_id),
        percent_encode(redirect_uri),
        percent_encode(&flow.state),
        percent_encode(&flow.nonce),
        percent_encode(&code_challenge)
    );

    let mut resp = Response::new(Full::new(Bytes::new()));
    *resp.status_mut() = StatusCode::FOUND;
    if let Ok(hv) = HeaderValue::from_str(&auth_url) {
        resp.headers_mut().insert(LOCATION, hv);
    }
    resp.headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

#[derive(Debug, Deserialize)]
struct OidcTokenResponse {
    id_token: String,
}

async fn handle_oidc_callback(
    engine: &DohEngine,
    query_str: Option<&str>,
    is_tls: bool,
    client_ip: Option<std::net::IpAddr>,
) -> Response<HttpBody> {
    let params = parse_query_params(query_str);
    let Some(code) = params.get("code").filter(|s| !s.is_empty()) else {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "OIDC_CALLBACK_ERROR",
            "Invalid OIDC Callback",
            "Authorization code is missing from callback parameters.",
            None,
        );
    };
    let Some(state) = params.get("state").filter(|s| !s.is_empty()) else {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "OIDC_CALLBACK_ERROR",
            "Invalid OIDC Callback",
            "State parameter is missing from callback parameters.",
            None,
        );
    };
    let Some(flow) = engine.admin_sessions().take_oidc_flow(state) else {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "OIDC_STATE_INVALID",
            "Invalid or Expired OIDC State",
            "The OIDC login session state is invalid or has expired. Please try signing in again.",
            None,
        );
    };

    let cfg = engine.config();
    let issuer = cfg
        .oidc_issuer_url
        .as_deref()
        .unwrap_or("")
        .trim_end_matches('/');
    let client_id = cfg.oidc_client_id.as_deref().unwrap_or("");
    let redirect_uri = cfg.oidc_redirect_uri.as_deref().unwrap_or("");

    let mut form_body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={}",
        percent_encode(code),
        percent_encode(redirect_uri),
        percent_encode(client_id),
        percent_encode(&flow.code_verifier)
    );
    if let Some(ref secret) = cfg.oidc_client_secret {
        if !secret.is_empty() {
            form_body.push_str("&client_secret=");
            form_body.push_str(&percent_encode(secret));
        }
    }

    let token_url = format!("{issuer}/protocol/openid-connect/token");
    let certs_url = format!("{issuer}/protocol/openid-connect/certs");

    let token_bytes = match fetch_oidc_endpoint(&token_url, Some(&form_body)).await {
        Ok(b) => b,
        Err(_) => {
            return problem_response(
                StatusCode::BAD_GATEWAY,
                "OIDC_TOKEN_EXCHANGE_FAILED",
                "OIDC Token Exchange Failed",
                "Could not exchange authorization code with the OIDC identity provider.",
                None,
            )
        }
    };
    let Ok(token_resp) = serde_json::from_slice::<OidcTokenResponse>(&token_bytes) else {
        return problem_response(
            StatusCode::BAD_GATEWAY,
            "OIDC_TOKEN_EXCHANGE_FAILED",
            "OIDC Token Exchange Failed",
            "Identity provider did not return a valid OIDC id_token.",
            None,
        );
    };

    let jwks_bytes = match fetch_oidc_endpoint(&certs_url, None).await {
        Ok(b) => b,
        Err(_) => {
            return problem_response(
                StatusCode::BAD_GATEWAY,
                "OIDC_JWKS_FETCH_FAILED",
                "OIDC Key Discovery Failed",
                "Could not retrieve JWKS signing keys from the OIDC identity provider.",
                None,
            )
        }
    };
    let Ok(jwks) = serde_json::from_slice::<JwksDocument>(&jwks_bytes) else {
        return problem_response(
            StatusCode::BAD_GATEWAY,
            "OIDC_JWKS_FETCH_FAILED",
            "OIDC Key Discovery Failed",
            "Identity provider returned an invalid JWKS document.",
            None,
        );
    };

    let (username, role) = match verify_oidc_id_token(
        &token_resp.id_token,
        &jwks,
        issuer,
        client_id,
        &flow.nonce,
        &cfg.oidc_admin_role,
        &cfg.oidc_viewer_role,
    ) {
        Ok(res) => res,
        Err(reason) => {
            tracing::warn!(
                event = "admin_oidc_denied",
                client_ip = ?client_ip,
                reason = %reason,
                "OIDC ID token verification or role mapping failed"
            );
            return problem_response(
                StatusCode::FORBIDDEN,
                "OIDC_VERIFICATION_FAILED",
                "OIDC Authentication Denied",
                "Your identity token could not be verified or lacks a required role.",
                None,
            );
        }
    };

    let session = match engine
        .admin_sessions()
        .create_session(username, role, "oidc")
    {
        Ok(s) => s,
        Err(_) => {
            return problem_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Session Creation Error",
                "Failed to initialize session.",
                None,
            )
        }
    };

    tracing::info!(
        event = "admin_login_success",
        auth_method = "oidc",
        username = %session.username,
        role = %session.role.as_str(),
        client_ip = ?client_ip,
        "admin OIDC session established"
    );

    let cookie = format_session_set_cookie(&session.session_id, is_tls);
    let mut resp = Response::new(Full::new(Bytes::new()));
    *resp.status_mut() = StatusCode::FOUND;
    resp.headers_mut()
        .insert(LOCATION, HeaderValue::from_static("/"));
    resp.headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(hv) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(SET_COOKIE, hv);
    }
    resp
}

/// Bounded HTTP/1.1 helper for contacting the configured OIDC issuer endpoints (`token` and `certs`).
async fn fetch_oidc_endpoint(url: &str, post_form: Option<&str>) -> Result<Vec<u8>, String> {
    let (is_https, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err("unsupported URL scheme".to_string());
    };

    let (host_port, path) = match rest.split_once('/') {
        Some((hp, p)) => (hp, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match host_port.split_once(':') {
        Some((h, p_str)) => (
            h,
            p_str
                .parse::<u16>()
                .map_err(|_| "invalid port".to_string())?,
        ),
        None => (host_port, if is_https { 443 } else { 80 }),
    };

    let req_bytes = if let Some(body) = post_form {
        format!(
            "POST {path} HTTP/1.1\r\nHost: {host_port}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    } else {
        format!("GET {path} HTTP/1.1\r\nHost: {host_port}\r\nAccept: application/json\r\nConnection: close\r\n\r\n")
            .into_bytes()
    };

    let connect_fut = TcpStream::connect((host, port));
    let stream = tokio::time::timeout(Duration::from_secs(5), connect_fut)
        .await
        .map_err(|_| "OIDC connection timed out".to_string())?
        .map_err(|e| format!("OIDC TCP connect error: {e}"))?;

    if is_https {
        #[cfg(feature = "tls")]
        {
            let connector = crate::tls::build_upstream_dot_connector(None)
                .map_err(|e| format!("TLS init error: {e}"))?;
            let server_name =
                tokio_rustls::rustls::pki_types::ServerName::try_from(host.to_string())
                    .map_err(|_| "invalid TLS server name".to_string())?;
            let mut tls_stream = tokio::time::timeout(
                Duration::from_secs(5),
                connector.connect(server_name, stream),
            )
            .await
            .map_err(|_| "OIDC TLS handshake timed out".to_string())?
            .map_err(|e| format!("OIDC TLS handshake error: {e}"))?;

            tls_stream
                .write_all(&req_bytes)
                .await
                .map_err(|e| format!("OIDC write error: {e}"))?;
            let mut buf = Vec::with_capacity(8192);
            let mut limited = tls_stream.take(65_536);
            tokio::time::timeout(Duration::from_secs(5), limited.read_to_end(&mut buf))
                .await
                .map_err(|_| "OIDC read timed out".to_string())?
                .map_err(|e| format!("OIDC read error: {e}"))?;
            extract_http_response_body(&buf)
        }
        #[cfg(not(feature = "tls"))]
        {
            Err("HTTPS OIDC requires the 'tls' feature".to_string())
        }
    } else {
        let mut tcp = stream;
        tcp.write_all(&req_bytes)
            .await
            .map_err(|e| format!("OIDC write error: {e}"))?;
        let mut buf = Vec::with_capacity(8192);
        let mut limited = tcp.take(65_536);
        tokio::time::timeout(Duration::from_secs(5), limited.read_to_end(&mut buf))
            .await
            .map_err(|_| "OIDC read timed out".to_string())?
            .map_err(|e| format!("OIDC read error: {e}"))?;
        extract_http_response_body(&buf)
    }
}

fn extract_http_response_body(raw: &[u8]) -> Result<Vec<u8>, String> {
    let Some(header_end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Err("incomplete HTTP response headers".to_string());
    };
    let header_str = String::from_utf8_lossy(&raw[..header_end]);
    let status_line = header_str.lines().next().unwrap_or("");
    if !status_line.contains(" 200 ") {
        return Err(format!("OIDC HTTP status was not 200: {status_line}"));
    }
    Ok(raw[header_end + 4..].to_vec())
}

// ============================================================================
// Hardened Static SPA Asset Server (Rule 1.1 Path Traversal Protection)
// ============================================================================

fn serve_admin_ui_asset(
    ui_dir: Option<&Path>,
    req_path: &str,
    _is_head: bool,
) -> Response<HttpBody> {
    let Some(base_dir) = ui_dir else {
        return serve_builtin_fallback_html();
    };
    let Ok(canonical_base) = fs::canonicalize(base_dir) else {
        return serve_builtin_fallback_html();
    };

    let rel_clean = req_path.trim_start_matches('/');
    // Reject any path containing null bytes or parent traversal segments
    if rel_clean.contains('\0') || rel_clean.split('/').any(|seg| seg == "..") {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "INVALID_PATH",
            "Bad Request",
            "Invalid asset path.",
            None,
        );
    }

    let candidate_rel = if rel_clean.is_empty() {
        "index.html"
    } else {
        rel_clean
    };
    let candidate_path = canonical_base.join(candidate_rel);

    if let Ok(canonical_file) = fs::canonicalize(&candidate_path) {
        if canonical_file.starts_with(&canonical_base) && canonical_file.is_file() {
            if let Ok(bytes) = fs::read(&canonical_file) {
                let mime = content_type_for_path(&canonical_file);
                return build_static_asset_response(StatusCode::OK, mime, bytes);
            }
        }
    }

    // Legacy browser `/favicon.ico` fallback -> serve `favicon.svg` if present
    if candidate_rel == "favicon.ico" {
        let svg_favicon = canonical_base.join("favicon.svg");
        if let Ok(canonical_svg) = fs::canonicalize(&svg_favicon) {
            if canonical_svg.starts_with(&canonical_base) && canonical_svg.is_file() {
                if let Ok(bytes) = fs::read(&canonical_svg) {
                    return build_static_asset_response(StatusCode::OK, "image/svg+xml", bytes);
                }
            }
        }
    }

    // SPA client-side route fallback: if the path has no file extension (e.g. `/records`, `/policy`),
    // serve `index.html` from `canonical_base`.
    if !candidate_rel.contains('.') {
        let index_path = canonical_base.join("index.html");
        if let Ok(canonical_index) = fs::canonicalize(&index_path) {
            if canonical_index.starts_with(&canonical_base) && canonical_index.is_file() {
                if let Ok(bytes) = fs::read(&canonical_index) {
                    return build_static_asset_response(
                        StatusCode::OK,
                        "text/html; charset=utf-8",
                        bytes,
                    );
                }
            }
        }
    }

    problem_response(
        StatusCode::NOT_FOUND,
        "ASSET_NOT_FOUND",
        "Not Found",
        "Requested UI asset was not found.",
        None,
    )
}

fn content_type_for_path(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "svg" => "image/svg+xml",
        "json" => "application/json; charset=utf-8",
        "webmanifest" => "application/manifest+json; charset=utf-8",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "ttf" => "font/ttf",
        "png" => "image/png",
        "ico" => "image/x-icon",
        _ => "application/octet-stream",
    }
}

fn build_static_asset_response(
    status: StatusCode,
    content_type: &'static str,
    bytes: Vec<u8>,
) -> Response<HttpBody> {
    let len = bytes.len();
    let mut resp = Response::new(Full::new(Bytes::from(bytes)));
    *resp.status_mut() = status;
    let h = resp.headers_mut();
    h.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    h.insert(CONTENT_LENGTH, HeaderValue::from(len));
    h.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    resp
}

fn serve_builtin_fallback_html() -> Response<HttpBody> {
    const FALLBACK: &[u8] = b"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Daviante DoH Admin</title></head><body><div id=\"root\">Daviante DoH Admin Control-Plane API is active. Build UI assets in ./ui/dist or configure --admin-ui-dir.</div></body></html>";
    build_static_asset_response(
        StatusCode::OK,
        "text/html; charset=utf-8",
        FALLBACK.to_vec(),
    )
}
