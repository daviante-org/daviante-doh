//! Admin Control-Plane Authentication, Session Management, CSRF Verification,
//! Brute-Force Login Rate Limiting, Local Argon2id Auth, and Keycloak OIDC (PKCE `S256` + RS256 JWKS).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hyper::header::{COOKIE, HOST, ORIGIN};
use hyper::HeaderMap;
use serde::{Deserialize, Serialize};

use crate::admin::crypto::{
    constant_time_eq, generate_random_token_b64, pkce_s256_challenge, verify_argon2id_phc,
    verify_rs256_jwk,
};

/// Maximum concurrent active admin sessions kept in memory.
pub const MAX_ACTIVE_SESSIONS: usize = 256;
/// Absolute session lifetime (8 hours).
pub const SESSION_TTL: Duration = Duration::from_secs(8 * 3600);
/// Idle session timeout (30 minutes).
pub const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Maximum concurrent pending OIDC PKCE authorization flows.
pub const MAX_PENDING_OIDC_FLOWS: usize = 128;
/// Pending OIDC PKCE state lifetime (5 minutes).
pub const OIDC_FLOW_TTL: Duration = Duration::from_secs(5 * 60);

/// Dummy Argon2id PHC hash (`m=19456,t=2,p=1`) evaluated when a login attempt supplies an unknown username,
/// preventing username enumeration via timing side channels (OWASP A07).
const DUMMY_ARGON2ID_PHC: &str =
    "$argon2id$v=19$m=19456,t=2,p=1$MDEyMzQ1Njc4OWFiY2RlZg$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// Role-based access control level for an authenticated admin session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AdminRole {
    /// Full read/write access to DNS records, protective policies, lookup tester, and telemetry.
    Admin,
    /// Read-only access to DNS records, protective policies, lookup tester, and telemetry.
    Viewer,
}

impl AdminRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Viewer => "viewer",
        }
    }

    pub fn can_write(&self) -> bool {
        matches!(self, Self::Admin)
    }
}

/// Active authenticated session stored server-side.
#[derive(Debug, Clone)]
pub struct AdminSession {
    pub session_id: String,
    pub csrf_token: String,
    pub username: String,
    pub role: AdminRole,
    pub auth_method: String,
    pub created_at: Instant,
    pub last_active_at: Instant,
    pub expires_at_unix: u64,
}

/// Pending OIDC Authorization Code + PKCE (`S256`) flow state.
#[derive(Debug, Clone)]
pub struct PendingOidcFlow {
    pub state: String,
    pub nonce: String,
    pub code_verifier: String,
    pub created_at: Instant,
}

#[derive(Debug, Clone)]
struct LoginAttemptWindow {
    failures: u32,
    window_started_at: Instant,
}

/// Brute-force login rate limiter (max 5 failed attempts per 60 seconds per IP).
#[derive(Debug, Clone, Default)]
pub struct LoginRateLimiter {
    attempts: Arc<Mutex<HashMap<IpAddr, LoginAttemptWindow>>>,
}

impl LoginRateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if `ip` is currently locked out due to excessive failed login attempts.
    pub fn is_locked_out(&self, ip: Option<IpAddr>) -> bool {
        let Some(addr) = ip else {
            return false;
        };
        let Ok(mut guard) = self.attempts.lock() else {
            return false;
        };
        let now = Instant::now();
        if let Some(entry) = guard.get(&addr) {
            if now.duration_since(entry.window_started_at) < Duration::from_secs(60) {
                return entry.failures >= 5;
            }
        }
        guard.remove(&addr);
        false
    }

    /// Records a failed login attempt for `ip`.
    pub fn record_failure(&self, ip: Option<IpAddr>) {
        let Some(addr) = ip else {
            return;
        };
        let Ok(mut guard) = self.attempts.lock() else {
            return;
        };
        let now = Instant::now();
        if guard.len() >= 1024 && !guard.contains_key(&addr) {
            guard.retain(|_, v| now.duration_since(v.window_started_at) < Duration::from_secs(60));
        }
        let entry = guard.entry(addr).or_insert(LoginAttemptWindow {
            failures: 0,
            window_started_at: now,
        });
        if now.duration_since(entry.window_started_at) >= Duration::from_secs(60) {
            entry.failures = 1;
            entry.window_started_at = now;
        } else {
            entry.failures = entry.failures.saturating_add(1);
        }
    }

    /// Clears failed login attempts for `ip` upon successful login.
    pub fn clear_ip(&self, ip: Option<IpAddr>) {
        if let Some(addr) = ip {
            if let Ok(mut guard) = self.attempts.lock() {
                guard.remove(&addr);
            }
        }
    }
}

/// Thread-safe bounded store for active admin sessions and pending OIDC PKCE flows.
#[derive(Debug, Clone, Default)]
pub struct AdminSessionStore {
    sessions: Arc<Mutex<HashMap<String, AdminSession>>>,
    oidc_flows: Arc<Mutex<HashMap<String, PendingOidcFlow>>>,
    pub login_limiter: LoginRateLimiter,
}

impl AdminSessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new authenticated session with fresh CSPRNG `session_id` and `csrf_token`.
    pub fn create_session(
        &self,
        username: String,
        role: AdminRole,
        auth_method: &str,
    ) -> Result<AdminSession, String> {
        let session_id = generate_random_token_b64()?;
        let csrf_token = generate_random_token_b64()?;
        let now = Instant::now();
        let expires_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| (d + SESSION_TTL).as_secs())
            .unwrap_or(0);

        let session = AdminSession {
            session_id: session_id.clone(),
            csrf_token,
            username,
            role,
            auth_method: auth_method.to_string(),
            created_at: now,
            last_active_at: now,
            expires_at_unix,
        };

        let mut guard = self
            .sessions
            .lock()
            .map_err(|_| "session store lock poisoned".to_string())?;

        // Evict expired or idle sessions first
        guard.retain(|_, s| {
            now.duration_since(s.created_at) < SESSION_TTL
                && now.duration_since(s.last_active_at) < SESSION_IDLE_TIMEOUT
        });

        // If still at capacity, evict the least-recently-active session
        if guard.len() >= MAX_ACTIVE_SESSIONS {
            if let Some(oldest_id) = guard
                .iter()
                .min_by_key(|(_, s)| s.last_active_at)
                .map(|(k, _)| k.clone())
            {
                guard.remove(&oldest_id);
            }
        }

        guard.insert(session_id, session.clone());
        Ok(session)
    }

    /// Looks up and refreshes `last_active_at` for an active session ID.
    pub fn get_and_touch(&self, session_id: &str) -> Option<AdminSession> {
        let mut guard = self.sessions.lock().ok()?;
        let now = Instant::now();
        let session = guard.get_mut(session_id)?;
        if now.duration_since(session.created_at) >= SESSION_TTL
            || now.duration_since(session.last_active_at) >= SESSION_IDLE_TIMEOUT
        {
            guard.remove(session_id);
            return None;
        }
        session.last_active_at = now;
        Some(session.clone())
    }

    /// Revokes a session server-side upon logout.
    pub fn revoke_session(&self, session_id: &str) {
        if let Ok(mut guard) = self.sessions.lock() {
            guard.remove(session_id);
        }
    }

    /// Creates a new pending OIDC PKCE (`S256`) flow and returns `(flow, code_challenge)`.
    pub fn create_oidc_flow(&self) -> Result<(PendingOidcFlow, String), String> {
        let state = generate_random_token_b64()?;
        let nonce = generate_random_token_b64()?;
        let code_verifier = generate_random_token_b64()?;
        let code_challenge = pkce_s256_challenge(&code_verifier);
        let now = Instant::now();

        let flow = PendingOidcFlow {
            state: state.clone(),
            nonce,
            code_verifier,
            created_at: now,
        };

        let mut guard = self
            .oidc_flows
            .lock()
            .map_err(|_| "oidc store lock poisoned".to_string())?;
        guard.retain(|_, f| now.duration_since(f.created_at) < OIDC_FLOW_TTL);
        if guard.len() >= MAX_PENDING_OIDC_FLOWS {
            if let Some(oldest) = guard
                .iter()
                .min_by_key(|(_, f)| f.created_at)
                .map(|(k, _)| k.clone())
            {
                guard.remove(&oldest);
            }
        }
        guard.insert(state, flow.clone());
        Ok((flow, code_challenge))
    }

    /// Consumes a pending OIDC PKCE flow by `state` if it has not expired.
    pub fn take_oidc_flow(&self, state: &str) -> Option<PendingOidcFlow> {
        let mut guard = self.oidc_flows.lock().ok()?;
        let flow = guard.remove(state)?;
        if Instant::now().duration_since(flow.created_at) >= OIDC_FLOW_TTL {
            return None;
        }
        Some(flow)
    }
}

/// Extracts the session cookie (`__Host-doh_session` or `doh_session`) from request headers.
pub fn extract_session_cookie(headers: &HeaderMap) -> Option<String> {
    for val in headers.get_all(COOKIE) {
        let Ok(cookie_str) = val.to_str() else {
            continue;
        };
        for pair in cookie_str.split(';') {
            let trimmed = pair.trim();
            if let Some((k, v)) = trimmed.split_once('=') {
                let key = k.trim();
                let value = v.trim();
                if (key == "__Host-doh_session" || key == "doh_session")
                    && !value.is_empty()
                    && value.len() <= 128
                {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

/// Formats the `Set-Cookie` header value for establishing an authenticated admin session.
pub fn format_session_set_cookie(session_id: &str, is_tls: bool) -> String {
    let max_age = SESSION_TTL.as_secs();
    if is_tls {
        format!(
            "__Host-doh_session={session_id}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={max_age}"
        )
    } else {
        format!("doh_session={session_id}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}")
    }
}

/// Formats the `Set-Cookie` header value for clearing an admin session on logout.
pub fn format_session_clear_cookie(is_tls: bool) -> String {
    if is_tls {
        "__Host-doh_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0".to_string()
    } else {
        "doh_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0".to_string()
    }
}

/// Verifies CSRF protection on state-changing requests (`POST`, `PUT`, `PATCH`, `DELETE`):
/// 1. Validates `Sec-Fetch-Site` (must be `same-origin` or `none` if present).
/// 2. Validates `Origin` host matches `Host` header if `Origin` is present.
/// 3. Validates `X-CSRF-Token` header matches `session.csrf_token` in constant time.
pub fn verify_csrf_request(headers: &HeaderMap, session: &AdminSession) -> Result<(), &'static str> {
    if let Some(sec_fetch) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        if !matches!(sec_fetch, "same-origin" | "none") {
            return Err("Cross-site request blocked by Sec-Fetch-Site policy.");
        }
    }

    if let Some(origin) = headers.get(ORIGIN).and_then(|v| v.to_str().ok()) {
        if let Some(host) = headers.get(HOST).and_then(|v| v.to_str().ok()) {
            let origin_host = origin
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .split('/')
                .next()
                .unwrap_or("");
            if !origin_host.eq_ignore_ascii_case(host) {
                return Err("Request Origin header does not match Host header.");
            }
        }
    }

    let Some(csrf_header) = headers.get("x-csrf-token").and_then(|v| v.to_str().ok()) else {
        return Err("Missing required X-CSRF-Token header.");
    };

    if !constant_time_eq(csrf_header.trim().as_bytes(), session.csrf_token.as_bytes()) {
        return Err("Invalid X-CSRF-Token header.");
    }

    Ok(())
}

/// Verifies local admin username and Argon2id password hash in constant time.
pub fn verify_local_credentials(
    configured_username: Option<&str>,
    configured_password_hash: Option<&str>,
    candidate_username: &str,
    candidate_password: &str,
) -> bool {
    let (Some(expected_user), Some(expected_hash)) =
        (configured_username, configured_password_hash)
    else {
        let _ = verify_argon2id_phc(DUMMY_ARGON2ID_PHC, candidate_password.as_bytes());
        return false;
    };

    if expected_user.trim().is_empty() || expected_hash.trim().is_empty() {
        let _ = verify_argon2id_phc(DUMMY_ARGON2ID_PHC, candidate_password.as_bytes());
        return false;
    }

    let user_matches = constant_time_eq(
        expected_user.trim().as_bytes(),
        candidate_username.trim().as_bytes(),
    );
    let hash_to_check = if user_matches {
        expected_hash
    } else {
        DUMMY_ARGON2ID_PHC
    };
    let password_matches = verify_argon2id_phc(hash_to_check, candidate_password.as_bytes());
    user_matches && password_matches
}

// ============================================================================
// Keycloak OIDC JWT / JWKS Verification (`RS256`, `iss`, `aud`, `exp`, `nonce`)
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct JwkKey {
    pub kty: String,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default, rename = "use")]
    pub key_use: Option<String>,
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwksDocument {
    pub keys: Vec<JwkKey>,
}

#[derive(Debug, Clone, Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum JwtAudience {
    Single(String),
    Multiple(Vec<String>),
}

impl JwtAudience {
    fn contains(&self, expected: &str) -> bool {
        match self {
            Self::Single(s) => s == expected,
            Self::Multiple(list) => list.iter().any(|s| s == expected),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
struct RealmAccess {
    #[serde(default)]
    roles: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct JwtClaims {
    iss: String,
    aud: JwtAudience,
    exp: u64,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    preferred_username: Option<String>,
    #[serde(default)]
    sub: String,
    #[serde(default)]
    realm_access: Option<RealmAccess>,
    #[serde(default)]
    resource_access: Option<HashMap<String, RealmAccess>>,
    #[serde(default)]
    groups: Vec<String>,
}

/// Verifies a Keycloak OIDC ID Token (`RS256` signature against `jwks`, plus `iss`, `aud`, `exp`, `nonce`)
/// and maps Keycloak realm/client roles (`admin_role`, `viewer_role`) to `(username, AdminRole)`.
pub fn verify_oidc_id_token(
    id_token: &str,
    jwks: &JwksDocument,
    expected_issuer: &str,
    expected_client_id: &str,
    expected_nonce: &str,
    admin_role: &str,
    viewer_role: &str,
) -> Result<(String, AdminRole), String> {
    let mut parts = id_token.trim().split('.');
    let (Some(header_b64), Some(payload_b64), Some(sig_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("Malformed JWT structure.".to_string());
    };

    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| "Invalid Base64URL in JWT header.".to_string())?;
    let header: JwtHeader = serde_json::from_slice(&header_bytes)
        .map_err(|_| "Invalid JSON in JWT header.".to_string())?;

    // Rule 1.2: Strictly enforce RS256; never trust algorithm from header if not RS256.
    if header.alg != "RS256" {
        return Err("Unsupported JWT algorithm; only RS256 is permitted.".to_string());
    }

    let matching_key = jwks
        .keys
        .iter()
        .find(|k| {
            k.kty == "RSA"
                && k.key_use.as_deref().unwrap_or("sig") == "sig"
                && match (&header.kid, &k.kid) {
                    (Some(h_kid), Some(k_kid)) => h_kid == k_kid,
                    (None, _) => true,
                    _ => false,
                }
        })
        .ok_or_else(|| "No matching RSA signing key found in JWKS.".to_string())?;

    let (Some(ref n_b64), Some(ref e_b64)) = (&matching_key.n, &matching_key.e) else {
        return Err("JWK is missing RSA modulus (n) or exponent (e).".to_string());
    };

    let signing_input = format!("{header_b64}.{payload_b64}");
    if !verify_rs256_jwk(n_b64, e_b64, signing_input.as_bytes(), sig_b64) {
        return Err("JWT RS256 signature verification failed.".to_string());
    }

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| "Invalid Base64URL in JWT payload.".to_string())?;
    let claims: JwtClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|_| "Invalid JSON in JWT claims.".to_string())?;

    if claims.iss.trim_end_matches('/') != expected_issuer.trim_end_matches('/') {
        return Err("JWT issuer (iss) mismatch.".to_string());
    }
    if !claims.aud.contains(expected_client_id) {
        return Err("JWT audience (aud) mismatch.".to_string());
    }
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if claims.exp <= now_unix {
        return Err("JWT has expired (exp).".to_string());
    }
    let Some(ref token_nonce) = claims.nonce else {
        return Err("JWT is missing required nonce claim.".to_string());
    };
    if !constant_time_eq(token_nonce.as_bytes(), expected_nonce.as_bytes()) {
        return Err("JWT nonce mismatch.".to_string());
    }

    // Collect all roles from realm_access, resource_access[client_id], and groups
    let mut roles: Vec<&str> = Vec::new();
    if let Some(ref ra) = claims.realm_access {
        for r in &ra.roles {
            roles.push(r.as_str());
        }
    }
    if let Some(ref res_map) = claims.resource_access {
        if let Some(client_ra) = res_map.get(expected_client_id) {
            for r in &client_ra.roles {
                roles.push(r.as_str());
            }
        }
    }
    for g in &claims.groups {
        roles.push(g.trim_start_matches('/'));
    }

    let resolved_role = if !admin_role.is_empty() && roles.contains(&admin_role) {
        AdminRole::Admin
    } else if !viewer_role.is_empty() && roles.contains(&viewer_role) {
        AdminRole::Viewer
    } else {
        return Err("User does not possess required OIDC role (doh-admin or doh-viewer).".to_string());
    };

    let username = claims
        .preferred_username
        .filter(|u| !u.trim().is_empty())
        .unwrap_or(claims.sub);

    Ok((username, resolved_role))
}
