//! Unified error type for `daviante-doh` derived via `thiserror`.

use std::io;

use hyper::StatusCode;
use thiserror::Error;

/// Unified error type for DoH, ODoH, and DNS wire operations.
#[derive(Debug, Error)]
pub enum DohError {
    /// Malformed DNS message or invalid query parameter (HTTP 400).
    #[error("bad request: {0}")]
    BadRequest(String),
    /// DNS packet is truncated or violates RFC 1035 / RFC 8484 wire constraints (HTTP 400).
    #[error("malformed DNS packet: {0}")]
    MalformedDnsPacket(&'static str),
    /// Request payload exceeds RFC 8484 / DNS maximum size (HTTP 413).
    #[error("DNS payload exceeds maximum allowed size")]
    PayloadTooLarge,
    /// Request URI or `?dns=` query parameter exceeds maximum length (HTTP 414, RFC 9110 §15.5.15).
    #[error("URI or query parameter exceeds maximum allowed length")]
    UriTooLong,
    /// HTTP method not allowed for this endpoint or configuration (HTTP 405).
    #[error("HTTP method not allowed")]
    MethodNotAllowed,
    /// Requested media type in Accept header is not supported (HTTP 406).
    #[error("no acceptable media type found")]
    NotAcceptable,
    /// Content-Type header is not supported (HTTP 415).
    #[error("unsupported Content-Type media type")]
    UnsupportedMediaType,
    /// Client exceeded per-IP rate limit (HTTP 429).
    #[error("rate limit exceeded")]
    RateLimited,
    /// Client request body or upstream operation timed out (HTTP 408).
    #[error("client request timed out")]
    RequestTimeout,
    /// Upstream DNS resolver timed out (HTTP 504 / DNS SERVFAIL EDE 22).
    #[error("upstream DNS resolver timed out")]
    UpstreamTimeout,
    /// Upstream DNS resolver returned an invalid response or I/O error (HTTP 502 / DNS SERVFAIL EDE 23).
    #[error("upstream DNS error: {0}")]
    UpstreamError(String),
    /// Oblivious DoH key ID does not match active or previous server key (HTTP 401).
    #[error("ODoH key ID mismatch or expired key")]
    OdohStaleKey,
    /// Oblivious DoH cryptographic or serialization error (HTTP 400).
    #[error("ODoH error: {0}")]
    OdohCryptoError(String),
    /// Invalid server configuration.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    /// Underlying network I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

impl DohError {
    /// Maps a `DohError` to its corresponding RFC 8484 / RFC 9110 / RFC 9230 HTTP status code.
    pub fn status_code(&self) -> StatusCode {
        match self {
            DohError::BadRequest(_)
            | DohError::OdohCryptoError(_)
            | DohError::MalformedDnsPacket(_) => StatusCode::BAD_REQUEST,
            DohError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            DohError::UriTooLong => StatusCode::URI_TOO_LONG,
            DohError::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            DohError::NotAcceptable => StatusCode::NOT_ACCEPTABLE,
            DohError::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            DohError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            DohError::RequestTimeout => StatusCode::REQUEST_TIMEOUT,
            DohError::UpstreamTimeout => StatusCode::GATEWAY_TIMEOUT,
            DohError::UpstreamError(_) | DohError::Io(_) => StatusCode::BAD_GATEWAY,
            DohError::OdohStaleKey => StatusCode::UNAUTHORIZED,
            DohError::InvalidConfig(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}
