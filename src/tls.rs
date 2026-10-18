//! Clean-room TLS 1.2 / 1.3 acceptor with background certificate hot-reload (`tokio-rustls`),
//! zero 0-RTT early-data replay exposure, configurable minimum TLS version (`1.2` / `1.3`),
//! and leaf-pinned TLS client verification for container self-healthchecks.

#![cfg(feature = "tls")]

use std::fmt;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwap;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::crypto::{
    verify_tls12_signature, verify_tls13_signature, CryptoProvider,
};
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use tokio_rustls::rustls::{
    ClientConfig, DigitallySignedStruct, Error as RustlsError, ServerConfig, SignatureScheme,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::error::DohError;

/// Minimum TLS protocol version permitted on incoming HTTPS connections (`DOH_TLS_MIN_VERSION`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsMinVersion {
    /// Allow both TLS 1.3 and TLS 1.2 (default).
    #[default]
    Tls12,
    /// Allow only TLS 1.3 (strict mode per RFC 8484 / modern enterprise policy).
    Tls13,
}

impl TlsMinVersion {
    pub fn from_str_name(s: &str) -> Result<Self, DohError> {
        match s.trim() {
            "1.2" | "tls1.2" | "TLS1.2" | "tls12" => Ok(Self::Tls12),
            "1.3" | "tls1.3" | "TLS1.3" | "tls13" => Ok(Self::Tls13),
            other => Err(DohError::InvalidConfig(format!(
                "invalid TLS minimum version '{other}' (expected '1.2' or '1.3')"
            ))),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tls12 => "1.2",
            Self::Tls13 => "1.3",
        }
    }
}

/// Loads a `ServerConfig` with ALPN `h2` and `http/1.1`, `max_early_data_size = 0` (0-RTT disabled, H-7),
/// and the specified `min_version` (`1.2` or `1.3`).
pub fn build_tls_server_config(
    cert_path: &Path,
    key_path: &Path,
    min_version: TlsMinVersion,
) -> Result<ServerConfig, DohError> {
    let certs = load_certs(cert_path)?;
    let private_key = load_private_key(key_path)?;

    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let versions: &[&'static tokio_rustls::rustls::SupportedProtocolVersion] = match min_version {
        TlsMinVersion::Tls12 => &[
            &tokio_rustls::rustls::version::TLS13,
            &tokio_rustls::rustls::version::TLS12,
        ],
        TlsMinVersion::Tls13 => &[&tokio_rustls::rustls::version::TLS13],
    };

    let mut server_cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .map_err(|e| DohError::InvalidConfig(format!("TLS protocol error: {e}")))?
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .map_err(|e| DohError::InvalidConfig(format!("TLS key/cert mismatch: {e}")))?;

    server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    // H-7: Explicitly keep 0-RTT early data disabled (0) to prevent replay and unbounded buffer DoS.
    server_cfg.max_early_data_size = 0;

    Ok(server_cfg)
}

/// Loads a `TlsAcceptor` with ALPN `h2` and `http/1.1` from PEM certificate and key files.
pub fn build_tls_acceptor(cert_path: &Path, key_path: &Path) -> Result<TlsAcceptor, DohError> {
    build_tls_acceptor_with_version(cert_path, key_path, TlsMinVersion::Tls12)
}

/// Loads a `TlsAcceptor` with explicit `TlsMinVersion` (`1.2` or `1.3`).
pub fn build_tls_acceptor_with_version(
    cert_path: &Path,
    key_path: &Path,
    min_version: TlsMinVersion,
) -> Result<TlsAcceptor, DohError> {
    let server_cfg = build_tls_server_config(cert_path, key_path, min_version)?;
    Ok(TlsAcceptor::from(Arc::new(server_cfg)))
}

#[doc(hidden)]
pub fn load_certs(cert_path: &Path) -> Result<Vec<CertificateDer<'static>>, DohError> {
    let cert_file = File::open(cert_path).map_err(|e| {
        DohError::InvalidConfig(format!(
            "failed to open TLS certificate {}: {e}",
            cert_path.display()
        ))
    })?;
    let cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| DohError::InvalidConfig(format!("invalid PEM certificate: {e}")))?;

    if certs.is_empty() {
        return Err(DohError::InvalidConfig(format!(
            "no certificates found in {}",
            cert_path.display()
        )));
    }
    Ok(certs)
}

#[doc(hidden)]
pub fn load_private_key(key_path: &Path) -> Result<PrivateKeyDer<'static>, DohError> {
    let key_file = File::open(key_path).map_err(|e| {
        DohError::InvalidConfig(format!(
            "failed to open TLS key {}: {e}",
            key_path.display()
        ))
    })?;
    let key_reader = BufReader::new(key_file);
    PrivateKeyDer::from_pem_reader(key_reader).map_err(|e| {
        DohError::InvalidConfig(format!(
            "invalid or missing PEM private key in {}: {e}",
            key_path.display()
        ))
    })
}

/// Leaf-certificate pinning verifier used by `daviante-doh --healthcheck` when probing the local HTTPS listener (M-11).
/// Verifies both that the server presented the exact leaf certificate from `DOH_TLS_CERT_PATH` and that
/// the TLS handshake signature over the ephemeral key exchange is cryptographically valid.
#[doc(hidden)]
pub struct PinnedLeafCertVerifier {
    pub pinned_leaf: CertificateDer<'static>,
    pub provider: Arc<CryptoProvider>,
}

impl fmt::Debug for PinnedLeafCertVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedLeafCertVerifier").finish()
    }
}

impl ServerCertVerifier for PinnedLeafCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        if end_entity.as_ref() == self.pinned_leaf.as_ref() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(RustlsError::General(
                "server leaf certificate does not match pinned DOH_TLS_CERT_PATH".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Builds a `TlsConnector` pinned to the leaf certificate in `cert_path` for `daviante-doh --healthcheck` (M-11).
pub fn build_pinned_healthcheck_connector(cert_path: &Path) -> Result<TlsConnector, DohError> {
    let mut certs = load_certs(cert_path)?;
    let pinned_leaf = certs.remove(0);
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let verifier = Arc::new(PinnedLeafCertVerifier {
        pinned_leaf,
        provider: Arc::clone(&provider),
    });

    let mut client_cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| DohError::InvalidConfig(format!("TLS client config error: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    client_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsConnector::from(Arc::new(client_cfg)))
}

/// Manages a hot-reloadable `TlsAcceptor` that checks certificate file modification times periodically
/// using `tokio::task::spawn_blocking` so worker threads are never blocked on filesystem I/O (L-9).
#[derive(Clone)]
pub struct ReloadableTlsAcceptor {
    current: Arc<ArcSwap<TlsAcceptor>>,
}

impl ReloadableTlsAcceptor {
    pub fn spawn(cert_path: PathBuf, key_path: PathBuf) -> Result<Self, DohError> {
        Self::spawn_with_version(cert_path, key_path, TlsMinVersion::Tls12)
    }

    pub fn spawn_with_version(
        cert_path: PathBuf,
        key_path: PathBuf,
        min_version: TlsMinVersion,
    ) -> Result<Self, DohError> {
        let initial = build_tls_acceptor_with_version(&cert_path, &key_path, min_version)?;
        let shared = Arc::new(ArcSwap::from_pointee(initial));
        let bg_shared = Arc::clone(&shared);

        let mut last_mtime = Self::combined_mtime(&cert_path, &key_path);

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                let c_path = cert_path.clone();
                let k_path = key_path.clone();
                let reload_res = tokio::task::spawn_blocking(move || {
                    let current_mtime = Self::combined_mtime(&c_path, &k_path);
                    (
                        current_mtime,
                        build_tls_acceptor_with_version(&c_path, &k_path, min_version),
                    )
                })
                .await;

                if let Ok((current_mtime, maybe_acceptor)) = reload_res {
                    if current_mtime != last_mtime {
                        match maybe_acceptor {
                            Ok(updated) => {
                                bg_shared.store(Arc::new(updated));
                                last_mtime = current_mtime;
                                tracing::info!("reloaded TLS certificate and private key");
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "failed to reload modified TLS certificate (keeping previous certificate): {e}"
                                );
                            }
                        }
                    }
                }
            }
        });

        Ok(Self { current: shared })
    }

    pub fn get(&self) -> Arc<TlsAcceptor> {
        Arc::clone(&self.current.load())
    }

    fn combined_mtime(cert: &Path, key: &Path) -> (Option<SystemTime>, Option<SystemTime>) {
        let m1 = std::fs::metadata(cert).and_then(|m| m.modified()).ok();
        let m2 = std::fs::metadata(key).and_then(|m| m.modified()).ok();
        (m1, m2)
    }
}
