//! Clean-room implementation of RFC 9230 (Oblivious DNS over HTTPS - ODoH) with 2-key rotation grace window
//! and RFC 9230 §7 / RFC 8467 468-byte response plaintext padding.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use bytes::Bytes;
use odoh_rs::{
    Deserialize, ObliviousDoHConfig, ObliviousDoHConfigs, ObliviousDoHKeyPair, ObliviousDoHMessage,
    ObliviousDoHMessagePlaintext, OdohSecret, ResponseNonce, Serialize,
};
use tokio::runtime::Handle;

use crate::dns::wire::RESPONSE_PADDING_BLOCK_SIZE;
use crate::error::DohError;

/// Active HPKE key pair and pre-serialized `ObliviousDoHConfigs` payload for `/.well-known/odohconfigs`.
#[derive(Clone)]
pub struct OdohActiveKey {
    key_pair: ObliviousDoHKeyPair,
    wire_configs: Vec<u8>,
}

impl fmt::Debug for OdohActiveKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OdohActiveKey").finish()
    }
}

/// Holds both the current HPKE key pair and the immediately preceding key pair during rotation grace window.
#[derive(Clone, Debug)]
pub struct OdohKeyRing {
    pub current: OdohActiveKey,
    pub previous: Option<OdohActiveKey>,
}

/// Per-request ODoH decryption state used to encrypt the corresponding DNS response.
#[derive(Clone, Debug)]
pub struct OdohResponseSession {
    plaintext_query: ObliviousDoHMessagePlaintext,
    secret: OdohSecret,
}

impl OdohActiveKey {
    /// Generates a fresh HPKE key pair and serializes its RFC 9230 `ObliviousDoHConfigs` representation.
    pub fn generate() -> Result<Self, DohError> {
        let mut rng = rand::rng();
        let key_pair = ObliviousDoHKeyPair::new(&mut rng);
        let single_cfg = ObliviousDoHConfig::from(key_pair.public().clone());
        let mut wire_configs = Vec::new();
        ObliviousDoHConfigs::from(vec![single_cfg])
            .serialize(&mut wire_configs)
            .map_err(|e| DohError::OdohCryptoError(e.to_string()))?;
        Ok(Self {
            key_pair,
            wire_configs,
        })
    }

    /// Returns the serialized `ObliviousDoHConfigs` bytes served at `/.well-known/odohconfigs`.
    pub fn serialized_configs(&self) -> Vec<u8> {
        self.wire_configs.clone()
    }

    /// Attempts to decrypt a parsed `ObliviousDoHMessage` with this key pair.
    pub fn try_open_message(
        &self,
        msg: &ObliviousDoHMessage,
    ) -> Result<Option<(Vec<u8>, OdohResponseSession)>, DohError> {
        let expected_id = self
            .key_pair
            .public()
            .identifier()
            .map_err(|e| DohError::OdohCryptoError(e.to_string()))?;

        if expected_id != msg.key_id() {
            return Ok(None);
        }

        let (plaintext_query, secret) = odoh_rs::decrypt_query(msg, &self.key_pair)
            .map_err(|_| DohError::BadRequest("failed to decrypt ODoH query".into()))?;

        let raw_dns = plaintext_query.clone().into_msg().to_vec();
        Ok(Some((
            raw_dns,
            OdohResponseSession {
                plaintext_query,
                secret,
            },
        )))
    }

    /// Decrypts an incoming `application/oblivious-dns-message` request body.
    pub fn open_query(
        &self,
        ciphertext: Vec<u8>,
    ) -> Result<(Vec<u8>, OdohResponseSession), DohError> {
        let msg = ObliviousDoHMessage::deserialize(&mut Bytes::from(ciphertext))
            .map_err(|_| DohError::BadRequest("malformed ODoH message".into()))?;
        self.try_open_message(&msg)?.ok_or(DohError::OdohStaleKey)
    }
}

impl OdohKeyRing {
    /// Returns the serialized `ObliviousDoHConfigs` bytes for the current active key.
    pub fn serialized_configs(&self) -> Vec<u8> {
        self.current.serialized_configs()
    }

    /// Decrypts an incoming `application/oblivious-dns-message` using the current key or the previous epoch key.
    pub fn open_query(
        &self,
        ciphertext: Vec<u8>,
    ) -> Result<(Vec<u8>, OdohResponseSession), DohError> {
        let msg = ObliviousDoHMessage::deserialize(&mut Bytes::from(ciphertext))
            .map_err(|_| DohError::BadRequest("malformed ODoH message".into()))?;

        if let Some(res) = self.current.try_open_message(&msg)? {
            return Ok(res);
        }
        if let Some(prev) = &self.previous {
            if let Some(res) = prev.try_open_message(&msg)? {
                return Ok(res);
            }
        }
        Err(DohError::OdohStaleKey)
    }
}

impl OdohResponseSession {
    /// Encrypts the DNS wire response back into an `application/oblivious-dns-message` payload,
    /// applying RFC 9230 §7 / RFC 8467 §4.1 468-byte block padding to the ODoH plaintext response (N-3).
    pub fn seal_response(self, dns_response: Vec<u8>) -> Result<Vec<u8>, DohError> {
        let nonce: ResponseNonce = rand::random();
        let msg_len = dns_response.len();
        let target_len = msg_len
            .max(1)
            .div_ceil(RESPONSE_PADDING_BLOCK_SIZE)
            .saturating_mul(RESPONSE_PADDING_BLOCK_SIZE);
        let padding_len = target_len.saturating_sub(msg_len).min(u16::MAX as usize);
        let plain_resp = ObliviousDoHMessagePlaintext::new(dns_response, padding_len);
        let encrypted =
            odoh_rs::encrypt_response(&self.plaintext_query, &plain_resp, self.secret, nonce)
                .map_err(|e| DohError::OdohCryptoError(e.to_string()))?;

        let mut out = Vec::new();
        encrypted
            .serialize(&mut out)
            .map_err(|e| DohError::OdohCryptoError(e.to_string()))?;
        Ok(out)
    }
}

/// Manages lock-free background rotation of ODoH HPKE keys with a 2-key grace window.
#[derive(Clone, Debug)]
pub struct OdohKeyManager {
    ring: Arc<ArcSwap<OdohKeyRing>>,
}

impl OdohKeyManager {
    /// Creates a new `OdohKeyManager` and spawns a background rotation task on `runtime`.
    pub fn spawn(runtime: Handle, rotation_period: Duration) -> Result<Self, DohError> {
        let initial_ring = OdohKeyRing {
            current: OdohActiveKey::generate()?,
            previous: None,
        };
        let shared = Arc::new(ArcSwap::from_pointee(initial_ring));
        let bg_shared = Arc::clone(&shared);
        let period = rotation_period.max(Duration::from_secs(60));

        runtime.spawn(async move {
            loop {
                tokio::time::sleep(period).await;
                match OdohActiveKey::generate() {
                    Ok(next_key) => {
                        let prev_current = bg_shared.load().current.clone();
                        bg_shared.store(Arc::new(OdohKeyRing {
                            current: next_key,
                            previous: Some(prev_current),
                        }));
                    }
                    Err(e) => {
                        tracing::error!("failed to rotate ODoH HPKE key: {e}");
                    }
                }
            }
        });

        Ok(Self { ring: shared })
    }

    /// Manually rotates the active key while preserving the previous key in the grace ring.
    pub fn rotate_now(&self) -> Result<(), DohError> {
        let next_key = OdohActiveKey::generate()?;
        let prev_current = self.ring.load().current.clone();
        self.ring.store(Arc::new(OdohKeyRing {
            current: next_key,
            previous: Some(prev_current),
        }));
        Ok(())
    }

    /// Returns a snapshot of the currently active ODoH key ring.
    pub fn snapshot(&self) -> Arc<OdohKeyRing> {
        Arc::clone(&self.ring.load())
    }
}
