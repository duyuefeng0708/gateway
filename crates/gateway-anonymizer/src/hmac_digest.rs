//! HMAC-SHA256 keyed digest for audit-log prompt and response hashes.
//!
//! Codex F12 (2026-04-25 plan-eng-review): bare SHA-256 of post-redaction
//! prompts and responses leaks via confirmation attacks. An adversary who
//! suspects a particular prompt can hash candidates and check against the
//! audit log. HMAC with a per-instance secret defeats this: without the key,
//! no candidate can be confirmed.
//!
//! Verifiers receive the key out-of-band (operator export) and validate
//! receipt digests with it. Receipts that travel without the key still
//! carry usefully tamper-evident structure (the entry hash chain itself
//! authenticates the digest values), so structural verification works
//! offline even without the HMAC key.

use gateway_common::errors::AuditError;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Holds an HMAC-SHA256 key and its stable identifier. Cheap to clone
/// (the inner key is a Vec<u8> shared by reference via Arc upstream
/// callers). Mac instances are NOT cloneable — construct a fresh one
/// per digest.
#[derive(Debug, Clone)]
pub struct HmacContext {
    key: Vec<u8>,
    /// Identifier carried into receipts so verifiers can look up the
    /// matching key in their trust store. Rotation: new key gets a new
    /// id; old receipts continue to validate against archived keys.
    pub key_id: String,
}

impl HmacContext {
    /// Construct from a hex-encoded key. Must decode to at least 32 bytes
    /// (recommended HMAC-SHA256 key size).
    pub fn from_hex(hex_key: &str, key_id: impl Into<String>) -> Result<Self, AuditError> {
        let key = decode_hex(hex_key.trim())
            .map_err(|e| AuditError::WriteError(format!("invalid hex HMAC key: {e}")))?;
        if key.len() < 32 {
            return Err(AuditError::WriteError(format!(
                "HMAC key must be at least 32 bytes (256 bits); got {} bytes",
                key.len()
            )));
        }
        Ok(Self {
            key,
            key_id: key_id.into(),
        })
    }

    /// Construct from raw bytes. Caller is responsible for ensuring the
    /// material is at least 32 bytes of high-entropy data.
    pub fn from_bytes(key: Vec<u8>, key_id: impl Into<String>) -> Result<Self, AuditError> {
        if key.len() < 32 {
            return Err(AuditError::WriteError(format!(
                "HMAC key must be at least 32 bytes; got {}",
                key.len()
            )));
        }
        Ok(Self {
            key,
            key_id: key_id.into(),
        })
    }

    /// Compute HMAC-SHA256 over `bytes`, returning lowercase hex.
    pub fn digest(&self, bytes: &[u8]) -> String {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.key)
            .expect("HMAC accepts any key length, but constructor enforces >= 32 bytes");
        mac.update(bytes);
        format!("{:x}", mac.finalize().into_bytes())
    }

    /// Begin a rolling digest for streaming responses. The caller pushes
    /// bytes via `update` as the response stream is forwarded to the
    /// client; once the stream ends, `finalize` returns the hex digest.
    pub fn rolling(&self) -> RollingDigest {
        let mac = <HmacSha256 as Mac>::new_from_slice(&self.key)
            .expect("constructor enforces >= 32 byte key");
        RollingDigest { mac }
    }
}

/// Stateful HMAC accumulator for streaming bodies. Codex F9.
pub struct RollingDigest {
    mac: HmacSha256,
}

impl RollingDigest {
    pub fn update(&mut self, bytes: &[u8]) {
        self.mac.update(bytes);
    }

    pub fn finalize(self) -> String {
        format!("{:x}", self.mac.finalize().into_bytes())
    }
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("hex string must have even length".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| format!("invalid hex byte at index {i}: {e}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> HmacContext {
        // 64 hex chars = 32 bytes. Pinned for deterministic test digests.
        HmacContext::from_hex(
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            "test-key",
        )
        .unwrap()
    }

    #[test]
    fn digest_is_deterministic_for_same_input() {
        let c = ctx();
        let a = c.digest(b"hello world");
        let b = c.digest(b"hello world");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64); // sha256 hex
    }

    #[test]
    fn digest_changes_with_input() {
        let c = ctx();
        assert_ne!(c.digest(b"a"), c.digest(b"b"));
    }

    #[test]
    fn digest_changes_with_key() {
        let c1 = HmacContext::from_hex(
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            "k1",
        )
        .unwrap();
        let c2 = HmacContext::from_hex(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "k2",
        )
        .unwrap();
        assert_ne!(c1.digest(b"same input"), c2.digest(b"same input"));
    }

    #[test]
    fn rolling_matches_one_shot_for_concatenation() {
        let c = ctx();
        let one_shot = c.digest(b"the quick brown fox jumps over the lazy dog");
        let mut rolling = c.rolling();
        rolling.update(b"the quick brown fox ");
        rolling.update(b"jumps over the lazy dog");
        assert_eq!(rolling.finalize(), one_shot);
    }

    #[test]
    fn rolling_handles_empty_chunks() {
        let c = ctx();
        let mut r = c.rolling();
        r.update(b"a");
        r.update(b"");
        r.update(b"b");
        let mut r2 = c.rolling();
        r2.update(b"ab");
        assert_eq!(r.finalize(), r2.finalize());
    }

    #[test]
    fn from_hex_rejects_short_key() {
        let result = HmacContext::from_hex("aabbccdd", "tiny");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("at least 32"));
    }

    #[test]
    fn from_hex_rejects_invalid_hex() {
        let result = HmacContext::from_hex(
            "ZZZZZZZZ0203040506070809000102030405060708090a0b0c0d0e0f10",
            "bad",
        );
        assert!(result.is_err());
    }

    #[test]
    fn from_hex_rejects_odd_length() {
        let result = HmacContext::from_hex(
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2",
            "odd",
        );
        assert!(result.is_err());
    }

    #[test]
    fn key_id_round_trips() {
        let c = ctx();
        assert_eq!(c.key_id, "test-key");
    }
}
