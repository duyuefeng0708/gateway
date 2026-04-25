//! Rekor hashedrekord HTTP client.
//!
//! Talks to a Sigstore Rekor instance over plain HTTPS. Intentionally does
//! NOT depend on the `rekor` or `rekor-rs` crates — both are alpha and
//! have churning APIs. Posting JSON ourselves is also less code.
//!
//! Reference: hashedrekord schema v0.0.1
//!   https://github.com/sigstore/rekor/blob/main/types/hashedrekord/v0.0.1/hashedrekord_v0_0_1_schema.json
//!
//! The body shape we POST:
//! ```json
//! {
//!   "kind": "hashedrekord",
//!   "apiVersion": "0.0.1",
//!   "spec": {
//!     "signature": {
//!       "content": "<base64 sig>",
//!       "publicKey": { "content": "<base64 PEM>" }
//!     },
//!     "data": {
//!       "hash": { "algorithm": "sha256", "value": "<hex>" }
//!     }
//!   }
//! }
//! ```
//!
//! The 201 response includes a single top-level entry whose key is the
//! Rekor UUID; its value contains `logIndex` and `verification.integratedTime`.

use serde_json::{json, Value};

use crate::transparency::state::{
    merkle_root_hex, pem_to_base64, signature_to_base64, PublishError,
};

/// Endpoint Rekor exposes for new entries.
const ENTRIES_PATH: &str = "/api/v1/log/entries";

/// Thin wrapper around `reqwest::Client` so the publisher can be tested
/// against `wiremock` without owning the URL plumbing.
pub(crate) struct RekorClient {
    http: reqwest::Client,
    base_url: String,
}

/// Successful Rekor acceptance — extracted from the 201 response body.
#[derive(Debug, Clone)]
pub(crate) struct RekorAcceptance {
    pub uuid: String,
    pub log_index: i64,
    pub integrated_time: u64,
}

impl RekorClient {
    pub(crate) fn new(http: reqwest::Client, base_url: String) -> Self {
        // Tolerate trailing slashes on the base URL; the public docs show
        // both forms in their CLI examples.
        let base_url = base_url.trim_end_matches('/').to_string();
        Self { http, base_url }
    }

    /// POST a hashedrekord body and return the raw JSON response on a 2xx.
    /// Non-2xx responses are mapped to `PublishError::Server(status, body)`.
    pub(crate) async fn publish(&self, body: &Value) -> Result<Value, PublishError> {
        let url = format!("{}{}", self.base_url, ENTRIES_PATH);
        let resp = self
            .http
            .post(&url)
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .json(body)
            .send()
            .await
            .map_err(|e| PublishError::Network(e.to_string()))?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| PublishError::Network(e.to_string()))?;

        if !status.is_success() {
            return Err(PublishError::Server(status.as_u16(), text));
        }

        serde_json::from_str(&text).map_err(|e| {
            // A 2xx with un-parseable JSON is server-side weirdness; bucket
            // it under "server_error" via the caller's mapping.
            PublishError::Server(status.as_u16(), format!("response not JSON: {e}: {text}"))
        })
    }
}

/// Build the body POSTed to Rekor for one batched anchor.
///
/// `merkle_root` is the 32-byte SHA-256 Merkle root over all pending
/// chain heads. `signature_bytes` is the 64-byte Ed25519 signature over
/// that root (NOT a hash of the root). `public_key_pem` is the PEM-encoded
/// Ed25519 public key whose private half produced the signature.
pub(crate) fn build_hashedrekord_body(
    merkle_root: &[u8; 32],
    signature_bytes: &[u8],
    public_key_pem: &str,
) -> Value {
    json!({
        "kind": "hashedrekord",
        "apiVersion": "0.0.1",
        "spec": {
            "signature": {
                "content": signature_to_base64(signature_bytes),
                "publicKey": {
                    "content": pem_to_base64(public_key_pem),
                }
            },
            "data": {
                "hash": {
                    "algorithm": "sha256",
                    "value": merkle_root_hex(merkle_root),
                }
            }
        }
    })
}

/// Parse a Rekor 201 response body into a [`RekorAcceptance`].
///
/// Rekor returns a JSON object whose single top-level key IS the new
/// entry's UUID; the value is the entry envelope. `logIndex` lives at the
/// top of that envelope; `integratedTime` lives under `verification`.
///
/// Real-world Rekor sometimes omits `verification` if signed-entry-timestamp
/// generation lagged. We tolerate that and default `integrated_time` to 0
/// rather than fail the cycle — the receipt verifier can re-fetch later.
pub(crate) fn parse_rekor_response(value: &Value) -> Result<RekorAcceptance, String> {
    let obj = value
        .as_object()
        .ok_or_else(|| "rekor response was not a JSON object".to_string())?;

    let (uuid, envelope) = obj
        .iter()
        .next()
        .ok_or_else(|| "rekor response object was empty".to_string())?;

    let log_index = envelope
        .get("logIndex")
        .and_then(Value::as_i64)
        .ok_or_else(|| "rekor response missing logIndex".to_string())?;

    let integrated_time = envelope
        .get("verification")
        .and_then(|v| v.get("integratedTime"))
        .and_then(Value::as_u64)
        .or_else(|| envelope.get("integratedTime").and_then(Value::as_u64))
        .unwrap_or(0);

    Ok(RekorAcceptance {
        uuid: uuid.clone(),
        log_index,
        integrated_time,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_body_has_expected_shape() {
        let root = [9u8; 32];
        let sig = [3u8; 64];
        let pem = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n";
        let body = build_hashedrekord_body(&root, &sig, pem);
        assert_eq!(body["kind"], "hashedrekord");
        assert_eq!(body["apiVersion"], "0.0.1");
        let spec = &body["spec"];
        assert!(spec["signature"]["content"].is_string());
        assert!(spec["signature"]["publicKey"]["content"].is_string());
        assert_eq!(spec["data"]["hash"]["algorithm"], "sha256");
        let value = spec["data"]["hash"]["value"].as_str().unwrap();
        assert_eq!(value.len(), 64); // hex of 32 bytes
        assert!(value.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn parse_response_extracts_uuid_and_index() {
        let raw = serde_json::json!({
            "abc123uuid": {
                "logIndex": 42,
                "verification": {
                    "integratedTime": 1_700_000_000u64
                }
            }
        });
        let acc = parse_rekor_response(&raw).unwrap();
        assert_eq!(acc.uuid, "abc123uuid");
        assert_eq!(acc.log_index, 42);
        assert_eq!(acc.integrated_time, 1_700_000_000);
    }

    #[test]
    fn parse_response_tolerates_missing_verification() {
        let raw = serde_json::json!({
            "uuid_x": {
                "logIndex": 7,
            }
        });
        let acc = parse_rekor_response(&raw).unwrap();
        assert_eq!(acc.integrated_time, 0);
    }
}
