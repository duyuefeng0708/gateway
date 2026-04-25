//! Public API for the transparency-log anchor publisher.
//!
//! `TransparencyState` owns the Ed25519 signing key, the pending-batch
//! queue of chain heads to anchor, and the published-state snapshot the
//! `GET /v1/transparency/head` route reads. The actual Rekor publication
//! work lives in `rekor.rs`; this module is the orchestration boundary
//! that handler code talks to.
//!
//! # Wiring
//! Construction: `TransparencyState::from_env()`. Reads the signing key,
//! Rekor URL, and anchor interval from environment variables. The caller
//! (the wiring PR, not this commit) owns the returned value inside an
//! `Arc` on `AppState` so handlers can reach it via the axum extractor.
//!
//! After construction the caller MUST call `spawn_publisher()` once to
//! start the background task. Without it, queued heads never make it to
//! Rekor — `record_head` would just fill an unbounded buffer.
//!
//! # Lifetime
//! `spawn_publisher` returns a `JoinHandle<()>`. The caller keeps it on
//! `AppState` and aborts on shutdown. The task itself runs forever; it
//! has no internal cancellation signal beyond Tokio runtime shutdown.

use base64::Engine as _;
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use gateway_common::types::AnchorStatus;
use rs_merkle::{algorithms::Sha256 as MerkleSha256, MerkleTree};
use serde::Serialize;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::Mutex;

use crate::metrics as gw_metrics;
use crate::transparency::rekor::{
    build_hashedrekord_body, parse_rekor_response, RekorAcceptance, RekorClient,
};

/// Default Rekor instance — Sigstore's public-good service.
const DEFAULT_REKOR_URL: &str = "https://rekor.sigstore.dev";
/// Default anchor interval, in seconds. 15 min × 96 cycles/day on Sigstore.
const DEFAULT_ANCHOR_INTERVAL_SECS: u64 = 900;
/// Default identifier embedded in receipts when `GATEWAY_SIGNING_KEY_ID`
/// is unset. Operators rotating keys SHOULD set this explicitly.
const DEFAULT_SIGNING_KEY_ID: &str = "primary";
/// Algorithm name written to receipts. Matches `AuditEntry.signature_alg`.
const SIGNATURE_ALG: &str = "ed25519";

/// Maximum exponential backoff between failed publish attempts.
const MAX_BACKOFF_SECS: u64 = 3600;
/// Initial backoff after a failure.
const INITIAL_BACKOFF_SECS: u64 = 30;

/// Errors returned by [`TransparencyState::from_env`].
#[derive(Debug, Error)]
pub enum TransparencyError {
    #[error("missing signing key: set GATEWAY_SIGNING_KEY or GATEWAY_SIGNING_KEY_FILE")]
    MissingSigningKey,
    #[error("invalid signing key: {0}")]
    InvalidSigningKey(String),
    #[error("rekor request failed: {0}")]
    RekorRequest(String),
    #[error("rekor returned status {0}: {1}")]
    RekorStatus(u16, String),
}

/// JSON snapshot returned by `GET /v1/transparency/head`. Mirrors the
/// receipt field set used elsewhere so clients can cross-check.
#[derive(Debug, Serialize, Clone)]
pub struct HeadSnapshot {
    pub current_chain_head: String,
    pub last_anchored_chain_head: String,
    pub last_publish_age_seconds: u64,
    pub anchor_status: AnchorStatus,
    pub rekor_uuid: String,
    pub log_index: i64,
    pub signing_key_id: String,
    pub signature_alg: String,
}

/// Mutable state guarded by a Tokio mutex. Held inside `TransparencyState`
/// behind an `Arc` so the publisher task and request handlers share a view.
#[derive(Debug, Default)]
struct InnerState {
    /// Most recent chain head recorded by the audit writer. Reflects what
    /// the proxy currently knows; not necessarily yet anchored.
    current_head: String,
    /// Most recent head that was actually anchored to Rekor.
    last_anchored_head: String,
    /// Pending chain heads to fold into the next Merkle root. Drained by
    /// every successful publisher cycle.
    pending: Vec<String>,
    /// Last successful publish — used for `last_publish_age_seconds`.
    last_publish_at: Option<Instant>,
    /// Last published receipt fields. Defaults until the first anchor.
    anchor_status: AnchorStatus,
    rekor_uuid: String,
    log_index: i64,
    integrated_time: u64,
}

/// Public transparency state. Cheaply cloneable — wraps an `Arc<Mutex<…>>`.
#[derive(Clone)]
pub struct TransparencyState {
    inner: Arc<Mutex<InnerState>>,
    signing_key: Arc<SigningKey>,
    verifying_key_pem: Arc<String>,
    signing_key_id: Arc<String>,
    rekor_url: Arc<String>,
    anchor_interval: Duration,
    /// Reqwest client used by the publisher. Independent of the proxy's
    /// upstream client so tuning one doesn't bleed into the other.
    http: reqwest::Client,
}

impl TransparencyState {
    /// Construct from environment variables. See module docs for the list.
    pub fn from_env() -> Result<Self, TransparencyError> {
        let signing_key = load_signing_key_from_env()?;
        let verifying_key = signing_key.verifying_key();
        let pem = encode_public_key_pem(&verifying_key);

        let signing_key_id =
            env::var("GATEWAY_SIGNING_KEY_ID").unwrap_or_else(|_| DEFAULT_SIGNING_KEY_ID.into());
        let rekor_url =
            env::var("GATEWAY_REKOR_URL").unwrap_or_else(|_| DEFAULT_REKOR_URL.into());
        let interval_secs = env::var("GATEWAY_REKOR_ANCHOR_INTERVAL")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(DEFAULT_ANCHOR_INTERVAL_SECS);

        let http = reqwest::Client::builder()
            .user_agent("gateway-proxy/transparency")
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| TransparencyError::RekorRequest(e.to_string()))?;

        Ok(Self {
            inner: Arc::new(Mutex::new(InnerState::default())),
            signing_key: Arc::new(signing_key),
            verifying_key_pem: Arc::new(pem),
            signing_key_id: Arc::new(signing_key_id),
            rekor_url: Arc::new(rekor_url),
            anchor_interval: Duration::from_secs(interval_secs),
            http,
        })
    }

    /// Construct from explicit values. Used by tests; production code uses
    /// [`from_env`]. The caller is responsible for environment cleanup.
    #[doc(hidden)]
    pub fn from_parts(
        signing_key: SigningKey,
        signing_key_id: String,
        rekor_url: String,
        anchor_interval: Duration,
    ) -> Self {
        let verifying_key = signing_key.verifying_key();
        let pem = encode_public_key_pem(&verifying_key);
        let http = reqwest::Client::builder()
            .user_agent("gateway-proxy/transparency")
            .timeout(Duration::from_secs(30))
            .build()
            .expect("reqwest client build for tests");
        Self {
            inner: Arc::new(Mutex::new(InnerState::default())),
            signing_key: Arc::new(signing_key),
            verifying_key_pem: Arc::new(pem),
            signing_key_id: Arc::new(signing_key_id),
            rekor_url: Arc::new(rekor_url),
            anchor_interval,
            http,
        }
    }

    /// Identifier of the Ed25519 signing key. Plumbed into every
    /// receipt so verifiers can pick the right public key from a trust
    /// store across rotations. Cheap O(1) string clone.
    pub fn signing_key_id(&self) -> String {
        self.signing_key_id.as_ref().clone()
    }

    /// Signature algorithm name (e.g. "ed25519"). Constant today; kept
    /// as a method so a post-quantum migration can switch without
    /// changing the call sites.
    pub fn signature_alg(&self) -> &'static str {
        SIGNATURE_ALG
    }

    /// Take a snapshot for the head route. Cheap; only acquires the mutex
    /// briefly to clone the relevant fields.
    pub async fn current_head(&self) -> HeadSnapshot {
        let inner = self.inner.lock().await;
        let last_publish_age_seconds = inner
            .last_publish_at
            .map(|t| t.elapsed().as_secs())
            .unwrap_or(0);
        HeadSnapshot {
            current_chain_head: inner.current_head.clone(),
            last_anchored_chain_head: inner.last_anchored_head.clone(),
            last_publish_age_seconds,
            anchor_status: inner.anchor_status,
            rekor_uuid: inner.rekor_uuid.clone(),
            log_index: inner.log_index,
            signing_key_id: self.signing_key_id.as_ref().clone(),
            signature_alg: SIGNATURE_ALG.to_string(),
        }
    }

    /// Record a new chain head. The publisher will pick it up on the next
    /// cycle. Duplicate calls with the same hash are de-duplicated.
    pub async fn record_head(&self, hash: String) {
        if hash.is_empty() {
            return;
        }
        let mut inner = self.inner.lock().await;
        inner.current_head = hash.clone();
        if inner.pending.last().map(String::as_str) != Some(hash.as_str()) {
            inner.pending.push(hash);
        }
    }

    /// Spawn the background publisher task. Safe to call multiple times in
    /// theory but the wiring layer should call it exactly once at startup.
    pub fn spawn_publisher(&self) -> tokio::task::JoinHandle<()> {
        let me = self.clone();
        tokio::spawn(async move { me.publisher_loop().await })
    }

    /// Run a single publisher cycle. Pure helper — exposed for tests so
    /// they can drive cycles deterministically without sleeping the test
    /// for the full 15-minute interval.
    #[doc(hidden)]
    pub async fn run_one_cycle_for_test(&self) {
        self.publish_pending().await;
    }

    /// Publisher main loop. Sleeps the configured interval, drains the
    /// pending queue, and on failure backs off exponentially up to one
    /// hour before resuming the regular cadence.
    async fn publisher_loop(self) {
        let mut backoff = Duration::from_secs(INITIAL_BACKOFF_SECS);
        loop {
            tokio::time::sleep(self.anchor_interval).await;
            let succeeded = self.publish_pending().await;
            if succeeded {
                backoff = Duration::from_secs(INITIAL_BACKOFF_SECS);
            } else {
                tokio::time::sleep(backoff).await;
                backoff = std::cmp::min(backoff * 2, Duration::from_secs(MAX_BACKOFF_SECS));
            }
        }
    }

    /// One publish step. Returns true if the cycle was either successful
    /// or a no-op (empty queue); false if a failure occurred so the caller
    /// can apply backoff. Tests call this directly via the test hook.
    async fn publish_pending(&self) -> bool {
        // Snapshot pending list and drain. Hold the lock only long enough
        // to take the queue — Rekor IO must NOT happen with the mutex held.
        let pending = {
            let mut inner = self.inner.lock().await;
            std::mem::take(&mut inner.pending)
        };

        if pending.is_empty() {
            return true;
        }

        let merkle_root = match compute_merkle_root(&pending) {
            Ok(root) => root,
            Err(e) => {
                tracing::warn!(error = %e, "transparency: merkle root computation failed");
                gw_metrics::record_transparency_publish_failed("merkle");
                self.mark_anchor_failed().await;
                self.requeue(pending).await;
                return false;
            }
        };

        let signature = self.signing_key.sign(&merkle_root);
        let signature_bytes = signature.to_bytes();

        let body = build_hashedrekord_body(
            &merkle_root,
            &signature_bytes,
            self.verifying_key_pem.as_str(),
        );

        let client = RekorClient::new(self.http.clone(), self.rekor_url.as_str().to_string());
        let result = client.publish(&body).await;

        match result {
            Ok(raw) => match parse_rekor_response(&raw) {
                Ok(acc) => {
                    self.mark_anchored(pending.last().cloned().unwrap_or_default(), acc)
                        .await;
                    true
                }
                Err(e) => {
                    tracing::warn!(error = %e, "transparency: rekor response parse failed");
                    gw_metrics::record_transparency_publish_failed("other");
                    self.mark_anchor_failed().await;
                    self.requeue(pending).await;
                    false
                }
            },
            Err(PublishError::Network(e)) => {
                tracing::warn!(error = %e, "transparency: rekor network error");
                gw_metrics::record_transparency_publish_failed("network");
                self.mark_anchor_failed().await;
                self.requeue(pending).await;
                false
            }
            Err(PublishError::Server(status, body)) => {
                tracing::warn!(status, body = %body, "transparency: rekor server error");
                gw_metrics::record_transparency_publish_failed("server_error");
                self.mark_anchor_failed().await;
                self.requeue(pending).await;
                false
            }
        }
    }

    async fn mark_anchored(&self, head: String, acc: RekorAcceptance) {
        let mut inner = self.inner.lock().await;
        if !head.is_empty() {
            inner.last_anchored_head = head;
        }
        inner.anchor_status = AnchorStatus::Anchored;
        inner.rekor_uuid = acc.uuid;
        inner.log_index = acc.log_index;
        inner.integrated_time = acc.integrated_time;
        inner.last_publish_at = Some(Instant::now());
        let age = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            .saturating_sub(acc.integrated_time);
        gw_metrics::set_transparency_last_publish_age(age as f64);
    }

    async fn mark_anchor_failed(&self) {
        let mut inner = self.inner.lock().await;
        inner.anchor_status = AnchorStatus::AnchorFailed;
    }

    /// Push the not-anchored heads back onto the pending queue so the next
    /// cycle re-attempts them. Without this we'd silently drop entries on
    /// every transient failure.
    async fn requeue(&self, mut heads: Vec<String>) {
        let mut inner = self.inner.lock().await;
        // Prepend so order is preserved relative to any heads recorded in
        // the meantime (which were appended after we drained).
        heads.append(&mut inner.pending);
        inner.pending = heads;
    }
}

/// Internal error type used by `publish_pending` to differentiate failure
/// modes for the metrics label without leaking through the public API.
#[derive(Debug)]
pub(crate) enum PublishError {
    Network(String),
    Server(u16, String),
}

fn load_signing_key_from_env() -> Result<SigningKey, TransparencyError> {
    if let Ok(hex_key) = env::var("GATEWAY_SIGNING_KEY") {
        return parse_hex_key(&hex_key);
    }
    if let Ok(path) = env::var("GATEWAY_SIGNING_KEY_FILE") {
        let pem = std::fs::read_to_string(PathBuf::from(&path))
            .map_err(|e| TransparencyError::InvalidSigningKey(format!("{path}: {e}")))?;
        return parse_pem_key(&pem);
    }
    Err(TransparencyError::MissingSigningKey)
}

fn parse_hex_key(hex_key: &str) -> Result<SigningKey, TransparencyError> {
    let bytes = hex::decode(hex_key.trim())
        .map_err(|e| TransparencyError::InvalidSigningKey(format!("hex decode: {e}")))?;
    if bytes.len() != 32 {
        return Err(TransparencyError::InvalidSigningKey(format!(
            "expected 32-byte ed25519 seed, got {}",
            bytes.len()
        )));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(SigningKey::from_bytes(&seed))
}

fn parse_pem_key(pem: &str) -> Result<SigningKey, TransparencyError> {
    SigningKey::from_pkcs8_pem(pem)
        .map_err(|e| TransparencyError::InvalidSigningKey(format!("pem decode: {e}")))
}

fn encode_public_key_pem(verifying_key: &VerifyingKey) -> String {
    use ed25519_dalek::pkcs8::EncodePublicKey;
    verifying_key
        .to_public_key_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
        .expect("ed25519 public key always encodes as PEM")
}

/// Compute the Merkle root over a list of chain-head hex strings.
///
/// Each input is decoded from hex (32 bytes expected for SHA-256). The
/// result is the 32-byte root. `rs_merkle` returns `None` for empty
/// inputs; we treat that as an internal error since the caller filters
/// out the empty case before reaching here.
fn compute_merkle_root(heads: &[String]) -> Result<[u8; 32], String> {
    if heads.is_empty() {
        return Err("empty heads".into());
    }
    let leaves: Vec<[u8; 32]> = heads
        .iter()
        .map(|h| {
            let bytes = hex::decode(h).map_err(|e| format!("hex decode: {e}"))?;
            if bytes.len() != 32 {
                return Err(format!("expected 32-byte hash, got {}", bytes.len()));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(arr)
        })
        .collect::<Result<_, String>>()?;
    let tree = MerkleTree::<MerkleSha256>::from_leaves(&leaves);
    tree.root().ok_or_else(|| "merkle root unavailable".into())
}

/// Hex-encode the Merkle root for inclusion in the Rekor body.
pub(crate) fn merkle_root_hex(root: &[u8; 32]) -> String {
    hex::encode(root)
}

/// Base64-encode the public key PEM. Rekor's hashedrekord schema accepts
/// either a base64-of-PEM blob or a base64-of-DER blob in `publicKey.content`;
/// the public Sigstore instance accepts either, and PEM round-trips
/// cleaner across keystores.
pub(crate) fn pem_to_base64(pem: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(pem.as_bytes())
}

/// Base64-encode raw signature bytes for the Rekor body.
pub(crate) fn signature_to_base64(sig: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_key() -> SigningKey {
        // Deterministic 32-byte seed so tests produce stable signatures.
        let seed = [7u8; 32];
        SigningKey::from_bytes(&seed)
    }

    #[test]
    fn parse_hex_key_accepts_64_chars() {
        let hex = hex::encode([1u8; 32]);
        let key = parse_hex_key(&hex).expect("parses");
        assert_eq!(key.to_bytes(), [1u8; 32]);
    }

    #[test]
    fn parse_hex_key_rejects_wrong_length() {
        assert!(parse_hex_key("deadbeef").is_err());
    }

    #[tokio::test]
    async fn state_initial_head_is_empty() {
        let state = TransparencyState::from_parts(
            fixture_key(),
            "primary".into(),
            "http://unused".into(),
            Duration::from_secs(900),
        );
        let head = state.current_head().await;
        assert_eq!(head.current_chain_head, "");
        assert_eq!(head.last_anchored_chain_head, "");
        assert_eq!(head.anchor_status, AnchorStatus::NotYetAnchored);
        assert_eq!(head.signing_key_id, "primary");
        assert_eq!(head.signature_alg, "ed25519");
    }

    #[tokio::test]
    async fn record_head_then_current_head_returns_it() {
        let state = TransparencyState::from_parts(
            fixture_key(),
            "primary".into(),
            "http://unused".into(),
            Duration::from_secs(900),
        );
        let h = hex::encode([42u8; 32]);
        state.record_head(h.clone()).await;
        let head = state.current_head().await;
        assert_eq!(head.current_chain_head, h);
    }

    #[test]
    fn merkle_root_is_deterministic() {
        let heads = vec![hex::encode([1u8; 32]), hex::encode([2u8; 32])];
        let root_a = compute_merkle_root(&heads).unwrap();
        let root_b = compute_merkle_root(&heads).unwrap();
        assert_eq!(root_a, root_b);
    }
}
