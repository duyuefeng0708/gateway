//! Per-request receipts: cache + HTTP route.
//!
//! Every successful audit write produces a receipt that the client
//! receives via the `x-gateway-receipt: <request_id>` response header.
//! The receipt itself is then retrievable at `GET /v1/receipts/{id}`,
//! which returns the full audit entry as JSON: chain hashes, model
//! routing, HMAC'd prompt/response digests, anchor status.
//!
//! Receipts are NOT attestation. They prove "this gateway logged this
//! digest under this signing key" — they do NOT prove PII removal,
//! upstream model authenticity, or response integrity in transit.
//! Codex F10. The README "Receipts and tamper-evidence" section
//! documents this honestly.

use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Mutex;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use gateway_common::types::AuditEntry;
use lru::LruCache;
use serde::Serialize;

use crate::state::AppState;

/// In-memory LRU cache of receipts keyed by `request_id`. Cache misses
/// fall through to a disk scan of the most recent two audit jsonl files;
/// older receipts are still verifiable but not served from this hot path.
///
/// Capacity is fixed at 10 000 entries (~5 MB) — tuned for the expected
/// request volume of a single proxy instance over a few hours. Operators
/// running higher volume should tune via `GATEWAY_RECEIPT_CACHE_CAPACITY`
/// (added when there's a real signal it matters; not yet env-driven).
pub struct ReceiptCache {
    inner: Mutex<LruCache<String, AuditEntry>>,
    audit_dir: PathBuf,
}

impl ReceiptCache {
    pub fn new(audit_dir: PathBuf, capacity: NonZeroUsize) -> Self {
        Self {
            inner: Mutex::new(LruCache::new(capacity)),
            audit_dir,
        }
    }

    pub fn with_default_capacity(audit_dir: PathBuf) -> Self {
        Self::new(audit_dir, NonZeroUsize::new(10_000).expect("non-zero literal"))
    }

    /// Insert a receipt (called after every successful audit write).
    pub fn put(&self, entry: AuditEntry) {
        if let Ok(mut cache) = self.inner.lock() {
            cache.put(entry.request_id.clone(), entry);
        }
    }

    /// Cache lookup. Returns None on miss; caller falls back to disk.
    pub fn get(&self, request_id: &str) -> Option<AuditEntry> {
        self.inner
            .lock()
            .ok()
            .and_then(|mut cache| cache.get(request_id).cloned())
    }

    /// Disk fallback: scan today's then yesterday's audit jsonl looking
    /// for the request_id. Returns None if not found.
    ///
    /// Older days are still on disk and will verify under
    /// `AuditWriter::verify_dir`, but we don't scan them here for the
    /// hot path; operators who need historical lookup can run
    /// `gateway-cli verify` directly against the file.
    pub fn lookup_on_disk(&self, request_id: &str) -> Option<AuditEntry> {
        let today = chrono::Utc::now();
        for offset in 0..=1 {
            let date = today - chrono::Duration::days(offset);
            let path = self
                .audit_dir
                .join(format!("{}.jsonl", date.format("%Y-%m-%d")));
            let Ok(content) = std::fs::read_to_string(&path) else {
                continue;
            };
            for line in content.lines().filter(|l| !l.trim().is_empty()) {
                if let Ok(entry) = serde_json::from_str::<AuditEntry>(line) {
                    if entry.request_id == request_id {
                        return Some(entry);
                    }
                }
            }
        }
        None
    }
}

/// Public receipt body. Currently a passthrough of `AuditEntry`; held
/// behind a wrapper struct so we can evolve the on-the-wire shape
/// (e.g. omit fields, add documentation links) without changing the
/// audit-log internal representation.
#[derive(Debug, Serialize)]
struct ReceiptBody<'a> {
    #[serde(flatten)]
    entry: &'a AuditEntry,
}

/// `GET /v1/receipts/{id}` — return the receipt for `id` if known.
///
/// Returns 200 with the receipt JSON on cache hit OR disk hit.
/// Returns 404 with a plain-text body when the id is not found.
pub async fn receipts_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    if let Some(entry) = state.receipts.get(&id) {
        return Json(ReceiptBody { entry: &entry }).into_response();
    }
    if let Some(entry) = state.receipts.lookup_on_disk(&id) {
        // Promote to cache so the next lookup is a hit.
        state.receipts.put(entry.clone());
        return Json(ReceiptBody { entry: &entry }).into_response();
    }
    (StatusCode::NOT_FOUND, "receipt not found").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_common::types::AuditEntry;
    use tempfile::TempDir;

    fn entry(request_id: &str) -> AuditEntry {
        AuditEntry {
            request_id: request_id.to_string(),
            session_id: "s1".to_string(),
            ..AuditEntry::default()
        }
    }

    #[test]
    fn put_and_get_round_trip() {
        let dir = TempDir::new().unwrap();
        let cache = ReceiptCache::with_default_capacity(dir.path().to_path_buf());
        cache.put(entry("a"));
        let got = cache.get("a").unwrap();
        assert_eq!(got.request_id, "a");
    }

    #[test]
    fn miss_returns_none() {
        let dir = TempDir::new().unwrap();
        let cache = ReceiptCache::with_default_capacity(dir.path().to_path_buf());
        assert!(cache.get("nonexistent").is_none());
    }

    #[test]
    fn lru_evicts_oldest_when_full() {
        let dir = TempDir::new().unwrap();
        let cap = NonZeroUsize::new(2).unwrap();
        let cache = ReceiptCache::new(dir.path().to_path_buf(), cap);
        cache.put(entry("a"));
        cache.put(entry("b"));
        cache.put(entry("c"));
        assert!(cache.get("a").is_none(), "oldest should have been evicted");
        assert!(cache.get("b").is_some());
        assert!(cache.get("c").is_some());
    }

    #[test]
    fn disk_fallback_finds_entry_in_todays_file() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let path = dir.path().join(format!("{today}.jsonl"));
        let entry = entry("on-disk");
        std::fs::write(&path, format!("{}\n", serde_json::to_string(&entry).unwrap()))
            .unwrap();

        let cache = ReceiptCache::with_default_capacity(dir.path().to_path_buf());
        assert!(cache.get("on-disk").is_none(), "not yet in cache");
        let found = cache.lookup_on_disk("on-disk").unwrap();
        assert_eq!(found.request_id, "on-disk");
    }

    #[test]
    fn disk_fallback_returns_none_for_unknown() {
        let dir = TempDir::new().unwrap();
        let cache = ReceiptCache::with_default_capacity(dir.path().to_path_buf());
        assert!(cache.lookup_on_disk("never-existed").is_none());
    }
}
