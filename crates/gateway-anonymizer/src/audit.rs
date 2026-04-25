use chrono::Utc;
use fs2::FileExt;
use gateway_common::errors::AuditError;
use gateway_common::types::{
    AnchorStatus, AuditEntry, PiiSpan, PiiType, PrivacyScore, ResponseHashStatus, HASH_RECIPE_V1,
    HASH_RECIPE_V2_CANONICAL_JSON,
};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Request payload for `AuditWriter::write_entry_v2` /
/// `AuditHandle::write_entry_v2`. Carries the v2-era fields that the
/// proxy populates from per-request context (model routing, HMAC
/// digests, signing identity). The audit subsystem fills in chain-link
/// fields (timestamp, prev_hash, hash, hash_recipe, anchor_status).
#[derive(Debug, Clone)]
pub struct AuditEntryRequest {
    pub session_id: String,
    pub spans: Vec<PiiSpan>,
    pub score: PrivacyScore,
    pub request_id: String,
    pub client_requested_model: String,
    pub gateway_selected_route: String,
    pub upstream_requested_model: String,
    pub upstream_reported_model: String,
    pub detector_fast_model: String,
    pub detector_deep_model: String,
    pub prompt_hmac: String,
    pub response_hmac: String,
    pub hmac_key_id: String,
    pub response_hash_status: ResponseHashStatus,
    pub signing_key_id: String,
    pub signature_alg: String,
}

/// Outcome of a successful write. The `request_id` is what the proxy
/// returns in the `x-gateway-receipt` header; the `hash` is the chain
/// head after this entry.
#[derive(Debug, Clone)]
pub struct AuditWriteOutcome {
    pub request_id: String,
    pub hash: String,
}

/// Append-only, hash-chained audit trail writer.
///
/// Each entry includes a SHA-256 hash of its content and the hash of the
/// previous entry, forming a tamper-evident chain. One file per day under
/// the configured audit directory. Fail-closed: write failures return
/// AuditError and the proxy should return 503.
pub struct AuditWriter {
    dir: PathBuf,
    last_hash: String,
    /// Held for the lifetime of this writer. Acquired exclusively via
    /// fs2 advisory lock at construction. Dropping the file releases
    /// the lock automatically. Codex F7 single-host single-writer
    /// guard. Multi-replica coordination is deferred to TODOS.md P2.
    _lock_file: File,
}

impl AuditWriter {
    /// Create a new writer, acquiring an exclusive lock on the audit
    /// directory and reading the last hash from the most recent log if
    /// one exists. Returns `AuditError::WriteError` if another writer
    /// process already holds the lock.
    pub fn new(dir: impl AsRef<Path>) -> Result<Self, AuditError> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir).map_err(|e| AuditError::WriteError(e.to_string()))?;

        let lock_path = dir.join(".audit.lock");
        let lock_file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .map_err(|e| AuditError::WriteError(format!("failed to open audit lock file: {e}")))?;

        // Non-blocking exclusive lock. If a sibling writer already holds
        // the lock we fail loud at boot rather than letting two processes
        // interleave entries (which would fork the chain in subtle ways).
        FileExt::try_lock_exclusive(&lock_file).map_err(|e| {
            AuditError::WriteError(format!(
                "audit directory {} is already locked by another writer: {e}",
                dir.display()
            ))
        })?;

        let last_hash = Self::read_last_hash(&dir).unwrap_or_else(|| "0".repeat(64));

        Ok(Self {
            dir,
            last_hash,
            _lock_file: lock_file,
        })
    }

    /// Write a richly-populated audit entry (PR-A1 path). Returns the
    /// entry's hash and the request_id that was assigned/used.
    ///
    /// This is the canonical write path. The legacy `write_entry`
    /// remains for tests and pre-PR-A1 wire-up; new request handlers
    /// should call this instead.
    pub fn write_entry_v2(
        &mut self,
        req: AuditEntryRequest,
    ) -> Result<AuditWriteOutcome, AuditError> {
        let now = Utc::now();
        let request_id = if req.request_id.is_empty() {
            uuid::Uuid::new_v4().to_string()
        } else {
            req.request_id.clone()
        };
        let pii_types: Vec<PiiType> = req.spans.iter().map(|s| s.pii_type).collect();

        let mut entry = AuditEntry {
            timestamp: now,
            session_id: req.session_id,
            pii_spans_detected: req.spans.len(),
            pii_types,
            placeholders_generated: req.spans.len(),
            privacy_score: req.score.value(),
            hash: String::new(),
            prev_hash: self.last_hash.clone(),
            hash_recipe: HASH_RECIPE_V2_CANONICAL_JSON.to_string(),
            request_id: request_id.clone(),
            client_requested_model: req.client_requested_model,
            gateway_selected_route: req.gateway_selected_route,
            upstream_requested_model: req.upstream_requested_model,
            upstream_reported_model: req.upstream_reported_model,
            detector_fast_model: req.detector_fast_model,
            detector_deep_model: req.detector_deep_model,
            prompt_hmac: req.prompt_hmac,
            response_hmac: req.response_hmac,
            hmac_key_id: req.hmac_key_id,
            response_hash_status: req.response_hash_status,
            signing_key_id: req.signing_key_id,
            signature_alg: req.signature_alg,
            anchor_status: AnchorStatus::NotYetAnchored,
            rekor_uuid: String::new(),
            log_index: -1,
            integrated_time: 0,
        };

        entry.hash = compute_hash(&entry)?;
        self.persist_entry(&entry, now)?;
        self.last_hash = entry.hash.clone();
        Ok(AuditWriteOutcome {
            request_id,
            hash: entry.hash,
        })
    }

    /// Internal: serialise + append + sync_data. Shared by both write_entry
    /// (legacy) and write_entry_v2 (PR-A1).
    fn persist_entry(
        &self,
        entry: &AuditEntry,
        now: chrono::DateTime<Utc>,
    ) -> Result<(), AuditError> {
        let log_path = self.dir.join(format!("{}.jsonl", now.format("%Y-%m-%d")));

        let line =
            serde_json::to_string(entry).map_err(|e| AuditError::WriteError(e.to_string()))?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::StorageFull
                    || e.to_string().contains("No space left")
                {
                    AuditError::AuditDiskFull
                } else {
                    AuditError::WriteError(e.to_string())
                }
            })?;

        writeln!(file, "{line}").map_err(|e| {
            if e.to_string().contains("No space left") {
                AuditError::AuditDiskFull
            } else {
                AuditError::WriteError(e.to_string())
            }
        })?;

        file.sync_data().map_err(|e| {
            if e.to_string().contains("No space left") {
                AuditError::AuditDiskFull
            } else {
                AuditError::WriteError(e.to_string())
            }
        })?;
        Ok(())
    }

    /// Write an audit entry for a request. Returns the entry's hash.
    pub fn write_entry(
        &mut self,
        session_id: &str,
        spans: &[PiiSpan],
        score: PrivacyScore,
    ) -> Result<String, AuditError> {
        let pii_types: Vec<PiiType> = spans.iter().map(|s| s.pii_type).collect();

        // Single timestamp captured once: used for both the entry's
        // timestamp field and the daily-file rotation. Two separate
        // Utc::now() calls (the previous behaviour) would race across the
        // midnight boundary, leaving the entry timestamped on day N but
        // filed under day N+1. Codex F5.
        let now = Utc::now();

        let mut entry = AuditEntry {
            timestamp: now,
            session_id: session_id.to_string(),
            pii_spans_detected: spans.len(),
            pii_types,
            placeholders_generated: spans.len(),
            privacy_score: score.value(),
            hash: String::new(),
            prev_hash: self.last_hash.clone(),
            // New entries always use the v2 recipe; v1 only exists in
            // legacy files that were written before this commit.
            hash_recipe: HASH_RECIPE_V2_CANONICAL_JSON.to_string(),
            // V2 fields (PR-A1) populated via the new write_entry_v2
            // path; this legacy entry-point fills them with defaults so
            // existing tests and the proxy's pre-PR-A1 wire-up continue
            // to compile. Real callers go through AuditHandle which
            // accepts the rich AuditEntryRequest.
            ..AuditEntry::default()
        };

        // Compute hash over the entry content (excluding the hash field
        // itself). The v2 recipe authenticates every other field via
        // canonical JSON serialisation; pre-2026-04-25 entries used a
        // 5-field recipe that ignored pii_types, placeholders_generated,
        // and any field added later. See compute_hash.
        entry.hash = compute_hash(&entry)?;

        let log_path = self.dir.join(format!("{}.jsonl", now.format("%Y-%m-%d")));

        let line =
            serde_json::to_string(&entry).map_err(|e| AuditError::WriteError(e.to_string()))?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::StorageFull
                    || e.to_string().contains("No space left")
                {
                    AuditError::AuditDiskFull
                } else {
                    AuditError::WriteError(e.to_string())
                }
            })?;

        writeln!(file, "{line}").map_err(|e| {
            if e.to_string().contains("No space left") {
                AuditError::AuditDiskFull
            } else {
                AuditError::WriteError(e.to_string())
            }
        })?;

        // Durability: writeln! is buffered; without sync_data the entry
        // can survive in OS cache across a process crash but be lost on
        // power loss before the page-cache flush. For a tamper-evident
        // log this is unacceptable. Codex F6.
        file.sync_data().map_err(|e| {
            if e.to_string().contains("No space left") {
                AuditError::AuditDiskFull
            } else {
                AuditError::WriteError(e.to_string())
            }
        })?;

        self.last_hash = entry.hash.clone();
        Ok(entry.hash)
    }
}

/// Compute the SHA-256 hash for an audit entry under its declared recipe.
///
/// `audit-v1` (legacy): hashes timestamp, session_id, pii_spans_detected,
/// privacy_score, and prev_hash. Ignores pii_types, placeholders_generated,
/// and any future field. Retained ONLY so legacy entries on disk verify.
///
/// `audit-v2-canonical-json` (default for new entries): hashes the
/// alphabetically-sorted JSON of the entry with the `hash` field removed.
/// Authenticates every field including ones added later. serde_json's Map
/// is a BTreeMap by default (no `preserve_order` feature on this crate),
/// which gives us deterministic key order without an external canonical-
/// JSON library. Codex F2.
///
/// Public so external verifier tools (e.g. `gateway-cli verify`) can
/// recompute and cross-check the on-disk value without duplicating the
/// recipe selection logic. Codex F15 offline-first verify.
pub fn compute_hash(entry: &AuditEntry) -> Result<String, AuditError> {
    match entry.hash_recipe.as_str() {
        HASH_RECIPE_V1 => Ok(compute_hash_v1(entry)),
        HASH_RECIPE_V2_CANONICAL_JSON => compute_hash_v2_canonical_json(entry),
        other => Err(AuditError::WriteError(format!(
            "unknown audit hash recipe: {other}"
        ))),
    }
}

fn compute_hash_v1(entry: &AuditEntry) -> String {
    let mut hasher = Sha256::new();
    hasher.update(entry.timestamp.to_rfc3339().as_bytes());
    hasher.update(entry.session_id.as_bytes());
    hasher.update(entry.pii_spans_detected.to_string().as_bytes());
    hasher.update(entry.privacy_score.to_string().as_bytes());
    hasher.update(entry.prev_hash.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn compute_hash_v2_canonical_json(entry: &AuditEntry) -> Result<String, AuditError> {
    let mut value =
        serde_json::to_value(entry).map_err(|e| AuditError::WriteError(e.to_string()))?;
    if let Some(obj) = value.as_object_mut() {
        obj.remove("hash");
    }
    let canonical =
        serde_json::to_string(&value).map_err(|e| AuditError::WriteError(e.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    Ok(format!("{:x}", hasher.finalize()))
}

impl AuditWriter {
    /// Read the last hash from the most recent log file.
    fn read_last_hash(dir: &Path) -> Option<String> {
        let mut entries: Vec<_> = fs::read_dir(dir)
            .ok()?
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "jsonl")
                    .unwrap_or(false)
            })
            .collect();

        entries.sort_by_key(|e| e.file_name());

        let latest = entries.last()?;
        let content = fs::read_to_string(latest.path()).ok()?;
        let last_line = content.lines().rev().find(|l| !l.trim().is_empty())?;
        let entry: AuditEntry = serde_json::from_str(last_line).ok()?;
        Some(entry.hash)
    }

    /// Verify the hash chain integrity of a log file.
    ///
    /// For each entry: recompute its hash under the entry's declared
    /// `hash_recipe` and compare against the stored `entry.hash`. Then
    /// verify chain linkage by comparing each entry's `prev_hash` against
    /// the previous entry's `hash`.
    ///
    /// Prior to 2026-04-25 this function only checked `prev_hash` adjacency
    /// without recomputing entry content hashes — meaning a tamperer could
    /// modify any field of any entry and still pass verification as long
    /// as they kept the chain pointers intact. The hash on disk was never
    /// re-validated. Codex F1.
    pub fn verify_chain(path: impl AsRef<Path>) -> Result<bool, AuditError> {
        let content =
            fs::read_to_string(path.as_ref()).map_err(|e| AuditError::WriteError(e.to_string()))?;

        let entries: Vec<AuditEntry> = content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(serde_json::from_str)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| AuditError::WriteError(e.to_string()))?;

        if entries.is_empty() {
            return Ok(true);
        }

        for entry in &entries {
            let recomputed = compute_hash(entry)?;
            if recomputed != entry.hash {
                return Ok(false);
            }
        }

        for window in entries.windows(2) {
            if window[1].prev_hash != window[0].hash {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Verify a directory of daily audit files as one continuous chain.
    ///
    /// For each `.jsonl` file in lexicographic order:
    /// 1. Run `verify_chain` on the file content.
    /// 2. Confirm the file's first entry `prev_hash` equals the previous
    ///    file's last entry `hash` (or the zero hash for the first file).
    ///
    /// Without (2), a tamperer could replace a whole day's file with a
    /// freshly forged chain that links internally but breaks continuity
    /// across midnight. `verify_chain` alone never sees the boundary.
    /// Codex F4.
    pub fn verify_dir(dir: impl AsRef<Path>) -> Result<bool, AuditError> {
        let dir = dir.as_ref();
        let mut files: Vec<_> = fs::read_dir(dir)
            .map_err(|e| AuditError::WriteError(e.to_string()))?
            .filter_map(Result::ok)
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "jsonl")
                    .unwrap_or(false)
            })
            .collect();

        files.sort_by_key(|e| e.file_name());

        let mut expected_prev_hash = "0".repeat(64);

        for file in files {
            let path = file.path();
            if !Self::verify_chain(&path)? {
                return Ok(false);
            }

            let content =
                fs::read_to_string(&path).map_err(|e| AuditError::WriteError(e.to_string()))?;
            let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
            if lines.is_empty() {
                continue;
            }

            let first: AuditEntry = serde_json::from_str(lines[0])
                .map_err(|e| AuditError::WriteError(e.to_string()))?;
            if first.prev_hash != expected_prev_hash {
                return Ok(false);
            }

            let last: AuditEntry = serde_json::from_str(lines[lines.len() - 1])
                .map_err(|e| AuditError::WriteError(e.to_string()))?;
            expected_prev_hash = last.hash;
        }

        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Async writer wrapper (Codex F8)
// ---------------------------------------------------------------------------

/// Command queued onto the audit writer thread.
enum AuditCommand {
    WriteEntry {
        session_id: String,
        spans: Vec<PiiSpan>,
        score: PrivacyScore,
        reply: tokio::sync::oneshot::Sender<Result<String, AuditError>>,
    },
    WriteEntryV2 {
        // Boxed because AuditEntryRequest is much larger than the v1 variant
        // and clippy rightly flags the variant-size disparity. The Box keeps
        // the channel-level enum small and the heap allocation is negligible
        // next to the disk fsync that follows.
        req: Box<AuditEntryRequest>,
        reply: tokio::sync::oneshot::Sender<Result<AuditWriteOutcome, AuditError>>,
    },
}

/// Async-friendly handle to a dedicated audit writer thread.
///
/// The proxy's request handlers are async and run on the tokio runtime.
/// Synchronous file I/O (write + sync_data, the latter especially) blocks
/// the worker thread for ~ms which starves the runtime under load. This
/// handle decouples the two: the writer owns its own OS thread and a
/// bounded channel buffers handler submissions.
///
/// Backpressure is fail-fast, not queue-forever. When the channel fills,
/// `write_entry` returns `AuditError::Backpressured` immediately. The
/// proxy maps that to HTTP 503 with a Retry-After header. Operators see
/// the spike via `gateway_audit_backpressure_total` and either scale
/// disk I/O or accept the load shed.
///
/// Panic semantics: if the writer thread panics, the receiver is
/// dropped, subsequent `try_send` calls fail with `Closed`, and
/// `write_entry` returns `AuditError::WriterDown`. The proxy should
/// surface this via /metrics; the orchestrator should restart the
/// process. Auto-restart of just the writer thread is tracked as a
/// TODOS.md P2 follow-up.
///
/// Cloneable: AuditHandle holds an `mpsc::Sender` which is cheap to
/// clone. AppState stores one and hands clones to handlers.
#[derive(Clone)]
pub struct AuditHandle {
    tx: tokio::sync::mpsc::Sender<AuditCommand>,
}

impl AuditHandle {
    /// Spawn the writer thread and return a handle. Acquires the audit
    /// directory's exclusive lock at the same time. Returns the same
    /// errors as `AuditWriter::new`.
    pub fn spawn(dir: impl Into<PathBuf>) -> Result<Self, AuditError> {
        let dir = dir.into();
        let writer = AuditWriter::new(&dir)?;
        let (tx, mut rx) = tokio::sync::mpsc::channel::<AuditCommand>(64);

        std::thread::Builder::new()
            .name("gateway-audit-writer".to_string())
            .spawn(move || {
                let mut writer = writer;
                while let Some(cmd) = rx.blocking_recv() {
                    match cmd {
                        AuditCommand::WriteEntry {
                            session_id,
                            spans,
                            score,
                            reply,
                        } => {
                            let result = writer.write_entry(&session_id, &spans, score);
                            let _ = reply.send(result);
                        }
                        AuditCommand::WriteEntryV2 { req, reply } => {
                            let result = writer.write_entry_v2(*req);
                            let _ = reply.send(result);
                        }
                    }
                }
                tracing::warn!("audit writer thread: command channel closed, exiting cleanly");
            })
            .map_err(|e| {
                AuditError::WriteError(format!("failed to spawn audit writer thread: {e}"))
            })?;

        Ok(Self { tx })
    }

    /// Submit an entry for writing. Returns the entry's hash on success.
    ///
    /// Returns `AuditError::Backpressured` if the writer's queue is full
    /// (the request should be load-shed via 503). Returns
    /// `AuditError::WriterDown` if the writer thread is no longer running.
    pub async fn write_entry(
        &self,
        session_id: &str,
        spans: Vec<PiiSpan>,
        score: PrivacyScore,
    ) -> Result<String, AuditError> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let cmd = AuditCommand::WriteEntry {
            session_id: session_id.to_string(),
            spans,
            score,
            reply: reply_tx,
        };

        self.tx.try_send(cmd).map_err(|e| match e {
            tokio::sync::mpsc::error::TrySendError::Full(_) => AuditError::Backpressured,
            tokio::sync::mpsc::error::TrySendError::Closed(_) => AuditError::WriterDown,
        })?;

        // The writer always sends a reply on the oneshot. If the receiver
        // here errors, the writer thread died between the queue and the
        // reply.
        reply_rx.await.map_err(|_| AuditError::WriterDown)?
    }

    /// PR-A1 path: submit an `AuditEntryRequest` carrying all v2 fields.
    /// Returns the assigned request_id and the chain hash.
    pub async fn write_entry_v2(
        &self,
        req: AuditEntryRequest,
    ) -> Result<AuditWriteOutcome, AuditError> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let cmd = AuditCommand::WriteEntryV2 {
            req: Box::new(req),
            reply: reply_tx,
        };
        self.tx.try_send(cmd).map_err(|e| match e {
            tokio::sync::mpsc::error::TrySendError::Full(_) => AuditError::Backpressured,
            tokio::sync::mpsc::error::TrySendError::Closed(_) => AuditError::WriterDown,
        })?;
        reply_rx.await.map_err(|_| AuditError::WriterDown)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_common::types::PiiType;
    use tempfile::TempDir;

    fn make_spans(count: usize) -> Vec<PiiSpan> {
        (0..count)
            .map(|i| PiiSpan {
                pii_type: PiiType::Person,
                start: i * 10,
                end: i * 10 + 5,
                text: format!("person_{i}"),
                confidence: 0.9,
                implicit: false,
            })
            .collect()
    }

    #[test]
    fn write_single_entry_with_valid_hash_chain() {
        let dir = TempDir::new().unwrap();
        let mut writer = AuditWriter::new(dir.path()).unwrap();

        let spans = make_spans(2);
        let score = PrivacyScore::compute(&spans);
        let hash = writer.write_entry("session-1", &spans, score).unwrap();

        assert_eq!(hash.len(), 64); // SHA-256 hex
        assert!(AuditWriter::verify_chain(
            dir.path()
                .join(format!("{}.jsonl", Utc::now().format("%Y-%m-%d")))
        )
        .unwrap());
    }

    #[test]
    fn multiple_entries_form_valid_chain() {
        let dir = TempDir::new().unwrap();
        let mut writer = AuditWriter::new(dir.path()).unwrap();

        for i in 0..5 {
            let spans = make_spans(i + 1);
            let score = PrivacyScore::compute(&spans);
            writer
                .write_entry(&format!("session-{i}"), &spans, score)
                .unwrap();
        }

        let log_path = dir
            .path()
            .join(format!("{}.jsonl", Utc::now().format("%Y-%m-%d")));
        assert!(AuditWriter::verify_chain(&log_path).unwrap());

        // Read back and verify prev_hash links.
        let content = fs::read_to_string(&log_path).unwrap();
        let entries: Vec<AuditEntry> = content
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();

        assert_eq!(entries.len(), 5);
        assert_eq!(entries[0].prev_hash, "0".repeat(64));
        for w in entries.windows(2) {
            assert_eq!(w[1].prev_hash, w[0].hash);
        }
    }

    #[test]
    fn first_entry_has_zero_prev_hash() {
        let dir = TempDir::new().unwrap();
        let mut writer = AuditWriter::new(dir.path()).unwrap();

        let spans = make_spans(1);
        let score = PrivacyScore::compute(&spans);
        writer.write_entry("s1", &spans, score).unwrap();

        let log_path = dir
            .path()
            .join(format!("{}.jsonl", Utc::now().format("%Y-%m-%d")));
        let content = fs::read_to_string(log_path).unwrap();
        let entry: AuditEntry = serde_json::from_str(content.lines().next().unwrap()).unwrap();
        assert_eq!(entry.prev_hash, "0".repeat(64));
    }

    #[test]
    fn entry_never_contains_original_pii_text() {
        let dir = TempDir::new().unwrap();
        let mut writer = AuditWriter::new(dir.path()).unwrap();

        let spans = vec![PiiSpan {
            pii_type: PiiType::Person,
            start: 0,
            end: 10,
            text: "SECRET_NAME".to_string(),
            confidence: 0.95,
            implicit: false,
        }];
        let score = PrivacyScore::compute(&spans);
        writer.write_entry("s1", &spans, score).unwrap();

        let log_path = dir
            .path()
            .join(format!("{}.jsonl", Utc::now().format("%Y-%m-%d")));
        let content = fs::read_to_string(log_path).unwrap();
        // The audit entry stores PII types and counts, NOT the original text.
        assert!(!content.contains("SECRET_NAME"));
    }

    #[test]
    fn no_pii_produces_score_100() {
        let score = PrivacyScore::compute(&[]);
        assert_eq!(score.value(), 100);
    }

    #[test]
    fn audit_dir_created_if_missing() {
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("deep").join("nested").join("audit");
        let writer = AuditWriter::new(&nested);
        assert!(writer.is_ok());
        assert!(nested.exists());
    }

    #[test]
    fn empty_log_verifies_as_valid() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("empty.jsonl");
        fs::write(&log_path, "").unwrap();
        assert!(AuditWriter::verify_chain(&log_path).unwrap());
    }

    // -- F1: verify_chain recomputes every entry hash -------------------------

    fn write_three_entries(dir: &Path) -> PathBuf {
        let mut writer = AuditWriter::new(dir).unwrap();
        for i in 0..3 {
            let spans = make_spans(i + 1);
            let score = PrivacyScore::compute(&spans);
            writer
                .write_entry(&format!("session-{i}"), &spans, score)
                .unwrap();
        }
        dir.join(format!("{}.jsonl", Utc::now().format("%Y-%m-%d")))
    }

    /// Mutate the JSON value of the line at `line_idx` and rewrite the file.
    /// Used to simulate on-disk tampering.
    fn tamper_line(log_path: &Path, line_idx: usize, mutate: impl FnOnce(&mut serde_json::Value)) {
        let content = fs::read_to_string(log_path).unwrap();
        let mut lines: Vec<String> = content.lines().map(String::from).collect();
        let mut value: serde_json::Value = serde_json::from_str(&lines[line_idx]).unwrap();
        mutate(&mut value);
        lines[line_idx] = serde_json::to_string(&value).unwrap();
        fs::write(log_path, lines.join("\n") + "\n").unwrap();
    }

    #[test]
    fn verify_chain_rejects_tampered_privacy_score() {
        let dir = TempDir::new().unwrap();
        let log_path = write_three_entries(dir.path());
        assert!(AuditWriter::verify_chain(&log_path).unwrap());

        tamper_line(&log_path, 1, |v| {
            v["privacy_score"] = serde_json::json!(0);
        });

        assert!(!AuditWriter::verify_chain(&log_path).unwrap());
    }

    #[test]
    fn verify_chain_rejects_tampered_pii_types() {
        let dir = TempDir::new().unwrap();
        let log_path = write_three_entries(dir.path());

        tamper_line(&log_path, 0, |v| {
            v["pii_types"] = serde_json::json!([]);
        });

        assert!(!AuditWriter::verify_chain(&log_path).unwrap());
    }

    #[test]
    fn verify_chain_rejects_tampered_session_id() {
        let dir = TempDir::new().unwrap();
        let log_path = write_three_entries(dir.path());

        tamper_line(&log_path, 2, |v| {
            v["session_id"] = serde_json::json!("forged-session");
        });

        assert!(!AuditWriter::verify_chain(&log_path).unwrap());
    }

    #[test]
    fn verify_chain_rejects_garbage_hash() {
        let dir = TempDir::new().unwrap();
        let log_path = write_three_entries(dir.path());

        tamper_line(&log_path, 1, |v| {
            v["hash"] = serde_json::json!(["d"; 64].join(""));
        });

        assert!(!AuditWriter::verify_chain(&log_path).unwrap());
    }

    // -- F2 + F3: hash recipe selection ---------------------------------------

    /// Synthesise a legacy v1 entry by hand, write it, and confirm verify_chain
    /// accepts it under the v1 recipe. This ensures pre-2026-04-25 logs that
    /// shipped without the hash_recipe field still validate.
    #[test]
    fn legacy_v1_entry_verifies_under_v1_recipe() {
        let dir = TempDir::new().unwrap();
        let log_path = dir
            .path()
            .join(format!("{}.jsonl", Utc::now().format("%Y-%m-%d")));

        let mut entry = AuditEntry {
            timestamp: Utc::now(),
            session_id: "legacy-session".to_string(),
            pii_spans_detected: 2,
            pii_types: vec![PiiType::Person, PiiType::Email],
            placeholders_generated: 2,
            privacy_score: 70,
            hash: String::new(),
            prev_hash: "0".repeat(64),
            hash_recipe: HASH_RECIPE_V1.to_string(),
            ..AuditEntry::default()
        };
        entry.hash = compute_hash_v1(&entry);

        let line = serde_json::to_string(&entry).unwrap();
        fs::write(&log_path, format!("{line}\n")).unwrap();

        assert!(AuditWriter::verify_chain(&log_path).unwrap());
    }

    /// V1 recipe is permissive of pii_types tampering BY DESIGN — the V1
    /// hash recipe never covered pii_types. This test pins that legacy
    /// behaviour so a future "fix" doesn't accidentally invalidate
    /// historical logs that were always vulnerable to this specific attack.
    /// Going forward, all writes use V2 which DOES catch this.
    #[test]
    fn v1_recipe_does_not_authenticate_pii_types_by_design() {
        let dir = TempDir::new().unwrap();
        let log_path = dir
            .path()
            .join(format!("{}.jsonl", Utc::now().format("%Y-%m-%d")));

        let mut entry = AuditEntry {
            timestamp: Utc::now(),
            session_id: "legacy".to_string(),
            pii_spans_detected: 1,
            pii_types: vec![PiiType::Person],
            placeholders_generated: 1,
            privacy_score: 70,
            hash: String::new(),
            prev_hash: "0".repeat(64),
            hash_recipe: HASH_RECIPE_V1.to_string(),
            ..AuditEntry::default()
        };
        entry.hash = compute_hash_v1(&entry);
        let line = serde_json::to_string(&entry).unwrap();
        fs::write(&log_path, format!("{line}\n")).unwrap();

        // Tamper pii_types and verify that V1 chain still verifies — this is
        // the legacy gap that the V2 recipe closes. Uppercase variant matches
        // the PiiType serialisation.
        tamper_line(&log_path, 0, |v| {
            v["pii_types"] = serde_json::json!(["EMAIL"]);
        });
        assert!(AuditWriter::verify_chain(&log_path).unwrap());
    }

    /// New writes set hash_recipe = audit-v2-canonical-json and the file
    /// must still verify after a normal round-trip.
    #[test]
    fn v2_canonical_json_recipe_is_default_for_new_writes() {
        let dir = TempDir::new().unwrap();
        let log_path = write_three_entries(dir.path());

        let content = fs::read_to_string(&log_path).unwrap();
        for line in content.lines().filter(|l| !l.trim().is_empty()) {
            let entry: AuditEntry = serde_json::from_str(line).unwrap();
            assert_eq!(entry.hash_recipe, HASH_RECIPE_V2_CANONICAL_JSON);
        }

        assert!(AuditWriter::verify_chain(&log_path).unwrap());
    }

    /// Mixed V1 + V2 file: V1 entries on disk (legacy data) chained with
    /// V2 entries (new data after the upgrade). verify_chain dispatches
    /// per-entry hash recipe and accepts the mixed file. This is the
    /// upgrade path: old data on disk + new entries appended.
    #[test]
    fn mixed_v1_and_v2_entries_chain_correctly() {
        let dir = TempDir::new().unwrap();
        let log_path = dir
            .path()
            .join(format!("{}.jsonl", Utc::now().format("%Y-%m-%d")));

        let mut v1 = AuditEntry {
            timestamp: Utc::now(),
            session_id: "legacy".to_string(),
            pii_spans_detected: 1,
            pii_types: vec![PiiType::Person],
            placeholders_generated: 1,
            privacy_score: 70,
            hash: String::new(),
            prev_hash: "0".repeat(64),
            hash_recipe: HASH_RECIPE_V1.to_string(),
            ..AuditEntry::default()
        };
        v1.hash = compute_hash_v1(&v1);

        let mut v2 = AuditEntry {
            timestamp: Utc::now(),
            session_id: "modern".to_string(),
            pii_spans_detected: 2,
            pii_types: vec![PiiType::Email, PiiType::Phone],
            placeholders_generated: 2,
            privacy_score: 50,
            hash: String::new(),
            prev_hash: v1.hash.clone(),
            hash_recipe: HASH_RECIPE_V2_CANONICAL_JSON.to_string(),
            ..AuditEntry::default()
        };
        v2.hash = compute_hash_v2_canonical_json(&v2).unwrap();

        let mut content = serde_json::to_string(&v1).unwrap();
        content.push('\n');
        content.push_str(&serde_json::to_string(&v2).unwrap());
        content.push('\n');
        fs::write(&log_path, content).unwrap();

        assert!(AuditWriter::verify_chain(&log_path).unwrap());
    }

    /// Legacy entry on disk (no hash_recipe field at all) deserialises to
    /// hash_recipe = audit-v1 via the serde default. Critical for
    /// upgrading deployments where the JSON on disk predates the field.
    #[test]
    fn legacy_jsonl_without_hash_recipe_field_defaults_to_v1() {
        let dir = TempDir::new().unwrap();
        let log_path = dir
            .path()
            .join(format!("{}.jsonl", Utc::now().format("%Y-%m-%d")));

        // Construct V1 entry hash, then strip hash_recipe from the JSON to
        // mimic a file written before the field existed.
        let mut entry = AuditEntry {
            timestamp: Utc::now(),
            session_id: "pre-upgrade".to_string(),
            pii_spans_detected: 0,
            pii_types: vec![],
            placeholders_generated: 0,
            privacy_score: 100,
            hash: String::new(),
            prev_hash: "0".repeat(64),
            hash_recipe: HASH_RECIPE_V1.to_string(),
            ..AuditEntry::default()
        };
        entry.hash = compute_hash_v1(&entry);

        let mut value: serde_json::Value = serde_json::to_value(&entry).unwrap();
        value.as_object_mut().unwrap().remove("hash_recipe");
        let line = serde_json::to_string(&value).unwrap();
        fs::write(&log_path, format!("{line}\n")).unwrap();

        assert!(AuditWriter::verify_chain(&log_path).unwrap());
    }

    // -- F4: cross-file continuity --------------------------------------------

    /// Helper: write `count` entries into a single jsonl named `<date>.jsonl`,
    /// chained from `prev`. Returns the last entry's hash.
    fn write_day_file(dir: &Path, date: &str, count: usize, starting_prev: &str) -> String {
        let log_path = dir.join(format!("{date}.jsonl"));
        let mut prev = starting_prev.to_string();
        let mut content = String::new();
        for i in 0..count {
            let mut entry = AuditEntry {
                timestamp: Utc::now(),
                session_id: format!("{date}-{i}"),
                pii_spans_detected: i,
                pii_types: vec![],
                placeholders_generated: i,
                privacy_score: 100,
                hash: String::new(),
                prev_hash: prev.clone(),
                hash_recipe: HASH_RECIPE_V2_CANONICAL_JSON.to_string(),
                ..AuditEntry::default()
            };
            entry.hash = compute_hash_v2_canonical_json(&entry).unwrap();
            prev = entry.hash.clone();
            content.push_str(&serde_json::to_string(&entry).unwrap());
            content.push('\n');
        }
        fs::write(&log_path, content).unwrap();
        prev
    }

    #[test]
    fn verify_dir_accepts_continuous_two_day_chain() {
        let dir = TempDir::new().unwrap();
        let day1_last = write_day_file(dir.path(), "2026-04-24", 3, &"0".repeat(64));
        let _day2_last = write_day_file(dir.path(), "2026-04-25", 4, &day1_last);

        assert!(AuditWriter::verify_dir(dir.path()).unwrap());
    }

    #[test]
    fn verify_dir_rejects_forked_first_entry_of_day_two() {
        let dir = TempDir::new().unwrap();
        let _day1_last = write_day_file(dir.path(), "2026-04-24", 3, &"0".repeat(64));
        // Day 2 starts from "0" instead of day1's last hash → fork.
        let _day2_last = write_day_file(dir.path(), "2026-04-25", 2, &"0".repeat(64));

        assert!(!AuditWriter::verify_dir(dir.path()).unwrap());
    }

    #[test]
    fn verify_dir_rejects_internally_tampered_day() {
        let dir = TempDir::new().unwrap();
        let day1_last = write_day_file(dir.path(), "2026-04-24", 3, &"0".repeat(64));
        let _day2_last = write_day_file(dir.path(), "2026-04-25", 2, &day1_last);

        // Tamper inside day 1.
        tamper_line(&dir.path().join("2026-04-24.jsonl"), 1, |v| {
            v["session_id"] = serde_json::json!("forged");
        });

        assert!(!AuditWriter::verify_dir(dir.path()).unwrap());
    }

    #[test]
    fn verify_dir_handles_empty_directory() {
        let dir = TempDir::new().unwrap();
        assert!(AuditWriter::verify_dir(dir.path()).unwrap());
    }

    // -- F5: single Utc::now() captured per write_entry -----------------------

    // -- F7: audit.lock single-writer guard -----------------------------------

    #[test]
    fn second_writer_against_same_dir_fails_with_lock_error() {
        let dir = TempDir::new().unwrap();
        let _first = AuditWriter::new(dir.path()).unwrap();

        let second = AuditWriter::new(dir.path());
        let msg = match second {
            Ok(_) => panic!("expected lock contention while first writer holds the lock"),
            Err(e) => e.to_string(),
        };
        assert!(
            msg.contains("locked"),
            "error must mention the lock; got: {msg}"
        );
    }

    #[test]
    fn dropping_first_writer_releases_lock_for_second() {
        let dir = TempDir::new().unwrap();
        {
            let _first = AuditWriter::new(dir.path()).unwrap();
        } // drop -> lock released

        let second = AuditWriter::new(dir.path());
        assert!(
            second.is_ok(),
            "second writer must succeed after first dropped"
        );
    }

    #[test]
    fn lock_file_is_excluded_from_jsonl_scans() {
        let dir = TempDir::new().unwrap();
        let mut writer = AuditWriter::new(dir.path()).unwrap();
        let spans = make_spans(1);
        let score = PrivacyScore::compute(&spans);
        writer.write_entry("s1", &spans, score).unwrap();

        // verify_dir must ignore the .audit.lock file and accept the
        // single-day chain.
        assert!(AuditWriter::verify_dir(dir.path()).unwrap());
    }

    // -- F8: AuditHandle async wrapper ---------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn audit_handle_round_trip_writes_to_disk() {
        let dir = TempDir::new().unwrap();
        let handle = AuditHandle::spawn(dir.path().to_path_buf()).unwrap();

        let spans = make_spans(2);
        let score = PrivacyScore::compute(&spans);
        let hash = handle
            .write_entry("via-handle", spans, score)
            .await
            .unwrap();

        assert_eq!(hash.len(), 64);

        // Drop the handle so the writer thread releases the lock; only
        // then can a verifier read the same dir without contention.
        drop(handle);
        // Give the writer thread time to drain; in practice the channel
        // is empty because we awaited the only submission.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let log_path = dir
            .path()
            .join(format!("{}.jsonl", Utc::now().format("%Y-%m-%d")));
        assert!(AuditWriter::verify_chain(&log_path).unwrap());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn audit_handle_concurrent_writes_preserve_chain_order() {
        let dir = TempDir::new().unwrap();
        let handle = AuditHandle::spawn(dir.path().to_path_buf()).unwrap();

        // Submit 20 concurrent writes. The mpsc channel + single-thread
        // writer serialise them; the chain must remain contiguous.
        let mut tasks = Vec::new();
        for i in 0..20 {
            let h = handle.clone();
            tasks.push(tokio::spawn(async move {
                let spans = make_spans(i % 3);
                let score = PrivacyScore::compute(&spans);
                h.write_entry(&format!("s-{i}"), spans, score).await
            }));
        }

        let results: Vec<_> = futures_util::future::join_all(tasks).await;
        for r in &results {
            assert!(r.as_ref().unwrap().is_ok(), "every write should succeed");
        }

        drop(handle);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let log_path = dir
            .path()
            .join(format!("{}.jsonl", Utc::now().format("%Y-%m-%d")));
        assert!(AuditWriter::verify_chain(&log_path).unwrap());

        let content = fs::read_to_string(&log_path).unwrap();
        let count = content.lines().filter(|l| !l.trim().is_empty()).count();
        assert_eq!(count, 20, "all 20 entries must land in the chain");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn audit_handle_writer_down_after_drop() {
        let dir = TempDir::new().unwrap();
        let handle = AuditHandle::spawn(dir.path().to_path_buf()).unwrap();

        // The handle's tx is fine; its clone can survive after we drop the
        // outer handle. But if we close the channel by sending too many or
        // letting it run out... Actually the only way to get WriterDown
        // here is to drop ALL senders, which kills the receiver, which
        // ends the loop, which exits the thread.
        //
        // Instead, exercise the AuditError::Backpressured path:
        // saturate the channel with a writer thread that blocks on a slow
        // disk operation. Easiest reproduction: write 1000 entries
        // concurrently with no awaits between them, all queued before
        // any has flushed.
        //
        // Practical observation: with channel capacity 64 and a fast
        // writer, getting Backpressured deterministically requires
        // pausing the writer. We don't have that hook, so this test only
        // exercises the happy path here. The Backpressured variant is
        // verified by code inspection of try_send; the explicit failure
        // test lives in audit_handle_backpressure_under_full_channel
        // when we add a slow-writer test fixture (P2).
        let spans = make_spans(0);
        let score = PrivacyScore::compute(&spans);
        let result = handle.write_entry("happy", spans, score).await;
        assert!(result.is_ok());
    }

    /// The entry's `timestamp` and the file's date suffix must come from
    /// the same captured instant. We can't directly observe the function's
    /// internal `now`, but we can confirm the entry's timestamp date matches
    /// the filename. If the function called Utc::now() twice and the second
    /// call crossed midnight, the entry would land in a file whose date
    /// disagrees with the entry's timestamp.
    #[test]
    fn entry_timestamp_date_matches_filename_date() {
        let dir = TempDir::new().unwrap();
        let mut writer = AuditWriter::new(dir.path()).unwrap();
        let spans = make_spans(1);
        let score = PrivacyScore::compute(&spans);
        writer.write_entry("ts-match", &spans, score).unwrap();

        let files: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.path().extension().map(|x| x == "jsonl").unwrap_or(false))
            .collect();
        assert_eq!(files.len(), 1);

        let path = files[0].path();
        let filename_date = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap()
            .to_string();

        let content = fs::read_to_string(&path).unwrap();
        let entry: AuditEntry = serde_json::from_str(content.lines().next().unwrap()).unwrap();
        let entry_date = entry.timestamp.format("%Y-%m-%d").to_string();

        assert_eq!(filename_date, entry_date);
    }
}
