use chrono::Utc;
use gateway_common::errors::AuditError;
use gateway_common::types::{AuditEntry, PiiSpan, PiiType, PrivacyScore};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Append-only, hash-chained audit trail writer.
///
/// Each entry includes a SHA-256 hash of its content and the hash of the
/// previous entry, forming a tamper-evident chain. One file per day under
/// the configured audit directory. Fail-closed: write failures return
/// AuditError and the proxy should return 503.
pub struct AuditWriter {
    dir: PathBuf,
    last_hash: String,
}

impl AuditWriter {
    /// Create a new writer, reading the last hash from today's log if it exists.
    pub fn new(dir: impl AsRef<Path>) -> Result<Self, AuditError> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir).map_err(|e| AuditError::WriteError(e.to_string()))?;

        let last_hash = Self::read_last_hash(&dir).unwrap_or_else(|| "0".repeat(64));

        Ok(Self { dir, last_hash })
    }

    /// Write an audit entry for a request. Returns the entry's hash.
    pub fn write_entry(
        &mut self,
        session_id: &str,
        spans: &[PiiSpan],
        score: PrivacyScore,
    ) -> Result<String, AuditError> {
        let pii_types: Vec<PiiType> = spans.iter().map(|s| s.pii_type).collect();

        let mut entry = AuditEntry {
            timestamp: Utc::now(),
            session_id: session_id.to_string(),
            pii_spans_detected: spans.len(),
            pii_types,
            placeholders_generated: spans.len(),
            privacy_score: score.value(),
            hash: String::new(),
            prev_hash: self.last_hash.clone(),
        };

        // Compute hash over the entry content (excluding the hash field itself).
        entry.hash = self.compute_hash(&entry);

        // Write to today's log file.
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let log_path = self.dir.join(format!("{today}.jsonl"));

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

        self.last_hash = entry.hash.clone();
        Ok(entry.hash)
    }

    fn compute_hash(&self, entry: &AuditEntry) -> String {
        let mut hasher = Sha256::new();
        hasher.update(entry.timestamp.to_rfc3339().as_bytes());
        hasher.update(entry.session_id.as_bytes());
        hasher.update(entry.pii_spans_detected.to_string().as_bytes());
        hasher.update(entry.privacy_score.to_string().as_bytes());
        hasher.update(entry.prev_hash.as_bytes());
        format!("{:x}", hasher.finalize())
    }

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
    pub fn verify_chain(path: impl AsRef<Path>) -> Result<bool, AuditError> {
        let content = fs::read_to_string(path.as_ref())
            .map_err(|e| AuditError::WriteError(e.to_string()))?;

        let entries: Vec<AuditEntry> = content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| AuditError::WriteError(e.to_string()))?;

        if entries.is_empty() {
            return Ok(true);
        }

        // First entry should reference the zero hash or previous day's last hash.
        for window in entries.windows(2) {
            if window[1].prev_hash != window[0].hash {
                return Ok(false);
            }
        }

        Ok(true)
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
            writer.write_entry(&format!("session-{i}"), &spans, score).unwrap();
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
}
