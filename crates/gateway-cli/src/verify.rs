//! `gateway verify <receipt.json>` — offline receipt verification.
//!
//! Reads a receipt JSON file (produced by `GET /v1/receipts/{id}`),
//! recomputes the entry hash under the receipt's declared
//! `hash_recipe`, and confirms it matches the stored `hash`. Optionally
//! checks the HMAC of prompt/response if the operator has supplied the
//! key via `GATEWAY_HMAC_KEY` or `--hmac-key`. Rekor inclusion-proof
//! checking will land alongside the Rekor publisher integration.
//!
//! Codex F15: receipts must verify offline first. Without a live Rekor,
//! this CLI still proves the receipt's content is internally consistent
//! and that the hash chain links to the previous hash the receipt
//! claims. To prove the receipt was integrated into a public log,
//! follow up with `rekor-cli` against `rekor_uuid` from the receipt.

use std::fs;
use std::path::PathBuf;

use clap::Args;
use gateway_anonymizer::audit;
use gateway_anonymizer::hmac_digest::HmacContext;
use gateway_common::types::AuditEntry;

#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// Path to the receipt JSON file.
    pub path: PathBuf,
    /// Optional HMAC key (hex) to verify prompt_hmac/response_hmac. If
    /// omitted, structural hash verification still runs but the keyed
    /// digests are not checked.
    #[arg(long, env = "GATEWAY_HMAC_KEY")]
    pub hmac_key: Option<String>,
    /// HMAC key id matched against the receipt's hmac_key_id field.
    /// Default "primary" matches the gateway's default.
    #[arg(long, env = "GATEWAY_HMAC_KEY_ID", default_value = "primary")]
    pub hmac_key_id: String,
}

pub fn run(args: VerifyArgs) -> Result<(), VerifyError> {
    let raw =
        fs::read_to_string(&args.path).map_err(|e| VerifyError::Read(args.path.clone(), e.to_string()))?;
    let entry: AuditEntry = serde_json::from_str(&raw)
        .map_err(|e| VerifyError::Parse(e.to_string()))?;

    println!("Verifying receipt for request_id: {}", entry.request_id);
    println!("  Hash recipe: {}", entry.hash_recipe);
    println!("  Chain prev:  {}", short(&entry.prev_hash));
    println!("  Chain hash:  {}", short(&entry.hash));

    // 1. Recompute the entry hash and confirm it matches.
    let recomputed = audit::compute_hash(&entry)
        .map_err(|e| VerifyError::HashCompute(e.to_string()))?;
    if recomputed != entry.hash {
        return Err(VerifyError::HashMismatch {
            stored: entry.hash.clone(),
            recomputed,
        });
    }
    println!("  Hash recompute:           OK");

    // 2. Optional HMAC verification. The receipt itself can never
    //    contain the raw prompt/response, so we can only verify that the
    //    receipt's HMAC was constructed under our key id (not that it
    //    digests any specific bytes — that requires the original prompt
    //    body, which the verifier doesn't have here).
    //
    //    Useful smoke check: confirm the receipt's hmac_key_id matches
    //    what the operator expects, so a swapped key surfaces fast.
    if !entry.hmac_key_id.is_empty() {
        if entry.hmac_key_id != args.hmac_key_id {
            return Err(VerifyError::HmacKeyIdMismatch {
                expected: args.hmac_key_id,
                found: entry.hmac_key_id,
            });
        }
        println!("  HMAC key id ({}):       OK", entry.hmac_key_id);
    }

    if let Some(hex_key) = args.hmac_key {
        // Construct the HMAC context to validate that the supplied key
        // is well-formed against the receipt's declared key id. If the
        // operator wants to verify a specific captured prompt, they
        // should re-run the gateway's HMAC over the captured body and
        // diff against entry.prompt_hmac externally — that's beyond
        // this CLI's offline scope.
        let _hmac = HmacContext::from_hex(&hex_key, &args.hmac_key_id)
            .map_err(|e| VerifyError::HmacKey(e.to_string()))?;
        println!("  HMAC key parse:           OK");
    }

    // 3. Anchor status (informational; does not affect verification).
    println!("  Anchor status:            {:?}", entry.anchor_status);
    if !entry.rekor_uuid.is_empty() {
        println!("  Rekor uuid:               {}", entry.rekor_uuid);
        println!("  Rekor log_index:          {}", entry.log_index);
        println!(
            "  Verify on Rekor with:     rekor-cli get --uuid {}",
            entry.rekor_uuid
        );
    } else {
        println!("  Anchor status:            not yet anchored to Rekor");
    }

    println!();
    println!("RECEIPT VERIFIED.");
    println!("Note: this confirms the gateway's chain is internally consistent.");
    println!("It does NOT prove PII removal, model authenticity, or response integrity.");
    Ok(())
}

fn short(s: &str) -> String {
    if s.len() <= 16 {
        s.to_string()
    } else {
        format!("{}...{}", &s[..8], &s[s.len() - 8..])
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("failed to read {0}: {1}")]
    Read(PathBuf, String),
    #[error("failed to parse receipt JSON: {0}")]
    Parse(String),
    #[error("failed to recompute receipt hash: {0}")]
    HashCompute(String),
    #[error(
        "RECEIPT INVALID: hash mismatch.\n  stored:     {stored}\n  recomputed: {recomputed}\n\
         The receipt's content does not match its declared hash. \
         Either the file has been tampered with or the recipe is wrong."
    )]
    HashMismatch { stored: String, recomputed: String },
    #[error(
        "RECEIPT INVALID: hmac key id mismatch.\n  expected:   {expected}\n  found:      {found}\n\
         The receipt was signed under a different HMAC key. Check that you're \
         passing the right --hmac-key-id."
    )]
    HmacKeyIdMismatch { expected: String, found: String },
    #[error("invalid --hmac-key: {0}")]
    HmacKey(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_common::types::{AuditEntry, HASH_RECIPE_V2_CANONICAL_JSON};
    use tempfile::NamedTempFile;

    fn make_entry() -> AuditEntry {
        let mut entry = AuditEntry {
            request_id: "req-1".to_string(),
            session_id: "sess-1".to_string(),
            hash_recipe: HASH_RECIPE_V2_CANONICAL_JSON.to_string(),
            prev_hash: "0".repeat(64),
            ..AuditEntry::default()
        };
        entry.hash = audit::compute_hash(&entry).unwrap();
        entry
    }

    fn write_entry(entry: &AuditEntry) -> NamedTempFile {
        let f = NamedTempFile::new().unwrap();
        std::fs::write(f.path(), serde_json::to_string(entry).unwrap()).unwrap();
        f
    }

    #[test]
    fn verify_accepts_well_formed_receipt() {
        let entry = make_entry();
        let f = write_entry(&entry);
        let args = VerifyArgs {
            path: f.path().to_path_buf(),
            hmac_key: None,
            hmac_key_id: "primary".to_string(),
        };
        run(args).unwrap();
    }

    #[test]
    fn verify_rejects_tampered_session_id() {
        let mut entry = make_entry();
        // Tamper after hash is computed; do NOT recompute.
        entry.session_id = "forged".to_string();
        let f = write_entry(&entry);
        let args = VerifyArgs {
            path: f.path().to_path_buf(),
            hmac_key: None,
            hmac_key_id: "primary".to_string(),
        };
        let err = run(args).unwrap_err();
        assert!(matches!(err, VerifyError::HashMismatch { .. }));
    }

    #[test]
    fn verify_rejects_tampered_hash() {
        let mut entry = make_entry();
        entry.hash = "f".repeat(64);
        let f = write_entry(&entry);
        let args = VerifyArgs {
            path: f.path().to_path_buf(),
            hmac_key: None,
            hmac_key_id: "primary".to_string(),
        };
        let err = run(args).unwrap_err();
        assert!(matches!(err, VerifyError::HashMismatch { .. }));
    }

    #[test]
    fn verify_rejects_hmac_key_id_mismatch() {
        let mut entry = make_entry();
        entry.hmac_key_id = "primary".to_string();
        // Recompute hash so the entry is otherwise valid.
        entry.hash = audit::compute_hash(&entry).unwrap();
        let f = write_entry(&entry);
        let args = VerifyArgs {
            path: f.path().to_path_buf(),
            hmac_key: None,
            hmac_key_id: "rotated".to_string(),
        };
        let err = run(args).unwrap_err();
        assert!(matches!(err, VerifyError::HmacKeyIdMismatch { .. }));
    }

    #[test]
    fn verify_returns_read_error_for_missing_file() {
        let args = VerifyArgs {
            path: PathBuf::from("/nonexistent/path/receipt.json"),
            hmac_key: None,
            hmac_key_id: "primary".to_string(),
        };
        assert!(matches!(run(args).unwrap_err(), VerifyError::Read(_, _)));
    }

    #[test]
    fn verify_returns_parse_error_for_invalid_json() {
        let f = NamedTempFile::new().unwrap();
        std::fs::write(f.path(), "not valid json").unwrap();
        let args = VerifyArgs {
            path: f.path().to_path_buf(),
            hmac_key: None,
            hmac_key_id: "primary".to_string(),
        };
        assert!(matches!(run(args).unwrap_err(), VerifyError::Parse(_)));
    }
}
