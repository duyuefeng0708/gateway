//! Integration tests for the transparency-log anchor publisher.
//!
//! Exercises the full TransparencyState surface: Rekor request shape,
//! signing round-trip, success/failure paths via wiremock, and the
//! basic queue + snapshot semantics.

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey, Verifier};
use gateway_common::types::AnchorStatus;
use gateway_proxy::transparency::TransparencyState;
use std::time::Duration;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn fixture_state(rekor_url: String) -> TransparencyState {
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    TransparencyState::from_parts(
        signing_key,
        "primary".into(),
        rekor_url,
        Duration::from_millis(50),
    )
}

fn fixture_head_hex(byte: u8) -> String {
    hex::encode([byte; 32])
}

#[tokio::test]
async fn state_initial_head_is_empty() {
    let state = fixture_state("http://unused".into());
    let head = state.current_head().await;
    assert_eq!(head.current_chain_head, "");
    assert_eq!(head.last_anchored_chain_head, "");
    assert_eq!(head.anchor_status, AnchorStatus::NotYetAnchored);
    assert_eq!(head.signing_key_id, "primary");
    assert_eq!(head.signature_alg, "ed25519");
    assert_eq!(head.log_index, 0);
    assert_eq!(head.rekor_uuid, "");
}

#[tokio::test]
async fn record_head_then_current_head_returns_it() {
    let state = fixture_state("http://unused".into());
    let h = fixture_head_hex(0xab);
    state.record_head(h.clone()).await;
    let head = state.current_head().await;
    assert_eq!(head.current_chain_head, h);
}

#[tokio::test]
async fn empty_queue_skip_cycle() {
    // Pointing at an unreachable URL is fine because the publisher should
    // never make a network call when the queue is empty. wiremock isn't
    // even started here — if the publisher tried to POST, it would hit
    // localhost:1 and fail, but it does NOT POST so the test just succeeds.
    let state = fixture_state("http://127.0.0.1:1".into());
    state.run_one_cycle_for_test().await;
    let head = state.current_head().await;
    // No anchor ever happened.
    assert_eq!(head.anchor_status, AnchorStatus::NotYetAnchored);
}

#[tokio::test]
async fn publisher_records_anchored_on_201() {
    let server = MockServer::start().await;

    // Mimic the public Rekor 201 response shape: top-level key is the
    // entry UUID, value is the entry envelope.
    Mock::given(method("POST"))
        .and(path("/api/v1/log/entries"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "deadbeef-uuid": {
                "logIndex": 12345,
                "verification": {
                    "integratedTime": 1_700_000_000u64,
                    "signedEntryTimestamp": "fake-set"
                }
            }
        })))
        .mount(&server)
        .await;

    let state = fixture_state(server.uri());
    state.record_head(fixture_head_hex(0x11)).await;
    state.record_head(fixture_head_hex(0x22)).await;

    state.run_one_cycle_for_test().await;
    let head = state.current_head().await;
    assert_eq!(head.anchor_status, AnchorStatus::Anchored);
    assert_eq!(head.rekor_uuid, "deadbeef-uuid");
    assert_eq!(head.log_index, 12345);
    assert_eq!(head.last_anchored_chain_head, fixture_head_hex(0x22));
}

#[tokio::test]
async fn publisher_records_failed_anchor_on_500() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/log/entries"))
        .respond_with(ResponseTemplate::new(500).set_body_string("rekor exploded"))
        .mount(&server)
        .await;

    let state = fixture_state(server.uri());
    state.record_head(fixture_head_hex(0x33)).await;

    state.run_one_cycle_for_test().await;
    let head = state.current_head().await;
    assert_eq!(head.anchor_status, AnchorStatus::AnchorFailed);
    // Re-queued: subsequent successful anchor still has the head waiting.
    // Confirmed indirectly by checking `last_anchored_chain_head` did not
    // get set to a fresh value.
    assert_eq!(head.last_anchored_chain_head, "");
}

#[tokio::test]
async fn rekor_request_body_matches_hashedrekord_schema() {
    let server = MockServer::start().await;

    // Capture the body that the publisher posts and verify shape. We
    // accept-then-record by returning a 201 and reading the request later
    // from the mock server's `received_requests`.
    Mock::given(method("POST"))
        .and(path("/api/v1/log/entries"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "uuid_z": {
                "logIndex": 1,
                "verification": { "integratedTime": 1u64 }
            }
        })))
        .mount(&server)
        .await;

    let state = fixture_state(server.uri());
    state.record_head(fixture_head_hex(0x44)).await;
    state.run_one_cycle_for_test().await;

    let received = server
        .received_requests()
        .await
        .expect("wiremock recorded requests");
    assert_eq!(received.len(), 1);
    let req = &received[0];
    let body: serde_json::Value =
        serde_json::from_slice(&req.body).expect("body parses as JSON");

    assert_eq!(body["kind"], "hashedrekord");
    assert_eq!(body["apiVersion"], "0.0.1");
    let spec = &body["spec"];

    let sig_b64 = spec["signature"]["content"].as_str().expect("sig is string");
    let sig = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .expect("signature base64 decodes");
    assert_eq!(sig.len(), 64, "ed25519 signatures are 64 bytes");

    let pk_b64 = spec["signature"]["publicKey"]["content"]
        .as_str()
        .expect("public key is string");
    let pk_pem = base64::engine::general_purpose::STANDARD
        .decode(pk_b64)
        .expect("public key base64 decodes");
    let pk_pem_str = std::str::from_utf8(&pk_pem).expect("PEM is utf8");
    assert!(pk_pem_str.contains("-----BEGIN PUBLIC KEY-----"));

    assert_eq!(spec["data"]["hash"]["algorithm"], "sha256");
    let hex_root = spec["data"]["hash"]["value"].as_str().unwrap();
    assert_eq!(hex_root.len(), 64); // SHA-256 hex
    assert!(hex_root.chars().all(|c| c.is_ascii_hexdigit()));
}

#[tokio::test]
async fn signing_round_trip() {
    // Independent of the Rekor publisher: confirm that the keypair we
    // load can sign a Merkle root and verify with its public half.
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let verifying_key = signing_key.verifying_key();

    let root = [0xabu8; 32];
    let sig = signing_key.sign(&root);
    assert!(verifying_key.verify(&root, &sig).is_ok());

    // Tampered payload must not verify.
    let tampered = [0xacu8; 32];
    assert!(verifying_key.verify(&tampered, &sig).is_err());
}
