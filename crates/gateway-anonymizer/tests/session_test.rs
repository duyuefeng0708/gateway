use std::time::Duration;

use gateway_anonymizer::session::SessionStore;
use gateway_common::types::{Placeholder, PiiType};

#[tokio::test]
async fn store_and_lookup_single_placeholder() {
    let store = SessionStore::in_memory().await.unwrap();
    let placeholder = Placeholder::new(PiiType::Person, "Alice".into());
    let placeholder_text = placeholder.placeholder_text.clone();

    store.store("sess-1", &[placeholder]).await.unwrap();

    let result = store.lookup("sess-1", &placeholder_text).await.unwrap();
    assert_eq!(result, Some("Alice".to_string()));
}

#[tokio::test]
async fn store_and_lookup_all() {
    let store = SessionStore::in_memory().await.unwrap();
    let p1 = Placeholder::new(PiiType::Person, "Alice".into());
    let p2 = Placeholder::new(PiiType::Email, "alice@example.com".into());

    store.store("sess-2", &[p1.clone(), p2.clone()]).await.unwrap();

    let all = store.lookup_all("sess-2").await.unwrap();
    assert_eq!(all.len(), 2);

    let originals: Vec<&str> = all.iter().map(|p| p.original_text.as_str()).collect();
    assert!(originals.contains(&"Alice"));
    assert!(originals.contains(&"alice@example.com"));
}

#[tokio::test]
async fn lookup_missing_placeholder_returns_none() {
    let store = SessionStore::in_memory().await.unwrap();
    let result = store.lookup("nonexistent", "[PERSON_00000000]").await.unwrap();
    assert_eq!(result, None);
}

#[tokio::test]
async fn lookup_all_empty_session_returns_empty() {
    let store = SessionStore::in_memory().await.unwrap();
    let all = store.lookup_all("nonexistent").await.unwrap();
    assert!(all.is_empty());
}

#[tokio::test]
async fn cleanup_expired_removes_old_entries() {
    let store = SessionStore::in_memory().await.unwrap();
    let p = Placeholder::new(PiiType::Ssn, "123-45-6789".into());
    store.store("old-sess", &[p]).await.unwrap();

    // With a TTL of 0 seconds, everything is expired immediately.
    let deleted = store.cleanup_expired(Duration::from_secs(0)).await.unwrap();
    assert_eq!(deleted, 1);

    // Verify it's gone.
    let all = store.lookup_all("old-sess").await.unwrap();
    assert!(all.is_empty());
}

#[tokio::test]
async fn cleanup_expired_preserves_recent_entries() {
    let store = SessionStore::in_memory().await.unwrap();
    let p = Placeholder::new(PiiType::Person, "Bob".into());
    store.store("recent-sess", &[p]).await.unwrap();

    // With a large TTL nothing should be deleted.
    let deleted = store.cleanup_expired(Duration::from_secs(86400)).await.unwrap();
    assert_eq!(deleted, 0);

    let all = store.lookup_all("recent-sess").await.unwrap();
    assert_eq!(all.len(), 1);
}

#[tokio::test]
async fn multiple_sessions_are_isolated() {
    let store = SessionStore::in_memory().await.unwrap();
    let p1 = Placeholder::new(PiiType::Person, "Alice".into());
    let p2 = Placeholder::new(PiiType::Person, "Bob".into());

    store.store("sess-a", &[p1]).await.unwrap();
    store.store("sess-b", &[p2]).await.unwrap();

    let a = store.lookup_all("sess-a").await.unwrap();
    let b = store.lookup_all("sess-b").await.unwrap();

    assert_eq!(a.len(), 1);
    assert_eq!(b.len(), 1);
    assert_eq!(a[0].original_text, "Alice");
    assert_eq!(b[0].original_text, "Bob");
}

#[tokio::test]
async fn stored_pii_types_roundtrip_correctly() {
    let store = SessionStore::in_memory().await.unwrap();

    let types_and_originals = [
        (PiiType::Person, "Alice"),
        (PiiType::Organization, "Acme"),
        (PiiType::Location, "NYC"),
        (PiiType::Email, "a@b.com"),
        (PiiType::Phone, "555-0000"),
        (PiiType::Ssn, "000-00-0000"),
        (PiiType::Credential, "sk-secret"),
    ];

    let placeholders: Vec<Placeholder> = types_and_originals
        .iter()
        .map(|(t, o)| Placeholder::new(*t, o.to_string()))
        .collect();

    store.store("sess-types", &placeholders).await.unwrap();
    let retrieved = store.lookup_all("sess-types").await.unwrap();

    assert_eq!(retrieved.len(), 7);

    for original_placeholder in &placeholders {
        let found = retrieved
            .iter()
            .find(|r| r.placeholder_text == original_placeholder.placeholder_text);
        assert!(
            found.is_some(),
            "missing placeholder: {}",
            original_placeholder.placeholder_text
        );
        let found = found.unwrap();
        assert_eq!(found.pii_type, original_placeholder.pii_type);
        assert_eq!(found.original_text, original_placeholder.original_text);
    }
}
