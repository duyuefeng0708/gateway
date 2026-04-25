use gateway_anonymizer::streaming::StreamingDeanonymizer;
use gateway_common::types::{PiiType, Placeholder};

fn make_placeholder(pii_type: PiiType, id: &str, original: &str) -> Placeholder {
    Placeholder {
        id: id.to_string(),
        pii_type,
        placeholder_text: format!("[{}_{id}]", pii_type.placeholder_prefix()),
        original_text: original.to_string(),
    }
}

#[test]
fn complete_placeholder_deanonymized_immediately() {
    let p = make_placeholder(PiiType::Person, "abc12345", "Alice Smith");
    let mut d = StreamingDeanonymizer::new(vec![p]);

    let out = d.process_token("[PERSON_abc12345]");
    assert_eq!(out, vec!["Alice Smith"]);
}

#[test]
fn placeholder_split_across_two_tokens() {
    let p = make_placeholder(PiiType::Person, "abc12345", "Alice Smith");
    let mut d = StreamingDeanonymizer::new(vec![p]);

    let out1 = d.process_token("[PER");
    assert!(out1.is_empty(), "should buffer partial placeholder");

    let out2 = d.process_token("SON_abc12345]");
    assert_eq!(out2, vec!["Alice Smith"]);
}

#[test]
fn no_placeholders_tokens_pass_through_unchanged() {
    let mut d = StreamingDeanonymizer::new(vec![]);

    let out = d.process_token("Hello world, no placeholders here.");
    let combined = out.join("");
    assert_eq!(combined, "Hello world, no placeholders here.");
}

#[test]
fn buffer_exceeds_32_chars_flushed_as_is() {
    let mut d = StreamingDeanonymizer::new(vec![]);

    // Start with `[` then 33 more characters without `]`.
    let long_token = format!("[{}", "a".repeat(33));
    let out = d.process_token(&long_token);
    let combined = out.join("");
    assert_eq!(combined, long_token);
}

#[test]
fn nested_opening_brackets_flush_outer_immediately() {
    let p = make_placeholder(PiiType::Email, "abc12345", "alice@test.com");
    let mut d = StreamingDeanonymizer::new(vec![p]);

    // The first `[` starts a buffer, then `[` flushes it and starts a new one.
    let out = d.process_token("[invalid[EMAIL_abc12345]");
    let combined = out.join("");
    assert_eq!(combined, "[invalidalice@test.com");
}

#[test]
fn non_ascii_in_buffer_flushes_immediately() {
    let mut d = StreamingDeanonymizer::new(vec![]);

    let out = d.process_token("[hello\u{00e9}");
    let combined = out.join("");
    assert_eq!(combined, "[hello\u{00e9}");
}

#[test]
fn flush_at_end_returns_remaining_buffer() {
    let mut d = StreamingDeanonymizer::new(vec![]);

    let out = d.process_token("[incomplete_placeholder");
    assert!(out.is_empty());

    let flushed = d.flush();
    assert_eq!(flushed, Some("[incomplete_placeholder".to_string()));
}

#[test]
fn flush_returns_none_when_buffer_empty() {
    let mut d = StreamingDeanonymizer::new(vec![]);
    let _ = d.process_token("no brackets");
    assert_eq!(d.flush(), None);
}

#[test]
fn multiple_placeholders_in_sequence() {
    let p1 = make_placeholder(PiiType::Person, "aaaa1111", "Alice");
    let p2 = make_placeholder(PiiType::Email, "bbbb2222", "alice@example.com");
    let mut d = StreamingDeanonymizer::new(vec![p1, p2]);

    let out = d.process_token("Hello [PERSON_aaaa1111], your email is [EMAIL_bbbb2222].");
    let combined = out.join("");
    assert_eq!(combined, "Hello Alice, your email is alice@example.com.");
}

#[test]
fn placeholder_split_across_three_tokens() {
    let p = make_placeholder(PiiType::Ssn, "de0f1234", "123-45-6789");
    let mut d = StreamingDeanonymizer::new(vec![p]);

    assert!(d.process_token("[SS").is_empty());
    assert!(d.process_token("N_de0f").is_empty());
    assert_eq!(d.process_token("1234]"), vec!["123-45-6789"]);
}

#[test]
fn invalid_bracket_content_flushed_on_close() {
    let mut d = StreamingDeanonymizer::new(vec![]);

    let out = d.process_token("[not_a_valid_placeholder]");
    let combined = out.join("");
    assert_eq!(combined, "[not_a_valid_placeholder]");
}

#[test]
fn text_before_and_after_placeholder() {
    let p = make_placeholder(PiiType::Phone, "dead0000", "555-1234");
    let mut d = StreamingDeanonymizer::new(vec![p]);

    let out = d.process_token("Call [PHONE_dead0000] now.");
    let combined = out.join("");
    assert_eq!(combined, "Call 555-1234 now.");
}

#[test]
fn unknown_placeholder_passes_through() {
    let mut d = StreamingDeanonymizer::new(vec![]);

    let out = d.process_token("[PERSON_deadbeef]");
    let combined = out.join("");
    // Placeholder regex matches but no lookup entry, so it passes through.
    assert_eq!(combined, "[PERSON_deadbeef]");
}

#[test]
fn all_pii_types_deanonymize_correctly() {
    let placeholders = vec![
        make_placeholder(PiiType::Person, "aa000001", "Alice"),
        make_placeholder(PiiType::Organization, "aa000002", "Acme"),
        make_placeholder(PiiType::Email, "aa000003", "a@b.com"),
        make_placeholder(PiiType::Location, "aa000004", "NYC"),
        make_placeholder(PiiType::Phone, "aa000005", "555-0100"),
        make_placeholder(PiiType::Ssn, "aa000006", "111-22-3333"),
        make_placeholder(PiiType::Credential, "aa000007", "sk-secret"),
    ];
    let mut d = StreamingDeanonymizer::new(placeholders);

    let input = concat!(
        "[PERSON_aa000001] at [ORG_aa000002] ",
        "[EMAIL_aa000003] [LOCATION_aa000004] ",
        "[PHONE_aa000005] [SSN_aa000006] ",
        "[CREDENTIAL_aa000007]"
    );
    let out = d.process_token(input);
    let combined = out.join("");
    assert_eq!(
        combined,
        "Alice at Acme a@b.com NYC 555-0100 111-22-3333 sk-secret"
    );
}
