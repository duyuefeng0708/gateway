use gateway_anonymizer::placeholder::{restore, substitute};
use gateway_common::types::{PiiSpan, PiiType};

fn span(pii_type: PiiType, start: usize, end: usize, text: &str) -> PiiSpan {
    PiiSpan {
        pii_type,
        start,
        end,
        text: text.to_string(),
        confidence: 0.95,
        implicit: false,
    }
}

#[test]
fn single_pii_entity_substituted_and_restored() {
    let text = "Contact John Smith for details.";
    let spans = vec![span(PiiType::Person, 8, 18, "John Smith")];

    let (redacted, placeholders) = substitute(text, &spans);
    assert!(!redacted.contains("John Smith"));
    assert!(redacted.contains("[PERSON_"));
    assert_eq!(placeholders.len(), 1);

    let restored = restore(&redacted, &placeholders);
    assert_eq!(restored, text);
}

#[test]
fn multiple_pii_entities_get_unique_placeholders() {
    let text = "Email alice@example.com or call 555-0100.";
    let spans = vec![
        span(PiiType::Email, 6, 23, "alice@example.com"),
        span(PiiType::Phone, 32, 40, "555-0100"),
    ];

    let (redacted, placeholders) = substitute(text, &spans);
    assert!(!redacted.contains("alice@example.com"));
    assert!(!redacted.contains("555-0100"));
    assert_eq!(placeholders.len(), 2);

    // Placeholders should have different prefixes.
    let prefixes: Vec<&str> = placeholders
        .iter()
        .map(|p| p.pii_type.placeholder_prefix())
        .collect();
    assert!(prefixes.contains(&"EMAIL"));
    assert!(prefixes.contains(&"PHONE"));
}

#[test]
fn dedup_identical_entities_same_placeholder() {
    let text = "Ask Alice about Alice.";
    let spans = vec![
        span(PiiType::Person, 4, 9, "Alice"),
        span(PiiType::Person, 16, 21, "Alice"),
    ];

    let (redacted, placeholders) = substitute(text, &spans);

    // Only one placeholder generated.
    assert_eq!(placeholders.len(), 1);
    assert_eq!(placeholders[0].original_text, "Alice");

    // Both occurrences replaced with the same token.
    let token = &placeholders[0].placeholder_text;
    assert_eq!(redacted.matches(token.as_str()).count(), 2);
}

#[test]
fn entity_text_with_brackets_handled() {
    let text = "User [admin] is active.";
    let spans = vec![span(PiiType::Person, 5, 12, "[admin]")];

    let (redacted, placeholders) = substitute(text, &spans);
    assert_eq!(placeholders[0].original_text, "[admin]");

    let restored = restore(&redacted, &placeholders);
    assert_eq!(restored, text);
}

#[test]
fn round_trip_substitution_and_restoration() {
    let text = "My SSN is 123-45-6789 and I work at Acme Corp in New York.";
    let spans = vec![
        span(PiiType::Ssn, 10, 21, "123-45-6789"),
        span(PiiType::Organization, 36, 45, "Acme Corp"),
        span(PiiType::Location, 49, 57, "New York"),
    ];

    let (redacted, placeholders) = substitute(text, &spans);
    assert!(!redacted.contains("123-45-6789"));
    assert!(!redacted.contains("Acme Corp"));
    assert!(!redacted.contains("New York"));

    let restored = restore(&redacted, &placeholders);
    assert_eq!(restored, text);
}

#[test]
fn unknown_placeholder_left_unchanged() {
    let text = "Hello [PERSON_deadbeef], meet [ORG_12345678].";
    let restored = restore(text, &[]);
    assert_eq!(restored, text);
}

#[test]
fn empty_spans_returns_original_text() {
    let text = "Nothing sensitive here.";
    let (redacted, placeholders) = substitute(text, &[]);
    assert_eq!(redacted, text);
    assert!(placeholders.is_empty());
}

#[test]
fn placeholder_format_is_correct() {
    let text = "Call 555-1234.";
    let spans = vec![span(PiiType::Phone, 5, 13, "555-1234")];

    let (redacted, placeholders) = substitute(text, &spans);
    let p = &placeholders[0];

    // Format: [TYPE_xxxxxxxx]
    assert!(p.placeholder_text.starts_with("[PHONE_"));
    assert!(p.placeholder_text.ends_with(']'));
    // 8 hex chars between underscore and closing bracket.
    let inner = p
        .placeholder_text
        .trim_start_matches("[PHONE_")
        .trim_end_matches(']');
    assert_eq!(inner.len(), 8);
    assert!(inner.chars().all(|c| c.is_ascii_hexdigit()));

    // The redacted text should contain the placeholder.
    assert!(redacted.contains(&p.placeholder_text));
}

// ---------------------------------------------------------------------------
// Correctness tests for bad offsets emitted by the 4B fast detector.
// ---------------------------------------------------------------------------

#[test]
fn test_valid_offsets_unchanged() {
    // Baseline: a valid span with matching text must still produce the
    // expected placeholder. No regression from the fallback logic.
    let text = "Hello Alice, welcome.";
    let spans = vec![span(PiiType::Person, 6, 11, "Alice")];

    let (redacted, placeholders) = substitute(text, &spans);
    assert_eq!(placeholders.len(), 1);
    assert_eq!(placeholders[0].original_text, "Alice");
    assert!(redacted.starts_with("Hello [PERSON_"));
    assert!(redacted.ends_with(", welcome."));
    assert!(!redacted.contains("Alice"));

    let restored = restore(&redacted, &placeholders);
    assert_eq!(restored, text);
}

#[test]
fn test_bad_byte_boundary_unicode() {
    // Text contains a multi-byte emoji. The span's start/end intentionally
    // split the emoji's UTF-8 code point, which would panic on
    // `replace_range`. Fallback should find the matching text elsewhere.
    //
    // Layout (byte offsets):
    //   "Hi \u{1F600} Alice and Alice"
    //    H(0) i(1) ' '(2) 😀(3..7) ' '(7) A(8) l(9) i(10) c(11) e(12)
    //    ' '(13) a(14) n(15) d(16) ' '(17) A(18) l(19) i(20) c(21) e(22)
    let text = "Hi \u{1F600} Alice and Alice";
    assert!(!text.is_char_boundary(5)); // sanity: mid-emoji

    // Offsets 4..6 slice through the emoji and do NOT equal "Alice".
    // span.text "Alice" appears at byte 8..13 and again at 18..23.
    let spans = vec![span(PiiType::Person, 4, 6, "Alice")];

    let (redacted, placeholders) = substitute(text, &spans);
    assert_eq!(placeholders.len(), 1, "fallback should find 'Alice'");
    assert!(redacted.contains("[PERSON_"));
    // Emoji must be preserved.
    assert!(redacted.contains('\u{1F600}'));
    // One occurrence of "Alice" remains (the fallback only takes the first
    // non-overlapping match).
    assert_eq!(redacted.matches("Alice").count(), 1);

    // Now verify the "no match anywhere" branch: same unicode text, but
    // span.text doesn't occur in it. Span should be skipped.
    let text2 = "Hi \u{1F600} there";
    let spans2 = vec![span(PiiType::Person, 4, 6, "Alice")];
    let (redacted2, placeholders2) = substitute(text2, &spans2);
    assert!(placeholders2.is_empty(), "no match -> span skipped");
    assert_eq!(redacted2, text2, "text unchanged when span skipped");
}

#[test]
fn test_text_mismatch_with_fallback() {
    // Offsets point to "welcome" but span.text is "alice@example.com".
    // Fallback should find the email elsewhere in the text.
    let text = "welcome! Email alice@example.com for info.";
    //          0         1         2         3
    //          0123456789012345678901234567890123456789012
    // Offsets 0..7 slice "welcome", which does not equal span.text.
    let spans = vec![span(PiiType::Email, 0, 7, "alice@example.com")];

    let (redacted, placeholders) = substitute(text, &spans);
    assert_eq!(placeholders.len(), 1);
    assert_eq!(placeholders[0].original_text, "alice@example.com");
    assert!(!redacted.contains("alice@example.com"));
    // "welcome" is preserved since the offset was rejected.
    assert!(redacted.starts_with("welcome! Email [EMAIL_"));

    let restored = restore(&redacted, &placeholders);
    assert_eq!(restored, text);
}

#[test]
fn test_text_mismatch_no_fallback_skip() {
    // span.text does not appear anywhere in the text -> span is skipped.
    let text = "No email here.";
    let spans = vec![span(PiiType::Email, 3, 8, "alice@example.com")];

    let (redacted, placeholders) = substitute(text, &spans);
    assert!(placeholders.is_empty(), "span with no match should be skipped");
    assert_eq!(redacted, text, "text unchanged when span skipped");
}

#[test]
fn test_overlap_prevention() {
    // Two spans. The first is valid and claims a range covering the only
    // occurrence of "Alice". The second has bad offsets; its fallback match
    // would land on that same "Alice", so it must be skipped.
    let text = "Ask Alice today.";
    //          0         1
    //          0123456789012345
    // "Alice" is at bytes 4..9.
    let spans = vec![
        // Valid span: offsets and text match.
        span(PiiType::Person, 4, 9, "Alice"),
        // Bad offsets (slice "k Alic" != "Alice"), fallback would find
        // "Alice" at 4..9 but that range is already claimed.
        span(PiiType::Person, 2, 8, "Alice"),
    ];

    let (redacted, placeholders) = substitute(text, &spans);
    // Only the first span's placeholder should be produced. (Since both
    // span.text are "Alice", dedup collapses to one entry anyway, but the
    // key correctness claim is that the second span does NOT trigger a new
    // substitution against an overlapping range.)
    assert_eq!(placeholders.len(), 1);
    assert_eq!(placeholders[0].original_text, "Alice");

    // "Alice" should be replaced exactly once, nothing else touched.
    assert!(!redacted.contains("Alice"));
    assert!(redacted.starts_with("Ask [PERSON_"));
    assert!(redacted.ends_with(" today."));

    let restored = restore(&redacted, &placeholders);
    assert_eq!(restored, text);
}
