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
