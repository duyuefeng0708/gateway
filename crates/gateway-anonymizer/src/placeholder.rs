use std::collections::HashMap;

use gateway_common::types::{Placeholder, PiiSpan};
use regex::Regex;

/// Replace PII spans in `text` with UUID-based placeholders.
///
/// Spans are processed in reverse order so that earlier byte offsets remain
/// valid after each substitution. If the same entity text appears more than
/// once, the same placeholder is reused (deduplication).
///
/// Returns the redacted text together with the generated placeholders.
pub fn substitute(text: &str, spans: &[PiiSpan]) -> (String, Vec<Placeholder>) {
    // Sort spans by start position descending so replacements don't shift
    // earlier offsets.
    let mut sorted: Vec<&PiiSpan> = spans.iter().collect();
    sorted.sort_by(|a, b| b.start.cmp(&a.start));

    // Dedup map: original_text -> Placeholder
    let mut dedup: HashMap<String, Placeholder> = HashMap::new();
    let mut result = text.to_string();

    for span in &sorted {
        let original = &span.text;
        let placeholder = dedup
            .entry(original.clone())
            .or_insert_with(|| Placeholder::new(span.pii_type, original.clone()));

        let start = span.start;
        let end = span.end;

        // Guard against out-of-bounds spans.
        if start > result.len() || end > result.len() || start > end {
            continue;
        }

        result.replace_range(start..end, &placeholder.placeholder_text);
    }

    let placeholders: Vec<Placeholder> = dedup.into_values().collect();
    (result, placeholders)
}

/// Restore original text by replacing every placeholder token with its
/// original value. Unknown placeholders (not present in the provided list)
/// are left as-is.
pub fn restore(text: &str, placeholders: &[Placeholder]) -> String {
    // Build a lookup: placeholder_text -> original_text
    let lookup: HashMap<&str, &str> = placeholders
        .iter()
        .map(|p| (p.placeholder_text.as_str(), p.original_text.as_str()))
        .collect();

    let pattern = Regex::new(
        r"\[(PERSON|ORG|EMAIL|LOCATION|PHONE|SSN|CREDENTIAL)_[a-f0-9]{8}\]",
    )
    .expect("hardcoded regex must compile");

    pattern
        .replace_all(text, |caps: &regex::Captures| {
            let matched = caps.get(0).unwrap().as_str();
            match lookup.get(matched) {
                Some(original) => (*original).to_string(),
                None => matched.to_string(),
            }
        })
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn single_entity_substitute_and_restore() {
        let text = "Call John Smith tomorrow.";
        let spans = vec![span(PiiType::Person, 5, 15, "John Smith")];
        let (redacted, placeholders) = substitute(text, &spans);

        assert!(!redacted.contains("John Smith"));
        assert!(redacted.starts_with("Call [PERSON_"));
        assert_eq!(placeholders.len(), 1);
        assert_eq!(placeholders[0].original_text, "John Smith");

        let restored = restore(&redacted, &placeholders);
        assert_eq!(restored, text);
    }

    #[test]
    fn multiple_entities() {
        let text = "Email alice@example.com or call 555-1234.";
        let spans = vec![
            span(PiiType::Email, 6, 23, "alice@example.com"),
            span(PiiType::Phone, 32, 40, "555-1234"),
        ];
        let (redacted, placeholders) = substitute(text, &spans);

        assert!(!redacted.contains("alice@example.com"));
        assert!(!redacted.contains("555-1234"));
        assert_eq!(placeholders.len(), 2);

        let restored = restore(&redacted, &placeholders);
        assert_eq!(restored, text);
    }

    #[test]
    fn dedup_identical_entities() {
        let text = "Ask Alice about Alice.";
        let spans = vec![
            span(PiiType::Person, 4, 9, "Alice"),
            span(PiiType::Person, 16, 21, "Alice"),
        ];
        let (redacted, placeholders) = substitute(text, &spans);

        // Only one unique placeholder should be generated.
        assert_eq!(placeholders.len(), 1);

        // Both occurrences replaced with the same token.
        let token = &placeholders[0].placeholder_text;
        let count = redacted.matches(token.as_str()).count();
        assert_eq!(count, 2, "expected 2 occurrences of {token} in: {redacted}");

        let restored = restore(&redacted, &placeholders);
        assert_eq!(restored, text);
    }

    #[test]
    fn entity_with_brackets() {
        // Brackets in entity text should not break the engine.
        let text = "User [admin] logged in.";
        let spans = vec![span(PiiType::Person, 5, 12, "[admin]")];
        let (redacted, placeholders) = substitute(text, &spans);

        assert!(!redacted.contains("[admin]") || redacted.contains("[PERSON_"));
        assert_eq!(placeholders[0].original_text, "[admin]");

        let restored = restore(&redacted, &placeholders);
        assert_eq!(restored, text);
    }

    #[test]
    fn round_trip() {
        let text = "My SSN is 123-45-6789 and I work at Acme Corp.";
        let spans = vec![
            span(PiiType::Ssn, 10, 21, "123-45-6789"),
            span(PiiType::Organization, 36, 45, "Acme Corp"),
        ];
        let (redacted, placeholders) = substitute(text, &spans);

        assert!(!redacted.contains("123-45-6789"));
        assert!(!redacted.contains("Acme Corp"));

        let restored = restore(&redacted, &placeholders);
        assert_eq!(restored, text);
    }

    #[test]
    fn unknown_placeholder_left_as_is() {
        let text = "Hello [PERSON_deadbeef], how are you?";
        let restored = restore(text, &[]);
        assert_eq!(restored, text);
    }

    #[test]
    fn no_spans_returns_original() {
        let text = "Nothing to redact here.";
        let (redacted, placeholders) = substitute(text, &[]);
        assert_eq!(redacted, text);
        assert!(placeholders.is_empty());
    }
}
