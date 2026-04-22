use std::collections::HashMap;

use gateway_common::types::{Placeholder, PiiSpan};
use regex::Regex;

/// Replace PII spans in `text` with UUID-based placeholders.
///
/// Spans are processed in reverse order so that earlier byte offsets remain
/// valid after each substitution. If the same entity text appears more than
/// once, the same placeholder is reused (deduplication).
///
/// The 4B fast detector sometimes emits offsets that don't land on UTF-8
/// char boundaries or don't match `span.text`. Before applying a span we:
///   1. Verify `text.is_char_boundary(start) && text.is_char_boundary(end)`.
///   2. Verify `text[start..end] == span.text`.
///   3. If either check fails, search for `span.text` in the original text
///      and accept the first match that doesn't overlap any range already
///      claimed by an earlier (valid) span.
///   4. If no non-overlapping match exists, log at warn and skip the span.
///
/// Returns the redacted text together with the generated placeholders.
pub fn substitute(text: &str, spans: &[PiiSpan]) -> (String, Vec<Placeholder>) {
    // Pre-validate every span so we can compute the set of claimed ranges
    // before any fallback searches run. Otherwise, a valid span that appears
    // later in `spans` could lose its byte range to an earlier span's fallback.
    let mut resolved: Vec<(usize, usize, &PiiSpan)> = Vec::with_capacity(spans.len());
    let mut claimed: Vec<(usize, usize)> = Vec::with_capacity(spans.len());

    // Pass 1: accept spans whose offsets are valid and whose text matches.
    let mut needs_fallback: Vec<&PiiSpan> = Vec::new();
    for span in spans {
        if offsets_valid(text, span) {
            resolved.push((span.start, span.end, span));
            claimed.push((span.start, span.end));
        } else {
            needs_fallback.push(span);
        }
    }

    // Pass 2: for spans with bad offsets, search for `span.text` and accept
    // the first occurrence that doesn't overlap an already-claimed range.
    for span in needs_fallback {
        if span.text.is_empty() {
            tracing::warn!(
                "placeholder substitute: bad offsets and no unambiguous text match, skipping span: type={:?}, text={:?}",
                span.pii_type,
                span.text,
            );
            continue;
        }
        match find_non_overlapping(text, &span.text, &claimed) {
            Some((s, e)) => {
                resolved.push((s, e, span));
                claimed.push((s, e));
            }
            None => {
                tracing::warn!(
                    "placeholder substitute: bad offsets and no unambiguous text match, skipping span: type={:?}, text={:?}",
                    span.pii_type,
                    span.text,
                );
            }
        }
    }

    // Sort resolved spans by start position descending so replacements don't
    // shift earlier offsets.
    resolved.sort_by_key(|r| std::cmp::Reverse(r.0));

    // Dedup map: original_text -> Placeholder
    let mut dedup: HashMap<String, Placeholder> = HashMap::new();
    let mut result = text.to_string();

    for (start, end, span) in &resolved {
        let original = &span.text;
        let placeholder = dedup
            .entry(original.clone())
            .or_insert_with(|| Placeholder::new(span.pii_type, original.clone()));

        result.replace_range(*start..*end, &placeholder.placeholder_text);
    }

    let placeholders: Vec<Placeholder> = dedup.into_values().collect();
    (result, placeholders)
}

/// True if the span's byte offsets land on char boundaries, are in-range,
/// and the slice `text[start..end]` equals `span.text`.
fn offsets_valid(text: &str, span: &PiiSpan) -> bool {
    let start = span.start;
    let end = span.end;
    if start > end || end > text.len() {
        return false;
    }
    if !text.is_char_boundary(start) || !text.is_char_boundary(end) {
        return false;
    }
    &text[start..end] == span.text.as_str()
}

/// Find the first occurrence of `needle` in `haystack` whose byte range does
/// not overlap any range in `claimed`. Adjacent ranges (touching endpoints)
/// do not count as overlap.
fn find_non_overlapping(
    haystack: &str,
    needle: &str,
    claimed: &[(usize, usize)],
) -> Option<(usize, usize)> {
    let mut search_from = 0;
    while search_from <= haystack.len() {
        let rel = haystack[search_from..].find(needle)?;
        let start = search_from + rel;
        let end = start + needle.len();
        let overlaps = claimed
            .iter()
            .any(|&(cs, ce)| start < ce && cs < end);
        if !overlaps {
            return Some((start, end));
        }
        // Advance past this match's start; step forward until we land on a
        // char boundary so the next slice is valid.
        let mut next = start + 1;
        while next < haystack.len() && !haystack.is_char_boundary(next) {
            next += 1;
        }
        search_from = next;
    }
    None
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
