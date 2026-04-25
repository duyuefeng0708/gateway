use std::collections::HashMap;
use std::time::Instant;

use gateway_common::types::Placeholder;
use regex::Regex;

/// Maximum buffer size before flushing as-is (not a placeholder).
const MAX_BUFFER_LEN: usize = 32;

/// Maximum time to hold a buffer before flushing as-is.
const BUFFER_TIMEOUT_MS: u128 = 500;

/// Processes streaming tokens and performs real-time deanonymization.
///
/// Tokens arrive one at a time from SSE chunks. When a `[` character is
/// encountered, the deanonymizer starts buffering because a placeholder
/// like `[PERSON_a7f3b2c1]` may be split across multiple tokens.
///
/// The buffer is flushed as-is when:
/// - It exceeds [`MAX_BUFFER_LEN`] characters without a closing `]`
/// - More than 500ms have elapsed since buffering started
/// - A nested `[[` is encountered (the outer buffer is flushed)
/// - A non-ASCII character appears in the buffer
///
/// When a closing `]` completes a valid placeholder, the original text is
/// looked up from the placeholder map and emitted in place of the token.
pub struct StreamingDeanonymizer {
    /// Lookup from placeholder text (e.g. `[PERSON_a7f3b2c1]`) to original.
    lookup: HashMap<String, String>,
    /// Compiled regex for validating placeholder format.
    placeholder_re: Regex,
    /// Accumulation buffer when inside a potential placeholder.
    buffer: String,
    /// When buffering started (for timeout detection).
    buffer_start: Option<Instant>,
}

impl StreamingDeanonymizer {
    /// Create a new deanonymizer from a list of placeholders.
    pub fn new(placeholders: Vec<Placeholder>) -> Self {
        let lookup: HashMap<String, String> = placeholders
            .into_iter()
            .map(|p| (p.placeholder_text, p.original_text))
            .collect();

        let placeholder_re =
            Regex::new(r"^\[(PERSON|ORG|EMAIL|LOCATION|PHONE|SSN|CREDENTIAL)_[a-f0-9]{8}\]$")
                .expect("hardcoded regex must compile");

        Self {
            lookup,
            placeholder_re,
            buffer: String::new(),
            buffer_start: None,
        }
    }

    /// Process a single incoming token and return zero or more output chunks.
    ///
    /// Most tokens pass through immediately. When a potential placeholder is
    /// being buffered, the token is accumulated and output is deferred until
    /// the placeholder is complete, the buffer overflows, or a timeout occurs.
    pub fn process_token(&mut self, token: &str) -> Vec<String> {
        let mut output = Vec::new();

        for ch in token.chars() {
            if self.buffer.is_empty() {
                // Not currently buffering.
                if ch == '[' {
                    // Start buffering a potential placeholder.
                    self.buffer.push(ch);
                    self.buffer_start = Some(Instant::now());
                } else {
                    // Pass through immediately.
                    output.push(ch.to_string());
                }
            } else {
                // Currently buffering.

                // Check for nested `[` -- flush outer buffer first.
                if ch == '[' {
                    // Flush current buffer as-is (not a placeholder).
                    output.push(self.take_buffer());
                    // Start new buffer for this `[`.
                    self.buffer.push(ch);
                    self.buffer_start = Some(Instant::now());
                    continue;
                }

                // Check for non-ASCII in buffer.
                if !ch.is_ascii() {
                    self.buffer.push(ch);
                    output.push(self.take_buffer());
                    continue;
                }

                self.buffer.push(ch);

                if ch == ']' {
                    // Potential end of placeholder -- check if it matches.
                    if self.placeholder_re.is_match(&self.buffer) {
                        // Valid placeholder -- look up the original text.
                        let buf = self.take_buffer();
                        if let Some(original) = self.lookup.get(&buf) {
                            output.push(original.clone());
                        } else {
                            // Unknown placeholder -- pass through as-is.
                            output.push(buf);
                        }
                    } else {
                        // Not a valid placeholder -- flush as-is.
                        output.push(self.take_buffer());
                    }
                } else if self.buffer.len() > MAX_BUFFER_LEN {
                    // Buffer too long -- flush as-is.
                    output.push(self.take_buffer());
                }
            }
        }

        // Check timeout on remaining buffer.
        if !self.buffer.is_empty() {
            if let Some(start) = self.buffer_start {
                if start.elapsed().as_millis() >= BUFFER_TIMEOUT_MS {
                    output.push(self.take_buffer());
                }
            }
        }

        output
    }

    /// Flush any remaining buffer content. Call this at the end of the stream.
    pub fn flush(&mut self) -> Option<String> {
        if self.buffer.is_empty() {
            None
        } else {
            Some(self.take_buffer())
        }
    }

    /// Take the buffer content and reset buffer state.
    fn take_buffer(&mut self) -> String {
        self.buffer_start = None;
        std::mem::take(&mut self.buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_common::types::PiiType;

    fn make_placeholder(pii_type: PiiType, id: &str, original: &str) -> Placeholder {
        Placeholder {
            id: id.to_string(),
            pii_type,
            placeholder_text: format!("[{}_{id}]", pii_type.placeholder_prefix()),
            original_text: original.to_string(),
        }
    }

    #[test]
    fn complete_placeholder_in_one_token() {
        let p = make_placeholder(PiiType::Person, "abc12345", "Alice");
        let mut d = StreamingDeanonymizer::new(vec![p]);

        let out = d.process_token("[PERSON_abc12345]");
        assert_eq!(out, vec!["Alice"]);
    }

    #[test]
    fn placeholder_split_across_tokens() {
        let p = make_placeholder(PiiType::Person, "abc12345", "Alice");
        let mut d = StreamingDeanonymizer::new(vec![p]);

        let out1 = d.process_token("[PER");
        assert!(out1.is_empty(), "should buffer partial placeholder");

        let out2 = d.process_token("SON_abc12345]");
        assert_eq!(out2, vec!["Alice"]);
    }

    #[test]
    fn no_placeholders_pass_through() {
        let mut d = StreamingDeanonymizer::new(vec![]);

        let out = d.process_token("Hello world");
        assert_eq!(out.join(""), "Hello world");
    }

    #[test]
    fn buffer_exceeds_max_length_flushed() {
        let mut d = StreamingDeanonymizer::new(vec![]);

        // Start with `[` then push more than 32 chars without `]`.
        let long_token = format!("[{}", "x".repeat(33));
        let out = d.process_token(&long_token);
        let combined = out.join("");
        assert_eq!(combined, long_token);
    }

    #[test]
    fn nested_bracket_flushes_outer() {
        let p = make_placeholder(PiiType::Email, "abc12345", "alice@test.com");
        let mut d = StreamingDeanonymizer::new(vec![p]);

        // First `[` starts buffer, second `[` flushes it and starts new.
        let out = d.process_token("[some[EMAIL_abc12345]");
        let combined = out.join("");
        assert_eq!(combined, "[somealice@test.com");
    }

    #[test]
    fn non_ascii_in_buffer_flushes() {
        let mut d = StreamingDeanonymizer::new(vec![]);

        let out = d.process_token("[hello\u{00e9}world");
        let combined = out.join("");
        assert_eq!(combined, "[hello\u{00e9}world");
    }

    #[test]
    fn flush_returns_remaining_buffer() {
        let mut d = StreamingDeanonymizer::new(vec![]);

        let out = d.process_token("[partial");
        assert!(out.is_empty());

        let flushed = d.flush();
        assert_eq!(flushed, Some("[partial".to_string()));
    }

    #[test]
    fn flush_returns_none_when_empty() {
        let mut d = StreamingDeanonymizer::new(vec![]);
        let _ = d.process_token("hello");
        assert_eq!(d.flush(), None);
    }

    #[test]
    fn multiple_placeholders_in_sequence() {
        let p1 = make_placeholder(PiiType::Person, "aaaa1111", "Alice");
        let p2 = make_placeholder(PiiType::Email, "bbbb2222", "alice@test.com");
        let mut d = StreamingDeanonymizer::new(vec![p1, p2]);

        let out = d.process_token("[PERSON_aaaa1111] sent email to [EMAIL_bbbb2222]");
        let combined = out.join("");
        assert_eq!(combined, "Alice sent email to alice@test.com");
    }

    #[test]
    fn unknown_placeholder_passes_through() {
        let mut d = StreamingDeanonymizer::new(vec![]);

        let out = d.process_token("[PERSON_deadbeef]");
        let combined = out.join("");
        assert_eq!(combined, "[PERSON_deadbeef]");
    }

    #[test]
    fn mixed_text_and_placeholders() {
        let p = make_placeholder(PiiType::Organization, "0fa12345", "Acme Corp");
        let mut d = StreamingDeanonymizer::new(vec![p]);

        let out = d.process_token("Contact [ORG_0fa12345] for details.");
        let combined = out.join("");
        assert_eq!(combined, "Contact Acme Corp for details.");
    }

    #[test]
    fn placeholder_split_three_tokens() {
        let p = make_placeholder(PiiType::Ssn, "de0f1234", "123-45-6789");
        let mut d = StreamingDeanonymizer::new(vec![p]);

        let out1 = d.process_token("[SS");
        assert!(out1.is_empty());

        let out2 = d.process_token("N_de0f");
        assert!(out2.is_empty());

        let out3 = d.process_token("1234]");
        assert_eq!(out3, vec!["123-45-6789"]);
    }

    #[test]
    fn invalid_bracket_content_flushed_on_close() {
        let mut d = StreamingDeanonymizer::new(vec![]);

        let out = d.process_token("[not_a_placeholder]");
        let combined = out.join("");
        assert_eq!(combined, "[not_a_placeholder]");
    }
}
