use async_trait::async_trait;
use gateway_common::errors::DetectionError;
use gateway_common::types::{PiiSpan, PiiType};
use regex::Regex;

use crate::detector::PiiDetector;

/// Pattern-based PII detector using compiled regular expressions.
///
/// Detects: email addresses, SSNs, phone numbers, API keys/tokens, and
/// URLs that embed credentials. Every match is reported with confidence 1.0
/// and implicit=false (regex matches are always explicit surface patterns).
pub struct RegexDetector {
    email: Regex,
    ssn: Regex,
    phone: Regex,
    api_key: Regex,
    url_credentials: Regex,
}

impl RegexDetector {
    pub fn new() -> Self {
        Self {
            email: Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap(),
            ssn: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
            phone: Regex::new(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b").unwrap(),
            api_key: Regex::new(r"\b(?:sk|pk|api|token|key|secret|bearer)[-_][a-zA-Z0-9_\-]{8,}\b")
                .unwrap(),
            url_credentials: Regex::new(
                r"https?://[a-zA-Z0-9._%+-]+:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\s]*",
            )
            .unwrap(),
        }
    }

    fn scan_pattern(
        &self,
        text: &str,
        pattern: &Regex,
        pii_type: PiiType,
        results: &mut Vec<PiiSpan>,
    ) {
        for m in pattern.find_iter(text) {
            results.push(PiiSpan {
                pii_type,
                start: m.start(),
                end: m.end(),
                text: m.as_str().to_string(),
                confidence: 1.0,
                implicit: false,
            });
        }
    }
}

impl Default for RegexDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PiiDetector for RegexDetector {
    async fn detect(&self, text: &str) -> Result<Vec<PiiSpan>, DetectionError> {
        let mut results = Vec::new();

        // Scan URL credentials first -- they take priority over email
        // matches that happen to overlap (the user:pass@host pattern
        // contains an @ that the email regex would also match).
        self.scan_pattern(
            text,
            &self.url_credentials,
            PiiType::Credential,
            &mut results,
        );
        self.scan_pattern(text, &self.email, PiiType::Email, &mut results);
        self.scan_pattern(text, &self.ssn, PiiType::Ssn, &mut results);
        self.scan_pattern(text, &self.phone, PiiType::Phone, &mut results);
        self.scan_pattern(text, &self.api_key, PiiType::Credential, &mut results);

        // Sort by start offset for deterministic output.
        results.sort_by_key(|s| s.start);

        // Remove spans fully contained inside a wider span (e.g. an email
        // match inside a URL-credential match).
        let mut deduped: Vec<PiiSpan> = Vec::with_capacity(results.len());
        for span in results {
            let dominated = deduped
                .iter()
                .any(|existing| existing.start <= span.start && span.end <= existing.end);
            if !dominated {
                deduped.push(span);
            }
        }

        Ok(deduped)
    }

    fn name(&self) -> &str {
        "regex"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect_blocking(text: &str) -> Vec<PiiSpan> {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let detector = RegexDetector::new();
        rt.block_on(detector.detect(text)).unwrap()
    }

    #[test]
    fn detects_email() {
        let spans = detect_blocking("Contact alice@example.com for info.");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].pii_type, PiiType::Email);
        assert_eq!(spans[0].text, "alice@example.com");
        assert_eq!(spans[0].confidence, 1.0);
        assert!(!spans[0].implicit);
    }

    #[test]
    fn detects_ssn() {
        let spans = detect_blocking("My SSN is 123-45-6789.");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].pii_type, PiiType::Ssn);
        assert_eq!(spans[0].text, "123-45-6789");
    }

    #[test]
    fn detects_phone() {
        let spans = detect_blocking("Call me at (555) 123-4567.");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].pii_type, PiiType::Phone);
    }

    #[test]
    fn detects_api_key() {
        let spans = detect_blocking("Use key sk-abc12345defg to authenticate.");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].pii_type, PiiType::Credential);
        assert_eq!(spans[0].text, "sk-abc12345defg");
    }

    #[test]
    fn detects_url_with_credentials() {
        let spans = detect_blocking("Connect to https://admin:p4ssw0rd@db.example.com/data");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].pii_type, PiiType::Credential);
        assert!(spans[0].text.contains("admin:p4ssw0rd"));
    }

    #[test]
    fn clean_text_returns_empty() {
        let spans = detect_blocking("The weather in Paris is nice today.");
        assert!(spans.is_empty());
    }

    #[test]
    fn multiple_pii_sorted_by_offset() {
        let text = "Email alice@example.com, SSN 123-45-6789, key sk-longtoken99xyz";
        let spans = detect_blocking(text);
        assert!(spans.len() >= 3);
        for window in spans.windows(2) {
            assert!(window[0].start <= window[1].start);
        }
    }
}
