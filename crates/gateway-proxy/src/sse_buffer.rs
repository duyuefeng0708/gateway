/// Line-buffered SSE event accumulator.
///
/// TCP delivers bytes at arbitrary boundaries. An SSE event like
/// `data: {"delta":"[PERSON_abc12345]"}\n\n` may arrive split across
/// multiple TCP frames. This buffer accumulates raw bytes and emits
/// complete SSE events (delimited by `\n\n`) only when they are fully
/// received. Incomplete UTF-8 sequences at chunk boundaries are held
/// until the next chunk completes them.

pub struct SseLineBuffer {
    /// Raw byte accumulator. May contain incomplete UTF-8 at the tail.
    buf: Vec<u8>,
}

impl SseLineBuffer {
    pub fn new() -> Self {
        Self { buf: Vec::with_capacity(4096) }
    }

    /// Push a chunk of bytes from the network. Returns any complete SSE
    /// events (each ending with `\n\n`) that can now be emitted.
    ///
    /// Returned strings are guaranteed to be valid UTF-8 and to end with
    /// `\n\n`. Partial events and incomplete UTF-8 remain in the buffer.
    pub fn push_bytes(&mut self, chunk: &[u8]) -> Vec<String> {
        self.buf.extend_from_slice(chunk);

        let mut events = Vec::new();
        loop {
            // Scan for the SSE event boundary: \n\n
            let boundary = self.find_double_newline();
            match boundary {
                Some(end_pos) => {
                    // end_pos points to the first byte AFTER the second \n.
                    let event_bytes: Vec<u8> = self.buf.drain(..end_pos).collect();

                    // Validate UTF-8. If invalid (should be rare for SSE),
                    // use lossy conversion rather than dropping the event.
                    let event_str = String::from_utf8(event_bytes)
                        .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());

                    events.push(event_str);
                }
                None => break,
            }
        }

        events
    }

    /// Flush any remaining data in the buffer (call at stream end).
    /// Returns None if the buffer is empty.
    pub fn flush(&mut self) -> Option<String> {
        if self.buf.is_empty() {
            return None;
        }
        let remaining: Vec<u8> = self.buf.drain(..).collect();
        let s = String::from_utf8(remaining)
            .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }

    /// Find the position just after a `\n\n` boundary in the buffer.
    fn find_double_newline(&self) -> Option<usize> {
        for i in 0..self.buf.len().saturating_sub(1) {
            if self.buf[i] == b'\n' && self.buf[i + 1] == b'\n' {
                return Some(i + 2);
            }
        }
        None
    }
}

impl Default for SseLineBuffer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_event_in_one_chunk() {
        let mut buf = SseLineBuffer::new();
        let events = buf.push_bytes(b"data: {\"text\":\"hello\"}\n\n");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], "data: {\"text\":\"hello\"}\n\n");
    }

    #[test]
    fn two_events_in_one_chunk() {
        let mut buf = SseLineBuffer::new();
        let events = buf.push_bytes(b"data: first\n\ndata: second\n\n");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0], "data: first\n\n");
        assert_eq!(events[1], "data: second\n\n");
    }

    #[test]
    fn event_split_across_two_chunks() {
        let mut buf = SseLineBuffer::new();

        let events1 = buf.push_bytes(b"data: {\"del");
        assert!(events1.is_empty(), "partial event should not be emitted");

        let events2 = buf.push_bytes(b"ta\":\"text\"}\n\n");
        assert_eq!(events2.len(), 1);
        assert_eq!(events2[0], "data: {\"delta\":\"text\"}\n\n");
    }

    #[test]
    fn event_split_across_three_chunks() {
        let mut buf = SseLineBuffer::new();

        assert!(buf.push_bytes(b"data: ").is_empty());
        assert!(buf.push_bytes(b"[PERSON_abc1").is_empty());

        let events = buf.push_bytes(b"2345]\n\n");
        assert_eq!(events.len(), 1);
        assert!(events[0].contains("[PERSON_abc12345]"));
    }

    #[test]
    fn split_at_double_newline_boundary() {
        let mut buf = SseLineBuffer::new();

        // First chunk ends with the first \n
        assert!(buf.push_bytes(b"data: hello\n").is_empty());

        // Second chunk starts with the second \n
        let events = buf.push_bytes(b"\n");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], "data: hello\n\n");
    }

    #[test]
    fn empty_chunk_produces_no_output() {
        let mut buf = SseLineBuffer::new();
        let events = buf.push_bytes(b"");
        assert!(events.is_empty());
    }

    #[test]
    fn flush_returns_remaining_data() {
        let mut buf = SseLineBuffer::new();
        buf.push_bytes(b"data: partial");
        let remaining = buf.flush();
        assert_eq!(remaining, Some("data: partial".to_string()));
    }

    #[test]
    fn flush_empty_buffer_returns_none() {
        let mut buf = SseLineBuffer::new();
        assert_eq!(buf.flush(), None);
    }

    #[test]
    fn utf8_multibyte_split_at_boundary() {
        let mut buf = SseLineBuffer::new();
        // "é" is 0xC3 0xA9 in UTF-8. Split between the two bytes.
        let events1 = buf.push_bytes(&[b'd', b'a', b't', b'a', b':', b' ', 0xC3]);
        assert!(events1.is_empty());

        let events2 = buf.push_bytes(&[0xA9, b'\n', b'\n']);
        assert_eq!(events2.len(), 1);
        assert!(events2[0].contains("é"));
    }

    #[test]
    fn large_event_no_size_limit() {
        let mut buf = SseLineBuffer::new();
        let large_data = "x".repeat(100_000);
        let event = format!("data: {large_data}\n\n");
        let events = buf.push_bytes(event.as_bytes());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].len(), event.len());
    }

    #[test]
    fn interleaved_events_and_partials() {
        let mut buf = SseLineBuffer::new();

        // Complete event + start of another
        let events = buf.push_bytes(b"data: first\n\ndata: sec");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], "data: first\n\n");

        // Finish the second + complete third
        let events = buf.push_bytes(b"ond\n\ndata: third\n\n");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0], "data: second\n\n");
        assert_eq!(events[1], "data: third\n\n");
    }
}
