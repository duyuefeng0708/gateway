use gateway_common::errors::GatewayError;
use serde_json::Value;

/// Supported API request/response formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiFormat {
    Anthropic,
    OpenAi,
}

/// Detect the API format based on the request URI path.
///
/// `/v1/chat/completions` maps to OpenAI; everything else defaults to Anthropic.
pub fn detect_format(path: &str) -> ApiFormat {
    if path.trim_end_matches('/') == "/v1/chat/completions" {
        ApiFormat::OpenAi
    } else {
        ApiFormat::Anthropic
    }
}

/// Extract the content strings from message objects in the JSON body.
///
/// Returns `(index, content_string)` pairs that can later be passed to
/// [`rebuild_body`] after anonymization.
///
/// Both Anthropic and OpenAI formats store user messages under
/// `body["messages"][i]["content"]` as a plain string, but the response
/// structures differ. This function handles the request side.
pub fn extract_messages(body: &Value, format: ApiFormat) -> Result<Vec<(usize, String)>, GatewayError> {
    let messages = body
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(|| GatewayError::BadRequest("missing or invalid 'messages' array".into()))?;

    let mut contents = Vec::new();
    for (idx, msg) in messages.iter().enumerate() {
        match format {
            ApiFormat::Anthropic | ApiFormat::OpenAi => {
                if let Some(content) = msg.get("content").and_then(Value::as_str) {
                    contents.push((idx, content.to_string()));
                }
            }
        }
    }
    Ok(contents)
}

/// Replace message content strings in the JSON body with anonymized versions.
pub fn rebuild_body(
    body: &mut Value,
    messages: &[(usize, String)],
    _format: ApiFormat,
) -> Result<(), GatewayError> {
    let msgs = body
        .get_mut("messages")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| GatewayError::Internal("messages array disappeared".into()))?;

    for (idx, new_content) in messages {
        if let Some(msg) = msgs.get_mut(*idx) {
            msg["content"] = Value::String(new_content.clone());
        }
    }
    Ok(())
}

/// Extract the assistant's response text from the upstream response body.
///
/// - Anthropic: `body["content"][0]["text"]`
/// - OpenAI:    `body["choices"][0]["message"]["content"]`
pub fn extract_response_content(body: &str, format: ApiFormat) -> Option<String> {
    let parsed: Value = serde_json::from_str(body).ok()?;
    match format {
        ApiFormat::Anthropic => parsed
            .get("content")
            .and_then(Value::as_array)
            .and_then(|arr| arr.first())
            .and_then(|block| block.get("text"))
            .and_then(Value::as_str)
            .map(String::from),
        ApiFormat::OpenAi => parsed
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|arr| arr.first())
            .and_then(|choice| choice.get("message"))
            .and_then(|msg| msg.get("content"))
            .and_then(Value::as_str)
            .map(String::from),
    }
}

/// Replace the assistant's response content with deanonymized text.
///
/// Returns the full response body string with the content field updated.
/// Falls back to a simple string replacement when the body is not valid JSON
/// or does not contain the expected structure.
pub fn rebuild_response(body: &str, deanonymized: &str, format: ApiFormat) -> String {
    let parsed: Result<Value, _> = serde_json::from_str(body);
    match parsed {
        Ok(mut value) => {
            let replaced = match format {
                ApiFormat::Anthropic => {
                    if let Some(arr) = value.get_mut("content").and_then(Value::as_array_mut) {
                        if let Some(block) = arr.first_mut() {
                            if block.get("text").is_some() {
                                block["text"] = Value::String(deanonymized.to_string());
                                true
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                ApiFormat::OpenAi => {
                    if let Some(arr) = value.get_mut("choices").and_then(Value::as_array_mut) {
                        if let Some(choice) = arr.first_mut() {
                            if let Some(msg) = choice.get_mut("message") {
                                if msg.get("content").is_some() {
                                    msg["content"] = Value::String(deanonymized.to_string());
                                    true
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
            };
            if replaced {
                serde_json::to_string(&value).unwrap_or_else(|_| body.to_string())
            } else {
                body.to_string()
            }
        }
        Err(_) => body.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -- detect_format ---------------------------------------------------------

    #[test]
    fn detect_format_openai_path() {
        assert_eq!(detect_format("/v1/chat/completions"), ApiFormat::OpenAi);
    }

    #[test]
    fn detect_format_openai_path_trailing_slash() {
        assert_eq!(detect_format("/v1/chat/completions/"), ApiFormat::OpenAi);
    }

    #[test]
    fn detect_format_anthropic_messages() {
        assert_eq!(detect_format("/v1/messages"), ApiFormat::Anthropic);
    }

    #[test]
    fn detect_format_unknown_defaults_to_anthropic() {
        assert_eq!(detect_format("/something/else"), ApiFormat::Anthropic);
    }

    // -- extract_messages (Anthropic) ------------------------------------------

    #[test]
    fn extract_anthropic_messages() {
        let body = json!({
            "messages": [
                {"role": "user", "content": "Hello, Alice!"},
                {"role": "assistant", "content": "Hi there."}
            ]
        });
        let result = extract_messages(&body, ApiFormat::Anthropic).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], (0, "Hello, Alice!".to_string()));
        assert_eq!(result[1], (1, "Hi there.".to_string()));
    }

    #[test]
    fn extract_anthropic_missing_messages() {
        let body = json!({"model": "claude-3"});
        let result = extract_messages(&body, ApiFormat::Anthropic);
        assert!(result.is_err());
    }

    // -- extract_messages (OpenAI) ---------------------------------------------

    #[test]
    fn extract_openai_messages() {
        let body = json!({
            "model": "gpt-4",
            "messages": [
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": "Email bob@example.com."}
            ]
        });
        let result = extract_messages(&body, ApiFormat::OpenAi).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], (0, "You are helpful.".to_string()));
        assert_eq!(result[1], (1, "Email bob@example.com.".to_string()));
    }

    // -- rebuild_body ----------------------------------------------------------

    #[test]
    fn rebuild_anthropic_body() {
        let mut body = json!({
            "messages": [
                {"role": "user", "content": "Hi Alice"},
                {"role": "assistant", "content": "Hello"}
            ]
        });
        let anonymized = vec![(0, "[PERSON_abc12345] greeting".to_string())];
        rebuild_body(&mut body, &anonymized, ApiFormat::Anthropic).unwrap();
        assert_eq!(
            body["messages"][0]["content"].as_str().unwrap(),
            "[PERSON_abc12345] greeting"
        );
        // Unmodified message stays the same.
        assert_eq!(
            body["messages"][1]["content"].as_str().unwrap(),
            "Hello"
        );
    }

    #[test]
    fn rebuild_openai_body() {
        let mut body = json!({
            "model": "gpt-4",
            "messages": [
                {"role": "system", "content": "Be helpful."},
                {"role": "user", "content": "Contact alice@example.com"}
            ]
        });
        let anonymized = vec![(1, "Contact [EMAIL_abc12345]".to_string())];
        rebuild_body(&mut body, &anonymized, ApiFormat::OpenAi).unwrap();
        assert_eq!(
            body["messages"][1]["content"].as_str().unwrap(),
            "Contact [EMAIL_abc12345]"
        );
        assert_eq!(
            body["messages"][0]["content"].as_str().unwrap(),
            "Be helpful."
        );
    }

    // -- extract_response_content ----------------------------------------------

    #[test]
    fn extract_anthropic_response() {
        let body = r#"{"content":[{"type":"text","text":"Hello from Claude!"}]}"#;
        let result = extract_response_content(body, ApiFormat::Anthropic);
        assert_eq!(result.unwrap(), "Hello from Claude!");
    }

    #[test]
    fn extract_openai_response() {
        let body = r#"{"choices":[{"index":0,"message":{"role":"assistant","content":"Hello from GPT!"}}]}"#;
        let result = extract_response_content(body, ApiFormat::OpenAi);
        assert_eq!(result.unwrap(), "Hello from GPT!");
    }

    #[test]
    fn extract_response_invalid_json() {
        let result = extract_response_content("not json", ApiFormat::Anthropic);
        assert!(result.is_none());
    }

    // -- rebuild_response ------------------------------------------------------

    #[test]
    fn rebuild_anthropic_response() {
        let body = r#"{"content":[{"type":"text","text":"Hello [EMAIL_abc12345]!"}]}"#;
        let result = rebuild_response(body, "Hello alice@example.com!", ApiFormat::Anthropic);
        let parsed: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(
            parsed["content"][0]["text"].as_str().unwrap(),
            "Hello alice@example.com!"
        );
    }

    #[test]
    fn rebuild_openai_response() {
        let body = r#"{"choices":[{"index":0,"message":{"role":"assistant","content":"Hello [EMAIL_abc12345]!"}}]}"#;
        let result = rebuild_response(body, "Hello alice@example.com!", ApiFormat::OpenAi);
        let parsed: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(
            parsed["choices"][0]["message"]["content"].as_str().unwrap(),
            "Hello alice@example.com!"
        );
    }

    #[test]
    fn rebuild_response_invalid_json_passthrough() {
        let body = "not json at all";
        let result = rebuild_response(body, "ignored", ApiFormat::Anthropic);
        assert_eq!(result, body);
    }
}
