use crate::types::ScanMode;
use std::env;
use std::time::Duration;

/// Gateway configuration parsed from environment variables.
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub listen_addr: String,
    pub upstream_url: String,
    pub fast_model: String,
    pub deep_model: String,
    pub ollama_url: String,
    pub scan_mode: ScanMode,
    pub db_path: String,
    pub session_ttl: Duration,
    pub audit_retention_days: u32,
    pub audit_path: String,
    pub log_level: String,
    pub show_score: bool,
    pub max_request_size: usize,
    pub model_timeout: Duration,
    pub escalation_confidence_threshold: f64,
    pub escalation_min_prompt_tokens: usize,
}

impl GatewayConfig {
    pub fn from_env() -> Result<Self, String> {
        // API key is required for upstream forwarding
        if env::var("ANTHROPIC_API_KEY").is_err() && env::var("OPENAI_API_KEY").is_err() {
            return Err(
                "at least one of ANTHROPIC_API_KEY or OPENAI_API_KEY must be set".into(),
            );
        }

        Ok(Self {
            listen_addr: env_or("GATEWAY_LISTEN", "127.0.0.1:8443"),
            upstream_url: env_or("GATEWAY_UPSTREAM", "https://api.anthropic.com"),
            fast_model: env_or("GATEWAY_FAST_MODEL", "MTBS/anonymizer"),
            deep_model: env_or(
                "GATEWAY_DEEP_MODEL",
                "qwen3.5-27b-claude-distilled",
            ),
            ollama_url: env_or("GATEWAY_OLLAMA_URL", "http://localhost:11434"),
            scan_mode: env_or("GATEWAY_SCAN_MODE", "fast")
                .parse()
                .map_err(|e: String| e)?,
            db_path: env_or("GATEWAY_DB_PATH", "./data/sessions.db"),
            session_ttl: parse_duration(&env_or("GATEWAY_SESSION_TTL", "24h"))?,
            audit_retention_days: env_or("GATEWAY_AUDIT_RETENTION", "30")
                .trim_end_matches('d')
                .parse()
                .map_err(|e| format!("invalid GATEWAY_AUDIT_RETENTION: {e}"))?,
            audit_path: env_or("GATEWAY_AUDIT_PATH", "./data/audit/"),
            log_level: env_or("GATEWAY_LOG_LEVEL", "info"),
            show_score: env_or("GATEWAY_SHOW_SCORE", "true")
                .parse()
                .unwrap_or(true),
            max_request_size: 128 * 1024, // 128KB
            model_timeout: Duration::from_secs(8),
            escalation_confidence_threshold: 0.7,
            escalation_min_prompt_tokens: 200,
        })
    }
}

fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if let Some(hours) = s.strip_suffix('h') {
        let h: u64 = hours.parse().map_err(|e| format!("invalid duration: {e}"))?;
        Ok(Duration::from_secs(h * 3600))
    } else if let Some(days) = s.strip_suffix('d') {
        let d: u64 = days.parse().map_err(|e| format!("invalid duration: {e}"))?;
        Ok(Duration::from_secs(d * 86400))
    } else {
        let secs: u64 = s.parse().map_err(|e| format!("invalid duration: {e}"))?;
        Ok(Duration::from_secs(secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_hours() {
        assert_eq!(parse_duration("24h").unwrap(), Duration::from_secs(86400));
    }

    #[test]
    fn parse_duration_days() {
        assert_eq!(parse_duration("7d").unwrap(), Duration::from_secs(604800));
    }

    #[test]
    fn parse_duration_seconds() {
        assert_eq!(parse_duration("3600").unwrap(), Duration::from_secs(3600));
    }

    #[test]
    fn parse_duration_invalid() {
        assert!(parse_duration("abc").is_err());
    }

    #[test]
    fn config_requires_api_key() {
        // Clear any existing keys
        env::remove_var("ANTHROPIC_API_KEY");
        env::remove_var("OPENAI_API_KEY");
        let result = GatewayConfig::from_env();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("API_KEY"));
    }

    #[test]
    fn config_parses_with_defaults() {
        env::set_var("ANTHROPIC_API_KEY", "test-key");
        let config = GatewayConfig::from_env().unwrap();
        assert_eq!(config.listen_addr, "127.0.0.1:8443");
        assert_eq!(config.upstream_url, "https://api.anthropic.com");
        assert_eq!(config.fast_model, "MTBS/anonymizer");
        assert_eq!(config.scan_mode, ScanMode::Fast);
        assert!(config.show_score);
        env::remove_var("ANTHROPIC_API_KEY");
    }
}
