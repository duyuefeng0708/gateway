use std::path::Path;

use serde::Deserialize;
use tracing::warn;

use crate::format::ApiFormat;

// ---------------------------------------------------------------------------
// Configuration types (YAML-loadable)
// ---------------------------------------------------------------------------

/// Top-level routing configuration loaded from YAML.
#[derive(Debug, Clone, Deserialize)]
pub struct RoutingConfig {
    pub routes: Vec<RouteEntry>,
}

/// A single route entry in the routing config.
#[derive(Debug, Clone, Deserialize)]
pub struct RouteEntry {
    pub name: String,
    pub score_min: u32,
    pub score_max: u32,
    pub upstream_url: String,
    pub api_format: String,
    pub api_key_env: String,
}

// ---------------------------------------------------------------------------
// Route target (returned by select)
// ---------------------------------------------------------------------------

/// The resolved target for a request based on its privacy score.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteTarget {
    pub upstream_url: String,
    pub api_format: ApiFormat,
    pub api_key_env: String,
    pub route_name: String,
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Routes requests to different upstream providers based on privacy score.
///
/// When no routing config is loaded (the default), every request uses the
/// upstream URL from `GatewayConfig`, preserving backward compatibility.
#[derive(Debug, Clone)]
pub struct Router {
    routes: Vec<ResolvedRoute>,
}

#[derive(Debug, Clone)]
struct ResolvedRoute {
    name: String,
    score_min: u32,
    score_max: u32,
    upstream_url: String,
    api_format: ApiFormat,
    api_key_env: String,
}

impl Router {
    /// Create a default router with no routing rules.
    ///
    /// `select()` will always return `None`, signaling the caller to fall
    /// back to the default upstream from `GatewayConfig`.
    pub fn default_router() -> Self {
        Self { routes: Vec::new() }
    }

    /// Load routing configuration from a YAML file.
    ///
    /// Returns an error if the file cannot be read, parsed, or contains
    /// overlapping score ranges.
    pub fn from_yaml_file(path: &str) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read routing config {path}: {e}"))?;
        Self::from_yaml(&content)
    }

    /// Parse routing configuration from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, String> {
        let config: RoutingConfig =
            serde_yaml::from_str(yaml).map_err(|e| format!("invalid routing YAML: {e}"))?;
        Self::from_config(config)
    }

    /// Build a router from a parsed configuration, validating constraints.
    pub fn from_config(config: RoutingConfig) -> Result<Self, String> {
        let mut routes = Vec::with_capacity(config.routes.len());

        for entry in &config.routes {
            if entry.score_min > entry.score_max {
                return Err(format!(
                    "route '{}': score_min ({}) > score_max ({})",
                    entry.name, entry.score_min, entry.score_max
                ));
            }
            if entry.score_max > 100 {
                return Err(format!(
                    "route '{}': score_max ({}) exceeds 100",
                    entry.name, entry.score_max
                ));
            }

            let api_format = parse_api_format(&entry.api_format)?;

            routes.push(ResolvedRoute {
                name: entry.name.clone(),
                score_min: entry.score_min,
                score_max: entry.score_max,
                upstream_url: entry.upstream_url.clone(),
                api_format,
                api_key_env: entry.api_key_env.clone(),
            });
        }

        // Validate no overlapping score ranges.
        for i in 0..routes.len() {
            for j in (i + 1)..routes.len() {
                let a = &routes[i];
                let b = &routes[j];
                if a.score_min <= b.score_max && b.score_min <= a.score_max {
                    return Err(format!(
                        "overlapping score ranges: '{}' [{}-{}] and '{}' [{}-{}]",
                        a.name, a.score_min, a.score_max, b.name, b.score_min, b.score_max
                    ));
                }
            }
        }

        Ok(Self { routes })
    }

    /// Try to load routing config from a file path. If the file does not
    /// exist, log a warning and return a default (no-routing) router.
    pub fn load_or_default(path: &str) -> Self {
        if !Path::new(path).exists() {
            warn!(
                path = %path,
                "routing config file not found, using default (no routing)"
            );
            return Self::default_router();
        }
        match Self::from_yaml_file(path) {
            Ok(router) => router,
            Err(e) => {
                warn!(
                    error = %e,
                    "failed to load routing config, using default (no routing)"
                );
                Self::default_router()
            }
        }
    }

    /// Select a route target for the given privacy score.
    ///
    /// Returns `None` when no routing rules are configured (default mode)
    /// or when no route matches the score, allowing the caller to fall back
    /// to the default upstream.
    pub fn select(&self, score: u32) -> Option<RouteTarget> {
        self.routes.iter().find_map(|r| {
            if score >= r.score_min && score <= r.score_max {
                Some(RouteTarget {
                    upstream_url: r.upstream_url.clone(),
                    api_format: r.api_format,
                    api_key_env: r.api_key_env.clone(),
                    route_name: r.name.clone(),
                })
            } else {
                None
            }
        })
    }

    /// Returns `true` if this router has routing rules configured.
    pub fn has_routes(&self) -> bool {
        !self.routes.is_empty()
    }
}

fn parse_api_format(s: &str) -> Result<ApiFormat, String> {
    match s.to_lowercase().as_str() {
        "anthropic" => Ok(ApiFormat::Anthropic),
        "openai" => Ok(ApiFormat::OpenAi),
        other => Err(format!(
            "unknown api_format '{other}': expected 'anthropic' or 'openai'"
        )),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_yaml() -> &'static str {
        r#"
routes:
  - name: "direct"
    score_min: 90
    score_max: 100
    upstream_url: "https://api.anthropic.com"
    api_format: "anthropic"
    api_key_env: "ANTHROPIC_API_KEY"
  - name: "anonymized-primary"
    score_min: 50
    score_max: 89
    upstream_url: "https://api.anthropic.com"
    api_format: "anthropic"
    api_key_env: "ANTHROPIC_API_KEY"
  - name: "anonymized-cheap"
    score_min: 0
    score_max: 49
    upstream_url: "https://api.openai.com"
    api_format: "openai"
    api_key_env: "OPENAI_API_KEY"
"#
    }

    #[test]
    fn parse_sample_config() {
        let router = Router::from_yaml(sample_yaml()).unwrap();
        assert_eq!(router.routes.len(), 3);
        assert!(router.has_routes());
    }

    #[test]
    fn select_direct_route_high_score() {
        let router = Router::from_yaml(sample_yaml()).unwrap();
        let target = router.select(95).unwrap();
        assert_eq!(target.route_name, "direct");
        assert_eq!(target.api_format, ApiFormat::Anthropic);
        assert_eq!(target.api_key_env, "ANTHROPIC_API_KEY");
    }

    #[test]
    fn select_cheap_route_low_score() {
        let router = Router::from_yaml(sample_yaml()).unwrap();
        let target = router.select(40).unwrap();
        assert_eq!(target.route_name, "anonymized-cheap");
        assert_eq!(target.api_format, ApiFormat::OpenAi);
        assert_eq!(target.api_key_env, "OPENAI_API_KEY");
    }

    #[test]
    fn select_boundary_score_50() {
        let router = Router::from_yaml(sample_yaml()).unwrap();
        let target = router.select(50).unwrap();
        assert_eq!(target.route_name, "anonymized-primary");
    }

    #[test]
    fn select_boundary_score_89() {
        let router = Router::from_yaml(sample_yaml()).unwrap();
        let target = router.select(89).unwrap();
        assert_eq!(target.route_name, "anonymized-primary");
    }

    #[test]
    fn select_boundary_score_90() {
        let router = Router::from_yaml(sample_yaml()).unwrap();
        let target = router.select(90).unwrap();
        assert_eq!(target.route_name, "direct");
    }

    #[test]
    fn select_boundary_score_0() {
        let router = Router::from_yaml(sample_yaml()).unwrap();
        let target = router.select(0).unwrap();
        assert_eq!(target.route_name, "anonymized-cheap");
    }

    #[test]
    fn select_boundary_score_100() {
        let router = Router::from_yaml(sample_yaml()).unwrap();
        let target = router.select(100).unwrap();
        assert_eq!(target.route_name, "direct");
    }

    #[test]
    fn default_router_returns_none() {
        let router = Router::default_router();
        assert!(!router.has_routes());
        assert!(router.select(50).is_none());
        assert!(router.select(100).is_none());
    }

    #[test]
    fn overlapping_ranges_rejected() {
        let yaml = r#"
routes:
  - name: "a"
    score_min: 0
    score_max: 60
    upstream_url: "https://a.com"
    api_format: "anthropic"
    api_key_env: "A_KEY"
  - name: "b"
    score_min: 50
    score_max: 100
    upstream_url: "https://b.com"
    api_format: "openai"
    api_key_env: "B_KEY"
"#;
        let result = Router::from_yaml(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("overlapping"), "error: {err}");
    }

    #[test]
    fn score_min_greater_than_max_rejected() {
        let yaml = r#"
routes:
  - name: "bad"
    score_min: 80
    score_max: 20
    upstream_url: "https://a.com"
    api_format: "anthropic"
    api_key_env: "A_KEY"
"#;
        let result = Router::from_yaml(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("score_min"), "error: {err}");
    }

    #[test]
    fn score_max_over_100_rejected() {
        let yaml = r#"
routes:
  - name: "bad"
    score_min: 90
    score_max: 150
    upstream_url: "https://a.com"
    api_format: "anthropic"
    api_key_env: "A_KEY"
"#;
        let result = Router::from_yaml(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("exceeds 100"), "error: {err}");
    }

    #[test]
    fn unknown_api_format_rejected() {
        let yaml = r#"
routes:
  - name: "bad"
    score_min: 0
    score_max: 100
    upstream_url: "https://a.com"
    api_format: "gemini"
    api_key_env: "A_KEY"
"#;
        let result = Router::from_yaml(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("gemini"), "error: {err}");
    }

    #[test]
    fn load_or_default_missing_file() {
        let router = Router::load_or_default("/nonexistent/path/routing.yaml");
        assert!(!router.has_routes());
        assert!(router.select(50).is_none());
    }
}
