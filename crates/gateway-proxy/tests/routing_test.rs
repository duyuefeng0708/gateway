use std::io::Write;

use gateway_proxy::format::ApiFormat;
use gateway_proxy::routing::Router;

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

// ---------------------------------------------------------------------------
// Score-to-route mapping
// ---------------------------------------------------------------------------

#[test]
fn score_95_routes_to_direct() {
    let router = Router::from_yaml(sample_yaml()).unwrap();
    let target = router.select(95).unwrap();
    assert_eq!(target.route_name, "direct");
    assert_eq!(target.api_format, ApiFormat::Anthropic);
    assert_eq!(target.api_key_env, "ANTHROPIC_API_KEY");
    assert_eq!(target.upstream_url, "https://api.anthropic.com");
}

#[test]
fn score_40_routes_to_anonymized_cheap() {
    let router = Router::from_yaml(sample_yaml()).unwrap();
    let target = router.select(40).unwrap();
    assert_eq!(target.route_name, "anonymized-cheap");
    assert_eq!(target.api_format, ApiFormat::OpenAi);
    assert_eq!(target.api_key_env, "OPENAI_API_KEY");
    assert_eq!(target.upstream_url, "https://api.openai.com");
}

#[test]
fn score_75_routes_to_anonymized_primary() {
    let router = Router::from_yaml(sample_yaml()).unwrap();
    let target = router.select(75).unwrap();
    assert_eq!(target.route_name, "anonymized-primary");
    assert_eq!(target.api_format, ApiFormat::Anthropic);
}

// ---------------------------------------------------------------------------
// Boundary tests
// ---------------------------------------------------------------------------

#[test]
fn boundary_score_50_matches_anonymized_primary() {
    let router = Router::from_yaml(sample_yaml()).unwrap();
    let target = router.select(50).unwrap();
    assert_eq!(target.route_name, "anonymized-primary");
}

#[test]
fn boundary_score_49_matches_anonymized_cheap() {
    let router = Router::from_yaml(sample_yaml()).unwrap();
    let target = router.select(49).unwrap();
    assert_eq!(target.route_name, "anonymized-cheap");
}

#[test]
fn boundary_score_89_matches_anonymized_primary() {
    let router = Router::from_yaml(sample_yaml()).unwrap();
    let target = router.select(89).unwrap();
    assert_eq!(target.route_name, "anonymized-primary");
}

#[test]
fn boundary_score_90_matches_direct() {
    let router = Router::from_yaml(sample_yaml()).unwrap();
    let target = router.select(90).unwrap();
    assert_eq!(target.route_name, "direct");
}

#[test]
fn boundary_score_0_matches_anonymized_cheap() {
    let router = Router::from_yaml(sample_yaml()).unwrap();
    let target = router.select(0).unwrap();
    assert_eq!(target.route_name, "anonymized-cheap");
}

#[test]
fn boundary_score_100_matches_direct() {
    let router = Router::from_yaml(sample_yaml()).unwrap();
    let target = router.select(100).unwrap();
    assert_eq!(target.route_name, "direct");
}

// ---------------------------------------------------------------------------
// Default (no routing config)
// ---------------------------------------------------------------------------

#[test]
fn no_routing_config_returns_none_for_any_score() {
    let router = Router::default_router();
    assert!(router.select(0).is_none());
    assert!(router.select(50).is_none());
    assert!(router.select(100).is_none());
    assert!(!router.has_routes());
}

// ---------------------------------------------------------------------------
// Validation errors
// ---------------------------------------------------------------------------

#[test]
fn overlapping_score_ranges_rejected_at_load_time() {
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
    assert!(
        err.contains("overlapping"),
        "expected overlapping error, got: {err}"
    );
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
    assert!(
        err.contains("score_min"),
        "expected score_min error, got: {err}"
    );
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
    assert!(
        err.contains("exceeds 100"),
        "expected exceeds 100 error, got: {err}"
    );
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
    assert!(
        err.contains("gemini"),
        "expected format error mentioning gemini, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// File loading
// ---------------------------------------------------------------------------

#[test]
fn config_file_not_found_uses_default() {
    let router = Router::load_or_default("/nonexistent/path/routing.yaml");
    assert!(!router.has_routes());
    assert!(router.select(50).is_none());
}

#[test]
fn from_yaml_file_loads_valid_config() {
    // Write a temporary YAML file.
    let dir = std::env::temp_dir().join("gateway_routing_test");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test_routing.yaml");
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(sample_yaml().as_bytes()).unwrap();
    f.flush().unwrap();

    let router = Router::from_yaml_file(path.to_str().unwrap()).unwrap();
    assert!(router.has_routes());
    let target = router.select(95).unwrap();
    assert_eq!(target.route_name, "direct");

    // Clean up.
    std::fs::remove_file(&path).ok();
}

#[test]
fn load_or_default_with_valid_file() {
    let dir = std::env::temp_dir().join("gateway_routing_test_2");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test_routing_2.yaml");
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(sample_yaml().as_bytes()).unwrap();
    f.flush().unwrap();

    let router = Router::load_or_default(path.to_str().unwrap());
    assert!(router.has_routes());
    let target = router.select(40).unwrap();
    assert_eq!(target.route_name, "anonymized-cheap");

    // Clean up.
    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------------
// Edge: non-contiguous ranges (gap between routes)
// ---------------------------------------------------------------------------

#[test]
fn gap_in_ranges_returns_none_for_unmatched_score() {
    let yaml = r#"
routes:
  - name: "low"
    score_min: 0
    score_max: 30
    upstream_url: "https://a.com"
    api_format: "openai"
    api_key_env: "A_KEY"
  - name: "high"
    score_min: 70
    score_max: 100
    upstream_url: "https://b.com"
    api_format: "anthropic"
    api_key_env: "B_KEY"
"#;
    let router = Router::from_yaml(yaml).unwrap();

    // Score in the gap should return None.
    assert!(router.select(50).is_none());
    assert!(router.select(31).is_none());
    assert!(router.select(69).is_none());

    // Scores within ranges should match.
    assert_eq!(router.select(10).unwrap().route_name, "low");
    assert_eq!(router.select(85).unwrap().route_name, "high");
}
