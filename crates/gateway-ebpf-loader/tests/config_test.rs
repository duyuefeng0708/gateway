use std::io::Write;

/// Helper to write YAML to a temp file and parse it.
fn parse_yaml(yaml: &str) -> Result<gateway_ebpf_loader::LoaderConfig, String> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.yaml");
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(yaml.as_bytes()).unwrap();
    gateway_ebpf_loader::LoaderConfig::from_file(&path).map_err(|e| e.to_string())
}

#[test]
fn valid_config_parses() {
    let yaml = r#"
endpoints:
  - host: api.anthropic.com
    port: 443
  - host: api.openai.com
    port: 443
proxy_port: 8443
dns_refresh_interval: 60
cgroup_path: /sys/fs/cgroup
"#;
    let config = parse_yaml(yaml).expect("valid YAML should parse");
    assert_eq!(config.endpoints.len(), 2);
    assert_eq!(config.endpoints[0].host, "api.anthropic.com");
    assert_eq!(config.endpoints[0].port, 443);
    assert_eq!(config.endpoints[1].host, "api.openai.com");
    assert_eq!(config.proxy_port, 8443);
    assert_eq!(config.dns_refresh_interval, 60);
    assert_eq!(config.cgroup_path, "/sys/fs/cgroup");
}

#[test]
fn defaults_applied_when_optional_fields_missing() {
    let yaml = r#"
endpoints:
  - host: api.anthropic.com
"#;
    let config = parse_yaml(yaml).expect("should parse with defaults");
    assert_eq!(config.endpoints[0].port, 443); // default port
    assert_eq!(config.proxy_port, 8443); // default proxy port
    assert_eq!(config.dns_refresh_interval, 60); // default refresh
    assert_eq!(config.cgroup_path, "/sys/fs/cgroup"); // default cgroup
}

#[test]
fn empty_endpoints_is_error() {
    let yaml = r#"
endpoints: []
proxy_port: 8443
"#;
    let err = parse_yaml(yaml).unwrap_err();
    assert!(
        err.contains("endpoints list must not be empty"),
        "expected empty endpoints error, got: {}",
        err
    );
}

#[test]
fn missing_endpoints_field_is_error() {
    let yaml = r#"
proxy_port: 8443
"#;
    let err = parse_yaml(yaml).unwrap_err();
    // The anyhow chain wraps the serde error; check that parsing fails.
    assert!(
        err.contains("missing field")
            || err.contains("endpoints")
            || err.contains("YAML")
            || err.contains("parse"),
        "expected missing field error, got: {}",
        err
    );
}

#[test]
fn empty_host_is_error() {
    let yaml = r#"
endpoints:
  - host: ""
    port: 443
"#;
    let err = parse_yaml(yaml).unwrap_err();
    assert!(
        err.contains("host must not be empty"),
        "expected empty host error, got: {}",
        err
    );
}

#[test]
fn zero_port_is_error() {
    let yaml = r#"
endpoints:
  - host: api.anthropic.com
    port: 0
"#;
    let err = parse_yaml(yaml).unwrap_err();
    assert!(
        err.contains("port must be non-zero"),
        "expected zero port error, got: {}",
        err
    );
}

#[tokio::test]
async fn dns_resolution_for_localhost_works() {
    // This test verifies that the DNS module can resolve localhost.
    // We test it through the public interface.
    let endpoints = vec![gateway_ebpf_loader::Endpoint {
        host: "localhost".to_string(),
        port: 80,
    }];
    let resolved = gateway_ebpf_loader::resolve_endpoints(&endpoints).await;
    assert!(
        !resolved.is_empty(),
        "localhost should resolve to at least one address"
    );
}
