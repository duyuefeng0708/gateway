use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::path::Path;

/// Configuration for the eBPF loader.
///
/// Loaded from YAML, specifies which LLM endpoints to intercept
/// and redirect through the privacy gateway proxy.
#[derive(Debug, Clone, Deserialize)]
pub struct LoaderConfig {
    /// LLM endpoints to intercept.
    pub endpoints: Vec<Endpoint>,

    /// Local proxy port to redirect traffic to.
    #[serde(default = "default_proxy_port")]
    pub proxy_port: u16,

    /// How often (in seconds) to re-resolve DNS for endpoint hostnames.
    #[serde(default = "default_dns_refresh_interval")]
    pub dns_refresh_interval: u64,

    /// Path to the cgroup to attach the eBPF program to.
    #[serde(default = "default_cgroup_path")]
    pub cgroup_path: String,
}

/// A single LLM API endpoint to intercept.
#[derive(Debug, Clone, Deserialize)]
pub struct Endpoint {
    /// Hostname (e.g. "api.anthropic.com").
    pub host: String,

    /// Port (typically 443 for HTTPS).
    #[serde(default = "default_endpoint_port")]
    pub port: u16,
}

fn default_proxy_port() -> u16 {
    8443
}

fn default_dns_refresh_interval() -> u64 {
    60
}

fn default_cgroup_path() -> String {
    // On systemd-based systems (cgroup v2), each user session gets its own
    // cgroup slice. Attaching to root "/sys/fs/cgroup" doesn't reliably
    // cover all sessions. Default to the current user's slice which covers
    // all sessions for this uid.
    if let Ok(uid) = std::env::var("SUDO_UID").or_else(|_| std::env::var("UID")) {
        let user_slice = format!("/sys/fs/cgroup/user.slice/user-{uid}.slice");
        if std::path::Path::new(&user_slice).exists() {
            return user_slice;
        }
    }
    // Try to detect from /proc/self/cgroup and go up to the user slice
    if let Ok(cgroup) = std::fs::read_to_string("/proc/self/cgroup") {
        if let Some(path) = cgroup.lines().next() {
            let cg_path = path.split("::").nth(1).unwrap_or("");
            // Walk up to user-XXXX.slice level
            if let Some(idx) = cg_path.find(".slice/") {
                let slice = &cg_path[..idx + 6]; // include ".slice"
                let full = format!("/sys/fs/cgroup{slice}");
                if std::path::Path::new(&full).exists() {
                    return full;
                }
            }
        }
    }
    "/sys/fs/cgroup".to_string()
}

fn default_endpoint_port() -> u16 {
    443
}

impl LoaderConfig {
    /// Load and validate configuration from a YAML file.
    pub fn from_file(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file: {}", path.display()))?;
        Self::from_yaml(&contents)
    }

    /// Parse and validate configuration from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self> {
        let config: LoaderConfig =
            serde_yaml::from_str(yaml).context("failed to parse YAML config")?;
        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration.
    fn validate(&self) -> Result<()> {
        if self.endpoints.is_empty() {
            bail!("endpoints list must not be empty");
        }
        for ep in &self.endpoints {
            if ep.host.is_empty() {
                bail!("endpoint host must not be empty");
            }
            if ep.port == 0 {
                bail!("endpoint port must be non-zero");
            }
        }
        if self.proxy_port == 0 {
            bail!("proxy_port must be non-zero");
        }
        Ok(())
    }
}
