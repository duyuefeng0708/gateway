use serde::Serialize;
use std::env;
use std::fs;
use std::path::Path;

/// Result of a single health check.
#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

/// Aggregated doctor report.
#[derive(Debug, Serialize)]
pub struct DoctorReport {
    pub checks: Vec<CheckResult>,
    pub passed: usize,
    pub total: usize,
}

fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Run all health checks and return a report.
pub async fn run_checks() -> DoctorReport {
    let ollama_url = env_or("GATEWAY_OLLAMA_URL", "http://localhost:11434");
    let fast_model = env_or("GATEWAY_FAST_MODEL", "MTBS/anonymizer");
    let db_path = env_or("GATEWAY_DB_PATH", "./data/sessions.db");
    let upstream_url = env_or("GATEWAY_UPSTREAM", "https://api.anthropic.com");
    let audit_path = env_or("GATEWAY_AUDIT_PATH", "./data/audit/");

    let (ollama_check, model_check) = check_ollama(&ollama_url, &fast_model).await;

    let checks = vec![
        ollama_check,
        model_check,
        check_sqlite(&db_path),
        check_upstream(&upstream_url).await,
        check_disk_space(&audit_path),
    ];

    let passed = checks.iter().filter(|c| c.passed).count();
    let total = checks.len();

    DoctorReport {
        checks,
        passed,
        total,
    }
}

/// Check if Ollama is reachable and if the expected model is loaded.
async fn check_ollama(ollama_url: &str, fast_model: &str) -> (CheckResult, CheckResult) {
    let tags_url = format!("{}/api/tags", ollama_url.trim_end_matches('/'));

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    match client.get(&tags_url).send().await {
        Ok(resp) if resp.status().is_success() => {
            let ollama_ok = CheckResult {
                name: "Ollama reachable".into(),
                passed: true,
                detail: ollama_url.to_string(),
            };

            // Try to parse response body to check for model
            let model_check = match resp.text().await {
                Ok(body) => check_model_in_response(&body, fast_model),
                Err(_) => CheckResult {
                    name: "Model loaded".into(),
                    passed: false,
                    detail: format!("failed to read Ollama response for {}", fast_model),
                },
            };

            (ollama_ok, model_check)
        }
        Ok(resp) => {
            let status = resp.status();
            (
                CheckResult {
                    name: "Ollama reachable".into(),
                    passed: false,
                    detail: format!("{} returned HTTP {}", ollama_url, status),
                },
                CheckResult {
                    name: "Model loaded".into(),
                    passed: false,
                    detail: format!("Ollama not healthy (HTTP {})", status),
                },
            )
        }
        Err(e) => (
            CheckResult {
                name: "Ollama reachable".into(),
                passed: false,
                detail: format!("{} ({})", ollama_url, e),
            },
            CheckResult {
                name: "Model loaded".into(),
                passed: false,
                detail: format!("{} not found (Ollama unreachable)", fast_model),
            },
        ),
    }
}

fn check_model_in_response(body: &str, fast_model: &str) -> CheckResult {
    // The /api/tags response is JSON with a "models" array, each having a "name" field.
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(models) = json.get("models").and_then(|m| m.as_array()) {
            let found = models.iter().any(|m| {
                m.get("name")
                    .and_then(|n| n.as_str())
                    .map(|name| name == fast_model || name.starts_with(&format!("{}:", fast_model)))
                    .unwrap_or(false)
            });
            if found {
                return CheckResult {
                    name: "Model loaded".into(),
                    passed: true,
                    detail: fast_model.to_string(),
                };
            }
        }
    }

    CheckResult {
        name: "Model loaded".into(),
        passed: false,
        detail: format!("{} not found", fast_model),
    }
}

/// Check that SQLite database is writable.
fn check_sqlite(db_path: &str) -> CheckResult {
    let name = "SQLite writable".to_string();

    // Ensure parent directory exists
    if let Some(parent) = Path::new(db_path).parent() {
        if !parent.exists() {
            if let Err(e) = fs::create_dir_all(parent) {
                return CheckResult {
                    name,
                    passed: false,
                    detail: format!("cannot create directory: {}", e),
                };
            }
        }
    }

    match rusqlite::Connection::open(db_path) {
        Ok(conn) => {
            // Try to write a test row and clean up
            let result = conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS _doctor_check (id INTEGER PRIMARY KEY);
                 INSERT INTO _doctor_check (id) VALUES (1);
                 DELETE FROM _doctor_check WHERE id = 1;
                 DROP TABLE _doctor_check;",
            );
            match result {
                Ok(()) => CheckResult {
                    name,
                    passed: true,
                    detail: db_path.to_string(),
                },
                Err(e) => CheckResult {
                    name,
                    passed: false,
                    detail: format!("{} ({})", db_path, e),
                },
            }
        }
        Err(e) => CheckResult {
            name,
            passed: false,
            detail: format!("{} ({})", db_path, e),
        },
    }
}

/// Check that the upstream API is reachable (any HTTP response is acceptable).
async fn check_upstream(upstream_url: &str) -> CheckResult {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    match client.head(upstream_url).send().await {
        Ok(_resp) => CheckResult {
            name: "Upstream reachable".into(),
            passed: true,
            detail: upstream_url.to_string(),
        },
        Err(e) => CheckResult {
            name: "Upstream reachable".into(),
            passed: false,
            detail: format!("{} ({})", upstream_url, e),
        },
    }
}

/// Check that the audit path exists (or can be created) and is writable,
/// and has reasonable disk space (>100MB free).
fn check_disk_space(audit_path: &str) -> CheckResult {
    let name = "Audit path writable".to_string();
    let path = Path::new(audit_path);

    // Create the directory if it doesn't exist
    if !path.exists() {
        if let Err(e) = fs::create_dir_all(path) {
            return CheckResult {
                name,
                passed: false,
                detail: format!("cannot create {}: {}", audit_path, e),
            };
        }
    }

    // Try writing a test file
    let test_file = path.join(".doctor_check");
    match fs::write(&test_file, b"ok") {
        Ok(()) => {
            let _ = fs::remove_file(&test_file);
        }
        Err(e) => {
            return CheckResult {
                name,
                passed: false,
                detail: format!("{} not writable: {}", audit_path, e),
            };
        }
    }

    // Check available disk space using libc statvfs
    match statvfs_free_mb(path) {
        Some(free_mb) if free_mb < 100 => CheckResult {
            name,
            passed: false,
            detail: format!("{} (only {}MB free, need >100MB)", audit_path, free_mb),
        },
        Some(_) => CheckResult {
            name,
            passed: true,
            detail: audit_path.to_string(),
        },
        None => {
            // Could not determine free space; path is writable so pass with a note
            CheckResult {
                name,
                passed: true,
                detail: format!("{} (writable, could not check free space)", audit_path),
            }
        }
    }
}

/// Get free disk space in MB for the given path using libc::statvfs.
fn statvfs_free_mb(path: &Path) -> Option<u64> {
    use std::ffi::CString;
    use std::mem::MaybeUninit;

    let c_path = CString::new(path.to_str()?).ok()?;
    let mut stat = MaybeUninit::<libc::statvfs>::uninit();

    let result = unsafe { libc::statvfs(c_path.as_ptr(), stat.as_mut_ptr()) };

    if result == 0 {
        let stat = unsafe { stat.assume_init() };
        let free_bytes = stat.f_bavail as u64 * stat.f_bsize as u64;
        Some(free_bytes / (1024 * 1024))
    } else {
        None
    }
}

/// Print the report in colored terminal format.
pub fn print_report(report: &DoctorReport) {
    println!("Gateway Health Check");
    for check in &report.checks {
        if check.passed {
            println!("  \x1b[32m\u{2713}\x1b[0m {} ({})", check.name, check.detail);
        } else {
            println!("  \x1b[31m\u{2717}\x1b[0m {} ({})", check.name, check.detail);
        }
    }
    println!();
    let color = if report.passed == report.total {
        "\x1b[32m"
    } else {
        "\x1b[31m"
    };
    println!(
        "Result: {}{}/{} checks passed\x1b[0m",
        color, report.passed, report.total
    );
}

/// Print the report as JSON.
pub fn print_report_json(report: &DoctorReport) {
    let json = serde_json::to_string_pretty(report).expect("report must serialize");
    println!("{}", json);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_model_found_in_response() {
        let body = r#"{"models":[{"name":"MTBS/anonymizer:latest","size":123}]}"#;
        let result = check_model_in_response(body, "MTBS/anonymizer");
        assert!(result.passed);
    }

    #[test]
    fn check_model_not_found_in_response() {
        let body = r#"{"models":[{"name":"llama3:latest","size":123}]}"#;
        let result = check_model_in_response(body, "MTBS/anonymizer");
        assert!(!result.passed);
        assert!(result.detail.contains("not found"));
    }

    #[test]
    fn check_model_empty_models() {
        let body = r#"{"models":[]}"#;
        let result = check_model_in_response(body, "MTBS/anonymizer");
        assert!(!result.passed);
    }

    #[test]
    fn check_model_invalid_json() {
        let result = check_model_in_response("not json", "MTBS/anonymizer");
        assert!(!result.passed);
    }

    #[test]
    fn sqlite_check_with_temp_db() {
        let dir = tempfile::TempDir::new().unwrap();
        let db_path = dir.path().join("test.db");
        let result = check_sqlite(db_path.to_str().unwrap());
        assert!(result.passed);
        assert!(result.detail.contains("test.db"));
    }

    #[test]
    fn sqlite_check_with_bad_path() {
        let result = check_sqlite("/nonexistent/deeply/nested/impossible/test.db");
        assert!(!result.passed);
    }

    #[test]
    fn disk_space_check_on_temp() {
        let dir = tempfile::TempDir::new().unwrap();
        let result = check_disk_space(dir.path().to_str().unwrap());
        assert!(result.passed);
    }

    #[test]
    fn report_json_is_valid() {
        let report = DoctorReport {
            checks: vec![
                CheckResult {
                    name: "Test check".into(),
                    passed: true,
                    detail: "ok".into(),
                },
                CheckResult {
                    name: "Fail check".into(),
                    passed: false,
                    detail: "bad".into(),
                },
            ],
            passed: 1,
            total: 2,
        };
        let json = serde_json::to_string(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["passed"], 1);
        assert_eq!(parsed["total"], 2);
        assert!(parsed["checks"].is_array());
        assert_eq!(parsed["checks"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn print_report_formats_correctly() {
        // Smoke test: just verify it doesn't panic
        let report = DoctorReport {
            checks: vec![CheckResult {
                name: "Test".into(),
                passed: true,
                detail: "ok".into(),
            }],
            passed: 1,
            total: 1,
        };
        print_report(&report);
        print_report_json(&report);
    }
}
