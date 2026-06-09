use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};

use gyrseek::{scan_packages_versions, PolicyConfig, SandboxRunner};

/// Builds a single-baseline policy pinning `package` to baseline `baseline`,
/// optionally with a git-clone allowlist.
fn policy_with_baseline(
    package: &str,
    baseline: &str,
    git_clone_allowlist: HashSet<String>,
) -> PolicyConfig {
    PolicyConfig {
        baseline_count: 1,
        git_clone_allowlist,
        baseline_overrides: HashMap::from([(
            package.to_string(),
            (Some(baseline.to_string()), None),
        )]),
        ..PolicyConfig::default()
    }
}

struct MockRunner {
    traces: HashMap<(String, String), String>,
}

impl SandboxRunner for MockRunner {
    fn trace_install(&self, _manager: &str, package: &str, version: &str) -> Result<String, String> {
        self.traces
            .get(&(package.to_string(), version.to_string()))
            .cloned()
            .ok_or_else(|| format!("missing mock trace for {}@{}", package, version))
    }
}

fn env_lock() -> &'static Mutex<()> {
    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    ENV_LOCK.get_or_init(|| Mutex::new(()))
}

#[tokio::test]
async fn scan_flags_new_install_time_git_clone_behavior() {
    let _guard = env_lock().lock().expect("env lock should succeed");
    unsafe {
        std::env::set_var("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0");
    }

    let current_trace = r#"
execve("/usr/bin/git", ["git", "clone", "https://github.com/evil/repo.git"], 0x7ff) = 0
"#;
    let baseline_trace = r#"
execve("/usr/bin/sh", ["sh", "-c", "echo ok"], 0x7ff) = 0
"#;

    let runner = MockRunner {
        traces: HashMap::from([
            (("pkg-a".to_string(), "1.3.0".to_string()), current_trace.to_string()),
            (("pkg-a".to_string(), "1.2.0".to_string()), baseline_trace.to_string()),
        ]),
    };

    let results = scan_packages_versions(
        &runner,
        "npm",
        &[("pkg-a".to_string(), "1.3.0".to_string())],
        &policy_with_baseline("pkg-a", "1.2.0", HashSet::new()),
    )
    .await;

    unsafe {
        std::env::remove_var("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H");
    }

    assert_eq!(results.get("pkg-a|1.3.0").map(|r| r.allowed), Some(false));
}

#[tokio::test]
async fn scan_allows_when_install_time_git_clone_behavior_matches_baseline() {
    let _guard = env_lock().lock().expect("env lock should succeed");
    unsafe {
        std::env::set_var("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0");
    }

    let current_trace = r#"
execve("/usr/bin/git", ["git", "clone", "https://github.com/acme/repo.git"], 0x7ff) = 0
"#;
    let baseline_trace = r#"
execve("/usr/bin/git", ["git", "clone", "https://github.com/acme/repo.git"], 0x7ff) = 0
"#;

    let runner = MockRunner {
        traces: HashMap::from([
            (("pkg-b".to_string(), "1.3.0".to_string()), current_trace.to_string()),
            (("pkg-b".to_string(), "1.2.0".to_string()), baseline_trace.to_string()),
        ]),
    };

    let results = scan_packages_versions(
        &runner,
        "npm",
        &[("pkg-b".to_string(), "1.3.0".to_string())],
        &policy_with_baseline("pkg-b", "1.2.0", HashSet::new()),
    )
    .await;

    unsafe {
        std::env::remove_var("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H");
    }

    assert_eq!(results.get("pkg-b|1.3.0").map(|r| r.allowed), Some(true));
}

#[tokio::test]
async fn scan_allows_new_git_clone_behavior_when_target_is_allowlisted() {
    let _guard = env_lock().lock().expect("env lock should succeed");
    unsafe {
        std::env::set_var("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0");
    }

    let current_trace = r#"
execve("/usr/bin/git", ["git", "clone", "https://github.com/acme/approved.git"], 0x7ff) = 0
"#;
    let baseline_trace = r#"
execve("/usr/bin/sh", ["sh", "-c", "echo ok"], 0x7ff) = 0
"#;

    let runner = MockRunner {
        traces: HashMap::from([
            (("pkg-c".to_string(), "1.3.0".to_string()), current_trace.to_string()),
            (("pkg-c".to_string(), "1.2.0".to_string()), baseline_trace.to_string()),
        ]),
    };

    let git_clone_allowlist: HashSet<String> =
        ["https://github.com/acme/approved.git".to_string()].into_iter().collect();

    let results = scan_packages_versions(
        &runner,
        "npm",
        &[("pkg-c".to_string(), "1.3.0".to_string())],
        &policy_with_baseline("pkg-c", "1.2.0", git_clone_allowlist),
    )
    .await;

    unsafe {
        std::env::remove_var("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H");
    }

    assert_eq!(results.get("pkg-c|1.3.0").map(|r| r.allowed), Some(true));
}
