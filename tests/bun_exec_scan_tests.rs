use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};

use gyrseek::{scan_packages_versions, PolicyConfig, SandboxRunner};

/// MockRunner returns canned strace output per (package, version) probe, so we
/// can drive the full scan_packages_versions pipeline deterministically.
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

/// Single-baseline policy with default watched executables (bun, deno).
fn policy_with_baseline(
    package: &str,
    baseline: &str,
    process_exec_allowlist: HashSet<String>,
) -> PolicyConfig {
    PolicyConfig {
        baseline_count: 1,
        process_exec_allowlist,
        baseline_overrides: HashMap::from([(
            package.to_string(),
            (Some(baseline.to_string()), None),
        )]),
        ..PolicyConfig::default()
    }
}

/// Case 1: the previous version never ran bun; the latest version downloads and
/// runs bun (the Shai-Hulud "Hades" loader). This must be flagged.
#[tokio::test]
async fn flags_newly_introduced_bun_execution() {
    let _guard = env_lock().lock().expect("env lock should succeed");
    unsafe {
        std::env::set_var("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0");
    }

    let current_trace = r#"
execve("/tmp/b/bun", ["/tmp/b/bun", "run", "_index.js"], 0x7ff) = 0
"#;
    let baseline_trace = r#"
execve("/usr/bin/node", ["node", "index.js"], 0x7ff) = 0
"#;

    let runner = MockRunner {
        traces: HashMap::from([
            (("evil-pkg".to_string(), "1.3.0".to_string()), current_trace.to_string()),
            (("evil-pkg".to_string(), "1.2.0".to_string()), baseline_trace.to_string()),
        ]),
    };

    let results = scan_packages_versions(
        &runner,
        "npm",
        &[("evil-pkg".to_string(), "1.3.0".to_string())],
        &policy_with_baseline("evil-pkg", "1.2.0", HashSet::new()),
    )
    .await;

    unsafe {
        std::env::remove_var("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H");
    }

    assert_eq!(results.get("evil-pkg|1.3.0").map(|r| r.allowed), Some(false));
}

/// Case 2: the package legitimately ran `bun run build` before, but the latest
/// version ALSO runs the stealer via bun. The additional invocation is flagged.
#[tokio::test]
async fn flags_existing_bun_with_additional_invocation() {
    let _guard = env_lock().lock().expect("env lock should succeed");
    unsafe {
        std::env::set_var("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0");
    }

    let current_trace = r#"
execve("/usr/bin/bun", ["bun", "run", "build"], 0x7ff) = 0
execve("/tmp/b/bun", ["bun", "run", "_index.js"], 0x7ff) = 0
"#;
    let baseline_trace = r#"
execve("/usr/bin/bun", ["bun", "run", "build"], 0x7ff) = 0
"#;

    let runner = MockRunner {
        traces: HashMap::from([
            (("buildy".to_string(), "2.1.0".to_string()), current_trace.to_string()),
            (("buildy".to_string(), "2.0.0".to_string()), baseline_trace.to_string()),
        ]),
    };

    let results = scan_packages_versions(
        &runner,
        "npm",
        &[("buildy".to_string(), "2.1.0".to_string())],
        &policy_with_baseline("buildy", "2.0.0", HashSet::new()),
    )
    .await;

    unsafe {
        std::env::remove_var("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H");
    }

    assert_eq!(results.get("buildy|2.1.0").map(|r| r.allowed), Some(false));
}

/// Identical bun behavior across versions must NOT be flagged.
#[tokio::test]
async fn allows_when_bun_behavior_matches_baseline() {
    let _guard = env_lock().lock().expect("env lock should succeed");
    unsafe {
        std::env::set_var("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0");
    }

    let trace = r#"
execve("/usr/bin/bun", ["bun", "run", "build"], 0x7ff) = 0
"#;

    let runner = MockRunner {
        traces: HashMap::from([
            (("buildy".to_string(), "2.1.0".to_string()), trace.to_string()),
            (("buildy".to_string(), "2.0.0".to_string()), trace.to_string()),
        ]),
    };

    let results = scan_packages_versions(
        &runner,
        "npm",
        &[("buildy".to_string(), "2.1.0".to_string())],
        &policy_with_baseline("buildy", "2.0.0", HashSet::new()),
    )
    .await;

    unsafe {
        std::env::remove_var("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H");
    }

    assert_eq!(results.get("buildy|2.1.0").map(|r| r.allowed), Some(true));
}

/// A newly introduced bun invocation that is explicitly allowlisted is permitted.
#[tokio::test]
async fn allows_new_bun_when_allowlisted() {
    let _guard = env_lock().lock().expect("env lock should succeed");
    unsafe {
        std::env::set_var("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0");
    }

    let current_trace = r#"
execve("/usr/bin/bun", ["bun", "run", "approved-task"], 0x7ff) = 0
"#;
    let baseline_trace = r#"
execve("/usr/bin/node", ["node", "index.js"], 0x7ff) = 0
"#;

    let runner = MockRunner {
        traces: HashMap::from([
            (("buildy".to_string(), "2.1.0".to_string()), current_trace.to_string()),
            (("buildy".to_string(), "2.0.0".to_string()), baseline_trace.to_string()),
        ]),
    };

    let allowlist: HashSet<String> = ["bun|run|approved-task".to_string()].into_iter().collect();

    let results = scan_packages_versions(
        &runner,
        "npm",
        &[("buildy".to_string(), "2.1.0".to_string())],
        &policy_with_baseline("buildy", "2.0.0", allowlist),
    )
    .await;

    unsafe {
        std::env::remove_var("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H");
    }

    assert_eq!(results.get("buildy|2.1.0").map(|r| r.allowed), Some(true));
}
