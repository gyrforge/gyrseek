use std::io::Write;
use std::process::Command;

use tempfile::NamedTempFile;

fn run_with_config(config_yaml: &str) -> std::process::Output {
    let mut cfg = NamedTempFile::new().expect("temp config should be created");
    write!(cfg, "{}", config_yaml).expect("config write should succeed");

    Command::new(env!("CARGO_BIN_EXE_gyrseek"))
        .arg("npm")
        .arg("install")
        .arg("left-pad")
        .env("GYRSEEK_CONFIG", cfg.path())
        .env("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "5")
        .env("GYRSEEK_TEST_BYPASS_RUNNER_INIT", "1")
        .output()
        .expect("gyrseek process should run")
}

fn run_with_config_and_env(config_yaml: &str, extra_env: &[(&str, &str)]) -> std::process::Output {
    let mut cfg = NamedTempFile::new().expect("temp config should be created");
    write!(cfg, "{}", config_yaml).expect("config write should succeed");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_gyrseek"));
    cmd.arg("npm")
        .arg("install")
        .arg("left-pad")
        .env("GYRSEEK_CONFIG", cfg.path())
        .env("GYRSEEK_TEST_BYPASS_RUNNER_INIT", "1");

    for (k, v) in extra_env {
        cmd.env(k, v);
    }

    cmd.output().expect("gyrseek process should run")
}

#[test]
fn exits_with_code_1_and_warning_when_release_burst_threshold_triggers() {
    let output = run_with_config("release_burst_threshold: 3\n");

    assert_eq!(output.status.code(), Some(1));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Release burst threshold triggered"));
    assert!(stdout.contains("last 24h"));
}

#[test]
fn exits_with_code_1_and_uses_configured_release_burst_window_hours() {
    let output = run_with_config("release_burst_threshold: 3\nrelease_burst_window_hours: 12\n");

    assert_eq!(output.status.code(), Some(1));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Release burst threshold triggered"));
    assert!(stdout.contains("last 12h"));
}

#[test]
fn exits_with_code_1_when_minimum_release_age_package_is_not_met() {
    let output = run_with_config_and_env(
        "minimum_release_age_package: 3\n",
        &[("GYRSEEK_TEST_FORCE_CURRENT_RELEASE_AGE_DAYS", "1")],
    );

    assert_eq!(output.status.code(), Some(1));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("minimum_release_age_package triggered"));
    assert!(stdout.contains("required >= 3"));
}

#[test]
fn minimum_release_age_package_runs_before_burst_threshold() {
    let output = run_with_config_and_env(
        "minimum_release_age_package: 3\nrelease_burst_threshold: 3\nrelease_burst_window_hours: 12\n",
        &[
            ("GYRSEEK_TEST_FORCE_CURRENT_RELEASE_AGE_DAYS", "1"),
            ("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "3"),
        ],
    );

    assert_eq!(output.status.code(), Some(1));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("minimum_release_age_package triggered"));
    assert!(!stdout.contains("Release burst threshold triggered"));
}

#[test]
fn new_package_exemptions_map_format_loaded_successfully() {
    let mut cfg = NamedTempFile::new().expect("temp config should be created");
    write!(cfg, "new_package_exemptions:\n  left-pad: \"1.0.0\"\n")
        .expect("config write should succeed");

    let output = Command::new(env!("CARGO_BIN_EXE_gyrseek"))
        .arg("npm")
        .arg("install")
        .arg("left-pad")
        .env("GYRSEEK_CONFIG", cfg.path())
        .env("GYRSEEK_TEST_BYPASS_RUNNER_INIT", "1")
        .env("GYRSEEK_TEST_FORCE_BASELINE_AGES_HOURS", "100,100")
        .output()
        .expect("gyrseek process should run");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Exemption for 'left-pad' is pinned to version '1.0.0'"),
        "expected exemption version mismatch message for map format config, got: {stdout}"
    );
    assert!(
        stdout.contains("ignoring for current version 'latest'"),
        "expected exemption to not match 'latest' (unpinned install), got: {stdout}"
    );
}

#[test]
fn new_package_exemptions_list_format_rejected_with_hard_error() {
    // Config uses the deprecated list format (`- left-pad`).
    // Expected behaviour:
    //  • The list format is now a hard error at config parse time.
    //  • The process exits non-zero with a clear error message.
    let mut cfg = NamedTempFile::new().expect("temp config should be created");
    write!(cfg, "new_package_exemptions:\n  - left-pad\n").expect("config write should succeed");

    let output = Command::new(env!("CARGO_BIN_EXE_gyrseek"))
        .arg("npm")
        .arg("install")
        .arg("left-pad")
        .env("GYRSEEK_CONFIG", cfg.path())
        .env("GYRSEEK_TEST_BYPASS_RUNNER_INIT", "1")
        .env("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0")
        .output()
        .expect("gyrseek process should run");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("no longer supported"),
        "expected hard error for list format in stdout, got stdout: {stdout}  stderr: {stderr}"
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "config parse error should exit non-zero"
    );
}

#[test]
fn exits_with_code_1_and_rejects_versions_newer_than_72_hours_by_default() {
    let output = run_with_config_and_env(
        "", // Empty config so default min_baseline_age_hours=72 applies
        &[
            // Provide candidates that are 2 hours old.
            // They should be filtered out by the 72h default gate.
            ("GYRSEEK_TEST_FORCE_BASELINE_AGES_HOURS", "2,2,2"),
        ],
    );

    assert_eq!(output.status.code(), Some(1));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Registry does not contain enough historical versions"));
    assert!(stdout.contains("(found 0)"));
}
