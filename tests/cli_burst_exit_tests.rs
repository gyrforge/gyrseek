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
    let output = run_with_config(
        "release_burst_threshold: 3\nrelease_burst_window_hours: 12\n",
    );

    assert_eq!(output.status.code(), Some(1));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Release burst threshold triggered"));
    assert!(stdout.contains("last 12h"));
}
