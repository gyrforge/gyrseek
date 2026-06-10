use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

/// Creates a fake executable at `dir/name` that exits with `exit_code`.
fn fake_binary(dir: &Path, name: &str, exit_code: u8) {
    let path = dir.join(name);
    fs::write(&path, format!("#!/bin/sh\nexit {}\n", exit_code)).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// Builds PATH as `dir:$PATH` so the fake binary shadows any real one.
fn prepend_path(dir: &Path) -> String {
    let current = std::env::var("PATH").unwrap_or_default();
    format!("{}:{}", dir.display(), current)
}

/// `gyrseek uv venv` is an unscanned subcommand that reaches
/// forward_original_command without touching the scanner, so it is the right
/// vehicle for testing forward_args behavior. The runner init is bypassed so no
/// docker call is made.
///
/// #7 — When gyrseek forwards to a host binary that does not exist, it must fail
/// closed (exit 1 with a diagnostic) rather than panicking or silently succeeding.
#[test]
fn forwarding_a_missing_host_binary_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    // Restrict PATH to only the empty temp dir so no real `uv` is reachable.
    let output = Command::new(env!("CARGO_BIN_EXE_gyrseek"))
        .args(["uv", "venv"])
        .env("GYRSEEK_TEST_BYPASS_RUNNER_INIT", "1")
        .env("PATH", dir.path())
        .output()
        .expect("gyrseek process should run");

    assert_eq!(
        output.status.code(),
        Some(1),
        "should exit non-zero when host binary is missing"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Failed to execute host command"),
        "expected fail-closed message, got: {stdout}"
    );
}

/// #8 — gyrseek must propagate the host manager's exit status. A forwarded
/// command that exits non-zero must surface the same code so a failed install
/// is not masked as success to the caller.
#[test]
fn forwarding_propagates_host_nonzero_exit_status() {
    let dir = tempfile::tempdir().unwrap();
    fake_binary(dir.path(), "uv", 42);

    let output = Command::new(env!("CARGO_BIN_EXE_gyrseek"))
        .args(["uv", "venv"])
        .env("GYRSEEK_TEST_BYPASS_RUNNER_INIT", "1")
        .env("PATH", prepend_path(dir.path()))
        .output()
        .expect("gyrseek process should run");

    assert_eq!(
        output.status.code(),
        Some(42),
        "gyrseek must exit with the host command's own status, not mask it as success or a generic 1"
    );
}

/// #8 — the success path is unchanged: a forwarded command that exits 0 leaves
/// gyrseek exiting 0.
#[test]
fn forwarding_preserves_host_success_exit_status() {
    let dir = tempfile::tempdir().unwrap();
    fake_binary(dir.path(), "uv", 0);

    let output = Command::new(env!("CARGO_BIN_EXE_gyrseek"))
        .args(["uv", "venv"])
        .env("GYRSEEK_TEST_BYPASS_RUNNER_INIT", "1")
        .env("PATH", prepend_path(dir.path()))
        .output()
        .expect("gyrseek process should run");

    assert_eq!(output.status.code(), Some(0), "clean host exit must stay 0");
}
