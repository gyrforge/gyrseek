use std::process::Command;

/// These tests pin the routing decision for bare `poetry lock` and `uv lock`:
/// both must reach the lockfile-scanning branch rather than being forwarded
/// unscanned. We prove this without Docker or network by running in a temp dir
/// with no lockfile — the scan branch's empty-lockfile guard fails closed with a
/// distinctive message *before* any sandbox/registry call. The old passthrough
/// behavior never printed that message, so its presence is the routing signal.
///
/// `GYRSEEK_TEST_BYPASS_RUNNER_INIT=1` swaps in the no-op sandbox runner so no
/// Docker daemon is required to reach the branch.
/// `poetry lock` is routed to lockfile scanning (mirrors `install`/`update`).
#[test]
fn poetry_lock_is_routed_to_lockfile_scan() {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_gyrseek"))
        .args(["poetry", "lock"])
        .current_dir(dir.path())
        .env("GYRSEEK_TEST_BYPASS_RUNNER_INIT", "1")
        .output()
        .expect("gyrseek process should run");

    assert_eq!(
        output.status.code(),
        Some(1),
        "poetry lock with no poetry.lock must fail closed, proving it reached the scan branch"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("'poetry lock' detected but no packages found in poetry.lock"),
        "expected the poetry-lock scan-branch fail-closed message, got: {stdout}"
    );
}

/// Bare `uv lock` (no `-U`/`-P`) is routed to lockfile scanning.
#[test]
fn bare_uv_lock_is_routed_to_lockfile_scan() {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_gyrseek"))
        .args(["uv", "lock"])
        .current_dir(dir.path())
        .env("GYRSEEK_TEST_BYPASS_RUNNER_INIT", "1")
        .output()
        .expect("gyrseek process should run");

    assert_eq!(
        output.status.code(),
        Some(1),
        "uv lock with no uv.lock must fail closed, proving it reached the scan branch"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("'uv lock' detected but no packages found in uv.lock"),
        "expected the uv-lock scan-branch fail-closed message, got: {stdout}"
    );
}

/// `uv venv` is NOT a scanned subcommand — it forwards unscanned. This pins the
/// assumption relied on by forward_fail_closed_tests.rs so a future routing
/// change can't silently turn it into a scanned command. With no `uv` on PATH
/// the forward fails closed, but crucially WITHOUT any lockfile-scan message.
#[test]
fn uv_venv_stays_unscanned_passthrough() {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_gyrseek"))
        .args(["uv", "venv"])
        .current_dir(dir.path())
        .env("GYRSEEK_TEST_BYPASS_RUNNER_INIT", "1")
        // Restrict PATH to the empty temp dir so the forward has no real `uv`.
        .env("PATH", dir.path())
        .output()
        .expect("gyrseek process should run");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("no packages found"),
        "uv venv must not reach any lockfile-scan branch, got: {stdout}"
    );
    assert!(
        stdout.contains("Failed to execute host command"),
        "uv venv should forward to the host binary, got: {stdout}"
    );
}
