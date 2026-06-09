use std::process::Command;

/// #7 — When gyrseek forwards the host command but the manager binary can't be
/// spawned, it must fail closed (exit 1 with an error) rather than panicking or
/// silently pretending the operation succeeded.
#[test]
fn forwarding_a_missing_host_binary_fails_closed() {
    // An unrecognised "manager" with no install semantics falls through to the
    // transparent forward path. The binary doesn't exist, so the spawn fails.
    let output = Command::new(env!("CARGO_BIN_EXE_gyrseek"))
        .arg("gyrseek-nonexistent-binary-xyz")
        .arg("--version")
        .env("GYRSEEK_TEST_BYPASS_RUNNER_INIT", "1")
        .output()
        .expect("gyrseek process should run");

    assert_eq!(output.status.code(), Some(1), "should exit non-zero when host binary is missing");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Failed to execute host command"),
        "expected fail-closed message, got: {stdout}"
    );
}

/// #8 — gyrseek must propagate the host manager's exit status, not its own. A
/// forwarded command that exits non-zero (e.g. version-not-found) must surface
/// the same non-zero code, otherwise a failed install looks successful to the
/// caller. Exit code is only observable from a child process, so this drives the
/// real binary. `sh -c 'exit 42'` forwards transparently to `sh`, which exits 42.
#[test]
fn forwarding_propagates_host_nonzero_exit_status() {
    let output = Command::new(env!("CARGO_BIN_EXE_gyrseek"))
        .arg("sh")
        .arg("-c")
        .arg("exit 42")
        .env("GYRSEEK_TEST_BYPASS_RUNNER_INIT", "1")
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
    let output = Command::new(env!("CARGO_BIN_EXE_gyrseek"))
        .arg("sh")
        .arg("-c")
        .arg("exit 0")
        .env("GYRSEEK_TEST_BYPASS_RUNNER_INIT", "1")
        .output()
        .expect("gyrseek process should run");

    assert_eq!(output.status.code(), Some(0), "clean host exit must stay 0");
}
