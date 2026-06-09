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
