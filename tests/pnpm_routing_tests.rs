use std::fs;
use std::process::Command;

fn pnpm_command(args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gyrseek"));
    command
        .args(args)
        .env("GYRSEEK_TEST_BYPASS_RUNNER_INIT", "1")
        .env("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0");
    command
}

#[test]
fn pnpm_add_reaches_scan_branch() {
    let output = pnpm_command(&["pnpm", "add", "left-pad"])
        .output()
        .expect("gyrseek process should run");

    assert_eq!(output.status.code(), Some(1));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("'add' detected. Testing 1 package(s)")
            || stdout.contains("Sandbox execution failed"),
        "expected pnpm add to reach the package scan branch, got: {stdout}"
    );
    assert!(
        !stdout.contains("Unrecognized manager"),
        "pnpm add must not be rejected as an unsupported manager, got: {stdout}"
    );
}

#[test]
fn pnpm_install_uses_package_json_fallback() {
    let dir = tempfile::tempdir().expect("temp dir should be created");
    fs::write(
        dir.path().join("package.json"),
        r#"{"dependencies":{"left-pad":"^1.3.0"}}"#,
    )
    .expect("package.json should be written");

    let output = pnpm_command(&["pnpm", "install"])
        .current_dir(dir.path())
        .output()
        .expect("gyrseek process should run");

    assert_eq!(output.status.code(), Some(1));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("'install' detected. Testing 1 package(s)")
            || stdout.contains("Sandbox execution failed"),
        "expected pnpm install to scan package.json dependencies, got: {stdout}"
    );
    assert!(
        !stdout.contains("no parseable package entries were found"),
        "pnpm install should find package.json dependencies, got: {stdout}"
    );
}

#[test]
fn pnpm_add_only_non_registry_specs_forwards_directly_without_scanning() {
    let dir = tempfile::tempdir().expect("temp dir should be created");
    // Even if a package.json with dependencies exists, non-registry targets must NOT scan it!
    fs::write(
        dir.path().join("package.json"),
        r#"{"dependencies":{"left-pad":"^1.3.0"}}"#,
    )
    .expect("package.json should be written");

    let output = pnpm_command(&["pnpm", "add", "file:../local-pkg"])
        .current_dir(dir.path())
        .output()
        .expect("gyrseek process should run");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(
            "Only non-registry package specifications detected. Forwarding command directly..."
        ),
        "expected non-registry specs to forward directly, got: {stdout}"
    );
    assert!(
        !stdout.contains("Testing 1 package(s)"),
        "must not scan package.json when non-registry targets are passed, got: {stdout}"
    );
}
