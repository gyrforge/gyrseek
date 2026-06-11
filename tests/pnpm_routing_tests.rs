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
