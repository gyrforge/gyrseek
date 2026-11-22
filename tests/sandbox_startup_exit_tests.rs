//! A sandbox that cannot start must stop gyrseek with exit code 1 and a message naming the
//! cause, before any registry lookup. These run the real binary with a fake `docker` script, so they need no Docker installed.

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Output;

/// Writes an executable `#!/bin/sh` script `name` with `body` into `dir`.
fn fake_exe(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

fn run_gyrseek(envs: &[(&str, &Path)]) -> (Output, String) {
    let mut cmd = common::gyrseek();
    cmd.args(["pip", "install", "six"]);
    for (key, value) in envs {
        cmd.env(key, value);
    }
    let output = cmd.output().expect("gyrseek process should run");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    (output, stdout)
}

#[test]
fn docker_not_installed_exits_1() {
    let empty_path = tempfile::tempdir().unwrap();
    let (output, stdout) = run_gyrseek(&[("PATH", empty_path.path())]);

    assert_eq!(output.status.code(), Some(1), "{stdout}");
    assert!(stdout.contains("Sandbox initialization failed"), "{stdout}");
    assert!(stdout.contains("Docker is not installed"), "{stdout}");
}

#[test]
fn docker_daemon_not_running_exits_1_with_a_hint() {
    let dir = tempfile::tempdir().unwrap();
    fake_exe(
        dir.path(),
        "docker",
        r#"case "$1" in --version) exit 0;; info) echo "Cannot connect to the Docker daemon. Is the docker daemon running?" >&2; exit 1;; esac"#,
    );
    let (output, stdout) = run_gyrseek(&[("PATH", dir.path())]);

    assert_eq!(output.status.code(), Some(1), "{stdout}");
    assert!(stdout.contains("daemon is not running"), "{stdout}");
    assert!(stdout.contains("Docker said: Cannot connect"), "{stdout}");
}

/// Commands that are forwarded without a scan must not need a working sandbox: `uv venv` runs
/// even when Docker is not installed, and a scan of the same manager still fails closed
/// (see `docker_not_installed_exits_1`).
#[test]
fn unscanned_passthrough_does_not_initialize_the_sandbox() {
    let dir = tempfile::tempdir().unwrap();
    fake_exe(dir.path(), "uv", "exit 0");
    let output = common::gyrseek()
        .args(["uv", "venv"])
        .env("PATH", dir.path())
        .output()
        .expect("gyrseek process should run");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0), "{stdout}");
    assert!(
        !stdout.contains("Sandbox initialization failed"),
        "{stdout}"
    );
}

/// The retired `GYRSEEK_SANDBOX` variable must not be able to switch isolation off.
#[test]
fn gyrseek_sandbox_env_var_is_ignored() {
    let empty_path = tempfile::tempdir().unwrap();
    let output = common::gyrseek()
        .args(["pip", "install", "six"])
        .env("GYRSEEK_SANDBOX", "host")
        .env("PATH", empty_path.path())
        .output()
        .expect("gyrseek process should run");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(1), "{stdout}");
    assert!(stdout.contains("Docker is not installed"), "{stdout}");
    assert!(!stdout.contains("HOST mode"), "{stdout}");
}
