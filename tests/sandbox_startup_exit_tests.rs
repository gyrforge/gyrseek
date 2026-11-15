//! A sandbox that cannot start must stop gyrseek with exit code 1 and a message naming the
//! cause, before any registry lookup. These run the real binary, so they need neither Docker
//! nor nono installed.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

/// Writes an executable `#!/bin/sh` script `name` with `body` into `dir`.
fn fake_exe(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

fn run_gyrseek(sandbox: &str, envs: &[(&str, &Path)]) -> (Output, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_gyrseek"));
    cmd.args(["pip", "install", "six"])
        .env("GYRSEEK_SANDBOX", sandbox);
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
    let (output, stdout) = run_gyrseek("docker", &[("PATH", empty_path.path())]);

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
    let (output, stdout) = run_gyrseek("docker", &[("PATH", dir.path())]);

    assert_eq!(output.status.code(), Some(1), "{stdout}");
    assert!(stdout.contains("daemon is not running"), "{stdout}");
    assert!(stdout.contains("Docker said: Cannot connect"), "{stdout}");
}

#[test]
fn nono_not_found_at_configured_path_exits_1() {
    let missing = Path::new("/nonexistent/gyrseek-test-nono");
    let (output, stdout) = run_gyrseek("nono", &[("GYRSEEK_NONO_PATH", missing)]);

    assert_eq!(output.status.code(), Some(1), "{stdout}");
    assert!(stdout.contains("GYRSEEK_NONO_PATH"), "{stdout}");
}

#[test]
fn nono_older_than_required_exits_1() {
    let dir = tempfile::tempdir().unwrap();
    let nono = fake_exe(dir.path(), "nono", r#"echo "nono 0.80.0""#);
    let (output, stdout) = run_gyrseek("nono", &[("GYRSEEK_NONO_PATH", &nono)]);

    assert_eq!(output.status.code(), Some(1), "{stdout}");
    assert!(stdout.contains("too old"), "{stdout}");
    assert!(stdout.contains("0.81.0"), "{stdout}");
}

/// A nono that cannot start the sandbox (for example no delegated cgroup session on a CI
/// runner) exits before running the install but has already opened its audit log. That must
/// fail the scan with nono's own message, not look like a clear, uneventful install.
#[test]
fn nono_that_fails_to_start_the_sandbox_exits_1_with_its_message() {
    let dir = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let nono = fake_exe(
        dir.path(),
        "nono",
        r#"case "$1" in
  --version) echo "nono 0.81.0";;
  setup) exit 0;;
  run) echo "nono: Sandbox initialization failed: resource: no delegated cgroup v2 subtree" >&2; exit 1;;
esac"#,
    );
    let (output, stdout) = run_gyrseek(
        "nono",
        &[
            ("GYRSEEK_NONO_PATH", &nono),
            ("XDG_STATE_HOME", state.path()),
        ],
    );

    assert_eq!(output.status.code(), Some(1), "{stdout}");
    assert!(stdout.contains("failed to start the sandbox"), "{stdout}");
    assert!(
        stdout.contains("no delegated cgroup v2 subtree"),
        "{stdout}"
    );
}

#[test]
fn nono_that_cannot_sandbox_exits_1() {
    let dir = tempfile::tempdir().unwrap();
    let nono = fake_exe(
        dir.path(),
        "nono",
        r#"case "$1" in --version) echo "nono 0.81.0";; setup) echo "sandbox support NOT available"; exit 1;; esac"#,
    );
    let (output, stdout) = run_gyrseek("nono", &[("GYRSEEK_NONO_PATH", &nono)]);

    assert_eq!(output.status.code(), Some(1), "{stdout}");
    assert!(stdout.contains("cannot sandbox on this system"), "{stdout}");
}

/// Commands that are forwarded without a scan must not need a working sandbox: `uv venv` runs
/// even when Docker is not installed, and a scan of the same manager still fails closed
/// (see `docker_not_installed_exits_1`).
#[test]
fn unscanned_passthrough_does_not_initialize_the_sandbox() {
    let dir = tempfile::tempdir().unwrap();
    fake_exe(dir.path(), "uv", "exit 0");
    let output = Command::new(env!("CARGO_BIN_EXE_gyrseek"))
        .args(["uv", "venv"])
        .env("GYRSEEK_SANDBOX", "docker")
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

#[test]
fn unknown_sandbox_mode_exits_1() {
    let (output, stdout) = run_gyrseek("not-a-sandbox", &[]);

    assert_eq!(output.status.code(), Some(1), "{stdout}");
    assert!(stdout.contains("Unsupported GYRSEEK_SANDBOX"), "{stdout}");
}
