use std::process::Command;

/// `gyrseek --version` / `-V` prints the crate version and exits 0, without
/// needing a config file, Docker, or a recognized manager subcommand. The
/// printed version must match the compiled crate version.
#[test]
fn version_flag_prints_crate_version_and_exits_zero() {
    for flag in ["--version", "-V"] {
        let output = Command::new(env!("CARGO_BIN_EXE_gyrseek"))
            .arg(flag)
            .output()
            .expect("gyrseek process should run");

        assert_eq!(
            output.status.code(),
            Some(0),
            "`gyrseek {flag}` should exit 0"
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        let expected = format!("gyrseek {}", env!("CARGO_PKG_VERSION"));
        assert!(
            stdout.contains(&expected),
            "`gyrseek {flag}` should print '{expected}', got: {stdout}"
        );
    }
}

/// A forwarded command's own `--version` flag must NOT be intercepted by
/// gyrseek: only a leading top-level `--version`/`-V` is treated as the version
/// request. Here `pip install --version` keeps `pip` as the manager and is
/// routed normally (it fails closed with no real pip on PATH), proving gyrseek
/// did not print its own version and bail out.
#[test]
fn version_flag_after_manager_is_not_intercepted() {
    let output = Command::new(env!("CARGO_BIN_EXE_gyrseek"))
        .args(["pip", "install", "requests", "--version"])
        .env("GYRSEEK_TEST_BYPASS_RUNNER_INIT", "1")
        .output()
        .expect("gyrseek process should run");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let crate_version = format!("gyrseek {}", env!("CARGO_PKG_VERSION"));
    assert!(
        !stdout.contains(&crate_version),
        "a trailing --version on a forwarded command must not trigger the version banner, got: {stdout}"
    );
}
