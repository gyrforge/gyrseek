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

/// `pnpm install` is a supported npm-family command and reaches the package
/// detection branch instead of being rejected as an unrecognized manager.
#[test]
fn pnpm_install_is_routed_to_package_scan() {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_gyrseek"))
        .args(["pnpm", "install"])
        .current_dir(dir.path())
        .env("GYRSEEK_TEST_BYPASS_RUNNER_INIT", "1")
        .output()
        .expect("gyrseek process should run");

    assert_eq!(output.status.code(), Some(1));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("No pnpm-lock.yaml found") && stdout.contains("Failing closed"),
        "expected pnpm scan-branch fail-closed message, got: {stdout}"
    );
    assert!(
        !stdout.contains("Unrecognized manager"),
        "pnpm must be a recognized supported manager, got: {stdout}"
    );
}

fn run_in(dir: &std::path::Path, args: &[&str]) -> (Option<i32>, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_gyrseek"))
        .args(args)
        .current_dir(dir)
        .env("GYRSEEK_TEST_BYPASS_RUNNER_INIT", "1")
        .env("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0")
        .output()
        .expect("gyrseek process should run");
    (
        output.status.code(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
}

/// A lockfile entry from a private index is not the PyPI package of the same name, so the scan
/// refuses it unless the package is exempt; the exemption lets the rest be scanned.
#[test]
fn python_lockfile_entries_from_another_index_fail_closed_unless_exempt() {
    let uv = "version = 1\n\n[[package]]\nname = \"corp-lib\"\nversion = \"1.0.0\"\nsource = { registry = \"https://nexus.corp.example/simple\" }\n\n[[package]]\nname = \"six\"\nversion = \"1.16.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n";
    let poetry = "[[package]]\nname = \"corp-lib\"\nversion = \"1.0.0\"\n\n[package.source]\ntype = \"legacy\"\nurl = \"https://nexus.corp.example/simple\"\n\n[[package]]\nname = \"six\"\nversion = \"1.16.0\"\n";
    for (args, file, lock) in [
        (&["uv", "sync"][..], "uv.lock", uv),
        (&["poetry", "install"], "poetry.lock", poetry),
    ] {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(file), lock).unwrap();
        let (code, out) = run_in(dir.path(), args);
        assert_eq!(code, Some(1), "{args:?}");
        assert!(
            out.contains("corp-lib@1.0.0") && out.contains("do not come from PyPI"),
            "{args:?}: {out}"
        );
        assert!(
            !out.contains("Testing"),
            "{args:?}: nothing is scanned when refused: {out}"
        );

        std::fs::write(
            dir.path().join("gyrseek.yaml"),
            "internal_package_exemptions:\n  - corp-lib\n",
        )
        .unwrap();
        let (code, out) = run_in(dir.path(), args);
        assert_eq!(code, Some(1), "no Docker, so the scan itself fails closed");
        assert!(out.contains("Testing 2"), "{args:?}: {out}");
    }
}

/// `uv pip sync pylock.toml` applies the same source rule as the other lockfiles.
#[test]
fn pylock_entries_from_another_source_fail_closed_unless_exempt() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("pylock.toml"),
        "lock-version = \"1.0\"\n\n[[packages]]\nname = \"corp-lib\"\nversion = \"1.0.0\"\n[packages.vcs]\ntype = \"git\"\nurl = \"https://git.corp.example/lib\"\n\n[[packages]]\nname = \"six\"\nversion = \"1.16.0\"\n",
    )
    .unwrap();
    let args = ["uv", "pip", "sync", "pylock.toml"];
    let (code, out) = run_in(dir.path(), &args);
    assert_eq!(code, Some(1));
    assert!(
        out.contains("corp-lib@1.0.0") && out.contains("do not come from PyPI"),
        "{out}"
    );
    assert!(
        !out.contains("Testing"),
        "nothing is scanned when refused: {out}"
    );

    std::fs::write(
        dir.path().join("gyrseek.yaml"),
        "internal_package_exemptions:\n  - corp-lib\n",
    )
    .unwrap();
    let (code, out) = run_in(dir.path(), &args);
    assert_eq!(code, Some(1), "no Docker, so the scan itself fails closed");
    assert!(out.contains("Testing 2"), "{out}");
}
