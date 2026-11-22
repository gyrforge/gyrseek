//! What is actually forwarded after a clear lockfile scan, observed with a stand-in package manager
//! that records its arguments. Every locked package is listed in `internal_package_exemptions`, so
//! the scan needs neither Docker nor the network.
mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Runs `gyrseek <args>` in `dir` with a fake `<args[0]>` first on PATH; returns the exit code,
/// gyrseek's output and the arguments the fake manager received (None if it never ran).
fn run(dir: &Path, args: &[&str]) -> (Option<i32>, String, Option<Vec<String>>) {
    let shim = dir.join("shim");
    fs::create_dir_all(&shim).unwrap();
    let record = dir.join("recorded-args");
    let _ = fs::remove_file(&record);
    let script = shim.join(args[0]);
    fs::write(&script, "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$RECORD\"\n").unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!(
        "{}:{}",
        shim.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = common::gyrseek()
        .args(args)
        .current_dir(dir)
        .env("PATH", path)
        .env("RECORD", &record)
        .env("GYRSEEK_TEST_BYPASS_RUNNER_INIT", "1")
        .output()
        .expect("gyrseek process should run");
    let seen = fs::read_to_string(&record)
        .ok()
        .map(|s| s.lines().map(str::to_string).collect());
    (
        output.status.code(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
        seen,
    )
}

fn project(files: &[(&str, &str)], exempt: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for (name, content) in files {
        fs::write(dir.path().join(name), content).unwrap();
    }
    fs::write(
        dir.path().join("gyrseek.yaml"),
        format!("internal_package_exemptions:\n  - {exempt}\n"),
    )
    .unwrap();
    dir
}

const UV_LOCK: &str = "version = 1\n\n[[package]]\nname = \"six\"\nversion = \"1.16.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n";

#[test]
fn uv_sync_is_forwarded_with_locked() {
    let dir = project(&[("uv.lock", UV_LOCK)], "six");
    let (code, out, seen) = run(dir.path(), &["uv", "sync", "--no-dev"]);
    assert_eq!(code, Some(0), "{out}");
    assert_eq!(seen.unwrap(), ["sync", "--locked", "--no-dev"], "{out}");
    assert!(out.contains("Installing exactly what was scanned"), "{out}");
}

#[test]
fn uv_sync_that_is_already_locked_or_frozen_is_forwarded_as_typed() {
    let dir = project(&[("uv.lock", UV_LOCK)], "six");
    for flag in ["--locked", "--frozen"] {
        let (code, out, seen) = run(dir.path(), &["uv", "sync", flag]);
        assert_eq!(code, Some(0), "{out}");
        assert_eq!(seen.unwrap(), ["sync", flag], "{out}");
        assert!(
            !out.contains("Installing exactly what was scanned"),
            "{out}"
        );
    }
}

#[test]
fn uv_sync_that_picks_new_versions_is_refused_before_the_scan_and_never_forwarded() {
    let dir = project(&[("uv.lock", UV_LOCK)], "six");
    for flag in ["--upgrade", "-U", "--upgrade-package=six"] {
        let (code, out, seen) = run(dir.path(), &["uv", "sync", flag]);
        assert_eq!(code, Some(1), "{flag}: {out}");
        assert!(
            out.contains("uv.lock it scanned") && !out.contains("Testing"),
            "{flag}: {out}"
        );
        assert!(seen.is_none(), "{flag}: the package manager must not run");
    }
}

#[test]
fn npm_install_is_forwarded_as_npm_ci() {
    let lock = r#"{"lockfileVersion":3,"packages":{"node_modules/left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}}"#;
    let dir = project(&[("package-lock.json", lock)], "left-pad");
    for (args, expected) in [
        (&["npm", "install"][..], &["ci"][..]),
        (&["npm", "i", "--omit=dev"], &["ci", "--omit=dev"]),
        (&["npm", "ci"], &["ci"]),
    ] {
        let (code, out, seen) = run(dir.path(), args);
        assert_eq!(code, Some(0), "{args:?}: {out}");
        assert_eq!(seen.unwrap(), expected, "{args:?}: {out}");
    }
}

#[test]
fn pnpm_install_is_forwarded_with_frozen_lockfile() {
    let lock = "lockfileVersion: '9.0'\npackages:\n  left-pad@1.3.0:\n    resolution: {integrity: sha512-a}\nsnapshots: {}\n";
    let dir = project(&[("pnpm-lock.yaml", lock)], "left-pad");
    let (code, out, seen) = run(dir.path(), &["pnpm", "install", "--prod"]);
    assert_eq!(code, Some(0), "{out}");
    assert_eq!(
        seen.unwrap(),
        ["install", "--frozen-lockfile", "--prod"],
        "{out}"
    );
}
