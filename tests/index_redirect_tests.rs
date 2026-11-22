//! An install that a package-manager setting sends to another registry than the public one gyrseek
//! scans is refused, unless the host is listed in `trusted_index_hosts`. A stand-in package
//! manager records whether (and with what) it was run. Packages are exempt so a permitted
//! install needs neither Docker nor the network.
mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Runs `gyrseek <args>` in `dir/project` with HOME set to `dir/home`; returns the exit code,
/// gyrseek's output and the arguments the fake manager received (None if it never ran).
fn run(
    dir: &Path,
    args: &[&str],
    envs: &[(&str, &str)],
) -> (Option<i32>, String, Option<Vec<String>>) {
    let shim = dir.join("shim");
    fs::create_dir_all(&shim).unwrap();
    let record = dir.join("recorded-args");
    let _ = fs::remove_file(&record); // a previous run in the same directory must not be mistaken for this one
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
        .current_dir(dir.join("project"))
        .env("PATH", path)
        .env("HOME", dir.join("home"))
        .env("XDG_CONFIG_HOME", dir.join("home/.config"))
        .env("RECORD", &record)
        .env("GYRSEEK_TEST_BYPASS_RUNNER_INIT", "1")
        .envs(envs.iter().copied())
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

/// A project directory with the given files, a gyrseek.yaml and an empty home.
fn project(files: &[(&str, &str)], config: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("project")).unwrap();
    fs::create_dir_all(dir.path().join("home")).unwrap();
    for (name, content) in files {
        fs::write(dir.path().join("project").join(name), content).unwrap();
    }
    fs::write(dir.path().join("project/gyrseek.yaml"), config).unwrap();
    dir
}

const EXEMPT_SIX: &str = "internal_package_exemptions:\n  - six\n";
const EVIL: &str = "https://user:s3cr3t@nexus.corp.example/repo/simple";
const NPM_LOCK: &str = r#"{"lockfileVersion":3,"packages":{"node_modules/left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}}"#;

fn assert_refused(code: Option<i32>, out: &str, seen: &Option<Vec<String>>) {
    assert_eq!(code, Some(1), "{out}");
    assert!(
        out.contains("trusted_index_hosts") && out.contains("nexus.corp.example"),
        "{out}"
    );
    assert!(
        !out.contains("s3cr3t") && !out.contains("/repo/simple"),
        "only the host is printed: {out}"
    );
    assert!(seen.is_none(), "the package manager must not run: {seen:?}");
}

#[test]
fn a_flag_that_points_pip_at_another_index_is_refused_and_a_trusted_host_is_let_through() {
    let dir = project(&[], EXEMPT_SIX);
    let args = ["pip", "install", "six==1.16.0", "--index-url", EVIL];
    let (code, out, seen) = run(dir.path(), &args, &[]);
    assert_refused(code, &out, &seen);

    fs::write(
        dir.path().join("project/gyrseek.yaml"),
        format!("{EXEMPT_SIX}trusted_index_hosts:\n  - Nexus.Corp.Example\n"),
    )
    .unwrap();
    let (code, out, seen) = run(dir.path(), &args, &[]);
    assert_eq!(code, Some(0), "{out}");
    assert_eq!(
        seen.unwrap()[..3],
        ["install", "six==1.16.0", "--index-url"]
    );
}

#[test]
fn environment_variables_and_config_files_are_refused_too() {
    let dir = project(&[], EXEMPT_SIX);
    let (code, out, seen) = run(
        dir.path(),
        &["pip", "install", "six==1.16.0"],
        &[("PIP_INDEX_URL", EVIL)],
    );
    assert_refused(code, &out, &seen);
    assert!(out.contains("PIP_INDEX_URL"), "{out}");

    fs::create_dir_all(dir.path().join("home/.config/pip")).unwrap();
    fs::write(
        dir.path().join("home/.config/pip/pip.conf"),
        format!("[global]\nindex-url = {EVIL}\n"),
    )
    .unwrap();
    let (code, out, seen) = run(dir.path(), &["pip", "install", "six==1.16.0"], &[]);
    assert_refused(code, &out, &seen);
    assert!(out.contains("pip.conf"), "{out}");

    let dir = project(
        &[(
            "requirements.txt",
            &format!("six==1.16.0\n--extra-index-url {EVIL}\n"),
        )],
        EXEMPT_SIX,
    );
    let (code, out, seen) = run(
        dir.path(),
        &["pip", "install", "-r", "requirements.txt"],
        &[],
    );
    assert_refused(code, &out, &seen);
}

#[test]
fn an_npmrc_registry_is_refused_for_npm_and_pnpm_until_its_host_is_trusted() {
    let rc = format!("registry={EVIL}\n");
    let dir = project(
        &[("package-lock.json", NPM_LOCK), (".npmrc", &rc)],
        "internal_package_exemptions:\n  - left-pad\n",
    );
    let (code, out, seen) = run(dir.path(), &["npm", "ci"], &[]);
    assert_refused(code, &out, &seen);
    assert!(out.contains(".npmrc"), "{out}");

    fs::write(
        dir.path().join("project/gyrseek.yaml"),
        "internal_package_exemptions:\n  - left-pad\ntrusted_index_hosts:\n  - nexus.corp.example\n",
    )
    .unwrap();
    let (code, out, seen) = run(dir.path(), &["npm", "ci"], &[]);
    assert_eq!(code, Some(0), "{out}");
    assert_eq!(seen.unwrap(), ["ci"]);

    let (code, out, seen) = run(
        dir.path(),
        &["npm", "ci", "--registry", "https://evil.example/"],
        &[],
    );
    assert_eq!(code, Some(1), "{out}");
    assert!(
        out.contains("--registry -> evil.example") && seen.is_none(),
        "{out}"
    );
}

#[test]
fn the_public_registry_and_unscanned_passthroughs_are_not_refused() {
    let dir = project(&[], EXEMPT_SIX);
    let public = [
        "pip",
        "install",
        "six==1.16.0",
        "--index-url",
        "https://pypi.org/simple",
    ];
    let (code, out, _) = run(dir.path(), &public, &[]);
    assert_eq!(code, Some(0), "{out}");
    // `uv venv` installs nothing and is never scanned, so a redirect setting does not matter.
    let (code, out, seen) = run(dir.path(), &["uv", "venv"], &[("UV_INDEX_URL", EVIL)]);
    assert_eq!(code, Some(0), "{out}");
    assert_eq!(seen.unwrap(), ["venv"]);
}

#[test]
fn bad_trusted_index_hosts_entries_are_ignored_with_a_warning() {
    let dir = project(
        &[],
        &format!("{EXEMPT_SIX}trusted_index_hosts:\n  - '*'\n  - '*.corp.example'\n  - 'a b'\n"),
    );
    let (code, out, seen) = run(
        dir.path(),
        &["pip", "install", "six==1.16.0", "--index-url", EVIL],
        &[],
    );
    assert_refused(code, &out, &seen);
    assert!(out.contains("Ignoring trusted_index_hosts entry"), "{out}");
}

#[test]
fn a_command_with_only_non_registry_specs_is_checked_too() {
    // Nothing is scanned on this path, but the package's own dependencies would still come from
    // the redirected registry.
    let dir = project(&[], "");
    let (code, out, seen) = run(
        dir.path(),
        &["npm", "install", "./local-pkg", "--registry", EVIL],
        &[],
    );
    assert_refused(code, &out, &seen);
    let (code, out, seen) = run(dir.path(), &["npm", "install", "./local-pkg"], &[]);
    assert_eq!(code, Some(0), "{out}");
    assert_eq!(seen.unwrap(), ["install", "./local-pkg"]);
}

#[test]
fn the_npmrc_of_the_project_root_applies_when_run_from_a_subdirectory() {
    let rc = format!("registry={EVIL}\n");
    let dir = project(
        &[("package.json", "{}"), (".npmrc", &rc)],
        "internal_package_exemptions:\n  - left-pad\n",
    );
    fs::create_dir_all(dir.path().join("project/sub")).unwrap();
    let shim = dir.path().join("shim");
    fs::create_dir_all(&shim).unwrap();
    fs::write(shim.join("npm"), "#!/bin/sh\ntouch \"$RECORD\"\n").unwrap();
    fs::set_permissions(shim.join("npm"), fs::Permissions::from_mode(0o755)).unwrap();
    let record = dir.path().join("ran");
    let output = common::gyrseek()
        .args([
            "--config",
            "../gyrseek.yaml",
            "npm",
            "install",
            "left-pad@1.3.0",
        ])
        .current_dir(dir.path().join("project/sub"))
        .env(
            "PATH",
            format!(
                "{}:{}",
                shim.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .env("HOME", dir.path().join("home"))
        .env("RECORD", &record)
        .env("GYRSEEK_TEST_BYPASS_RUNNER_INIT", "1")
        .output()
        .unwrap();
    let out = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(1), "{out}");
    assert!(
        out.contains(".npmrc: registry -> nexus.corp.example"),
        "{out}"
    );
    assert!(!record.exists(), "npm must not run");
}
