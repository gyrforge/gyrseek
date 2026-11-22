use std::fs;
use std::path::Path;
use std::process::Command;

fn run(dir: &Path, args: &[&str]) -> (Option<i32>, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_gyrseek"))
        .args(args)
        .current_dir(dir)
        .env("GYRSEEK_TEST_BYPASS_RUNNER_INIT", "1")
        .env("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0")
        .output()
        .expect("gyrseek process should run");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).to_string(),
    )
}

fn project_with_lock() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    fs::write(
        dir.path().join("package.json"),
        r#"{"dependencies":{"left-pad":"^1.3.0","is-odd":"~3.0.0"}}"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"":{"name":"app"},
            "node_modules/left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"},
            "node_modules/is-odd":{"version":"3.0.1","resolved":"https://registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz"}}}"#,
    )
    .unwrap();
    dir
}

#[test]
fn npm_install_ci_and_i_scan_the_exact_versions_in_the_lockfile() {
    let dir = project_with_lock();
    for (args, label) in [
        (&["npm", "install"][..], "'install'"),
        (&["npm", "i"], "'i'"),
        (&["npm", "ci"], "'ci'"),
    ] {
        let (code, out) = run(dir.path(), args);
        assert_eq!(code, Some(1), "no Docker: the scan must fail closed");
        assert!(
            out.contains(&format!("{label} detected. Testing 2 package(s)")),
            "{args:?}: both locked packages must be scanned, got: {out}"
        );
    }
}

#[test]
fn without_a_lockfile_the_install_fails_closed_and_says_how_to_create_one() {
    let dir = tempfile::tempdir().expect("temp dir");
    fs::write(
        dir.path().join("package.json"),
        r#"{"dependencies":{"left-pad":"^1.3.0"}}"#,
    )
    .unwrap();
    for args in [&["npm", "install"][..], &["npm", "ci"]] {
        let (code, out) = run(dir.path(), args);
        assert_eq!(code, Some(1), "{args:?}");
        assert!(
            out.contains("No npm-shrinkwrap.json or package-lock.json"),
            "{args:?}: {out}"
        );
        assert!(
            out.contains("npm install --package-lock-only"),
            "{args:?}: {out}"
        );
        assert!(!out.contains("Testing"), "nothing may be scanned: {out}");
    }
    let (code, out) = run(dir.path(), &["pnpm", "install"]);
    assert_eq!(code, Some(1));
    assert!(out.contains("pnpm install --lockfile-only"), "{out}");
}

#[test]
fn npm_shrinkwrap_takes_precedence_over_package_lock() {
    let dir = project_with_lock(); // package-lock.json lists 2 packages
    fs::write(
        dir.path().join("npm-shrinkwrap.json"),
        r#"{"lockfileVersion":3,"packages":{"":{"name":"app"},
            "node_modules/left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}}"#,
    )
    .unwrap();
    let (_, out) = run(dir.path(), &["npm", "ci"]);
    assert!(
        out.contains("'ci' detected. Testing 1 package(s)"),
        "npm uses npm-shrinkwrap.json when both exist, got: {out}"
    );
}

#[test]
fn lockfile_only_flag_set_to_false_is_scanned_not_forwarded() {
    let dir = project_with_lock();
    for args in [
        &["npm", "install", "--package-lock-only", "false"][..],
        &["npm", "install", "--package-lock-only=false"],
        &["npm", "install", "--no-package-lock-only"],
    ] {
        let (code, out) = run(dir.path(), args);
        assert_eq!(code, Some(1), "{args:?}");
        assert!(out.contains("Testing 2 package(s)"), "{args:?}: {out}");
        assert!(!out.contains("Lockfile-only"), "{args:?}: {out}");
    }
}

#[test]
fn lockfile_only_commands_are_forwarded_with_ignore_scripts() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (_, out) = run(dir.path(), &["npm", "install", "--package-lock-only"]);
    assert!(out.contains("--ignore-scripts"), "{out}");
}

#[test]
fn update_without_packages_exits_1_with_the_lockfile_only_route() {
    let dir = project_with_lock();
    let (code, out) = run(dir.path(), &["npm", "update"]);
    assert_eq!(code, Some(1));
    assert!(out.contains("npm update --package-lock-only"), "{out}");
    assert!(!out.contains("Testing"), "{out}");
}

#[test]
fn ranges_on_the_command_line_are_scanned_at_the_latest_version() {
    let dir = project_with_lock();
    for args in [
        &["npm", "install", "lodash@^3.0.0"][..],
        &["npm", "install", "express", "lodash@>=4 <5"],
        &["pnpm", "add", "react@4.x"],
        &["npm", "update", "lodash@^3"],
    ] {
        let (code, out) = run(dir.path(), args);
        assert_eq!(
            code,
            Some(1),
            "no Docker: the scan itself fails closed, {args:?}"
        );
        assert!(
            out.contains("Testing"),
            "a range must reach the scan, {args:?}: {out}"
        );
        assert!(!out.contains("exact versions"), "{args:?}: {out}");
    }
}

#[test]
fn dist_tags_and_aliases_on_the_command_line_still_exit_1() {
    let dir = project_with_lock();
    for args in [
        &["pnpm", "add", "react@next"][..],
        &["npm", "install", "lodash@beta"],
        &["npm", "install", "foo@npm:bar@1.0.0"],
        &["npm", "install", "lodash@v"],
        &["pnpm", "add", "react@dev"],
    ] {
        let (code, out) = run(dir.path(), args);
        assert_eq!(code, Some(1), "{args:?}");
        assert!(
            out.contains("Failing closed") && out.contains("alias"),
            "{args:?}: {out}"
        );
        assert!(!out.contains("Testing"), "{args:?}: {out}");
    }
}

#[test]
fn lockfile_only_commands_are_forwarded_without_a_scan() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (_, out) = run(dir.path(), &["npm", "install", "--package-lock-only"]);
    assert!(out.contains("Lockfile-only command"), "{out}");
    assert!(!out.contains("Testing"), "{out}");
}

#[test]
fn empty_or_unparseable_lockfiles_fail_closed_instead_of_scanning_nothing() {
    for (name, content) in [
        ("package-lock.json", "{}"),
        (
            "package-lock.json",
            r#"{"lockfileVersion":3,"packages":{"":{"name":"app"}}}"#,
        ),
        ("package-lock.json", "this is not json"),
        ("package-lock.json", ""),
        ("npm-shrinkwrap.json", "[]"),
    ] {
        let dir = tempfile::tempdir().expect("temp dir");
        fs::write(dir.path().join(name), content).unwrap();
        let (code, out) = run(dir.path(), &["npm", "ci"]);
        assert_eq!(code, Some(1), "{name}: {content:?}");
        assert!(
            out.contains("lists no registry packages"),
            "{name}: {content:?}: {out}"
        );
        assert!(!out.contains("Testing"), "{name}: {out}");
    }
    let dir = tempfile::tempdir().expect("temp dir");
    fs::write(
        dir.path().join("pnpm-lock.yaml"),
        "lockfileVersion: '9.0'\n",
    )
    .unwrap();
    let (code, out) = run(dir.path(), &["pnpm", "install"]);
    assert_eq!(code, Some(1));
    assert!(out.contains("lists no registry packages"), "{out}");
}

#[test]
fn an_old_v1_lockfile_and_a_lockfile_with_git_sources_are_counted_correctly() {
    let dir = tempfile::tempdir().expect("temp dir");
    fs::write(
        dir.path().join("package-lock.json"),
        r#"{"lockfileVersion":1,"dependencies":{
            "left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"},
            "is-odd":{"version":"3.0.1","resolved":"https://registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz","dependencies":{
                "is-number":{"version":"6.0.0","resolved":"https://registry.npmjs.org/is-number/-/is-number-6.0.0.tgz"}}},
            "from-git":{"version":"github:user/repo#abc"}}}"#,
    )
    .unwrap();
    let (code, out) = run(dir.path(), &["npm", "ci"]);
    assert_eq!(code, Some(1));
    assert!(
        out.contains("Testing 3 package(s)"),
        "git source skipped, the rest counted: {out}"
    );
}

#[test]
fn flags_around_exact_specs_do_not_change_what_is_scanned() {
    let dir = project_with_lock();
    for args in [
        &["npm", "install", "-D", "left-pad@1.3.0"][..],
        &["npm", "install", "left-pad@1.3.0", "--save-exact"],
        &["pnpm", "add", "-D", "left-pad@1.3.0", "-w"],
    ] {
        let (code, out) = run(dir.path(), args);
        assert_eq!(code, Some(1), "{args:?}");
        assert!(out.contains("Testing 1 package(s)"), "{args:?}: {out}");
    }
}

#[test]
fn pnpm_install_and_i_with_frozen_lockfile_flags_scan_the_lockfile() {
    let dir = tempfile::tempdir().expect("temp dir");
    fs::write(
        dir.path().join("pnpm-lock.yaml"),
        "lockfileVersion: '9.0'\npackages:\n  left-pad@1.3.0:\n    resolution: {integrity: sha512-a}\nsnapshots: {}\n",
    )
    .unwrap();
    for args in [
        &["pnpm", "install", "--frozen-lockfile"][..],
        &["pnpm", "i", "--prefer-offline"],
        &["pnpm", "install"],
    ] {
        let (code, out) = run(dir.path(), args);
        assert_eq!(code, Some(1), "{args:?}");
        assert!(out.contains("Testing 1 package(s)"), "{args:?}: {out}");
    }
}
