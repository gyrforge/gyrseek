use std::process::Command;

fn run(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_gyrseek"))
        .args(args)
        .env("GYRSEEK_TEST_BYPASS_RUNNER_INIT", "1")
        .env("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0")
        .output()
        .expect("gyrseek process should run");
    assert_eq!(
        output.status.code(),
        Some(1),
        "no Docker: the scan must fail closed"
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

#[test]
fn uv_pip_install_scans_every_named_package() {
    let out = run(&["uv", "pip", "install", "six==1.16.0", "pandas==2.2.2"]);
    assert!(
        out.contains("'uv pip install' detected. Testing 2 package(s)"),
        "both packages must be scanned, got: {out}"
    );
}

#[test]
fn uv_add_scans_every_named_package_and_skips_flag_values() {
    let out = run(&["uv", "add", "--group", "dev", "pytest", "ruff==0.5.0"]);
    assert!(
        out.contains("'uv add' detected. Testing 2 package(s)"),
        "`dev` is a flag value, not a package; pytest and ruff are, got: {out}"
    );
}

#[test]
fn poetry_add_scans_every_named_package() {
    let out = run(&["poetry", "add", "-G", "dev", "pytest", "requests==2.31.0"]);
    assert!(
        out.contains("'poetry add' detected. Testing 2 package(s)"),
        "both packages must be scanned, got: {out}"
    );
}

#[test]
fn uv_pip_install_requirements_file_is_scanned() {
    let dir = tempfile::tempdir().expect("temp dir");
    let req = dir.path().join("req.txt");
    std::fs::write(&req, "six==1.16.0\npandas==2.2.2\n").unwrap();
    let out = run(&["uv", "pip", "install", "-r", req.to_str().unwrap(), "attrs"]);
    assert!(
        out.contains("'uv pip install' detected. Testing 3 package(s)"),
        "requirements file entries and the named package must all be scanned, got: {out}"
    );
}

#[test]
fn packages_in_an_included_requirements_file_are_scanned() {
    let dir = tempfile::tempdir().expect("temp dir");
    std::fs::write(dir.path().join("base.txt"), "six==1.16.0\npandas==2.2.2\n").unwrap();
    let top = dir.path().join("requirements.txt");
    std::fs::write(&top, "attrs==24.2.0\n-r base.txt\n").unwrap();
    let out = run(&["pip", "install", "-r", top.to_str().unwrap()]);
    assert!(
        out.contains("'pip' install detected. Testing 3 package(s)"),
        "the included file's packages must be scanned too, got: {out}"
    );
}

#[test]
fn r_pyproject_toml_fails_closed_instead_of_scanning_a_package_named_after_the_file() {
    let out = run(&["uv", "pip", "install", "-r", "./pyproject.toml"]);
    assert!(
        out.contains("cannot resolve to a scanned version"),
        "got: {out}"
    );
    assert!(
        !out.contains("Testing"),
        "no package may be scanned, got: {out}"
    );
}

#[test]
fn version_ranges_exit_1_with_a_message_about_exact_versions() {
    for args in [
        &["uv", "add", "pytest>=9.0.3"][..],
        &["pip", "install", "requests", "six~=1.16"],
        &["poetry", "add", "requests@^2.0"],
    ] {
        let out = run(args);
        assert!(out.contains("version range"), "{args:?}: {out}");
        assert!(out.contains("exact versions"), "{args:?}: {out}");
        assert!(
            !out.contains("Testing"),
            "nothing may be scanned for {args:?}: {out}"
        );
    }
}

#[test]
fn direct_references_are_not_scanned_as_if_they_were_registry_packages() {
    let out = run(&["pip", "install", "requests @ https://evil.example/r.whl"]);
    assert!(out.contains("not from the registry"), "got: {out}");
    assert!(!out.contains("Testing"), "got: {out}");
}

#[test]
fn an_attached_r_option_and_unpinned_file_lines_are_not_missed() {
    let dir = tempfile::tempdir().expect("temp dir");
    let hidden = dir.path().join("hidden.txt");
    std::fs::write(&hidden, "pandas==2.2.2\n").unwrap();
    let out = run(&[
        "pip",
        "install",
        "six==1.16.0",
        &format!("-r{}", hidden.display()),
    ]);
    assert!(
        out.contains("Testing 2 package(s)"),
        "-rFILE must be scanned, got: {out}"
    );

    let bare = dir.path().join("bare.txt");
    std::fs::write(&bare, "six==1.16.0\nrequests\n").unwrap();
    let out = run(&["pip", "install", "-r", bare.to_str().unwrap()]);
    assert!(out.contains("no pinned version"), "got: {out}");
    assert!(!out.contains("Testing"), "got: {out}");
}

#[test]
fn install_with_no_package_names_fails_closed() {
    let out = run(&["uv", "add", "--dev"]);
    assert!(
        out.contains("no parseable package entries were found. Failing closed."),
        "got: {out}"
    );
}

#[test]
fn a_missing_requirements_file_fails_closed_for_every_spelling() {
    for flag in [
        &["-r", "/no/such/req.txt"][..],
        &["--requirement", "/no/such/req.txt"],
        &["--requirement=/no/such/req.txt"],
        &["-r/no/such/req.txt"],
    ] {
        let mut args = vec!["pip", "install"];
        args.extend_from_slice(flag);
        let out = run(&args);
        assert!(
            out.contains("Cannot read the requirements file"),
            "{flag:?}: {out}"
        );
        assert!(!out.contains("Testing"), "{flag:?}: {out}");
    }
}

#[test]
fn spaced_ranges_markers_and_poetry_latest_are_classified_correctly() {
    let out = run(&["pip", "install", "requests >= 2"]);
    assert!(out.contains("version range"), "{out}");
    let out = run(&["pip", "install", "re quests==1.0"]);
    assert!(out.contains("space inside"), "{out}");
    // Exact, with spaces and a marker, is accepted and scanned.
    let out = run(&["pip", "install", "six == 1.16.0 ; python_version >= '3.8'"]);
    assert!(out.contains("Testing 1 package(s)"), "{out}");
    let out = run(&["poetry", "add", "requests@latest"]);
    assert!(out.contains("Testing 1 package(s)"), "{out}");
}

#[test]
fn requirements_files_from_windows_editors_and_include_cycles_work() {
    let dir = tempfile::tempdir().expect("temp dir");
    let a = dir.path().join("a.txt");
    let b = dir.path().join("b.txt");
    std::fs::write(&a, "\u{feff}six==1.16.0\r\n-r b.txt\r\n").unwrap();
    std::fs::write(&b, "attrs==24.2.0\r\n-r a.txt\r\n").unwrap();
    let out = run(&["pip", "install", "-r", a.to_str().unwrap()]);
    assert!(
        out.contains("Testing 2 package(s)"),
        "BOM, CRLF and a cycle must all be fine: {out}"
    );
}

#[test]
fn an_empty_requirements_file_fails_closed_instead_of_scanning_nothing() {
    let dir = tempfile::tempdir().expect("temp dir");
    let empty = dir.path().join("empty.txt");
    std::fs::write(&empty, "# nothing here\n\n").unwrap();
    let out = run(&["pip", "install", "-r", empty.to_str().unwrap()]);
    assert!(out.contains("no parseable package entries"), "{out}");
}
