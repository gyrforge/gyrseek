use gyrseek::{
    parse_npm_install_packages_from_args,
    parse_npm_packages_from_package_json_content,
    parse_pip_install_packages_from_args,
    parse_poetry_lock_packages_from_content,
    parse_pylock_packages_from_content,
    parse_requirements_packages_from_content,
    parse_uv_lock_upgrade_packages_from_args,
    parse_uv_lock_packages_from_content,
    rewrite_args_with_pinned_versions,
    GyrSeek,
};
use std::collections::HashMap;
use std::fs;

// --- #2 pin the forwarded command to the exact scanned version ---

fn args(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

#[test]
fn pins_unpinned_npm_install_to_resolved_version() {
    let pins = HashMap::from([("left-pad".to_string(), "1.3.0".to_string())]);
    let out = rewrite_args_with_pinned_versions(
        "npm",
        &args(&["npm", "install", "left-pad"]),
        &pins,
    );
    assert_eq!(out, args(&["npm", "install", "left-pad@1.3.0"]));
}

#[test]
fn pins_scoped_npm_package() {
    let pins = HashMap::from([("@scope/pkg".to_string(), "2.5.1".to_string())]);
    let out = rewrite_args_with_pinned_versions(
        "npm",
        &args(&["npm", "install", "@scope/pkg"]),
        &pins,
    );
    assert_eq!(out, args(&["npm", "install", "@scope/pkg@2.5.1"]));
}

#[test]
fn does_not_repin_npm_package_that_already_has_a_version() {
    let pins = HashMap::from([("left-pad".to_string(), "1.3.0".to_string())]);
    let out = rewrite_args_with_pinned_versions(
        "npm",
        &args(&["npm", "install", "left-pad@1.2.0"]),
        &pins,
    );
    // User explicitly asked for 1.2.0; leave it untouched.
    assert_eq!(out, args(&["npm", "install", "left-pad@1.2.0"]));
}

#[test]
fn pins_unpinned_pip_install_to_resolved_version() {
    let pins = HashMap::from([("requests".to_string(), "2.31.0".to_string())]);
    let out = rewrite_args_with_pinned_versions(
        "pip",
        &args(&["pip", "install", "requests"]),
        &pins,
    );
    assert_eq!(out, args(&["pip", "install", "requests==2.31.0"]));
}

#[test]
fn pins_pip_package_with_extras() {
    let pins = HashMap::from([("requests".to_string(), "2.31.0".to_string())]);
    let out = rewrite_args_with_pinned_versions(
        "pip",
        &args(&["pip", "install", "requests[security]"]),
        &pins,
    );
    assert_eq!(out, args(&["pip", "install", "requests[security]==2.31.0"]));
}

#[test]
fn leaves_pip_flags_and_pinned_specs_untouched() {
    let pins = HashMap::from([("requests".to_string(), "2.31.0".to_string())]);
    let out = rewrite_args_with_pinned_versions(
        "pip",
        &args(&["pip", "install", "--no-cache-dir", "requests==2.30.0"]),
        &pins,
    );
    assert_eq!(out, args(&["pip", "install", "--no-cache-dir", "requests==2.30.0"]));
}

#[test]
fn pins_uv_pip_install_respecting_three_token_prefix() {
    let pins = HashMap::from([("flask".to_string(), "3.0.0".to_string())]);
    let out = rewrite_args_with_pinned_versions(
        "uv",
        &args(&["uv", "pip", "install", "flask"]),
        &pins,
    );
    assert_eq!(out, args(&["uv", "pip", "install", "flask==3.0.0"]));
}

#[test]
fn empty_pins_is_a_noop() {
    let out = rewrite_args_with_pinned_versions(
        "npm",
        &args(&["npm", "install", "left-pad"]),
        &HashMap::new(),
    );
    assert_eq!(out, args(&["npm", "install", "left-pad"]));
}

#[test]
fn does_not_pin_unrelated_packages() {
    let pins = HashMap::from([("requests".to_string(), "2.31.0".to_string())]);
    let out = rewrite_args_with_pinned_versions(
        "pip",
        &args(&["pip", "install", "flask"]),
        &pins,
    );
    // flask isn't in the pin set, so it's left as-is.
    assert_eq!(out, args(&["pip", "install", "flask"]));
}

#[test]
fn parses_uv_add_as_latest_when_unpinned() {
    let eye = GyrSeek::new(vec!["uv".to_string(), "add".to_string(), "pytest".to_string()]);
    let (pkg, version) = eye.parse_package_details();

    assert_eq!(pkg.as_deref(), Some("pytest"));
    assert_eq!(version, None);
}

#[test]
fn parses_uv_pip_install_with_pinned_version() {
    let eye = GyrSeek::new(vec![
        "uv".to_string(),
        "pip".to_string(),
        "install".to_string(),
        "requests==2.31.0".to_string(),
    ]);
    let (pkg, version) = eye.parse_package_details();

    assert_eq!(pkg.as_deref(), Some("requests"));
    assert_eq!(version.as_deref(), Some("2.31.0"));
}

#[test]
fn parses_poetry_update_as_latest_when_unpinned() {
    let eye = GyrSeek::new(vec!["poetry".to_string(), "update".to_string(), "pytest".to_string()]);
    let (pkg, version) = eye.parse_package_details();

    assert_eq!(pkg.as_deref(), Some("pytest"));
    assert_eq!(version, None);
}

#[test]
fn ignores_non_install_commands() {
    let eye = GyrSeek::new(vec!["uv".to_string(), "run".to_string(), "script.py".to_string()]);
    let (pkg, version) = eye.parse_package_details();

    assert_eq!(pkg, None);
    assert_eq!(version, None);
}

#[test]
fn parses_npm_install_as_latest_when_unpinned() {
    let eye = GyrSeek::new(vec!["npm".to_string(), "install".to_string(), "lodash".to_string()]);
    let (pkg, version) = eye.parse_package_details();

    assert_eq!(pkg.as_deref(), Some("lodash"));
    assert_eq!(version, None);
}

#[test]
fn parses_npm_install_with_pinned_version() {
    let eye = GyrSeek::new(vec!["npm".to_string(), "install".to_string(), "lodash@4.17.21".to_string()]);
    let (pkg, version) = eye.parse_package_details();

    assert_eq!(pkg.as_deref(), Some("lodash"));
    assert_eq!(version.as_deref(), Some("4.17.21"));
}

#[test]
fn uv_sync_has_no_single_package_target() {
    let eye = GyrSeek::new(vec!["uv".to_string(), "sync".to_string()]);
    let (pkg, version) = eye.parse_package_details();

    assert_eq!(pkg, None);
    assert_eq!(version, None);
}

#[test]
fn parses_uv_lock_packages_for_sync_scanning() {
    let lock = r#"
version = 1

[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "pytest"
version = "9.0.1"
"#;

    let parsed = parse_uv_lock_packages_from_content(lock);
    assert_eq!(
        parsed,
        vec![
            ("requests".to_string(), "2.31.0".to_string()),
            ("pytest".to_string(), "9.0.1".to_string())
        ]
    );
}

#[test]
fn skips_local_project_package_from_uv_lock_scanning() {
    let lock = r#"
version = 1

[[package]]
name = "test"
version = "0.1.0"
source = { editable = "." }

[[package]]
name = "requests"
version = "2.31.0"
"#;

    let parsed = parse_uv_lock_packages_from_content(lock);
    assert_eq!(
        parsed,
        vec![("requests".to_string(), "2.31.0".to_string())]
    );
}

#[test]
fn parses_requirements_packages_for_uv_pip_sync() {
    let requirements = r#"
# comment
requests==2.31.0
pytest
-r dev-requirements.txt
"#;

    let parsed = parse_requirements_packages_from_content(requirements);
    assert_eq!(
        parsed,
        vec![
            ("requests".to_string(), Some("2.31.0".to_string())),
            ("pytest".to_string(), None),
        ]
    );
}

#[test]
fn parses_pylock_packages_for_uv_pip_sync() {
    let pylock = r#"
version = 1

[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "pytest"
version = "9.0.1"

[[package]]
name = "local-editable"
"#;

    let parsed = parse_pylock_packages_from_content(pylock);
    assert_eq!(
        parsed,
        vec![
            ("requests".to_string(), Some("2.31.0".to_string())),
            ("pytest".to_string(), Some("9.0.1".to_string())),
            ("local-editable".to_string(), None),
        ]
    );
}

#[test]
fn parses_pip_install_multi_packages_and_requirements_file() {
    let req_path = std::env::temp_dir().join(format!(
        "gyrseek-requirements-{}-{}.txt",
        std::process::id(),
        1
    ));
    fs::write(&req_path, "requests==2.31.0\npytest\n").unwrap();

    let args = vec![
        "pip3".to_string(),
        "install".to_string(),
        "-r".to_string(),
        req_path.to_string_lossy().to_string(),
        "flask==3.0.0".to_string(),
    ];

    let parsed = parse_pip_install_packages_from_args(&args);
    assert_eq!(
        parsed,
        vec![
            ("requests".to_string(), Some("2.31.0".to_string())),
            ("pytest".to_string(), None),
            ("flask".to_string(), Some("3.0.0".to_string())),
        ]
    );

    let _ = fs::remove_file(req_path);
}

#[test]
fn parses_poetry_lock_packages_for_install_scanning() {
    let lock = r#"
[[package]]
name = "pytest"
version = "9.0.3"

[[package]]
name = "requests"
version = "2.31.0"
"#;

    let parsed = parse_poetry_lock_packages_from_content(lock);
    assert_eq!(
        parsed,
        vec![
            ("pytest".to_string(), "9.0.3".to_string()),
            ("requests".to_string(), "2.31.0".to_string()),
        ]
    );
}

#[test]
fn skips_local_project_package_from_poetry_lock_scanning() {
    let lock = r#"
[[package]]
name = "test"
version = "0.1.0"
develop = true

[package.source]
type = "directory"
url = "."

[[package]]
name = "requests"
version = "2.31.0"
"#;

    let parsed = parse_poetry_lock_packages_from_content(lock);
    assert_eq!(
        parsed,
        vec![("requests".to_string(), "2.31.0".to_string())]
    );
}

#[test]
fn parses_npm_install_multi_packages_from_args() {
    let args = vec![
        "npm".to_string(),
        "install".to_string(),
        "lodash@4.17.21".to_string(),
        "express".to_string(),
    ];

    let parsed = parse_npm_install_packages_from_args(&args);
    assert_eq!(
        parsed,
        vec![
            ("lodash".to_string(), Some("4.17.21".to_string())),
            ("express".to_string(), None),
        ]
    );
}

#[test]
fn parses_npm_update_multi_packages_from_args() {
    let args = vec![
        "npm".to_string(),
        "update".to_string(),
        "lodash".to_string(),
        "typescript".to_string(),
    ];

    let parsed = parse_npm_install_packages_from_args(&args);
    assert_eq!(
        parsed,
        vec![
            ("lodash".to_string(), None),
            ("typescript".to_string(), None),
        ]
    );
}

#[test]
fn parses_npm_packages_from_package_json_content() {
    let package_json = r#"
{
  "name": "demo",
  "dependencies": {
    "lodash": "^4.17.21",
    "axios": "1.8.2"
  },
  "devDependencies": {
    "vitest": "~1.6.0"
  }
}
"#;

    let mut parsed = parse_npm_packages_from_package_json_content(package_json);
    parsed.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        parsed,
        vec![
            ("axios".to_string(), Some("1.8.2".to_string())),
            ("lodash".to_string(), None),
            ("vitest".to_string(), None),
        ]
    );
}

#[test]
fn skips_local_source_npm_dependencies_from_package_json_content() {
        let package_json = r#"
{
    "name": "demo",
    "dependencies": {
        "local-file": "file:../local-file",
        "local-workspace": "workspace:*",
        "git-dep": "git+https://github.com/example/repo.git",
        "url-dep": "https://example.com/pkg.tgz",
        "axios": "1.8.2"
    }
}
"#;

        let parsed = parse_npm_packages_from_package_json_content(package_json);
        assert_eq!(parsed, vec![("axios".to_string(), Some("1.8.2".to_string()))]);
}

#[test]
fn parses_uv_lock_upgrade_packages_multi_targets() {
    let args = vec![
        "uv".to_string(),
        "lock".to_string(),
        "-P".to_string(),
        "pytest".to_string(),
        "--upgrade-package=requests".to_string(),
        "--dry-run".to_string(),
    ];

    let parsed = parse_uv_lock_upgrade_packages_from_args(&args);
    assert_eq!(parsed, vec!["pytest".to_string(), "requests".to_string()]);
}