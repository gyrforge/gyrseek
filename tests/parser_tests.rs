use gyrseek::{
    parse_npm_install_packages_from_args,
    parse_npm_packages_from_package_json_content,
    parse_pip_install_packages_from_args,
    parse_poetry_lock_packages_from_content,
    parse_pylock_packages_from_content,
    parse_requirements_packages_from_content,
    parse_uv_lock_upgrade_packages_from_args,
    parse_uv_lock_packages_from_content,
    GyrSeek,
};
use std::fs;

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