use gyrseek::GyrSeek;

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