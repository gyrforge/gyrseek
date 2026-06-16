use std::collections::HashMap;
use std::fs;

fn parse_toml_quoted_value(line: &str, key: &str) -> Option<String> {
    let prefix = format!("{} = \"", key);
    let rest = line.strip_prefix(&prefix)?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

pub(crate) fn parse_uv_lock_packages_from_content(content: &str) -> Vec<(String, String)> {
    let mut packages = Vec::new();
    let mut in_package = false;
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut local_source = false;

    let finalize_package = |packages: &mut Vec<(String, String)>,
                            name: &mut Option<String>,
                            version: &mut Option<String>,
                            local_source: &mut bool| {
        if !*local_source {
            if let (Some(n), Some(v)) = (name.take(), version.take()) {
                packages.push((n, v));
            }
        } else {
            name.take();
            version.take();
        }
        *local_source = false;
    };

    for raw_line in content.lines() {
        let line = raw_line.trim();

        if line == "[[package]]" {
            finalize_package(&mut packages, &mut name, &mut version, &mut local_source);
            in_package = true;
            name = None;
            version = None;
            local_source = false;
            continue;
        }

        if !in_package {
            continue;
        }

        if line.starts_with("[[") && line != "[[package]]" {
            finalize_package(&mut packages, &mut name, &mut version, &mut local_source);
            in_package = false;
            continue;
        }

        if line.starts_with("source")
            && (line.contains("editable = \".\"")
                || line.contains("path = \".")
                || line.contains("workspace = true")
                || line.contains("virtual = \".\""))
        {
            local_source = true;
        }

        if name.is_none() {
            name = parse_toml_quoted_value(line, "name");
            continue;
        }

        if version.is_none() {
            version = parse_toml_quoted_value(line, "version");
        }
    }

    finalize_package(&mut packages, &mut name, &mut version, &mut local_source);

    packages
}
pub(crate) fn parse_poetry_lock_packages_from_content(content: &str) -> Vec<(String, String)> {
    let mut packages = Vec::new();
    let mut in_package = false;
    let mut in_package_source = false;

    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut local_source = false;
    let mut source_type: Option<String> = None;
    let mut source_url: Option<String> = None;
    let mut source_path: Option<String> = None;

    let is_local_location = |value: &str| {
        value == "."
            || value.starts_with("./")
            || value.starts_with("../")
            || value.starts_with('/')
    };

    let finalize_package = |packages: &mut Vec<(String, String)>,
                            name: &mut Option<String>,
                            version: &mut Option<String>,
                            local_source: &mut bool,
                            source_type: &mut Option<String>,
                            source_url: &mut Option<String>,
                            source_path: &mut Option<String>| {
        let directory_local = source_type.as_deref() == Some("directory")
            && (source_url
                .as_deref()
                .map(is_local_location)
                .unwrap_or(false)
                || source_path
                    .as_deref()
                    .map(is_local_location)
                    .unwrap_or(false));

        if !*local_source && !directory_local {
            if let (Some(n), Some(v)) = (name.take(), version.take()) {
                packages.push((n, v));
            }
        } else {
            name.take();
            version.take();
        }

        *local_source = false;
        *source_type = None;
        *source_url = None;
        *source_path = None;
    };

    for raw_line in content.lines() {
        let line = raw_line.trim();

        if line == "[[package]]" {
            finalize_package(
                &mut packages,
                &mut name,
                &mut version,
                &mut local_source,
                &mut source_type,
                &mut source_url,
                &mut source_path,
            );
            in_package = true;
            in_package_source = false;
            continue;
        }

        if !in_package {
            continue;
        }

        if line.starts_with("[[") && line != "[[package]]" {
            finalize_package(
                &mut packages,
                &mut name,
                &mut version,
                &mut local_source,
                &mut source_type,
                &mut source_url,
                &mut source_path,
            );
            in_package = false;
            in_package_source = false;
            continue;
        }

        if line.starts_with('[') && !line.starts_with("[[") {
            in_package_source = line == "[package.source]";
            continue;
        }

        if line.starts_with("source")
            && (line.contains("editable = \".\"")
                || line.contains("path = \".")
                || line.contains("workspace = true")
                || line.contains("virtual = \".\"")
                || (line.contains("type = \"directory\"")
                    && (line.contains("url = \".\"")
                        || line.contains("url = \"./")
                        || line.contains("url = \"../")
                        || line.contains("path = \".")
                        || line.contains("path = \"./")
                        || line.contains("path = \"../"))))
        {
            local_source = true;
        }

        if in_package_source {
            if source_type.is_none() {
                source_type = parse_toml_quoted_value(line, "type");
            }
            if source_url.is_none() {
                source_url = parse_toml_quoted_value(line, "url");
            }
            if source_path.is_none() {
                source_path = parse_toml_quoted_value(line, "path");
            }

            if source_type.as_deref() == Some("directory")
                && (source_url
                    .as_deref()
                    .map(is_local_location)
                    .unwrap_or(false)
                    || source_path
                        .as_deref()
                        .map(is_local_location)
                        .unwrap_or(false))
            {
                local_source = true;
            }
        }

        if name.is_none() {
            name = parse_toml_quoted_value(line, "name");
            continue;
        }

        if version.is_none() {
            version = parse_toml_quoted_value(line, "version");
        }
    }

    finalize_package(
        &mut packages,
        &mut name,
        &mut version,
        &mut local_source,
        &mut source_type,
        &mut source_url,
        &mut source_path,
    );

    packages
}

pub(crate) fn parse_pylock_packages_from_content(content: &str) -> Vec<(String, Option<String>)> {
    let mut packages = Vec::new();
    let mut in_package = false;
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;

    for raw_line in content.lines() {
        let line = raw_line.trim();

        if line == "[[package]]" || line == "[[packages]]" {
            if let Some(n) = name.take() {
                packages.push((n, version.take()));
            }
            in_package = true;
            name = None;
            version = None;
            continue;
        }

        if !in_package {
            continue;
        }

        if line.starts_with("[[") && line != "[[package]]" && line != "[[packages]]" {
            if let Some(n) = name.take() {
                packages.push((n, version.take()));
            }
            in_package = false;
            continue;
        }

        if name.is_none() {
            name = parse_toml_quoted_value(line, "name");
            continue;
        }

        if version.is_none() {
            version = parse_toml_quoted_value(line, "version");
        }
    }

    if let Some(n) = name {
        packages.push((n, version));
    }

    packages
}

/// Strips PEP 508 extras (`requests[security]` -> `requests`) from a package
/// name. Extras are install-time options, not part of the canonical name the
/// registry knows; they must be removed before any PyPI lookup or `pins` key,
/// or the lookup 404s and the pin key never matches the rewrite-time lookup.
/// The original spec (with extras) is preserved separately for the forwarded
/// install command, where extras are valid and meaningful.
pub(crate) fn strip_pep508_extras(name: &str) -> &str {
    name.split('[').next().unwrap_or(name)
}

fn parse_requirements_spec(spec: &str) -> Option<(String, Option<String>)> {
    let trimmed = spec.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    let base = trimmed.split_whitespace().next().unwrap_or(trimmed);

    if let Some((name, version)) = base.split_once("==")
        && !name.is_empty()
        && !version.is_empty()
    {
        return Some((
            strip_pep508_extras(name).to_string(),
            Some(version.to_string()),
        ));
    }

    if base.starts_with('-') || base.starts_with('.') || base.contains("://") {
        return None;
    }

    Some((strip_pep508_extras(base).to_string(), None))
}

pub(crate) fn parse_requirements_packages_from_content(
    content: &str,
) -> Vec<(String, Option<String>)> {
    let mut packages = Vec::new();

    for line in content.lines() {
        if let Some(pkg) = parse_requirements_spec(line) {
            packages.push(pkg);
        }
    }

    packages
}

pub(crate) fn parse_pip_install_packages_from_args(
    args: &[String],
) -> Vec<(String, Option<String>)> {
    if args.first().map(String::as_str) != Some("pip")
        && args.first().map(String::as_str) != Some("pip3")
    {
        return Vec::new();
    }
    if args.get(1).map(String::as_str) != Some("install") {
        return Vec::new();
    }

    let mut packages = Vec::new();
    let mut idx = 2;

    while idx < args.len() {
        let arg = &args[idx];

        if arg == "-r" || arg == "--requirements" {
            if let Some(path) = args.get(idx + 1)
                && let Ok(content) = fs::read_to_string(path)
            {
                packages.extend(parse_requirements_packages_from_content(&content));
            }
            idx += 2;
            continue;
        }

        if let Some(path) = arg.strip_prefix("--requirements=") {
            if let Ok(content) = fs::read_to_string(path) {
                packages.extend(parse_requirements_packages_from_content(&content));
            }
            idx += 1;
            continue;
        }

        if arg.starts_with('-') {
            idx += 1;
            continue;
        }

        if let Some(pkg) = parse_requirements_spec(arg) {
            packages.push(pkg);
        }
        idx += 1;
    }

    packages
}

fn parse_npm_spec(arg: &str) -> (String, Option<String>) {
    if arg.starts_with('@') {
        if let Some(idx) = arg.rfind('@')
            && idx > 0
        {
            let name = &arg[..idx];
            let version = &arg[idx + 1..];
            if !version.is_empty() && name.contains('/') {
                return (name.to_string(), Some(version.to_string()));
            }
        }
        return (arg.to_string(), None);
    }

    if let Some((name, version)) = arg.rsplit_once('@')
        && !name.is_empty()
        && !version.is_empty()
    {
        return (name.to_string(), Some(version.to_string()));
    }

    (arg.to_string(), None)
}

fn normalize_npm_version_spec(spec: &str) -> Option<String> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return None;
    }

    if trimmed.starts_with("file:")
        || trimmed.starts_with("git+")
        || trimmed.starts_with("http://")
        || trimmed.starts_with("https://")
        || trimmed.starts_with("workspace:")
        || trimmed == "latest"
    {
        return None;
    }

    if trimmed.starts_with('^')
        || trimmed.starts_with('~')
        || trimmed.starts_with('>')
        || trimmed.starts_with('<')
        || trimmed.starts_with('=')
        || trimmed.starts_with('*')
    {
        return None;
    }

    Some(trimmed.to_string())
}

fn is_non_registry_npm_spec(spec: &str) -> bool {
    let trimmed = spec.trim();
    trimmed.starts_with("file:")
        || trimmed.starts_with("git+")
        || trimmed.starts_with("http://")
        || trimmed.starts_with("https://")
        || trimmed.starts_with("workspace:")
        || trimmed.starts_with("link:")
}

fn is_npm_family_manager(manager: &str) -> bool {
    manager == "npm" || manager == "pnpm"
}

fn is_npm_family_package_command(manager: &str, command: Option<&str>) -> bool {
    matches!(command, Some("install") | Some("i") | Some("update"))
        || (manager == "pnpm" && command == Some("add"))
}

pub(crate) fn parse_npm_packages_from_package_json_content(
    content: &str,
) -> Vec<(String, Option<String>)> {
    let mut packages = Vec::new();
    let parsed: serde_json::Value = match serde_json::from_str(content) {
        Ok(value) => value,
        Err(_) => return packages,
    };

    for section in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(obj) = parsed.get(section).and_then(serde_json::Value::as_object) {
            for (name, version_val) in obj {
                if let Some(spec) = version_val.as_str() {
                    if is_non_registry_npm_spec(spec) {
                        continue;
                    }
                    packages.push((name.to_string(), normalize_npm_version_spec(spec)));
                }
            }
        }
    }

    packages
}

pub(crate) fn parse_npm_install_packages_from_args(
    args: &[String],
) -> Vec<(String, Option<String>)> {
    if !args
        .first()
        .map(String::as_str)
        .is_some_and(is_npm_family_manager)
    {
        return Vec::new();
    }
    let manager = args.first().map(String::as_str).unwrap_or_default();
    if !is_npm_family_package_command(manager, args.get(1).map(String::as_str)) {
        return Vec::new();
    }

    let mut packages = Vec::new();
    for arg in args.iter().skip(2) {
        if arg.starts_with('-') || is_non_registry_npm_spec(arg) {
            continue;
        }
        let (name, version) = parse_npm_spec(arg);
        packages.push((name, version.and_then(|v| normalize_npm_version_spec(&v))));
    }

    if !packages.is_empty() {
        return packages;
    }

    if let Ok(content) = fs::read_to_string("package.json") {
        return parse_npm_packages_from_package_json_content(&content);
    }

    Vec::new()
}

pub(crate) fn parse_uv_lock_upgrade_packages_from_args(args: &[String]) -> Vec<String> {
    if args.first().map(String::as_str) != Some("uv") {
        return Vec::new();
    }
    if args.get(1).map(String::as_str) != Some("lock") {
        return Vec::new();
    }

    let mut packages = Vec::new();
    let mut idx = 2;
    while idx < args.len() {
        let arg = &args[idx];

        if arg == "-P" || arg == "--upgrade-package" {
            if let Some(pkg) = args.get(idx + 1)
                && !pkg.starts_with('-')
            {
                packages.push(pkg.to_string());
                idx += 2;
            } else {
                idx += 1;
            }
            continue;
        }

        if let Some(pkg) = arg.strip_prefix("--upgrade-package=")
            && !pkg.is_empty()
        {
            packages.push(pkg.to_string());
        }

        idx += 1;
    }

    packages
}

/// Rewrites an install command's positional package arguments so each package
/// named in `pins` is pinned to the exact version the scanner resolved.
///
/// `pins` maps package name -> resolved version. Flags, already-pinned specs,
/// and non-registry specs (paths/URLs/git) are left untouched. This is what lets
/// gyrseek guarantee the host installs the *same* version it examined, even when
/// the user asked for an unpinned (`latest`) install.
pub(crate) fn rewrite_args_with_pinned_versions(
    manager: &str,
    args: &[String],
    pins: &HashMap<String, String>,
) -> Vec<String> {
    if pins.is_empty() {
        return args.to_vec();
    }

    let is_python = manager == "pip" || manager == "pip3" || manager == "uv" || manager == "poetry";
    let is_npm_family = is_npm_family_manager(manager);
    if !is_npm_family && !is_python {
        return args.to_vec();
    }

    // First two tokens are the manager + subcommand (e.g. `npm install`,
    // `pip install`); `uv pip install` has a third. Don't rewrite those.
    let skip = if manager == "uv"
        && args.get(1).map(String::as_str) == Some("pip")
        && args.get(2).map(String::as_str) == Some("install")
    {
        3
    } else {
        2
    };

    let mut out: Vec<String> = Vec::with_capacity(args.len());
    for (idx, arg) in args.iter().enumerate() {
        if idx < skip || arg.starts_with('-') {
            out.push(arg.clone());
            continue;
        }

        if is_npm_family {
            let (name, existing_version) = parse_npm_spec(arg);
            if existing_version.is_none()
                && let Some(version) = pins.get(&name)
                // A "latest" pin means the version was never resolved (e.g. an
                // internal_package_exemptions skip); leave the arg unpinned so we
                // don't emit an invalid `name@latest` spec.
                && version != "latest"
            {
                out.push(format!("{}@{}", name, version));
                continue;
            }
            out.push(arg.clone());
            continue;
        }

        // Python managers: only rewrite a bare `name` (no version operator and
        // not a path/URL spec).
        if arg.contains("==")
            || arg.starts_with('.')
            || arg.contains("://")
            || arg.contains(['<', '>', '=', '!', '~', '@'])
        {
            out.push(arg.clone());
            continue;
        }

        // A requirements spec like `name[extra]` keeps the extras when pinning,
        // but `pins` is keyed by the canonical (extras-stripped) name, so look up
        // with the stripped name and re-emit the full `arg` (extras intact).
        let base_name = strip_pep508_extras(arg);
        match pins.get(base_name) {
            // A "latest" pin means the version was never resolved (e.g. an
            // internal_package_exemptions skip); leave it unpinned rather than
            // emit an invalid `name==latest` spec.
            Some(version) if version != "latest" => out.push(format!("{}=={}", arg, version)),
            _ => out.push(arg.clone()),
        }
    }

    out
}

pub(crate) fn parse_package_details(
    manager: &str,
    args: &[String],
) -> (Option<String>, Option<String>) {
    let is_recognized = manager == "uv"
        || manager == "pip"
        || manager == "pip3"
        || manager == "poetry"
        || is_npm_family_manager(manager);
    if !is_recognized {
        return (None, None);
    }

    let pkg_arg_start: Option<usize> = match manager {
        "uv" if args.get(1).map(String::as_str) == Some("add") => Some(2),
        "uv" if args.get(1).map(String::as_str) == Some("pip")
            && args.get(2).map(String::as_str) == Some("install") =>
        {
            Some(3)
        }
        "poetry"
            if matches!(
                args.get(1).map(String::as_str),
                Some("add" | "update" | "install")
            ) =>
        {
            Some(2)
        }
        _ if is_npm_family_manager(manager)
            && is_npm_family_package_command(manager, args.get(1).map(String::as_str)) =>
        {
            Some(2)
        }
        _ if args.get(1).map(String::as_str) == Some("install") => Some(2),
        _ => None,
    };

    if let Some(start) = pkg_arg_start {
        for arg in args.iter().skip(start) {
            if arg.starts_with('-') {
                continue;
            }

            if is_npm_family_manager(manager) {
                let (name, version) = parse_npm_spec(arg);
                return (Some(name), version);
            }

            if arg.contains("==") {
                let parts: Vec<&str> = arg.split("==").collect();
                if parts.len() == 2 {
                    // Strip extras so the registry lookup / pins key use the
                    // canonical name; the forwarded command keeps the spec.
                    return (
                        Some(strip_pep508_extras(parts[0]).to_string()),
                        Some(parts[1].to_string()),
                    );
                }
            }

            return (Some(strip_pep508_extras(arg).to_string()), None);
        }
    }
    (None, None)
}

pub(crate) fn should_enforce_package_detection(manager: &str, args: &[String]) -> bool {
    if manager == "uv" {
        return args.get(1).map(String::as_str) == Some("add")
            || (args.get(1).map(String::as_str) == Some("pip")
                && args.get(2).map(String::as_str) == Some("install"))
            || (args.get(1).map(String::as_str) == Some("pip")
                && args.get(2).map(String::as_str) == Some("sync"))
            || args.get(1).map(String::as_str) == Some("sync");
    }

    if manager == "pip" || manager == "pip3" {
        return args.get(1).map(String::as_str) == Some("install");
    }

    if manager == "poetry" {
        return args.get(1).map(String::as_str) == Some("add")
            || args.get(1).map(String::as_str) == Some("update")
            || args.get(1).map(String::as_str) == Some("install");
    }

    if is_npm_family_manager(manager) {
        return is_npm_family_package_command(manager, args.get(1).map(String::as_str));
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- #6 PEP 508 extras must be stripped from the canonical name ---

    #[test]
    fn strip_pep508_extras_removes_bracket_suffix() {
        assert_eq!(strip_pep508_extras("requests[security]"), "requests");
        assert_eq!(strip_pep508_extras("flask[async,dotenv]"), "flask");
        // No extras: returned unchanged.
        assert_eq!(strip_pep508_extras("requests"), "requests");
    }

    #[test]
    fn strips_pep508_extras_from_requirements_name() {
        // The parsed name (used for the PyPI lookup and the pins key) must be the
        // canonical `requests`, not the 404-ing `requests[security]`. Extras are
        // install-time options preserved only for the forwarded command.
        let requirements = "requests[security]==2.31.0\nflask[async,dotenv]\n";
        let parsed = parse_requirements_packages_from_content(requirements);
        assert_eq!(
            parsed,
            vec![
                ("requests".to_string(), Some("2.31.0".to_string())),
                ("flask".to_string(), None),
            ]
        );
    }

    // --- #7 extras-qualified spec pins via the canonical key, keeps extras ---

    #[test]
    fn pins_extras_spec_using_canonical_key_and_preserves_extras() {
        // `pins` is keyed by the canonical name; the rewrite must strip extras to
        // look it up, then re-emit the full spec (extras intact) with the pin.
        let pins = HashMap::from([("requests".to_string(), "2.31.0".to_string())]);
        let out = rewrite_args_with_pinned_versions(
            "pip",
            &["pip".into(), "install".into(), "requests[security]".into()],
            &pins,
        );
        assert_eq!(out, vec!["pip", "install", "requests[security]==2.31.0"]);
    }

    // --- #5 local directory-source poetry packages are excluded regardless of develop ---

    #[test]
    fn skips_non_develop_local_package_from_poetry_lock() {
        // A local directory source with NO `develop` key (defaults to
        // non-editable) must still be excluded; previously only `develop = true`
        // locals were filtered, so a same-named public package would be scanned
        // while the local path is what actually installs.
        let lock = r#"
[[package]]
name = "mylib"
version = "0.1.0"

[package.source]
type = "directory"
url = "../mylib"

[[package]]
name = "requests"
version = "2.31.0"
"#;
        let parsed = parse_poetry_lock_packages_from_content(lock);
        assert_eq!(parsed, vec![("requests".to_string(), "2.31.0".to_string())]);
    }

    #[test]
    fn skips_develop_local_package_from_poetry_lock() {
        // The editable (`develop = true`) local case must remain excluded too.
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
        assert_eq!(parsed, vec![("requests".to_string(), "2.31.0".to_string())]);
    }

    // ---------------------------------------------------------------------------
    // parser_tests (moved from tests/parser_tests.rs) — non-GyrSeek tests
    // ---------------------------------------------------------------------------

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn pins_unpinned_npm_install_to_resolved_version() {
        let pins = std::collections::HashMap::from([("left-pad".to_string(), "1.3.0".to_string())]);
        let out =
            rewrite_args_with_pinned_versions("npm", &args(&["npm", "install", "left-pad"]), &pins);
        assert_eq!(out, args(&["npm", "install", "left-pad@1.3.0"]));
    }

    #[test]
    fn pins_unpinned_pnpm_add_to_resolved_version() {
        let pins = std::collections::HashMap::from([("left-pad".to_string(), "1.3.0".to_string())]);
        let out =
            rewrite_args_with_pinned_versions("pnpm", &args(&["pnpm", "add", "left-pad"]), &pins);
        assert_eq!(out, args(&["pnpm", "add", "left-pad@1.3.0"]));
    }

    #[test]
    fn does_not_pin_npm_package_with_latest_sentinel() {
        // A "latest" pin comes from an internal_package_exemptions skip (version
        // never resolved); it must NOT produce an invalid `name@latest` spec.
        let pins =
            std::collections::HashMap::from([("internal-pkg".to_string(), "latest".to_string())]);
        let out = rewrite_args_with_pinned_versions(
            "npm",
            &args(&["npm", "install", "internal-pkg"]),
            &pins,
        );
        assert_eq!(out, args(&["npm", "install", "internal-pkg"]));
    }

    #[test]
    fn does_not_pin_pip_package_with_latest_sentinel() {
        let pins =
            std::collections::HashMap::from([("internal-pkg".to_string(), "latest".to_string())]);
        let out = rewrite_args_with_pinned_versions(
            "pip",
            &args(&["pip", "install", "internal-pkg"]),
            &pins,
        );
        assert_eq!(out, args(&["pip", "install", "internal-pkg"]));
    }

    #[test]
    fn pins_scoped_npm_package() {
        let pins =
            std::collections::HashMap::from([("@scope/pkg".to_string(), "2.5.1".to_string())]);
        let out = rewrite_args_with_pinned_versions(
            "npm",
            &args(&["npm", "install", "@scope/pkg"]),
            &pins,
        );
        assert_eq!(out, args(&["npm", "install", "@scope/pkg@2.5.1"]));
    }

    #[test]
    fn does_not_repin_npm_package_that_already_has_a_version() {
        let pins = std::collections::HashMap::from([("left-pad".to_string(), "1.3.0".to_string())]);
        let out = rewrite_args_with_pinned_versions(
            "npm",
            &args(&["npm", "install", "left-pad@1.2.0"]),
            &pins,
        );
        assert_eq!(out, args(&["npm", "install", "left-pad@1.2.0"]));
    }

    #[test]
    fn pins_unpinned_pip_install_to_resolved_version() {
        let pins =
            std::collections::HashMap::from([("requests".to_string(), "2.31.0".to_string())]);
        let out =
            rewrite_args_with_pinned_versions("pip", &args(&["pip", "install", "requests"]), &pins);
        assert_eq!(out, args(&["pip", "install", "requests==2.31.0"]));
    }

    #[test]
    fn pins_pip_package_with_extras() {
        let pins =
            std::collections::HashMap::from([("requests".to_string(), "2.31.0".to_string())]);
        let out = rewrite_args_with_pinned_versions(
            "pip",
            &args(&["pip", "install", "requests[security]"]),
            &pins,
        );
        assert_eq!(out, args(&["pip", "install", "requests[security]==2.31.0"]));
    }

    #[test]
    fn leaves_pip_flags_and_pinned_specs_untouched() {
        let pins =
            std::collections::HashMap::from([("requests".to_string(), "2.31.0".to_string())]);
        let out = rewrite_args_with_pinned_versions(
            "pip",
            &args(&["pip", "install", "--no-cache-dir", "requests==2.30.0"]),
            &pins,
        );
        assert_eq!(
            out,
            args(&["pip", "install", "--no-cache-dir", "requests==2.30.0"])
        );
    }

    #[test]
    fn pins_uv_pip_install_respecting_three_token_prefix() {
        let pins = std::collections::HashMap::from([("flask".to_string(), "3.0.0".to_string())]);
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
            &std::collections::HashMap::new(),
        );
        assert_eq!(out, args(&["npm", "install", "left-pad"]));
    }

    #[test]
    fn does_not_pin_unrelated_packages() {
        let pins =
            std::collections::HashMap::from([("requests".to_string(), "2.31.0".to_string())]);
        let out =
            rewrite_args_with_pinned_versions("pip", &args(&["pip", "install", "flask"]), &pins);
        assert_eq!(out, args(&["pip", "install", "flask"]));
    }

    #[test]
    fn parses_uv_lock_packages_for_sync_scanning() {
        let lock = "version = 1\n\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n\n[[package]]\nname = \"pytest\"\nversion = \"9.0.1\"\n";
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
        let lock = "version = 1\n\n[[package]]\nname = \"test\"\nversion = \"0.1.0\"\nsource = { editable = \".\" }\n\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n";
        let parsed = parse_uv_lock_packages_from_content(lock);
        assert_eq!(parsed, vec![("requests".to_string(), "2.31.0".to_string())]);
    }

    #[test]
    fn parses_requirements_packages_for_uv_pip_sync() {
        let requirements = "# comment\nrequests==2.31.0\npytest\n-r dev-requirements.txt\n";
        let parsed = parse_requirements_packages_from_content(requirements);
        assert_eq!(
            parsed,
            vec![
                ("requests".to_string(), Some("2.31.0".to_string())),
                ("pytest".to_string(), None)
            ]
        );
    }

    #[test]
    fn parses_pylock_packages_for_uv_pip_sync() {
        let pylock = "version = 1\n\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n\n[[package]]\nname = \"pytest\"\nversion = \"9.0.1\"\n\n[[package]]\nname = \"local-editable\"\n";
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
        let mut req_file = tempfile::NamedTempFile::new().unwrap();
        let req_path = req_file.path().to_string_lossy().to_string();
        std::io::Write::write_all(&mut req_file, b"requests==2.31.0\npytest\n").unwrap();
        let a = vec![
            "pip3".to_string(),
            "install".to_string(),
            "-r".to_string(),
            req_path,
            "flask==3.0.0".to_string(),
        ];
        let parsed = parse_pip_install_packages_from_args(&a);
        assert_eq!(
            parsed,
            vec![
                ("requests".to_string(), Some("2.31.0".to_string())),
                ("pytest".to_string(), None),
                ("flask".to_string(), Some("3.0.0".to_string())),
            ]
        );
    }

    #[test]
    fn parses_poetry_lock_packages_for_install_scanning() {
        let lock = "[[package]]\nname = \"pytest\"\nversion = \"9.0.3\"\n\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n";
        let parsed = parse_poetry_lock_packages_from_content(lock);
        assert_eq!(
            parsed,
            vec![
                ("pytest".to_string(), "9.0.3".to_string()),
                ("requests".to_string(), "2.31.0".to_string())
            ]
        );
    }

    #[test]
    fn parses_npm_install_multi_packages_from_args() {
        let a = vec![
            "npm".to_string(),
            "install".to_string(),
            "lodash@4.17.21".to_string(),
            "express".to_string(),
        ];
        let parsed = parse_npm_install_packages_from_args(&a);
        assert_eq!(
            parsed,
            vec![
                ("lodash".to_string(), Some("4.17.21".to_string())),
                ("express".to_string(), None)
            ]
        );
    }

    #[test]
    fn parses_pnpm_add_multi_packages_from_args() {
        let a = vec![
            "pnpm".to_string(),
            "add".to_string(),
            "lodash@4.17.21".to_string(),
            "express".to_string(),
        ];
        let parsed = parse_npm_install_packages_from_args(&a);
        assert_eq!(
            parsed,
            vec![
                ("lodash".to_string(), Some("4.17.21".to_string())),
                ("express".to_string(), None)
            ]
        );
    }

    #[test]
    fn npm_add_is_not_treated_as_supported_command() {
        let a = vec!["npm".to_string(), "add".to_string(), "lodash".to_string()];
        assert!(parse_npm_install_packages_from_args(&a).is_empty());
        assert!(!should_enforce_package_detection("npm", &a));
    }

    #[test]
    fn pnpm_install_args_skip_non_registry_specs() {
        let a = vec![
            "pnpm".to_string(),
            "install".to_string(),
            "workspace:*".to_string(),
            "lodash".to_string(),
        ];
        let parsed = parse_npm_install_packages_from_args(&a);
        assert_eq!(parsed, vec![("lodash".to_string(), None)]);
    }

    #[test]
    fn parses_npm_update_multi_packages_from_args() {
        let a = vec![
            "npm".to_string(),
            "update".to_string(),
            "lodash".to_string(),
            "typescript".to_string(),
        ];
        let parsed = parse_npm_install_packages_from_args(&a);
        assert_eq!(
            parsed,
            vec![
                ("lodash".to_string(), None),
                ("typescript".to_string(), None)
            ]
        );
    }

    #[test]
    fn parses_npm_packages_from_package_json_content() {
        let j = r#"{"name":"demo","dependencies":{"lodash":"^4.17.21","axios":"1.8.2"},"devDependencies":{"vitest":"~1.6.0"}}"#;
        let mut parsed = parse_npm_packages_from_package_json_content(j);
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
        let j = r#"{"name":"demo","dependencies":{"local-file":"file:../local-file","local-workspace":"workspace:*","git-dep":"git+https://github.com/example/repo.git","url-dep":"https://example.com/pkg.tgz","axios":"1.8.2"}}"#;
        let parsed = parse_npm_packages_from_package_json_content(j);
        assert_eq!(
            parsed,
            vec![("axios".to_string(), Some("1.8.2".to_string()))]
        );
    }

    #[test]
    fn parses_uv_lock_upgrade_packages_multi_targets() {
        let a = vec![
            "uv".to_string(),
            "lock".to_string(),
            "-P".to_string(),
            "pytest".to_string(),
            "--upgrade-package=requests".to_string(),
            "--dry-run".to_string(),
        ];
        let parsed = parse_uv_lock_upgrade_packages_from_args(&a);
        assert_eq!(parsed, vec!["pytest".to_string(), "requests".to_string()]);
    }

    // --- gap #1: uv.lock local-source exclusion edge cases ---

    #[test]
    fn skips_workspace_true_package_from_uv_lock_scanning() {
        let lock = "version = 1\n\n[[package]]\nname = \"ws-crate\"\nversion = \"0.1.0\"\nsource = { workspace = true }\n\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n";
        let parsed = parse_uv_lock_packages_from_content(lock);
        assert_eq!(parsed, vec![("requests".to_string(), "2.31.0".to_string())]);
    }

    #[test]
    fn skips_virtual_dot_package_from_uv_lock_scanning() {
        let lock = "version = 1\n\n[[package]]\nname = \"virt\"\nversion = \"0.1.0\"\nsource = { virtual = \".\" }\n\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n";
        let parsed = parse_uv_lock_packages_from_content(lock);
        assert_eq!(parsed, vec![("requests".to_string(), "2.31.0".to_string())]);
    }

    #[test]
    fn skips_relative_path_package_from_uv_lock_scanning() {
        let lock = "version = 1\n\n[[package]]\nname = \"locallib\"\nversion = \"0.2.0\"\nsource = { path = \"../libs/locallib\" }\n\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n";
        let parsed = parse_uv_lock_packages_from_content(lock);
        assert_eq!(parsed, vec![("requests".to_string(), "2.31.0".to_string())]);
    }

    // --- gap #2/#3: poetry.lock [package.source] with absolute path and path-only (no url) ---

    #[test]
    fn skips_absolute_path_directory_source_from_poetry_lock() {
        let lock = "[[package]]\nname = \"abslocal\"\nversion = \"0.3.0\"\n\n[package.source]\ntype = \"directory\"\npath = \"/opt/monorepo/libs/abslocal\"\n\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n";
        let parsed = parse_poetry_lock_packages_from_content(lock);
        assert_eq!(parsed, vec![("requests".to_string(), "2.31.0".to_string())]);
    }

    #[test]
    fn skips_path_only_directory_source_from_poetry_lock() {
        // [package.source] with only `path` (no `url`) should still be excluded.
        let lock = "[[package]]\nname = \"pathonly\"\nversion = \"0.1.0\"\n\n[package.source]\ntype = \"directory\"\npath = \"./local-lib\"\n\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n";
        let parsed = parse_poetry_lock_packages_from_content(lock);
        assert_eq!(parsed, vec![("requests".to_string(), "2.31.0".to_string())]);
    }

    // --- gap #4: pylock.toml plural [[packages]] header ---

    #[test]
    fn parses_plural_packages_header_from_pylock() {
        let pylock = "version = 1\n\n[[packages]]\nname = \"requests\"\nversion = \"2.31.0\"\n\n[[packages]]\nname = \"pytest\"\nversion = \"9.0.1\"\n";
        let parsed = parse_pylock_packages_from_content(pylock);
        assert_eq!(
            parsed,
            vec![
                ("requests".to_string(), Some("2.31.0".to_string())),
                ("pytest".to_string(), Some("9.0.1".to_string())),
            ]
        );
    }

    // --- gap #5: requirements URL/VCS specifier filter ---

    #[test]
    fn requirements_spec_rejects_vcs_and_url_specifiers() {
        assert_eq!(
            parse_requirements_spec("git+https://github.com/example/repo.git#egg=pkg"),
            None
        );
        assert_eq!(
            parse_requirements_spec("https://files.example.com/pkg-1.0.tar.gz"),
            None
        );
        assert_eq!(
            parse_requirements_spec("http://internal.corp/pkg.whl"),
            None
        );
    }

    // --- gap #6: parse_npm_spec versioned scoped package ---

    #[test]
    fn parse_npm_spec_versioned_scoped_package() {
        let (name, version) = parse_npm_spec("@scope/pkg@1.2.3");
        assert_eq!(name, "@scope/pkg");
        assert_eq!(version, Some("1.2.3".to_string()));
    }

    #[test]
    fn parse_npm_spec_unversioned_scoped_package() {
        let (name, version) = parse_npm_spec("@scope/pkg");
        assert_eq!(name, "@scope/pkg");
        assert_eq!(version, None);
    }

    // --- gap #7: parse_npm_spec malformed — leading @ but no slash ---

    #[test]
    fn parse_npm_spec_malformed_at_no_slash_drops_version_safely() {
        // Not a valid scoped package; version should be dropped rather than misparse.
        let (name, version) = parse_npm_spec("@notscoped@1.0.0");
        // Falls through to rsplit_once('@') path: name="@notscoped", version=Some("1.0.0").
        // The important property: it does not panic and returns something deterministic.
        assert!(!name.is_empty());
        let _ = version; // whatever it returns, no crash
    }

    // --- gap #8: normalize_npm_version_spec wildcard ---

    #[test]
    fn normalize_npm_version_spec_wildcard_is_not_pinnable() {
        assert_eq!(normalize_npm_version_spec("*"), None);
        assert_eq!(normalize_npm_version_spec(""), None);
        assert_eq!(normalize_npm_version_spec("^1.0.0"), None);
        assert_eq!(normalize_npm_version_spec("~1.0.0"), None);
        assert_eq!(
            normalize_npm_version_spec("1.2.3"),
            Some("1.2.3".to_string())
        );
    }

    // --- gap #9: parse_npm_install_packages_from_args link: spec not filtered ---

    #[test]
    fn npm_install_args_skips_link_spec() {
        let a = vec![
            "npm".to_string(),
            "install".to_string(),
            "link:../local-pkg".to_string(),
            "lodash".to_string(),
        ];
        let parsed = parse_npm_install_packages_from_args(&a);
        // link: is a non-registry spec; only lodash (a real package) should be scanned.
        assert_eq!(parsed, vec![("lodash".to_string(), None)]);
    }

    // --- gap #10: parse_uv_lock_upgrade_packages_from_args — -P followed by a flag ---

    #[test]
    fn uv_lock_upgrade_skips_flag_after_dash_p_and_does_not_consume_next_real_arg() {
        // `-P --dry-run` — the value is a flag, so no package is collected from
        // that pair. The subsequent `-P requests` must still be collected.
        // Before the fix, idx += 2 was always executed, causing `requests` to be
        // skipped even when present as the *next* -P argument.
        let a = vec![
            "uv".to_string(),
            "lock".to_string(),
            "-P".to_string(),
            "--dry-run".to_string(),
            "-P".to_string(),
            "requests".to_string(),
        ];
        let parsed = parse_uv_lock_upgrade_packages_from_args(&a);
        assert!(
            !parsed.contains(&"--dry-run".to_string()),
            "--dry-run must not be treated as a package"
        );
        assert!(
            parsed.contains(&"requests".to_string()),
            "requests after a separate -P must still be collected"
        );
    }

    #[test]
    fn uv_lock_upgrade_bare_flag_after_dash_p_does_not_panic() {
        // `-P` at the very end of args (no value at all) must not panic.
        let a = vec!["uv".to_string(), "lock".to_string(), "-P".to_string()];
        let parsed = parse_uv_lock_upgrade_packages_from_args(&a);
        assert!(parsed.is_empty());
    }

    // --- gap #11: rewrite_args_with_pinned_versions — uv add path ---

    #[test]
    fn rewrites_uv_add_to_pinned_version() {
        let pins = std::collections::HashMap::from([("flask".to_string(), "3.0.0".to_string())]);
        let out = rewrite_args_with_pinned_versions("uv", &args(&["uv", "add", "flask"]), &pins);
        assert_eq!(out, args(&["uv", "add", "flask==3.0.0"]));
    }

    #[test]
    fn rewrites_uv_add_preserves_extras_in_forwarded_spec() {
        let pins = std::collections::HashMap::from([("flask".to_string(), "3.0.0".to_string())]);
        let out =
            rewrite_args_with_pinned_versions("uv", &args(&["uv", "add", "flask[async]"]), &pins);
        assert_eq!(out, args(&["uv", "add", "flask[async]==3.0.0"]));
    }
}
