use std::fs;

fn parse_toml_quoted_value(line: &str, key: &str) -> Option<String> {
    let prefix = format!("{} = \"", key);
    let rest = line.strip_prefix(&prefix)?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

pub fn parse_uv_lock_packages_from_content(content: &str) -> Vec<(String, String)> {
    let mut packages = Vec::new();
    let mut in_package = false;
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut local_source = false;

    let finalize_package = |packages: &mut Vec<(String, String)>, name: &mut Option<String>, version: &mut Option<String>, local_source: &mut bool| {
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

pub fn parse_poetry_lock_packages_from_content(content: &str) -> Vec<(String, String)> {
    let mut packages = Vec::new();
    let mut in_package = false;
    let mut in_package_source = false;

    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut local_source = false;
    let mut source_type: Option<String> = None;
    let mut source_url: Option<String> = None;
    let mut source_path: Option<String> = None;
    let mut develop = false;

    let is_local_location = |value: &str| {
        value == "." || value.starts_with("./") || value.starts_with("../") || value.starts_with('/')
    };

    let finalize_package = |
        packages: &mut Vec<(String, String)>,
        name: &mut Option<String>,
        version: &mut Option<String>,
        local_source: &mut bool,
        source_type: &mut Option<String>,
        source_url: &mut Option<String>,
        source_path: &mut Option<String>,
        develop: &mut bool,
    | {
        let directory_local = source_type.as_deref() == Some("directory")
            && (source_url
                .as_deref()
                .map(is_local_location)
                .unwrap_or(false)
                || source_path
                    .as_deref()
                    .map(is_local_location)
                    .unwrap_or(false));

        if !*local_source && !(directory_local && *develop) {
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
        *develop = false;
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
                &mut develop,
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
                &mut develop,
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

        if line.starts_with("develop") && line.contains("true") {
            develop = true;
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
        &mut develop,
    );

    packages
}

pub fn parse_pylock_packages_from_content(content: &str) -> Vec<(String, Option<String>)> {
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

fn parse_requirements_spec(spec: &str) -> Option<(String, Option<String>)> {
    let trimmed = spec.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    let base = trimmed.split_whitespace().next().unwrap_or(trimmed);

    if let Some((name, version)) = base.split_once("==") {
        if !name.is_empty() && !version.is_empty() {
            return Some((name.to_string(), Some(version.to_string())));
        }
    }

    if base.starts_with('-') || base.starts_with('.') || base.contains("://") {
        return None;
    }

    Some((base.to_string(), None))
}

pub fn parse_requirements_packages_from_content(content: &str) -> Vec<(String, Option<String>)> {
    let mut packages = Vec::new();

    for line in content.lines() {
        if let Some(pkg) = parse_requirements_spec(line) {
            packages.push(pkg);
        }
    }

    packages
}

pub fn parse_pip_install_packages_from_args(args: &[String]) -> Vec<(String, Option<String>)> {
    if args.first().map(String::as_str) != Some("pip") && args.first().map(String::as_str) != Some("pip3") {
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
            if let Some(path) = args.get(idx + 1) {
                if let Ok(content) = fs::read_to_string(path) {
                    packages.extend(parse_requirements_packages_from_content(&content));
                }
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
        if let Some(idx) = arg.rfind('@') {
            if idx > 0 {
                let name = &arg[..idx];
                let version = &arg[idx + 1..];
                if !version.is_empty() && name.contains('/') {
                    return (name.to_string(), Some(version.to_string()));
                }
            }
        }
        return (arg.to_string(), None);
    }

    if let Some((name, version)) = arg.rsplit_once('@') {
        if !name.is_empty() && !version.is_empty() {
            return (name.to_string(), Some(version.to_string()));
        }
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

pub fn parse_npm_packages_from_package_json_content(content: &str) -> Vec<(String, Option<String>)> {
    let mut packages = Vec::new();
    let parsed: serde_json::Value = match serde_json::from_str(content) {
        Ok(value) => value,
        Err(_) => return packages,
    };

    for section in ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] {
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

pub fn parse_npm_install_packages_from_args(args: &[String]) -> Vec<(String, Option<String>)> {
    if args.first().map(String::as_str) != Some("npm") {
        return Vec::new();
    }
    if args.get(1).map(String::as_str) != Some("install")
        && args.get(1).map(String::as_str) != Some("i")
        && args.get(1).map(String::as_str) != Some("update")
    {
        return Vec::new();
    }

    let mut packages = Vec::new();
    for arg in args.iter().skip(2) {
        if arg.starts_with('-') {
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

pub fn parse_uv_lock_upgrade_packages_from_args(args: &[String]) -> Vec<String> {
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
            if let Some(pkg) = args.get(idx + 1) {
                if !pkg.starts_with('-') {
                    packages.push(pkg.to_string());
                }
            }
            idx += 2;
            continue;
        }

        if let Some(pkg) = arg.strip_prefix("--upgrade-package=") {
            if !pkg.is_empty() {
                packages.push(pkg.to_string());
            }
        }

        idx += 1;
    }

    packages
}

pub fn parse_package_details(manager: &str, args: &[String]) -> (Option<String>, Option<String>) {
    if manager == "uv" || manager == "pip" || manager == "pip3" || manager == "poetry" || manager == "npm" {
        let pkg_arg_start = if manager == "uv" {
            if args.get(1).map(String::as_str) == Some("add") {
                Some(2)
            } else if args.get(1).map(String::as_str) == Some("pip") && args.get(2).map(String::as_str) == Some("install") {
                Some(3)
            } else {
                None
            }
        } else if manager == "poetry" {
            if args.get(1).map(String::as_str) == Some("add")
                || args.get(1).map(String::as_str) == Some("update")
                || args.get(1).map(String::as_str) == Some("install")
            {
                Some(2)
            } else {
                None
            }
        } else if manager == "npm" {
            if args.get(1).map(String::as_str) == Some("install")
                || args.get(1).map(String::as_str) == Some("i")
                || args.get(1).map(String::as_str) == Some("update")
            {
                Some(2)
            } else {
                None
            }
        } else if args.get(1).map(String::as_str) == Some("install") {
            Some(2)
        } else {
            None
        };

        if let Some(start) = pkg_arg_start {
            for arg in args.iter().skip(start) {
                if arg.starts_with('-') {
                    continue;
                }

                if manager == "npm" {
                    let (name, version) = parse_npm_spec(arg);
                    return (Some(name), version);
                }

                if arg.contains("==") {
                    let parts: Vec<&str> = arg.split("==").collect();
                    if parts.len() == 2 {
                        return (Some(parts[0].to_string()), Some(parts[1].to_string()));
                    }
                }

                return (Some(arg.to_string()), None);
            }
        }
    }
    (None, None)
}

pub fn should_enforce_package_detection(manager: &str, args: &[String]) -> bool {
    if manager == "uv" {
        return args.get(1).map(String::as_str) == Some("add")
            || (args.get(1).map(String::as_str) == Some("pip") && args.get(2).map(String::as_str) == Some("install"))
            || (args.get(1).map(String::as_str) == Some("pip") && args.get(2).map(String::as_str) == Some("sync"))
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

    if manager == "npm" {
        return args.get(1).map(String::as_str) == Some("install")
            || args.get(1).map(String::as_str) == Some("i")
            || args.get(1).map(String::as_str) == Some("update");
    }

    false
}
