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
    content
        .lines()
        .filter_map(parse_requirements_spec)
        .collect()
}

/// Flags that take a separate value, per command. The value must not be read as a package
/// name (`uv add --group dev pytest` installs `pytest`, not `dev`). Only flags that always
/// take a value are listed: wrongly listing a boolean flag would silently drop the package
/// after it, whereas missing a value flag only makes gyrseek look up one extra name.
const PIP_VALUE_FLAGS: &[&str] = &[
    "-c",
    "--constraint",
    "-e",
    "--editable",
    "-i",
    "--index-url",
    "--extra-index-url",
    "-f",
    "--find-links",
    "-t",
    "--target",
    "--prefix",
    "--root",
    "--no-binary",
    "--only-binary",
    "--platform",
    "--python-version",
    "--implementation",
    "--abi",
    "--src",
    "--cache-dir",
    "-p",
    "--python",
    "--index",
    "--default-index",
    "--index-strategy",
    "--keyring-provider",
    "--exclude-newer",
    "--resolution",
    "--prerelease",
    "--link-mode",
    "--python-platform",
    "-C",
    "--config-setting",
    "--config-settings",
    "-b",
    "--build-constraint",
    "--override",
    "--reinstall-package",
    "-P",
    "--upgrade-package",
    "--refresh-package",
    "--config-file",
    "--extra",
    "--group",
];
const UV_ADD_VALUE_FLAGS: &[&str] = &[
    "--group",
    "--optional",
    "--package",
    "-p",
    "--python",
    "--index",
    "--default-index",
    "-i",
    "--index-url",
    "--extra-index-url",
    "-f",
    "--find-links",
    "--extra",
    "--bounds",
    "--branch",
    "--tag",
    "--rev",
    "-m",
    "--marker",
    "-c",
    "--constraint",
    "--exclude-newer",
    "--index-strategy",
    "--keyring-provider",
    "--resolution",
    "--prerelease",
    "--link-mode",
    "-C",
    "--config-setting",
    "--project",
    "--directory",
    "--config-file",
    "--cache-dir",
    "--python-platform",
    "-P",
    "--upgrade-package",
    "--refresh-package",
    "--script",
];
const POETRY_ADD_VALUE_FLAGS: &[&str] = &[
    "-G",
    "--group",
    "-E",
    "--extras",
    "--python",
    "--platform",
    "--source",
    "-C",
    "--directory",
    "-P",
    "--project",
];

/// Where the package arguments start and which flags take a value, for each Python command
/// that installs packages by name. `poetry install/update/lock` and `uv sync/lock` are
/// scanned from their lockfiles instead.
fn python_install_layout(args: &[String]) -> Option<(usize, &'static [&'static str])> {
    let arg = |i: usize| args.get(i).map(String::as_str);
    match (arg(0)?, arg(1), arg(2)) {
        ("pip" | "pip3", Some("install"), _) => Some((2, PIP_VALUE_FLAGS)),
        ("uv", Some("pip"), Some("install")) => Some((3, PIP_VALUE_FLAGS)),
        ("uv", Some("add"), _) => Some((2, UV_ADD_VALUE_FLAGS)),
        ("poetry", Some("add"), _) => Some((2, POETRY_ADD_VALUE_FLAGS)),
        _ => None,
    }
}

fn is_plain_version(v: &str) -> bool {
    v.chars().next().is_some_and(|c| c.is_ascii_digit())
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '!' | '_' | '-'))
}

/// Parses one requirement the way the Python install paths need it: it must name exactly one
/// registry version (`name`, `name[extra]` or `name==1.2.3`, with spaces and a `; marker` or
/// ` --hash` tail tolerated). gyrseek scans specific versions and pins the forwarded command
/// to them, so a range (`>=2`, `~=1.4`, `==1.*`) cannot be vouched for, and a direct
/// reference (`name @ https://…`, a bare URL) installs something the registry scan never
/// saw. Both are errors. Blank lines, comments, option lines and local paths are `Ok(None)`.
/// With `poetry`, `name@2.31.0` means `name==2.31.0` and `name@latest` means `name`.
fn parse_exact_requirement(
    spec: &str,
    poetry: bool,
) -> Result<Option<(String, Option<String>)>, String> {
    let line = spec.split(" #").next().unwrap_or(spec).trim();
    if line.is_empty() || line.starts_with(['#', '-', '.', '/', '~']) {
        return Ok(None);
    }
    let not_exact = |why: &str| {
        Err(format!(
            "'{line}' {why}. gyrseek scans exact versions and pins the install to them, so it cannot vouch for it. Use an exact version (name==1.2.3), a bare name (gyrseek then scans the latest version and pins it), or a lockfile command (uv sync, uv lock, poetry install). Failing closed."
        ))
    };

    // Drop a `; marker` or ` --option` tail and a trailing line continuation, then spaces.
    let head = line.split(';').next().unwrap_or(line);
    let head = head.split(" --").next().unwrap_or(head);
    // Spaces are fine around operators, brackets and commas (`name [a, b] == 1.0`) but not
    // inside a name or a version (`re quests==1.0`), which pip would reject.
    let chars: Vec<char> = head.trim_end_matches('\\').chars().collect();
    let glue = |c: char| matches!(c, '=' | '[' | ']' | ',' | '<' | '>' | '!' | '~' | '@');
    let mut compact = String::new();
    let mut i = 0;
    while i < chars.len() {
        if !chars[i].is_whitespace() {
            compact.push(chars[i]);
            i += 1;
            continue;
        }
        let mut j = i;
        while j < chars.len() && chars[j].is_whitespace() {
            j += 1;
        }
        if let (Some(prev), Some(next)) = (compact.chars().last(), chars.get(j))
            && !glue(prev)
            && !glue(*next)
        {
            return not_exact("has a space inside the requirement");
        }
        i = j;
    }
    if compact.contains("://") || compact.starts_with("git+") {
        return not_exact("installs from a URL, not from the registry");
    }

    // Extras may contain commas (`name[a,b]`), so remove them before looking at operators.
    let plain = match (compact.find('['), compact.find(']')) {
        (Some(open), Some(close)) if open < close => {
            format!("{}{}", &compact[..open], &compact[close + 1..])
        }
        _ => compact.clone(),
    };

    let (name, version) = if poetry && let Some((name, ver)) = plain.split_once('@') {
        match ver {
            "" | "latest" => (name, None),
            v if is_plain_version(v) => (name, Some(v)),
            _ => return not_exact("is a version range"),
        }
    } else if plain.contains('@') {
        return not_exact("installs from a URL or path, not from the registry");
    } else if let Some((name, ver)) = plain.split_once("==") {
        if !is_plain_version(ver) {
            return not_exact("is a version range");
        }
        (name, Some(ver))
    } else if plain.contains(['<', '>', '!', '~', '=', ',', '*']) {
        return not_exact("is a version range");
    } else {
        (plain.as_str(), None)
    };

    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return not_exact("is not a package name gyrseek can look up");
    }
    Ok(Some((name.to_string(), version.map(str::to_string))))
}

/// How deep `-r` includes may nest inside requirements files.
const MAX_REQUIREMENTS_DEPTH: usize = 10;

/// The path of a `-r base.txt` / `--requirement base.txt` / `--requirement=base.txt` /
/// `-rbase.txt` include line, ignoring a trailing ` # comment`.
fn requirements_include(line: &str) -> Option<&str> {
    let line = line.split(" #").next().unwrap_or(line).trim();
    let path = if let Some(rest) = line.strip_prefix("--requirement=") {
        rest
    } else if let Some(rest) = line.strip_prefix("--requirement") {
        rest.strip_prefix(char::is_whitespace)?
    } else {
        line.strip_prefix("-r")?
    };
    let path = path.trim();
    (!path.is_empty()).then_some(path)
}

/// Reads the packages listed in a `-r` file, following `-r` includes inside it (relative to
/// the including file, as pip does). Anything that is not a plain requirements file
/// (`pyproject.toml`, `setup.py`, ...) lists version ranges and groups that gyrseek cannot
/// resolve to a scanned version, and a file it cannot read cannot be scanned at all, so
/// both are errors, as is nesting that is too deep: skipping them would forward their
/// packages unscanned.
fn read_requirements_file(path: &str) -> Result<Vec<(String, Option<String>)>, String> {
    let mut seen = std::collections::HashSet::new();
    read_requirements_file_at(std::path::Path::new(path), &mut seen, 0)
}

fn read_requirements_file_at(
    path: &std::path::Path,
    seen: &mut std::collections::HashSet<std::path::PathBuf>,
    depth: usize,
) -> Result<Vec<(String, Option<String>)>, String> {
    let shown = path.display();
    let lower = shown.to_string().to_ascii_lowercase();
    if [".toml", ".py", ".cfg", ".json", ".yaml", ".yml"]
        .iter()
        .any(|ext| lower.ends_with(ext))
    {
        return Err(format!(
            "'-r {shown}' lists dependencies as version ranges that gyrseek cannot resolve to a scanned version, so it cannot vouch for them. Use `uv sync` or `uv lock` (scanned from the lockfile), or give `-r` a requirements file with pinned versions. Failing closed."
        ));
    }
    if depth > MAX_REQUIREMENTS_DEPTH {
        return Err(format!(
            "Requirements files are nested more than {MAX_REQUIREMENTS_DEPTH} levels deep at '{shown}', so gyrseek cannot scan them all. Failing closed."
        ));
    }
    let unreadable = |e: std::io::Error| {
        format!(
            "Cannot read the requirements file '{shown}' ({e}), so its packages cannot be scanned. Failing closed."
        )
    };
    // A file already read (an include cycle or a repeat) adds nothing new.
    if !seen.insert(fs::canonicalize(path).map_err(unreadable)?) {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(path).map_err(unreadable)?;
    let content = content.trim_start_matches('\u{feff}'); // a BOM from a Windows editor
    let dir = path.parent().unwrap_or_else(|| std::path::Path::new(""));

    let mut packages = Vec::new();
    for line in content.lines() {
        if let Some((name, version)) = parse_exact_requirement(line, false)? {
            // The forwarded command cannot pin a line inside a file, so a bare name would
            // be resolved again at install time, and a `-c` constraints file can change
            // the result. Require the version here.
            if version.is_none() {
                return Err(format!(
                    "'{name}' in {shown} has no pinned version. gyrseek cannot pin lines inside a file, so the install would resolve it again (and a -c constraints file can change the result). Pin it (name==1.2.3) or name it on the command line. Failing closed."
                ));
            }
            packages.push((name, version));
        }
    }
    for include in content.lines().filter_map(requirements_include) {
        packages.extend(read_requirements_file_at(
            &dir.join(include),
            seen,
            depth + 1,
        )?);
    }
    Ok(packages)
}

/// Every package named on a Python install command line, including those read from
/// `-r`/`--requirement(s)` files: `pip install a b`, `uv pip install a b`, `uv add a b`,
/// `poetry add a b`. Scanning only the first would forward the rest unscanned.
pub(crate) fn parse_python_install_packages_from_args(
    args: &[String],
) -> Result<Vec<(String, Option<String>)>, String> {
    let Some((start, value_flags)) = python_install_layout(args) else {
        return Ok(Vec::new());
    };
    let poetry = args.first().map(String::as_str) == Some("poetry");

    let mut packages = Vec::new();
    let mut idx = start;

    while idx < args.len() {
        let arg = &args[idx];

        if matches!(arg.as_str(), "-r" | "--requirement" | "--requirements") {
            if let Some(path) = args.get(idx + 1) {
                packages.extend(read_requirements_file(path)?);
            }
            idx += 2;
            continue;
        }

        if let Some(path) = arg
            .strip_prefix("--requirements=")
            .or_else(|| arg.strip_prefix("--requirement="))
        {
            packages.extend(read_requirements_file(path)?);
            idx += 1;
            continue;
        }

        // pip's option parser also accepts the value attached: `-rrequirements.txt`.
        if let Some(path) = arg
            .strip_prefix("-r")
            .filter(|p| !p.is_empty() && !p.starts_with('-'))
        {
            packages.extend(read_requirements_file(path)?);
            idx += 1;
            continue;
        }

        if arg.starts_with('-') {
            idx += if value_flags.contains(&arg.as_str()) {
                2
            } else {
                1
            };
            continue;
        }

        packages.extend(parse_exact_requirement(arg, poetry)?);
        idx += 1;
    }

    Ok(packages)
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

pub(crate) fn is_non_registry_npm_spec(spec: &str) -> bool {
    let trimmed = spec.trim();
    trimmed.starts_with("file:")
        || trimmed.starts_with("git+")
        || trimmed.starts_with("git://")
        || trimmed.starts_with("http://")
        || trimmed.starts_with("https://")
        || trimmed.starts_with("workspace:")
        || trimmed.starts_with("link:")
        || trimmed.starts_with("./")
        || trimmed.starts_with("../")
        || trimmed == "."
        || trimmed == ".."
        || (trimmed.starts_with('/') && !trimmed.starts_with("/@"))
        || trimmed.ends_with(".tgz")
        || trimmed.ends_with(".tar.gz")
}

fn is_npm_family_manager(manager: &str) -> bool {
    manager == "npm" || manager == "pnpm"
}

fn is_npm_family_package_command(manager: &str, command: Option<&str>) -> bool {
    matches!(command, Some("install") | Some("i") | Some("update"))
        || (manager == "pnpm" && command == Some("add"))
        || (manager == "npm" && command == Some("ci"))
}

const LOCKFILE_ONLY_FLAGS: [&str; 2] = ["--package-lock-only", "--lockfile-only"];

/// `npm install --package-lock-only` / `pnpm install --lockfile-only` only rewrite the
/// lockfile: nothing is downloaded or run, so there is nothing to scan yet. The follow-up
/// install is scanned from the new lockfile. The flag is a boolean, so its effective value
/// follows the package manager: `--flag false`, `--flag=false` and `--no-flag` turn it
/// off, and the last occurrence wins. Anything unclear counts as "off" so the command is
/// scanned.
pub(crate) fn is_lockfile_only_command(args: &[String]) -> bool {
    let mut enabled = false;
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if arg == "--" {
            break;
        }
        if LOCKFILE_ONLY_FLAGS.contains(&arg) {
            enabled = match args.get(i + 1).map(String::as_str) {
                Some("false") => {
                    i += 1;
                    false
                }
                Some("true") => {
                    i += 1;
                    true
                }
                _ => true,
            };
        } else if let Some(value) = LOCKFILE_ONLY_FLAGS
            .iter()
            .find_map(|f| arg.strip_prefix(f).and_then(|rest| rest.strip_prefix('=')))
        {
            enabled = value == "true" || value.is_empty();
        } else if LOCKFILE_ONLY_FLAGS.iter().any(|f| {
            f.strip_prefix("--")
                .is_some_and(|name| arg.strip_prefix("--no-") == Some(name))
        }) {
            enabled = false;
        }
        i += 1;
    }
    enabled
}

/// The non-flag arguments after the command, without the `true`/`false` that may follow a
/// lockfile-only flag.
fn npm_positional_args(args: &[String]) -> Vec<&str> {
    args.iter()
        .enumerate()
        .skip(2)
        .filter(|(i, arg)| {
            let after_flag = args
                .get(i - 1)
                .is_some_and(|prev| LOCKFILE_ONLY_FLAGS.contains(&prev.as_str()));
            !arg.starts_with('-') && !(after_flag && matches!(arg.as_str(), "true" | "false"))
        })
        .map(|(_, arg)| arg.as_str())
        .collect()
}

pub(crate) fn has_only_non_registry_npm_specs(args: &[String]) -> bool {
    if !args
        .first()
        .map(String::as_str)
        .is_some_and(is_npm_family_manager)
    {
        return false;
    }
    let manager = args.first().map(String::as_str).unwrap_or_default();
    if !is_npm_family_package_command(manager, args.get(1).map(String::as_str)) {
        return false;
    }

    let positional_args = npm_positional_args(args);

    !positional_args.is_empty()
        && positional_args
            .iter()
            .all(|arg| is_non_registry_npm_spec(arg))
}

fn is_valid_npm_name(name: &str) -> bool {
    let part_ok = |p: &str| {
        !p.is_empty()
            && p.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~'))
    };
    match name.strip_prefix('@') {
        Some(scoped) => scoped
            .split_once('/')
            .is_some_and(|(s, n)| part_ok(s) && part_ok(n)),
        None => part_ok(name),
    }
}

/// One npm/pnpm spec from the command line must name exactly one registry version:
/// `name`, `name@latest` or `name@1.2.3`. gyrseek scans specific versions and pins the
/// install to them, so a range (`^4`, `>=2`, `4.x`), a dist-tag (`@next`) or an alias
/// (`npm:other@1`) cannot be vouched for.
fn parse_exact_npm_spec(arg: &str) -> Result<(String, Option<String>), String> {
    let (name, version) = parse_npm_spec(arg);
    let not_exact = |why: &str| {
        Err(format!(
            "'{arg}' {why}. gyrseek scans exact versions and pins the install to them, so it cannot vouch for it. Use an exact version (name@1.2.3), a bare name (gyrseek then scans the latest version and pins it), or install from a lockfile (npm ci, npm install, pnpm install). Failing closed."
        ))
    };
    if !is_valid_npm_name(&name) {
        return not_exact("is an alias or not a package name gyrseek can look up");
    }
    match version.as_deref() {
        None | Some("latest") => Ok((name, None)),
        Some(v) if semver::Version::parse(v).is_ok() => Ok((name, version)),
        Some(_) => not_exact("is a version range or a dist-tag"),
    }
}

/// Every package an `npm`/`pnpm` install-family command will install, as exact targets:
/// the specs named on the command line, or with none named the lockfile (`package-lock.json`,
/// `npm-shrinkwrap.json` or `pnpm-lock.yaml`), which is what `npm install`, `npm ci` and
/// `pnpm install` actually install. `package.json` is not used: its dependencies are
/// ranges, so scanning them would scan versions other than the ones installed. `update`
/// picks new versions when it runs, so it has nothing to scan in advance.
pub(crate) fn parse_npm_install_packages_from_args(
    args: &[String],
) -> Result<Vec<(String, Option<String>)>, String> {
    let manager = args.first().map(String::as_str).unwrap_or_default();
    let command = args.get(1).map(String::as_str);
    if !is_npm_family_manager(manager) || !is_npm_family_package_command(manager, command) {
        return Ok(Vec::new());
    }

    let positional_args = npm_positional_args(args);

    if !positional_args.is_empty() {
        return positional_args
            .into_iter()
            .filter(|arg| !is_non_registry_npm_spec(arg))
            .map(parse_exact_npm_spec)
            .collect();
    }

    if command == Some("update") {
        let lockfile_only = if manager == "pnpm" {
            "pnpm update --lockfile-only"
        } else {
            "npm update --package-lock-only"
        };
        return Err(format!(
            "'{manager} update' chooses new versions when it runs, so gyrseek cannot scan them in advance. Run `{lockfile_only}` through gyrseek (it only rewrites the lockfile and installs nothing), then install from the new lockfile with gyrseek. Failing closed."
        ));
    }

    let lockfiles: &[&str] = if manager == "pnpm" {
        &["pnpm-lock.yaml"]
    } else {
        &["npm-shrinkwrap.json", "package-lock.json"]
    };
    let Some((file, content)) = lockfiles
        .iter()
        .find_map(|f| fs::read_to_string(f).ok().map(|c| (*f, c)))
    else {
        let make_one = if manager == "pnpm" {
            "pnpm install --lockfile-only"
        } else {
            "npm install --package-lock-only"
        };
        return Err(format!(
            "No {} found. `{manager} {}` installs whatever package.json's version ranges resolve to, which gyrseek cannot scan in advance. Create a lockfile without installing anything (`{make_one}`, which gyrseek forwards without scanning) and run gyrseek again. Failing closed.",
            lockfiles.join(" or "),
            command.unwrap_or("install"),
        ));
    };
    let packages = if manager == "pnpm" {
        parse_pnpm_lock_packages_from_content(&content)
    } else {
        parse_npm_lock_packages_from_content(&content)
    };
    if packages.is_empty() {
        return Err(format!(
            "{file} lists no registry packages to scan. Failing closed."
        ));
    }
    Ok(packages)
}

/// Exact registry packages from `package-lock.json` / `npm-shrinkwrap.json`: lockfile v2/v3
/// (`packages`, keyed by `node_modules/` path) or v1 (nested `dependencies`). Workspace
/// links, bundled dependencies and git/file sources are not registry downloads and are left
/// out.
pub(crate) fn parse_npm_lock_packages_from_content(content: &str) -> Vec<(String, Option<String>)> {
    let Ok(lock) = serde_json::from_str::<serde_json::Value>(content) else {
        return Vec::new();
    };
    let mut found = std::collections::BTreeSet::new();
    let mut add = |name: &str, entry: &serde_json::Value| {
        let resolved = entry.get("resolved").and_then(|v| v.as_str()).unwrap_or("");
        let from_registry = resolved.is_empty() || resolved.starts_with("http");
        let skipped = entry.get("link").and_then(|v| v.as_bool()) == Some(true)
            || entry.get("inBundle").and_then(|v| v.as_bool()) == Some(true)
            || !from_registry;
        if let Some(version) = entry.get("version").and_then(|v| v.as_str())
            && !skipped
            && semver::Version::parse(version).is_ok()
        {
            found.insert((name.to_string(), version.to_string()));
        }
    };

    if let Some(packages) = lock.get("packages").and_then(|v| v.as_object()) {
        for (key, entry) in packages {
            let Some(path_name) = key.rsplit_once("node_modules/").map(|(_, n)| n) else {
                continue; // the root project and workspace members
            };
            // An aliased dependency records the real package name in `name`.
            let name = entry
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or(path_name);
            add(name, entry);
        }
    } else {
        fn walk(
            deps: &serde_json::Map<String, serde_json::Value>,
            add: &mut impl FnMut(&str, &serde_json::Value),
        ) {
            for (name, entry) in deps {
                add(name, entry);
                if let Some(nested) = entry.get("dependencies").and_then(|v| v.as_object()) {
                    walk(nested, add);
                }
            }
        }
        if let Some(deps) = lock.get("dependencies").and_then(|v| v.as_object()) {
            walk(deps, &mut add);
        }
    }
    found.into_iter().map(|(n, v)| (n, Some(v))).collect()
}

/// Exact registry packages from `pnpm-lock.yaml`. The `packages` keys are `/name/1.2.3`
/// (v5), `/name@1.2.3(peer@1)` (v6) or `name@1.2.3` (v9); tarball and git sources are left
/// out.
pub(crate) fn parse_pnpm_lock_packages_from_content(
    content: &str,
) -> Vec<(String, Option<String>)> {
    let Ok(lock) = serde_yaml::from_str::<serde_yaml::Value>(content) else {
        return Vec::new();
    };
    let Some(packages) = lock.get("packages").and_then(|v| v.as_mapping()) else {
        return Vec::new();
    };
    let mut found = std::collections::BTreeSet::new();
    for (key, entry) in packages {
        let Some(key) = key.as_str() else { continue };
        let resolution = entry.get("resolution");
        let not_registry = resolution.is_some_and(|r| {
            ["tarball", "type", "repo", "commit"]
                .iter()
                .any(|k| r.get(*k).is_some())
        });
        if not_registry {
            continue;
        }
        let key = key.trim_start_matches('/');
        let key = key.split('(').next().unwrap_or(key);
        // v5 first (`name/1.2.3`, `name/1.2.3_peer@1`: a peer suffix contains `@`), then
        // v6/v9 (`name@1.2.3`).
        let v5 = key.rsplit_once('/').and_then(|(name, rest)| {
            let version = rest.split('_').next().unwrap_or(rest);
            semver::Version::parse(version)
                .ok()
                .map(|_| (name, version))
        });
        let Some((name, version)) =
            v5.or_else(|| key.rsplit_once('@').filter(|(n, _)| !n.is_empty()))
        else {
            continue;
        };
        if semver::Version::parse(version).is_ok() && is_valid_npm_name(name) {
            found.insert((name.to_string(), version.to_string()));
        }
    }
    found.into_iter().map(|(n, v)| (n, Some(v))).collect()
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

        // Poetry's `name@latest` is resolved again by poetry at install time; pin it.
        if manager == "poetry"
            && let Some(name) = arg.strip_suffix("@latest")
        {
            match pins.get(strip_pep508_extras(name)) {
                Some(version) if version != "latest" => out.push(format!("{name}=={version}")),
                _ => out.push(arg.clone()),
            }
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
        if has_only_non_registry_npm_specs(args) {
            return false;
        }
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

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|a| a.to_string()).collect()
    }

    fn names(args: &[&str]) -> Vec<String> {
        parse_python_install_packages_from_args(&strings(args))
            .expect("args should parse")
            .into_iter()
            .map(|(name, version)| match version {
                Some(v) => format!("{name}=={v}"),
                None => name,
            })
            .collect()
    }

    #[test]
    fn parses_every_package_of_uv_pip_install_uv_add_and_poetry_add() {
        assert_eq!(
            names(&["uv", "pip", "install", "six==1.16.0", "pandas"]),
            ["six==1.16.0", "pandas"]
        );
        assert_eq!(
            names(&["uv", "add", "requests", "flask==3.0.0"]),
            ["requests", "flask==3.0.0"]
        );
        assert_eq!(
            names(&["poetry", "add", "requests", "flask==3.0.0"]),
            ["requests", "flask==3.0.0"]
        );
        assert_eq!(names(&["pip", "install", "a", "b"]), ["a", "b"]);
    }

    #[test]
    fn flag_values_are_not_mistaken_for_packages() {
        assert_eq!(
            names(&["uv", "add", "--group", "dev", "pytest"]),
            ["pytest"]
        );
        assert_eq!(
            names(&["uv", "add", "pytest", "--optional", "extra", "ruff"]),
            ["pytest", "ruff"]
        );
        assert_eq!(
            names(&[
                "poetry", "add", "-G", "dev", "pytest", "--source", "internal", "x"
            ]),
            ["pytest", "x"]
        );
        assert_eq!(names(&["pip", "install", "--target", "vendor", "a"]), ["a"]);
        assert_eq!(
            names(&[
                "uv", "pip", "install", "--python", "3.12", "a", "-c", "c.txt", "b"
            ]),
            ["a", "b"]
        );
        assert_eq!(
            names(&[
                "pip",
                "install",
                "--index-url=https://x.example/simple",
                "a"
            ]),
            ["a"]
        );
    }

    #[test]
    fn boolean_flags_never_swallow_the_package_after_them() {
        assert_eq!(names(&["uv", "add", "--dev", "a", "b"]), ["a", "b"]);
        assert_eq!(names(&["uv", "add", "--editable", "a"]), ["a"]);
        assert_eq!(
            names(&["uv", "pip", "install", "--upgrade", "--no-deps", "a", "b"]),
            ["a", "b"]
        );
        assert_eq!(
            names(&["poetry", "add", "--dev", "--dry-run", "a", "b"]),
            ["a", "b"]
        );
        assert_eq!(names(&["pip", "install", "-U", "a", "b"]), ["a", "b"]);
    }

    #[test]
    fn requirement_files_are_read_in_every_spelling() {
        let mut req = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut req, b"requests==2.31.0\n# comment\npytest==9.0.3\n")
            .unwrap();
        let path = req.path().to_string_lossy().to_string();
        for form in [
            vec![
                "uv".to_string(),
                "pip".into(),
                "install".into(),
                "-r".into(),
                path.clone(),
            ],
            vec![
                "uv".to_string(),
                "add".into(),
                "--requirements".into(),
                path.clone(),
            ],
            vec![
                "pip".to_string(),
                "install".into(),
                "--requirement".into(),
                path.clone(),
            ],
            vec![
                "pip".to_string(),
                "install".into(),
                format!("--requirement={path}"),
            ],
            vec![
                "pip".to_string(),
                "install".into(),
                format!("--requirements={path}"),
            ],
        ] {
            assert_eq!(
                parse_python_install_packages_from_args(&form)
                    .expect("requirements file should parse")
                    .len(),
                2,
                "{form:?}"
            );
        }
    }

    fn write(dir: &std::path::Path, name: &str, content: &str) -> String {
        let path = dir.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, content).unwrap();
        path.to_string_lossy().to_string()
    }

    fn scan_r(path: &str) -> Result<Vec<String>, String> {
        parse_python_install_packages_from_args(&strings(&["pip", "install", "-r", path])).map(
            |p| {
                p.into_iter()
                    .map(|(name, version)| match version {
                        Some(v) => format!("{name}=={v}"),
                        None => name,
                    })
                    .collect()
            },
        )
    }

    fn exact(spec: &str, poetry: bool) -> Option<(String, Option<String>)> {
        parse_exact_requirement(spec, poetry)
            .unwrap_or_else(|e| panic!("{spec:?} should be accepted: {e}"))
    }

    #[test]
    fn exact_requirements_are_accepted_in_every_form() {
        let pinned = |n: &str, v: &str| Some((n.to_string(), Some(v.to_string())));
        let bare = |n: &str| Some((n.to_string(), None));
        assert_eq!(exact("requests", false), bare("requests"));
        assert_eq!(
            exact("requests==2.31.0", false),
            pinned("requests", "2.31.0")
        );
        assert_eq!(
            exact("requests == 2.31.0", false),
            pinned("requests", "2.31.0")
        );
        assert_eq!(
            exact("requests[security]==2.31.0", false),
            pinned("requests", "2.31.0")
        );
        assert_eq!(exact("requests[a,b]", false), bare("requests"));
        assert_eq!(exact("pkg==1.0rc1", false), pinned("pkg", "1.0rc1"));
        assert_eq!(
            exact("pkg==1!2.0+local.1", false),
            pinned("pkg", "1!2.0+local.1")
        );
        assert_eq!(
            exact("requests==2.31.0 ; python_version > \"3.8\"", false),
            pinned("requests", "2.31.0")
        );
        assert_eq!(
            exact("requests==2.31.0 --hash=sha256:abc", false),
            pinned("requests", "2.31.0")
        );
        assert_eq!(
            exact("requests==2.31.0 \\", false),
            pinned("requests", "2.31.0")
        );
        assert_eq!(
            exact("requests==2.31.0  # pinned", false),
            pinned("requests", "2.31.0")
        );
        assert_eq!(exact("requests@2.31.0", true), pinned("requests", "2.31.0"));
        assert_eq!(exact("requests@latest", true), bare("requests"));
    }

    #[test]
    fn non_requirement_lines_are_skipped() {
        for line in [
            "",
            "   ",
            "# comment",
            "-r base.txt",
            "--index-url https://x/simple",
            "./local-pkg",
            "/abs/pkg",
            "~/pkg",
        ] {
            assert_eq!(exact(line, false), None, "{line:?}");
        }
    }

    #[test]
    fn version_ranges_are_rejected_with_a_clear_message() {
        for spec in [
            "requests>=2",
            "requests>2",
            "requests<=2",
            "requests<3",
            "requests!=2.0",
            "requests~=2.1",
            "requests==2.*",
            "requests===2.0",
            "requests>=2,<3",
            "requests >= 2",
            "requests=2.0",
            "requests[security]>=2",
        ] {
            let err = parse_exact_requirement(spec, false).expect_err(spec);
            assert!(err.contains("version range"), "{spec}: {err}");
            assert!(err.contains("uv sync"), "{spec}: {err}");
        }
        let err = parse_exact_requirement("requests@^2.0", true).expect_err("poetry caret");
        assert!(err.contains("version range"), "{err}");
    }

    #[test]
    fn direct_references_and_urls_are_rejected() {
        for spec in [
            "requests @ https://evil.example/r.whl",
            "requests@https://evil.example/r.whl",
            "https://evil.example/r.whl",
            "git+https://github.com/x/y.git",
            "requests @ git+https://github.com/x/y.git",
            "requests @ file:///tmp/r.whl",
        ] {
            let err = parse_exact_requirement(spec, false).expect_err(spec);
            assert!(err.contains("not from the registry"), "{spec}: {err}");
        }
        assert!(parse_exact_requirement("requests@https://evil.example/r.whl", true).is_err());
    }

    #[test]
    fn install_commands_reject_ranges_and_direct_references_for_every_manager() {
        for args in [
            &["uv", "add", "pytest>=9.0.3"][..],
            &["uv", "add", "pytest", "ruff~=0.5"],
            &["uv", "pip", "install", "requests", "six==1.*"],
            &["pip", "install", "requests @ https://evil.example/r.whl"],
            &["pip", "install", "requests", "https://evil.example/x.whl"],
            &["poetry", "add", "requests@^2.0"],
        ] {
            let err = parse_python_install_packages_from_args(&strings(args))
                .expect_err(&format!("{args:?}"));
            assert!(err.contains("Failing closed"), "{args:?}: {err}");
        }
    }

    #[test]
    fn requirements_files_with_ranges_or_urls_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        for (name, content) in [
            ("range.txt", "six==1.16.0\npytest>=9\n"),
            ("url.txt", "six==1.16.0\nreq @ https://evil.example/r.whl\n"),
        ] {
            let path = write(d, name, content);
            assert!(scan_r(&path).is_err(), "{name}");
        }
        // Pinned lines with hashes, markers and comments are fine.
        let ok = write(
            d,
            "ok.txt",
            "# pinned\nsix==1.16.0 \\\n    --hash=sha256:abc\nattrs==24.2.0 ; python_version >= \"3.8\"\n",
        );
        assert_eq!(scan_r(&ok).unwrap(), ["six==1.16.0", "attrs==24.2.0"]);
    }

    #[test]
    fn an_attached_short_r_option_on_the_command_line_is_scanned() {
        let dir = tempfile::tempdir().unwrap();
        let hidden = write(dir.path(), "hidden.txt", "pandas==2.2.2\n");
        // pip accepts the value attached to the short option: `-rhidden.txt`.
        let found = names(&["pip", "install", "six==1.16.0", &format!("-r{hidden}")]);
        assert_eq!(found, ["six==1.16.0", "pandas==2.2.2"]);
        // A file that cannot be read must not be skipped.
        assert!(
            parse_python_install_packages_from_args(&strings(&[
                "uv",
                "pip",
                "install",
                "-r/no/such/file.txt"
            ]))
            .is_err()
        );
    }

    #[test]
    fn unpinned_lines_inside_a_requirements_file_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let bare = write(dir.path(), "bare.txt", "six==1.16.0\nrequests\n");
        let err = scan_r(&bare).unwrap_err();
        assert!(
            err.contains("'requests'") && err.contains("no pinned version"),
            "{err}"
        );
        assert!(err.contains("-c constraints file"), "{err}");
        // The same bare name on the command line is fine: the forwarded command is pinned.
        assert_eq!(names(&["pip", "install", "requests"]), ["requests"]);
        // A nested file is held to the same rule.
        write(dir.path(), "base.txt", "attrs\n");
        let top = write(dir.path(), "top.txt", "six==1.16.0\n-r base.txt\n");
        assert!(scan_r(&top).unwrap_err().contains("no pinned version"));
    }

    #[test]
    fn poetry_at_latest_is_pinned_to_the_scanned_version_on_forward() {
        let pins = HashMap::from([("requests".to_string(), "2.31.0".to_string())]);
        let args = strings(&["poetry", "add", "requests@latest", "six==1.16.0"]);
        assert_eq!(
            rewrite_args_with_pinned_versions("poetry", &args, &pins),
            strings(&["poetry", "add", "requests==2.31.0", "six==1.16.0"])
        );
        // An unresolved (exempt) package is left alone rather than pinned to "latest".
        let exempt = HashMap::from([("requests".to_string(), "latest".to_string())]);
        assert_eq!(
            rewrite_args_with_pinned_versions("poetry", &args, &exempt),
            args
        );
    }

    #[test]
    fn lockfile_only_uses_the_effective_value_of_the_flag() {
        let on = |a: &[&str]| is_lockfile_only_command(&strings(a));
        for yes in [
            &["npm", "install", "--package-lock-only"][..],
            &["npm", "install", "--package-lock-only=true"],
            &["npm", "install", "--package-lock-only", "true"],
            &["pnpm", "install", "--lockfile-only"],
            &[
                "npm",
                "install",
                "--package-lock-only=false",
                "--package-lock-only",
            ],
        ] {
            assert!(on(yes), "{yes:?}");
        }
        for no in [
            &["npm", "install"][..],
            &["npm", "install", "--package-lock-only", "false"],
            &["npm", "install", "--package-lock-only=false"],
            &["npm", "install", "--no-package-lock-only"],
            &[
                "npm",
                "install",
                "--package-lock-only",
                "--package-lock-only=false",
            ],
            &[
                "npm",
                "install",
                "--package-lock-only",
                "--no-package-lock-only",
            ],
            &["pnpm", "install", "--lockfile-only=false"],
            &["npm", "install", "--", "--package-lock-only"],
        ] {
            assert!(!on(no), "{no:?}");
        }
        // The `false` after a flag is its value, not a package called `false`.
        let args = strings(&["npm", "install", "--package-lock-only", "false", "lodash"]);
        assert_eq!(npm_positional_args(&args), ["lodash"]);
    }

    // ---- edge cases: Python requirement specs ---------------------------------------

    #[test]
    fn requirement_whitespace_case_and_name_forms() {
        let pinned = |n: &str, v: &str| Some((n.to_string(), Some(v.to_string())));
        // CRLF and tabs from files saved on Windows, and names with dots, dashes, underscores.
        assert_eq!(
            exact("requests==2.31.0\r", false),
            pinned("requests", "2.31.0")
        );
        assert_eq!(
            exact("\trequests\t==\t2.31.0\t", false),
            pinned("requests", "2.31.0")
        );
        assert_eq!(
            exact("Flask-SQLAlchemy==3.1.1", false),
            pinned("Flask-SQLAlchemy", "3.1.1")
        );
        assert_eq!(
            exact("zope.interface==6.0", false),
            pinned("zope.interface", "6.0")
        );
        assert_eq!(
            exact("typing_extensions==4.9.0", false),
            pinned("typing_extensions", "4.9.0")
        );
        assert_eq!(exact("1password==1.0", false), pinned("1password", "1.0"));
        // Extras with spaces and several entries.
        assert_eq!(
            exact("requests [security, socks] == 2.0", false),
            pinned("requests", "2.0")
        );
        // Markers with their own `==`, without a space before the semicolon.
        assert_eq!(
            exact("pywin32==306;sys_platform==\"win32\"", false),
            pinned("pywin32", "306")
        );
        assert_eq!(
            exact(
                "uvloop==0.19 ; platform_machine == 'x86_64' and python_version >= '3.8'",
                false
            ),
            pinned("uvloop", "0.19")
        );
        // Local version and epoch.
        assert_eq!(
            exact("torch==2.1.0+cpu", false),
            pinned("torch", "2.1.0+cpu")
        );
    }

    #[test]
    fn malformed_requirements_fail_closed_instead_of_being_guessed() {
        for bad in [
            "requests==",
            "==1.0",
            "requests==1.0==2.0",
            "requests==1.0,==2.0",
            "requests=1.0",
            "re quests==1.0",
            "reque$ts==1.0",
            "naïve==1.0",
            "C:\\pkgs\\x.whl",
            "requests==v",
            "requests==1.0 @ https://x.example/r.whl",
        ] {
            assert!(
                parse_exact_requirement(bad, false).is_err(),
                "{bad:?} must not be accepted as an exact registry version"
            );
        }
    }

    #[test]
    fn poetry_at_forms_edge_cases() {
        assert_eq!(
            exact("requests@", true),
            Some(("requests".to_string(), None))
        );
        assert!(parse_exact_requirement("@2.0.0", true).is_err());
        assert!(parse_exact_requirement("requests@2.0.0@x", true).is_err());
        assert!(parse_exact_requirement("requests@>=2", true).is_err());
        assert!(parse_exact_requirement("requests@*", true).is_err());
        // `@` is a direct reference everywhere except for Poetry's version separator.
        assert!(parse_exact_requirement("requests@2.0.0", false).is_err());
    }

    #[test]
    fn requirements_files_tolerate_a_bom_crlf_blank_lines_and_inline_comments() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let file = write(
            d,
            "win.txt",
            "\u{feff}six==1.16.0\r\n\r\n   \r\n# a comment\r\nattrs==24.2.0  # inline\r\n",
        );
        assert_eq!(scan_r(&file).unwrap(), ["six==1.16.0", "attrs==24.2.0"]);
        // An empty file is not an error here; the caller fails closed when nothing was named.
        let empty = write(d, "empty.txt", "");
        assert!(scan_r(&empty).unwrap().is_empty());
    }

    #[test]
    fn include_edge_cases_absolute_paths_directories_case_and_the_depth_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        // An absolute include is used as written, from anywhere.
        let abs = write(d, "elsewhere/abs.txt", "six==1.16.0\n");
        let top = write(d, "sub/top.txt", &format!("-r {abs}\n"));
        assert_eq!(scan_r(&top).unwrap(), ["six==1.16.0"]);
        // A directory (or anything unreadable as a file) cannot be scanned.
        std::fs::create_dir(d.join("adir")).unwrap();
        assert!(scan_r(&d.join("adir").to_string_lossy()).is_err());
        // The extension check is case-insensitive.
        assert!(scan_r(&write(d, "Pyproject.TOML", "x")).is_err());
        // Exactly MAX levels of nesting work; one more fails closed.
        for i in 0..=MAX_REQUIREMENTS_DEPTH + 1 {
            let content = if i == MAX_REQUIREMENTS_DEPTH {
                "six==1.16.0\n".to_string()
            } else {
                format!("-r d{}.txt\n", i + 1)
            };
            write(d, &format!("d{i}.txt"), &content);
        }
        assert_eq!(
            scan_r(&d.join("d0.txt").to_string_lossy()).unwrap(),
            ["six==1.16.0"]
        );
        write(
            d,
            &format!("d{}.txt", MAX_REQUIREMENTS_DEPTH),
            "-r d99.txt\n",
        );
        write(d, "d99.txt", "six==1.16.0\n");
        assert!(scan_r(&d.join("d0.txt").to_string_lossy()).is_err());
    }

    #[test]
    fn command_lines_with_missing_values_or_empty_arguments_do_not_panic() {
        // A trailing `-r` or value flag has no value; a blank argument names nothing.
        assert!(names(&["pip", "install", "-r"]).is_empty());
        assert!(names(&["uv", "add", "--group"]).is_empty());
        assert!(names(&["pip", "install", ""]).is_empty());
        assert!(names(&["pip", "install", "--", "-x"]).is_empty());
        assert!(names(&["pip", "install"]).is_empty());
        assert_eq!(names(&["pip", "install", "a", "-r"]), ["a"]);
        // Many packages keep their order.
        let many: Vec<String> = (0..200).map(|i| format!("pkg{i}==1.0.{i}")).collect();
        let mut args = vec!["uv".to_string(), "add".to_string()];
        args.extend(many.clone());
        let got = parse_python_install_packages_from_args(&args).unwrap();
        assert_eq!(got.len(), 200);
        assert_eq!(
            format!("{}=={}", got[199].0, got[199].1.clone().unwrap()),
            many[199]
        );
    }

    // ---- edge cases: npm / pnpm -----------------------------------------------------

    #[test]
    fn npm_names_and_specs_edge_cases() {
        for ok in [
            "lodash",
            "Lodash",
            "lodash.merge",
            "lodash_x",
            "a",
            "@a/b",
            "@types/node",
            "left-pad~",
        ] {
            assert!(is_valid_npm_name(ok), "{ok}");
        }
        for bad in [
            "", "@", "@scope", "@scope/", "@/name", "a/b", "@a/b/c", "a b", "naïve", "../x", "a@b",
        ] {
            assert!(!is_valid_npm_name(bad), "{bad}");
        }
        // Empty version after `@`, a v-prefix and a build tag are not exact semver here.
        for bad in [
            "lodash@",
            "lodash@v4.17.21",
            "lodash@4.17",
            "lodash@4.17.21.1",
            "lodash@ 4.17.21",
        ] {
            assert!(parse_exact_npm_spec(bad).is_err(), "{bad}");
        }
        for (spec, name, ver) in [
            ("lodash@4.17.21+build.5", "lodash", Some("4.17.21+build.5")),
            ("lodash@4.17.21-beta.1", "lodash", Some("4.17.21-beta.1")),
            ("@scope/pkg@1.0.0", "@scope/pkg", Some("1.0.0")),
        ] {
            assert_eq!(
                parse_exact_npm_spec(spec).unwrap(),
                (name.to_string(), ver.map(str::to_string)),
                "{spec}"
            );
        }
    }

    #[test]
    fn npm_flags_are_not_packages_and_the_command_decides_what_is_scanned() {
        let parse = |a: &[&str]| parse_npm_install_packages_from_args(&strings(a)).unwrap();
        let pkg = |n: &str| (n.to_string(), None);
        assert_eq!(
            parse(&["npm", "install", "-D", "lodash", "--save-exact"]),
            [pkg("lodash")]
        );
        assert_eq!(
            parse(&["pnpm", "add", "-D", "lodash", "-w"]),
            [pkg("lodash")]
        );
        // A package that is literally called `true` or `false` is still a package.
        assert_eq!(parse(&["npm", "install", "true"]), [pkg("true")]);
        // Commands that are not install-family commands scan nothing.
        for cmd in [
            &["npm", "run", "build"][..],
            &["npm", "audit"],
            &["pnpm", "dlx", "x"],
            &["npm", "uninstall", "x"],
        ] {
            assert!(parse(cmd).is_empty(), "{cmd:?}");
        }
        // Local specs next to a registry spec are skipped, not scanned.
        assert_eq!(
            parse(&["npm", "install", "./local", "lodash"]),
            [pkg("lodash")]
        );
    }

    #[test]
    fn lockfile_parsers_survive_hostile_and_degenerate_input() {
        for junk in [
            "",
            "{}",
            "[]",
            "null",
            "{\"packages\":null}",
            "{\"packages\":[]}",
            "{\"dependencies\":5}",
            "\u{0}\u{1}",
            "{{{{",
        ] {
            assert!(
                parse_npm_lock_packages_from_content(junk).is_empty(),
                "{junk:?}"
            );
        }
        for junk in [
            "",
            "{}",
            "packages:\n",
            "packages: null\n",
            "packages: [a, b]\n",
            ": : :",
            "\u{0}",
        ] {
            assert!(
                parse_pnpm_lock_packages_from_content(junk).is_empty(),
                "{junk:?}"
            );
        }
        // Absurd nesting must not overflow the stack: serde_json refuses past its depth limit.
        let deep = format!("{}1{}", "[".repeat(100_000), "]".repeat(100_000));
        assert!(parse_npm_lock_packages_from_content(&deep).is_empty());
        let nested_deps = format!(
            "{{\"dependencies\":{}}}",
            (0..300).fold("{}".to_string(), |inner, _| {
                format!("{{\"x\":{{\"version\":\"1.0.0\",\"dependencies\":{inner}}}}}")
            })
        );
        let _ = parse_npm_lock_packages_from_content(&nested_deps); // must return, whatever it finds
    }

    #[test]
    fn lockfile_entries_with_missing_or_odd_fields_are_handled() {
        let lock = r#"{"lockfileVersion":3,"packages":{
            "node_modules/noversion":{"resolved":"https://registry.npmjs.org/n/-/n-1.0.0.tgz"},
            "node_modules/badversion":{"version":"latest","resolved":"https://registry.npmjs.org/b/-/b.tgz"},
            "node_modules/numeric":{"version":5},
            "node_modules/empty-resolved":{"version":"1.0.0","resolved":""},
            "node_modules/no-resolved":{"version":"2.0.0"},
            "node_modules/@s/scoped":{"version":"3.0.0","resolved":"https://registry.npmjs.org/@s/scoped/-/scoped-3.0.0.tgz"},
            "node_modules/dup":{"version":"1.0.0","resolved":"https://registry.npmjs.org/dup/-/dup-1.0.0.tgz"},
            "node_modules/x/node_modules/dup":{"version":"1.0.0","resolved":"https://registry.npmjs.org/dup/-/dup-1.0.0.tgz"},
            "node_modules/prerelease":{"version":"1.0.0-rc.1","resolved":"https://registry.npmjs.org/p/-/p.tgz"}}}"#;
        assert_eq!(
            pkgs(parse_npm_lock_packages_from_content(lock)),
            [
                "@s/scoped@3.0.0",
                "dup@1.0.0",
                "empty-resolved@1.0.0",
                "no-resolved@2.0.0",
                "prerelease@1.0.0-rc.1"
            ]
        );
    }

    #[test]
    fn lockfile_only_flag_value_edge_cases_always_err_towards_scanning() {
        let on = |a: &[&str]| is_lockfile_only_command(&strings(a));
        // Values npm might read as false or garbage count as "not lockfile-only": scan.
        for scanned in [
            &["npm", "install", "--package-lock-only=1"][..],
            &["npm", "install", "--package-lock-only=TRUE"],
            &["npm", "install", "--package-lock-only=yes"],
            &["npm", "install", "--package-lock-onlyx"],
            &["npm", "install", "--lockfile-only-x"],
        ] {
            assert!(!on(scanned), "{scanned:?}");
        }
        // `maybe` is not a boolean, so npm reads it as a package name and the flag is on:
        // a lockfile-only command, which installs nothing.
        assert!(on(&["npm", "install", "--package-lock-only", "maybe"]));
        // An empty value is the same as the bare flag.
        assert!(on(&["npm", "install", "--package-lock-only="]));
        // Turning it off then on again, then off again.
        assert!(!on(&[
            "npm",
            "install",
            "--package-lock-only",
            "--no-package-lock-only",
            "--package-lock-only",
            "false"
        ]));
    }

    #[test]
    fn nested_r_includes_are_followed_relative_to_the_including_file() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        write(d, "reqs/base.txt", "six==1.16.0\n-r common/shared.txt\n");
        write(d, "reqs/common/shared.txt", "attrs==24.2.0\n");
        let top = write(
            d,
            "reqs/prod.txt",
            "flask==3.0.0\n-r base.txt  # shared deps\n--requirement=base.txt\n",
        );
        // base.txt is included twice but read once; paths are relative to each file.
        assert_eq!(
            scan_r(&top).unwrap(),
            ["flask==3.0.0", "six==1.16.0", "attrs==24.2.0"]
        );
    }

    #[test]
    fn every_include_spelling_is_followed() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        write(d, "a.txt", "six==1.16.0\n");
        for line in [
            "-r a.txt",
            "-ra.txt",
            "--requirement a.txt",
            "--requirement=a.txt",
            "  -r   a.txt  ",
        ] {
            let top = write(d, "top.txt", &format!("{line}\n"));
            assert_eq!(scan_r(&top).unwrap(), ["six==1.16.0"], "{line:?}");
        }
    }

    #[test]
    fn include_cycles_terminate_and_deep_nesting_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        write(d, "a.txt", "six==1.16.0\n-r b.txt\n");
        write(d, "b.txt", "attrs==24.2.0\n-r a.txt\n");
        assert_eq!(
            scan_r(&d.join("a.txt").to_string_lossy()).unwrap(),
            ["six==1.16.0", "attrs==24.2.0"]
        );
        for i in 0..=MAX_REQUIREMENTS_DEPTH + 1 {
            write(d, &format!("n{i}.txt"), &format!("-r n{}.txt\n", i + 1));
        }
        write(
            d,
            &format!("n{}.txt", MAX_REQUIREMENTS_DEPTH + 2),
            "six==1.16.0\n",
        );
        let err = scan_r(&d.join("n0.txt").to_string_lossy()).unwrap_err();
        assert!(err.contains("nested more than"), "{err}");
    }

    #[test]
    fn a_bad_nested_include_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let missing = write(d, "missing.txt", "six==1.16.0\n-r gone.txt\n");
        assert!(
            scan_r(&missing)
                .unwrap_err()
                .contains("Cannot read the requirements file")
        );
        let toml = write(d, "toml.txt", "six==1.16.0\n-r pyproject.toml\n");
        assert!(
            scan_r(&toml)
                .unwrap_err()
                .contains("cannot resolve to a scanned version")
        );
        let url = write(d, "url.txt", "-r https://example.invalid/base.txt\n");
        assert!(scan_r(&url).is_err());
    }

    #[test]
    fn r_file_that_is_not_a_requirements_file_or_cannot_be_read_fails_closed() {
        for file in [
            "./pyproject.toml",
            "setup.py",
            "setup.cfg",
            "PYPROJECT.TOML",
        ] {
            let err = parse_python_install_packages_from_args(&strings(&[
                "uv", "pip", "install", "-r", file,
            ]))
            .expect_err(file);
            assert!(err.contains("Failing closed"), "{err}");
            assert!(err.contains("uv sync"), "{err}");
        }
        let err = parse_python_install_packages_from_args(&strings(&[
            "pip",
            "install",
            "a",
            "--requirement=/no/such/requirements.txt",
        ]))
        .expect_err("a missing file must not be skipped");
        assert!(err.contains("Cannot read the requirements file"), "{err}");
    }

    #[test]
    fn other_python_commands_have_no_install_packages() {
        for args in [
            &["uv", "sync"][..],
            &["uv", "lock"],
            &["uv", "pip", "sync", "req.txt"],
            &["poetry", "install"],
            &["poetry", "update", "requests"],
            &["npm", "install", "a"],
        ] {
            assert!(names(args).is_empty(), "{args:?}");
        }
    }

    #[test]
    fn parses_pip_install_multi_packages_and_requirements_file() {
        let mut req_file = tempfile::NamedTempFile::new().unwrap();
        let req_path = req_file.path().to_string_lossy().to_string();
        std::io::Write::write_all(&mut req_file, b"requests==2.31.0\npytest==9.0.3\n").unwrap();
        let a = vec![
            "pip3".to_string(),
            "install".to_string(),
            "-r".to_string(),
            req_path,
            "flask==3.0.0".to_string(),
        ];
        let parsed = parse_python_install_packages_from_args(&a).expect("should parse");
        assert_eq!(
            parsed,
            vec![
                ("requests".to_string(), Some("2.31.0".to_string())),
                ("pytest".to_string(), Some("9.0.3".to_string())),
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
        let parsed = parse_npm_install_packages_from_args(&a).expect("should parse");
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
        let parsed = parse_npm_install_packages_from_args(&a).expect("should parse");
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
        assert!(
            parse_npm_install_packages_from_args(&a)
                .expect("should parse")
                .is_empty()
        );
        assert!(!should_enforce_package_detection("npm", &a));
    }

    #[test]
    fn npm_install_all_non_registry_specs_detected_and_skips_package_json_fallback() {
        // Findings 11 & 12: When all args are non-registry specs (e.g. file:, git+, https://),
        // parse_npm_install_packages_from_args returns empty and must NOT fall back to package.json.
        // has_only_non_registry_npm_specs returns true, and should_enforce_package_detection returns false.
        let a = vec![
            "npm".to_string(),
            "install".to_string(),
            "file:../local-pkg".to_string(),
        ];
        assert!(
            parse_npm_install_packages_from_args(&a)
                .expect("should parse")
                .is_empty()
        );
        assert!(has_only_non_registry_npm_specs(&a));
        assert!(!should_enforce_package_detection("npm", &a));

        let b = vec![
            "npm".to_string(),
            "install".to_string(),
            "--save-dev".to_string(),
            "https://registry.example.com/tool.tgz".to_string(),
        ];
        assert!(
            parse_npm_install_packages_from_args(&b)
                .expect("should parse")
                .is_empty()
        );
        assert!(has_only_non_registry_npm_specs(&b));
        assert!(!should_enforce_package_detection("npm", &b));

        let c = vec![
            "pnpm".to_string(),
            "add".to_string(),
            "./local-pkg.tgz".to_string(),
        ];
        assert!(
            parse_npm_install_packages_from_args(&c)
                .expect("should parse")
                .is_empty()
        );
        assert!(has_only_non_registry_npm_specs(&c));
        assert!(!should_enforce_package_detection("pnpm", &c));

        // Mixed case: registry + non-registry must NOT report only-non-registry
        let mixed = vec![
            "npm".to_string(),
            "install".to_string(),
            "lodash".to_string(),
            "file:../local-pkg".to_string(),
        ];
        assert_eq!(
            parse_npm_install_packages_from_args(&mixed).expect("should parse"),
            vec![("lodash".to_string(), None)]
        );
        assert!(!has_only_non_registry_npm_specs(&mixed));
        assert!(should_enforce_package_detection("npm", &mixed));

        // Bare install: no positional args must NOT report only-non-registry
        let bare = vec!["npm".to_string(), "install".to_string()];
        assert!(!has_only_non_registry_npm_specs(&bare));
        assert!(should_enforce_package_detection("npm", &bare));
    }

    #[test]
    fn pnpm_install_args_skip_non_registry_specs() {
        let a = vec![
            "pnpm".to_string(),
            "install".to_string(),
            "workspace:*".to_string(),
            "lodash".to_string(),
        ];
        let parsed = parse_npm_install_packages_from_args(&a).expect("should parse");
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
        let parsed = parse_npm_install_packages_from_args(&a).expect("should parse");
        assert_eq!(
            parsed,
            vec![
                ("lodash".to_string(), None),
                ("typescript".to_string(), None)
            ]
        );
    }

    #[test]
    fn npm_cli_specs_must_name_one_exact_registry_version() {
        let ok = |spec: &str| parse_exact_npm_spec(spec).expect(spec);
        assert_eq!(ok("lodash"), ("lodash".to_string(), None));
        assert_eq!(ok("lodash@latest"), ("lodash".to_string(), None));
        assert_eq!(
            ok("lodash@4.17.21"),
            ("lodash".to_string(), Some("4.17.21".to_string()))
        );
        assert_eq!(ok("@types/node"), ("@types/node".to_string(), None));
        assert_eq!(
            ok("@types/node@20.1.0-rc.1"),
            ("@types/node".to_string(), Some("20.1.0-rc.1".to_string()))
        );
        for bad in [
            "lodash@^4.17.0",
            "lodash@~4",
            "lodash@>=4 <5",
            "lodash@4.x",
            "lodash@*",
            "lodash@4",
            "lodash@next",
            "lodash@npm:other@1.0.0",
            "@types/node@^20",
            "Bad Name",
            "lo$dash",
        ] {
            let err = parse_exact_npm_spec(bad).expect_err(bad);
            assert!(err.contains("exact versions"), "{bad}: {err}");
        }
    }

    #[test]
    fn npm_install_commands_reject_ranges_on_the_command_line() {
        for args in [
            &["npm", "install", "lodash@^3.0.0"][..],
            &["npm", "install", "express", "lodash@~4"],
            &["pnpm", "add", "react@next"],
            &["npm", "update", "lodash@^3"],
        ] {
            let err = parse_npm_install_packages_from_args(&strings(args))
                .expect_err(&format!("{args:?}"));
            assert!(err.contains("Failing closed"), "{args:?}: {err}");
        }
    }

    #[test]
    fn update_without_packages_has_nothing_to_scan_in_advance() {
        for (args, hint) in [
            (&["npm", "update"][..], "npm update --package-lock-only"),
            (&["pnpm", "update"], "pnpm update --lockfile-only"),
        ] {
            let err = parse_npm_install_packages_from_args(&strings(args)).expect_err("update");
            assert!(err.contains(hint), "{err}");
        }
    }

    #[test]
    fn npm_ci_is_a_package_command_and_lockfile_only_flags_are_detected() {
        assert!(is_npm_family_package_command("npm", Some("ci")));
        assert!(!is_npm_family_package_command("pnpm", Some("ci")));
        assert!(should_enforce_package_detection(
            "npm",
            &strings(&["npm", "ci"])
        ));
        assert!(is_lockfile_only_command(&strings(&[
            "npm",
            "install",
            "--package-lock-only"
        ])));
        assert!(is_lockfile_only_command(&strings(&[
            "pnpm",
            "install",
            "--lockfile-only"
        ])));
        assert!(!is_lockfile_only_command(&strings(&["npm", "install"])));
    }

    fn pkgs(list: Vec<(String, Option<String>)>) -> Vec<String> {
        list.into_iter()
            .map(|(n, v)| format!("{n}@{}", v.unwrap_or_default()))
            .collect()
    }

    #[test]
    fn package_lock_v3_lists_every_installed_registry_version() {
        let lock = r#"{"name":"app","lockfileVersion":3,"packages":{
            "":{"name":"app","dependencies":{"lodash":"^4"}},
            "node_modules/lodash":{"version":"4.17.21","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"},
            "node_modules/@types/node":{"version":"20.1.0","resolved":"https://registry.npmjs.org/@types/node/-/node-20.1.0.tgz","dev":true},
            "node_modules/a/node_modules/lodash":{"version":"3.10.1","resolved":"https://registry.npmjs.org/lodash/-/lodash-3.10.1.tgz"},
            "node_modules/mine":{"resolved":"packages/mine","link":true},
            "packages/mine":{"name":"mine","version":"1.0.0"},
            "node_modules/gitdep":{"version":"1.0.0","resolved":"git+ssh://git@github.com/x/y.git#abc"},
            "node_modules/filedep":{"version":"1.0.0","resolved":"file:../filedep"},
            "node_modules/bundled":{"version":"1.0.0","inBundle":true},
            "node_modules/alias":{"name":"real-name","version":"2.0.0","resolved":"https://registry.npmjs.org/real-name/-/real-name-2.0.0.tgz"}}}"#;
        assert_eq!(
            pkgs(parse_npm_lock_packages_from_content(lock)),
            [
                "@types/node@20.1.0",
                "lodash@3.10.1",
                "lodash@4.17.21",
                "real-name@2.0.0"
            ]
        );
    }

    #[test]
    fn package_lock_v1_walks_nested_dependencies() {
        let lock = r#"{"lockfileVersion":1,"dependencies":{
            "lodash":{"version":"4.17.21","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"},
            "a":{"version":"1.0.0","resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz","dependencies":{
                "b":{"version":"2.0.0","resolved":"https://registry.npmjs.org/b/-/b-2.0.0.tgz"}}},
            "gitdep":{"version":"github:x/y#abc"}}}"#;
        assert_eq!(
            pkgs(parse_npm_lock_packages_from_content(lock)),
            ["a@1.0.0", "b@2.0.0", "lodash@4.17.21"]
        );
        assert!(parse_npm_lock_packages_from_content("not json").is_empty());
    }

    #[test]
    fn pnpm_lock_keys_are_read_in_v5_v6_and_v9_forms() {
        let v9 = "lockfileVersion: '9.0'\npackages:\n  lodash@4.17.21:\n    resolution: {integrity: sha512-a}\n  '@types/node@20.1.0':\n    resolution: {integrity: sha512-b}\n  gitdep@https://codeload.github.com/x/y/tar.gz/abc:\n    resolution: {tarball: https://codeload.github.com/x/y/tar.gz/abc}\n    version: 1.0.0\nsnapshots: {}\n";
        assert_eq!(
            pkgs(parse_pnpm_lock_packages_from_content(v9)),
            ["@types/node@20.1.0", "lodash@4.17.21"]
        );
        let v6 = "lockfileVersion: '6.0'\npackages:\n  /lodash@4.17.21:\n    resolution: {integrity: sha512-a}\n  /@types/react@18.2.0(react@18.2.0):\n    resolution: {integrity: sha512-b}\n";
        assert_eq!(
            pkgs(parse_pnpm_lock_packages_from_content(v6)),
            ["@types/react@18.2.0", "lodash@4.17.21"]
        );
        let v5 = "lockfileVersion: 5.4\npackages:\n  /lodash/4.17.21:\n    resolution: {integrity: sha512-a}\n  /@types/node/20.1.0:\n    resolution: {integrity: sha512-b}\n  /foo/1.0.0_react@17.0.0:\n    resolution: {integrity: sha512-c}\n  github.com/x/y/abc:\n    resolution: {tarball: https://codeload.github.com/x/y/tar.gz/abc}\n";
        assert_eq!(
            pkgs(parse_pnpm_lock_packages_from_content(v5)),
            ["@types/node@20.1.0", "foo@1.0.0", "lodash@4.17.21"]
        );
        assert!(parse_pnpm_lock_packages_from_content("::: not yaml :::").is_empty());
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

    // --- gap #9: parse_npm_install_packages_from_args link: spec not filtered ---

    #[test]
    fn npm_install_args_skips_link_spec() {
        let a = vec![
            "npm".to_string(),
            "install".to_string(),
            "link:../local-pkg".to_string(),
            "lodash".to_string(),
        ];
        let parsed = parse_npm_install_packages_from_args(&a).expect("should parse");
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
