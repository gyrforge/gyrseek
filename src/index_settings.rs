//! Package-manager settings that send an install to another index or registry than the public one
//! gyrseek scans (FIXED #445). The sandbox probes the public package of the same name and
//! version, so an install that is redirected by a flag, an environment variable, a requirements
//! file or a config file (`pip.conf`, `uv.toml`, `pyproject.toml`, `.npmrc`) would fetch something
//! the scan never saw (dependency confusion). A redirect is refused unless its host is the public
//! registry or is listed in `trusted_index_hosts`. A value that is a local path is the user's own
//! files and is left alone.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::parsing::read_input;

const PYPI_HOSTS: &[&str] = &["pypi.org", "files.pythonhosted.org"];
const NPM_HOSTS: &[&str] = &["registry.npmjs.org"];
const MAX_REQUIREMENTS_DEPTH: usize = 10;

/// Where settings are read from. A struct so tests can point it at a temporary directory.
pub(crate) struct Settings {
    pub vars: HashMap<String, String>,
    pub cwd: PathBuf,
    pub home: Option<PathBuf>,
}

impl Settings {
    pub(crate) fn from_process() -> Self {
        Self {
            vars: std::env::vars().collect(),
            cwd: std::env::current_dir().unwrap_or_default(),
            home: std::env::var_os("HOME").map(PathBuf::from),
        }
    }

    fn var(&self, key: &str) -> Option<&str> {
        self.vars
            .get(key)
            .map(String::as_str)
            .filter(|v| !v.is_empty())
    }

    fn config_home(&self) -> Option<PathBuf> {
        self.var("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| self.home.as_ref().map(|h| h.join(".config")))
    }
}

/// One setting that names an index or registry.
struct Redirect {
    setting: String,
    url: String,
}

fn redirect(setting: impl Into<String>, url: impl Into<String>) -> Redirect {
    Redirect {
        setting: setting.into(),
        url: url.into(),
    }
}

/// The host of a URL, lowercase and without credentials or port (an IPv6 literal keeps its
/// brackets); `None` for anything that is not a URL (a local path, `file:`).
fn host_of(url: &str) -> Option<String> {
    let rest = url.trim().split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let host = match host.strip_prefix('[') {
        Some(inner) => format!("[{}]", inner.split(']').next().unwrap_or(inner)),
        None => host.split(':').next().unwrap_or(host).to_string(),
    };
    let host = host.to_ascii_lowercase();
    (!host.is_empty()).then_some(host) // `file:///path` has no host: it is a local path
}

/// A `trusted_index_hosts` entry as a bare lowercase host (a pasted URL or `host:port` is cut down).
pub(crate) fn normalize_trusted_host(entry: &str) -> String {
    let entry = entry.trim();
    host_of(entry)
        .or_else(|| host_of(&format!("https://{entry}")))
        .unwrap_or_default()
}

/// The host a setting's value points at: a URL's host, the host of a protocol-relative
/// `//host/path`, or, for a value without a scheme, the first segment when it looks like a host
/// (`nexus.corp.example/simple`) and is not a path that exists here. `None` is a local path.
fn host_of_value(value: &str, cwd: &Path) -> Option<String> {
    let value = value.trim();
    if let Some(host) = host_of(value) {
        return Some(host);
    }
    if let Some(rest) = value.strip_prefix("//") {
        return host_of(&format!("https://{rest}"));
    }
    let first = value.split('/').next().unwrap_or("");
    let local = value.is_empty()
        || value.starts_with(['.', '/', '~'])
        || value.starts_with("file:")
        || !first.contains('.')
        || cwd.join(value).exists();
    if local {
        None
    } else {
        host_of(&format!("https://{value}"))
    }
}

/// `Some(host)` if `url` sends the install somewhere that is neither public nor trusted.
fn untrusted_host(
    url: &str,
    public: &[&str],
    trusted: &HashSet<String>,
    cwd: &Path,
) -> Option<String> {
    if url.contains("${") {
        return Some("an unresolved variable".to_string()); // cannot be checked, so refused
    }
    let host = host_of_value(url, cwd)?;
    (!public.contains(&host.as_str()) && !trusted.contains(&host)).then_some(host)
}

fn read(path: &Path) -> Option<String> {
    read_input(&path.to_string_lossy()).ok()
}

fn words(value: &str) -> impl Iterator<Item = &str> {
    value
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|w| !w.is_empty())
}

/// uv's `--index NAME=URL` / `UV_INDEX=NAME=URL`: the URL is what follows the name.
fn index_url(value: &str) -> &str {
    match value.split_once('=') {
        Some((name, url)) if !name.contains("://") => url,
        _ => value,
    }
}

// ---------------------------------------------------------------- Python

const PYTHON_LONG_FLAGS: &[&str] = &[
    "--index-url",
    "--extra-index-url",
    "--default-index",
    "--index",
    "--find-links",
];

fn python_flag_redirects(args: &[String], short_flags: bool) -> Vec<Redirect> {
    let mut found = Vec::new();
    let mut it = args.iter().skip(1);
    while let Some(arg) = it.next() {
        let (flag, value) = if let Some((f, v)) = arg.split_once('=')
            && PYTHON_LONG_FLAGS.contains(&f)
        {
            (f.to_string(), Some(v.to_string()))
        } else if PYTHON_LONG_FLAGS.contains(&arg.as_str())
            || (short_flags && (arg == "-i" || arg == "-f"))
        {
            (arg.clone(), it.next().cloned())
        } else if short_flags
            && (arg.starts_with("-i") || arg.starts_with("-f"))
            && !arg.starts_with("--")
            && arg.contains("://")
        {
            (arg[..2].to_string(), Some(arg[2..].to_string()))
        } else {
            continue;
        };
        if let Some(value) = value {
            found.push(redirect(flag, index_url(&value)));
        }
    }
    found
}

/// Index options inside a requirements file (and the files it includes with `-r`).
fn requirements_redirects(
    path: &Path,
    seen: &mut HashSet<PathBuf>,
    depth: usize,
    found: &mut Vec<Redirect>,
) {
    if depth > MAX_REQUIREMENTS_DEPTH || !seen.insert(path.to_path_buf()) {
        return;
    }
    let Some(content) = read(path) else { return };
    let dir = path.parent().unwrap_or_else(|| Path::new(""));
    for line in content.lines() {
        let line = line.split(" #").next().unwrap_or(line).trim();
        let mut tokens = line.split_whitespace();
        let Some(first) = tokens.next() else { continue };
        let (flag, inline) = match first.split_once('=') {
            Some((f, v)) => (f, Some(v)),
            None => (first, None),
        };
        let value = inline.or_else(|| tokens.next());
        match (flag, value) {
            ("-r" | "--requirement", Some(file)) => {
                requirements_redirects(&dir.join(file), seen, depth + 1, found)
            }
            (f, Some(v)) if f == "-i" || f == "-f" || PYTHON_LONG_FLAGS.contains(&f) => {
                found.push(redirect(format!("{}: {f}", path.display()), index_url(v)));
            }
            _ => {}
        }
    }
}

/// Requirements files named on the command line: `-r FILE`, `--requirement FILE`, `-rFILE`, and
/// the files given to `uv pip sync`.
fn requirements_files(args: &[String]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let sync = args.get(1).map(String::as_str) == Some("pip")
        && args.get(2).map(String::as_str) == Some("sync");
    let mut it = args.iter().skip(1);
    while let Some(arg) = it.next() {
        if arg == "-r" || arg == "--requirement" {
            files.extend(it.next().map(PathBuf::from));
        } else if let Some(v) = arg.strip_prefix("--requirement=") {
            files.push(PathBuf::from(v));
        } else if let Some(v) = arg
            .strip_prefix("-r")
            .filter(|v| !v.is_empty() && !arg.starts_with("--"))
        {
            files.push(PathBuf::from(v));
        } else if sync && !arg.starts_with('-') && Path::new(arg).is_file() {
            files.push(PathBuf::from(arg));
        }
    }
    files
}

fn python_env_redirects(manager: &str, s: &Settings) -> Vec<Redirect> {
    let names: &[&str] = match manager {
        "uv" => &[
            "UV_INDEX_URL",
            "UV_EXTRA_INDEX_URL",
            "UV_DEFAULT_INDEX",
            "UV_INDEX",
            "UV_FIND_LINKS",
        ],
        "poetry" => &[],
        _ => &["PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS"],
    };
    let mut found: Vec<Redirect> = names
        .iter()
        .filter_map(|n| s.var(n).map(|v| (*n, v)))
        .flat_map(|(n, v)| words(v).map(move |w| redirect(n, index_url(w))))
        .collect();
    if manager == "poetry" {
        found.extend(
            s.vars
                .iter()
                .filter(|(k, _)| k.starts_with("POETRY_REPOSITORIES_") && k.ends_with("_URL"))
                .map(|(k, v)| redirect(k.clone(), v.as_str())),
        );
    }
    found
}

/// `[global]` / `[install]` index settings of a `pip.conf` (ini; values may continue on
/// indented lines).
fn pip_conf_redirects(path: &Path) -> Vec<Redirect> {
    let Some(content) = read(path) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    let mut section = String::new();
    let mut key: Option<String> = None;
    for raw in content.lines() {
        if raw.trim().is_empty() || raw.trim_start().starts_with(['#', ';']) {
            continue;
        }
        if raw.starts_with(char::is_whitespace) {
            if let (Some(k), true) = (&key, section == "global" || section == "install") {
                found.extend(words(raw).map(|w| redirect(format!("{}: {k}", path.display()), w)));
            }
            continue;
        }
        let line = raw.trim();
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name.trim().to_ascii_lowercase();
            key = None;
            continue;
        }
        let Some((k, v)) = line.split_once(['=', ':']) else {
            continue;
        };
        let k = k.trim().to_ascii_lowercase().replace('_', "-");
        key = ["index-url", "extra-index-url", "find-links"]
            .contains(&k.as_str())
            .then_some(k.clone());
        if let (Some(k), true) = (&key, section == "global" || section == "install") {
            found.extend(words(v).map(|w| redirect(format!("{}: {k}", path.display()), w)));
        }
    }
    found
}

fn toml_strings(value: Option<&toml::Value>) -> Vec<&str> {
    match value {
        Some(toml::Value::String(s)) => vec![s.as_str()],
        Some(toml::Value::Array(items)) => items
            .iter()
            .filter_map(|i| i.as_str().or_else(|| i.get("url").and_then(|u| u.as_str())))
            .collect(),
        _ => Vec::new(),
    }
}

/// uv's index settings in a `uv.toml` or `[tool.uv]` table (and its `[pip]` table).
fn uv_table_redirects(table: &toml::Table, label: &str, found: &mut Vec<Redirect>) {
    for key in [
        "index-url",
        "extra-index-url",
        "find-links",
        "index",
        "default-index",
    ] {
        for url in toml_strings(table.get(key)) {
            found.push(redirect(format!("{label}: {key}"), index_url(url)));
        }
    }
    if let Some(pip) = table.get("pip").and_then(|p| p.as_table()) {
        uv_table_redirects(pip, label, found);
    }
}

fn parse_toml(path: &Path) -> Option<toml::Table> {
    read(path)?.parse::<toml::Table>().ok()
}

fn ancestors(cwd: &Path) -> impl Iterator<Item = &Path> {
    cwd.ancestors()
}

fn python_file_redirects(manager: &str, s: &Settings) -> Vec<Redirect> {
    let mut found = Vec::new();
    match manager {
        "uv" => {
            let mut user: Vec<PathBuf> = s
                .config_home()
                .map(|c| c.join("uv/uv.toml"))
                .into_iter()
                .collect();
            user.push(PathBuf::from("/etc/uv/uv.toml"));
            user.extend(s.var("UV_CONFIG_FILE").map(PathBuf::from));
            let project =
                ancestors(&s.cwd).flat_map(|d| [d.join("uv.toml"), d.join("pyproject.toml")]);
            for path in project.chain(user) {
                let Some(table) = parse_toml(&path) else {
                    continue;
                };
                let label = path.display().to_string();
                if path.ends_with("pyproject.toml") {
                    if let Some(uv) = table
                        .get("tool")
                        .and_then(|t| t.get("uv"))
                        .and_then(|u| u.as_table())
                    {
                        uv_table_redirects(uv, &label, &mut found);
                    }
                } else {
                    uv_table_redirects(&table, &label, &mut found);
                }
            }
        }
        "poetry" => {
            for dir in ancestors(&s.cwd) {
                let path = dir.join("pyproject.toml");
                let Some(table) = parse_toml(&path) else {
                    continue;
                };
                let sources = table
                    .get("tool")
                    .and_then(|t| t.get("poetry"))
                    .and_then(|p| p.get("source"))
                    .and_then(|s| s.as_array());
                for url in sources
                    .into_iter()
                    .flatten()
                    .filter_map(|s| s.get("url")?.as_str())
                {
                    found.push(redirect(
                        format!("{}: tool.poetry.source", path.display()),
                        url,
                    ));
                }
            }
            let user = s
                .config_home()
                .map(|c| c.join("pypoetry/config.toml"))
                .into_iter()
                .chain(
                    s.home
                        .as_ref()
                        .map(|h| h.join("Library/Application Support/pypoetry/config.toml")),
                );
            for path in user {
                let Some(table) = parse_toml(&path) else {
                    continue;
                };
                if let Some(repos) = table.get("repositories").and_then(|r| r.as_table()) {
                    for url in repos.values().filter_map(|r| r.get("url")?.as_str()) {
                        found.push(redirect(format!("{}: repositories", path.display()), url));
                    }
                }
            }
        }
        _ => {
            let mut files: Vec<PathBuf> = vec![
                PathBuf::from("/etc/pip.conf"),
                PathBuf::from("/Library/Application Support/pip/pip.conf"),
            ];
            files.extend(s.config_home().map(|c| c.join("pip/pip.conf")));
            if let Some(home) = &s.home {
                files.push(home.join(".pip/pip.conf"));
                files.push(home.join("Library/Application Support/pip/pip.conf"));
            }
            files.extend(s.var("VIRTUAL_ENV").map(|v| Path::new(v).join("pip.conf")));
            files.extend(s.var("PIP_CONFIG_FILE").map(PathBuf::from));
            for path in files {
                found.extend(pip_conf_redirects(&path));
            }
        }
    }
    found
}

fn python_redirects(manager: &str, args: &[String], s: &Settings) -> Vec<Redirect> {
    let mut found = python_flag_redirects(args, manager != "poetry");
    let mut seen = HashSet::new();
    for file in requirements_files(args) {
        requirements_redirects(&file, &mut seen, 0, &mut found);
    }
    found.extend(python_env_redirects(manager, s));
    found.extend(python_file_redirects(manager, s));
    found
}

// ---------------------------------------------------------------- npm and pnpm

fn is_registry_key(key: &str) -> bool {
    key == "registry" || (key.starts_with('@') && key.ends_with(":registry"))
}

/// Replaces `${NAME}` with the variable's value; one that is not set stays as `${NAME}`.
fn expand_vars(value: &str, s: &Settings) -> String {
    let mut out = String::new();
    let mut rest = value;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        match rest[start..].find('}') {
            Some(len) => {
                let name = &rest[start + 2..start + len];
                match s.var(name) {
                    Some(v) => out.push_str(v),
                    None => out.push_str(&rest[start..=start + len]),
                }
                rest = &rest[start + len + 1..];
            }
            None => {
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

fn npmrc_redirects(path: &Path, s: &Settings) -> Vec<Redirect> {
    let Some(content) = read(path) else {
        return Vec::new();
    };
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with([';', '#']) {
                return None;
            }
            let (key, value) = line.split_once('=')?;
            let key = key.trim();
            let value = value.trim().trim_matches(['"', '\'']);
            is_registry_key(key)
                .then(|| redirect(format!("{}: {key}", path.display()), expand_vars(value, s)))
        })
        .collect()
}

fn manager_of(args: &[String]) -> &str {
    args.first().map(String::as_str).unwrap_or_default()
}

/// The `.npmrc` files of the project: npm reads the one in the nearest directory with a
/// `package.json` (the project root), which is not always the directory gyrseek runs in; pnpm
/// also reads the workspace root's, so it keeps going up to the directory with a
/// `pnpm-workspace.yaml`.
fn project_npmrcs(manager: &str, s: &Settings) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut root_found = false;
    for dir in s.cwd.ancestors() {
        files.push(dir.join(".npmrc"));
        let has = |name: &str| dir.join(name).exists();
        root_found |= has("package.json");
        let done = if manager == "pnpm" {
            has("pnpm-workspace.yaml")
        } else {
            root_found
        };
        if done {
            return files;
        }
    }
    // No project root above: only the current directory counts.
    files.truncate(1);
    files
}

fn node_redirects(args: &[String], s: &Settings) -> Vec<Redirect> {
    let mut found = Vec::new();
    let mut it = args.iter().skip(1);
    while let Some(arg) = it.next() {
        let Some(flag) = arg.strip_prefix("--") else {
            continue;
        };
        let (name, inline) = match flag.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (flag, None),
        };
        if is_registry_key(name)
            && let Some(value) = inline.or_else(|| it.next().cloned())
        {
            found.push(redirect(format!("--{name}"), value));
        }
    }
    for (key, value) in &s.vars {
        let lower = key.to_ascii_lowercase();
        if lower
            .strip_prefix("npm_config_")
            .is_some_and(is_registry_key)
            && !value.is_empty()
        {
            found.push(redirect(key.clone(), value.as_str()));
        }
    }
    let mut files = project_npmrcs(manager_of(args), s);
    let user = s
        .var("NPM_CONFIG_USERCONFIG")
        .or_else(|| s.var("npm_config_userconfig"))
        .map(PathBuf::from)
        .or_else(|| s.home.as_ref().map(|h| h.join(".npmrc")));
    files.extend(user);
    if manager_of(args) == "pnpm" {
        files.extend(s.config_home().map(|c| c.join("pnpm/rc")));
        files.extend(
            s.home
                .as_ref()
                .map(|h| h.join("Library/Preferences/pnpm/rc")),
        );
    }
    for path in files {
        found.extend(npmrc_redirects(&path, s));
    }
    found
}

// ---------------------------------------------------------------- the check

/// The message that refuses this command, if a setting sends it to a host that is neither the
/// public registry nor trusted. Only hosts are printed, never a whole URL.
pub(crate) fn refusal(
    manager: &str,
    args: &[String],
    settings: &Settings,
    trusted: &HashSet<String>,
) -> Option<String> {
    let (public, redirects) = match manager {
        "npm" | "pnpm" => (NPM_HOSTS, node_redirects(args, settings)),
        _ => (PYPI_HOSTS, python_redirects(manager, args, settings)),
    };
    let mut bad: Vec<String> = Vec::new();
    for r in &redirects {
        if let Some(host) = untrusted_host(&r.url, public, trusted, &settings.cwd) {
            let entry = format!("{} -> {host}", r.setting);
            if !bad.contains(&entry) {
                bad.push(entry);
            }
        }
    }
    if bad.is_empty() {
        return None;
    }
    let more = bad.len().saturating_sub(5);
    let shown = bad.iter().take(5).cloned().collect::<Vec<_>>().join("; ");
    Some(format!(
        "{shown}{} send this install to a registry that gyrseek did not scan: gyrseek scans the public registry package of the same name and version, so what would be installed could be a different package (dependency confusion). If the host is a mirror of the public registry that you trust, add it to `trusted_index_hosts` in gyrseek.yaml; otherwise remove the setting. Failing closed.",
        if more > 0 {
            format!(" and {more} more")
        } else {
            String::new()
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn settings(dir: &Path) -> Settings {
        Settings {
            vars: HashMap::new(),
            cwd: dir.join("project"),
            home: Some(dir.join("home")),
        }
    }

    fn setup() -> (tempfile::TempDir, Settings) {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("project")).unwrap();
        fs::create_dir_all(dir.path().join("home/.config")).unwrap();
        let s = settings(dir.path());
        (dir, s)
    }

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    fn check(manager: &str, a: &[&str], s: &Settings) -> Option<String> {
        refusal(manager, &args(a), s, &HashSet::new())
    }

    fn write(dir: &Path, rel: &str, content: &str) -> PathBuf {
        let path = dir.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn nothing_set_is_not_a_redirect() {
        let (_dir, s) = setup();
        for (m, a) in [
            ("pip", &["pip", "install", "six"][..]),
            ("uv", &["uv", "sync"]),
            ("poetry", &["poetry", "install"]),
            ("npm", &["npm", "ci"]),
            ("pnpm", &["pnpm", "install"]),
        ] {
            assert_eq!(check(m, a, &s), None, "{m}");
        }
    }

    #[test]
    fn python_flags_to_other_hosts_are_refused_and_public_or_local_ones_are_not() {
        let (_dir, s) = setup();
        for a in [
            &[
                "pip",
                "install",
                "six",
                "--index-url",
                "https://nexus.corp.example/simple",
            ][..],
            &[
                "pip",
                "install",
                "six",
                "--index-url=https://nexus.corp.example/simple",
            ],
            &[
                "pip",
                "install",
                "six",
                "-i",
                "https://nexus.corp.example/simple",
            ],
            &[
                "pip",
                "install",
                "six",
                "-ihttps://nexus.corp.example/simple",
            ],
            &[
                "pip",
                "install",
                "six",
                "--extra-index-url",
                "https://user:tok@nexus.corp.example/simple",
            ],
            &[
                "pip",
                "install",
                "six",
                "-f",
                "https://nexus.corp.example/wheels",
            ],
            &[
                "pip",
                "install",
                "six",
                "--find-links=https://nexus.corp.example/wheels",
            ],
            &[
                "uv",
                "pip",
                "install",
                "six",
                "--default-index",
                "https://nexus.corp.example/simple",
            ],
            &[
                "uv",
                "add",
                "six",
                "--index",
                "corp=https://nexus.corp.example/simple",
            ],
            &[
                "pip",
                "install",
                "six",
                "--index-url",
                "https://pypi.org.evil.example/simple",
            ],
            &[
                "pip",
                "install",
                "six",
                "--index-url",
                "https://pypi.org@evil.example/simple",
            ],
        ] {
            let manager = if a[0] == "uv" { "uv" } else { "pip" };
            let err = check(manager, a, &s).unwrap_or_else(|| panic!("{a:?}"));
            assert!(
                err.contains("trusted_index_hosts") && !err.contains("tok"),
                "{a:?}: {err}"
            );
        }
        for a in [
            &[
                "pip",
                "install",
                "six",
                "--index-url",
                "https://pypi.org/simple",
            ][..],
            &["pip", "install", "six", "-f", "./wheels"],
            &[
                "pip",
                "install",
                "six",
                "--find-links",
                "file:///srv/wheels",
            ],
            &["pip", "install", "six", "--no-index"],
        ] {
            assert_eq!(check("pip", a, &s), None, "{a:?}");
        }
        // Poetry has no `-i`: that is not a flag there.
        assert_eq!(
            check(
                "poetry",
                &["poetry", "add", "six", "-i", "https://x.example"],
                &s
            ),
            None
        );
    }

    #[test]
    fn a_trusted_host_is_let_through_and_the_message_names_the_setting_and_host_only() {
        let (_dir, s) = setup();
        let a = [
            "pip",
            "install",
            "six",
            "--index-url",
            "https://u:secret@Nexus.Corp.Example:8443/repo/simple?t=1",
        ];
        let err = check("pip", &a, &s).unwrap();
        assert!(
            err.contains("--index-url -> nexus.corp.example")
                && !err.contains("secret")
                && !err.contains("repo/simple"),
            "{err}"
        );
        let trusted: HashSet<String> =
            [normalize_trusted_host("https://Nexus.Corp.Example:8443/x")].into();
        assert_eq!(trusted, HashSet::from(["nexus.corp.example".to_string()]));
        assert_eq!(refusal("pip", &args(&a), &s, &trusted), None);
        assert_eq!(
            normalize_trusted_host(" nexus.corp.example:443 "),
            "nexus.corp.example"
        );
    }

    #[test]
    fn python_environment_variables_are_read_per_manager() {
        let (_dir, mut s) = setup();
        let evil = "https://nexus.corp.example/simple";
        for (manager, var) in [
            ("pip", "PIP_INDEX_URL"),
            ("pip3", "PIP_EXTRA_INDEX_URL"),
            ("pip", "PIP_FIND_LINKS"),
            ("uv", "UV_INDEX_URL"),
            ("uv", "UV_EXTRA_INDEX_URL"),
            ("uv", "UV_DEFAULT_INDEX"),
            ("uv", "UV_FIND_LINKS"),
            ("poetry", "POETRY_REPOSITORIES_CORP_URL"),
        ] {
            s.vars = HashMap::from([(var.to_string(), evil.to_string())]);
            let err = check(manager, &[manager, "install"], &s).unwrap_or_else(|| panic!("{var}"));
            assert!(err.contains(var), "{err}");
        }
        // UV_INDEX holds `name=url` pairs; a space-separated list is read word by word.
        s.vars = HashMap::from([(
            "UV_INDEX".to_string(),
            "a=https://pypi.org/simple corp=https://nexus.corp.example/simple".to_string(),
        )]);
        assert!(
            check("uv", &["uv", "sync"], &s)
                .unwrap()
                .contains("nexus.corp.example")
        );
        // The other manager's variables do not apply.
        s.vars = HashMap::from([("PIP_INDEX_URL".to_string(), evil.to_string())]);
        assert_eq!(check("uv", &["uv", "sync"], &s), None);
        s.vars = HashMap::from([(
            "PIP_INDEX_URL".to_string(),
            "https://pypi.org/simple".to_string(),
        )]);
        assert_eq!(check("pip", &["pip", "install", "six"], &s), None);
    }

    #[test]
    fn requirements_files_and_their_includes_are_searched_for_index_options() {
        let (dir, s) = setup();
        let top = write(&s.cwd, "top.txt", "six==1.16.0  # fine\n-r base.txt\n");
        write(
            &s.cwd,
            "base.txt",
            "--extra-index-url https://nexus.corp.example/simple\nattrs==24.2.0\n",
        );
        let top_s = top.to_string_lossy().to_string();
        let err = check("pip", &["pip", "install", "-r", &top_s], &s).unwrap();
        assert!(
            err.contains("base.txt: --extra-index-url -> nexus.corp.example"),
            "{err}"
        );
        assert!(check("pip", &["pip", "install", &format!("-r{top_s}")], &s).is_some());
        assert!(check("uv", &["uv", "pip", "install", "--requirement", &top_s], &s).is_some());
        // A clean file, a cycle and a missing file are fine.
        let clean = write(
            &s.cwd,
            "clean.txt",
            "-r clean.txt\nsix==1.16.0\n-i https://pypi.org/simple\n",
        );
        assert_eq!(
            check(
                "pip",
                &["pip", "install", "-r", &clean.to_string_lossy()],
                &s
            ),
            None
        );
        assert_eq!(
            check("pip", &["pip", "install", "-r", "missing.txt"], &s),
            None
        );
        // uv pip sync takes its files as positional arguments.
        assert!(check("uv", &["uv", "pip", "sync", &top_s], &s).is_some());
        drop(dir);
    }

    #[test]
    fn pip_conf_is_read_in_every_location_and_spelling() {
        let (dir, mut s) = setup();
        let evil = "https://nexus.corp.example/simple";
        for rel in [
            "home/.config/pip/pip.conf",
            "home/.pip/pip.conf",
            "home/Library/Application Support/pip/pip.conf",
        ] {
            let path = write(dir.path(), rel, &format!("[global]\nindex-url = {evil}\n"));
            let err =
                check("pip", &["pip", "install", "six"], &s).unwrap_or_else(|| panic!("{rel}"));
            assert!(
                err.contains("pip.conf: index-url -> nexus.corp.example"),
                "{err}"
            );
            fs::remove_file(path).unwrap();
        }
        for body in [
            format!("[install]\nextra-index-url={evil}\n"),
            format!("[global]\nextra_index_url: {evil}\n"),
            format!("[global]\nfind-links =\n    ./wheels\n    {evil}\n"),
            format!("[global]\nINDEX-URL = {evil}\n"),
        ] {
            let path = write(dir.path(), "home/.config/pip/pip.conf", &body);
            assert!(
                check("pip", &["pip", "install", "six"], &s).is_some(),
                "{body}"
            );
            fs::remove_file(path).unwrap();
        }
        // Other sections, comments, a public index and a missing file are not redirects.
        write(
            dir.path(),
            "home/.config/pip/pip.conf",
            &format!(
                "# index-url = {evil}\n[list]\nindex-url = {evil}\n[global]\nindex-url = https://pypi.org/simple\ntimeout = 5\n"
            ),
        );
        assert_eq!(check("pip", &["pip", "install", "six"], &s), None);
        // PIP_CONFIG_FILE and the virtualenv's pip.conf.
        let extra = write(
            dir.path(),
            "extra.conf",
            &format!("[global]\nindex-url = {evil}\n"),
        );
        s.vars = HashMap::from([(
            "PIP_CONFIG_FILE".to_string(),
            extra.to_string_lossy().to_string(),
        )]);
        assert!(check("pip", &["pip", "install", "six"], &s).is_some());
        let venv = dir.path().join("venv");
        write(
            &venv,
            "pip.conf",
            &format!("[global]\nindex-url = {evil}\n"),
        );
        s.vars = HashMap::from([(
            "VIRTUAL_ENV".to_string(),
            venv.to_string_lossy().to_string(),
        )]);
        assert!(check("pip", &["pip", "install", "six"], &s).is_some());
    }

    #[test]
    fn uv_and_poetry_project_and_user_settings_are_read() {
        let (dir, s) = setup();
        let evil = "https://nexus.corp.example/simple";
        for (rel, body) in [
            ("project/uv.toml", format!("index-url = \"{evil}\"\n")),
            (
                "project/uv.toml",
                format!("extra-index-url = [\"{evil}\"]\n"),
            ),
            (
                "project/uv.toml",
                format!("[[index]]\nname = \"corp\"\nurl = \"{evil}\"\n"),
            ),
            (
                "project/uv.toml",
                format!("[pip]\nindex-url = \"{evil}\"\n"),
            ),
            (
                "project/pyproject.toml",
                format!("[tool.uv]\nindex-url = \"{evil}\"\n"),
            ),
            (
                "project/pyproject.toml",
                format!("[[tool.uv.index]]\nurl = \"{evil}\"\n"),
            ),
            (
                "home/.config/uv/uv.toml",
                format!("index-url = \"{evil}\"\n"),
            ),
            (
                "pyproject.toml",
                format!("[tool.uv]\nfind-links = [\"{evil}\"]\n"),
            ), // a parent directory
        ] {
            let path = write(dir.path(), rel, &body);
            assert!(check("uv", &["uv", "sync"], &s).is_some(), "{rel}: {body}");
            fs::remove_file(path).unwrap();
        }
        write(
            dir.path(),
            "project/pyproject.toml",
            "[tool.uv]\nindex-url = \"https://pypi.org/simple\"\n[tool.other]\nindex-url = \"https://x.example\"\n",
        );
        assert_eq!(check("uv", &["uv", "sync"], &s), None);

        for (rel, body) in [
            (
                "project/pyproject.toml",
                format!(
                    "[[tool.poetry.source]]\nname = \"corp\"\nurl = \"{evil}\"\npriority = \"primary\"\n"
                ),
            ),
            (
                "home/.config/pypoetry/config.toml",
                format!("[repositories.corp]\nurl = \"{evil}\"\n"),
            ),
        ] {
            let path = write(dir.path(), rel, &body);
            let err =
                check("poetry", &["poetry", "install"], &s).unwrap_or_else(|| panic!("{rel}"));
            assert!(
                err.contains("nexus.corp.example") && !err.contains("/simple"),
                "{err}"
            );
            fs::remove_file(path).unwrap();
        }
        // uv settings do not affect poetry or the reverse.
        write(
            dir.path(),
            "project/uv.toml",
            &format!("index-url = \"{evil}\"\n"),
        );
        assert_eq!(check("poetry", &["poetry", "install"], &s), None);
    }

    #[test]
    fn npm_and_pnpm_registry_settings_are_read_from_flags_env_and_npmrc() {
        let (dir, mut s) = setup();
        let evil = "https://nexus.corp.example/npm/";
        for a in [
            &["npm", "ci", "--registry", evil][..],
            &["npm", "install", &format!("--registry={evil}")],
            &[
                "npm",
                "install",
                "left-pad@1.3.0",
                &format!("--@corp:registry={evil}"),
            ],
            &["pnpm", "add", "left-pad@1.3.0", "--registry", evil],
        ] {
            let err = check(a[0], a, &s).unwrap_or_else(|| panic!("{a:?}"));
            assert!(
                err.contains("nexus.corp.example") && !err.contains("/npm/"),
                "{a:?}: {err}"
            );
        }
        for var in [
            "npm_config_registry",
            "NPM_CONFIG_REGISTRY",
            "npm_config_@corp:registry",
        ] {
            s.vars = HashMap::from([(var.to_string(), evil.to_string())]);
            assert!(check("npm", &["npm", "ci"], &s).is_some(), "{var}");
        }
        s.vars = HashMap::new();
        for (rel, body) in [
            ("project/.npmrc", format!("registry={evil}\n")),
            (
                "project/.npmrc",
                format!("; comment\n@corp:registry = \"{evil}\"\n"),
            ),
            ("home/.npmrc", format!("registry={evil}\n")),
        ] {
            let path = write(dir.path(), rel, &body);
            let err = check("npm", &["npm", "ci"], &s).unwrap_or_else(|| panic!("{rel}"));
            assert!(
                err.contains(".npmrc") && err.contains("nexus.corp.example"),
                "{err}"
            );
            assert!(check("pnpm", &["pnpm", "install"], &s).is_some());
            fs::remove_file(path).unwrap();
        }
        // pnpm's own rc, NPM_CONFIG_USERCONFIG, variables, the public registry and other keys.
        write(
            dir.path(),
            "home/.config/pnpm/rc",
            &format!("registry={evil}\n"),
        );
        assert!(check("pnpm", &["pnpm", "install"], &s).is_some());
        assert_eq!(
            check("npm", &["npm", "ci"], &s),
            None,
            "npm does not read pnpm's rc"
        );
        let custom = write(dir.path(), "custom-npmrc", &format!("registry={evil}\n"));
        s.vars = HashMap::from([(
            "NPM_CONFIG_USERCONFIG".to_string(),
            custom.to_string_lossy().to_string(),
        )]);
        assert!(check("npm", &["npm", "ci"], &s).is_some());
        write(
            dir.path(),
            "project/.npmrc",
            "registry=${REG}\n//host/:_authToken=abc\nsave-exact=true\n",
        );
        s.vars = HashMap::from([("REG".to_string(), "https://registry.npmjs.org/".to_string())]);
        assert_eq!(check("npm", &["npm", "ci"], &s), None);
        s.vars = HashMap::new(); // not set: cannot be checked, so refused
        assert!(
            check("npm", &["npm", "ci"], &s)
                .unwrap()
                .contains("an unresolved variable")
        );
    }

    #[test]
    fn the_npmrc_of_the_project_root_is_read_from_a_subdirectory() {
        let (dir, mut s) = setup();
        let evil = "https://nexus.corp.example/npm/";
        // The project root is `project` (it has the package.json); gyrseek runs in `project/packages/app`.
        write(&s.cwd, "package.json", "{}");
        s.cwd = s.cwd.join("packages/app");
        fs::create_dir_all(&s.cwd).unwrap();
        write(dir.path(), "project/.npmrc", &format!("registry={evil}\n"));
        assert!(check("npm", &["npm", "ci"], &s).is_some());
        // A directory above the project root is not read by npm.
        fs::remove_file(dir.path().join("project/.npmrc")).unwrap();
        write(dir.path(), ".npmrc", &format!("registry={evil}\n"));
        assert_eq!(check("npm", &["npm", "ci"], &s), None);
        // The nearest package.json wins: a nested one hides the outer .npmrc.
        write(dir.path(), "project/.npmrc", &format!("registry={evil}\n"));
        write(&s.cwd, "package.json", "{}");
        assert_eq!(check("npm", &["npm", "ci"], &s), None);
        // pnpm also reads the workspace root's, found by pnpm-workspace.yaml.
        write(
            dir.path(),
            "project/pnpm-workspace.yaml",
            "packages: ['packages/*']\n",
        );
        assert!(check("pnpm", &["pnpm", "install"], &s).is_some());
        // With no project root above at all only the current directory counts.
        let lone = dir.path().join("lone");
        fs::create_dir_all(&lone).unwrap();
        write(dir.path(), ".npmrc", &format!("registry={evil}\n"));
        s.cwd = lone;
        assert_eq!(check("npm", &["npm", "ci"], &s), None);
    }

    #[test]
    fn hosts_are_read_from_ipv6_literals_and_scheme_less_values() {
        let (dir, s) = setup();
        // An IPv6 literal is one host, so trusting one does not trust them all.
        let a = [
            "pip",
            "install",
            "six",
            "--index-url",
            "http://[2001:db8::1]:8080/simple",
        ];
        assert!(check("pip", &a, &s).unwrap().contains("[2001:db8::1]"));
        let trusted: HashSet<String> = [normalize_trusted_host("[2001:db8::1]:8080")].into();
        assert_eq!(trusted, HashSet::from(["[2001:db8::1]".to_string()]));
        assert_eq!(refusal("pip", &args(&a), &s, &trusted), None);
        let other = [
            "pip",
            "install",
            "six",
            "--index-url",
            "http://[2001:db8::2]/simple",
        ];
        assert!(refusal("pip", &args(&other), &s, &trusted).is_some());
        // A scheme-less value that looks like host/path is a host; protocol-relative too.
        for value in ["nexus.corp.example/simple", "//nexus.corp.example/simple"] {
            let err = check("pip", &["pip", "install", "six", "--index-url", value], &s)
                .unwrap_or_else(|| panic!("{value}"));
            assert!(err.contains("nexus.corp.example"), "{err}");
        }
        write(&s.cwd, "wheels.d/keep", "");
        for local in [
            "wheels",
            "wheels.d",
            "./wheels",
            "../wheels",
            "/srv/wheels",
            "~/wheels",
            "pypi.org/simple",
        ] {
            assert_eq!(
                check("pip", &["pip", "install", "six", "-f", local], &s),
                None,
                "{local}"
            );
        }
        // A short intranet host name can be trusted (hosts are matched exactly, not by suffix).
        let trusted: HashSet<String> = [normalize_trusted_host("nexus")].into();
        let a = [
            "pip",
            "install",
            "six",
            "--index-url",
            "https://nexus/simple",
        ];
        assert!(check("pip", &a, &s).is_some());
        assert_eq!(refusal("pip", &args(&a), &s, &trusted), None);
        drop(dir);
    }

    #[test]
    fn many_redirects_are_summarised_and_repeats_are_listed_once() {
        let (_dir, s) = setup();
        let mut a = vec!["pip".to_string(), "install".to_string(), "six".to_string()];
        for i in 0..8 {
            a.push("--extra-index-url".to_string());
            a.push(format!("https://h{i}.example/simple"));
        }
        a.extend([
            "--extra-index-url".to_string(),
            "https://h0.example/simple".to_string(),
        ]);
        let err = refusal("pip", &a, &s, &HashSet::new()).unwrap();
        assert!(err.contains("and 3 more"), "{err}");
        assert_eq!(err.matches("h0.example").count(), 1, "{err}");
    }
}
