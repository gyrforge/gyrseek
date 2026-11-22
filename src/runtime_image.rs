//! Chooses the Python or Node image the Docker sandbox runs on, from the project's own
//! version files. Only digest-pinned images built into gyrseek can be selected, so a
//! project file never names an image.

use std::path::{Path, PathBuf};
use std::str::FromStr;

#[derive(Clone, Copy, PartialEq)]
enum Runtime {
    Python,
    Node,
}

/// Python versions the sandbox can run, keyed by minor version. 3.13 keeps the pin gyrseek
/// has always shipped as its default.
const PYTHON_IMAGES: &[(&str, &str)] = &[
    (
        "3.10",
        "python:3.10-slim-bookworm@sha256:5be5aaecb962a41567bc8041f1e9e3432cb085b037fe057f9a562630b2e4b370",
    ),
    (
        "3.11",
        "python:3.11-slim-bookworm@sha256:a83ba18aef0f865b1a4a611c2cf460fe446f2795673bbb9fe43be570439e3b39",
    ),
    (
        "3.12",
        "python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df",
    ),
    (
        "3.13",
        "python:3.13-slim-bookworm@sha256:a5a7017efc5969e00ae2b91c8eb0631049a569652aa4ffc4501769049ae45c72",
    ),
    (
        "3.14",
        "python:3.14-slim-bookworm@sha256:3fe1a0b6c2d6b2ebb572906cdabeca75aeb558c0c17db5ffefbcf8094871c32b",
    ),
];
const DEFAULT_PYTHON: &str = "3.13";

/// Node versions the sandbox can run, keyed by major version. 26 keeps the pin gyrseek has
/// always shipped as its default.
const NODE_IMAGES: &[(&str, &str)] = &[
    (
        "20",
        "node:20-bookworm-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0",
    ),
    (
        "22",
        "node:22-bookworm-slim@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee",
    ),
    (
        "24",
        "node:24-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54",
    ),
    (
        "26",
        "node:26.3-bookworm-slim@sha256:9898bb74f4ee319780e87819df703b3633113bc3422f151fd11155cf974a2749",
    ),
];
const DEFAULT_NODE: &str = "26";

/// The image a probe runs on, and a human-readable account of why.
#[derive(Clone, Debug)]
pub(crate) struct ImageChoice {
    pub image: String,
    pub description: String,
}

/// The image for `manager`: npm and pnpm get a Node image, everything else a Python image.
pub(crate) fn select_for_manager(
    manager: &str,
    python_config: Option<&str>,
    node_config: Option<&str>,
    start_dir: &Path,
) -> ImageChoice {
    if crate::sandbox::is_npm_family_manager(manager) {
        select_image(Runtime::Node, node_config, start_dir)
    } else {
        select_image(Runtime::Python, python_config, start_dir)
    }
}

impl Runtime {
    fn images(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Self::Python => PYTHON_IMAGES,
            Self::Node => NODE_IMAGES,
        }
    }

    fn default_key(self) -> &'static str {
        match self {
            Self::Python => DEFAULT_PYTHON,
            Self::Node => DEFAULT_NODE,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Python => "Python",
            Self::Node => "Node",
        }
    }

    fn image_for(self, key: &str) -> Option<&'static str> {
        self.images()
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, i)| *i)
    }

    fn supported(self) -> String {
        self.images()
            .iter()
            .map(|(k, _)| *k)
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// `3.11.4` / `cpython-3.11` -> `3.11`; `v22.1.0` / `22.x` -> `22`. Anything else is `None`.
    fn parse_key(self, raw: &str) -> Option<String> {
        let t = raw.trim();
        match self {
            Self::Python => {
                let t = ["cpython-", "cpython@", "python-", "python"]
                    .iter()
                    .find_map(|p| t.strip_prefix(p))
                    .unwrap_or(t);
                let (major, rest) = t.split_once('.')?;
                let minor: String = rest.chars().take_while(char::is_ascii_digit).collect();
                (major == "3" && !minor.is_empty()).then(|| format!("3.{minor}"))
            }
            Self::Node => {
                let t = t.strip_prefix('v').unwrap_or(t);
                let major: String = t.chars().take_while(char::is_ascii_digit).collect();
                let rest = &t[major.len()..];
                (!major.is_empty() && (rest.is_empty() || rest.starts_with('.'))).then_some(major)
            }
        }
    }

    /// Does the version range `spec` allow some version of this release line? Checked against
    /// a grid of minor and patch versions of the line. `None` when the range cannot be
    /// understood.
    fn range_allows(self, spec: &str, key: &str) -> Option<bool> {
        match self {
            Self::Python => python_range_allows(spec, key),
            Self::Node => node_range_allows(spec, key),
        }
    }
}

/// Numeric sort key: `3.10` -> [3, 10], `22` -> [22].
fn ordinal(key: &str) -> Vec<u32> {
    key.split('.').filter_map(|p| p.parse().ok()).collect()
}

/// Picks the supported version a range allows: the default if it fits, else the closest
/// one below it, else the closest above. The default is the best-tested choice, and
/// newer versions have fewer wheels for older releases.
fn pick_from_range(rt: Runtime, spec: &str) -> Result<Option<&'static str>, ()> {
    let mut allowed = Vec::new();
    for (key, _) in rt.images() {
        allowed.push((*key, rt.range_allows(spec, key).ok_or(())?));
    }
    let allowed: Vec<&str> = allowed
        .into_iter()
        .filter(|(_, ok)| *ok)
        .map(|(k, _)| k)
        .collect();
    let default = rt.default_key();
    if allowed.contains(&default) {
        return Ok(Some(default));
    }
    let below = allowed
        .iter()
        .filter(|k| ordinal(k) < ordinal(default))
        .max_by_key(|k| ordinal(k));
    let above = allowed
        .iter()
        .filter(|k| ordinal(k) > ordinal(default))
        .min_by_key(|k| ordinal(k));
    Ok(below.or(above).copied())
}

// ---- PEP 440 / Poetry ranges (Python) ----

/// Poetry (`^3.9`, `~3.10`, `3.11.*`, `3.11`) and PEP 440 constraints become one PEP 440 string
/// per `||` alternative.
fn poetry_group_to_pep440(group: &str) -> Option<String> {
    if group.trim() == "*" {
        return Some(">=0".to_string()); // any version
    }
    let mut g = group.trim().to_string();
    for op in [">=", "<=", "==", "!=", "~=", ">", "<", "^", "~"] {
        while g.contains(&format!("{op} ")) {
            g = g.replace(&format!("{op} "), op);
        }
    }
    let mut parts = Vec::new();
    for token in g
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|t| !t.is_empty())
    {
        let nums = |v: &str| -> Option<Vec<u64>> { v.split('.').map(|p| p.parse().ok()).collect() };
        if let Some(v) = token.strip_prefix('^') {
            let n = nums(v)?;
            let i = n.iter().position(|x| *x != 0).unwrap_or(n.len() - 1);
            let upper: Vec<String> = n[..i]
                .iter()
                .map(u64::to_string)
                .chain([(n[i] + 1).to_string()])
                .collect();
            parts.push(format!(">={v},<{}", upper.join(".")));
        } else if let Some(v) = token.strip_prefix('~').filter(|v| !v.starts_with('=')) {
            let n = nums(v)?;
            let upper = if n.len() == 1 {
                format!("{}", n[0] + 1)
            } else {
                format!("{}.{}", n[0], n[1] + 1)
            };
            parts.push(format!(">={v},<{upper}"));
        } else if token.chars().next()?.is_ascii_digit() {
            // A bare 3.11 means "any 3.11"; a full 3.11.4 is exact.
            let dots = token.matches('.').count();
            if token.contains('*') || dots >= 2 {
                parts.push(format!("=={token}"));
            } else {
                parts.push(format!("=={token}.*"));
            }
        } else {
            parts.push(token.to_string());
        }
    }
    (!parts.is_empty()).then(|| parts.join(","))
}

/// A Poetry or PEP 440 constraint as one specifier set per `||` alternative.
fn python_specifier_sets(spec: &str) -> Option<Vec<pep440_rs::VersionSpecifiers>> {
    spec.split("||")
        .map(|group| pep440_rs::VersionSpecifiers::from_str(&poetry_group_to_pep440(group)?).ok())
        .collect()
}

/// Does the Poetry/PEP 440 constraint `spec` allow this exact version? `None` when either
/// cannot be understood.
pub(crate) fn python_range_contains(spec: &str, version: &str) -> Option<bool> {
    let version = pep440_rs::Version::from_str(version).ok()?;
    Some(
        python_specifier_sets(spec)?
            .iter()
            .any(|set| set.contains(&version)),
    )
}

fn python_range_allows(spec: &str, key: &str) -> Option<bool> {
    let (_, minor) = key.split_once('.')?;
    // Patch releases of one minor line run 0..~20; sample them all.
    let reps: Vec<pep440_rs::Version> = (0..=30)
        .map(|p| pep440_rs::Version::from_str(&format!("3.{minor}.{p}")).ok())
        .collect::<Option<_>>()?;
    Some(
        python_specifier_sets(spec)?
            .iter()
            .any(|set| reps.iter().any(|v| set.contains(v))),
    )
}

// ---- npm semver ranges (Node) ----

/// npm allows a leading `v` on a version (`v22`, `>=v1.2.3`, `^v4`). Only that `v` is removed:
/// a lone `v` is a dist-tag, and a `v` inside a prerelease name (`1.0.0-dev.1`) is part of it.
fn strip_version_v(token: &str) -> String {
    let split = token
        .find(|c: char| !matches!(c, '<' | '>' | '=' | '^' | '~'))
        .unwrap_or(token.len());
    let (operator, rest) = token.split_at(split);
    match rest.strip_prefix(['v', 'V']) {
        Some(version) if version.starts_with(|c: char| c.is_ascii_digit()) => {
            format!("{operator}{version}")
        }
        _ => token.to_string(),
    }
}

/// npm reads a bare `4` or `4.17` as `4.*` / `4.17.*` and a bare `4.17.21` as exactly that
/// version, while the `semver` crate would read all of them as a caret range.
fn npm_bare_version(token: &str) -> String {
    if !token.starts_with(|c: char| c.is_ascii_digit()) {
        return token.to_string();
    }
    match token.matches('.').count() {
        0 | 1 if !token.contains(['x', 'X', '*']) => format!("{token}.*"),
        2 if semver::Version::parse(token).is_ok() => format!("={token}"),
        _ => token.to_string(),
    }
}

/// An npm semver range as one requirement per `||` alternative. Hyphen ranges are not
/// supported.
fn npm_requirement_sets(spec: &str) -> Option<Vec<semver::VersionReq>> {
    spec.split("||")
        .map(|group| {
            let mut g = group.trim().to_string();
            if g.contains(" - ") {
                return None;
            }
            for op in [">=", "<=", ">", "<", "=", "^", "~"] {
                while g.contains(&format!("{op} ")) {
                    g = g.replace(&format!("{op} "), op);
                }
            }
            let comparators: Vec<String> = g
                .split(|c: char| c == ',' || c.is_whitespace())
                .filter(|t| !t.is_empty())
                .map(|t| npm_bare_version(&strip_version_v(t)))
                .collect();
            semver::VersionReq::parse(&if comparators.is_empty() {
                "*".to_string()
            } else {
                comparators.join(", ")
            })
            .ok()
        })
        .collect()
}

/// Does the npm range `spec` allow this exact version? `None` when either cannot be
/// understood (a dist-tag such as `next` is not a range).
pub(crate) fn npm_range_contains(spec: &str, version: &str) -> Option<bool> {
    let version = semver::Version::parse(version).ok()?;
    Some(
        npm_requirement_sets(spec)?
            .iter()
            .any(|r| r.matches(&version)),
    )
}

fn node_range_allows(spec: &str, key: &str) -> Option<bool> {
    let major: u64 = key.parse().ok()?;
    // A major line has minors up to ~30 and patches up to ~20; sample a grid of both.
    let reps: Vec<semver::Version> = (0..=60)
        .flat_map(|minor| {
            (0..=10)
                .chain([99])
                .map(move |patch| semver::Version::new(major, minor, patch))
        })
        .collect();
    Some(
        npm_requirement_sets(spec)?
            .iter()
            .any(|req| reps.iter().any(|v| req.matches(v))),
    )
}

// ---- project files ----

/// The first usable line of a version file such as `.python-version` or `.nvmrc`.
fn first_value_line(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()?
        .trim_start_matches('\u{feff}') // a BOM from a Windows editor
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
}

/// A quoted string value, ignoring a trailing comment.
fn quoted_value(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let quote = raw.chars().next().filter(|c| *c == '"' || *c == '\'')?;
    let rest = &raw[1..];
    rest.find(quote).map(|end| rest[..end].to_string())
}

/// `requires-python` from `[project]`, else Poetry's `python` from
/// `[tool.poetry.dependencies]`. A line scanner is enough for these two single-line keys.
fn pyproject_python_spec(content: &str) -> Option<String> {
    let (mut table, mut project, mut poetry) = ("", None, None);
    for line in content
        .trim_start_matches('\u{feff}')
        .lines()
        .map(str::trim)
    {
        if line.starts_with('[') {
            table = line.trim_matches(|c| c == '[' || c == ']').trim();
        } else if let Some((key, value)) = line.split_once('=') {
            match (table, key.trim()) {
                ("project", "requires-python") => project = quoted_value(value),
                ("tool.poetry.dependencies", "python") => poetry = quoted_value(value),
                _ => {}
            }
        }
    }
    project.or(poetry)
}

fn package_json_node_spec(content: &str) -> Option<String> {
    let json: serde_json::Value =
        serde_json::from_str(content.trim_start_matches('\u{feff}')).ok()?;
    json.get("engines")?
        .get("node")?
        .as_str()
        .map(str::to_string)
}

enum Source {
    /// A file naming one version (`.python-version`, `.nvmrc`).
    Exact(String),
    /// A range (`requires-python`, `engines.node`).
    Range(String),
}

/// The nearest directory (searching upwards, like uv) that has a usable version file.
fn find_source(rt: Runtime, start: &Path) -> Option<(PathBuf, Source)> {
    start.ancestors().find_map(|dir| match rt {
        Runtime::Python => {
            let file = dir.join(".python-version");
            if let Some(v) = first_value_line(&file) {
                return Some((file, Source::Exact(v)));
            }
            let file = dir.join("pyproject.toml");
            let spec = pyproject_python_spec(&std::fs::read_to_string(&file).ok()?)?;
            Some((file, Source::Range(spec)))
        }
        Runtime::Node => {
            for name in [".nvmrc", ".node-version"] {
                let file = dir.join(name);
                if let Some(v) = first_value_line(&file) {
                    return Some((file, Source::Exact(v)));
                }
            }
            let file = dir.join("package.json");
            let spec = package_json_node_spec(&std::fs::read_to_string(&file).ok()?)?;
            Some((file, Source::Range(spec)))
        }
    })
}

fn choice(rt: Runtime, key: &str, source: &str) -> ImageChoice {
    ImageChoice {
        image: rt
            .image_for(key)
            .unwrap_or_else(|| unreachable!("{key} is not in the {} table", rt.label()))
            .to_string(),
        description: format!("{} {key} ({source})", rt.label()),
    }
}

/// The config value (`python_version` / `node_version`) if set, else the nearest project
/// file, else the default. An unusable project file falls back to the default with a
/// message rather than stopping the scan.
fn select_image(rt: Runtime, configured: Option<&str>, start_dir: &Path) -> ImageChoice {
    if let Some(key) = configured.filter(|k| rt.image_for(k).is_some()) {
        return choice(rt, key, "from the gyrseek config");
    }
    let mut reason = "default; no version file found";
    if let Some((path, source)) = find_source(rt, start_dir) {
        reason = "default; the project's version is not supported";
        let shown = path.display();
        match source {
            Source::Exact(raw) => match rt.parse_key(&raw).filter(|k| rt.image_for(k).is_some()) {
                Some(key) => return choice(rt, &key, &format!("from {shown}")),
                None => eprintln!(
                    "⚠️ [gyrseek] Ignoring '{raw}' in {shown}: not a supported {} version (supported: {}). Using {} {}.",
                    rt.label(),
                    rt.supported(),
                    rt.label(),
                    rt.default_key()
                ),
            },
            Source::Range(spec) => match pick_from_range(rt, &spec) {
                Ok(Some(key)) => {
                    return choice(rt, key, &format!("from {shown}, which allows '{spec}'"));
                }
                Ok(None) => eprintln!(
                    "⚠️ [gyrseek] '{spec}' in {shown} allows none of the supported {} versions ({}). Using {} {}.",
                    rt.label(),
                    rt.supported(),
                    rt.label(),
                    rt.default_key()
                ),
                Err(()) => eprintln!(
                    "⚠️ [gyrseek] Could not understand the {} version range '{spec}' in {shown}. Using {} {}.",
                    rt.label(),
                    rt.label(),
                    rt.default_key()
                ),
            },
        }
    }
    choice(rt, rt.default_key(), reason)
}

/// Validates the `python_version` config value, returning the normalised key (`3.11`).
pub(crate) fn normalize_python_config(raw: &str) -> Result<String, String> {
    normalize_config(Runtime::Python, raw)
}

/// Validates the `node_version` config value, returning the normalised key (`22`).
pub(crate) fn normalize_node_config(raw: &str) -> Result<String, String> {
    normalize_config(Runtime::Node, raw)
}

fn normalize_config(rt: Runtime, raw: &str) -> Result<String, String> {
    rt.parse_key(raw)
        .filter(|k| rt.image_for(k).is_some())
        .ok_or_else(|| {
            format!(
                "'{raw}' is not a supported {} version (supported: {})",
                rt.label(),
                rt.supported()
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir_with(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("temp dir");
        for (name, content) in files {
            std::fs::write(dir.path().join(name), content).unwrap();
        }
        dir
    }

    fn py(dir: &Path, configured: Option<&str>) -> ImageChoice {
        select_image(Runtime::Python, configured, dir)
    }

    fn node(dir: &Path, configured: Option<&str>) -> ImageChoice {
        select_image(Runtime::Node, configured, dir)
    }

    #[test]
    fn tables_are_digest_pinned_and_contain_their_defaults() {
        for (key, image) in PYTHON_IMAGES {
            assert!(
                image.starts_with(&format!("python:{key}-slim-bookworm@sha256:")),
                "{image}"
            );
        }
        for (key, image) in NODE_IMAGES {
            assert!(image.contains("-bookworm-slim@sha256:"), "{key}: {image}");
            assert!(image.starts_with(&format!("node:{key}")), "{key}: {image}");
        }
        assert!(Runtime::Python.image_for(DEFAULT_PYTHON).is_some());
        assert!(Runtime::Node.image_for(DEFAULT_NODE).is_some());
    }

    #[test]
    fn parse_python_minor_accepts_common_python_version_file_forms() {
        for ok in [
            "3.11",
            "3.11.4",
            "3.11.4rc1",
            "cpython-3.11.4",
            "python3.11",
            " 3.11 ",
        ] {
            assert_eq!(
                Runtime::Python.parse_key(ok).as_deref(),
                Some("3.11"),
                "{ok}"
            );
        }
        assert_eq!(Runtime::Python.parse_key("3.10").as_deref(), Some("3.10"));
        for bad in ["3", "system", "pypy3.10", "2.7", "3.x", ""] {
            assert!(Runtime::Python.parse_key(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn parse_node_major_accepts_nvmrc_forms_and_rejects_aliases() {
        for ok in ["22", "v22", "v22.1.0", "22.x", " 22 "] {
            assert_eq!(Runtime::Node.parse_key(ok).as_deref(), Some("22"), "{ok}");
        }
        for bad in [
            "lts/*", "lts/iron", "node", "latest", "stable", ">=18", "", "v",
        ] {
            assert!(Runtime::Node.parse_key(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn python_version_file_picks_the_image_and_walks_up_to_parents() {
        let root = dir_with(&[(".python-version", "# pinned\n3.11.4\n3.12\n")]);
        let nested = root.path().join("a/b");
        std::fs::create_dir_all(&nested).unwrap();
        let c = py(&nested, None);
        assert!(c.image.starts_with("python:3.11-slim-bookworm@sha256:"));
        assert!(c.description.starts_with("Python 3.11 (from "));
        assert!(c.description.contains(".python-version"));
    }

    #[test]
    fn config_value_wins_over_project_files() {
        let root = dir_with(&[(".python-version", "3.11\n"), (".nvmrc", "22\n")]);
        let c = py(root.path(), Some("3.12"));
        assert!(c.image.starts_with("python:3.12-slim-bookworm@sha256:"));
        assert!(c.description.contains("config"));
        assert!(node(root.path(), Some("20")).image.starts_with("node:20-"));
    }

    #[test]
    fn unusable_version_file_falls_back_to_the_default_and_says_why() {
        let root = dir_with(&[]);
        for (content, expected) in [
            ("pypy3.10\n", "not supported"),
            ("3.8\n", "not supported"),
            ("3.99\n", "not supported"),
            ("\n# only a comment\n", "no version file found"),
        ] {
            std::fs::write(root.path().join(".python-version"), content).unwrap();
            let c = py(root.path(), None);
            assert!(
                c.image.starts_with("python:3.13-slim-bookworm@sha256:"),
                "{content:?}"
            );
            assert!(
                c.description.contains(expected),
                "{content:?}: {}",
                c.description
            );
        }
    }

    #[test]
    fn no_version_file_uses_the_default() {
        let root = dir_with(&[]);
        assert!(
            py(root.path(), None)
                .description
                .contains("no version file found")
        );
        assert!(node(root.path(), None).image.starts_with("node:26.3-"));
    }

    #[test]
    fn pyproject_requires_python_ranges_pick_the_default_or_the_closest_version() {
        let cases = [
            (">=3.9", "3.13"),
            (">=3.9,<3.13", "3.12"),
            (">=3.9, <3.12", "3.11"),
            ("~=3.10", "3.13"),
            ("==3.11.*", "3.11"),
            (">=3.14", "3.14"),
            ("<3.11", "3.10"),
            (">=3.11.2,<3.11.4", "3.11"),
            (">=3.8,<3.11", "3.10"),
        ];
        for (spec, expected) in cases {
            let root = dir_with(&[(
                "pyproject.toml",
                &format!("[project]\nname = \"x\"\nrequires-python = \"{spec}\"\n"),
            )]);
            let c = py(root.path(), None);
            assert!(
                c.description
                    .starts_with(&format!("Python {expected} (from ")),
                "{spec}: {}",
                c.description
            );
        }
    }

    #[test]
    fn poetry_constraints_are_understood() {
        let cases = [
            ("^3.9", "3.13"),
            ("^3.9 || ^3.10", "3.13"),
            ("~3.11", "3.11"),
            ("~3.10.2", "3.10"),
            ("3.12.*", "3.12"),
            ("3.11", "3.11"),
            (">=3.9 <3.13", "3.12"),
            (">= 3.9, < 3.12", "3.11"),
            ("^3.14", "3.14"),
        ];
        for (spec, expected) in cases {
            let root = dir_with(&[(
                "pyproject.toml",
                &format!("[tool.poetry.dependencies]\npython = \"{spec}\"\nrequests = \"^2\"\n"),
            )]);
            let c = py(root.path(), None);
            assert!(
                c.description
                    .starts_with(&format!("Python {expected} (from ")),
                "{spec}: {}",
                c.description
            );
        }
    }

    #[test]
    fn python_version_file_wins_over_pyproject_in_the_same_directory() {
        let root = dir_with(&[
            (".python-version", "3.11\n"),
            (
                "pyproject.toml",
                "[project]\nrequires-python = \">=3.12\"\n",
            ),
        ]);
        assert!(py(root.path(), None).image.starts_with("python:3.11-"));
    }

    #[test]
    fn project_requires_python_wins_over_poetry_and_other_tables_are_ignored() {
        let root = dir_with(&[(
            "pyproject.toml",
            "[tool.other]\nrequires-python = \">=3.14\"\n[tool.poetry.dependencies]\npython = \"^3.14\"\n[project]\nrequires-python = \"<3.12\" # old\n",
        )]);
        assert!(
            py(root.path(), None)
                .description
                .starts_with("Python 3.11 (from ")
        );
    }

    #[test]
    fn unsatisfiable_or_unreadable_ranges_fall_back_with_a_warning() {
        for spec in ["<3.9", ">=4", "banana", "^"] {
            let root = dir_with(&[(
                "pyproject.toml",
                &format!("[project]\nrequires-python = \"{spec}\"\n"),
            )]);
            let c = py(root.path(), None);
            assert!(c.image.starts_with("python:3.13-"), "{spec}");
            assert!(
                c.description.contains("not supported"),
                "{spec}: {}",
                c.description
            );
        }
    }

    #[test]
    fn pyproject_without_a_python_constraint_keeps_looking_upwards() {
        let root = dir_with(&[(".python-version", "3.12\n")]);
        let nested = root.path().join("sub");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("pyproject.toml"), "[project]\nname = \"x\"\n").unwrap();
        assert!(py(&nested, None).image.starts_with("python:3.12-"));
    }

    #[test]
    fn nvmrc_and_node_version_files_pick_the_node_image() {
        let root = dir_with(&[(".nvmrc", "v22.1.0\n")]);
        let c = node(root.path(), None);
        assert!(c.image.starts_with("node:22-bookworm-slim@sha256:"));
        assert!(c.description.starts_with("Node 22 (from "));
        let root = dir_with(&[(".node-version", "20\n")]);
        assert!(node(root.path(), None).image.starts_with("node:20-"));
        let root = dir_with(&[(".nvmrc", "lts/*\n")]);
        let c = node(root.path(), None);
        assert!(c.image.starts_with("node:26.3-"));
        assert!(c.description.contains("not supported"));
    }

    #[test]
    fn engines_node_ranges_pick_the_default_or_the_closest_version() {
        let cases = [
            (">=18", "26"),
            (">=18 <23", "22"),
            ("^20.9.0 || ^22", "22"),
            ("20.x", "20"),
            ("^22", "22"),
            ("~24.1", "24"),
            (">= 20, < 25", "24"),
            ("*", "26"),
            ("<=20", "20"),
        ];
        for (spec, expected) in cases {
            let root = dir_with(&[(
                "package.json",
                &format!("{{\"name\":\"x\",\"engines\":{{\"node\":\"{spec}\"}}}}"),
            )]);
            let c = node(root.path(), None);
            assert!(
                c.description
                    .starts_with(&format!("Node {expected} (from ")),
                "{spec}: {}",
                c.description
            );
        }
    }

    #[test]
    fn unusable_engines_ranges_fall_back_to_the_default() {
        for spec in ["16 - 18", "<18", "banana"] {
            let root = dir_with(&[(
                "package.json",
                &format!("{{\"engines\":{{\"node\":\"{spec}\"}}}}"),
            )]);
            let c = node(root.path(), None);
            assert!(c.image.starts_with("node:26.3-"), "{spec}");
            assert!(
                c.description.contains("not supported"),
                "{spec}: {}",
                c.description
            );
        }
        let root = dir_with(&[("package.json", "{\"name\":\"x\"}")]);
        assert!(
            node(root.path(), None)
                .description
                .contains("no version file found")
        );
    }

    // ---- edge cases -----------------------------------------------------------------

    #[test]
    fn version_files_tolerate_windows_editors() {
        // BOM and CRLF line endings are common when the file was saved on Windows.
        for (name, content, expect_py) in [
            (".python-version", "\u{feff}3.11\r\n", true),
            (".python-version", "3.11\r\n3.12\r\n", true),
            (".nvmrc", "\u{feff}v22.1.0\r\n", false),
            (".node-version", "20\r\n", false),
        ] {
            let root = dir_with(&[(name, content)]);
            let image = if expect_py {
                py(root.path(), None).image
            } else {
                node(root.path(), None).image
            };
            let wanted = match (name, content.contains("22")) {
                (".python-version", _) => "python:3.11-",
                (".nvmrc", _) => "node:22-",
                _ => "node:20-",
            };
            assert!(image.starts_with(wanted), "{name} {content:?} -> {image}");
        }
    }

    #[test]
    fn an_empty_blank_or_unreadable_version_file_is_skipped_not_fatal() {
        // Empty file, whitespace only, and a directory named like the file all fall through to
        // the next source in the same directory.
        for content in ["", "   \n\t\n"] {
            let root = dir_with(&[
                (".python-version", content),
                ("pyproject.toml", "[project]\nrequires-python = \"<3.12\"\n"),
            ]);
            assert!(
                py(root.path(), None).image.starts_with("python:3.11-"),
                "{content:?}"
            );
        }
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join(".python-version")).unwrap();
        std::fs::write(
            root.path().join("pyproject.toml"),
            "[project]\nrequires-python = \"<3.12\"\n",
        )
        .unwrap();
        assert!(py(root.path(), None).image.starts_with("python:3.11-"));
    }

    #[test]
    fn the_nearest_directory_wins_even_when_a_parent_disagrees() {
        let root = dir_with(&[(".python-version", "3.10\n")]);
        let child = root.path().join("app");
        std::fs::create_dir_all(&child).unwrap();
        std::fs::write(child.join(".python-version"), "3.14\n").unwrap();
        assert!(py(&child, None).image.starts_with("python:3.14-"));
        assert!(py(root.path(), None).image.starts_with("python:3.10-"));
    }

    #[test]
    fn pyproject_reading_ignores_other_tables_and_tolerates_odd_formatting() {
        let cases = [
            // single quotes, no spaces around `=`, trailing comment
            ("[project]\nrequires-python='<3.12' # old\n", "3.11"),
            // the key under an unrelated table is not the project's
            ("[project.urls]\nrequires-python = \"<3.12\"\n", "3.13"),
            ("[[tool.something]]\nrequires-python = \"<3.12\"\n", "3.13"),
            // unterminated quote and a non-string value are ignored
            ("[project]\nrequires-python = \"<3.12\n", "3.13"),
            ("[project]\nrequires-python = 3.11\n", "3.13"),
            // an empty file or a file with no python constraint
            ("", "3.13"),
            ("[project]\nname = \"x\"\n", "3.13"),
        ];
        for (content, expected) in cases {
            let root = dir_with(&[("pyproject.toml", content)]);
            let c = py(root.path(), None);
            assert!(
                c.image.starts_with(&format!("python:{expected}-")),
                "{content:?} -> {}",
                c.description
            );
        }
    }

    #[test]
    fn poetry_constraints_edge_forms() {
        let allows = |spec: &str, key: &str| python_range_allows(spec, key);
        // `*` means any version.
        assert_eq!(allows("*", "3.12"), Some(true));
        // Caret and tilde on short and zero-leading versions.
        assert_eq!(poetry_group_to_pep440("^3").as_deref(), Some(">=3,<4"));
        assert_eq!(
            poetry_group_to_pep440("^0.2.3").as_deref(),
            Some(">=0.2.3,<0.3")
        );
        assert_eq!(
            poetry_group_to_pep440("^0.0.3").as_deref(),
            Some(">=0.0.3,<0.0.4")
        );
        assert_eq!(poetry_group_to_pep440("~3").as_deref(), Some(">=3,<4"));
        assert_eq!(
            poetry_group_to_pep440("~3.9.1").as_deref(),
            Some(">=3.9.1,<3.10")
        );
        // Space-separated, mixed separators and operator spacing.
        assert_eq!(
            poetry_group_to_pep440(">= 3.9 , < 3.13").as_deref(),
            Some(">=3.9,<3.13")
        );
        // Alternatives, with one side excluding the line.
        assert_eq!(allows("^3.9 || ^2.7", "3.12"), Some(true));
        assert_eq!(allows("~3.10 || ~3.12", "3.11"), Some(false));
        assert_eq!(allows("~3.10 || ~3.12", "3.12"), Some(true));
        // Exclusion of one patch line leaves the minor allowed.
        assert_eq!(allows(">=3.9,!=3.11.4", "3.11"), Some(true));
        assert_eq!(allows("!=3.11.*", "3.11"), Some(false));
        // Garbage never panics and is "not understood".
        for bad in [
            "", "   ", "||", "^3.9 ||", "^", "~", "^x.y", ">>3", "3.9.", "😀",
        ] {
            assert_eq!(allows(bad, "3.12"), None, "{bad:?}");
        }
    }

    #[test]
    fn node_ranges_edge_forms() {
        let allows = |spec: &str, key: &str| node_range_allows(spec, key);
        assert_eq!(allows("*", "22"), Some(true));
        assert_eq!(
            allows("", "22"),
            Some(true),
            "an empty engines.node means any version"
        );
        assert_eq!(allows(">=18.0.0 <20.0.0", "20"), Some(false));
        assert_eq!(
            allows(">=18.0.0 <20.0.0", "20.0.0".split('.').next().unwrap()),
            Some(false)
        );
        assert_eq!(allows("18.x.x || 20.x", "20"), Some(true));
        assert_eq!(allows("v22", "22"), Some(true));
        assert_eq!(allows(" ^22 ", "22"), Some(true));
        assert_eq!(allows("^18 || >=20.5.0", "22"), Some(true));
        assert_eq!(allows("=22.0.0", "22"), Some(true));
        assert_eq!(
            allows("16 - 18", "22"),
            None,
            "hyphen ranges are not supported"
        );
        // An empty alternative is `*` in npm, so it allows everything.
        assert_eq!(allows("||x", "22"), Some(true));
        for bad in ["lts/*", "latest", "banana", "^", ">=", "😀"] {
            assert_eq!(allows(bad, "22"), None, "{bad:?}");
        }
    }

    #[test]
    fn engines_node_of_the_wrong_json_shape_is_ignored() {
        for content in [
            "not json",
            "[]",
            "{}",
            r#"{"engines":[]}"#,
            r#"{"engines":{"node":22}}"#,
            r#"{"engines":{"node":null}}"#,
            r#"{"engines":"node"}"#,
        ] {
            let root = dir_with(&[("package.json", content)]);
            let c = node(root.path(), None);
            assert!(
                c.image.starts_with("node:26.3-"),
                "{content}: {}",
                c.description
            );
            assert!(c.description.contains("no version file found"), "{content}");
        }
    }

    #[test]
    fn the_default_is_kept_whenever_a_range_allows_it_and_otherwise_the_closest() {
        // The default wins even when other versions fit.
        assert_eq!(pick_from_range(Runtime::Python, ">=3.10"), Ok(Some("3.13")));
        // Below the default beats above it, and the highest below is chosen.
        assert_eq!(pick_from_range(Runtime::Python, "<3.13"), Ok(Some("3.12")));
        // Only versions above the default fit: the lowest of them.
        assert_eq!(pick_from_range(Runtime::Python, ">=3.14"), Ok(Some("3.14")));
        assert_eq!(pick_from_range(Runtime::Node, ">=27"), Ok(None));
        // Unsupported-only ranges and unparseable ranges are told apart.
        assert_eq!(pick_from_range(Runtime::Python, "<3.9"), Ok(None));
        assert_eq!(pick_from_range(Runtime::Python, "banana"), Err(()));
    }

    #[test]
    fn a_v_inside_a_prerelease_name_is_kept_and_only_a_leading_v_is_removed() {
        for (token, expected) in [
            ("v22", "22"),
            ("V22", "22"),
            (">=v1.2.3", ">=1.2.3"),
            ("^v4", "^4"),
            ("<=v2", "<=2"),
            ("v", "v"),
            ("dev", "dev"),
            ("vnext", "vnext"),
            ("1.0.0-dev.1", "1.0.0-dev.1"),
            (">=1.0.0-dev.1", ">=1.0.0-dev.1"),
            ("^1.0.0-vv.1", "^1.0.0-vv.1"),
            ("", ""),
        ] {
            assert_eq!(strip_version_v(token), expected, "{token:?}");
        }
        // The prerelease name survives into the requirement, so the comparison is honest.
        assert_eq!(
            npm_range_contains(">=1.0.0-dev.1", "1.0.0-dev.2"),
            Some(true)
        );
        assert_eq!(
            npm_range_contains(">=1.0.0-dev.1", "1.0.0-de.9"),
            Some(false)
        );
        // A lone `v` is not a range at all.
        assert_eq!(npm_range_contains("v", "1.0.0"), None);
        assert_eq!(npm_range_contains("v22", "22.1.0"), Some(true));
        assert_eq!(npm_range_contains(">=v18 <v23", "22.1.0"), Some(true));
    }

    #[test]
    fn the_manager_decides_which_runtime_is_selected() {
        let root = dir_with(&[(".python-version", "3.11\n"), (".nvmrc", "22\n")]);
        let npm = select_for_manager("pnpm", None, None, root.path());
        assert!(npm.image.starts_with("node:22-"));
        let pip = select_for_manager("poetry", None, None, root.path());
        assert!(pip.image.starts_with("python:3.11-"));
        let cfg = select_for_manager("npm", Some("3.12"), Some("20"), root.path());
        assert!(cfg.image.starts_with("node:20-"));
    }

    #[test]
    fn config_values_are_normalised_and_validated() {
        assert_eq!(normalize_python_config("3.12.4").unwrap(), "3.12");
        assert_eq!(normalize_python_config("3.10").unwrap(), "3.10");
        assert_eq!(normalize_node_config("v22.1.0").unwrap(), "22");
        for bad in ["3.8", "pypy3.10", "banana"] {
            let err = normalize_python_config(bad).unwrap_err();
            assert!(err.contains("not a supported Python version"), "{err}");
        }
        assert!(
            normalize_node_config("16")
                .unwrap_err()
                .contains("20, 22, 24, 26")
        );
    }
}
