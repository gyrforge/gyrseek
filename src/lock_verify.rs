//! Checks that the artifacts a lockfile pins are files the public registry publishes for that
//! release (FIXED #447, #452). The probe installs `name==version` from the public registry and
//! scans what it gets; a lockfile hash that is not one of the public hashes for that version
//! means the install would fetch something the scan never saw (another file of the release, or
//! whatever a trusted mirror serves). Package managers enforce lockfile hashes, so a locked hash
//! that equals a public hash pins the install to a public file whichever host serves it.

use std::collections::{BTreeSet, HashMap, HashSet};

use crate::parsing::{
    pnpm_key_without_peers, pnpm_package_key, pylock_version, strip_pep508_extras,
};
use crate::sandbox::base64_decode;

type Key = (String, String);
/// One locked Python file: is it a wheel, and its hashes.
type PyFile = (bool, Vec<String>);

/// What a lockfile pins for one package version.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct Locked {
    /// `sha256:<hex>`, `sha512-<base64>` or `sha1-<base64>`: the form the lockfile uses.
    pub hashes: BTreeSet<String>,
    pub wheel: bool,
    pub sdist: bool,
    /// Some occurrence or file of this version records no hash, whatever the others carry.
    pub unhashed: bool,
    /// A requirements file may leave out `--hash`: that only matters when a trusted mirror may
    /// serve other files, so no hash is refused only then (WONT_FIX #448 for the public registry).
    pub hash_optional: bool,
}

/// What the public registry publishes for one package version.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct Public {
    pub hashes: BTreeSet<String>,
    pub wheel: bool,
    pub sdist: bool,
}

fn py_hash(value: &str) -> String {
    let value = value.trim();
    match value.split_once([':', '=']) {
        Some((alg, hex)) => format!("{}:{}", alg.to_ascii_lowercase(), hex.to_ascii_lowercase()),
        None => value.to_ascii_lowercase(),
    }
}

fn add_py_file(entry: &mut Locked, hashes: Vec<String>, wheel: bool) {
    entry.unhashed |= hashes.is_empty();
    entry.hashes.extend(hashes);
    if wheel {
        entry.wheel = true;
    } else {
        entry.sdist = true;
    }
}

fn npm_locked(content: &str) -> HashMap<Key, Locked> {
    let mut out: HashMap<Key, Locked> = HashMap::new();
    let Ok(lock) = serde_json::from_str::<serde_json::Value>(content) else {
        return out;
    };
    let mut add = |name: &str, entry: &serde_json::Value| {
        // As `parse_npm_lock`: links and bundled copies are not downloaded from the registry.
        let flag = |k: &str| entry.get(k).and_then(|v| v.as_bool()) == Some(true);
        let Some(version) = entry.get("version").and_then(|v| v.as_str()) else {
            return;
        };
        if flag("link") || flag("inBundle") {
            return;
        }
        let locked = out
            .entry((name.to_string(), version.to_string()))
            .or_default();
        match entry.get("integrity").and_then(|v| v.as_str()) {
            Some(h) => {
                locked.hashes.insert(h.to_string());
            }
            None => locked.unhashed = true,
        }
    };
    if let Some(packages) = lock.get("packages").and_then(|v| v.as_object()) {
        for (key, entry) in packages {
            let Some(path_name) = key.rsplit_once("node_modules/").map(|(_, n)| n) else {
                continue;
            };
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
    out
}

fn pnpm_locked(content: &str) -> HashMap<Key, Locked> {
    let mut out: HashMap<Key, Locked> = HashMap::new();
    let Ok(lock) = serde_yaml::from_str::<serde_yaml::Value>(content) else {
        return out;
    };
    let Some(packages) = lock.get("packages").and_then(|v| v.as_mapping()) else {
        return out;
    };
    for (key, entry) in packages {
        let Some((name, version)) = key
            .as_str()
            .map(pnpm_key_without_peers)
            .and_then(pnpm_package_key)
        else {
            continue;
        };
        let locked = out
            .entry((name.to_string(), version.to_string()))
            .or_default();
        match entry
            .get("resolution")
            .and_then(|r| r.get("integrity"))
            .and_then(|i| i.as_str())
        {
            Some(h) => {
                locked.hashes.insert(h.to_string());
            }
            None => locked.unhashed = true,
        }
    }
    out
}

fn toml_tables<'a>(doc: &'a toml::Table, keys: &[&str]) -> Vec<&'a toml::Table> {
    keys.iter()
        .find_map(|k| doc.get(*k).and_then(|v| v.as_array()))
        .map(|items| items.iter().filter_map(|v| v.as_table()).collect())
        .unwrap_or_default()
}

fn str_of<'a>(t: &'a toml::Table, k: &str) -> Option<&'a str> {
    t.get(k).and_then(|v| v.as_str())
}

/// `hash = "sha256:…"` (uv.lock) or `hashes = { sha256 = "…" }` (pylock.toml).
fn file_hashes(file: &toml::Table) -> Vec<String> {
    let mut out: Vec<String> = str_of(file, "hash").map(py_hash).into_iter().collect();
    if let Some(table) = file.get("hashes").and_then(|v| v.as_table()) {
        out.extend(
            table
                .iter()
                .filter_map(|(alg, v)| v.as_str().map(|h| py_hash(&format!("{alg}:{h}")))),
        );
    }
    out
}

fn python_locked(
    content: &str,
    keys: &[&str],
    version: fn(&toml::Table) -> Option<String>,
    files: fn(&toml::Table) -> Vec<PyFile>,
) -> HashMap<Key, Locked> {
    let mut out: HashMap<Key, Locked> = HashMap::new();
    let Ok(doc) = content.parse::<toml::Table>() else {
        return out;
    };
    for pkg in toml_tables(&doc, keys) {
        let (Some(name), Some(version)) = (str_of(pkg, "name"), version(pkg)) else {
            continue;
        };
        let locked = out.entry((name.to_string(), version)).or_default();
        for (wheel, hashes) in files(pkg) {
            add_py_file(locked, hashes, wheel);
        }
    }
    out
}

fn plain_version(pkg: &toml::Table) -> Option<String> {
    str_of(pkg, "version").map(str::to_string)
}

/// As `parse_pylock`: a version from the file names, and `latest` (what the scan uses) when
/// there is none, so such an entry is verified instead of skipped.
fn pylock_entry_version(pkg: &toml::Table) -> Option<String> {
    Some(
        pylock_version(pkg)
            .ok()
            .flatten()
            .unwrap_or_else(|| "latest".to_string()),
    )
}

fn uv_files(pkg: &toml::Table) -> Vec<PyFile> {
    let sdist = pkg.get("sdist").and_then(|v| v.as_table());
    let wheels = pkg.get("wheels").and_then(|v| v.as_array());
    sdist
        .into_iter()
        .map(|t| (false, file_hashes(t)))
        .chain(
            wheels
                .into_iter()
                .flatten()
                .filter_map(|v| v.as_table())
                .map(|t| (true, file_hashes(t))),
        )
        .collect()
}

fn poetry_files(pkg: &toml::Table) -> Vec<PyFile> {
    pkg.get("files")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_table())
        .map(|t| {
            let wheel = str_of(t, "file").is_some_and(|f| f.ends_with(".whl"));
            (wheel, file_hashes(t))
        })
        .collect()
}

fn pylock_files(pkg: &toml::Table) -> Vec<PyFile> {
    let single = ["archive", "sdist"]
        .iter()
        .filter_map(|k| pkg.get(*k).and_then(|v| v.as_table()))
        .map(|t| {
            let wheel = str_of(t, "path")
                .or_else(|| str_of(t, "url"))
                .is_some_and(|f| f.ends_with(".whl"));
            (wheel, file_hashes(t))
        });
    let wheels = pkg
        .get("wheels")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_table())
        .map(|t| (true, file_hashes(t)));
    single.chain(wheels).collect()
}

/// `name==version` lines of a requirements file with their `--hash=alg:hex` options, which may
/// continue on following lines after a trailing backslash.
fn requirements_locked(content: &str) -> HashMap<Key, Locked> {
    let mut out: HashMap<Key, Locked> = HashMap::new();
    let joined = content.replace("\\\r\n", " ").replace("\\\n", " ");
    for line in joined.lines() {
        let mut tokens = line.split_whitespace();
        let Some((name, version)) = tokens.next().and_then(|t| t.split_once("==")) else {
            continue;
        };
        let version = version.split(';').next().unwrap_or(version);
        if name.is_empty() || version.is_empty() || name.starts_with('-') {
            continue;
        }
        let mut hashes = Vec::new();
        let mut rest = tokens.take_while(|t| *t != "#");
        while let Some(t) = rest.next() {
            let value = match t.strip_prefix("--hash=") {
                Some(v) => Some(v),
                None if t == "--hash" => rest.next(),
                None => None,
            };
            hashes.extend(value.map(py_hash));
        }
        let locked = out
            .entry((strip_pep508_extras(name).to_string(), version.to_string()))
            .or_default();
        locked.hash_optional = true;
        add_py_file(locked, hashes, true);
    }
    out
}

/// The pins of a recorded lockfile, chosen by its file name; `None` for any other input.
pub(crate) fn locked_files(path: &str, content: &str) -> Option<HashMap<Key, Locked>> {
    let file = path.rsplit('/').next().unwrap_or(path);
    Some(match file {
        "package-lock.json" | "npm-shrinkwrap.json" => npm_locked(content),
        "pnpm-lock.yaml" => pnpm_locked(content),
        "uv.lock" => python_locked(content, &["package"], plain_version, uv_files),
        "poetry.lock" => python_locked(content, &["package"], plain_version, poetry_files),
        f if f.ends_with("pylock.toml") => python_locked(
            content,
            &["packages", "package"],
            pylock_entry_version,
            pylock_files,
        ),
        _ => requirements_locked(content),
    })
}

/// `sha1-<base64>` as lowercase hex, for comparison with npm's `dist.shasum`.
fn sha1_hex(integrity: &str) -> Option<String> {
    let bytes = base64_decode(integrity.strip_prefix("sha1-")?.as_bytes())?;
    Some(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// The reason a locked version cannot be shown to be a public file, if there is one.
pub(crate) fn mismatch(
    mirror: bool,
    name: &str,
    version: &str,
    locked: &Locked,
    public: &Public,
) -> Option<String> {
    if (mirror || !locked.hash_optional) && (locked.hashes.is_empty() || locked.unhashed) {
        return Some(format!(
            "{name}@{version}: the lockfile or requirements file records no hash for at least one occurrence or file of it"
        ));
    }
    let unknown: Vec<&str> = locked
        .hashes
        .iter()
        .filter(|h| {
            !public.hashes.contains(*h)
                && !sha1_hex(h).is_some_and(|hex| public.hashes.contains(&format!("sha1:{hex}")))
        })
        .map(String::as_str)
        .collect();
    if !unknown.is_empty() {
        return Some(format!(
            "{name}@{version}: the lockfile or requirements file pins a file the public registry does not publish for this version ({})",
            unknown.join(", ")
        ));
    }
    if locked.sdist && !locked.wheel && public.wheel {
        return Some(format!(
            "{name}@{version}: the lockfile pins only the source distribution although the registry publishes wheels, so the install would build it and the scan did not"
        ));
    }
    None
}

async fn fetch_public(
    client: &reqwest::Client,
    npm: bool,
    name: &str,
    version: &str,
) -> Option<Public> {
    let get = |url: String| async move {
        client
            .get(url)
            .send()
            .await
            .ok()?
            .error_for_status()
            .ok()?
            .json::<serde_json::Value>()
            .await
            .ok()
    };
    let mut public = Public::default();
    if npm {
        let doc = get(format!(
            "https://registry.npmjs.org/{}/{version}",
            name.replace('/', "%2f")
        ))
        .await?;
        let dist = doc.get("dist")?;
        public.hashes.extend(
            dist.get("integrity")
                .and_then(|v| v.as_str())
                .map(str::to_string),
        );
        public.hashes.extend(
            dist.get("shasum")
                .and_then(|v| v.as_str())
                .map(|h| format!("sha1:{}", h.to_ascii_lowercase())),
        );
    } else {
        let doc = if version == "latest" {
            get(format!("https://pypi.org/pypi/{name}/json")).await?
        } else {
            get(format!("https://pypi.org/pypi/{name}/{version}/json")).await?
        };
        for file in doc.get("urls")?.as_array()? {
            let kind = file.get("packagetype").and_then(|v| v.as_str());
            public.wheel |= kind == Some("bdist_wheel");
            public.sdist |= kind == Some("sdist");
            public.hashes.extend(
                file.get("digests")
                    .and_then(|d| d.get("sha256"))
                    .and_then(|v| v.as_str())
                    .map(|h| py_hash(&format!("sha256:{h}"))),
            );
        }
    }
    (!public.hashes.is_empty()).then_some(public)
}

/// Checks every scanned target that a recorded lockfile pins. `Err` lists what could not be
/// shown to be a public file. Targets no lockfile pins (a package named on the command line) are
/// not covered; internal packages are skipped because they are not on the public registry.
pub(crate) async fn verify_lockfile_artifacts(
    manager: &str,
    recorded: &[(String, String)],
    targets: &[(String, String)],
    exempt: &HashSet<String>,
    mirror: bool,
) -> Result<(), String> {
    let npm = matches!(manager, "npm" | "pnpm");
    let locks: Vec<HashMap<Key, Locked>> = recorded
        .iter()
        .filter_map(|(path, content)| locked_files(path, content))
        .collect();
    if locks.is_empty() {
        return Ok(());
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("could not build the registry client ({e})"))?;
    let mut problems: Vec<String> = Vec::new();
    let wanted: Vec<(&Key, Locked)> = {
        let mut seen = HashSet::new();
        targets
            .iter()
            .filter(|(n, _)| !exempt.contains(n))
            .filter(|t| seen.insert((*t).clone()))
            .filter_map(|t| {
                let mut merged = Locked::default();
                let mut found = false;
                for lock in &locks {
                    if let Some(l) = lock.get(t) {
                        found = true;
                        merged.hashes.extend(l.hashes.iter().cloned());
                        merged.wheel |= l.wheel;
                        merged.sdist |= l.sdist;
                        merged.unhashed |= l.unhashed;
                        merged.hash_optional |= l.hash_optional;
                    }
                }
                // A requirements entry without a hash needs no check unless a mirror is trusted.
                let skip = merged.hash_optional && merged.hashes.is_empty() && !mirror;
                (found && !skip).then_some((t, merged))
            })
            .collect()
    };
    for batch in wanted.chunks(16) {
        let mut set = tokio::task::JoinSet::new();
        for ((name, version), locked) in batch {
            let (client, name, version) = (client.clone(), name.clone(), version.clone());
            let locked = Locked {
                hashes: locked.hashes.clone(),
                wheel: locked.wheel,
                sdist: locked.sdist,
                unhashed: locked.unhashed,
                hash_optional: locked.hash_optional,
            };
            set.spawn(async move {
                let public = fetch_public(&client, npm, &name, &version).await;
                match public {
                    Some(p) => mismatch(mirror, &name, &version, &locked, &p),
                    None => Some(format!(
                        "{name}@{version}: the public registry's hashes could not be fetched"
                    )),
                }
            });
        }
        while let Some(done) = set.join_next().await {
            match done {
                Ok(Some(p)) => problems.push(p),
                Ok(None) => {}
                Err(e) => problems.push(format!("a verification task failed ({e})")),
            }
        }
    }
    if problems.is_empty() {
        return Ok(());
    }
    problems.sort();
    Err(format!(
        "{} pinned package(s) cannot be shown to be files the public registry publishes, so the scan would not describe the install:\n  {}\nRegenerate the lockfile or requirements file from the public registry, or add an internal package to internal_package_exemptions.",
        problems.len(),
        problems.join("\n  ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: &str, v: &str) -> Key {
        (n.to_string(), v.to_string())
    }

    fn public(hashes: &[&str], wheel: bool, sdist: bool) -> Public {
        Public {
            hashes: hashes.iter().map(|h| h.to_string()).collect(),
            wheel,
            sdist,
        }
    }

    #[test]
    fn npm_lock_integrity_is_read_for_v3_and_v1() {
        let v3 = r#"{"packages":{"":{},"node_modules/a":{"version":"1.0.0","integrity":"sha512-AAA"},"node_modules/x/node_modules/@s/b":{"version":"2.0.0","integrity":"sha512-BBB"},"node_modules/c":{"name":"real","version":"3.0.0","integrity":"sha512-CCC"}}}"#;
        let got = npm_locked(v3);
        assert!(got[&key("a", "1.0.0")].hashes.contains("sha512-AAA"));
        assert!(got[&key("@s/b", "2.0.0")].hashes.contains("sha512-BBB"));
        assert!(got.contains_key(&key("real", "3.0.0")));
        let v1 = r#"{"dependencies":{"a":{"version":"1.0.0","integrity":"sha1-AAA=","dependencies":{"b":{"version":"2.0.0"}}}}}"#;
        let got = npm_locked(v1);
        assert!(got[&key("a", "1.0.0")].hashes.contains("sha1-AAA="));
        assert!(got[&key("b", "2.0.0")].hashes.is_empty());
    }

    #[test]
    fn pnpm_lock_integrity_is_read_in_all_key_forms() {
        let lock = "packages:\n  /lodash/4.17.21:\n    resolution: {integrity: sha512-a}\n  /@types/react@18.2.0(react@18.2.0):\n    resolution: {integrity: sha512-b}\n  chalk@5.0.0:\n    resolution: {integrity: sha512-c}\n";
        let got = pnpm_locked(lock);
        assert!(got[&key("lodash", "4.17.21")].hashes.contains("sha512-a"));
        assert!(
            got[&key("@types/react", "18.2.0")]
                .hashes
                .contains("sha512-b")
        );
        assert!(got[&key("chalk", "5.0.0")].hashes.contains("sha512-c"));
    }

    #[test]
    fn python_locks_record_hashes_and_file_kinds() {
        let uv = "[[package]]\nname = \"six\"\nversion = \"1.16.0\"\nsdist = { url = \"https://files.pythonhosted.org/six-1.16.0.tar.gz\", hash = \"sha256:AA\" }\nwheels = [{ url = \"https://files.pythonhosted.org/six-1.16.0-py2.py3-none-any.whl\", hash = \"sha256:bb\" }]\n";
        let got = &locked_files("uv.lock", uv).unwrap()[&key("six", "1.16.0")];
        assert_eq!(
            got.hashes,
            ["sha256:aa", "sha256:bb"].map(String::from).into()
        );
        assert!(got.wheel && got.sdist);

        let poetry = "[[package]]\nname = \"six\"\nversion = \"1.16.0\"\nfiles = [\n  {file = \"six-1.16.0.tar.gz\", hash = \"sha256:aa\"},\n]\n";
        let got = &locked_files("poetry.lock", poetry).unwrap()[&key("six", "1.16.0")];
        assert!(got.sdist && !got.wheel);

        let pylock = "[[packages]]\nname = \"six\"\nversion = \"1.16.0\"\nsdist = { url = \"https://files.pythonhosted.org/six.tar.gz\", hashes = { sha256 = \"AA\" } }\n[[packages.wheels]]\nurl = \"https://files.pythonhosted.org/six.whl\"\nhashes = { sha256 = \"bb\" }\n";
        let got = &locked_files("sub/pylock.toml", pylock).unwrap()[&key("six", "1.16.0")];
        assert_eq!(got.hashes.len(), 2);
        assert!(got.wheel && got.sdist);
    }

    #[test]
    fn a_locked_hash_the_registry_does_not_publish_is_refused() {
        let locked = Locked {
            hashes: ["sha256:evil".to_string()].into(),
            wheel: true,
            sdist: false,
            unhashed: false,
            hash_optional: false,
        };
        let msg = mismatch(
            true,
            "six",
            "1.16.0",
            &locked,
            &public(&["sha256:good"], true, true),
        )
        .expect("must be refused");
        assert!(msg.contains("does not publish") && msg.contains("sha256:evil"));
        let ok = Locked {
            hashes: ["sha256:good".to_string()].into(),
            wheel: true,
            sdist: false,
            unhashed: false,
            hash_optional: false,
        };
        assert_eq!(
            mismatch(
                true,
                "six",
                "1.16.0",
                &ok,
                &public(&["sha256:good", "sha256:other"], true, true)
            ),
            None
        );
    }

    #[test]
    fn a_lock_entry_without_a_hash_is_refused() {
        let msg = mismatch(
            true,
            "a",
            "1.0.0",
            &Locked::default(),
            &public(&["sha512-x"], false, false),
        );
        assert!(msg.unwrap().contains("no hash"));
    }

    #[test]
    fn an_sdist_only_pin_is_refused_when_wheels_exist() {
        let locked = Locked {
            hashes: ["sha256:aa".to_string()].into(),
            wheel: false,
            sdist: true,
            unhashed: false,
            hash_optional: false,
        };
        let msg = mismatch(
            true,
            "six",
            "1.16.0",
            &locked,
            &public(&["sha256:aa", "sha256:bb"], true, true),
        );
        assert!(msg.unwrap().contains("source distribution"));
        // The registry has nothing but the sdist: the probe builds it too.
        assert_eq!(
            mismatch(
                true,
                "six",
                "1.16.0",
                &locked,
                &public(&["sha256:aa"], false, true)
            ),
            None
        );
    }

    #[test]
    fn an_old_sha1_integrity_matches_the_registry_shasum() {
        // sha1 of "" is da39a3ee5e6b4b0d3255bfef95601890afd80709
        let locked = Locked {
            hashes: ["sha1-2jmj7l5rSw0yVb/vlWAYkK/YBwk=".to_string()].into(),
            ..Default::default()
        };
        assert_eq!(
            mismatch(
                true,
                "a",
                "1.0.0",
                &locked,
                &public(
                    &["sha1:da39a3ee5e6b4b0d3255bfef95601890afd80709"],
                    false,
                    false
                )
            ),
            None
        );
        assert!(
            mismatch(
                true,
                "a",
                "1.0.0",
                &locked,
                &public(&["sha1:00"], false, false)
            )
            .is_some()
        );
    }

    #[test]
    fn one_hashless_occurrence_is_not_hidden_by_a_hashed_one() {
        let lock = r#"{"packages":{"node_modules/a":{"version":"1.0.0","integrity":"sha512-AAA"},"node_modules/x/node_modules/a":{"version":"1.0.0"}}}"#;
        let locked = &npm_locked(lock)[&key("a", "1.0.0")];
        let msg = mismatch(
            true,
            "a",
            "1.0.0",
            locked,
            &public(&["sha512-AAA"], false, false),
        );
        assert!(msg.unwrap().contains("no hash"));
        let ok = r#"{"packages":{"node_modules/a":{"version":"1.0.0","integrity":"sha512-AAA"},"node_modules/x/node_modules/a":{"version":"1.0.0","integrity":"sha512-AAA"}}}"#;
        let locked = &npm_locked(ok)[&key("a", "1.0.0")];
        assert_eq!(
            mismatch(
                true,
                "a",
                "1.0.0",
                locked,
                &public(&["sha512-AAA"], false, false)
            ),
            None
        );
    }

    #[test]
    fn a_python_file_without_a_hash_is_refused() {
        let uv = "[[package]]\nname = \"six\"\nversion = \"1.16.0\"\nwheels = [{ url = \"https://files.pythonhosted.org/six-1.16.0-py2.py3-none-any.whl\", hash = \"sha256:aa\" }, { url = \"https://files.pythonhosted.org/six-1.16.0-py3-none-any.whl\" }]\n";
        let locked = &locked_files("uv.lock", uv).unwrap()[&key("six", "1.16.0")];
        assert!(locked.unhashed);
        assert!(
            mismatch(
                true,
                "six",
                "1.16.0",
                locked,
                &public(&["sha256:aa"], true, false)
            )
            .is_some()
        );
    }

    #[test]
    fn a_pylock_entry_without_a_version_is_read_from_its_file_names_or_as_latest() {
        let named = "[[packages]]\nname = \"six\"\nwheels = [{ url = \"https://files.pythonhosted.org/six-1.16.0-py2.py3-none-any.whl\", hashes = { sha256 = \"aa\" } }]\n";
        assert!(
            locked_files("pylock.toml", named)
                .unwrap()
                .contains_key(&key("six", "1.16.0"))
        );
        let bare = "[[packages]]\nname = \"six\"\n";
        assert!(
            locked_files("pylock.toml", bare)
                .unwrap()
                .contains_key(&key("six", "latest"))
        );
    }

    #[test]
    fn bundled_and_linked_npm_entries_do_not_count_as_hashless() {
        let lock = r#"{"packages":{"node_modules/a":{"version":"1.0.0","integrity":"sha512-AAA"},"node_modules/x/node_modules/a":{"version":"1.0.0","inBundle":true},"node_modules/l":{"version":"1.0.0","link":true}}}"#;
        let got = npm_locked(lock);
        assert!(!got[&key("a", "1.0.0")].unhashed);
        assert!(!got.contains_key(&key("l", "1.0.0")));
    }

    #[test]
    fn requirements_hashes_are_read_across_continuation_lines() {
        let req = "# pins\nsix[extra]==1.16.0 ; python_version >= \"3\" \\\n    --hash=sha256:AA \\\n    --hash sha256:bb\nattrs==24.2.0\n-r other.txt\n";
        let got = requirements_locked(req);
        let six = &got[&key("six", "1.16.0")];
        assert_eq!(
            six.hashes,
            ["sha256:aa", "sha256:bb"].map(String::from).into()
        );
        assert!(six.hash_optional);
        assert!(got[&key("attrs", "24.2.0")].hashes.is_empty());
    }

    #[test]
    fn a_requirements_line_without_a_hash_is_refused_only_with_a_trusted_mirror() {
        let got = requirements_locked("attrs==24.2.0\n");
        let locked = &got[&key("attrs", "24.2.0")];
        let public = public(&["sha256:aa"], true, false);
        assert_eq!(mismatch(false, "attrs", "24.2.0", locked, &public), None);
        assert!(
            mismatch(true, "attrs", "24.2.0", locked, &public)
                .unwrap()
                .contains("no hash")
        );
    }

    #[test]
    fn a_requirements_hash_the_registry_does_not_publish_is_refused_without_a_mirror_too() {
        let got = requirements_locked("attrs==24.2.0 --hash=sha256:evil\n");
        let locked = &got[&key("attrs", "24.2.0")];
        assert!(
            mismatch(
                false,
                "attrs",
                "24.2.0",
                locked,
                &public(&["sha256:aa"], true, false)
            )
            .unwrap()
            .contains("does not publish")
        );
    }
}
