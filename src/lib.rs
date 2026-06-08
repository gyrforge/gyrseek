use std::collections::HashSet;
use std::fs;
use std::process::{Command, Stdio};

use regex::Regex;
use serde::Deserialize;

#[derive(Deserialize, Debug)]
struct PyPiResponse {
    releases: std::collections::HashMap<String, serde_json::Value>,
}

#[derive(Deserialize, Debug)]
struct NpmResponse {
    versions: std::collections::HashMap<String, serde_json::Value>,
}

pub struct GyrSeek {
    passthrough_args: Vec<String>,
    manager: String,
}

/// Returns connections present in the current version but absent in baseline versions.
pub fn find_new_connections(ips_curr: &HashSet<String>, baseline_ips: &HashSet<String>) -> Vec<String> {
    ips_curr.difference(baseline_ips).cloned().collect()
}

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

    for raw_line in content.lines() {
        let line = raw_line.trim();

        if line == "[[package]]" {
            if let (Some(n), Some(v)) = (name.take(), version.take()) {
                packages.push((n, v));
            }
            in_package = true;
            name = None;
            version = None;
            continue;
        }

        if !in_package {
            continue;
        }

        if line.starts_with("[[") && line != "[[package]]" {
            if let (Some(n), Some(v)) = (name.take(), version.take()) {
                packages.push((n, v));
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

    if let (Some(n), Some(v)) = (name, version) {
        packages.push((n, v));
    }

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

impl GyrSeek {
    pub fn new(args: Vec<String>) -> Self {
        let manager = args.first().cloned().unwrap_or_default();
        Self {
            passthrough_args: args,
            manager,
        }
    }

    /// Extracts package names and explicit versions from commands
    /// like: uv pip install requests==2.31.0
    pub fn parse_package_details(&self) -> (Option<String>, Option<String>) {
        if self.manager == "uv"
            || self.manager == "pip"
            || self.manager == "pip3"
            || self.manager == "poetry"
            || self.manager == "npm"
        {
            let pkg_arg_start = if self.manager == "uv" {
                if self.passthrough_args.get(1).map(String::as_str) == Some("add") {
                    Some(2)
                } else if self.passthrough_args.get(1).map(String::as_str) == Some("pip")
                    && self.passthrough_args.get(2).map(String::as_str) == Some("install")
                {
                    Some(3)
                } else {
                    None
                }
            } else if self.manager == "poetry" {
                if self.passthrough_args.get(1).map(String::as_str) == Some("add")
                    || self.passthrough_args.get(1).map(String::as_str) == Some("update")
                    || self.passthrough_args.get(1).map(String::as_str) == Some("install")
                {
                    Some(2)
                } else {
                    None
                }
            } else if self.manager == "npm" {
                if self.passthrough_args.get(1).map(String::as_str) == Some("install")
                    || self.passthrough_args.get(1).map(String::as_str) == Some("i")
                {
                    Some(2)
                } else {
                    None
                }
            } else if self.passthrough_args.get(1).map(String::as_str) == Some("install") {
                Some(2)
            } else {
                None
            };

            if let Some(start) = pkg_arg_start {
                for arg in self.passthrough_args.iter().skip(start) {
                    if arg.starts_with('-') {
                        continue;
                    }

                    if self.manager == "npm" {
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

    /// Queries registries asynchronously to pull target, v-1, and v-2 versions
    pub async fn fetch_history(&self, package: &str, target_v: &str) -> (String, Option<String>, Option<String>) {
        println!("🔍 [gyrseek] Fetching version matrix from registry for '{}'...", package);
        let client = reqwest::Client::new();

        if self.manager == "npm" {
            let encoded = package.replace('/', "%2f");
            let url = format!("https://registry.npmjs.org/{}", encoded);
            if let Ok(res) = client.get(&url).send().await {
                if let Ok(data) = res.json::<NpmResponse>().await {
                    let mut versions: Vec<String> = data.versions.keys().cloned().collect();
                    // Basic sorting (for production, use a semantic versioning crate like 'semver')
                    versions.sort();

                    let current = if target_v == "latest" {
                        versions.last().cloned().unwrap_or_else(|| target_v.to_string())
                    } else {
                        target_v.to_string()
                    };

                    if let Some(idx) = versions.iter().position(|v| v == &current) {
                        let v_m1 = if idx > 0 { Some(versions[idx - 1].clone()) } else { None };
                        let v_m2 = if idx > 1 { Some(versions[idx - 2].clone()) } else { None };
                        return (current, v_m1, v_m2);
                    }
                }
            }
        } else {
            let url = format!("https://pypi.org/pypi/{}/json", package);
            if let Ok(res) = client.get(&url).send().await {
                if let Ok(data) = res.json::<PyPiResponse>().await {
                    let mut versions: Vec<String> = data.releases.keys().cloned().collect();
                    // Basic sorting (for production, use a semantic versioning crate like 'semver')
                    versions.sort();

                    let current = if target_v == "latest" {
                        versions.last().cloned().unwrap_or_else(|| target_v.to_string())
                    } else {
                        target_v.to_string()
                    };

                    if let Some(idx) = versions.iter().position(|v| v == &current) {
                        let v_m1 = if idx > 0 { Some(versions[idx - 1].clone()) } else { None };
                        let v_m2 = if idx > 1 { Some(versions[idx - 2].clone()) } else { None };
                        return (current, v_m1, v_m2);
                    }
                }
            }
        }
        (target_v.to_string(), None, None)
    }

    /// Spawns an isolated sandbox tracking system calls with strace
    pub fn trace_sandbox_install(&self, package: &str, version: &str) -> HashSet<String> {
        let mut ips = HashSet::new();
        let temp_dir = tempfile::tempdir().unwrap();
        let target_path = temp_dir.path().to_str().unwrap();

        let cmd_args = if self.manager == "npm" {
            vec![
                "-f".to_string(),
                "-e".to_string(),
                "trace=network,execve".to_string(),
                "npm".to_string(),
                "install".to_string(),
                format!("{}@{}", package, version),
                "--prefix".to_string(),
                target_path.to_string(),
                "--no-save".to_string(),
            ]
        } else {
            // Build owned args to avoid borrowing temporary formatted strings.
            vec![
                "-f".to_string(),
                "-e".to_string(),
                "trace=network,execve".to_string(),
                "uv".to_string(),
                "pip".to_string(),
                "install".to_string(),
                format!("{}=={}", package, version),
                "--target".to_string(),
                target_path.to_string(),
                "--no-cache".to_string(),
            ]
        };

        let output = Command::new("strace")
            .args(&cmd_args)
            .stderr(Stdio::piped())
            .stdout(Stdio::null())
            .output();

        if let Ok(res) = output {
            let stderr_str = String::from_utf8_lossy(&res.stderr);
            let re = Regex::new(r#"sin_addr=inet_addr\("([\d.]+)"\)"#).unwrap();
            for cap in re.captures_iter(&stderr_str) {
                ips.insert(cap[1].to_string());
            }
        }
        ips
    }

    /// Executes the user's raw host operation transparently
    pub fn forward_original_command(&self) {
        if self.passthrough_args.is_empty() {
            return;
        }

        let mut child = Command::new(&self.manager)
            .args(&self.passthrough_args[1..])
            .spawn()
            .expect("Failed to execute host command");

        let _ = child.wait();
    }

    fn parse_uv_lock_packages(&self) -> Vec<(String, String)> {
        let lock_content = match fs::read_to_string("uv.lock") {
            Ok(content) => content,
            Err(_) => return Vec::new(),
        };

        parse_uv_lock_packages_from_content(&lock_content)
    }

    fn parse_uv_pip_sync_packages(&self) -> Vec<(String, Option<String>)> {
        let mut packages = Vec::new();
        for arg in self.passthrough_args.iter().skip(3) {
            if arg.starts_with('-') {
                continue;
            }

            if !fs::metadata(arg).map(|m| m.is_file()).unwrap_or(false) {
                continue;
            }

            if let Ok(content) = fs::read_to_string(arg) {
                if arg.ends_with("pylock.toml") {
                    packages.extend(parse_pylock_packages_from_content(&content));
                } else {
                    packages.extend(parse_requirements_packages_from_content(&content));
                }
            }
        }

        packages
    }
}

async fn scan_package_versions(eye: &GyrSeek, pkg_name: &str, tgt_version: &str) -> bool {
    let (v_curr, v_m1, v_m2) = eye.fetch_history(pkg_name, tgt_version).await;
    let baseline_m1 = v_m1.clone().unwrap_or_else(|| "n/a".to_string());
    let baseline_m2 = v_m2.clone().unwrap_or_else(|| "n/a".to_string());
    println!(
        "🛡️ [gyrseek] Comparing versions for '{}': current={} baseline-1={} baseline-2={}",
        pkg_name, v_curr, baseline_m1, baseline_m2
    );

    // Execute scans inside clean environments
    let ips_curr = eye.trace_sandbox_install(pkg_name, &v_curr);

    let mut baseline_ips = HashSet::new();
    if let Some(ref v) = v_m1 {
        baseline_ips.extend(eye.trace_sandbox_install(pkg_name, v));
    }
    if let Some(ref v) = v_m2 {
        baseline_ips.extend(eye.trace_sandbox_install(pkg_name, v));
    }

    // Isolate anomalies introduced in the newest package release.
    let new_connections = find_new_connections(&ips_curr, &baseline_ips);

    if !new_connections.is_empty() {
        println!("\n❌ [gyrseek] CRITICAL WARNING: Behavioral anomaly flagged!");
        println!(
            "The requested version tried contacting new endpoints not seen in previous versions: {:?}",
            new_connections
        );
        println!("Aborting host operation securely.");
        return false;
    }

    true
}

fn should_enforce_package_detection(eye: &GyrSeek) -> bool {
    if eye.manager == "uv" {
        return eye.passthrough_args.get(1).map(String::as_str) == Some("add")
            || (eye.passthrough_args.get(1).map(String::as_str) == Some("pip")
                && eye.passthrough_args.get(2).map(String::as_str) == Some("install"))
            || (eye.passthrough_args.get(1).map(String::as_str) == Some("pip")
                && eye.passthrough_args.get(2).map(String::as_str) == Some("sync"))
            || eye.passthrough_args.get(1).map(String::as_str) == Some("sync");
    }

    if eye.manager == "pip" || eye.manager == "pip3" {
        return eye.passthrough_args.get(1).map(String::as_str) == Some("install");
    }

    if eye.manager == "poetry" {
        return eye.passthrough_args.get(1).map(String::as_str) == Some("add")
            || eye.passthrough_args.get(1).map(String::as_str) == Some("update")
            || eye.passthrough_args.get(1).map(String::as_str) == Some("install");
    }

    if eye.manager == "npm" {
        return eye.passthrough_args.get(1).map(String::as_str) == Some("install")
            || eye.passthrough_args.get(1).map(String::as_str) == Some("i");
    }

    false
}

pub async fn run(args: Vec<String>) {
    let eye = GyrSeek::new(args);

    if eye.manager == "uv"
        && eye.passthrough_args.get(1).map(String::as_str) == Some("pip")
        && eye.passthrough_args.get(2).map(String::as_str) == Some("sync")
    {
        let sync_packages = eye.parse_uv_pip_sync_packages();
        if sync_packages.is_empty() {
            println!(
                "❌ [gyrseek] 'uv pip sync' detected but no parseable package entries were found. Failing closed."
            );
            std::process::exit(1);
        }

        println!(
            "🛡️ [gyrseek] 'uv pip sync' detected. Testing {} package(s) from sync sources...",
            sync_packages.len()
        );

        for (pkg_name, maybe_version) in sync_packages {
            let tgt_version = maybe_version.unwrap_or_else(|| "latest".to_string());
            if !scan_package_versions(&eye, &pkg_name, &tgt_version).await {
                std::process::exit(1);
            }
        }

        println!("\n✅ [gyrseek] Clear behavioral report for sync package set. Forwarding command safely...");
        eye.forward_original_command();
        return;
    }

    if eye.manager == "uv" && eye.passthrough_args.get(1).map(String::as_str) == Some("sync") {
        let lock_packages = eye.parse_uv_lock_packages();
        if lock_packages.is_empty() {
            println!(
                "❌ [gyrseek] 'uv sync' detected but no packages found in uv.lock. Failing closed."
            );
            std::process::exit(1);
        }

        println!(
            "🛡️ [gyrseek] 'uv sync' detected. Testing {} locked package(s) from uv.lock...",
            lock_packages.len()
        );

        for (pkg_name, locked_version) in lock_packages {
            if !scan_package_versions(&eye, &pkg_name, &locked_version).await {
                std::process::exit(1);
            }
        }

        println!("\n✅ [gyrseek] Clear behavioral report for all locked packages. Forwarding command safely...");
        eye.forward_original_command();
        return;
    }

    let (package, target_v) = eye.parse_package_details();

    if package.is_none() {
        if should_enforce_package_detection(&eye) {
            println!(
                "❌ [gyrseek] Expected package target could not be detected for this command. Failing closed."
            );
            std::process::exit(1);
        }
        eye.forward_original_command();
        return;
    }

    let pkg_name = package.unwrap();
    let tgt_version = target_v.unwrap_or_else(|| "latest".to_string());

    if !scan_package_versions(&eye, &pkg_name, &tgt_version).await {
        std::process::exit(1);
    }

    println!("\n✅ [gyrseek] Clear behavioral report. Forwarding command safely...");
    eye.forward_original_command();
}