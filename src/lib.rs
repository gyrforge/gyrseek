mod parsing;
mod sandbox;
mod scanning;

use std::collections::HashMap;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::net::IpAddr;
use std::process::Command;

use serde::Deserialize;

pub use parsing::{
    parse_npm_install_packages_from_args,
    parse_npm_packages_from_package_json_content,
    parse_pip_install_packages_from_args,
    parse_poetry_lock_packages_from_content,
    parse_pylock_packages_from_content,
    parse_requirements_packages_from_content,
    parse_uv_lock_upgrade_packages_from_args,
    parse_uv_lock_packages_from_content,
};
pub use scanning::find_new_connections;
pub use scanning::enrich_new_connection_domains_with;
pub use scanning::filter_allowlisted_new_connections;
pub use scanning::filter_domain_allowlisted_new_connections_with;

use parsing::{parse_package_details, should_enforce_package_detection};
use sandbox::{build_runner_from_env, list_docker_runtimes, SandboxRunner};
use scanning::{scan_package_versions, scan_packages_versions};

const DEFAULT_CONFIG_PATH: &str = "gyrseek.yaml";

#[derive(Deserialize, Default)]
struct GyrseekConfig {
    #[serde(default)]
    ip_allowlist: Vec<String>,
    #[serde(default)]
    domain_allowlist: Vec<String>,
}

fn parse_global_options(args: Vec<String>) -> Result<(Vec<String>, String, bool), String> {
    let mut cfg_path = env::var("GYRSEEK_CONFIG").unwrap_or_else(|_| DEFAULT_CONFIG_PATH.to_string());
    let mut cfg_explicit = env::var("GYRSEEK_CONFIG").is_ok();
    let mut idx = 0usize;

    while idx < args.len() {
        let arg = &args[idx];
        if arg == "--config" || arg == "-c" {
            let Some(next) = args.get(idx + 1) else {
                return Err("Missing value for --config/-c".to_string());
            };
            cfg_path = next.clone();
            cfg_explicit = true;
            idx += 2;
            continue;
        }
        if let Some(path) = arg.strip_prefix("--config=") {
            if path.is_empty() {
                return Err("Missing value for --config option".to_string());
            }
            cfg_path = path.to_string();
            cfg_explicit = true;
            idx += 1;
            continue;
        }

        break;
    }

    Ok((args[idx..].to_vec(), cfg_path, cfg_explicit))
}

fn load_allowlists(path: &str, explicit: bool) -> Result<(HashSet<String>, HashSet<String>), String> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if !explicit && e.kind() == std::io::ErrorKind::NotFound => {
            return Ok((HashSet::new(), HashSet::new()));
        }
        Err(e) => {
            return Err(format!("Failed to read config file '{}': {}", path, e));
        }
    };

    let cfg: GyrseekConfig = serde_yaml::from_str(&content)
        .map_err(|e| format!("Failed to parse YAML config '{}': {}", path, e))?;

    let mut set = HashSet::new();
    for entry in cfg.ip_allowlist {
        match entry.parse::<IpAddr>() {
            Ok(addr) => {
                set.insert(addr.to_string());
            }
            Err(_) => {
                println!(
                    "⚠️ [gyrseek] Ignoring invalid ip_allowlist entry (not an IP): {}",
                    entry
                );
            }
        }
    }

    let mut domain_set = HashSet::new();
    for entry in cfg.domain_allowlist {
        let normalized = entry.trim().trim_end_matches('.').to_ascii_lowercase();
        if normalized.is_empty() {
            continue;
        }
        domain_set.insert(normalized);
    }

    Ok((set, domain_set))
}

#[cfg(test)]
mod config_tests {
    use super::{load_allowlists, parse_global_options};
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn parses_global_config_flag_and_strips_it_from_manager_args() {
        let args = vec![
            "--config".to_string(),
            "my-policy.yaml".to_string(),
            "npm".to_string(),
            "install".to_string(),
            "lodash".to_string(),
        ];

        let (manager_args, path, explicit) = parse_global_options(args).expect("parse should succeed");
        assert_eq!(manager_args, vec!["npm", "install", "lodash"]);
        assert_eq!(path, "my-policy.yaml");
        assert!(explicit);
    }

    #[test]
    fn keeps_args_untouched_when_no_global_options_present() {
        let args = vec!["uv".to_string(), "sync".to_string()];
        let (manager_args, _, _) = parse_global_options(args).expect("parse should succeed");
        assert_eq!(manager_args, vec!["uv", "sync"]);
    }

    #[test]
    fn missing_default_config_returns_empty_allowlist() {
        let missing = "gyrseek-config-does-not-exist.yaml";
        let (ip_allowlist, domain_allowlist) =
            load_allowlists(missing, false).expect("missing default should be allowed");
        assert!(ip_allowlist.is_empty());
        assert!(domain_allowlist.is_empty());
    }

    #[test]
    fn missing_explicit_config_fails_closed() {
        let missing = "gyrseek-config-does-not-exist.yaml";
        let err = load_allowlists(missing, true).expect_err("explicit config missing should fail");
        assert!(err.contains("Failed to read config file"));
    }

    #[test]
    fn parses_allowlists_and_ignores_invalid_ip_entries() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(
            file,
            "ip_allowlist:\n  - 1.1.1.1\n  - invalid-entry\n  - 8.8.8.8\n  - 2001:0db8:0000:0000:0000:ff00:0042:8329\ndomain_allowlist:\n  -  Example.COM.  \n  - sub.safe.net"
        )
        .expect("config should be written");

        let (ip_allowlist, domain_allowlist) = load_allowlists(
            file.path().to_str().expect("path should be utf8"),
            true,
        )
        .expect("config should parse");

        assert_eq!(ip_allowlist.len(), 3);
        assert!(ip_allowlist.contains("1.1.1.1"));
        assert!(ip_allowlist.contains("8.8.8.8"));
        assert!(ip_allowlist.contains("2001:db8::ff00:42:8329"));
        assert!(domain_allowlist.contains("example.com"));
        assert!(domain_allowlist.contains("sub.safe.net"));
    }
}

pub struct GyrSeek {
    passthrough_args: Vec<String>,
    manager: String,
}

impl GyrSeek {
    pub fn new(args: Vec<String>) -> Self {
        let manager = args.first().cloned().unwrap_or_default();
        Self {
            passthrough_args: args,
            manager,
        }
    }

    pub fn parse_package_details(&self) -> (Option<String>, Option<String>) {
        parse_package_details(&self.manager, &self.passthrough_args)
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

    fn parse_poetry_lock_packages(&self) -> Vec<(String, String)> {
        let lock_content = match fs::read_to_string("poetry.lock") {
            Ok(content) => content,
            Err(_) => return Vec::new(),
        };

        parse_poetry_lock_packages_from_content(&lock_content)
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

    fn parse_pip_install_packages(&self) -> Vec<(String, Option<String>)> {
        parse_pip_install_packages_from_args(&self.passthrough_args)
    }

    fn parse_npm_install_packages(&self) -> Vec<(String, Option<String>)> {
        parse_npm_install_packages_from_args(&self.passthrough_args)
    }

    fn parse_uv_lock_upgrade_packages(&self) -> Vec<String> {
        parse_uv_lock_upgrade_packages_from_args(&self.passthrough_args)
    }
}

async fn scan_with_cache(
    cache: &mut HashMap<String, bool>,
    runner: &dyn SandboxRunner,
    manager: &str,
    pkg_name: &str,
    tgt_version: &str,
    ip_allowlist: &HashSet<String>,
    domain_allowlist: &HashSet<String>,
) -> bool {
    let key = format!("{}|{}|{}", manager, pkg_name, tgt_version);
    if let Some(cached) = cache.get(&key) {
        println!(
            "🧠 [gyrseek] Cache hit for '{}@{}' in current run.",
            pkg_name, tgt_version
        );
        return *cached;
    }

    let result =
        scan_package_versions(runner, manager, pkg_name, tgt_version, ip_allowlist, domain_allowlist).await;
    cache.insert(key, result);
    result
}

async fn scan_many_with_cache(
    cache: &mut HashMap<String, bool>,
    runner: &dyn SandboxRunner,
    manager: &str,
    targets: Vec<(String, String)>,
    ip_allowlist: &HashSet<String>,
    domain_allowlist: &HashSet<String>,
) -> bool {
    let mut uncached: Vec<(String, String)> = Vec::new();

    for (pkg_name, tgt_version) in targets {
        let key = format!("{}|{}|{}", manager, pkg_name, tgt_version);
        if let Some(cached) = cache.get(&key) {
            println!(
                "🧠 [gyrseek] Cache hit for '{}@{}' in current run.",
                pkg_name, tgt_version
            );
            if !cached {
                return false;
            }
            continue;
        }
        uncached.push((pkg_name, tgt_version));
    }

    if uncached.is_empty() {
        return true;
    }

    let batch_results = scan_packages_versions(runner, manager, &uncached, ip_allowlist, domain_allowlist).await;

    for (pkg_name, tgt_version) in uncached {
        let result = batch_results
            .get(&format!("{}|{}", pkg_name, tgt_version))
            .copied()
            .unwrap_or(false);
        let key = format!("{}|{}|{}", manager, pkg_name, tgt_version);
        cache.insert(key, result);
        if !result {
            return false;
        }
    }

    true
}

pub async fn run(args: Vec<String>) {
    let (args, config_path, config_explicit) = match parse_global_options(args) {
        Ok(v) => v,
        Err(e) => {
            println!("❌ [gyrseek] {}", e);
            std::process::exit(1);
        }
    };

    let (ip_allowlist, domain_allowlist) = match load_allowlists(&config_path, config_explicit) {
        Ok(v) => v,
        Err(e) => {
            println!("❌ [gyrseek] {}", e);
            std::process::exit(1);
        }
    };

    if !ip_allowlist.is_empty() {
        println!(
            "ℹ️ [gyrseek] Loaded {} allowlisted IP(s) from {}",
            ip_allowlist.len(),
            config_path
        );
    }
    if !domain_allowlist.is_empty() {
        println!(
            "ℹ️ [gyrseek] Loaded {} allowlisted domain(s) from {}",
            domain_allowlist.len(),
            config_path
        );
    }

    let eye = GyrSeek::new(args);

    if eye.manager == "sandbox" && eye.passthrough_args.get(1).map(String::as_str) == Some("runtimes") {
        match list_docker_runtimes() {
            Ok(runtimes) => {
                if runtimes.is_empty() {
                    println!("ℹ️ [gyrseek] Docker reports no configured runtimes.");
                } else {
                    println!("ℹ️ [gyrseek] Detected Docker runtimes: {}", runtimes.join(", "));
                }
            }
            Err(e) => {
                println!("❌ [gyrseek] Failed to list Docker runtimes: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }

    let mut scan_cache: HashMap<String, bool> = HashMap::new();
    let runner = match build_runner_from_env() {
        Ok(r) => r,
        Err(e) => {
            println!("❌ [gyrseek] Sandbox initialization failed: {}", e);
            std::process::exit(1);
        }
    };

    if eye.manager == "uv" && eye.passthrough_args.get(1).map(String::as_str) == Some("lock") {
        let upgrade_packages = eye.parse_uv_lock_upgrade_packages();
        let upgrade_all = eye.passthrough_args.iter().any(|arg| arg == "-U" || arg == "--upgrade");

        if !upgrade_packages.is_empty() {
            println!(
                "🛡️ [gyrseek] 'uv lock' update detected. Testing {} target package(s)...",
                upgrade_packages.len()
            );

            let targets: Vec<(String, String)> = upgrade_packages
                .into_iter()
                .map(|pkg_name| (pkg_name, "latest".to_string()))
                .collect();
            if !scan_many_with_cache(
                &mut scan_cache,
                runner.as_ref(),
                &eye.manager,
                targets,
                &ip_allowlist,
                &domain_allowlist,
            )
            .await
            {
                std::process::exit(1);
            }

            println!("\n✅ [gyrseek] Clear behavioral report for uv lock update targets. Forwarding command safely...");
            eye.forward_original_command();
            return;
        }

        if upgrade_all {
            let lock_packages = eye.parse_uv_lock_packages();
            if lock_packages.is_empty() {
                println!(
                    "❌ [gyrseek] 'uv lock --upgrade' detected but no packages found in uv.lock. Failing closed."
                );
                std::process::exit(1);
            }

            println!(
                "🛡️ [gyrseek] 'uv lock --upgrade' detected. Testing {} locked package(s) from uv.lock...",
                lock_packages.len()
            );

            if !scan_many_with_cache(
                &mut scan_cache,
                runner.as_ref(),
                &eye.manager,
                lock_packages,
                &ip_allowlist,
                &domain_allowlist,
            )
            .await
            {
                std::process::exit(1);
            }

            println!("\n✅ [gyrseek] Clear behavioral report for uv lock upgrade set. Forwarding command safely...");
            eye.forward_original_command();
            return;
        }

        eye.forward_original_command();
        return;
    }

    if eye.manager == "poetry"
        && (eye.passthrough_args.get(1).map(String::as_str) == Some("install")
            || eye.passthrough_args.get(1).map(String::as_str) == Some("update"))
    {
        let poetry_cmd = eye.passthrough_args.get(1).map(String::as_str).unwrap_or("install");
        let lock_packages = eye.parse_poetry_lock_packages();
        if lock_packages.is_empty() {
            println!(
                "❌ [gyrseek] 'poetry {}' detected but no packages found in poetry.lock. Failing closed.",
                poetry_cmd
            );
            std::process::exit(1);
        }

        println!(
            "🛡️ [gyrseek] 'poetry {}' detected. Testing {} locked package(s) from poetry.lock...",
            poetry_cmd,
            lock_packages.len()
        );

        if !scan_many_with_cache(
            &mut scan_cache,
            runner.as_ref(),
            &eye.manager,
            lock_packages,
            &ip_allowlist,
            &domain_allowlist,
        )
        .await
        {
            std::process::exit(1);
        }

        println!(
            "\n✅ [gyrseek] Clear behavioral report for poetry lock package set. Forwarding command safely..."
        );
        eye.forward_original_command();
        return;
    }

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

        let targets: Vec<(String, String)> = sync_packages
            .into_iter()
            .map(|(pkg_name, maybe_version)| {
                (pkg_name, maybe_version.unwrap_or_else(|| "latest".to_string()))
            })
            .collect();
        if !scan_many_with_cache(
            &mut scan_cache,
            runner.as_ref(),
            &eye.manager,
            targets,
            &ip_allowlist,
            &domain_allowlist,
        )
        .await
        {
            std::process::exit(1);
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

        if !scan_many_with_cache(
            &mut scan_cache,
            runner.as_ref(),
            &eye.manager,
            lock_packages,
            &ip_allowlist,
            &domain_allowlist,
        )
        .await
        {
            std::process::exit(1);
        }

        println!("\n✅ [gyrseek] Clear behavioral report for all locked packages. Forwarding command safely...");
        eye.forward_original_command();
        return;
    }

    if (eye.manager == "pip" || eye.manager == "pip3")
        && eye.passthrough_args.get(1).map(String::as_str) == Some("install")
    {
        let pip_packages = eye.parse_pip_install_packages();
        if pip_packages.is_empty() {
            println!(
                "❌ [gyrseek] 'pip install' detected but no parseable package entries were found. Failing closed."
            );
            std::process::exit(1);
        }

        println!(
            "🛡️ [gyrseek] '{}' install detected. Testing {} package(s)...",
            eye.manager,
            pip_packages.len()
        );

        let targets: Vec<(String, String)> = pip_packages
            .into_iter()
            .map(|(pkg_name, maybe_version)| {
                (pkg_name, maybe_version.unwrap_or_else(|| "latest".to_string()))
            })
            .collect();
        if !scan_many_with_cache(
            &mut scan_cache,
            runner.as_ref(),
            &eye.manager,
            targets,
            &ip_allowlist,
            &domain_allowlist,
        )
        .await
        {
            std::process::exit(1);
        }

        println!("\n✅ [gyrseek] Clear behavioral report for pip package set. Forwarding command safely...");
        eye.forward_original_command();
        return;
    }

    if eye.manager == "npm"
        && (eye.passthrough_args.get(1).map(String::as_str) == Some("install")
            || eye.passthrough_args.get(1).map(String::as_str) == Some("i")
            || eye.passthrough_args.get(1).map(String::as_str) == Some("update"))
    {
        let npm_packages = eye.parse_npm_install_packages();
        if npm_packages.is_empty() {
            println!(
                "❌ [gyrseek] 'npm {}' detected but no parseable package entries were found. Failing closed.",
                eye.passthrough_args.get(1).map(String::as_str).unwrap_or("install")
            );
            std::process::exit(1);
        }

        println!(
            "🛡️ [gyrseek] '{}' detected. Testing {} package(s)...",
            eye.passthrough_args.get(1).map(String::as_str).unwrap_or("install"),
            npm_packages.len()
        );

        let targets: Vec<(String, String)> = npm_packages
            .into_iter()
            .map(|(pkg_name, maybe_version)| {
                (pkg_name, maybe_version.unwrap_or_else(|| "latest".to_string()))
            })
            .collect();
        if !scan_many_with_cache(
            &mut scan_cache,
            runner.as_ref(),
            &eye.manager,
            targets,
            &ip_allowlist,
            &domain_allowlist,
        )
        .await
        {
            std::process::exit(1);
        }

        println!("\n✅ [gyrseek] Clear behavioral report for npm package set. Forwarding command safely...");
        eye.forward_original_command();
        return;
    }

    let (package, target_v) = eye.parse_package_details();

    if package.is_none() {
        if should_enforce_package_detection(&eye.manager, &eye.passthrough_args) {
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

    if !scan_with_cache(
        &mut scan_cache,
        runner.as_ref(),
        &eye.manager,
        &pkg_name,
        &tgt_version,
        &ip_allowlist,
        &domain_allowlist,
    )
    .await
    {
        std::process::exit(1);
    }

    println!("\n✅ [gyrseek] Clear behavioral report. Forwarding command safely...");
    eye.forward_original_command();
}
