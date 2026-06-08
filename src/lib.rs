mod parsing;
mod sandbox;
mod scanning;

use std::collections::HashMap;
use std::fs;
use std::process::Command;

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

use parsing::{parse_package_details, should_enforce_package_detection};
use sandbox::{build_runner_from_env, list_docker_runtimes, SandboxRunner};
use scanning::{scan_package_versions, scan_packages_versions};

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
) -> bool {
    let key = format!("{}|{}|{}", manager, pkg_name, tgt_version);
    if let Some(cached) = cache.get(&key) {
        println!(
            "🧠 [gyrseek] Cache hit for '{}@{}' in current run.",
            pkg_name, tgt_version
        );
        return *cached;
    }

    let result = scan_package_versions(runner, manager, pkg_name, tgt_version).await;
    cache.insert(key, result);
    result
}

async fn scan_many_with_cache(
    cache: &mut HashMap<String, bool>,
    runner: &dyn SandboxRunner,
    manager: &str,
    targets: Vec<(String, String)>,
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

    let batch_results = scan_packages_versions(runner, manager, &uncached).await;

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
            if !scan_many_with_cache(&mut scan_cache, runner.as_ref(), &eye.manager, targets).await {
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

            if !scan_many_with_cache(&mut scan_cache, runner.as_ref(), &eye.manager, lock_packages).await {
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

        if !scan_many_with_cache(&mut scan_cache, runner.as_ref(), &eye.manager, lock_packages).await {
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
        if !scan_many_with_cache(&mut scan_cache, runner.as_ref(), &eye.manager, targets).await {
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

        if !scan_many_with_cache(&mut scan_cache, runner.as_ref(), &eye.manager, lock_packages).await {
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
        if !scan_many_with_cache(&mut scan_cache, runner.as_ref(), &eye.manager, targets).await {
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
        if !scan_many_with_cache(&mut scan_cache, runner.as_ref(), &eye.manager, targets).await {
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
    )
    .await
    {
        std::process::exit(1);
    }

    println!("\n✅ [gyrseek] Clear behavioral report. Forwarding command safely...");
    eye.forward_original_command();
}
