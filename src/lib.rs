mod parsing;
mod scanning;

use std::fs;
use std::process::Command;

pub use parsing::{
    parse_pip_install_packages_from_args,
    parse_poetry_lock_packages_from_content,
    parse_pylock_packages_from_content,
    parse_requirements_packages_from_content,
    parse_uv_lock_packages_from_content,
};
pub use scanning::find_new_connections;

use parsing::{parse_package_details, should_enforce_package_detection};
use scanning::scan_package_versions;

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
}

pub async fn run(args: Vec<String>) {
    let eye = GyrSeek::new(args);

    if eye.manager == "poetry" && eye.passthrough_args.get(1).map(String::as_str) == Some("install") {
        let lock_packages = eye.parse_poetry_lock_packages();
        if lock_packages.is_empty() {
            println!(
                "❌ [gyrseek] 'poetry install' detected but no packages found in poetry.lock. Failing closed."
            );
            std::process::exit(1);
        }

        println!(
            "🛡️ [gyrseek] 'poetry install' detected. Testing {} locked package(s) from poetry.lock...",
            lock_packages.len()
        );

        for (pkg_name, locked_version) in lock_packages {
            if !scan_package_versions(&eye.manager, &pkg_name, &locked_version).await {
                std::process::exit(1);
            }
        }

        println!("\n✅ [gyrseek] Clear behavioral report for poetry lock package set. Forwarding command safely...");
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

        for (pkg_name, maybe_version) in sync_packages {
            let tgt_version = maybe_version.unwrap_or_else(|| "latest".to_string());
            if !scan_package_versions(&eye.manager, &pkg_name, &tgt_version).await {
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
            if !scan_package_versions(&eye.manager, &pkg_name, &locked_version).await {
                std::process::exit(1);
            }
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

        for (pkg_name, maybe_version) in pip_packages {
            let tgt_version = maybe_version.unwrap_or_else(|| "latest".to_string());
            if !scan_package_versions(&eye.manager, &pkg_name, &tgt_version).await {
                std::process::exit(1);
            }
        }

        println!("\n✅ [gyrseek] Clear behavioral report for pip package set. Forwarding command safely...");
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

    if !scan_package_versions(&eye.manager, &pkg_name, &tgt_version).await {
        std::process::exit(1);
    }

    println!("\n✅ [gyrseek] Clear behavioral report. Forwarding command safely...");
    eye.forward_original_command();
}
