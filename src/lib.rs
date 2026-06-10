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

use parsing::{
    parse_npm_install_packages_from_args, parse_pip_install_packages_from_args,
    parse_poetry_lock_packages_from_content, parse_pylock_packages_from_content,
    parse_requirements_packages_from_content, parse_uv_lock_packages_from_content,
    parse_uv_lock_upgrade_packages_from_args, rewrite_args_with_pinned_versions,
};
use parsing::{parse_package_details, should_enforce_package_detection};
use sandbox::{SandboxRunner, build_runner_from_env, list_docker_runtimes};
use scanning::{PolicyConfig, ScanReport, scan_package_versions, scan_packages_versions};

const DEFAULT_CONFIG_PATH: &str = "gyrseek.yaml";

#[derive(Deserialize, Default)]
struct GyrseekConfig {
    #[serde(default)]
    ip_allowlist: Vec<String>,
    #[serde(default)]
    domain_allowlist: Vec<String>,
    #[serde(default)]
    git_clone_allowlist: Vec<String>,
    #[serde(default)]
    baseline_overrides: HashMap<String, BaselineOverrideConfig>,
    #[serde(default)]
    baseline_count: Option<usize>,
    #[serde(default)]
    min_baseline_age_hours: HashMap<String, usize>,
    #[serde(default)]
    new_package_exemptions: Vec<String>,
    #[serde(default)]
    release_burst_threshold: Option<usize>,
    #[serde(default)]
    release_burst_window_hours: Option<usize>,
    #[serde(default)]
    minimum_release_age_package: Option<usize>,
    #[serde(default)]
    watched_executables: Vec<String>,
    #[serde(default)]
    process_exec_allowlist: Vec<String>,
}

#[derive(Deserialize, Default)]
struct BaselineOverrideConfig {
    #[serde(default, rename = "baseline-1")]
    baseline_1: Option<String>,
    #[serde(default, rename = "baseline-2")]
    baseline_2: Option<String>,
}

fn parse_global_options(args: Vec<String>) -> Result<(Vec<String>, String, bool), String> {
    let mut cfg_path =
        env::var("GYRSEEK_CONFIG").unwrap_or_else(|_| DEFAULT_CONFIG_PATH.to_string());
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

fn load_policy_config(path: &str, explicit: bool) -> Result<PolicyConfig, String> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if !explicit && e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(PolicyConfig::default());
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

    let mut git_clone_allowlist = HashSet::new();
    for entry in cfg.git_clone_allowlist {
        let normalized = entry.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            continue;
        }
        git_clone_allowlist.insert(normalized);
    }

    let mut baseline_overrides = HashMap::new();
    for (package, cfg) in cfg.baseline_overrides {
        let package = package.trim().to_string();
        if package.is_empty() {
            continue;
        }

        let baseline_1 = cfg
            .baseline_1
            .as_ref()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        let baseline_2 = cfg
            .baseline_2
            .as_ref()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());

        if baseline_1.is_some() || baseline_2.is_some() {
            baseline_overrides.insert(package, (baseline_1, baseline_2));
        }
    }

    let baseline_count = match cfg.baseline_count {
        Some(0) => {
            println!("⚠️ [gyrseek] Ignoring invalid baseline_count=0; using default 2");
            2
        }
        Some(v) => v,
        None => 2,
    };

    let mut min_baseline_age_hours = HashMap::new();
    for (package, hours) in cfg.min_baseline_age_hours {
        let package = package.trim().to_string();
        if package.is_empty() {
            continue;
        }
        if hours == 0 {
            println!(
                "⚠️ [gyrseek] Ignoring invalid min_baseline_age_hours for '{}': 0",
                package
            );
            continue;
        }
        min_baseline_age_hours.insert(package, hours);
    }

    let mut new_package_exemptions = HashSet::new();
    for package in cfg.new_package_exemptions {
        let package = package.trim().to_string();
        if package.is_empty() {
            continue;
        }
        new_package_exemptions.insert(package);
    }

    let release_burst_threshold = match cfg.release_burst_threshold {
        Some(0) => {
            println!(
                "⚠️ [gyrseek] Ignoring invalid release_burst_threshold=0; disabling burst checker"
            );
            None
        }
        Some(v) => Some(v),
        None => None,
    };

    let release_burst_window_hours = match cfg.release_burst_window_hours {
        Some(0) => {
            println!(
                "⚠️ [gyrseek] Ignoring invalid release_burst_window_hours=0; using default 24"
            );
            24
        }
        Some(v) => v,
        None => 24,
    };

    let minimum_release_age_package = match cfg.minimum_release_age_package {
        Some(0) => {
            println!(
                "⚠️ [gyrseek] Ignoring invalid minimum_release_age_package=0; disabling minimum release age check"
            );
            None
        }
        Some(v) => Some(v),
        None => None,
    };

    // watched_executables from config are unioned onto the built-in defaults
    // (bun, deno) so the high-value Shai-Hulud runtimes are always watched even
    // if a user only adds their own entries. Normalized to lowercase basenames.
    let mut watched_executables = scanning::default_watched_executables();
    for entry in cfg.watched_executables {
        let normalized = entry.trim().to_ascii_lowercase();
        if !normalized.is_empty() {
            watched_executables.insert(normalized);
        }
    }

    let mut process_exec_allowlist = HashSet::new();
    for entry in cfg.process_exec_allowlist {
        let normalized = entry.trim().to_ascii_lowercase();
        if !normalized.is_empty() {
            process_exec_allowlist.insert(normalized);
        }
    }

    Ok(PolicyConfig {
        ip_allowlist: set,
        domain_allowlist: domain_set,
        git_clone_allowlist,
        baseline_overrides,
        baseline_count,
        min_baseline_age_hours_by_package: min_baseline_age_hours,
        new_package_exemptions,
        release_burst_threshold,
        release_burst_window_hours,
        minimum_release_age_package,
        watched_executables,
        process_exec_allowlist,
    })
}

#[cfg(test)]
mod config_tests {
    use super::{load_policy_config, parse_global_options};
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

        let (manager_args, path, explicit) =
            parse_global_options(args).expect("parse should succeed");
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

    fn load(file: &NamedTempFile) -> super::PolicyConfig {
        load_policy_config(file.path().to_str().expect("path should be utf8"), true)
            .expect("config should parse")
    }

    #[test]
    fn missing_default_config_returns_empty_allowlist() {
        let missing = "gyrseek-config-does-not-exist.yaml";
        let cfg = load_policy_config(missing, false).expect("missing default should be allowed");
        assert!(cfg.ip_allowlist.is_empty());
        assert!(cfg.domain_allowlist.is_empty());
        assert!(cfg.baseline_overrides.is_empty());
        assert_eq!(cfg.baseline_count, 2);
        assert!(cfg.min_baseline_age_hours_by_package.is_empty());
        assert!(cfg.new_package_exemptions.is_empty());
        assert!(cfg.release_burst_threshold.is_none());
        assert_eq!(cfg.release_burst_window_hours, 24);
        assert!(cfg.minimum_release_age_package.is_none());
        assert!(cfg.git_clone_allowlist.is_empty());
    }

    #[test]
    fn missing_explicit_config_fails_closed() {
        let missing = "gyrseek-config-does-not-exist.yaml";
        let err =
            load_policy_config(missing, true).expect_err("explicit config missing should fail");
        assert!(err.contains("Failed to read config file"));
    }

    #[test]
    fn parses_allowlists_and_baseline_overrides() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(
            file,
            "ip_allowlist:\n  - 1.1.1.1\n  - invalid-entry\n  - 8.8.8.8\n  - 2001:0db8:0000:0000:0000:ff00:0042:8329\ndomain_allowlist:\n  -  Example.COM.  \n  - sub.safe.net\nbaseline_overrides:\n  requests:\n    baseline-1: \"2.30.0\"\n    baseline-2: \"2.29.0\"\n  lodash:\n    baseline-1: \"4.17.20\""
        )
        .expect("config should be written");

        let cfg = load(&file);

        assert_eq!(cfg.ip_allowlist.len(), 3);
        assert!(cfg.ip_allowlist.contains("1.1.1.1"));
        assert!(cfg.ip_allowlist.contains("8.8.8.8"));
        assert!(cfg.ip_allowlist.contains("2001:db8::ff00:42:8329"));
        assert!(cfg.domain_allowlist.contains("example.com"));
        assert!(cfg.domain_allowlist.contains("sub.safe.net"));
        assert_eq!(cfg.baseline_overrides.len(), 2);
        assert_eq!(
            cfg.baseline_overrides.get("requests"),
            Some(&(Some("2.30.0".to_string()), Some("2.29.0".to_string())))
        );
        assert_eq!(
            cfg.baseline_overrides.get("lodash"),
            Some(&(Some("4.17.20".to_string()), None))
        );
        assert_eq!(cfg.baseline_count, 2);
        assert!(cfg.min_baseline_age_hours_by_package.is_empty());
        assert!(cfg.new_package_exemptions.is_empty());
        assert!(cfg.release_burst_threshold.is_none());
        assert_eq!(cfg.release_burst_window_hours, 24);
        assert!(cfg.minimum_release_age_package.is_none());
        assert!(cfg.git_clone_allowlist.is_empty());
    }

    #[test]
    fn parses_baseline_count_override_from_config() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(file, "baseline_count: 4").expect("config should be written");
        assert_eq!(load(&file).baseline_count, 4);
    }

    #[test]
    fn parses_per_package_min_baseline_age_hours() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(
            file,
            "min_baseline_age_hours:\n  requests: 6\n  lodash: 12\n  badpkg: 0"
        )
        .expect("config should be written");

        let cfg = load(&file);
        assert_eq!(
            cfg.min_baseline_age_hours_by_package.get("requests"),
            Some(&6)
        );
        assert_eq!(
            cfg.min_baseline_age_hours_by_package.get("lodash"),
            Some(&12)
        );
        assert!(!cfg.min_baseline_age_hours_by_package.contains_key("badpkg"));
    }

    #[test]
    fn parses_new_package_exemptions() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(
            file,
            "new_package_exemptions:\n  - requests\n  - lodash\n  - '  '"
        )
        .expect("config should be written");

        let cfg = load(&file);
        assert!(cfg.new_package_exemptions.contains("requests"));
        assert!(cfg.new_package_exemptions.contains("lodash"));
        assert_eq!(cfg.new_package_exemptions.len(), 2);
    }

    #[test]
    fn parses_release_burst_threshold_override() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(file, "release_burst_threshold: 3").expect("config should be written");

        let cfg = load(&file);
        assert_eq!(cfg.release_burst_threshold, Some(3));
        assert_eq!(cfg.release_burst_window_hours, 24);
        assert!(cfg.minimum_release_age_package.is_none());
        assert!(cfg.git_clone_allowlist.is_empty());
    }

    #[test]
    fn release_burst_threshold_zero_disables_checker() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(file, "release_burst_threshold: 0").expect("config should be written");
        assert!(load(&file).release_burst_threshold.is_none());
    }

    #[test]
    fn baseline_count_zero_falls_back_to_default_two() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(file, "baseline_count: 0").expect("config should be written");
        assert_eq!(load(&file).baseline_count, 2);
    }

    #[test]
    fn trims_package_keys_for_baseline_and_age_policies() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(
            file,
            "baseline_overrides:\n  \"  requests  \":\n    baseline-1: \"2.30.0\"\nmin_baseline_age_hours:\n  \"  requests  \": 6"
        )
        .expect("config should be written");

        let cfg = load(&file);
        assert_eq!(
            cfg.baseline_overrides.get("requests"),
            Some(&(Some("2.30.0".to_string()), None))
        );
        assert_eq!(
            cfg.min_baseline_age_hours_by_package.get("requests"),
            Some(&6)
        );
    }

    #[test]
    fn parses_release_burst_window_hours_override() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(file, "release_burst_window_hours: 12").expect("config should be written");
        assert_eq!(load(&file).release_burst_window_hours, 12);
    }

    #[test]
    fn release_burst_window_hours_zero_falls_back_to_24() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(file, "release_burst_window_hours: 0").expect("config should be written");
        assert_eq!(load(&file).release_burst_window_hours, 24);
    }

    #[test]
    fn parses_minimum_release_age_package_override() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(file, "minimum_release_age_package: 7").expect("config should be written");
        assert_eq!(load(&file).minimum_release_age_package, Some(7));
    }

    #[test]
    fn minimum_release_age_package_zero_disables_policy() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(file, "minimum_release_age_package: 0").expect("config should be written");
        assert!(load(&file).minimum_release_age_package.is_none());
    }

    #[test]
    fn parses_git_clone_allowlist() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(
            file,
            "git_clone_allowlist:\n  - https://github.com/acme/repo.git\n  - '  '"
        )
        .expect("config should be written");

        let cfg = load(&file);
        assert!(
            cfg.git_clone_allowlist
                .contains("https://github.com/acme/repo.git")
        );
        assert_eq!(cfg.git_clone_allowlist.len(), 1);
    }

    // --- gap #12: parse_global_options edge cases ---

    #[test]
    fn config_path_starting_with_dash_is_accepted() {
        // A valid (if unusual) config path that begins with '-' must not be mistaken
        // for a flag and must be forwarded verbatim to load_policy_config.
        let args = vec![
            "--config".to_string(),
            "-relative.yaml".to_string(),
            "npm".to_string(),
            "install".to_string(),
            "pkg".to_string(),
        ];
        let (manager_args, path, explicit) = parse_global_options(args).expect("should parse");
        assert_eq!(path, "-relative.yaml");
        assert!(explicit);
        assert_eq!(manager_args, vec!["npm", "install", "pkg"]);
    }

    #[test]
    fn config_equals_form_preserves_equals_in_path() {
        // --config=path=with=equals.yaml: only the first '=' is the separator.
        let args = vec![
            "--config=path=with=equals.yaml".to_string(),
            "pip".to_string(),
            "install".to_string(),
            "requests".to_string(),
        ];
        let (manager_args, path, explicit) = parse_global_options(args).expect("should parse");
        assert_eq!(path, "path=with=equals.yaml");
        assert!(explicit);
        assert_eq!(manager_args, vec!["pip", "install", "requests"]);
    }
}

pub struct GyrSeek {
    passthrough_args: Vec<String>,
    manager: String,
}

struct NoopRunner;

impl SandboxRunner for NoopRunner {
    fn trace_install(
        &self,
        _manager: &str,
        _package: &str,
        _version: &str,
    ) -> Result<String, String> {
        Err("noop runner invoked".to_string())
    }
}

impl GyrSeek {
    pub(crate) fn new(args: Vec<String>) -> Self {
        let manager = args.first().cloned().unwrap_or_default();
        Self {
            passthrough_args: args,
            manager,
        }
    }

    pub(crate) fn parse_package_details(&self) -> (Option<String>, Option<String>) {
        parse_package_details(&self.manager, &self.passthrough_args)
    }

    /// Executes the user's raw host operation transparently.
    pub(crate) fn forward_original_command(&self) {
        self.forward_args(&self.passthrough_args);
    }

    /// Forwards the install command, but rewrites the version specifiers of the
    /// named packages to the exact versions the scanner resolved and examined.
    /// This closes the gap where an unpinned `install foo` is scanned at one
    /// version while the host manager would otherwise resolve a different one.
    pub(crate) fn forward_pinned_command(&self, pins: &HashMap<String, String>) {
        let pinned = rewrite_args_with_pinned_versions(&self.manager, &self.passthrough_args, pins);
        self.forward_args(&pinned);
    }

    fn forward_args(&self, args: &[String]) {
        if args.is_empty() {
            return;
        }

        match Command::new(&self.manager).args(&args[1..]).spawn() {
            Ok(mut child) => {
                // Propagate the host manager's exit status. Discarding it makes a
                // failed install (e.g. version-not-found) look successful to the
                // caller — misleading agents and breaking any CI step that checks
                // `$?` after a gyrseek-wrapped command.
                match child.wait() {
                    Ok(status) if status.success() => {}
                    Ok(status) => std::process::exit(status.code().unwrap_or(1)),
                    Err(e) => {
                        println!(
                            "❌ [gyrseek] Failed to wait on host command '{}': {}",
                            self.manager, e
                        );
                        std::process::exit(1);
                    }
                }
            }
            Err(e) => {
                // Fail closed: if we can't even launch the host command, don't
                // pretend the operation succeeded.
                println!(
                    "❌ [gyrseek] Failed to execute host command '{}': {}",
                    self.manager, e
                );
                std::process::exit(1);
            }
        }
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
    cache: &mut HashMap<String, ScanReport>,
    runner: &dyn SandboxRunner,
    manager: &str,
    pkg_name: &str,
    tgt_version: &str,
    policy: &PolicyConfig,
) -> ScanReport {
    let key = format!("{}|{}|{}", manager, pkg_name, tgt_version);
    if let Some(cached) = cache.get(&key) {
        println!(
            "🧠 [gyrseek] Cache hit for '{}@{}' in current run.",
            pkg_name, tgt_version
        );
        return cached.clone();
    }

    let result = scan_package_versions(runner, manager, pkg_name, tgt_version, policy).await;
    cache.insert(key, result.clone());
    result
}

/// Scans a batch of targets. On success returns the resolved-version pins
/// (requested package name -> concrete version actually examined) so callers
/// can pin the forwarded command. Returns `None` if any target is blocked.
async fn scan_many_with_cache(
    cache: &mut HashMap<String, ScanReport>,
    runner: &dyn SandboxRunner,
    manager: &str,
    targets: Vec<(String, String)>,
    policy: &PolicyConfig,
) -> Option<HashMap<String, String>> {
    let mut pins: HashMap<String, String> = HashMap::new();
    let mut uncached: Vec<(String, String)> = Vec::new();

    for (pkg_name, tgt_version) in targets {
        let key = format!("{}|{}|{}", manager, pkg_name, tgt_version);
        if let Some(cached) = cache.get(&key) {
            println!(
                "🧠 [gyrseek] Cache hit for '{}@{}' in current run.",
                pkg_name, tgt_version
            );
            if !cached.allowed {
                return None;
            }
            pins.insert(pkg_name, cached.resolved_version.clone());
            continue;
        }
        uncached.push((pkg_name, tgt_version));
    }

    if uncached.is_empty() {
        return Some(pins);
    }

    let batch_results = scan_packages_versions(runner, manager, &uncached, policy).await;

    for (pkg_name, tgt_version) in uncached {
        let report = batch_results
            .get(&format!("{}|{}", pkg_name, tgt_version))
            .cloned()
            .unwrap_or_else(|| ScanReport {
                allowed: false,
                resolved_version: tgt_version.clone(),
            });
        let key = format!("{}|{}|{}", manager, pkg_name, tgt_version);
        cache.insert(key, report.clone());
        if !report.allowed {
            return None;
        }
        pins.insert(pkg_name, report.resolved_version);
    }

    Some(pins)
}

pub async fn run(args: Vec<String>) {
    let (args, config_path, config_explicit) = match parse_global_options(args) {
        Ok(v) => v,
        Err(e) => {
            println!("❌ [gyrseek] {}", e);
            std::process::exit(1);
        }
    };

    let policy = match load_policy_config(&config_path, config_explicit) {
        Ok(v) => v,
        Err(e) => {
            println!("❌ [gyrseek] {}", e);
            std::process::exit(1);
        }
    };

    if !policy.ip_allowlist.is_empty() {
        println!(
            "ℹ️ [gyrseek] Loaded {} allowlisted IP(s) from {}",
            policy.ip_allowlist.len(),
            config_path
        );
    }
    if !policy.domain_allowlist.is_empty() {
        println!(
            "ℹ️ [gyrseek] Loaded {} allowlisted domain(s) from {}",
            policy.domain_allowlist.len(),
            config_path
        );
    }
    if !policy.git_clone_allowlist.is_empty() {
        println!(
            "ℹ️ [gyrseek] Loaded {} allowlisted git clone target(s) from {}",
            policy.git_clone_allowlist.len(),
            config_path
        );
    }
    if !policy.baseline_overrides.is_empty() {
        println!(
            "ℹ️ [gyrseek] Loaded {} baseline override package(s) from {}",
            policy.baseline_overrides.len(),
            config_path
        );
    }
    println!(
        "ℹ️ [gyrseek] Using baseline_count={}",
        policy.baseline_count
    );
    if !policy.min_baseline_age_hours_by_package.is_empty() {
        println!(
            "ℹ️ [gyrseek] Loaded per-package min_baseline_age_hours for {} package(s)",
            policy.min_baseline_age_hours_by_package.len()
        );
    }
    if !policy.new_package_exemptions.is_empty() {
        println!(
            "ℹ️ [gyrseek] Loaded new package exemptions for {} package(s)",
            policy.new_package_exemptions.len()
        );
    }
    if let Some(threshold) = policy.release_burst_threshold {
        println!(
            "ℹ️ [gyrseek] Release burst checker enabled (threshold={} releases/{}h)",
            threshold, policy.release_burst_window_hours
        );
    }
    if let Some(days) = policy.minimum_release_age_package {
        println!(
            "ℹ️ [gyrseek] Minimum release age policy enabled (minimum_release_age_package={} day(s))",
            days
        );
    }

    let eye = GyrSeek::new(args);

    // Fail closed for unrecognized managers. gyrseek's contract is "I scanned
    // this before forwarding it" — silently forwarding an unscanned command
    // violates that contract and provides false assurance in a security pipeline.
    // The only built-in exception is the `sandbox runtimes` diagnostic subcommand.
    const SUPPORTED_MANAGERS: &[&str] = &["pip", "pip3", "uv", "poetry", "npm"];
    let is_sandbox_runtimes = eye.manager == "sandbox"
        && eye.passthrough_args.get(1).map(String::as_str) == Some("runtimes");
    if !SUPPORTED_MANAGERS.contains(&eye.manager.as_str()) && !is_sandbox_runtimes {
        println!(
            "❌ [gyrseek] Unrecognized manager '{}'. Supported managers: {}. Failing closed.",
            eye.manager,
            SUPPORTED_MANAGERS.join(", ")
        );
        std::process::exit(1);
    }

    if is_sandbox_runtimes {
        match list_docker_runtimes() {
            Ok(runtimes) => {
                if runtimes.is_empty() {
                    println!("ℹ️ [gyrseek] Docker reports no configured runtimes.");
                } else {
                    println!(
                        "ℹ️ [gyrseek] Detected Docker runtimes: {}",
                        runtimes.join(", ")
                    );
                }
            }
            Err(e) => {
                println!("❌ [gyrseek] Failed to list Docker runtimes: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }

    let mut scan_cache: HashMap<String, ScanReport> = HashMap::new();
    let runner = if env::var("GYRSEEK_TEST_BYPASS_RUNNER_INIT").ok().as_deref() == Some("1") {
        Box::new(NoopRunner) as Box<dyn SandboxRunner>
    } else {
        match build_runner_from_env() {
            Ok(r) => r,
            Err(e) => {
                println!("❌ [gyrseek] Sandbox initialization failed: {}", e);
                std::process::exit(1);
            }
        }
    };

    if eye.manager == "uv" && eye.passthrough_args.get(1).map(String::as_str) == Some("lock") {
        let upgrade_packages = eye.parse_uv_lock_upgrade_packages();
        let upgrade_all = eye
            .passthrough_args
            .iter()
            .any(|arg| arg == "-U" || arg == "--upgrade");

        if !upgrade_packages.is_empty() {
            println!(
                "🛡️ [gyrseek] 'uv lock' update detected. Testing {} target package(s)...",
                upgrade_packages.len()
            );

            let targets: Vec<(String, String)> = upgrade_packages
                .into_iter()
                .map(|pkg_name| (pkg_name, "latest".to_string()))
                .collect();
            if scan_many_with_cache(
                &mut scan_cache,
                runner.as_ref(),
                &eye.manager,
                targets,
                &policy,
            )
            .await
            .is_none()
            {
                std::process::exit(1);
            }

            println!(
                "\n✅ [gyrseek] Clear behavioral report for uv lock update targets. Forwarding command safely..."
            );
            eye.forward_original_command();
            return;
        }

        let lock_packages = eye.parse_uv_lock_packages();
        if lock_packages.is_empty() {
            println!(
                "❌ [gyrseek] 'uv lock' detected but no packages found in uv.lock. Failing closed."
            );
            std::process::exit(1);
        }

        let lock_label = if upgrade_all {
            "uv lock --upgrade"
        } else {
            "uv lock"
        };
        println!(
            "🛡️ [gyrseek] '{}' detected. Testing {} locked package(s) from uv.lock...",
            lock_label,
            lock_packages.len()
        );

        if scan_many_with_cache(
            &mut scan_cache,
            runner.as_ref(),
            &eye.manager,
            lock_packages,
            &policy,
        )
        .await
        .is_none()
        {
            std::process::exit(1);
        }

        println!(
            "\n✅ [gyrseek] Clear behavioral report for uv lock package set. Forwarding command safely..."
        );
        eye.forward_original_command();
        return;
    }

    if eye.manager == "poetry"
        && (eye.passthrough_args.get(1).map(String::as_str) == Some("install")
            || eye.passthrough_args.get(1).map(String::as_str) == Some("update")
            || eye.passthrough_args.get(1).map(String::as_str) == Some("lock"))
    {
        let poetry_cmd = eye
            .passthrough_args
            .get(1)
            .map(String::as_str)
            .unwrap_or("install");
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

        if scan_many_with_cache(
            &mut scan_cache,
            runner.as_ref(),
            &eye.manager,
            lock_packages,
            &policy,
        )
        .await
        .is_none()
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
                (
                    pkg_name,
                    maybe_version.unwrap_or_else(|| "latest".to_string()),
                )
            })
            .collect();
        if scan_many_with_cache(
            &mut scan_cache,
            runner.as_ref(),
            &eye.manager,
            targets,
            &policy,
        )
        .await
        .is_none()
        {
            std::process::exit(1);
        }

        println!(
            "\n✅ [gyrseek] Clear behavioral report for sync package set. Forwarding command safely..."
        );
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

        if scan_many_with_cache(
            &mut scan_cache,
            runner.as_ref(),
            &eye.manager,
            lock_packages,
            &policy,
        )
        .await
        .is_none()
        {
            std::process::exit(1);
        }

        println!(
            "\n✅ [gyrseek] Clear behavioral report for all locked packages. Forwarding command safely..."
        );
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
                (
                    pkg_name,
                    maybe_version.unwrap_or_else(|| "latest".to_string()),
                )
            })
            .collect();
        let pins = match scan_many_with_cache(
            &mut scan_cache,
            runner.as_ref(),
            &eye.manager,
            targets,
            &policy,
        )
        .await
        {
            Some(pins) => pins,
            None => std::process::exit(1),
        };

        println!(
            "\n✅ [gyrseek] Clear behavioral report for pip package set. Forwarding command safely..."
        );
        eye.forward_pinned_command(&pins);
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
                eye.passthrough_args
                    .get(1)
                    .map(String::as_str)
                    .unwrap_or("install")
            );
            std::process::exit(1);
        }

        println!(
            "🛡️ [gyrseek] '{}' detected. Testing {} package(s)...",
            eye.passthrough_args
                .get(1)
                .map(String::as_str)
                .unwrap_or("install"),
            npm_packages.len()
        );

        let targets: Vec<(String, String)> = npm_packages
            .into_iter()
            .map(|(pkg_name, maybe_version)| {
                (
                    pkg_name,
                    maybe_version.unwrap_or_else(|| "latest".to_string()),
                )
            })
            .collect();
        let pins = match scan_many_with_cache(
            &mut scan_cache,
            runner.as_ref(),
            &eye.manager,
            targets,
            &policy,
        )
        .await
        {
            Some(pins) => pins,
            None => std::process::exit(1),
        };

        println!(
            "\n✅ [gyrseek] Clear behavioral report for npm package set. Forwarding command safely..."
        );
        eye.forward_pinned_command(&pins);
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

    let report = scan_with_cache(
        &mut scan_cache,
        runner.as_ref(),
        &eye.manager,
        &pkg_name,
        &tgt_version,
        &policy,
    )
    .await;

    if !report.allowed {
        std::process::exit(1);
    }

    println!("\n✅ [gyrseek] Clear behavioral report. Forwarding command safely...");
    let pins = HashMap::from([(pkg_name, report.resolved_version)]);
    eye.forward_pinned_command(&pins);
}

#[cfg(test)]
mod gyrseek_tests {
    use super::GyrSeek;

    // ---------------------------------------------------------------------------
    // GyrSeek::parse_package_details tests (moved from tests/parser_tests.rs)
    // ---------------------------------------------------------------------------

    #[test]
    fn parses_uv_add_as_latest_when_unpinned() {
        let eye = GyrSeek::new(vec![
            "uv".to_string(),
            "add".to_string(),
            "pytest".to_string(),
        ]);
        let (pkg, version) = eye.parse_package_details();
        assert_eq!(pkg.as_deref(), Some("pytest"));
        assert_eq!(version, None);
    }

    #[test]
    fn parses_uv_pip_install_with_pinned_version() {
        let eye = GyrSeek::new(vec![
            "uv".to_string(),
            "pip".to_string(),
            "install".to_string(),
            "requests==2.31.0".to_string(),
        ]);
        let (pkg, version) = eye.parse_package_details();
        assert_eq!(pkg.as_deref(), Some("requests"));
        assert_eq!(version.as_deref(), Some("2.31.0"));
    }

    #[test]
    fn parses_poetry_update_as_latest_when_unpinned() {
        let eye = GyrSeek::new(vec![
            "poetry".to_string(),
            "update".to_string(),
            "pytest".to_string(),
        ]);
        let (pkg, version) = eye.parse_package_details();
        assert_eq!(pkg.as_deref(), Some("pytest"));
        assert_eq!(version, None);
    }

    #[test]
    fn ignores_non_install_commands() {
        let eye = GyrSeek::new(vec![
            "uv".to_string(),
            "run".to_string(),
            "script.py".to_string(),
        ]);
        let (pkg, version) = eye.parse_package_details();
        assert_eq!(pkg, None);
        assert_eq!(version, None);
    }

    #[test]
    fn parses_npm_install_as_latest_when_unpinned() {
        let eye = GyrSeek::new(vec![
            "npm".to_string(),
            "install".to_string(),
            "lodash".to_string(),
        ]);
        let (pkg, version) = eye.parse_package_details();
        assert_eq!(pkg.as_deref(), Some("lodash"));
        assert_eq!(version, None);
    }

    #[test]
    fn parses_npm_install_with_pinned_version() {
        let eye = GyrSeek::new(vec![
            "npm".to_string(),
            "install".to_string(),
            "lodash@4.17.21".to_string(),
        ]);
        let (pkg, version) = eye.parse_package_details();
        assert_eq!(pkg.as_deref(), Some("lodash"));
        assert_eq!(version.as_deref(), Some("4.17.21"));
    }

    #[test]
    fn uv_sync_has_no_single_package_target() {
        let eye = GyrSeek::new(vec!["uv".to_string(), "sync".to_string()]);
        let (pkg, version) = eye.parse_package_details();
        assert_eq!(pkg, None);
        assert_eq!(version, None);
    }
}
