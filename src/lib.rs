mod parsing;
mod sandbox;
mod scanning;

use std::collections::HashMap;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::net::IpAddr;
use std::process::Command;

use serde::{Deserialize, Deserializer};

use parsing::{
    parse_npm_install_packages_from_args, parse_pip_install_packages_from_args,
    parse_poetry_lock_packages_from_content, parse_pylock_packages_from_content,
    parse_requirements_packages_from_content, parse_uv_lock_packages_from_content,
    parse_uv_lock_upgrade_packages_from_args, rewrite_args_with_pinned_versions,
};
use parsing::{parse_package_details, should_enforce_package_detection};
use sandbox::{SandboxRunner, build_runner_from_env, list_docker_runtimes};
use scanning::{
    HARD_MINIMUM_AGE_HOURS, PolicyConfig, ScanReport, scan_package_versions, scan_packages_versions,
};

const DEFAULT_CONFIG_PATH: &str = "gyrseek.yaml";

fn deserialize_new_package_exemptions<'de, D>(d: D) -> Result<HashMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum NewPkgExemptions {
        Map(HashMap<String, String>),
        #[allow(dead_code)]
        InvalidMap(HashMap<String, serde_yaml::Value>),
        #[allow(dead_code)]
        List(Vec<String>),
        Null,
    }

    match NewPkgExemptions::deserialize(d)? {
        NewPkgExemptions::Map(m) => Ok(m),
        NewPkgExemptions::InvalidMap(_) => Err(serde::de::Error::custom(
            "Values in 'new_package_exemptions' must be strings (e.g. 'requests: \"1.0.0\"'). Found a non-string value.",
        )),
        NewPkgExemptions::List(v) if v.is_empty() => Ok(HashMap::new()),
        NewPkgExemptions::List(_) => Err(serde::de::Error::custom(
            "The 'new_package_exemptions' list format (e.g. '- pkg') is no longer supported. Use the map format: 'pkg: \"<version>\"'.",
        )),
        NewPkgExemptions::Null => Ok(HashMap::new()),
    }
}

/// One element of a mixed allowlist sequence: either a bare global entry or a
/// single-key map `{pkg_name: [entries]}` scoping the entries to one package.
#[derive(Deserialize)]
#[serde(untagged)]
enum AllowlistEntry {
    Global(String),
    PerPackage(HashMap<String, Vec<String>>),
}

#[derive(Deserialize, Default)]
struct GyrseekConfig {
    #[serde(default)]
    ip_allowlist: Vec<AllowlistEntry>,
    #[serde(default)]
    domain_allowlist: Vec<AllowlistEntry>,
    #[serde(default)]
    git_clone_allowlist: HashMap<String, Vec<String>>,
    #[serde(default)]
    baseline_overrides: HashMap<String, BaselineOverrideConfig>,
    #[serde(default)]
    baseline_count: Option<usize>,
    #[serde(default)]
    min_baseline_age_hours: HashMap<String, i64>,
    #[serde(default, deserialize_with = "deserialize_new_package_exemptions")]
    new_package_exemptions: HashMap<String, String>,
    #[serde(default)]
    internal_package_exemptions: Vec<String>,
    #[serde(default)]
    release_burst_threshold: Option<usize>,
    #[serde(default)]
    release_burst_window_hours: Option<usize>,
    #[serde(default)]
    minimum_release_age_package: Option<usize>,
    #[serde(default)]
    process_exec_allowlist: HashMap<String, Vec<String>>,
    #[serde(default)]
    artifact_allowlist: HashMap<String, Vec<String>>,
    #[serde(default)]
    sensitive_file_access_allowlist: HashMap<String, Vec<String>>,
}

#[derive(Deserialize, Default)]
struct BaselineOverrideConfig {
    #[serde(default, rename = "baseline-1")]
    baseline_1: Option<String>,
    #[serde(default, rename = "baseline-2")]
    baseline_2: Option<String>,
}

fn parse_global_options(args: Vec<String>) -> Result<(Vec<String>, String, bool, bool), String> {
    if env::var("GYRSEEK_DOCKER_SECCOMP_PROFILE").is_ok() {
        eprintln!(
            "⚠️ [gyrseek] Warning: GYRSEEK_DOCKER_SECCOMP_PROFILE is deprecated and ignored. Use --danger-disable-seccomp instead."
        );
    }

    let mut cfg_path =
        env::var("GYRSEEK_CONFIG").unwrap_or_else(|_| DEFAULT_CONFIG_PATH.to_string());
    let mut cfg_explicit = env::var("GYRSEEK_CONFIG").is_ok();

    let danger_disable_seccomp = args.iter().any(|arg| arg == "--danger-disable-seccomp");
    let mut filtered_args = Vec::with_capacity(args.len());
    for arg in args {
        if arg != "--danger-disable-seccomp" {
            filtered_args.push(arg);
        }
    }
    let args = filtered_args;

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

    Ok((
        args[idx..].to_vec(),
        cfg_path,
        cfg_explicit,
        danger_disable_seccomp,
    ))
}

fn parse_list(items: Vec<String>, lowercase: bool) -> HashSet<String> {
    items
        .into_iter()
        .map(|e| {
            if lowercase {
                e.trim().to_ascii_lowercase()
            } else {
                e.trim().to_string()
            }
        })
        .filter(|e| !e.is_empty())
        .collect()
}

/// Validates a per-package allowlist map key: trims whitespace, rejects blank
/// and reserved `"*"` keys (with warnings), and warns on whitespace-variant
/// collisions. Returns `Some(trimmed_key)` if valid, `None` to skip the entry.
fn validate_allowlist_pkg_key(
    pkg_raw: &str,
    allowlist_name: &str,
    existing: &HashMap<String, HashSet<String>>,
    has_global_variant: bool,
) -> Option<String> {
    let pkg = pkg_raw.trim().to_string();
    if pkg.is_empty() {
        println!("⚠️ [gyrseek] Ignoring {allowlist_name} entry with blank package name");
        return None;
    }
    if pkg == "*" {
        if has_global_variant {
            println!(
                "⚠️ [gyrseek] Ignoring {allowlist_name} per-package entry with reserved key \"*\"; use a bare global entry instead. Per-package entries are additive to global entries — global entries already apply to all packages."
            );
        } else {
            println!(
                "⚠️ [gyrseek] Ignoring {allowlist_name} entry with reserved key \"*\"; this allowlist does not support a global wildcard — use a specific package name"
            );
        }
        return None;
    }
    if pkg != pkg_raw && existing.contains_key(&pkg) {
        println!(
            "⚠️ [gyrseek] {allowlist_name} key {:?} trimmed to {:?} which already has entries; merging (check for duplicate/whitespace-variant keys)",
            pkg_raw, pkg
        );
    }
    Some(pkg)
}

/// Maps `Some(0)` → `None` with a warning, passes other `Some(v)` through,
/// and maps `None` → `None`. Used for optional config fields where 0 disables
/// the feature and should warn rather than silently no-op.
fn option_zero_to_none(val: Option<usize>, warn_msg: &str) -> Option<usize> {
    match val {
        Some(0) => {
            println!("⚠️ [gyrseek] {}", warn_msg);
            None
        }
        other => other,
    }
}

fn parse_list_map(
    map: HashMap<String, Vec<String>>,
    lowercase: bool,
    name: &str,
) -> HashMap<String, HashSet<String>> {
    let mut result: HashMap<String, HashSet<String>> = HashMap::new();
    for (package_raw, items) in map {
        let Some(package) = validate_allowlist_pkg_key(&package_raw, name, &result, false) else {
            continue;
        };
        let list = parse_list(items, lowercase);
        if list.is_empty() {
            println!(
                "⚠️ [gyrseek] {name} package key {:?} has no valid entries; no allowlist protection will be applied for this package",
                package
            );
        } else {
            result.entry(package).or_default().extend(list);
        }
    }
    result
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

    let mut ip_allowlist: HashMap<String, HashSet<String>> = HashMap::new();
    for entry in cfg.ip_allowlist {
        match entry {
            AllowlistEntry::Global(s) => match s.parse::<IpAddr>() {
                Ok(_) => {
                    ip_allowlist
                        .entry("*".to_string())
                        .or_default()
                        .insert(scanning::normalize_ip_string(&s));
                }
                Err(_) => {
                    println!(
                        "⚠️ [gyrseek] Ignoring invalid ip_allowlist entry (not an IP): {}",
                        s
                    );
                }
            },
            AllowlistEntry::PerPackage(map) => {
                for (pkg_raw, ips) in map {
                    let Some(pkg) =
                        validate_allowlist_pkg_key(&pkg_raw, "ip_allowlist", &ip_allowlist, true)
                    else {
                        continue;
                    };
                    let set = ip_allowlist.entry(pkg.clone()).or_default();
                    for s in ips {
                        match s.parse::<IpAddr>() {
                            Ok(_) => {
                                set.insert(scanning::normalize_ip_string(&s));
                            }
                            Err(_) => {
                                println!(
                                    "⚠️ [gyrseek] Ignoring invalid ip_allowlist entry '{}' for package '{}'",
                                    s, pkg
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    let mut domain_allowlist: HashMap<String, HashSet<String>> = HashMap::new();
    for entry in cfg.domain_allowlist {
        match entry {
            AllowlistEntry::Global(s) => {
                let normalized = s.trim().trim_end_matches('.').to_ascii_lowercase();
                if normalized == "*" {
                    println!(
                        "⚠️ [gyrseek] Ignoring overly permissive domain_allowlist entry: \"*\" does not match any domain. Use exact domain names (e.g. 'pypi.org') or remove this entry."
                    );
                } else if normalized.is_empty() {
                    println!("⚠️ [gyrseek] Ignoring blank domain_allowlist entry");
                } else if !normalized.contains('.') {
                    println!(
                        "⚠️ [gyrseek] Ignoring domain_allowlist entry {:?}: a bare label without a dot would match all subdomains of any TLD. Use a fully-qualified domain (e.g. 'pypi.org').",
                        s.trim()
                    );
                } else {
                    domain_allowlist
                        .entry("*".to_string())
                        .or_default()
                        .insert(normalized);
                }
            }
            AllowlistEntry::PerPackage(map) => {
                for (pkg_raw, domains) in map {
                    let Some(pkg) = validate_allowlist_pkg_key(
                        &pkg_raw,
                        "domain_allowlist",
                        &domain_allowlist,
                        true,
                    ) else {
                        continue;
                    };
                    let set = domain_allowlist.entry(pkg.clone()).or_default();
                    for s in domains {
                        let normalized = s.trim().trim_end_matches('.').to_ascii_lowercase();
                        if normalized == "*" {
                            println!(
                                "⚠️ [gyrseek] Ignoring overly permissive domain_allowlist entry \"*\" for package '{}': does not match any domain. Use exact domain names (e.g. 'pypi.org') or remove this entry.",
                                pkg
                            );
                        } else if normalized.is_empty() {
                            println!(
                                "⚠️ [gyrseek] Ignoring blank domain_allowlist entry for package '{}'",
                                pkg
                            );
                        } else if !normalized.contains('.') {
                            println!(
                                "⚠️ [gyrseek] Ignoring domain_allowlist entry {:?} for package '{}': a bare label without a dot would match all subdomains of any TLD. Use a fully-qualified domain (e.g. 'pypi.org').",
                                s.trim(),
                                pkg
                            );
                        } else {
                            set.insert(normalized);
                        }
                    }
                }
            }
        }
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
    for (package, mut hours) in cfg.min_baseline_age_hours {
        let package = package.trim().to_string();
        if package.is_empty() {
            continue;
        }
        if hours < HARD_MINIMUM_AGE_HOURS {
            println!(
                "⚠️ [gyrseek] Warning: min_baseline_age_hours for '{}' is set to {} hours, which is below the hardcoded security floor. Automatically raising it to {} hours.",
                package, hours, HARD_MINIMUM_AGE_HOURS
            );
            hours = HARD_MINIMUM_AGE_HOURS;
        }
        min_baseline_age_hours.insert(package, hours);
    }

    let new_package_exemptions: HashMap<String, String> = cfg
        .new_package_exemptions
        .into_iter()
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .filter(|(k, v)| {
            if k.is_empty() {
                return false;
            }
            if v.is_empty() {
                println!(
                    "⚠️ [gyrseek] Warning: new_package_exemption for '{}' has an empty version. \
                     This exemption will never match and has been removed. \
                     Specify a version: '{}: \"<version>\"' in your configuration.",
                    k, k
                );
                return false;
            }
            true
        })
        .collect();
    let internal_package_exemptions = parse_list(cfg.internal_package_exemptions, false);

    let release_burst_threshold = option_zero_to_none(
        cfg.release_burst_threshold,
        "Ignoring invalid release_burst_threshold=0; disabling burst checker",
    );

    let release_burst_window_hours = option_zero_to_none(
        cfg.release_burst_window_hours,
        "Ignoring invalid release_burst_window_hours=0; using default 24",
    )
    .unwrap_or(24);

    let minimum_release_age_package = option_zero_to_none(
        cfg.minimum_release_age_package,
        "Ignoring invalid minimum_release_age_package=0; disabling minimum release age check",
    );

    let process_exec_allowlist =
        parse_list_map(cfg.process_exec_allowlist, true, "process_exec_allowlist");
    let artifact_allowlist = parse_list_map(cfg.artifact_allowlist, false, "artifact_allowlist");
    let mut sensitive_file_access_allowlist = parse_list_map(
        cfg.sensitive_file_access_allowlist,
        false,
        "sensitive_file_access_allowlist",
    );
    for (pkg, entries) in sensitive_file_access_allowlist.iter_mut() {
        entries.retain(|v| {
            let t = v.trim();
            if t == "*" || t == "/" || t == "*/" || t == "/*" {
                println!(
                    "⚠️ [gyrseek] Ignoring overly permissive sensitive_file_access_allowlist entry '{}' for package '{}'",
                    v, pkg
                );
                false
            } else {
                true
            }
        });
    }
    sensitive_file_access_allowlist.retain(|pkg, entries| {
        if entries.is_empty() {
            println!(
                "⚠️ [gyrseek] sensitive_file_access_allowlist package '{}' has no valid entries after filtering; no allowlist protection will be applied",
                pkg
            );
            false
        } else {
            true
        }
    });
    let git_clone_allowlist = parse_list_map(cfg.git_clone_allowlist, true, "git_clone_allowlist");

    Ok(PolicyConfig {
        ip_allowlist,
        domain_allowlist,
        git_clone_allowlist,
        baseline_overrides,
        baseline_count,
        min_baseline_age_hours_by_package: min_baseline_age_hours,
        new_package_exemptions,
        internal_package_exemptions,
        release_burst_threshold,
        release_burst_window_hours,
        minimum_release_age_package,
        process_exec_allowlist,
        artifact_allowlist,
        sensitive_file_access_allowlist,
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

        let (manager_args, cfg_path, cfg_explicit, _) =
            parse_global_options(args).expect("parse should succeed");
        assert_eq!(manager_args, vec!["npm", "install", "lodash"]);
        assert_eq!(cfg_path, "my-policy.yaml");
        assert!(cfg_explicit);
    }

    #[test]
    fn keeps_args_untouched_when_no_global_options_present() {
        let args = vec!["uv".to_string(), "sync".to_string()];
        let (manager_args, _, _, _) = parse_global_options(args).expect("parse should succeed");
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

        let global_ips = cfg
            .ip_allowlist
            .get("*")
            .expect("global ip_allowlist entry");
        assert_eq!(global_ips.len(), 3);
        assert!(global_ips.contains("1.1.1.1"));
        assert!(global_ips.contains("8.8.8.8"));
        assert!(global_ips.contains("2001:db8::ff00:42:8329"));
        let global_domains = cfg
            .domain_allowlist
            .get("*")
            .expect("global domain_allowlist entry");
        assert!(global_domains.contains("example.com"));
        assert!(global_domains.contains("sub.safe.net"));
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
    fn parses_per_package_ip_and_domain_allowlist() {
        let yaml = "ip_allowlist:\n  - 1.1.1.1\n  - requests:\n    - 5.6.7.8\n  - boto3:\n    - 9.10.11.12\ndomain_allowlist:\n  - global.example.com\n  - requests:\n    - api.requests-cdn.net\n";
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(file, "{}", yaml).expect("config should be written");
        let cfg = load(&file);

        let global_ips = cfg.ip_allowlist.get("*").expect("global ips");
        assert_eq!(global_ips.len(), 1);
        assert!(global_ips.contains("1.1.1.1"));

        let requests_ips = cfg.ip_allowlist.get("requests").expect("requests ips");
        assert!(requests_ips.contains("5.6.7.8"));

        let boto3_ips = cfg.ip_allowlist.get("boto3").expect("boto3 ips");
        assert!(boto3_ips.contains("9.10.11.12"));

        // requests per-package IP must not appear in global or boto3 entries
        assert!(!global_ips.contains("5.6.7.8"));
        assert!(!boto3_ips.contains("5.6.7.8"));

        let global_domains = cfg.domain_allowlist.get("*").expect("global domains");
        assert!(global_domains.contains("global.example.com"));

        let requests_domains = cfg
            .domain_allowlist
            .get("requests")
            .expect("requests domains");
        assert!(requests_domains.contains("api.requests-cdn.net"));
        assert!(!global_domains.contains("api.requests-cdn.net"));
    }

    #[test]
    fn ip_allowlist_config_load_normalizes_ipv4_mapped_ipv6() {
        // Fix #305 collapses ::ffff:x.x.x.x → bare IPv4 at config-load time.
        // This test exercises the glue between load_policy_config and
        // normalize_ip_string — a regression would store raw ::ffff: forms,
        // causing bare-IPv4 connection IPs to miss the allowlist.
        let yaml = concat!(
            "ip_allowlist:\n",
            "  - \"::ffff:203.0.113.5\"\n", // global IPv4-mapped
            "  - requests:\n",
            "    - \"::ffff:198.51.100.1\"\n", // per-package IPv4-mapped
        );
        let mut file = NamedTempFile::new().expect("temp file");
        writeln!(file, "{}", yaml).expect("write");
        let cfg = load(&file);

        let global = cfg.ip_allowlist.get("*").expect("global bucket");
        assert!(
            global.contains("203.0.113.5"),
            "global ::ffff:203.0.113.5 must be stored as bare IPv4"
        );
        assert!(
            !global.contains("::ffff:203.0.113.5"),
            "raw IPv4-mapped form must not be stored"
        );

        let pkg = cfg.ip_allowlist.get("requests").expect("requests bucket");
        assert!(
            pkg.contains("198.51.100.1"),
            "per-package ::ffff:198.51.100.1 must be stored as bare IPv4"
        );
        assert!(
            !pkg.contains("::ffff:198.51.100.1"),
            "raw IPv4-mapped form must not be stored in per-package bucket"
        );
    }

    #[test]
    fn per_package_allowlist_key_trimmed_and_blank_key_dropped() {
        // Key with surrounding whitespace must be stored under the trimmed name.
        // A key that trims to "" must be silently dropped (not stored under "").
        let yaml = concat!(
            "ip_allowlist:\n",
            "  - \"  requests  \":\n",
            "    - 5.6.7.8\n",
            "  - \"   \":\n", // blank after trim — should be dropped
            "    - 9.9.9.9\n",
            "domain_allowlist:\n",
            "  - \"  boto3  \":\n",
            "    - api.boto3-cdn.net\n",
            "  - \"  \":\n", // blank after trim — should be dropped
            "    - bad.example.com\n",
        );
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(file, "{}", yaml).expect("config should be written");
        let cfg = load(&file);

        // Trimmed key present, untrimmed absent — regression guard for #302
        let req_ips = cfg.ip_allowlist.get("requests").expect("requests ips");
        assert!(req_ips.contains("5.6.7.8"));
        assert!(!cfg.ip_allowlist.contains_key("  requests  "));

        // Blank key dropped entirely
        assert!(!cfg.ip_allowlist.contains_key(""));
        assert!(!cfg.ip_allowlist.contains_key("   "));

        let boto3_domains = cfg.domain_allowlist.get("boto3").expect("boto3 domains");
        assert!(boto3_domains.contains("api.boto3-cdn.net"));
        assert!(!cfg.domain_allowlist.contains_key("  boto3  "));
        assert!(!cfg.domain_allowlist.contains_key(""));
        assert!(!cfg.domain_allowlist.contains_key("  "));
    }

    #[test]
    fn per_package_allowlist_star_key_rejected_for_ip_domain_and_list_map() {
        // "*" as a per-package key must be dropped with a warning, not silently
        // merged into the global "*" bucket or stored as a per-package entry.
        let yaml = concat!(
            "ip_allowlist:\n",
            "  - \"*\":\n",
            "    - 9.9.9.9\n",
            "domain_allowlist:\n",
            "  - \"*\":\n",
            "    - cdn.example.com\n",
            "git_clone_allowlist:\n",
            "  \"*\":\n",
            "    - https://github.com/evil/repo.git\n",
        );
        let mut file = NamedTempFile::new().expect("temp file");
        writeln!(file, "{}", yaml).expect("write");
        let cfg = load(&file);

        // ip_allowlist: global "*" bucket must be empty — the per-package "*" was rejected
        assert!(
            cfg.ip_allowlist.get("*").is_none_or(|s| s.is_empty()),
            "ip_allowlist \"*\" bucket must be empty when only per-package \"*\" key was used"
        );
        // domain_allowlist: same
        assert!(
            cfg.domain_allowlist.get("*").is_none_or(|s| s.is_empty()),
            "domain_allowlist \"*\" bucket must be empty when only per-package \"*\" key was used"
        );
        // git_clone_allowlist: "*" key must be dropped, not stored
        assert!(
            !cfg.git_clone_allowlist.contains_key("*"),
            "git_clone_allowlist must not store \"*\" as a package key"
        );
    }

    #[test]
    fn domain_allowlist_star_value_rejected_in_global_and_per_package_positions() {
        // "*" as a domain VALUE (not key) must be dropped with a warning in both
        // the global list and the per-package list positions. It passes serde
        // parsing but domain_is_allowlisted never matches it (neither exact nor
        // ends_with(".*")), so silently keeping it would create a dead entry with
        // no diagnostic — FIXED_FINDINGS.md #315.
        let yaml = concat!(
            "domain_allowlist:\n",
            "  - \"*\"\n", // global position
            "  - requests:\n",
            "    - \"*\"\n",           // per-package position
            "    - cdn.example.com\n", // legitimate entry must survive
        );
        let mut file = NamedTempFile::new().expect("temp file");
        writeln!(file, "{}", yaml).expect("write");
        let cfg = load(&file);

        // Global "*" bucket must not contain the literal "*"
        let star_not_in_global = cfg
            .domain_allowlist
            .get("*")
            .is_none_or(|s| !s.contains("*"));
        assert!(
            star_not_in_global,
            "global domain_allowlist must not store \"*\" as a domain value"
        );
        // Per-package "requests" entry must not contain "*", but must keep cdn.example.com
        let pkg_domains = cfg
            .domain_allowlist
            .get("requests")
            .expect("requests domain entry must exist");
        assert!(
            !pkg_domains.contains("*"),
            "per-package domain_allowlist must not store \"*\" as a domain value"
        );
        assert!(
            pkg_domains.contains("cdn.example.com"),
            "legitimate per-package domain entry must be kept"
        );
    }

    #[test]
    fn domain_allowlist_empty_value_dropped_in_global_and_per_package_positions() {
        // An empty string or whitespace-only value normalizes to "" and must be
        // silently dropped (with a warning) in both global and per-package positions.
        // FIXED_FINDINGS.md #328.
        let yaml = concat!(
            "domain_allowlist:\n",
            "  - \"\"\n",   // global empty
            "  - \"  \"\n", // global whitespace-only
            "  - requests:\n",
            "    - \"\"\n",            // per-package empty
            "    - cdn.example.com\n", // legitimate entry must survive
        );
        let mut file = NamedTempFile::new().expect("temp file");
        writeln!(file, "{}", yaml).expect("write");
        let cfg = load(&file);

        // Global "*" bucket must not contain empty string
        assert!(
            cfg.domain_allowlist
                .get("*")
                .is_none_or(|s| !s.contains("")),
            "global domain_allowlist must not store empty string as a domain value"
        );
        // Per-package "requests" must not have empty entry but must keep cdn.example.com
        let pkg_domains = cfg
            .domain_allowlist
            .get("requests")
            .expect("requests domain entry must exist");
        assert!(
            !pkg_domains.contains(""),
            "per-package domain_allowlist must not store empty string as a domain value"
        );
        assert!(
            pkg_domains.contains("cdn.example.com"),
            "legitimate per-package domain entry must be kept"
        );
    }

    #[test]
    fn per_package_allowlist_whitespace_collision_merges_both_ip_sets() {
        // Two YAML keys that differ only by surrounding whitespace both trim to
        // the same package name — their IP sets must be merged, not silently
        // dropped. This is the allowlist analogue of OPEN #277.
        let yaml = concat!(
            "ip_allowlist:\n",
            "  - requests:\n",
            "    - 1.2.3.4\n",
            "  - \"  requests  \":\n",
            "    - 5.6.7.8\n",
        );
        let mut file = NamedTempFile::new().expect("temp file");
        writeln!(file, "{}", yaml).expect("write");
        let cfg = load(&file);

        let ips = cfg
            .ip_allowlist
            .get("requests")
            .expect("requests must be present");
        assert!(ips.contains("1.2.3.4"), "first key's IP must be present");
        assert!(
            ips.contains("5.6.7.8"),
            "whitespace-variant key's IP must be merged in"
        );
    }

    #[test]
    fn domain_allowlist_bare_tld_rejected_in_global_and_per_package_positions() {
        // A domain entry with no dot (e.g. "com") would match evil.com, attacker.com, etc.
        // via ends_with(".com"). It must be rejected at config-load time (FIXED #367).
        let yaml = concat!(
            "domain_allowlist:\n",
            "  - com\n",      // global bare TLD — must be dropped
            "  - pypi.org\n", // global valid — must be kept
            "  - requests:\n",
            "    - org\n",                    // per-package bare TLD — must be dropped
            "    - files.pythonhosted.org\n", // per-package valid — must be kept
        );
        let mut file = NamedTempFile::new().expect("temp file");
        writeln!(file, "{}", yaml).expect("write");
        let cfg = load(&file);

        let global = cfg.domain_allowlist.get("*").expect("global bucket");
        assert!(!global.contains("com"), "bare TLD 'com' must be rejected");
        assert!(
            global.contains("pypi.org"),
            "valid global entry must be kept"
        );

        let pkg = cfg
            .domain_allowlist
            .get("requests")
            .expect("requests bucket");
        assert!(
            !pkg.contains("org"),
            "bare TLD 'org' must be rejected for per-package"
        );
        assert!(
            pkg.contains("files.pythonhosted.org"),
            "valid per-package entry must be kept"
        );
    }

    #[test]
    fn sensitive_file_access_allowlist_all_values_filtered_drops_key() {
        // When all values for a package in sensitive_file_access_allowlist are
        // overly-permissive ("*", "/", "*/", "/*"), the package key must be removed
        // from the map entirely — not left as an empty HashSet (FIXED #368).
        let yaml = concat!(
            "sensitive_file_access_allowlist:\n",
            "  all-bad-pkg:\n",
            "    - \"*\"\n",
            "    - /\n",
            "  mixed-pkg:\n",
            "    - \"*\"\n",
            "    - .env\n", // one valid entry survives
        );
        let mut file = NamedTempFile::new().expect("temp file");
        writeln!(file, "{}", yaml).expect("write");
        let cfg = load(&file);

        assert!(
            !cfg.sensitive_file_access_allowlist
                .contains_key("all-bad-pkg"),
            "key with only overly-permissive values must be removed entirely"
        );
        let mixed = cfg
            .sensitive_file_access_allowlist
            .get("mixed-pkg")
            .expect("mixed-pkg must be present");
        assert!(mixed.contains(".env"), "valid entry must survive");
        assert!(
            !mixed.contains("*"),
            "overly-permissive entry must be removed"
        );
    }

    #[test]
    fn parse_list_map_whitespace_collision_merges_both_value_sets() {
        // Two YAML keys differing only in surrounding whitespace must merge their
        // value sets, not silently drop one. Covers the parse_list_map path (here
        // via git_clone_allowlist) which shares the same validate_allowlist_pkg_key
        // → entry().or_default().extend() merge semantics as ip/domain PerPackage.
        let yaml = concat!(
            "git_clone_allowlist:\n",
            "  requests:\n",
            "    - https://github.com/psf/requests.git\n",
            "  \"  requests  \":\n",
            "    - https://github.com/psf/requests-cache.git\n",
        );
        let mut file = NamedTempFile::new().expect("temp file");
        writeln!(file, "{}", yaml).expect("write");
        let cfg = load(&file);

        let urls = cfg
            .git_clone_allowlist
            .get("requests")
            .expect("requests must be present");
        assert!(
            urls.contains("https://github.com/psf/requests.git"),
            "first key's URL must be present"
        );
        assert!(
            urls.contains("https://github.com/psf/requests-cache.git"),
            "whitespace-variant key's URL must be merged in"
        );
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
            "min_baseline_age_hours:\n  requests: 36\n  lodash: 48\n  badpkg: 0"
        )
        .expect("config should be written");

        let cfg = load(&file);
        assert_eq!(
            cfg.min_baseline_age_hours_by_package.get("requests"),
            Some(&36)
        );
        assert_eq!(
            cfg.min_baseline_age_hours_by_package.get("lodash"),
            Some(&48)
        );
        assert_eq!(
            cfg.min_baseline_age_hours_by_package.get("badpkg"),
            Some(&24)
        );
    }

    #[test]
    fn clamps_min_baseline_age_hours_to_hard_floor() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(
            file,
            "min_baseline_age_hours:\n  pkg_zero: 0\n  pkg_below: 23\n  pkg_exact: 24\n  pkg_above: 25\n  pkg_high: 999\n  \"  pkg_whitespace  \": 10"
        )
        .expect("config should be written");

        let cfg = load(&file);

        // 0 -> clamped to 24
        assert_eq!(
            cfg.min_baseline_age_hours_by_package.get("pkg_zero"),
            Some(&24)
        );

        // 23 -> clamped to 24
        assert_eq!(
            cfg.min_baseline_age_hours_by_package.get("pkg_below"),
            Some(&24)
        );

        // 24 -> exactly the floor, remains 24
        assert_eq!(
            cfg.min_baseline_age_hours_by_package.get("pkg_exact"),
            Some(&24)
        );

        // 25 -> above floor, remains 25
        assert_eq!(
            cfg.min_baseline_age_hours_by_package.get("pkg_above"),
            Some(&25)
        );

        // 999 -> above floor, remains 999
        assert_eq!(
            cfg.min_baseline_age_hours_by_package.get("pkg_high"),
            Some(&999)
        );

        // Whitespace trimmed and clamped
        assert_eq!(
            cfg.min_baseline_age_hours_by_package.get("pkg_whitespace"),
            Some(&24)
        );
        // Belt-and-suspenders: untrimmed form is absent — regression in trimming would
        // leave "  pkg_whitespace  " in the map and "pkg_whitespace" absent.
        assert_eq!(
            cfg.min_baseline_age_hours_by_package
                .get("  pkg_whitespace  "),
            None
        );
    }

    #[test]
    fn parses_new_package_exemptions() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(
            file,
            "new_package_exemptions:\n  requests: \"2.30.0\"\n  lodash: \"1.0.0\"\n  '  ': \"1.0.0\""
        )
        .expect("config should be written");

        let cfg = load(&file);
        assert_eq!(
            cfg.new_package_exemptions.get("requests").unwrap(),
            "2.30.0"
        );
        assert_eq!(cfg.new_package_exemptions.get("lodash").unwrap(), "1.0.0");
        assert_eq!(cfg.new_package_exemptions.len(), 2);
    }

    #[test]
    fn rejects_new_package_exemptions_old_list_format() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(file, "new_package_exemptions:\n  - requests\n  - lodash")
            .expect("config should be written");

        let err = load_policy_config(file.path().to_str().expect("path should be utf8"), true)
            .expect_err("old list format should be rejected");
        assert!(err.contains("list format") && err.contains("no longer supported"));
    }

    #[test]
    fn parses_new_package_exemptions_invalid_map_rejected_with_custom_error() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(file, "new_package_exemptions:\n  requests: 1.0")
            .expect("config should be written");

        let err = load_policy_config(file.path().to_str().expect("path should be utf8"), true)
            .expect_err("invalid map format should be rejected");
        assert!(err.contains("must be strings") && err.contains("Found a non-string value."));
    }

    #[test]
    fn parses_new_package_exemptions_empty_version_removed() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(file, "new_package_exemptions:\n  badpkg: \"\"")
            .expect("config should be written");

        let cfg = load(&file);
        assert!(
            cfg.new_package_exemptions.is_empty(),
            "empty version entries are removed with a warning"
        );
    }

    #[test]
    fn parses_new_package_exemptions_mixed_valid_and_empty() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(
            file,
            "new_package_exemptions:\n  goodpkg: \"1.0.0\"\n  badpkg: \"\""
        )
        .expect("config should be written");

        let cfg = load(&file);
        assert_eq!(cfg.new_package_exemptions.len(), 1);
        assert_eq!(cfg.new_package_exemptions.get("goodpkg").unwrap(), "1.0.0");
    }

    #[test]
    fn new_package_exemptions_whitespace_only_value_removed() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(file, "new_package_exemptions:\n  badpkg: \"  \"")
            .expect("config should be written");

        let cfg = load(&file);
        assert!(
            cfg.new_package_exemptions.is_empty(),
            "whitespace-only value after trim should be treated as empty"
        );
    }

    #[test]
    fn new_package_exemptions_empty_key_and_empty_value_removed() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(file, "new_package_exemptions:\n  '': ''").expect("config should be written");

        let cfg = load(&file);
        assert!(
            cfg.new_package_exemptions.is_empty(),
            "empty key with empty value should be removed"
        );
    }

    #[test]
    fn rejects_new_package_exemptions_list_whitespace_and_empty_entries() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(
            file,
            "new_package_exemptions:\n  - '  pkg  '\n  - '  '\n  - ''\n  - other"
        )
        .expect("config should be written");

        let err = load_policy_config(file.path().to_str().expect("path should be utf8"), true)
            .expect_err("list format should be rejected");
        assert!(err.contains("no longer supported"));
    }

    #[test]
    fn rejects_new_package_exemptions_list_only_whitespace_entries() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(file, "new_package_exemptions:\n  - '  '\n  - '\t'")
            .expect("config should be written");

        let err = load_policy_config(file.path().to_str().expect("path should be utf8"), true)
            .expect_err("list format should be rejected");
        assert!(err.contains("no longer supported"));
    }

    #[test]
    fn new_package_exemptions_null_section_is_empty() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(file, "new_package_exemptions:").expect("config should be written");

        let cfg = load(&file);
        assert!(
            cfg.new_package_exemptions.is_empty(),
            "null/empty new_package_exemptions section should produce empty map"
        );
    }

    #[test]
    fn rejects_new_package_exemptions_list_single_entry() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(file, "new_package_exemptions:\n  - requests").expect("config should be written");

        let err = load_policy_config(file.path().to_str().expect("path should be utf8"), true)
            .expect_err("list format should be rejected");
        assert!(err.contains("no longer supported"));
    }

    #[test]
    fn accepts_new_package_exemptions_empty_list_as_no_exemptions() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(file, "new_package_exemptions: []").expect("config should be written");

        let cfg = load(&file);
        assert!(
            cfg.new_package_exemptions.is_empty(),
            "empty list [] should be accepted as no exemptions"
        );
    }

    #[test]
    fn parses_new_package_exemptions_explicit_empty_map() {
        // An explicit empty YAML map (`{}`) must deserialise to an empty
        // HashMap — not an error.  Some users write this when clearing the
        // section without removing the key entirely.
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(file, "new_package_exemptions: {{}}").expect("config should be written");

        let cfg = load(&file);
        assert!(
            cfg.new_package_exemptions.is_empty(),
            "explicit empty map should produce an empty exemptions map"
        );
    }

    #[test]
    fn new_package_exemptions_map_key_with_whitespace_is_trimmed() {
        // Keys with surrounding whitespace must be trimmed so that the lookup
        // `policy.new_package_exemptions.get("requests")` succeeds — the raw
        // YAML key is `"  requests  "` here.
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(file, "new_package_exemptions:\n  '  requests  ': \"1.0.0\"")
            .expect("config should be written");

        let cfg = load(&file);
        assert_eq!(cfg.new_package_exemptions.len(), 1);
        assert_eq!(
            cfg.new_package_exemptions.get("requests"),
            Some(&"1.0.0".to_string()),
            "key must be trimmed from '  requests  ' to 'requests'"
        );
        assert!(
            !cfg.new_package_exemptions.contains_key("  requests  "),
            "untrimmed key must not be present"
        );
    }

    #[test]
    fn parses_sensitive_file_access_allowlist() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(
            file,
            "sensitive_file_access_allowlist:\n  my-pkg:\n    - .env\n    - /etc/passwd\n    - '  '"
        )
        .expect("config should be written");

        let cfg = load(&file);
        let list = cfg.sensitive_file_access_allowlist.get("my-pkg").unwrap();
        assert!(list.contains(".env"));
        assert!(list.contains("/etc/passwd"));
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn parses_internal_package_exemptions() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(
            file,
            "internal_package_exemptions:\n  - internal-pkg-logger\n  - '  internal-thing  '\n  - '  '"
        )
        .expect("config should be written");

        let cfg = load(&file);
        assert!(
            cfg.internal_package_exemptions
                .contains("internal-pkg-logger")
        );
        // Trimmed of surrounding whitespace, blank entries dropped.
        assert!(cfg.internal_package_exemptions.contains("internal-thing"));
        assert_eq!(cfg.internal_package_exemptions.len(), 2);
    }

    #[test]
    fn missing_internal_package_exemptions_defaults_empty() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(file, "baseline_count: 2").expect("config should be written");

        let cfg = load(&file);
        assert!(cfg.internal_package_exemptions.is_empty());
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
            "baseline_overrides:\n  \"  requests  \":\n    baseline-1: \"2.30.0\"\nmin_baseline_age_hours:\n  \"  requests  \": 36"
        )
        .expect("config should be written");

        let cfg = load(&file);
        assert_eq!(
            cfg.baseline_overrides.get("requests"),
            Some(&(Some("2.30.0".to_string()), None))
        );
        assert_eq!(
            cfg.min_baseline_age_hours_by_package.get("requests"),
            Some(&36)
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
            "git_clone_allowlist:\n  my-pkg:\n    - https://github.com/acme/repo.git\n    - '  '"
        )
        .expect("config should be written");

        let cfg = load(&file);
        let list = cfg.git_clone_allowlist.get("my-pkg").unwrap();
        assert!(list.contains("https://github.com/acme/repo.git"));
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn parse_list_map_empty_value_set_drops_key() {
        // A package key whose entire value list is blank/whitespace must not be
        // inserted into the allowlist — operator has no protection for that key
        // and must see a warning (FIXED #363).
        let yaml = concat!(
            "git_clone_allowlist:\n",
            "  my-pkg:\n",
            "    - \"  \"\n", // whitespace-only — filtered by parse_list
            "    - \"\"\n",   // empty — filtered by parse_list
            "  other-pkg:\n",
            "    - https://github.com/acme/repo.git\n",
        );
        let mut file = NamedTempFile::new().expect("temp file");
        writeln!(file, "{}", yaml).expect("write");
        let cfg = load(&file);

        assert!(
            !cfg.git_clone_allowlist.contains_key("my-pkg"),
            "key with only blank values must not appear in the allowlist"
        );
        assert!(
            cfg.git_clone_allowlist.contains_key("other-pkg"),
            "key with valid values must be present"
        );
    }

    #[test]
    fn option_zero_to_none_direct() {
        use crate::option_zero_to_none;
        assert_eq!(option_zero_to_none(Some(0), "warn"), None);
        assert_eq!(option_zero_to_none(Some(42), "warn"), Some(42));
        assert_eq!(option_zero_to_none(None, "warn"), None);
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
        let (manager_args, path, explicit, _) = parse_global_options(args).expect("should parse");
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
        let (manager_args, path, explicit, _) = parse_global_options(args).expect("should parse");
        assert_eq!(path, "path=with=equals.yaml");
        assert!(explicit);
        assert_eq!(manager_args, vec!["pip", "install", "requests"]);
    }

    #[test]
    fn danger_disable_seccomp_parsing_edge_cases() {
        // (a) Flag before --config
        let args = vec![
            "--danger-disable-seccomp".to_string(),
            "--config=my.yaml".to_string(),
            "npm".to_string(),
            "install".to_string(),
        ];
        let (mgr_args, _, _, danger) = parse_global_options(args).expect("should parse");
        assert!(danger);
        assert_eq!(mgr_args, vec!["npm", "install"]);

        // (a) Flag after --config
        let args = vec![
            "--config=my.yaml".to_string(),
            "--danger-disable-seccomp".to_string(),
            "npm".to_string(),
            "install".to_string(),
        ];
        let (mgr_args, _, _, danger) = parse_global_options(args).expect("should parse");
        assert!(danger);
        assert_eq!(mgr_args, vec!["npm", "install"]);

        // (b) Multiple occurrences
        let args = vec![
            "--danger-disable-seccomp".to_string(),
            "--danger-disable-seccomp".to_string(),
            "npm".to_string(),
            "install".to_string(),
        ];
        let (mgr_args, _, _, danger) = parse_global_options(args).expect("should parse");
        assert!(danger);
        assert_eq!(mgr_args, vec!["npm", "install"]);

        // (c) Flag after manager command is forwarded/consumed globally
        let args = vec![
            "npm".to_string(),
            "install".to_string(),
            "lodash".to_string(),
            "--danger-disable-seccomp".to_string(),
        ];
        let (mgr_args, _, _, danger) = parse_global_options(args).expect("should parse");
        assert!(danger);
        assert_eq!(mgr_args, vec!["npm", "install", "lodash"]);
    }
}

pub struct GyrSeek {
    passthrough_args: Vec<String>,
    manager: String,
}

struct NoopRunner;
impl SandboxRunner for NoopRunner {
    fn trace_install(&self, _: &str, _: &str, _: &str) -> Result<String, String> {
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

struct ScanTimer(std::time::Instant);
impl ScanTimer {
    fn start() -> Self {
        Self(std::time::Instant::now())
    }
}
impl Drop for ScanTimer {
    fn drop(&mut self) {
        let elapsed = self.0.elapsed();
        let ms = elapsed.as_secs_f64() * 1000.0;
        if ms >= 1000.0 {
            println!("⏱️ [gyrseek] Checks completed in {:.2}s", ms / 1000.0);
        } else {
            println!("⏱️ [gyrseek] Checks completed in {:.0}ms", ms);
        }
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
    let _scan_timer = ScanTimer::start();
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
    let _scan_timer = ScanTimer::start();
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
                blocked_reasons: vec!["scan_failed".to_string()],
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

async fn scan_targets(
    scan_cache: &mut HashMap<String, ScanReport>,
    runner: &dyn SandboxRunner,
    manager: &str,
    targets: Vec<(String, String)>,
    policy: &PolicyConfig,
) -> Option<HashMap<String, String>> {
    scan_many_with_cache(scan_cache, runner, manager, targets, policy).await
}

enum ForwardMode {
    Original,
    Pinned,
}

fn exit_with(msg: &str) -> ! {
    println!("❌ [gyrseek] {}", msg);
    std::process::exit(1)
}

pub async fn run(args: Vec<String>) {
    // Handle --version/-V as a top-level flag before anything else so it works
    // without a config file, Docker, or a recognized manager subcommand. Only
    // the first arg is checked so a forwarded command's own --version flag
    // (e.g. `gyrseek pip install foo --version`) is left untouched.
    if matches!(
        args.first().map(String::as_str),
        Some("--version") | Some("-V")
    ) {
        println!("gyrseek {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    let (args, config_path, config_explicit, danger_disable_seccomp) =
        match parse_global_options(args) {
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

    let total_ips: usize = policy.ip_allowlist.values().map(|s| s.len()).sum();
    if total_ips > 0 {
        println!(
            "ℹ️ [gyrseek] Loaded {} allowlisted IP(s) from {}",
            total_ips, config_path
        );
    }
    let total_domains: usize = policy.domain_allowlist.values().map(|s| s.len()).sum();
    if total_domains > 0 {
        println!(
            "ℹ️ [gyrseek] Loaded {} allowlisted domain(s) from {}",
            total_domains, config_path
        );
    }
    if !policy.git_clone_allowlist.is_empty() {
        println!(
            "ℹ️ [gyrseek] Loaded git clone allowlist for {} package(s) from {}",
            policy.git_clone_allowlist.len(),
            config_path
        );
    }
    if !policy.artifact_allowlist.is_empty() {
        println!(
            "ℹ️ [gyrseek] Loaded artifact allowlist for {} package(s) from {}",
            policy.artifact_allowlist.len(),
            config_path
        );
    }
    if !policy.sensitive_file_access_allowlist.is_empty() {
        println!(
            "ℹ️ [gyrseek] Loaded sensitive file access allowlist for {} package(s) from {}",
            policy.sensitive_file_access_allowlist.len(),
            config_path
        );
    }
    if !policy.process_exec_allowlist.is_empty() {
        println!(
            "ℹ️ [gyrseek] Loaded process exec allowlist for {} package(s) from {}",
            policy.process_exec_allowlist.len(),
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
    let os = std::env::consts::OS;
    let sandbox_mode = env::var("GYRSEEK_SANDBOX").unwrap_or_else(|_| "docker".to_string());
    println!("🖥️ [gyrseek] OS: {} | Sandbox mode: {}", os, sandbox_mode);
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
    if !policy.internal_package_exemptions.is_empty() {
        println!(
            "ℹ️ [gyrseek] Loaded internal package exemptions for {} package(s)",
            policy.internal_package_exemptions.len()
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
    const SUPPORTED_MANAGERS: &[&str] = &["pip", "pip3", "uv", "poetry", "npm", "pnpm"];
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
        match build_runner_from_env(danger_disable_seccomp) {
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
            let targets: Vec<(String, String)> = upgrade_packages
                .into_iter()
                .map(|pkg_name| (pkg_name, "latest".to_string()))
                .collect();
            println!(
                "🛡️ [gyrseek] 'uv lock' update detected. Testing {} target package(s)...",
                targets.len()
            );
            if scan_targets(
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
            exit_with("'uv lock' detected but no packages found in uv.lock. Failing closed.");
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

        if scan_targets(
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
            exit_with(&format!(
                "'poetry {}' detected but no packages found in poetry.lock. Failing closed.",
                poetry_cmd
            ));
        }

        println!(
            "🛡️ [gyrseek] 'poetry {}' detected. Testing {} locked package(s) from poetry.lock...",
            poetry_cmd,
            lock_packages.len()
        );

        if scan_targets(
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

    // Shared bulk-scan body for the manager branches that parse a package list,
    // scan it, and forward on a clean report. Only the diagnostic strings differ
    // between branches, so they are passed in verbatim ($empty_msg, $testing_msg,
    // $clear_noun) to keep stdout byte-for-byte identical to the pre-refactor
    // per-branch code — the control flow and security semantics are the dedup.
    // $testing_msg is a closure of the package count so each branch keeps its own
    // wording around the count.
    macro_rules! bulk_scan {
        ($packages:expr, $mode:ident, $clear_noun:expr, $empty_msg:expr, $testing_msg:expr $(,)?) => {{
            let packages = $packages;
            if packages.is_empty() {
                exit_with($empty_msg);
            }
            println!("{}", ($testing_msg)(packages.len()));
            let targets: Vec<(String, String)> = packages
                .into_iter()
                .map(|(pkg_name, maybe_version)| {
                    (pkg_name, maybe_version.unwrap_or_else(|| "latest".to_string()))
                })
                .collect();
            let pins = match scan_targets(
                &mut scan_cache,
                runner.as_ref(),
                &eye.manager,
                targets,
                &policy,
            )
            .await
            {
                Some(p) => p,
                None => std::process::exit(1),
            };
            println!(
                "\n✅ [gyrseek] Clear behavioral report for {} package set. Forwarding command safely...",
                $clear_noun
            );
            match ForwardMode::$mode {
                ForwardMode::Original => eye.forward_original_command(),
                ForwardMode::Pinned => eye.forward_pinned_command(&pins),
            }
            return;
        }};
    }

    if eye.manager == "uv"
        && eye.passthrough_args.get(1).map(String::as_str) == Some("pip")
        && eye.passthrough_args.get(2).map(String::as_str) == Some("sync")
    {
        bulk_scan!(
            eye.parse_uv_pip_sync_packages(),
            Original,
            "sync",
            "'uv pip sync' detected but no parseable package entries were found. Failing closed.",
            |n| format!(
                "🛡️ [gyrseek] 'uv pip sync' detected. Testing {} package(s) from sync sources...",
                n
            )
        );
    }

    if eye.manager == "uv" && eye.passthrough_args.get(1).map(String::as_str) == Some("sync") {
        let lock_packages = eye.parse_uv_lock_packages();
        if lock_packages.is_empty() {
            exit_with("'uv sync' detected but no packages found in uv.lock. Failing closed.");
        }
        println!(
            "🛡️ [gyrseek] 'uv sync' detected. Testing {} locked package(s) from uv.lock...",
            lock_packages.len()
        );
        if scan_targets(
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
        let manager = eye.manager.clone();
        bulk_scan!(
            eye.parse_pip_install_packages(),
            Pinned,
            "pip",
            "'pip install' detected but no parseable package entries were found. Failing closed.",
            |n| format!(
                "🛡️ [gyrseek] '{}' install detected. Testing {} package(s)...",
                manager, n
            )
        );
    }

    if (eye.manager == "npm" || eye.manager == "pnpm")
        && (eye.passthrough_args.get(1).map(String::as_str) == Some("install")
            || eye.passthrough_args.get(1).map(String::as_str) == Some("i")
            || eye.passthrough_args.get(1).map(String::as_str) == Some("update")
            || (eye.manager == "pnpm"
                && eye.passthrough_args.get(1).map(String::as_str) == Some("add")))
    {
        let npm_sub = eye
            .passthrough_args
            .get(1)
            .map(String::as_str)
            .unwrap_or("install")
            .to_string();
        bulk_scan!(
            eye.parse_npm_install_packages(),
            Pinned,
            eye.manager.as_str(),
            &format!(
                "'{} {}' detected but no parseable package entries were found. Failing closed.",
                eye.manager, npm_sub
            ),
            |n| format!(
                "🛡️ [gyrseek] '{}' detected. Testing {} package(s)...",
                npm_sub, n
            )
        );
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
    fn parses_pnpm_add_as_latest_when_unpinned() {
        let eye = GyrSeek::new(vec![
            "pnpm".to_string(),
            "add".to_string(),
            "lodash".to_string(),
        ]);
        let (pkg, version) = eye.parse_package_details();
        assert_eq!(pkg.as_deref(), Some("lodash"));
        assert_eq!(version, None);
    }

    #[test]
    fn parses_pnpm_add_with_pinned_version() {
        let eye = GyrSeek::new(vec![
            "pnpm".to_string(),
            "add".to_string(),
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

    #[derive(serde::Deserialize, Debug)]
    struct DummyExemptionConfig {
        #[serde(deserialize_with = "crate::deserialize_new_package_exemptions")]
        new_package_exemptions: std::collections::HashMap<String, String>,
    }

    #[test]
    fn test_deserialize_new_package_exemptions_map() {
        let yaml = "new_package_exemptions:\n  requests: \"1.0.0\"\n  urllib3: \"2.0.0\"";
        let cfg: DummyExemptionConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.new_package_exemptions.get("requests").unwrap(), "1.0.0");
        assert_eq!(cfg.new_package_exemptions.get("urllib3").unwrap(), "2.0.0");
    }

    #[test]
    fn test_deserialize_new_package_exemptions_invalid_map() {
        // boolean instead of string
        let yaml = "new_package_exemptions:\n  requests: true";
        let err = serde_yaml::from_str::<DummyExemptionConfig>(yaml).unwrap_err();
        assert!(err.to_string().contains("must be strings"));

        // integer instead of string
        let yaml2 = "new_package_exemptions:\n  requests: 123";
        let err2 = serde_yaml::from_str::<DummyExemptionConfig>(yaml2).unwrap_err();
        assert!(err2.to_string().contains("must be strings"));
    }

    #[test]
    fn test_deserialize_new_package_exemptions_list() {
        // empty list is allowed and yields empty map
        let yaml_empty = "new_package_exemptions: []";
        let cfg: DummyExemptionConfig = serde_yaml::from_str(yaml_empty).unwrap();
        assert!(cfg.new_package_exemptions.is_empty());

        // non-empty list is rejected
        let yaml_list = "new_package_exemptions:\n  - requests";
        let err = serde_yaml::from_str::<DummyExemptionConfig>(yaml_list).unwrap_err();
        assert!(
            err.to_string()
                .contains("list format (e.g. '- pkg') is no longer supported")
        );
    }

    #[test]
    fn test_deserialize_new_package_exemptions_null() {
        let yaml = "new_package_exemptions: null";
        let cfg: DummyExemptionConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(cfg.new_package_exemptions.is_empty());
    }
}
