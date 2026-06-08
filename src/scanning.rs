use std::collections::{HashMap, HashSet};

use regex::Regex;
use serde::Deserialize;

use crate::sandbox::SandboxRunner;

#[derive(Deserialize, Debug)]
struct PyPiResponse {
    releases: std::collections::HashMap<String, serde_json::Value>,
}

#[derive(Deserialize, Debug)]
struct NpmResponse {
    versions: std::collections::HashMap<String, serde_json::Value>,
}

/// Returns connections present in the current version but absent in baseline versions.
pub fn find_new_connections(ips_curr: &HashSet<String>, baseline_ips: &HashSet<String>) -> Vec<String> {
    ips_curr.difference(baseline_ips).cloned().collect()
}

pub async fn fetch_history(manager: &str, package: &str, target_v: &str) -> (String, Option<String>, Option<String>) {
    println!("🔍 [gyrseek] Fetching version matrix from registry for '{}'...", package);
    let client = reqwest::Client::new();

    if manager == "npm" {
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

pub fn trace_sandbox_install_batch(
    runner: &dyn SandboxRunner,
    manager: &str,
    package: &str,
    versions: &[String],
) -> Result<HashMap<String, HashSet<String>>, String> {
    let traces = runner.trace_install_batch(manager, package, versions)?;
    let re = Regex::new(r#"sin_addr=inet_addr\("([\d.]+)"\)"#).unwrap();
    let mut by_version: HashMap<String, HashSet<String>> = HashMap::new();

    for (version, stderr_str) in traces {
        let mut ips = HashSet::new();
        for cap in re.captures_iter(&stderr_str) {
            ips.insert(cap[1].to_string());
        }
        by_version.insert(version, ips);
    }

    Ok(by_version)
}

pub async fn scan_package_versions(runner: &dyn SandboxRunner, manager: &str, pkg_name: &str, tgt_version: &str) -> bool {
    let (v_curr, v_m1, v_m2) = fetch_history(manager, pkg_name, tgt_version).await;
    let baseline_m1 = v_m1.clone().unwrap_or_else(|| "n/a".to_string());
    let baseline_m2 = v_m2.clone().unwrap_or_else(|| "n/a".to_string());
    println!(
        "🛡️ [gyrseek] Comparing versions for '{}': current={} baseline-1={} baseline-2={}",
        pkg_name, v_curr, baseline_m1, baseline_m2
    );

    let mut requested_versions = vec![v_curr.clone()];
    if let Some(ref v) = v_m1 {
        requested_versions.push(v.clone());
    }
    if let Some(ref v) = v_m2 {
        requested_versions.push(v.clone());
    }

    let traces_by_version = match trace_sandbox_install_batch(runner, manager, pkg_name, &requested_versions) {
        Ok(v) => v,
        Err(e) => {
            println!("❌ [gyrseek] Sandbox execution failed for '{}': {}", pkg_name, e);
            return false;
        }
    };

    let ips_curr = match traces_by_version.get(&v_curr) {
        Some(v) => v.clone(),
        None => {
            println!(
                "❌ [gyrseek] Sandbox trace missing for '{}@{}'.",
                pkg_name, v_curr
            );
            return false;
        }
    };

    let mut baseline_ips = HashSet::new();
    if let Some(ref v) = v_m1 {
        match traces_by_version.get(v) {
            Some(found) => baseline_ips.extend(found.iter().cloned()),
            None => {
                println!(
                    "❌ [gyrseek] Sandbox trace missing for baseline '{}@{}'.",
                    pkg_name, v
                );
                return false;
            }
        }
    }
    if let Some(ref v) = v_m2 {
        match traces_by_version.get(v) {
            Some(found) => baseline_ips.extend(found.iter().cloned()),
            None => {
                println!(
                    "❌ [gyrseek] Sandbox trace missing for baseline '{}@{}'.",
                    pkg_name, v
                );
                return false;
            }
        }
    }

    let new_connections = find_new_connections(&ips_curr, &baseline_ips);

    if !new_connections.is_empty() {
        println!("\n❌ [gyrseek] CRITICAL WARNING: Behavioral anomaly flagged!");
        println!(
            "Package '{}', version '{}' contacted new endpoints not seen in baseline versions ({} and {}): {:?}",
            pkg_name, v_curr, baseline_m1, baseline_m2, new_connections
        );
        println!("Aborting host operation securely.");
        return false;
    }

    true
}
