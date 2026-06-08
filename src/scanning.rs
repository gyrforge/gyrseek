use std::collections::{HashMap, HashSet};

use regex::Regex;
use serde::Deserialize;

use crate::sandbox::SandboxRunner;

#[derive(Clone)]
struct VersionPlan {
    package: String,
    target_version: String,
    current: String,
    baseline_m1: Option<String>,
    baseline_m2: Option<String>,
}

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

pub fn trace_sandbox_install_matrix(
    runner: &dyn SandboxRunner,
    manager: &str,
    probes: &[(String, String)],
) -> Result<HashMap<(String, String), HashSet<String>>, String> {
    let traces = runner.trace_install_matrix(manager, probes)?;
    let re = Regex::new(r#"sin_addr=inet_addr\("([\d.]+)"\)"#).unwrap();
    let mut by_probe: HashMap<(String, String), HashSet<String>> = HashMap::new();

    for ((package, version), stderr_str) in traces {
        let mut ips = HashSet::new();
        for cap in re.captures_iter(&stderr_str) {
            ips.insert(cap[1].to_string());
        }
        by_probe.insert((package, version), ips);
    }

    Ok(by_probe)
}

pub async fn scan_packages_versions(
    runner: &dyn SandboxRunner,
    manager: &str,
    pkg_targets: &[(String, String)],
) -> HashMap<String, bool> {
    let mut results = HashMap::new();
    if pkg_targets.is_empty() {
        return results;
    }

    let mut plans = Vec::new();
    for (pkg_name, tgt_version) in pkg_targets {
        let (v_curr, v_m1, v_m2) = fetch_history(manager, pkg_name, tgt_version).await;
        let baseline_m1 = v_m1.clone().unwrap_or_else(|| "n/a".to_string());
        let baseline_m2 = v_m2.clone().unwrap_or_else(|| "n/a".to_string());
        println!(
            "🛡️ [gyrseek] Comparing versions for '{}': current={} baseline-1={} baseline-2={}",
            pkg_name, v_curr, baseline_m1, baseline_m2
        );

        plans.push(VersionPlan {
            package: pkg_name.clone(),
            target_version: tgt_version.clone(),
            current: v_curr,
            baseline_m1: v_m1,
            baseline_m2: v_m2,
        });
    }

    let mut probes: Vec<(String, String)> = Vec::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();
    for plan in &plans {
        let mut add_probe = |package: &str, version: &str| {
            let probe = (package.to_string(), version.to_string());
            if seen.insert(probe.clone()) {
                probes.push(probe);
            }
        };

        add_probe(&plan.package, &plan.current);
        if let Some(ref v) = plan.baseline_m1 {
            add_probe(&plan.package, v);
        }
        if let Some(ref v) = plan.baseline_m2 {
            add_probe(&plan.package, v);
        }
    }

    let traces_by_probe = match trace_sandbox_install_matrix(runner, manager, &probes) {
        Ok(v) => v,
        Err(e) => {
            for plan in &plans {
                println!("❌ [gyrseek] Sandbox execution failed for '{}': {}", plan.package, e);
                results.insert(format!("{}|{}", plan.package, plan.target_version), false);
            }
            return results;
        }
    };

    for plan in plans {
        let key = format!("{}|{}", plan.package, plan.target_version);
        let current_key = (plan.package.clone(), plan.current.clone());
        let ips_curr = match traces_by_probe.get(&current_key) {
            Some(v) => v.clone(),
            None => {
                println!(
                    "❌ [gyrseek] Sandbox trace missing for '{}@{}'.",
                    plan.package, plan.current
                );
                results.insert(key, false);
                continue;
            }
        };

        let mut baseline_ips = HashSet::new();
        let mut missing = false;

        if let Some(ref v) = plan.baseline_m1 {
            let k = (plan.package.clone(), v.clone());
            match traces_by_probe.get(&k) {
                Some(found) => baseline_ips.extend(found.iter().cloned()),
                None => {
                    println!(
                        "❌ [gyrseek] Sandbox trace missing for baseline '{}@{}'.",
                        plan.package, v
                    );
                    missing = true;
                }
            }
        }
        if let Some(ref v) = plan.baseline_m2 {
            let k = (plan.package.clone(), v.clone());
            match traces_by_probe.get(&k) {
                Some(found) => baseline_ips.extend(found.iter().cloned()),
                None => {
                    println!(
                        "❌ [gyrseek] Sandbox trace missing for baseline '{}@{}'.",
                        plan.package, v
                    );
                    missing = true;
                }
            }
        }

        if missing {
            results.insert(key, false);
            continue;
        }

        let new_connections = find_new_connections(&ips_curr, &baseline_ips);
        if !new_connections.is_empty() {
            let baseline_m1 = plan.baseline_m1.clone().unwrap_or_else(|| "n/a".to_string());
            let baseline_m2 = plan.baseline_m2.clone().unwrap_or_else(|| "n/a".to_string());
            println!("\n❌ [gyrseek] CRITICAL WARNING: Behavioral anomaly flagged!");
            println!(
                "Package '{}', version '{}' contacted new endpoints not seen in baseline versions ({} and {}): {:?}",
                plan.package, plan.current, baseline_m1, baseline_m2, new_connections
            );
            println!("Aborting host operation securely.");
            results.insert(key, false);
            continue;
        }

        results.insert(key, true);
    }

    results
}

pub async fn scan_package_versions(runner: &dyn SandboxRunner, manager: &str, pkg_name: &str, tgt_version: &str) -> bool {
    let targets = vec![(pkg_name.to_string(), tgt_version.to_string())];
    let outcome = scan_packages_versions(runner, manager, &targets).await;
    outcome
        .get(&format!("{}|{}", pkg_name, tgt_version))
        .copied()
        .unwrap_or(false)
}
