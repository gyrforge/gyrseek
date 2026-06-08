use std::collections::HashSet;
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

pub fn trace_sandbox_install(manager: &str, package: &str, version: &str) -> HashSet<String> {
    let mut ips = HashSet::new();
    let temp_dir = tempfile::tempdir().unwrap();
    let target_path = temp_dir.path().to_str().unwrap();

    let cmd_args = if manager == "npm" {
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

pub async fn scan_package_versions(manager: &str, pkg_name: &str, tgt_version: &str) -> bool {
    let (v_curr, v_m1, v_m2) = fetch_history(manager, pkg_name, tgt_version).await;
    let baseline_m1 = v_m1.clone().unwrap_or_else(|| "n/a".to_string());
    let baseline_m2 = v_m2.clone().unwrap_or_else(|| "n/a".to_string());
    println!(
        "🛡️ [gyrseek] Comparing versions for '{}': current={} baseline-1={} baseline-2={}",
        pkg_name, v_curr, baseline_m1, baseline_m2
    );

    let ips_curr = trace_sandbox_install(manager, pkg_name, &v_curr);

    let mut baseline_ips = HashSet::new();
    if let Some(ref v) = v_m1 {
        baseline_ips.extend(trace_sandbox_install(manager, pkg_name, v));
    }
    if let Some(ref v) = v_m2 {
        baseline_ips.extend(trace_sandbox_install(manager, pkg_name, v));
    }

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
