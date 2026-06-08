use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use dns_lookup::lookup_addr;
use regex::Regex;
use serde::Deserialize;

use crate::sandbox::SandboxRunner;

#[derive(Clone)]
struct VersionPlan {
    package: String,
    target_version: String,
    current: String,
    baselines: Vec<String>,
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

pub fn filter_allowlisted_new_connections(
    new_connections: Vec<String>,
    ip_allowlist: &HashSet<String>,
) -> (Vec<String>, Vec<String>) {
    let mut remaining = Vec::new();
    let mut allowlisted = Vec::new();

    let canonical_allowlist: HashSet<String> = ip_allowlist
        .iter()
        .filter_map(|ip| ip.parse::<IpAddr>().ok().map(|addr| addr.to_string()))
        .collect();

    for ip in new_connections {
        match ip.parse::<IpAddr>() {
            Ok(addr) => {
                let canonical = addr.to_string();
                if canonical_allowlist.contains(&canonical) {
                    allowlisted.push(ip);
                } else {
                    remaining.push(ip);
                }
            }
            Err(_) => remaining.push(ip),
        }
    }

    (remaining, allowlisted)
}

fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn domain_is_allowlisted(domain: &str, domain_allowlist: &HashSet<String>) -> bool {
    let normalized = normalize_domain(domain);
    for allowed in domain_allowlist {
        let allowed = normalize_domain(allowed);
        if normalized == allowed || normalized.ends_with(&format!(".{}", allowed)) {
            return true;
        }
    }
    false
}

pub fn filter_domain_allowlisted_new_connections_with<F>(
    new_connections: Vec<String>,
    domain_allowlist: &HashSet<String>,
    resolver: F,
) -> (Vec<String>, Vec<String>)
where
    F: Fn(&str) -> Option<String>,
{
    let mut remaining = Vec::new();
    let mut allowlisted = Vec::new();

    for ip in new_connections {
        match resolver(&ip) {
            Some(domain) if domain_is_allowlisted(&domain, domain_allowlist) => {
                allowlisted.push(format!("{} -> {}", ip, domain));
            }
            _ => remaining.push(ip),
        }
    }

    (remaining, allowlisted)
}

fn reverse_dns_domain(ip: &str) -> Option<String> {
    let addr: IpAddr = ip.parse().ok()?;
    lookup_addr(&addr).ok()
}

pub fn enrich_new_connection_domains_with<F>(
    new_connections: &[String],
    baseline_ips: &HashSet<String>,
    resolver: F,
) -> (Vec<String>, Vec<String>)
where
    F: Fn(&str) -> Option<String>,
{
    let mut baseline_domains = HashSet::new();
    for ip in baseline_ips {
        if let Some(domain) = resolver(ip) {
            baseline_domains.insert(domain);
        }
    }

    let mut new_ip_domain_matches = Vec::new();
    let mut new_ip_domain_context = Vec::new();

    for ip in new_connections {
        if let Some(domain) = resolver(ip) {
            new_ip_domain_context.push(format!("{} -> {}", ip, domain));
            if baseline_domains.contains(&domain) {
                new_ip_domain_matches.push(format!("{} -> {}", ip, domain));
            }
        }
    }

    (new_ip_domain_context, new_ip_domain_matches)
}

pub async fn fetch_history_with_baselines(
    manager: &str,
    package: &str,
    target_v: &str,
    baseline_count: usize,
) -> (String, Vec<String>) {
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
                    let start = idx.saturating_sub(baseline_count);
                    let baselines = versions[start..idx].iter().rev().cloned().collect();
                    return (current, baselines);
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
                    let start = idx.saturating_sub(baseline_count);
                    let baselines = versions[start..idx].iter().rev().cloned().collect();
                    return (current, baselines);
                }
            }
        }
    }

    (target_v.to_string(), Vec::new())
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

fn select_effective_baselines(
    current: &str,
    fetched_baselines: Vec<String>,
    baseline_override: Option<&(Option<String>, Option<String>)>,
    baseline_count: usize,
) -> Vec<String> {
    if baseline_count == 0 {
        return Vec::new();
    }

    let mut baselines = fetched_baselines;

    if let Some((override_m1, override_m2)) = baseline_override {
        let mut merged = Vec::new();
        if let Some(v) = override_m1.clone() {
            merged.push(v);
        }
        if let Some(v) = override_m2.clone() {
            if !merged.contains(&v) {
                merged.push(v);
            }
        }

        for v in &baselines {
            if merged.len() >= baseline_count {
                break;
            }
            if !merged.contains(v) && v != current {
                merged.push(v.clone());
            }
        }

        baselines = merged;
    }

    if baselines.len() > baseline_count {
        baselines.truncate(baseline_count);
    }

    baselines
}

pub async fn scan_packages_versions(
    runner: &dyn SandboxRunner,
    manager: &str,
    pkg_targets: &[(String, String)],
    ip_allowlist: &HashSet<String>,
    domain_allowlist: &HashSet<String>,
    baseline_overrides: &HashMap<String, (Option<String>, Option<String>)>,
    baseline_count: usize,
) -> HashMap<String, bool> {
    let mut results = HashMap::new();
    if pkg_targets.is_empty() {
        return results;
    }

    let mut plans = Vec::new();
    for (pkg_name, tgt_version) in pkg_targets {
        let (v_curr, fetched_baselines) =
            fetch_history_with_baselines(manager, pkg_name, tgt_version, baseline_count).await;
        let baselines = select_effective_baselines(
            &v_curr,
            fetched_baselines,
            baseline_overrides.get(pkg_name),
            baseline_count,
        );

        if baseline_overrides.get(pkg_name).is_some() {
            println!(
                "ℹ️ [gyrseek] Applying baseline override(s) for '{}': baseline set={:?}",
                pkg_name,
                baselines
            );
        }

        println!(
            "🛡️ [gyrseek] Comparing versions for '{}': current={} baselines={:?}",
            pkg_name, v_curr, baselines
        );

        plans.push(VersionPlan {
            package: pkg_name.clone(),
            target_version: tgt_version.clone(),
            current: v_curr,
            baselines,
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
        for v in &plan.baselines {
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

        for v in &plan.baselines {
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
        let (new_connections, allowlisted_connections) =
            filter_allowlisted_new_connections(new_connections, ip_allowlist);
        let (new_connections, allowlisted_domain_connections) = filter_domain_allowlisted_new_connections_with(
            new_connections,
            domain_allowlist,
            reverse_dns_domain,
        );

        if !allowlisted_connections.is_empty() {
            println!(
                "ℹ️ [gyrseek] IP allowlist ignored new endpoint(s) for '{}': {:?}",
                plan.package, allowlisted_connections
            );
        }
        if !allowlisted_domain_connections.is_empty() {
            println!(
                "ℹ️ [gyrseek] Domain allowlist ignored new endpoint(s) for '{}': {:?}",
                plan.package, allowlisted_domain_connections
            );
        }

        if !new_connections.is_empty() {
            let baseline_label = if plan.baselines.is_empty() {
                "n/a".to_string()
            } else {
                plan.baselines.join(", ")
            };

            let (new_ip_domain_context, new_ip_domain_matches) =
                enrich_new_connection_domains_with(&new_connections, &baseline_ips, reverse_dns_domain);

            println!("\n❌ [gyrseek] CRITICAL WARNING: Behavioral anomaly flagged!");
            println!(
                "Package '{}', version '{}' contacted new endpoints not seen in baseline versions ({}): {:?}",
                plan.package, plan.current, baseline_label, new_connections
            );
            if !new_ip_domain_context.is_empty() {
                println!(
                    "ℹ️ [gyrseek] Reverse DNS context for new IPs (informational only): {:?}",
                    new_ip_domain_context
                );
            }
            if !new_ip_domain_matches.is_empty() {
                println!(
                    "ℹ️ [gyrseek] Some new IPs map to domains seen in baseline traffic: {:?}",
                    new_ip_domain_matches
                );
            }
            println!("Aborting host operation securely.");
            results.insert(key, false);
            continue;
        }

        results.insert(key, true);
    }

    results
}

#[cfg(test)]
mod tests {
    use super::select_effective_baselines;

    #[test]
    fn baseline_count_limits_fetched_baselines_without_overrides() {
        let out = select_effective_baselines(
            "3.0.0",
            vec!["2.9.0".to_string(), "2.8.0".to_string(), "2.7.0".to_string()],
            None,
            2,
        );
        assert_eq!(out, vec!["2.9.0".to_string(), "2.8.0".to_string()]);
    }

    #[test]
    fn overrides_take_priority_and_fill_remaining_slots() {
        let override_pair = (Some("2.5.0".to_string()), None);
        let out = select_effective_baselines(
            "3.0.0",
            vec!["2.9.0".to_string(), "2.8.0".to_string(), "2.7.0".to_string()],
            Some(&override_pair),
            3,
        );
        assert_eq!(
            out,
            vec!["2.5.0".to_string(), "2.9.0".to_string(), "2.8.0".to_string()]
        );
    }

    #[test]
    fn duplicate_override_versions_are_deduped_and_truncated() {
        let override_pair = (Some("2.9.0".to_string()), Some("2.9.0".to_string()));
        let out = select_effective_baselines(
            "3.0.0",
            vec!["2.9.0".to_string(), "2.8.0".to_string()],
            Some(&override_pair),
            2,
        );
        assert_eq!(out, vec!["2.9.0".to_string(), "2.8.0".to_string()]);
    }
}

pub async fn scan_package_versions(
    runner: &dyn SandboxRunner,
    manager: &str,
    pkg_name: &str,
    tgt_version: &str,
    ip_allowlist: &HashSet<String>,
    domain_allowlist: &HashSet<String>,
    baseline_overrides: &HashMap<String, (Option<String>, Option<String>)>,
    baseline_count: usize,
) -> bool {
    let targets = vec![(pkg_name.to_string(), tgt_version.to_string())];
    let outcome = scan_packages_versions(
        runner,
        manager,
        &targets,
        ip_allowlist,
        domain_allowlist,
        baseline_overrides,
        baseline_count,
    )
    .await;
    outcome
        .get(&format!("{}|{}", pkg_name, tgt_version))
        .copied()
        .unwrap_or(false)
}
