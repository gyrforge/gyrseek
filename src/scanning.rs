use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use chrono::{DateTime, Duration, Utc};
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
    eligible_baseline_versions: usize,
    new_package_exempt: bool,
}

#[derive(Deserialize, Debug)]
struct PyPiResponse {
    releases: std::collections::HashMap<String, Vec<PyPiReleaseFile>>,
}

#[derive(Deserialize, Debug)]
struct PyPiReleaseFile {
    upload_time_iso_8601: Option<String>,
    upload_time: Option<String>,
}

#[derive(Deserialize, Debug)]
struct NpmResponse {
    versions: std::collections::HashMap<String, serde_json::Value>,
    #[serde(default)]
    time: std::collections::HashMap<String, String>,
}

const DEFAULT_MIN_BASELINE_AGE_HOURS: i64 = 2;

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
    min_baseline_age_hours: i64,
    release_burst_window_hours: i64,
) -> (String, Vec<String>, usize, Option<i64>) {
    let forced_releases_last_24h = std::env::var("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H")
        .ok()
        .and_then(|v| v.parse::<usize>().ok());
    let forced_current_release_age_days = std::env::var("GYRSEEK_TEST_FORCE_CURRENT_RELEASE_AGE_DAYS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok());
    if forced_releases_last_24h.is_some() || forced_current_release_age_days.is_some() {
        return (
            target_v.to_string(),
            Vec::new(),
            forced_releases_last_24h.unwrap_or(0),
            forced_current_release_age_days,
        );
    }

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
                    let now = Utc::now();
                    let cutoff = now - Duration::hours(min_baseline_age_hours.max(0));
                    let mut published_at: HashMap<String, DateTime<Utc>> = HashMap::new();
                    for (version, ts) in data.time {
                        if let Ok(dt) = DateTime::parse_from_rfc3339(&ts) {
                            published_at.insert(version, dt.with_timezone(&Utc));
                        }
                    }
                    let releases_last_24h = count_releases_in_window(
                        &published_at,
                        now - Duration::hours(release_burst_window_hours.max(1)),
                        now,
                    );
                    let current_release_age_days = published_at
                        .get(&current)
                        .map(|ts| (now - *ts).num_days());
                    let candidates: Vec<String> = versions[..idx].iter().rev().cloned().collect();
                    let baselines =
                        select_age_eligible_baselines(candidates, &published_at, cutoff, baseline_count);
                    return (current, baselines, releases_last_24h, current_release_age_days);
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
                    let now = Utc::now();
                    let cutoff = now - Duration::hours(min_baseline_age_hours.max(0));
                    let mut published_at: HashMap<String, DateTime<Utc>> = HashMap::new();

                    for (version, files) in data.releases {
                        let mut earliest: Option<DateTime<Utc>> = None;
                        for file in files {
                            let parsed = file
                                .upload_time_iso_8601
                                .as_deref()
                                .or(file.upload_time.as_deref())
                                .and_then(|ts| DateTime::parse_from_rfc3339(ts).ok())
                                .map(|dt| dt.with_timezone(&Utc));
                            if let Some(parsed) = parsed {
                                earliest = match earliest {
                                    Some(curr) if curr <= parsed => Some(curr),
                                    _ => Some(parsed),
                                };
                            }
                        }
                        if let Some(ts) = earliest {
                            published_at.insert(version, ts);
                        }
                    }
                    let releases_last_24h = count_releases_in_window(
                        &published_at,
                        now - Duration::hours(release_burst_window_hours.max(1)),
                        now,
                    );
                    let current_release_age_days = published_at
                        .get(&current)
                        .map(|ts| (now - *ts).num_days());

                    let candidates: Vec<String> = versions[..idx].iter().rev().cloned().collect();
                    let baselines =
                        select_age_eligible_baselines(candidates, &published_at, cutoff, baseline_count);
                    return (current, baselines, releases_last_24h, current_release_age_days);
                }
            }
        }
    }

    (target_v.to_string(), Vec::new(), 0, None)
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

fn select_age_eligible_baselines(
    candidates_newest_first: Vec<String>,
    published_at: &HashMap<String, DateTime<Utc>>,
    cutoff: DateTime<Utc>,
    baseline_count: usize,
) -> Vec<String> {
    let mut selected = Vec::new();
    for version in candidates_newest_first {
        if let Some(ts) = published_at.get(&version) {
            if *ts <= cutoff {
                selected.push(version);
                if selected.len() >= baseline_count {
                    break;
                }
            }
        }
    }
    selected
}

fn count_releases_in_window(
    published_at: &HashMap<String, DateTime<Utc>>,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
) -> usize {
    published_at
        .values()
        .filter(|ts| **ts >= window_start && **ts <= window_end)
        .count()
}

fn burst_triggered(releases_in_window: usize, release_burst_threshold: Option<usize>) -> bool {
    match release_burst_threshold {
        Some(threshold) if threshold > 0 => releases_in_window >= threshold,
        _ => false,
    }
}

fn burst_policy_warning(
    package: &str,
    releases_in_window: usize,
    release_burst_threshold: Option<usize>,
    release_burst_window_hours: usize,
) -> Option<String> {
    if !burst_triggered(releases_in_window, release_burst_threshold) {
        return None;
    }

    Some(format!(
        "⚠️ [gyrseek] Release burst threshold triggered for '{}': {} release(s) in last {}h (threshold={}).",
        package,
        releases_in_window,
        release_burst_window_hours,
        release_burst_threshold.unwrap_or(0)
    ))
}

fn minimum_release_age_policy_warning(
    package: &str,
    current_release_age_days: Option<i64>,
    minimum_release_age_package: Option<usize>,
) -> Option<String> {
    let required_days = minimum_release_age_package?;

    let Some(age_days) = current_release_age_days else {
        return Some(format!(
            "⚠️ [gyrseek] minimum_release_age_package triggered for '{}': unable to determine current release age in days.",
            package
        ));
    };

    if age_days < required_days as i64 {
        return Some(format!(
            "⚠️ [gyrseek] minimum_release_age_package triggered for '{}': current release age is {} day(s), required >= {} day(s).",
            package,
            age_days,
            required_days
        ));
    }

    None
}

fn exemption_behavior(new_package_exempt: bool, eligible_baseline_versions: usize) -> (bool, bool) {
    if !new_package_exempt {
        return (false, false);
    }
    if eligible_baseline_versions < 2 {
        return (true, false);
    }
    (false, true)
}

pub async fn scan_packages_versions(
    runner: &dyn SandboxRunner,
    manager: &str,
    pkg_targets: &[(String, String)],
    ip_allowlist: &HashSet<String>,
    domain_allowlist: &HashSet<String>,
    baseline_overrides: &HashMap<String, (Option<String>, Option<String>)>,
    baseline_count: usize,
    min_baseline_age_hours_by_package: &HashMap<String, usize>,
    new_package_exemptions: &HashSet<String>,
    release_burst_threshold: Option<usize>,
    release_burst_window_hours: usize,
    minimum_release_age_package: Option<usize>,
) -> HashMap<String, bool> {
    let mut results = HashMap::new();
    if pkg_targets.is_empty() {
        return results;
    }

    let mut plans = Vec::new();
    for (pkg_name, tgt_version) in pkg_targets {
        let min_baseline_age_hours = min_baseline_age_hours_by_package
            .get(pkg_name)
            .copied()
            .unwrap_or(DEFAULT_MIN_BASELINE_AGE_HOURS as usize) as i64;

        let fetch_count = baseline_count.max(2);
        let (v_curr, fetched_baselines, releases_last_24h, current_release_age_days) =
            fetch_history_with_baselines(
                manager,
                pkg_name,
                tgt_version,
                fetch_count,
                min_baseline_age_hours,
                release_burst_window_hours as i64,
            )
            .await;

        if let Some(warning) = minimum_release_age_policy_warning(
            pkg_name,
            current_release_age_days,
            minimum_release_age_package,
        ) {
            println!("{}", warning);
            println!("Aborting host operation securely.");
            results.insert(format!("{}|{}", pkg_name, tgt_version), false);
            continue;
        }

        if let Some(warning) = burst_policy_warning(
            pkg_name,
            releases_last_24h,
            release_burst_threshold,
            release_burst_window_hours,
        ) {
            println!("{}", warning);
            println!("Aborting host operation securely.");
            results.insert(format!("{}|{}", pkg_name, tgt_version), false);
            continue;
        }

        let eligible_baseline_versions = fetched_baselines.len();

        let baselines = select_effective_baselines(
            &v_curr,
            fetched_baselines,
            baseline_overrides.get(pkg_name),
            baseline_count,
        );

        let new_package_exempt = new_package_exemptions.contains(pkg_name);
        let (_, should_warn_exemption) = exemption_behavior(new_package_exempt, eligible_baseline_versions);
        if should_warn_exemption {
            println!(
                "⚠️ [gyrseek] Package '{}' is listed in new_package_exemptions but now has {} eligible baseline versions; consider removing the exemption.",
                pkg_name, eligible_baseline_versions
            );
        }

        if baseline_overrides.get(pkg_name).is_some() {
            println!(
                "ℹ️ [gyrseek] Applying baseline override(s) for '{}': baseline set={:?}",
                pkg_name,
                baselines
            );
        }

        println!(
            "🛡️ [gyrseek] Comparing versions for '{}': current={} baselines={:?} (min_baseline_age_hours={})",
            pkg_name, v_curr, baselines, min_baseline_age_hours
        );

        plans.push(VersionPlan {
            package: pkg_name.clone(),
            target_version: tgt_version.clone(),
            current: v_curr,
            baselines,
            eligible_baseline_versions,
            new_package_exempt,
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

        let (skip_due_to_exemption, _) =
            exemption_behavior(plan.new_package_exempt, plan.eligible_baseline_versions);
        if skip_due_to_exemption {
            println!(
                "⚠️ [gyrseek] New package exemption applied for '{}': only {} eligible baseline version(s) available (<2). Skipping anomaly block for now.",
                plan.package, plan.eligible_baseline_versions
            );
            results.insert(key, true);
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
    use std::collections::HashMap;

    use chrono::{TimeZone, Utc};

    use super::{
        burst_policy_warning, burst_triggered, exemption_behavior,
        minimum_release_age_policy_warning, select_age_eligible_baselines,
        select_effective_baselines,
    };

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

    #[test]
    fn age_filter_keeps_only_versions_older_than_cutoff() {
        let candidates = vec![
            "2.9.0".to_string(),
            "2.8.0".to_string(),
            "2.7.0".to_string(),
        ];
        let cutoff = Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap();

        let mut published = HashMap::new();
        published.insert(
            "2.9.0".to_string(),
            Utc.with_ymd_and_hms(2026, 1, 1, 13, 0, 0).unwrap(),
        );
        published.insert(
            "2.8.0".to_string(),
            Utc.with_ymd_and_hms(2026, 1, 1, 11, 59, 0).unwrap(),
        );
        published.insert(
            "2.7.0".to_string(),
            Utc.with_ymd_and_hms(2025, 12, 31, 10, 0, 0).unwrap(),
        );

        let selected = select_age_eligible_baselines(candidates, &published, cutoff, 2);
        assert_eq!(selected, vec!["2.8.0".to_string(), "2.7.0".to_string()]);
    }

    #[test]
    fn age_filter_includes_versions_exactly_at_cutoff() {
        let candidates = vec!["2.9.0".to_string(), "2.8.0".to_string()];
        let cutoff = Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap();

        let mut published = HashMap::new();
        published.insert("2.9.0".to_string(), cutoff);
        published.insert(
            "2.8.0".to_string(),
            Utc.with_ymd_and_hms(2026, 1, 1, 11, 0, 0).unwrap(),
        );

        let selected = select_age_eligible_baselines(candidates, &published, cutoff, 2);
        assert_eq!(selected, vec!["2.9.0".to_string(), "2.8.0".to_string()]);
    }

    #[test]
    fn age_filter_skips_candidates_without_publish_timestamps() {
        let candidates = vec!["2.9.0".to_string(), "2.8.0".to_string(), "2.7.0".to_string()];
        let cutoff = Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap();

        let mut published = HashMap::new();
        published.insert(
            "2.8.0".to_string(),
            Utc.with_ymd_and_hms(2026, 1, 1, 11, 0, 0).unwrap(),
        );
        published.insert(
            "2.7.0".to_string(),
            Utc.with_ymd_and_hms(2026, 1, 1, 10, 0, 0).unwrap(),
        );

        let selected = select_age_eligible_baselines(candidates, &published, cutoff, 2);
        assert_eq!(selected, vec!["2.8.0".to_string(), "2.7.0".to_string()]);
    }

    #[test]
    fn age_filter_still_respects_baseline_count_limit() {
        let candidates = vec![
            "2.9.0".to_string(),
            "2.8.0".to_string(),
            "2.7.0".to_string(),
            "2.6.0".to_string(),
        ];
        let cutoff = Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap();

        let mut published = HashMap::new();
        published.insert(
            "2.9.0".to_string(),
            Utc.with_ymd_and_hms(2026, 1, 1, 11, 59, 0).unwrap(),
        );
        published.insert(
            "2.8.0".to_string(),
            Utc.with_ymd_and_hms(2026, 1, 1, 11, 0, 0).unwrap(),
        );
        published.insert(
            "2.7.0".to_string(),
            Utc.with_ymd_and_hms(2026, 1, 1, 10, 0, 0).unwrap(),
        );
        published.insert(
            "2.6.0".to_string(),
            Utc.with_ymd_and_hms(2026, 1, 1, 9, 0, 0).unwrap(),
        );

        let selected = select_age_eligible_baselines(candidates, &published, cutoff, 2);
        assert_eq!(selected, vec!["2.9.0".to_string(), "2.8.0".to_string()]);
    }

    #[test]
    fn exemption_applies_only_when_less_than_two_baselines() {
        assert_eq!(exemption_behavior(true, 0), (true, false));
        assert_eq!(exemption_behavior(true, 1), (true, false));
        assert_eq!(exemption_behavior(true, 2), (false, true));
        assert_eq!(exemption_behavior(false, 0), (false, false));
    }

    #[test]
    fn baseline_count_zero_returns_no_effective_baselines() {
        let out = select_effective_baselines(
            "3.0.0",
            vec!["2.9.0".to_string(), "2.8.0".to_string()],
            None,
            0,
        );
        assert!(out.is_empty());
    }

    #[test]
    fn override_order_is_preserved_then_filled_from_fetched() {
        let override_pair = (Some("2.7.0".to_string()), Some("2.6.0".to_string()));
        let out = select_effective_baselines(
            "3.0.0",
            vec!["2.9.0".to_string(), "2.8.0".to_string(), "2.7.0".to_string()],
            Some(&override_pair),
            4,
        );
        assert_eq!(
            out,
            vec![
                "2.7.0".to_string(),
                "2.6.0".to_string(),
                "2.9.0".to_string(),
                "2.8.0".to_string()
            ]
        );
    }

    #[test]
    fn burst_threshold_disabled_by_default() {
        assert!(!burst_triggered(100, None));
    }

    #[test]
    fn burst_threshold_triggers_at_or_above_threshold() {
        assert!(!burst_triggered(2, Some(3)));
        assert!(burst_triggered(3, Some(3)));
        assert!(burst_triggered(4, Some(3)));
    }

    #[test]
    fn burst_policy_emits_warning_when_triggered() {
        let warning = burst_policy_warning("requests", 3, Some(3), 12);
        assert!(warning.is_some());
        let text = warning.unwrap_or_default();
        assert!(text.contains("Release burst threshold triggered"));
        assert!(text.contains("requests"));
        assert!(text.contains("last 12h"));
    }

    #[test]
    fn burst_policy_has_no_warning_when_not_triggered() {
        assert!(burst_policy_warning("requests", 2, Some(3), 24).is_none());
        assert!(burst_policy_warning("requests", 100, None, 24).is_none());
    }

    #[test]
    fn minimum_release_age_policy_warns_when_release_is_too_new() {
        let warning = minimum_release_age_policy_warning("requests", Some(1), Some(3));
        assert!(warning.is_some());
        let text = warning.unwrap_or_default();
        assert!(text.contains("minimum_release_age_package triggered"));
        assert!(text.contains("required >= 3"));
    }

    #[test]
    fn minimum_release_age_policy_has_no_warning_when_release_is_old_enough() {
        assert!(minimum_release_age_policy_warning("requests", Some(5), Some(3)).is_none());
    }

    #[test]
    fn minimum_release_age_policy_disabled_by_default() {
        assert!(minimum_release_age_policy_warning("requests", Some(0), None).is_none());
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
    min_baseline_age_hours_by_package: &HashMap<String, usize>,
    new_package_exemptions: &HashSet<String>,
    release_burst_threshold: Option<usize>,
    release_burst_window_hours: usize,
    minimum_release_age_package: Option<usize>,
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
        min_baseline_age_hours_by_package,
        new_package_exemptions,
        release_burst_threshold,
        release_burst_window_hours,
        minimum_release_age_package,
    )
    .await;
    outcome
        .get(&format!("{}|{}", pkg_name, tgt_version))
        .copied()
        .unwrap_or(false)
}
