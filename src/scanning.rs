use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::OnceLock;

use chrono::{DateTime, Duration, Utc};
use dns_lookup::{lookup_addr, lookup_host};
use regex::Regex;
use serde::Deserialize;

use crate::sandbox::SandboxRunner;

/// Policy knobs resolved from the YAML config (or defaults), passed by reference
/// into the scanner so call sites don't have to thread a dozen positional args.
#[derive(Clone, Debug)]
pub(crate) struct PolicyConfig {
    pub ip_allowlist: HashSet<String>,
    pub domain_allowlist: HashSet<String>,
    pub git_clone_allowlist: HashSet<String>,
    pub baseline_overrides: HashMap<String, (Option<String>, Option<String>)>,
    pub baseline_count: usize,
    pub min_baseline_age_hours_by_package: HashMap<String, usize>,
    pub new_package_exemptions: HashSet<String>,
    pub release_burst_threshold: Option<usize>,
    pub release_burst_window_hours: usize,
    pub minimum_release_age_package: Option<usize>,
    /// Executable basenames whose execution during install is tracked and diffed
    /// across versions (e.g. `bun`, `deno`). New or changed invocations of these
    /// are fail-closed anomalies.
    pub watched_executables: HashSet<String>,
    /// Watched-process signatures (`bun|run|build`) or bare executables (`bun`)
    /// that are explicitly allowed even when newly introduced.
    pub process_exec_allowlist: HashSet<String>,
}

/// The executables gyrseek watches by default. These are runtimes that
/// essentially never appear in a normal npm/pip install, so flagging a newly
/// introduced invocation has a very low false-positive rate while catching the
/// Shai-Hulud "download Bun and run the stealer" pattern.
pub(crate) fn default_watched_executables() -> HashSet<String> {
    ["bun", "deno"].into_iter().map(String::from).collect()
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            ip_allowlist: HashSet::new(),
            domain_allowlist: HashSet::new(),
            git_clone_allowlist: HashSet::new(),
            baseline_overrides: HashMap::new(),
            baseline_count: 2,
            min_baseline_age_hours_by_package: HashMap::new(),
            new_package_exemptions: HashSet::new(),
            release_burst_threshold: None,
            release_burst_window_hours: 24,
            minimum_release_age_package: None,
            watched_executables: default_watched_executables(),
            process_exec_allowlist: HashSet::new(),
        }
    }
}

/// Outcome of scanning a single (package, requested-version) target.
#[derive(Clone, Debug)]
pub(crate) struct ScanReport {
    /// Whether the host command is allowed to proceed for this target.
    pub allowed: bool,
    /// The concrete version the scanner actually resolved and examined. For an
    /// unpinned ("latest") request this is the version the registry ordering
    /// selected, which callers should pin the forwarded command to.
    pub resolved_version: String,
}

/// Orders version strings using real semantics rather than lexicographically:
/// semver for npm, PEP 440 for the Python managers. Strings that fail to parse
/// are treated as lower than any parseable version (so junk is never selected as
/// "latest"), with two unparseable strings falling back to lexical order.
fn compare_version_strings(manager: &str, a: &str, b: &str) -> Ordering {
    if manager == "npm" {
        match (semver::Version::parse(a), semver::Version::parse(b)) {
            (Ok(x), Ok(y)) => x.cmp(&y),
            (Ok(_), Err(_)) => Ordering::Greater,
            (Err(_), Ok(_)) => Ordering::Less,
            (Err(_), Err(_)) => a.cmp(b),
        }
    } else {
        match (
            a.parse::<pep440_rs::Version>(),
            b.parse::<pep440_rs::Version>(),
        ) {
            (Ok(x), Ok(y)) => x.cmp(&y),
            (Ok(_), Err(_)) => Ordering::Greater,
            (Err(_), Ok(_)) => Ordering::Less,
            (Err(_), Err(_)) => a.cmp(b),
        }
    }
}

/// Sorts versions ascending (oldest/lowest first) by semantic order.
fn sort_versions_ascending(manager: &str, versions: &mut [String]) {
    versions.sort_by(|a, b| compare_version_strings(manager, a, b));
}

#[derive(Default, Clone)]
struct TraceSignals {
    ips: HashSet<String>,
    git_clone_signatures: HashSet<String>,
    process_exec_signatures: HashSet<String>,
}

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
pub(crate) fn find_new_connections(ips_curr: &HashSet<String>, baseline_ips: &HashSet<String>) -> Vec<String> {
    ips_curr.difference(baseline_ips).cloned().collect()
}

pub(crate) fn filter_allowlisted_new_connections(
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

pub(crate) fn filter_domain_allowlisted_new_connections_with<F>(
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

/// Forward-confirmed reverse DNS (FCrDNS) for `ip`.
///
/// A raw PTR record is controlled by whoever owns the IP address, so an attacker
/// can point their C2 server's reverse DNS at any allowlisted domain. To prevent
/// that bypass we resolve the PTR hostname *forward* and only return it if one of
/// its A/AAAA records maps back to the original IP. A hostname that does not
/// forward-confirm is discarded (treated as if there were no reverse record).
fn reverse_dns_domain(ip: &str) -> Option<String> {
    let addr: IpAddr = ip.parse().ok()?;
    forward_confirmed_hostname(addr, |a| lookup_addr(&a).ok(), |h| lookup_host(h).ok())
}

/// Pure FCrDNS decision, with DNS lookups injected so it is deterministically
/// testable. Returns the PTR hostname only if its forward resolution includes
/// the original address; otherwise `None`.
fn forward_confirmed_hostname<R, F>(addr: IpAddr, reverse: R, forward: F) -> Option<String>
where
    R: Fn(IpAddr) -> Option<String>,
    F: Fn(&str) -> Option<Vec<IpAddr>>,
{
    let hostname = reverse(addr)?;
    let resolved = forward(&hostname)?;
    if resolved.contains(&addr) {
        Some(hostname)
    } else {
        None
    }
}

pub(crate) fn enrich_new_connection_domains_with<F>(
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

pub(crate) async fn fetch_history_with_baselines(
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
        if let Ok(res) = client.get(&url).send().await
            && let Ok(data) = res.json::<NpmResponse>().await {
                let mut versions: Vec<String> = data.versions.keys().cloned().collect();
                sort_versions_ascending(manager, &mut versions);

                let current = if target_v == "latest" {
                    versions.last().cloned().unwrap_or_else(|| target_v.to_string())
                } else {
                    target_v.to_string()
                };

                if let Some(idx) = versions.iter().position(|v| v == &current) {
                    let now = Utc::now();
                    let cutoff = now - Duration::hours(min_baseline_age_hours.max(0));
                    let version_keys: HashSet<String> = data.versions.keys().cloned().collect();
                    let published_at = npm_published_times(&data.time, &version_keys);
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
    } else {
        let url = format!("https://pypi.org/pypi/{}/json", package);
        if let Ok(res) = client.get(&url).send().await
            && let Ok(data) = res.json::<PyPiResponse>().await {
                let mut versions: Vec<String> = data.releases.keys().cloned().collect();
                sort_versions_ascending(manager, &mut versions);

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

    (target_v.to_string(), Vec::new(), 0, None)
}

fn trace_sandbox_install_matrix(
    runner: &dyn SandboxRunner,
    manager: &str,
    probes: &[(String, String)],
    watched_executables: &HashSet<String>,
) -> Result<HashMap<(String, String), TraceSignals>, String> {
    let traces = runner.trace_install_matrix(manager, probes)?;
    let mut by_probe: HashMap<(String, String), TraceSignals> = HashMap::new();

    for ((package, version), stderr_str) in traces {
        let signals = TraceSignals {
            ips: extract_connection_ips(&stderr_str),
            git_clone_signatures: extract_git_clone_signatures(&stderr_str),
            process_exec_signatures: extract_process_exec_signatures(&stderr_str, watched_executables),
        };
        by_probe.insert((package, version), signals);
    }

    Ok(by_probe)
}

/// Extracts both IPv4 and IPv6 connection endpoints from an strace trace.
///
/// IPv4 appears as `sin_addr=inet_addr("1.2.3.4")`. IPv6 appears as
/// `sin6_addr=inet_pton(AF_INET6, "2001:db8::1", ...)` (and the abbreviated
/// `inet_pton("2001:db8::1")` form some strace builds emit). Captured IPv6
/// values are normalised through `IpAddr` so equivalent textual forms compare
/// equal against baselines and allowlists.
fn extract_connection_ips(trace: &str) -> HashSet<String> {
    static V4: OnceLock<Regex> = OnceLock::new();
    static V6: OnceLock<Regex> = OnceLock::new();

    let v4 = V4.get_or_init(|| Regex::new(r#"sin_addr=inet_addr\("([\d.]+)"\)"#).unwrap());
    let v6 = V6.get_or_init(|| {
        Regex::new(r#"inet_pton\(\s*AF_INET6\s*,\s*"([0-9A-Fa-f:.]+)"|sin6_addr=inet_pton\(\s*AF_INET6\s*,\s*"([0-9A-Fa-f:.]+)""#)
            .unwrap()
    });

    let mut ips = HashSet::new();
    for cap in v4.captures_iter(trace) {
        ips.insert(cap[1].to_string());
    }
    for cap in v6.captures_iter(trace) {
        if let Some(raw) = cap.get(1).or_else(|| cap.get(2)) {
            let raw = raw.as_str();
            let canonical = raw
                .parse::<IpAddr>()
                .map(|addr| addr.to_string())
                .unwrap_or_else(|_| raw.to_string());
            ips.insert(canonical);
        }
    }
    ips
}

/// Parses every `execve(..., [argv], ...)` line in an strace trace into its
/// decoded argv vector. Shared by the git-clone and watched-process extractors.
fn parse_execve_argvs(trace: &str) -> Vec<Vec<String>> {
    static EXECVE_RE: OnceLock<Regex> = OnceLock::new();
    static QUOTED_ARG_RE: OnceLock<Regex> = OnceLock::new();

    // The argv group must tolerate `]` *inside* arguments (e.g. PEP 508 extras
    // like `requests[security]` or a path such as `script[obf].js`). A plain
    // `[^\]]*` stops at the first inner `]` and truncates the argument, which
    // both corrupts extracted signatures and lets a truncated baseline/current
    // pair match and bypass detection. `[^\[\]]*(?:\[[^\]]*\][^\[\]]*)*` consumes
    // any number of balanced `[...]` spans before the array's real closing `]`.
    let execve_re = EXECVE_RE.get_or_init(|| {
        Regex::new(r#"execve\([^,]+,\s*\[(?P<argv>[^\[\]]*(?:\[[^\]]*\][^\[\]]*)*)\]"#).unwrap()
    });
    let quoted_arg_re =
        QUOTED_ARG_RE.get_or_init(|| Regex::new(r#"\"((?:\\.|[^\"])*)\""#).unwrap());

    let mut argvs = Vec::new();
    for cap in execve_re.captures_iter(trace) {
        let argv = cap.name("argv").map(|m| m.as_str()).unwrap_or("");
        let args: Vec<String> = quoted_arg_re
            .captures_iter(argv)
            .filter_map(|m| m.get(1).map(|x| x.as_str().replace("\\\"", "\"")))
            .collect();
        if !args.is_empty() {
            argvs.push(args);
        }
    }
    argvs
}

/// Returns the lowercased basename of an executable path (`/usr/bin/bun` -> `bun`).
fn executable_basename(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase()
}

fn extract_git_clone_signatures(trace: &str) -> HashSet<String> {
    let mut signatures = HashSet::new();

    for mut args in parse_execve_argvs(trace) {
        // strace argv usually starts with executable name as argv[0].
        let first = args.remove(0);
        let first_lower = first.to_ascii_lowercase();
        let first_is_git = first_lower == "git" || first_lower.ends_with("/git");
        if !first_is_git {
            continue;
        }

        let clone_pos = args.iter().position(|a| a == "clone");
        let Some(clone_pos) = clone_pos else {
            continue;
        };

        let post_clone = &args[(clone_pos + 1)..];
        let mut target: Option<String> = None;
        for token in post_clone {
            if token.starts_with('-') {
                continue;
            }
            target = Some(token.to_string());
            break;
        }

        let recursive = post_clone
            .iter()
            .any(|a| a == "--recursive" || a == "--recurse-submodules");
        let target = target.unwrap_or_else(|| "unknown-target".to_string());
        let signature = if recursive {
            format!("{}|recursive", target)
        } else {
            format!("{}|non-recursive", target)
        };
        signatures.insert(signature);
    }

    signatures
}

/// Extracts execution signatures for *watched* executables (default `bun`,
/// `deno`) from an strace trace. Each signature is the executable basename
/// joined with its argv, e.g. `bun|run|_index.js`.
///
/// This is what detects the Shai-Hulud "Hades/miasma" class of attack, where a
/// compromised package downloads the Bun runtime during install and runs an
/// obfuscated stealer via `bun run`. Diffed against baseline versions, it flags
/// both "this version started executing bun" and "this version runs bun but with
/// new/extra arguments not seen before".
fn extract_process_exec_signatures(
    trace: &str,
    watched_executables: &HashSet<String>,
) -> HashSet<String> {
    if watched_executables.is_empty() {
        return HashSet::new();
    }

    let watched: HashSet<String> = watched_executables
        .iter()
        .map(|e| e.trim().to_ascii_lowercase())
        .filter(|e| !e.is_empty())
        .collect();

    let mut signatures = HashSet::new();
    for args in parse_execve_argvs(trace) {
        let exe = executable_basename(&args[0]);
        if !watched.contains(&exe) {
            continue;
        }
        // Signature = basename + remaining argv, so changed/extra args produce a
        // distinct signature that won't match the baseline set.
        let mut parts = vec![exe];
        parts.extend(args[1..].iter().cloned());
        signatures.insert(parts.join("|"));
    }
    signatures
}

fn find_new_git_clone_signatures(
    current: &HashSet<String>,
    baseline: &HashSet<String>,
) -> Vec<String> {
    let mut out: Vec<String> = current.difference(baseline).cloned().collect();
    out.sort();
    out
}

/// Signatures present in the current version but absent from every baseline.
fn find_new_process_exec_signatures(
    current: &HashSet<String>,
    baseline: &HashSet<String>,
) -> Vec<String> {
    let mut out: Vec<String> = current.difference(baseline).cloned().collect();
    out.sort();
    out
}

/// Splits watched-process signatures into (blocked, allowlisted). An entry is
/// allowlisted if the policy lists either the exact signature (`bun|run|build`)
/// or just the executable basename (`bun`), both compared case-insensitively.
fn filter_allowlisted_process_exec_signatures(
    signatures: Vec<String>,
    process_exec_allowlist: &HashSet<String>,
) -> (Vec<String>, Vec<String>) {
    let normalized_allowlist: HashSet<String> = process_exec_allowlist
        .iter()
        .map(|v| v.trim().to_ascii_lowercase())
        .filter(|v| !v.is_empty())
        .collect();

    let mut remaining = Vec::new();
    let mut allowlisted = Vec::new();

    for signature in signatures {
        let lower = signature.to_ascii_lowercase();
        let exe = lower.split('|').next().unwrap_or("").to_string();
        if normalized_allowlist.contains(&lower) || normalized_allowlist.contains(&exe) {
            allowlisted.push(signature);
        } else {
            remaining.push(signature);
        }
    }

    (remaining, allowlisted)
}

fn filter_allowlisted_git_clone_signatures(
    signatures: Vec<String>,
    git_clone_allowlist: &HashSet<String>,
) -> (Vec<String>, Vec<String>) {
    let mut remaining = Vec::new();
    let mut allowlisted = Vec::new();

    let normalized_allowlist: HashSet<String> = git_clone_allowlist
        .iter()
        .map(|v| v.trim().to_ascii_lowercase())
        .filter(|v| !v.is_empty())
        .collect();

    for signature in signatures {
        let target = signature
            .split('|')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();

        if !target.is_empty() && normalized_allowlist.contains(&target) {
            allowlisted.push(signature);
        } else {
            remaining.push(signature);
        }
    }

    (remaining, allowlisted)
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
        if let Some(v) = override_m2.clone()
            && !merged.contains(&v) {
                merged.push(v);
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
        if let Some(ts) = published_at.get(&version)
            && *ts <= cutoff {
                selected.push(version);
                if selected.len() >= baseline_count {
                    break;
                }
            }
    }
    selected
}

/// Parses npm's `time` map into per-version publish timestamps, excluding the
/// `created`/`modified` bookkeeping keys and any key that isn't an actual
/// published version. Without this filter the release-burst counter would
/// over-count by up to two and falsely trip the threshold.
fn npm_published_times(
    time: &HashMap<String, String>,
    version_keys: &HashSet<String>,
) -> HashMap<String, DateTime<Utc>> {
    let mut published_at = HashMap::new();
    for (version, ts) in time {
        if version == "created" || version == "modified" {
            continue;
        }
        if !version_keys.contains(version) {
            continue;
        }
        if let Ok(dt) = DateTime::parse_from_rfc3339(ts) {
            published_at.insert(version.clone(), dt.with_timezone(&Utc));
        }
    }
    published_at
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

pub(crate) async fn scan_packages_versions(
    runner: &dyn SandboxRunner,
    manager: &str,
    pkg_targets: &[(String, String)],
    policy: &PolicyConfig,
) -> HashMap<String, ScanReport> {
    let mut results: HashMap<String, ScanReport> = HashMap::new();
    if pkg_targets.is_empty() {
        return results;
    }

    let mut plans = Vec::new();
    for (pkg_name, tgt_version) in pkg_targets {
        let min_baseline_age_hours = policy
            .min_baseline_age_hours_by_package
            .get(pkg_name)
            .copied()
            .unwrap_or(DEFAULT_MIN_BASELINE_AGE_HOURS as usize) as i64;

        let fetch_count = policy.baseline_count.max(2);
        let (v_curr, fetched_baselines, releases_last_24h, current_release_age_days) =
            fetch_history_with_baselines(
                manager,
                pkg_name,
                tgt_version,
                fetch_count,
                min_baseline_age_hours,
                policy.release_burst_window_hours as i64,
            )
            .await;

        if let Some(warning) = minimum_release_age_policy_warning(
            pkg_name,
            current_release_age_days,
            policy.minimum_release_age_package,
        ) {
            println!("{}", warning);
            println!("Aborting host operation securely.");
            results.insert(
                format!("{}|{}", pkg_name, tgt_version),
                ScanReport { allowed: false, resolved_version: v_curr.clone() },
            );
            continue;
        }

        if let Some(warning) = burst_policy_warning(
            pkg_name,
            releases_last_24h,
            policy.release_burst_threshold,
            policy.release_burst_window_hours,
        ) {
            println!("{}", warning);
            println!("Aborting host operation securely.");
            results.insert(
                format!("{}|{}", pkg_name, tgt_version),
                ScanReport { allowed: false, resolved_version: v_curr.clone() },
            );
            continue;
        }

        let eligible_baseline_versions = fetched_baselines.len();

        let baselines = select_effective_baselines(
            &v_curr,
            fetched_baselines,
            policy.baseline_overrides.get(pkg_name),
            policy.baseline_count,
        );

        let new_package_exempt = policy.new_package_exemptions.contains(pkg_name);
        let (_, should_warn_exemption) = exemption_behavior(new_package_exempt, eligible_baseline_versions);
        if should_warn_exemption {
            println!(
                "⚠️ [gyrseek] Package '{}' is listed in new_package_exemptions but now has {} eligible baseline versions; consider removing the exemption.",
                pkg_name, eligible_baseline_versions
            );
        }

        if policy.baseline_overrides.contains_key(pkg_name) {
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

    let traces_by_probe = match trace_sandbox_install_matrix(runner, manager, &probes, &policy.watched_executables) {
        Ok(v) => v,
        Err(e) => {
            for plan in &plans {
                println!("❌ [gyrseek] Sandbox execution failed for '{}': {}", plan.package, e);
                results.insert(
                    format!("{}|{}", plan.package, plan.target_version),
                    ScanReport { allowed: false, resolved_version: plan.current.clone() },
                );
            }
            return results;
        }
    };

    for plan in plans {
        let key = format!("{}|{}", plan.package, plan.target_version);
        let resolved_version = plan.current.clone();
        let blocked = |results: &mut HashMap<String, ScanReport>, key: String| {
            results.insert(key, ScanReport { allowed: false, resolved_version: resolved_version.clone() });
        };
        let current_key = (plan.package.clone(), plan.current.clone());
        let current_signals = match traces_by_probe.get(&current_key) {
            Some(v) => v.clone(),
            None => {
                println!(
                    "❌ [gyrseek] Sandbox trace missing for '{}@{}'.",
                    plan.package, plan.current
                );
                blocked(&mut results, key);
                continue;
            }
        };
        let ips_curr = current_signals.ips;
        let git_curr = current_signals.git_clone_signatures;
        let proc_curr = current_signals.process_exec_signatures;

        let mut baseline_ips = HashSet::new();
        let mut baseline_git_clone_signatures = HashSet::new();
        let mut baseline_process_exec_signatures = HashSet::new();
        let mut missing = false;

        for v in &plan.baselines {
            let k = (plan.package.clone(), v.clone());
            match traces_by_probe.get(&k) {
                Some(found) => {
                    baseline_ips.extend(found.ips.iter().cloned());
                    baseline_git_clone_signatures
                        .extend(found.git_clone_signatures.iter().cloned());
                    baseline_process_exec_signatures
                        .extend(found.process_exec_signatures.iter().cloned());
                }
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
            blocked(&mut results, key);
            continue;
        }

        let (skip_due_to_exemption, _) =
            exemption_behavior(plan.new_package_exempt, plan.eligible_baseline_versions);
        if skip_due_to_exemption {
            println!(
                "⚠️ [gyrseek] New package exemption applied for '{}': only {} eligible baseline version(s) available (<2). Skipping anomaly block for now.",
                plan.package, plan.eligible_baseline_versions
            );
            results.insert(key, ScanReport { allowed: true, resolved_version });
            continue;
        }

        let new_process_exec_signatures =
            find_new_process_exec_signatures(&proc_curr, &baseline_process_exec_signatures);
        let (new_process_exec_signatures, allowlisted_process_exec_signatures) =
            filter_allowlisted_process_exec_signatures(
                new_process_exec_signatures,
                &policy.process_exec_allowlist,
            );

        if !allowlisted_process_exec_signatures.is_empty() {
            println!(
                "ℹ️ [gyrseek] process_exec_allowlist ignored new process execution behavior for '{}': {:?}",
                plan.package, allowlisted_process_exec_signatures
            );
        }

        if !new_process_exec_signatures.is_empty() {
            let baseline_label = if plan.baselines.is_empty() {
                "n/a".to_string()
            } else {
                plan.baselines.join(", ")
            };

            println!("\n❌ [gyrseek] CRITICAL WARNING: Behavioral anomaly flagged!");
            println!(
                "Package '{}', version '{}' introduced new watched-process execution (for example bun/deno) not seen in baseline versions ({}): {:?}",
                plan.package, plan.current, baseline_label, new_process_exec_signatures
            );
            println!("This matches the Shai-Hulud class of attack (download a runtime like Bun and execute a hidden payload).");
            println!("Aborting host operation securely.");
            blocked(&mut results, key);
            continue;
        }

        let new_git_clone_signatures =
            find_new_git_clone_signatures(&git_curr, &baseline_git_clone_signatures);
        let (new_git_clone_signatures, allowlisted_git_clone_signatures) =
            filter_allowlisted_git_clone_signatures(new_git_clone_signatures, &policy.git_clone_allowlist);

        if !allowlisted_git_clone_signatures.is_empty() {
            println!(
                "ℹ️ [gyrseek] git_clone_allowlist ignored new git clone behavior for '{}': {:?}",
                plan.package, allowlisted_git_clone_signatures
            );
        }

        if !new_git_clone_signatures.is_empty() {
            let baseline_label = if plan.baselines.is_empty() {
                "n/a".to_string()
            } else {
                plan.baselines.join(", ")
            };

            println!("\n❌ [gyrseek] CRITICAL WARNING: Behavioral anomaly flagged!");
            println!(
                "Package '{}', version '{}' introduced new git clone behavior not seen in baseline versions ({}): {:?}",
                plan.package, plan.current, baseline_label, new_git_clone_signatures
            );
            println!("Aborting host operation securely.");
            blocked(&mut results, key);
            continue;
        }

        let new_connections = find_new_connections(&ips_curr, &baseline_ips);
        let (new_connections, allowlisted_connections) =
            filter_allowlisted_new_connections(new_connections, &policy.ip_allowlist);
        let (new_connections, allowlisted_domain_connections) = filter_domain_allowlisted_new_connections_with(
            new_connections,
            &policy.domain_allowlist,
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
            blocked(&mut results, key);
            continue;
        }

        results.insert(key, ScanReport { allowed: true, resolved_version });
    }

    results
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use chrono::{TimeZone, Utc};

    use super::{
        burst_policy_warning, burst_triggered, compare_version_strings, count_releases_in_window,
        default_watched_executables, enrich_new_connection_domains_with, exemption_behavior,
        extract_connection_ips, extract_process_exec_signatures,
        filter_allowlisted_git_clone_signatures, filter_allowlisted_new_connections,
        filter_allowlisted_process_exec_signatures,
        filter_domain_allowlisted_new_connections_with, find_new_connections,
        find_new_process_exec_signatures, forward_confirmed_hostname,
        minimum_release_age_policy_warning, npm_published_times, scan_packages_versions,
        select_age_eligible_baselines, select_effective_baselines, sort_versions_ascending,
        PolicyConfig,
    };
    use chrono::Duration;
    use std::cmp::Ordering;
    use std::collections::HashSet;
    use std::net::IpAddr;

    // --- #1 semantic version ordering ---

    #[test]
    fn npm_versions_sort_semantically_not_lexically() {
        // Lexically "10.0.0" < "9.0.0"; semver must order it the other way.
        let mut versions = vec![
            "9.0.0".to_string(),
            "10.0.0".to_string(),
            "10.0.0-rc.1".to_string(),
            "2.0.0".to_string(),
        ];
        sort_versions_ascending("npm", &mut versions);
        assert_eq!(
            versions,
            vec![
                "2.0.0".to_string(),
                "9.0.0".to_string(),
                "10.0.0-rc.1".to_string(), // prerelease sorts below its release
                "10.0.0".to_string(),
            ]
        );
        // The "latest" pick (last element) must be the true newest release.
        assert_eq!(versions.last().map(String::as_str), Some("10.0.0"));
    }

    #[test]
    fn pypi_versions_sort_by_pep440_not_lexically() {
        // Lexically "0.10.0" < "0.9.0" and "1.0.0a1" > "1.0.0"; PEP 440 fixes both.
        let mut versions = vec![
            "0.9.0".to_string(),
            "0.10.0".to_string(),
            "1.0.0".to_string(),
            "1.0.0a1".to_string(),
        ];
        sort_versions_ascending("pip", &mut versions);
        assert_eq!(
            versions,
            vec![
                "0.9.0".to_string(),
                "0.10.0".to_string(),
                "1.0.0a1".to_string(), // alpha pre-release sorts below final
                "1.0.0".to_string(),
            ]
        );
        assert_eq!(versions.last().map(String::as_str), Some("1.0.0"));
    }

    #[test]
    fn unparseable_versions_sort_below_parseable_ones() {
        // Junk must never be selected as "latest" over a real version.
        assert_eq!(compare_version_strings("npm", "not-a-version", "1.0.0"), Ordering::Less);
        assert_eq!(compare_version_strings("npm", "1.0.0", "not-a-version"), Ordering::Greater);

        let mut versions = vec!["garbage".to_string(), "1.2.3".to_string()];
        sort_versions_ascending("npm", &mut versions);
        assert_eq!(versions.last().map(String::as_str), Some("1.2.3"));
    }

    // --- #3 IPv6 connection capture ---

    #[test]
    fn extract_connection_ips_captures_ipv4() {
        let trace = r#"connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 0"#;
        let ips = extract_connection_ips(trace);
        assert!(ips.contains("93.184.216.34"));
    }

    #[test]
    fn extract_connection_ips_captures_ipv6_inet_pton() {
        let trace = r#"connect(3, {sa_family=AF_INET6, sin6_port=htons(443), sin6_addr=inet_pton(AF_INET6, "2606:2800:220:1:248:1893:25c8:1946")}, 28) = 0"#;
        let ips = extract_connection_ips(trace);
        // Normalised through IpAddr, so the canonical form is what we compare on.
        assert!(ips.contains("2606:2800:220:1:248:1893:25c8:1946"));
    }

    #[test]
    fn extract_connection_ips_normalises_ipv6_equivalents() {
        let trace = r#"inet_pton(AF_INET6, "2001:0db8:0000:0000:0000:0000:0000:0001", ...) = 1"#;
        let ips = extract_connection_ips(trace);
        // Expanded and compressed forms must collapse to one canonical entry.
        assert!(ips.contains("2001:db8::1"));
    }

    #[test]
    fn extract_connection_ips_handles_mixed_v4_and_v6() {
        let trace = r#"
sin_addr=inet_addr("8.8.8.8")
sin6_addr=inet_pton(AF_INET6, "fe80::1")
"#;
        let ips = extract_connection_ips(trace);
        assert!(ips.contains("8.8.8.8"));
        assert!(ips.contains("fe80::1"));
        assert_eq!(ips.len(), 2);
    }

    // --- #6 created/modified must not inflate the release-burst count ---

    #[test]
    fn npm_published_times_excludes_created_and_modified_keys() {
        let time = HashMap::from([
            ("created".to_string(), "2020-01-01T00:00:00.000Z".to_string()),
            ("modified".to_string(), "2026-01-01T00:00:00.000Z".to_string()),
            ("1.0.0".to_string(), "2026-06-01T00:00:00.000Z".to_string()),
            ("1.0.1".to_string(), "2026-06-02T00:00:00.000Z".to_string()),
        ]);
        let version_keys: HashSet<String> =
            ["1.0.0".to_string(), "1.0.1".to_string()].into_iter().collect();

        let published = npm_published_times(&time, &version_keys);
        assert_eq!(published.len(), 2);
        assert!(published.contains_key("1.0.0"));
        assert!(published.contains_key("1.0.1"));
        assert!(!published.contains_key("created"));
        assert!(!published.contains_key("modified"));
    }

    #[test]
    fn npm_published_times_ignores_time_keys_without_a_matching_version() {
        let time = HashMap::from([
            ("created".to_string(), "2020-01-01T00:00:00.000Z".to_string()),
            ("modified".to_string(), "2026-01-01T00:00:00.000Z".to_string()),
            ("9.9.9-yanked".to_string(), "2026-06-01T00:00:00.000Z".to_string()),
        ]);
        // Only 1.0.0 is a real version; the time map has stale extras.
        let version_keys: HashSet<String> = ["1.0.0".to_string()].into_iter().collect();

        let published = npm_published_times(&time, &version_keys);
        assert!(published.is_empty());
    }

    #[test]
    fn burst_count_is_not_inflated_by_created_modified() {
        // Simulate a quiet package: one real release, but created/modified both
        // fall in the window. Without filtering this would count as 3.
        let now = chrono::Utc::now();
        let ts = |dt: chrono::DateTime<chrono::Utc>| dt.to_rfc3339();
        let time = HashMap::from([
            ("created".to_string(), ts(now - Duration::hours(1))),
            ("modified".to_string(), ts(now - Duration::hours(1))),
            ("1.0.0".to_string(), ts(now - Duration::hours(1))),
        ]);
        let version_keys: HashSet<String> = ["1.0.0".to_string()].into_iter().collect();

        let published = npm_published_times(&time, &version_keys);
        let count = count_releases_in_window(&published, now - Duration::hours(24), now);
        assert_eq!(count, 1, "created/modified must not be counted as releases");
    }

    // --- watched-process (bun/deno) execution detection (Shai-Hulud class) ---

    fn watched() -> HashSet<String> {
        default_watched_executables()
    }

    #[test]
    fn default_watched_set_includes_bun_and_deno() {
        let w = default_watched_executables();
        assert!(w.contains("bun"));
        assert!(w.contains("deno"));
    }

    #[test]
    fn extract_process_exec_captures_bun_run_with_argv() {
        // The Shai-Hulud loader downloads bun and runs the obfuscated stealer.
        let trace = r#"execve("/tmp/b/bun", ["/tmp/b/bun", "run", "_index.js"], 0x7ff) = 0"#;
        let sigs = extract_process_exec_signatures(trace, &watched());
        assert!(sigs.contains("bun|run|_index.js"), "got: {sigs:?}");
    }

    // --- #2 domain allowlist must require forward-confirmed reverse DNS ---

    #[test]
    fn fcrdns_accepts_hostname_that_forward_resolves_back_to_ip() {
        let addr: IpAddr = "1.2.3.4".parse().unwrap();
        let got = forward_confirmed_hostname(
            addr,
            |_| Some("cdn.example.com".to_string()),
            // Forward lookup returns the original IP -> confirmed.
            |_| Some(vec!["1.2.3.4".parse().unwrap()]),
        );
        assert_eq!(got, Some("cdn.example.com".to_string()));
    }

    #[test]
    fn fcrdns_rejects_spoofed_ptr_that_does_not_forward_confirm() {
        let addr: IpAddr = "1.2.3.4".parse().unwrap();
        let got = forward_confirmed_hostname(
            addr,
            // Attacker sets their C2 IP's PTR to an allowlisted domain...
            |_| Some("cdn.example.com".to_string()),
            // ...but the domain's real A record points elsewhere -> rejected.
            |_| Some(vec!["9.9.9.9".parse().unwrap()]),
        );
        assert_eq!(got, None);
    }

    #[test]
    fn fcrdns_rejects_when_no_ptr_record() {
        let addr: IpAddr = "1.2.3.4".parse().unwrap();
        let got = forward_confirmed_hostname(addr, |_| None, |_| Some(vec![]));
        assert_eq!(got, None);
    }

    #[test]
    fn extract_process_exec_preserves_brackets_in_argv() {
        // Regression for the argv-truncation bug (#3): a `]` inside an argument
        // must not terminate the argv capture early. `script[obf].js` has to
        // survive intact, otherwise current/baseline both truncate identically
        // and a payload bypasses detection.
        let trace = r#"execve("/tmp/b/bun", ["bun", "run", "script[obf].js"], 0x7ff) = 0"#;
        let sigs = extract_process_exec_signatures(trace, &watched());
        assert!(sigs.contains("bun|run|script[obf].js"), "got: {sigs:?}");
    }

    #[test]
    fn extract_process_exec_uses_basename_so_path_does_not_matter() {
        let a = extract_process_exec_signatures(
            r#"execve("/tmp/b/bun", ["/tmp/b/bun", "run", "x.js"], 0x7ff) = 0"#,
            &watched(),
        );
        let b = extract_process_exec_signatures(
            r#"execve("/usr/local/bin/bun", ["bun", "run", "x.js"], 0x7ff) = 0"#,
            &watched(),
        );
        // Both normalize to the same signature regardless of install path / argv0.
        assert_eq!(a, b);
        assert!(a.contains("bun|run|x.js"));
    }

    #[test]
    fn extract_process_exec_ignores_non_watched_executables() {
        // node/sh/python are intentionally NOT watched (too noisy in installs).
        let trace = r#"
execve("/usr/bin/node", ["node", "build.js"], 0x7ff) = 0
execve("/bin/sh", ["sh", "-c", "echo hi"], 0x7ff) = 0
execve("/usr/bin/python3", ["python3", "setup.py"], 0x7ff) = 0
"#;
        let sigs = extract_process_exec_signatures(trace, &watched());
        assert!(sigs.is_empty(), "got: {sigs:?}");
    }

    #[test]
    fn empty_watched_set_extracts_nothing() {
        let trace = r#"execve("/tmp/bun", ["bun", "run", "x.js"], 0x7ff) = 0"#;
        assert!(extract_process_exec_signatures(trace, &HashSet::new()).is_empty());
    }

    #[test]
    fn case_1_new_bun_is_flagged_against_clean_baseline() {
        // Baseline never ran bun; latest does -> the bun signature is "new".
        let baseline = extract_process_exec_signatures(
            r#"execve("/usr/bin/node", ["node", "index.js"], 0x7ff) = 0"#,
            &watched(),
        );
        let current = extract_process_exec_signatures(
            r#"execve("/tmp/b/bun", ["bun", "run", "_index.js"], 0x7ff) = 0"#,
            &watched(),
        );
        let new = find_new_process_exec_signatures(&current, &baseline);
        assert_eq!(new, vec!["bun|run|_index.js".to_string()]);
    }

    #[test]
    fn case_2_existing_bun_plus_additional_invocation_is_flagged() {
        // Baseline legitimately runs `bun run build`. Latest still does that, but
        // ALSO runs the stealer. Only the new invocation should surface.
        let baseline = extract_process_exec_signatures(
            r#"execve("/usr/bin/bun", ["bun", "run", "build"], 0x7ff) = 0"#,
            &watched(),
        );
        let current = extract_process_exec_signatures(
            r#"
execve("/usr/bin/bun", ["bun", "run", "build"], 0x7ff) = 0
execve("/tmp/b/bun", ["bun", "run", "_index.js"], 0x7ff) = 0
"#,
            &watched(),
        );
        let new = find_new_process_exec_signatures(&current, &baseline);
        assert_eq!(new, vec!["bun|run|_index.js".to_string()]);
    }

    #[test]
    fn case_2b_changed_bun_arguments_are_flagged() {
        // Same executable, different args -> distinct signature, so it's "new".
        let baseline = extract_process_exec_signatures(
            r#"execve("/usr/bin/bun", ["bun", "run", "build"], 0x7ff) = 0"#,
            &watched(),
        );
        let current = extract_process_exec_signatures(
            r#"execve("/usr/bin/bun", ["bun", "run", "build", "--evil-flag"], 0x7ff) = 0"#,
            &watched(),
        );
        let new = find_new_process_exec_signatures(&current, &baseline);
        assert_eq!(new, vec!["bun|run|build|--evil-flag".to_string()]);
    }

    #[test]
    fn identical_bun_behavior_is_not_flagged() {
        let baseline = extract_process_exec_signatures(
            r#"execve("/usr/bin/bun", ["bun", "run", "build"], 0x7ff) = 0"#,
            &watched(),
        );
        let current = baseline.clone();
        assert!(find_new_process_exec_signatures(&current, &baseline).is_empty());
    }

    #[test]
    fn process_exec_allowlist_matches_exact_signature_and_bare_executable() {
        let sigs = vec!["bun|run|build".to_string(), "deno|run|task.ts".to_string()];

        // Exact-signature allowlist clears only that one.
        let allow_exact: HashSet<String> = ["bun|run|build".to_string()].into_iter().collect();
        let (remaining, allowed) =
            filter_allowlisted_process_exec_signatures(sigs.clone(), &allow_exact);
        assert_eq!(allowed, vec!["bun|run|build".to_string()]);
        assert_eq!(remaining, vec!["deno|run|task.ts".to_string()]);

        // Bare-executable allowlist clears every invocation of that executable.
        let allow_exe: HashSet<String> = ["bun".to_string()].into_iter().collect();
        let (remaining, allowed) = filter_allowlisted_process_exec_signatures(sigs, &allow_exe);
        assert_eq!(allowed, vec!["bun|run|build".to_string()]);
        assert_eq!(remaining, vec!["deno|run|task.ts".to_string()]);
    }

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

    // ---------------------------------------------------------------------------
    // behavior_tests (moved from tests/behavior_tests.rs)
    // ---------------------------------------------------------------------------

    #[test]
    fn detects_anomalous_new_connection() {
        let ips_curr: HashSet<String> = ["1.1.1.1", "8.8.8.8"].into_iter().map(String::from).collect();
        let baseline_ips: HashSet<String> = ["1.1.1.1"].into_iter().map(String::from).collect();
        let mut new = find_new_connections(&ips_curr, &baseline_ips);
        new.sort();
        assert_eq!(new, vec!["8.8.8.8".to_string()]);
    }

    #[test]
    fn no_anomaly_when_connections_match_baseline() {
        let ips_curr: HashSet<String> = ["1.1.1.1"].into_iter().map(String::from).collect();
        let baseline_ips: HashSet<String> = ["1.1.1.1", "9.9.9.9"].into_iter().map(String::from).collect();
        assert!(find_new_connections(&ips_curr, &baseline_ips).is_empty());
    }

    #[test]
    fn dns_enrichment_reports_context_and_domain_overlap_matches() {
        let baseline_ips: HashSet<String> = ["1.1.1.1", "9.9.9.9"].into_iter().map(String::from).collect();
        let new_connections = vec!["8.8.8.8".to_string(), "5.5.5.5".to_string()];
        let resolver = |ip: &str| match ip {
            "1.1.1.1" => Some("example.net".to_string()),
            "9.9.9.9" => Some("baseline-only.net".to_string()),
            "8.8.8.8" => Some("example.net".to_string()),
            "5.5.5.5" => Some("new.net".to_string()),
            _ => None,
        };
        let (mut context, mut matches) = enrich_new_connection_domains_with(&new_connections, &baseline_ips, resolver);
        context.sort();
        matches.sort();
        assert_eq!(context, vec!["5.5.5.5 -> new.net".to_string(), "8.8.8.8 -> example.net".to_string()]);
        assert_eq!(matches, vec!["8.8.8.8 -> example.net".to_string()]);
    }

    #[test]
    fn dns_enrichment_ignores_unresolved_ips_without_failing() {
        let baseline_ips: HashSet<String> = ["1.1.1.1"].into_iter().map(String::from).collect();
        let new_connections = vec!["8.8.8.8".to_string()];
        let (context, matches) = enrich_new_connection_domains_with(&new_connections, &baseline_ips, |_| None);
        assert!(context.is_empty());
        assert!(matches.is_empty());
    }

    #[test]
    fn ip_allowlist_filters_new_ips_before_blocking() {
        let new_connections = vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()];
        let ip_allowlist: HashSet<String> = ["1.1.1.1"].into_iter().map(String::from).collect();
        let (mut remaining, mut allowlisted) = filter_allowlisted_new_connections(new_connections, &ip_allowlist);
        remaining.sort();
        allowlisted.sort();
        assert_eq!(remaining, vec!["8.8.8.8".to_string()]);
        assert_eq!(allowlisted, vec!["1.1.1.1".to_string()]);
    }

    #[test]
    fn domain_allowlist_filters_resolved_domains_before_blocking() {
        let new_connections = vec!["8.8.8.8".to_string(), "5.5.5.5".to_string()];
        let domain_allowlist: HashSet<String> = ["example.net"].into_iter().map(String::from).collect();
        let resolver = |ip: &str| match ip {
            "8.8.8.8" => Some("cdn.example.net".to_string()),
            "5.5.5.5" => Some("other.net".to_string()),
            _ => None,
        };
        let (mut remaining, mut allowlisted) = filter_domain_allowlisted_new_connections_with(new_connections, &domain_allowlist, resolver);
        remaining.sort();
        allowlisted.sort();
        assert_eq!(remaining, vec!["5.5.5.5".to_string()]);
        assert_eq!(allowlisted, vec!["8.8.8.8 -> cdn.example.net".to_string()]);
    }

    #[test]
    fn domain_allowlist_does_not_filter_when_lookup_fails() {
        let new_connections = vec!["8.8.8.8".to_string()];
        let domain_allowlist: HashSet<String> = ["example.net"].into_iter().map(String::from).collect();
        let (remaining, allowlisted) = filter_domain_allowlisted_new_connections_with(new_connections, &domain_allowlist, |_| None);
        assert_eq!(remaining, vec!["8.8.8.8".to_string()]);
        assert!(allowlisted.is_empty());
    }

    #[test]
    fn domain_allowlist_normalization_matches_case_whitespace_and_trailing_dot() {
        let new_connections = vec!["8.8.8.8".to_string()];
        let domain_allowlist: HashSet<String> = [" Example.NET. "].into_iter().map(String::from).collect();
        let resolver = |_ip: &str| Some("CDN.Example.Net.".to_string());
        let (remaining, allowlisted) = filter_domain_allowlisted_new_connections_with(new_connections, &domain_allowlist, resolver);
        assert!(remaining.is_empty());
        assert_eq!(allowlisted, vec!["8.8.8.8 -> CDN.Example.Net.".to_string()]);
    }

    #[test]
    fn ip_allowlist_matches_equivalent_ipv6_representations() {
        let new_connections = vec!["2001:0db8:0000:0000:0000:ff00:0042:8329".to_string()];
        let ip_allowlist: HashSet<String> = ["2001:db8::ff00:42:8329"].into_iter().map(String::from).collect();
        let (remaining, allowlisted) = filter_allowlisted_new_connections(new_connections, &ip_allowlist);
        assert!(remaining.is_empty());
        assert_eq!(allowlisted, vec!["2001:0db8:0000:0000:0000:ff00:0042:8329".to_string()]);
    }

    // ---------------------------------------------------------------------------
    // git_clone_behavior_tests (moved from tests/git_clone_behavior_tests.rs)
    // ---------------------------------------------------------------------------

    #[test]
    fn detects_new_connection_in_git_clone_simulation() {
        let clone_ips: HashSet<String> = ["140.82.112.3", "185.199.108.133"].into_iter().map(String::from).collect();
        let baseline_ips: HashSet<String> = ["140.82.112.3"].into_iter().map(String::from).collect();
        let mut new = find_new_connections(&clone_ips, &baseline_ips);
        new.sort();
        assert_eq!(new, vec!["185.199.108.133".to_string()]);
    }

    #[test]
    fn no_new_connection_in_git_clone_simulation() {
        let clone_ips: HashSet<String> = ["140.82.112.3"].into_iter().map(String::from).collect();
        let baseline_ips: HashSet<String> = ["140.82.112.3", "140.82.113.3"].into_iter().map(String::from).collect();
        assert!(find_new_connections(&clone_ips, &baseline_ips).is_empty());
    }

    // ---------------------------------------------------------------------------
    // bun_exec_scan_tests (moved from tests/bun_exec_scan_tests.rs)
    // ---------------------------------------------------------------------------

    use std::sync::{Mutex, OnceLock};

    struct MockRunner {
        traces: HashMap<(String, String), String>,
    }

    impl crate::sandbox::SandboxRunner for MockRunner {
        fn trace_install(&self, _manager: &str, package: &str, version: &str) -> Result<String, String> {
            self.traces
                .get(&(package.to_string(), version.to_string()))
                .cloned()
                .ok_or_else(|| format!("missing mock trace for {}@{}", package, version))
        }
    }

    fn env_lock() -> &'static Mutex<()> {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        ENV_LOCK.get_or_init(|| Mutex::new(()))
    }

    fn policy_with_baseline_and_process_allowlist(
        package: &str,
        baseline: &str,
        process_exec_allowlist: HashSet<String>,
    ) -> PolicyConfig {
        PolicyConfig {
            baseline_count: 1,
            process_exec_allowlist,
            baseline_overrides: HashMap::from([(package.to_string(), (Some(baseline.to_string()), None))]),
            ..PolicyConfig::default()
        }
    }

    fn policy_with_baseline_and_git_allowlist(
        package: &str,
        baseline: &str,
        git_clone_allowlist: HashSet<String>,
    ) -> PolicyConfig {
        PolicyConfig {
            baseline_count: 1,
            git_clone_allowlist,
            baseline_overrides: HashMap::from([(package.to_string(), (Some(baseline.to_string()), None))]),
            ..PolicyConfig::default()
        }
    }

    #[tokio::test]
    async fn flags_newly_introduced_bun_execution() {
        let _guard = env_lock().lock().expect("env lock");
        unsafe { std::env::set_var("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0"); }
        let runner = MockRunner {
            traces: HashMap::from([
                (("evil-pkg".to_string(), "1.3.0".to_string()),
                 "execve(\"/tmp/b/bun\", [\"/tmp/b/bun\", \"run\", \"_index.js\"], 0x7ff) = 0\n".to_string()),
                (("evil-pkg".to_string(), "1.2.0".to_string()),
                 "execve(\"/usr/bin/node\", [\"node\", \"index.js\"], 0x7ff) = 0\n".to_string()),
            ]),
        };
        let results = scan_packages_versions(&runner, "npm", &[("evil-pkg".to_string(), "1.3.0".to_string())],
            &policy_with_baseline_and_process_allowlist("evil-pkg", "1.2.0", HashSet::new())).await;
        unsafe { std::env::remove_var("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H"); }
        assert_eq!(results.get("evil-pkg|1.3.0").map(|r| r.allowed), Some(false));
    }

    #[tokio::test]
    async fn flags_existing_bun_with_additional_invocation() {
        let _guard = env_lock().lock().expect("env lock");
        unsafe { std::env::set_var("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0"); }
        let runner = MockRunner {
            traces: HashMap::from([
                (("buildy".to_string(), "2.1.0".to_string()),
                 "execve(\"/usr/bin/bun\", [\"bun\", \"run\", \"build\"], 0x7ff) = 0\nexecve(\"/tmp/b/bun\", [\"bun\", \"run\", \"_index.js\"], 0x7ff) = 0\n".to_string()),
                (("buildy".to_string(), "2.0.0".to_string()),
                 "execve(\"/usr/bin/bun\", [\"bun\", \"run\", \"build\"], 0x7ff) = 0\n".to_string()),
            ]),
        };
        let results = scan_packages_versions(&runner, "npm", &[("buildy".to_string(), "2.1.0".to_string())],
            &policy_with_baseline_and_process_allowlist("buildy", "2.0.0", HashSet::new())).await;
        unsafe { std::env::remove_var("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H"); }
        assert_eq!(results.get("buildy|2.1.0").map(|r| r.allowed), Some(false));
    }

    #[tokio::test]
    async fn allows_when_bun_behavior_matches_baseline() {
        let _guard = env_lock().lock().expect("env lock");
        unsafe { std::env::set_var("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0"); }
        let trace = "execve(\"/usr/bin/bun\", [\"bun\", \"run\", \"build\"], 0x7ff) = 0\n".to_string();
        let runner = MockRunner {
            traces: HashMap::from([
                (("buildy".to_string(), "2.1.0".to_string()), trace.clone()),
                (("buildy".to_string(), "2.0.0".to_string()), trace),
            ]),
        };
        let results = scan_packages_versions(&runner, "npm", &[("buildy".to_string(), "2.1.0".to_string())],
            &policy_with_baseline_and_process_allowlist("buildy", "2.0.0", HashSet::new())).await;
        unsafe { std::env::remove_var("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H"); }
        assert_eq!(results.get("buildy|2.1.0").map(|r| r.allowed), Some(true));
    }

    #[tokio::test]
    async fn allows_new_bun_when_allowlisted() {
        let _guard = env_lock().lock().expect("env lock");
        unsafe { std::env::set_var("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0"); }
        let runner = MockRunner {
            traces: HashMap::from([
                (("buildy".to_string(), "2.1.0".to_string()),
                 "execve(\"/usr/bin/bun\", [\"bun\", \"run\", \"approved-task\"], 0x7ff) = 0\n".to_string()),
                (("buildy".to_string(), "2.0.0".to_string()),
                 "execve(\"/usr/bin/node\", [\"node\", \"index.js\"], 0x7ff) = 0\n".to_string()),
            ]),
        };
        let allowlist: HashSet<String> = ["bun|run|approved-task".to_string()].into_iter().collect();
        let results = scan_packages_versions(&runner, "npm", &[("buildy".to_string(), "2.1.0".to_string())],
            &policy_with_baseline_and_process_allowlist("buildy", "2.0.0", allowlist)).await;
        unsafe { std::env::remove_var("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H"); }
        assert_eq!(results.get("buildy|2.1.0").map(|r| r.allowed), Some(true));
    }

    // ---------------------------------------------------------------------------
    // git_clone_scan_tests (moved from tests/git_clone_scan_tests.rs)
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn scan_flags_new_install_time_git_clone_behavior() {
        let _guard = env_lock().lock().expect("env lock");
        unsafe { std::env::set_var("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0"); }
        let runner = MockRunner {
            traces: HashMap::from([
                (("pkg-a".to_string(), "1.3.0".to_string()),
                 "execve(\"/usr/bin/git\", [\"git\", \"clone\", \"https://github.com/evil/repo.git\"], 0x7ff) = 0\n".to_string()),
                (("pkg-a".to_string(), "1.2.0".to_string()),
                 "execve(\"/usr/bin/sh\", [\"sh\", \"-c\", \"echo ok\"], 0x7ff) = 0\n".to_string()),
            ]),
        };
        let results = scan_packages_versions(&runner, "npm", &[("pkg-a".to_string(), "1.3.0".to_string())],
            &policy_with_baseline_and_git_allowlist("pkg-a", "1.2.0", HashSet::new())).await;
        unsafe { std::env::remove_var("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H"); }
        assert_eq!(results.get("pkg-a|1.3.0").map(|r| r.allowed), Some(false));
    }

    #[tokio::test]
    async fn scan_allows_when_install_time_git_clone_behavior_matches_baseline() {
        let _guard = env_lock().lock().expect("env lock");
        unsafe { std::env::set_var("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0"); }
        let trace = "execve(\"/usr/bin/git\", [\"git\", \"clone\", \"https://github.com/acme/repo.git\"], 0x7ff) = 0\n".to_string();
        let runner = MockRunner {
            traces: HashMap::from([
                (("pkg-b".to_string(), "1.3.0".to_string()), trace.clone()),
                (("pkg-b".to_string(), "1.2.0".to_string()), trace),
            ]),
        };
        let results = scan_packages_versions(&runner, "npm", &[("pkg-b".to_string(), "1.3.0".to_string())],
            &policy_with_baseline_and_git_allowlist("pkg-b", "1.2.0", HashSet::new())).await;
        unsafe { std::env::remove_var("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H"); }
        assert_eq!(results.get("pkg-b|1.3.0").map(|r| r.allowed), Some(true));
    }

    #[tokio::test]
    async fn scan_allows_new_git_clone_behavior_when_target_is_allowlisted() {
        let _guard = env_lock().lock().expect("env lock");
        unsafe { std::env::set_var("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0"); }
        let runner = MockRunner {
            traces: HashMap::from([
                (("pkg-c".to_string(), "1.3.0".to_string()),
                 "execve(\"/usr/bin/git\", [\"git\", \"clone\", \"https://github.com/acme/approved.git\"], 0x7ff) = 0\n".to_string()),
                (("pkg-c".to_string(), "1.2.0".to_string()),
                 "execve(\"/usr/bin/sh\", [\"sh\", \"-c\", \"echo ok\"], 0x7ff) = 0\n".to_string()),
            ]),
        };
        let git_clone_allowlist: HashSet<String> = ["https://github.com/acme/approved.git".to_string()].into_iter().collect();
        let results = scan_packages_versions(&runner, "npm", &[("pkg-c".to_string(), "1.3.0".to_string())],
            &policy_with_baseline_and_git_allowlist("pkg-c", "1.2.0", git_clone_allowlist)).await;
        unsafe { std::env::remove_var("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H"); }
        assert_eq!(results.get("pkg-c|1.3.0").map(|r| r.allowed), Some(true));
    }

    // --- gap #13: filter_allowlisted_git_clone_signatures — recursive suffix stripped before match ---

    #[test]
    fn git_clone_allowlist_matches_recursive_clone_of_allowed_url() {
        // The allowlist stores the URL; the signature includes |recursive. The URL
        // must be extracted before comparison so the recursive flag does not prevent
        // the allowlisted URL from matching.
        let signatures = vec![
            "https://github.com/acme/repo.git|recursive".to_string(),
        ];
        let allowlist: HashSet<String> = ["https://github.com/acme/repo.git".to_string()].into_iter().collect();
        let (remaining, allowlisted) = filter_allowlisted_git_clone_signatures(signatures, &allowlist);
        assert!(remaining.is_empty(), "recursive clone of an allowed URL must be allowlisted");
        assert_eq!(allowlisted, vec!["https://github.com/acme/repo.git|recursive".to_string()]);
    }

    #[test]
    fn git_clone_allowlist_matches_non_recursive_clone_of_allowed_url() {
        let signatures = vec!["https://github.com/acme/repo.git|non-recursive".to_string()];
        let allowlist: HashSet<String> = ["https://github.com/acme/repo.git".to_string()].into_iter().collect();
        let (remaining, allowlisted) = filter_allowlisted_git_clone_signatures(signatures, &allowlist);
        assert!(remaining.is_empty());
        assert_eq!(allowlisted.len(), 1);
    }

    #[test]
    fn git_clone_allowlist_does_not_match_different_url() {
        let signatures = vec!["https://github.com/evil/repo.git|non-recursive".to_string()];
        let allowlist: HashSet<String> = ["https://github.com/acme/repo.git".to_string()].into_iter().collect();
        let (remaining, allowlisted) = filter_allowlisted_git_clone_signatures(signatures, &allowlist);
        assert_eq!(remaining.len(), 1);
        assert!(allowlisted.is_empty());
    }

    // --- gap #14: select_effective_baselines — override version equal to current ---

    #[test]
    fn override_equal_to_current_is_included_as_baseline_producing_empty_diff() {
        // An override that pins the same version as `current` means the baseline IS
        // the current version. The diff will always be empty — no anomaly ever fires.
        // This is a footgun: the test documents the behavior so a future change that
        // guards against it is visible and deliberate.
        let override_pair = (Some("3.0.0".to_string()), None);
        let out = select_effective_baselines(
            "3.0.0",
            vec!["2.9.0".to_string()],
            Some(&override_pair),
            2,
        );
        // The override version equals current; it ends up in the baseline set.
        // Any scan using this baseline will produce an empty diff — always allowed.
        assert!(out.contains(&"3.0.0".to_string()),
            "override equal to current is currently included; if this changes, update the override validation in load_policy_config");
    }

    #[test]
    fn override_different_from_current_is_used_normally() {
        let override_pair = (Some("2.8.0".to_string()), None);
        let out = select_effective_baselines(
            "3.0.0",
            vec!["2.9.0".to_string(), "2.7.0".to_string()],
            Some(&override_pair),
            2,
        );
        assert!(out.contains(&"2.8.0".to_string()));
        assert!(!out.contains(&"3.0.0".to_string()));
    }

    // --- gap #15: scan_packages_versions — missing baseline trace fails closed ---

    #[tokio::test]
    async fn scan_fails_closed_when_one_baseline_trace_is_missing() {
        let _guard = env_lock().lock().expect("env lock");
        unsafe { std::env::set_var("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0"); }

        // Runner has trace for current and baseline-1 but NOT baseline-2.
        // With baseline_count=2 both baselines are in the plan; the missing one
        // must cause a fail-closed result rather than a silent partial diff.
        let runner = MockRunner {
            traces: HashMap::from([
                (("pkg".to_string(), "2.0.0".to_string()),
                 "sin_addr=inet_addr(\"1.2.3.4\")\n".to_string()),
                (("pkg".to_string(), "1.9.0".to_string()),
                 "sin_addr=inet_addr(\"1.2.3.4\")\n".to_string()),
                // baseline-2 ("1.8.0") intentionally absent from the map
            ]),
        };

        let policy = PolicyConfig {
            baseline_count: 2,
            baseline_overrides: HashMap::from([(
                "pkg".to_string(),
                (Some("1.9.0".to_string()), Some("1.8.0".to_string())),
            )]),
            ..PolicyConfig::default()
        };

        let results = scan_packages_versions(&runner, "pip", &[("pkg".to_string(), "2.0.0".to_string())], &policy).await;

        unsafe { std::env::remove_var("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H"); }

        assert_eq!(results.get("pkg|2.0.0").map(|r| r.allowed), Some(false),
            "missing baseline trace must fail closed, not silently allow");
    }

}

pub(crate) async fn scan_package_versions(
    runner: &dyn SandboxRunner,
    manager: &str,
    pkg_name: &str,
    tgt_version: &str,
    policy: &PolicyConfig,
) -> ScanReport {
    let targets = vec![(pkg_name.to_string(), tgt_version.to_string())];
    let outcome = scan_packages_versions(runner, manager, &targets, policy).await;
    outcome
        .get(&format!("{}|{}", pkg_name, tgt_version))
        .cloned()
        .unwrap_or_else(|| ScanReport {
            allowed: false,
            resolved_version: tgt_version.to_string(),
        })
}
