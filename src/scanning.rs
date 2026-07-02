use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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
    /// Global entries live under key `"*"`; per-package entries under the package name.
    /// Effective allowlist for a scan = `"*"` entries ∪ per-package entries.
    pub ip_allowlist: HashMap<String, HashSet<String>>,
    pub domain_allowlist: HashMap<String, HashSet<String>>,
    pub git_clone_allowlist: HashMap<String, HashSet<String>>,
    pub baseline_overrides: HashMap<String, (Option<String>, Option<String>)>,
    pub baseline_count: usize,
    pub min_baseline_age_hours_by_package: HashMap<String, i64>,
    /// Packages that bypass the insufficient-baselines block.
    /// The map semantics are `pkg_name -> specifically_vetted_version`.
    /// Empty version values (`""`) are rejected with a warning at parse time.
    pub new_package_exemptions: HashMap<String, String>,
    /// Packages that are skipped entirely — no registry history fetch, no
    /// sandbox install, no diff. Intended for first-party / internal packages
    /// served from a private index (e.g. Nexus) that gyrseek's open-source
    /// registry lookups cannot resolve, so scanning them only produces noise.
    pub internal_package_exemptions: HashSet<String>,
    pub release_burst_threshold: Option<usize>,
    pub release_burst_window_hours: usize,
    pub minimum_release_age_package: Option<usize>,
    /// Watched-process signatures (`bun|run|build`) or bare executables (`bun`)
    /// that are explicitly allowed even when newly introduced.
    pub process_exec_allowlist: HashMap<String, HashSet<String>>,
    /// Artifact finding strings (or `type|path` prefixes) that are explicitly
    /// allowed even when newly introduced. For example `binary|/work/bin/tool`
    /// allows that binary regardless of the `file -b` output.
    pub artifact_allowlist: HashMap<String, HashSet<String>>,
    pub sensitive_file_access_allowlist: HashMap<String, HashSet<String>>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            ip_allowlist: HashMap::new(),
            domain_allowlist: HashMap::new(),
            git_clone_allowlist: HashMap::new(),
            baseline_overrides: HashMap::new(),
            baseline_count: 2,
            min_baseline_age_hours_by_package: HashMap::new(),
            new_package_exemptions: HashMap::new(),
            internal_package_exemptions: HashSet::new(),
            release_burst_threshold: None,
            release_burst_window_hours: 24,
            minimum_release_age_package: None,
            process_exec_allowlist: HashMap::new(),
            artifact_allowlist: HashMap::new(),
            sensitive_file_access_allowlist: HashMap::new(),
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
    /// If not allowed, the list of reasons why the package was blocked.
    pub blocked_reasons: Vec<String>,
}

/// Orders version strings using real semantics rather than lexicographically:
/// semver for npm, PEP 440 for the Python managers. Strings that fail to parse
/// are treated as lower than any parseable version (so junk is never selected as
/// "latest"), with two unparseable strings falling back to lexical order.
fn parse_and_cmp<T: std::cmp::Ord + std::str::FromStr>(a: &str, b: &str) -> Ordering {
    match (a.parse::<T>(), b.parse::<T>()) {
        (Ok(x), Ok(y)) => x.cmp(&y),
        (Ok(_), _) => Ordering::Greater,
        (_, Ok(_)) => Ordering::Less,
        _ => a.cmp(b),
    }
}

fn compare_version_strings(manager: &str, a: &str, b: &str) -> Ordering {
    if is_npm_family_manager(manager) {
        parse_and_cmp::<semver::Version>(a, b)
    } else {
        parse_and_cmp::<pep440_rs::Version>(a, b)
    }
}

fn is_npm_family_manager(manager: &str) -> bool {
    manager == "npm" || manager == "pnpm"
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
    /// Findings from post-install file artifact scan (class-specific IoCs
    /// like suspicious .pth files, unexpected runtime binaries).
    artifact_findings: HashSet<String>,
    /// Sensitive file reads (e.g. ~/.aws/credentials) captured via open/openat.
    sensitive_file_reads: HashSet<String>,
    /// Domain → IP map extracted from DNS responses captured by strace.
    /// Used as a fallback when FCrDNS is unavailable (e.g. CDN edge IPs
    /// without PTR records).
    dns_map: HashMap<String, Vec<IpAddr>>,
}

#[derive(Clone)]
struct VersionPlan {
    package: String,
    target_version: String,
    current: String,
    baselines: Vec<String>,
    baseline_threshold: usize,
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

pub(crate) const HARD_MINIMUM_AGE_HOURS: i64 = 24;
pub(crate) const DEFAULT_MIN_BASELINE_AGE_HOURS: i64 = 72;

/// The cloud instance metadata endpoint (link-local by address, but a real
/// SSRF / credential-theft target). We never filter it as "local noise" so a
/// package reaching for it is always surfaced.
const CLOUD_METADATA_IPV4: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);

/// Canonicalises an IP string for comparison. Beyond `IpAddr`'s own
/// normalisation (textual IPv6 forms), this collapses IPv4-mapped IPv6
/// (`::ffff:172.17.0.2`) down to its bare IPv4 form (`172.17.0.2`) so the two
/// representations compare equal against baselines and allowlists. Unparseable
/// inputs are returned unchanged.
pub(crate) fn normalize_ip_string(ip: &str) -> String {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => IpAddr::V6(v6).to_string(),
        },
        Ok(addr) => addr.to_string(),
        Err(_) => ip.to_string(),
    }
}

/// True for addresses that are sandbox plumbing rather than meaningful
/// destinations: loopback, link-local, and private (RFC1918 / Docker bridge /
/// Docker Desktop gateway) ranges. These can never represent exfiltration off
/// the host from inside an isolated single-container sandbox, so filtering them
/// before the baseline diff removes a whole class of harness-nondeterminism
/// false positives. The cloud metadata endpoint is deliberately exempt.
pub(crate) fn is_sandbox_local_ip(ip: &str) -> bool {
    // Compare on the IPv4-mapped-collapsed form so `::ffff:10.0.0.1` is judged
    // by its IPv4 semantics.
    let addr: IpAddr = match normalize_ip_string(ip).parse() {
        Ok(addr) => addr,
        Err(_) => return false,
    };

    match addr {
        IpAddr::V4(v4) => {
            if v4 == CLOUD_METADATA_IPV4 {
                return false;
            }
            v4.is_loopback() || v4.is_private() || v4.is_link_local()
        }
        IpAddr::V6(v6) => {
            // fe80::/10 link-local (no stable std helper) plus loopback.
            let is_link_local = (v6.segments()[0] & 0xffc0) == 0xfe80;
            v6.is_loopback() || is_link_local
        }
    }
}

/// Returns connections present in the current version but absent in baseline versions.
/// Domain-aware IP diff: if a current IP resolves via FCrDNS to a domain that
/// was already seen in baseline traffic, it is not a new connection — just a
/// benign CDN edge rotation. IPs that do not resolve (no PTR record, or FCrDNS
/// fails) fall back to a plain IP-level membership check, so the diff remains
/// fail-closed for genuinely new or spoofed endpoints.
pub(crate) fn find_new_connections_domain_aware<F, G>(
    ips_curr: &HashSet<String>,
    baseline_ips: &HashSet<String>,
    resolver: F,
    dns_map: &HashMap<String, Vec<IpAddr>>,
    baseline_dns_domains: &HashSet<String>,
    forward_resolver: G,
) -> Vec<String>
where
    F: Fn(&str) -> Option<String>,
    G: Fn(&str) -> Option<Vec<IpAddr>>,
{
    // Build set of domains known from baseline runs: FCrDNS of baseline IPs
    // plus any domains observed in baseline DNS traces.
    let baseline_domains: HashSet<String> = baseline_ips
        .iter()
        .filter_map(|ip| resolver(ip))
        .chain(baseline_dns_domains.iter().cloned())
        .collect();

    ips_curr
        .iter()
        .filter(|ip| match resolver(ip) {
            Some(domain) => !baseline_domains.contains(&domain),
            None => {
                // FCrDNS failed (no PTR record, e.g. CDN edge IP).
                // Fall back to DNS interceptor: if a baseline-known domain
                // was observed resolving to this IP inside the sandbox,
                // verify the binding on the host side and skip if valid.
                let host_verified: bool = dns_map.iter().any(|(domain, dns_ips)| {
                    if !baseline_domains.contains(domain.as_str()) {
                        return false;
                    }
                    let parsed: IpAddr = match ip.parse() {
                        Ok(a) => a,
                        Err(_) => return false,
                    };
                    if !dns_ips.contains(&parsed) {
                        return false;
                    }
                    // Host-side forward resolution: confirm the domain
                    // legitimately resolves to this IP (anti-spoofing).
                    matches!(forward_resolver(domain), Some(ref addrs) if addrs.contains(&parsed))
                });
                if host_verified {
                    false
                } else {
                    !baseline_ips.contains(*ip)
                }
            }
        })
        .cloned()
        .collect()
}

pub(crate) fn filter_allowlisted_new_connections(
    package_name: &str,
    new_connections: Vec<String>,
    ip_allowlist: &HashMap<String, HashSet<String>>,
) -> (Vec<String>, Vec<String>) {
    let empty = HashSet::new();
    let canonical_allowlist: HashSet<&str> = ip_allowlist
        .get("*")
        .unwrap_or(&empty)
        .iter()
        .chain(ip_allowlist.get(package_name).unwrap_or(&empty).iter())
        .map(|s| s.as_str())
        .collect();

    new_connections
        .into_iter()
        .partition(|ip| match ip.parse::<IpAddr>() {
            Ok(_) => !canonical_allowlist.contains(normalize_ip_string(ip).as_str()),
            Err(_) => true,
        })
}

fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn domain_is_allowlisted(domain: &str, domain_allowlist: &HashSet<String>) -> bool {
    let normalized = normalize_domain(domain);
    domain_allowlist.iter().any(|allowed| {
        // Entries are pre-normalized at config-load time; no re-allocation needed.
        normalized == *allowed || normalized.ends_with(&format!(".{}", allowed))
    })
}

pub(crate) fn filter_domain_allowlisted_new_connections_with<F>(
    package_name: &str,
    new_connections: Vec<String>,
    domain_allowlist: &HashMap<String, HashSet<String>>,
    resolver: F,
) -> (Vec<String>, Vec<String>)
where
    F: Fn(&str) -> Option<String>,
{
    let empty = HashSet::new();
    let effective: HashSet<String> = domain_allowlist
        .get("*")
        .unwrap_or(&empty)
        .iter()
        .chain(domain_allowlist.get(package_name).unwrap_or(&empty).iter())
        .cloned()
        .collect();

    let mut remaining = Vec::new();
    let mut allowlisted = Vec::new();

    for ip in new_connections {
        match resolver(&ip) {
            Some(domain) if domain_is_allowlisted(&domain, &effective) => {
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

// ---------------------------------------------------------------------------
// DNS response extraction from strace trace (requires strace -xx flag)
// ---------------------------------------------------------------------------

/// Converts a strace hex-escaped string (`\xab\xcd...`) back into raw bytes.
/// Works correctly with `-xx` (all bytes as `\xNN`) and also handles the mixed
/// ASCII/escape format produced without it.
fn unescape_strace_string(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() / 4);
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('x') => {
                    let hi = chars.next().and_then(|c| c.to_digit(16)).unwrap_or(0);
                    let lo = chars.next().and_then(|c| c.to_digit(16)).unwrap_or(0);
                    out.push((hi as u8) << 4 | lo as u8);
                }
                Some(c2) => out.push(c2 as u8),
                None => break,
            }
        } else {
            out.push(c as u8);
        }
    }
    out
}

/// Decodes a DNS wire-format name starting at `offset`.  Handles standard
/// length-prefixed labels (1–63 bytes) and compression pointers (0xc0 prefix,
/// pointing back into the packet).  Updates `offset` past the compressed or
/// literal name.  Returns `None` on malformed input.
fn decode_dns_name(raw: &[u8], offset: &mut usize) -> Option<String> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = *offset;
    let mut jumped = false;
    let mut resume_at = 0;
    let mut pointer_count = 0;

    loop {
        if pos >= raw.len() {
            return None;
        }
        let len = raw[pos] as usize;
        if len == 0 {
            // Root label — end of name.
            pos += 1;
            break;
        }
        if len & 0xc0 == 0xc0 {
            // Compression pointer: 2 bytes, offset in lower 14 bits.
            if pos + 2 > raw.len() {
                return None;
            }
            let ptr = ((len & 0x3f) << 8) | raw[pos + 1] as usize;
            pointer_count += 1;
            // Limit pointer hops to prevent circular/repeating pointers
            // from hanging the parser.  5 hops covers any legitimate DNS
            // name (RFC permits at most 255 total bytes in a name, and
            // each compression pointer saves at least 1 byte).
            if pointer_count > 5 {
                return None;
            }
            if !jumped {
                resume_at = pos + 2;
                jumped = true;
            }
            pos = ptr;
            continue;
        }
        // Normal label: 1-byte length + label bytes.
        pos += 1;
        if pos + len > raw.len() {
            return None;
        }
        let label = std::str::from_utf8(&raw[pos..pos + len]).ok()?;
        labels.push(label.to_string());
        pos += len;
    }

    *offset = if jumped { resume_at } else { pos };
    Some(labels.join("."))
}

/// Parses a single DNS response payload, extracting the query name and all
/// A / AAAA record addresses from the answer section.  Ignores CNAME, NS,
/// and other record types.  Returns `None` if the payload is not a DNS
/// response (QR flag not set) or is too short to parse.
fn parse_dns_response(raw: &[u8]) -> Option<(String, Vec<IpAddr>)> {
    if raw.len() < 12 {
        return None;
    }
    // Byte 2, bit 15 = QR (response flag).
    if raw[2] & 0x80 == 0 {
        return None;
    }
    let ancount = u16::from_be_bytes([raw[6], raw[7]]) as usize;
    if ancount == 0 {
        return None;
    }

    let mut offset: usize = 12;
    let qname = decode_dns_name(raw, &mut offset)?;
    // Skip qtype (2) + qclass (2).
    offset += 4;

    let mut answers: Vec<IpAddr> = Vec::new();
    for _ in 0..ancount {
        if offset + 10 > raw.len() {
            break;
        }
        // Skip NAME (usually a 2-byte pointer 0xc00c).
        offset += 2;
        if offset + 10 > raw.len() {
            break;
        }
        let rtype = u16::from_be_bytes([raw[offset], raw[offset + 1]]);
        let rdlen = u16::from_be_bytes([raw[offset + 8], raw[offset + 9]]);
        offset += 10; // past TYPE + CLASS + TTL + RDLENGTH
        let rdlen = rdlen as usize;
        if offset + rdlen > raw.len() {
            break;
        }
        match (rtype, rdlen) {
            (1, 4) => {
                answers.push(IpAddr::V4(Ipv4Addr::new(
                    raw[offset],
                    raw[offset + 1],
                    raw[offset + 2],
                    raw[offset + 3],
                )));
            }
            (28, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&raw[offset..offset + 16]);
                answers.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            _ => {}
        }
        offset += rdlen;
    }

    if answers.is_empty() {
        None
    } else {
        Some((qname, answers))
    }
}

/// Extracts a domain → IP map from DNS response packets visible in the strace
/// trace.  Requires strace `-xx` so all bytes appear as `\xNN` for reliable
/// wire-format parsing.
fn extract_dns_map(trace: &str) -> HashMap<String, Vec<IpAddr>> {
    // UDP DNS: recvfrom with sin_port=htons(53) — responses from the DNS resolver.
    static UDP_RE: OnceLock<Regex> = OnceLock::new();
    let udp_re = UDP_RE.get_or_init(|| {
        Regex::new(
            r#"recvfrom\(\d+,\s*"((?:\\x[0-9a-fA-F]{2}|[^"\\])*)",\s*\d+,\s*\d+,\s*\{[^}]*\bsin6?_port=htons\(53\)"#
        ).unwrap()
    });

    // TCP DNS: track fds connected to port 53, then capture read() on them.
    // TCP DNS wire format prepends a 2-byte length prefix before the DNS message.
    static CONNECT_RE: OnceLock<Regex> = OnceLock::new();
    let connect_re = CONNECT_RE.get_or_init(|| {
        Regex::new(r#"connect\((\d+),.*?sin6?_port=htons\(53\).*\)\s*=\s*0\b"#).unwrap()
    });

    static READ_RE: OnceLock<Regex> = OnceLock::new();
    let read_re = READ_RE.get_or_init(|| {
        Regex::new(
            r#"(?:read|recvmsg)\((\d+),(?:.*?msg_iov=\[\{(?:iov_base=)?)?\s*"((?:\\x[0-9a-fA-F]{2}|[^"\\])*)""#,
        )
        .unwrap()
    });

    let dns_fds: HashSet<i32> = connect_re
        .captures_iter(trace)
        .filter_map(|c| c[1].parse().ok())
        .collect();

    let mut map: HashMap<String, Vec<IpAddr>> = HashMap::new();

    // Parse UDP DNS responses
    for caps in udp_re.captures_iter(trace) {
        let raw = unescape_strace_string(&caps[1]);
        if let Some((qname, ips)) = parse_dns_response(&raw) {
            map.entry(qname).or_default().extend(ips);
        }
    }

    // Parse TCP DNS responses (read() on fds connected to port 53)
    if !dns_fds.is_empty() {
        for caps in read_re.captures_iter(trace) {
            let fd: i32 = match caps[1].parse() {
                Ok(fd) => fd,
                Err(_) => continue,
            };
            if !dns_fds.contains(&fd) {
                continue;
            }
            let raw = unescape_strace_string(&caps[2]);
            if raw.len() < 3 {
                continue;
            }
            if let Some((qname, ips)) = parse_dns_response(&raw[2..]) {
                map.entry(qname).or_default().extend(ips);
            }
        }
    }

    map
}

fn exemption_behavior<'a>(
    exempt_version: Option<&'a str>,
    v_curr: &str,
    baselines_len: usize,
    baseline_count: usize,
    pkg_name: &'a str,
) -> (bool, Vec<String>) {
    let Some(exempt_version) = exempt_version else {
        return (false, vec![]);
    };
    let is_exempt = exempt_version == v_curr;
    let msgs = if baselines_len >= baseline_count && is_exempt {
        vec![format!(
            "ℹ️ [gyrseek] You have an exemption for '{pkg_name}' pinned to version '{exempt_version}'. Since the package now has sufficient baselines, you can safely remove it from your configuration.",
        )]
    } else if !is_exempt {
        vec![format!(
            "ℹ️ [gyrseek] Exemption for '{pkg_name}' is pinned to version '{exempt_version}', ignoring for current version '{v_curr}'.",
        )]
    } else {
        vec![]
    };
    (is_exempt, msgs)
}

fn filter_override_version<'a>(
    v: &'a str,
    package: &str,
    published_at: &std::collections::HashMap<String, DateTime<Utc>>,
    now: DateTime<Utc>,
    warnings: &mut Vec<String>,
) -> Option<&'a str> {
    if let Some(ts) = published_at.get(v) {
        let age_hours = (now - *ts).num_hours();
        if age_hours < HARD_MINIMUM_AGE_HOURS {
            warnings.push(format!(
                "⚠️ [gyrseek] Warning: baseline override '{}' for package '{}' is only {} hours old, which is below the hardcoded security floor of {} hours. Skipping it.",
                v, package, age_hours, HARD_MINIMUM_AGE_HOURS
            ));
            return None;
        }
    } else {
        warnings.push(format!(
            "⚠️ [gyrseek] Warning: baseline override '{}' for package '{}' could not be found in the registry history. Skipping it.",
            v, package
        ));
        return None;
    }
    Some(v)
}
pub(crate) type BaselineOverrides = (Option<String>, Option<String>);

fn check_override_ages(
    package: &str,
    overrides: Option<&BaselineOverrides>,
    published_at: &std::collections::HashMap<String, DateTime<Utc>>,
    now: DateTime<Utc>,
) -> (Vec<String>, Option<BaselineOverrides>) {
    let mut warnings = Vec::new();
    let filtered = overrides.map(|(m1, m2)| {
        (
            m1.as_ref()
                .and_then(|v| filter_override_version(v, package, published_at, now, &mut warnings))
                .map(String::from),
            m2.as_ref()
                .and_then(|v| filter_override_version(v, package, published_at, now, &mut warnings))
                .map(String::from),
        )
    });
    (warnings, filtered)
}

#[cfg(any(debug_assertions, test))]
fn active_test_env_vars() -> Vec<&'static str> {
    let test_vars = [
        "GYRSEEK_TEST_FORCE_BASELINE_AGES_HOURS",
        "GYRSEEK_TEST_FORCE_RELEASES_LAST_24H",
        "GYRSEEK_TEST_FORCE_CURRENT_RELEASE_AGE_DAYS",
        "GYRSEEK_TEST_ECHO_MIN_BASELINE_AGE_HOURS",
    ];
    test_vars
        .iter()
        .filter(|v| std::env::var(v).is_ok())
        .copied()
        .collect()
}

pub(crate) struct BaselineHistory {
    pub v_curr: String,
    pub fetched_baselines: Vec<String>,
    pub releases_last_24h: usize,
    pub current_release_age_days: Option<i64>,
    pub published_at: HashMap<String, DateTime<Utc>>,
}

pub(crate) async fn fetch_history_with_baselines(
    manager: &str,
    package: &str,
    target_v: &str,
    baseline_count: usize,
    min_baseline_age_hours: i64,
    release_burst_window_hours: i64,
    now: DateTime<Utc>,
) -> BaselineHistory {
    #[cfg(any(debug_assertions, test))]
    {
        let active = active_test_env_vars();
        if !active.is_empty() {
            eprintln!(
                "⚠️ [gyrseek] debug build: test env vars active — registry-based baseline selection bypassed: {}",
                active.join(", ")
            );
        }
    }

    #[cfg(any(debug_assertions, test))]
    if let Ok(ages_str) = std::env::var("GYRSEEK_TEST_FORCE_BASELINE_AGES_HOURS") {
        let ages: Vec<i64> = ages_str.split(',').filter_map(|s| s.parse().ok()).collect();
        let mut published_at = std::collections::HashMap::new();
        let mut candidates = Vec::new();
        for (i, age) in ages.iter().enumerate() {
            let v = format!("0.{}.0", i);
            candidates.push(v.clone());
            published_at.insert(v, now - chrono::Duration::hours(*age));
        }
        let cutoff = now - chrono::Duration::hours(min_baseline_age_hours);
        let baselines =
            select_age_eligible_baselines(candidates, &published_at, cutoff, baseline_count);
        return BaselineHistory {
            v_curr: target_v.to_string(),
            fetched_baselines: baselines,
            releases_last_24h: 0,
            current_release_age_days: None,
            published_at: HashMap::new(),
        };
    }

    #[cfg(any(debug_assertions, test))]
    {
        let forced_releases_last_24h = std::env::var("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H")
            .ok()
            .and_then(|v| v.parse::<usize>().ok());
        let forced_current_release_age_days =
            std::env::var("GYRSEEK_TEST_FORCE_CURRENT_RELEASE_AGE_DAYS")
                .ok()
                .and_then(|v| v.parse::<i64>().ok());
        if forced_releases_last_24h.is_some() || forced_current_release_age_days.is_some() {
            return BaselineHistory {
                v_curr: target_v.to_string(),
                fetched_baselines: Vec::new(),
                releases_last_24h: forced_releases_last_24h.unwrap_or(0),
                current_release_age_days: forced_current_release_age_days,
                published_at: HashMap::new(),
            };
        }
    }

    #[cfg(any(debug_assertions, test))]
    if std::env::var("GYRSEEK_TEST_ECHO_MIN_BASELINE_AGE_HOURS").is_ok() {
        return BaselineHistory {
            v_curr: target_v.to_string(),
            fetched_baselines: vec![
                format!("{}_echo1", min_baseline_age_hours),
                format!("{}_echo2", min_baseline_age_hours),
            ],
            releases_last_24h: 0,
            current_release_age_days: None,
            published_at: HashMap::new(),
        };
    }

    println!(
        "🔍 [gyrseek] Fetching version matrix from registry for '{}'...",
        package
    );
    let client = reqwest::Client::new();

    if is_npm_family_manager(manager) {
        let encoded = package.replace('/', "%2f");
        let url = format!("https://registry.npmjs.org/{}", encoded);
        if let Ok(res) = client.get(&url).send().await
            && let Ok(data) = res.json::<NpmResponse>().await
        {
            let mut versions: Vec<String> = data.versions.keys().cloned().collect();
            sort_versions_ascending(manager, &mut versions);

            let current = if target_v == "latest" {
                versions
                    .last()
                    .cloned()
                    .unwrap_or_else(|| target_v.to_string())
            } else {
                target_v.to_string()
            };

            if let Some(idx) = versions.iter().position(|v| v == &current) {
                let cutoff = now - Duration::hours(min_baseline_age_hours);
                let version_keys: HashSet<String> = data.versions.keys().cloned().collect();
                let published_at = npm_published_times(&data.time, &version_keys);
                let releases_last_24h = count_releases_in_window(
                    &published_at,
                    now - Duration::hours(release_burst_window_hours.max(1)),
                    now,
                );
                let current_release_age_days =
                    published_at.get(&current).map(|ts| (now - *ts).num_days());
                let candidates: Vec<String> = versions[..idx].iter().rev().cloned().collect();
                let baselines = select_age_eligible_baselines(
                    candidates,
                    &published_at,
                    cutoff,
                    baseline_count,
                );
                return BaselineHistory {
                    v_curr: current,
                    fetched_baselines: baselines,
                    releases_last_24h,
                    current_release_age_days,
                    published_at,
                };
            }
        }
    } else {
        let url = format!("https://pypi.org/pypi/{}/json", package);
        if let Ok(res) = client.get(&url).send().await
            && let Ok(data) = res.json::<PyPiResponse>().await
        {
            let mut versions: Vec<String> = data.releases.keys().cloned().collect();
            sort_versions_ascending(manager, &mut versions);

            let current = if target_v == "latest" {
                versions
                    .last()
                    .cloned()
                    .unwrap_or_else(|| target_v.to_string())
            } else {
                target_v.to_string()
            };

            if let Some(idx) = versions.iter().position(|v| v == &current) {
                let cutoff = now - Duration::hours(min_baseline_age_hours);
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
                let current_release_age_days =
                    published_at.get(&current).map(|ts| (now - *ts).num_days());

                let candidates: Vec<String> = versions[..idx].iter().rev().cloned().collect();
                let baselines = select_age_eligible_baselines(
                    candidates,
                    &published_at,
                    cutoff,
                    baseline_count,
                );
                return BaselineHistory {
                    v_curr: current,
                    fetched_baselines: baselines,
                    releases_last_24h,
                    current_release_age_days,
                    published_at,
                };
            }
        }
    }

    BaselineHistory {
        v_curr: target_v.to_string(),
        fetched_baselines: Vec::new(),
        releases_last_24h: 0,
        current_release_age_days: None,
        published_at: HashMap::new(),
    }
}

/// Delimiter between the strace trace and post-install artifact findings embedded
/// in the same probe string by the sandbox runner.
const ARTIFACT_DELIMITER: &str = "\n=== gyrseek_artifacts ===\n";

/// Threshold for large_file classification (10 MB).
const LARGE_FILE_THRESHOLD: u64 = 10 * 1024 * 1024;

/// Patterns that make a .pth file suspicious (matched case-insensitively
/// against the first 300 bytes of content).
const SUSPICIOUS_PTH_PATTERNS: &[&str] = &[
    "import ",
    "exec(",
    "eval(",
    "urllib",
    "subprocess",
    "ctypes",
    "socket.",
];

/// Returns the trace portion (before the artifact delimiter) for the existing
/// strace-parsing extractors (IPs, execve, git clone).
fn strip_artifact_section(full: &str) -> &str {
    if let Some(pos) = full.find(ARTIFACT_DELIMITER) {
        &full[..pos]
    } else {
        full
    }
}

/// Parses artifact findings from the post-install scan embedded in the probe
/// string. Each line is a structured finding (e.g.
/// `suspicious_pth|/path|content`).
fn extract_artifact_findings(full: &str) -> HashSet<String> {
    if let Some(pos) = full.find(ARTIFACT_DELIMITER) {
        let section = &full[pos + ARTIFACT_DELIMITER.len()..];
        section
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| l.trim().to_string())
            .collect()
    } else {
        HashSet::new()
    }
}

/// Classifies raw inventory lines (generated by `build_artifact_scan_steps`)
/// into structured finding tags. Inventory format per line:
///   `path\0size\0file_type\0content`  (null-byte delimited)
///
/// Produces findings:
///   - `binary|path|file_type`       — ELF / Mach-O / PE binary
///   - `unexpected_runtime|path|type` — bun/deno binary (subset of binary)
///   - `suspicious_pth|path|content`  — .pth with executable import/call patterns
///   - `large_file|path|size`        — file >10 MB
fn classify_inventory_lines(raw: HashSet<String>) -> HashSet<String> {
    let mut findings = HashSet::new();
    for line in raw {
        let parts: Vec<&str> = line.splitn(4, '\x00').collect();
        if parts.len() < 2 {
            continue;
        }
        let path = parts[0];
        let size_str = parts[1];
        let file_type = if parts.len() > 2 { parts[2] } else { "" };
        let content = if parts.len() > 3 { parts[3] } else { "" };

        let size: u64 = size_str.parse().unwrap_or(0);

        // Large file check (before binary check so both tags can coexist).
        if size > LARGE_FILE_THRESHOLD {
            findings.insert(format!("large_file|{}|{}", path, size));
        }

        // Binary executable detection (ELF, Mach-O, PE).
        let is_binary = file_type.contains("ELF")
            || file_type.contains("Mach-O")
            || file_type.contains("PE32")
            || file_type.contains("PE32+");
        if is_binary {
            let fname = std::path::Path::new(path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            // Unexpected runtime binaries (bun / deno).
            if fname.starts_with("bun-")
                || fname.starts_with("deno-")
                || fname == "bun"
                || fname == "deno"
            {
                findings.insert(format!("unexpected_runtime|{}|{}", path, file_type));
            }
            findings.insert(format!("binary|{}|{}", path, file_type));
        }

        // Suspicious .pth detection.
        if path.ends_with(".pth") {
            let content_lower = content.to_lowercase();
            if SUSPICIOUS_PTH_PATTERNS
                .iter()
                .any(|pat| content_lower.contains(pat))
            {
                findings.insert(format!("suspicious_pth|{}|{}", path, content));
            }
        }
    }
    findings
}

fn trace_sandbox_install_matrix(
    runner: &dyn SandboxRunner,
    manager: &str,
    probes: &[(String, String)],
) -> Result<HashMap<(String, String), TraceSignals>, String> {
    let traces = runner.trace_install_matrix(manager, probes)?;
    let mut by_probe: HashMap<(String, String), TraceSignals> = HashMap::new();

    for ((package, version), stderr_str) in traces {
        let trace = strip_artifact_section(&stderr_str);
        let raw_artifact_lines = extract_artifact_findings(&stderr_str);
        let artifact_findings = classify_inventory_lines(raw_artifact_lines);
        let signals = TraceSignals {
            ips: extract_connection_ips(trace),
            git_clone_signatures: extract_git_clone_signatures(trace),
            process_exec_signatures: extract_process_exec_signatures(trace),
            artifact_findings,
            sensitive_file_reads: extract_sensitive_file_reads(trace),
            dns_map: extract_dns_map(trace),
        };
        by_probe.insert((package, version), signals);
    }

    Ok(by_probe)
}

/// Extracts both IPv4 and IPv6 connection endpoints from an strace trace.
///
/// IPv4 appears as `sin_addr=inet_addr("1.2.3.4")`. IPv6 appears as
/// `sin6_addr=inet_pton(AF_INET6, "2001:db8::1", ...)` (and the abbreviated
/// `inet_pton("2001:db8::1")` form some strace builds emit). Captured values
/// are run through [`normalize_ip_string`] so equivalent textual forms — and
/// IPv4-mapped IPv6 (`::ffff:1.2.3.4`) vs bare IPv4 — compare equal against
/// baselines and allowlists.
///
/// Sandbox-local addresses (loopback / link-local / private — see
/// [`is_sandbox_local_ip`]) are dropped here, before any baseline diff, because
/// inside an isolated single-container sandbox they are the container's own
/// plumbing (Docker bridge, host gateway, DNS resolver) and can never be a
/// meaningful exfiltration signal. The cloud metadata endpoint is exempt.
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
        let canonical = normalize_ip_string(&cap[1]);
        if !is_sandbox_local_ip(&canonical) {
            ips.insert(canonical);
        }
    }
    for cap in v6.captures_iter(trace) {
        if let Some(raw) = cap.get(1).or_else(|| cap.get(2)) {
            let canonical = normalize_ip_string(raw.as_str());
            if !is_sandbox_local_ip(&canonical) {
                ips.insert(canonical);
            }
        }
    }
    ips
}

/// Parses every `execve(..., [argv], ...)` line in an strace trace into its
/// decoded argv vector. Shared by the git-clone and process-execution extractors.
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

    execve_re
        .captures_iter(trace)
        .filter_map(|cap| {
            let argv = cap.name("argv").map(|m| m.as_str()).unwrap_or("");
            let args: Vec<String> = quoted_arg_re
                .captures_iter(argv)
                .filter_map(|m| m.get(1).map(|x| x.as_str().replace("\\\"", "\"")))
                .collect();
            if args.is_empty() { None } else { Some(args) }
        })
        .collect()
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
/// Returns true if the parsed execve corresponds to the sandbox's own
/// machinery (install command, interpreter discovery) rather than the
/// package's own behavior. These are excluded from process-exec signatures
/// because their argv contains version-specific strings that would always
/// appear as "new" between versions.
fn is_harness_command(exe: &str, args: &[String]) -> bool {
    let contains = |needle: &str| args.iter().any(|a| a.contains(needle));
    match exe {
        "uv" => args.len() >= 2 && args[0] == "pip" && args[1] == "install" && contains("--target"),
        "npm" => {
            // npm install <pkg>@<ver> --prefix /work --no-save
            // Note: uses `contains("--prefix")` as a harness heuristic. If a
            // package's own build script happens to pass `--prefix` to npm,
            // it would be excluded from exec signatures. This is acceptably
            // unlikely — npm uses `--prefix` for target-dir, not as a common
            // build flag.
            args.len() >= 2 && args[0] == "install" && contains("--prefix")
        }
        "node" => {
            // node <npm-path> install <pkg>@<ver> --prefix /work --no-save
            // or node <pnpm-path> add <pkg>@<ver> --dir /work --lockfile=false
            args.len() >= 2
                && ((contains("install") && contains("--prefix"))
                    || (contains("add") && contains("--dir")))
        }
        "pnpm" => {
            // pnpm add <pkg>@<ver> --dir /work --lockfile=false
            args.len() >= 2 && args[0] == "add" && contains("--dir")
        }
        e if e.starts_with("python") => contains("get_interpreter_info"),
        "env" => {
            if let Some(idx) = args.iter().position(|a| !a.contains('=')) {
                let inner_exe = executable_basename(&args[idx]);
                let inner_args = &args[idx + 1..];
                is_harness_command(&inner_exe, inner_args)
            } else {
                false
            }
        }
        _ => false,
    }
}

/// both "this version started executing bun" and "this version runs bun but with
/// new/extra arguments not seen before".
fn extract_process_exec_signatures(trace: &str) -> HashSet<String> {
    let mut signatures = HashSet::new();
    for args in parse_execve_argvs(trace) {
        // With strace -xx the argv is hex-escaped; unescape so
        // executable_basename / is_harness_command match correctly.
        let unescaped: Vec<String> = args
            .iter()
            .map(|a| String::from_utf8_lossy(&unescape_strace_string(a)).to_string())
            .collect();
        let exe = executable_basename(&unescaped[0]);
        if is_harness_command(&exe, &unescaped[1..]) {
            continue;
        }
        // Signature = basename + remaining argv, so changed/extra args produce a
        // distinct signature that won't match the baseline set.
        let mut parts = vec![exe];
        parts.extend(unescaped[1..].iter().cloned());
        signatures.insert(parts.join("|"));
    }
    signatures
}

fn is_sensitive_file_read(path: &str) -> bool {
    let path = path.trim();
    if path.is_empty() {
        return false;
    }

    if path == "/proc/self/environ" || (path.starts_with("/proc/") && path.ends_with("/environ")) {
        return true;
    }

    let ends_with_any = [
        "/.aws/credentials",
        "/.aws/config",
        "/.ssh/id_rsa",
        "/.ssh/id_ed25519",
        "/.ssh/id_ecdsa",
        "/.ssh/id_dsa",
        "/.npmrc",
        "/.env",
        "/.kube/config",
        "/.netrc",
        "/.docker/config.json",
        "/etc/passwd",
        "/etc/shadow",
        "/.config/gcloud/application_default_credentials.json",
        "/.config/openstack/clouds.yaml",
        "/.m2/settings.xml",
        "/.git-credentials",
        "/.cargo/credentials",
        "/.gem/credentials",
    ];
    let exact_match = [
        ".aws/credentials",
        ".aws/config",
        ".npmrc",
        ".env",
        ".netrc",
        "/etc/passwd",
        "/etc/shadow",
        ".config/gcloud/application_default_credentials.json",
        ".config/openstack/clouds.yaml",
        ".m2/settings.xml",
        ".git-credentials",
        ".cargo/credentials",
        ".gem/credentials",
    ];

    for s in ends_with_any.iter() {
        if path.ends_with(s) {
            return true;
        }
    }
    for s in exact_match.iter() {
        if path == *s {
            return true;
        }
    }
    if path.contains("/.gnupg/private-keys-v1.d/") || path.contains("/.azure/") {
        return true;
    }

    false
}

fn lexical_clean_path(path: &str) -> String {
    let is_absolute = path.starts_with('/');
    let mut parts = Vec::new();
    for comp in path.split('/') {
        if comp.is_empty() || comp == "." {
            continue;
        }
        if comp == ".." {
            if parts.is_empty() {
                if !is_absolute {
                    parts.push("..");
                }
            } else if parts.last() == Some(&"..") {
                parts.push("..");
            } else {
                parts.pop();
            }
        } else {
            parts.push(comp);
        }
    }
    if is_absolute {
        format!("/{}", parts.join("/"))
    } else {
        parts.join("/")
    }
}

fn extract_first_arg_fd(args_str: &str) -> Option<i32> {
    let delim = args_str.find([',', ')']).unwrap_or(args_str.len());
    args_str[..delim].trim().parse::<i32>().ok()
}

fn extract_sensitive_file_reads(trace: &str) -> HashSet<String> {
    static LINE_RE: OnceLock<Regex> = OnceLock::new();
    static SYSCALL_RE: OnceLock<Regex> = OnceLock::new();
    static RESUMED_RE: OnceLock<Regex> = OnceLock::new();
    static PROC_FD_RE: OnceLock<Regex> = OnceLock::new();

    let line_re = LINE_RE.get_or_init(|| {
        Regex::new(r#"^(?:\[pid\s+(?P<pid1>\d+)\]\s+|(?P<pid2>\d+)\s+)?(?P<rest>.*)"#).unwrap()
    });
    let syscall_re = SYSCALL_RE.get_or_init(|| {
        Regex::new(
            r#"^(?P<syscall>open|openat|openat64|openat2|link|linkat|symlink|symlinkat|clone|clone3|fork|vfork|dup|dup2|dup3|fcntl)\((?P<args>.*)"#,
        )
        .unwrap()
    });
    let resumed_re = RESUMED_RE.get_or_init(|| {
        Regex::new(r#"^<\.\.\.\s*(?P<syscall>[a-z0-9_]+)\s+resumed>\s*(?P<args_and_ret>.*)"#)
            .unwrap()
    });
    let proc_fd_re = PROC_FD_RE
        .get_or_init(|| Regex::new(r#"^/proc/(?:self|\d+)/fd/(?P<fd>\d+)(?P<rest>.*)"#).unwrap());

    let mut reads = HashSet::new();
    let mut fd_table: HashMap<(u32, i32), String> = HashMap::new(); // (pid, fd) -> absolute path
    let mut pending_syscalls: HashMap<u32, String> = HashMap::new(); // pid -> path of unfinished open/openat
    let mut pending_dup_args: HashMap<u32, i32> = HashMap::new(); // pid -> old_fd

    for line in trace.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let Some(caps) = line_re.captures(line) else {
            continue;
        };
        let pid_match = caps.name("pid1").or_else(|| caps.name("pid2"));
        let pid: u32 = pid_match
            .map(|m| m.as_str().parse().unwrap_or(0))
            .unwrap_or(0);
        let rest = caps.name("rest").map(|m| m.as_str()).unwrap_or("");

        if let Some(resumed_caps) = resumed_re.captures(rest) {
            let syscall = resumed_caps
                .name("syscall")
                .map(|m| m.as_str())
                .unwrap_or("");
            let args_and_ret = resumed_caps
                .name("args_and_ret")
                .map(|m| m.as_str())
                .unwrap_or("");

            let mut ret_val: Option<i32> = None;
            if let Some(idx) = args_and_ret.rfind(" = ") {
                let ret_str = &args_and_ret[idx + 3..].trim();
                ret_val = ret_str.parse::<i32>().ok();
            }

            if matches!(syscall, "clone" | "clone3" | "fork" | "vfork") {
                if let Some(child_pid) = ret_val.map(|v| v as u32)
                    && child_pid > 0
                {
                    let mut to_insert = Vec::new();
                    for (&(p, fd), path) in &fd_table {
                        if p == pid {
                            to_insert.push((child_pid, fd, path.clone()));
                        }
                    }
                    for (c_pid, fd, path) in to_insert {
                        fd_table.insert((c_pid, fd), path);
                    }
                }
            } else if matches!(syscall, "dup" | "dup2" | "dup3" | "fcntl") {
                if let Some(new_fd) = ret_val
                    && new_fd >= 0
                    && let Some(old_fd) = pending_dup_args.remove(&pid)
                    && let Some(path) = fd_table.get(&(pid, old_fd)).cloned()
                {
                    fd_table.insert((pid, new_fd), path);
                }
            } else if matches!(syscall, "open" | "openat" | "openat64" | "openat2")
                && let Some(path) = pending_syscalls.remove(&pid)
                && let Some(fd) = ret_val
                && fd >= 0
            {
                fd_table.insert((pid, fd), path);
            }
            continue;
        }

        if let Some(syscall_caps) = syscall_re.captures(rest) {
            let syscall = syscall_caps
                .name("syscall")
                .map(|m| m.as_str())
                .unwrap_or("");
            let args_str = syscall_caps.name("args").map(|m| m.as_str()).unwrap_or("");

            let unfinished = args_str.ends_with("<unfinished ...>");
            let mut ret_val: Option<i32> = None;
            if !unfinished && let Some(idx) = args_str.rfind(" = ") {
                let ret_str = &args_str[idx + 3..].trim();
                ret_val = ret_str.parse::<i32>().ok();
            }

            if matches!(syscall, "clone" | "clone3" | "fork" | "vfork") {
                if let Some(child_pid) = ret_val.map(|v| v as u32)
                    && child_pid > 0
                {
                    let mut to_insert = Vec::new();
                    for (&(p, fd), path) in &fd_table {
                        if p == pid {
                            to_insert.push((child_pid, fd, path.clone()));
                        }
                    }
                    for (c_pid, fd, path) in to_insert {
                        fd_table.insert((c_pid, fd), path);
                    }
                }
                continue;
            }

            if matches!(syscall, "dup" | "dup2" | "dup3" | "fcntl") {
                if !args_str.contains("F_DUPFD") && syscall == "fcntl" {
                    continue;
                }
                if let Some(old_fd) = extract_first_arg_fd(args_str) {
                    if unfinished {
                        pending_dup_args.insert(pid, old_fd);
                    } else if let Some(new_fd) = ret_val
                        && new_fd >= 0
                        && let Some(path) = fd_table.get(&(pid, old_fd)).cloned()
                    {
                        fd_table.insert((pid, new_fd), path);
                    }
                }
                continue;
            }

            // Extract all dirfds and strings
            let mut dirfds = Vec::new();
            let mut extracted_paths = Vec::new();

            let mut i = 0;
            while i < args_str.len() {
                if let Some(start_quote) = args_str[i..].find('"') {
                    let start_quote = i + start_quote;
                    let before_str = &args_str[i..start_quote];
                    // Parse any dirfds before this string
                    for token in before_str.split(',') {
                        let t = token.trim();
                        if !t.is_empty() && t != "AT_FDCWD" && t != "-100" {
                            if let Ok(fd) = t.parse::<i32>() {
                                dirfds.push(Some(fd));
                            } else {
                                dirfds.push(None);
                            }
                        } else if t == "AT_FDCWD" {
                            dirfds.push(None); // AT_FDCWD handled natively by None fallback
                        }
                    }

                    let mut end_quote = None;
                    let mut escaped = false;
                    for (j, c) in args_str[start_quote + 1..].char_indices() {
                        if escaped {
                            escaped = false;
                        } else if c == '\\' {
                            escaped = true;
                        } else if c == '"' {
                            end_quote = Some(start_quote + 1 + j);
                            break;
                        }
                    }

                    if let Some(end_idx) = end_quote {
                        let raw_str = &args_str[start_quote + 1..end_idx];
                        let unescaped_bytes = unescape_strace_string(raw_str);
                        extracted_paths.push(String::from_utf8_lossy(&unescaped_bytes).to_string());
                        i = end_idx + 1;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }

            // Align dirfds to extracted_paths depending on the syscall
            let mut aligned = Vec::new();
            if matches!(syscall, "openat" | "openat64" | "openat2") {
                let dfd = dirfds.first().copied().flatten();
                if let Some(p) = extracted_paths.first() {
                    aligned.push((dfd, p.clone()));
                }
            } else if syscall == "symlinkat" {
                // symlinkat(target, newdirfd, linkpath)
                let dfd = dirfds.first().copied().flatten();
                if let Some(p1) = extracted_paths.first() {
                    aligned.push((None, p1.clone())); // target doesn't use newdirfd
                }
                if let Some(p2) = extracted_paths.get(1) {
                    aligned.push((dfd, p2.clone()));
                }
            } else if syscall == "linkat" {
                // linkat(olddirfd, oldpath, newdirfd, newpath, flags)
                let old_dfd = dirfds.first().copied().flatten();
                let new_dfd = dirfds.get(1).copied().flatten();
                if let Some(p1) = extracted_paths.first() {
                    aligned.push((old_dfd, p1.clone()));
                }
                if let Some(p2) = extracted_paths.get(1) {
                    aligned.push((new_dfd, p2.clone()));
                }
            } else {
                // open, link, symlink
                for p in extracted_paths.iter() {
                    aligned.push((None, p.clone()));
                }
            }

            for (dirfd, mut path) in aligned {
                if let Some(caps) = proc_fd_re.captures(&path) {
                    if let Ok(fd) = caps.name("fd").unwrap().as_str().parse::<i32>() {
                        let proc_rest = caps.name("rest").unwrap().as_str();
                        if let Some(parent) = fd_table.get(&(pid, fd)) {
                            let clean_rest = proc_rest.strip_prefix('/').unwrap_or(proc_rest);
                            if parent.ends_with('/') {
                                path = format!("{}{}", parent, clean_rest);
                            } else {
                                path = format!("{}/{}", parent, clean_rest);
                            }
                        }
                    }
                } else if !path.starts_with('/')
                    && !path.starts_with('.')
                    && let Some(dfd) = dirfd
                    && let Some(parent) = fd_table.get(&(pid, dfd))
                {
                    if parent.ends_with('/') {
                        path = format!("{}{}", parent, path);
                    } else {
                        path = format!("{}/{}", parent, path);
                    }
                }

                path = lexical_clean_path(&path);

                if is_sensitive_file_read(&path) {
                    reads.insert(path.clone());
                }

                if matches!(syscall, "open" | "openat" | "openat64" | "openat2") {
                    if unfinished {
                        pending_syscalls.insert(pid, path);
                    } else if let Some(fd) = ret_val
                        && fd >= 0
                    {
                        fd_table.insert((pid, fd), path);
                    }
                }
            }
        }
    }
    reads
}
fn find_new_items(current: &HashSet<String>, baseline: &HashSet<String>) -> Vec<String> {
    let mut out: Vec<String> = current.difference(baseline).cloned().collect();
    out.sort();
    out
}

fn find_new_sensitive_reads(current: &HashSet<String>, baseline: &HashSet<String>) -> Vec<String> {
    find_new_items(current, baseline)
}

fn filter_allowlisted_sensitive_reads(
    package_name: &str,
    reads: Vec<String>,
    allowlist_map: &HashMap<String, HashSet<String>>,
) -> (Vec<String>, Vec<String>) {
    let empty_set = HashSet::new();
    let allowlist: HashSet<&str> = allowlist_map
        .get(package_name)
        .unwrap_or(&empty_set)
        .iter()
        .map(|s| s.as_str())
        .collect();

    reads.into_iter().partition(|read| {
        !allowlist.iter().copied().any(|allowed| {
            if let Some(stripped) = allowed.strip_prefix('*') {
                read == stripped || read.ends_with(&format!("/{}", stripped))
            } else {
                read == allowed
            }
        })
    })
}

fn find_new_git_clone_signatures(
    current: &HashSet<String>,
    baseline: &HashSet<String>,
) -> Vec<String> {
    find_new_items(current, baseline)
}

/// Signatures present in the current version but absent from every baseline.
fn find_new_process_exec_signatures(
    current: &HashSet<String>,
    baseline: &HashSet<String>,
) -> Vec<String> {
    find_new_items(current, baseline)
}

/// Splits process-execution signatures into (blocked, allowlisted). An entry is
/// allowlisted if the policy lists either the exact signature (`bun|run|build`)
/// or just the executable basename (`bun`), both compared case-insensitively.
fn filter_allowlisted_process_exec_signatures(
    package_name: &str,
    signatures: Vec<String>,
    process_exec_allowlist: &HashMap<String, HashSet<String>>,
) -> (Vec<String>, Vec<String>) {
    let empty_set = HashSet::new();
    let normalized_allowlist: HashSet<&str> = process_exec_allowlist
        .get(package_name)
        .unwrap_or(&empty_set)
        .iter()
        .map(|s| s.as_str())
        .collect();

    signatures.into_iter().partition(|signature| {
        let lower = signature.to_ascii_lowercase();
        let exe = lower.split('|').next().unwrap_or("");
        !normalized_allowlist.contains(lower.as_str()) && !normalized_allowlist.contains(exe)
    })
}

/// Splits artifact findings into (blocked, allowlisted). An entry is
/// allowlisted if the policy lists either the exact finding string
/// (e.g. `binary|/path|ELF...`) or just the `type|path` prefix
/// (e.g. `binary|/path`), so changes in the trailing type/size/content column
/// do not break the allowlist.
fn filter_allowlisted_artifact_findings(
    package_name: &str,
    findings: Vec<String>,
    artifact_allowlist: &HashMap<String, HashSet<String>>,
) -> (Vec<String>, Vec<String>) {
    let empty_set = HashSet::new();
    let normalized_allowlist: HashSet<&str> = artifact_allowlist
        .get(package_name)
        .unwrap_or(&empty_set)
        .iter()
        .map(|s| s.as_str())
        .collect();

    findings.into_iter().partition(|finding| {
        let prefix = {
            let parts: Vec<&str> = finding.splitn(3, '|').collect();
            if parts.len() >= 2 {
                format!("{}|{}", parts[0], parts[1])
            } else {
                finding.clone()
            }
        };
        !normalized_allowlist.contains(finding.as_str())
            && !normalized_allowlist.contains(prefix.as_str())
    })
}

fn filter_allowlisted_git_clone_signatures(
    package_name: &str,
    signatures: Vec<String>,
    git_clone_allowlist: &HashMap<String, HashSet<String>>,
) -> (Vec<String>, Vec<String>) {
    let empty_set = HashSet::new();
    let normalized_allowlist: HashSet<&str> = git_clone_allowlist
        .get(package_name)
        .unwrap_or(&empty_set)
        .iter()
        .map(|s| s.as_str())
        .collect();

    signatures.into_iter().partition(|signature| {
        let target = signature
            .split('|')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();

        target.is_empty() || !normalized_allowlist.contains(target.as_str())
    })
}

fn select_effective_baselines(
    current: &str,
    fetched_baselines: Vec<String>,
    baseline_override: Option<&BaselineOverrides>,
    baseline_count: usize,
) -> (Vec<String>, bool) {
    if baseline_count == 0 {
        return (Vec::new(), false);
    }

    let mut baselines = fetched_baselines;

    let mut self_ref = false;
    if let Some((override_m1, override_m2)) = baseline_override {
        if override_m1.as_deref() == Some(current) || override_m2.as_deref() == Some(current) {
            self_ref = true;
        }

        let mut merged = Vec::new();
        if let Some(v) = override_m1.clone()
            && v != *current
        {
            merged.push(v);
        }
        if let Some(v) = override_m2.clone()
            && !merged.contains(&v)
            && v != *current
        {
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

    (baselines, self_ref)
}

fn select_age_eligible_baselines(
    candidates_newest_first: Vec<String>,
    published_at: &HashMap<String, DateTime<Utc>>,
    cutoff: DateTime<Utc>,
    baseline_count: usize,
) -> Vec<String> {
    candidates_newest_first
        .into_iter()
        .filter(|version| published_at.get(version).is_some_and(|ts| *ts <= cutoff))
        .take(baseline_count)
        .collect()
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

fn burst_policy_warning(
    package: &str,
    releases_in_window: usize,
    release_burst_threshold: Option<usize>,
    release_burst_window_hours: usize,
) -> Option<String> {
    let triggered = match release_burst_threshold {
        Some(threshold) if threshold > 0 => releases_in_window >= threshold,
        _ => false,
    };
    if !triggered {
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
            package, age_days, required_days
        ));
    }

    None
}

fn warn_and_block(
    results: &mut HashMap<String, ScanReport>,
    key: &str,
    resolved_version: &str,
    warning_type: &str,
    detail_line: &str,
    extra_help: Option<&str>,
) {
    println!("\n❌ [gyrseek] CRITICAL WARNING: {} flagged!", warning_type);
    println!("{}", detail_line);
    if let Some(help) = extra_help {
        println!("{}", help);
    }
    let entry = results
        .entry(key.to_string())
        .or_insert_with(|| ScanReport {
            allowed: false,
            resolved_version: resolved_version.to_string(),
            blocked_reasons: vec![],
        });
    entry.allowed = false;
    entry.blocked_reasons.push(warning_type.to_string());
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
        // Internal packages are skipped before any network call: they live on a
        // private index gyrseek can't query, so a history fetch would 404 and
        // every endpoint would look "new" against an empty baseline. Allow them
        // through unscanned, pinned to whatever version was requested.
        if policy.internal_package_exemptions.contains(pkg_name) {
            println!(
                "⏭️ [gyrseek] Package '{}' is listed in internal_package_exemptions; skipping scan (private/first-party index).",
                pkg_name
            );
            results.insert(
                format!("{}|{}", pkg_name, tgt_version),
                ScanReport {
                    allowed: true,
                    resolved_version: tgt_version.clone(),
                    blocked_reasons: vec![],
                },
            );
            continue;
        }

        let min_baseline_age_hours = policy
            .min_baseline_age_hours_by_package
            .get(pkg_name)
            .copied()
            .unwrap_or(DEFAULT_MIN_BASELINE_AGE_HOURS);

        let fetch_count = policy.baseline_count.max(2);
        let now = Utc::now();
        let history = fetch_history_with_baselines(
            manager,
            pkg_name,
            tgt_version,
            fetch_count,
            min_baseline_age_hours,
            policy.release_burst_window_hours as i64,
            now,
        )
        .await;

        let baseline_overrides = policy.baseline_overrides.get(pkg_name);

        let (override_warnings, filtered_overrides) = if history.published_at.is_empty() {
            let mut warnings = Vec::new();
            let mut filtered = None;
            #[cfg(any(debug_assertions, test))]
            let is_test_env = !active_test_env_vars().is_empty();
            #[cfg(not(any(debug_assertions, test)))]
            let is_test_env = false;

            if is_test_env {
                filtered = baseline_overrides.cloned();
            } else if baseline_overrides.is_some() {
                warnings.push(format!(
                    "⚠️ [gyrseek] Registry fetch failed (empty publish times) for '{}'; discarding baseline overrides securely.",
                    pkg_name
                ));
            }
            (warnings, filtered)
        } else {
            check_override_ages(pkg_name, baseline_overrides, &history.published_at, now)
        };
        for w in &override_warnings {
            println!("{}", w);
        }

        if let Some(warning) = minimum_release_age_policy_warning(
            pkg_name,
            history.current_release_age_days,
            policy.minimum_release_age_package,
        ) {
            println!("{}", warning);
            println!("Aborting host operation securely.");
            results.insert(
                format!("{}|{}", pkg_name, tgt_version),
                ScanReport {
                    allowed: false,
                    resolved_version: history.v_curr.clone(),
                    blocked_reasons: vec!["minimum_release_age_package".to_string()],
                },
            );
            continue;
        }

        if let Some(warning) = burst_policy_warning(
            pkg_name,
            history.releases_last_24h,
            policy.release_burst_threshold,
            policy.release_burst_window_hours,
        ) {
            println!("{}", warning);
            println!("Aborting host operation securely.");
            results.insert(
                format!("{}|{}", pkg_name, tgt_version),
                ScanReport {
                    allowed: false,
                    resolved_version: history.v_curr.clone(),
                    blocked_reasons: vec!["burst_policy".to_string()],
                },
            );
            continue;
        }

        let (baselines, self_ref) = select_effective_baselines(
            &history.v_curr,
            history.fetched_baselines,
            filtered_overrides.as_ref(),
            policy.baseline_count,
        );

        let (new_package_exempt, exemption_msgs) = exemption_behavior(
            policy
                .new_package_exemptions
                .get(pkg_name)
                .map(String::as_str),
            &history.v_curr,
            baselines.len(),
            policy.baseline_count,
            pkg_name,
        );
        for msg in &exemption_msgs {
            println!("{}", msg);
        }

        if baselines.len() < policy.baseline_count && !new_package_exempt {
            println!(
                "❌ [gyrseek] Registry does not contain enough historical versions for '{}' to satisfy baseline_count={} (found {}). Failing closed.",
                pkg_name,
                policy.baseline_count,
                baselines.len()
            );
            println!("Aborting host operation securely.");
            results.insert(
                format!("{}|{}", pkg_name, tgt_version),
                ScanReport {
                    allowed: false,
                    resolved_version: history.v_curr.clone(),
                    blocked_reasons: vec!["insufficient_baselines".to_string()],
                },
            );
            continue;
        }

        if self_ref {
            println!(
                "⚠️ [gyrseek] Baseline override for '{}' equals the version being scanned; ignoring (if not, it would silently disable all anomaly detection); one fewer baseline compared",
                pkg_name
            );
        }
        if matches!(filtered_overrides, Some((Some(_), _)) | Some((_, Some(_)))) {
            println!(
                "ℹ️ [gyrseek] Applying baseline override(s) for '{}': baseline set={:?}",
                pkg_name, baselines
            );
        }

        println!(
            "🛡️ [gyrseek] Comparing versions for '{}': current={} baselines={:?} (min_baseline_age_hours={})",
            pkg_name, history.v_curr, baselines, min_baseline_age_hours
        );

        plans.push(VersionPlan {
            package: pkg_name.clone(),
            target_version: tgt_version.clone(),
            current: history.v_curr,
            baselines,
            baseline_threshold: policy.baseline_count,
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
                println!(
                    "❌ [gyrseek] Sandbox execution failed for '{}': {}",
                    plan.package, e
                );
                results.insert(
                    format!("{}|{}", plan.package, plan.target_version),
                    ScanReport {
                        allowed: false,
                        resolved_version: plan.current.clone(),
                        blocked_reasons: vec!["sandbox_execution_failed".to_string()],
                    },
                );
            }
            return results;
        }
    };

    for plan in plans {
        let key = format!("{}|{}", plan.package, plan.target_version);
        let resolved_version = plan.current.clone();
        let blocked = |results: &mut HashMap<String, ScanReport>, key: String| {
            let entry = results.entry(key).or_insert(ScanReport {
                allowed: false,
                resolved_version: resolved_version.clone(),
                blocked_reasons: vec![],
            });
            entry.allowed = false;
            entry
                .blocked_reasons
                .push("sandbox_trace_missing".to_string());
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
        let artifact_curr = current_signals.artifact_findings.clone();
        let sensitive_curr = current_signals.sensitive_file_reads;
        let dns_curr = current_signals.dns_map.clone();

        let mut baseline_ips = HashSet::new();
        let mut baseline_git_clone_signatures = HashSet::new();
        let mut baseline_process_exec_signatures = HashSet::new();
        let mut baseline_artifact_findings = HashSet::new();
        let mut baseline_sensitive_reads = HashSet::new();
        let mut baseline_dns_domains = HashSet::new();
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
                    baseline_artifact_findings.extend(found.artifact_findings.iter().cloned());
                    baseline_sensitive_reads.extend(found.sensitive_file_reads.iter().cloned());
                    baseline_dns_domains.extend(found.dns_map.keys().cloned());
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

        if plan.new_package_exempt && plan.baselines.len() < plan.baseline_threshold {
            println!(
                "⚠️ [gyrseek] New package exemption applied for '{}': only {} eligible baseline version(s) available (<{}). Skipping anomaly block for now.",
                plan.package,
                plan.baselines.len(),
                plan.baseline_threshold
            );
            results.insert(
                key,
                ScanReport {
                    allowed: true,
                    resolved_version,
                    blocked_reasons: vec![],
                },
            );
            continue;
        }

        let new_process_exec_signatures =
            find_new_process_exec_signatures(&proc_curr, &baseline_process_exec_signatures);
        let (new_process_exec_signatures, allowlisted_process_exec_signatures) =
            filter_allowlisted_process_exec_signatures(
                &plan.package,
                new_process_exec_signatures,
                &policy.process_exec_allowlist,
            );

        if !allowlisted_process_exec_signatures.is_empty() {
            println!(
                "ℹ️ [gyrseek] process_exec_allowlist ignored new process execution behavior for '{}': {:?}",
                plan.package, allowlisted_process_exec_signatures
            );
        }

        let mut package_blocked = false;

        if !new_process_exec_signatures.is_empty() {
            let baseline_label = if plan.baselines.is_empty() {
                "n/a".to_string()
            } else {
                plan.baselines.join(", ")
            };

            warn_and_block(
                &mut results,
                &key,
                &resolved_version,
                "process_exec_anomaly",
                &format!(
                    "Package '{}', version '{}' introduced new process execution not seen in baseline versions ({}): {:?}",
                    plan.package, plan.current, baseline_label, new_process_exec_signatures
                ),
                Some(
                    "This matches the Shai-Hulud class of attack (download a runtime like Bun and execute a hidden payload).",
                ),
            );
            package_blocked = true;
        }

        let new_sensitive_reads =
            find_new_sensitive_reads(&sensitive_curr, &baseline_sensitive_reads);
        let (blocked_sensitive_reads, _allowed_sensitive_reads) =
            filter_allowlisted_sensitive_reads(
                &plan.package,
                new_sensitive_reads,
                &policy.sensitive_file_access_allowlist,
            );

        if !blocked_sensitive_reads.is_empty() {
            let baseline_label = if plan.baselines.is_empty() {
                "n/a".to_string()
            } else {
                plan.baselines.join(", ")
            };

            warn_and_block(
                &mut results,
                &key,
                &resolved_version,
                "sensitive_file_read_anomaly",
                &format!(
                    "Package '{}', version '{}' attempted to access sensitive file(s) not seen in baseline versions ({}): {:?}",
                    plan.package, plan.current, baseline_label, blocked_sensitive_reads
                ),
                Some("This indicates an attempt to steal credentials or configuration files."),
            );
            package_blocked = true;
        }

        // Post-install artifact check — suspicious .pth files with executable
        // content, unexpected runtime binaries, and other file-level IoCs that
        // are identified by the in-container artifact scan (written to disk
        // during install, captured before the container exits).
        let new_artifact_findings = artifact_curr
            .difference(&baseline_artifact_findings)
            .cloned()
            .collect::<Vec<_>>();
        let (new_artifact_findings, allowlisted_artifact_findings) =
            filter_allowlisted_artifact_findings(
                &plan.package,
                new_artifact_findings,
                &policy.artifact_allowlist,
            );

        if !allowlisted_artifact_findings.is_empty() {
            println!(
                "ℹ️ [gyrseek] artifact_allowlist ignored new artifact finding(s) for '{}': {:?}",
                plan.package, allowlisted_artifact_findings
            );
        }

        if !new_artifact_findings.is_empty() {
            let baseline_label = if plan.baselines.is_empty() {
                "n/a".to_string()
            } else {
                plan.baselines.join(", ")
            };

            warn_and_block(
                &mut results,
                &key,
                &resolved_version,
                "Suspicious artifact(s) discovered after install",
                &format!(
                    "Package '{}', version '{}' introduced new suspicious file artifact(s) not seen in baseline versions ({}): {:?}",
                    plan.package, plan.current, baseline_label, new_artifact_findings
                ),
                Some(
                    "This may indicate a .pth file with executable content or an unexpected runtime binary.",
                ),
            );
            package_blocked = true;
        }

        let new_git_clone_signatures =
            find_new_git_clone_signatures(&git_curr, &baseline_git_clone_signatures);
        let (new_git_clone_signatures, allowlisted_git_clone_signatures) =
            filter_allowlisted_git_clone_signatures(
                &plan.package,
                new_git_clone_signatures,
                &policy.git_clone_allowlist,
            );

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

            warn_and_block(
                &mut results,
                &key,
                &resolved_version,
                "git_clone_anomaly",
                &format!(
                    "Package '{}', version '{}' introduced new git clone behavior not seen in baseline versions ({}): {:?}",
                    plan.package, plan.current, baseline_label, new_git_clone_signatures
                ),
                None,
            );
            package_blocked = true;
        }

        let new_connections = find_new_connections_domain_aware(
            &ips_curr,
            &baseline_ips,
            reverse_dns_domain,
            &dns_curr,
            &baseline_dns_domains,
            |d| lookup_host(d).ok(),
        );
        let (new_connections, allowlisted_connections) = filter_allowlisted_new_connections(
            &plan.package,
            new_connections,
            &policy.ip_allowlist,
        );
        let (new_connections, allowlisted_domain_connections) =
            filter_domain_allowlisted_new_connections_with(
                &plan.package,
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

            let enriched: Vec<String> = new_connections
                .iter()
                .map(|ip| match reverse_dns_domain(ip) {
                    Some(d) => format!("{} -> {}", ip, d),
                    None => ip.clone(),
                })
                .collect();

            warn_and_block(
                &mut results,
                &key,
                &resolved_version,
                "network_anomaly",
                &format!(
                    "Package '{}', version '{}' contacted new endpoints not seen in baseline versions ({}): {:?}",
                    plan.package, plan.current, baseline_label, enriched
                ),
                None,
            );
            package_blocked = true;
        }

        if package_blocked {
            continue;
        }

        results.insert(
            key,
            ScanReport {
                allowed: true,
                resolved_version,
                blocked_reasons: vec![],
            },
        );
    }

    results
}

pub(crate) async fn scan_package_versions(
    runner: &dyn SandboxRunner,
    manager: &str,
    pkg_name: &str,
    tgt_version: &str,
    policy: &PolicyConfig,
) -> ScanReport {
    let targets = vec![(pkg_name.to_string(), tgt_version.to_string())];
    let mut outcome = scan_packages_versions(runner, manager, &targets, policy).await;
    outcome
        .remove(&format!("{}|{}", pkg_name, tgt_version))
        .unwrap_or_else(|| ScanReport {
            allowed: false,
            resolved_version: tgt_version.to_string(),
            blocked_reasons: vec!["scan_failed".to_string()],
        })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use chrono::{TimeZone, Utc};

    use super::{
        PolicyConfig, burst_policy_warning, classify_inventory_lines, compare_version_strings,
        count_releases_in_window, decode_dns_name, extract_artifact_findings,
        extract_connection_ips, extract_dns_map, extract_process_exec_signatures,
        extract_sensitive_file_reads, filter_allowlisted_artifact_findings,
        filter_allowlisted_git_clone_signatures, filter_allowlisted_new_connections,
        filter_allowlisted_process_exec_signatures, filter_allowlisted_sensitive_reads,
        filter_domain_allowlisted_new_connections_with, find_new_connections_domain_aware,
        find_new_process_exec_signatures, find_new_sensitive_reads, forward_confirmed_hostname,
        is_harness_command, is_sandbox_local_ip, is_sensitive_file_read,
        minimum_release_age_policy_warning, normalize_ip_string, npm_published_times,
        parse_dns_response, reverse_dns_domain, scan_packages_versions,
        select_age_eligible_baselines, select_effective_baselines, sort_versions_ascending,
        strip_artifact_section, unescape_strace_string,
    };

    #[test]
    fn test_is_sensitive_file_read() {
        assert!(is_sensitive_file_read("/home/user/.aws/credentials"));
        assert!(is_sensitive_file_read(".aws/credentials"));
        assert!(is_sensitive_file_read("/root/.ssh/id_rsa"));
        assert!(is_sensitive_file_read(".env"));
        assert!(is_sensitive_file_read("/app/.env"));
        assert!(is_sensitive_file_read("/etc/passwd"));
        assert!(is_sensitive_file_read(
            "/home/user/.config/gcloud/application_default_credentials.json"
        ));
        assert!(!is_sensitive_file_read(
            "/var/lib/malware/.config/gcloud/tools/steal"
        ));
        assert!(is_sensitive_file_read("/proc/self/environ"));
        assert!(is_sensitive_file_read("/proc/123/environ"));
        assert!(is_sensitive_file_read("/home/user/.git-credentials"));
        assert!(is_sensitive_file_read("/home/user/.cargo/credentials"));
        assert!(is_sensitive_file_read("/home/user/.gem/credentials"));
        assert!(is_sensitive_file_read("/home/user/.m2/settings.xml"));
        assert!(is_sensitive_file_read(
            "/home/user/.config/openstack/clouds.yaml"
        ));
        assert!(is_sensitive_file_read(
            "/home/user/.azure/accessTokens.json"
        ));
        assert!(is_sensitive_file_read(
            "/home/user/.gnupg/private-keys-v1.d/foo.key"
        ));
        assert!(!is_sensitive_file_read("/usr/bin/node"));
        assert!(!is_sensitive_file_read("index.js"));
        assert!(!is_sensitive_file_read(".env_backup"));
        assert!(!is_sensitive_file_read(".ENV"));
        assert!(!is_sensitive_file_read(".aws/credentials.tmp"));
        assert!(!is_sensitive_file_read("/etc/./passwd"));
        assert!(is_sensitive_file_read("/proc/1/root/etc/passwd"));
        assert!(is_sensitive_file_read("/etc/shadow"));
    }

    #[test]
    fn test_extract_sensitive_file_reads() {
        let trace = r#"
openat(AT_FDCWD, "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64", O_RDONLY|O_CLOEXEC) = 3
open("\x2e\x65\x6e\x76", O_RDONLY) = 4
openat(AT_FDCWD, "\x2f\x6f\x70\x74\x2f\x61\x70\x70\x2f\x69\x6e\x64\x65\x78\x2e\x6a\x73", O_RDONLY) = 5
"#;
        let reads = extract_sensitive_file_reads(trace);
        println!("READS: {:?}", reads);
        assert!(reads.contains("/etc/passwd"));
        assert!(reads.contains(".env"));
        assert!(!reads.contains("/opt/app/index.js"));
        assert_eq!(reads.len(), 2);
    }

    #[test]
    fn test_extract_sensitive_file_reads_edge_cases() {
        let trace = r#"
[pid 1234] openat(AT_FDCWD, "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64", O_RDONLY|O_CLOEXEC) = 3
1234  open("\x2e\x65\x6e\x76", O_RDONLY) = 4
[pid 5678] <... openat resumed> "\x2f\x6f\x70\x74\x2f\x61\x70\x70\x2f\x69\x6e\x64\x65\x78\x2e\x6a\x73", O_RDONLY) = 5
[pid 1234] openat(AT_FDCWD, "\x2f\x72\x6f\x6f\x74\x2f\x2e\x61\x77\x73", O_RDONLY <unfinished ...>
[pid 5678] close(3) = 0
[pid 1234] <... openat resumed> ) = 5
[pid 1234] openat(5, "credentials", O_RDONLY) = 6
[pid 9999] symlink("/root/.aws/credentials", "util.js") = 0
[pid 1111] openat64(-100, "/etc/shadow", O_RDONLY) = 7
[pid 2222] openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 8
"#;
        let reads = extract_sensitive_file_reads(trace);
        println!("READS: {:?}", reads);
        assert!(reads.contains("/etc/passwd"));
        assert!(reads.contains(".env"));
        assert!(reads.contains("/root/.aws/credentials"));
        assert!(reads.contains("/etc/shadow"));
        assert!(!reads.contains("/opt/app/index.js"));
        assert_eq!(reads.len(), 4);

        assert_eq!(extract_sensitive_file_reads("").len(), 0);
        assert_eq!(extract_sensitive_file_reads("   \n \t  \n").len(), 0);
        assert_eq!(
            extract_sensitive_file_reads("this is not strace output\njust random text() = 0").len(),
            0
        );

        let long_path = "a".repeat(10000);
        let long_trace = format!("openat(AT_FDCWD, \"/{long_path}/.env\", O_RDONLY) = 3");
        assert!(extract_sensitive_file_reads(&long_trace).contains(&format!("/{long_path}/.env")));
    }

    #[test]
    fn test_appsec_evasion_bypasses() {
        let trace = r#"
[pid 100] openat(AT_FDCWD, "/etc", O_RDONLY) = 3
[pid 100] open("/proc/self/fd/3/passwd", O_RDONLY) = 4
[pid 100] dup2(3, 7) = 7
[pid 100] openat(7, "shadow", O_RDONLY) = 8
[pid 100] clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f8) = 200
[pid 200] openat(3, "passwd", O_RDONLY) = 4
[pid 300] openat(AT_FDCWD, "../../etc/passwd", O_RDONLY) = 3
"#;
        let reads = extract_sensitive_file_reads(trace);
        println!("READS: {:?}", reads);
        assert!(reads.contains("/etc/passwd"));
        assert!(reads.contains("/etc/shadow"));
        assert!(reads.contains("../../etc/passwd"));
        assert_eq!(reads.len(), 3);
    }

    #[test]
    fn test_appsec_evasion_exhaustive_variants() {
        let trace = r#"
[pid 100] openat(AT_FDCWD, "/etc", O_RDONLY) = 3
[pid 100] fcntl(3, F_DUPFD, 10) = 10
[pid 100] openat(10, "shadow", O_RDONLY) = 11
[pid 100] dup3(3, 12, O_CLOEXEC) = 12
[pid 100] openat(12, "shadow", O_RDONLY) = 13
[pid 100] fork() = 200
[pid 200] openat(3, "passwd", O_RDONLY) = 14
[pid 100] vfork() = 300
[pid 300] openat(10, "passwd", O_RDONLY) = 15
[pid 100] clone3({flags=CLONE_PIDFD, pidfd=0x7ff}, 88) = 400
[pid 400] open("/proc/100/fd/12/passwd", O_RDONLY) = 16
[pid 100] clone( <unfinished ...>
[pid 500] openat(AT_FDCWD, "/tmp", O_RDONLY) = 3
[pid 100] <... clone resumed> child_stack=NULL) = 600
[pid 600] openat(3, "passwd", O_RDONLY) = 17
[pid 100] dup( <unfinished ...>
[pid 500] openat(3, "foo", O_RDONLY) = 4
[pid 100] <... dup resumed> 3) = 18
[pid 100] openat(18, "passwd", O_RDONLY) = 19
"#;
        let reads = extract_sensitive_file_reads(trace);
        println!("READS: {:?}", reads);
        assert!(reads.contains("/etc/passwd"));
        assert!(reads.contains("/etc/shadow"));
        // Count should be exactly 2 distinct files (passwd, shadow) accessed many times
        assert_eq!(reads.len(), 2);
    }

    #[test]
    fn test_find_new_sensitive_reads() {
        let mut baseline = std::collections::HashSet::new();
        baseline.insert("/etc/passwd".to_string());

        let mut current = std::collections::HashSet::new();
        current.insert("/etc/passwd".to_string());
        current.insert(".env".to_string());

        let new_reads = find_new_sensitive_reads(&current, &baseline);
        assert_eq!(new_reads.len(), 1);
        assert_eq!(new_reads[0], ".env");

        // Empty current
        let empty_current = std::collections::HashSet::new();
        assert_eq!(find_new_sensitive_reads(&empty_current, &baseline).len(), 0);

        // Empty baseline
        assert_eq!(find_new_sensitive_reads(&current, &empty_current).len(), 2);

        // Both empty
        assert_eq!(
            find_new_sensitive_reads(&empty_current, &empty_current).len(),
            0
        );

        // Current subset of baseline
        let mut subset_current = std::collections::HashSet::new();
        subset_current.insert("/etc/passwd".to_string());
        assert_eq!(
            find_new_sensitive_reads(&subset_current, &baseline).len(),
            0
        );

        // Duplicates are natively handled by HashSet so we just ensure behavior is clean
        let mut dup_baseline = baseline.clone();
        dup_baseline.insert("/etc/passwd".to_string()); // no-op for set
        assert_eq!(
            find_new_sensitive_reads(&subset_current, &dup_baseline).len(),
            0
        );
    }

    #[test]
    fn test_filter_allowlisted_sensitive_reads() {
        let reads = vec![
            "/etc/passwd".to_string(),
            "/home/user/.aws/credentials".to_string(),
            "/app/.env".to_string(),
            "/tmp/malicious/.env".to_string(),
        ];
        let mut allowlist = std::collections::HashSet::new();
        // exact match
        allowlist.insert("/etc/passwd".to_string());
        // wildcard suffix match
        allowlist.insert("*.env".to_string());

        let mut allowlist_map = std::collections::HashMap::new();
        allowlist_map.insert("test-pkg".to_string(), allowlist);

        let (blocked, allowed) =
            filter_allowlisted_sensitive_reads("test-pkg", reads, &allowlist_map);

        assert_eq!(blocked, vec!["/home/user/.aws/credentials".to_string()]);
        assert!(allowed.contains(&"/etc/passwd".to_string()));
        assert!(allowed.contains(&"/app/.env".to_string()));
        assert!(allowed.contains(&"/tmp/malicious/.env".to_string()));
    }

    use chrono::Duration;
    use std::cmp::Ordering;
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv6Addr};

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
    fn pnpm_versions_use_npm_semver_ordering() {
        let mut versions = vec![
            "9.0.0".to_string(),
            "10.0.0".to_string(),
            "2.0.0".to_string(),
        ];
        sort_versions_ascending("pnpm", &mut versions);
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
        assert_eq!(
            compare_version_strings("npm", "not-a-version", "1.0.0"),
            Ordering::Less
        );
        assert_eq!(
            compare_version_strings("npm", "1.0.0", "not-a-version"),
            Ordering::Greater
        );

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
sin6_addr=inet_pton(AF_INET6, "2606:2800:220:1:248:1893:25c8:1946")
"#;
        let ips = extract_connection_ips(trace);
        assert!(ips.contains("8.8.8.8"));
        assert!(ips.contains("2606:2800:220:1:248:1893:25c8:1946"));
        assert_eq!(ips.len(), 2);
    }

    // --- Sandbox-local IPs are dropped at extraction, before the baseline diff ---

    #[test]
    fn extract_connection_ips_drops_loopback_link_local_and_private() {
        let trace = r#"
sin_addr=inet_addr("8.8.8.8")
sin_addr=inet_addr("127.0.0.1")
sin_addr=inet_addr("172.17.0.2")
sin_addr=inet_addr("192.168.65.7")
sin_addr=inet_addr("10.1.2.3")
sin6_addr=inet_pton(AF_INET6, "::1")
sin6_addr=inet_pton(AF_INET6, "fe80::1")
"#;
        let ips = extract_connection_ips(trace);
        // Only the public address survives; all sandbox plumbing is filtered.
        assert_eq!(ips, ["8.8.8.8".to_string()].into_iter().collect());
    }

    #[test]
    fn extract_connection_ips_collapses_ipv4_mapped_ipv6() {
        // A Docker-bridge hit seen as IPv4-mapped IPv6 must be recognised as the
        // private IPv4 address it really is, and dropped.
        let trace = r#"sin6_addr=inet_pton(AF_INET6, "::ffff:172.17.0.2")"#;
        let ips = extract_connection_ips(trace);
        assert!(ips.is_empty());
    }

    #[test]
    fn extract_connection_ips_keeps_public_ipv4_mapped_ipv6_as_ipv4() {
        let trace = r#"sin6_addr=inet_pton(AF_INET6, "::ffff:8.8.8.8")"#;
        let ips = extract_connection_ips(trace);
        // Collapsed to its bare IPv4 form so it diffs/allowlists consistently.
        assert_eq!(ips, ["8.8.8.8".to_string()].into_iter().collect());
    }

    #[test]
    fn extract_connection_ips_keeps_cloud_metadata_endpoint() {
        // 169.254.169.254 is link-local by address but a real SSRF target, so it
        // must NOT be filtered as local noise.
        let trace = r#"sin_addr=inet_addr("169.254.169.254")"#;
        let ips = extract_connection_ips(trace);
        assert!(ips.contains("169.254.169.254"));
    }

    #[test]
    fn is_sandbox_local_ip_classification() {
        for local in [
            "127.0.0.1",
            "::1",
            "10.0.0.1",
            "172.17.0.2",
            "192.168.65.7",
            "fe80::1",
            "::ffff:172.17.0.2",
        ] {
            assert!(is_sandbox_local_ip(local), "{local} should be local");
        }
        for public in [
            "8.8.8.8",
            "151.101.0.223",
            "169.254.169.254",
            "2606:2800::1",
        ] {
            assert!(!is_sandbox_local_ip(public), "{public} should not be local");
        }
    }

    #[test]
    fn normalize_ip_string_collapses_mapped_and_preserves_others() {
        assert_eq!(normalize_ip_string("::ffff:172.17.0.2"), "172.17.0.2");
        assert_eq!(normalize_ip_string("8.8.8.8"), "8.8.8.8");
        assert_eq!(
            normalize_ip_string("2001:0db8:0000:0000:0000:0000:0000:0001"),
            "2001:db8::1"
        );
        assert_eq!(normalize_ip_string("not-an-ip"), "not-an-ip");
    }

    // --- #6 created/modified must not inflate the release-burst count ---

    #[test]
    fn npm_published_times_excludes_created_and_modified_keys() {
        let time = HashMap::from([
            (
                "created".to_string(),
                "2020-01-01T00:00:00.000Z".to_string(),
            ),
            (
                "modified".to_string(),
                "2026-01-01T00:00:00.000Z".to_string(),
            ),
            ("1.0.0".to_string(), "2026-06-01T00:00:00.000Z".to_string()),
            ("1.0.1".to_string(), "2026-06-02T00:00:00.000Z".to_string()),
        ]);
        let version_keys: HashSet<String> = ["1.0.0".to_string(), "1.0.1".to_string()]
            .into_iter()
            .collect();

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
            (
                "created".to_string(),
                "2020-01-01T00:00:00.000Z".to_string(),
            ),
            (
                "modified".to_string(),
                "2026-01-01T00:00:00.000Z".to_string(),
            ),
            (
                "9.9.9-yanked".to_string(),
                "2026-06-01T00:00:00.000Z".to_string(),
            ),
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

    // --- process-execution detection (all executables, least-privilege) ---

    #[test]
    fn extract_process_exec_captures_bun_run_with_argv() {
        // The Shai-Hulud loader downloads bun and runs the obfuscated stealer.
        let trace = r#"execve("/tmp/b/bun", ["/tmp/b/bun", "run", "_index.js"], 0x7ff) = 0"#;
        let sigs = extract_process_exec_signatures(trace);
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
        let sigs = extract_process_exec_signatures(trace);
        assert!(sigs.contains("bun|run|script[obf].js"), "got: {sigs:?}");
    }

    #[test]
    fn extract_process_exec_uses_basename_so_path_does_not_matter() {
        let a = extract_process_exec_signatures(
            r#"execve("/tmp/b/bun", ["/tmp/b/bun", "run", "x.js"], 0x7ff) = 0"#,
        );
        let b = extract_process_exec_signatures(
            r#"execve("/usr/local/bin/bun", ["bun", "run", "x.js"], 0x7ff) = 0"#,
        );
        // Both normalize to the same signature regardless of install path / argv0.
        assert_eq!(a, b);
        assert!(a.contains("bun|run|x.js"));
    }

    #[test]
    fn extract_process_exec_captures_all_executables() {
        let trace = r#"
execve("/usr/bin/node", ["node", "build.js"], 0x7ff) = 0
execve("/bin/sh", ["sh", "-c", "echo hi"], 0x7ff) = 0
execve("/usr/bin/python3", ["python3", "setup.py"], 0x7ff) = 0
"#;
        let sigs = extract_process_exec_signatures(trace);
        assert_eq!(sigs.len(), 3, "got: {sigs:?}");
        assert!(sigs.contains("node|build.js"));
        assert!(sigs.contains("sh|-c|echo hi"));
        assert!(sigs.contains("python3|setup.py"));
    }

    #[test]
    fn extract_process_exec_skips_harness_uv_pip_install() {
        // The sandbox's own install command (uv pip install) must be excluded
        // because its argv contains the package version, which would always
        // look "new" when comparing different versions.
        let trace = r#"
execve("/usr/bin/uv", ["uv", "pip", "install", "black==26.5.1", "--target", "/work", "--no-cache"], 0x7ff) = 0
execve("/usr/bin/node", ["node", "index.js"], 0x7ff) = 0
"#;
        let sigs = extract_process_exec_signatures(trace);
        assert!(!sigs.contains("uv|pip|install|black==26.5.1|--target|/work|--no-cache"));
        assert!(sigs.contains("node|index.js"));
    }

    #[test]
    fn extract_process_exec_skips_harness_python_interpreter_info() {
        let trace = r#"
execve("/usr/bin/python3.12", ["python3.12", "-I", "-B", "-c", "import sys; sys.path = ['/tmp/.tmpX'] + sys.path; from python.get_interpreter_info import main; main()"], 0x7ff) = 0
"#;
        let sigs = extract_process_exec_signatures(trace);
        assert!(
            sigs.is_empty(),
            "interpreter info should be excluded: {sigs:?}"
        );
    }

    #[test]
    fn extract_process_exec_skips_harness_env_wrapper() {
        let trace = r#"
execve("/usr/bin/env", ["env", "HOME=/work", "uv", "pip", "install", "pkg==1.0.0", "--target", "/work", "--no-cache"], 0x7ff) = 0
execve("/usr/bin/env", ["env", "HOME=/work", "npm", "install", "pkg@1.0.0", "--prefix", "/work", "--no-save"], 0x7ff) = 0
execve("/usr/bin/env", ["env", "HOME=/work", "pnpm", "add", "pkg@1.0.0", "--dir", "/work", "--lockfile=false"], 0x7ff) = 0
"#;
        let sigs = extract_process_exec_signatures(trace);
        assert!(
            sigs.is_empty(),
            "all env wrappers should be excluded: {sigs:?}"
        );
    }

    #[test]
    fn extract_process_exec_skips_harness_npm_install() {
        let trace = r#"
execve("/usr/local/bin/npm", ["npm", "install", "lodash@4.18.1", "--prefix", "/work", "--no-save"], 0x7ff) = 0
execve("/usr/local/bin/node", ["node", "/usr/local/bin/npm", "install", "lodash@4.18.1", "--prefix", "/work", "--no-save"], 0x7ff) = 0
"#;
        let sigs = extract_process_exec_signatures(trace);
        assert!(
            sigs.is_empty(),
            "npm install harness should be excluded: {sigs:?}"
        );
    }

    #[test]
    fn extract_process_exec_skips_harness_pnpm_add() {
        let trace = r#"
execve("/usr/local/bin/pnpm", ["pnpm", "add", "lodash@4.18.1", "--dir", "/work", "--lockfile=false"], 0x7ff) = 0
execve("/usr/local/bin/node", ["node", "/usr/local/bin/pnpm", "add", "lodash@4.18.1", "--dir", "/work", "--lockfile=false"], 0x7ff) = 0
"#;
        let sigs = extract_process_exec_signatures(trace);
        assert!(
            sigs.is_empty(),
            "pnpm add harness should be excluded: {sigs:?}"
        );
    }

    #[test]
    fn case_1_new_bun_is_flagged_against_clean_baseline() {
        // Baseline never ran bun; latest does -> the bun signature is "new".
        let baseline = extract_process_exec_signatures(
            r#"execve("/usr/bin/node", ["node", "index.js"], 0x7ff) = 0"#,
        );
        let current = extract_process_exec_signatures(
            r#"execve("/tmp/b/bun", ["bun", "run", "_index.js"], 0x7ff) = 0"#,
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
        );
        let current = extract_process_exec_signatures(
            r#"
execve("/usr/bin/bun", ["bun", "run", "build"], 0x7ff) = 0
execve("/tmp/b/bun", ["bun", "run", "_index.js"], 0x7ff) = 0
"#,
        );
        let new = find_new_process_exec_signatures(&current, &baseline);
        assert_eq!(new, vec!["bun|run|_index.js".to_string()]);
    }

    #[test]
    fn case_2b_changed_bun_arguments_are_flagged() {
        // Same executable, different args -> distinct signature, so it's "new".
        let baseline = extract_process_exec_signatures(
            r#"execve("/usr/bin/bun", ["bun", "run", "build"], 0x7ff) = 0"#,
        );
        let current = extract_process_exec_signatures(
            r#"execve("/usr/bin/bun", ["bun", "run", "build", "--evil-flag"], 0x7ff) = 0"#,
        );
        let new = find_new_process_exec_signatures(&current, &baseline);
        assert_eq!(new, vec!["bun|run|build|--evil-flag".to_string()]);
    }

    #[test]
    fn identical_bun_behavior_is_not_flagged() {
        let baseline = extract_process_exec_signatures(
            r#"execve("/usr/bin/bun", ["bun", "run", "build"], 0x7ff) = 0"#,
        );
        let current = baseline.clone();
        assert!(find_new_process_exec_signatures(&current, &baseline).is_empty());
    }

    #[test]
    fn process_exec_allowlist_matches_exact_signature_and_bare_executable() {
        let sigs = vec!["bun|run|build".to_string(), "deno|run|task.ts".to_string()];

        // Exact-signature allowlist clears only that one.
        let allow_exact_set: HashSet<String> = ["bun|run|build".to_string()].into_iter().collect();
        let mut allow_exact = HashMap::new();
        allow_exact.insert("test-pkg".to_string(), allow_exact_set);
        let (remaining, allowed) =
            filter_allowlisted_process_exec_signatures("test-pkg", sigs.clone(), &allow_exact);
        assert_eq!(allowed, vec!["bun|run|build".to_string()]);
        assert_eq!(remaining, vec!["deno|run|task.ts".to_string()]);

        // Bare-executable allowlist clears every invocation of that executable.
        let allow_exe_set: HashSet<String> = ["bun".to_string()].into_iter().collect();
        let mut allow_exe = HashMap::new();
        allow_exe.insert("test-pkg".to_string(), allow_exe_set);
        let (remaining, allowed) =
            filter_allowlisted_process_exec_signatures("test-pkg", sigs, &allow_exe);
        assert_eq!(allowed, vec!["bun|run|build".to_string()]);
        assert_eq!(remaining, vec!["deno|run|task.ts".to_string()]);
    }

    #[test]
    fn process_exec_allowlist_does_not_leak_across_packages() {
        let sigs = vec!["bun|run|build".to_string()];
        let allow_exact_set: HashSet<String> = ["bun|run|build".to_string()].into_iter().collect();
        let mut allow_exact = HashMap::new();
        allow_exact.insert("other-pkg".to_string(), allow_exact_set);

        // Pass "target-pkg" which has no allowlist
        let (remaining, allowed) =
            filter_allowlisted_process_exec_signatures("target-pkg", sigs.clone(), &allow_exact);
        assert!(
            allowed.is_empty(),
            "Allowlist must not leak across packages"
        );
        assert_eq!(remaining, sigs);
    }

    #[test]
    fn artifact_allowlist_matches_exact_finding_and_prefix() {
        let findings = vec![
            "binary|/work/bin/tool|ELF 64-bit LSB executable".to_string(),
            "suspicious_pth|/work/helper.pth|import urllib".to_string(),
        ];

        // Exact-signature allowlist.
        let exact_set: HashSet<String> =
            ["binary|/work/bin/tool|ELF 64-bit LSB executable".to_string()]
                .into_iter()
                .collect();
        let mut exact = HashMap::new();
        exact.insert("test-pkg".to_string(), exact_set);
        let (remaining, allowed) =
            filter_allowlisted_artifact_findings("test-pkg", findings.clone(), &exact);
        assert_eq!(
            allowed,
            vec!["binary|/work/bin/tool|ELF 64-bit LSB executable"]
        );
        assert_eq!(remaining.len(), 1);
        assert!(remaining[0].starts_with("suspicious_pth"));

        // Prefix (type|path) allowlist — ignores trailing type/content column.
        let prefix_set: HashSet<String> = ["suspicious_pth|/work/helper.pth".to_string()]
            .into_iter()
            .collect();
        let mut prefix = HashMap::new();
        prefix.insert("test-pkg".to_string(), prefix_set);
        let (remaining, allowed) =
            filter_allowlisted_artifact_findings("test-pkg", findings, &prefix);
        assert_eq!(
            allowed,
            vec!["suspicious_pth|/work/helper.pth|import urllib"]
        );
        assert_eq!(remaining.len(), 1);
        assert!(remaining[0].starts_with("binary"));
    }

    #[test]
    fn artifact_allowlist_does_not_leak_across_packages() {
        let findings = vec!["binary|/work/bin/tool|ELF".to_string()];
        let exact_set: HashSet<String> = ["binary|/work/bin/tool|ELF".to_string()]
            .into_iter()
            .collect();
        let mut allow_exact = HashMap::new();
        allow_exact.insert("other-pkg".to_string(), exact_set);

        let (remaining, allowed) =
            filter_allowlisted_artifact_findings("target-pkg", findings.clone(), &allow_exact);
        assert!(
            allowed.is_empty(),
            "Allowlist must not leak across packages"
        );
        assert_eq!(remaining, findings);
    }

    #[test]
    fn sensitive_reads_allowlist_does_not_leak_across_packages() {
        let path = "/home/user/.aws/credentials".to_string();
        let mut allowlist: HashMap<String, HashSet<String>> = HashMap::new();
        allowlist.insert("aws-sdk".to_string(), [path.clone()].into_iter().collect());
        let (remaining, allowed) =
            filter_allowlisted_sensitive_reads("boto3", vec![path.clone()], &allowlist);
        assert!(
            allowed.is_empty(),
            "sensitive_reads allowlist must not leak across packages"
        );
        assert_eq!(remaining, vec![path]);
    }

    #[test]
    fn baseline_count_limits_fetched_baselines_without_overrides() {
        let (out, _) = select_effective_baselines(
            "3.0.0",
            vec![
                "2.9.0".to_string(),
                "2.8.0".to_string(),
                "2.7.0".to_string(),
            ],
            None,
            2,
        );
        assert_eq!(out, vec!["2.9.0".to_string(), "2.8.0".to_string()]);
    }

    #[test]
    fn overrides_take_priority_and_fill_remaining_slots() {
        let override_pair = (Some("2.5.0".to_string()), None);
        let (out, _) = select_effective_baselines(
            "3.0.0",
            vec![
                "2.9.0".to_string(),
                "2.8.0".to_string(),
                "2.7.0".to_string(),
            ],
            Some(&override_pair),
            3,
        );
        assert_eq!(
            out,
            vec![
                "2.5.0".to_string(),
                "2.9.0".to_string(),
                "2.8.0".to_string()
            ]
        );
    }

    #[test]
    fn duplicate_override_versions_are_deduped_and_truncated() {
        let override_pair = (Some("2.9.0".to_string()), Some("2.9.0".to_string()));
        let (out, _) = select_effective_baselines(
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
        let candidates = vec![
            "2.9.0".to_string(),
            "2.8.0".to_string(),
            "2.7.0".to_string(),
        ];
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
    fn baseline_count_zero_returns_no_effective_baselines() {
        let (out, _) = select_effective_baselines(
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
        let (out, _) = select_effective_baselines(
            "3.0.0",
            vec![
                "2.9.0".to_string(),
                "2.8.0".to_string(),
                "2.7.0".to_string(),
            ],
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
    fn burst_policy_emits_warning_when_triggered() {
        let warning = burst_policy_warning("requests", 3, Some(3), 12);
        assert!(warning.is_some());
        let text = warning.unwrap_or_default();
        assert!(text.contains("Release burst threshold triggered"));
        assert!(text.contains("requests"));
        assert!(text.contains("last 12h"));
    }

    #[test]
    fn burst_policy_no_warning_below_threshold_or_disabled() {
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
        let ips_curr: HashSet<String> = ["1.1.1.1", "8.8.8.8"]
            .into_iter()
            .map(String::from)
            .collect();
        let baseline_ips: HashSet<String> = ["1.1.1.1"].into_iter().map(String::from).collect();
        let mut new = find_new_connections_domain_aware(
            &ips_curr,
            &baseline_ips,
            |_| None,
            &HashMap::new(),
            &HashSet::new(),
            |_| None,
        );
        new.sort();
        assert_eq!(new, vec!["8.8.8.8".to_string()]);
    }

    #[test]
    fn no_anomaly_when_connections_match_baseline() {
        let ips_curr: HashSet<String> = ["1.1.1.1"].into_iter().map(String::from).collect();
        let baseline_ips: HashSet<String> = ["1.1.1.1", "9.9.9.9"]
            .into_iter()
            .map(String::from)
            .collect();
        assert!(
            find_new_connections_domain_aware(
                &ips_curr,
                &baseline_ips,
                |_| None,
                &HashMap::new(),
                &HashSet::new(),
                |_| None
            )
            .is_empty()
        );
    }

    #[test]
    fn ip_allowlist_filters_new_ips_before_blocking() {
        let new_connections = vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()];
        let ip_allowlist: HashMap<String, HashSet<String>> = [(
            "*".to_string(),
            ["1.1.1.1"].into_iter().map(String::from).collect(),
        )]
        .into_iter()
        .collect();
        let (mut remaining, mut allowlisted) =
            filter_allowlisted_new_connections("pkg", new_connections, &ip_allowlist);
        remaining.sort();
        allowlisted.sort();
        assert_eq!(remaining, vec!["8.8.8.8".to_string()]);
        assert_eq!(allowlisted, vec!["1.1.1.1".to_string()]);
    }

    #[test]
    fn domain_allowlist_filters_resolved_domains_before_blocking() {
        let new_connections = vec!["8.8.8.8".to_string(), "5.5.5.5".to_string()];
        let domain_allowlist: HashMap<String, HashSet<String>> = [(
            "*".to_string(),
            ["example.net"].into_iter().map(String::from).collect(),
        )]
        .into_iter()
        .collect();
        let resolver = |ip: &str| match ip {
            "8.8.8.8" => Some("cdn.example.net".to_string()),
            "5.5.5.5" => Some("other.net".to_string()),
            _ => None,
        };
        let (mut remaining, mut allowlisted) = filter_domain_allowlisted_new_connections_with(
            "pkg",
            new_connections,
            &domain_allowlist,
            resolver,
        );
        remaining.sort();
        allowlisted.sort();
        assert_eq!(remaining, vec!["5.5.5.5".to_string()]);
        assert_eq!(allowlisted, vec!["8.8.8.8 -> cdn.example.net".to_string()]);
    }

    #[test]
    fn domain_allowlist_does_not_filter_when_lookup_fails() {
        let new_connections = vec!["8.8.8.8".to_string()];
        let domain_allowlist: HashMap<String, HashSet<String>> = [(
            "*".to_string(),
            ["example.net"].into_iter().map(String::from).collect(),
        )]
        .into_iter()
        .collect();
        let (remaining, allowlisted) = filter_domain_allowlisted_new_connections_with(
            "pkg",
            new_connections,
            &domain_allowlist,
            |_| None,
        );
        assert_eq!(remaining, vec!["8.8.8.8".to_string()]);
        assert!(allowlisted.is_empty());
    }

    #[test]
    fn domain_allowlist_normalization_matches_case_whitespace_and_trailing_dot() {
        // Entries are normalized at config-load time; the map must hold canonical
        // lowercase, trimmed, no-trailing-dot forms. domain_is_allowlisted compares
        // against these stored canonical forms directly (no re-allocation).
        let new_connections = vec!["8.8.8.8".to_string()];
        let domain_allowlist: HashMap<String, HashSet<String>> = [(
            "*".to_string(),
            ["example.net"].into_iter().map(String::from).collect(),
        )]
        .into_iter()
        .collect();
        let resolver = |_ip: &str| Some("CDN.Example.Net.".to_string());
        let (remaining, allowlisted) = filter_domain_allowlisted_new_connections_with(
            "pkg",
            new_connections,
            &domain_allowlist,
            resolver,
        );
        assert!(remaining.is_empty());
        assert_eq!(allowlisted, vec!["8.8.8.8 -> CDN.Example.Net.".to_string()]);
    }

    #[test]
    fn domain_aware_diff_discards_ip_when_domain_seen_in_baseline() {
        let ips_curr: HashSet<String> = ["151.101.1.54", "5.5.5.5"]
            .into_iter()
            .map(String::from)
            .collect();
        let baseline_ips: HashSet<String> = ["151.101.0.1"].into_iter().map(String::from).collect();
        let resolver = |ip: &str| match ip {
            "151.101.0.1" => Some("files.pythonhosted.org".to_string()),
            "151.101.1.54" => Some("files.pythonhosted.org".to_string()),
            "5.5.5.5" => Some("evil.example.com".to_string()),
            _ => None,
        };
        let mut new = find_new_connections_domain_aware(
            &ips_curr,
            &baseline_ips,
            resolver,
            &HashMap::new(),
            &HashSet::new(),
            |_| None,
        );
        new.sort();
        assert_eq!(new, vec!["5.5.5.5".to_string()]);
    }

    #[test]
    fn domain_aware_diff_keeps_ip_when_domain_is_new() {
        let ips_curr: HashSet<String> = ["8.8.8.8"].into_iter().map(String::from).collect();
        let baseline_ips: HashSet<String> = ["151.101.0.1"].into_iter().map(String::from).collect();
        let resolver = |ip: &str| match ip {
            "151.101.0.1" => Some("files.pythonhosted.org".to_string()),
            "8.8.8.8" => Some("google.com".to_string()),
            _ => None,
        };
        let new = find_new_connections_domain_aware(
            &ips_curr,
            &baseline_ips,
            resolver,
            &HashMap::new(),
            &HashSet::new(),
            |_| None,
        );
        assert_eq!(new, vec!["8.8.8.8".to_string()]);
    }

    #[test]
    fn domain_aware_diff_falls_back_to_ip_when_neither_resolves() {
        let ips_curr: HashSet<String> = ["8.8.8.8"].into_iter().map(String::from).collect();
        let baseline_ips: HashSet<String> = ["1.1.1.1"].into_iter().map(String::from).collect();
        let new = find_new_connections_domain_aware(
            &ips_curr,
            &baseline_ips,
            |_| None,
            &HashMap::new(),
            &HashSet::new(),
            |_| None,
        );
        assert_eq!(new, vec!["8.8.8.8".to_string()]);
    }

    #[test]
    fn domain_aware_diff_not_new_when_ip_in_baseline_and_no_resolution() {
        let ips_curr: HashSet<String> = ["1.1.1.1"].into_iter().map(String::from).collect();
        let baseline_ips: HashSet<String> = ["1.1.1.1", "9.9.9.9"]
            .into_iter()
            .map(String::from)
            .collect();
        let new = find_new_connections_domain_aware(
            &ips_curr,
            &baseline_ips,
            |_| None,
            &HashMap::new(),
            &HashSet::new(),
            |_| None,
        );
        assert!(new.is_empty());
    }

    #[test]
    fn domain_aware_diff_multiple_ips_same_domain_all_discarded() {
        let ips_curr: HashSet<String> = vec![
            "151.101.1.1".to_string(),
            "151.101.2.2".to_string(),
            "151.101.3.3".to_string(),
            "1.2.3.4".to_string(),
        ]
        .into_iter()
        .collect();
        let baseline_ips: HashSet<String> = ["151.101.0.1"].into_iter().map(String::from).collect();
        let resolver = |ip: &str| match ip {
            "151.101.0.1" | "151.101.1.1" | "151.101.2.2" | "151.101.3.3" => {
                Some("files.pythonhosted.org".to_string())
            }
            _ => None,
        };
        let new = find_new_connections_domain_aware(
            &ips_curr,
            &baseline_ips,
            resolver,
            &HashMap::new(),
            &HashSet::new(),
            |_| None,
        );
        assert_eq!(new, vec!["1.2.3.4".to_string()]);
    }

    #[test]
    fn domain_aware_diff_mixed_resolved_and_unresolved() {
        let ips_curr: HashSet<String> = vec![
            "151.101.1.54".to_string(),
            "10.0.0.1".to_string(),
            "1.2.3.4".to_string(),
        ]
        .into_iter()
        .collect();
        let baseline_ips: HashSet<String> = ["151.101.0.1"].into_iter().map(String::from).collect();
        let resolver = |ip: &str| match ip {
            "151.101.0.1" | "151.101.1.54" => Some("files.pythonhosted.org".to_string()),
            "10.0.0.1" => Some("unknown.internal".to_string()),
            _ => None,
        };
        let mut new = find_new_connections_domain_aware(
            &ips_curr,
            &baseline_ips,
            resolver,
            &HashMap::new(),
            &HashSet::new(),
            |_| None,
        );
        new.sort();
        assert_eq!(new, vec!["1.2.3.4".to_string(), "10.0.0.1".to_string()]);
    }

    #[test]
    fn domain_aware_diff_empty_current_returns_nothing() {
        let ips_curr: HashSet<String> = HashSet::new();
        let baseline_ips: HashSet<String> = ["151.101.0.1"].into_iter().map(String::from).collect();
        let resolver = |_ip: &str| Some("files.pythonhosted.org".to_string());
        let new = find_new_connections_domain_aware(
            &ips_curr,
            &baseline_ips,
            resolver,
            &HashMap::new(),
            &HashSet::new(),
            |_| None,
        );
        assert!(new.is_empty());
    }

    #[test]
    fn domain_aware_diff_empty_baseline_flags_all_current() {
        let ips_curr: HashSet<String> = ["151.101.1.54", "8.8.8.8"]
            .into_iter()
            .map(String::from)
            .collect();
        let baseline_ips: HashSet<String> = HashSet::new();
        let resolver = |ip: &str| match ip {
            "151.101.1.54" => Some("files.pythonhosted.org".to_string()),
            _ => None,
        };
        let mut new = find_new_connections_domain_aware(
            &ips_curr,
            &baseline_ips,
            resolver,
            &HashMap::new(),
            &HashSet::new(),
            |_| None,
        );
        new.sort();
        assert_eq!(new, vec!["151.101.1.54".to_string(), "8.8.8.8".to_string()]);
    }

    #[test]
    fn domain_aware_diff_same_ip_same_domain_not_flagged() {
        let ips_curr: HashSet<String> = ["151.101.1.54"].into_iter().map(String::from).collect();
        let baseline_ips: HashSet<String> =
            ["151.101.1.54"].into_iter().map(String::from).collect();
        let resolver = |ip: &str| match ip {
            "151.101.1.54" => Some("files.pythonhosted.org".to_string()),
            _ => None,
        };
        let new = find_new_connections_domain_aware(
            &ips_curr,
            &baseline_ips,
            resolver,
            &HashMap::new(),
            &HashSet::new(),
            |_| None,
        );
        assert!(new.is_empty());
    }

    #[test]
    fn domain_aware_diff_current_unresolved_ip_in_baseline_not_flagged() {
        let ips_curr: HashSet<String> = ["8.8.8.8"].into_iter().map(String::from).collect();
        let baseline_ips: HashSet<String> = ["8.8.8.8"].into_iter().map(String::from).collect();
        let resolver = |_ip: &str| match _ip {
            "8.8.8.8" => None,
            _ => None,
        };
        let new = find_new_connections_domain_aware(
            &ips_curr,
            &baseline_ips,
            resolver,
            &HashMap::new(),
            &HashSet::new(),
            |_| None,
        );
        assert!(new.is_empty());
    }

    #[test]
    fn domain_aware_diff_current_resolves_baseline_ip_unresolvable() {
        // Baseline has IPs but none resolve — baseline_domains is empty,
        // so any current domain is treated as new.
        let ips_curr: HashSet<String> = ["151.101.1.54"].into_iter().map(String::from).collect();
        let baseline_ips: HashSet<String> = ["1.1.1.1"].into_iter().map(String::from).collect();
        let resolver = |ip: &str| match ip {
            "151.101.1.54" => Some("files.pythonhosted.org".to_string()),
            _ => None,
        };
        let mut new = find_new_connections_domain_aware(
            &ips_curr,
            &baseline_ips,
            resolver,
            &HashMap::new(),
            &HashSet::new(),
            |_| None,
        );
        new.sort();
        assert_eq!(new, vec!["151.101.1.54".to_string()]);
    }

    #[test]
    fn domain_aware_diff_same_ip_changed_domain() {
        // Same IP in baseline and current, but the resolver returns a
        // *different* domain for the current call. This exercises the
        // A2 path (domain not in baseline_domains) even though the IP
        // itself is in baseline_ips.
        use std::cell::Cell;
        let call_count = Cell::new(0u8);
        let resolver = |ip: &str| {
            if ip == "1.1.1.1" {
                let n = call_count.get();
                call_count.set(n + 1);
                if n == 0 {
                    // Called during baseline_domains collection
                    Some("old.domain.com".to_string())
                } else {
                    // Called during current IP iteration
                    Some("new.domain.com".to_string())
                }
            } else {
                None
            }
        };
        let ips_curr: HashSet<String> = ["1.1.1.1"].into_iter().map(String::from).collect();
        let baseline_ips: HashSet<String> = ["1.1.1.1"].into_iter().map(String::from).collect();
        let mut new = find_new_connections_domain_aware(
            &ips_curr,
            &baseline_ips,
            resolver,
            &HashMap::new(),
            &HashSet::new(),
            |_| None,
        );
        new.sort();
        assert_eq!(new, vec!["1.1.1.1".to_string()]);
    }

    #[test]
    fn domain_aware_diff_same_ip_baseline_resolves_current_not() {
        // Same IP — baseline resolves to a domain, current does not.
        // IP itself is in baseline_ips, so IP-membership fallback neutralizes it.
        use std::cell::Cell;
        let call_count = Cell::new(0u8);
        let resolver = |ip: &str| {
            if ip == "1.1.1.1" {
                let n = call_count.get();
                call_count.set(n + 1);
                if n == 0 {
                    Some("known.cdn.com".to_string())
                } else {
                    None
                }
            } else {
                None
            }
        };
        let ips_curr: HashSet<String> = ["1.1.1.1"].into_iter().map(String::from).collect();
        let baseline_ips: HashSet<String> = ["1.1.1.1"].into_iter().map(String::from).collect();
        let new = find_new_connections_domain_aware(
            &ips_curr,
            &baseline_ips,
            resolver,
            &HashMap::new(),
            &HashSet::new(),
            |_| None,
        );
        assert!(new.is_empty());
    }

    #[test]
    fn domain_aware_diff_same_ip_baseline_not_resolves_current_resolves() {
        // Same IP — baseline did not resolve, but current does.
        // Since baseline_domains is empty the domain appears new, so the IP is flagged.
        use std::cell::Cell;
        let call_count = Cell::new(0u8);
        let resolver = |ip: &str| {
            if ip == "1.1.1.1" {
                let n = call_count.get();
                call_count.set(n + 1);
                if n == 0 {
                    None
                } else {
                    Some("newly.seen.com".to_string())
                }
            } else {
                None
            }
        };
        let ips_curr: HashSet<String> = ["1.1.1.1"].into_iter().map(String::from).collect();
        let baseline_ips: HashSet<String> = ["1.1.1.1"].into_iter().map(String::from).collect();
        let mut new = find_new_connections_domain_aware(
            &ips_curr,
            &baseline_ips,
            resolver,
            &HashMap::new(),
            &HashSet::new(),
            |_| None,
        );
        new.sort();
        assert_eq!(new, vec!["1.1.1.1".to_string()]);
    }

    #[test]
    fn reverse_dns_domain_invalid_ip_returns_none() {
        assert!(reverse_dns_domain("not_an_ip").is_none());
    }

    #[test]
    fn pipeline_chains_domain_aware_diff_with_allowlists() {
        // Full 3-stage pipeline matching production (lines 1406–1453):
        //   1. find_new_connections_domain_aware  (domain-aware IP diff)
        //   2. filter_allowlisted_new_connections  (IP allowlist)
        //   3. filter_domain_allowlisted_new_connections_with (domain allowlist)

        let ips_curr: HashSet<String> = ["151.101.1.54", "8.8.8.8", "5.5.5.5"]
            .into_iter()
            .map(String::from)
            .collect();
        let baseline_ips: HashSet<String> = ["151.101.0.1"].into_iter().map(String::from).collect();
        let resolver = |ip: &str| match ip {
            "151.101.0.1" | "151.101.1.54" => Some("files.pythonhosted.org".to_string()),
            "5.5.5.5" => Some("evil.example.com".to_string()),
            _ => None,
        };

        // Stage 1: 151.101.1.54 filtered (same domain), 8.8.8.8 flagged (unresolvable),
        //          5.5.5.5 flagged (new domain)
        let new_connections = find_new_connections_domain_aware(
            &ips_curr,
            &baseline_ips,
            resolver,
            &HashMap::new(),
            &HashSet::new(),
            |_| None,
        );
        let mut sorted: Vec<_> = new_connections.into_iter().collect();
        sorted.sort();
        assert_eq!(sorted, vec!["5.5.5.5".to_string(), "8.8.8.8".to_string()]);

        // Stage 2: IP allowlist removes 8.8.8.8
        let ip_allowlist: HashMap<String, HashSet<String>> = [(
            "*".to_string(),
            ["8.8.8.8"].into_iter().map(String::from).collect(),
        )]
        .into_iter()
        .collect();
        let (new_connections, allowlisted_ips) =
            filter_allowlisted_new_connections("pkg", sorted, &ip_allowlist);
        assert_eq!(allowlisted_ips, vec!["8.8.8.8".to_string()]);
        assert_eq!(new_connections, vec!["5.5.5.5".to_string()]);

        // Stage 3: Domain allowlist catches 5.5.5.5 -> evil.example.com
        let domain_allowlist: HashMap<String, HashSet<String>> = [(
            "*".to_string(),
            ["evil.example.com"].into_iter().map(String::from).collect(),
        )]
        .into_iter()
        .collect();
        let resolver2 = |ip: &str| match ip {
            "5.5.5.5" => Some("evil.example.com".to_string()),
            _ => None,
        };
        let (new_connections, allowlisted_domains) = filter_domain_allowlisted_new_connections_with(
            "pkg",
            new_connections,
            &domain_allowlist,
            resolver2,
        );
        assert_eq!(
            allowlisted_domains,
            vec!["5.5.5.5 -> evil.example.com".to_string()]
        );
        assert!(new_connections.is_empty());
    }

    // ---------------------------------------------------------------------------
    // CDN rotation without PTR records — handled by DNS interceptor fallback.
    //
    // When both baseline and current IPs belong to the same CDN (Fastly, Cloudflare,
    // etc.) but the IPs themselves have no PTR records, the domain-aware diff
    // cannot use FCrDNS.  Instead it falls back to the strace-parsed DNS map:
    // if the current IPs were resolved under a domain that baseline traffic also
    // resolved, and host-side forward confirmation verifies the binding, the
    // rotation is discarded as benign.
    //
    // This test reproduces the real-world scenario from iniconfig 2.3.0:
    //
    //   baseline IPs (2.2.0 / 2.1.0):  140.248.144.220, 2a04:4e42:94::200
    //   current IPs  (2.3.0):           140.248.144.223, 2a04:4e42:94::223
    //
    // Both sets of Fastly IPs lack PTR records.  Baseline DNS traces captured
    // the domain `objects.fastly.com`; current DNS traces show the same domain
    // resolving to the new IPs.  Host-side forward_resolver confirms the binding.
    #[test]
    fn domain_aware_diff_cdn_rotation_without_ptr_handled_by_dns_interceptor() {
        let ips_curr: HashSet<String> = ["2a04:4e42:94::223", "140.248.144.223"]
            .into_iter()
            .map(String::from)
            .collect();
        let baseline_ips: HashSet<String> = ["140.248.144.220", "2a04:4e42:94::200"]
            .into_iter()
            .map(String::from)
            .collect();
        // Fastly edge IPs — no PTR records
        let resolver = |_ip: &str| None;

        // DNS interceptor data: current DNS trace maps a domain to the new IPs
        let mut dns_map: HashMap<String, Vec<IpAddr>> = HashMap::new();
        dns_map.insert(
            "objects.fastly.com".to_string(),
            vec![
                "140.248.144.223".parse::<IpAddr>().unwrap(),
                "2a04:4e42:94::223".parse::<IpAddr>().unwrap(),
            ],
        );
        // Baseline DNS trace logged the same domain
        let baseline_dns_domains: HashSet<String> =
            ["objects.fastly.com".to_string()].into_iter().collect();
        // Host-side forward resolution confirms the binding
        let forward_resolver = |d: &str| {
            if d == "objects.fastly.com" {
                Some(vec![
                    "140.248.144.223".parse::<IpAddr>().unwrap(),
                    "2a04:4e42:94::223".parse::<IpAddr>().unwrap(),
                ])
            } else {
                None
            }
        };

        let mut new = find_new_connections_domain_aware(
            &ips_curr,
            &baseline_ips,
            resolver,
            &dns_map,
            &baseline_dns_domains,
            forward_resolver,
        );
        new.sort();
        assert!(
            new.is_empty(),
            "CDN rotation with no PTR should not be flagged, but got: {:?}",
            new
        );
    }

    #[test]
    fn ip_allowlist_matches_equivalent_ipv6_representations() {
        let new_connections = vec!["2001:0db8:0000:0000:0000:ff00:0042:8329".to_string()];
        let ip_allowlist: HashMap<String, HashSet<String>> = [(
            "*".to_string(),
            ["2001:db8::ff00:42:8329"]
                .into_iter()
                .map(String::from)
                .collect(),
        )]
        .into_iter()
        .collect();
        let (remaining, allowlisted) =
            filter_allowlisted_new_connections("pkg", new_connections, &ip_allowlist);
        assert!(remaining.is_empty());
        assert_eq!(
            allowlisted,
            vec!["2001:0db8:0000:0000:0000:ff00:0042:8329".to_string()]
        );
    }

    #[test]
    fn ip_allowlist_matches_across_ipv4_mapped_and_bare_forms() {
        // A bare-IPv4 allowlist entry must match an IPv4-mapped IPv6 hit...
        let (remaining, allowlisted) = filter_allowlisted_new_connections(
            "pkg",
            vec!["::ffff:203.0.113.5".to_string()],
            &[(
                "*".to_string(),
                ["203.0.113.5".to_string()].into_iter().collect(),
            )]
            .into_iter()
            .collect(),
        );
        assert!(remaining.is_empty());
        assert_eq!(allowlisted, vec!["::ffff:203.0.113.5".to_string()]);

        // ...and an allowlist entry stored as bare IPv4 (load_policy_config collapses
        // ::ffff:-prefixed forms at parse time) matches a bare-IPv4 hit.
        let (remaining, allowlisted) = filter_allowlisted_new_connections(
            "pkg",
            vec!["203.0.113.5".to_string()],
            &[(
                "*".to_string(),
                ["203.0.113.5".to_string()].into_iter().collect(),
            )]
            .into_iter()
            .collect(),
        );
        assert!(remaining.is_empty());
        assert_eq!(allowlisted, vec!["203.0.113.5".to_string()]);
    }

    #[test]
    fn per_package_ip_allowlist_does_not_leak_to_other_packages() {
        let ip_allowlist: HashMap<String, HashSet<String>> = [(
            "requests".to_string(),
            ["1.2.3.4"].into_iter().map(String::from).collect(),
        )]
        .into_iter()
        .collect();
        // 1.2.3.4 is in requests' per-package list — allowed for requests
        let (remaining, allowlisted) = filter_allowlisted_new_connections(
            "requests",
            vec!["1.2.3.4".to_string()],
            &ip_allowlist,
        );
        assert!(remaining.is_empty());
        assert_eq!(allowlisted, vec!["1.2.3.4".to_string()]);

        // Same IP must NOT be allowlisted for a different package
        let (remaining, allowlisted) =
            filter_allowlisted_new_connections("boto3", vec!["1.2.3.4".to_string()], &ip_allowlist);
        assert_eq!(remaining, vec!["1.2.3.4".to_string()]);
        assert!(allowlisted.is_empty());
    }

    #[test]
    fn per_package_domain_allowlist_does_not_leak_to_other_packages() {
        let domain_allowlist: HashMap<String, HashSet<String>> = [(
            "boto3".to_string(),
            ["s3.amazonaws.com"].into_iter().map(String::from).collect(),
        )]
        .into_iter()
        .collect();
        let resolver = |_ip: &str| Some("s3.amazonaws.com".to_string());

        // Allowed for boto3
        let (remaining, allowlisted) = filter_domain_allowlisted_new_connections_with(
            "boto3",
            vec!["52.216.0.1".to_string()],
            &domain_allowlist,
            resolver,
        );
        assert!(remaining.is_empty());
        assert_eq!(
            allowlisted,
            vec!["52.216.0.1 -> s3.amazonaws.com".to_string()]
        );

        // NOT allowed for requests
        let (remaining, allowlisted) = filter_domain_allowlisted_new_connections_with(
            "requests",
            vec!["52.216.0.1".to_string()],
            &domain_allowlist,
            resolver,
        );
        assert_eq!(remaining, vec!["52.216.0.1".to_string()]);
        assert!(allowlisted.is_empty());
    }

    #[test]
    fn global_ip_allowlist_applies_to_all_packages() {
        let ip_allowlist: HashMap<String, HashSet<String>> = [(
            "*".to_string(),
            ["8.8.8.8"].into_iter().map(String::from).collect(),
        )]
        .into_iter()
        .collect();
        for pkg in &["requests", "boto3", "numpy"] {
            let (remaining, allowlisted) =
                filter_allowlisted_new_connections(pkg, vec!["8.8.8.8".to_string()], &ip_allowlist);
            assert!(
                remaining.is_empty(),
                "global entry should allow for {}",
                pkg
            );
            assert_eq!(allowlisted, vec!["8.8.8.8".to_string()]);
        }
    }

    #[test]
    fn mixed_global_and_per_package_ip_allowlist() {
        // Global: 8.8.8.8; per-package for "requests": 1.2.3.4
        let ip_allowlist: HashMap<String, HashSet<String>> = [
            (
                "*".to_string(),
                ["8.8.8.8"].into_iter().map(String::from).collect(),
            ),
            (
                "requests".to_string(),
                ["1.2.3.4"].into_iter().map(String::from).collect(),
            ),
        ]
        .into_iter()
        .collect();

        // requests: both global and per-package IPs allowed
        let (remaining, _) = filter_allowlisted_new_connections(
            "requests",
            vec![
                "8.8.8.8".to_string(),
                "1.2.3.4".to_string(),
                "5.5.5.5".to_string(),
            ],
            &ip_allowlist,
        );
        assert_eq!(remaining, vec!["5.5.5.5".to_string()]);

        // boto3: only global IP allowed; per-package 1.2.3.4 is NOT allowed
        let (remaining, allowlisted) = filter_allowlisted_new_connections(
            "boto3",
            vec!["8.8.8.8".to_string(), "1.2.3.4".to_string()],
            &ip_allowlist,
        );
        assert_eq!(remaining, vec!["1.2.3.4".to_string()]);
        assert_eq!(allowlisted, vec!["8.8.8.8".to_string()]);
    }

    #[test]
    fn global_domain_allowlist_applies_to_all_packages() {
        let domain_allowlist: HashMap<String, HashSet<String>> = [(
            "*".to_string(),
            ["files.pythonhosted.org"]
                .into_iter()
                .map(String::from)
                .collect(),
        )]
        .into_iter()
        .collect();
        let resolver = |_ip: &str| Some("files.pythonhosted.org".to_string());

        for pkg in &["requests", "boto3", "numpy"] {
            let (remaining, allowlisted) = filter_domain_allowlisted_new_connections_with(
                pkg,
                vec!["151.101.0.1".to_string()],
                &domain_allowlist,
                resolver,
            );
            assert!(
                remaining.is_empty(),
                "global domain entry should allow for {}",
                pkg
            );
            assert_eq!(
                allowlisted,
                vec!["151.101.0.1 -> files.pythonhosted.org".to_string()]
            );
        }
    }

    #[test]
    fn mixed_global_and_per_package_domain_allowlist() {
        // Global: files.pythonhosted.org; per-package for "boto3": s3.amazonaws.com
        let domain_allowlist: HashMap<String, HashSet<String>> = [
            (
                "*".to_string(),
                ["files.pythonhosted.org"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
            ),
            (
                "boto3".to_string(),
                ["s3.amazonaws.com"].into_iter().map(String::from).collect(),
            ),
        ]
        .into_iter()
        .collect();

        // boto3 gets both global and per-package domains; c2.evil.com is still blocked
        let resolver_boto3 = |ip: &str| match ip {
            "151.101.0.1" => Some("files.pythonhosted.org".to_string()),
            "52.216.0.1" => Some("s3.amazonaws.com".to_string()),
            _ => None,
        };
        let (remaining, _) = filter_domain_allowlisted_new_connections_with(
            "boto3",
            vec![
                "151.101.0.1".to_string(),
                "52.216.0.1".to_string(),
                "1.2.3.4".to_string(),
            ],
            &domain_allowlist,
            resolver_boto3,
        );
        assert_eq!(remaining, vec!["1.2.3.4".to_string()]);

        // requests only gets the global domain; s3.amazonaws.com is NOT allowed
        let resolver_req = |ip: &str| match ip {
            "52.216.0.1" => Some("s3.amazonaws.com".to_string()),
            _ => None,
        };
        let (remaining, allowlisted) = filter_domain_allowlisted_new_connections_with(
            "requests",
            vec!["52.216.0.1".to_string()],
            &domain_allowlist,
            resolver_req,
        );
        assert_eq!(remaining, vec!["52.216.0.1".to_string()]);
        assert!(allowlisted.is_empty());
    }

    // ---------------------------------------------------------------------------
    // git_clone_behavior_tests (moved from tests/git_clone_behavior_tests.rs)
    // ---------------------------------------------------------------------------

    #[test]
    fn detects_new_connection_in_git_clone_simulation() {
        let clone_ips: HashSet<String> = ["140.82.112.3", "185.199.108.133"]
            .into_iter()
            .map(String::from)
            .collect();
        let baseline_ips: HashSet<String> =
            ["140.82.112.3"].into_iter().map(String::from).collect();
        let mut new = find_new_connections_domain_aware(
            &clone_ips,
            &baseline_ips,
            |_| None,
            &HashMap::new(),
            &HashSet::new(),
            |_| None,
        );
        new.sort();
        assert_eq!(new, vec!["185.199.108.133".to_string()]);
    }

    #[test]
    fn no_new_connection_in_git_clone_simulation() {
        let clone_ips: HashSet<String> = ["140.82.112.3"].into_iter().map(String::from).collect();
        let baseline_ips: HashSet<String> = ["140.82.112.3", "140.82.113.3"]
            .into_iter()
            .map(String::from)
            .collect();
        assert!(
            find_new_connections_domain_aware(
                &clone_ips,
                &baseline_ips,
                |_| None,
                &HashMap::new(),
                &HashSet::new(),
                |_| None
            )
            .is_empty()
        );
    }

    // ---------------------------------------------------------------------------
    // DNS interceptor parser tests
    // ---------------------------------------------------------------------------

    #[test]
    fn unescape_bare_ascii_passthrough() {
        assert_eq!(unescape_strace_string("hello"), b"hello");
    }

    #[test]
    fn unescape_hex_escape_decode() {
        assert_eq!(unescape_strace_string("\\x41\\x42\\x43"), b"ABC");
    }

    #[test]
    fn unescape_mixed_ascii_and_hex() {
        assert_eq!(unescape_strace_string("ab\\x63\\x64ef"), b"abcdef");
    }

    #[test]
    fn unescape_empty_string() {
        assert!(unescape_strace_string("").is_empty());
    }

    #[test]
    fn unescape_trailing_backslash() {
        assert_eq!(unescape_strace_string("ab"), b"ab");
    }

    #[test]
    fn unescape_backslash_escape_non_hex() {
        assert_eq!(unescape_strace_string("a\\nb"), b"anb");
    }

    #[test]
    fn decode_dns_name_simple_two_label() {
        let raw = b"\x03foo\x03com\x00";
        let mut offset = 0usize;
        let got = decode_dns_name(raw, &mut offset);
        assert_eq!(got, Some("foo.com".to_string()));
        assert_eq!(offset, 9);
    }

    #[test]
    fn decode_dns_name_root_label_only() {
        let raw = b"\x00";
        let mut offset = 0usize;
        let got = decode_dns_name(raw, &mut offset);
        assert_eq!(got, Some(String::new()));
        assert_eq!(offset, 1);
    }

    #[test]
    fn decode_dns_name_single_byte_pointer() {
        // Label "foo" at offset 0, then pointer 0xc000 at offset 5
        // (points back to offset 0).
        let raw = b"\x03foo\x00\xc0\x00";
        let mut offset = 5usize;
        let got = decode_dns_name(raw, &mut offset);
        assert_eq!(got, Some("foo".to_string()));
        // After a pointer, offset advances past the 2-byte pointer.
        assert_eq!(offset, 7);
    }

    #[test]
    fn decode_dns_name_recursive_pointer_chain() {
        // Two compression pointers chained:
        //   offset 0: \x03foo\x00  → "foo"
        //   offset 5: \xc0\x00      → points to offset 0
        //   offset 7: \xc0\x05      → points to offset 5 (which itself is a pointer)
        // Starting at offset 7, the chain resolves through two hops to "foo".
        let raw = b"\x03foo\x00\xc0\x00\xc0\x05";
        let mut offset = 7usize;
        let got = decode_dns_name(raw, &mut offset);
        assert_eq!(got, Some("foo".to_string()));
        assert_eq!(offset, 9);
    }

    #[test]
    fn decode_dns_name_out_of_bounds_returns_none() {
        let raw = b"\x10\x01\x02"; // label length 16 but only 2 bytes available
        let mut offset = 0usize;
        assert!(decode_dns_name(raw, &mut offset).is_none());
    }

    #[test]
    fn decode_dns_name_circular_pointer_returns_none() {
        // Self-referencing compression pointer: at offset 0, the byte is
        // 0xc0 | 0x00 = 0xc0, second byte is 0x00, so the 14-bit target
        // is 0 — pointing back to itself.
        let raw = b"\xc0\x00";
        let mut offset = 0usize;
        assert!(decode_dns_name(raw, &mut offset).is_none());
        // Ensure offset is unmodified on failure (no partial advance).
        assert_eq!(offset, 0);
    }

    #[test]
    fn decode_dns_name_long_but_not_circular_pointer_chain() {
        // Three valid pointer hops: offset 0\xc0\x02 → offset 2\xc0\x04 →
        // offset 4\xc0\x06 → offset 6\x03foo\x00 → resolves to "foo".
        let raw = b"\xc0\x02\xc0\x04\xc0\x06\x03foo\x00";
        let mut offset = 0usize;
        let result = decode_dns_name(raw, &mut offset);
        assert_eq!(result.as_deref(), Some("foo"));
        assert_eq!(offset, 2);
    }

    #[test]
    fn decode_dns_name_excessive_pointer_hops_returns_none() {
        // Six pointer hops (limit is 5).  Each hop points 2 bytes ahead.
        // Offsets: 0→2→4→6→8→10→12 → next hop is within bounds but exceeds count.
        let mut raw = Vec::new();
        for _ in 0..6 {
            raw.extend_from_slice(b"\xc0\x02"); // ptr to next 2-byte ptr
        }
        raw.extend_from_slice(b"\x03foo\x00");
        let mut offset = 0usize;
        assert!(decode_dns_name(&raw, &mut offset).is_none());
    }

    #[test]
    fn parse_dns_response_a_record() {
        // Craft a minimal DNS response with one A record.
        let mut raw = vec![
            0x00, 0x00, // TXID (ignored)
            0x81, 0x80, // Flags: response + standard query
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x01, // ANCOUNT = 1
            0x00, 0x00, 0x00, 0x00, // NSCOUNT, ARCOUNT
        ];
        // QNAME: \x03foo\x03com\x00
        raw.extend_from_slice(b"\x03foo\x03com\x00");
        // QTYPE=1 (A), QCLASS=1 (IN)
        raw.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        // ANSWER: NAME=0xc00c (compression pointer to QNAME)
        raw.extend_from_slice(&[0xc0, 0x0c]);
        // TYPE=1 (A), CLASS=1, TTL=300, RDLENGTH=4
        raw.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04]);
        // RDATA: 93.184.216.34
        raw.extend_from_slice(&[0x5d, 0xb8, 0xd8, 0x22]);

        let (qname, ips) = parse_dns_response(&raw).unwrap();
        assert_eq!(qname, "foo.com");
        assert_eq!(ips, vec!["93.184.216.34".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn parse_dns_response_aaaa_record() {
        let mut raw = vec![
            0x00, 0x00, // TXID
            0x81, 0x80, // response + standard query
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x01, // ANCOUNT = 1
            0x00, 0x00, 0x00, 0x00,
        ];
        let ipv6_addr = "2001:db8::1".parse::<Ipv6Addr>().unwrap();
        raw.extend_from_slice(b"\x03foo\x00");
        raw.extend_from_slice(&[0x00, 0x1c, 0x00, 0x01]); // QTYPE=28 (AAAA)
        raw.extend_from_slice(&[0xc0, 0x0c]);
        raw.extend_from_slice(&[0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x10]);
        raw.extend_from_slice(&ipv6_addr.octets());

        let (qname, ips) = parse_dns_response(&raw).unwrap();
        assert_eq!(qname, "foo");
        assert_eq!(ips, vec![IpAddr::V6(ipv6_addr)]);
    }

    #[test]
    fn parse_dns_response_non_response_returns_none() {
        // QR flag not set (byte 2 is 0x00 instead of 0x80)
        let raw = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(parse_dns_response(&raw).is_none());
    }

    #[test]
    fn parse_dns_response_too_short_returns_none() {
        assert!(parse_dns_response(b"\x00\x01\x02").is_none());
    }

    #[test]
    fn extract_dns_map_connect_failure_ignored() {
        // connect() returns -1 ECONNREFUSED; fd 5 should not be considered a DNS socket
        let trace = r#"
connect(5, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, 16) = -1 ECONNREFUSED (Connection refused)
read(5, "\x00\x44\x00\x00\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00\x03\x66\x6f\x6f\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x8c\xf8\x90\xdf\xc0\x0c\x00\x1c\x00\x01\x00\x00\x01\x2c\x00\x10\x2a\x04\x4e\x42\x00\x94\x00\x00\x00\x00\x00\x00\x00\x00\x02\x23", 4096) = 70
"#;
        let map = extract_dns_map(trace);
        assert!(map.is_empty(), "Failed connect should not populate dns_fds");
    }

    #[test]
    fn extract_dns_map_ipv6_udp_dns_response() {
        let trace = r#"
recvfrom(3, "\x00\x00\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00\x03\x66\x6f\x6f\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x8c\xf8\x90\xdf\xc0\x0c\x00\x1c\x00\x01\x00\x00\x01\x2c\x00\x10\x2a\x04\x4e\x42\x00\x94\x00\x00\x00\x00\x00\x00\x00\x00\x02\x23", 1024, 0, {sa_family=AF_INET6, sin6_port=htons(53), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2001:4860:4860::8888", &sin6_addr), sin6_scope_id=0}, [28]) = 68
"#;
        let map = extract_dns_map(trace);
        assert_eq!(map.len(), 1);
        let ips = map.get("foo.com").unwrap();
        assert_eq!(ips.len(), 2);
    }

    #[test]
    fn extract_dns_map_ipv6_tcp_dns_response() {
        let trace = r#"
connect(6, {sa_family=AF_INET6, sin6_port=htons(53), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2001:4860:4860::8888", &sin6_addr), sin6_scope_id=0}, 28) = 0
read(6, "\x00\x44\x00\x00\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00\x03\x66\x6f\x6f\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x8c\xf8\x90\xdf\xc0\x0c\x00\x1c\x00\x01\x00\x00\x01\x2c\x00\x10\x2a\x04\x4e\x42\x00\x94\x00\x00\x00\x00\x00\x00\x00\x00\x02\x23", 4096) = 70
"#;
        let map = extract_dns_map(trace);
        assert_eq!(map.len(), 1);
        let ips = map.get("foo.com").unwrap();
        assert_eq!(ips.len(), 2);
        let ip_strs: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
        assert!(ip_strs.contains(&"140.248.144.223".to_string()));
        assert!(ip_strs.contains(&"2a04:4e42:94::223".to_string()));
    }

    #[test]
    fn extract_dns_map_empty_trace() {
        let map = extract_dns_map("no dns traffic here");
        assert!(map.is_empty());
    }

    #[test]
    fn extract_dns_map_malformed_payload_skipped() {
        let trace = r#"recvfrom(5, "\x00\x01\x00\x01", 1024, 0, {sa_family=AF_INET, sin_port=htons(53)}, [16]) = 200"#;
        let map = extract_dns_map(trace);
        assert!(map.is_empty(), "malformed DNS payload should be skipped");
    }

    #[test]
    fn extract_dns_map_tcp_dns_response() {
        // TCP DNS: connect to port 53, then read() with a valid DNS
        // response (with 2-byte TCP length prefix).
        let tcp_payload = "\
            \\x00\\x44\
            \\x00\\x00\\x81\\x80\\x00\\x01\\x00\\x02\\x00\\x00\\x00\\x00\
            \\x03\\x66\\x6f\\x6f\\x03\\x63\\x6f\\x6d\\x00\
            \\x00\\x01\\x00\\x01\
            \\xc0\\x0c\\x00\\x01\\x00\\x01\\x00\\x00\\x01\\x2c\\x00\\x04\
            \\x8c\\xf8\\x90\\xdf\
            \\xc0\\x0c\\x00\\x1c\\x00\\x01\\x00\\x00\\x01\\x2c\\x00\\x10\
            \\x2a\\x04\\x4e\\x42\\x00\\x94\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x02\\x23";

        let trace = format!(
            "[pid 123] connect(7, {{sa_family=AF_INET, sin_port=htons(53), \
             sin_addr=inet_addr(\"8.8.8.8\")}}, 16) = 0\n\
             [pid 123] read(7, \"{}\", 4096) = 70\n\
             [pid 123] connect(5, {{sa_family=AF_INET, sin_port=htons(443), \
             sin_addr=inet_addr(\"1.2.3.4\")}}, 16) = 0",
            tcp_payload
        );

        let map = extract_dns_map(&trace);
        assert_eq!(map.len(), 1, "TCP DNS should yield 1 domain entry");
        let (domain, ips) = map.iter().next().unwrap();
        assert_eq!(domain, "foo.com");

        let ip_strs: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
        assert!(ip_strs.contains(&"140.248.144.223".to_string()));
        assert!(ip_strs.contains(&"2a04:4e42:94::223".to_string()));
    }

    #[test]
    fn extract_dns_map_tcp_non_dns_fd_ignored() {
        // A `read()` on an fd connected to port 443 (not DNS) should not
        // be parsed as a TCP DNS response.
        let trace = r#"[pid 123] connect(7, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}, 16) = 0
[pid 123] read(7, "\x00\x44\x00\x00\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00\x03\x66\x6f\x6f\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x8c\xf8\x90\xdf\xc0\x0c\x00\x1c\x00\x01\x00\x00\x01\x2c\x00\x10\x2a\x04\x4e\x42\x00\x94\x00\x00\x00\x00\x00\x00\x00\x00\x02\x23", 4096) = 70"#;

        let map = extract_dns_map(trace);
        assert!(map.is_empty(), "non-DNS fd should not produce DNS entries");
    }

    #[test]
    fn extract_dns_map_tcp_too_short_skipped() {
        // A TCP `read()` with only the 2-byte length prefix (no DNS
        // message body) should be skipped.
        let trace = r#"[pid 123] connect(7, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, 16) = 0
[pid 123] read(7, "\x00\x01", 2) = 2"#;

        let map = extract_dns_map(trace);
        assert!(map.is_empty(), "partial TCP read should be skipped");
    }

    #[test]
    fn extract_dns_map_tcp_malformed_payload_skipped() {
        // A TCP DNS response with a valid 2-byte length prefix but
        // malformed DNS payload should be skipped (mirrors the UDP
        // malformed_payload_skipped test).
        let trace = r#"[pid 123] connect(7, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, 16) = 0
[pid 123] read(7, "\x00\x04\x00\x01\x00\x01", 6) = 6"#;

        let map = extract_dns_map(trace);
        assert!(
            map.is_empty(),
            "malformed TCP DNS payload should be skipped"
        );
    }

    #[test]
    fn extract_dns_map_mixed_udp_and_tcp_dns() {
        // Both UDP (recvfrom) and TCP (connect + read) DNS responses
        // should contribute to the same map.
        let dns_payload = "\
            \\x00\\x00\\x81\\x80\\x00\\x01\\x00\\x02\\x00\\x00\\x00\\x00\
            \\x03\\x66\\x6f\\x6f\\x03\\x63\\x6f\\x6d\\x00\
            \\x00\\x01\\x00\\x01\
            \\xc0\\x0c\\x00\\x01\\x00\\x01\\x00\\x00\\x01\\x2c\\x00\\x04\
            \\x8c\\xf8\\x90\\xdf\
            \\xc0\\x0c\\x00\\x1c\\x00\\x01\\x00\\x00\\x01\\x2c\\x00\\x10\
            \\x2a\\x04\\x4e\\x42\\x00\\x94\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x02\\x23";

        let tcp_payload = "\
            \\x00\\x44\
            \\x00\\x00\\x81\\x80\\x00\\x01\\x00\\x02\\x00\\x00\\x00\\x00\
            \\x03\\x62\\x61\\x72\\x03\\x63\\x6f\\x6d\\x00\
            \\x00\\x01\\x00\\x01\
            \\xc0\\x0c\\x00\\x01\\x00\\x01\\x00\\x00\\x01\\x2c\\x00\\x04\
            \\x8c\\xf8\\x90\\xfe\
            \\xc0\\x0c\\x00\\x1c\\x00\\x01\\x00\\x00\\x01\\x2c\\x00\\x10\
            \\x2a\\x04\\x4e\\x42\\x00\\x94\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x02\\x24";

        let trace = format!(
            "[pid 123] recvfrom(5, \"{dns_payload}\", 1024, 0, \
             {{sa_family=AF_INET, sin_port=htons(53)}}, [16]) = 200\n\
             [pid 123] connect(7, {{sa_family=AF_INET, sin_port=htons(53), \
             sin_addr=inet_addr(\"8.8.8.8\")}}, 16) = 0\n\
             [pid 123] read(7, \"{tcp_payload}\", 4096) = 70"
        );

        let map = extract_dns_map(&trace);
        assert_eq!(map.len(), 2, "mixed UDP+TCP should yield 2 domain entries");
        assert!(
            map.contains_key("foo.com"),
            "UDP path should resolve foo.com"
        );
        assert!(
            map.contains_key("bar.com"),
            "TCP path should resolve bar.com"
        );
    }

    // ---------------------------------------------------------------------------
    // DNS interceptor fallback edge-case tests
    // ---------------------------------------------------------------------------

    #[test]
    fn dns_interceptor_skips_when_domain_not_in_baseline() {
        let ips_curr: HashSet<String> = ["140.248.144.223"].into_iter().map(String::from).collect();
        let baseline_ips: HashSet<String> =
            ["140.248.144.220"].into_iter().map(String::from).collect();
        let resolver = |_ip: &str| None;
        let mut dns_map: HashMap<String, Vec<IpAddr>> = HashMap::new();
        dns_map.insert(
            "new-cdn.example.com".to_string(),
            vec!["140.248.144.223".parse::<IpAddr>().unwrap()],
        );
        // Baseline DNS traces don't include this domain
        let baseline_dns_domains: HashSet<String> = HashSet::new();
        let forward_resolver = |d: &str| {
            if d == "new-cdn.example.com" {
                Some(vec!["140.248.144.223".parse::<IpAddr>().unwrap()])
            } else {
                None
            }
        };
        let mut new = find_new_connections_domain_aware(
            &ips_curr,
            &baseline_ips,
            resolver,
            &dns_map,
            &baseline_dns_domains,
            forward_resolver,
        );
        new.sort();
        assert_eq!(
            new,
            vec!["140.248.144.223".to_string()],
            "IP should be flagged because its domain is not in baseline"
        );
    }

    #[test]
    fn dns_interceptor_skips_when_forward_resolver_does_not_confirm() {
        let ips_curr: HashSet<String> = ["140.248.144.223"].into_iter().map(String::from).collect();
        let baseline_ips: HashSet<String> =
            ["140.248.144.220"].into_iter().map(String::from).collect();
        let resolver = |_ip: &str| None;
        let mut dns_map: HashMap<String, Vec<IpAddr>> = HashMap::new();
        dns_map.insert(
            "objects.fastly.com".to_string(),
            vec!["140.248.144.223".parse::<IpAddr>().unwrap()],
        );
        let baseline_dns_domains: HashSet<String> =
            ["objects.fastly.com".to_string()].into_iter().collect();
        // Forward resolver does NOT confirm the binding (spoofed DNS)
        let forward_resolver = |_d: &str| None;
        let mut new = find_new_connections_domain_aware(
            &ips_curr,
            &baseline_ips,
            resolver,
            &dns_map,
            &baseline_dns_domains,
            forward_resolver,
        );
        new.sort();
        assert_eq!(
            new,
            vec!["140.248.144.223".to_string()],
            "IP should be flagged when forward resolver doesn't confirm"
        );
    }

    #[test]
    fn dns_interceptor_end_to_end_with_realistic_strace_trace() {
        // Build a realistic strace -xx trace: connect calls to Fastly CDN
        // (no PTR) + recvfrom from port 53 with DNS A + AAAA responses.
        //
        // The hex-escaped DNS response packet contains:
        //   QNAME: foo.com
        //   Answer 1: A      140.248.144.223
        //   Answer 2: AAAA   2a04:4e42:94::223
        let dns_payload = "\
            \\x00\\x00\\x81\\x80\\x00\\x01\\x00\\x02\\x00\\x00\\x00\\x00\
            \\x03\\x66\\x6f\\x6f\\x03\\x63\\x6f\\x6d\\x00\
            \\x00\\x01\\x00\\x01\
            \\xc0\\x0c\\x00\\x01\\x00\\x01\\x00\\x00\\x01\\x2c\\x00\\x04\
            \\x8c\\xf8\\x90\\xdf\
            \\xc0\\x0c\\x00\\x1c\\x00\\x01\\x00\\x00\\x01\\x2c\\x00\\x10\
            \\x2a\\x04\\x4e\\x42\\x00\\x94\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x02\\x23";

        let trace = format!(
            "[pid 123] connect(5, {{sa_family=AF_INET, sin_port=htons(443), \
             sin_addr=inet_addr(\"140.248.144.223\")}}, 16) = 0\n\
             [pid 123] connect(5, {{sa_family=AF_INET6, sin6_port=htons(443), \
             sin6_addr=inet_pton(AF_INET6, \"2a04:4e42:94::223\")}}, 28) = 0\n\
             [pid 123] recvfrom(5, \"{}\", 1024, 0, \
             {{sa_family=AF_INET, sin_port=htons(53)}}, [16]) = 70\n\
             [pid 123] connect(5, {{sa_family=AF_INET, sin_port=htons(443), \
             sin_addr=inet_addr(\"151.101.1.54\")}}, 16) = 0",
            dns_payload
        );

        // Stage 1: extract_dns_map parses the wire-format DNS response
        // from the strace trace — same code path as production.
        let dns_curr = extract_dns_map(&trace);

        // Verify the parser correctly extracted the domain and IPs
        assert_eq!(dns_curr.len(), 1, "should have 1 domain entry");
        let (domain, ips) = dns_curr.iter().next().unwrap();
        assert_eq!(domain, "foo.com");

        let ip_strs: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
        assert!(
            ip_strs.contains(&"140.248.144.223".to_string()),
            "dns_map should contain the A record IP"
        );
        assert!(
            ip_strs.contains(&"2a04:4e42:94::223".to_string()),
            "dns_map should contain the AAAA record IP"
        );

        // Stage 2: feed the parsed dns_map into the domain-aware diff.
        // Current Fastly IPs (no PTR), baseline from same CDN.
        let ips_curr: HashSet<String> = ["140.248.144.223", "2a04:4e42:94::223"]
            .into_iter()
            .map(String::from)
            .collect();
        let baseline_ips: HashSet<String> = ["140.248.144.220", "2a04:4e42:94::200"]
            .into_iter()
            .map(String::from)
            .collect();
        // Fastly edge IPs — no PTR records
        let resolver = |_ip: &str| None;
        // Baseline DNS traces from previous runs also resolved foo.com
        let baseline_dns_domains: HashSet<String> = ["foo.com".to_string()].into_iter().collect();
        // Host-side forward resolution confirms the binding
        let forward_resolver = |d: &str| {
            if d == "foo.com" {
                Some(vec![
                    "140.248.144.223".parse::<IpAddr>().unwrap(),
                    "2a04:4e42:94::223".parse::<IpAddr>().unwrap(),
                ])
            } else {
                None
            }
        };

        let mut new = find_new_connections_domain_aware(
            &ips_curr,
            &baseline_ips,
            resolver,
            &dns_curr,
            &baseline_dns_domains,
            forward_resolver,
        );
        new.sort();
        assert!(
            new.is_empty(),
            "CDN rotation should not be flagged via DNS interceptor, got: {:?}",
            new
        );
    }

    // ---------------------------------------------------------------------------
    // bun_exec_scan_tests (moved from tests/bun_exec_scan_tests.rs)
    // ---------------------------------------------------------------------------

    use std::sync::{Mutex, OnceLock};

    struct MockRunner {
        traces: HashMap<(String, String), String>,
    }

    impl crate::sandbox::SandboxRunner for MockRunner {
        fn trace_install(
            &self,
            _manager: &str,
            package: &str,
            version: &str,
        ) -> Result<String, String> {
            self.traces
                .get(&(package.to_string(), version.to_string()))
                .cloned()
                .ok_or_else(|| format!("missing mock trace for {}@{}", package, version))
        }

        fn trace_install_matrix(
            &self,
            _manager: &str,
            probes: &[(String, String)],
        ) -> Result<Vec<crate::sandbox::ProbeTrace>, String> {
            let mut results = Vec::new();
            for probe in probes {
                if let Some(trace) = self.traces.get(probe) {
                    results.push((probe.clone(), trace.clone()));
                }
            }
            Ok(results)
        }
    }

    fn env_lock() -> &'static Mutex<()> {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        ENV_LOCK.get_or_init(|| Mutex::new(()))
    }

    /// RAII guard for a test env var. Acquiring it locks `env_lock` for the whole
    /// lifetime of the guard (serializing every test that reads the var, including
    /// across the scan `.await`) and sets the var; dropping it removes the var.
    /// Drop runs on panic too, so a failing assertion can never leave the var set.
    /// The lock is recovered from poisoning (`into_inner`) so one panicking test
    /// does not cascade into PoisonError panics in every subsequent test —
    /// closes FIXED_FINDINGS.md #13 without reintroducing the cross-test race.
    struct EnvVarGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        key: &'static str,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let lock = env_lock()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            unsafe {
                std::env::set_var(key, value);
            }
            Self { _lock: lock, key }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            unsafe {
                std::env::remove_var(self.key);
            }
        }
    }

    fn policy_with_baseline_and_process_allowlist(
        package: &str,
        baseline: &str,
        process_exec_allowlist: HashMap<String, HashSet<String>>,
    ) -> PolicyConfig {
        PolicyConfig {
            baseline_count: 1,
            process_exec_allowlist,
            baseline_overrides: HashMap::from([(
                package.to_string(),
                (Some(baseline.to_string()), None),
            )]),
            ..PolicyConfig::default()
        }
    }

    fn policy_with_baseline_and_git_allowlist(
        package: &str,
        baseline: &str,
        git_clone_allowlist: HashMap<String, HashSet<String>>,
        process_exec_allowlist: HashMap<String, HashSet<String>>,
    ) -> PolicyConfig {
        PolicyConfig {
            baseline_count: 1,
            git_clone_allowlist,
            process_exec_allowlist,
            baseline_overrides: HashMap::from([(
                package.to_string(),
                (Some(baseline.to_string()), None),
            )]),
            ..PolicyConfig::default()
        }
    }

    #[tokio::test]
    async fn flags_newly_introduced_bun_execution() {
        let _env = EnvVarGuard::set("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0");
        let runner = MockRunner {
            traces: HashMap::from([
                (
                    ("evil-pkg".to_string(), "1.3.0".to_string()),
                    "execve(\"/tmp/b/bun\", [\"/tmp/b/bun\", \"run\", \"_index.js\"], 0x7ff) = 0\n"
                        .to_string(),
                ),
                (
                    ("evil-pkg".to_string(), "1.2.0".to_string()),
                    "execve(\"/usr/bin/node\", [\"node\", \"index.js\"], 0x7ff) = 0\n".to_string(),
                ),
            ]),
        };
        let results = scan_packages_versions(
            &runner,
            "npm",
            &[("evil-pkg".to_string(), "1.3.0".to_string())],
            &policy_with_baseline_and_process_allowlist("evil-pkg", "1.2.0", HashMap::new()),
        )
        .await;
        assert_eq!(
            results.get("evil-pkg|1.3.0").map(|r| r.allowed),
            Some(false)
        );
    }

    #[tokio::test]
    async fn flags_existing_bun_with_additional_invocation() {
        let _env = EnvVarGuard::set("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0");
        let runner = MockRunner {
            traces: HashMap::from([
                (("buildy".to_string(), "2.1.0".to_string()),
                 "execve(\"/usr/bin/bun\", [\"bun\", \"run\", \"build\"], 0x7ff) = 0\nexecve(\"/tmp/b/bun\", [\"bun\", \"run\", \"_index.js\"], 0x7ff) = 0\n".to_string()),
                (("buildy".to_string(), "2.0.0".to_string()),
                 "execve(\"/usr/bin/bun\", [\"bun\", \"run\", \"build\"], 0x7ff) = 0\n".to_string()),
            ]),
        };
        let results = scan_packages_versions(
            &runner,
            "npm",
            &[("buildy".to_string(), "2.1.0".to_string())],
            &policy_with_baseline_and_process_allowlist("buildy", "2.0.0", HashMap::new()),
        )
        .await;
        assert_eq!(results.get("buildy|2.1.0").map(|r| r.allowed), Some(false));
    }

    #[tokio::test]
    async fn allows_when_bun_behavior_matches_baseline() {
        let _env = EnvVarGuard::set("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0");
        let trace =
            "execve(\"/usr/bin/bun\", [\"bun\", \"run\", \"build\"], 0x7ff) = 0\n".to_string();
        let runner = MockRunner {
            traces: HashMap::from([
                (("buildy".to_string(), "2.1.0".to_string()), trace.clone()),
                (("buildy".to_string(), "2.0.0".to_string()), trace),
            ]),
        };
        let results = scan_packages_versions(
            &runner,
            "npm",
            &[("buildy".to_string(), "2.1.0".to_string())],
            &policy_with_baseline_and_process_allowlist("buildy", "2.0.0", HashMap::new()),
        )
        .await;
        assert_eq!(results.get("buildy|2.1.0").map(|r| r.allowed), Some(true));
    }

    #[tokio::test]
    async fn allows_new_bun_when_allowlisted() {
        let _env = EnvVarGuard::set("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0");
        let runner = MockRunner {
            traces: HashMap::from([
                (
                    ("buildy".to_string(), "2.1.0".to_string()),
                    "execve(\"/usr/bin/bun\", [\"bun\", \"run\", \"approved-task\"], 0x7ff) = 0\n"
                        .to_string(),
                ),
                (
                    ("buildy".to_string(), "2.0.0".to_string()),
                    "execve(\"/usr/bin/node\", [\"node\", \"index.js\"], 0x7ff) = 0\n".to_string(),
                ),
            ]),
        };
        let allowlist: HashSet<String> =
            ["bun|run|approved-task".to_string()].into_iter().collect();
        let mut allowlist_map = HashMap::new();
        allowlist_map.insert("buildy".to_string(), allowlist);
        let results = scan_packages_versions(
            &runner,
            "npm",
            &[("buildy".to_string(), "2.1.0".to_string())],
            &policy_with_baseline_and_process_allowlist("buildy", "2.0.0", allowlist_map),
        )
        .await;
        assert_eq!(results.get("buildy|2.1.0").map(|r| r.allowed), Some(true));
    }

    // ---------------------------------------------------------------------------
    // git_clone_scan_tests (moved from tests/git_clone_scan_tests.rs)
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn scan_flags_new_install_time_git_clone_behavior() {
        let _env = EnvVarGuard::set("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0");
        let runner = MockRunner {
            traces: HashMap::from([
                (("pkg-a".to_string(), "1.3.0".to_string()),
                 "execve(\"/usr/bin/git\", [\"git\", \"clone\", \"https://github.com/evil/repo.git\"], 0x7ff) = 0\n".to_string()),
                (("pkg-a".to_string(), "1.2.0".to_string()),
                 "execve(\"/usr/bin/sh\", [\"sh\", \"-c\", \"echo ok\"], 0x7ff) = 0\n".to_string()),
            ]),
        };
        let results = scan_packages_versions(
            &runner,
            "npm",
            &[("pkg-a".to_string(), "1.3.0".to_string())],
            &policy_with_baseline_and_git_allowlist(
                "pkg-a",
                "1.2.0",
                HashMap::new(),
                HashMap::new(),
            ),
        )
        .await;
        assert_eq!(results.get("pkg-a|1.3.0").map(|r| r.allowed), Some(false));
    }

    #[tokio::test]
    async fn scan_allows_when_install_time_git_clone_behavior_matches_baseline() {
        let _env = EnvVarGuard::set("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0");
        let trace = "execve(\"/usr/bin/git\", [\"git\", \"clone\", \"https://github.com/acme/repo.git\"], 0x7ff) = 0\n".to_string();
        let runner = MockRunner {
            traces: HashMap::from([
                (("pkg-b".to_string(), "1.3.0".to_string()), trace.clone()),
                (("pkg-b".to_string(), "1.2.0".to_string()), trace),
            ]),
        };
        let results = scan_packages_versions(
            &runner,
            "npm",
            &[("pkg-b".to_string(), "1.3.0".to_string())],
            &policy_with_baseline_and_git_allowlist(
                "pkg-b",
                "1.2.0",
                HashMap::new(),
                HashMap::new(),
            ),
        )
        .await;
        assert_eq!(results.get("pkg-b|1.3.0").map(|r| r.allowed), Some(true));
    }

    #[tokio::test]
    async fn scan_allows_new_git_clone_behavior_when_target_is_allowlisted() {
        let _env = EnvVarGuard::set("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0");
        let runner = MockRunner {
            traces: HashMap::from([
                (("pkg-c".to_string(), "1.3.0".to_string()),
                 "execve(\"/usr/bin/git\", [\"git\", \"clone\", \"https://github.com/acme/approved.git\"], 0x7ff) = 0\n".to_string()),
                (("pkg-c".to_string(), "1.2.0".to_string()),
                 "execve(\"/usr/bin/sh\", [\"sh\", \"-c\", \"echo ok\"], 0x7ff) = 0\n".to_string()),
            ]),
        };
        let allowlist_set: HashSet<String> = ["https://github.com/acme/approved.git".to_string()]
            .into_iter()
            .collect();
        let mut git_clone_allowlist = HashMap::new();
        git_clone_allowlist.insert("pkg-c".to_string(), allowlist_set);
        let process_exec_allowlist_set: HashSet<String> =
            ["git|clone|https://github.com/acme/approved.git".to_string()]
                .into_iter()
                .collect();
        let mut process_exec_allowlist = HashMap::new();
        process_exec_allowlist.insert("pkg-c".to_string(), process_exec_allowlist_set);
        let results = scan_packages_versions(
            &runner,
            "npm",
            &[("pkg-c".to_string(), "1.3.0".to_string())],
            &policy_with_baseline_and_git_allowlist(
                "pkg-c",
                "1.2.0",
                git_clone_allowlist,
                process_exec_allowlist,
            ),
        )
        .await;
        assert_eq!(results.get("pkg-c|1.3.0").map(|r| r.allowed), Some(true));
    }

    // --- gap #13: filter_allowlisted_git_clone_signatures — recursive suffix stripped before match ---

    #[test]
    fn git_clone_allowlist_matches_recursive_clone_of_allowed_url() {
        // The allowlist stores the URL; the signature includes |recursive. The URL
        // must be extracted before comparison so the recursive flag does not prevent
        // the allowlisted URL from matching.
        let signatures = vec!["https://github.com/acme/repo.git|recursive".to_string()];
        let allowlist_set: HashSet<String> = ["https://github.com/acme/repo.git".to_string()]
            .into_iter()
            .collect();
        let mut allowlist = HashMap::new();
        allowlist.insert("test-pkg".to_string(), allowlist_set);
        let (remaining, allowlisted) =
            filter_allowlisted_git_clone_signatures("test-pkg", signatures, &allowlist);
        assert!(
            remaining.is_empty(),
            "recursive clone of an allowed URL must be allowlisted"
        );
        assert_eq!(
            allowlisted,
            vec!["https://github.com/acme/repo.git|recursive".to_string()]
        );
    }

    #[test]
    fn git_clone_allowlist_matches_non_recursive_clone_of_allowed_url() {
        let signatures = vec!["https://github.com/acme/repo.git|non-recursive".to_string()];
        let allowlist_set: HashSet<String> = ["https://github.com/acme/repo.git".to_string()]
            .into_iter()
            .collect();
        let mut allowlist = HashMap::new();
        allowlist.insert("test-pkg".to_string(), allowlist_set);
        let (remaining, allowlisted) =
            filter_allowlisted_git_clone_signatures("test-pkg", signatures, &allowlist);
        assert!(remaining.is_empty());
        assert_eq!(allowlisted.len(), 1);
    }

    #[test]
    fn git_clone_allowlist_does_not_match_different_url() {
        let signatures = vec!["https://github.com/evil/repo.git|non-recursive".to_string()];
        let allowlist_set: HashSet<String> = ["https://github.com/acme/repo.git".to_string()]
            .into_iter()
            .collect();
        let mut allowlist = HashMap::new();
        allowlist.insert("test-pkg".to_string(), allowlist_set);
        let (remaining, allowlisted) =
            filter_allowlisted_git_clone_signatures("test-pkg", signatures, &allowlist);
        assert_eq!(remaining.len(), 1);
        assert!(allowlisted.is_empty());
    }

    #[test]
    fn git_clone_allowlist_does_not_leak_across_packages() {
        let signatures = vec!["https://github.com/acme/repo.git|non-recursive".to_string()];
        let allowlist_set: HashSet<String> = ["https://github.com/acme/repo.git".to_string()]
            .into_iter()
            .collect();
        let mut allowlist = HashMap::new();
        allowlist.insert("other-pkg".to_string(), allowlist_set);

        let (remaining, allowlisted) =
            filter_allowlisted_git_clone_signatures("target-pkg", signatures.clone(), &allowlist);
        assert!(
            allowlisted.is_empty(),
            "Allowlist must not leak across packages"
        );
        assert_eq!(remaining, signatures);
    }

    // --- gap #14: select_effective_baselines — override version equal to current ---

    #[test]
    fn override_equal_to_current_is_excluded_from_baselines() {
        // An override that pins the same version as `current` would make the
        // baseline identical to the scan target, producing an empty diff in
        // every signal category — silently disabling all anomaly detection.
        // The guard in select_effective_baselines skips it.
        let override_pair = (Some("3.0.0".to_string()), None);
        let (out, self_ref) =
            select_effective_baselines("3.0.0", vec!["2.9.0".to_string()], Some(&override_pair), 2);
        assert!(
            self_ref,
            "self_ref flag must be true when override equals current"
        );
        assert!(
            !out.contains(&"3.0.0".to_string()),
            "override equal to current must be excluded"
        );
        // The fetched baseline 2.9.0 should fill the slot instead.
        assert!(out.contains(&"2.9.0".to_string()));
    }

    #[test]
    fn override_different_from_current_is_used_normally() {
        let override_pair = (Some("2.8.0".to_string()), None);
        let (out, self_ref) = select_effective_baselines(
            "3.0.0",
            vec!["2.9.0".to_string(), "2.7.0".to_string()],
            Some(&override_pair),
            2,
        );
        assert!(
            !self_ref,
            "self_ref flag must be false when override differs from current"
        );
        assert!(out.contains(&"2.8.0".to_string()));
        assert!(!out.contains(&"3.0.0".to_string()));
    }

    #[test]
    fn override_m2_equal_to_current_is_excluded_from_baselines() {
        // Same as above but the self-reference is in baseline-2 (m2), not baseline-1.
        let override_pair = (Some("2.8.0".to_string()), Some("3.0.0".to_string()));
        let (out, self_ref) =
            select_effective_baselines("3.0.0", vec!["2.9.0".to_string()], Some(&override_pair), 2);
        assert!(
            self_ref,
            "self_ref flag must be true when override equals current"
        );
        assert!(
            !out.contains(&"3.0.0".to_string()),
            "override m2 equal to current must be excluded"
        );
        // m1 (2.8.0) should be kept since it differs from current.
        assert!(out.contains(&"2.8.0".to_string()));
        // Fetched baseline fills the second slot.
        assert!(out.contains(&"2.9.0".to_string()));
    }

    #[test]
    fn both_overrides_equal_to_current_skipped_and_filled_from_fetched() {
        // Both override slots equal current; both skipped, fetched baselines fill.
        let override_pair = (Some("3.0.0".to_string()), Some("3.0.0".to_string()));
        let (out, _) = select_effective_baselines(
            "3.0.0",
            vec!["2.9.0".to_string(), "2.8.0".to_string()],
            Some(&override_pair),
            2,
        );
        assert!(
            !out.contains(&"3.0.0".to_string()),
            "both overrides equal to current must be excluded"
        );
        assert_eq!(out, vec!["2.9.0".to_string(), "2.8.0".to_string()]);
    }

    #[test]
    fn override_equal_to_current_with_no_fetched_baselines_returns_empty() {
        // No fetched baselines available and the only override equals current.
        let override_pair = (Some("3.0.0".to_string()), None);
        let (out, self_ref) = select_effective_baselines("3.0.0", vec![], Some(&override_pair), 2);
        assert!(
            self_ref,
            "self_ref flag must be true when override equals current"
        );
        assert!(
            out.is_empty(),
            "no baselines when only override equals current and no fetched baselines"
        );
    }

    #[test]
    fn only_m2_is_set_and_equals_current_is_excluded() {
        // m1 is absent, m2 (the second override slot) equals current.
        let override_pair = (None, Some("3.0.0".to_string()));
        let (out, self_ref) =
            select_effective_baselines("3.0.0", vec!["2.9.0".to_string()], Some(&override_pair), 2);
        assert!(
            self_ref,
            "self_ref flag must be true when m2 override equals current"
        );
        assert!(!out.contains(&"3.0.0".to_string()));
        assert!(out.contains(&"2.9.0".to_string()));
    }

    #[test]
    fn override_equal_to_current_with_baseline_count_one_is_skipped() {
        // baseline_count=1, the only override equals current, one fetched
        // baseline available to fill the slot.
        let override_pair = (Some("3.0.0".to_string()), None);
        let out =
            select_effective_baselines("3.0.0", vec!["2.9.0".to_string()], Some(&override_pair), 1)
                .0;
        assert_eq!(out, vec!["2.9.0".to_string()]);
    }

    #[test]
    fn baseline_count_zero_with_override_equal_to_current_returns_empty() {
        // The early-return on baseline_count == 0 should fire before any
        // override logic is reached.
        let override_pair = (Some("3.0.0".to_string()), Some("2.8.0".to_string()));
        let out =
            select_effective_baselines("3.0.0", vec!["2.9.0".to_string()], Some(&override_pair), 0)
                .0;
        assert!(out.is_empty());
    }

    #[test]
    fn both_override_slots_none_falls_through_to_fetched_baselines() {
        // baseline_overrides.get(pkg_name) returns Some(&(None, None)) —
        // enters the override block but neither slot has a value to push.
        // Should behave as if no overrides were configured.
        let override_pair: (Option<String>, Option<String>) = (None, None);
        let (out, _) = select_effective_baselines(
            "3.0.0",
            vec!["2.9.0".to_string(), "2.8.0".to_string()],
            Some(&override_pair),
            2,
        );
        assert_eq!(out, vec!["2.9.0".to_string(), "2.8.0".to_string()]);
    }

    #[test]
    fn baseline_count_zero_does_not_fail_closed() {
        let (out, _) = select_effective_baselines("3.0.0", vec![], None, 0);
        assert!(out.is_empty(), "baseline_count 0 should return empty list");
    }

    // --- gap #15: scan_packages_versions — missing baseline trace fails closed ---

    #[tokio::test]
    async fn scan_fails_closed_when_one_baseline_trace_is_missing() {
        let _env = EnvVarGuard::set("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0");

        // Runner has trace for current and baseline-1 but NOT baseline-2.
        // With baseline_count=2 both baselines are in the plan; the missing one
        // must cause a fail-closed result rather than a silent partial diff.
        let runner = MockRunner {
            traces: HashMap::from([
                (
                    ("pkg".to_string(), "2.0.0".to_string()),
                    "sin_addr=inet_addr(\"1.2.3.4\")\n".to_string(),
                ),
                (
                    ("pkg".to_string(), "1.9.0".to_string()),
                    "sin_addr=inet_addr(\"1.2.3.4\")\n".to_string(),
                ),
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

        let results = scan_packages_versions(
            &runner,
            "pip",
            &[("pkg".to_string(), "2.0.0".to_string())],
            &policy,
        )
        .await;

        let report = results.get("pkg|2.0.0").expect("should have result");
        assert!(
            !report.allowed,
            "missing baseline trace must fail closed, not silently allow"
        );
        assert!(
            report
                .blocked_reasons
                .contains(&"sandbox_trace_missing".to_string()),
            "must push sandbox_trace_missing block reason"
        );
    }

    #[tokio::test]
    async fn internal_package_exemption_skips_scan_entirely() {
        // An empty runner has NO traces, so any sandbox install would error and
        // fail closed. The internal exemption must short-circuit before the
        // registry fetch and the sandbox matrix, yielding an allowed result
        // pinned to the requested version.
        let runner = MockRunner {
            traces: HashMap::new(),
        };

        let policy = PolicyConfig {
            internal_package_exemptions: ["internal-pkg-logger".to_string()].into_iter().collect(),
            ..PolicyConfig::default()
        };

        let results = scan_packages_versions(
            &runner,
            "pip",
            &[("internal-pkg-logger".to_string(), "0.5.0".to_string())],
            &policy,
        )
        .await;

        let report = results
            .get("internal-pkg-logger|0.5.0")
            .expect("result present");
        assert!(report.allowed, "internal-exempt package must be allowed");
        assert_eq!(
            report.resolved_version, "0.5.0",
            "internal-exempt package keeps its requested version (no resolution)"
        );
    }

    #[tokio::test]
    async fn internal_package_exemption_only_skips_listed_package() {
        // A non-exempt package alongside an exempt one must still be scanned.
        // The exempt one is skipped without a trace; the scanned one diffs
        // cleanly against its baseline and is allowed.
        let _env = EnvVarGuard::set("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0");

        let runner = MockRunner {
            traces: HashMap::from([
                (
                    ("public-pkg".to_string(), "2.0.0".to_string()),
                    "sin_addr=inet_addr(\"1.2.3.4\")\n".to_string(),
                ),
                (
                    ("public-pkg".to_string(), "1.9.0".to_string()),
                    "sin_addr=inet_addr(\"1.2.3.4\")\n".to_string(),
                ),
            ]),
        };

        let policy = PolicyConfig {
            baseline_count: 1,
            internal_package_exemptions: ["internal-pkg".to_string()].into_iter().collect(),
            baseline_overrides: HashMap::from([(
                "public-pkg".to_string(),
                (Some("1.9.0".to_string()), None),
            )]),
            ..PolicyConfig::default()
        };

        let results = scan_packages_versions(
            &runner,
            "pip",
            &[
                ("internal-pkg".to_string(), "0.1.0".to_string()),
                ("public-pkg".to_string(), "2.0.0".to_string()),
            ],
            &policy,
        )
        .await;

        assert_eq!(
            results.get("internal-pkg|0.1.0").map(|r| r.allowed),
            Some(true),
            "exempt package skipped and allowed"
        );
        assert_eq!(
            results.get("public-pkg|2.0.0").map(|r| r.allowed),
            Some(true),
            "non-exempt package still scanned (clean diff -> allowed)"
        );
    }

    // ---------------------------------------------------------------------------
    // artifact_scan_tests
    // ---------------------------------------------------------------------------

    #[test]
    fn extracts_artifact_findings_when_delimiter_present() {
        let trace = format!(
            "some strace output\n{}/work/foo.pth|100|ASCII text|import urllib\n/work/bun-x64|5678|ELF 64-bit LSB executable|...",
            super::ARTIFACT_DELIMITER
        );
        let findings = extract_artifact_findings(&trace);
        assert_eq!(findings.len(), 2);
        assert!(findings.contains("/work/foo.pth|100|ASCII text|import urllib"));
        assert!(findings.contains("/work/bun-x64|5678|ELF 64-bit LSB executable|..."));
    }

    #[test]
    fn extracts_artifact_findings_empty_when_no_delimiter() {
        let trace = "just strace output\nno artifacts here";
        let findings = extract_artifact_findings(trace);
        assert!(findings.is_empty());
    }

    #[test]
    fn strips_artifact_section_returns_only_trace_part() {
        let trace = format!(
            "strace line 1\nstrace line 2\n{}/work/foo.pth|100|ASCII text|import urllib",
            super::ARTIFACT_DELIMITER
        );
        let result = strip_artifact_section(&trace);
        assert_eq!(result, "strace line 1\nstrace line 2\n");
        assert!(!result.contains("gyrseek_artifacts"));
    }

    #[test]
    fn strips_artifact_section_noop_when_no_delimiter() {
        let trace = "strace line 1\nstrace line 2";
        let result = strip_artifact_section(trace);
        assert_eq!(result, trace);
    }

    #[test]
    fn extracts_artifact_findings_skips_blank_lines() {
        let trace = format!(
            "strace\n{}/work/foo.pth|100|ASCII text|import urllib\n\n\n\n   \n/work/deno|5678|ELF 64-bit LSB executable|...",
            super::ARTIFACT_DELIMITER
        );
        let findings = extract_artifact_findings(&trace);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn artifact_findings_empty_for_clean_install() {
        let trace = format!("strace output\n{}", super::ARTIFACT_DELIMITER);
        let findings = extract_artifact_findings(&trace);
        assert!(findings.is_empty());
    }

    // --- classify_inventory_lines ---

    #[test]
    fn classify_inventory_binary_elf() {
        let raw: HashSet<String> =
            ["/usr/bin/somebin\x0012345\x00ELF 64-bit LSB executable x86-64\x00..."]
                .iter()
                .map(|s| s.to_string())
                .collect();
        let out = classify_inventory_lines(raw);
        assert!(out.contains("binary|/usr/bin/somebin|ELF 64-bit LSB executable x86-64"));
        assert!(!out.iter().any(|f| f.starts_with("large_file")));
    }

    #[test]
    fn classify_inventory_unexpected_runtime() {
        let raw: HashSet<String> = [
            "/work/bun-x64\x005678\x00ELF 64-bit LSB executable\x00...",
            "/work/node\x001234\x00ELF 64-bit LSB executable\x00...",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let out = classify_inventory_lines(raw);
        assert!(out.contains("unexpected_runtime|/work/bun-x64|ELF 64-bit LSB executable"));
        assert!(out.contains("binary|/work/bun-x64|ELF 64-bit LSB executable"));
        assert!(out.contains("binary|/work/node|ELF 64-bit LSB executable"));
        assert!(!out.contains("unexpected_runtime|/work/node|ELF 64-bit LSB executable"));
    }

    #[test]
    fn classify_inventory_suspicious_pth() {
        let raw: HashSet<String> =
            ["/work/site-packages/evil.pth\x00100\x00ASCII text\x00import socket subprocess"]
                .iter()
                .map(|s| s.to_string())
                .collect();
        let out = classify_inventory_lines(raw);
        assert!(
            out.contains("suspicious_pth|/work/site-packages/evil.pth|import socket subprocess")
        );
    }

    #[test]
    fn classify_inventory_benign_pth() {
        let raw: HashSet<String> =
            ["/work/site-packages/happy.pth\x0050\x00ASCII text\x00# just a path\n../../lib"]
                .iter()
                .map(|s| s.to_string())
                .collect();
        let out = classify_inventory_lines(raw);
        assert!(!out.iter().any(|f| f.starts_with("suspicious_pth")));
    }

    #[test]
    fn classify_inventory_large_file() {
        let raw: HashSet<String> = ["/work/data.bin\x0020971520\x00data\x00..."]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let out = classify_inventory_lines(raw);
        assert!(out.contains("large_file|/work/data.bin|20971520"));
    }

    #[test]
    fn classify_inventory_skips_malformed_lines() {
        let raw: HashSet<String> = ["not-enough-fields", "/work/ok\x0010\x00\x00"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let out = classify_inventory_lines(raw);
        assert!(out.is_empty());
    }

    #[test]
    fn classify_inventory_empty_input() {
        let raw: HashSet<String> = HashSet::new();
        let out = classify_inventory_lines(raw);
        assert!(out.is_empty());
    }

    #[test]
    fn classify_inventory_mixed_findings() {
        let raw: HashSet<String> = [
            "/work/bun\x001000\x00ELF 64-bit LSB executable\x00...",
            "/work/hack.pth\x00300\x00ASCII text\x00import urllib.request",
            "/work/big.bin\x0010485761\x00data\x00...",
            "/work/normal.py\x00200\x00ASCII text\x00print('hello')",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let out = classify_inventory_lines(raw);
        assert!(out.contains("binary|/work/bun|ELF 64-bit LSB executable"));
        assert!(out.contains("unexpected_runtime|/work/bun|ELF 64-bit LSB executable"));
        assert!(out.contains("suspicious_pth|/work/hack.pth|import urllib.request"));
        assert!(out.contains("large_file|/work/big.bin|10485761"));
        assert_eq!(out.len(), 4);
    }

    #[test]
    fn artifact_delimiter_pipe_in_path_is_not_injected() {
        // Finding 20 regression: a file with | in its name must not hijack the
        // null-byte delimiter. The full path is treated as one field regardless
        // of how many | characters it contains.
        let raw: HashSet<String> = [
            // Basic injection: |0|ASCII text in name attempts to override size+type.
            // Path=payload.bin|0|ASCII text, size=30000000, type=ELF 64-bit
            "/work/payload.bin|0|ASCII text\x0030000000\x00ELF 64-bit\x00...",
            // Multiple pipes in filename (small file, should not produce findings).
            "/work/a|b|c|d.bin\x00123\x00data\x00...",
            // Pipe at start of filename (small file, should not produce findings).
            "/work/|leading-pipe\x00456\x00ASCII text\x00content",
            // Pipe at end of filename (small file, should not produce findings).
            "/work/trailing-pipe|\x00789\x00data\x00content",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let out = classify_inventory_lines(raw);
        // The path "payload.bin|0|ASCII text" must be treated as one field.
        // Size 30000000 → large_file. Type "ELF 64-bit" → binary.
        assert!(
            out.contains("large_file|/work/payload.bin|0|ASCII text|30000000"),
            "pipe-delimited injection in path must not override size field: {:?}",
            out
        );
        assert!(
            out.contains("binary|/work/payload.bin|0|ASCII text|ELF 64-bit"),
            "pipe-delimited injection in path must not override type field: {:?}",
            out
        );
        // The other files (small, non-binary) must produce no findings at all,
        // confirming their pipe-containing paths did not generate false signals.
        assert_eq!(
            out.len(),
            2,
            "only payload.bin should produce findings; pipe chars in other paths must not generate spurious findings: {:?}",
            out
        );
    }

    #[tokio::test]
    async fn artifact_delimiter_injection_attack_defeated_end_to_end() {
        // Finding 20 end-to-end regression: simulate an attacker package that
        // contains a file named "payload.bin|0|ASCII text" (30 MB ELF binary).
        // With the null-byte delimiter fix, the parser must:
        //   1. Treat the |0|ASCII text as part of the path, NOT as injected fields
        //   2. Read size=30000000 from the second null-delimited field (not 0)
        //   3. Read type="ELF 64-bit" from the third field (not "ASCII text")
        //   4. Block the package (binary + large_file findings, both new)
        let _env = EnvVarGuard::set("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0");

        let runner = MockRunner {
            traces: HashMap::from([
                (
                    ("evil-pkg".to_string(), "2.0.0".to_string()),
                    format!(
                        "strace output\n{}/work/payload.bin|0|ASCII text\x0030000000\x00ELF 64-bit\x00...",
                        crate::scanning::ARTIFACT_DELIMITER
                    ),
                ),
                (
                    ("evil-pkg".to_string(), "1.0.0".to_string()),
                    "strace output\n".to_string(),
                ),
            ]),
        };

        let policy = PolicyConfig {
            baseline_count: 1,
            baseline_overrides: HashMap::from([(
                "evil-pkg".to_string(),
                (Some("1.0.0".to_string()), None),
            )]),
            ..PolicyConfig::default()
        };

        let results = scan_packages_versions(
            &runner,
            "pip",
            &[("evil-pkg".to_string(), "2.0.0".to_string())],
            &policy,
        )
        .await;

        assert_eq!(
            results.get("evil-pkg|2.0.0").map(|r| r.allowed),
            Some(false),
            "large ELF binary with | in filename must be detected and blocked"
        );
    }

    #[tokio::test]
    async fn artifact_delimiter_injection_does_not_block_clean_package() {
        // Negative test for Finding 20: a package whose installed files happen to
        // contain pipe characters in paths but are otherwise clean (small, non-binary)
        // must NOT be falsely blocked.
        let _env = EnvVarGuard::set("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0");

        let runner = MockRunner {
            traces: HashMap::from([
                (
                    ("clean-pkg".to_string(), "2.0.0".to_string()),
                    format!(
                        "strace output\n{}/work/readme|notes.txt\x00100\x00ASCII text\x00# docs\n/work/setup|helpers.py\x00200\x00ASCII text\x00import os",
                        crate::scanning::ARTIFACT_DELIMITER
                    ),
                ),
                (
                    ("clean-pkg".to_string(), "1.0.0".to_string()),
                    "strace output\n".to_string(),
                ),
            ]),
        };

        let policy = PolicyConfig {
            baseline_count: 1,
            baseline_overrides: HashMap::from([(
                "clean-pkg".to_string(),
                (Some("1.0.0".to_string()), None),
            )]),
            ..PolicyConfig::default()
        };

        let results = scan_packages_versions(
            &runner,
            "pip",
            &[("clean-pkg".to_string(), "2.0.0".to_string())],
            &policy,
        )
        .await;

        assert_eq!(
            results.get("clean-pkg|2.0.0").map(|r| r.allowed),
            Some(true),
            "clean files with pipe in name must not be falsely blocked"
        );
    }

    #[tokio::test]
    async fn flags_new_artifact_findings_across_versions() {
        // Current version introduces a suspicious .pth file not seen in baseline.
        let _env = EnvVarGuard::set("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0");

        let runner = MockRunner {
            traces: HashMap::from([
                (
                    ("evil-pkg".to_string(), "2.0.0".to_string()),
                    format!(
                        "sin_addr=inet_addr(\"1.2.3.4\")\n{}/work/site-packages/evil.pth\x00150\x00ASCII text\x00import socket",
                        crate::scanning::ARTIFACT_DELIMITER
                    ),
                ),
                (
                    ("evil-pkg".to_string(), "1.9.0".to_string()),
                    "sin_addr=inet_addr(\"1.2.3.4\")\n".to_string(),
                ),
            ]),
        };

        let policy = PolicyConfig {
            baseline_count: 1,
            baseline_overrides: HashMap::from([(
                "evil-pkg".to_string(),
                (Some("1.9.0".to_string()), None),
            )]),
            ..PolicyConfig::default()
        };

        let results = scan_packages_versions(
            &runner,
            "pip",
            &[("evil-pkg".to_string(), "2.0.0".to_string())],
            &policy,
        )
        .await;

        assert_eq!(
            results.get("evil-pkg|2.0.0").map(|r| r.allowed),
            Some(false),
            "new artifact finding must block the package"
        );
    }

    #[tokio::test]
    async fn artifact_allowlist_unblocks_new_findings() {
        // Same scenario as flags_new_artifact_findings_across_versions, but
        // with the artifact allowlist matching the new finding.
        let _env = EnvVarGuard::set("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0");

        let runner = MockRunner {
            traces: HashMap::from([
                (
                    ("evil-pkg".to_string(), "2.0.0".to_string()),
                    format!(
                        "sin_addr=inet_addr(\"1.2.3.4\")\n{}/work/site-packages/evil.pth\x00150\x00ASCII text\x00import socket",
                        crate::scanning::ARTIFACT_DELIMITER
                    ),
                ),
                (
                    ("evil-pkg".to_string(), "1.9.0".to_string()),
                    "sin_addr=inet_addr(\"1.2.3.4\")\n".to_string(),
                ),
            ]),
        };

        let artifact_allowlist_set: HashSet<String> =
            ["suspicious_pth|/work/site-packages/evil.pth".to_string()]
                .into_iter()
                .collect();
        let mut artifact_allowlist = HashMap::new();
        artifact_allowlist.insert("evil-pkg".to_string(), artifact_allowlist_set);

        let policy = PolicyConfig {
            baseline_count: 1,
            artifact_allowlist,
            baseline_overrides: HashMap::from([(
                "evil-pkg".to_string(),
                (Some("1.9.0".to_string()), None),
            )]),
            ..PolicyConfig::default()
        };

        let results = scan_packages_versions(
            &runner,
            "pip",
            &[("evil-pkg".to_string(), "2.0.0".to_string())],
            &policy,
        )
        .await;

        assert_eq!(
            results.get("evil-pkg|2.0.0").map(|r| r.allowed),
            Some(true),
            "artifact allowlist must unblock a new finding"
        );
    }

    #[tokio::test]
    async fn allows_when_artifact_findings_match_baseline() {
        // .pth file present in both baseline and current — no new signal.
        let _env = EnvVarGuard::set("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0");

        let pth = format!(
            "some strace{}/work/pkg.pth\x0080\x00ASCII text\x00import helper",
            crate::scanning::ARTIFACT_DELIMITER
        );

        let runner = MockRunner {
            traces: HashMap::from([
                (("legacy-pkg".to_string(), "3.0.0".to_string()), pth.clone()),
                (("legacy-pkg".to_string(), "2.0.0".to_string()), pth.clone()),
            ]),
        };

        let policy = PolicyConfig {
            baseline_count: 1,
            baseline_overrides: HashMap::from([(
                "legacy-pkg".to_string(),
                (Some("2.0.0".to_string()), None),
            )]),
            ..PolicyConfig::default()
        };

        let results = scan_packages_versions(
            &runner,
            "pip",
            &[("legacy-pkg".to_string(), "3.0.0".to_string())],
            &policy,
        )
        .await;

        assert_eq!(
            results.get("legacy-pkg|3.0.0").map(|r| r.allowed),
            Some(true),
            "artifact finding present in baseline must not block"
        );
    }

    #[tokio::test]
    async fn test_multiple_anomalies_evaluate_completely() {
        let _env = EnvVarGuard::set("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0");

        let runner = MockRunner {
            traces: HashMap::from([
                // Baseline: Clean
                (
                    ("multi-pkg".to_string(), "1.0.0".to_string()),
                    "sin_addr=inet_addr(\"127.0.0.1\")\n".to_string(),
                ),
                // Current: Contains all 5 types of anomalies
                (
                    ("multi-pkg".to_string(), "2.0.0".to_string()),
                    format!(
                        "execve(\"/bin/bun\", [\"bun\", \"run\", \"evil.js\"], 0x7ff) = 0\n\
                        open(\"/home/user/.aws/credentials\", O_RDONLY) = 3\n\
                        execve(\"/usr/bin/git\", [\"git\", \"clone\", \"https://evil.com/repo.git\"], 0x7ff) = 0\n\
                        sin_addr=inet_addr(\"1.2.3.4\")\n\
                        {}/work/evil.pth\x00150\x00ASCII text\x00import os",
                        crate::scanning::ARTIFACT_DELIMITER
                    ),
                ),
            ]),
        };

        let policy = PolicyConfig {
            baseline_count: 1,
            baseline_overrides: HashMap::from([(
                "multi-pkg".to_string(),
                (Some("1.0.0".to_string()), None),
            )]),
            ..PolicyConfig::default()
        };

        let results = scan_packages_versions(
            &runner,
            "pip",
            &[("multi-pkg".to_string(), "2.0.0".to_string())],
            &policy,
        )
        .await;

        let report = results.get("multi-pkg|2.0.0").expect("result should exist");
        assert!(!report.allowed, "multiple anomalies must block the package");
        assert_eq!(
            report.blocked_reasons.len(),
            5,
            "must evaluate all 5 anomalies without short-circuiting"
        );
        let mut reasons = report.blocked_reasons.clone();
        reasons.sort();
        assert_eq!(
            reasons,
            vec![
                "Suspicious artifact(s) discovered after install",
                "git_clone_anomaly",
                "network_anomaly",
                "process_exec_anomaly",
                "sensitive_file_read_anomaly"
            ]
        );
    }

    #[tokio::test]
    async fn test_two_anomalies_evaluate_completely() {
        let _env = EnvVarGuard::set("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0");

        let runner = MockRunner {
            traces: HashMap::from([
                (
                    ("multi-pkg".to_string(), "1.0.0".to_string()),
                    "sin_addr=inet_addr(\"127.0.0.1\")\n".to_string(),
                ),
                (
                    ("multi-pkg".to_string(), "2.0.0".to_string()),
                    "execve(\"/bin/bun\", [\"bun\", \"run\", \"evil.js\"], 0x7ff) = 0\n\
                    sin_addr=inet_addr(\"1.2.3.4\")\n"
                        .to_string(),
                ),
            ]),
        };

        let policy = PolicyConfig {
            baseline_count: 1,
            baseline_overrides: HashMap::from([(
                "multi-pkg".to_string(),
                (Some("1.0.0".to_string()), None),
            )]),
            ..PolicyConfig::default()
        };

        let results = scan_packages_versions(
            &runner,
            "pip",
            &[("multi-pkg".to_string(), "2.0.0".to_string())],
            &policy,
        )
        .await;
        let report = results.get("multi-pkg|2.0.0").expect("result should exist");
        assert!(!report.allowed);
        assert_eq!(
            report.blocked_reasons.len(),
            2,
            "must evaluate exactly 2 anomalies without short-circuiting"
        );
        let mut reasons = report.blocked_reasons.clone();
        reasons.sort();
        assert_eq!(reasons, vec!["network_anomaly", "process_exec_anomaly"]);
    }

    #[tokio::test]
    async fn test_three_anomalies_evaluate_completely() {
        let _env = EnvVarGuard::set("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0");

        let runner = MockRunner {
            traces: HashMap::from([
                (
                    ("multi-pkg".to_string(), "1.0.0".to_string()),
                    "sin_addr=inet_addr(\"127.0.0.1\")\n".to_string(),
                ),
                (
                    ("multi-pkg".to_string(), "2.0.0".to_string()),
                    format!(
                        "execve(\"/bin/bun\", [\"bun\", \"run\", \"evil.js\"], 0x7ff) = 0\n\
                        sin_addr=inet_addr(\"1.2.3.4\")\n\
                        {}/work/evil.pth\x00150\x00ASCII text\x00import os",
                        crate::scanning::ARTIFACT_DELIMITER
                    ),
                ),
            ]),
        };

        let policy = PolicyConfig {
            baseline_count: 1,
            baseline_overrides: HashMap::from([(
                "multi-pkg".to_string(),
                (Some("1.0.0".to_string()), None),
            )]),
            ..PolicyConfig::default()
        };

        let results = scan_packages_versions(
            &runner,
            "pip",
            &[("multi-pkg".to_string(), "2.0.0".to_string())],
            &policy,
        )
        .await;
        let report = results.get("multi-pkg|2.0.0").expect("result should exist");
        assert!(!report.allowed);
        assert_eq!(
            report.blocked_reasons.len(),
            3,
            "must evaluate exactly 3 anomalies without short-circuiting"
        );
    }

    #[tokio::test]
    async fn test_four_anomalies_evaluate_completely() {
        let _env = EnvVarGuard::set("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0");

        let runner = MockRunner {
            traces: HashMap::from([
                (
                    ("multi-pkg".to_string(), "1.0.0".to_string()),
                    "sin_addr=inet_addr(\"127.0.0.1\")\n".to_string(),
                ),
                (
                    ("multi-pkg".to_string(), "2.0.0".to_string()),
                    format!(
                        "execve(\"/bin/bun\", [\"bun\", \"run\", \"evil.js\"], 0x7ff) = 0\n\
                        open(\"/home/user/.aws/credentials\", O_RDONLY) = 3\n\
                        sin_addr=inet_addr(\"1.2.3.4\")\n\
                        {}/work/evil.pth\x00150\x00ASCII text\x00import os",
                        crate::scanning::ARTIFACT_DELIMITER
                    ),
                ),
            ]),
        };

        let policy = PolicyConfig {
            baseline_count: 1,
            baseline_overrides: HashMap::from([(
                "multi-pkg".to_string(),
                (Some("1.0.0".to_string()), None),
            )]),
            ..PolicyConfig::default()
        };

        let results = scan_packages_versions(
            &runner,
            "pip",
            &[("multi-pkg".to_string(), "2.0.0".to_string())],
            &policy,
        )
        .await;
        let report = results.get("multi-pkg|2.0.0").expect("result should exist");
        assert!(!report.allowed);
        assert_eq!(
            report.blocked_reasons.len(),
            4,
            "must evaluate exactly 4 anomalies without short-circuiting"
        );
    }

    #[tokio::test]
    async fn new_package_exemption_skips_artifact_check() {
        // A new package (<2 eligible baselines) with new artifact findings must
        // be exempted, not blocked.
        let _env = EnvVarGuard::set("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0");

        let runner = MockRunner {
            traces: HashMap::from([(
                ("new-pkg".to_string(), "1.0.0".to_string()),
                format!(
                    "sin_addr=inet_addr(\"1.2.3.4\")\n{}/work/site-packages/evil.pth\x00150\x00ASCII text\x00import socket",
                    crate::scanning::ARTIFACT_DELIMITER
                ),
            )]),
        };

        let policy = PolicyConfig {
            baseline_count: 2,
            new_package_exemptions: [("new-pkg".to_string(), "1.0.0".to_string())]
                .into_iter()
                .collect(),
            ..PolicyConfig::default()
        };

        let results = scan_packages_versions(
            &runner,
            "pip",
            &[("new-pkg".to_string(), "1.0.0".to_string())],
            &policy,
        )
        .await;

        assert_eq!(
            results.get("new-pkg|1.0.0").map(|r| r.allowed),
            Some(true),
            "new package with artifact findings must be exempt"
        );
    }

    #[tokio::test]
    async fn new_package_exemption_ignored_if_version_mismatch() {
        // Exemption is pinned to 1.0.0, but we are installing 1.0.1.
        // It should be ignored and block because it lacks baselines.
        let _env = EnvVarGuard::set("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0");

        let runner = MockRunner {
            traces: HashMap::from([(
                ("new-pkg".to_string(), "1.0.1".to_string()),
                "".to_string(), // Empty trace, no anomalies, just lack of baselines
            )]),
        };

        let policy = PolicyConfig {
            baseline_count: 2,
            new_package_exemptions: [("new-pkg".to_string(), "1.0.0".to_string())]
                .into_iter()
                .collect(),
            ..PolicyConfig::default()
        };

        let results = scan_packages_versions(
            &runner,
            "pip",
            &[("new-pkg".to_string(), "1.0.1".to_string())],
            &policy,
        )
        .await;

        let report = results.get("new-pkg|1.0.1").unwrap();
        assert!(
            !report.allowed,
            "exemption should be ignored and package blocked"
        );
        assert_eq!(
            report.blocked_reasons,
            vec!["insufficient_baselines".to_string()],
            "must be blocked early due to lack of baselines"
        );
    }

    #[tokio::test]
    async fn new_package_exemption_warns_and_scans_if_sufficient_baselines() {
        // Exemption is pinned and matches, but the package actually has enough baselines.
        // It should print a warning and then undergo standard scan (and fail if there's an anomaly).
        let _env = EnvVarGuard::set("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0");

        let runner = MockRunner {
            traces: HashMap::from([
                (
                    ("new-pkg".to_string(), "1.0.0".to_string()),
                    format!(
                        "sin_addr=inet_addr(\"1.2.3.4\")\n{}/work/site-packages/evil.pth\x00150\x00ASCII text\x00import socket",
                        crate::scanning::ARTIFACT_DELIMITER
                    ),
                ),
                (
                    ("new-pkg".to_string(), "0.9.0".to_string()),
                    "sin_addr=inet_addr(\"1.2.3.4\")".to_string(),
                ),
                (
                    ("new-pkg".to_string(), "0.8.0".to_string()),
                    "sin_addr=inet_addr(\"1.2.3.4\")".to_string(),
                ),
            ]),
        };

        let policy = PolicyConfig {
            baseline_count: 2,
            baseline_overrides: HashMap::from([(
                "new-pkg".to_string(),
                (Some("0.9.0".to_string()), Some("0.8.0".to_string())),
            )]),
            new_package_exemptions: [("new-pkg".to_string(), "1.0.0".to_string())]
                .into_iter()
                .collect(),
            ..PolicyConfig::default()
        };

        let results = scan_packages_versions(
            &runner,
            "pip",
            &[("new-pkg".to_string(), "1.0.0".to_string())],
            &policy,
        )
        .await;

        let report = results.get("new-pkg|1.0.0").unwrap();
        assert!(
            !report.allowed,
            "must be blocked due to the artifact anomaly, because the exemption is ignored when baselines are sufficient"
        );
        assert!(
            report
                .blocked_reasons
                .iter()
                .any(|r| r.contains("Suspicious artifact(s)")),
            "must flag the suspicious_pth anomaly"
        );
    }

    #[tokio::test]
    async fn new_package_exemption_mismatch_with_sufficient_baselines_allows() {
        // Exemption is pinned to 1.0.0, installing 2.0.0 (doesn't match).
        // GYRSEEK_TEST_FORCE_BASELINE_AGES_HOURS provides two synthetic
        // baselines (0.0.0 and 0.1.0) satisfying baseline_count=2, so the
        // install proceeds normally.  The "safe to remove" message must NOT
        // fire because the exemption was not in play — only the "ignoring
        // for current version" message should appear.
        let _base_env = EnvVarGuard::set("GYRSEEK_TEST_FORCE_BASELINE_AGES_HOURS", "1000,1000");

        let runner = MockRunner {
            traces: HashMap::from([
                (
                    ("new-pkg".to_string(), "2.0.0".to_string()),
                    "sin_addr=inet_addr(\"1.2.3.4\")".to_string(),
                ),
                (
                    ("new-pkg".to_string(), "0.0.0".to_string()),
                    "sin_addr=inet_addr(\"1.2.3.4\")".to_string(),
                ),
                (
                    ("new-pkg".to_string(), "0.1.0".to_string()),
                    "sin_addr=inet_addr(\"1.2.3.4\")".to_string(),
                ),
            ]),
        };

        let policy = PolicyConfig {
            baseline_count: 2,
            new_package_exemptions: [("new-pkg".to_string(), "1.0.0".to_string())]
                .into_iter()
                .collect(),
            ..PolicyConfig::default()
        };

        let results = scan_packages_versions(
            &runner,
            "pip",
            &[("new-pkg".to_string(), "2.0.0".to_string())],
            &policy,
        )
        .await;

        let report = results.get("new-pkg|2.0.0").unwrap();
        assert!(
            report.allowed,
            "must be allowed when exemption version does not match but baselines suffice"
        );
    }

    #[tokio::test]
    async fn new_package_exemption_mismatch_no_baselines_blocks() {
        // Exemption is pinned to 1.0.0, installing 2.0.0 (doesn't match).
        // Zero fetched baselines, so baseline_count=2 is not satisfied.
        // Should block — exercises the else-if branch where exemption
        // does not match AND baselines are insufficient.
        let _env = EnvVarGuard::set("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0");

        let runner = MockRunner {
            traces: HashMap::from([(("new-pkg".to_string(), "2.0.0".to_string()), "".to_string())]),
        };

        let policy = PolicyConfig {
            baseline_count: 2,
            new_package_exemptions: [("new-pkg".to_string(), "1.0.0".to_string())]
                .into_iter()
                .collect(),
            ..PolicyConfig::default()
        };

        let results = scan_packages_versions(
            &runner,
            "pip",
            &[("new-pkg".to_string(), "2.0.0".to_string())],
            &policy,
        )
        .await;

        let report = results.get("new-pkg|2.0.0").unwrap();
        assert!(
            !report.allowed,
            "must block when exemption version does not match and baselines are insufficient"
        );
        assert_eq!(
            report.blocked_reasons,
            vec!["insufficient_baselines".to_string()]
        );
    }

    #[tokio::test]
    async fn new_package_exemption_tgt_version_no_longer_checked() {
        // Before the fix, exempt_version == tgt_version let an exemption
        // pinned to any string bypass the baseline check whenever
        // tgt_version happened to match (e.g. "latest" == "latest").
        // Now only v_curr (the resolved version) is compared, so an
        // exemption set to an impossible version string has no effect.
        //
        // Test env: env-var shortcuts keep v_curr == tgt_version, but we
        // verify the exemption value "latest" does not match a pinned
        // version "1.0.0".
        let _env = EnvVarGuard::set("GYRSEEK_TEST_FORCE_RELEASES_LAST_24H", "0");

        let runner = MockRunner {
            traces: HashMap::from([(("new-pkg".to_string(), "1.0.0".to_string()), "".to_string())]),
        };

        let policy = PolicyConfig {
            baseline_count: 2,
            new_package_exemptions: [("new-pkg".to_string(), "latest".to_string())]
                .into_iter()
                .collect(),
            ..PolicyConfig::default()
        };

        let results = scan_packages_versions(
            &runner,
            "pip",
            &[("new-pkg".to_string(), "1.0.0".to_string())],
            &policy,
        )
        .await;

        let report = results.get("new-pkg|1.0.0").unwrap();
        assert!(
            !report.allowed,
            "exemption for literal 'latest' must not match resolved version '1.0.0'"
        );
        assert_eq!(
            report.blocked_reasons,
            vec!["insufficient_baselines".to_string()]
        );
    }

    #[tokio::test]
    async fn new_package_exemption_matches_sufficient_baselines_allows_clean() {
        // Exemption matches the current version (1.0.0), baselines suffice
        // (2 provided via GYRSEEK_TEST_FORCE_BASELINE_AGES_HOURS), and
        // there are no anomalies.  The "safe to remove" message fires (not
        // testable in stdout) and the install is allowed.
        let _base_env = EnvVarGuard::set("GYRSEEK_TEST_FORCE_BASELINE_AGES_HOURS", "1000,1000");

        let runner = MockRunner {
            traces: HashMap::from([
                (
                    ("new-pkg".to_string(), "1.0.0".to_string()),
                    "sin_addr=inet_addr(\"1.2.3.4\")".to_string(),
                ),
                (
                    ("new-pkg".to_string(), "0.0.0".to_string()),
                    "sin_addr=inet_addr(\"1.2.3.4\")".to_string(),
                ),
                (
                    ("new-pkg".to_string(), "0.1.0".to_string()),
                    "sin_addr=inet_addr(\"1.2.3.4\")".to_string(),
                ),
            ]),
        };

        let policy = PolicyConfig {
            baseline_count: 2,
            new_package_exemptions: [("new-pkg".to_string(), "1.0.0".to_string())]
                .into_iter()
                .collect(),
            ..PolicyConfig::default()
        };

        let results = scan_packages_versions(
            &runner,
            "pip",
            &[("new-pkg".to_string(), "1.0.0".to_string())],
            &policy,
        )
        .await;

        let report = results.get("new-pkg|1.0.0").unwrap();
        assert!(
            report.allowed,
            "exemption matches and baselines suffice — must be allowed"
        );
        assert!(
            report.blocked_reasons.is_empty(),
            "no anomalies, so no blocked reasons"
        );
    }

    #[test]
    fn test_is_harness_command_env() {
        assert!(is_harness_command(
            "env",
            &[
                "HOME=/work".to_string(),
                "uv".to_string(),
                "pip".to_string(),
                "install".to_string(),
                "--target".to_string(),
                "/work/foo".to_string()
            ]
        ));
        assert!(!is_harness_command(
            "env",
            &[
                "HOME=/work".to_string(),
                "uv".to_string(),
                "pip".to_string(),
                "install".to_string(),
                "malware".to_string()
            ]
        ));
        assert!(is_harness_command(
            "env",
            &[
                "HOME=/work".to_string(),
                "npm".to_string(),
                "install".to_string(),
                "--prefix".to_string(),
                "/work/foo".to_string()
            ]
        ));
        assert!(!is_harness_command(
            "env",
            &[
                "HOME=/work".to_string(),
                "npm".to_string(),
                "install".to_string(),
                "malware".to_string()
            ]
        ));
        assert!(is_harness_command(
            "env",
            &[
                "HOME=/work".to_string(),
                "pnpm".to_string(),
                "add".to_string(),
                "pkg@1.0".to_string(),
                "--dir".to_string(),
                "/work".to_string()
            ]
        ));
        assert!(!is_harness_command(
            "env",
            &[
                "HOME=/work".to_string(),
                "pnpm".to_string(),
                "add".to_string(),
                "malware".to_string()
            ]
        ));
    }

    #[test]
    fn test_extract_sensitive_file_reads_at_fdcwd_and_minus_100() {
        // Test that -100 and AT_FDCWD are ignored as dirfds
        let trace = "123 openat(-100, \"/etc/passwd\", O_RDONLY) = 3\\n\\\n                     124 openat(AT_FDCWD, \"/etc/shadow\", O_RDONLY) = 4\\n";
        let reads = extract_sensitive_file_reads(trace);
        println!("READS: {:?}", reads);
        assert!(reads.contains("/etc/passwd"));
        assert!(reads.contains("/etc/shadow"));
    }

    #[test]
    fn test_extract_sensitive_file_reads_symlinkat_linkat() {
        // Test symlinkat and linkat properly extract strings and apply rules
        let trace = "123 symlinkat(\"/etc/passwd\", 5, \"/work/malware\") = 0\\n\\\n                     124 linkat(AT_FDCWD, \"/etc/shadow\", AT_FDCWD, \"/work/bad\", 0) = 0\\n";
        let reads = extract_sensitive_file_reads(trace);
        println!("READS: {:?}", reads);
        // symlinkat target is evaluated
        assert!(reads.contains("/etc/passwd"));
        // linkat oldpath is evaluated
        assert!(reads.contains("/etc/shadow"));
    }

    #[test]
    fn test_strict_allowlist_suffix_boundaries() {
        let reads = vec![
            "/.env".to_string(),
            "/path/to/.env".to_string(),
            "/path/to/backup.env".to_string(),
        ];
        let mut allowlist = std::collections::HashSet::new();
        allowlist.insert("*.env".to_string());

        let mut allowlist_map = std::collections::HashMap::new();
        allowlist_map.insert("test-pkg".to_string(), allowlist);

        let (blocked, allowed) =
            filter_allowlisted_sensitive_reads("test-pkg", reads, &allowlist_map);

        // /.env and /path/to/.env should be allowed
        assert!(allowed.contains(&"/.env".to_string()));
        assert!(allowed.contains(&"/path/to/.env".to_string()));

        // /path/to/backup.env should be blocked because the suffix is .env but it's not preceded by a slash
        assert!(blocked.contains(&"/path/to/backup.env".to_string()));
    }

    #[test]
    fn check_override_ages_warnings() {
        use chrono::TimeZone;
        let now = Utc.with_ymd_and_hms(2023, 1, 5, 12, 0, 0).unwrap();
        let mut published_at = std::collections::HashMap::new();
        // 10 hours old
        published_at.insert("1.0.0".to_string(), now - chrono::Duration::hours(10));
        // 48 hours old
        published_at.insert("1.1.0".to_string(), now - chrono::Duration::hours(48));
        // Exactly 24 hours old (boundary — should NOT warn)
        published_at.insert("1.2.0".to_string(), now - chrono::Duration::hours(24));

        let overrides = (Some("1.0.0".to_string()), Some("1.1.0".to_string()));

        let (warnings, filtered) =
            super::check_override_ages("pkg", Some(&overrides), &published_at, now);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("is only 10 hours old"));
        // 1.0.0 is too young (10h < 24h), so filtered_out; 1.1.0 is old enough (48h), kept
        assert_eq!(filtered, Some((None, Some("1.1.0".to_string()))));

        // Exactly 24h boundary: should NOT warn
        let boundary = (Some("1.2.0".to_string()), None);
        let (warnings4, filtered4) =
            super::check_override_ages("pkg", Some(&boundary), &published_at, now);
        assert!(
            warnings4.is_empty(),
            "exactly 24h must not produce a warning, got: {:?}",
            warnings4
        );
        assert_eq!(filtered4, Some((Some("1.2.0".to_string()), None)));

        let missing = (Some("9.9.9".to_string()), None);
        let (warnings2, filtered2) =
            super::check_override_ages("pkg", Some(&missing), &published_at, now);
        assert_eq!(warnings2.len(), 1);
        assert!(warnings2[0].contains("could not be found in the registry history"));
        assert_eq!(filtered2, Some((None, None)));

        let ok_overrides = (Some("1.1.0".to_string()), None);
        let (warnings3, filtered3) =
            super::check_override_ages("pkg", Some(&ok_overrides), &published_at, now);
        assert!(warnings3.is_empty());
        assert_eq!(filtered3, Some((Some("1.1.0".to_string()), None)));
    }

    #[test]
    fn check_override_ages_none_overrides_returns_none() {
        // When no overrides are provided, the function must return an empty
        // warning vec and None for the filtered overrides — callers rely on
        // this to distinguish "no overrides configured" from "all overrides
        // were stripped".
        use chrono::TimeZone;
        let now = Utc.with_ymd_and_hms(2023, 1, 5, 12, 0, 0).unwrap();
        let published_at = std::collections::HashMap::new();

        let (warnings, filtered) = super::check_override_ages("pkg", None, &published_at, now);
        assert!(warnings.is_empty(), "no overrides → no warnings");
        assert_eq!(filtered, None, "no overrides → filtered is None");
    }

    #[test]
    fn check_override_ages_both_overrides_too_young() {
        // Both m1 and m2 are only 5h old — both should produce a warning and
        // be set to None in the filtered output.
        use chrono::TimeZone;
        let now = Utc.with_ymd_and_hms(2023, 1, 5, 12, 0, 0).unwrap();
        let mut published_at = std::collections::HashMap::new();
        published_at.insert("1.0.0".to_string(), now - chrono::Duration::hours(5));
        published_at.insert("1.0.1".to_string(), now - chrono::Duration::hours(3));

        let overrides = (Some("1.0.0".to_string()), Some("1.0.1".to_string()));
        let (warnings, filtered) =
            super::check_override_ages("mypkg", Some(&overrides), &published_at, now);

        assert_eq!(warnings.len(), 2, "both overrides too young → two warnings");
        assert!(warnings.iter().any(|w| w.contains("1.0.0")));
        assert!(warnings.iter().any(|w| w.contains("1.0.1")));
        assert_eq!(
            filtered,
            Some((None, None)),
            "both too young → both filtered to None"
        );
    }

    #[test]
    fn check_override_ages_both_overrides_old_enough() {
        // Both m1 and m2 exceed the 24h hard minimum — no warnings and both
        // versions are preserved in the filtered output.
        use chrono::TimeZone;
        let now = Utc.with_ymd_and_hms(2023, 1, 5, 12, 0, 0).unwrap();
        let mut published_at = std::collections::HashMap::new();
        published_at.insert("2.0.0".to_string(), now - chrono::Duration::hours(48));
        published_at.insert("2.1.0".to_string(), now - chrono::Duration::hours(72));

        let overrides = (Some("2.0.0".to_string()), Some("2.1.0".to_string()));
        let (warnings, filtered) =
            super::check_override_ages("mypkg", Some(&overrides), &published_at, now);

        assert!(warnings.is_empty(), "both old enough → no warnings");
        assert_eq!(
            filtered,
            Some((Some("2.0.0".to_string()), Some("2.1.0".to_string()))),
            "both old enough → both kept"
        );
    }

    #[test]
    fn check_override_ages_23h59m_is_too_young() {
        // Strict `<` boundary: 23h 59m (= 23h in num_hours(), rounds down) is
        // treated as 23 hours old which is < 24, so it must warn and be
        // filtered out.  This is one minute short of the exact boundary that
        // the `== 24` case already tests above.
        use chrono::TimeZone;
        let now = Utc.with_ymd_and_hms(2023, 1, 5, 12, 0, 0).unwrap();
        let mut published_at = std::collections::HashMap::new();
        // 23 hours and 59 minutes → num_hours() returns 23
        published_at.insert(
            "1.0.0".to_string(),
            now - chrono::Duration::minutes(23 * 60 + 59),
        );

        let overrides = (Some("1.0.0".to_string()), None);
        let (warnings, filtered) =
            super::check_override_ages("pkg", Some(&overrides), &published_at, now);

        assert_eq!(
            warnings.len(),
            1,
            "23h 59m must warn (< 24h hard minimum), got: {:?}",
            warnings
        );
        assert!(warnings[0].contains("is only 23 hours old"));
        assert_eq!(filtered, Some((None, None)));
    }

    #[test]
    fn filter_override_version_old_enough_passes() {
        use chrono::TimeZone;
        let now = Utc.with_ymd_and_hms(2023, 1, 10, 12, 0, 0).unwrap();
        let mut published_at = std::collections::HashMap::new();
        published_at.insert("1.0.0".to_string(), now - chrono::Duration::hours(48));
        let mut warnings = Vec::new();
        let result =
            super::filter_override_version("1.0.0", "pkg", &published_at, now, &mut warnings);
        assert_eq!(result, Some("1.0.0"));
        assert!(warnings.is_empty());
    }

    #[test]
    fn filter_override_version_too_young_warns() {
        use chrono::TimeZone;
        let now = Utc.with_ymd_and_hms(2023, 1, 10, 12, 0, 0).unwrap();
        let mut published_at = std::collections::HashMap::new();
        published_at.insert("1.0.0".to_string(), now - chrono::Duration::hours(5));
        let mut warnings = Vec::new();
        let result =
            super::filter_override_version("1.0.0", "pkg", &published_at, now, &mut warnings);
        assert_eq!(result, None);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("is only 5 hours old"));
    }

    #[test]
    fn filter_override_version_exact_boundary_passes() {
        use chrono::TimeZone;
        let now = Utc.with_ymd_and_hms(2023, 1, 10, 12, 0, 0).unwrap();
        let mut published_at = std::collections::HashMap::new();
        published_at.insert("1.0.0".to_string(), now - chrono::Duration::hours(24));
        let mut warnings = Vec::new();
        let result =
            super::filter_override_version("1.0.0", "pkg", &published_at, now, &mut warnings);
        assert_eq!(result, Some("1.0.0"));
        assert!(
            warnings.is_empty(),
            "exactly 24h must pass, got: {:?}",
            warnings
        );
    }

    #[test]
    fn filter_override_version_not_found_warns() {
        use chrono::TimeZone;
        let now = Utc.with_ymd_and_hms(2023, 1, 10, 12, 0, 0).unwrap();
        let published_at = std::collections::HashMap::new();
        let mut warnings = Vec::new();
        let result =
            super::filter_override_version("9.9.9", "pkg", &published_at, now, &mut warnings);
        assert_eq!(result, None);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("could not be found in the registry history"));
    }

    #[test]
    fn filter_override_version_accumulates_warnings() {
        use chrono::TimeZone;
        let now = Utc.with_ymd_and_hms(2023, 1, 10, 12, 0, 0).unwrap();
        let mut published_at = std::collections::HashMap::new();
        published_at.insert("1.0.0".to_string(), now - chrono::Duration::hours(5));
        published_at.insert("2.0.0".to_string(), now - chrono::Duration::hours(3));
        let mut warnings = Vec::new();
        // First call adds a warning
        assert!(
            super::filter_override_version("1.0.0", "pkg", &published_at, now, &mut warnings)
                .is_none()
        );
        // Second call appends to the same vec
        assert!(
            super::filter_override_version("2.0.0", "pkg", &published_at, now, &mut warnings)
                .is_none()
        );
        assert_eq!(warnings.len(), 2);
        assert!(warnings[0].contains("1.0.0"));
        assert!(warnings[1].contains("2.0.0"));
    }

    #[test]
    fn active_test_env_vars_none_set_returns_empty() {
        let _lock = env_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let active = super::active_test_env_vars();
        assert!(
            active.is_empty(),
            "expected no active test env vars, got: {:?}",
            active
        );
    }

    #[test]
    fn active_test_env_vars_set_var_is_detected() {
        let _g = EnvVarGuard::set("GYRSEEK_TEST_ECHO_MIN_BASELINE_AGE_HOURS", "1");
        let active = super::active_test_env_vars();
        assert!(active.contains(&"GYRSEEK_TEST_ECHO_MIN_BASELINE_AGE_HOURS"));
    }

    #[tokio::test]
    async fn scan_packages_versions_uses_default_min_baseline_age_hours_when_empty() {
        let mut traces = std::collections::HashMap::new();
        traces.insert(
            ("dummy".to_string(), "1.0".to_string()),
            "execve(\"/bin/ls\", [\"ls\"], 0x7ffd5340 /* 10 vars */) = 0".to_string(),
        );
        traces.insert(
            (
                "dummy".to_string(),
                format!("{}_echo1", super::DEFAULT_MIN_BASELINE_AGE_HOURS),
            ),
            "execve(\"/bin/ls\", [\"ls\"], 0x7ffd5340 /* 10 vars */) = 0".to_string(),
        );
        traces.insert(
            (
                "dummy".to_string(),
                format!("{}_echo2", super::DEFAULT_MIN_BASELINE_AGE_HOURS),
            ),
            "execve(\"/bin/ls\", [\"ls\"], 0x7ffd5340 /* 10 vars */) = 0".to_string(),
        );

        let runner = MockRunner { traces };
        let policy = crate::PolicyConfig {
            min_baseline_age_hours_by_package: std::collections::HashMap::new(),
            ..crate::PolicyConfig::default()
        };

        let _env = EnvVarGuard::set("GYRSEEK_TEST_ECHO_MIN_BASELINE_AGE_HOURS", "1");

        let mut results = scan_packages_versions(
            &runner,
            "pip",
            &[("dummy".to_string(), "1.0".to_string())],
            &policy,
        )
        .await;

        let report = results.remove("dummy|1.0").expect("Report should exist");
        assert!(
            report.allowed,
            "Should be allowed; if it blocked for missing_baseline_trace, it means the echoed baseline age did not match the expected default."
        );
    }

    #[test]
    fn exemption_behavior_no_exemption_returns_false_empty() {
        let (is_exempt, msgs) = super::exemption_behavior(None, "1.0.0", 0, 2, "pkg");
        assert!(!is_exempt, "no exemption → not exempt");
        assert!(msgs.is_empty(), "no exemption → no messages");
    }

    #[test]
    fn exemption_behavior_match_version_exempt() {
        let (is_exempt, msgs) = super::exemption_behavior(Some("1.0.0"), "1.0.0", 0, 2, "pkg");
        assert!(is_exempt, "version match → exempt");
        assert!(
            msgs.is_empty(),
            "version match + insufficient baselines → no messages"
        );
    }

    #[test]
    fn exemption_behavior_mismatch_version_not_exempt() {
        let (is_exempt, msgs) = super::exemption_behavior(Some("1.0.0"), "2.0.0", 0, 2, "pkg");
        assert!(!is_exempt, "version mismatch → not exempt");
        assert_eq!(msgs.len(), 1, "version mismatch → one info message");
        assert!(msgs[0].contains("ignoring for current version"));
    }

    #[test]
    fn exemption_behavior_sufficient_baselines_prints_cleanup() {
        let (is_exempt, msgs) = super::exemption_behavior(Some("1.0.0"), "1.0.0", 3, 2, "pkg");
        assert!(is_exempt, "version match → exempt");
        assert_eq!(msgs.len(), 1, "sufficient baselines → one message");
        assert!(msgs[0].contains("safely remove it from your configuration"));
    }

    #[test]
    fn exemption_behavior_zero_baseline_count_always_fires() {
        // When baseline_count is 0, the `>=` comparison always considers
        // baselines sufficient even with 0 baselines.
        let (is_exempt, msgs) = super::exemption_behavior(Some("1.0.0"), "1.0.0", 0, 0, "pkg");
        assert!(is_exempt, "version match → exempt");
        assert_eq!(
            msgs.len(),
            1,
            "baseline_count=0 → always triggers cleanup message"
        );
        assert!(msgs[0].contains("safely remove it from your configuration"));
    }

    #[tokio::test]
    async fn scan_packages_versions_discards_overrides_when_registry_fails() {
        let _lock = EnvVarGuard::set("GYRSEEK_TEST_LOCK_ONLY", "1");

        // Setup a mock runner with one trace for the current version
        let mut traces = std::collections::HashMap::new();
        traces.insert(
            (
                "gyrseek-test-nonexistent-pkg".to_string(),
                "1.0.0".to_string(),
            ),
            "execve(\"/bin/ls\", [\"ls\"], 0x7ffd5340 /* 10 vars */) = 0".to_string(),
        );
        let runner = MockRunner { traces };

        // Setup policy with an override
        let mut overrides = std::collections::HashMap::new();
        overrides.insert(
            "gyrseek-test-nonexistent-pkg".to_string(),
            (Some("0.9.0".to_string()), None),
        );
        let policy = crate::PolicyConfig {
            baseline_overrides: overrides,
            baseline_count: 2,
            ..crate::PolicyConfig::default()
        };

        // Note: No GYRSEEK_TEST_* env vars are set here, so `active_test_env_vars()` is empty.
        // `fetch_history_with_baselines` will attempt to query PyPI for `gyrseek-test-nonexistent-pkg`.
        // It will fail (404), returning empty `published_at`.
        // The override logic must see empty `published_at` + empty test env vars, emit a warning,
        // discard the override, and fall back to 0 baselines, triggering fail-closed.
        let mut results = scan_packages_versions(
            &runner,
            "pip",
            &[(
                "gyrseek-test-nonexistent-pkg".to_string(),
                "1.0.0".to_string(),
            )],
            &policy,
        )
        .await;

        let report = results
            .remove("gyrseek-test-nonexistent-pkg|1.0.0")
            .expect("Report should exist");
        assert!(
            !report.allowed,
            "Must fail-closed due to insufficient_baselines after discarding the override"
        );
        assert_eq!(
            report.blocked_reasons,
            vec!["insufficient_baselines".to_string()]
        );
    }
    #[test]
    fn check_override_ages_rejects_version_younger_than_24_hours() {
        let mut published_at = HashMap::new();
        let now = chrono::DateTime::parse_from_rfc3339("2024-01-02T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        // 23 hours and 59 minutes old
        published_at.insert(
            "1.0.0".to_string(),
            now - Duration::hours(23) - Duration::minutes(59),
        );

        let overrides: super::BaselineOverrides = (Some("1.0.0".to_string()), None);
        let (warnings, result) =
            super::check_override_ages("pkg", Some(&overrides), &published_at, now);

        assert_eq!(result, Some((None, None)));
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("below the hardcoded security floor"));
    }

    #[test]
    fn check_override_ages_accepts_version_24_hours_or_older() {
        let mut published_at = HashMap::new();
        let now = chrono::DateTime::parse_from_rfc3339("2024-01-02T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        // exactly 24 hours old
        published_at.insert("1.0.0".to_string(), now - Duration::hours(24));

        // 25 hours old
        published_at.insert("2.0.0".to_string(), now - Duration::hours(25));

        let overrides: super::BaselineOverrides =
            (Some("1.0.0".to_string()), Some("2.0.0".to_string()));
        let (warnings, result) =
            super::check_override_ages("pkg", Some(&overrides), &published_at, now);

        assert_eq!(
            result,
            Some((Some("1.0.0".to_string()), Some("2.0.0".to_string())))
        );
        assert!(warnings.is_empty());
    }

    #[test]
    fn extract_dns_map_tcp_recvmsg_dns_response() {
        // TCP DNS: connect to port 53, then recvmsg() with a valid DNS response
        let trace = r#"
connect(6, {sa_family=AF_INET6, sin6_port=htons(53), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2001:4860:4860::8888", &sin6_addr), sin6_scope_id=0}, 28) = 0
recvmsg(6, {msg_name=NULL, msg_namelen=0, msg_iov=[{iov_base="\x00\x44\x00\x00\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00\x03\x66\x6f\x6f\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x8c\xf8\x90\xdf\xc0\x0c\x00\x1c\x00\x01\x00\x00\x01\x2c\x00\x10\x2a\x04\x4e\x42\x00\x94\x00\x00\x00\x00\x00\x00\x00\x00\x02\x23", iov_len=4096}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, 0) = 70
"#;
        let map = extract_dns_map(trace);
        assert_eq!(map.len(), 1);
        let ips = map.get("foo.com").unwrap();
        assert_eq!(ips.len(), 2);
        let ip_strs: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
        assert!(ip_strs.contains(&"140.248.144.223".to_string()));
        assert!(ip_strs.contains(&"2a04:4e42:94::223".to_string()));
    }
}
