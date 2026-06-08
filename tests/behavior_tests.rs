use std::collections::HashSet;

use gyrseek::{
    enrich_new_connection_domains_with,
    filter_allowlisted_new_connections,
    filter_domain_allowlisted_new_connections_with,
    find_new_connections,
};

#[test]
fn detects_anomalous_new_connection() {
    let ips_curr: HashSet<String> = ["1.1.1.1", "8.8.8.8"]
        .into_iter()
        .map(String::from)
        .collect();
    let baseline_ips: HashSet<String> = ["1.1.1.1"].into_iter().map(String::from).collect();

    let mut new_connections = find_new_connections(&ips_curr, &baseline_ips);
    new_connections.sort();

    assert_eq!(new_connections, vec!["8.8.8.8".to_string()]);
}

#[test]
fn no_anomaly_when_connections_match_baseline() {
    let ips_curr: HashSet<String> = ["1.1.1.1"].into_iter().map(String::from).collect();
    let baseline_ips: HashSet<String> = ["1.1.1.1", "9.9.9.9"]
        .into_iter()
        .map(String::from)
        .collect();

    let new_connections = find_new_connections(&ips_curr, &baseline_ips);
    assert!(new_connections.is_empty());
}

#[test]
fn dns_enrichment_reports_context_and_domain_overlap_matches() {
    let baseline_ips: HashSet<String> = ["1.1.1.1", "9.9.9.9"]
        .into_iter()
        .map(String::from)
        .collect();
    let new_connections = vec!["8.8.8.8".to_string(), "5.5.5.5".to_string()];

    let resolver = |ip: &str| match ip {
        "1.1.1.1" => Some("example.net".to_string()),
        "9.9.9.9" => Some("baseline-only.net".to_string()),
        "8.8.8.8" => Some("example.net".to_string()),
        "5.5.5.5" => Some("new.net".to_string()),
        _ => None,
    };

    let (mut context, mut matches) =
        enrich_new_connection_domains_with(&new_connections, &baseline_ips, resolver);
    context.sort();
    matches.sort();

    assert_eq!(
        context,
        vec![
            "5.5.5.5 -> new.net".to_string(),
            "8.8.8.8 -> example.net".to_string()
        ]
    );
    assert_eq!(matches, vec!["8.8.8.8 -> example.net".to_string()]);
}

#[test]
fn dns_enrichment_ignores_unresolved_ips_without_failing() {
    let baseline_ips: HashSet<String> = ["1.1.1.1"].into_iter().map(String::from).collect();
    let new_connections = vec!["8.8.8.8".to_string()];

    let resolver = |_ip: &str| None;

    let (context, matches) =
        enrich_new_connection_domains_with(&new_connections, &baseline_ips, resolver);

    assert!(context.is_empty());
    assert!(matches.is_empty());
}

#[test]
fn ip_allowlist_filters_new_ips_before_blocking() {
    let new_connections = vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()];
    let ip_allowlist: HashSet<String> = ["1.1.1.1"].into_iter().map(String::from).collect();

    let (mut remaining, mut allowlisted) =
        filter_allowlisted_new_connections(new_connections, &ip_allowlist);
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

    let (mut remaining, mut allowlisted) =
        filter_domain_allowlisted_new_connections_with(new_connections, &domain_allowlist, resolver);
    remaining.sort();
    allowlisted.sort();

    assert_eq!(remaining, vec!["5.5.5.5".to_string()]);
    assert_eq!(allowlisted, vec!["8.8.8.8 -> cdn.example.net".to_string()]);
}

#[test]
fn domain_allowlist_does_not_filter_when_lookup_fails() {
    let new_connections = vec!["8.8.8.8".to_string()];
    let domain_allowlist: HashSet<String> = ["example.net"].into_iter().map(String::from).collect();

    let resolver = |_ip: &str| None;

    let (remaining, allowlisted) =
        filter_domain_allowlisted_new_connections_with(new_connections, &domain_allowlist, resolver);

    assert_eq!(remaining, vec!["8.8.8.8".to_string()]);
    assert!(allowlisted.is_empty());
}

#[test]
fn domain_allowlist_normalization_matches_case_whitespace_and_trailing_dot() {
    let new_connections = vec!["8.8.8.8".to_string()];
    let domain_allowlist: HashSet<String> = [" Example.NET. "]
        .into_iter()
        .map(String::from)
        .collect();

    let resolver = |_ip: &str| Some("CDN.Example.Net.".to_string());

    let (remaining, allowlisted) =
        filter_domain_allowlisted_new_connections_with(new_connections, &domain_allowlist, resolver);

    assert!(remaining.is_empty());
    assert_eq!(allowlisted, vec!["8.8.8.8 -> CDN.Example.Net.".to_string()]);
}

#[test]
fn ip_allowlist_matches_equivalent_ipv6_representations() {
    let new_connections = vec!["2001:0db8:0000:0000:0000:ff00:0042:8329".to_string()];
    let ip_allowlist: HashSet<String> = ["2001:db8::ff00:42:8329"].into_iter().map(String::from).collect();

    let (remaining, allowlisted) =
        filter_allowlisted_new_connections(new_connections, &ip_allowlist);

    assert!(remaining.is_empty());
    assert_eq!(allowlisted, vec!["2001:0db8:0000:0000:0000:ff00:0042:8329".to_string()]);
}