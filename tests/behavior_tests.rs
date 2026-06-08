use std::collections::HashSet;

use gyrseek::{enrich_new_connection_domains_with, find_new_connections};

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