use std::collections::HashSet;

use gyrseek::find_new_connections;

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