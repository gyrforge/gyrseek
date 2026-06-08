use std::collections::HashSet;

use gyrseek::find_new_connections;

#[test]
fn detects_new_connection_in_git_clone_simulation() {
    // Simulated network endpoints seen during a clone of a suspicious repo.
    let clone_ips: HashSet<String> = ["140.82.112.3", "185.199.108.133"]
        .into_iter()
        .map(String::from)
        .collect();

    // Baseline endpoints observed for known-safe clone behavior.
    let baseline_ips: HashSet<String> = ["140.82.112.3"].into_iter().map(String::from).collect();

    let mut new_connections = find_new_connections(&clone_ips, &baseline_ips);
    new_connections.sort();

    assert_eq!(new_connections, vec!["185.199.108.133".to_string()]);
}

#[test]
fn no_new_connection_in_git_clone_simulation() {
    let clone_ips: HashSet<String> = ["140.82.112.3"].into_iter().map(String::from).collect();
    let baseline_ips: HashSet<String> = ["140.82.112.3", "140.82.113.3"]
        .into_iter()
        .map(String::from)
        .collect();

    let new_connections = find_new_connections(&clone_ips, &baseline_ips);
    assert!(new_connections.is_empty());
}