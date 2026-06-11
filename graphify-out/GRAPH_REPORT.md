# Graph Report - .  (2026-06-11)

## Corpus Check
- Corpus is ~32,474 words - fits in a single context window. You may not need a graph.

## Summary
- 419 nodes · 991 edges · 30 communities (22 shown, 8 thin omitted)
- Extraction: 97% EXTRACTED · 3% INFERRED · 0% AMBIGUOUS · INFERRED: 34 edges (avg confidence: 0.82)
- Token cost: 206,000 input · 9,200 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Package Parsing & Version Pinning|Package Parsing & Version Pinning]]
- [[_COMMUNITY_Routing, Config & Scan Orchestration|Routing, Config & Scan Orchestration]]
- [[_COMMUNITY_Sandbox Backends & Dockerstrace|Sandbox Backends & Docker/strace]]
- [[_COMMUNITY_Connection IP Extraction & Filtering|Connection IP Extraction & Filtering]]
- [[_COMMUNITY_Git-Clone & Process-Exec Signatures|Git-Clone & Process-Exec Signatures]]
- [[_COMMUNITY_Bun Execution Detection & Exemptions|Bun Execution Detection & Exemptions]]
- [[_COMMUNITY_FCrDNS Allowlist Verification|FCrDNS Allowlist Verification]]
- [[_COMMUNITY_Registry History & Baseline Selection|Registry History & Baseline Selection]]
- [[_COMMUNITY_Shai-Hulud Watched-Process Detection|Shai-Hulud Watched-Process Detection]]
- [[_COMMUNITY_npm package.json Manifest|npm package.json Manifest]]
- [[_COMMUNITY_Host Command Forwarding|Host Command Forwarding]]
- [[_COMMUNITY_Domain Allowlist & DNS Enrichment|Domain Allowlist & DNS Enrichment]]
- [[_COMMUNITY_BurstRelease-Age CLI Tests|Burst/Release-Age CLI Tests]]
- [[_COMMUNITY_Fail-Closed Forwarding Tests|Fail-Closed Forwarding Tests]]
- [[_COMMUNITY_Semantic Version Ordering|Semantic Version Ordering]]
- [[_COMMUNITY_Entry Point & Agent Docs|Entry Point & Agent Docs]]
- [[_COMMUNITY_Fail-Closed Policy & Findings|Fail-Closed Policy & Findings]]
- [[_COMMUNITY_Network Anomaly Decision|Network Anomaly Decision]]
- [[_COMMUNITY_Developer Guide & just|Developer Guide & just]]
- [[_COMMUNITY_Community 23|Community 23]]
- [[_COMMUNITY_Community 24|Community 24]]
- [[_COMMUNITY_Community 25|Community 25]]
- [[_COMMUNITY_Community 26|Community 26]]
- [[_COMMUNITY_Community 27|Community 27]]
- [[_COMMUNITY_Community 28|Community 28]]
- [[_COMMUNITY_Community 29|Community 29]]

## God Nodes (most connected - your core abstractions)
1. `String` - 41 edges
2. `run()` - 35 edges
3. `scan_packages_versions()` - 35 edges
4. `rewrite_args_with_pinned_versions()` - 25 edges
5. `HashSet` - 22 edges
6. `String` - 20 edges
7. `String` - 19 edges
8. `extract_process_exec_signatures()` - 17 edges
9. `GyrSeek` - 16 edges
10. `String` - 16 edges

## Surprising Connections (you probably didn't know these)
- `In-Run Scan Cache` --references--> `scan_with_cache()`  [INFERRED]
  docs/ARCHITECTURE.md → src/lib.rs
- `Finding 12: Non-Registry npm Args + No package.json Blocks Install (Open)` --references--> `run()`  [EXTRACTED]
  docs/FINDINGS.md → src/lib.rs
- `Finding 9: Unrecognized Managers Forwarded Unscanned` --references--> `run()`  [EXTRACTED]
  docs/FINDINGS.md → src/lib.rs
- `run()` --implements--> `Fail-Closed Guarantee`  [INFERRED]
  src/lib.rs → README.md
- `rewrite_args_with_pinned_versions()` --implements--> `Resolved-Version Pinning`  [INFERRED]
  src/parsing.rs → README.md

## Import Cycles
- 1-file cycle: `src/lib.rs -> src/lib.rs`
- 1-file cycle: `src/scanning.rs -> src/scanning.rs`
- 1-file cycle: `src/parsing.rs -> src/parsing.rs`
- 1-file cycle: `tests/forward_fail_closed_tests.rs -> tests/forward_fail_closed_tests.rs`

## Hyperedges (group relationships)
- **SandboxRunner backend strategy** — src_sandbox_sandboxrunner, src_sandbox_dockerrunner, src_sandbox_microvmrunner, src_sandbox_hostrunner [INFERRED 0.85]
- **Install-time behavioral signal extraction** — src_scanning_extract_connection_ips, src_scanning_extract_git_clone_signatures, src_scanning_extract_process_exec_signatures [INFERRED 0.85]
- **Scan-then-forward orchestration pipeline** — src_lib_run, src_scanning_scan_packages_versions, src_lib_forward_pinned_command [INFERRED 0.85]
- **Fail-Closed Situations** — docs_findings_finding_1_empty_trace, docs_findings_finding_9_unrecognized_manager, docs_architecture_empty_trace_fail_closed, docs_architecture_fail_closed_policy [EXTRACTED 1.00]
- **Three Behavioral Signal Classes (network/git-clone/watched-process)** — src_scanning_extract_connection_ips, src_scanning_extract_process_exec_signatures, docs_architecture_behavioral_diffing [EXTRACTED 1.00]
- **Binary-Spawning CLI Integration Tests** — cli_burst_exit_tests_exits_with_code_1_release_burst_threshold, forward_fail_closed_tests_forwarding_propagates_host_nonzero_exit_status, lock_routing_tests_poetry_lock_is_routed_to_lockfile_scan, version_flag_tests_version_flag_prints_crate_version_and_exits_zero [EXTRACTED 1.00]

## Communities (30 total, 8 thin omitted)

### Community 0 - "Package Parsing & Version Pinning"
Cohesion: 0.07
Nodes (70): PEP 508 Extras Stripping, Forwarded-Command Version Pinning, Finding 11: Non-Registry npm Args Trigger package.json Fallback (Open), Finding 12: Non-Registry npm Args + No package.json Blocks Install (Open), Finding 5: Poetry Non-Develop Local Path Leak, Finding 6: PEP 508 Extras Cause PyPI 404, Finding 7: Extras Key Mismatch Breaks Pinning, Resolved-Version Pinning (+62 more)

### Community 1 - "Routing, Config & Scan Orchestration"
Cohesion: 0.08
Nodes (57): BaselineOverrideConfig, test: minimum_release_age_package not met exits 1, test: release_burst_threshold triggers exit 1, In-Run Scan Cache, test: bare uv lock routed to lockfile scan, test: bare poetry lock routed to lockfile scan, NamedTempFile, PolicyConfig (+49 more)

### Community 2 - "Sandbox Backends & Docker/strace"
Cohesion: 0.12
Nodes (41): Box, CAP_SYS_PTRACE for Cross-UID Tracing, Unprivileged-Payload Trace Integrity (strace -u), Sandbox Mode Selection (GYRSEEK_SANDBOX), MicroVM Sandbox Backend (planned hardening), ProbeTrace, build_docker_run_args(), build_matrix_script() (+33 more)

### Community 3 - "Connection IP Extraction & Filtering"
Cohesion: 0.09
Nodes (26): Cloud Metadata IP Exemption (169.254.169.254), Sandbox-Local IP Filtering, Finding 10: Self-Referencing Baseline Override (Open), baseline_count_limits_fetched_baselines_without_overrides(), baseline_count_zero_returns_no_effective_baselines(), duplicate_override_versions_are_deduped_and_truncated(), extract_connection_ips(), extract_connection_ips_captures_ipv4() (+18 more)

### Community 4 - "Git-Clone & Process-Exec Signatures"
Cohesion: 0.12
Nodes (27): Behavioral Diffing Across Versions, Finding 3: Argv Regex Truncation at ], Direct Git Clone Runtime Interception, HashSet, PyPiReleaseFile, default_watched_executables(), default_watched_set_includes_bun_and_deno(), domain_is_allowlisted() (+19 more)

### Community 5 - "Bun Execution Detection & Exemptions"
Cohesion: 0.15
Nodes (25): Default, Adding a New Supported Command, Policy Config Surface, Mutex, Behavioral Diffing, allows_new_bun_when_allowlisted(), allows_when_bun_behavior_matches_baseline(), env_lock() (+17 more)

### Community 6 - "FCrDNS Allowlist Verification"
Cohesion: 0.15
Nodes (17): Forward-Confirmed Reverse DNS (FCrDNS), Finding 2: PTR-Record Allowlist Bypass, IpAddr, R, Forward-Confirmed Reverse DNS, burst_policy_emits_warning_when_triggered(), burst_policy_warning(), burst_triggered() (+9 more)

### Community 7 - "Registry History & Baseline Selection"
Cohesion: 0.18
Nodes (16): DateTime, age_filter_includes_versions_exactly_at_cutoff(), age_filter_keeps_only_versions_older_than_cutoff(), age_filter_skips_candidates_without_publish_timestamps(), age_filter_still_respects_baseline_count_limit(), burst_count_is_not_inflated_by_created_modified(), count_releases_in_window(), fetch_history_with_baselines() (+8 more)

### Community 8 - "Shai-Hulud Watched-Process Detection"
Cohesion: 0.24
Nodes (14): Shai-Hulud Attack Class, Watched-Process Execution Detection, Shai-Hulud Attack, case_1_new_bun_is_flagged_against_clean_baseline(), case_2_existing_bun_plus_additional_invocation_is_flagged(), case_2b_changed_bun_arguments_are_flagged(), extract_process_exec_captures_bun_run_with_argv(), extract_process_exec_ignores_non_watched_executables() (+6 more)

### Community 9 - "npm package.json Manifest"
Cohesion: 0.15
Nodes (12): author, dependencies, lodash, typescript, description, license, main, name (+4 more)

### Community 10 - "Host Command Forwarding"
Cohesion: 0.25
Nodes (8): Test Location Convention (inline vs tests/), Finding 8: Child Exit Status Discarded, test: missing host binary fails closed, test: forwarding preserves host success exit, test: forwarding propagates host non-zero exit, forward_args, forward_original_command, forward_pinned_command

### Community 11 - "Domain Allowlist & DNS Enrichment"
Cohesion: 0.25
Nodes (8): F, dns_enrichment_ignores_unresolved_ips_without_failing(), dns_enrichment_reports_context_and_domain_overlap_matches(), domain_allowlist_does_not_filter_when_lookup_fails(), domain_allowlist_filters_resolved_domains_before_blocking(), domain_allowlist_normalization_matches_case_whitespace_and_trailing_dot(), enrich_new_connection_domains_with(), filter_domain_allowlisted_new_connections_with()

### Community 12 - "Burst/Release-Age CLI Tests"
Cohesion: 0.43
Nodes (7): Output, exits_with_code_1_and_uses_configured_release_burst_window_hours(), exits_with_code_1_and_warning_when_release_burst_threshold_triggers(), exits_with_code_1_when_minimum_release_age_package_is_not_met(), minimum_release_age_package_runs_before_burst_threshold(), run_with_config(), run_with_config_and_env()

### Community 13 - "Fail-Closed Forwarding Tests"
Cohesion: 0.46
Nodes (6): Path, fake_binary(), forwarding_preserves_host_success_exit_status(), forwarding_propagates_host_nonzero_exit_status(), prepend_path(), String

### Community 14 - "Semantic Version Ordering"
Cohesion: 0.29
Nodes (7): Semantic Version Ordering (semver / PEP 440), Ordering, compare_version_strings(), npm_versions_sort_semantically_not_lexically(), pypi_versions_sort_by_pep440_not_lexically(), sort_versions_ascending(), unparseable_versions_sort_below_parseable_ones()

### Community 15 - "Entry Point & Agent Docs"
Cohesion: 0.33
Nodes (5): Agents Memory and Workflow, Mandatory Doc Update Policy, Runtime Entry Flow, Structured Logging Mode (planned), main()

### Community 16 - "Fail-Closed Policy & Findings"
Cohesion: 0.33
Nodes (6): Empty-Trace Hard Error, Fail-Closed Policy, Finding 1: Empty Trace Passes As Clean, Finding 4: || true Suppresses strace Failures, Finding 9: Unrecognized Managers Forwarded Unscanned, Security & Correctness Findings

### Community 17 - "Network Anomaly Decision"
Cohesion: 0.40
Nodes (5): Anomaly Decision Model, Internal Package Exemption, detects_anomalous_new_connection(), detects_new_connection_in_git_clone_simulation(), find_new_connections()

## Knowledge Gaps
- **60 isolated node(s):** `BaselineOverrideConfig`, `Self`, `Box`, `Default`, `Self` (+55 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **8 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `run()` connect `Routing, Config & Scan Orchestration` to `Package Parsing & Version Pinning`, `Sandbox Backends & Docker/strace`, `Host Command Forwarding`, `Entry Point & Agent Docs`, `Fail-Closed Policy & Findings`?**
  _High betweenness centrality (0.272) - this node is a cross-community bridge._
- **Why does `HashSet` connect `Git-Clone & Process-Exec Signatures` to `Routing, Config & Scan Orchestration`, `Connection IP Extraction & Filtering`, `Bun Execution Detection & Exemptions`, `Registry History & Baseline Selection`, `Shai-Hulud Watched-Process Detection`, `Domain Allowlist & DNS Enrichment`, `Network Anomaly Decision`?**
  _High betweenness centrality (0.101) - this node is a cross-community bridge._
- **Why does `trace_sandbox_install_matrix()` connect `Git-Clone & Process-Exec Signatures` to `Sandbox Backends & Docker/strace`, `Connection IP Extraction & Filtering`, `Bun Execution Detection & Exemptions`, `Registry History & Baseline Selection`, `Shai-Hulud Watched-Process Detection`?**
  _High betweenness centrality (0.096) - this node is a cross-community bridge._
- **Are the 7 inferred relationships involving `run()` (e.g. with `test: minimum_release_age_package not met exits 1` and `test: release_burst_threshold triggers exit 1`) actually correct?**
  _`run()` has 7 INFERRED edges - model-reasoned connections that need verification._
- **Are the 2 inferred relationships involving `rewrite_args_with_pinned_versions()` (e.g. with `.forward_pinned_command()` and `Resolved-Version Pinning`) actually correct?**
  _`rewrite_args_with_pinned_versions()` has 2 INFERRED edges - model-reasoned connections that need verification._
- **What connects `BaselineOverrideConfig`, `Self`, `Box` to the rest of the system?**
  _63 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Package Parsing & Version Pinning` be split into smaller, more focused modules?**
  _Cohesion score 0.06590151795631248 - nodes in this community are weakly interconnected._