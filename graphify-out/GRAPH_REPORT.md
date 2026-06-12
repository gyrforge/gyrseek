# Graph Report - gyrseek  (2026-06-12)

## Corpus Check
- 24 files · ~44,324 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 597 nodes · 1270 edges · 30 communities (23 shown, 7 thin omitted)
- Extraction: 97% EXTRACTED · 3% INFERRED · 0% AMBIGUOUS · INFERRED: 34 edges (avg confidence: 0.82)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `45570ede`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

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
- [[_COMMUNITY_Community 14|Community 14]]
- [[_COMMUNITY_Community 15|Community 15]]
- [[_COMMUNITY_Fail-Closed Policy & Findings|Fail-Closed Policy & Findings]]
- [[_COMMUNITY_Network Anomaly Decision|Network Anomaly Decision]]
- [[_COMMUNITY_Community 18|Community 18]]
- [[_COMMUNITY_Version Flag Tests|Version Flag Tests]]
- [[_COMMUNITY_Community 20|Community 20]]
- [[_COMMUNITY_Community 23|Community 23]]
- [[_COMMUNITY_Community 24|Community 24]]
- [[_COMMUNITY_Community 25|Community 25]]
- [[_COMMUNITY_Community 26|Community 26]]
- [[_COMMUNITY_Community 27|Community 27]]
- [[_COMMUNITY_Community 28|Community 28]]
- [[_COMMUNITY_Community 29|Community 29]]

## God Nodes (most connected - your core abstractions)
1. `String` - 43 edges
2. `scan_packages_versions()` - 40 edges
3. `run()` - 37 edges
4. `rewrite_args_with_pinned_versions()` - 27 edges
5. `String` - 23 edges
6. `HashSet` - 23 edges
7. `extract_process_exec_signatures()` - 23 edges
8. `gyrseek` - 22 edges
9. `String` - 20 edges
10. `Security & Correctness Findings` - 19 edges

## Surprising Connections (you probably didn't know these)
- `In-Run Scan Cache` --references--> `scan_with_cache()`  [INFERRED]
  docs/ARCHITECTURE.md → src/lib.rs
- `run()` --implements--> `Fail-Closed Guarantee`  [INFERRED]
  src/lib.rs → README.md
- `Finding 11: Non-Registry npm Args Trigger package.json Fallback (Open)` --references--> `parse_npm_install_packages_from_args()`  [EXTRACTED]
  docs/FINDINGS.md → src/parsing.rs
- `rewrite_args_with_pinned_versions()` --implements--> `Resolved-Version Pinning`  [INFERRED]
  src/parsing.rs → README.md
- `Sandbox Mode` --references--> `build_runner_from_env()`  [EXTRACTED]
  docs/DEV_GUIDE.md → src/sandbox.rs

## Import Cycles
- 1-file cycle: `tests/forward_fail_closed_tests.rs -> tests/forward_fail_closed_tests.rs`
- 1-file cycle: `src/lib.rs -> src/lib.rs`
- 1-file cycle: `tests/pnpm_routing_tests.rs -> tests/pnpm_routing_tests.rs`
- 1-file cycle: `src/scanning.rs -> src/scanning.rs`
- 1-file cycle: `src/parsing.rs -> src/parsing.rs`

## Hyperedges (group relationships)
- **SandboxRunner backend strategy** — src_sandbox_sandboxrunner, src_sandbox_dockerrunner, src_sandbox_microvmrunner, src_sandbox_hostrunner [INFERRED 0.85]
- **Install-time behavioral signal extraction** — src_scanning_extract_connection_ips, src_scanning_extract_git_clone_signatures, src_scanning_extract_process_exec_signatures [INFERRED 0.85]
- **Scan-then-forward orchestration pipeline** — src_lib_run, src_scanning_scan_packages_versions, src_lib_forward_pinned_command [INFERRED 0.85]
- **Fail-Closed Situations** — docs_findings_finding_1_empty_trace, docs_findings_finding_9_unrecognized_manager, docs_architecture_empty_trace_fail_closed, docs_architecture_fail_closed_policy [EXTRACTED 1.00]
- **Three Behavioral Signal Classes (network/git-clone/watched-process)** — src_scanning_extract_connection_ips, src_scanning_extract_process_exec_signatures, docs_architecture_behavioral_diffing [EXTRACTED 1.00]
- **Binary-Spawning CLI Integration Tests** — cli_burst_exit_tests_exits_with_code_1_release_burst_threshold, forward_fail_closed_tests_forwarding_propagates_host_nonzero_exit_status, lock_routing_tests_poetry_lock_is_routed_to_lockfile_scan, version_flag_tests_version_flag_prints_crate_version_and_exits_zero [EXTRACTED 1.00]

## Communities (30 total, 7 thin omitted)

### Community 0 - "Package Parsing & Version Pinning"
Cohesion: 0.06
Nodes (73): PEP 508 Extras Stripping, Forwarded-Command Version Pinning, Finding 5: Poetry Non-Develop Local Path Leak, Finding 6: PEP 508 Extras Cause PyPI 404, Finding 7: Extras Key Mismatch Breaks Pinning, Resolved-Version Pinning, args(), does_not_pin_npm_package_with_latest_sentinel() (+65 more)

### Community 1 - "Routing, Config & Scan Orchestration"
Cohesion: 0.06
Nodes (67): BaselineOverrideConfig, test: minimum_release_age_package not met exits 1, test: release_burst_threshold triggers exit 1, Fail-Closed Policy, In-Run Scan Cache, Finding 11: Non-Registry npm Args Trigger package.json Fallback (Open), Finding 12: Non-Registry npm Args + No package.json Blocks Install (Open), Finding 9: Unrecognized Managers Forwarded Unscanned (+59 more)

### Community 2 - "Sandbox Backends & Docker/strace"
Cohesion: 0.08
Nodes (57): Box, CAP_SYS_PTRACE for Cross-UID Tracing, Unprivileged-Payload Trace Integrity (strace -u), MicroVM Sandbox Backend (planned hardening), ProbeTrace, announce_seccomp_status(), artifact_scan_steps_inventory_all_files(), artifact_scan_steps_output_to_correct_log() (+49 more)

### Community 3 - "Connection IP Extraction & Filtering"
Cohesion: 0.08
Nodes (28): Finding 10: Self-Referencing Baseline Override (Open), artifact_findings_empty_for_clean_install(), baseline_count_limits_fetched_baselines_without_overrides(), baseline_count_zero_returns_no_effective_baselines(), classify_inventory_benign_pth(), classify_inventory_binary_elf(), classify_inventory_empty_input(), classify_inventory_large_file() (+20 more)

### Community 4 - "Git-Clone & Process-Exec Signatures"
Cohesion: 0.13
Nodes (15): PyPiReleaseFile, artifact_allowlist_matches_exact_finding_and_prefix(), detects_anomalous_new_connection(), detects_new_connection_in_git_clone_simulation(), filter_allowlisted_artifact_findings(), filter_allowlisted_git_clone_signatures(), filter_allowlisted_process_exec_signatures(), find_new_connections() (+7 more)

### Community 5 - "Bun Execution Detection & Exemptions"
Cohesion: 0.11
Nodes (32): Default, Adding a New Supported Command, Policy Config Surface, MutexGuard, Behavioral Diffing, allows_new_bun_when_allowlisted(), allows_when_artifact_findings_match_baseline(), allows_when_bun_behavior_matches_baseline() (+24 more)

### Community 6 - "FCrDNS Allowlist Verification"
Cohesion: 0.15
Nodes (17): Forward-Confirmed Reverse DNS (FCrDNS), Finding 2: PTR-Record Allowlist Bypass, IpAddr, R, Forward-Confirmed Reverse DNS, burst_policy_emits_warning_when_triggered(), burst_policy_warning(), burst_triggered() (+9 more)

### Community 7 - "Registry History & Baseline Selection"
Cohesion: 0.18
Nodes (16): DateTime, age_filter_includes_versions_exactly_at_cutoff(), age_filter_keeps_only_versions_older_than_cutoff(), age_filter_skips_candidates_without_publish_timestamps(), age_filter_still_respects_baseline_count_limit(), burst_count_is_not_inflated_by_created_modified(), count_releases_in_window(), fetch_history_with_baselines() (+8 more)

### Community 8 - "Shai-Hulud Watched-Process Detection"
Cohesion: 0.05
Nodes (39): 1) Build the scanner images, 1. Prerequisites, 2. Build, 2) Use a prebuilt image, 3) Enable prebuilt mode globally (optional), 3. Run your first scan, 4) Verify images are usable, 5) Use pinned image digests (recommended for reproducibility) (+31 more)

### Community 9 - "npm package.json Manifest"
Cohesion: 0.22
Nodes (9): Semantic Version Ordering (semver / PEP 440), Ordering, compare_version_strings(), is_npm_family_manager(), npm_versions_sort_semantically_not_lexically(), pnpm_versions_use_npm_semver_ordering(), pypi_versions_sort_by_pep440_not_lexically(), sort_versions_ascending() (+1 more)

### Community 10 - "Host Command Forwarding"
Cohesion: 0.11
Nodes (17): Build and Test, Developer Guide, just Task Runner, Local Setup, Practical Review Checklist, Required Change Hygiene, Sandbox Mode, Sandbox Security & Hardening (+9 more)

### Community 11 - "Domain Allowlist & DNS Enrichment"
Cohesion: 0.10
Nodes (32): Behavioral Diffing Across Versions, Shai-Hulud Attack Class, Watched-Process Execution Detection, Finding 3: Argv Regex Truncation at ], Direct Git Clone Runtime Interception, HashSet, Shai-Hulud Attack, case_1_new_bun_is_flagged_against_clean_baseline() (+24 more)

### Community 12 - "Burst/Release-Age CLI Tests"
Cohesion: 0.09
Nodes (18): Command, NamedTempFile, Output, Path, exits_with_code_1_and_uses_configured_release_burst_window_hours(), exits_with_code_1_and_warning_when_release_burst_threshold_triggers(), exits_with_code_1_when_minimum_release_age_package_is_not_met(), minimum_release_age_package_runs_before_burst_threshold() (+10 more)

### Community 13 - "Fail-Closed Forwarding Tests"
Cohesion: 0.14
Nodes (17): Cloud Metadata IP Exemption (169.254.169.254), Sandbox-Local IP Filtering, extract_connection_ips(), extract_connection_ips_captures_ipv4(), extract_connection_ips_captures_ipv6_inet_pton(), extract_connection_ips_collapses_ipv4_mapped_ipv6(), extract_connection_ips_drops_loopback_link_local_and_private(), extract_connection_ips_handles_mixed_v4_and_v6() (+9 more)

### Community 14 - "Community 14"
Cohesion: 0.15
Nodes (11): Architecture, Core Components, Current Limitations, Decision Model, Docker Sandbox Security, Goal, Internal Package Exemption, Main Files (+3 more)

### Community 15 - "Community 15"
Cohesion: 0.29
Nodes (6): Agents Memory and Workflow, graphify, Mandatory Update Policy (After Every Change), Purpose, Quick Post-Change Checklist, Repository Memory

### Community 16 - "Fail-Closed Policy & Findings"
Cohesion: 0.07
Nodes (28): Empty-Trace Hard Error, Finding 10 — Critical | `scanning.rs:654` | ⚠️ Open, Finding 11 — High | `parsing.rs:468` | ⚠️ Open, Finding 12 — High | `lib.rs:1021` | ⚠️ Open, Finding 13 — Medium | `scanning.rs:1852` | ✅ Fixed, Finding 14 — Low | `parsing.rs:880` | ⚠️ Open, Finding 1 — Critical | `sandbox.rs:188` | ✅ Fixed, Finding 1: Empty Trace Passes As Clean (+20 more)

### Community 17 - "Network Anomaly Decision"
Cohesion: 0.29
Nodes (6): Agents Memory and Workflow, graphify, Mandatory Update Policy (After Every Change), Purpose, Quick Post-Change Checklist, Repository Memory

### Community 18 - "Community 18"
Cohesion: 0.15
Nodes (12): Backout plan, Docker Hardening Validation Checklist, Files in repo, Platform note, Regression signals to watch for, Scope, Step 1: Baseline sanity (no custom seccomp/apparmor), Step 2: Validate seccomp profile syntax quickly (+4 more)

### Community 20 - "Community 20"
Cohesion: 0.25
Nodes (8): F, dns_enrichment_ignores_unresolved_ips_without_failing(), dns_enrichment_reports_context_and_domain_overlap_matches(), domain_allowlist_does_not_filter_when_lookup_fails(), domain_allowlist_filters_resolved_domains_before_blocking(), domain_allowlist_normalization_matches_case_whitespace_and_trailing_dot(), enrich_new_connection_domains_with(), filter_domain_allowlisted_new_connections_with()

### Community 28 - "Community 28"
Cohesion: 0.20
Nodes (9): Best Practices, Collaboration, Completed, Direct Git Clone Runtime Support, Generated File Comparison Across Versions, Hardening, Mid Term, Near Term (+1 more)

## Knowledge Gaps
- **144 isolated node(s):** `$schema`, `plugin`, `BaselineOverrideConfig`, `Drop`, `ForwardMode` (+139 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **7 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `run()` connect `Routing, Config & Scan Orchestration` to `Package Parsing & Version Pinning`, `Host Command Forwarding`, `Sandbox Backends & Docker/strace`, `Community 14`?**
  _High betweenness centrality (0.226) - this node is a cross-community bridge._
- **Why does `SandboxRunner` connect `Sandbox Backends & Docker/strace` to `Routing, Config & Scan Orchestration`, `Domain Allowlist & DNS Enrichment`?**
  _High betweenness centrality (0.106) - this node is a cross-community bridge._
- **Why does `trace_sandbox_install_matrix()` connect `Domain Allowlist & DNS Enrichment` to `Sandbox Backends & Docker/strace`, `Connection IP Extraction & Filtering`, `Bun Execution Detection & Exemptions`, `Registry History & Baseline Selection`, `Fail-Closed Forwarding Tests`?**
  _High betweenness centrality (0.104) - this node is a cross-community bridge._
- **Are the 7 inferred relationships involving `run()` (e.g. with `test: minimum_release_age_package not met exits 1` and `test: release_burst_threshold triggers exit 1`) actually correct?**
  _`run()` has 7 INFERRED edges - model-reasoned connections that need verification._
- **Are the 2 inferred relationships involving `rewrite_args_with_pinned_versions()` (e.g. with `.forward_pinned_command()` and `Resolved-Version Pinning`) actually correct?**
  _`rewrite_args_with_pinned_versions()` has 2 INFERRED edges - model-reasoned connections that need verification._
- **What connects `$schema`, `plugin`, `BaselineOverrideConfig` to the rest of the system?**
  _146 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Package Parsing & Version Pinning` be split into smaller, more focused modules?**
  _Cohesion score 0.06426906426906427 - nodes in this community are weakly interconnected._