# Graph Report - gyrseek  (2026-06-14)

## Corpus Check
- 23 files · ~46,517 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 631 nodes · 1318 edges · 29 communities (22 shown, 7 thin omitted)
- Extraction: 97% EXTRACTED · 3% INFERRED · 0% AMBIGUOUS · INFERRED: 35 edges (avg confidence: 0.82)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `819abb4c`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 12|Community 12]]
- [[_COMMUNITY_Community 13|Community 13]]
- [[_COMMUNITY_Community 14|Community 14]]
- [[_COMMUNITY_Community 15|Community 15]]
- [[_COMMUNITY_Community 16|Community 16]]
- [[_COMMUNITY_Community 17|Community 17]]
- [[_COMMUNITY_Community 19|Community 19]]
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
5. `String` - 25 edges
6. `HashSet` - 23 edges
7. `extract_process_exec_signatures()` - 23 edges
8. `gyrseek` - 21 edges
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
- 1-file cycle: `src/lib.rs -> src/lib.rs`
- 1-file cycle: `tests/pnpm_routing_tests.rs -> tests/pnpm_routing_tests.rs`
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

## Communities (29 total, 7 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.06
Nodes (73): PEP 508 Extras Stripping, Forwarded-Command Version Pinning, Finding 5: Poetry Non-Develop Local Path Leak, Finding 6: PEP 508 Extras Cause PyPI 404, Finding 7: Extras Key Mismatch Breaks Pinning, Resolved-Version Pinning, args(), does_not_pin_npm_package_with_latest_sentinel() (+65 more)

### Community 1 - "Community 1"
Cohesion: 0.05
Nodes (78): BaselineOverrideConfig, test: minimum_release_age_package not met exits 1, test: release_burst_threshold triggers exit 1, Architecture, Core Components, Current Limitations, Decision Model, Docker Sandbox Security (+70 more)

### Community 2 - "Community 2"
Cohesion: 0.07
Nodes (64): Box, CAP_SYS_PTRACE for Cross-UID Tracing, Unprivileged-Payload Trace Integrity (strace -u), MicroVM Sandbox Backend (planned hardening), ProbeTrace, announce_apparmor_status(), announce_seccomp_status(), apparmor_disabled_wont_call_apparmor_parser() (+56 more)

### Community 3 - "Community 3"
Cohesion: 0.06
Nodes (46): Shai-Hulud Attack Class, Watched-Process Execution Detection, Finding 10: Self-Referencing Baseline Override (Open), Shai-Hulud Attack, artifact_findings_empty_for_clean_install(), baseline_count_limits_fetched_baselines_without_overrides(), baseline_count_zero_returns_no_effective_baselines(), case_1_new_bun_is_flagged_against_clean_baseline() (+38 more)

### Community 4 - "Community 4"
Cohesion: 0.09
Nodes (38): Behavioral Diffing Across Versions, Finding 3: Argv Regex Truncation at ], Direct Git Clone Runtime Interception, F, HashSet, PyPiReleaseFile, artifact_allowlist_matches_exact_finding_and_prefix(), detects_anomalous_new_connection() (+30 more)

### Community 5 - "Community 5"
Cohesion: 0.14
Nodes (27): Default, Policy Config Surface, Behavioral Diffing, allows_new_bun_when_allowlisted(), allows_when_artifact_findings_match_baseline(), allows_when_bun_behavior_matches_baseline(), artifact_allowlist_unblocks_new_findings(), env_lock() (+19 more)

### Community 6 - "Community 6"
Cohesion: 0.15
Nodes (17): Forward-Confirmed Reverse DNS (FCrDNS), Finding 2: PTR-Record Allowlist Bypass, IpAddr, R, Forward-Confirmed Reverse DNS, burst_policy_emits_warning_when_triggered(), burst_policy_warning(), burst_triggered() (+9 more)

### Community 7 - "Community 7"
Cohesion: 0.18
Nodes (16): DateTime, age_filter_includes_versions_exactly_at_cutoff(), age_filter_keeps_only_versions_older_than_cutoff(), age_filter_skips_candidates_without_publish_timestamps(), age_filter_still_respects_baseline_count_limit(), burst_count_is_not_inflated_by_created_modified(), count_releases_in_window(), fetch_history_with_baselines() (+8 more)

### Community 8 - "Community 8"
Cohesion: 0.05
Nodes (38): 1) Build the scanner images, 1. Prerequisites, 2. Build, 2) Use a prebuilt image, 3) Enable prebuilt mode globally (optional), 3. Run your first scan, 4) Verify images are usable, 5) Use pinned image digests (recommended for reproducibility) (+30 more)

### Community 9 - "Community 9"
Cohesion: 0.22
Nodes (9): Semantic Version Ordering (semver / PEP 440), Ordering, compare_version_strings(), is_npm_family_manager(), npm_versions_sort_semantically_not_lexically(), pnpm_versions_use_npm_semver_ordering(), pypi_versions_sort_by_pep440_not_lexically(), sort_versions_ascending() (+1 more)

### Community 10 - "Community 10"
Cohesion: 0.11
Nodes (18): Adding a New Supported Command, Build and Test, Developer Guide, just Task Runner, Local Setup, Practical Review Checklist, Required Change Hygiene, Sandbox Mode (+10 more)

### Community 11 - "Community 11"
Cohesion: 0.06
Nodes (35): Allowed operations, AppArmor, Backout plan, Capabilities and privileges, Configuration, Configuration, Current hardening limitations, Docker Security (+27 more)

### Community 12 - "Community 12"
Cohesion: 0.10
Nodes (18): Command, NamedTempFile, Output, exits_with_code_1_and_uses_configured_release_burst_window_hours(), exits_with_code_1_and_warning_when_release_burst_threshold_triggers(), exits_with_code_1_when_minimum_release_age_package_is_not_met(), minimum_release_age_package_runs_before_burst_threshold(), run_with_config() (+10 more)

### Community 13 - "Community 13"
Cohesion: 0.14
Nodes (17): Cloud Metadata IP Exemption (169.254.169.254), Sandbox-Local IP Filtering, extract_connection_ips(), extract_connection_ips_captures_ipv4(), extract_connection_ips_captures_ipv6_inet_pton(), extract_connection_ips_collapses_ipv4_mapped_ipv6(), extract_connection_ips_drops_loopback_link_local_and_private(), extract_connection_ips_handles_mixed_v4_and_v6() (+9 more)

### Community 14 - "Community 14"
Cohesion: 0.29
Nodes (6): Agents Memory and Workflow, graphify, Mandatory Update Policy (After Every Change), Purpose, Quick Post-Change Checklist, Repository Memory

### Community 15 - "Community 15"
Cohesion: 0.50
Nodes (3): MutexGuard, EnvVarGuard, Drop

### Community 16 - "Community 16"
Cohesion: 0.07
Nodes (28): Empty-Trace Hard Error, Finding 10 — Critical | `scanning.rs:654` | ⚠️ Open, Finding 11 — High | `parsing.rs:468` | ⚠️ Open, Finding 12 — High | `lib.rs:1021` | ⚠️ Open, Finding 13 — Medium | `scanning.rs:1852` | ✅ Fixed, Finding 14 — Low | `parsing.rs:880` | ⚠️ Open, Finding 1 — Critical | `sandbox.rs:188` | ✅ Fixed, Finding 1: Empty Trace Passes As Clean (+20 more)

### Community 17 - "Community 17"
Cohesion: 0.29
Nodes (6): Agents Memory and Workflow, graphify, Mandatory Update Policy (After Every Change), Purpose, Quick Post-Change Checklist, Repository Memory

### Community 28 - "Community 28"
Cohesion: 0.20
Nodes (9): Best Practices, Collaboration, Completed, Direct Git Clone Runtime Support, Generated File Comparison Across Versions, Hardening, Mid Term, Near Term (+1 more)

## Knowledge Gaps
- **163 isolated node(s):** `$schema`, `plugin`, `BaselineOverrideConfig`, `Drop`, `ForwardMode` (+158 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **7 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `run()` connect `Community 1` to `Community 0`, `Community 10`, `Community 2`?**
  _High betweenness centrality (0.202) - this node is a cross-community bridge._
- **Why does `SandboxRunner` connect `Community 2` to `Community 1`, `Community 4`?**
  _High betweenness centrality (0.103) - this node is a cross-community bridge._
- **Why does `trace_sandbox_install_matrix()` connect `Community 4` to `Community 2`, `Community 3`, `Community 5`, `Community 7`, `Community 13`?**
  _High betweenness centrality (0.103) - this node is a cross-community bridge._
- **Are the 7 inferred relationships involving `run()` (e.g. with `test: minimum_release_age_package not met exits 1` and `test: release_burst_threshold triggers exit 1`) actually correct?**
  _`run()` has 7 INFERRED edges - model-reasoned connections that need verification._
- **Are the 2 inferred relationships involving `rewrite_args_with_pinned_versions()` (e.g. with `.forward_pinned_command()` and `Resolved-Version Pinning`) actually correct?**
  _`rewrite_args_with_pinned_versions()` has 2 INFERRED edges - model-reasoned connections that need verification._
- **What connects `$schema`, `plugin`, `BaselineOverrideConfig` to the rest of the system?**
  _165 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.06426906426906427 - nodes in this community are weakly interconnected._