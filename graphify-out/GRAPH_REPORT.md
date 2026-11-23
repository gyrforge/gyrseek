# Graph Report - gyrseek  (2026-11-23)

## Corpus Check
- 107 files · ~275,040 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 10 file(s) not represented in the graph (top: (none) 6, .npm 1, .python 1)

## Summary
- 2789 nodes · 4585 edges · 213 communities (156 shown, 57 thin omitted)
- Extraction: 95% EXTRACTED · 5% INFERRED · 0% AMBIGUOUS · INFERRED: 241 edges (avg confidence: 0.84)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `2c3aaeb8`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- Review history
- Routing, Config & Scan Orchestration
- Detailed Findings
- scanning.rs
- sandbox.rs
- Bun Execution Detection & Exemptions
- FCrDNS Allowlist Verification
- High Impact
- native.sh
- NonoRunner backend
- run
- Semgrep Quick Reference
- python_multi_package_tests.rs
- Docker Security
- extract_process_exec_signatures
- Code Correctness Rules
- Fail-Closed Policy & Findings
- Network Anomaly Decision
- Detailed Findings
- rewrite_args_with_pinned_versions
- npm/package.json
- index_settings.rs
- runtime_image.rs
- extract_connection_ips
- parse_global_options
- Critical Impact
- parsing.rs
- extract_dns_map
- find_new_connections_domain_aware
- redirects.sh
- gyrseek
- Prevent Insecure Deserialization
- Semgrep Skill
- npm_lockfile_tests.rs
- env
- Code Security Skill
- Prevent Path Traversal
- Prevent Cross-Site Scripting (XSS)
- LLM Security Skill
- Decision Model
- deserialize_new_package_exemptions
- lock_verify.rs
- General Best Practices for Avoiding Race Conditions
- Semgrep Rule Creation Workflow
- collect_probe_traces
- load_policy_config
- build_docker_run_args
- filter_domain_allowlisted_new_connections_with
- Process-Execution Behavior Detection
- Prevent XML External Entity (XXE) Injection
- Part 2: Creating Custom Rules
- .new
- Architecture
- Roadmap
- LockSource
- pnpm/package.json
- Code Best Practices
- terraform-gcp.md
- Categories
- LLM Security Guidelines (OWASP Top 10 for LLM 2025)
- check_phase
- Network Behavior Detection
- Prevent Cross-Site Request Forgery
- Secure Kubernetes Configurations
- Secure Azure Terraform Configurations
- Interrogation
- semgrep/SKILL.md
- Python
- Prevent SQL Injection
- LLM03: Secure LLM Supply Chain
- Ponytail
- Agents Memory and Workflow
- Sandbox Modes
- scan_r
- Post-install artifact detection
- Code Security
- Secure Docker Configurations
- Avoid Insecure Cryptography
- Use Secure Transport
- Prevent Server-Side Request Forgery (SSRF)
- Secure AWS Terraform Configurations
- LLM04: Prevent Data and Model Poisoning
- LLM06: Control Excessive Agency
- LLM09: Mitigate Misinformation and Hallucinations
- LLM05: Secure Output Handling
- LLM02: Prevent Sensitive Information Disclosure
- LLM07: Prevent System Prompt Leakage
- LLM10: Prevent Unbounded Consumption
- LLM08: Secure Vector and Embedding Systems
- Ponytail Help
- Part 1: Running Scans
- Sandbox Infrastructure
- AGENTS.md repository memory
- Prevent Command Injection
- Secure GitHub Actions
- Ensure Memory Safety
- Threat Model & Accepted Risks
- Validation checklist
- Open Findings
- How It Works
- Prebuilt Scanner Images
- InstallFailure
- env_lock
- LLM01: Prevent Prompt Injection
- read_import_run
- Understand Code
- WONT_FIX_FINDINGS_DETAILED.md
- unescape_strace_string
- Pattern Operators
- trace_install_docker_matrix
- .yamllint.yaml
- Prevent Regular Expression DoS (ReDoS)
- ponytail-review/SKILL.md
- AppArmor
- Common Patterns by Vulnerability
- build_runner_from_env
- Configuration
- build_runner_from_env
- forward_fail_closed_tests.rs
- code-injection.md
- decode_dns_name
- Quick Start
- SandboxRunner
- frozen_forward_tests.rs
- Seccomp
- cli_burst_exit_tests.rs
- test
- classify_requirement
- index_redirect_tests.rs
- read_frames
- steps
- sandbox_startup_exit_tests.rs
- name
- Usage
- reviews
- lock_routing_tests.rs
- Feedback
- ForwardMode
- 10. Insecure Cryptography
- 11. Insecure Transport
- 12. Server-Side Request Forgery
- 13. JWT Authentication
- 14. Cross-Site Request Forgery
- 15. Prototype Pollution
- 16. Unsafe Functions
- 17. Terraform AWS Security
- 18. Terraform Azure Security
- 19. Terraform GCP Security
- 1. SQL Injection
- 20. Kubernetes Security
- 21. Docker Security
- 24. Race Conditions
- 25. Code Correctness
- 26. Best Practices
- 27. Performance
- 28. Maintainability
- 2. Command Injection
- 3. Cross-Site Scripting
- 4. XML External Entity
- 5. Path Traversal
- 6. Insecure Deserialization
- 7. Code Injection
- 8. Hardcoded Secrets
- 9. Memory Safety
- authentication-jwt.md
- maintainability.md
- prototype-pollution.md
- _template.md
- unsafe-functions.md
- steps
- copilot-instructions.md
- opencode.json
- with
- cargo-audit
- gyrseek
- test
- parse_npm_lock
- mirror_proxy.py
- Step 6: Validate and Test
- fs
- Step 4: Choose Pattern Operators
- Step 5: Write Taint Rules
- steps
- steps
- steps
- steps
- lockfile-guards.sh
- uses
- read_input
- strings
- Step 2: Create Test Cases First
- Troubleshooting
- on
- scan_with_failing
- build_matrix_script_with
- load_yaml

## God Nodes (most connected - your core abstractions)
1. `Review history` - 240 edges
2. `Won't Fix Findings - Detailed` - 121 edges
3. `Detailed Findings` - 119 edges
4. `scan_packages_versions()` - 55 edges
5. `load()` - 47 edges
6. `run()` - 36 edges
7. `Code Security` - 31 edges
8. `find_new_connections_domain_aware()` - 28 edges
9. `extract_process_exec_signatures()` - 26 edges
10. `gyrseek()` - 25 edges

## Surprising Connections (you probably didn't know these)
- `run()` --implements--> `Fail-closed policy`  [INFERRED]
  src/lib.rs → README.md
- `extract_process_exec_signatures()` --references--> `Shai-Hulud campaign`  [INFERRED]
  src/scanning.rs → README.md
- `forward_confirmed_hostname()` --implements--> `FCrDNS (forward-confirmed reverse DNS)`  [INFERRED]
  src/scanning.rs → README.md
- `rewrite_args_with_pinned_versions()` --implements--> `Exact-version pinning of forwarded command`  [INFERRED]
  src/parsing.rs → README.md
- `test: minimum_release_age_package not met exits 1` --references--> `run()`  [INFERRED]
  tests/cli_burst_exit_tests.rs → src/lib.rs

## Import Cycles
- 1-file cycle: `src/sandbox.rs -> src/sandbox.rs`
- 1-file cycle: `src/scanning.rs -> src/scanning.rs`
- 1-file cycle: `src/lib.rs -> src/lib.rs`

## Hyperedges (group relationships)
- **Docker sandbox hardening layers** — docs_docker_security_sys_ptrace, docs_docker_security_seccomp, docs_docker_security_apparmor, docs_docker_security_unprivileged_payload [EXTRACTED 0.90]
- **Network anomaly domain-aware diff pipeline** — docs_architecture_domain_aware_diff, docs_architecture_fcrdns, docs_architecture_dns_interceptor, docs_architecture_allowlists [EXTRACTED 0.90]
- **Nono detection parity instrumentation** — docs_architecture_canary_trap, docs_architecture_path_shims, docs_architecture_scan_target_artifacts, docs_architecture_nono_runner [EXTRACTED 0.90]
- **Core source modules** — src_main, src_lib, src_parsing, src_scanning, src_sandbox [EXTRACTED 1.00]
- **Five behavioral anomaly checks** — readme_network_behavior_detection, readme_git_clone_behavior_detection, readme_process_execution_behavior_detection, readme_sensitive_file_detection, readme_artifact_detection [EXTRACTED 1.00]
- **Sandbox backends** — readme_docker_sandbox, readme_nono_sandbox, readme_host_sandbox [EXTRACTED 1.00]
- **Install-time behavioral signal extraction** — src_scanning_extract_connection_ips, src_scanning_extract_git_clone_signatures, src_scanning_extract_process_exec_signatures [INFERRED 0.85]
- **Scan-then-forward orchestration pipeline** — src_lib_run, src_scanning_scan_packages_versions, src_lib_forward_pinned_command [INFERRED 0.85]

## Communities (213 total, 57 thin omitted)

### Community 0 - "Review history"
Cohesion: 0.01
Nodes (240): Design change after Findings 428 and 429: ranges on the command line are scanned at the latest version, Finding 100 — Low | `.github/workflows/ci.yml` | ✅ Fixed, Finding 101 — Low | `.github/workflows/ci.yml` | ✅ Fixed, Finding 102 — Medium | `.github/workflows/post_review.yml` | ✅ Fixed, Finding 103 — Low | `.github/workflows/ci.yml` | ✅ Fixed, Finding 104 — Low | `.github/workflows/ci.yml` | ✅ Fixed, Finding 105 — Low | `.github/workflows/ci.yml` | ✅ Fixed, Finding 106 — High | `.github/workflows/ci.yml` | ✅ Fixed (+232 more)

### Community 1 - "Routing, Config & Scan Orchestration"
Cohesion: 0.02
Nodes (121): Finding 118 — Low | `.github/workflows/ci.yml` | 🛑 Wont Fix, Finding 123 — High | `.github/workflows/post_review.yml` | 🛑 Wont Fix / Invalid, Finding 124 — Low | `.github/scripts/sanitize_review.py` | 🛑 Wont Fix, Finding 125 — Low | `.github/scripts/post_comment.sh` | 🛑 Wont Fix / Invalid, Finding 129 — Low | `.github/scripts/post_comment.sh` | 🛑 Wont Fix / Accepted Risk, Finding 138 — Low | `.github/scripts/sanitize_review.py` | 🛑 Wont Fix / Accepted Risk, Finding 151 — Invalid | `.github/scripts/sanitize_review.py` | 🛑 Wont Fix, Finding 152 — Accepted Risk | `.github/scripts/sanitize_review.py` | 🛑 Wont Fix (+113 more)

### Community 2 - "Detailed Findings"
Cohesion: 0.02
Nodes (119): Detailed Findings, Finding 170 — Medium | `ARCHITECTURE.md` | ⚠️ Open, Finding 171 — High | `scanning.rs` | ⚠️ Open, Finding 172 — Medium | `ARCHITECTURE.md` | ⚠️ Open, Finding 173 — Medium | `ARCHITECTURE.md` | ⚠️ Open, Finding 180 — Low | `lib.rs:1092-1173` | ⚠️ Open, Finding 22 — Medium | `scanning.rs:188` | ⚠️ Open, Finding 256 — Low | `scanning.rs:511` | ⚠️ Open (+111 more)

### Community 3 - "scanning.rs"
Cohesion: 0.03
Nodes (68): DNS wire-format parser (extract_dns_map), scan_packages_versions / ScanReport, a_file_outside_work_is_a_dropped_file_and_one_inside_is_not(), a_url_allowlist_entry_does_not_cover_risky_clone_options(), ARTIFACT_DELIMITER, artifact_delimiter_pipe_in_path_is_not_injected(), baseline_count_limits_fetched_baselines_without_overrides(), baseline_count_zero_does_not_fail_closed() (+60 more)

### Community 4 - "sandbox.rs"
Cohesion: 0.04
Nodes (52): APPARMOR_LOAD_ERR, ARTIFACT_INVENTORY_NODE, ARTIFACT_INVENTORY_PYTHON, build_matrix_script(), DEFAULT_PROBE_TIMEOUT_SECS, DEFAULT_TRACE_LIMIT, docker_preflight_distinguishes_daemon_down_permission_and_broken_cli(), DOCKER_STDERR_KEEP_BYTES (+44 more)

### Community 5 - "Bun Execution Detection & Exemptions"
Cohesion: 0.07
Nodes (46): validate_allowlist_pkg_key, accepts_new_package_exemptions_empty_list_as_no_exemptions(), baseline_count_zero_falls_back_to_default_two(), clamps_min_baseline_age_hours_to_hard_floor(), DEFAULT_CONFIG_PATH, domain_allowlist_bare_tld_rejected_in_global_and_per_package_positions(), domain_allowlist_empty_value_dropped_in_global_and_per_package_positions(), domain_allowlist_star_value_rejected_in_global_and_per_package_positions() (+38 more)

### Community 6 - "FCrDNS Allowlist Verification"
Cohesion: 0.07
Nodes (56): ImportRun, a_candidate_that_fails_to_load_when_a_baseline_loaded_blocks(), a_candidate_that_loads_when_no_baseline_did_is_not_compared(), a_candidate_that_ran_something_new_before_failing_reports_both(), a_failed_baseline_blocks_on_install_failed_alone(), a_failed_install_blocks_only_its_own_package_in_a_batch(), a_failed_load_still_compares_what_ran_before_the_failure(), a_load_that_times_out_blocks_whichever_version_it_was() (+48 more)

### Community 7 - "High Impact"
Cohesion: 0.06
Nodes (34): 10. Insecure Cryptography (insecure-crypto), 11. Insecure Transport (insecure-transport), 12. Server-Side Request Forgery (ssrf), 13. JWT Authentication (authentication-jwt), 14. Cross-Site Request Forgery (csrf), 15. Prototype Pollution (prototype-pollution), 16. Unsafe Functions (unsafe-functions), 17. Terraform AWS Security (terraform-aws) (+26 more)

### Community 8 - "native.sh"
Cohesion: 0.40
Nodes (3): DOCKER_CONFIG, HOME, native.sh script

### Community 9 - "NonoRunner backend"
Cohesion: 0.50
Nodes (4): CanaryTrap FIFO decoys, NonoRunner backend, PathShims, scan_target_artifacts / classify_inventory_lines

### Community 10 - "run"
Cohesion: 0.15
Nodes (10): exit_with(), GyrSeek, LazyRunner, no_sandbox_flag_is_consumed_wherever_it_appears(), run(), take_flag(), take_no_sandbox_flag(), main() (+2 more)

### Community 11 - "Semgrep Quick Reference"
Cohesion: 0.15
Nodes (13): Basic Structure, Commands, Metadata Fields, Path Filtering, Propagators, Required Rule Fields, Semgrep Quick Reference, Source/Sink Options (+5 more)

### Community 12 - "python_multi_package_tests.rs"
Cohesion: 0.22
Nodes (17): a_missing_requirements_file_fails_closed_for_every_spelling(), a_range_inside_a_requirements_file_still_exits_1(), an_attached_r_option_and_unpinned_file_lines_are_not_missed(), an_empty_requirements_file_fails_closed_instead_of_scanning_nothing(), direct_references_are_not_scanned_as_if_they_were_registry_packages(), install_with_no_package_names_fails_closed(), packages_in_an_included_requirements_file_are_scanned(), poetry_add_scans_every_named_package() (+9 more)

### Community 13 - "Docker Security"
Cohesion: 0.20
Nodes (11): Backout plan, Current hardening limitations, Docker Security, Overview, Platform support matrix, Prebuilt scanner images, Regression signals, Related env vars (+3 more)

### Community 14 - "extract_process_exec_signatures"
Cohesion: 0.09
Nodes (25): a_program_that_only_looks_like_the_import_step_is_still_reported(), case_1_new_bun_is_flagged_against_clean_baseline(), case_2_existing_bun_plus_additional_invocation_is_flagged(), case_2b_changed_bun_arguments_are_flagged(), executable_basename(), extract_process_exec_captures_all_executables(), extract_process_exec_captures_bun_run_with_argv(), extract_process_exec_preserves_brackets_in_argv() (+17 more)

### Community 15 - "Code Correctness Rules"
Cohesion: 0.08
Nodes (23): Assignment in Condition, ato* Functions, Bash, C, Code Correctness Rules, Elixir: Atom Exhaustion, Go, Integer Overflow from Atoi (+15 more)

### Community 16 - "Fail-Closed Policy & Findings"
Cohesion: 0.08
Nodes (23): 10.1 LLM10 - Prevent Unbounded Consumption, 10. Unbounded Consumption, 1.1 LLM01 - Prevent Prompt Injection, 1. Prompt Injection, 2.1 LLM02 - Prevent Sensitive Information Disclosure, 2. Sensitive Information Disclosure, 3.1 LLM03 - Secure LLM Supply Chain, 3. Supply Chain (+15 more)

### Community 17 - "Network Anomaly Decision"
Cohesion: 0.13
Nodes (22): active_test_env_vars(), age_filter_includes_versions_exactly_at_cutoff(), age_filter_keeps_only_versions_older_than_cutoff(), age_filter_skips_candidates_without_publish_timestamps(), age_filter_still_respects_baseline_count_limit(), BaselineHistory, burst_count_is_not_inflated_by_created_modified(), check_override_ages() (+14 more)

### Community 18 - "Detailed Findings"
Cohesion: 0.09
Nodes (21): Cross-Finding Chains (Architectural Context), Detailed Findings, Finding 10 — Critical | `scanning.rs:654` | ✅ Fixed, Finding 13 — Medium | `scanning.rs:1852` | ✅ Fixed, Finding 15 — Low | `sandbox.rs:511` | ✅ Fixed, Finding 16 — Medium | `scanning.rs:509` | ✅ Fixed, Finding 17 — High | `scanning.rs:972` | ✅ Fixed, Finding 18 — Medium | `scanning.rs:467` | ✅ Fixed (+13 more)

### Community 19 - "rewrite_args_with_pinned_versions"
Cohesion: 0.17
Nodes (20): rewrite_args_with_pinned_versions, Exact-version pinning of forwarded command, args(), does_not_pin_npm_package_with_latest_sentinel(), does_not_pin_pip_package_with_latest_sentinel(), does_not_pin_unrelated_packages(), does_not_repin_npm_package_that_already_has_a_version(), empty_pins_is_a_noop() (+12 more)

### Community 20 - "npm/package.json"
Cohesion: 0.15
Nodes (14): author, dependencies, lodash@^4.18.1, typescript@^6.0.3, description, lodash, typescript, license (+6 more)

### Community 21 - "index_settings.rs"
Cohesion: 0.10
Nodes (50): a_trusted_host_is_let_through_and_the_message_names_the_setting_and_host_only(), ancestors(), args(), check(), expand_vars(), host_of(), host_of_value(), hosts_are_read_from_ipv6_literals_and_scheme_less_values() (+42 more)

### Community 22 - "runtime_image.rs"
Cohesion: 0.06
Nodes (60): a_v_inside_a_prerelease_name_is_kept_and_only_a_leading_v_is_removed(), an_empty_blank_or_unreadable_version_file_is_skipped_not_fatal(), choice(), config_value_wins_over_project_files(), config_values_are_normalised_and_validated(), DEFAULT_NODE, DEFAULT_PYTHON, dir_with() (+52 more)

### Community 23 - "extract_connection_ips"
Cohesion: 0.17
Nodes (13): extract_connection_ips(), extract_connection_ips_captures_ipv4(), extract_connection_ips_captures_ipv6_inet_pton(), extract_connection_ips_collapses_ipv4_mapped_ipv6(), extract_connection_ips_drops_loopback_link_local_and_private(), extract_connection_ips_handles_mixed_v4_and_v6(), extract_connection_ips_keeps_cloud_metadata_endpoint(), extract_connection_ips_keeps_public_ipv4_mapped_ipv6_as_ipv4() (+5 more)

### Community 24 - "parse_global_options"
Cohesion: 0.33
Nodes (6): config_equals_form_preserves_equals_in_path(), config_path_starting_with_dash_is_accepted(), danger_disable_seccomp_parsing_edge_cases(), keeps_args_untouched_when_no_global_options_present(), parse_global_options(), parses_global_config_flag_and_strips_it_from_manager_args()

### Community 27 - "Critical Impact"
Cohesion: 0.12
Nodes (16): 10. Unbounded Consumption (unbounded-consumption), 1. Prompt Injection (prompt-injection), 2. Sensitive Information Disclosure (sensitive-disclosure), 3. Supply Chain (supply-chain), 4. Data and Model Poisoning (data-poisoning), 5. Improper Output Handling (output-handling), 6. Excessive Agency (excessive-agency), 7. System Prompt Leakage (system-prompt-leakage) (+8 more)

### Community 28 - "parsing.rs"
Cohesion: 0.06
Nodes (50): freeze_uv_sync(), LOCKFILE_ONLY_FLAGS, MAX_REQUIREMENTS_DEPTH, npm_flags_are_not_packages_and_the_command_decides_what_is_scanned(), npm_install_args_skips_link_spec(), NPM_REGISTRY_HOSTS, NPM_VALUE_FLAGS, parse_npm_install_packages_from_args() (+42 more)

### Community 29 - "extract_dns_map"
Cohesion: 0.09
Nodes (22): artifact_findings_empty_for_clean_install(), dns_interceptor_end_to_end_with_realistic_strace_trace(), extract_artifact_findings(), extract_dns_map(), extract_dns_map_connect_failure_ignored(), extract_dns_map_empty_trace(), extract_dns_map_ipv6_tcp_dns_response(), extract_dns_map_ipv6_udp_dns_response() (+14 more)

### Community 30 - "find_new_connections_domain_aware"
Cohesion: 0.07
Nodes (27): detects_anomalous_new_connection(), detects_new_connection_in_git_clone_simulation(), dns_interceptor_skips_when_domain_not_in_baseline(), dns_interceptor_skips_when_forward_resolver_does_not_confirm(), domain_aware_diff_cdn_rotation_without_ptr_handled_by_dns_interceptor(), domain_aware_diff_current_resolves_baseline_ip_unresolvable(), domain_aware_diff_current_unresolved_ip_in_baseline_not_flagged(), domain_aware_diff_discards_ip_when_domain_seen_in_baseline() (+19 more)

### Community 31 - "redirects.sh"
Cohesion: 0.34
Nodes (18): DOCKER_CONFIG, expect_mirror_used(), expect_refused(), expect_refused_host(), expect_tampered_hash_refused(), fail(), gyrseek(), HOME (+10 more)

### Community 32 - "gyrseek"
Cohesion: 0.17
Nodes (11): Behavior Reference, gyrseek, Introduction, Just Recipes, License, Package Related Supply Chain Attack Detection Coverage, Project Layout & Docs, Supported Commands (+3 more)

### Community 33 - "Prevent Insecure Deserialization"
Cohesion: 0.13
Nodes (14): BinaryFormatter Deserialization, General Prevention Guidelines, Language: C#, Language: Java, Language: JavaScript / TypeScript, Language: PHP, Language: Python, Language: Ruby (+6 more)

### Community 34 - "Semgrep Skill"
Cohesion: 0.13
Nodes (14): Acknowledgments, Capabilities, Creating Custom Rules, Example Prompts, For End Users, Quick Reference, Resources, Rule Creation Workflow (+6 more)

### Community 35 - "npm_lockfile_tests.rs"
Cohesion: 0.19
Nodes (20): a_flag_that_turns_the_lockfile_off_is_refused_before_anything_is_scanned(), a_lockfile_entry_that_is_not_from_the_npm_registry_fails_closed(), an_exempt_package_lets_an_old_v1_lockfile_with_a_git_source_be_scanned(), both_npm_lockfiles_are_scanned_because_npm_versions_pick_different_ones(), dist_tags_and_aliases_on_the_command_line_still_exit_1(), empty_or_unparseable_lockfiles_fail_closed_instead_of_scanning_nothing(), flags_around_exact_specs_do_not_change_what_is_scanned(), lockfile_only_commands_are_forwarded_with_ignore_scripts() (+12 more)

### Community 36 - "env"
Cohesion: 0.29
Nodes (7): GYRSEEK_DOCKER_APPARMOR_PROFILE, GYRSEEK_NPM_SCANNER_IMAGE, GYRSEEK_NPM_SCANNER_PREBUILT, GYRSEEK_PY_SCANNER_IMAGE, GYRSEEK_PY_SCANNER_PREBUILT, GYRSEEK_REQUIRE_NPM, env

### Community 37 - "Code Security Skill"
Cohesion: 0.14
Nodes (13): Acknowledgments, Categories (28 Total), Code Security Skill, Creating a New Rule, Critical Impact, For Contributors, For End Users, High Impact (+5 more)

### Community 38 - "Prevent Path Traversal"
Cohesion: 0.14
Nodes (13): File Inclusion (LFI/RFI), filepath.Clean Misuse, HttpServlet Path Traversal, Language: Go, Language: Java, Language: JavaScript/Node.js, Language: PHP, Language: Python (+5 more)

### Community 39 - "Prevent Cross-Site Scripting (XSS)"
Cohesion: 0.14
Nodes (13): Browser DOM Manipulation, Direct ResponseWriter Write, Django HttpResponse, Echo with Request Data, Flask Unsanitized Response, General Prevention Guidelines, Language: Go, Language: Java (+5 more)

### Community 40 - "LLM Security Skill"
Cohesion: 0.14
Nodes (13): Acknowledgments, Categories (10 Total), Creating a New Rule, Critical Impact, For Contributors, For End Users, High Impact, Impact Levels (+5 more)

### Community 41 - "Decision Model"
Cohesion: 0.29
Nodes (7): Policy allowlists (global and per-package), Config-loading helpers (parse_list_map, validate_allowlist_pkg_key, option_zero_to_none), Decision Model, DNS interceptor (extract_dns_map, parse_dns_response, decode_dns_name), Domain-aware IP diff (find_new_connections_domain_aware), FCrDNS (forward_confirmed_hostname), Process-execution signature diffing (Shai-Hulud class)

### Community 43 - "lock_verify.rs"
Cohesion: 0.13
Nodes (38): a_lock_entry_without_a_hash_is_refused(), a_locked_hash_the_registry_does_not_publish_is_refused(), a_pylock_entry_without_a_version_is_read_from_its_file_names_or_as_latest(), a_python_file_without_a_hash_is_refused(), a_requirements_hash_the_registry_does_not_publish_is_refused_without_a_mirror_too(), a_requirements_line_without_a_hash_is_refused_only_with_a_trusted_mirror(), add_py_file(), an_old_sha1_integrity_matches_the_registry_shasum() (+30 more)

### Community 44 - "General Best Practices for Avoiding Race Conditions"
Cohesion: 0.15
Nodes (11): General Best Practices for Avoiding Race Conditions, Hardcoded /tmp Path, Insecure Temporary File Creation, Insecure Temporary File Creation, Language: Go, Language: OCaml, Language: Python, Language-Specific Secure Alternatives (+3 more)

### Community 45 - "Semgrep Rule Creation Workflow"
Cohesion: 0.17
Nodes (12): Common Fixes, Common Redundancies to Remove, Example: Complete Taint Rule, Optimization Checklist, Semgrep Pattern Equivalences, Semgrep Rule Creation Workflow, Step 1: Analyze the Problem, Step 3: Analyze AST Structure (+4 more)

### Community 46 - "collect_probe_traces"
Cohesion: 0.29
Nodes (15): a_blank_trace_fails_closed_with_the_strace_error(), a_blank_trace_fails_the_batch_because_strace_does_not_work(), a_probe_that_filled_the_trace_tmpfs_is_blocked_alone(), a_probe_with_no_trace_file_is_left_out_and_named_and_nothing_is_re_run(), a_timed_out_probe_is_omitted_and_never_re_run(), an_exit_code_file_marks_only_that_probe_as_a_failed_install(), collect_probe_traces(), collects_each_probes_trace_in_order_and_appends_the_artifact_inventory() (+7 more)

### Community 47 - "load_policy_config"
Cohesion: 0.10
Nodes (25): AllowlistEntry, Global, PerPackage, BaselineOverrideConfig, GyrseekConfig, load_policy_config(), missing_default_config_returns_empty_allowlist(), missing_explicit_config_fails_closed() (+17 more)

### Community 48 - "build_docker_run_args"
Cohesion: 0.09
Nodes (22): INPUTS, a_node_package_is_loaded_after_it_is_installed(), a_pnpm_package_is_loaded_after_it_is_installed(), a_python_package_is_loaded_after_it_is_installed(), an_install_can_run_a_binary_from_work_and_extract_a_large_wheel_into_tmp(), build_docker_run_args(), custom_scanner_images_are_named_in_the_description(), docker_args_adds_seccomp_profile_by_default() (+14 more)

### Community 49 - "filter_domain_allowlisted_new_connections_with"
Cohesion: 0.12
Nodes (17): domain_allowlist_does_not_filter_when_lookup_fails(), domain_allowlist_filters_resolved_domains_before_blocking(), domain_allowlist_normalization_matches_case_whitespace_and_trailing_dot(), domain_is_allowlisted(), filter_allowlisted_new_connections(), filter_domain_allowlisted_new_connections_with(), global_domain_allowlist_applies_to_all_packages(), global_ip_allowlist_applies_to_all_packages() (+9 more)

### Community 50 - "Process-Execution Behavior Detection"
Cohesion: 0.15
Nodes (14): extract_process_exec_signatures, NonoRunner, Direct git clone runtime interception, Behavioral diff against baseline versions, Canary trap FIFO decoys, Common Attack Patterns Caught, Git Clone Behavior Detection, How it works (+6 more)

### Community 51 - "Prevent XML External Entity (XXE) Injection"
Cohesion: 0.17
Nodes (11): DocumentBuilderFactory - Disallow DOCTYPE Declaration, Language: C\#, Language: Go, Language: Java, Language: JavaScript, Language: Python, libxml2 - External Entities Enabled, libxmljs - noent Option Enabled (+3 more)

### Community 52 - "Part 2: Creating Custom Rules"
Cohesion: 0.17
Nodes (12): Anti-Patterns to Avoid, Approach Selection, Command Reference, Detailed References, Part 2: Creating Custom Rules, Pattern Syntax Quick Reference, Quick Start: Pattern Matching, Quick Start: Taint Mode (+4 more)

### Community 53 - ".new"
Cohesion: 0.33
Nodes (9): ignores_non_install_commands(), parses_npm_install_as_latest_when_unpinned(), parses_npm_install_with_pinned_version(), parses_pnpm_add_as_latest_when_unpinned(), parses_pnpm_add_with_pinned_version(), parses_poetry_update_as_latest_when_unpinned(), parses_uv_add_as_latest_when_unpinned(), parses_uv_pip_install_with_pinned_version() (+1 more)

### Community 54 - "Architecture"
Cohesion: 0.24
Nodes (10): Architecture, CI/CD Pipeline Architecture, Core Components, Current Limitations, Docker Sandbox Security, Fail-Closed Policy, Goal, gyrseek command-wrapper CLI (+2 more)

### Community 55 - "Roadmap"
Cohesion: 0.18
Nodes (11): External CodeRabbit review migration, Completed, Detection & Analysis, Hardening & Infrastructure, Hardening & Infrastructure, Long Term, Mid Term, Near Term (+3 more)

### Community 56 - "LockSource"
Cohesion: 0.15
Nodes (29): pylock_entry_version(), lock_url_source(), LockSource, Local, Registry, Remote, normalize_python_name(), parse_lock_toml() (+21 more)

### Community 57 - "pnpm/package.json"
Cohesion: 0.24
Nodes (9): dependencies, lodash@^4.18.1, typescript@^5.9.3, lodash, typescript, name, private, type (+1 more)

### Community 59 - "Code Best Practices"
Cohesion: 0.18
Nodes (10): Avoid Deprecated Libraries, Code Best Practices, Cookie Security Flags, File Handling - Always Close Files, Load Modules at Top Level, Network Requests Need Timeouts, Remove Debug Statements, Secure Temporary File Creation (+2 more)

### Community 60 - "terraform-gcp.md"
Cohesion: 0.18
Nodes (10): Cloud Run, Cloud Build, Dataproc, and Vertex AI, Cloud SQL, Google Cloud Storage (GCS), Google Compute Engine and Firewall, Google Kubernetes Engine (GKE), IAM, VPC, and Networking, KMS, Redis, BigQuery, and Pub/Sub, References (+2 more)

### Community 61 - "Categories"
Cohesion: 0.18
Nodes (10): Categories, Code Security Guidelines, Critical Impact, High Impact, How to Use This Skill, Infrastructure, Language-Specific Priority Rules, Medium/Low Impact (+2 more)

### Community 62 - "LLM Security Guidelines (OWASP Top 10 for LLM 2025)"
Cohesion: 0.18
Nodes (10): Categories, Critical Impact, High Impact, How to Use This Skill, Key Principles, LLM Security Guidelines (OWASP Top 10 for LLM 2025), Quick Reference, References (+2 more)

### Community 63 - "check_phase"
Cohesion: 0.07
Nodes (31): a_dropped_file_is_compared_by_path_whatever_its_size(), a_hash_or_version_in_a_vendored_file_name_does_not_make_the_file_new(), a_new_or_different_executable_is_still_new(), AllowlistRefs, artifact_allowlist_does_not_leak_across_packages(), artifact_allowlist_matches_exact_finding_and_prefix(), artifact_key(), check_phase() (+23 more)

### Community 64 - "Network Behavior Detection"
Cohesion: 0.22
Nodes (10): find_new_connections_domain_aware, HARD_MINIMUM_AGE_HOURS gate, Allowlists (ip, domain, git clone, artifact, sensitive file, process exec), YAML policy config (gyrseek.yaml), Domain-aware IP diff, FCrDNS (forward-confirmed reverse DNS), internal_package_exemptions, Network Behavior Detection (+2 more)

### Community 65 - "Prevent Cross-Site Request Forgery"
Cohesion: 0.20
Nodes (9): CSRF Disabled, CSRF Exempt Decorator, Language: Java / Spring, Language: JavaScript / Express, Language: Python / Django, Language: Ruby / Rails, Missing CSRF Middleware, Missing CSRF Protection (+1 more)

### Community 66 - "Secure Kubernetes Configurations"
Cohesion: 0.20
Nodes (9): Docker Socket Exposure, Host IPC Namespace, Host Network Namespace, Host PID Namespace, Privilege Escalation, Privileged Containers, Run as Non-Root, Secrets in Config Files (+1 more)

### Community 67 - "Secure Azure Terraform Configurations"
Cohesion: 0.20
Nodes (9): AKS Security, App Service Security, Database Security, IAM - Custom Roles, Key Vault Security, Public Network Access and Network Isolation, Secure Azure Terraform Configurations, Storage Account Security (+1 more)

### Community 68 - "Interrogation"
Cohesion: 0.20
Nodes (9): Activation, Answer Handling, Boundaries, Branch Resolution, Depth Control, Interrogation, Termination, The Method (+1 more)

### Community 69 - "semgrep/SKILL.md"
Cohesion: 0.20
Nodes (7): CI/CD Integration, GitHub Actions, Installation (CLI), MCP Tools Available, Resources, Semgrep Static Analysis, When to Use Semgrep

### Community 71 - "Python"
Cohesion: 0.22
Nodes (8): Avoid Unnecessary Operations in Loops, Django - Access Foreign Keys Directly, JavaScript/TypeScript, Performance Best Practices, Python, React - Define Styled Components at Module Level, SQLAlchemy - Batch Database Operations, SQLAlchemy - Use count() Instead of len(all())

### Community 72 - "Prevent SQL Injection"
Cohesion: 0.22
Nodes (8): C# (SqlCommand), Go (database/sql), Java (JDBC), JavaScript/Node.js (pg), Key Prevention Rules, Prevent SQL Injection, Python (psycopg2), Ruby (pg gem)

### Community 73 - "LLM03: Secure LLM Supply Chain"
Cohesion: 0.22
Nodes (8): Dependency Management, Key Prevention Rules, LLM03: Secure LLM Supply Chain, LoRA Adapter Security, ML Bill of Materials (ML-BOM), Model Verification, Safe Model Loading (Avoid Pickle Exploits), Vendor and Data Source Vetting

### Community 74 - "Ponytail"
Cohesion: 0.22
Nodes (8): Boundaries, Intensity, Output, Persistence, Ponytail, Rules, The ladder, When NOT to be lazy

### Community 75 - "Agents Memory and Workflow"
Cohesion: 0.25
Nodes (8): Agent Portability Symlinks, Agents Memory and Workflow, graphify, Mandatory Post-Change Policy, Mandatory Pre-Session Setup, Purpose, Quick Post-Change Checklist, Repository Memory

### Community 76 - "Sandbox Modes"
Cohesion: 0.25
Nodes (8): Default-deny seccomp architecture, Docker sandbox, Host mode (reduced safety), nono configuration, Platform support matrix, Sandbox Modes, Scanner image configuration, Seccomp and AppArmor profiles

### Community 77 - "scan_r"
Cohesion: 0.14
Nodes (22): a_bad_nested_include_fails_closed(), a_range_inside_a_requirements_file_is_rejected_because_it_cannot_be_pinned(), an_attached_short_r_option_on_the_command_line_is_scanned(), boolean_flags_never_swallow_the_package_after_them(), command_lines_with_missing_values_or_empty_arguments_do_not_panic(), every_include_spelling_is_followed(), flag_values_are_not_mistaken_for_packages(), include_cycles_terminate_and_deep_nesting_fails_closed() (+14 more)

### Community 78 - "Post-install artifact detection"
Cohesion: 0.25
Nodes (8): build_artifact_scan_steps, Enhanced generated-file comparison, Post-install interpreter trigger, Post-install artifact detection, Supply chain attack detection coverage table, classify_inventory_lines, Deferred Python execution gap, Shai-Hulud campaign

### Community 79 - "Code Security"
Cohesion: 0.25
Nodes (7): 22.1 Secure GitHub Actions, 22. GitHub Actions Security, 23.1 Prevent Regular Expression DoS, 23. Regular Expression DoS, Abstract, Code Security, Table of Contents

### Community 80 - "Secure Docker Configurations"
Cohesion: 0.25
Nodes (7): Arbitrary Container Run (Python Docker SDK), Exposing Docker Socket, Missing Image Version, Privileged Mode (Docker Compose), Running as Root, Secure Docker Configurations, Using Latest Tag

### Community 81 - "Avoid Insecure Cryptography"
Cohesion: 0.25
Nodes (7): Avoid Insecure Cryptography, Best Practices, Go, Java, JavaScript, Python, Remediation Summary

### Community 82 - "Use Secure Transport"
Cohesion: 0.25
Nodes (7): Language: Go, Language: Java, Language: JavaScript/Node.js, Language: Python, References, Summary of CWEs, Use Secure Transport

### Community 83 - "Prevent Server-Side Request Forgery (SSRF)"
Cohesion: 0.25
Nodes (7): Language: Go, Language: Java, Language: JavaScript / Node.js, Language: PHP, Language: Python, Language: Ruby, Prevent Server-Side Request Forgery (SSRF)

### Community 84 - "Secure AWS Terraform Configurations"
Cohesion: 0.25
Nodes (7): Credentials, IAM Overly Permissive Policies, Key Management, Network Security, S3 Encryption, Secure AWS Terraform Configurations, Unencrypted Storage

### Community 85 - "LLM04: Prevent Data and Model Poisoning"
Cohesion: 0.25
Nodes (7): Anomaly Detection During Training, Data Version Control, Detecting Poisoned Examples, Key Prevention Rules, LLM04: Prevent Data and Model Poisoning, Sandboxed Data Processing, Training Data Validation

### Community 86 - "LLM06: Control Excessive Agency"
Cohesion: 0.25
Nodes (7): Human-in-the-Loop for High-Impact Actions, Implementing Least Privilege, Key Prevention Rules, LLM06: Control Excessive Agency, Minimizing Tool/Extension Functionality, Monitoring and Audit Logging, Rate Limiting and Quotas

### Community 87 - "LLM09: Mitigate Misinformation and Hallucinations"
Cohesion: 0.25
Nodes (7): Confidence Scoring and Disclaimers, Fact Verification Pipeline, Key Prevention Rules, LLM09: Mitigate Misinformation and Hallucinations, Output Validation for Critical Domains, Retrieval-Augmented Generation (RAG), User Education and Transparency

### Community 88 - "LLM05: Secure Output Handling"
Cohesion: 0.25
Nodes (7): Content Security Policy for LLM Applications, Key Prevention Rules, LLM05: Secure Output Handling, Preventing Command Injection from LLM Output, Preventing SQL Injection from LLM Output, Preventing SSRF from LLM Output, Preventing XSS from LLM Output

### Community 89 - "LLM02: Prevent Sensitive Information Disclosure"
Cohesion: 0.25
Nodes (7): Access Control for RAG Systems, Data Sanitization Before Training/Fine-tuning, Key Prevention Rules, LLM02: Prevent Sensitive Information Disclosure, Output Filtering for Sensitive Data, System Prompt Security, User Education and Consent

### Community 90 - "LLM07: Prevent System Prompt Leakage"
Cohesion: 0.25
Nodes (7): Defense in Depth: External Guardrails, Input Filtering for Extraction Attempts, Key Prevention Rules, LLM07: Prevent System Prompt Leakage, Monitoring and Alerting, Never Store Secrets in System Prompts, Separating Sensitive Logic from Prompts

### Community 91 - "LLM10: Prevent Unbounded Consumption"
Cohesion: 0.25
Nodes (7): Cost Control and Budget Limits, Input Validation and Size Limits, Key Prevention Rules, LLM10: Prevent Unbounded Consumption, Model Theft Prevention, Rate Limiting, Resource Monitoring and Alerting

### Community 92 - "LLM08: Secure Vector and Embedding Systems"
Cohesion: 0.25
Nodes (7): Data Validation Before Embedding, Key Prevention Rules, LLM08: Secure Vector and Embedding Systems, Monitoring and Audit Logging, Multi-Tenant Data Isolation, Permission-Aware Vector Retrieval, Preventing Embedding Inversion Attacks

### Community 93 - "Ponytail Help"
Cohesion: 0.25
Nodes (7): Configure Default Mode, Deactivate, Levels, More, Ponytail Help, Skills, Update

### Community 94 - "Part 1: Running Scans"
Cohesion: 0.25
Nodes (8): Configuration, Output Formats, Part 1: Running Scans, Quick Scan, Scan Specific Paths, .semgrepignore, Suppress False Positives, Using Rulesets

### Community 95 - "Sandbox Infrastructure"
Cohesion: 0.40
Nodes (5): Capabilities and privileges, Probe batching, Sandbox Infrastructure, strace configuration, Unprivileged payload integrity

### Community 96 - "AGENTS.md repository memory"
Cohesion: 0.29
Nodes (7): AGENTS.md repository memory, CI workflow (ci.yml), Findings docs (open, fixed, wont-fix), graphify workflow rules, Mandatory post-change policy, Agent skills (ponytail, interrogation, code-security), Test strategy (inline tests plus binary-spawning integration tests)

### Community 97 - "Prevent Command Injection"
Cohesion: 0.29
Nodes (6): Language: Go, Language: Java, Language: JavaScript / Node.js, Language: Python, Language: Ruby, Prevent Command Injection

### Community 98 - "Secure GitHub Actions"
Cohesion: 0.29
Nodes (6): Key Security Risks, Pull Request Target Code Checkout (CWE-913), Run Shell Injection (CWE-78), Secure GitHub Actions, Third-Party Action Not Pinned to Commit SHA (CWE-1357), Workflow Run Target Code Checkout (CWE-913)

### Community 99 - "Ensure Memory Safety"
Cohesion: 0.29
Nodes (6): Buffer Overflow (CWE-119, CWE-120), Double Free (CWE-415), Ensure Memory Safety, Format String Vulnerabilities (CWE-134), Prevention Best Practices, Use After Free (CWE-416)

### Community 100 - "Threat Model & Accepted Risks"
Cohesion: 0.33
Nodes (6): 1. External AI Code Review, 2. Sandbox Syscall Permissiveness, 3. CI/CD Architecture Trade-offs, 4. DNS Exfiltration Boundaries, CI/CD Pipeline Architecture (ci.yml, CodeRabbit), Threat Model & Accepted Risks

### Community 101 - "Validation checklist"
Cohesion: 0.29
Nodes (7): Step 1: Baseline sanity (no custom seccomp/apparmor), Step 2: Validate seccomp profile syntax, Step 3: Smoke test ptrace with network access, Step 4: Run gyrseek e2e with seccomp, Step 5: AppArmor validation (Linux hosts), Step 5a: Troubleshooting, Validation checklist

### Community 102 - "Open Findings"
Cohesion: 0.29
Nodes (5): Complexity & Over-Engineering Findings, Open Findings - Detailed, Open Findings, Security & Correctness Findings, Summary

### Community 103 - "How It Works"
Cohesion: 0.40
Nodes (5): How It Works, How it works, Post-Install Artifact Behavior Detection, Sensitive File Access Behavior Detection, Why Baseline Diffing is Essential Here

### Community 104 - "Prebuilt Scanner Images"
Cohesion: 0.29
Nodes (7): Prebuilt scanner images as default, 1) Build the scanner images, 2) Use a prebuilt image, 3) Enable prebuilt mode globally (optional), 4) Verify images are usable, 5) Use pinned image digests (recommended for reproducibility), Prebuilt Scanner Images

### Community 105 - "InstallFailure"
Cohesion: 0.13
Nodes (12): InstallFailure, add_block_reason(), check_import(), FailingInstallRunner, failure_tails(), ImportingRunner, ImportSignals, install_failed_message() (+4 more)

### Community 106 - "env_lock"
Cohesion: 0.29
Nodes (3): active_test_env_vars_none_set_returns_empty(), env_lock(), EnvVarGuard

### Community 107 - "LLM01: Prevent Prompt Injection"
Cohesion: 0.33
Nodes (5): Direct Prompt Injection Prevention, Indirect Prompt Injection Prevention (RAG Systems), Key Prevention Rules, LLM01: Prevent Prompt Injection, Output Filtering

### Community 108 - "read_import_run"
Cohesion: 0.09
Nodes (26): a_blank_import_trace_is_a_failed_import_not_a_clean_one(), a_blank_import_trace_is_not_made_clean_by_a_new_file(), a_clean_import_keeps_its_trace_and_only_the_files_it_created(), a_module_the_package_leaves_in_work_does_not_run_in_the_root_inventory(), a_package_that_cannot_be_loaded_reports_why_and_is_not_a_failed_install(), a_package_under_a_namespace_directory_is_the_one_that_is_loaded(), a_payload_cannot_tamper_with_its_own_or_another_probes_trace(), a_probe_that_floods_its_trace_is_blocked_and_the_next_probe_is_unaffected() (+18 more)

### Community 109 - "Understand Code"
Cohesion: 0.33
Nodes (5): Approach, Checklist, Goal, Understand Code, Verification

### Community 110 - "WONT_FIX_FINDINGS_DETAILED.md"
Cohesion: 0.33
Nodes (4): Detailed Rationale, Won't Fix Findings (Detailed), Summary, Won't Fix Findings

### Community 111 - "unescape_strace_string"
Cohesion: 0.11
Nodes (17): a_different_order_of_a_repeated_option_is_a_different_clone(), a_version_that_adds_a_risky_clone_option_is_new_behaviour(), clone_sigs(), extract_git_clone_signatures(), git_clone_argument(), git_clone_risky_long(), git_clone_signatures_name_the_repository_and_the_risky_options(), parse_execve_argvs() (+9 more)

### Community 112 - "Pattern Operators"
Cohesion: 0.29
Nodes (7): Basic Matching, Deep Matching, Metavariable Filters, Metavariables, Negation, Pattern Operators, Scope Operators

### Community 113 - "trace_install_docker_matrix"
Cohesion: 0.15
Nodes (16): append_inventory(), collect_probe_traces_expecting(), container_name(), DockerRunner, import_missing_message(), is_valid_trace_limit(), probe_chunks(), ProbeTrace (+8 more)

### Community 114 - ".yamllint.yaml"
Cohesion: 0.33
Nodes (5): extends, ignore, level, rules, line-length

### Community 115 - "Prevent Regular Expression DoS (ReDoS)"
Cohesion: 0.40
Nodes (4): General Mitigation Strategies, Language: JavaScript / TypeScript, Language: Python, Prevent Regular Expression DoS (ReDoS)

### Community 116 - "ponytail-review/SKILL.md"
Cohesion: 0.40
Nodes (4): Boundaries, Examples, Format, Scoring

### Community 117 - "AppArmor"
Cohesion: 0.25
Nodes (8): Allowed operations, AppArmor, Configuration, Platform note, Recommendation, Requirements, Setup, Status output

### Community 118 - "Common Patterns by Vulnerability"
Cohesion: 0.29
Nodes (7): Command Injection, Common Patterns by Vulnerability, Dangerous Functions (Pattern Matching), Hardcoded Secrets (Pattern Matching), Path Traversal, SQL Injection, XSS

### Community 119 - "build_runner_from_env"
Cohesion: 0.29
Nodes (7): HostRunner, is_timeout_exit(), npm_family_install_dir_flag(), npm_family_install_subcommand(), probe_timeout_message(), timeout_exit_codes_cover_term_and_kill_only(), timeout_message_names_the_probe_and_the_setting()

### Community 120 - "Configuration"
Cohesion: 0.40
Nodes (5): CLI Arguments, Config keys, Config loading behavior, Configuration, Example config

### Community 121 - "build_runner_from_env"
Cohesion: 0.15
Nodes (14): announce_apparmor_status(), announce_seccomp_status(), apparmor_disabled_wont_call_apparmor_parser(), apparmor_env_var_default_false(), build_runner_from_env(), docker_apparmor_enabled_from_env(), docker_apparmor_profile_name(), docker_daemon_error_message() (+6 more)

### Community 122 - "forward_fail_closed_tests.rs"
Cohesion: 0.24
Nodes (9): forward_args, forward_original_command, forward_pinned_command, fake_binary(), forwarding_a_missing_host_binary_fails_closed(), test: missing host binary fails closed, forwarding_preserves_host_success_exit_status(), forwarding_propagates_host_nonzero_exit_status() (+1 more)

### Community 123 - "code-injection.md"
Cohesion: 0.50
Nodes (3): Key Prevention Patterns, Prevent Code Injection, References

### Community 124 - "decode_dns_name"
Cohesion: 0.14
Nodes (14): decode_dns_name(), decode_dns_name_circular_pointer_returns_none(), decode_dns_name_excessive_pointer_hops_returns_none(), decode_dns_name_long_but_not_circular_pointer_chain(), decode_dns_name_out_of_bounds_returns_none(), decode_dns_name_recursive_pointer_chain(), decode_dns_name_root_label_only(), decode_dns_name_simple_two_label() (+6 more)

### Community 125 - "Quick Start"
Cohesion: 0.50
Nodes (4): 1. Prerequisites, 2. Build, 3. Run your first scan, Quick Start

### Community 126 - "SandboxRunner"
Cohesion: 0.24
Nodes (10): NoopRunner, scan_many_with_cache(), scan_targets(), scan_with_cache(), recorded_inputs(), SandboxRunner, ImportAllowlists, PolicyConfig (+2 more)

### Community 127 - "frozen_forward_tests.rs"
Cohesion: 0.42
Nodes (8): npm_install_is_forwarded_as_npm_ci(), pnpm_install_is_forwarded_with_frozen_lockfile(), project(), run(), UV_LOCK, uv_sync_is_forwarded_with_locked(), uv_sync_that_is_already_locked_or_frozen_is_forwarded_as_typed(), uv_sync_that_picks_new_versions_is_refused_before_the_scan_and_never_forwarded()

### Community 128 - "Seccomp"
Cohesion: 0.40
Nodes (5): Configuration, Platform note, Profile behavior, Seccomp, Status output

### Community 129 - "cli_burst_exit_tests.rs"
Cohesion: 0.26
Nodes (9): exits_with_code_1_and_rejects_versions_newer_than_72_hours_by_default(), exits_with_code_1_and_uses_configured_release_burst_window_hours(), exits_with_code_1_and_warning_when_release_burst_threshold_triggers(), exits_with_code_1_when_minimum_release_age_package_is_not_met(), minimum_release_age_package_runs_before_burst_threshold(), new_package_exemptions_list_format_rejected_with_hard_error(), new_package_exemptions_map_format_loaded_successfully(), run_with_config() (+1 more)

### Community 131 - "classify_requirement"
Cohesion: 0.12
Nodes (20): classify_npm_spec(), classify_requirement(), direct_references_and_urls_are_rejected(), exact(), exact_requirements_are_accepted_in_every_form(), is_plain_version(), is_valid_npm_name(), malformed_requirements_fail_closed_instead_of_being_guessed() (+12 more)

### Community 132 - "index_redirect_tests.rs"
Cohesion: 0.30
Nodes (13): a_command_with_only_non_registry_specs_is_checked_too(), a_flag_that_points_pip_at_another_index_is_refused_and_a_trusted_host_is_let_through(), an_npmrc_registry_is_refused_for_npm_and_pnpm_until_its_host_is_trusted(), assert_refused(), bad_trusted_index_hosts_entries_are_ignored_with_a_warning(), environment_variables_and_config_files_are_refused_too(), EVIL, EXEMPT_SIX (+5 more)

### Community 133 - "read_frames"
Cohesion: 0.17
Nodes (14): a_frame_that_cannot_be_trusted_is_an_error_not_a_partial_trace(), base64_decode(), base64_decoding_matches_the_standard_alphabet_and_rejects_anything_else(), frame(), frames_from_the_container_become_files_and_everything_else_is_ignored(), is_probe_file_name(), LineRead, End (+6 more)

### Community 135 - "steps"
Cohesion: 0.50
Nodes (4): linux-docker-apparmor-seccomp-npm-test, name, runs-on, steps

### Community 136 - "sandbox_startup_exit_tests.rs"
Cohesion: 0.43
Nodes (6): docker_daemon_not_running_exits_1_with_a_hint(), docker_not_installed_exits_1(), fake_exe(), gyrseek_sandbox_env_var_is_ignored(), run_gyrseek(), unscanned_passthrough_does_not_initialize_the_sandbox()

### Community 137 - "name"
Cohesion: 0.22
Nodes (10): linux-docker-seccomp-uv-test, linux-docker-uv-test, name, runs-on, steps, name, runs-on, steps (+2 more)

### Community 138 - "Usage"
Cohesion: 0.50
Nodes (4): npm examples, pnpm examples, Python examples, Usage

### Community 140 - "lock_routing_tests.rs"
Cohesion: 0.23
Nodes (10): gyrseek(), bare_uv_lock_is_routed_to_lockfile_scan(), pnpm_install_is_routed_to_package_scan(), poetry_lock_is_routed_to_lockfile_scan(), pylock_entries_from_another_source_fail_closed_unless_exempt(), python_lockfile_entries_from_another_index_fail_closed_unless_exempt(), run_in(), uv_venv_stays_unscanned_passthrough() (+2 more)

### Community 142 - "ForwardMode"
Cohesion: 0.67
Nodes (3): ForwardMode, Original, Pinned

### Community 174 - "steps"
Cohesion: 0.50
Nodes (4): rust-checks, name, runs-on, steps

### Community 178 - "with"
Cohesion: 0.25
Nodes (8): with, components, dockerfile, just-version, python-version, recursive, token, version

### Community 181 - "cargo-audit"
Cohesion: 0.18
Nodes (11): name, permissions, runs-on, env, CARGO_TERM_COLOR, jobs, cargo-audit, name (+3 more)

### Community 184 - "parse_npm_lock"
Cohesion: 0.12
Nodes (33): a_download_must_be_the_file_of_the_package_it_is_listed_under(), a_local_artifact_stays_excluded_when_the_entry_names_an_index(), a_pylock_entry_without_a_version_takes_it_from_its_files(), exempt(), internal_package_exemptions_let_a_private_registry_package_through(), lockfile_entries_from_anywhere_but_the_npm_registry_fail_closed(), lockfile_entries_with_missing_or_odd_fields_are_handled(), lockfile_parsers_survive_hostile_and_degenerate_input() (+25 more)

### Community 188 - "Step 6: Validate and Test"
Cohesion: 0.33
Nodes (6): Debug Failures, Debug Taint Rules, Expected Output, Run Tests, Step 6: Validate and Test, Validate YAML Syntax

### Community 189 - "fs"
Cohesion: 0.26
Nodes (8): a_lockfile_hash_the_public_registry_does_not_publish_is_refused_before_the_scan(), LODASH_INTEGRITY, run_with_integrity(), the_real_lockfile_hash_passes_the_check(), pnpm_add_only_non_registry_specs_forwards_directly_without_scanning(), pnpm_add_reaches_scan_branch(), pnpm_command(), pnpm_install_scans_the_lockfile_not_package_json()

### Community 190 - "Step 4: Choose Pattern Operators"
Cohesion: 0.40
Nodes (5): Basic Pattern Matching, Focus Metavariable, Metavariable Filters, Scope Operators, Step 4: Choose Pattern Operators

### Community 191 - "Step 5: Write Taint Rules"
Cohesion: 0.40
Nodes (5): Basic Taint Structure, Step 5: Write Taint Rules, Taint Sanitizer Options, Taint Sink with Focus, Taint Source Options

### Community 192 - "steps"
Cohesion: 0.50
Nodes (4): linux-docker-apparmor-seccomp-pip-test, name, runs-on, steps

### Community 193 - "steps"
Cohesion: 0.50
Nodes (4): linux-docker-apparmor-seccomp-pnpm-test, name, runs-on, steps

### Community 194 - "steps"
Cohesion: 0.50
Nodes (4): linux-docker-apparmor-seccomp-poetry-test, name, runs-on, steps

### Community 195 - "steps"
Cohesion: 0.50
Nodes (4): linux-docker-apparmor-seccomp-uv-test, name, runs-on, steps

### Community 196 - "lockfile-guards.sh"
Cohesion: 0.60
Nodes (3): npm_check(), refused(), lockfile-guards.sh script

### Community 198 - "uses"
Cohesion: 0.40
Nodes (5): steps, continue-on-error, id, if, uses

### Community 199 - "read_input"
Cohesion: 0.33
Nodes (7): a_file_that_appears_after_the_scan_is_detected(), a_lockfile_edited_after_it_was_read_is_detected_before_forwarding(), changed_inputs(), every_file_the_scan_reads_is_tracked(), read_input(), read_requirements_file(), read_requirements_file_at()

### Community 200 - "strings"
Cohesion: 0.16
Nodes (24): a_no_argument_install_is_frozen_to_the_scanned_lockfile(), a_range_argument_is_replaced_by_the_scanned_version_on_forward(), check_ranges_against_scanned(), direct_references_and_malformed_specs_are_still_rejected_on_the_command_line(), freeze_lockfile_install(), is_npm_family_manager(), npm_install_commands_scan_latest_for_ranges_and_reject_tags(), npm_positions_are_recorded_and_used_for_the_rewrite() (+16 more)

### Community 201 - "Step 2: Create Test Cases First"
Cohesion: 0.50
Nodes (4): Directory Structure, Step 2: Create Test Cases First, Test Annotations, Test Case Design

### Community 203 - "Troubleshooting"
Cohesion: 0.50
Nodes (4): Pattern Not Matching, Taint Not Propagating, Too Many False Positives, Troubleshooting

### Community 205 - "on"
Cohesion: 0.15
Nodes (17): on, pull_request, push, workflow_dispatch, branches, has_only_non_registry_npm_specs(), is_lockfile_only_command(), is_non_registry_npm_spec() (+9 more)

### Community 206 - "scan_with_failing"
Cohesion: 0.50
Nodes (4): clean_installs_are_not_blocked_by_install_failed(), failed_baseline_install_also_blocks_with_install_failed(), failed_candidate_install_blocks_with_install_failed(), scan_with_failing()

### Community 207 - "build_matrix_script_with"
Cohesion: 0.12
Nodes (22): a_missing_or_failing_interpreter_stops_the_script_instead_of_leaving_an_empty_inventory(), a_scanner_image_without_a_working_interpreter_fails_the_scan_with_a_message(), artifact_scan_steps(), artifact_scan_steps_inventory_all_files(), artifact_scan_steps_output_to_correct_log(), build_artifact_scan_steps(), build_matrix_script_core(), build_matrix_script_with() (+14 more)

### Community 211 - "load_yaml"
Cohesion: 0.33
Nodes (6): a_zero_import_timeout_falls_back_to_300_rather_than_disabling_it(), import_allowlists_are_read_separately_from_the_install_ones(), import_allowlists_reject_the_same_things_the_install_ones_do(), import_scanning_can_be_switched_off_and_given_its_own_timeout(), import_scanning_is_on_by_default_with_the_install_timeout(), load_yaml()

## Knowledge Gaps
- **62 isolated node(s):** `EMBEDDED_SECCOMP_PROFILE_JSON`, `EMBEDDED_APPARMOR_PROFILE_NAME`, `EMBEDDED_APPARMOR_PROFILE_TEXT`, `End`, `Line` (+57 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 1351 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **57 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `gyrseek` connect `gyrseek` to `Network Behavior Detection`, `DOCKER_SECURITY.md`, `How It Works`, `Prebuilt Scanner Images`, `Usage`, `Sandbox Modes`, `Process-Execution Behavior Detection`, `rewrite_args_with_pinned_versions`, `Configuration`, `Quick Start`?**
  _High betweenness centrality (0.056) - this node is a cross-community bridge._
- **Are the 13 inferred relationships involving `load()` (e.g. with `baseline_count_zero_falls_back_to_default_two()` and `minimum_release_age_package_zero_disables_policy()`) actually correct?**
  _`load()` has 13 INFERRED edges - model-reasoned connections that need verification._
- **What connects `EMBEDDED_SECCOMP_PROFILE_JSON`, `EMBEDDED_APPARMOR_PROFILE_NAME`, `EMBEDDED_APPARMOR_PROFILE_TEXT` to the rest of the system?**
  _62 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Review history` be split into smaller, more focused modules?**
  _Cohesion score 0.008333333333333333 - nodes in this community are weakly interconnected._
- **Why does `Docker Security` connect `Docker Security` to `Seccomp`, `Validation checklist`, `DOCKER_SECURITY.md`, `AppArmor`, `Architecture`, `Sandbox Infrastructure`?**
  _High betweenness centrality (0.029) - this node is a cross-community bridge._
- **Should `Routing, Config & Scan Orchestration` be split into smaller, more focused modules?**
  _Cohesion score 0.01652892561983471 - nodes in this community are weakly interconnected._
- **Why does `run()` connect `run` to `gyrseek`, `Bun Execution Detection & Exemptions`, `lock_routing_tests.rs`, `on`, `load_policy_config`, `.new`, `runtime_image.rs`, `parse_global_options`, `build_runner_from_env`, `forward_fail_closed_tests.rs`, `parsing.rs`, `SandboxRunner`?**
  _High betweenness centrality (0.026) - this node is a cross-community bridge._