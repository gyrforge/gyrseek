# Graph Report - gyrseek  (2026-11-22)

## Corpus Check
- 97 files · ~218,709 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 10 file(s) not represented in the graph (top: (none) 6, .npm 1, .python 1)

## Summary
- 2270 nodes · 3297 edges · 178 communities (125 shown, 53 thin omitted)
- Extraction: 95% EXTRACTED · 5% INFERRED · 0% AMBIGUOUS · INFERRED: 154 edges (avg confidence: 0.85)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `cc0da1f5`
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
- parse_npm_install_packages_from_args
- NonoRunner backend
- run
- Semgrep Quick Reference
- trace_install_docker_matrix
- Docker Security
- extract_process_exec_signatures
- Code Correctness Rules
- Fail-Closed Policy & Findings
- Network Anomaly Decision
- Detailed Findings
- Version Flag Tests
- npm/package.json
- trace_sandbox_install_matrix
- runtime_image.rs
- extract_sensitive_file_reads
- parse_global_options
- Critical Impact
- parsing.rs
- select_effective_baselines
- build_matrix_script
- filter_domain_allowlisted_new_connections_with
- gyrseek
- Prevent Insecure Deserialization
- Semgrep Skill
- Command
- with
- Code Security Skill
- Prevent Path Traversal
- Prevent Cross-Site Scripting (XSS)
- LLM Security Skill
- Decision Model
- deserialize_new_package_exemptions
- python_multi_package_tests.rs
- General Best Practices for Avoiding Race Conditions
- Semgrep Rule Creation Workflow
- collect_probe_traces
- load_policy_config
- build_docker_run_args
- extract_connection_ips
- Process-Execution Behavior Detection
- Prevent XML External Entity (XXE) Injection
- Part 2: Creating Custom Rules
- .new
- Architecture
- Roadmap
- main.rs
- pnpm/package.json
- Code Best Practices
- terraform-gcp.md
- Categories
- LLM Security Guidelines (OWASP Top 10 for LLM 2025)
- parse_python_install_packages_from_args
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
- NpmResponse
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
- decode_dns_name
- env_lock
- LLM01: Prevent Prompt Injection
- read_install_failure
- Understand Code
- WONT_FIX_FINDINGS_DETAILED.md
- Pattern Operators
- Common Patterns by Vulnerability
- rewrite_args_with_pinned_versions
- .yamllint.yaml
- Prevent Regular Expression DoS (ReDoS)
- ponytail-review/SKILL.md
- AppArmor
- Taint Mode
- build_runner_from_env
- Configuration
- AllowlistEntry
- docker_apparmor_profile_name
- code-injection.md
- parsing.rs
- Quick Start
- PolicyConfig
- Seccomp
- test
- Usage
- reviews
- Fixed Findings (Detailed)
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
- copilot-instructions.md
- opencode.json
- gyrseek
- test
- parse_npm_spec

## God Nodes (most connected - your core abstractions)
1. `Review history` - 193 edges
2. `Won't Fix Findings - Detailed` - 118 edges
3. `Detailed Findings` - 107 edges
4. `scan_packages_versions()` - 63 edges
5. `load()` - 45 edges
6. `run()` - 33 edges
7. `Code Security` - 31 edges
8. `find_new_connections_domain_aware()` - 28 edges
9. `rewrite_args_with_pinned_versions()` - 24 edges
10. `extract_process_exec_signatures()` - 24 edges

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
- 1-file cycle: `src/lib.rs -> src/lib.rs`
- 1-file cycle: `src/sandbox.rs -> src/sandbox.rs`
- 1-file cycle: `src/scanning.rs -> src/scanning.rs`

## Hyperedges (group relationships)
- **Docker sandbox hardening layers** — docs_docker_security_sys_ptrace, docs_docker_security_seccomp, docs_docker_security_apparmor, docs_docker_security_unprivileged_payload [EXTRACTED 0.90]
- **Network anomaly domain-aware diff pipeline** — docs_architecture_domain_aware_diff, docs_architecture_fcrdns, docs_architecture_dns_interceptor, docs_architecture_allowlists [EXTRACTED 0.90]
- **Nono detection parity instrumentation** — docs_architecture_canary_trap, docs_architecture_path_shims, docs_architecture_scan_target_artifacts, docs_architecture_nono_runner [EXTRACTED 0.90]
- **Core source modules** — src_main, src_lib, src_parsing, src_scanning, src_sandbox [EXTRACTED 1.00]
- **Five behavioral anomaly checks** — readme_network_behavior_detection, readme_git_clone_behavior_detection, readme_process_execution_behavior_detection, readme_sensitive_file_detection, readme_artifact_detection [EXTRACTED 1.00]
- **Sandbox backends** — readme_docker_sandbox, readme_nono_sandbox, readme_host_sandbox [EXTRACTED 1.00]
- **Install-time behavioral signal extraction** — src_scanning_extract_connection_ips, src_scanning_extract_git_clone_signatures, src_scanning_extract_process_exec_signatures [INFERRED 0.85]
- **Scan-then-forward orchestration pipeline** — src_lib_run, src_scanning_scan_packages_versions, src_lib_forward_pinned_command [INFERRED 0.85]

## Communities (178 total, 53 thin omitted)

### Community 0 - "Review history"
Cohesion: 0.01
Nodes (193): Finding 100 — Low | `.github/workflows/ci.yml` | ✅ Fixed, Finding 101 — Low | `.github/workflows/ci.yml` | ✅ Fixed, Finding 102 — Medium | `.github/workflows/post_review.yml` | ✅ Fixed, Finding 103 — Low | `.github/workflows/ci.yml` | ✅ Fixed, Finding 104 — Low | `.github/workflows/ci.yml` | ✅ Fixed, Finding 105 — Low | `.github/workflows/ci.yml` | ✅ Fixed, Finding 106 — High | `.github/workflows/ci.yml` | ✅ Fixed, Finding 107 — Low | `docs/ARCHITECTURE.md` | ✅ Fixed (+185 more)

### Community 1 - "Routing, Config & Scan Orchestration"
Cohesion: 0.02
Nodes (118): Finding 118 — Low | `.github/workflows/ci.yml` | 🛑 Wont Fix, Finding 123 — High | `.github/workflows/post_review.yml` | 🛑 Wont Fix / Invalid, Finding 124 — Low | `.github/scripts/sanitize_review.py` | 🛑 Wont Fix, Finding 125 — Low | `.github/scripts/post_comment.sh` | 🛑 Wont Fix / Invalid, Finding 129 — Low | `.github/scripts/post_comment.sh` | 🛑 Wont Fix / Accepted Risk, Finding 138 — Low | `.github/scripts/sanitize_review.py` | 🛑 Wont Fix / Accepted Risk, Finding 151 — Invalid | `.github/scripts/sanitize_review.py` | 🛑 Wont Fix, Finding 152 — Accepted Risk | `.github/scripts/sanitize_review.py` | 🛑 Wont Fix (+110 more)

### Community 2 - "Detailed Findings"
Cohesion: 0.02
Nodes (107): Detailed Findings, Finding 14 — Low | `parsing.rs:880` | ⚠️ Open, Finding 170 — Medium | `ARCHITECTURE.md` | ⚠️ Open, Finding 171 — High | `scanning.rs` | ⚠️ Open, Finding 172 — Medium | `ARCHITECTURE.md` | ⚠️ Open, Finding 173 — Medium | `ARCHITECTURE.md` | ⚠️ Open, Finding 177 — Low | `*_DETAILED.md` | ⚠️ Open, Finding 180 — Low | `lib.rs:1092-1173` | ⚠️ Open (+99 more)

### Community 3 - "scanning.rs"
Cohesion: 0.04
Nodes (53): DNS wire-format parser (extract_dns_map), scan_packages_versions / ScanReport, artifact_allowlist_does_not_leak_across_packages(), artifact_allowlist_matches_exact_finding_and_prefix(), ARTIFACT_DELIMITER, burst_policy_emits_warning_when_triggered(), burst_policy_no_warning_below_threshold_or_disabled(), burst_policy_warning() (+45 more)

### Community 4 - "sandbox.rs"
Cohesion: 0.06
Nodes (28): APPARMOR_LOAD_ERR, artifact_scan_steps_inventory_all_files(), artifact_scan_steps_output_to_correct_log(), artifact_scan_steps_pipe_char_in_content_replaced(), artifact_scan_steps_uses_null_byte_delimiter(), build_artifact_scan_steps(), DEFAULT_PROBE_TIMEOUT_SECS, docker_preflight_distinguishes_daemon_down_permission_and_broken_cli() (+20 more)

### Community 5 - "Bun Execution Detection & Exemptions"
Cohesion: 0.07
Nodes (44): validate_allowlist_pkg_key, accepts_new_package_exemptions_empty_list_as_no_exemptions(), baseline_count_zero_falls_back_to_default_two(), clamps_min_baseline_age_hours_to_hard_floor(), DEFAULT_CONFIG_PATH, domain_allowlist_bare_tld_rejected_in_global_and_per_package_positions(), domain_allowlist_empty_value_dropped_in_global_and_per_package_positions(), domain_allowlist_star_value_rejected_in_global_and_per_package_positions() (+36 more)

### Community 6 - "FCrDNS Allowlist Verification"
Cohesion: 0.08
Nodes (44): a_candidate_that_ran_something_new_before_failing_reports_both(), a_failed_baseline_blocks_on_install_failed_alone(), a_failed_install_blocks_only_its_own_package_in_a_batch(), a_new_package_exemption_cannot_clear_a_failed_install(), allows_new_bun_when_allowlisted(), allows_when_artifact_findings_match_baseline(), allows_when_bun_behavior_matches_baseline(), artifact_allowlist_unblocks_new_findings() (+36 more)

### Community 7 - "High Impact"
Cohesion: 0.06
Nodes (34): 10. Insecure Cryptography (insecure-crypto), 11. Insecure Transport (insecure-transport), 12. Server-Side Request Forgery (ssrf), 13. JWT Authentication (authentication-jwt), 14. Cross-Site Request Forgery (csrf), 15. Prototype Pollution (prototype-pollution), 16. Unsafe Functions (unsafe-functions), 17. Terraform AWS Security (terraform-aws) (+26 more)

### Community 8 - "parse_npm_install_packages_from_args"
Cohesion: 0.11
Nodes (29): on, pull_request, push, workflow_dispatch, branches, has_only_non_registry_npm_specs(), is_lockfile_only_command(), is_non_registry_npm_spec() (+21 more)

### Community 9 - "NonoRunner backend"
Cohesion: 0.50
Nodes (4): CanaryTrap FIFO decoys, NonoRunner backend, PathShims, scan_target_artifacts / classify_inventory_lines

### Community 10 - "run"
Cohesion: 0.13
Nodes (11): exit_with(), GyrSeek, no_sandbox_flag_is_consumed_wherever_it_appears(), run(), take_no_sandbox_flag(), test: minimum_release_age_package not met exits 1, test: release_burst_threshold triggers exit 1, bare_uv_lock_is_routed_to_lockfile_scan() (+3 more)

### Community 11 - "Semgrep Quick Reference"
Cohesion: 0.25
Nodes (8): Commands, Metadata Fields, Path Filtering, Required Rule Fields, Semgrep Quick Reference, Supported Languages, Test Annotations, Testing

### Community 12 - "trace_install_docker_matrix"
Cohesion: 0.20
Nodes (7): DockerRunner, InstallFailure, ProbeTrace, trace_install_docker_matrix(), FailingInstallRunner, install_failed_message(), MockRunner

### Community 13 - "Docker Security"
Cohesion: 0.20
Nodes (11): Backout plan, Current hardening limitations, Docker Security, Overview, Platform support matrix, Prebuilt scanner images, Regression signals, Related env vars (+3 more)

### Community 14 - "extract_process_exec_signatures"
Cohesion: 0.08
Nodes (29): case_1_new_bun_is_flagged_against_clean_baseline(), case_2_existing_bun_plus_additional_invocation_is_flagged(), case_2b_changed_bun_arguments_are_flagged(), executable_basename(), extract_git_clone_signatures(), extract_process_exec_captures_all_executables(), extract_process_exec_captures_bun_run_with_argv(), extract_process_exec_preserves_brackets_in_argv() (+21 more)

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
Cohesion: 0.12
Nodes (17): Detailed Findings, Finding 10 — Critical | `scanning.rs:654` | ✅ Fixed, Finding 13 — Medium | `scanning.rs:1852` | ✅ Fixed, Finding 15 — Low | `sandbox.rs:511` | ✅ Fixed, Finding 16 — Medium | `scanning.rs:509` | ✅ Fixed, Finding 17 — High | `scanning.rs:972` | ✅ Fixed, Finding 18 — Medium | `scanning.rs:467` | ✅ Fixed, Finding 19 — High | `scanning.rs:392` | ✅ Fixed (+9 more)

### Community 19 - "Version Flag Tests"
Cohesion: 0.06
Nodes (30): detects_anomalous_new_connection(), detects_new_connection_in_git_clone_simulation(), dns_interceptor_skips_when_domain_not_in_baseline(), dns_interceptor_skips_when_forward_resolver_does_not_confirm(), domain_aware_diff_cdn_rotation_without_ptr_handled_by_dns_interceptor(), domain_aware_diff_current_resolves_baseline_ip_unresolvable(), domain_aware_diff_current_unresolved_ip_in_baseline_not_flagged(), domain_aware_diff_discards_ip_when_domain_seen_in_baseline() (+22 more)

### Community 20 - "npm/package.json"
Cohesion: 0.15
Nodes (14): author, dependencies, lodash@^4.18.1, typescript@^6.0.3, description, lodash, typescript, license (+6 more)

### Community 21 - "trace_sandbox_install_matrix"
Cohesion: 0.11
Nodes (19): artifact_delimiter_pipe_in_path_is_not_injected(), artifact_findings_empty_for_clean_install(), classify_inventory_benign_pth(), classify_inventory_binary_elf(), classify_inventory_empty_input(), classify_inventory_large_file(), classify_inventory_lines(), classify_inventory_mixed_findings() (+11 more)

### Community 22 - "runtime_image.rs"
Cohesion: 0.07
Nodes (53): an_empty_blank_or_unreadable_version_file_is_skipped_not_fatal(), choice(), config_value_wins_over_project_files(), config_values_are_normalised_and_validated(), DEFAULT_NODE, DEFAULT_PYTHON, dir_with(), engines_node_of_the_wrong_json_shape_is_ignored() (+45 more)

### Community 23 - "extract_sensitive_file_reads"
Cohesion: 0.14
Nodes (14): extract_first_arg_fd(), extract_sensitive_file_reads(), is_sensitive_file_read(), lexical_clean_path(), parse_syscall_return(), test_appsec_evasion_bypasses(), test_appsec_evasion_exhaustive_variants(), test_extract_sensitive_file_reads() (+6 more)

### Community 24 - "parse_global_options"
Cohesion: 0.33
Nodes (6): config_equals_form_preserves_equals_in_path(), config_path_starting_with_dash_is_accepted(), danger_disable_seccomp_parsing_edge_cases(), keeps_args_untouched_when_no_global_options_present(), parse_global_options(), parses_global_config_flag_and_strips_it_from_manager_args()

### Community 27 - "Critical Impact"
Cohesion: 0.12
Nodes (16): 10. Unbounded Consumption (unbounded-consumption), 1. Prompt Injection (prompt-injection), 2. Sensitive Information Disclosure (sensitive-disclosure), 3. Supply Chain (supply-chain), 4. Data and Model Poisoning (data-poisoning), 5. Improper Output Handling (output-handling), 6. Excessive Agency (excessive-agency), 7. System Prompt Leakage (system-prompt-leakage) (+8 more)

### Community 28 - "parsing.rs"
Cohesion: 0.10
Nodes (32): LOCKFILE_ONLY_FLAGS, MAX_REQUIREMENTS_DEPTH, parse_poetry_lock_packages_from_content(), parse_pylock_packages_from_content(), parse_requirements_packages_from_content(), parse_requirements_spec(), parse_toml_quoted_value(), parse_uv_lock_packages_from_content() (+24 more)

### Community 29 - "select_effective_baselines"
Cohesion: 0.12
Nodes (17): baseline_count_limits_fetched_baselines_without_overrides(), baseline_count_zero_does_not_fail_closed(), baseline_count_zero_returns_no_effective_baselines(), baseline_count_zero_with_override_equal_to_current_returns_empty(), BaselineOverrides, both_override_slots_none_falls_through_to_fetched_baselines(), both_overrides_equal_to_current_skipped_and_filled_from_fetched(), duplicate_override_versions_are_deduped_and_truncated() (+9 more)

### Community 30 - "build_matrix_script"
Cohesion: 0.14
Nodes (17): build_matrix_script(), build_single_script(), every_probe_runs_under_the_configured_timeout(), image_setup_steps(), is_npm_family_manager(), matrix_and_single_scripts_disable_truncation(), matrix_script_captures_strace_stderr_not_devnull(), matrix_script_creates_scanner_user_before_install() (+9 more)

### Community 31 - "filter_domain_allowlisted_new_connections_with"
Cohesion: 0.12
Nodes (17): domain_allowlist_does_not_filter_when_lookup_fails(), domain_allowlist_filters_resolved_domains_before_blocking(), domain_allowlist_normalization_matches_case_whitespace_and_trailing_dot(), domain_is_allowlisted(), filter_allowlisted_new_connections(), filter_domain_allowlisted_new_connections_with(), global_domain_allowlist_applies_to_all_packages(), global_ip_allowlist_applies_to_all_packages() (+9 more)

### Community 32 - "gyrseek"
Cohesion: 0.17
Nodes (11): Behavior Reference, gyrseek, Introduction, Just Recipes, License, Package Related Supply Chain Attack Detection Coverage, Project Layout & Docs, Supported Commands (+3 more)

### Community 33 - "Prevent Insecure Deserialization"
Cohesion: 0.13
Nodes (14): BinaryFormatter Deserialization, General Prevention Guidelines, Language: C#, Language: Java, Language: JavaScript / TypeScript, Language: PHP, Language: Python, Language: Ruby (+6 more)

### Community 34 - "Semgrep Skill"
Cohesion: 0.13
Nodes (14): Acknowledgments, Capabilities, Creating Custom Rules, Example Prompts, For End Users, Quick Reference, Resources, Rule Creation Workflow (+6 more)

### Community 35 - "Command"
Cohesion: 0.07
Nodes (38): forward_args, forward_original_command, forward_pinned_command, exits_with_code_1_and_rejects_versions_newer_than_72_hours_by_default(), exits_with_code_1_and_uses_configured_release_burst_window_hours(), exits_with_code_1_and_warning_when_release_burst_threshold_triggers(), exits_with_code_1_when_minimum_release_age_package_is_not_met(), minimum_release_age_package_runs_before_burst_threshold() (+30 more)

### Community 36 - "with"
Cohesion: 0.05
Nodes (61): name, permissions, runs-on, steps, env, CARGO_TERM_COLOR, GYRSEEK_DOCKER_APPARMOR_PROFILE, GYRSEEK_NPM_SCANNER_IMAGE (+53 more)

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

### Community 43 - "python_multi_package_tests.rs"
Cohesion: 0.24
Nodes (15): a_missing_requirements_file_fails_closed_for_every_spelling(), an_attached_r_option_and_unpinned_file_lines_are_not_missed(), an_empty_requirements_file_fails_closed_instead_of_scanning_nothing(), direct_references_are_not_scanned_as_if_they_were_registry_packages(), install_with_no_package_names_fails_closed(), packages_in_an_included_requirements_file_are_scanned(), poetry_add_scans_every_named_package(), r_pyproject_toml_fails_closed_instead_of_scanning_a_package_named_after_the_file() (+7 more)

### Community 44 - "General Best Practices for Avoiding Race Conditions"
Cohesion: 0.15
Nodes (11): General Best Practices for Avoiding Race Conditions, Hardcoded /tmp Path, Insecure Temporary File Creation, Insecure Temporary File Creation, Language: Go, Language: OCaml, Language: Python, Language-Specific Secure Alternatives (+3 more)

### Community 45 - "Semgrep Rule Creation Workflow"
Cohesion: 0.06
Nodes (36): Basic Pattern Matching, Basic Taint Structure, Common Fixes, Common Redundancies to Remove, Debug Failures, Debug Taint Rules, Directory Structure, Example: Complete Taint Rule (+28 more)

### Community 46 - "collect_probe_traces"
Cohesion: 0.35
Nodes (13): a_blank_trace_even_after_the_re_run_fails_closed_with_the_strace_error(), a_failed_re_run_is_an_error_not_a_clean_scan(), a_missing_or_blank_batch_trace_is_re_run_on_its_own(), a_timed_out_probe_is_omitted_and_never_re_run(), an_exit_code_file_marks_only_that_probe_as_a_failed_install(), collect_probe_traces(), collects_each_probes_trace_in_order_and_appends_the_artifact_inventory(), empty_or_whitespace_artifact_inventories_add_nothing() (+5 more)

### Community 47 - "load_policy_config"
Cohesion: 0.14
Nodes (16): load_policy_config(), missing_default_config_returns_empty_allowlist(), missing_explicit_config_fails_closed(), node_version_config_is_validated_against_the_supported_table(), option_zero_to_none(), option_zero_to_none_direct(), parse_list(), parse_list_map() (+8 more)

### Community 48 - "build_docker_run_args"
Cohesion: 0.12
Nodes (14): build_docker_run_args(), custom_scanner_images_are_named_in_the_description(), docker_args_adds_seccomp_profile_by_default(), docker_args_disables_seccomp_when_danger_flag_true(), docker_args_grant_sys_ptrace_capability(), docker_args_keep_out_mount_when_provided_and_omit_when_empty(), docker_args_memory_limit_defaults_to_2g_and_is_configurable(), docker_enforces_sandbox_constraints() (+6 more)

### Community 49 - "extract_connection_ips"
Cohesion: 0.17
Nodes (13): extract_connection_ips(), extract_connection_ips_captures_ipv4(), extract_connection_ips_captures_ipv6_inet_pton(), extract_connection_ips_collapses_ipv4_mapped_ipv6(), extract_connection_ips_drops_loopback_link_local_and_private(), extract_connection_ips_handles_mixed_v4_and_v6(), extract_connection_ips_keeps_cloud_metadata_endpoint(), extract_connection_ips_keeps_public_ipv4_mapped_ipv6_as_ipv4() (+5 more)

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

### Community 63 - "parse_python_install_packages_from_args"
Cohesion: 0.18
Nodes (12): direct_references_and_urls_are_rejected(), exact(), exact_requirements_are_accepted_in_every_form(), is_plain_version(), malformed_requirements_fail_closed_instead_of_being_guessed(), non_requirement_lines_are_skipped(), parse_exact_requirement(), poetry_at_forms_edge_cases() (+4 more)

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

### Community 105 - "decode_dns_name"
Cohesion: 0.14
Nodes (14): decode_dns_name(), decode_dns_name_circular_pointer_returns_none(), decode_dns_name_excessive_pointer_hops_returns_none(), decode_dns_name_long_but_not_circular_pointer_chain(), decode_dns_name_out_of_bounds_returns_none(), decode_dns_name_recursive_pointer_chain(), decode_dns_name_root_label_only(), decode_dns_name_simple_two_label() (+6 more)

### Community 106 - "env_lock"
Cohesion: 0.29
Nodes (3): active_test_env_vars_none_set_returns_empty(), env_lock(), EnvVarGuard

### Community 107 - "LLM01: Prevent Prompt Injection"
Cohesion: 0.33
Nodes (5): Direct Prompt Injection Prevention, Indirect Prompt Injection Prevention (RAG Systems), Key Prevention Rules, LLM01: Prevent Prompt Injection, Output Filtering

### Community 108 - "read_install_failure"
Cohesion: 0.40
Nodes (6): install_failure_output_is_read_from_the_end_of_a_huge_log(), install_output_tail(), install_output_tail_is_printable_and_drops_strace_noise(), read_file_tail(), read_install_failure(), read_install_failure_needs_the_exit_code_marker()

### Community 109 - "Understand Code"
Cohesion: 0.33
Nodes (5): Approach, Checklist, Goal, Understand Code, Verification

### Community 110 - "WONT_FIX_FINDINGS_DETAILED.md"
Cohesion: 0.33
Nodes (4): Detailed Rationale, Won't Fix Findings (Detailed), Summary, Won't Fix Findings

### Community 111 - "Pattern Operators"
Cohesion: 0.29
Nodes (7): Basic Matching, Deep Matching, Metavariable Filters, Metavariables, Negation, Pattern Operators, Scope Operators

### Community 112 - "Common Patterns by Vulnerability"
Cohesion: 0.29
Nodes (7): Command Injection, Common Patterns by Vulnerability, Dangerous Functions (Pattern Matching), Hardcoded Secrets (Pattern Matching), Path Traversal, SQL Injection, XSS

### Community 113 - "rewrite_args_with_pinned_versions"
Cohesion: 0.18
Nodes (19): rewrite_args_with_pinned_versions, Exact-version pinning of forwarded command, args(), does_not_pin_npm_package_with_latest_sentinel(), does_not_pin_pip_package_with_latest_sentinel(), does_not_pin_unrelated_packages(), does_not_repin_npm_package_that_already_has_a_version(), empty_pins_is_a_noop() (+11 more)

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

### Community 118 - "Taint Mode"
Cohesion: 0.40
Nodes (5): Basic Structure, Propagators, Source/Sink Options, Taint Components, Taint Mode

### Community 119 - "build_runner_from_env"
Cohesion: 0.27
Nodes (8): HostRunner, is_timeout_exit(), npm_family_install_dir_flag(), npm_family_install_subcommand(), probe_timeout_message(), timeout_exit_codes_cover_term_and_kill_only(), timeout_message_names_the_probe_and_the_setting(), trace_install_docker_single()

### Community 120 - "Configuration"
Cohesion: 0.40
Nodes (5): CLI Arguments, Config keys, Config loading behavior, Configuration, Example config

### Community 121 - "AllowlistEntry"
Cohesion: 0.40
Nodes (5): AllowlistEntry, Global, PerPackage, BaselineOverrideConfig, GyrseekConfig

### Community 122 - "docker_apparmor_profile_name"
Cohesion: 0.15
Nodes (14): announce_apparmor_status(), announce_seccomp_status(), apparmor_disabled_wont_call_apparmor_parser(), apparmor_env_var_default_false(), build_runner_from_env(), docker_apparmor_enabled_from_env(), docker_apparmor_profile_name(), docker_daemon_error_message() (+6 more)

### Community 123 - "code-injection.md"
Cohesion: 0.50
Nodes (3): Key Prevention Patterns, Prevent Code Injection, References

### Community 124 - "parsing.rs"
Cohesion: 0.13
Nodes (23): a_bad_nested_include_fails_closed(), an_attached_short_r_option_on_the_command_line_is_scanned(), boolean_flags_never_swallow_the_package_after_them(), command_lines_with_missing_values_or_empty_arguments_do_not_panic(), every_include_spelling_is_followed(), flag_values_are_not_mistaken_for_packages(), include_cycles_terminate_and_deep_nesting_fails_closed(), include_edge_cases_absolute_paths_directories_case_and_the_depth_boundary() (+15 more)

### Community 125 - "Quick Start"
Cohesion: 0.50
Nodes (4): 1. Prerequisites, 2. Build, 3. Run your first scan, Quick Start

### Community 126 - "PolicyConfig"
Cohesion: 0.18
Nodes (11): LazyRunner, NoopRunner, scan_many_with_cache(), scan_targets(), scan_with_cache(), ScanTimer, SandboxRunner, PolicyConfig (+3 more)

### Community 128 - "Seccomp"
Cohesion: 0.40
Nodes (5): Configuration, Platform note, Profile behavior, Seccomp, Status output

### Community 138 - "Usage"
Cohesion: 0.50
Nodes (4): npm examples, pnpm examples, Python examples, Usage

### Community 140 - "Fixed Findings (Detailed)"
Cohesion: 0.33
Nodes (4): Cross-Finding Chains (Architectural Context), Fixed Findings (Detailed), Fixed Findings, Summary

### Community 142 - "ForwardMode"
Cohesion: 0.67
Nodes (3): ForwardMode, Original, Pinned

### Community 184 - "parse_npm_spec"
Cohesion: 0.16
Nodes (16): is_valid_npm_name(), lockfile_entries_with_missing_or_odd_fields_are_handled(), lockfile_parsers_survive_hostile_and_degenerate_input(), npm_cli_specs_must_name_one_exact_registry_version(), npm_names_and_specs_edge_cases(), package_lock_v1_walks_nested_dependencies(), package_lock_v3_lists_every_installed_registry_version(), parse_exact_npm_spec() (+8 more)

## Knowledge Gaps
- **43 isolated node(s):** `Global`, `PerPackage`, `Original`, `Pinned`, `Python` (+38 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 1219 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **53 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `on` connect `parse_npm_install_packages_from_args` to `with`?**
  _High betweenness centrality (0.027) - this node is a cross-community bridge._
- **Are the 12 inferred relationships involving `load()` (e.g. with `baseline_count_zero_falls_back_to_default_two()` and `minimum_release_age_package_zero_disables_policy()`) actually correct?**
  _`load()` has 12 INFERRED edges - model-reasoned connections that need verification._
- **What connects `Global`, `PerPackage`, `Original` to the rest of the system?**
  _43 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Review history` be split into smaller, more focused modules?**
  _Cohesion score 0.010362694300518135 - nodes in this community are weakly interconnected._
- **Why does `gyrseek` connect `gyrseek` to `Network Behavior Detection`, `DOCKER_SECURITY.md`, `How It Works`, `Prebuilt Scanner Images`, `Usage`, `Sandbox Modes`, `rewrite_args_with_pinned_versions`, `Process-Execution Behavior Detection`, `Configuration`, `Quick Start`?**
  _High betweenness centrality (0.022) - this node is a cross-community bridge._
- **Should `Routing, Config & Scan Orchestration` be split into smaller, more focused modules?**
  _Cohesion score 0.01694915254237288 - nodes in this community are weakly interconnected._
- **Should `Detailed Findings` be split into smaller, more focused modules?**
  _Cohesion score 0.018691588785046728 - nodes in this community are weakly interconnected._