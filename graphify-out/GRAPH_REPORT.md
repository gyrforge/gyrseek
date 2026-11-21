# Graph Report - gyrseek  (2026-11-21)

## Corpus Check
- 97 files · ~194,806 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 10 file(s) not represented in the graph (top: (none) 6, .npm 1, .python 1)

## Summary
- 2076 nodes · 2798 edges · 178 communities (130 shown, 48 thin omitted)
- Extraction: 97% EXTRACTED · 3% INFERRED · 0% AMBIGUOUS · INFERRED: 91 edges (avg confidence: 0.85)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `911b6aab`
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
- select_effective_baselines
- NonoRunner backend
- run
- Semgrep Quick Reference
- Burst/Release-Age CLI Tests
- Docker Security
- extract_process_exec_signatures
- Code Correctness Rules
- Fail-Closed Policy & Findings
- Network Anomaly Decision
- Detailed Findings
- Version Flag Tests
- npm/package.json
- decode_dns_name
- build_runner_from_env
- forward_confirmed_hostname
- Fixed Findings (Detailed)
- Critical Impact
- parsing.rs
- cli_burst_exit_tests.rs
- build_matrix_script
- filter_domain_allowlisted_new_connections_with
- gyrseek
- Prevent Insecure Deserialization
- Semgrep Skill
- sandbox_startup_exit_tests.rs
- uses
- Code Security Skill
- Prevent Path Traversal
- Prevent Cross-Site Scripting (XSS)
- LLM Security Skill
- Tests documentation
- Developer Guide
- env
- General Best Practices for Avoiding Race Conditions
- Semgrep Rule Creation Workflow
- jobs
- load_policy_config
- SandboxEnvVarGuard
- extract_connection_ips
- Process-Execution Behavior Detection
- Prevent XML External Entity (XXE) Injection
- Part 2: Creating Custom Rules
- .new
- Architecture
- Roadmap
- with
- pnpm/package.json
- Code Best Practices
- terraform-gcp.md
- Categories
- LLM Security Guidelines (OWASP Top 10 for LLM 2025)
- Pattern Operators
- Network Behavior Detection
- Prevent Cross-Site Request Forgery
- Secure Kubernetes Configurations
- Secure Azure Terraform Configurations
- Interrogation
- semgrep/SKILL.md
- filter_allowlisted_git_clone_signatures
- Python
- Prevent SQL Injection
- LLM03: Secure LLM Supply Chain
- Ponytail
- Agents Memory and Workflow
- Sandbox Modes
- name
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
- AGENTS.md repository memory
- Prevent Command Injection
- Secure GitHub Actions
- Ensure Memory Safety
- Threat Model & Accepted Risks
- Validation checklist
- Open Findings
- How It Works
- Prebuilt Scanner Images
- extract_dns_map
- env_lock
- LLM01: Prevent Prompt Injection
- trace_install_docker_matrix
- Understand Code
- WONT_FIX_FINDINGS_DETAILED.md
- Common Patterns by Vulnerability
- strace_install_command
- .yamllint.yaml
- Prevent Regular Expression DoS (ReDoS)
- ponytail-review/SKILL.md
- AppArmor
- build_docker_run_args
- Configuration
- AllowlistEntry
- docker_apparmor_profile_name
- code-injection.md
- Taint Mode
- Quick Start
- PolicyConfig
- steps
- Seccomp
- on
- Policy allowlists (global and per-package)
- steps
- steps
- Usage
- reviews
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
- deserialize_new_package_exemptions
- copilot-instructions.md
- opencode.json
- steps
- gyrseek
- test
- test

## God Nodes (most connected - your core abstractions)
1. `Review history` - 176 edges
2. `Won't Fix Findings - Detailed` - 118 edges
3. `Detailed Findings` - 102 edges
4. `scan_packages_versions()` - 58 edges
5. `load()` - 40 edges
6. `Code Security` - 31 edges
7. `run()` - 29 edges
8. `find_new_connections_domain_aware()` - 28 edges
9. `extract_process_exec_signatures()` - 24 edges
10. `rewrite_args_with_pinned_versions()` - 23 edges

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

## Communities (178 total, 48 thin omitted)

### Community 0 - "Review history"
Cohesion: 0.01
Nodes (176): Finding 100 — Low | `.github/workflows/ci.yml` | ✅ Fixed, Finding 101 — Low | `.github/workflows/ci.yml` | ✅ Fixed, Finding 102 — Medium | `.github/workflows/post_review.yml` | ✅ Fixed, Finding 103 — Low | `.github/workflows/ci.yml` | ✅ Fixed, Finding 104 — Low | `.github/workflows/ci.yml` | ✅ Fixed, Finding 105 — Low | `.github/workflows/ci.yml` | ✅ Fixed, Finding 106 — High | `.github/workflows/ci.yml` | ✅ Fixed, Finding 107 — Low | `docs/ARCHITECTURE.md` | ✅ Fixed (+168 more)

### Community 1 - "Routing, Config & Scan Orchestration"
Cohesion: 0.02
Nodes (118): Finding 118 — Low | `.github/workflows/ci.yml` | 🛑 Wont Fix, Finding 123 — High | `.github/workflows/post_review.yml` | 🛑 Wont Fix / Invalid, Finding 124 — Low | `.github/scripts/sanitize_review.py` | 🛑 Wont Fix, Finding 125 — Low | `.github/scripts/post_comment.sh` | 🛑 Wont Fix / Invalid, Finding 129 — Low | `.github/scripts/post_comment.sh` | 🛑 Wont Fix / Accepted Risk, Finding 138 — Low | `.github/scripts/sanitize_review.py` | 🛑 Wont Fix / Accepted Risk, Finding 151 — Invalid | `.github/scripts/sanitize_review.py` | 🛑 Wont Fix, Finding 152 — Accepted Risk | `.github/scripts/sanitize_review.py` | 🛑 Wont Fix (+110 more)

### Community 2 - "Detailed Findings"
Cohesion: 0.02
Nodes (102): Detailed Findings, Finding 14 — Low | `parsing.rs:880` | ⚠️ Open, Finding 170 — Medium | `ARCHITECTURE.md` | ⚠️ Open, Finding 171 — High | `scanning.rs` | ⚠️ Open, Finding 172 — Medium | `ARCHITECTURE.md` | ⚠️ Open, Finding 173 — Medium | `ARCHITECTURE.md` | ⚠️ Open, Finding 177 — Low | `*_DETAILED.md` | ⚠️ Open, Finding 180 — Low | `lib.rs:1092-1173` | ⚠️ Open (+94 more)

### Community 3 - "scanning.rs"
Cohesion: 0.04
Nodes (52): DNS wire-format parser (extract_dns_map), scan_packages_versions / ScanReport, artifact_allowlist_does_not_leak_across_packages(), artifact_allowlist_matches_exact_finding_and_prefix(), ARTIFACT_DELIMITER, artifact_delimiter_pipe_in_path_is_not_injected(), artifact_findings_empty_for_clean_install(), burst_policy_emits_warning_when_triggered() (+44 more)

### Community 4 - "sandbox.rs"
Cohesion: 0.10
Nodes (13): APPARMOR_LOAD_ERR, artifact_scan_steps_inventory_all_files(), artifact_scan_steps_output_to_correct_log(), artifact_scan_steps_pipe_char_in_content_replaced(), artifact_scan_steps_uses_null_byte_delimiter(), build_artifact_scan_steps(), docker_preflight_distinguishes_daemon_down_permission_and_broken_cli(), EMBEDDED_APPARMOR_PROFILE_NAME (+5 more)

### Community 5 - "Bun Execution Detection & Exemptions"
Cohesion: 0.08
Nodes (41): validate_allowlist_pkg_key, accepts_new_package_exemptions_empty_list_as_no_exemptions(), baseline_count_zero_falls_back_to_default_two(), clamps_min_baseline_age_hours_to_hard_floor(), DEFAULT_CONFIG_PATH, domain_allowlist_bare_tld_rejected_in_global_and_per_package_positions(), domain_allowlist_empty_value_dropped_in_global_and_per_package_positions(), domain_allowlist_star_value_rejected_in_global_and_per_package_positions() (+33 more)

### Community 6 - "FCrDNS Allowlist Verification"
Cohesion: 0.09
Nodes (39): allows_new_bun_when_allowlisted(), allows_when_artifact_findings_match_baseline(), allows_when_bun_behavior_matches_baseline(), artifact_allowlist_unblocks_new_findings(), artifact_delimiter_injection_attack_defeated_end_to_end(), artifact_delimiter_injection_does_not_block_clean_package(), exemption_behavior(), find_new_git_clone_signatures() (+31 more)

### Community 7 - "High Impact"
Cohesion: 0.06
Nodes (34): 10. Insecure Cryptography (insecure-crypto), 11. Insecure Transport (insecure-transport), 12. Server-Side Request Forgery (ssrf), 13. JWT Authentication (authentication-jwt), 14. Cross-Site Request Forgery (csrf), 15. Prototype Pollution (prototype-pollution), 16. Unsafe Functions (unsafe-functions), 17. Terraform AWS Security (terraform-aws) (+26 more)

### Community 8 - "select_effective_baselines"
Cohesion: 0.12
Nodes (17): baseline_count_limits_fetched_baselines_without_overrides(), baseline_count_zero_does_not_fail_closed(), baseline_count_zero_returns_no_effective_baselines(), baseline_count_zero_with_override_equal_to_current_returns_empty(), BaselineOverrides, both_override_slots_none_falls_through_to_fetched_baselines(), both_overrides_equal_to_current_skipped_and_filled_from_fetched(), duplicate_override_versions_are_deduped_and_truncated() (+9 more)

### Community 9 - "NonoRunner backend"
Cohesion: 0.50
Nodes (4): CanaryTrap FIFO decoys, NonoRunner backend, PathShims, scan_target_artifacts / classify_inventory_lines

### Community 10 - "run"
Cohesion: 0.10
Nodes (15): config_equals_form_preserves_equals_in_path(), config_path_starting_with_dash_is_accepted(), danger_disable_seccomp_parsing_edge_cases(), exit_with(), keeps_args_untouched_when_no_global_options_present(), parse_global_options(), parses_global_config_flag_and_strips_it_from_manager_args(), run() (+7 more)

### Community 11 - "Semgrep Quick Reference"
Cohesion: 0.25
Nodes (8): Commands, Metadata Fields, Path Filtering, Required Rule Fields, Semgrep Quick Reference, Supported Languages, Test Annotations, Testing

### Community 12 - "Burst/Release-Age CLI Tests"
Cohesion: 0.07
Nodes (26): 10. Full pipeline integration: strace → dns_map → domain-aware diff (1 test), 11. Expanded Test Coverage (310 tests total), 12. `check_override_ages` — filtered-override return value (5 tests), 13. `HARD_MINIMUM_AGE_HOURS` floor enforcement (1 test), 1. `forward_confirmed_hostname` — FCrDNS core logic (3 tests), 2. `reverse_dns_domain` — production resolver parse guard (1 test), 3. `find_new_connections_domain_aware` — domain-aware IP diff (14 tests), 4. `filter_allowlisted_new_connections` — IP allowlist (3 tests) (+18 more)

### Community 13 - "Docker Security"
Cohesion: 0.14
Nodes (16): Backout plan, Capabilities and privileges, Current hardening limitations, Docker Security, Overview, Platform support matrix, Prebuilt scanner images, Probe batching (+8 more)

### Community 14 - "extract_process_exec_signatures"
Cohesion: 0.10
Nodes (25): case_1_new_bun_is_flagged_against_clean_baseline(), case_2_existing_bun_plus_additional_invocation_is_flagged(), case_2b_changed_bun_arguments_are_flagged(), executable_basename(), extract_git_clone_signatures(), extract_process_exec_captures_all_executables(), extract_process_exec_captures_bun_run_with_argv(), extract_process_exec_preserves_brackets_in_argv() (+17 more)

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
Cohesion: 0.09
Nodes (22): detects_anomalous_new_connection(), detects_new_connection_in_git_clone_simulation(), dns_interceptor_skips_when_domain_not_in_baseline(), dns_interceptor_skips_when_forward_resolver_does_not_confirm(), domain_aware_diff_cdn_rotation_without_ptr_handled_by_dns_interceptor(), domain_aware_diff_current_resolves_baseline_ip_unresolvable(), domain_aware_diff_current_unresolved_ip_in_baseline_not_flagged(), domain_aware_diff_discards_ip_when_domain_seen_in_baseline() (+14 more)

### Community 20 - "npm/package.json"
Cohesion: 0.15
Nodes (14): author, dependencies, lodash@^4.18.1, typescript@^6.0.3, description, lodash, typescript, license (+6 more)

### Community 21 - "decode_dns_name"
Cohesion: 0.09
Nodes (22): extract_first_arg_fd(), extract_sensitive_file_reads(), is_sensitive_file_read(), lexical_clean_path(), parse_syscall_return(), test_appsec_evasion_bypasses(), test_appsec_evasion_exhaustive_variants(), test_extract_sensitive_file_reads() (+14 more)

### Community 22 - "build_runner_from_env"
Cohesion: 0.22
Nodes (8): announce_seccomp_status(), build_runner_from_env(), docker_daemon_error_message(), docker_preflight(), HostRunner, npm_family_install_dir_flag(), npm_family_install_subcommand(), unsupported_sandbox_mode_lists_supported_modes()

### Community 23 - "forward_confirmed_hostname"
Cohesion: 0.25
Nodes (6): fcrdns_accepts_hostname_that_forward_resolves_back_to_ip(), fcrdns_rejects_spoofed_ptr_that_does_not_forward_confirm(), fcrdns_rejects_when_no_ptr_record(), forward_confirmed_hostname(), reverse_dns_domain(), reverse_dns_domain_invalid_ip_returns_none()

### Community 24 - "Fixed Findings (Detailed)"
Cohesion: 0.33
Nodes (4): Cross-Finding Chains (Architectural Context), Fixed Findings (Detailed), Fixed Findings, Summary

### Community 27 - "Critical Impact"
Cohesion: 0.12
Nodes (16): 10. Unbounded Consumption (unbounded-consumption), 1. Prompt Injection (prompt-injection), 2. Sensitive Information Disclosure (sensitive-disclosure), 3. Supply Chain (supply-chain), 4. Data and Model Poisoning (data-poisoning), 5. Improper Output Handling (output-handling), 6. Excessive Agency (excessive-agency), 7. System Prompt Leakage (system-prompt-leakage) (+8 more)

### Community 28 - "parsing.rs"
Cohesion: 0.05
Nodes (72): rewrite_args_with_pinned_versions, Exact-version pinning of forwarded command, GyrSeek, args(), does_not_pin_npm_package_with_latest_sentinel(), does_not_pin_pip_package_with_latest_sentinel(), does_not_pin_unrelated_packages(), does_not_repin_npm_package_that_already_has_a_version() (+64 more)

### Community 29 - "cli_burst_exit_tests.rs"
Cohesion: 0.26
Nodes (7): exits_with_code_1_and_rejects_versions_newer_than_72_hours_by_default(), exits_with_code_1_and_uses_configured_release_burst_window_hours(), exits_with_code_1_and_warning_when_release_burst_threshold_triggers(), exits_with_code_1_when_minimum_release_age_package_is_not_met(), minimum_release_age_package_runs_before_burst_threshold(), run_with_config(), run_with_config_and_env()

### Community 30 - "build_matrix_script"
Cohesion: 0.24
Nodes (11): build_matrix_script(), build_single_script(), image_setup_steps(), is_npm_family_manager(), matrix_and_single_scripts_disable_truncation(), matrix_script_captures_strace_stderr_not_devnull(), matrix_script_creates_scanner_user_before_install(), matrix_script_includes_artifact_scan_after_each_probe() (+3 more)

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

### Community 35 - "sandbox_startup_exit_tests.rs"
Cohesion: 0.12
Nodes (18): forward_args, forward_original_command, forward_pinned_command, fake_binary(), test: missing host binary fails closed, forwarding_preserves_host_success_exit_status(), forwarding_propagates_host_nonzero_exit_status(), prepend_path() (+10 more)

### Community 36 - "uses"
Cohesion: 0.22
Nodes (11): linux-docker-seccomp-uv-test, linux-docker-uv-test, steps, name, runs-on, steps, name, runs-on (+3 more)

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

### Community 41 - "Tests documentation"
Cohesion: 0.27
Nodes (10): DNS interceptor (extract_dns_map, parse_dns_response, decode_dns_name), Domain-aware IP diff (find_new_connections_domain_aware), FCrDNS (forward_confirmed_hostname), check_override_ages and hard minimum age tests, DNS interceptor fallback tests, DNS wire-format parser tests, Domain-aware IP diff truth-table tests, Expanded test coverage by module (+2 more)

### Community 42 - "Developer Guide"
Cohesion: 0.14
Nodes (14): Adding a New Supported Command, Adding a New Supported Command procedure, Agent Portability Symlinks, Build and Test, CI/CD Security Architecture, Developer Guide, Local Setup, Policy Config Surface (+6 more)

### Community 43 - "env"
Cohesion: 0.20
Nodes (10): GYRSEEK_DOCKER_APPARMOR_PROFILE, GYRSEEK_NPM_SCANNER_IMAGE, GYRSEEK_NPM_SCANNER_PREBUILT, GYRSEEK_PY_SCANNER_IMAGE, GYRSEEK_PY_SCANNER_PREBUILT, linux-docker-apparmor-seccomp-uv-test, name, runs-on (+2 more)

### Community 44 - "General Best Practices for Avoiding Race Conditions"
Cohesion: 0.15
Nodes (11): General Best Practices for Avoiding Race Conditions, Hardcoded /tmp Path, Insecure Temporary File Creation, Insecure Temporary File Creation, Language: Go, Language: OCaml, Language: Python, Language-Specific Secure Alternatives (+3 more)

### Community 45 - "Semgrep Rule Creation Workflow"
Cohesion: 0.06
Nodes (36): Basic Pattern Matching, Basic Taint Structure, Common Fixes, Common Redundancies to Remove, Debug Failures, Debug Taint Rules, Directory Structure, Example: Complete Taint Rule (+28 more)

### Community 46 - "jobs"
Cohesion: 0.25
Nodes (7): env, CARGO_TERM_COLOR, jobs, linux-docker-apparmor-seccomp-poetry-test, name, runs-on, name

### Community 47 - "load_policy_config"
Cohesion: 0.18
Nodes (13): load_policy_config(), missing_default_config_returns_empty_allowlist(), missing_explicit_config_fails_closed(), option_zero_to_none(), option_zero_to_none_direct(), parse_list(), parse_list_map(), parses_new_package_exemptions_invalid_map_rejected_with_custom_error() (+5 more)

### Community 48 - "SandboxEnvVarGuard"
Cohesion: 0.20
Nodes (6): apparmor_env_var_default_false(), docker_args_memory_limit_defaults_to_2g_and_is_configurable(), env_lock(), sandbox_max_processes(), SandboxEnvVarGuard, test_sandbox_max_processes_env_fallback()

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
Cohesion: 0.21
Nodes (12): Architecture, CI/CD Pipeline Architecture, Core Components, Current Limitations, Decision Model, Docker Sandbox Security, Fail-Closed Policy, Goal (+4 more)

### Community 55 - "Roadmap"
Cohesion: 0.18
Nodes (11): External CodeRabbit review migration, Completed, Detection & Analysis, Hardening & Infrastructure, Hardening & Infrastructure, Long Term, Mid Term, Near Term (+3 more)

### Community 56 - "with"
Cohesion: 0.25
Nodes (8): with, components, dockerfile, just-version, python-version, recursive, token, version

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

### Community 63 - "Pattern Operators"
Cohesion: 0.29
Nodes (7): Basic Matching, Deep Matching, Metavariable Filters, Metavariables, Negation, Pattern Operators, Scope Operators

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

### Community 70 - "filter_allowlisted_git_clone_signatures"
Cohesion: 0.40
Nodes (5): filter_allowlisted_git_clone_signatures(), git_clone_allowlist_does_not_leak_across_packages(), git_clone_allowlist_does_not_match_different_url(), git_clone_allowlist_matches_non_recursive_clone_of_allowed_url(), git_clone_allowlist_matches_recursive_clone_of_allowed_url()

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
Cohesion: 0.14
Nodes (8): Agent Portability Symlinks, Agents Memory and Workflow, graphify, Mandatory Post-Change Policy, Mandatory Pre-Session Setup, Purpose, Quick Post-Change Checklist, Repository Memory

### Community 76 - "Sandbox Modes"
Cohesion: 0.25
Nodes (8): Default-deny seccomp architecture, Docker sandbox, Host mode (reduced safety), nono configuration, Platform support matrix, Sandbox Modes, Scanner image configuration, Seccomp and AppArmor profiles

### Community 77 - "name"
Cohesion: 0.22
Nodes (9): name, permissions, runs-on, steps, cargo-audit, permissions, checks, contents (+1 more)

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
Cohesion: 0.29
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

### Community 105 - "extract_dns_map"
Cohesion: 0.09
Nodes (24): dns_interceptor_end_to_end_with_realistic_strace_trace(), extract_dns_map(), extract_dns_map_connect_failure_ignored(), extract_dns_map_empty_trace(), extract_dns_map_ipv6_tcp_dns_response(), extract_dns_map_ipv6_udp_dns_response(), extract_dns_map_malformed_payload_skipped(), extract_dns_map_mixed_udp_and_tcp_dns() (+16 more)

### Community 106 - "env_lock"
Cohesion: 0.29
Nodes (3): active_test_env_vars_none_set_returns_empty(), env_lock(), EnvVarGuard

### Community 107 - "LLM01: Prevent Prompt Injection"
Cohesion: 0.33
Nodes (5): Direct Prompt Injection Prevention, Indirect Prompt Injection Prevention (RAG Systems), Key Prevention Rules, LLM01: Prevent Prompt Injection, Output Filtering

### Community 108 - "trace_install_docker_matrix"
Cohesion: 0.23
Nodes (7): DockerRunner, ProbeTrace, scanner_image_config(), ScannerImageConfig, trace_install_docker_matrix(), trace_install_docker_single(), MockRunner

### Community 109 - "Understand Code"
Cohesion: 0.33
Nodes (5): Approach, Checklist, Goal, Understand Code, Verification

### Community 110 - "WONT_FIX_FINDINGS_DETAILED.md"
Cohesion: 0.33
Nodes (4): Detailed Rationale, Won't Fix Findings (Detailed), Summary, Won't Fix Findings

### Community 111 - "Common Patterns by Vulnerability"
Cohesion: 0.29
Nodes (7): Command Injection, Common Patterns by Vulnerability, Dangerous Functions (Pattern Matching), Hardcoded Secrets (Pattern Matching), Path Traversal, SQL Injection, XSS

### Community 113 - "strace_install_command"
Cohesion: 0.29
Nodes (7): install_invocation(), pnpm_install_invocation_uses_pnpm_add(), SCANNER_USER, shell_single_quoted(), strace_command_disables_string_truncation(), strace_drops_payload_to_unprivileged_user(), strace_install_command()

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

### Community 118 - "build_docker_run_args"
Cohesion: 0.25
Nodes (8): build_docker_run_args(), docker_args_adds_seccomp_profile_by_default(), docker_args_disables_seccomp_when_danger_flag_true(), docker_args_grant_sys_ptrace_capability(), docker_args_keep_out_mount_when_provided_and_omit_when_empty(), docker_enforces_sandbox_constraints(), embedded_seccomp_profile_path(), sandbox_mem_limit()

### Community 120 - "Configuration"
Cohesion: 0.40
Nodes (5): CLI Arguments, Config keys, Config loading behavior, Configuration, Example config

### Community 121 - "AllowlistEntry"
Cohesion: 0.40
Nodes (5): AllowlistEntry, Global, PerPackage, BaselineOverrideConfig, GyrseekConfig

### Community 122 - "docker_apparmor_profile_name"
Cohesion: 0.40
Nodes (6): announce_apparmor_status(), apparmor_disabled_wont_call_apparmor_parser(), docker_apparmor_enabled_from_env(), docker_apparmor_profile_name(), parse_bool_env(), try_load_apparmor()

### Community 123 - "code-injection.md"
Cohesion: 0.50
Nodes (3): Key Prevention Patterns, Prevent Code Injection, References

### Community 124 - "Taint Mode"
Cohesion: 0.40
Nodes (5): Basic Structure, Propagators, Source/Sink Options, Taint Components, Taint Mode

### Community 125 - "Quick Start"
Cohesion: 0.50
Nodes (4): 1. Prerequisites, 2. Build, 3. Run your first scan, Quick Start

### Community 126 - "PolicyConfig"
Cohesion: 0.20
Nodes (11): LazyRunner, NoopRunner, scan_many_with_cache(), scan_targets(), scan_with_cache(), ScanTimer, SandboxRunner, PolicyConfig (+3 more)

### Community 127 - "steps"
Cohesion: 0.50
Nodes (4): linux-docker-apparmor-seccomp-pip-test, name, runs-on, steps

### Community 128 - "Seccomp"
Cohesion: 0.40
Nodes (5): Configuration, Platform note, Profile behavior, Seccomp, Status output

### Community 129 - "on"
Cohesion: 0.40
Nodes (5): on, pull_request, push, workflow_dispatch, branches

### Community 130 - "Policy allowlists (global and per-package)"
Cohesion: 0.50
Nodes (4): Policy allowlists (global and per-package), Config-loading helpers (parse_list_map, validate_allowlist_pkg_key, option_zero_to_none), Policy Config Surface (gyrseek.yaml), IP and domain allowlist tests

### Community 131 - "steps"
Cohesion: 0.50
Nodes (4): linux-docker-apparmor-seccomp-npm-test, name, runs-on, steps

### Community 132 - "steps"
Cohesion: 0.50
Nodes (4): linux-docker-apparmor-seccomp-pnpm-test, name, runs-on, steps

### Community 138 - "Usage"
Cohesion: 0.50
Nodes (4): npm examples, pnpm examples, Python examples, Usage

### Community 142 - "ForwardMode"
Cohesion: 0.67
Nodes (3): ForwardMode, Original, Pinned

### Community 178 - "steps"
Cohesion: 0.50
Nodes (4): rust-checks, name, runs-on, steps

## Knowledge Gaps
- **37 isolated node(s):** `Global`, `PerPackage`, `Original`, `Pinned`, `gyrseek` (+32 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 1197 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **48 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `gyrseek` connect `gyrseek` to `Network Behavior Detection`, `How It Works`, `Prebuilt Scanner Images`, `Usage`, `Agents Memory and Workflow`, `Sandbox Modes`, `Process-Execution Behavior Detection`, `Configuration`, `parsing.rs`, `Quick Start`?**
  _High betweenness centrality (0.043) - this node is a cross-community bridge._
- **Are the 7 inferred relationships involving `load()` (e.g. with `baseline_count_zero_falls_back_to_default_two()` and `minimum_release_age_package_zero_disables_policy()`) actually correct?**
  _`load()` has 7 INFERRED edges - model-reasoned connections that need verification._
- **What connects `Global`, `PerPackage`, `Original` to the rest of the system?**
  _37 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Review history` be split into smaller, more focused modules?**
  _Cohesion score 0.011363636363636364 - nodes in this community are weakly interconnected._
- **Why does `Docker Security` connect `Docker Security` to `Seccomp`, `Validation checklist`, `Developer Guide`, `Agents Memory and Workflow`, `AppArmor`, `Architecture`?**
  _High betweenness centrality (0.024) - this node is a cross-community bridge._
- **Should `Routing, Config & Scan Orchestration` be split into smaller, more focused modules?**
  _Cohesion score 0.01694915254237288 - nodes in this community are weakly interconnected._
- **Why does `Post-install artifact detection` connect `Post-install artifact detection` to `Process-Execution Behavior Detection`?**
  _High betweenness centrality (0.018) - this node is a cross-community bridge._