# Graph Report - gyrseek  (2026-11-15)

## Corpus Check
- 97 files · ~203,944 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 10 file(s) not represented in the graph (top: (none) 6, .npm 1, .python 1)

## Summary
- 2163 nodes · 2998 edges · 169 communities (121 shown, 48 thin omitted)
- Extraction: 97% EXTRACTED · 3% INFERRED · 0% AMBIGUOUS · INFERRED: 95 edges (avg confidence: 0.84)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `8ecae235`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- parsing.rs
- Routing, Config & Scan Orchestration
- sandbox.rs
- scanning.rs
- SandboxRunner
- Bun Execution Detection & Exemptions
- FCrDNS Allowlist Verification
- fetch_history_with_baselines
- gyrseek
- High Impact
- Host Command Forwarding
- Docker Security
- Burst/Release-Age CLI Tests
- Semgrep Quick Reference
- Open Findings
- Review history
- Fail-Closed Policy & Findings
- Network Anomaly Decision
- Code Correctness Rules
- Version Flag Tests
- Llm Security
- find_new_connections_domain_aware
- Critical Impact
- build_docker_run_args
- trace_sandbox_install_matrix
- filter_domain_allowlisted_new_connections_with
- Prevent Insecure Deserialization
- No-Execution-First Comparison Stage
- extract_process_exec_signatures
- Semgrep Skill
- Detailed Findings
- uses
- npm/package.json
- Code Security Skill
- Prevent Path Traversal
- Prevent Cross-Site Scripting (XSS)
- LLM Security Skill
- env
- General Best Practices for Avoiding Race Conditions
- Semgrep Rule Creation Workflow
- jobs
- Prevent XML External Entity (XXE) Injection
- WONT_FIX_FINDINGS_DETAILED.md
- Part 2: Creating Custom Rules
- with
- parse_nono_audit_log
- Code Best Practices
- terraform-gcp.md
- Categories
- LLM Security Guidelines (OWASP Top 10 for LLM 2025)
- .new
- Prevent Cross-Site Request Forgery
- Tests — Network Anomaly Detection (Domain-Aware IP Diff)
- Secure Kubernetes Configurations
- Secure Azure Terraform Configurations
- Interrogation
- semgrep/SKILL.md
- CanaryTrap
- pnpm/package.json
- Python
- Prevent SQL Injection
- LLM03: Secure LLM Supply Chain
- Ponytail
- name
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
- parse_global_options
- Prevent Command Injection
- Secure GitHub Actions
- Ensure Memory Safety
- Threat Model & Accepted Risks
- LLM01: Prevent Prompt Injection
- Pattern Operators
- Understand Code
- .yamllint.yaml
- Prevent Regular Expression DoS (ReDoS)
- ponytail-review/SKILL.md
- Common Patterns by Vulnerability
- 6. Post-Install Artifact Scanning
- Taint Mode
- code-injection.md
- discover_registry_domains_from_env
- deserialize_new_package_exemptions
- steps
- steps
- steps
- steps
- steps
- steps
- steps
- steps
- steps
- steps
- steps
- build_matrix_script
- reviews
- Feedback
- ForwardMode
- 10. Insecure Cryptography
- 11. Insecure Transport
- build_runner_from_env
- 12. Server-Side Request Forgery
- extract_sensitive_file_reads
- extract_dns_map
- PathShims
- load_policy_config
- AllowlistEntry
- nono_resource_limit_args_for_os
- Developer Guide
- Roadmap
- 13. JWT Authentication
- Agents Memory and Workflow
- 14. Cross-Site Request Forgery
- 15. Prototype Pollution
- 16. Unsafe Functions
- 17. Terraform AWS Security
- 18. Terraform Azure Security
- 19. Terraform GCP Security
- Sandbox Comparison: Docker vs. Nono
- 1. SQL Injection
- 20. Kubernetes Security
- 21. Docker Security
- .trace_install_with_domains
- 24. Race Conditions
- 25. Code Correctness
- 26. Best Practices
- 27. Performance
- 28. Maintainability
- 2. Command Injection
- copilot-instructions.md
- run
- 3. Cross-Site Scripting
- 4. XML External Entity
- env_lock
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
- gyrseek
- test
- test

## God Nodes (most connected - your core abstractions)
1. `Review history` - 176 edges
2. `Won't Fix Findings - Detailed` - 119 edges
3. `Detailed Findings` - 100 edges
4. `scan_packages_versions()` - 60 edges
5. `load()` - 41 edges
6. `run()` - 31 edges
7. `Code Security` - 31 edges
8. `find_new_connections_domain_aware()` - 28 edges
9. `with` - 26 edges
10. `extract_process_exec_signatures()` - 25 edges

## Surprising Connections (you probably didn't know these)
- `Policy Config Surface` --references--> `PolicyConfig`  [INFERRED]
  docs/DEV_GUIDE.md → src/scanning.rs
- `MicroVM Sandbox Backend (planned hardening)` --references--> `build_runner_from_env()`  [INFERRED]
  docs/ROADMAP.md → src/sandbox.rs
- `CAP_SYS_PTRACE for Cross-UID Tracing` --references--> `DockerRunner`  [INFERRED]
  docs/ARCHITECTURE.md → src/sandbox.rs
- `Unprivileged-Payload Trace Integrity (strace -u)` --references--> `DockerRunner`  [INFERRED]
  docs/ARCHITECTURE.md → src/sandbox.rs
- `Test Locations` --rationale_for--> `test: forwarding propagates host non-zero exit`  [INFERRED]
  docs/DEV_GUIDE.md → tests/forward_fail_closed_tests.rs

## Import Cycles
- 1-file cycle: `src/sandbox.rs -> src/sandbox.rs`
- 1-file cycle: `src/lib.rs -> src/lib.rs`
- 1-file cycle: `src/scanning.rs -> src/scanning.rs`

## Hyperedges (group relationships)
- **Binary-Spawning CLI Integration Tests** — tests_cli_burst_exit_tests_exits_with_code_1_release_burst_threshold, tests_forward_fail_closed_tests_forwarding_propagates_host_nonzero_exit_status, tests_lock_routing_tests_poetry_lock_is_routed_to_lockfile_scan, tests_version_flag_tests_version_flag_prints_crate_version_and_exits_zero [EXTRACTED 1.00]
- **Three Behavioral Signal Classes (network/git-clone/watched-process)** — src_scanning_extract_connection_ips, src_scanning_extract_process_exec_signatures, docs_architecture_behavioral_diffing [EXTRACTED 1.00]
- **Install-time behavioral signal extraction** — src_scanning_extract_connection_ips, src_scanning_extract_git_clone_signatures, src_scanning_extract_process_exec_signatures [INFERRED 0.85]
- **SandboxRunner backend strategy** — src_sandbox_sandboxrunner, src_sandbox_dockerrunner, src_sandbox_microvmrunner, src_sandbox_hostrunner [INFERRED 0.85]
- **Scan-then-forward orchestration pipeline** — src_lib_run, src_scanning_scan_packages_versions, src_lib_forward_pinned_command [INFERRED 0.85]

## Communities (169 total, 48 thin omitted)

### Community 0 - "parsing.rs"
Cohesion: 0.05
Nodes (73): PEP 508 Extras Stripping, Forwarded-Command Version Pinning, Resolved-Version Pinning, GyrSeek, args(), does_not_pin_npm_package_with_latest_sentinel(), does_not_pin_pip_package_with_latest_sentinel(), does_not_pin_unrelated_packages() (+65 more)

### Community 1 - "Routing, Config & Scan Orchestration"
Cohesion: 0.07
Nodes (41): accepts_new_package_exemptions_empty_list_as_no_exemptions(), baseline_count_zero_falls_back_to_default_two(), clamps_min_baseline_age_hours_to_hard_floor(), DEFAULT_CONFIG_PATH, domain_allowlist_bare_tld_rejected_in_global_and_per_package_positions(), domain_allowlist_empty_value_dropped_in_global_and_per_package_positions(), domain_allowlist_star_value_rejected_in_global_and_per_package_positions(), DummyExemptionConfig (+33 more)

### Community 2 - "sandbox.rs"
Cohesion: 0.05
Nodes (34): APPARMOR_LOAD_ERR, artifact_scan_steps_inventory_all_files(), artifact_scan_steps_output_to_correct_log(), artifact_scan_steps_pipe_char_in_content_replaced(), artifact_scan_steps_uses_null_byte_delimiter(), build_artifact_scan_steps(), CANARY_CUSTOM_PREFIX, CANARY_EXTRA_RELATIVE_PATHS (+26 more)

### Community 3 - "scanning.rs"
Cohesion: 0.04
Nodes (57): artifact_allowlist_does_not_leak_across_packages(), artifact_allowlist_matches_exact_finding_and_prefix(), ARTIFACT_DELIMITER, baseline_count_limits_fetched_baselines_without_overrides(), baseline_count_zero_does_not_fail_closed(), baseline_count_zero_returns_no_effective_baselines(), baseline_count_zero_with_override_equal_to_current_returns_empty(), BaselineOverrides (+49 more)

### Community 4 - "SandboxRunner"
Cohesion: 0.22
Nodes (11): In-Run Scan Cache, NoopRunner, scan_many_with_cache(), scan_targets(), scan_with_cache(), ScanTimer, SandboxRunner, PolicyConfig (+3 more)

### Community 5 - "Bun Execution Detection & Exemptions"
Cohesion: 0.08
Nodes (40): Behavioral Diffing, allows_new_bun_when_allowlisted(), allows_when_artifact_findings_match_baseline(), allows_when_bun_behavior_matches_baseline(), artifact_allowlist_unblocks_new_findings(), artifact_delimiter_injection_attack_defeated_end_to_end(), artifact_delimiter_injection_does_not_block_clean_package(), exemption_behavior() (+32 more)

### Community 6 - "FCrDNS Allowlist Verification"
Cohesion: 0.18
Nodes (11): Architecture, CI/CD Pipeline Architecture, Core Components, Current Limitations, Decision Model, Docker Sandbox Security, Empty-Trace Hard Error, Fail-Closed Policy (+3 more)

### Community 7 - "fetch_history_with_baselines"
Cohesion: 0.13
Nodes (23): Semantic Version Ordering (semver / PEP 440), active_test_env_vars(), age_filter_includes_versions_exactly_at_cutoff(), age_filter_keeps_only_versions_older_than_cutoff(), age_filter_skips_candidates_without_publish_timestamps(), age_filter_still_respects_baseline_count_limit(), BaselineHistory, burst_count_is_not_inflated_by_created_modified() (+15 more)

### Community 8 - "gyrseek"
Cohesion: 0.05
Nodes (46): 1) Build the scanner images, 1. Prerequisites, 2. Build, 2) Use a prebuilt image, 3) Enable prebuilt mode globally (optional), 3. Run your first scan, 4) Verify images are usable, 5) Use pinned image digests (recommended for reproducibility) (+38 more)

### Community 9 - "High Impact"
Cohesion: 0.06
Nodes (34): 10. Insecure Cryptography (insecure-crypto), 11. Insecure Transport (insecure-transport), 12. Server-Side Request Forgery (ssrf), 13. JWT Authentication (authentication-jwt), 14. Cross-Site Request Forgery (csrf), 15. Prototype Pollution (prototype-pollution), 16. Unsafe Functions (unsafe-functions), 17. Terraform AWS Security (terraform-aws) (+26 more)

### Community 10 - "Host Command Forwarding"
Cohesion: 0.10
Nodes (22): Sandbox-Local IP Filtering, extract_connection_ips(), extract_connection_ips_captures_ipv4(), extract_connection_ips_captures_ipv6_inet_pton(), extract_connection_ips_collapses_ipv4_mapped_ipv6(), extract_connection_ips_drops_loopback_link_local_and_private(), extract_connection_ips_handles_mixed_v4_and_v6(), extract_connection_ips_keeps_cloud_metadata_endpoint() (+14 more)

### Community 11 - "Docker Security"
Cohesion: 0.06
Nodes (34): Allowed operations, AppArmor, Backout plan, Capabilities and privileges, Configuration, Configuration, Current hardening limitations, Docker Security (+26 more)

### Community 12 - "Burst/Release-Age CLI Tests"
Cohesion: 0.09
Nodes (20): Test Locations, forward_args, forward_original_command, forward_pinned_command, exits_with_code_1_and_rejects_versions_newer_than_72_hours_by_default(), exits_with_code_1_and_uses_configured_release_burst_window_hours(), exits_with_code_1_and_warning_when_release_burst_threshold_triggers(), exits_with_code_1_when_minimum_release_age_package_is_not_met() (+12 more)

### Community 13 - "Semgrep Quick Reference"
Cohesion: 0.25
Nodes (8): Commands, Metadata Fields, Path Filtering, Required Rule Fields, Semgrep Quick Reference, Supported Languages, Test Annotations, Testing

### Community 14 - "Open Findings"
Cohesion: 0.29
Nodes (5): Complexity & Over-Engineering Findings, Open Findings - Detailed, Open Findings, Security & Correctness Findings, Summary

### Community 15 - "Review history"
Cohesion: 0.01
Nodes (176): Finding 100 — Low | `.github/workflows/ci.yml` | ✅ Fixed, Finding 101 — Low | `.github/workflows/ci.yml` | ✅ Fixed, Finding 102 — Medium | `.github/workflows/post_review.yml` | ✅ Fixed, Finding 103 — Low | `.github/workflows/ci.yml` | ✅ Fixed, Finding 104 — Low | `.github/workflows/ci.yml` | ✅ Fixed, Finding 105 — Low | `.github/workflows/ci.yml` | ✅ Fixed, Finding 106 — High | `.github/workflows/ci.yml` | ✅ Fixed, Finding 107 — Low | `docs/ARCHITECTURE.md` | ✅ Fixed (+168 more)

### Community 16 - "Fail-Closed Policy & Findings"
Cohesion: 0.09
Nodes (21): Cross-Finding Chains (Architectural Context), Detailed Findings, Finding 10 — Critical | `scanning.rs:654` | ✅ Fixed, Finding 13 — Medium | `scanning.rs:1852` | ✅ Fixed, Finding 15 — Low | `sandbox.rs:511` | ✅ Fixed, Finding 16 — Medium | `scanning.rs:509` | ✅ Fixed, Finding 17 — High | `scanning.rs:972` | ✅ Fixed, Finding 18 — Medium | `scanning.rs:467` | ✅ Fixed (+13 more)

### Community 17 - "Network Anomaly Decision"
Cohesion: 0.02
Nodes (119): Finding 118 — Low | `.github/workflows/ci.yml` | 🛑 Wont Fix, Finding 123 — High | `.github/workflows/post_review.yml` | 🛑 Wont Fix / Invalid, Finding 124 — Low | `.github/scripts/sanitize_review.py` | 🛑 Wont Fix, Finding 125 — Low | `.github/scripts/post_comment.sh` | 🛑 Wont Fix / Invalid, Finding 129 — Low | `.github/scripts/post_comment.sh` | 🛑 Wont Fix / Accepted Risk, Finding 138 — Low | `.github/scripts/sanitize_review.py` | 🛑 Wont Fix / Accepted Risk, Finding 151 — Invalid | `.github/scripts/sanitize_review.py` | 🛑 Wont Fix, Finding 152 — Accepted Risk | `.github/scripts/sanitize_review.py` | 🛑 Wont Fix (+111 more)

### Community 18 - "Code Correctness Rules"
Cohesion: 0.08
Nodes (23): Assignment in Condition, ato* Functions, Bash, C, Code Correctness Rules, Elixir: Atom Exhaustion, Go, Integer Overflow from Atoi (+15 more)

### Community 20 - "Llm Security"
Cohesion: 0.08
Nodes (23): 10.1 LLM10 - Prevent Unbounded Consumption, 10. Unbounded Consumption, 1.1 LLM01 - Prevent Prompt Injection, 1. Prompt Injection, 2.1 LLM02 - Prevent Sensitive Information Disclosure, 2. Sensitive Information Disclosure, 3.1 LLM03 - Secure LLM Supply Chain, 3. Supply Chain (+15 more)

### Community 21 - "find_new_connections_domain_aware"
Cohesion: 0.09
Nodes (22): detects_anomalous_new_connection(), detects_new_connection_in_git_clone_simulation(), dns_interceptor_skips_when_domain_not_in_baseline(), dns_interceptor_skips_when_forward_resolver_does_not_confirm(), domain_aware_diff_cdn_rotation_without_ptr_handled_by_dns_interceptor(), domain_aware_diff_current_resolves_baseline_ip_unresolvable(), domain_aware_diff_current_unresolved_ip_in_baseline_not_flagged(), domain_aware_diff_discards_ip_when_domain_seen_in_baseline() (+14 more)

### Community 22 - "Critical Impact"
Cohesion: 0.12
Nodes (16): 10. Unbounded Consumption (unbounded-consumption), 1. Prompt Injection (prompt-injection), 2. Sensitive Information Disclosure (sensitive-disclosure), 3. Supply Chain (supply-chain), 4. Data and Model Poisoning (data-poisoning), 5. Improper Output Handling (output-handling), 6. Excessive Agency (excessive-agency), 7. System Prompt Leakage (system-prompt-leakage) (+8 more)

### Community 23 - "build_docker_run_args"
Cohesion: 0.21
Nodes (10): CAP_SYS_PTRACE for Cross-UID Tracing, Unprivileged-Payload Trace Integrity (strace -u), DockerRunner, MicroVmRunner, parse_bool_env(), ProbeTrace, scanner_image_config(), ScannerImageConfig (+2 more)

### Community 24 - "trace_sandbox_install_matrix"
Cohesion: 0.08
Nodes (24): Behavioral Diffing Across Versions, Direct Git Clone Runtime Interception, artifact_delimiter_pipe_in_path_is_not_injected(), artifact_findings_empty_for_clean_install(), classify_inventory_benign_pth(), classify_inventory_binary_elf(), classify_inventory_empty_input(), classify_inventory_install_script() (+16 more)

### Community 25 - "filter_domain_allowlisted_new_connections_with"
Cohesion: 0.11
Nodes (17): Forward-Confirmed Reverse DNS (FCrDNS), Forward-Confirmed Reverse DNS, domain_allowlist_does_not_filter_when_lookup_fails(), domain_allowlist_filters_resolved_domains_before_blocking(), domain_allowlist_normalization_matches_case_whitespace_and_trailing_dot(), domain_is_allowlisted(), fcrdns_accepts_hostname_that_forward_resolves_back_to_ip(), fcrdns_rejects_spoofed_ptr_that_does_not_forward_confirm() (+9 more)

### Community 26 - "Prevent Insecure Deserialization"
Cohesion: 0.13
Nodes (14): BinaryFormatter Deserialization, General Prevention Guidelines, Language: C#, Language: Java, Language: JavaScript / TypeScript, Language: PHP, Language: Python, Language: Ruby (+6 more)

### Community 28 - "extract_process_exec_signatures"
Cohesion: 0.08
Nodes (28): Shai-Hulud Attack Class, Watched-Process Execution Detection, Shai-Hulud Attack, case_1_new_bun_is_flagged_against_clean_baseline(), case_2_existing_bun_plus_additional_invocation_is_flagged(), case_2b_changed_bun_arguments_are_flagged(), executable_basename(), extract_git_clone_signatures() (+20 more)

### Community 29 - "Semgrep Skill"
Cohesion: 0.13
Nodes (14): Acknowledgments, Capabilities, Creating Custom Rules, Example Prompts, For End Users, Quick Reference, Resources, Rule Creation Workflow (+6 more)

### Community 30 - "Detailed Findings"
Cohesion: 0.02
Nodes (100): Detailed Findings, Finding 14 — Low | `parsing.rs:880` | ⚠️ Open, Finding 170 — Medium | `ARCHITECTURE.md` | ⚠️ Open, Finding 171 — High | `scanning.rs` | ⚠️ Open, Finding 172 — Medium | `ARCHITECTURE.md` | ⚠️ Open, Finding 173 — Medium | `ARCHITECTURE.md` | ⚠️ Open, Finding 177 — Low | `*_DETAILED.md` | ⚠️ Open, Finding 180 — Low | `lib.rs:1092-1173` | ⚠️ Open (+92 more)

### Community 31 - "uses"
Cohesion: 0.16
Nodes (15): linux-docker-seccomp-uv-test, linux-docker-uv-test, linux-nono-npm-test, name, runs-on, steps, name, runs-on (+7 more)

### Community 32 - "npm/package.json"
Cohesion: 0.15
Nodes (14): author, dependencies, lodash@^4.18.1, typescript@^6.0.3, description, lodash, typescript, license (+6 more)

### Community 33 - "Code Security Skill"
Cohesion: 0.14
Nodes (13): Acknowledgments, Categories (28 Total), Code Security Skill, Creating a New Rule, Critical Impact, For Contributors, For End Users, High Impact (+5 more)

### Community 34 - "Prevent Path Traversal"
Cohesion: 0.14
Nodes (13): File Inclusion (LFI/RFI), filepath.Clean Misuse, HttpServlet Path Traversal, Language: Go, Language: Java, Language: JavaScript/Node.js, Language: PHP, Language: Python (+5 more)

### Community 35 - "Prevent Cross-Site Scripting (XSS)"
Cohesion: 0.14
Nodes (13): Browser DOM Manipulation, Direct ResponseWriter Write, Django HttpResponse, Echo with Request Data, Flask Unsanitized Response, General Prevention Guidelines, Language: Go, Language: Java (+5 more)

### Community 36 - "LLM Security Skill"
Cohesion: 0.14
Nodes (13): Acknowledgments, Categories (10 Total), Creating a New Rule, Critical Impact, For Contributors, For End Users, High Impact, Impact Levels (+5 more)

### Community 37 - "env"
Cohesion: 0.14
Nodes (14): GYRSEEK_DOCKER_APPARMOR_PROFILE, GYRSEEK_NPM_SCANNER_IMAGE, GYRSEEK_NPM_SCANNER_PREBUILT, GYRSEEK_PY_SCANNER_IMAGE, GYRSEEK_PY_SCANNER_PREBUILT, linux-docker-apparmor-seccomp-npm-test, linux-docker-apparmor-seccomp-pnpm-test, name (+6 more)

### Community 38 - "General Best Practices for Avoiding Race Conditions"
Cohesion: 0.15
Nodes (11): General Best Practices for Avoiding Race Conditions, Hardcoded /tmp Path, Insecure Temporary File Creation, Insecure Temporary File Creation, Language: Go, Language: OCaml, Language: Python, Language-Specific Secure Alternatives (+3 more)

### Community 39 - "Semgrep Rule Creation Workflow"
Cohesion: 0.06
Nodes (36): Basic Pattern Matching, Basic Taint Structure, Common Fixes, Common Redundancies to Remove, Debug Failures, Debug Taint Rules, Directory Structure, Example: Complete Taint Rule (+28 more)

### Community 40 - "jobs"
Cohesion: 0.15
Nodes (12): env, CARGO_TERM_COLOR, jobs, rust-checks, name, on, pull_request, push (+4 more)

### Community 41 - "Prevent XML External Entity (XXE) Injection"
Cohesion: 0.17
Nodes (11): DocumentBuilderFactory - Disallow DOCTYPE Declaration, Language: C\#, Language: Go, Language: Java, Language: JavaScript, Language: Python, libxml2 - External Entities Enabled, libxmljs - noent Option Enabled (+3 more)

### Community 42 - "WONT_FIX_FINDINGS_DETAILED.md"
Cohesion: 0.33
Nodes (4): Detailed Rationale, Won't Fix Findings (Detailed), Summary, Won't Fix Findings

### Community 43 - "Part 2: Creating Custom Rules"
Cohesion: 0.17
Nodes (12): Anti-Patterns to Avoid, Approach Selection, Command Reference, Detailed References, Part 2: Creating Custom Rules, Pattern Syntax Quick Reference, Quick Start: Pattern Matching, Quick Start: Taint Mode (+4 more)

### Community 44 - "with"
Cohesion: 0.17
Nodes (12): macos-nono-pip-test, name, runs-on, steps, with, components, dockerfile, just-version (+4 more)

### Community 45 - "parse_nono_audit_log"
Cohesion: 0.20
Nodes (11): build_synthetic_dns_response(), build_synthetic_dns_response_roundtrip(), escape_strace_synthetic(), format_synthetic_dns_trace_line(), parse_nono_audit_log(), parse_nono_audit_log_captured_https_connect_fixture(), parse_nono_audit_log_command_and_exec_events(), parse_nono_audit_log_network_events() (+3 more)

### Community 46 - "Code Best Practices"
Cohesion: 0.18
Nodes (10): Avoid Deprecated Libraries, Code Best Practices, Cookie Security Flags, File Handling - Always Close Files, Load Modules at Top Level, Network Requests Need Timeouts, Remove Debug Statements, Secure Temporary File Creation (+2 more)

### Community 47 - "terraform-gcp.md"
Cohesion: 0.18
Nodes (10): Cloud Run, Cloud Build, Dataproc, and Vertex AI, Cloud SQL, Google Cloud Storage (GCS), Google Compute Engine and Firewall, Google Kubernetes Engine (GKE), IAM, VPC, and Networking, KMS, Redis, BigQuery, and Pub/Sub, References (+2 more)

### Community 48 - "Categories"
Cohesion: 0.18
Nodes (10): Categories, Code Security Guidelines, Critical Impact, High Impact, How to Use This Skill, Infrastructure, Language-Specific Priority Rules, Medium/Low Impact (+2 more)

### Community 49 - "LLM Security Guidelines (OWASP Top 10 for LLM 2025)"
Cohesion: 0.18
Nodes (10): Categories, Critical Impact, High Impact, How to Use This Skill, Key Principles, LLM Security Guidelines (OWASP Top 10 for LLM 2025), Quick Reference, References (+2 more)

### Community 50 - ".new"
Cohesion: 0.33
Nodes (9): ignores_non_install_commands(), parses_npm_install_as_latest_when_unpinned(), parses_npm_install_with_pinned_version(), parses_pnpm_add_as_latest_when_unpinned(), parses_pnpm_add_with_pinned_version(), parses_poetry_update_as_latest_when_unpinned(), parses_uv_add_as_latest_when_unpinned(), parses_uv_pip_install_with_pinned_version() (+1 more)

### Community 51 - "Prevent Cross-Site Request Forgery"
Cohesion: 0.20
Nodes (9): CSRF Disabled, CSRF Exempt Decorator, Language: Java / Spring, Language: JavaScript / Express, Language: Python / Django, Language: Ruby / Rails, Missing CSRF Middleware, Missing CSRF Protection (+1 more)

### Community 52 - "Tests — Network Anomaly Detection (Domain-Aware IP Diff)"
Cohesion: 0.07
Nodes (26): 10. Full pipeline integration: strace → dns_map → domain-aware diff (1 test), 11. Expanded Test Coverage (310 tests total), 12. `check_override_ages` — filtered-override return value (5 tests), 13. `HARD_MINIMUM_AGE_HOURS` floor enforcement (1 test), 1. `forward_confirmed_hostname` — FCrDNS core logic (3 tests), 2. `reverse_dns_domain` — production resolver parse guard (1 test), 3. `find_new_connections_domain_aware` — domain-aware IP diff (14 tests), 4. `filter_allowlisted_new_connections` — IP allowlist (3 tests) (+18 more)

### Community 53 - "Secure Kubernetes Configurations"
Cohesion: 0.20
Nodes (9): Docker Socket Exposure, Host IPC Namespace, Host Network Namespace, Host PID Namespace, Privilege Escalation, Privileged Containers, Run as Non-Root, Secrets in Config Files (+1 more)

### Community 54 - "Secure Azure Terraform Configurations"
Cohesion: 0.20
Nodes (9): AKS Security, App Service Security, Database Security, IAM - Custom Roles, Key Vault Security, Public Network Access and Network Isolation, Secure Azure Terraform Configurations, Storage Account Security (+1 more)

### Community 55 - "Interrogation"
Cohesion: 0.20
Nodes (9): Activation, Answer Handling, Boundaries, Branch Resolution, Depth Control, Interrogation, Termination, The Method (+1 more)

### Community 56 - "semgrep/SKILL.md"
Cohesion: 0.20
Nodes (7): CI/CD Integration, GitHub Actions, Installation (CLI), MCP Tools Available, Resources, Semgrep Static Analysis, When to Use Semgrep

### Community 57 - "CanaryTrap"
Cohesion: 0.23
Nodes (7): CanaryTrap, is_safe_canary_rel_path(), test_canary_trap_covers_extra_credential_stores(), test_canary_trap_detects_read_and_clean_teardown(), test_canary_trap_plants_configured_paths_and_skips_unsafe(), test_canary_trap_skips_npmrc_for_npm(), test_canary_trap_untouched_clean_teardown()

### Community 58 - "pnpm/package.json"
Cohesion: 0.24
Nodes (9): dependencies, lodash@^4.18.1, typescript@^5.9.3, lodash, typescript, name, private, type (+1 more)

### Community 59 - "Python"
Cohesion: 0.22
Nodes (8): Avoid Unnecessary Operations in Loops, Django - Access Foreign Keys Directly, JavaScript/TypeScript, Performance Best Practices, Python, React - Define Styled Components at Module Level, SQLAlchemy - Batch Database Operations, SQLAlchemy - Use count() Instead of len(all())

### Community 60 - "Prevent SQL Injection"
Cohesion: 0.22
Nodes (8): C# (SqlCommand), Go (database/sql), Java (JDBC), JavaScript/Node.js (pg), Key Prevention Rules, Prevent SQL Injection, Python (psycopg2), Ruby (pg gem)

### Community 61 - "LLM03: Secure LLM Supply Chain"
Cohesion: 0.22
Nodes (8): Dependency Management, Key Prevention Rules, LLM03: Secure LLM Supply Chain, LoRA Adapter Security, ML Bill of Materials (ML-BOM), Model Verification, Safe Model Loading (Avoid Pickle Exploits), Vendor and Data Source Vetting

### Community 62 - "Ponytail"
Cohesion: 0.22
Nodes (8): Boundaries, Intensity, Output, Persistence, Ponytail, Rules, The ladder, When NOT to be lazy

### Community 63 - "name"
Cohesion: 0.22
Nodes (9): name, permissions, runs-on, steps, cargo-audit, permissions, checks, contents (+1 more)

### Community 64 - "Code Security"
Cohesion: 0.25
Nodes (7): 22.1 Secure GitHub Actions, 22. GitHub Actions Security, 23.1 Prevent Regular Expression DoS, 23. Regular Expression DoS, Abstract, Code Security, Table of Contents

### Community 65 - "Secure Docker Configurations"
Cohesion: 0.25
Nodes (7): Arbitrary Container Run (Python Docker SDK), Exposing Docker Socket, Missing Image Version, Privileged Mode (Docker Compose), Running as Root, Secure Docker Configurations, Using Latest Tag

### Community 66 - "Avoid Insecure Cryptography"
Cohesion: 0.25
Nodes (7): Avoid Insecure Cryptography, Best Practices, Go, Java, JavaScript, Python, Remediation Summary

### Community 67 - "Use Secure Transport"
Cohesion: 0.25
Nodes (7): Language: Go, Language: Java, Language: JavaScript/Node.js, Language: Python, References, Summary of CWEs, Use Secure Transport

### Community 68 - "Prevent Server-Side Request Forgery (SSRF)"
Cohesion: 0.25
Nodes (7): Language: Go, Language: Java, Language: JavaScript / Node.js, Language: PHP, Language: Python, Language: Ruby, Prevent Server-Side Request Forgery (SSRF)

### Community 69 - "Secure AWS Terraform Configurations"
Cohesion: 0.25
Nodes (7): Credentials, IAM Overly Permissive Policies, Key Management, Network Security, S3 Encryption, Secure AWS Terraform Configurations, Unencrypted Storage

### Community 70 - "LLM04: Prevent Data and Model Poisoning"
Cohesion: 0.25
Nodes (7): Anomaly Detection During Training, Data Version Control, Detecting Poisoned Examples, Key Prevention Rules, LLM04: Prevent Data and Model Poisoning, Sandboxed Data Processing, Training Data Validation

### Community 71 - "LLM06: Control Excessive Agency"
Cohesion: 0.25
Nodes (7): Human-in-the-Loop for High-Impact Actions, Implementing Least Privilege, Key Prevention Rules, LLM06: Control Excessive Agency, Minimizing Tool/Extension Functionality, Monitoring and Audit Logging, Rate Limiting and Quotas

### Community 72 - "LLM09: Mitigate Misinformation and Hallucinations"
Cohesion: 0.25
Nodes (7): Confidence Scoring and Disclaimers, Fact Verification Pipeline, Key Prevention Rules, LLM09: Mitigate Misinformation and Hallucinations, Output Validation for Critical Domains, Retrieval-Augmented Generation (RAG), User Education and Transparency

### Community 73 - "LLM05: Secure Output Handling"
Cohesion: 0.25
Nodes (7): Content Security Policy for LLM Applications, Key Prevention Rules, LLM05: Secure Output Handling, Preventing Command Injection from LLM Output, Preventing SQL Injection from LLM Output, Preventing SSRF from LLM Output, Preventing XSS from LLM Output

### Community 74 - "LLM02: Prevent Sensitive Information Disclosure"
Cohesion: 0.25
Nodes (7): Access Control for RAG Systems, Data Sanitization Before Training/Fine-tuning, Key Prevention Rules, LLM02: Prevent Sensitive Information Disclosure, Output Filtering for Sensitive Data, System Prompt Security, User Education and Consent

### Community 75 - "LLM07: Prevent System Prompt Leakage"
Cohesion: 0.25
Nodes (7): Defense in Depth: External Guardrails, Input Filtering for Extraction Attempts, Key Prevention Rules, LLM07: Prevent System Prompt Leakage, Monitoring and Alerting, Never Store Secrets in System Prompts, Separating Sensitive Logic from Prompts

### Community 76 - "LLM10: Prevent Unbounded Consumption"
Cohesion: 0.25
Nodes (7): Cost Control and Budget Limits, Input Validation and Size Limits, Key Prevention Rules, LLM10: Prevent Unbounded Consumption, Model Theft Prevention, Rate Limiting, Resource Monitoring and Alerting

### Community 77 - "LLM08: Secure Vector and Embedding Systems"
Cohesion: 0.25
Nodes (7): Data Validation Before Embedding, Key Prevention Rules, LLM08: Secure Vector and Embedding Systems, Monitoring and Audit Logging, Multi-Tenant Data Isolation, Permission-Aware Vector Retrieval, Preventing Embedding Inversion Attacks

### Community 78 - "Ponytail Help"
Cohesion: 0.25
Nodes (7): Configure Default Mode, Deactivate, Levels, More, Ponytail Help, Skills, Update

### Community 79 - "Part 1: Running Scans"
Cohesion: 0.25
Nodes (8): Configuration, Output Formats, Part 1: Running Scans, Quick Scan, Scan Specific Paths, .semgrepignore, Suppress False Positives, Using Rulesets

### Community 80 - "parse_global_options"
Cohesion: 0.33
Nodes (6): config_equals_form_preserves_equals_in_path(), config_path_starting_with_dash_is_accepted(), danger_disable_seccomp_parsing_edge_cases(), keeps_args_untouched_when_no_global_options_present(), parse_global_options(), parses_global_config_flag_and_strips_it_from_manager_args()

### Community 81 - "Prevent Command Injection"
Cohesion: 0.29
Nodes (6): Language: Go, Language: Java, Language: JavaScript / Node.js, Language: Python, Language: Ruby, Prevent Command Injection

### Community 82 - "Secure GitHub Actions"
Cohesion: 0.29
Nodes (6): Key Security Risks, Pull Request Target Code Checkout (CWE-913), Run Shell Injection (CWE-78), Secure GitHub Actions, Third-Party Action Not Pinned to Commit SHA (CWE-1357), Workflow Run Target Code Checkout (CWE-913)

### Community 83 - "Ensure Memory Safety"
Cohesion: 0.29
Nodes (6): Buffer Overflow (CWE-119, CWE-120), Double Free (CWE-415), Ensure Memory Safety, Format String Vulnerabilities (CWE-134), Prevention Best Practices, Use After Free (CWE-416)

### Community 84 - "Threat Model & Accepted Risks"
Cohesion: 0.40
Nodes (5): 1. External AI Code Review, 2. Sandbox Syscall Permissiveness, 3. CI/CD Architecture Trade-offs, 4. DNS Exfiltration Boundaries, Threat Model & Accepted Risks

### Community 85 - "LLM01: Prevent Prompt Injection"
Cohesion: 0.33
Nodes (5): Direct Prompt Injection Prevention, Indirect Prompt Injection Prevention (RAG Systems), Key Prevention Rules, LLM01: Prevent Prompt Injection, Output Filtering

### Community 86 - "Pattern Operators"
Cohesion: 0.29
Nodes (7): Basic Matching, Deep Matching, Metavariable Filters, Metavariables, Negation, Pattern Operators, Scope Operators

### Community 87 - "Understand Code"
Cohesion: 0.33
Nodes (5): Approach, Checklist, Goal, Understand Code, Verification

### Community 89 - ".yamllint.yaml"
Cohesion: 0.33
Nodes (5): extends, ignore, level, rules, line-length

### Community 90 - "Prevent Regular Expression DoS (ReDoS)"
Cohesion: 0.40
Nodes (4): General Mitigation Strategies, Language: JavaScript / TypeScript, Language: Python, Prevent Regular Expression DoS (ReDoS)

### Community 91 - "ponytail-review/SKILL.md"
Cohesion: 0.40
Nodes (4): Boundaries, Examples, Format, Scoring

### Community 92 - "Common Patterns by Vulnerability"
Cohesion: 0.29
Nodes (7): Command Injection, Common Patterns by Vulnerability, Dangerous Functions (Pattern Matching), Hardcoded Secrets (Pattern Matching), Path Traversal, SQL Injection, XSS

### Community 93 - "6. Post-Install Artifact Scanning"
Cohesion: 0.67
Nodes (3): 6. Post-Install Artifact Scanning, Docker: In-Container `find` Pipeline, Nono: Host-Side `scan_target_artifacts`

### Community 94 - "Taint Mode"
Cohesion: 0.40
Nodes (5): Basic Structure, Propagators, Source/Sink Options, Taint Components, Taint Mode

### Community 95 - "code-injection.md"
Cohesion: 0.50
Nodes (3): Key Prevention Patterns, Prevent Code Injection, References

### Community 96 - "discover_registry_domains_from_env"
Cohesion: 0.50
Nodes (4): discover_registry_domains_from_env(), extract_host_from_url(), test_discover_registry_domains_from_env(), test_extract_host_from_url()

### Community 99 - "steps"
Cohesion: 0.50
Nodes (4): linux-docker-apparmor-seccomp-pip-test, name, runs-on, steps

### Community 100 - "steps"
Cohesion: 0.50
Nodes (4): linux-docker-apparmor-seccomp-poetry-test, name, runs-on, steps

### Community 101 - "steps"
Cohesion: 0.50
Nodes (4): linux-docker-apparmor-seccomp-uv-test, name, runs-on, steps

### Community 102 - "steps"
Cohesion: 0.50
Nodes (4): linux-nono-pip-test, name, runs-on, steps

### Community 103 - "steps"
Cohesion: 0.50
Nodes (4): linux-nono-pnpm-test, name, runs-on, steps

### Community 104 - "steps"
Cohesion: 0.50
Nodes (4): linux-nono-poetry-test, name, runs-on, steps

### Community 105 - "steps"
Cohesion: 0.50
Nodes (4): linux-nono-uv-test, name, runs-on, steps

### Community 106 - "steps"
Cohesion: 0.50
Nodes (4): macos-nono-npm-test, name, runs-on, steps

### Community 107 - "steps"
Cohesion: 0.50
Nodes (4): macos-nono-pnpm-test, name, runs-on, steps

### Community 108 - "steps"
Cohesion: 0.50
Nodes (4): macos-nono-poetry-test, name, runs-on, steps

### Community 109 - "steps"
Cohesion: 0.50
Nodes (4): macos-nono-uv-test, name, runs-on, steps

### Community 110 - "build_matrix_script"
Cohesion: 0.15
Nodes (16): build_matrix_script(), build_single_script(), image_setup_steps(), install_invocation(), matrix_and_single_scripts_disable_truncation(), matrix_script_captures_strace_stderr_not_devnull(), matrix_script_creates_scanner_user_before_install(), matrix_script_includes_artifact_scan_after_each_probe() (+8 more)

### Community 114 - "ForwardMode"
Cohesion: 0.67
Nodes (3): ForwardMode, Original, Pinned

### Community 117 - "build_runner_from_env"
Cohesion: 0.18
Nodes (13): Sandbox Mode, MicroVM Sandbox Backend (planned hardening), announce_apparmor_status(), announce_seccomp_status(), apparmor_disabled_wont_call_apparmor_parser(), build_runner_from_env(), docker_apparmor_enabled_from_env(), docker_apparmor_profile_name() (+5 more)

### Community 119 - "extract_sensitive_file_reads"
Cohesion: 0.09
Nodes (22): every_nono_canary_label_is_classified_sensitive(), extract_first_arg_fd(), extract_sensitive_file_reads(), is_sensitive_file_read(), lexical_clean_path(), parse_syscall_return(), test_appsec_evasion_bypasses(), test_appsec_evasion_exhaustive_variants() (+14 more)

### Community 121 - "extract_dns_map"
Cohesion: 0.10
Nodes (20): dns_interceptor_end_to_end_with_realistic_strace_trace(), extract_dns_map(), extract_dns_map_connect_failure_ignored(), extract_dns_map_empty_trace(), extract_dns_map_ipv6_tcp_dns_response(), extract_dns_map_ipv6_udp_dns_response(), extract_dns_map_malformed_payload_skipped(), extract_dns_map_mixed_udp_and_tcp_dns() (+12 more)

### Community 122 - "PathShims"
Cohesion: 0.35
Nodes (4): ExecEvents, PathShims, test_path_shims_logging_and_event_parsing(), test_path_shims_shutdown_with_held_writer()

### Community 123 - "load_policy_config"
Cohesion: 0.18
Nodes (13): load_policy_config(), missing_default_config_returns_empty_allowlist(), missing_explicit_config_fails_closed(), option_zero_to_none(), option_zero_to_none_direct(), parse_list(), parse_list_map(), parses_new_package_exemptions_invalid_map_rejected_with_custom_error() (+5 more)

### Community 124 - "AllowlistEntry"
Cohesion: 0.40
Nodes (5): AllowlistEntry, Global, PerPackage, BaselineOverrideConfig, GyrseekConfig

### Community 125 - "nono_resource_limit_args_for_os"
Cohesion: 0.09
Nodes (22): apparmor_env_var_default_false(), build_docker_run_args(), docker_args_adds_seccomp_profile_by_default(), docker_args_disables_seccomp_when_danger_flag_true(), docker_args_grant_sys_ptrace_capability(), docker_args_keep_out_mount_when_provided_and_omit_when_empty(), docker_args_memory_limit_defaults_to_2g_and_is_configurable(), docker_args_pass_runtime_when_set() (+14 more)

### Community 126 - "Developer Guide"
Cohesion: 0.17
Nodes (12): Adding a New Supported Command, Agent Portability Symlinks, Build and Test, CI/CD Security Architecture, Developer Guide, just Task Runner, Local Setup, Policy Config Surface (+4 more)

### Community 127 - "Roadmap"
Cohesion: 0.20
Nodes (9): Completed, Detection & Analysis, Hardening & Infrastructure, Hardening & Infrastructure, Long Term, Mid Term, Near Term, Reliability & UX (+1 more)

### Community 129 - "Agents Memory and Workflow"
Cohesion: 0.25
Nodes (8): Agent Portability Symlinks, Agents Memory and Workflow, graphify, Mandatory Post-Change Policy, Mandatory Pre-Session Setup, Purpose, Quick Post-Change Checklist, Repository Memory

### Community 137 - "Sandbox Comparison: Docker vs. Nono"
Cohesion: 0.12
Nodes (16): 1. Overview & Core Philosophy, 2. Isolation Boundaries & Blast Radius, 3. Network Confinement & Anomaly Detection, 4. Process Execution & Dropper Tracking, 5. Sensitive File Access & Credential Harvesting, 7. Comparative Technical Nuances, 8. Summary & Recommendation, Docker: Kernel Syscall Tracing (`ptrace`) (+8 more)

### Community 141 - ".trace_install_with_domains"
Cohesion: 0.17
Nodes (12): darwin_user_cache_dir(), default_allowed_domains_for_manager(), extract_domains_from_nono_audit_log(), HostRunner, is_npm_family_manager(), nono_state_dir_creation_failure_names_the_path(), NonoRunner, npm_family_install_dir_flag() (+4 more)

### Community 149 - "run"
Cohesion: 0.13
Nodes (13): Runtime Entry Flow, Structured Logging Mode (planned), Fail-Closed Guarantee, exit_with(), run(), main(), test: minimum_release_age_package not met exits 1, test: release_burst_threshold triggers exit 1 (+5 more)

### Community 152 - "env_lock"
Cohesion: 0.29
Nodes (3): active_test_env_vars_none_set_returns_empty(), env_lock(), EnvVarGuard

## Knowledge Gaps
- **31 isolated node(s):** `EMBEDDED_SECCOMP_PROFILE_JSON`, `EMBEDDED_APPARMOR_PROFILE_NAME`, `EMBEDDED_APPARMOR_PROFILE_TEXT`, `Original`, `Pinned` (+26 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 1228 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **48 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Developer Guide` connect `Developer Guide` to `DOCKER_SECURITY.md`, `Burst/Release-Age CLI Tests`, `build_runner_from_env`?**
  _High betweenness centrality (0.030) - this node is a cross-community bridge._
- **Are the 7 inferred relationships involving `load()` (e.g. with `baseline_count_zero_falls_back_to_default_two()` and `minimum_release_age_package_zero_disables_policy()`) actually correct?**
  _`load()` has 7 INFERRED edges - model-reasoned connections that need verification._
- **What connects `EMBEDDED_SECCOMP_PROFILE_JSON`, `EMBEDDED_APPARMOR_PROFILE_NAME`, `EMBEDDED_APPARMOR_PROFILE_TEXT` to the rest of the system?**
  _31 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `parsing.rs` be split into smaller, more focused modules?**
  _Cohesion score 0.05249569707401033 - nodes in this community are weakly interconnected._
- **Why does `Docker Security` connect `Docker Security` to `DOCKER_SECURITY.md`?**
  _High betweenness centrality (0.017) - this node is a cross-community bridge._
- **Should `Routing, Config & Scan Orchestration` be split into smaller, more focused modules?**
  _Cohesion score 0.07102040816326531 - nodes in this community are weakly interconnected._
- **Why does `scan_packages_versions()` connect `Bun Execution Detection & Exemptions` to `Routing, Config & Scan Orchestration`, `extract_dns_map`, `scanning.rs`, `SandboxRunner`, `fetch_history_with_baselines`, `Host Command Forwarding`, `find_new_connections_domain_aware`, `trace_sandbox_install_matrix`, `filter_domain_allowlisted_new_connections_with`, `extract_process_exec_signatures`, `Developer Guide`?**
  _High betweenness centrality (0.016) - this node is a cross-community bridge._