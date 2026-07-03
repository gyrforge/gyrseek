# Open Findings

## Security & Correctness Findings

### Summary

| #  | File          | Line | Severity | Description                                                           | Status    |
|----|---------------|------|----------|-----------------------------------------------------------------------|-----------|
| 11 | `parsing.rs`  | 468  | High     | All-non-registry npm CLI args trigger package.json fallback           | ⚠️ Open  |
| 12 | `lib.rs`      | 1021 | High     | All-non-registry npm CLI args + no package.json → valid install blocked | ⚠️ Open |
| 14 | `parsing.rs`  | 880  | Low      | Temp file not cleaned up on test assertion failure                    | ⚠️ Open  |
| 21 | `sandbox.rs`  | 629  | High     | Hardcoded 512 MB container memory — npm/pnpm native builds routinely OOM-killed | ⚠️ Open  |
| 22 | `scanning.rs` | 222  | Medium   | IPv6 ULA (`fc00::/7`) not filtered as local — internal container traffic flagged as exfiltration | ⚠️ Open  |
| 23 | `sandbox.rs`  | 191  | Medium   | Host mode selected silently — no stderr warning that sandbox protection is disabled | ⚠️ Open  |
| 24 | `sandbox.rs`  | 555  | Medium   | Artifact scan spawns 3 processes per file — O(N) subprocess overhead on large node_modules | ⚠️ Open  |
| 25 | `README.md` / `sandbox.rs` | 363 / —  | High     | Import-time execution not captured — Telnyx T26 bypasses install-window sandbox entirely | ⚠️ Open  |
| 26 | `lib.rs`      | 588  | Medium   | `Command::new` relies on PATH — relative-path hijacking in untrusted working dirs | ⚠️ Open  |
| 27 | `lib.rs`      | 64   | Low      | `--config` value not validated — flag-like value silently swallowed as file path | ⚠️ Open  |
| 28 | `scanning.rs` | —    | High     | Baseline poisoning evasion for sensitive file access                  | ⚠️ Open  |
| 82  | `sandbox.rs`  | —    | High     | `scanner_image_config` torn/stale env-var reads during concurrent test execution | ⚠️ Open  |
| 84  | `scanning.rs` | —    | High     | Async cache race in baseline counting during concurrent `scan_with_cache` calls | ⚠️ Open  |
| 85  | `scanning.rs` | —    | Medium   | Blocking DNS I/O inside async runtime causes tokio worker-thread DoS   | ⚠️ Open  |
| 86  | `scanning.rs` | —    | Low      | `scan_package_versions` fallback returns generic `scan_failed` with zero diagnostics | ⚠️ Open  |
| 178 | `sandbox.rs`  | —    | Critical | `pidfd_open` and `pidfd_getfd` not blocked, allowing fd theft          | ⚠️ Open  |
| 32 | `scanning.rs` | —    | Critical | NUL-byte path truncation bypass in strace path unescaping              | ⚠️ Open  |
| 33 | `sandbox.rs`  | —    | High     | `execveat` double gap: absent from trace list and parser regex         | ⚠️ Open  |
| 35 | `scanning.rs` | —    | High     | `close` and `execve` omitted from strace causing stale fd_table        | ⚠️ Open  |
| 36 | `scanning.rs` | —    | High     | `F_DUPFD` numeric check missing; `F_DUPFD_CLOEXEC` ignored             | ⚠️ Open  |
| 37 | `scanning.rs` | —    | Medium   | `is_harness_command` `env` delegation footgun                          | ⚠️ Open  |
| 38 | `scanning.rs` | —    | Medium   | `*` prefix allowlist warns but silently blocks everything              | ⚠️ Open  |
| 39 | `scanning.rs` | —    | Medium   | `.env` variant blind spot (misses `.env.production`, etc.)             | ⚠️ Open  |
| 42 | `scanning.rs` | —    | Low      | Test duplication across anomaly-counting tests                         | ⚠️ Open  |
| 43 | `scanning.rs` | —    | Low      | `lexical_clean_path` reinvents stdlib path normalization               | ⚠️ Open  |
| 44 | `scanning.rs` | —    | Low      | Test coverage regression: `unescape_trailing_backslash`               | ⚠️ Open  |
| 45 | `.github/workflows/ci.yml` | — | High | CI prompt injection via unsanitized `review_ledger.md`, skill files, findings files, AGENTS.md, and graphify output | ⚠️ Open  |
| 46 | `scanning.rs` | —    | Medium   | `is_harness_command` `uv` check coupling with sandbox script           | ⚠️ Open  |
| 47 | `scanning.rs` | —    | Medium   | `extract_sensitive_file_reads` requires decomposition (includes clone/fork fd-inheritance duplication — see Finding 67) | ⚠️ Open  |
| 48 | `.github/workflows/ci.yml` | — | Medium | CI `gh run download`, `gh run list`, and fallback `cat` silently swallow errors | ⚠️ Open  |
| 49 | `.github/workflows/ci.yml` | — | Medium | CI `GH_TOKEN` in environment for consolidation step increases blast radius | ⚠️ Open  |
| 51 | `.github/workflows/ci.yml` | — | Medium | Ledger delimiter collision can corrupt review history            | ⚠️ Open  |
| 52 | `.github/workflows/ci.yml` | — | Medium | Review ledger Python capping drops leading newline               | ⚠️ Open  |
| 53 | `scanning.rs` | —    | Medium   | `clone3` return value ambiguity for TID vs PID                         | ⚠️ Open  |
| 54 | `scanning.rs` | —    | Medium   | DNS compression pointer 5-hop limit can force fail-to-plain fallback   | ⚠️ Open  |
| 55 | `scanning.rs` | —    | Low      | `OnceLock` regex `.unwrap()` panics without context                    | ⚠️ Open  |
| 56 | `scanning.rs` | —    | Low      | `warn_and_block` `entry.allowed = false` is redundant                  | ⚠️ Open  |
| 57 | `scanning.rs` | —    | Low      | `_allowed_sensitive_reads` destructure is noise                        | ⚠️ Open  |
| 58 | `scanning.rs` | —    | Medium   | `is_sensitive_file_read` overlapping lists create a maintenance trap   | ⚠️ Open  |
| 59 | `scanning.rs` | —    | Medium   | Test traces do not exercise real strace `-xx` hex-escape path          | ⚠️ Open  |
| 60 | `scanning.rs` | —    | High     | Failed `open()` populates baselines without allowlist check            | ⚠️ Open  |
| 61 | `sandbox.rs`  | —    | Medium   | Performance regression from expanded strace trace set                  | ⚠️ Open  |
| 62 | `scanning.rs` | —    | Low      | `warn_and_block` unconditionally pushes without deduplication          | ⚠️ Open  |
| 63 | `scanning.rs` | —    | Low      | `blocked_reasons` fragile string literal comparisons                   | ⚠️ Open  |
| 64 | `scanning.rs` | —    | Low      | `extract_first_arg_fd` silently returns None on parse failure          | ⚠️ Open  |
| 65 | `graphify-out`| —    | Low      | `GRAPH_REPORT.md` references stale `docs/FINDINGS.md`                  | ⚠️ Open  |
| 66 | `.github/workflows/ci.yml` | — | Low | LLM prompt instructs model to suggest holistic fix under attacker influence | ⚠️ Open  |
| 67 | `scanning.rs` | — | Medium | Clone/fork fd-inheritance block duplicated verbatim in `extract_sensitive_file_reads` | ⚠️ Open  |
| 68 | `.github/workflows/ci.yml` | — | Medium | `gh run list` and `download` missing `--repo` flag                     | ⚠️ Open  |

| 72 | `.github/workflows/ci.yml` | — | Low | `PR_HEAD_REF` branch name passed to `gh` without validation            | ⚠️ Open  |
| 78 | `.github/workflows/ci.yml` | 449 | Medium | `grep -qi "^# consolidated review"` weakens post-consolidation check | ⚠️ Open |
| 80 | `.github/workflows/ci.yml` | 163 | Low | Symlink path for `.github/skills/` not validated before `cat` | ⚠️ Open |
| 29 | `scanning.rs` | —    | High     | `/proc/self/fd/N` evasion for sensitive file access                    | ⚠️ Open  |
| 34 | `scanning.rs` | —    | High     | Cross-PID `/proc/N/fd/` resolution bypass                              | ⚠️ Open  |
| 40 | `scanning.rs` | —    | High     | `/proc/self/fd/N` relative path traversal bypasses fd resolution       | ⚠️ Open  |
| 75 | `scanning.rs` | 1312 | High   | Relative path + cwd manipulation bypasses absolute string matches      | ⚠️ Open  |
| 76 | `scanning.rs` | 1753 | High | Missing integration test for insufficient_baselines fail-closed | ⚠️ Open |
| 171 | `scanning.rs` | — | High | `close` syscall not tracked — stale fd_table entries create `/proc/fd` bypass window | ⚠️ Open |
| 172 | `ARCHITECTURE.md` | — | Medium | `process_vm_readv` accepted risk understates inter-process memory read risk | ⚠️ Open |
| 173 | `ARCHITECTURE.md` | — | Medium | DNS exfiltration risk statement understates query-side data embedding | ⚠️ Open |
| 170 | `ARCHITECTURE.md` | — | Medium | Import-time execution gap omitted from Threat Model | ⚠️ Open |
| 177 | `*_DETAILED.md` | Low | Duplicate summary tables create a two-source-of-truth maintenance burden | ⚠️ Open |
| 256 | `scanning.rs:511` | Low | UDP DNS regex only matches `recvfrom`; `recvmsg()` used by glibc ≥2.40, musl, and async Rust resolvers produces no domain→IP mapping, degrading FCrDNS enrichment fallback to plain IP for those responses | ⚠️ Open |
| 257 | `scanning.rs:506-566` | Low | DNS interceptor only matches port-53 strace traffic; DoH (port 443) and DoT (port 853) bypass enrichment — C2 IPs still caught fail-closed but without domain context | ⚠️ Open |
| 258 | `scanning.rs:1976-1982` | Low | `insufficient_baselines` error message reports only the count shortfall; does not mention that age-gate filtering (`min_baseline_age_hours`) may have caused the shortage, making the failure opaque to users | ⚠️ Open |
| 262 | `.githooks/pre-commit:30` | Low | Echo message says "on staged Rust files" but `cargo fmt` at line 10 formats every `.rs` file in the workspace — unstaged formatting changes are silently normalized on commit; the scope widened from file-scoped (old `xargs -I {} cargo fmt {}`) to workspace-wide without updating the echo | ⚠️ Open |
| 263 | `scanning.rs:578` | Low | `exemption_behavior` uses raw `==` to compare version strings; build metadata (`1.0.0+build1` vs `1.0.0`) or non-normalised PEP 440 forms would silently fail to match, causing valid exemptions to be ignored (fail-closed, but operator churn) | ⚠️ Open |
| 264 | `scanning.rs:1893-1908` | Low | When registry fetch returns empty `published_at`, override handling is asymmetric: test mode (with active test env vars) silently trusts the override; production discards it with a warning. The discard path is never exercised by CI tests. | ⚠️ Open |
| 265 | `scanning.rs:1911` | Low | `check_override_ages` has thorough unit tests but no integration test verifies that a too-young override is dropped and a fetched baseline fills the slot in the `scan_packages_versions` production path | ⚠️ Open |
| 266 | `scanning.rs:601-604` | Low | `num_hours()` floors to whole hours; a 23h59m-old version reports "is only 23 hours old" in the warning — numeric comparison is accurate but message is misleading to operators | ⚠️ Open |
| 269 | `parsing.rs:346-348,506-507` | High | TOCTOU: requirements files and package.json are read eagerly at parse time; sandbox execution and the forwarded command run against the live filesystem — a file swap between parse and install causes a scan-install mismatch | ⚠️ Open |
| 270 | `scanning.rs:1291-1555` | Medium | Symlink traversal bypasses sensitive-file-read detection: `open("innocent")` where "innocent" is a symlink to `~/.aws/credentials` shows only the link path in strace; `is_sensitive_file_read("innocent")` returns false, so the credential read is never flagged | ⚠️ Open |
| 271 | `scanning.rs:522-528` | Medium | TCP DNS `recvfrom()` blind spot: READ_RE matches `read\|recvmsg` only; `recvfrom()` is valid on connected TCP sockets and used by some bespoke/async resolvers, bypassing DNS enrichment | ⚠️ Open |
| 277 | `lib.rs:270` | Low | `new_package_exemptions` key trimming silently overwrites if two YAML keys differ only by whitespace (`pkg` vs `pkg  `) — second entry wins with no warning | ⚠️ Open |
| 278 | `sandbox.rs:982-1004` | Low | `SandboxEnvVarGuard::set` does not save/restore the pre-existing env var value; Drop always calls `remove_var` unconditionally, losing any value that was set before the guard — test isolation concern | ⚠️ Open |
| 281 | `scanning.rs:241-254` | Medium | Domain planting: DNS interceptor fallback checks `baseline_domains` membership but verifies IP presence in the **current** trace's DNS map, not the baseline's — an attacker whose domain appeared in any baseline can route new C2 IPs through it and have them silently treated as benign CDN edge rotations | ⚠️ Open |
| 282 | `scanning.rs:1878` | Low | `baseline_count: 1` silently overridden to 2 via `.max(2)` with no warning; config parser warns on 0 but not 1, inconsistent handling | ⚠️ Open |
| 283 | `lib.rs:289-298,311-320` | Low | `release_burst_threshold` and `minimum_release_age_package` match blocks have redundant `None => None` arms — `Some(v) => Some(v), None => None` is identical to `v => v` | ⚠️ Open |
| 284 | `scanning.rs:596,623` | Low | `filter_override_version` and `check_override_ages` use `&std::collections::HashMap<...>` despite `HashMap` being imported at line 2 | ⚠️ Open |
| 285 | `scanning.rs:2000` | Low | `matches!(filtered_overrides, Some((Some(_), _)) \| Some((_, Some(_))))` re-derives whether any override survived age-filtering, duplicating logic already computed by `check_override_ages` | ⚠️ Open |
| 286 | `scanning.rs:684-685` | Low | `GYRSEEK_TEST_FORCE_BASELINE_AGES_HOURS` parse failures silently drop all entries via `filter_map(|s| s.parse().ok())`, returning zero candidates with no diagnostic (test-only code path) | ⚠️ Open |
| 287 | `scanning.rs:4249-4257` | Low | `extract_dns_map_ipv6_udp_dns_response` only asserts map and IP count; no concrete IP address verification unlike the IPv4 TCP equivalent | ⚠️ Open |
| 288 | `src/lib.rs` | Low | 0.6.0→1.0.0 upgrade introduces multiple breaking/behavior-changing items with no changelog or migration guide: `new_package_exemptions` list→map hard error, bare-TLD domain entries now silently dropped with warning, `"*"` and empty values in allowlists now emit warnings, per-package allowlist syntax is new | ⚠️ Open |
| 289 | `scanning.rs:6628-6681` | Medium | `scan_packages_versions_discards_overrides_when_registry_fails` test makes a real HTTP request to PyPI — `GYRSEEK_TEST_LOCK_ONLY` is not read by `fetch_history_with_baselines` and not listed in `active_test_env_vars()`; test fails in offline CI | ⚠️ Open |
| 294 | `scanning.rs:156-203` | Medium | Cloud metadata IP `169.254.169.254` is exempt from sandbox-local filtering, but Docker may route it through gateway `172.17.0.1`; strace then shows `connect()` to `172.17.0.1` which is filtered as RFC1918 private — credential theft signal lost | ⚠️ Open |
| 295 | `scanning.rs:6480-6490` | Low | `filter_override_version` tests only exercise empty `published_at`; no test uses a partial map where other versions are present but the override version is absent — distinct code path untested | ⚠️ Open |
| 296 | `tests/cli_burst_exit_tests.rs:152` | Low | Test name `exits_with_code_1_and_rejects_versions_newer_than_72_hours_by_default` is ambiguous — "newer than 72 hours" can mean either direction; `younger_than_72_hours` would be unambiguous | ⚠️ Open |









## Complexity & Over-Engineering Findings

| #  | File          | Tag      | What                                                                                     | Fix                                                                 | Status    |
|----|---------------|----------|------------------------------------------------------------------------------------------|---------------------------------------------------------------------|-----------|
| 180 | `lib.rs:1092-1173` | yagni | `bulk_scan!` macro spans 3 packaging ecosystems — a regression in one leaks to all | Replace with typed per-ecosystem functions (`bulk_scan_pip`, `bulk_scan_npm`, etc.) | ⚠️ Open  |
| 378 | `src/lib.rs` | Low | Parse-time warnings in `load_policy_config` (invalid IP, invalid domain, overly-permissive sensitive_file values) omit the config file path — operators with multi-project CI cannot identify which config file triggered the warning | Include `path` in all parse-time warning messages | ⚠️ Open |
| 379 | `src/lib.rs` | Low | Startup IP/domain count messages sum global and per-package buckets together — `total_ips` includes the `"*"` global bucket, so "Loaded N allowlisted IP(s)" conflates global and per-package entries with no breakdown | Separate or annotate the count (e.g. "2 global, 13 per-package") | ⚠️ Open |
| 380 | `src/lib.rs` | Low | All config-load warnings use `println!` (stdout) — lost in CI pipelines that only highlight stderr; `load_policy_config` has ~60 `println!` vs 1 `eprintln!` | Switch config validation warnings to `eprintln!` | ⚠️ Open |
| 381 | `src/lib.rs`, `src/scanning.rs` | Medium | Per-package allowlists are permanent trust anchors with no version-pinning — an allowlist entry granted for a legitimate version applies unchanged to any future compromised version of the same package | Add optional version-scoping to per-package allowlist entries | ⚠️ Open |
| 382 | `src/lib.rs` | Low | `sensitive_file_access_allowlist_all_values_filtered_drops_key` test only exercises `"*"` and `"/"` guards; `"*/"` and `"/*"` patterns are not tested — a regression removing either guard passes CI undetected | Add test cases for `"*/"` and `"/*"` in the all-values-filtered scenario | ⚠️ Open |
| 383 | `AGENTS.md`, `docs/ARCHITECTURE.md` | Low | `validate_allowlist_pkg_key`, `parse_list_map`, and `option_zero_to_none` are documented in full detail in both AGENTS.md and ARCHITECTURE.md — dual-source-of-truth drift risk; a future change to one is likely to leave the other stale | Make AGENTS.md the authoritative source; reduce ARCHITECTURE.md to a brief description with a cross-reference | ⚠️ Open |
| 387 | `src/scanning.rs` | Low | No test for `domain_is_allowlisted` when FCrDNS returns a trailing-dot hostname (e.g. `"example.com."`) — `normalize_domain` strips it but the path is untested; a regression removing the strip silently produces miss | Add unit test with trailing-dot input to `domain_is_allowlisted` | ⚠️ Open |
| 388 | `src/lib.rs` | Medium | Empty per-package IP/domain value list (`- my-pkg: []`) silently creates a dead `HashSet` entry — ip/domain PerPackage branches use `entry(pkg).or_default()` before iterating items; FIXED #363 warning only covers `parse_list_map`-based allowlists | Add post-loop empty-set check with warning in ip and domain PerPackage branches, consistent with FIXED #363 | ⚠️ Open |
| 389 | `src/scanning.rs` | Medium | `find_new_items` is used inconsistently — artifact diff uses inline `.difference().cloned().collect()` without the sort that `find_new_items` provides; three patterns exist for set-difference across the codebase | Use `find_new_items` (or an equivalent sorted helper) at the artifact diff site for consistency | ⚠️ Open |
| 390 | `src/scanning.rs` | Low | Triple `reverse_dns_domain` resolution per network endpoint — called in `find_new_connections_domain_aware`, again in `filter_domain_allowlisted_new_connections_with`, and again in the enrichment display loop; redundant PTR lookups per scan | Cache results in a `HashMap<String, Option<String>>` in the caller and pass it to all three sites | ⚠️ Open |
| 391 | `src/lib.rs` | Low | `parse_list_map_empty_value_set_drops_key` test only exercises blank/whitespace string values — a bare `my-pkg:` YAML key with no list items (empty Vec after serde) is not tested; regression in the empty-list warning path passes CI | Add test case with `my-pkg:` and no value list items | ⚠️ Open |
| 393 | `src/scanning.rs` | Medium | `filter_allowlisted_git_clone_signatures` matches URL only — splits signature on `\|`, takes index 0, discards all flags (`--recurse-submodules`, `--config core.gitProxy=...`, etc.); an operator allowlisting a URL for a package also silently permits the same URL cloned with malicious flags | Include flags in the allowlist match or require exact signature match | ⚠️ Open |
| 394 | `README.md` | Low | README `domain_allowlist` config table row does not mention bare-TLD rejection (FIXED #367) — operators upgrading with a bare-TLD entry (e.g. `"com"`) see a startup warning but no README explanation of the dot-presence requirement | Add bare-TLD rejection note to the README `domain_allowlist` row | ⚠️ Open |

---


*For detailed root causes and failure scenarios, see [OPEN_FINDINGS_DETAILED.md](./OPEN_FINDINGS_DETAILED.md).*
