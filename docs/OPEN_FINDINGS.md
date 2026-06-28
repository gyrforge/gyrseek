# Open Findings

## Security & Correctness Findings

### Summary

| #  | File          | Line | Severity | Description                                                           | Status    |
|----|---------------|------|----------|-----------------------------------------------------------------------|-----------|
| 11 | `parsing.rs`  | 468  | High     | All-non-registry npm CLI args trigger package.json fallback           | ⚠️ Open  |
| 12 | `lib.rs`      | 1021 | High     | All-non-registry npm CLI args + no package.json → valid install blocked | ⚠️ Open |
| 14 | `parsing.rs`  | 880  | Low      | Temp file not cleaned up on test assertion failure                    | ⚠️ Open  |
| 21 | `sandbox.rs`  | 629  | High     | Hardcoded 512 MB container memory — npm/pnpm native builds routinely OOM-killed | ⚠️ Open  |
| 22 | `scanning.rs` | 188  | Medium   | IPv6 ULA (`fc00::/7`) not filtered as local — internal container traffic flagged as exfiltration | ⚠️ Open  |
| 23 | `sandbox.rs`  | 215  | Medium   | Host mode selected silently — no stderr warning that sandbox protection is disabled | ⚠️ Open  |
| 24 | `sandbox.rs`  | 555  | Medium   | Artifact scan spawns 3 processes per file — O(N) subprocess overhead on large node_modules | ⚠️ Open  |
| 25 | `README.md` / `sandbox.rs` | 363 / —  | High     | Import-time execution not captured — Telnyx T26 bypasses install-window sandbox entirely | ⚠️ Open  |
| 26 | `lib.rs`      | 588  | Medium   | `Command::new` relies on PATH — relative-path hijacking in untrusted working dirs | ⚠️ Open  |
| 27 | `lib.rs`      | 64   | Low      | `--config` value not validated — flag-like value silently swallowed as file path | ⚠️ Open  |
| 28 | `scanning.rs` | —    | High     | Baseline poisoning evasion for sensitive file access                  | ⚠️ Open  |
| 31 | `sandbox.rs`  | —    | Critical | `pidfd_open` and `pidfd_getfd` not blocked, allowing fd theft          | ⚠️ Open  |
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
| 47 | `scanning.rs` | —    | Medium   | `extract_sensitive_file_reads` requires decomposition                  | ⚠️ Open  |
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
| 67 | `scanning.rs` | —    | Medium   | Clone/fork fd-inheritance block duplicated verbatim                    | ⚠️ Open  |
| 68 | `.github/workflows/ci.yml` | — | Medium | `gh run list` and `download` missing `--repo` flag                     | ⚠️ Open  |
| 69 | `sandbox.rs`  | —    | Medium   | `env_lock` unsafe pattern in tests misses RAII guard                   | ⚠️ Open  |
| 72 | `.github/workflows/ci.yml` | — | Low | `PR_HEAD_REF` branch name passed to `gh` without validation            | ⚠️ Open  |
| 78 | `.github/workflows/ci.yml` | 449 | Medium | `grep -qi "^# consolidated review"` weakens post-consolidation check | ⚠️ Open |
| 79 | `lib.rs`      | 133  | Low    | `parse_list_map` has no inline tests | ⚠️ Open |
| 80 | `.github/workflows/ci.yml` | 163 | Low | Symlink path for `.github/skills/` not validated before `cat` | ⚠️ Open |
| 29 | `scanning.rs` | —    | High     | `/proc/self/fd/N` evasion for sensitive file access                    | ⚠️ Open  |
| 34 | `scanning.rs` | —    | High     | Cross-PID `/proc/N/fd/` resolution bypass                              | ⚠️ Open  |
| 40 | `scanning.rs` | —    | High     | `/proc/self/fd/N` relative path traversal bypasses fd resolution       | ⚠️ Open  |
| 75 | `scanning.rs` | 1312 | High   | Relative path + cwd manipulation bypasses absolute string matches      | ⚠️ Open  |
| 76 | `scanning.rs` | 1753 | High | Missing integration test for insufficient_baselines fail-closed | ⚠️ Open |
| 77 | `scanning.rs` | 1363 | High | Missing cross-package isolation test for sensitive_file_access_allowlist | ⚠️ Open |
| TM-2 | `scanning.rs` | — | High | `close` syscall not tracked — stale fd_table entries create `/proc/fd` bypass window | ⚠️ Open |
| TM-4 | `ARCHITECTURE.md` | — | Medium | `process_vm_readv` accepted risk understates inter-process memory read risk | ⚠️ Open |
| TM-6 | `ARCHITECTURE.md` | — | Medium | DNS exfiltration risk statement understates query-side data embedding | ⚠️ Open |
| CURL-SH | `.githooks/pre-commit` | 20 | High | Pre-commit `curl | sh` without integrity verification | ⚠️ Open |
| APPSEC-3 | `.githooks/pre-commit` | 29 | Medium | `go install ...@latest` unpinned tool version | ⚠️ Open |
| APPSEC-4 | `.githooks/pre-commit` | 25 | Low | `sudo apt-get` in pre-commit hook without user warning | ⚠️ Open |
| SENIOR-3 | `.githooks/pre-commit` | 29 | Low | `go install` without Go prerequisite check | ⚠️ Open |
| DOC-1 | `ARCHITECTURE.md` | — | Medium | Import-time execution gap omitted from Threat Model | ⚠️ Open |






## Complexity & Over-Engineering Findings

| #  | File          | Tag      | What                                                                                     | Fix                                                                 | Status    |
|----|---------------|----------|------------------------------------------------------------------------------------------|---------------------------------------------------------------------|-----------|
| C16 | `lib.rs:1092-1173` | yagni | `bulk_scan!` macro spans 3 packaging ecosystems — a regression in one leaks to all | Replace with typed per-ecosystem functions (`bulk_scan_pip`, `bulk_scan_npm`, etc.) | ⚠️ Open  |

---


*For detailed root causes and failure scenarios, see [OPEN_FINDINGS_DETAILED.md](./OPEN_FINDINGS_DETAILED.md).*
