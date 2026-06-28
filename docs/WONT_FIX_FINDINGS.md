# Won't Fix Findings

This document tracks findings that were raised by static analysis, AI reviews, or manual inspection, but have been explicitly marked as "Won't Fix" along with extensive rationale.

## Summary

| #   | File                       | Tag / Type       | What                                                                                     | Status       |
|-----|----------------------------|------------------|------------------------------------------------------------------------------------------|--------------|
| 190  | `lib.rs`                   | `shrink`         | 31-line manual arg-loop for `--config`/`-c`.                                             | 🚫 Won't Fix |
| 191  | `lib.rs`                   | `yagni`          | `NoopRunner` struct with full trait impl for test bypass.                                | 🚫 Won't Fix |
| 192  | `lib.rs`                   | `shrink`         | `ScanTimer` struct with `Instant`, `Drop`, two print branches.                           | 🚫 Won't Fix |
| 193  | `lib.rs`                   | `yagni`          | `scan_targets` is a 1-line delegate to `scan_many_with_cache`.                           | 🚫 Won't Fix |
| 194 | `parsing.rs`               | `shrink`         | `parse_poetry_lock_packages_from_content` has 7-param closure.                           | 🚫 Won't Fix |
| 195 | `sandbox.rs`               | `shrink`         | `scanner_user_setup_steps` returns `vec!["..."]`, called once.                           | 🚫 Won't Fix |
| 196 | `sandbox.rs`               | `shrink`         | `image_setup_steps` 4× `steps.push(...)` with `format!`.                                 | 🚫 Won't Fix |
| 197 | `scanning.rs`              | `false-positive` | Host-mode `uv pip install` leaks into exec signatures.                                   | 🚫 Won't Fix |
| 198 | `.github/workflows/ci.yml` | `false-positive` | `actions/checkout@v7` does not exist.                                                    | 🚫 Won't Fix |
| 199 | `scanning.rs`              | `false-positive` | `/.azure/` test exists but no `/.gnupg/` test.                                           | 🚫 Won't Fix |
| 200 | `README.md`                | `false-positive` | Exfiltration "caught at the network boundary" docs claim overstates completeness.        | 🚫 Won't Fix |
| 201 | `AGENTS.md`                | `false-positive` | Graphify skill referenced but skill file does not exist.                 | 🚫 Won't Fix |
| 202 | `docs/common_prompts.md` | `false-positive` | Raw CI prompt committed into documentation directory. | 🚫 Won't Fix |
| 203 | `sandbox.rs`               | `false-positive` | `process_vm_readv` is permitted in the seccomp profile.                                  | 🚫 Won't Fix |
| 204 | `scanning.rs`              | `false-positive` | Race condition in insufficient_baselines check ordering.                                 | 🚫 Won't Fix |
| 205| `.github/workflows/`       | `false-positive` | Prompt Injection / Runner Compromise exfiltrating deployment secrets.                    | 🚫 Won't Fix |
| 206| `.github/workflows/`       | `false-positive` | Autonomous Agent execution via `--dangerously-skip-permissions`.                         | 🚫 Won't Fix |
| 81 | `.github/scripts/sanitize_review.py` | `low` | Python truncation decodes by byte count and ignores UTF-8 errors. | 🚫 Won't Fix |
| 118 | `.github/workflows/ci.yml` | `low` | Doctest CI tests PR-head sanitizer, not default-branch production script. | 🚫 Won't Fix |
| 123 | `.github/workflows/post_review.yml` | `invalid` | Adding `actions/checkout` without `ref` would hand `GH_TOKEN` to attacker. | 🚫 Won't Fix |
| 124 | `.github/scripts/sanitize_review.py` | `low` | Code-block URL defanging is missing AST backtick-context awareness. | 🚫 Won't Fix |
| 125 | `.github/scripts/post_comment.sh` | `invalid` | `cmark --safe` flag deprecated in cmark ≥0.31. | 🚫 Won't Fix |
| 129 | `.github/scripts/post_comment.sh` | `accepted-risk` | No automated tests for `post_comment.sh`. | 🚫 Won't Fix |
| 207| `.github/workflows/ci.yml` | `accepted-risk`  | `timeout-minutes: 10` with no partial-output trap.                                       | 🚫 Won't Fix |
| 208| `.github/workflows/ci.yml` | `accepted-risk`  | `max-parallel: 3` vector for CI inference budget exhaustion.                             | 🚫 Won't Fix |
| 209| `AGENTS.md`                | `false-positive` | `AGENTS.md` CI description omits operational details (model name, SHA hash).             | 🚫 Won't Fix |
| 210| `.github/workflows/ci.yml` | `false-positive` | Redundant OpenCode installation script in dependent consolidation job.                   | 🚫 Won't Fix |
| 211| `.github/workflows/ci.yml` | `accepted-risk`  | LLM self-censoring via tool access (`--dangerously-skip-permissions`).                   | 🚫 Won't Fix |
| 212| `.github/workflows/ci.yml` | `accepted-risk`  | Findings documents (`OPEN_FINDINGS`, `WONT_FIX`) are not protected from PR tampering.    | 🚫 Won't Fix |
| 213| `.github/workflows/ci.yml` | `accepted-risk`  | `graphify update` parsing vulnerability leading to CI runner RCE.                        | 🚫 Won't Fix |
| 214| `.github/workflows/ci.yml` | `false-positive` | CI job fails if `gyrseek_review.md` or other artifact files are missing.                 | 🚫 Won't Fix |
| 215| `.github/workflows/ci.yml` | `false-positive` | Permissions fragmentation for `checks: write` across jobs.                               | 🚫 Won't Fix |
| 138 | `.github/scripts/sanitize_review.py` | `accepted-risk` | `PARENS_REGEX` depth-1 limit causes cosmetic artifacts on deeply-nested URLs. | 🚫 Won't Fix |
| 151 | `.github/scripts/sanitize_review.py` | `invalid` | `www.` defang is case-sensitive — GFM cmark-gfm is also case-sensitive; `WWW.` does not auto-link. | 🚫 Won't Fix |
| 152 | `.github/scripts/sanitize_review.py` | `accepted-risk` | Autolink `[^>]+` truncates at first literal `>` in URL — RFC-invalid URLs; `cmark --safe` second layer covers it. | 🚫 Won't Fix |
| 161 | `.github/scripts/sanitize_review.py` | `invalid`       | `@mention` defang regex fails on second `@` in malformed string like `@evil@user`. | 🚫 Won't Fix |
| 216| `.github/workflows/`       | `accepted-risk`  | Third-party actions use moving tags instead of being SHA-pinned.                         | 🚫 Won't Fix |
| 217| `.github/workflows/ci.yml` | `false-positive` | Truncated consolidation prompt is undetected due to lack of file size verification.      | 🚫 Won't Fix |
| 218| `.github/workflows/ci.yml` | `false-positive` | "Enhanced Only" template has no section for purely-new findings.                         | 🚫 Won't Fix |
| 219| `.github/workflows/ci.yml` | `false-positive` | No integrity verification (SHA-256) of multi-agent review outputs.                       | 🚫 Won't Fix |
| 220| `.github/workflows/ci.yml` | `accepted-risk`  | Per-reviewer skill injection removed, relying on autonomous discovery.                   | 🚫 Won't Fix |
| 221| `.github/workflows/ci.yml` | `false-positive` | Duplicated "checkout trusted policies" bash loop violates DRY.                           | 🚫 Won't Fix |
| 222| `.github/workflows/ci.yml` | `false-positive` | `consolidate-reviews` lacks explicit `success()` gate.                                   | 🚫 Won't Fix |
| 223| `.github/workflows/ci.yml` | `false-positive` | No SHA hash pin on `graphify` dependency. Duplicate of 179.                             | 🚫 Won't Fix |
| 224| `.github/workflows/ci.yml` | `false-positive` | `git fetch` race conditions across concurrent matrix pods.                               | 🚫 Won't Fix |
| 225| `.github/workflows/ci.yml` | `false-positive` | `rm -rf graphify-out` flagged as unnecessary noise.                                      | 🚫 Won't Fix |
| 226| `.github/workflows/ci.yml` | `false-positive` | `graphify-out/` architecture context flagged as generated but never consumed.            | 🚫 Won't Fix |
| 227| `.github/workflows/ci.yml` | `false-positive` | Latent coupling warning between cache key and temp script path.                          | 🚫 Won't Fix |
| 233| `docs/FIXED_FINDINGS.md` | `false-positive` | Fixed finding 92 fix description references stale architecture (graphify injection into prompt.txt) | 🚫 Won't Fix |
| 234| `.github/workflows/ci.yml` | `false-positive` | `fetch-err.log` never cleaned up, stale log could produce false warnings                 | 🚫 Won't Fix |
| 235| `.github/workflows/ci.yml` | `false-positive` | No script-level test to validate heredoc prompt well-formedness                          | 🚫 Won't Fix |
| 236| `scanning.rs` | `accepted-risk` | Slow-rolling behavioral poisoning — attacker introduces malicious behavior gradually over many versions to blend into baselines | 🚫 Won't Fix |
| 237| `scanning.rs` | `accepted-risk` | Baseline override allows pointing to an old version whose endpoints are allowlisted, framing it as the comparison point to bypass C2 detection | 🚫 Won't Fix |
| 179 | `.github/workflows/post_review.yml` + `.github/scripts/post_comment.sh` | `accepted-risk` | `workflow_run.pull_requests[0].number` does not exist; commit-based PR resolution returns first ambiguous match. | 🚫 Won't Fix |
| 240 | `docs/ARCHITECTURE.md` | `false-positive` | Claim that ARCHITECTURE.md line 94 documents `deserialize_new_package_exemptions` accepting deprecated list format with deprecation warning. | 🚫 Won't Fix |
| 241 | `AGENTS.md` | `false-positive` | Claim that AGENTS.md:117 states `min_baseline_age_hours` default as "2 hours" contradicting code value of 72. | 🚫 Won't Fix |
| 242 | `docs/FIXED_FINDINGS_DETAILED.md` | `false-positive` | Claim that Finding 239 omits the empty-list exception to the hard config-parse error for `new_package_exemptions`. | 🚫 Won't Fix |
| 243 | `README.md` | `false-positive` | Claim that `min_baseline_age_hours` config table row omits the 24h hard floor clamp. | 🚫 Won't Fix |
| 244 | `AGENTS.md` | `false-positive` | Claim that AGENTS.md overstates TCP DNS parser capability by saying it "tolerates short TCP reads" without disclosing the < 3 byte threshold or lack of reassembly. | 🚫 Won't Fix |
| 246 | `src/scanning.rs` | `false-positive` | Claim that `check_override_ages` tests use `Utc::now()` instead of deterministic timestamps. | 🚫 Won't Fix |
| 247 | `src/lib.rs` | `false-positive` | Claim that `deserialize_new_package_exemptions` error message uses `[pkg]` bracket syntax instead of correct YAML list format. | 🚫 Won't Fix |
| 248 | `src/scanning.rs` | `false-positive` | Claim that TCP DNS parser only captures `read()` and misses `recvmsg()`, allowing native resolvers to bypass DNS enrichment. | 🚫 Won't Fix |
| 249 | `src/scanning.rs` | `false-positive` | Claim that `Utc::now()` is captured once at `scan_packages_versions` function entry, becoming stale for late packages in bulk scans. | 🚫 Won't Fix |
| 250 | `docs/FIXED_FINDINGS_DETAILED.md` | `false-positive` | Claim that Finding 245 is documented twice (at line 1190 and 1442) with different detail levels. | 🚫 Won't Fix |
| 251 | `docs/OPEN_FINDINGS.md` | `false-positive` | Claim that Finding 70 was removed from OPEN_FINDINGS.md but never migrated to FIXED_FINDINGS.md. | 🚫 Won't Fix |
| 300a | `docs/FIXED_FINDINGS.md` | `false-positive` | Claim that Finding 241 summary table entry is 530+ words, violating single-line convention. (Originally filed as #252 — renumbered to avoid namespace collision with FIXED #252; see OPEN #299.) | 🚫 Won't Fix |
| 253 | `AGENTS.md` | `false-positive` | Claim that AGENTS.md lines routinely exceed 2000 characters, creating merge conflict hotspots. | 🚫 Won't Fix |
| 259 | `AGENTS.md` / `scanning.rs` | `false-positive` | Claim that concatenated TCP DNS responses are silently dropped and that an attacker could inject a second poisoned response — AGENTS.md already explicitly documents this limitation. | 🚫 Won't Fix |
| 260 | `scanning.rs:1994-1999` | `false-positive` | Claim that self-ref override warns but does not block, allowing YAML-write attackers to disable anomaly detection. Config is an explicitly trusted boundary (accepted per Finding 237). | 🚫 Won't Fix |
| 261 | `src/lib.rs` / `AGENTS.md` | `false-positive` | Claim that `min_baseline_age_hours` default was changed from 2h to 72h with no backward-compat migration warning. The default has always been 72h; the "2h" value was fabricated. | 🚫 Won't Fix |
| 267 | `scanning.rs:640` | `yagni` | Claim that `active_test_env_vars()` lacks a dedicated unit test verifying each env-var name is correctly detected. | 🚫 Won't Fix |
| 268 | `docs/OPEN_FINDINGS.md` | `false-positive` | Claim that OPEN_FINDINGS.md #177 must be annotated with partial-progress status because the FIXED_FINDINGS_DETAILED.md summary table was removed in this PR. | 🚫 Won't Fix |
| 273 | `docs/FIXED_FINDINGS.md` | `false-positive` | Claim that findings 254–255 omit the `src/` prefix inconsistently with adjacent entries — entries 244–251 in the same table also lack the `src/` prefix; no consistent convention was violated. | 🚫 Won't Fix |
| 274 | `scanning.rs:1893-1908` | `false-positive` | Claim that operators cannot distinguish age-rejection from registry-outage as the cause of override removal — the two paths emit distinct messages ("security floor" vs "Registry fetch failed (empty publish times)"). | 🚫 Won't Fix |
| 279 | `sandbox.rs:990-996` | `yagni` | Claim that `SandboxEnvVarGuard::remove` redundantly calls `remove_var` in both constructor and Drop — the double-remove is idempotent and ensures the var is absent regardless of what the test body does. | 🚫 Won't Fix |
| 280 | `scanning.rs:693,764,808` | `yagni` | Claim that removing `.max(0)` from `Duration::hours(min_baseline_age_hours)` removes a defense layer — config parser already enforces ≥24h at the single correct enforcement point; a redundant guard that can never trigger is defensive bloat. | 🚫 Won't Fix |
| 290 | `docs/FIXED_FINDINGS_DETAILED.md` | `false-positive` | Claim that Finding 229 references a `MapVisitor` implementation that was never committed — no such reference exists in the file; the documented fix correctly describes the `#[serde(untagged)]` enum approach throughout. | 🚫 Won't Fix |
| 293 | `src/lib.rs:36-41` | `false-positive` | Claim that `#[allow(dead_code)]` on `InvalidMap` and `List` variants is unnecessary because they appear in match arms — with `#[serde(untagged)]` serde constructs variants through macro-generated code invisible to rustc's dead-code analysis; the annotation is required to suppress spurious unused-variant warnings. | 🚫 Won't Fix |
| 297 | `scanning.rs:156-190` | `false-positive` | Claim that an unparseable IP string in a strace trace would be silently ignored — `normalize_ip_string` returns the string unchanged and `is_sandbox_local_ip` returns `false` on parse error, so malformed strings are NOT filtered and WILL be flagged as new endpoints (fail-closed). | 🚫 Won't Fix |
| 300 | `scanning.rs:1671-1719` | `yagni` | Claim that `select_effective_baselines` returning `(Vec<String>, bool)` couples selection logic to diagnostic output — the `self_ref` bool flags a distinct semantic state ("override equals current version") separate from whether any overrides survived; the coupling is minimal and the bool is semantically meaningful, not a diagnostic artifact. | 🚫 Won't Fix |
| 301 | `scanning.rs:1839-2373` | `yagni` | Claim that `scan_packages_versions` at ~534 lines has too many responsibilities and the `#[cfg(any(debug_assertions, test))]` branching creates behavioral asymmetry — function size is a style concern not tied to correctness; the test/production asymmetry is already tracked as OPEN #264. | 🚫 Won't Fix |


*For detailed reasoning, see [WONT_FIX_FINDINGS_DETAILED.md](./WONT_FIX_FINDINGS_DETAILED.md).*
