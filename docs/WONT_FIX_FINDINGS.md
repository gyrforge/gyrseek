# Won't Fix Findings

This document tracks findings that were raised by static analysis, AI reviews, or manual inspection, but have been explicitly marked as "Won't Fix" along with extensive rationale.

## Summary

| #   | File                       | Tag / Type       | What                                                                                     | Status       |
|-----|----------------------------|------------------|------------------------------------------------------------------------------------------|--------------|
| 213  | `lib.rs`                   | `shrink`         | 31-line manual arg-loop for `--config`/`-c`.                                             | 🚫 Won't Fix |
| 215  | `lib.rs`                   | `yagni`          | `NoopRunner` struct with full trait impl for test bypass.                                | 🚫 Won't Fix |
| 216  | `lib.rs`                   | `shrink`         | `ScanTimer` struct with `Instant`, `Drop`, two print branches.                           | 🚫 Won't Fix |
| 217  | `lib.rs`                   | `yagni`          | `scan_targets` is a 1-line delegate to `scan_many_with_cache`.                           | 🚫 Won't Fix |
| 198 | `parsing.rs`               | `shrink`         | `parse_poetry_lock_packages_from_content` has 7-param closure.                           | 🚫 Won't Fix |
| 199 | `sandbox.rs`               | `shrink`         | `scanner_user_setup_steps` returns `vec!["..."]`, called once.                           | 🚫 Won't Fix |
| 200 | `sandbox.rs`               | `shrink`         | `image_setup_steps` 4× `steps.push(...)` with `format!`.                                 | 🚫 Won't Fix |
| 205 | `scanning.rs`              | `false-positive` | Host-mode `uv pip install` leaks into exec signatures.                                   | 🚫 Won't Fix |
| 206 | `.github/workflows/ci.yml` | `false-positive` | `actions/checkout@v7` does not exist.                                                    | 🚫 Won't Fix |
| 207 | `scanning.rs`              | `false-positive` | `/.azure/` test exists but no `/.gnupg/` test.                                           | 🚫 Won't Fix |
| 208 | `README.md`                | `false-positive` | Exfiltration "caught at the network boundary" docs claim overstates completeness.        | 🚫 Won't Fix |
| 209 | `AGENTS.md`                | `false-positive` | Graphify skill referenced but skill file does not exist.                 | 🚫 Won't Fix |
| 210 | `docs/common_prompts.md` | `false-positive` | Raw CI prompt committed into documentation directory. | 🚫 Won't Fix |
| 211 | `sandbox.rs`               | `false-positive` | `process_vm_readv` is permitted in the seccomp profile.                                  | 🚫 Won't Fix |
| 212 | `scanning.rs`              | `false-positive` | Race condition in insufficient_baselines check ordering.                                 | 🚫 Won't Fix |
| 171| `.github/workflows/`       | `false-positive` | Prompt Injection / Runner Compromise exfiltrating deployment secrets.                    | 🚫 Won't Fix |
| 172| `.github/workflows/`       | `false-positive` | Autonomous Agent execution via `--dangerously-skip-permissions`.                         | 🚫 Won't Fix |
| 81  | `.github/scripts/sanitize_review.py` | `low` | Python truncation decodes by byte count and ignores UTF-8 errors. | 🚫 Won't Fix |
| 118 | `.github/workflows/ci.yml` | `low` | Doctest CI tests PR-head sanitizer, not default-branch production script. | 🚫 Won't Fix |
| 123 | `.github/workflows/post_review.yml` | `invalid` | Adding `actions/checkout` without `ref` would hand `GH_TOKEN` to attacker. | 🚫 Won't Fix |
| 124 | `.github/scripts/sanitize_review.py` | `low` | Code-block URL defanging is missing AST backtick-context awareness. | 🚫 Won't Fix |
| 125 | `.github/scripts/post_comment.sh` | `invalid` | `cmark --safe` flag deprecated in cmark ≥0.31. | 🚫 Won't Fix |
| 129 | `.github/scripts/post_comment.sh` | `accepted-risk` | No automated tests for `post_comment.sh`. | 🚫 Won't Fix |
| 173| `.github/workflows/ci.yml` | `accepted-risk`  | `timeout-minutes: 10` with no partial-output trap.                                       | 🚫 Won't Fix |
| 174| `.github/workflows/ci.yml` | `accepted-risk`  | `max-parallel: 3` vector for CI inference budget exhaustion.                             | 🚫 Won't Fix |
| 175| `AGENTS.md`                | `false-positive` | `AGENTS.md` CI description omits operational details (model name, SHA hash).             | 🚫 Won't Fix |
| 176| `.github/workflows/ci.yml` | `false-positive` | Redundant OpenCode installation script in dependent consolidation job.                   | 🚫 Won't Fix |
| 177| `.github/workflows/ci.yml` | `accepted-risk`  | LLM self-censoring via tool access (`--dangerously-skip-permissions`).                   | 🚫 Won't Fix |
| 178| `.github/workflows/ci.yml` | `accepted-risk`  | Findings documents (`OPEN_FINDINGS`, `WONT_FIX`) are not protected from PR tampering.    | 🚫 Won't Fix |
| 179| `.github/workflows/ci.yml` | `accepted-risk`  | `graphify update` parsing vulnerability leading to CI runner RCE.                        | 🚫 Won't Fix |
| 180| `.github/workflows/ci.yml` | `false-positive` | CI job fails if `gyrseek_review.md` or other artifact files are missing.                 | 🚫 Won't Fix |
| 181| `.github/workflows/ci.yml` | `false-positive` | Permissions fragmentation for `checks: write` across jobs.                               | 🚫 Won't Fix |
| 138 | `.github/scripts/sanitize_review.py` | `accepted-risk` | `PARENS_REGEX` depth-1 limit causes cosmetic artifacts on deeply-nested URLs. | 🚫 Won't Fix |
| 151 | `.github/scripts/sanitize_review.py` | `invalid` | `www.` defang is case-sensitive — GFM cmark-gfm is also case-sensitive; `WWW.` does not auto-link. | 🚫 Won't Fix |
| 152 | `.github/scripts/sanitize_review.py` | `accepted-risk` | Autolink `[^>]+` truncates at first literal `>` in URL — RFC-invalid URLs; `cmark --safe` second layer covers it. | 🚫 Won't Fix |
| 161 | `.github/scripts/sanitize_review.py` | `invalid`       | `@mention` defang regex fails on second `@` in malformed string like `@evil@user`. | 🚫 Won't Fix |
| 182| `.github/workflows/`       | `accepted-risk`  | Third-party actions use moving tags instead of being SHA-pinned.                         | 🚫 Won't Fix |
| 183| `.github/workflows/ci.yml` | `false-positive` | Truncated consolidation prompt is undetected due to lack of file size verification.      | 🚫 Won't Fix |
| 184| `.github/workflows/ci.yml` | `false-positive` | "Enhanced Only" template has no section for purely-new findings.                         | 🚫 Won't Fix |
| 185| `.github/workflows/ci.yml` | `false-positive` | No integrity verification (SHA-256) of multi-agent review outputs.                       | 🚫 Won't Fix |
| 186| `.github/workflows/ci.yml` | `accepted-risk`  | Per-reviewer skill injection removed, relying on autonomous discovery.                   | 🚫 Won't Fix |
| 187| `.github/workflows/ci.yml` | `false-positive` | Duplicated "checkout trusted policies" bash loop violates DRY.                           | 🚫 Won't Fix |
| 188| `.github/workflows/ci.yml` | `false-positive` | `consolidate-reviews` lacks explicit `success()` gate.                                   | 🚫 Won't Fix |
| 189| `.github/workflows/ci.yml` | `false-positive` | No SHA hash pin on `graphify` dependency. Duplicate of 179.                             | 🚫 Won't Fix |
| 190| `.github/workflows/ci.yml` | `false-positive` | `git fetch` race conditions across concurrent matrix pods.                               | 🚫 Won't Fix |
| 191| `.github/workflows/ci.yml` | `false-positive` | `rm -rf graphify-out` flagged as unnecessary noise.                                      | 🚫 Won't Fix |
| 192| `.github/workflows/ci.yml` | `false-positive` | `graphify-out/` architecture context flagged as generated but never consumed.            | 🚫 Won't Fix |
| 193| `.github/workflows/ci.yml` | `false-positive` | Latent coupling warning between cache key and temp script path.                          | 🚫 Won't Fix |
| 130 | `.github/workflows/post_review.yml` + `.github/scripts/post_comment.sh` | `accepted-risk` | `workflow_run.pull_requests[0].number` does not exist; commit-based PR resolution returns first ambiguous match. | 🚫 Won't Fix |


*For detailed reasoning, see [WONT_FIX_FINDINGS_DETAILED.md](./WONT_FIX_FINDINGS_DETAILED.md).*
