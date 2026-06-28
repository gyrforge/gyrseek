# Fixed Findings

### Summary

| # | File | Tag/Severity | Description | Fix/Notes | Status |
|---|------|--------------|-------------|-----------|--------|
| 1 | `sandbox.rs`:188 | Critical | Empty trace on strace failure passes as clean scan | — | ✅ Fixed |
| 2 | `scanning.rs`:199 | Critical | PTR-record domain allowlist bypassable by attacker | — | ✅ Fixed |
| 3 | `scanning.rs`:427 | High | Argv regex truncates at first `]` — corrupts signatures | — | ✅ Fixed |
| 4 | `sandbox.rs`:307 | High | `\|\| true` suppresses strace failures — root cause of #1 | — | ✅ Fixed |
| 5 | `parsing.rs`:113 | High | Poetry non-develop local-path packages leak through filter | — | ✅ Fixed |
| 6 | `parsing.rs`:298 | Medium | PEP 508 extras in package name → PyPI 404 → zero baselines | — | ✅ Fixed |
| 7 | `parsing.rs`:576 | Medium | Extras key mismatch breaks version pinning in forwarded command | — | ✅ Fixed |
| 8 | `lib.rs`:536 | Medium | Child exit status discarded — failed installs appear successful | — | ✅ Fixed |
| 9 | `lib.rs` | Medium | Unrecognized managers silently forwarded unscanned | — | ✅ Fixed |
| 10 | `scanning.rs`:654 | Critical | Self-referencing baseline override disables all anomaly detection | — | ✅ Fixed |
| 13 | `scanning.rs`:1852 | Medium | Async tests set env var without drop-guard — panic leaves it set | — | ✅ Fixed |
| 15 | `sandbox.rs`:511 | Low | Empty `GYRSEEK_*_SCANNER_IMAGE` env var used as docker image ref | — | ✅ Fixed |
| 16 | `scanning.rs`:509 | Medium | `extract_dns_map` regex missing `\s*` — never matches real strace output | — | ✅ Fixed |
| 17 | `scanning.rs`:972 | High | `-xx` strace flag hex-escapes execve argv → `is_harness_command` false positives | — | ✅ Fixed |
| 18 | `scanning.rs`:467 | Medium | `parse_dns_response` RDLEN offset reads TTL bytes instead of RDLENGTH | — | ✅ Fixed |
| 19 | `scanning.rs`:392 | High | `decode_dns_name` no cycle detection → infinite loop on circular pointer | — | ✅ Fixed |
| 20 | `sandbox.rs` / `scanning.rs`:559 / 730 | Critical | Pipe delimiter in artifact log — filename injection bypasses all artifact checks | — | ✅ Fixed |
| 30 | `sandbox.rs` | Critical | `io_uring` syscalls not blocked by seccomp, bypassing strace | Added to blocklist | ✅ Fixed |
| 31 | `sandbox.rs` | High | `process_vm_writev` not blocked by seccomp, allowing sibling memory corruption | Added to blocklist | ✅ Fixed |
| 214 | `lib.rs:97-274` | `shrink` | `load_policy_config` is 177 lines of trim→filter→collect for 8 list fields. | `parse_list()` helper; 5 list fields collapsed to 1-liners. | ✅ Fixed |
| 218 | `Cargo.toml:7` | `shrink` | `tokio` with `features = ["full"]` pulls in 30+ features. | `["rt", "rt-multi-thread", "macros"]` — 3 features instead of 30+. | ✅ Fixed |
| 219 | `scanning.rs:76-95` | `shrink` | `compare_version_strings` repeats the same Ok/Err/Err/Ok match on both branches. | `parse_and_cmp::<T>` generic helper unifies both arms. | ✅ Fixed |
| 220 | `scanning.rs:1009-1013` | `yagni` | `burst_triggered` has one caller (`burst_policy_warning`). | Inlined `match` at caller; tests updated to use `burst_policy_warning`. | ✅ Fixed |
| 221 | `scanning.rs:1325-1343, 1400-1415, 1440-1473` | `shrink` | Three near-identical "CRITICAL WARNING: Behavioral anomaly flagged" blocks. | `fn warn_and_block(...)` saves ~50 lines; all 3 + artifact block consolidated. | ✅ Fixed |
| 197 | `parsing.rs:648-714` | `shrink` | `parse_package_details` has 5-layer nested if/else per manager. | `match` with guards replaces 5-layer if/else chain. | ✅ Fixed |
| 201 | `sandbox.rs:662-669` | `yagni` | `docker_seccomp_profile_arg` wraps one format call. | Inline `format!("seccomp={}", path?)` at call site. | ✅ Fixed |
| 202 | `scanning.rs:1383-1391` | `shrink` | 8-line loop+flatten over two `Option<String>` refs to print warning. | `if m1.as_deref() == Some(&v_curr) \|\| m2.as_deref() == Some(&v_curr)`, 3 lines. | ✅ Fixed |
| 204 | `scanning.rs` / `parsing.rs` / `sandbox.rs` | `shrink` | 14× `Vec::new()` + push-loop that could be iterator adaptors (`.filter_map().collect()`, `.partition()`, `.filter().take().collect()`, `.map().collect()`). Most clear-cut: `parse_requirements_packages_from_content` (`parsing.rs:321`, 5 lines → 1), `select_age_eligible_baselines` (`scanning.rs:1166`, 11 lines → 3 with `.filter().take()`), and 5 allowlist-split functions that could use `.partition()` (e.g. `filter_allowlisted_new_connections` at `scanning.rs:261`, 26 lines → 6). The double-collect to reverse stdout tail lines (`sandbox.rs:345`, `.collect::<Vec<_>>().into_iter().rev().collect()`) is a standalone allocation. | Convert to iterator adaptors. | ✅ Fixed |
| 41 | `.github/workflows/ci.yml` | `audit-trail` | Migrated to Won't Fix as **182** (Third-party actions not SHA-pinned) | See `WONT_FIX_FINDINGS.md` | ✅ Migrated |
| 71 | `docs/FIXED_FINDINGS.md` | ``documentation`` | Drops cross-finding chain documentation from original file | Restore architectural context | ✅ Fixed |
| 73 | `docs/common_prompts.md` | ``formatting`` | Missing trailing newline | Append newline | ✅ Fixed |
| 83 | `.github/workflows/ci.yml` | High | `graphify` runs from PR workspace, allowing arbitrary prompt injection | Regenerate on PR branch + Python `<REDACTED>` tag replacement | ✅ Fixed |
| 87 | `.github/workflows/post_review.yml` | Critical | `post_review.yml` untrusted PR artifact spoofing ("Pwn Request") | Use GitHub API `head_sha` instead of artifact | ✅ Fixed |
| 88 | `.github/workflows/ci.yml` | High | Fail-open checkout allows prompt injection via `AGENTS.md` | Replaced atomic checkout with robust `rm -rf` loop | ✅ Fixed |
| 89 | `.github/workflows/ci.yml` | Low | Hardcoded `/tmp` paths susceptible to symlink race conditions | Use `${{ runner.temp }}` instead of `/tmp` | ✅ Fixed |
| 90 | `.github/workflows/ci.yml` | Low | First-run ledger retrieval fetches literal `"null"` as run ID | Added `"null"` guard to ledger logic | ✅ Fixed |
| 91 | `.github/review-prompts/`  | Low | Stale XML references to removed static skill-injection script | Updated prompts to mandate autonomous tool-use | ✅ Fixed |
| 92 | `.github/workflows/ci.yml` | Low | Shallow-fetch error output written but never read | Log file is checked and emitted as `::warning::` | ✅ Fixed |
| 93 | `.github/workflows/`       | Low | Outdated `${{ secrets.GITHUB_TOKEN }}` syntax | Replaced with modern idiomatic `${{ github.token }}` | ✅ Fixed |
| 94 | `.github/workflows/`       | Low | Missing `timeout-minutes` on PR comment job | Added `timeout-minutes: 10` | ✅ Fixed |
| 95 | `.github/workflows/`       | Low | Undocumented fragile `workflow_run` name coupling | Added explicit sync `WARNING` comments to both files | ✅ Fixed |
| 96 | `.github/workflows/ci.yml` | Low | Unnecessary YAML block scalar `|` for single path | Flattened YAML formatting | ✅ Fixed |
| 97 | `.github/workflows/ci.yml` | Low | `|| true` on `git fetch` masked legitimate network failures | Removed `|| true` to enforce fast-fail on network hangups | ✅ Fixed |
| 98 | `.github/workflows/ci.yml` | High | Missing `.github/review-prompts/` in trusted policy checkout allows system prompt injection | Added prompt dir to the base-branch checkout loop | ✅ Fixed |
| 99 | `.github/workflows/ci.yml` | Low | `2>/dev/null` on trusted policy checkout masks diagnostic output | Removed `2>/dev/null` to restore git error logging | ✅ Fixed |
| 100 | `.github/workflows/ci.yml` | Low | `|| true` on `rm -rf graphify-out` masks immutable-file errors | Removed `|| true` to enforce strict workspace sanitization | ✅ Fixed |
| 101 | `.github/workflows/ci.yml` | Low | Legacy `${{ secrets.GITHUB_TOKEN }}` syntax | Replaced with modern idiomatic `${{ github.token }}` | ✅ Fixed |
| 102 | `.github/workflows/post_review.yml` | Medium | Missing `--safe` flag on `cmark` fails to sanitize HTML/XSS | Added `--safe` flag to omit raw HTML and dangerous URLs | ✅ Fixed |
| 103 | `.github/workflows/ci.yml` | Low | Prompt asymmetry in consolidation template | Added explicit usage instructions for severity sections | ✅ Fixed |
| 104 | `.github/workflows/ci.yml` | Low | Stale XML tag references in prompt caused AI hallucinations | Replaced `<open_findings>` with explicit file paths | ✅ Fixed |
| 105 | `.github/workflows/ci.yml` | Low | Additional stale XML tag references in consolidation prompt | Replaced `<untrusted_inputs>` and `<previous_review>` with file paths | ✅ Fixed |
| 106 | `.github/workflows/ci.yml` | High | Blind stdout fallback copied errors/injections to official review artifact | Removed stdout fallback and forced explicit file output | ✅ Fixed |
| 107 | `docs/ARCHITECTURE.md` | Low | CI Pipeline privilege separation boundary not formally documented | Added `CI/CD Pipeline Architecture` section | ✅ Fixed |
| 108 | `.github/workflows/post_review.yml` | High | `cmark --safe` fails to sanitize valid phishing markdown links | Extracted logic to `post_comment.sh` and `sanitize_review.py` | ✅ Fixed |
| 109 | `.github/scripts/sanitize_review.py` | High | Empty alt-text (`![]()`) bypasses regex link stripping | Changed regex `+` to `*` to catch empty brackets | ✅ Fixed |
| 110 | `.github/scripts/post_comment.sh` | Medium | Fails open with exit 0 if review artifact or PR number is missing | Changed `exit 0` to `exit 1` with `::error::` | ✅ Fixed |
| 111 | `.github/scripts/sanitize_review.py` | Low | Reference link definition regex misses non-HTTP schemes | Replaced `http.*` with `\S+` to strip any protocol | ✅ Fixed |
| 112 | `.github/scripts/sanitize_review.py` | Low | Nested parenthesis in URLs causes partial stripping | Refactored regex to properly consume balanced parentheses | ✅ Fixed |
| 113 | `.github/scripts/sanitize_review.py` | Low | Missing CI tests for regex logic | Added `doctest` step to `ci.yml` to prevent regressions | ✅ Fixed |
| 114 | `.github/scripts/sanitize_review.py` | Medium | Bare URLs and IPv6 literals auto-link in GitHub | Added universal defang step to replace `://` with `[://]` | ✅ Fixed |
| 115 | `.github/scripts/post_comment.sh` | Low | Dead variable `truncated_file` | Removed dead variable and cleaned up trap | ✅ Fixed |
| 116 | `.github/scripts/sanitize_review.py` | Low | Unnecessary `argparse` boilerplate | Replaced with native `sys.argv` matching lazy engineering | ✅ Fixed |
| 117 | `.github/scripts/post_comment.sh` | Medium | Source file re-check gap | Added check to fail closed if `sanitized_file` is empty before posting | ✅ Fixed |
| 119 | `.github/scripts/sanitize_review.py` | Low | Autolink regex ignores non-HTTP schemes | Replaced `https?` with RFC 3986 generic scheme regex | ✅ Fixed |
| 120 | `.github/workflows/post_review.yml` | High | `GH_TOKEN` exposed to Python subprocess | Used `env -u GH_TOKEN` to explicitly strip the token from the Python environment | ✅ Fixed |
| 121 | `.github/workflows/ci.yml` | Low | `doctest` passes silently with 0 tests | Enforced test execution by asserting `res.attempted > 0` | ✅ Fixed |
| 122 | `.github/scripts/sanitize_review.py` | Low | Unnecessary nested function `defang_url` | Replaced with an inline `lambda` matching lazy engineering | ✅ Fixed |
| 126 | `.github/scripts/sanitize_review.py` | Low | Dead flexibility in `max_bytes` parameter | Converted to a module-level constant `MAX_REVIEW_BYTES` | ✅ Fixed |
| 127 | `.github/scripts/sanitize_review.py` | Low | Duplicated regex fragment | Extracted balanced-parenthesis regex to `PARENS_REGEX` constant | ✅ Fixed |
| 128 | `.github/scripts/post_comment.sh` | Low | Disjointed comment numbering | Re-numbered steps chronologically and merged related comments | ✅ Fixed |
| 130 | `.github/scripts/sanitize_review.py` | Low | `sanitize()` function has zero test coverage | Added 4 `tempfile` round-trip unit tests in `test_sanitize_review.py` | ✅ Fixed |
| 131 | `.github/scripts/post_comment.sh` | Low | `cmark` failure emits no `::error::` diagnostic | Added explicit `\|\| { echo "::error::..." >&2; exit 1; }` trap on `cmark` | ✅ Fixed |
| 132 | `.github/scripts/post_comment.sh` | Low | `stripped_file` emptiness not checked before `cmark` | Added `[ ! -s "$stripped_file" ]` guard to localize failure to the stripping stage | ✅ Fixed |
| 133 | `.github/scripts/sanitize_review.py` | Medium | `www.`-prefixed bare URLs bypass GFM defanging | Extended step 5 regex to also match `www\.` bare domains; `www.evil.com` → `www[.]evil.com` | ✅ Fixed |
| 134 | `.github/scripts/sanitize_review.py` | Medium | Inline link regex `[^\]]*` breaks on `]` in link text | Added `LINK_TEXT_REGEX` constant allowing one level of nested brackets | ✅ Fixed |
| 135 | `.github/scripts/sanitize_review.py` | Medium | Email autolinks `<user@host>` not stripped | Added email autolink stripping in step 4; renders as `[EMAIL STRIPPED]` | ✅ Fixed |
| 136 | `.github/scripts/test_sanitize_review.py` | Low | Temp file cleanup not panic-safe | Replaced bare `try/finally` with `@contextlib.contextmanager _tmpfiles()` helper | ✅ Fixed |
| 137 | `.github/scripts/sanitize_review.py` | Low | IPv6 literal bare URL defanging has no test coverage | Added doctest for `http://[::1]:8080/path` | ✅ Fixed |
| 139 | `.github/scripts/sanitize_review.py` | Low | `_defang` named inner function reintroduced | Inlined as lambda per Finding 122 guidance | ✅ Fixed |
| 140 | `.github/scripts/post_comment.sh` | Low | Missing `\|\|` error trap on Python subprocess | Added `\|\| { echo "::error::..." >&2; exit 1; }` trap | ✅ Fixed |
| 141 | `.github/workflows/ci.yml` | Low | `black . --check` scoped too broadly | Scoped to `.github/scripts/` only | ✅ Fixed |
| 142 | `.github/scripts/test_sanitize_review.py` | Low | `test_sanitize_utf8_boundary` off-by-one — truncation path never exercised | Added extra bytes so `file_size > MAX_REVIEW_BYTES` is True | ✅ Fixed |
| 143 | `.github/scripts/sanitize_review.py` | High | `LINK_TEXT_REGEX` depth-1 allows 2+ nested bracket bypass | Expanded to 3-level depth via build loop; `[a [b [c]]](url)` now stripped | ✅ Fixed |
| 144 | `.github/scripts/test_sanitize_review.py` | Low | Tautological assertion `e.code == 1 or e.code is not None` | Replaced with strict `assert e.code == 1` | ✅ Fixed |
| 145 | `.github/scripts/sanitize_review.py` | Low | Indented reference definitions bypass step 3 | Added `[ \t]*` leading whitespace to ref definition regex | ✅ Fixed |
| 146 | `.github/scripts/post_comment.sh` | Low | Cleanup trap runs `rm -f "" ""` on early exit | Added `[ -n ... ] && rm -f` guards per variable | ✅ Fixed |
| 147 | `.github/workflows/post_review.yml` | Low | Missing security comment on `workflow_run` checkout | Added `# SECURITY:` block warning against adding `ref: head_sha` | ✅ Fixed |
| 148 | `.github/scripts/test_sanitize_review.py` | Low | Truncation test missing prefix content integrity assertion | Added `assert result.startswith(known_prefix)` | ✅ Fixed |
| 149 | `.github/scripts/test_sanitize_review.py` | Low | No test for entirely-stripped input | Added `test_sanitize_all_links_stripped` | ✅ Fixed |
| 150 | `.github/scripts/test_sanitize_review.py` | Low | `/tmp/out.md` hardcoded outside `_tmpfiles()` in missing-input test | Test now uses `_tmpfiles()` for both paths | ✅ Fixed |
| 153 | `.github/scripts/sanitize_review.py` | Medium | `@mention` injection bypasses sanitization, enabling notification spam | Added step 6 to defang `@username` and `@org/team` to `@[username]` | ✅ Fixed |
| 154 | `.github/workflows/ci.yml` | Low | `black` formatting check is over-engineered for a single file | Replaced `black` with built-in `python3 -m py_compile` syntax check | ✅ Fixed |
| 155 | `.github/workflows/ci.yml` | Low | ShellCheck `ignore_paths` is dead configuration | Removed unused `ignore_paths` setting | ✅ Fixed |
| 156 | `.github/scripts/post_comment.sh` | Low | Redundant `|| true` on cleanup trap `rm -f` | Removed dead `|| true` | ✅ Fixed |
| 157 | `.github/scripts/test_sanitize_review.py` | Low | Missing test for reference-definitions-only input | Added `test_sanitize_reference_definitions_only` | ✅ Fixed |
| 158 | `.github/scripts/test_sanitize_review.py` | Low | `.strip()` in assertion hides whitespace differences | Dropped `.strip()` from assertion | ✅ Fixed |
| 159 | `.github/scripts/post_comment.sh` | Low | Missing `REPO_NAME` emptiness guard | Added `[ -z "$REPO_NAME" ]` guard before API call | ✅ Fixed |
| 160 | `.github/scripts/post_comment.sh` | Low | Missing `HEAD_SHA` format validation | Added regex validation `^[0-9a-f]{40}$` before API call | ✅ Fixed |
| 162 | `.github/scripts/post_comment.sh` | High | `GH_TOKEN` exposed to `cmark` C binary when processing untrusted input | Added `env -u GH_TOKEN` before `cmark` execution | ✅ Fixed |
| 163 | `.github/scripts/sanitize_review.py` | Low | Bare URL defang regex greedily captures trailing punctuation | Updated bare URL regex to trim GFM trailing punctuation | ✅ Fixed |
| 164 | `.github/scripts/test_sanitize_review.py` | Low | Missing test for zero-byte input file | Added `test_sanitize_empty_input` | ✅ Fixed |
| 50 | `README.md`:465 | Medium | `sensitive_file_access_allowlist` example is dangerous and non-functional | Changed to prefix matching | ✅ Fixed |
| 169 | `.githooks/pre-commit`:20 | High | Pre-commit `curl \| sh` without integrity verification | Removed auto-install in favor of fail-closed checks | ✅ Fixed |
| 165 | `.githooks/pre-commit`:29 | Medium | `go install ...@latest` unpinned tool version | Removed auto-install in favor of fail-closed checks | ✅ Fixed |
| 166 | `.githooks/pre-commit`:25 | Low | `sudo apt-get` in pre-commit hook without user warning | Removed auto-install in favor of fail-closed checks | ✅ Fixed |
| 167 | `.githooks/pre-commit`:29 | Low | `go install` without Go prerequisite check | Removed auto-install in favor of fail-closed checks | ✅ Fixed |
| 168 | `ARCHITECTURE.md`:116 | Medium | "Context Contradiction" accepted risk understates AI tampering detectability gap | Updated ARCHITECTURE.md | ✅ Fixed |
| 222 | `ARCHITECTURE.md`:116 | Medium | `_DETAILED.md` excluded from context contradiction | Added to exclusions | ✅ Fixed |
| 223 | `ARCHITECTURE.md`:120 | Low | `process_vm_writev` claim overstates memory protection | Clarified open vectors | ✅ Fixed |
| 224 | `FIXED_FINDINGS.md` | Low | New fixed findings reference stale pre-commit line numbers | Removed bare line numbers for legacy code | ✅ Fixed |




---
## Cross-Finding Chains (Architectural Context)

The following chains document how independent bugs created compounded attack surfaces. Preserved here as critical threat modeling context:
- **Chain 1:** To Do #4 → Starting Code #1 (Missing capability check allowed empty traces to fail open).
- **Chain 2:** Enforce fail-closed behavior and PEP508 handling #6 → Allow only supported package manager #7 (Unrecognized managers bypassed the sandbox entirely, while malformed package names crashed the parser).
- **Chain 3:** Add CI pipeline #11 → Route lock commands to scanner and add tests #12 (Lockfile execution lacked sandbox tracing, requiring a new CI pipeline approach to detect regressions).
- **Chain 4:** Add post-install artifact scan #17 → Add EnvVarGuard and refactor run with bulk_scan #16 → Doco update #18 (Artifact scan introduced locking issues, prompting the RAII EnvVarGuard refactor to ensure panic-safety).


*For detailed root causes, failure scenarios, and review history, see [FIXED_FINDINGS_DETAILED.md](./FIXED_FINDINGS_DETAILED.md).*
