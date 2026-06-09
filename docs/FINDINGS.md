# Security & Correctness Findings

Reviewed: 2026-06-09  
Scope: `src/lib.rs`, `src/scanning.rs`, `src/parsing.rs`, `src/sandbox.rs`  
Method: 7-angle static review (line-by-line, removed-behavior, cross-file, reuse, simplification, efficiency, altitude) + 1-vote verification

---

## Verification (2026-06-09, re-reviewed against HEAD `7a6d073`)

**Verdict: all 8 findings are accurate.** Each points to real code at the cited line number, and the described mechanism matches what the code does. Every finding was re-traced against current source, including the chained behavioral claims (not just the cited line).

| # | Cited location | Verified | Notes |
|---|----------------|----------|-------|
| 1 | `sandbox.rs:188` | ✅ | `unwrap_or_else(...).unwrap_or_default()` returns `""` on double failure; empty-vs-empty diff in `scan_packages_versions` falls through to `allowed: true`. The recommended `Err(...)` batch-block path exists (scanning.rs:884–893). |
| 2 | `scanning.rs:199` | ✅ | Allowlist match (line 203) runs on `resolver(&ip)` = PTR record via `reverse_dns_domain`→`lookup_addr` (line 213), with no forward-confirmation. Attacker-controlled. |
| 3 | `scanning.rs:427` | ✅ | Regex is exactly `\[(?P<argv>[^\]]*)\]` — stops at first `]`. |
| 4 | `sandbox.rs:307` | ✅ | `"{} >/dev/null 2>&1 \|\| true"` wraps the whole strace command. Root cause of #1. |
| 5 | `parsing.rs:113` | ✅ | `if !*local_source && !(directory_local && *develop)` — non-develop local-path packages leak through. |
| 6 | `parsing.rs:298` | ✅ | `base.split_once("==")` keeps extras in `name`. See caveat below. |
| 7 | `parsing.rs:576` | ✅ | Strips extras for the `pins` lookup but the map is keyed by full name → miss → unpinned forward. |
| 8 | `lib.rs:536` | ✅ | `let _ = child.wait();` discards the child exit status. |

**Caveats (do not change the verdict):**
- **Finding 6** — the closing claim that the empty baseline causes *every* connection to be flagged as new is slightly too strong. With zero baselines, the new-package-exemption / `<2 baselines` logic (scanning.rs:948–957) can instead produce a **silent skip-and-allow** for an unexempted package, rather than a false-positive block. The 404→zero-baseline mechanism is correct; the precise downstream outcome (block vs. silent allow) depends on the exemption path — which is arguably worse than the document states.
- **Findings 1 and 4** are effectively one bug (effect + root cause); the doc's own "Chains" section already notes this. Fine to list separately, but they should be fixed together.
- Severities are reasonable editorial judgments.

---

## How to read this document

Each finding has:
- **Location** — file and line number
- **Severity** — Critical / High / Medium
- **Summary** — one sentence describing the defect
- **Root cause** — what the code does wrong
- **Failure scenario** — concrete inputs/state that trigger the bug and the resulting wrong behavior
- **Fix direction** — suggested remediation

---

## Finding 1 — Critical | `sandbox.rs:188`

**Summary:** Missing trace log silently falls back to an empty string, which the scanner treats as a clean zero-connection trace, allowing the package.

**Root cause:** `trace_install_docker_matrix_with_runtime` reads each per-probe log file with:
```rust
std::fs::read_to_string(&trace_path).unwrap_or_else(|_| {
    trace_install_docker_single_with_runtime(...)
        .unwrap_or_default()
})
```
If the log file is absent (strace failed to write it) and the single-probe fallback Docker call also fails, `unwrap_or_default()` returns `""`. An empty string produces empty `TraceSignals` (no IPs, no git-clone signatures, no process-exec signatures). The diff of empty-vs-empty produces zero anomalies, so `allowed: true` is returned with no actual tracing data.

**Failure scenario:** In a Kubernetes environment where the container seccomp profile blocks `ptrace` (the default in most managed K8s clusters), strace exits non-zero and writes nothing to `/out/gyrseek_trace_N.log`. The fallback single-probe container runs the same image under the same restriction and also produces no trace. `unwrap_or_default()` returns `""`. Every package scanned in that environment silently passes.

**Chained with:** Finding 4 (the `|| true` in the matrix script is the direct cause of the log file being absent with no error surfaced).

**Fix direction:** If both the matrix log read and the single-probe fallback fail, return `Err(...)` from `trace_install_docker_matrix_with_runtime` rather than returning an empty string. The error path in `scan_packages_versions` already handles `Err` from the tracer by marking all packages in the batch as blocked — use it.

---

## Finding 2 — Critical | `scanning.rs:199`

**Summary:** The domain allowlist is checked against the attacker-controlled PTR record of the connecting IP, allowing a C2 server to bypass the allowlist by setting its reverse-DNS to an allowlisted domain.

**Root cause:** `filter_domain_allowlisted_new_connections_with` calls the user-supplied `resolver` (which in production is `reverse_dns_domain` → `lookup_addr`) on each new IP to get a hostname, then checks that hostname against `domain_allowlist`. PTR records are controlled by whoever owns the IP address — an attacker who controls their C2 server controls its PTR record.

```rust
match resolver(&ip) {
    Some(domain) if domain_is_allowlisted(&domain, domain_allowlist) => {
        allowlisted.push(...)   // connection silently passes
    }
    _ => remaining.push(ip),
}
```

**Failure scenario:** Organization sets `domain_allowlist: ['cdn.example.com']`. Attacker registers C2 IP `1.2.3.4` and sets its PTR record to `cdn.example.com`. During install, the malicious package connects to `1.2.3.4`. `reverse_dns_domain("1.2.3.4")` returns `"cdn.example.com"`. `domain_is_allowlisted` returns `true`. The connection is allowlisted and not flagged.

**Fix direction:** Domain allowlisting should check forward-confirmed reverse DNS: resolve the PTR record and then verify the resulting hostname resolves back to the original IP (FCrDNS). Alternatively, document clearly that `domain_allowlist` provides no security guarantee against IP-allowlist bypass and should only be used for convenience in low-trust scenarios.

---

## Finding 3 — High | `scanning.rs:427`

**Summary:** The execve argv regex `[^\]]*` stops at the first `]` in any argument, silently truncating arguments that contain `]` — such as package extras or bracket-containing paths.

**Root cause:** The regex for capturing execve argv is:
```rust
Regex::new(r#"execve\([^,]+,\s*\[(?P<argv>[^\]]*)\]"#)
```
The `[^\]]*` character class matches any character except `]`. strace output for `execve("/bin/pip", ["pip", "install", "requests[security]"], ...)` has `requests[security]` inside the argv brackets. The `]` in `security]` terminates the `argv` capture group early, so the captured argv is `"pip", "install", "requests[security` — a malformed string where the last argument is incomplete and un-closeable by the quoted-arg extractor.

**Failure scenario (false positive):** A package whose install runs `git clone https://host/path[mirror]` has its clone URL truncated. The extracted signature `https://host/path[mirror` never matches any `git_clone_allowlist` entry → false-positive block.

**Failure scenario (bypass):** A package runs `bun run script[obf].js`. The truncated signature is `bun|run|script[obf` instead of `bun|run|script[obf].js`. If an operator tries to add the actual signature to `process_exec_allowlist`, it will never match because the stored signature is already truncated. Conversely, if the baseline version also runs the same bun invocation, both current and baseline produce the same truncated signature → no anomaly → bypass.

**Fix direction:** Change the argv group to a non-greedy match or to a balanced-bracket-aware approach. The simplest fix is to match the full `[...]` content including nested brackets: replace `[^\]]*` with `[^\[]*(?:\[[^\]]*\][^\[]*)*` — or use a different parsing strategy (split the full strace line, then parse quoted strings from within the bracket region without relying on a single character exclusion).

---

## Finding 4 — High | `sandbox.rs:307`

**Summary:** The matrix script appends `>/dev/null 2>&1 || true` to each strace invocation, suppressing strace's own stderr and exit code, so ptrace capability failures produce an empty log file with no diagnostic output.

**Root cause:** In `build_matrix_script`:
```rust
steps.push(format!(
    "{} >/dev/null 2>&1 || true",
    strace_install_command(manager, &spec, Some(&log))
));
```
`strace_install_command` already redirects its output to a log file via `-o /out/gyrseek_trace_N.log`. The additional `>/dev/null 2>&1` redirects strace's own stderr (error messages) to null, and `|| true` overrides its exit code. When strace cannot attach (`PTRACE_ATTACH` denied), it writes an error to stderr and exits non-zero — both are now invisible. The Docker container exits 0. No log file is written. The caller has no way to distinguish this from a successful but connection-free install.

**Failure scenario:** Direct cause of Finding 1. Any environment blocking ptrace (K8s default seccomp, rootless Docker, GitHub Actions without special capabilities) will have every scan pass silently.

**Fix direction:** Remove `>/dev/null 2>&1` from the strace step specifically. Redirect only the install's own stdout/stderr (`>/dev/null 2>&1` should wrap only the install invocation, not the strace wrapper). Propagate strace exit non-zero as a hard failure in the matrix script (let `set -e` catch it rather than using `|| true` around the strace command).

---

## Finding 5 — High | `parsing.rs:113`

**Summary:** The poetry lock parser's local-package filter only excludes `develop=true` directory-source entries; non-develop local-path packages pass through and are submitted to the registry scanner as if they were public packages.

**Root cause:** The exclusion condition in `finalize_package` is:
```rust
if !*local_source && !(directory_local && *develop) {
    packages.push((n, v));
}
```
`directory_local` is `true` when the package source is `type = "directory"` with a local URL or path. But the exclusion fires only when `directory_local && develop` — i.e., both conditions must be true. A non-develop local directory package has `develop=false`, so `directory_local && develop = false`, and `!(false) = true`, so the package is pushed.

**Failure scenario:** A `poetry.lock` entry has:
```toml
[package.source]
type = "directory"
url = "../mylib"
```
with no `develop` key (defaults to `false`). `local_source=false` (the inline single-line heuristic did not fire), `directory_local=true`, `develop=false`. Condition evaluates to `true` → package name `mylib` is submitted to PyPI scanner. If a public package named `mylib` exists, it gets scanned and approved. The actual install uses the local path, so the approval is meaningless — a compromised local package bypasses behavioral detection.

**Fix direction:** Change the condition to exclude any local-source package regardless of `develop` flag: `if !*local_source && !directory_local`. The `develop` flag is a poetry concept for editable installs; all local directory sources should be excluded from registry scanning.

---

## Finding 6 — Medium | `parsing.rs:298`

**Summary:** PEP 508 extras (e.g., `requests[security]`) are preserved in the package name after `split_once("==")`, causing the PyPI registry lookup to receive an invalid URL that returns 404 and leaves the package with zero baselines.

**Root cause:** `parse_requirements_spec` splits on `==` to extract name and version:
```rust
if let Some((name, version)) = base.split_once("==") {
    return Some((name.to_string(), Some(version.to_string())));
}
```
For `requests[security]==2.31.0`, `name = "requests[security]"`. This is passed to `fetch_history_with_baselines`, which builds `https://pypi.org/pypi/requests[security]/json` — PyPI does not accept extras in the package path and returns 404. The function falls back to `(tgt_version, [], 0, None)`: zero baselines, zero burst count, no release-age data. With zero baselines and the package not in `new_package_exemptions`, the scan runs against an empty baseline — any connection (including to pypi.org itself) is flagged as new, producing a false-positive block.

**Failure scenario:** A `requirements.txt` with `requests[security]==2.31.0` causes every scan to block on the spurious "new connection to pypi.org" anomaly, since the empty baseline means there is no known-good network traffic to compare against.

**Chained with:** Finding 7 — the extras mismatch also breaks version pinning.

**Fix direction:** Strip extras before registry lookups. Extract extras separately: `let (base_name, _extras) = name.split_once('[').unzip_or((name, ""))`. Use `base_name` for PyPI/npm lookups while keeping the original full spec for sandbox invocations (where extras are valid PEP 508).

---

## Finding 7 — Medium | `parsing.rs:576`

**Summary:** `rewrite_args_with_pinned_versions` strips extras before looking up the package in the `pins` map, but `pins` is keyed by the full name including extras, so the lookup always misses and the version is forwarded unpinned.

**Root cause:** The `pins` map is built by `scan_many_with_cache` using the package name as returned by the parser — `requests[security]` for an extras-qualified requirement. `rewrite_args_with_pinned_versions` does:
```rust
let base_name = arg.split('[').next().unwrap_or(arg);
if let Some(version) = pins.get(base_name) { ... }
```
`pins.get("requests")` returns `None` because the key is `"requests[security]"`. The argument is forwarded as the original unpinned spec, re-opening the time-of-check/time-of-use gap the pinning was designed to close.

**Failure scenario:** `pip install requests[security]` is scanned at version `2.31.0`. A new version `2.32.0` containing a backdoor is published between the scan and the forwarded install. The forwarded command is `pip install requests[security]` (unpinned). pip resolves `2.32.0` and installs it. gyrseek exits 0.

**Fix direction:** Normalize package names consistently throughout the pipeline. Either: (a) strip extras at parse time and pass only the canonical name as the `pins` key, or (b) in `rewrite_args_with_pinned_versions`, try both `base_name` and the full name when looking up `pins`.

---

## Finding 8 — Medium | `lib.rs:536`

**Summary:** The child process exit status is discarded. If the host package manager exits non-zero, gyrseek exits 0, misreporting a failed install as successful.

**Root cause:** `forward_args` spawns the child and calls `wait()` but discards the result:
```rust
Ok(mut child) => {
    let _ = child.wait();
}
```

**Failure scenario:** An AI coding agent runs `gyrseek npm install nonexistent-package@99.0.0`. Gyrseek scans, finds it clean, forwards to npm. npm exits 1 (version not found). The `ExitStatus` is dropped. Gyrseek exits 0. The agent interprets this as a successful install and continues, producing broken builds or runtime failures attributed to unrelated code. Any CI pipeline that checks `$?` after a gyrseek-wrapped install will be misled.

**Fix direction:**
```rust
Ok(mut child) => {
    if let Ok(status) = child.wait() {
        if !status.success() {
            std::process::exit(status.code().unwrap_or(1));
        }
    }
}
```

---

## Summary Table

| # | File | Line | Severity | One-line description |
|---|------|------|----------|----------------------|
| 1 | `sandbox.rs` | 188 | Critical | Empty trace on strace failure passes as clean scan |
| 2 | `scanning.rs` | 199 | Critical | PTR-record domain allowlist bypassable by attacker |
| 3 | `scanning.rs` | 427 | High | Argv regex `[^\]]*` truncates at first `]` in any argument |
| 4 | `sandbox.rs` | 307 | High | `\|\| true` suppresses strace failures — root cause of #1 |
| 5 | `parsing.rs` | 113 | High | Poetry non-develop local-path packages leak through filter |
| 6 | `parsing.rs` | 298 | Medium | PEP 508 extras in package name cause PyPI 404 → zero baselines |
| 7 | `parsing.rs` | 576 | Medium | Extras key mismatch breaks version pinning in forwarded command |
| 8 | `lib.rs` | 536 | Medium | Child process exit status discarded — failed installs exit 0 |

**Chains:**
- #4 → #1: strace errors suppressed → empty log file → empty trace → bypass
- #6 → #7: extras break PyPI lookup AND break version pinning for the same package
