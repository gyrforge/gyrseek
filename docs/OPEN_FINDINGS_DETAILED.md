# Open Findings - Detailed

*This document contains the detailed root-cause analyses for open findings. For the brief overview, see [OPEN_FINDINGS.md](./OPEN_FINDINGS.md).*

## Detailed Findings

### Finding 22 — Medium | `scanning.rs:188` | ⚠️ Open

**Summary:** `is_sandbox_local_ip` filters IPv6 loopback and link-local (`fe80::/10`) but does not filter Unique Local Addresses (`fc00::/7`), the IPv6 equivalent of RFC 1918 private ranges. Internal container traffic over IPv6 ULAs is flagged as external exfiltration.

**Root cause:** The IPv6 branch at `scanning.rs:188–192`:
```rust
IpAddr::V6(v6) => {
    let is_link_local = (v6.segments()[0] & 0xffc0) == 0xfe80;
    v6.is_loopback() || is_link_local
}
```
`fc00::/7` (ULA) is not checked. An IPv6-capable Docker daemon on a ULA-enabled network assigns container addresses from the `fd00::/8` space. Connections to these peers pass through as "new endpoints".

**Failure scenario:** A package install contacts a local registry or caching proxy at `fd12:3456::1`. This is sandbox-internal traffic. `is_sandbox_local_ip` returns `false` → `find_new_connections_domain_aware` flags it → `warn_and_block` fires → install blocked. The operator sees an exfiltration alarm for a local proxy.

**Fix direction:** Add `v6.is_unicast_link_local()` (stabilised in Rust 1.80) or manually check `(v6.segments()[0] & 0xfe00) == 0xfc00` for ULA. The IPv6 branch becomes:
```rust
let is_ula = (v6.segments()[0] & 0xfe00) == 0xfc00;
v6.is_loopback() || is_link_local || is_ula
```

---

### Finding 25 — High | `README.md:363` / `sandbox.rs` | ⚠️ Open

**Summary:** gyrseek's sandbox only monitors behavior during `pip install`. A Python package that places malicious code at module scope (e.g. Telnyx T26's `_client.py` with `FetchAudio()` / `setup()` calls) executes entirely on `import <pkg>` — after the sandbox exits — and is never observed.

**Root cause:** The containerized scan pipeline (`sandbox.rs:build_matrix_script`) runs only the install command and the post-install artifact `find` pipeline. There is no post-install import trigger step that forces Python to load the installed package while strace is still attached. Module-scope code in `__init__.py` or deeply nested SDK files fires outside the sandbox window.

**Failure scenario:** `gyrseek pip install telnyx==2.0.0` installs normally inside the sandbox. The malicious `_client.py` sits dormant during install. gyrseek reports a clear scan (no anomalous execve, no anomalous network, no artifact findings — the code is in a legitimate `.py` file, not a `.pth` or binary). The host command is forwarded. On the developer's machine, `import telnyx` triggers credential exfiltration via AES-256-CBC + RSA-4096 to `83.142.209.203:8080`.

**Fix direction:** Add a post-install import trigger step for Python managers. After the install probe completes, run:
```sh
su -s /bin/sh gyrseek -c "python3 -c 'import $(basename $pkg)'"
```
inside the same container with strace still attached. Any execve or connect that fires during import is captured by the existing trace pipeline and diffed against baselines. The package name-to-top-level-module mapping (handling namespace packages, dashes-to-underscores, etc.) must be resolved accurately to avoid false negatives or false-positive import errors.

---

### Finding 26 — Medium | `lib.rs:588` | ⚠️ Open

**Summary:** The forwarding code in `GyrSeek::forward_args` uses `Command::new(&self.manager)` with no PATH validation, making it vulnerable to relative-path hijacking when run inside an untrusted directory containing a malicious `./pip` or `./npm` script.

**Root cause:** At `lib.rs:588`:
```rust
match Command::new(&self.manager).args(&args[1..]).spawn() {
```
`Command::new` resolves `self.manager` (e.g. `"pip"`) against the current `PATH`. If the working directory or a parent directory has a `./pip` script (placed there by a previous malicious package or a repo checkout), the spawned subprocess runs the attacker's binary instead of the system package manager.

**Failure scenario:** A CI pipeline runs `gyrseek pip install requests` in a repository where a malicious contributor committed `./pip` as a shell script exfiltrating CI credentials. `Command::new("pip")` resolves to `./pip` before `/usr/bin/pip` (since `.` is typically first in CI $PATH or the file is in the cwd). The attacker's script runs with full CI access.

**Fix direction:** Resolve the manager binary path to an absolute canonical path before spawning:
```rust
use std::process::Command;

fn resolve_manager_path(manager: &str) -> Option<String> {
    Command::new("which")
        .arg(manager)
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout).ok().map(|s| s.trim().to_string())
            } else {
                None
            }
        })
}
```
Then verify the resolved path starts with a trusted prefix (`/usr/bin/`, `/usr/local/bin/`) before passing to `Command::new`. Under host mode (`GYRSEEK_SANDBOX=host`), additionally validate that PATH contains no writable entries (`.` or world-writable dirs) before forwarding.

---

### Finding 27 — Low | `lib.rs:64` | ⚠️ Open

**Summary:** `parse_global_options` accepts any string as the value for `--config`/`-c` without validation. If a user accidentally types a flag-like value (e.g. `--config --version`), the parser swallows `--version` as the config path and the intended flag is silently ignored.

**Root cause:** At `lib.rs:72–77`:
```rust
if arg == "--config" || arg == "-c" {
    let Some(next) = args.get(idx + 1) else {
        return Err("Missing value for --config/-c".to_string());
    };
    cfg_path = next.clone();
```
There is no check that `next` is a plausible file path (not starting with `-`, not empty).

**Failure scenario:** User types `gyrseek --config --version`. The parser sets `cfg_path = "--version"`, continues past the loop with no `break`. The remaining args are `["--version"]`. Since `--version` is handled as a leading top-level flag before config load, the user gets the version output — but `cfg_path` is `"--version"`, and subsequent `load_policy_config("--version")` is called. If `"--version"` happens to exist as a file, it is read as the YAML config (producing an empty/partial config). If it does not exist, `fs::read_to_string` errors and gyrseek exits with a confusing "Config file not found: --version" message.

**Fix direction:** Add a simple guard:
```rust
let Some(next) = args.get(idx + 1) else {
    return Err("Missing value for --config/-c".to_string());
};
if next.starts_with('-') {
    return Err(format!("Invalid value for --config/-c: '{}' looks like a flag", next));
}
```
---

### Finding 28 — High | `scanning.rs` | ⚠️ Open

**Summary:** Baseline Poisoning: A package can deliberately read a sensitive file (e.g. `/etc/passwd`) benignly in an early version to populate the baseline, and then read it maliciously in a later version without triggering the anomaly detector.

**Root cause:** The sensitive file access diffing relies on a simple set difference between current and baseline reads.

**Failure scenario:** Because `strace` post-processing cannot reliably trace every `open()` to a specific process tree without risk of spoofing, this evasion technique works.

**Fix direction:** Currently an accepted architectural limitation, but marked as open to track potential future process-tree tracking via eBPF.

---

### Finding 35 — High | `scanning.rs` | ⚠️ Open

**Summary:** `close` and `execve` omitted from strace and `fd_table`.

**Root cause:** The `fd_table` is never cleared when file descriptors are closed or upon `execve`.

**Failure scenario:** Leads to stale paths in the fd_table. Reusing a file descriptor number for a benign file could falsely trigger a sensitive file read alarm, or conversely mask malicious intent.

**Fix direction:** Trace `close` and `execve` to properly evict `fd_table` state.

---

### Finding 36 — High | `scanning.rs` | ⚠️ Open

**Summary:** `F_DUPFD` numeric check missing; `F_DUPFD_CLOEXEC` ignored.

**Root cause:** `args_str.contains("F_DUPFD")` relies on strace's symbolic representation. A numeric `0` or `1030` goes untracked.

**Failure scenario:** Duplicating a file descriptor using numeric flags evades fd-tracking, allowing an attacker to read a sensitive file via the untracked duplicated fd.

**Fix direction:** Parse the numeric argument or expand symbolic coverage to `F_DUPFD_CLOEXEC`.

---

### Finding 37 — Medium | `scanning.rs` | ⚠️ Open

**Summary:** `is_harness_command` `env` delegation footgun.

**Root cause:** No recursion depth limit when parsing `env` wrapper arguments.

**Failure scenario:** If an argument happens to be `env` without an `=`, it could cause infinite recursion.

**Fix direction:** Add a depth guard or assert `inner_exe != "env"`.

---

### Finding 38 — Medium | `scanning.rs` | ⚠️ Open

**Summary:** `*` prefix allowlist warns but silently blocks everything.

**Root cause:** When a user adds `*` to the allowlist, `filter_allowlisted_sensitive_reads` prints a warning but then evaluates and returns `false` (meaning NOT allowlisted).

**Failure scenario:** A user attempting to allowlist everything with `*` receives a warning (easily lost in CI noise) but the function silently blocks access, acting in complete opposition to user intent.

**Fix direction:** Implement correct glob semantics. Either explicitly handle `*` to return `true` after the warning, or fail fast with a clear configuration error.

---

### Finding 39 — Medium | `scanning.rs` | ⚠️ Open

**Summary:** `.env` variant blind spot and symlink evasion.

**Root cause:** Hardcoded `/.env` and `.env` misses `.env.production`, `.env.local`, etc.

**Failure scenario:** Exfiltration of production secrets stored in `.env.production` goes undetected.

**Fix direction:** Broaden the `.env` match to include common suffixes.

**Enhancements:**
- **Variant Paths & Symlinks:** The finite hardcoded sensitive path set allows evasion by variant paths (e.g. `~/.config/aws/credentials` vs `~/.aws/credentials`, `/var/run/secrets/*` vs `/.docker/config.json`) and symlink traversal. An attacker opening a symlink pointing to `/etc/shadow` will log the symlink path in `strace`, evading the exact-match filter. Fix: add `realpath`/`canonicalize` resolution before `is_sensitive_file_read` and drastically expand the variant path list.

---

### Finding 42 — Low | `scanning.rs` | ⚠️ Open

**Summary:** Test duplication across anomaly-counting tests.

**Root cause:** Four near-identical tests (`test_multiple_anomalies_evaluate_completely`, `test_two_anomalies_evaluate_completely`, etc.) differ only in injected trace count.

**Failure scenario:** Increased maintenance burden when updating test setups.

**Fix direction:** Parameterize these tests using a helper loop.

---

### Finding 43 — Low | `scanning.rs` | ⚠️ Open

**Summary:** `lexical_clean_path` reinvents stdlib path normalization.

**Root cause:** Duplicates `std::path::Component` logic.

**Failure scenario:** Potential edge-case bugs in path normalization that the standard library already handles correctly.

**Fix direction:** Refactor to use `Path::new(path).components().collect::<PathBuf>()`.

---

### Finding 44 — Low | `scanning.rs` | ⚠️ Open

**Summary:** Test coverage regression: `unescape_trailing_backslash`.

**Root cause:** The test `assert_eq!(unescape_strace_string("ab\\"), b"ab")` was changed, leaving the trailing backslash edge case untested.

**Failure scenario:** In strace `-xx` output, a lone `\` at the end can occur mid-escape, potentially crashing the parser if unhandled.

**Fix direction:** Restore the trailing backslash test case.

---

### Finding 46 — Medium | `scanning.rs` | ⚠️ Open

**Summary:** `is_harness_command` `uv` check coupling with sandbox script.

**Root cause:** `is_harness_command` requires `--target` for the `uv` arm to correctly exclude legitimate harness commands. If `sandbox.rs` changes to use `--prefix` or similar, detection silently breaks.

**Failure scenario:** Every legitimate `uv` probe appears as a new process-exec anomaly due to out-of-sync coupling.

**Fix direction:** Add a doc comment in both locations explicitly documenting the coupling.

---

### Finding 47 — Medium | `scanning.rs` | ⚠️ Open

**Summary:** `extract_sensitive_file_reads` requires decomposition.

**Root cause:** The function is very long and conflates `fd_table` construction, `/proc/N/fd/M` resolution, clone/fork fd inheritance, dup/fcntl tracking, and sensitivity classification. The clone/fork fd-inheritance block in the resumed-syscall handler and the initial-syscall handler is duplicated verbatim — see also Finding 67.

**Failure scenario:** Increased maintenance burden, higher risk of introducing logic bugs, and poor testability.

**Fix direction:** Extract helper functions like `build_fd_table` and `resolve_proc_fd_path`. Start by extracting the shared clone/fork inheritance logic (Finding 67) as `fn inherit_fds(child_pid, parent_pid, fd_table)`.

---

### Finding 53 — Medium | `scanning.rs` | ⚠️ Open

**Summary:** `clone3` return value ambiguity for TID vs PID.

**Root cause:** `clone3` child return values in strace may represent a TID, but the code casts `ret_val as u32` as the child PID for `fd_table` insertion.

**Failure scenario:** In multithreaded installs, fd inheritance might be assigned to the wrong PID key in `fd_table`.

**Fix direction:** Cross-reference with `gettid` if thread-group leaders are ambiguous, or document the limitation.

---

### Finding 54 — Medium | `scanning.rs` | ⚠️ Open

**Summary:** DNS compression pointer 5-hop limit can force fail-to-plain fallback.

**Root cause:** The parser has a strict 5-hop limit for DNS compression pointers, while RFC 1035 theoretically supports many more.

**Failure scenario:** An attacker can craft a DNS response with 6+ hops, causing `decode_dns_name` to fail and forcing the system to fall back to plain IP tracking (disabling domain-aware CDNs).

**Fix direction:** Document the trade-off and consider raising the limit.

---

### Finding 55 — Low | `scanning.rs` | ⚠️ Open

**Summary:** `OnceLock` regex `.unwrap()` panics without context.

**Root cause:** Multiple regex initializations use `.unwrap()`.

**Failure scenario:** If a regex is accidentally broken in a future commit, the panic message gives no actionable context.

**Fix direction:** Replace with `.expect("LINE_RE pattern should be valid")`.

---

### Finding 56 — Low | `scanning.rs` | ⚠️ Open

**Summary:** `warn_and_block` `entry.allowed = false` is redundant.

**Root cause:** The `or_insert_with` closure already initializes the report with `allowed: false`.

**Failure scenario:** Dead code.

**Fix direction:** Delete the assignment.

---

### Finding 57 — Low | `scanning.rs` | ⚠️ Open

**Summary:** `_allowed_sensitive_reads` destructure is noise.

**Root cause:** `filter_allowlisted_sensitive_reads` returns a tuple but the second element is always immediately discarded.

**Failure scenario:** Unnecessary code verbosity.

**Fix direction:** Change the return type to `Vec<String>`.

---

### Finding 58 — Medium | `scanning.rs` | ⚠️ Open

**Summary:** `is_sensitive_file_read` overlapping lists create a maintenance trap.

**Root cause:** `ends_with_any` and `exact_match` share many duplicate entries (e.g. `.env`, `/etc/passwd`).

**Failure scenario:** Adding a new sensitive path to one array but forgetting the other creates a silent detection gap.

**Fix direction:** Define a single `SensitivePath` enum with `Suffix` and `Exact` variants and loop once.

---

### Finding 59 — Medium | `scanning.rs` | ⚠️ Open

**Summary:** Test traces do not exercise real strace `-xx` hex-escape path.

**Root cause:** Tests inject bare `/etc/passwd` strings via raw literals instead of properly hex-encoded representations like `\x2f\x65...`.

**Failure scenario:** The unescape hex decoder (`unescape_strace_string`) is technically untested end-to-end for real strace output, meaning parser regressions might slip through.

**Fix direction:** Replace the test strings with properly hex-escaped strings generated by strace `-xx`.

---

### Finding 61 — Medium | `sandbox.rs` | ⚠️ Open

**Summary:** Performance regression from expanded strace trace set.

**Root cause:** The `strace -e trace=` argument list grew from 2 families to 18 syscalls.

**Failure scenario:** The trace volume can be amplified 10-100x during heavily concurrent installs, significantly bogging down I/O and increasing analysis time.

**Fix direction:** Add a trace-line-count warning log, configure a line limit, or benchmark the overhead.

---

### Finding 62 — Low | `scanning.rs` | ⚠️ Open

**Summary:** `warn_and_block` unconditionally pushes without deduplication.

**Root cause:** Calling `warn_and_block` twice with the same key and warning type pushes duplicate entries into `blocked_reasons`.

**Failure scenario:** Accumulation of duplicate entries bloats the JSON output and CLI reports.

**Fix direction:** Deduplicate strings before pushing or change `blocked_reasons` to a `HashSet<String>`.

---

### Finding 63 — Low | `scanning.rs` | ⚠️ Open

**Summary:** `blocked_reasons` fragile string literal comparisons.

**Root cause:** `warning_type` is sometimes a static identifier and sometimes a dynamically generated phrase, which tests rely on for assertions.

**Failure scenario:** Trivial formatting changes to these strings will break multiple tests simultaneously.

**Fix direction:** Define a strongly-typed `BlockReason` enum instead of raw string comparisons.

---

### Finding 64 — Low | `scanning.rs` | ⚠️ Open

**Summary:** `extract_first_arg_fd` silently returns None on parse failure.

**Root cause:** If parsing an integer fails (e.g. encountering `AT_FDCWD` or an empty string), it silently returns `None`.

**Failure scenario:** It's impossible to distinguish between "there is no argument" and "the argument failed to parse", complicating debugging of unsupported syscall formats.

**Fix direction:** Emit a `debug!` or `warn!` level log when a non-empty string fails to parse.

---

### Finding 67 — Medium | `scanning.rs` | ⚠️ Open

**Summary:** Clone/fork fd-inheritance block duplicated verbatim.

**Root cause:** A 12-line fd-inheritance loop (`let mut to_insert = Vec::new(); for (&(p, fd), path) in &fd_table { … } for (c_pid, fd, path) in to_insert { … }`) appears identically in both the resumed-syscall handler and the initial-syscall handler of `extract_sensitive_file_reads`. See also Finding 47 which tracks the broader decomposition.

**Failure scenario:** Maintenance trap; updating one copy but not the other causes the two paths to drift out of sync.

**Fix direction:** Extract to `fn inherit_fds(child_pid: u32, pid: u32, fd_table: &mut HashMap<(u32, i32), String>)` and call it from both sites.

---

### Finding 82 — High | `sandbox.rs` | ⚠️ Open

**Summary:** `scanner_image_config` creates torn/stale reads of environment variables during concurrent test execution.

**Root cause:** `scanner_image_config` reads environment variables (like `GYRSEEK_NPM_SCANNER_IMAGE`, `GYRSEEK_PREBUILT_SCANNER_IMAGES`) via `std::env::var` on every call without synchronization. Tests execute concurrently under `#[tokio::test]` and mutate these variables using `EnvVarGuard`, producing torn or stale reads across threads.

**Failure scenario:** Test failures or unpredictable behavior in CI due to environment variable mutations bleeding into concurrently executing `sandbox.rs` logic.

**Fix direction:** Pass the configuration directly through the `SandboxRunner` or `PolicyConfig` rather than re-reading global environment variables on the fly.

---

### Finding 84 — High | `scanning.rs` | ⚠️ Open

**Summary:** Async cache race in baseline counting during concurrent `scan_with_cache` calls.

**Root cause:** Two concurrent `scan_with_cache` tasks processing the same package version can race on populating the async cache. This allows inconsistent evaluations of `baselines.len()` across threads, bypassing the intent of the `baseline_count` threshold. 

**Failure scenario:** One thread sees an empty cache and computes an incomplete baseline, allowing an anomalous package to pass the scan without raising the `insufficient_baselines` error.

**Fix direction:** Use a thread-safe caching mechanism (e.g., `moka::future::Cache` or an async `Mutex`/`RwLock` around the `HashMap`) and ensure cache population is an atomic future execution per package version.

---

### Finding 85 — Medium | `scanning.rs` | ⚠️ Open

**Summary:** Blocking DNS I/O inside async runtime causes Denial of Service (DoS) against tokio worker thread pool.

**Root cause:** `reverse_dns_domain` performs blocking DNS lookups (`lookup_addr`, `lookup_host`) from `std::net` inside the async function `find_new_connections_domain_aware`.

**Failure scenario:** A malicious package interacting with a custom registry or server that intentionally returns extremely slow-to-resolve IPs will cause the single-threaded (or limited-thread) tokio executor to block entirely, stalling all other concurrent tasks.

**Fix direction:** Replace `std::net` blocking lookup calls with async DNS resolution (e.g., via `tokio::net::lookup_host` or a crate like `trust-dns-resolver`/`hickory-resolver`).

---

### Finding 86 — Low | `scanning.rs` | ⚠️ Open

**Summary:** `scan_package_versions` fallback returns a generic `scan_failed` with zero diagnostics.

**Root cause:** When `scan_packages_versions` is called but the resulting `outcome` hashmap lacks the expected key, the fallback `unwrap_or_else(|| ScanReport { allowed: false, blocked_reasons: vec!["scan_failed"] })` fails closed without providing insight into why the package was missing.

**Failure scenario:** If an internal filtering mechanism silently drops a package, the user sees a generic `scan_failed` block reason without actionable telemetry.

**Fix direction:** Include a distinct diagnostic error message explaining why the package version was missing from the scan outcome, or use an `Result`/`Option` to explicitly surface parsing failures vs. silent omissions.

---

### Finding 29 — High | `scanning.rs` | ⚠️ Open

**Summary:** `/proc/self/fd/N` evasion and regex anchor bypass via relative paths.

**Root cause:** The `proc_fd_re` regex anchor `^/proc/` is bypassed by `../../proc/self/fd/N` relative paths entering via `open()` (no dirfd) or `openat(AT_FDCWD, ...)`. The relative path flows through `lexical_clean_path` and `is_sensitive_file_read` which tests `ends_with` — neither resolves against `/proc/`.

**Failure scenario:** An attacker opens `../../proc/self/fd/3` which bypasses both the `/proc/` regex anchor and the sensitive file string match.

**Fix direction:** Make `proc_fd_re` accept leading `../` components, or re-lex the path before checking.

---

### Finding 34 — High | `scanning.rs` | ⚠️ Open

**Summary:** Cross-PID `/proc/N/fd/` resolution bypass.

**Root cause:** `proc_fd_re` uses the strace line's PID to resolve the fd instead of the target PID in the `/proc/<pid>/fd/N` path.

**Failure scenario:** A process reading another process's sensitive file descriptor goes undetected because the scanner looks up the fd in the wrong process's table.

**Fix direction:** Extract the target PID from the path and use it for the fd_table lookup.

---

### Finding 40 — High | `scanning.rs` | ⚠️ Open

**Summary:** `/proc/self/fd/N` resolution regex requires absolute path, allowing traversal bypass.

**Root cause:** Regex `^/proc/(?:self|\d+)/fd/` fails on relative paths. The path is sent through `lexical_clean_path` which preserves relative structures like `../../proc`.

**Failure scenario:** An `open(\"../../proc/self/fd/3/passwd\")` never matches the regex anchor. The `is_sensitive_file_read` function fails to match it since it doesn't end with `/etc/passwd`. Additionally, this general lack of path canonicalization allows symlink bypasses: an attacker creates `ln -s /etc/passwd readme.txt` then `cat readme.txt` -> strace logs the symlink path (`readme.txt`), bypassing string matches completely.

**Fix direction:** Classify paths through any known symlink by resolving with `std::fs::canonicalize` before passing to `is_sensitive_file_read`.

---

### Finding 75 — High | `scanning.rs` | ⚠️ Open

**Summary:** `openat` relative path bypasses absolute suffix checks in `is_sensitive_file_read`.

**Root cause:** `extract_sensitive_file_reads` resolves `openat(AT_FDCWD, "etc/passwd")` to the relative path `"etc/passwd"`. Because `is_sensitive_file_read` checks `ends_with_any` (which expects leading slashes, e.g., `/.env`) and `exact_match` (which lacks relative handling, e.g., `/etc/passwd`), relative paths fail to match.

**Failure scenario:** Since no CWD tracking exists per PID (because `chdir`/`fchdir` syscalls are not intercepted), an attacker postinstall script can simply call `chdir("/")` followed by `open("etc/passwd")`. This produces the path `"etc/passwd"` in strace, completely bypassing all detection. This also applies to `open("passwd")` from cwd `/etc`.

**Fix direction:** Track cwd per PID by adding `chdir`/`fchdir` to the strace trace set. For `openat(AT_FDCWD, ...)` and `open(...)` with relative paths, resolve against the tracked cwd before passing to `is_sensitive_file_read`.

---

### Finding 171 — High | `scanning.rs` | ⚠️ Open

**Summary:** `close` syscall not tracked — stale fd_table entries create `/proc/fd` bypass window.
**Root cause:** `SYSCALL_RE` traces open, dup, fcntl but NOT close. When a fd is closed and reused, fd_table retains the stale mapping.
**Failure scenario:** An attacker can use `/proc/self/fd/N` to reference a previously-open sensitive file through a now-reused fd number.
**Fix direction:** Add `close` to `SYSCALL_RE` and remove entries from `fd_table` on close.

### Finding 172 — Medium | `ARCHITECTURE.md` | ⚠️ Open

**Summary:** `process_vm_readv` accepted risk understates inter-process memory read risk.
**Root cause:** ARCHITECTURE.md states "poses no threat to the integrity". While true for integrity, it omits data confidentiality.
**Failure scenario:** A malicious preinstall script enumerates `/proc/*/maps` to find the npm CLI process, reads its heap via `process_vm_readv` to capture `//registry.npmjs.org/:_authToken=...`, then exfiltrates via allowed registry API calls (network diff sees zero new IPs).

**Fix direction:** Update ARCHITECTURE.md to document the confidentiality risk and UID separation model.

### Finding 173 — Medium | `ARCHITECTURE.md` | ⚠️ Open

**Summary:** DNS exfiltration risk statement understates query-side data embedding.
**Root cause:** ARCHITECTURE.md narrows exfiltration to "queries sent to an allowed domain." Any DNS recursive resolver forwards queries to the attacker NS.
**Failure scenario:** Data embedded in `[hex].exfil.example.com` arrives at attacker NS regardless of allowlists, because we only parse `recvfrom` responses.
**Fix direction:** Update docs to acknowledge any DNS query can exfiltrate data.

### Finding 170 — Medium | `ARCHITECTURE.md` | ⚠️ Open

**Summary:** Import-time execution gap omitted from Threat Model.
**Root cause:** ARCHITECTURE.md accepted risks section omits the Telnyx T26 bypass (where Python module-scope code executes after sandbox exits).
**Failure scenario:** Security auditors and developers reading the threat model are unaware of the highest-severity known bypass in the sandbox architecture.
**Fix direction:** Add a dedicated accepted risk entry for the import-time execution gap in ARCHITECTURE.md.

---

### Finding 180 — Low | `lib.rs:1092-1173` | ⚠️ Open

**Summary:** `bulk_scan!` macro spans 3 packaging ecosystems — a regression in one leaks to all.

**Root cause:** The `bulk_scan!` macro is used to deduplicate the routing logic for multiple package managers (pip, npm, pnpm, uv sync). However, this creates tight coupling. A change or bug in one package manager's handling can easily break the others or introduce subtle bugs due to shared macro expansion.

**Failure scenario:** Modifying the macro to fix an npm-specific issue accidentally breaks pip argument extraction, causing pip scans to fail open or fail closed silently, and tests for pip might not catch the side-effect if not comprehensive.

**Fix direction:** Replace the macro with explicit typed per-ecosystem functions (`bulk_scan_pip`, `bulk_scan_npm`, etc.) to isolate the logic.

---

### Finding 256 — Low | `scanning.rs:511` | ⚠️ Open

**Summary:** UDP DNS regex only matches `recvfrom`; `recvmsg()` used by glibc ≥2.40, musl, and async Rust resolvers produces no domain→IP mapping.

**Root cause:** `UDP_RE` at line 511 only matches `recvfrom(`. The `recvmsg()` syscall is semantically equivalent for UDP and is used by newer glibc, musl, and async resolver implementations. DNS responses received via `recvmsg()` on a UDP socket are silently skipped, degrading FCrDNS enrichment fallback to plain IP membership for those resolutions.

**Failure scenario:** A package using a resolver that emits `recvmsg()` instead of `recvfrom()` for UDP DNS has its C2 IP caught fail-closed but without domain context, reducing the quality of the anomaly report.

**Fix direction:** Extend `UDP_RE` to match `(?:recvfrom|recvmsg)` on AF_INET/AF_INET6 port-53 sockets, similar to how `READ_RE` handles TCP.

---

### Finding 257 — Low | `scanning.rs:506-566` | ⚠️ Open

**Summary:** DNS interceptor only matches port-53 strace traffic; DoH (port 443) and DoT (port 853) bypass enrichment.

**Root cause:** Both `UDP_RE` and `CONNECT_RE` filter on `sin6?_port=htons(53)`. Packages using DNS-over-HTTPS or DNS-over-TLS connect to port 443 or 853 respectively; those connections are invisible to the DNS interceptor.

**Failure scenario:** A malicious package resolves its C2 domain via DoH. The C2 IP is still caught fail-closed by the network diff, but the domain→IP mapping is absent, so FCrDNS enrichment cannot match the IP to a known-good domain and the warning lacks domain context.

**Fix direction:** Noted architectural scope limitation; DoH/DoT interception would require HTTPS/TLS traffic inspection beyond strace port filtering.

---

### Finding 258 — Low | `scanning.rs:1976-1982` | ⚠️ Open

**Summary:** `insufficient_baselines` error message reports only the count shortfall, not that age-gate filtering may have caused it.

**Root cause:** The message at line 1977 says "Registry does not contain enough historical versions...found N". If `min_baseline_age_hours` filtered out available versions, the user sees the same message as if the package simply has few releases — no indication that raising or removing the age gate would resolve it.

**Failure scenario:** An operator running gyrseek on a package with frequent releases but a high `min_baseline_age_hours` setting sees `insufficient_baselines` with no actionable diagnosis, leading to confusion and unnecessary exemptions.

**Fix direction:** Track how many versions were filtered by the age gate and include that count in the error message.

---

### Finding 262 — Low | `.githooks/pre-commit:30` | ⚠️ Open

**Summary:** Echo message says "on staged Rust files" but `cargo fmt` formats all `.rs` files in the workspace.

**Root cause:** Line 30 prints "Running cargo check, cargo fmt, and just lint on staged Rust files..." but `cargo fmt` at line 32 formats every `.rs` file in the project, not just staged ones. Unstaged formatting changes are silently normalized on commit without the operator being aware.

**Failure scenario:** A developer edits two files, stages one, and commits. The pre-commit hook formats both files but only mentions the staged file in its output. The developer is surprised to find their unstaged file modified.

**Fix direction:** Either change the echo to accurately say "all Rust files" or use `cargo fmt -- $(git diff --cached --name-only | grep '\.rs$')` to limit formatting to staged files.

---

### Finding 263 — Low | `scanning.rs:578` | ⚠️ Open

**Summary:** `exemption_behavior` uses raw `==` to compare version strings; build metadata or non-normalised PEP 440 forms silently fail to match.

**Root cause:** `let is_exempt = exempt_version == v_curr` at line 578 is a byte-for-byte string comparison. PyPI normalises versions before publishing (e.g. `1.0.0+local` → `1.0.0`), so in practice `v_curr` from the registry will already be normalised. However, an operator who manually sets `new_package_exemptions: {pkg: "1.0.0+build1"}` would find their exemption silently ignored.

**Failure scenario:** Operator sets an exemption for a version with build metadata. The exemption never matches, the package continues to fail closed, and no warning explains the mismatch.

**Fix direction:** Normalise both strings before comparison using the same version-parsing logic already present in the codebase (PEP 440 / semver).

---

### Finding 264 — Low | `scanning.rs:1893-1908` | ⚠️ Open

**Summary:** Registry fetch failure (empty `published_at`) has asymmetric override handling between test and production modes that is never exercised by CI.

**Root cause:** Lines 1896-1908: when `published_at.is_empty()`, test mode (any active test env vars) silently trusts the override while production discards it with a warning. The production discard path is the security-relevant behaviour, but CI tests use the test mode path exclusively — the discard path has no test coverage.

**Failure scenario:** A regression that accidentally trusts overrides on registry failure in production would not be caught by the test suite.

**Fix direction:** Add a test that exercises the production discard path by simulating an empty `published_at` without any active test env vars.

---

### Finding 265 — Low | `scanning.rs:1911` | ⚠️ Open

**Summary:** No integration test verifies that a too-young baseline override is dropped and a fetched baseline fills the slot in the `scan_packages_versions` production path.

**Root cause:** `check_override_ages` has thorough unit tests, but the call at line 1911 inside `scan_packages_versions` is exercised only via network-dependent end-to-end tests. No test verifies the full path: override rejected by age gate → falls back to fetched baselines → scan proceeds correctly.

**Failure scenario:** A regression in the age-gate wiring inside `scan_packages_versions` (e.g. discarded overrides accidentally still used) would not be caught by unit tests alone.

**Fix direction:** Add an integration test using `NoopRunner` + mock registry data that sets a too-young override and confirms the fetched baseline is used instead.

---

### Finding 266 — Low | `scanning.rs:601-604` | ⚠️ Open

**Summary:** `num_hours()` floors to whole hours; a version 23h59m old reports "is only 23 hours old" — accurate for rejection but misleading to operators.

**Root cause:** `chrono::Duration::num_hours()` truncates fractional hours. A version published 23 hours and 59 minutes ago correctly fails the 24h floor check, but the warning message says "23 hours old", suggesting it is nearly an hour short when it is actually less than a minute away from passing.

**Failure scenario:** An operator sees "is only 23 hours old" and waits a full hour before retrying, when retrying in one minute would suffice.

**Fix direction:** Use `num_minutes()` and format as `Xh Ym` in the warning, or compute the remaining wait time explicitly.

---

### Finding 270 — Medium | `scanning.rs:1291-1555` | ⚠️ Open

**Summary:** Symlink traversal bypasses sensitive-file-read detection: `open("innocent")` where "innocent" is a symlink to `~/.aws/credentials` is not flagged.

**Root cause:** `extract_sensitive_file_reads` checks the path string as passed to the syscall against `is_sensitive_file_read`. If the package creates a symlink named `innocent` pointing to `~/.aws/credentials` and then opens `innocent`, strace records `open("innocent", ...)`. `is_sensitive_file_read("innocent")` returns false because the string does not match any sensitive pattern; the credential access goes undetected.

**Failure scenario:** A malicious package creates `ln -s ~/.aws/credentials innocent` then reads `innocent`, bypassing the sensitive-file-read detector entirely.

**Fix direction:** Track `symlink`/`symlinkat` syscalls to build a symlink resolution map, then resolve the ultimate target before calling `is_sensitive_file_read`. (Note: `extract_sensitive_file_reads` already parses `symlink`/`symlinkat` syscalls but only records their paths — the resolution step is missing.)

---

### Finding 271 — Medium | `scanning.rs:522-528` | ⚠️ Open

**Summary:** TCP DNS `recvfrom()` blind spot: READ_RE matches `read|recvmsg` only; `recvfrom()` on connected TCP sockets bypasses DNS enrichment.

**Root cause:** `READ_RE` at line 525 is `(?:read|recvmsg)\((\d+),...`. While `recvfrom()` is most common on UDP, it is also valid on a connected TCP socket. Some bespoke or async resolver implementations use `recvfrom()` for both UDP and TCP sockets; TCP DNS responses received this way are not captured.

**Failure scenario:** A resolver using `recvfrom()` on a TCP DNS socket produces no domain→IP mapping, degrading enrichment to plain IP membership (fail-closed but context-free).

**Fix direction:** Extend `READ_RE` to `(?:read|recvmsg|recvfrom)` and handle both the recvmsg `msg_iov` format and the bare-buffer recvfrom format.

---

### Finding 277 — Low | `lib.rs:270` | ⚠️ Open

**Summary:** `new_package_exemptions` key trimming silently overwrites colliding entries when two YAML keys differ only by whitespace.

**Root cause:** Line 270 maps `(k, v)` to `(k.trim().to_string(), v.trim().to_string())`. If the YAML config contains both `pkg` and `pkg  ` (trailing spaces) as keys, both trim to `pkg` and the second silently overwrites the first in the resulting `HashMap` with no warning.

**Failure scenario:** A misconfigured YAML with accidental whitespace-duplicate keys produces a silently truncated exemption map, potentially dropping a vetted version without operator awareness.

**Fix direction:** After trimming, check for collisions and emit a warning if two keys normalise to the same string.

---

### Finding 278 — Low | `sandbox.rs:982-1004` | ⚠️ Open

**Summary:** `SandboxEnvVarGuard::set` does not save/restore the pre-existing env var value; Drop unconditionally removes the var, losing any value set before the guard.

**Root cause:** `SandboxEnvVarGuard::set` (lines 982–987) calls `set_var(key, value)` without first saving the previous value of `key`. `Drop` at line 1002 calls `remove_var(self.key)` unconditionally. If a test or the environment had `key` set before the guard was created, the original value is lost after the guard drops.

**Failure scenario:** A test that relies on a pre-existing env var value (e.g. `GYRSEEK_PY_SCANNER_IMAGE` set in the outer test environment) has that value silently removed after the inner guard drops, causing subsequent assertions in the same test or concurrently running tests to see an absent variable.

**Fix direction:** In `set`, save `std::env::var(key).ok()` before setting; in `Drop`, either restore the saved value or call `remove_var` only if the saved value was `None`.

---

### Finding 281 — Medium | `scanning.rs:241-254` | ⚠️ Open

**Summary:** Domain planting: DNS interceptor fallback checks domain presence in `baseline_domains` but verifies IP presence in the current trace's DNS map, not the baseline's.

**Root cause:** Lines 241–254: when FCrDNS fails, the interceptor iterates `dns_map` (the current trace's domain→IP mapping) looking for a domain that is in `baseline_domains` and whose `dns_ips` contain the current IP. It then does host-side forward resolution to confirm. However, `dns_ips` comes from the current trace — not from any baseline. An attacker whose domain appeared in a single baseline trace (e.g. innocuous telemetry ping in v1.0.0) has that domain in `baseline_domains`. In a later version, the attacker points the domain at a new C2 IP; the sandbox resolves the domain to the C2 IP (populating the current trace's `dns_map`); the interceptor finds domain∈baseline_domains + current dns_map has the IP + host forward resolution confirms it (attacker controls DNS) → the C2 IP is silently discarded as a known CDN edge rotation.

**Failure scenario:** Attacker publishes v1.0.0 with a benign telemetry ping to `telemetry.attacker.com`. In v2.0.0, `telemetry.attacker.com` is pointed at a C2 IP. The new C2 IP is silently treated as a benign CDN rotation and not flagged.

**Fix direction:** Thread the baseline DNS map (domain→Vec<IpAddr>) into `find_new_connections_domain_aware` and check that the current IP was also seen in a baseline response for that domain, not just that the domain was seen.

---

### Finding 282 — Low | `scanning.rs:1878` | ⚠️ Open

**Summary:** `baseline_count: 1` is silently overridden to 2 via `.max(2)` with no user warning; config parser warns on 0 but not 1.

**Root cause:** `let fetch_count = policy.baseline_count.max(2)` at line 1878 silently bumps a configured value of 1 to 2. The config parser at `src/lib.rs:242–249` emits a warning when `baseline_count=0` but passes `baseline_count=1` through unchanged — so an operator who sets `baseline_count: 1` gets 2 baselines fetched with no explanation.

**Failure scenario:** An operator explicitly sets `baseline_count: 1` expecting single-baseline behaviour (e.g. for a package with only one prior version). Gyrseek silently fetches 2, the missing second baseline causes `insufficient_baselines`, and the operator has no diagnostic explaining why.

**Fix direction:** Either warn in the config parser when `baseline_count < 2` (matching the 0 case), or document that the effective minimum is 2 and reject values below it with a clear message.

---

### Finding 284 — Low | `scanning.rs:596,623` | ⚠️ Open

**Summary:** `filter_override_version` and `check_override_ages` use the fully-qualified `&std::collections::HashMap<...>` despite `HashMap` being imported at line 2.

**Root cause:** `use std::collections::{HashMap, HashSet}` is at line 2. The function signatures at lines 596 and 623 (and 686) use `&std::collections::HashMap<...>` unnecessarily, adding visual noise and inconsistency with all other call sites that use the bare `HashMap`.

**Fix direction:** Replace `std::collections::HashMap` with `HashMap` in those two function signatures.

---

### Finding 285 — Low | `scanning.rs:2000` | ⚠️ Open

**Summary:** `matches!(filtered_overrides, Some((Some(_), _)) | Some((_, Some(_))))` re-derives whether any override survived age-filtering, duplicating logic already implicit in `check_override_ages`'s return value.

**Root cause:** `check_override_ages` returns `(warnings, filtered_overrides)` where `filtered_overrides` is `None` if all overrides were stripped, or `Some((opt1, opt2))` if any survived. The `matches!` guard at line 2000 re-tests the structure of the return value to decide whether to print the "Applying baseline override(s)" message. This is a structural re-derivation of what the return value already communicates.

**Fix direction:** Either add a helper `has_any_override(filtered_overrides)` or extend `check_override_ages` to return a boolean `override_applied` flag, eliminating the structural pattern match at the call site.

---

### Finding 286 — Low | `scanning.rs:684-685` | ⚠️ Open

**Summary:** `GYRSEEK_TEST_FORCE_BASELINE_AGES_HOURS` silently drops all entries when any value fails to parse as `i64`.

**Root cause:** Line 685: `ages_str.split(',').filter_map(|s| s.parse().ok()).collect()`. If the env var is set to `abc,def` or `100,oops,72`, all unparseable entries are silently dropped via `.ok()`. The result is an unexpectedly short or empty `ages` vec with no warning, causing the test to produce zero candidates and potentially masking test logic errors.

**Failure scenario:** A developer sets `GYRSEEK_TEST_FORCE_BASELINE_AGES_HOURS=100,72,` (trailing comma) expecting 2 baselines. The empty string after the comma is silently dropped — no issue. But `100,72,abc` silently drops `abc` and the test proceeds with only 2 entries, potentially hiding the intent.

**Fix direction:** After collecting, emit a `eprintln!` warning if `ages.len() != ages_str.split(',').count()`, signalling that some entries were malformed.

---

### Finding 287 — Low | `scanning.rs:4249-4257` | ⚠️ Open

**Summary:** `extract_dns_map_ipv6_udp_dns_response` only asserts map and IP count; no concrete IP address verification unlike the IPv4 TCP equivalent.

**Root cause:** Lines 4254–4256 assert `map.len()==1`, `map.get("foo.com")` exists, and `ips.len()==2`. No assertion checks the actual IP values decoded from the hex payload. The IPv4 TCP equivalent at lines 4312–4314 additionally asserts `ip_strs.contains(&"140.248.144.223")` and `ip_strs.contains(&"2a04:4e42:94::223")`.

**Failure scenario:** A parsing bug in the IPv6 UDP path that produces wrong IP addresses (e.g. misparses the AAAA record bytes) would pass all three count assertions undetected.

**Fix direction:** Add concrete IP address assertions matching the hex payload bytes in the test trace, consistent with the IPv4 TCP equivalent.

---

### Finding 288 — Low | `src/lib.rs:48-51` | ⚠️ Open

**Summary:** The 0.6.0→1.0.0 upgrade introduces multiple breaking or behavior-changing items that have no changelog entry or migration guide.

**Root cause:** Several config-validation and schema changes landed in this release without being documented in a CHANGELOG or upgrade guide. Operators upgrading from 0.6.x will encounter silent behavior changes and hard errors with no actionable guidance.

**Affected changes:**
1. `new_package_exemptions` list format (`- pkg`) is now a hard config-parse error (FIXED #239). Migration: replace `- pkg` with `pkg: "<version>"`. Previously silently mapped to `""` (no-op), now rejected outright.
2. Bare-TLD domain entries (e.g. `"com"`) are now dropped with a warning (FIXED #367). Operators with such entries will see warnings and reduced allowlist coverage.
3. `"*"` and empty values in `ip_allowlist`, `domain_allowlist`, and `parse_list_map`-based allowlists now emit explicit warnings (FIXED #304, #315, #328). Previously silent no-ops now produce startup noise that may alarm operators.
4. Per-package allowlist syntax for `ip_allowlist` and `domain_allowlist` is new. Operators with global-only configs are unaffected, but those who attempt per-package scoping need to learn the new YAML shape.

**Failure scenario:** An operator upgrades gyrseek in CI, their `gyrseek.yaml` uses the old `new_package_exemptions` list format, gyrseek refuses to start with a config-parse error, and the pipeline breaks with no actionable guidance. Separately, an operator's domain allowlist had a bare-TLD entry that silently provided coverage before; after upgrade it is silently dropped, reducing protection without a clear migration path.

**Fix direction:** Add a CHANGELOG entry and/or upgrade guide for 1.0.0 documenting all breaking and behavior-changing config items with before/after examples.

---

### Finding 289 — Medium | `scanning.rs:6628-6681` | ⚠️ Open

**Summary:** `scan_packages_versions_discards_overrides_when_registry_fails` test makes a real HTTP request to PyPI, failing in offline CI.

**Root cause:** The test sets `GYRSEEK_TEST_LOCK_ONLY=1` but this env var is not listed in `active_test_env_vars()` (which only knows `GYRSEEK_TEST_FORCE_BASELINE_AGES_HOURS`, `GYRSEEK_TEST_FORCE_RELEASES_LAST_24H`, `GYRSEEK_TEST_FORCE_CURRENT_RELEASE_AGE_DAYS`, `GYRSEEK_TEST_ECHO_MIN_BASELINE_AGE_HOURS`) and is never read by `fetch_history_with_baselines`. The test comment at line 6654 explicitly states: "fetch_history_with_baselines will attempt to query PyPI for `gyrseek-test-nonexistent-pkg`. It will fail (404), returning empty `published_at`." This is a deliberate network call, not a mocked one.

**Failure scenario:** Running `cargo test` in an offline CI environment (no internet access) causes `fetch_history_with_baselines` to hang or fail with a connection error rather than a 404, causing the test to panic with an unexpected error rather than the expected `insufficient_baselines` outcome.

**Fix direction:** Intercept the registry fetch using the existing test env var mechanism (`GYRSEEK_TEST_FORCE_BASELINE_AGES_HOURS=""` or similar) to simulate an empty response without a real network call, or add `GYRSEEK_TEST_EMPTY_REGISTRY` to `active_test_env_vars()` and handle it in `fetch_history_with_baselines`.

---

### Finding 294 — Medium | `scanning.rs:156-203` | ⚠️ Open

**Summary:** Cloud metadata IP `169.254.169.254` is explicitly exempted from sandbox-local filtering, but the exemption only applies when strace shows a direct `connect()` to that IP. If the container's network path routes through the Docker bridge gateway (`172.17.0.1`), strace shows `connect()` to `172.17.0.1` instead — which is filtered as RFC1918 private — so the credential theft signal is silently lost.

**Root cause:** `is_sandbox_local_ip` (lines 183–204) checks `v4 == CLOUD_METADATA_IPV4` before `v4.is_private()`, correctly exempting the IP when seen directly. But container networking may substitute the gateway address as the observed endpoint in certain Docker network topologies (host-gateway routing, custom networks). In that case strace records `connect()` to `172.17.0.1`, which passes the `is_private()` check and is filtered out.

**Failure scenario:** A malicious package issues `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/` and the container routes via `172.17.0.1`. The strace `connect()` record shows `172.17.0.1:80`. `is_sandbox_local_ip` returns `true`, filtering it as a benign gateway address. The credential theft attempt appears as zero new connections — allowed.

**Fix direction:** Consider also exempting connections to the Docker bridge gateway port 80 from RFC1918 filtering, or add a DNS-layer check to detect `169.254.169.254` lookups regardless of the resolved connect target.

---

### Finding 295 — Low | `scanning.rs:6480-6490` | ⚠️ Open

**Summary:** `filter_override_version` tests only exercise a completely empty `published_at` map; no test exercises the case where the map has entries for other versions but is missing the override version — a distinct code path.

**Root cause:** `filter_override_version_not_found_warns` (lines 6480–6490) passes an empty `HashMap::new()` as `published_at`. The "not found" branch executes because the map is empty. The case where `published_at` has entries for some versions but the override version is specifically absent (key lookup returns `None`) hits the same branch via the same code path, but the test never exercises it with partial data — so a regression that accidentally matches a wrong key would not be caught.

**Failure scenario:** A refactor that changes the lookup key (e.g., trims whitespace or normalises version strings) could cause a partially-populated map lookup to match an unrelated version entry, silently accepting a bad override. The empty-map test would still pass.

**Fix direction:** Add a test case passing a `published_at` map with one or more entries for different version strings, asserting the override version is correctly identified as absent.

---

### Finding 296 — Low | `tests/cli_burst_exit_tests.rs:152` | ⚠️ Open

**Summary:** Test name `exits_with_code_1_and_rejects_versions_newer_than_72_hours_by_default` is semantically ambiguous — "newer than 72 hours" can mean either "published less than 72 hours ago" (correct) or "published more than 72 hours ago" (opposite meaning). The comment in the test clarifies the intent, but the function name alone is misleading.

**Root cause:** The test validates that gyrseek rejects packages whose baselines are younger than the 72-hour default `min_baseline_age_hours` gate. The phrasing "newer than 72 hours" means "less than 72 hours old" in natural English when talking about freshness, but "newer than N hours" is ambiguous with "older than N hours" in a temporal context.

**Failure scenario:** A developer reading only the test name may interpret it as testing the opposite gate direction, causing confusion during debugging or when writing related tests.

**Fix direction:** Rename to `exits_with_code_1_when_baselines_younger_than_72h_default_age_gate` or similar to make the direction unambiguous.

---

### Finding 380: Config-load warnings use stdout instead of stderr

**Summary:** All `~60` warning `println!` calls in `load_policy_config` write to stdout. CI pipelines typically only surface stderr in failure highlights; stdout warnings scroll past silently. The one `eprintln!` in the file is inconsistent with all config validation warnings.

**Root cause:** Warning messages were written with `println!` throughout `load_policy_config` without considering CI stdout/stderr routing conventions.

**Failure scenario:** A bare-TLD domain entry dropped with a warning, a `"*"` key rejected, or a whitespace-collision merged in config — all emit stdout-only diagnostics that are invisible in CI dashboards that filter to stderr.

**Fix direction:** Switch all config validation `println!("⚠️ [gyrseek] ...")` calls to `eprintln!` so warnings route to stderr and appear in CI failure output.

---

### Finding 381: Per-package allowlists are permanent trust anchors with no version-pinning

**Summary:** An allowlist entry (e.g. `sensitive_file_access_allowlist: { telemetry-sdk: ["/etc/ssl/certs"] }`) is granted for a package name unconditionally. It applies equally to v1.0.0 (legitimate) and v5.0.0 (compromised). No mechanism exists to scope an allowlist entry to a specific version or version range.

**Root cause:** All per-package allowlist structures (`ip_allowlist`, `domain_allowlist`, `sensitive_file_access_allowlist`, `git_clone_allowlist`, `artifact_allowlist`, `process_exec_allowlist`) key on package name only. There is no version field in the config schema or the `PolicyConfig` struct.

**Failure scenario:** An operator allowlists a known-good SDK's network traffic or file access. The package is later compromised and a new version is published with malicious additions. The allowlist silently passes the new version's behavior because the name matches, defeating the anomaly detection that would otherwise catch the new activity.

**Fix direction:** Add optional version-scoping syntax (e.g. `telemetry-sdk@1.x: [...]`) to per-package allowlist entries; at scan time, check the resolved version before applying the allowlist. Unversioned entries retain current behavior for backward compatibility.

**Precedent:** `new_package_exemptions` already implements version-pinning at the config level (`pkg: "1.2.3"` — the exemption only matches the exact resolved version). The same pattern could be applied to per-package allowlist keys, using the resolved `v_curr` at scan time as the comparand.

---

### Finding 382: Missing test coverage for `"*/"` and `"/*"` overly-permissive guards

**Summary:** `sensitive_file_access_allowlist_all_values_filtered_drops_key` tests only the `"*"` and `"/"` guard cases. The test comment mentions all four patterns (`"*"`, `"/"`, `"*/"`, `"/*"`) but only two are exercised. A regression removing `"*/"` or `"/*"` from the `retain` guard passes CI undetected.

**Root cause:** The test was written to cover FIXED #368 (empty-set cleanup) and FIXED #360 (`"/*"` guard addition) but the test body was not updated to exercise the newly added `"/*"` and `"*/"` patterns.

**Failure scenario:** A future refactor consolidates or rewrites the four-value retain condition and accidentally drops `"*/"` or `"/*"`. The test passes because it only asserts on `"*"` and `"/"`. An operator config with `"*/"` now passes the guard silently as a dead entry with no warning.

**Fix direction:** Add `"*/"` and `"/*"` to the `all-bad-pkg` value list in the test and assert they are also removed, consistent with the comment that describes all four patterns.

---

### Finding 412 — Medium | `src/sandbox.rs`, `docs/DOCKER_SECURITY.md` | ⚠️ Open

**Summary:** The 2nd stage of a supply-chain package (for example the Shai-Hulud pattern of downloading Bun and running an obfuscated stealer) runs inside the sandbox in every backend. Docker probes have open egress: the payload can download and run a 2nd stage and send data to any host.

**Why not simply close egress:** installs legitimately fetch native binaries, prebuilt wheels and `postinstall` downloads, and the tool is meant to support many registries, so a strict allow-list produces false positives. Detection does not depend on blocking: the diff flags the new endpoint or exec either way. Blocking only limits damage during the probe and hides the 2nd stage's behaviour.

**Unmeasured:** whether the Docker bridge can reach private addresses (LAN, `host.docker.internal` on Docker Desktop).

**Fix direction:** an optional egress proxy that logs full URLs so path-level differences are visible regardless of registry, with allow or block selectable by policy; test private-range reachability and block it if reachable. See the roadmap item "Optional egress mediation/proxy mode".

---

### Finding 415 — Low | `Cargo.toml` | ⚠️ Open

**Summary:** `cargo audit` reports `chrono` 0.4.45 as unmaintained (RUSTSEC-2026-0543, dated 2026-09-14). It is a direct dependency (`features = ["clock"]`) used for release-age and burst-window calculations.

**Impact:** no known vulnerability; the risk is that future defects or security issues in `chrono` will not be fixed. CI reports it as an allowed warning and does not fail.

**Fix direction:** migrate to a maintained crate (`jiff` or `time`), keeping the `i64` hour comparisons (`HARD_MINIMUM_AGE_HOURS`, `DEFAULT_MIN_BASELINE_AGE_HOURS`) and the tests for age gates and burst filtering.

---

### Finding 416 — Low | `Cargo.toml` | ⚠️ Open

**Summary:** `serde_yaml` 0.9.34 (a direct dependency, published as `+deprecated`) depends on `unsafe-libyaml` 0.2.11, which `cargo audit` reports as unmaintained (RUSTSEC-2024-0449). It parses the `gyrseek.yaml` policy config.

**Impact:** no known vulnerability. The config is operator-controlled, not package-controlled, which limits exposure; the risk is a long-term lack of fixes. CI reports it as an allowed warning.

**Fix direction:** move to a maintained YAML crate and re-run the config tests (allowlist validation, `new_package_exemptions` deserializer, per-package versus global entries).

---

### Finding 394 — Low | `README.md` | ⚠️ Open

**Summary:** The README `domain_allowlist` config table row does not document the bare-TLD rejection gate added by FIXED #367. An operator who has a bare label like `"com"` in their config will see a startup warning after upgrading but find no explanation in the README.

**Root cause:** FIXED #367 updated AGENTS.md and added the check to `load_policy_config`, but the README config table was not updated to mention that entries without a dot are rejected.

**Failure scenario:** An operator upgrading from 0.6.0 with `domain_allowlist: ["com"]` (intending something like "allow all .com domains") sees `⚠️ [gyrseek] Ignoring domain_allowlist entry "com": a bare label without a dot would match all subdomains of any TLD` and has no README reference explaining why or what to write instead.

**Fix direction:** Add a note to the README `domain_allowlist` row explaining that entries must contain at least one dot (e.g. `"pypi.org"`, not `"org"`) and that bare labels are rejected at startup with a warning.

---

### Finding 388 — Medium | `src/lib.rs` | ⚠️ Open

**Summary:** An empty per-package IP or domain value list (`- my-pkg: []`) silently creates a dead `HashSet` entry in `ip_allowlist` or `domain_allowlist`. The operator believes protection is active for that package but no entries are stored.

**Root cause:** The ip and domain PerPackage branches call `ip_allowlist.entry(pkg.clone()).or_default()` before iterating the value list. If the list is empty, the entry is created with an empty set and no warning is emitted. FIXED #363 added the equivalent empty-set warning to `parse_list_map`, but the ip/domain PerPackage branches were not updated.

**Failure scenario:** An operator writes `- my-pkg: []` expecting to grant per-package exemption later, or accidentally clears the list. The startup message counts the entry as "loaded"; at scan time `get("my-pkg")` returns an empty set, so no IPs or domains are exempted — silently defeating the allowlist.

**Fix direction:** After the per-entry loop in both PerPackage branches, check `if set.is_empty()` and emit a warning consistent with FIXED #363: "ip_allowlist package 'pkg' has no valid entries; no allowlist protection will be applied for this package." Consider also removing the empty key to avoid counting it in the startup summary.

---

### Finding 389 — Medium | `src/scanning.rs` | ⚠️ Open

**Summary:** `find_new_items` is used at three set-difference sites but not at the artifact diff site, which uses an inline `.difference().cloned().collect()` without sorting. Three patterns for set-difference exist across the codebase.

**Root cause:** The artifact finding diff predates the `find_new_items` extraction (FIXED #330) and was not updated. `find_new_items` adds a deterministic sort on top of `HashSet::difference`; the inline call skips it.

**Failure scenario:** `new_artifact_findings` is an unsorted `Vec`. Any consumer that compares it against a sorted expected list (e.g. in tests) or displays it to the operator sees non-deterministic ordering. A future change to `find_new_items` (e.g. adding dedup logic) would silently miss the inline artifact site.

**Fix direction:** Replace the inline `.difference(&baseline_artifact_findings).cloned().collect::<Vec<_>>()` with `find_new_items(&artifact_curr, &baseline_artifact_findings)` for consistency and determinism.

---

### Finding 390 — Low | `src/scanning.rs` | ⚠️ Open

**Summary:** `reverse_dns_domain` is called three times for overlapping IP sets per scan: (1) inside `find_new_connections_domain_aware` for the domain-level diff, (2) inside `filter_domain_allowlisted_new_connections_with` for allowlist matching, and (3) in the enrichment display loop. Each call does a live PTR lookup; two-thirds of these are redundant.

**Root cause:** The three call sites evolved independently. No shared cache was introduced when the enrichment display loop was added.

**Failure scenario:** Each redundant PTR lookup adds latency per new connection endpoint per scan. For a package with many new IPs, this compounds. In offline or slow-DNS environments it delays scan results.

**Fix direction:** Build a `HashMap<String, Option<String>>` cache before the first call site, pass it through to all three, and memoize results on first lookup. Alternatively, make `reverse_dns_domain` accept a mutable cache reference so callers share state naturally.

---

### Finding 391 — Low | `src/lib.rs` | ⚠️ Open

**Summary:** `parse_list_map_empty_value_set_drops_key` tests blank and whitespace string values within a list, but not a bare `my-pkg:` YAML key with no list items (which serde deserializes as an empty `Vec<String>`). The FIXED #363 warning path for a genuinely empty list is untested.

**Root cause:** The test was written to cover blank/empty string entries inside a list; the case of no items at all was not considered.

**Failure scenario:** A serde change that delivers a bare key as `None` instead of an empty `Vec`, or a future refactor of `parse_list_map` that handles the empty-vec path differently, would silently skip the warning. CI passes because the tested path (blank string values) still triggers correctly.

**Fix direction:** Add a test case with `my-pkg:` and no value list items (empty YAML sequence or null). Assert the key is absent from the result and the warning is emitted.

---

### Finding 383 — Low | `AGENTS.md`, `docs/ARCHITECTURE.md` | ⚠️ Open

**Summary:** `validate_allowlist_pkg_key`, `parse_list_map`, and `option_zero_to_none` are documented in full parameter-level detail in both AGENTS.md (lines ~52–56) and ARCHITECTURE.md (Config-loading helpers subsection). Two authoritative sources for the same specification will drift as the helpers evolve.

**Root cause:** FIXED #374 added a "Config-loading helpers" subsection to ARCHITECTURE.md that duplicated the level of detail already present in AGENTS.md rather than cross-referencing it.

**Failure scenario:** A future change to a helper's signature or semantics is reflected in one document but not the other. Both appear authoritative, leaving readers uncertain which is correct.

**Fix direction:** Designate AGENTS.md as the single authoritative source for helper implementation detail. Reduce the ARCHITECTURE.md subsection to a one-line description per helper with a "see AGENTS.md for full detail" cross-reference.

---

### Finding 378: Parse-time warnings omit config file path

**Summary:** `load_policy_config` receives the config file `path` as a parameter but parse-time warnings (invalid IP entries, invalid domain entries, overly-permissive `sensitive_file_access_allowlist` values) do not include it in their output. Only the post-load startup summary lines include `config_path`.

**Root cause:** Warning `println!` calls inside `load_policy_config` were written without the path parameter, while the startup messages in `run()` (which do have `config_path` in scope) include it.

**Failure scenario:** In a multi-project CI environment where several repos each have a `gyrseek.yaml`, a `⚠️ [gyrseek] Ignoring invalid ip_allowlist entry` line in aggregated logs provides no indication of which project's config file is misconfigured.

**Fix direction:** Pass `path` through to each warning inside `load_policy_config`, or thread it into helper functions, so every diagnostic names the source file.

---

### Finding 379: Startup IP/domain count conflates global and per-package buckets

**Summary:** `total_ips` at startup is computed as `policy.ip_allowlist.values().map(|s| s.len()).sum()`, which sums all map values including the `"*"` global bucket. The message "Loaded N allowlisted IP(s)" does not distinguish global entries from per-package entries, making it impossible to audit allowlist scope from startup output alone.

**Root cause:** The ip_allowlist and domain_allowlist `HashMap` stores both global entries under key `"*"` and per-package entries under package name keys. Summing all values conflates the two.

**Failure scenario:** An operator configured 2 global IPs and 13 per-package IPs across 5 packages sees "Loaded 15 allowlisted IP(s)" — they cannot tell whether all 15 are global (applying to every package) or scoped per-package without reading the config file.

**Fix direction:** Separate the count: `N global, M per-package across P package(s)` by checking `ip_allowlist.get("*")` for the global count and summing the rest for per-package.

---

### Finding 420 — Medium | `src/scanning.rs` | ⚠️ Open

**Summary:** `extract_process_exec_signatures` builds each signature from the full argv (`exe|arg1|arg2|…`). When a package is built from source, the installer runs helper processes whose arguments contain freshly generated temp directories, for example `python -c "… backend.build_wheel(b\"/tmp/.tmpvmamp8/builds-v0/.tmpTcdcXQ\" …"` from `uv`'s build isolation. The directory names are random, so the same build in a baseline produces a different signature and the candidate's signatures always look new.

**Impact:** a false `process_exec_anomaly` (reported as the Shai-Hulud class) for any package that is built from source in the sandbox. Seen with `pandas==2.2.2` on the Python 3.13 scanner image, which has no wheel for it. Operators are pushed to add `process_exec_allowlist` entries, which cannot match random paths anyway, or to disable checks.

**Note:** since FIXED #421 a source build that fails in the sandbox (the usual case today, see #425) is blocked earlier as `install_failed`; this finding still applies to builds that succeed, for example in a custom scanner image with a toolchain.

**Fix direction:** normalise generated temp paths in signatures before diffing (for example collapse `/tmp/.tmp*` components) for both the candidate and the baselines. Do not "fix" it by forcing wheels only (`--only-binary`): source builds run package code, which is exactly the behaviour the probe exists to observe.

---

### Finding 424 — Low | `src/sandbox.rs` | ⚠️ Open

**Summary:** In host mode the probe is `timeout <secs> strace …`. GNU `timeout` moves itself into a new process group so it can signal the whole tree, which means a terminal Ctrl-C is delivered to gyrseek but not to that group.

**Impact:** after Ctrl-C the traced install can keep running on the host until it finishes or the limit fires. Host mode has no isolation, so a package under test keeps executing. Not tested: macOS has no `strace`, and this was reasoned from how `timeout` works, not observed.

**Fix direction:** confirm on Linux first. If it reproduces, forward SIGINT/SIGTERM from gyrseek to the `timeout` process (it relays them to its child). Do not use `timeout --foreground`: it signals only the direct child, so package-manager subprocesses would survive a real timeout.

---

### Finding 433 — Medium | `src/sandbox.rs` | ⚠️ Open

**Summary:** In host mode the probe is `timeout -k 5 N strace … ` with stderr piped back to `Command::output()`. GNU `timeout` returns when `strace` exits, so its SIGKILL timer does not reach descendants that `strace` detached on SIGTERM, and a descendant that keeps the stderr pipe open keeps `output()` waiting for end-of-file indefinitely. Docker mode is not affected: the container is the process boundary and the cleanup loop covers survivors. Not reproduced here because macOS has no `strace`.

**Impact:** the probe time limit may not fire in host mode against a package that ignores SIGTERM, which is the case the limit exists for. Host mode already has no isolation, so this is a denial of service, not an escape.

**Fix direction:** write the trace with `-o` to a file and send the child's stderr to a file, not a pipe, so no descendant can hold the read end; run the probe in its own process group and SIGKILL the whole group after the grace period. Test with a fixture that ignores SIGTERM and holds the pipe.

---

### Finding 450 — Medium | `src/index_settings.rs` | ⚠️ Open

**Summary:** Some package-manager settings that redirect an install are not read.

**Root cause:** `index_settings` reads the common locations (flags, requirements files, environment, `pip.conf`, `uv.toml`/`pyproject.toml`, Poetry sources, `.npmrc`). `[tool.uv.sources]`, npm's global and built-in config, pip config under the interpreter prefix, `--config-file`, `-c` constraints files and pnpm workspace settings are not.

**Fix direction:** add those sources, or have the package manager report its effective index (`pip config list`, `npm config get registry`).

---

### Finding 451 — Low | `src/index_settings.rs` | ⚠️ Open

**Summary:** A scoped registry refuses the whole command.

**Root cause:** `node_redirects` returns every `registry` and `@scope:registry` setting and `refusal` runs in `LazyRunner::get()` before the package list is known, so the scope cannot be compared with the packages.

**Fix direction:** pass the packages (named on the command line or from the lockfile) to the check and drop scoped redirects whose scope matches none of them; keep the default `registry` unconditional.


---

### Finding 453 — Medium | `src/parsing.rs` | ⚠️ Open

**Summary:** npm/pnpm value-flag lists are maintained by hand.

**Root cause:** `npm_positional_indexed` skips the argument after a listed flag and treats every other non-flag argument as a package. The lists were written from the documentation, with no test that compares them with what the installed npm and pnpm accept.

**Fix direction:** add a CI test that reads the flag tables of the installed npm and pnpm and compares them with the lists, and refuse (rather than guess) an unknown flag followed by a non-flag argument.


---

### Finding 454 — Low | `src/index_settings.rs` | ⚠️ Open

**Summary:** Project-root discovery for .npmrc is unverified against real npm and pnpm.

**Root cause:** `project_npmrcs` stops at the first directory with a `package.json` (npm) or `pnpm-workspace.yaml` (pnpm). Real npm also treats a directory with `node_modules` as a root and pnpm has its own workspace rules; only the documented behaviour was implemented.

**Fix direction:** compare with `npm config get registry` and `pnpm config get registry` run from nested directories in a CI test, and read every candidate root when the tools disagree.


---

### Finding 455 — Low | `src/index_settings.rs` | ⚠️ Open

**Summary:** Redirect check ignores scheme and port.

**Root cause:** `host_of` drops the scheme and port before the comparison with `trusted_index_hosts`.

**Fix direction:** require https for trusted hosts, optionally with a port in the config entry.


---

### Finding 456 — Low | `src/index_settings.rs` | ⚠️ Open

**Summary:** Switches that disable settings are not honoured.

**Root cause:** `python_redirects` always reads `pip.conf` locations and `PIP_*` variables; pip skips them with `--isolated` and when `PIP_CONFIG_FILE` points at the null device, and uv with `--no-config`.

**Fix direction:** detect those switches and skip the config and environment sources they disable (never the command-line flags).


---

### Finding 458 — Low | `tests/e2e/redirects.sh` | ⚠️ Open

**Summary:** uv and poetry e2e checks do not confirm the setting is read or the mirror used.

**Root cause:** `tests/e2e/redirects.sh` asserts `npm/pnpm config get registry` and `pip config list` and the proxy's request log for npm, pnpm and pip. uv and poetry install from the lockfile's own URLs, and neither has an equally cheap way to print the effective index, so only the refusal and the exit code are asserted.

**Fix direction:** find a command per manager that prints the effective index (or use verbose output) and assert it; point a lockfile-less install at the mirror so the request log can be checked.


---

### Finding 459 — Low | `tests/e2e/redirects.sh`, `justfile` | ⚠️ Open

**Summary:** e2e redirect checks depend on live registries.

**Root cause:** The script creates fixtures with the real tools against the public registries (`npm install --package-lock-only`, `uv lock`, `poetry lock`) and the sandbox probes the public registry, so it needs network. The machine's own settings, caches and stores are no longer a factor: the run uses its own `HOME`.

**Fix direction:** a fixture registry for the lockfile creation, served by the stand-in mirror.


---

### Finding 460 — Low | `src/index_settings.rs` | ⚠️ Open

**Summary:** POETRY_REPOSITORIES_*_URL is probably not an install source.

**Root cause:** `python_env_redirects` treats every `POETRY_REPOSITORIES_*_URL` variable and the `[repositories]` table of Poetry's `config.toml` as an index setting; Poetry documents them as upload targets. Neither the unit tests nor the e2e test checked what Poetry does with them.

**Fix direction:** confirm with a real Poetry (install from a lockfile-less project with the variable set and watch the requests); remove the sources that are publish-only and keep `[[tool.poetry.source]]`.


---

### Finding 462 — Low | `src/sandbox.rs` | ⚠️ Open

**Summary:** Trace data on the host is bounded per probe, not per batch.

**Root cause:** `read_frames` writes every streamed file to a host temp directory and `collect_probe_traces` reads it later; only a single probe's size is capped.

**Fix direction:** extract the signals of each probe as it arrives and discard the raw trace, or cap the total bytes written and fail closed with a message naming `GYRSEEK_TRACE_LIMIT`.


---

### Finding 463 — Low | `src/sandbox.rs` | ⚠️ Open

**Summary:** Trace tmpfs memory use and the tools the streaming needs.

**Root cause:** The tmpfs is memory-backed and the matrix script relies on coreutils/BusyBox tools being in the scanner image.

**Fix direction:** derive the trace limit from `GYRSEEK_MEM_LIMIT`; add a `command -v base64 df tr cut` check at the start of the script that exits with a clear message.


---

### Finding 464 — Medium | `src/sandbox.rs`, `src/scanning.rs` | ⚠️ Open

**Summary:** Host memory use is bounded by the trace limit, not small.

**Root cause:** FIXED #434 bounds what the container can produce and what `read_frames` writes, but the signal extraction in `scanning.rs` takes a `&str` of the whole trace.

**Fix direction:** make the extractors take a reader and keep only the signals (executables, network endpoints, file reads, git clones) per probe; until then keep the default as small as the heaviest legitimate install allows.


---

### Finding 465 — Low | `src/sandbox.rs` | ⚠️ Open

**Summary:** A flooding probe is blocked late.

**Root cause:** The trace limit is checked once, after the install and its artifact scan, by `gyrseek_publish`.

**Fix direction:** run a small watcher beside the probe that checks `df` every second and, below the threshold, kills the scanner user's processes (the existing `KILL_PAYLOAD_PROCESSES_STEP`) and leaves the limit marker.


---

### Finding 466 — Low | `src/lib.rs`, `src/sandbox.rs` | ⚠️ Open

**Summary:** Trace limit and probe timeout cannot be set per package.

**Root cause:** `PolicyConfig` carries one `trace_limit` and one `probe_timeout_seconds` for the whole batch, and the matrix script gives every probe the same tmpfs.

**Fix direction:** pass a per-probe limit (the tmpfs is shared by the batch, so size it for the largest configured value and compare each probe's usage with its own limit in `gyrseek_publish`).


---

### Finding 470 — Low | `src/sandbox.rs` | ⚠️ Open

**Summary:** A custom image can have the package manager but no interpreter on PATH.

**Root cause:** `build_artifact_scan_steps` resolves the interpreter with `command -v` as root, which is not the environment the install runs in.

**Fix direction:** add `GYRSEEK_INVENTORY_INTERPRETER` (or a config key) that overrides the lookup, and mention it in the exit 126 message.


---

### Finding 472 — Low | `.github/workflows/ci.yml`, `src/sandbox.rs` | ⚠️ Open

**Summary:** Docker tests depend on pulling images and apt packages.

**Root cause:** `a_scanner_image_without_a_working_interpreter_fails_the_scan_with_a_message` names a public image by tag; the other tests need the network for apt.

**Fix direction:** pin `busybox` by digest, add `docker pull` with a retry to the recipe before running the tests, and use the prebuilt scanner images in CI.


---

### Finding 473 — Low | `src/scanning.rs` | ⚠️ Open

**Summary:** Comparing `binary` findings by a normalised path hides a hostile file that differs from a baseline file only by a hash or a version.

**Root cause:** `normalize_artifact_path` replaces hex runs and dotted versions by `*`; the comparison is a set membership test on the result, so any number of files with the same normalised name and type match one baseline file.

**Fix direction:** compare the count of files per normalised name as well and flag an increase, and keep an exact comparison for executables outside the package's own directories.

---

### Finding 474 — Low | `src/scanning.rs` | ⚠️ Open

**Summary:** `normalize_artifact_path` recognises hex runs, dotted versions with a short list of pre-release tags, and cache fan-out directories; other ways a vendored file changes name between releases still make it "new".

**Root cause:** the rules were derived from the failures seen when scanning numpy, pillow, psycopg2-binary, sharp and @swc/core. A single-number soname (`libssl.so.3`) is kept on purpose, because normalising it would also hide a hostile `libssl.so.9`; Python's PEP 440 spellings and other tags are simply not covered.

**Fix direction:** scan more native packages (grpcio, cryptography, lxml and pydantic-core were clear only because they ship few vendored files), add the spellings that occur, and decide whether a soname bump inside the package's own `.libs` directory is the same library.

---

### Finding 476 — Low | `src/sandbox.rs` | ⚠️ Open

**Summary:** The artifact inventory recognises only three executable formats and lists neither symlinks nor `/tmp`.

**Root cause:** `ARTIFACT_INVENTORY_PYTHON` and `ARTIFACT_INVENTORY_NODE` check four magic numbers, `find -type f` skips symlinks, and `/tmp` was left out as noisy.

**Fix direction:** report new shebang scripts and WebAssembly only outside the package's own directories, list symlinks whose target is outside `/work`, and decide about `/tmp`.

---

### Finding 477 — Low | `src/sandbox.rs` | ⚠️ Open

**Summary:** The writable places outside /work are a fixed list.

**Root cause:** The list was measured once in the default images and hard-coded; the inventory `find` and `WORK_RESET_STEP` both use it.

**Fix direction:** probe writability at the start of the matrix script with `runuser -u gyrseek -- find / -xdev -writable -type d`, keep the result in a shell variable, and build both the `find` and the reset from it.


---

### Finding 479 — Medium | `src/sandbox.rs`, `docker/Dockerfile.*` | ⚠️ Open

**Summary:** A package that must be built from source cannot be built in the sandbox: the default images have no compiler, and `/tmp` is `noexec`.

**Root cause:** `/tmp` is mounted `noexec` (FIXED #425 enlarged it but kept it `noexec`), and build tools that pip and uv run from their build-isolation environment under `/tmp` (`meson`, `cmake`) fail with `Permission denied` even if a compiler is present; and the images have no compiler, so `node-pre-gyp --fallback-to-build`, `node-gyp rebuild` and source builds of Python packages fail. Seen with bcrypt 5.0.1 on Node 26 (the candidate 5.1.1 installed, its older baseline did not, which blocks the package).

**Fix direction:** either ship a toolchain in the prebuilt scanner image and review what a build script may then do (this includes whether a dedicated executable build directory is acceptable, see WONT_FIX #480), or pick the sandbox runtime from the versions for which the package has prebuilds. Until then `node_version` or `python_version` is the escape hatch.

---

---

### Finding 481 — Medium | `src/lock_verify.rs`, `src/index_settings.rs` | ⚠️ Open

**Summary:** A command-line install through a trusted mirror is not hash-checked.

**Root cause:** FIXED #447/#452 compare the hashes a lockfile pins with the public registry's. A package named on the command line has no lockfile and no hash, so `trusted_index_hosts` still means "assumed to serve the public files".

**Fix direction:** install the scanned artifact by hash, or refuse a command-line install while a trusted mirror is configured. `pip --require-hashes` demands hashes for every dependency, and npm cannot take an integrity value on the command line, so neither is a drop-in.

---

### Finding 482 — Medium | `src/lock_verify.rs`, `src/sandbox.rs` | ⚠️ Open

**Summary:** The scan traces one platform's wheel; a lockfile pins several.

**Root cause:** `verify_lockfile_artifacts` requires every locked hash to be a public hash of that version, which proves the file is public but not that the probe ran it. uv.lock and poetry.lock list a wheel for each platform, and the real install takes the one for its own machine, while the probe container (Linux) took its own.

**Fix direction:** probe the lockfile's wheel for each platform that is in use, or accept a lockfile only when the probe's wheel is the one the install will pick. Related to the native-package normalisation trade-off (#473).

---

---

### Finding 483 — Medium | `src/lock_verify.rs` | ⚠️ Open

**Summary:** Requirements files are not hash-checked.

**Root cause:** `verify_lockfile_artifacts` handles only recorded lockfiles. `uv pip sync` and `pip -r` requirement lines carry `--hash=` values that are never compared, so the #452 mirror gap remains for them.


---

### Finding 484 — Low | `src/lock_verify.rs` | ⚠️ Open

**Summary:** One extra registry request per locked package.

**Root cause:** The verification fetches `/<name>/<version>` per package, separately from the history fetch, in batches of 16, and any failure blocks. A big lockfile or an outage blocks every lockfile install.


---

### Finding 485 — Low | `src/lock_verify.rs` | ⚠️ Open

**Summary:** Hash forms that cannot be compared block a valid lockfile.

**Root cause:** Only `sha1-` against `dist.shasum` is converted. A local `sha512-` against a sha1-only old package, non-sha256 pylock hashes and files removed from PyPI are all reported as not published.


---

### Finding 486 — Low | `src/lock_verify.rs` | ⚠️ Open

**Summary:** Several lockfiles are merged before the sdist rule.

**Root cause:** Pins are unioned per name and version, so the wheel flag of one lockfile masks an sdist-only entry in another.


---

### Finding 487 — Low | `src/lock_verify.rs` | ⚠️ Open

**Summary:** Name and version spelling is sent to the registry as written.

**Root cause:** PyPI is expected to redirect non-normalised names and versions; this was not measured, and an npm alias relies on the `name` field of the entry.


---
