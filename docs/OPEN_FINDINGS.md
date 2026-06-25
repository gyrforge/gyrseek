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
| 29 | `scanning.rs` | —    | High     | `/proc/self/fd/N` evasion for sensitive file access                    | ⚠️ Open  |
| 31 | `sandbox.rs`  | —    | Critical | `pidfd_open` and `pidfd_getfd` not blocked, allowing fd theft          | ⚠️ Open  |
| 32 | `scanning.rs` | —    | Critical | NUL-byte path truncation bypass in strace path unescaping              | ⚠️ Open  |
| 33 | `sandbox.rs`  | —    | High     | `execveat` double gap: absent from trace list and parser regex         | ⚠️ Open  |
| 34 | `scanning.rs` | —    | High     | Cross-PID `/proc/N/fd/` resolution bypass                              | ⚠️ Open  |
| 35 | `scanning.rs` | —    | High     | `close` and `execve` omitted from strace causing stale fd_table        | ⚠️ Open  |
| 36 | `scanning.rs` | —    | High     | `F_DUPFD` numeric check missing; `F_DUPFD_CLOEXEC` ignored             | ⚠️ Open  |
| 37 | `scanning.rs` | —    | Medium   | `is_harness_command` `env` delegation footgun                          | ⚠️ Open  |
| 38 | `scanning.rs` | —    | Medium   | `*` prefix allowlist warns but silently blocks everything              | ⚠️ Open  |
| 39 | `scanning.rs` | —    | Medium   | `.env` variant blind spot (misses `.env.production`, etc.)             | ⚠️ Open  |
| 40 | `scanning.rs` | —    | High     | `/proc/self/fd/N` relative path traversal bypasses fd resolution       | ⚠️ Open  |
| 41 | `.github/workflows/ci.yml` | — | Low | `actions/checkout@v7` moving tag not SHA-pinned | ⚠️ Open  |
| 42 | `scanning.rs` | —    | Low      | Test duplication across anomaly-counting tests                         | ⚠️ Open  |
| 43 | `scanning.rs` | —    | Low      | `lexical_clean_path` reinvents stdlib path normalization               | ⚠️ Open  |
| 44 | `scanning.rs` | —    | Low      | Test coverage regression: `unescape_trailing_backslash`               | ⚠️ Open  |
| 45 | `.github/workflows/ci.yml` | — | High | CI prompt injection via unsanitized `review_ledger.md`           | ⚠️ Open  |
| 46 | `scanning.rs` | —    | Medium   | `is_harness_command` `uv` check coupling with sandbox script           | ⚠️ Open  |
| 47 | `scanning.rs` | —    | Medium   | `extract_sensitive_file_reads` requires decomposition                  | ⚠️ Open  |
| 48 | `.github/workflows/ci.yml` | — | Medium | CI `gh run download` silently swallows errors                    | ⚠️ Open  |
| 49 | `.github/workflows/ci.yml` | — | Medium | CI `GH_TOKEN` in environment for consolidation step increases blast radius | ⚠️ Open  |
| 50 | `README.md`   | —    | Medium   | `sensitive_file_access_allowlist` example is dangerous and non-functional | ⚠️ Open  |
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
| 75 | `scanning.rs` | 1312 | High   | Relative path + cwd manipulation bypasses absolute string matches      | ⚠️ Open  |

## Complexity & Over-Engineering Findings

| #  | File          | Tag      | What                                                                                     | Fix                                                                 | Status    |
|----|---------------|----------|------------------------------------------------------------------------------------------|---------------------------------------------------------------------|-----------|
| C16 | `lib.rs:1092-1173` | yagni | `bulk_scan!` macro spans 3 packaging ecosystems — a regression in one leaks to all | Replace with typed per-ecosystem functions (`bulk_scan_pip`, `bulk_scan_npm`, etc.) | ⚠️ Open  |

---

## Detailed Findings

### Finding 11 — High | `parsing.rs:468` | ⚠️ Open

**Summary:** When all npm CLI args are non-registry specs (`file:`, `git+`, `https://`, `link:`), the package.json fallback fires and scans unrelated registry dependencies; any policy hit on those deps blocks the install the user actually requested.

**Root cause:** `parse_npm_install_packages_from_args` correctly filters non-registry specs, but when all args are filtered, `packages` is empty and the `!packages.is_empty()` guard falls through to the `package.json` fallback. That fallback reads all `dependencies`, `devDependencies`, etc. — none of which were part of the user's command — and returns them as scan targets.

**Failure scenario:** User runs `gyrseek npm install file:../local-pkg`. Arg filtered → `packages=[]`. `package.json` lists `moment` published 10 minutes ago. `minimum_release_age_package: 1` is configured. `scan_many_with_cache` blocks on `moment`. `exit(1)`. The local-file install never runs.

**Chained with:** Finding 12 — same root cause when no `package.json` exists.

**Fix direction:** When all CLI args are non-registry specs, forward the command directly without scanning. The package.json fallback should only fire when the user typed `npm install` with no arguments at all.

---

### Finding 12 — High | `lib.rs:1021` | ⚠️ Open

**Summary:** When all npm CLI args are non-registry specs and no `package.json` exists, gyrseek exits 1, blocking a valid local or URL-based install.

**Root cause:** Same filter path as Finding 11. With no `package.json` in the working directory, the fallback returns `Vec::new()`. Back in `lib.rs`, `npm_packages.is_empty()` → `std::process::exit(1)`.

**Failure scenario:** A C++ project that pulls one npm utility runs `gyrseek npm install https://registry.example.com/tool.tgz`. No `package.json` exists. All args filtered → `packages=[]` → fallback fails → `exit(1)`. Valid install blocked.

**Fix direction:** Same as Finding 11 — treat the all-non-registry-args case as a passthrough rather than fail-closed.

---

### Finding 14 — Low | `parsing.rs:880` | ⚠️ Open

**Summary:** A test writes a temp requirements file but only removes it on the success path — assertion failures leave the file on disk.

**Root cause:** `let _ = std::fs::remove_file(req_path)` is placed after the `assert_eq!` calls. A panicking assertion skips the removal.

**Failure scenario:** Any `assert_eq!` in the test panics → temp file accumulates across repeated runs. Low impact in practice (OS temp cleanup handles it) but adds noise in CI.

**Fix direction:** Use `tempfile::NamedTempFile` (already a project dependency), which removes the file automatically on drop.

---

### Finding 21 — High | `sandbox.rs:629` | ⚠️ Open

**Summary:** The container memory limit is hardcoded to 512 MB. Heavy npm/pnpm dependency trees with native compilation (node-gyp, esbuild, swc) routinely exceed this, causing OOM-killed probes and false-positive blocks.

**Root cause:** `build_docker_run_args` appends `"--memory".to_string(), "512m".to_string()` (`sandbox.rs:629–630`) unconditionally. npm packages like `@parcel/watcher`, `esbuild`, `sharp`, or any Python package compiling C extensions can use 1–4 GB during install. A legitimate scan is OOM-killed, the trace is empty, and `scan_packages_versions` fails closed.

**Failure scenario:** A CI pipeline scans `npm install @parcel/watcher`. The container is OOM-killed during native build. gyrseek sees an empty trace → blocks the install → engineer disables gyrseek entirely.

**Fix direction:** Make the memory limit configurable via an env var (e.g. `GYRSEEK_MEM_LIMIT`, default `2g`), or remove the limit and let the container inherit the host Docker daemon limit. At minimum, a generous default like `2g` would cover 95% of packages.

---

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


### Finding 24 — Medium | `sandbox.rs:555` | ⚠️ Open

**Summary:** The post-install artifact scan shell loop spawns 3 child processes (stat, file, head) per discovered file. On a standard `node_modules` tree with 10,000 files, this launches 30,000–40,000 processes, causing the scan phase to take minutes or time out.

**Root cause:** The script at `sandbox.rs:555–559` iterates with a `while read` loop and calls `stat`, `file`, and `head` individually per file:
```sh
find /work -type f 2>/dev/null | while IFS= read -r f; do \
  size=$(stat -c%s "$f" 2>/dev/null || wc -c < "$f" 2>/dev/null); \
  type=$(file -b "$f" 2>/dev/null | head -c 100); \
  content=$(head -c 300 "$f" 2>/dev/null | tr '|' ' '); \
  echo "$f|$size|$type|$content" >> {}; done || true
```
Each invocation forks a new process. On large projects (e.g. a Next.js app with 10k+ `node_modules` files), this creates prohibitive overhead.

**Failure scenario:** `gyrseek npm install next` triggers a post-install artifact scan of 15,000 files. The container times out (default Docker `--stop-timeout` or CI job timeout) before the scan finishes. gyrseek fails closed on an incomplete/empty artifact log, blocking a legitimate install.

**Fix direction:** Replace the per-file shell loop with bulk operations:
```
find /work -type f -exec stat -c '%s|%n' {} + > /tmp/sizes
find /work -type f -exec file -b {} + > /tmp/types
```
Or, more robustly, compile a small Rust helper (`src/artifact_scanner.rs`) that walks the tree and writes the log directly — a single process, no shell overhead, and the delimiter-injection surface (Finding 20) is eliminated at the same time.

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

### Finding 29 — High | `scanning.rs` | ⚠️ Open

**Summary:** `/proc/self/fd/N` evasion and regex anchor bypass via relative paths.

**Root cause:** The `proc_fd_re` regex anchor `^/proc/` is bypassed by `../../proc/self/fd/N` relative paths entering via `open()` (no dirfd) or `openat(AT_FDCWD, ...)`. The relative path flows through `lexical_clean_path` and `is_sensitive_file_read` which tests `ends_with` — neither resolves against `/proc/`.

**Failure scenario:** An attacker opens `../../proc/self/fd/3` which bypasses both the `/proc/` regex anchor and the sensitive file string match.

**Fix direction:** Make `proc_fd_re` accept leading `../` components, or re-lex the path before checking.


---


### Finding 31 — Critical | `sandbox.rs` | ⚠️ Open

**Summary:** `pidfd_open` and `pidfd_getfd` not blocked.

**Root cause:** Missing from seccomp blocklist and strace trace list.

**Failure scenario:** A process can steal file descriptors from a child process using `pidfd_getfd` and read from them without the original path opening being traced to the parent.

**Fix direction:** Block `pidfd_open` and `pidfd_getfd` via seccomp.

---

### Finding 32 — Critical | `scanning.rs` | ⚠️ Open

**Summary:** NUL-byte path truncation bypass in strace path unescaping.

**Root cause:** `unescape_strace_string` converts `\x00` to byte `0`, then `String::from_utf8_lossy` replaces it with `U+FFFD`.

**Failure scenario:** An attacker path like `/etc/passwd\x00harmless.txt` resolves to `/etc/passwd` in the kernel but evades the string suffix match because the rust string contains `\u{FFFD}harmless.txt`.

**Fix direction:** Truncate the unescaped byte string at the first NUL byte before converting to String.

---

### Finding 33 — High | `sandbox.rs`, `scanning.rs` | ⚠️ Open

**Summary:** `execveat` double gap — not in strace trace list AND not in parser regex.

**Root cause:** `execveat` is omitted from the `-e trace=` list in `sandbox.rs`. Additionally, the `parse_execve_argvs` regex in `scanning.rs` only matches `execve(`.

**Failure scenario:** Executing a payload via `execveat` with `AT_EMPTY_PATH` produces zero execve syscalls in the trace and zero argv parsing, leading to a fully invisible detection bypass.

**Fix direction:** Add `execveat` to the strace `-e trace=` list AND extend the regex parser to `(?:execve|execveat)\(`.

---

### Finding 34 — High | `scanning.rs` | ⚠️ Open

**Summary:** Cross-PID `/proc/N/fd/` resolution bypass.

**Root cause:** `proc_fd_re` uses the strace line's PID to resolve the fd instead of the target PID in the `/proc/<pid>/fd/N` path.

**Failure scenario:** A process reading another process's sensitive file descriptor goes undetected because the scanner looks up the fd in the wrong process's table.

**Fix direction:** Extract the target PID from the path and use it for the fd_table lookup.

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

### Finding 40 — High | `scanning.rs` | ⚠️ Open

**Summary:** `/proc/self/fd/N` resolution regex requires absolute path, allowing traversal bypass.

**Root cause:** Regex `^/proc/(?:self|\d+)/fd/` fails on relative paths. The path is sent through `lexical_clean_path` which preserves relative structures like `../../proc`.

**Failure scenario:** An `open(\"../../proc/self/fd/3/passwd\")` never matches the regex anchor. The `is_sensitive_file_read` function fails to match it since it doesn't end with `/etc/passwd`. Additionally, this general lack of path canonicalization allows symlink bypasses: an attacker creates `ln -s /etc/passwd readme.txt` then `cat readme.txt` -> strace logs the symlink path (`readme.txt`), bypassing string matches completely.

**Fix direction:** Classify paths through any known symlink by resolving with `std::fs::canonicalize` before passing to `is_sensitive_file_read`.

---

### Finding 41 — Low | `.github/workflows/ci.yml` | ⚠️ Open

**Summary:** `actions/checkout@v7` moving tag not SHA-pinned.

**Root cause:** All other actions use pinned SHAs, but `actions/checkout` relies on a moving major version tag.

**Failure scenario:** A compromised release to the `v7` ref propagates to all CI jobs without detection.

**Fix direction:** Pin the action to a specific commit SHA.

**Enhancements:**
- **No CI Verification:** There is no CI verification step that the `actions/checkout@v7` SHA matches an expected release. The moving tag could be force-pushed at any time. Fix: Add a step that resolves and pins the SHA automatically or audit it periodically.

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

### Finding 45 — High | `.github/workflows/ci.yml` | ⚠️ Open

**Summary:** CI prompt injection amplification and censorship vector via deduplication instruction.

**Root cause:** 
1. The deduplication instruction at line 295-298 creates a censorship vector.
2. `gh run download` at line 261 lacks `--run-id` or `--repo` scoping.
3. No SHA-256 verification on the downloaded `review_ledger.md`.
4. Bundle `GH_TOKEN` draining across both the consolidation step (line 244) AND the sanitize/post step (line 395).
5. **Ledger LLM output re-injection loop**: The ledger accumulates raw LLM output (`consolidated_gyrseek_review.md`) which is re-injected as `<previous_review>` in the next run. A one-time compromise propagates to all subsequent PRs on the same branch.
6. **Fallback-path poisoning**: When the consolidation LLM exits non-zero, raw untrusted reviewer inputs are concatenated directly into the ledger — bypassing LLM-mediated sanitization.
7. **`WONT_FIX_FINDINGS.md` injected as accepted attack surface**: When injected unsanitized, the LLM is effectively told "these attacks are accepted — do not flag them."


**Failure scenario:** 
1. A PR author adds their vulnerability to `OPEN_FINDINGS.md`, and the consolidation LLM removes it from the report due to the deduplication instruction ("If an incoming finding is already documented… you MUST remove it entirely").
2. A compromised fork uploads a fake `review-ledger` artifact which is picked up cross-run due to missing `--run-id` and `--repo` flags.

**Fix direction:** Fetch findings files from base-branch SHA; add `--repo`/`--run-id` to `gh`; upload/verify `review_ledger.sha256`; scope `GH_TOKEN` strictly; truncate ledger to only finding IDs; write a static "Consolidation failed" message in the fallback path.

**Enhancements:**
- **Broader Injection Surface:** The injection surface is 3×, not 1×. `docs/WONT_FIX_FINDINGS.md` and `docs/OPEN_FINDINGS.md` are also injected unsanitized. A PR author modifying these files can inject arbitrary instructions. Fix: Redact closing tags from these files as well.
- **Artifact Name Confusion:** `gh run download` uses only `--name review-ledger` without `--run-id` or `--repo`. A compromised fork could upload an identically named artifact picked up by consolidation, allowing cross-run prompt injection.
- **Ledger Integrity:** The downloaded `review_ledger.md` has no SHA-256 checksum verification. Any artifact named `review-ledger` is accepted. Fix: Upload a `review_ledger.sha256` artifact and verify with `sha256sum --check` before use.

---

### Finding 46 — Medium | `scanning.rs` | ⚠️ Open

**Summary:** `is_harness_command` `uv` check coupling with sandbox script.

**Root cause:** `is_harness_command` requires `--target` for the `uv` arm to correctly exclude legitimate harness commands. If `sandbox.rs` changes to use `--prefix` or similar, detection silently breaks.

**Failure scenario:** Every legitimate `uv` probe appears as a new process-exec anomaly due to out-of-sync coupling.

**Fix direction:** Add a doc comment in both locations explicitly documenting the coupling.

---

### Finding 47 — Medium | `scanning.rs` | ⚠️ Open

**Summary:** `extract_sensitive_file_reads` requires decomposition.

**Root cause:** The function is 264 lines long and conflates `fd_table` construction, `/proc/N/fd/M` resolution, clone/fork fd inheritance, dup/fcntl tracking, and sensitivity classification.

**Failure scenario:** Increased maintenance burden, higher risk of introducing logic bugs, and poor testability.

**Fix direction:** Extract helper functions like `build_fd_table` and `resolve_proc_fd_path`.

---

### Finding 48 — Medium | `.github/workflows/ci.yml` | ⚠️ Open

**Summary:** CI `gh run download` and `gh run list` silently swallow errors and lack integrity checks.

**Root cause:** The `|| true` on both the `gh run download` and `gh run list` commands hides auth failures, missing artifacts, and network blips. Furthermore, the download path lacks a SHA-256 integrity check.

**Failure scenario:** Failed downloads or listing fail silently, and the downstream `if [ -f ... ]` check gives no diagnostic feedback. Without SHA-256, tampered artifacts are accepted.

**Fix direction:** Log stderr before `|| true`, or explicitly check and log the exit code. Implement SHA-256 artifact verification.

---

### Finding 49 — Medium | `.github/workflows/ci.yml` | ⚠️ Open

**Summary:** CI `GH_TOKEN` in environment for consolidation step increases blast radius.

**Root cause:** `GH_TOKEN` is set globally for a multi-step bash script that iterates over files with `find ... | while read ...`.

**Failure scenario:** If an attacker crafts a filename with shell metacharacters, they could exfiltrate the GitHub token (which has `pull-requests: write`).

**Fix direction:** Drain the token from the environment before file iteration or use a separate step for API calls.

**Enhancements:**
- **Exposure in Multiple Steps:** `GH_TOKEN` is exposed in both the "Consolidate Reviews" step and the "Sanitize and Post Consolidated Comment" step. Fix: Drain token from env before `cmark` processing; scope strictly to `gh` CLI calls via prefix.

---

### Finding 50 — Medium | `README.md` | ⚠️ Open

**Summary:** `sensitive_file_access_allowlist` example is dangerous and semantically wrong.

**Root cause:** The documentation shows `.aws/credentials` and `.env` as example allowlist entries. However, exact-match semantics (`read == allowed`) means `.env` never matches strace's absolute path `/work/.env`.

**Failure scenario:** Users copying the snippet will inadvertently leave their allowlist completely non-functional for those entries, leading to false positives.

**Fix direction:** Change the example to use prefix matching like `*.env` and `*.aws/credentials`, and add a note explaining prefix-matching semantics vs exact-match.

---

### Finding 51 — Medium | `.github/workflows/ci.yml` | ⚠️ Open

**Summary:** Ledger delimiter collision can corrupt review history.

**Root cause:** Python capping logic splits strictly on `"=== REVIEW FROM RUN"`.

**Failure scenario:** If a reviewer's text happens to contain this string, the split generates false fragments and incorrectly truncates valid history.

**Fix direction:** Use a UUID or a highly unpredictable string for the ledger delimiter.

---

### Finding 52 — Medium | `.github/workflows/ci.yml` | ⚠️ Open

**Summary:** Review ledger Python capping drops leading newline.

**Root cause:** `.join([""] + kept)` does not prepend a newline to the reconstructed string.

**Failure scenario:** The formatting of the first review in the truncated ledger is incorrectly stitched.

**Fix direction:** Change `""` to `"\n"` in the Python join statement.

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

### Finding 60 — High | `scanning.rs` | ⚠️ Open

**Summary:** Failed `open()` counted as successful sensitive read (Baseline Poisoning).

**Root cause:** The scanner calls `is_sensitive_file_read` unconditionally on extracted paths before verifying the syscall return value at lines 1346-1350.

**Failure scenario:** An attacker ships v1.0.0 with failed reads on every sensitive path. Since failed opens populate baselines without any allowlist interaction, all seed the baseline. When v1.0.1 reads the same paths successfully (via alternate interfaces), `find_new_sensitive_reads` returns empty since paths are already in the baseline.

**Fix direction:** Skip tracking or separately classify reads where `ret_val < 0`.

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

### Finding 65 — Low | `graphify-out` | ⚠️ Open

**Summary:** `GRAPH_REPORT.md` references stale `docs/FINDINGS.md`.

**Root cause:** The knowledge graph extraction engine retained edges pointing to `docs/FINDINGS.md` even after it was renamed and removed from Git.

**Failure scenario:** AI agents reading the knowledge graph might attempt to read or modify a file that no longer exists.

**Fix direction:** Address graphify's caching mechanism or run a clean rebuild.

---

### Finding 66 — Low | `.github/workflows/ci.yml` | ⚠️ Open

**Summary:** LLM prompt instructs model to suggest holistic fix under attacker influence.

**Root cause:** On loop cycle detection, the LLM is explicitly asked to "suggest a holistic fix that resolves both constraints." Combined with the ledger persisting across runs, this creates an attacker-controlled iterative fix generator.

**Failure scenario:** An attacker can craft review inputs that intentionally induce a cycle and steer the LLM into generating code-level fixes that introduce subtle vulnerabilities.

**Fix direction:** Instruct the LLM to only output a natural language explanation of the cycle, without proposing code-level fixes.

---

### Finding 67 — Medium | `scanning.rs` | ⚠️ Open

**Summary:** Clone/fork fd-inheritance block duplicated verbatim.

**Root cause:** A 12-line fd-inheritance loop appears identically in both the resumed-syscall handler and the initial-syscall handler.

**Failure scenario:** Maintenance trap; updating one but not the other causes the paths to drift out of sync.

**Fix direction:** Extract to `fn inherit_fds(child_pid, parent_pid, fd_table)`.

---

### Finding 68 — Medium | `.github/workflows/ci.yml` | ⚠️ Open

**Summary:** `gh run list` and `download` missing `--repo` flag.

**Root cause:** Commands infer the repository from the git remote, which in a fork PR context may resolve to the fork rather than the canonical repository.

**Failure scenario:** Prevents retrieving artifacts correctly in fork PR scenarios.

**Fix direction:** Scope explicitly with `--repo "${{ github.repository }}"`.

---

### Finding 69 — Medium | `sandbox.rs` | ⚠️ Open

**Summary:** `env_lock` unsafe pattern in tests misses RAII guard.

**Root cause:** Multiple test functions use `env_lock().lock() + unsafe { set_var }` manually without the `EnvVarGuard` that was introduced in `scanning.rs`.

**Failure scenario:** An assertion panic skips the manual teardown, leaking the environment variable and poisoning subsequent tests.

**Fix direction:** Adopt the `EnvVarGuard` pattern in `sandbox.rs` tests.

---

---

---

### Finding 72 — Low | `.github/workflows/ci.yml` | ⚠️ Open

**Summary:** `PR_HEAD_REF` branch name passed to `gh` without validation.

**Root cause:** The branch name `${{ github.event.pull_request.head.ref }}` is interpolated via `${{ }}` which GitHub evaluates before shell execution. Branch names containing `$()`, backticks, or newlines are a YAML injection risk.

**Failure scenario:** Unexpected behavior from the GitHub CLI if the branch name mimics a flag or special path.

**Fix direction:** Use `github.head_ref` which GitHub pre-validates, or sanitize the ref before passing to `gh`.

---



### Finding 75 — High | `scanning.rs` | ⚠️ Open

**Summary:** `openat` relative path bypasses absolute suffix checks in `is_sensitive_file_read`.

**Root cause:** `extract_sensitive_file_reads` resolves `openat(AT_FDCWD, "etc/passwd")` to the relative path `"etc/passwd"`. Because `is_sensitive_file_read` checks `ends_with_any` (which expects leading slashes, e.g., `/.env`) and `exact_match` (which lacks relative handling, e.g., `/etc/passwd`), relative paths fail to match.

**Failure scenario:** Since no CWD tracking exists per PID (because `chdir`/`fchdir` syscalls are not intercepted), an attacker postinstall script can simply call `chdir("/")` followed by `open("etc/passwd")`. This produces the path `"etc/passwd"` in strace, completely bypassing all detection. This also applies to `open("passwd")` from cwd `/etc`.

**Fix direction:** Track cwd per PID by adding `chdir`/`fchdir` to the strace trace set. For `openat(AT_FDCWD, ...)` and `open(...)` with relative paths, resolve against the tracked cwd before passing to `is_sensitive_file_read`.

---
