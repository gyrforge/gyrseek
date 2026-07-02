# Open Findings - Detailed

*This document contains the detailed root-cause analyses for open findings. For the brief overview, see [OPEN_FINDINGS.md](./OPEN_FINDINGS.md).*

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

### Finding 178 — Critical | `sandbox.rs` | ⚠️ Open

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
- **Skill File Injection Vector:** The new skill file injection block (added to fix dead skill references) uses four `cat` blocks (`.github/workflows/ci.yml:157-207`) to inject skill content into `<code_security_skill>`, `<llm_security_skill>`, `<ponytail_skill>`, and `<ponytail_review_skill>` tags without `</tag> → <REDACTED>` escaping. This expands the injection surface by 4 additional XML injection points outside `<untrusted_diff>`. Additionally, the content is read from the PR workspace (`actions/checkout` of PR head), not the base ref. A PR modifying `code-security/SKILL.md`, `llm-security/SKILL.md`, `ponytail/SKILL.md`, or `ponytail-review/SKILL.md` can embed arbitrary instructions ("Ignore all vulnerabilities") that are implicitly trusted as authoritative security guidance. Fix: Apply `</tag> → <REDACTED>` escaping to all 4 skill content blocks before injection; read the skill files strictly from the base branch (e.g., `git show origin/${{ github.base_ref }}:.github/skills/$skill/SKILL.md`). Note that relying on CODEOWNERS is insufficient, as CODEOWNERS only blocks PR merges but does not prevent CI data-flow attacks from the PR workspace during the review run itself.
- **Review Ledger Tag-Escaping Gap and Persistence:** `cat review_ledger.md` (`.github/workflows/ci.yml:406`) writes raw LLM output inside `<previous_review>` without closing-tag redaction, unlike `<untrusted_diff>` (line 226) and `<untrusted_inputs>` (line 435). A compromised review entry in the ledger can break the prompt structure. Furthermore, final assembly (`ci.yml:458-459`) uses `cat consolidated_gyrseek_review.md >> review_ledger.md` to append raw LLM output to the ledger without closing-tag redaction. This persistence means a one-time compromise propagates to all subsequent PRs on the same branch via capped-run persistence by re-introducing injection markers (`</previous_review>`, `SYSTEM:`). Fix: Apply closing-tag redaction (`python3 -c "import sys; print(sys.stdin.read().replace('</previous_review>', '<REDACTED>'))"`) before injecting the ledger and before appending to it.
- **Unsanitized File Content in XML Tags:** `AGENTS.md` (in `<agents_rules>`), `WONT_FIX_FINDINGS.md` (in `<wont_fix_findings>`), `OPEN_FINDINGS.md` (in `<open_findings>`), and `graphify-out/GRAPH_REPORT.md` (in `<graph_context>`) are all catted into `prompt.txt` (`.github/workflows/ci.yml:408-427`) inside XML tags without closing-tag redaction. The `<graph_context>` specifically cats `GRAPH_REPORT.md` generated from the PR workspace (not base ref), compounding the vector. This creates a total of 9 untagged XML injection points (5 in the consolidation prompt: `previous_review`, `wont_fix_findings`, `open_findings`, `agents_rules`, `graph_context`; and 4 skill tags in the first-stage prompt). Any PR modifying these files can inject arbitrary instructions by embedding a closing tag. Fix: Apply closing-tag redaction to every file catted into an XML context.
- **Consolidation Fallback Silent Errors:** `cat all_reviewer_inputs.md >> consolidated_gyrseek_review.md 2>/dev/null || true` (`ci.yml:442, 454`) silently discards I/O and missing file errors. Fix: Replace with `test -f all_reviewer_inputs.md && cat ... || echo "::error::fallback file missing"`.

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

### Finding 48 — High | `.github/workflows/ci.yml` | ⚠️ Open

**Summary:** CI commands silenced with `|| true` and `>/dev/null 2>&1` create blind spots and swallow errors.

**Root cause:** The `|| true` combined with output redirection (`>/dev/null 2>&1`) on `gh run download`, `gh run list`, and `graphify update .` hides auth failures, missing artifacts, tool failures, and network blips by silencing ALL diagnostics (stdout, stderr, AND exit code). Furthermore, the download path lacks a SHA-256 integrity check. The consolidation fallback `cat all_reviewer_inputs.md >> consolidated_gyrseek_review.md 2>/dev/null || true` expands this pattern to two locations (`ci.yml:442, 454`), silently swallowing missing-file and I/O errors.

**Failure scenario:** Failed downloads or tool executions fail silently. Graphify failures inject stale or missing graph content with no diagnostic. In the two fallback paths, the `|| true` swallows the error and produces an empty/partial review with no `::error` or `::warning` diagnostic. Every command silenced this way is a complete observability blind spot.

**Fix direction:** Capture stderr before `|| true` and emit `::error` on failure. At a minimum, remove `2>&1`. Implement SHA-256 artifact verification. For the consolidation fallback `cat` in both locations, add a presence check (`test -f`) and emit an `::error` when the file is missing.

---

### Finding 49 — Medium | `.github/workflows/ci.yml` | ⚠️ Open

**Summary:** CI `GH_TOKEN` in environment for consolidation step increases blast radius.

**Root cause:** `GH_TOKEN` is set globally for a multi-step bash script that iterates over files with `find ... | while read ...`.

**Failure scenario:** If an attacker crafts a filename with shell metacharacters, they could exfiltrate the GitHub token (which has `pull-requests: write`).

**Fix direction:** Drain the token from the environment before file iteration or use a separate step for API calls.

**Enhancements:**
- **Exposure in Multiple Steps:** `GH_TOKEN` is exposed in both the "Consolidate Reviews" step and the "Sanitize and Post Consolidated Comment" step. Fix: Drain token from env before `cmark` processing; scope strictly to `gh` CLI calls via prefix.

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



---

---

### Finding 72 — Low | `.github/workflows/ci.yml` | ⚠️ Open

**Summary:** `PR_HEAD_REF` branch name passed to `gh` without validation.

**Root cause:** The branch name `${{ github.event.pull_request.head.ref }}` is interpolated via `${{ }}` which GitHub evaluates before shell execution. Branch names containing `$()`, backticks, or newlines are a YAML injection risk.

**Failure scenario:** Unexpected behavior from the GitHub CLI if the branch name mimics a flag or special path.

**Fix direction:** Use `github.head_ref` which GitHub pre-validates, or sanitize the ref before passing to `gh`.

---



### Finding 78 — High | `.github/workflows/ci.yml:449` | ⚠️ Open

**Summary:** `grep -qi "^# consolidated review"` creates XML injection gate and silent pass.

**Root cause:** The `-i` flag combined with `2>/dev/null` creates an unauthenticated XML injection gate into `<previous_review>` via casing bypass (e.g., `# CONSOLIDATED REVIEW`). Additionally, the `2>/dev/null` allows a missing file to silently pass the check (exit 0 from grep on non-existent file), which is more dangerous than case-insensitivity.

**Failure scenario:** If the LLM generates a malformed header, or an attacker injects a mixed-case bypass, or the file goes missing, the check will pass and inject corrupted, attacker-controlled, or empty review content into the ledger.

**Fix direction:** Add a `if [ ! -f consolidated_gyrseek_review.md ]; then exit 1; fi` guard before the grep check. Remove the `-i` flag to enforce exact case, and do not swallow stderr so failures are visible.

---

### Finding 79 — High | `lib.rs:133` | ⚠️ Open

**Summary:** `parse_list_map` lacks tests for exploitable edge cases.

**Root cause:** `parse_list_map` is the central trust boundary for all 4 allowlist types (`process_exec_allowlist`, `artifact_allowlist`, `git_clone_allowlist`, `sensitive_file_access_allowlist`), but lacks inline tests. Untested edge cases create exploitable parser-level attacks: colon injection in values (`C:\Users\...` splits on wrong delimiter), comma injection in package names, and empty-value collapsing (`package:` produces `[""]` which downstream empty-string matches bypass all allowlist entries).

**Failure scenario:** Edge cases in parsing break allowlist boundaries. **Coupled Vulnerability (F77 + F79):** A `parse_list_map` bug that flattens all allowlist keys into a single global key, combined with the missing cross-package isolation test (Finding 77), creates a concrete attack chain: an operator adds `package-b` to `sensitive_file_access_allowlist` for `~/.aws/credentials`, and the parser bug silently grants that exemption to a malicious `package-c` as well.

**Fix direction:** Add comprehensive inline unit tests for `parse_list_map` covering colons, commas, empty values, and strict key isolation.

---

### Finding 80 — Low | `.github/workflows/ci.yml:163` | ⚠️ Open

**Summary:** Symlink TOCTOU race for `.github/skills/`.

**Root cause:** The symlink `.github/skills/` → `.agents/skills/` is checked at workflow start but could be swapped before `cat`.

**Failure scenario:** A malicious PR or concurrent process could modify the symlink target to redirect `cat` to read arbitrary files (e.g., repository secrets stored on disk) and inject them into the LLM context.

**Fix direction:** Use `.agents/skills/` directly instead of following the symlink, since the workflow has its own checkout of `.agents/skills/`.

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


---

### Finding 34 — High | `scanning.rs` | ⚠️ Open

**Summary:** Cross-PID `/proc/N/fd/` resolution bypass.

**Root cause:** `proc_fd_re` uses the strace line's PID to resolve the fd instead of the target PID in the `/proc/<pid>/fd/N` path.

**Failure scenario:** A process reading another process's sensitive file descriptor goes undetected because the scanner looks up the fd in the wrong process's table.

**Fix direction:** Extract the target PID from the path and use it for the fd_table lookup.

---

---

### Finding 40 — High | `scanning.rs` | ⚠️ Open

**Summary:** `/proc/self/fd/N` resolution regex requires absolute path, allowing traversal bypass.

**Root cause:** Regex `^/proc/(?:self|\d+)/fd/` fails on relative paths. The path is sent through `lexical_clean_path` which preserves relative structures like `../../proc`.

**Failure scenario:** An `open(\"../../proc/self/fd/3/passwd\")` never matches the regex anchor. The `is_sensitive_file_read` function fails to match it since it doesn't end with `/etc/passwd`. Additionally, this general lack of path canonicalization allows symlink bypasses: an attacker creates `ln -s /etc/passwd readme.txt` then `cat readme.txt` -> strace logs the symlink path (`readme.txt`), bypassing string matches completely.

**Fix direction:** Classify paths through any known symlink by resolving with `std::fs::canonicalize` before passing to `is_sensitive_file_read`.

---

---

### Finding 75 — High | `scanning.rs` | ⚠️ Open

**Summary:** `openat` relative path bypasses absolute suffix checks in `is_sensitive_file_read`.

**Root cause:** `extract_sensitive_file_reads` resolves `openat(AT_FDCWD, "etc/passwd")` to the relative path `"etc/passwd"`. Because `is_sensitive_file_read` checks `ends_with_any` (which expects leading slashes, e.g., `/.env`) and `exact_match` (which lacks relative handling, e.g., `/etc/passwd`), relative paths fail to match.

**Failure scenario:** Since no CWD tracking exists per PID (because `chdir`/`fchdir` syscalls are not intercepted), an attacker postinstall script can simply call `chdir("/")` followed by `open("etc/passwd")`. This produces the path `"etc/passwd"` in strace, completely bypassing all detection. This also applies to `open("passwd")` from cwd `/etc`.

**Fix direction:** Track cwd per PID by adding `chdir`/`fchdir` to the strace trace set. For `openat(AT_FDCWD, ...)` and `open(...)` with relative paths, resolve against the tracked cwd before passing to `is_sensitive_file_read`.

---

---

### Finding 76 — High | `scanning.rs:1753-1768` | ⚠️ Open

**Summary:** Missing inline test for insufficient_baselines fail-closed.

**Root cause:** No inline test asserts the `insufficient_baselines` blocked_reason. The related test `scan_fails_closed_when_one_baseline_trace_is_missing` tests `sandbox_trace_missing` only. 

**Failure scenario:** A regression in `insufficient_baselines` means a package with 0 baselines and no `new_package_exemptions` bypass passes through, producing an empty `TraceSignals` diff (trivially passing all anomaly checks).

**Fix direction:** Add explicit inline tests targeting the `insufficient_baselines` blocked reason. The tests should assert both: "0 baselines + no exemption → blocked" AND "0 baselines + wildcard exemption → allowed."

---

---

### Finding 77 — High | `scanning.rs:1363-1385` | ⚠️ Open

**Summary:** Missing cross-package isolation test for `sensitive_file_access_allowlist`.

**Root cause:** While tests exist for `process_exec_allowlist`, `artifact_allowlist`, and `git_clone_allowlist`, there is no test for `filter_allowlisted_sensitive_reads` demonstrating that an allowlist entry for one package does not leak and allow access for another package.

**Failure scenario:** A bug in the allowlist evaluation could allow any package to read a sensitive file if *any* package in the config is allowed to read it.

**Fix direction:** Add tests verifying isolation and exact matching behavior for `sensitive_file_access_allowlist`.

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

### Finding 177 — Low | `*_DETAILED.md` | ⚠️ Open

**Summary:** Duplicate summary tables create a two-source-of-truth maintenance burden.

**Root cause:** The `_DETAILED.md` files begin with an exact copy of the summary table from the main files, requiring agents to perfectly synchronize both files on every update.

**Failure scenario:** Agents often fail to update the detailed file's summary table, causing checklist drift and contradictory documentation states.

**Fix direction:** Consider a future consolidation where the detailed file omits the summary table entirely, leaving the main file as the single source of truth for the index.


---

### Finding 180 — Low | `lib.rs:1092-1173` | ⚠️ Open

**Summary:** `bulk_scan!` macro spans 3 packaging ecosystems — a regression in one leaks to all.

**Root cause:** The `bulk_scan!` macro is used to deduplicate the routing logic for multiple package managers (pip, npm, pnpm, uv sync). However, this creates tight coupling. A change or bug in one package manager's handling can easily break the others or introduce subtle bugs due to shared macro expansion.

**Failure scenario:** Modifying the macro to fix an npm-specific issue accidentally breaks pip argument extraction, causing pip scans to fail open or fail closed silently, and tests for pip might not catch the side-effect if not comprehensive.

**Fix direction:** Replace the macro with explicit typed per-ecosystem functions (`bulk_scan_pip`, `bulk_scan_npm`, etc.) to isolate the logic.

---

### Finding 23 — Medium | `sandbox.rs:191` | ⚠️ Open

**Summary:** Host mode selected silently — no stderr warning that sandbox protection is disabled.

**Root cause:** When `GYRSEEK_SANDBOX=host`, the sandbox mode is selected without any visible warning to the operator. A misconfiguration or accidental environment variable inheritance can leave users unprotected without knowing it.

**Failure scenario:** A developer running gyrseek in host mode (e.g. via a CI environment that sets `GYRSEEK_SANDBOX=host`) has no indication that the sandbox is disabled and that a malicious package can execute on the host.

**Fix direction:** Emit a prominent stderr warning when host mode is selected, ideally printing to stderr before any scan begins.

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

### Finding 269 — High | `parsing.rs:346-348,506-507` | ⚠️ Open

**Summary:** TOCTOU: requirements files and package.json are read eagerly at parse time; the sandbox and forwarded command use the live filesystem.

**Root cause:** `parse_pip_install_packages_from_args` reads `-r` requirement files at parse time; `parse_npm_install_packages_from_args` reads `package.json` at parse time. The sandbox probe and the forwarded install command execute later against the live filesystem. A file swap between parse and install causes the scanned package list to differ from what actually gets installed.

**Failure scenario:** An attacker with write access to the working directory swaps `requirements.txt` after gyrseek reads it but before the forwarded `pip install` runs, causing an unscanned package to be installed.

**Fix direction:** Either snapshot the file contents at parse time and pass them to the sandbox and forwarder, or re-read the files immediately before forwarding and compare against the parsed snapshot, failing closed on any diff.

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

### Finding 283 — Low | `lib.rs:289-298,311-320` | ⚠️ Open

**Summary:** `release_burst_threshold` and `minimum_release_age_package` match blocks contain redundant `None => None` arms.

**Root cause:** Both match blocks have the pattern `Some(v) => Some(v), None => None`, which is semantically identical to `v => v` (or just removing the match entirely and using the value as-is). The `None => None` arm is dead code that adds noise without functionality.

**Failure scenario:** No correctness impact. Maintenance hazard: a future contributor adding another arm may not notice the redundancy and introduce inconsistent handling.

**Fix direction:** Simplify each match to `Some(0) => { warn; None }, v => v` (collapsing `Some(v) => Some(v)` and `None => None` into a single wildcard arm).

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

**Summary:** `new_package_exemptions` list→map format change has no deprecation window; operators upgrading encounter a hard config-parse error with no migration path documented in release notes.

**Root cause:** FIXED_FINDINGS #239 replaced silent list-format acceptance with a hard config-parse error. This is correct security behaviour (the old list format mapped entries to `""` versions, creating a no-op bypass). However, operators upgrading gyrseek with an existing `gyrseek.yaml` using the old `- pkg` list syntax will get an immediate hard parse error on startup with no mention of how to migrate. Release notes have not been updated to call this out.

**Failure scenario:** An operator upgrades gyrseek in CI, their `gyrseek.yaml` uses the old list format, gyrseek refuses to start with a config-parse error, and the CI pipeline breaks with no actionable message beyond the error text.

**Fix direction:** Document the breaking change prominently in the changelog/release notes with the migration instruction: replace `- pkg` list entries with `pkg: "<version>"` map entries.

---

### Finding 289 — Medium | `scanning.rs:6628-6681` | ⚠️ Open

**Summary:** `scan_packages_versions_discards_overrides_when_registry_fails` test makes a real HTTP request to PyPI, failing in offline CI.

**Root cause:** The test sets `GYRSEEK_TEST_LOCK_ONLY=1` but this env var is not listed in `active_test_env_vars()` (which only knows `GYRSEEK_TEST_FORCE_BASELINE_AGES_HOURS`, `GYRSEEK_TEST_FORCE_RELEASES_LAST_24H`, `GYRSEEK_TEST_FORCE_CURRENT_RELEASE_AGE_DAYS`, `GYRSEEK_TEST_ECHO_MIN_BASELINE_AGE_HOURS`) and is never read by `fetch_history_with_baselines`. The test comment at line 6654 explicitly states: "fetch_history_with_baselines will attempt to query PyPI for `gyrseek-test-nonexistent-pkg`. It will fail (404), returning empty `published_at`." This is a deliberate network call, not a mocked one.

**Failure scenario:** Running `cargo test` in an offline CI environment (no internet access) causes `fetch_history_with_baselines` to hang or fail with a connection error rather than a 404, causing the test to panic with an unexpected error rather than the expected `insufficient_baselines` outcome.

**Fix direction:** Intercept the registry fetch using the existing test env var mechanism (`GYRSEEK_TEST_FORCE_BASELINE_AGES_HOURS=""` or similar) to simulate an empty response without a real network call, or add `GYRSEEK_TEST_EMPTY_REGISTRY` to `active_test_env_vars()` and handle it in `fetch_history_with_baselines`.

---

### Finding 291 — Low | `AGENTS.md:186` | ⚠️ Open

**Summary:** AGENTS.md instructs agents to "keep the summary tables synced across both the main and detailed files" but the detailed files no longer have summary tables.

**Root cause:** The AGENTS.md post-change policy at line 186 says: "Remember to keep the summary tables synced across both the main and detailed files." The summary tables in FIXED_FINDINGS_DETAILED.md and OPEN_FINDINGS_DETAILED.md were removed in a prior PR. The instruction now refers to tables that do not exist, potentially causing agents to attempt to maintain phantom tables or misunderstand the document structure.

**Failure scenario:** An agent following AGENTS.md instructions adds a summary table row to OPEN_FINDINGS_DETAILED.md (which has no such table), creating an inconsistency in the detailed file format.

**Fix direction:** Update AGENTS.md line 186 to remove the reference to summary tables in detailed files, clarifying that only the main `*_FINDINGS.md` files have summary tables.

---

### Finding 292 — Low | `README.md:434` | ⚠️ Open

**Summary:** `min_baseline_age_hours` config table says values below 24h are "silently clamped" but the code emits an explicit warning — not silent.

**Root cause:** README.md line 434 reads: "Values below 24h are silently clamped to the 24h security floor." The code at `src/lib.rs:258-262` emits: `"⚠️ [gyrseek] Warning: min_baseline_age_hours for '{}' is set to {} hours, which is below the hardcoded security floor. Automatically raising it to {} hours."` — a visible `println!` warning. The word "silently" is inaccurate.

**Failure scenario:** An operator reading the README expects no feedback when their value is clamped, and may miss the warning in their logs thinking it is expected behaviour.

**Fix direction:** Change "silently clamped" to "clamped (with a warning)" in the README config table row.

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

### Finding 298 — Low | `AGENTS.md:128` | ⚠️ Open

**Summary:** AGENTS.md claims the `min_baseline_age_hours` security floor is "enforced in all three code paths of `fetch_history_with_baselines`" but the floor enforcement lives entirely at config-parse time in `src/lib.rs:257-262`. The value arrives at `fetch_history_with_baselines` already clamped; the function has no inline `HARD_MINIMUM_AGE_HOURS` check.

**Root cause:** FIXED #247 centralized floor enforcement to config-parse time (correct change), but the AGENTS.md documentation was not updated to reflect the new enforcement location. The phrase "all three code paths of `fetch_history_with_baselines`" is stale and points maintainers to the wrong place when reasoning about where the guarantee lives.

**Failure scenario:** A maintainer searching for the floor enforcement to audit or extend it looks inside `fetch_history_with_baselines` (as AGENTS.md instructs), finds no floor check, and either concludes the enforcement is missing or adds a redundant inline check — diverging from the actual enforcement point at lib.rs.

**Fix direction:** Update AGENTS.md line 128 to say the floor is enforced at config-parse time in `src/lib.rs:257-262`; the clamped value is passed through to `fetch_history_with_baselines` and no inline check is needed there.

---

### Finding 299 — Low | `docs/FIXED_FINDINGS.md:137` / `docs/WONT_FIX_FINDINGS.md:74` | ⚠️ Open

**Summary:** Finding number 252 is used in both FIXED_FINDINGS.md and WONT_FIX_FINDINGS.md, violating the flat numeric namespace convention. FIXED #252 is the IPv6 TCP test regression (never actually fixed — see OPEN #275). WONT_FIX #252 is the false-positive claim about a 530-word table row.

**Root cause:** The flat numeric namespace is supposed to have no collisions across all three finding categories. The WONT_FIX #252 entry was filed without checking whether #252 was already taken in FIXED_FINDINGS.md.

**Failure scenario:** A reference to "finding 252" is ambiguous — it could mean either entry depending on which file the reader is looking at.

**Fix direction:** Renumber WONT_FIX #252 to the next available ID (currently 300). Update all cross-references.
