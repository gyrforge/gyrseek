# Architecture

## Goal
gyrseek is a command-wrapper CLI that evaluates dependency installation network behavior before allowing the original package-manager command to proceed.

## Runtime Entry Flow
1. The binary entrypoint in src/main.rs collects CLI args and calls run in src/lib.rs.
2. The run function in src/lib.rs routes by manager and subcommand.
3. Supported command paths are either:
   - single-target scans (for example uv add pkg)
  - bulk scans (for example uv sync, uv pip sync, uv lock update flags, poetry install or poetry update, pip or pip3 install with multiple targets, npm install or npm i or npm update)
4. If detection and scanning pass, the command is forwarded. For explicit unpinned install targets (for example npm install pkg, pip install pkg) the forwarded command is rewritten to pin the exact version that was scanned; lockfile/manifest-driven flows (uv sync, uv pip sync, uv lock, poetry install/update) are forwarded verbatim because the lockfile already pins versions.
5. If anomaly or required detection failure occurs, execution exits non-zero (fail-closed). If the host command itself cannot be spawned after a clear scan, gyrseek also fails closed. If a sandbox probe yields an empty/whitespace trace (e.g. strace could not attach), that is a hard error and the whole batch is blocked — a blank trace is never treated as a clean install.
6. When the host command is forwarded, gyrseek waits on the child and exits with the child's own status, so a non-zero host install is reported as non-zero rather than masked as success.

## Core Components
- Command parsing:
  - parse_package_details extracts package and optional version for single-target commands.
- Bulk source parsing:
  - parse_uv_lock_packages_from_content parses uv.lock package entries.
  - parse_poetry_lock_packages_from_content parses poetry.lock package entries.
  - parse_requirements_packages_from_content parses requirements-style entries. PEP 508 extras are stripped from the canonical package name (strip_pep508_extras) so registry lookups and the version-pin map key use `requests`, not `requests[security]`; the forwarded install command still carries the full extras-qualified spec.
  - parse_pylock_packages_from_content parses pylock package entries.
  - parse_pip_install_packages_from_args resolves package targets from pip or pip3 install args, including -r or --requirements files.
  - parse_npm_install_packages_from_args resolves npm targets from explicit args or package.json when no explicit target is given.
  - parse_uv_lock_upgrade_packages_from_args resolves update targets from uv lock -P or --upgrade-package arguments.
- Version history lookup:
  - fetch_history_with_baselines queries PyPI for Python packages and the npm registry for npm packages.
  - Version lists are ordered semantically: semver for npm, PEP 440 for Python managers (compare_version_strings / sort_versions_ascending). Unparseable strings sort below any parseable version, so junk is never resolved as `latest`.
  - npm `time` map parsing (npm_published_times) excludes the `created`/`modified` bookkeeping keys and any non-version key, so the release-burst counter is not inflated.
- Behavior capture:
  - trace_sandbox_install_matrix runs via SandboxRunner backend and captures, per package-version: connection IPs (IPv4 via inet_addr and IPv6 via inet_pton, normalized to canonical form by extract_connection_ips), install-time git clone command signatures, and watched-process execution signatures (extract_process_exec_signatures: `exe|arg1|...` for watched runtimes such as bun/deno).
  - strace runs with `-s 4096 -v` (no argv/address truncation) and `-u <scanner-user>` so the traced install payload runs unprivileged while strace and its root-owned /out trace logs remain tamper-resistant.
  - execve argv parsing (extract_process_exec_signatures / git-clone signature extraction) uses a balanced-bracket-aware regex so arguments containing `]` (e.g. PEP 508 extras `requests[security]`, paths like `script[obf].js`) are captured intact rather than truncated at the first `]`.
  - The Docker container is run with `--cap-add SYS_PTRACE`: strace runs as root but attaches to the install running as the unprivileged scanner user, and cross-UID ptrace requires CAP_SYS_PTRACE (not in Docker's default capability set). The capability is scoped to the container PID namespace and cannot trace host processes.
  - strace's own stderr is captured to a per-probe `/out/gyrseek_err_N.log` (not `>/dev/null 2>&1`); `|| true` is retained only so a single failing install does not abort sibling probes. A genuine attach failure produces a blank trace log, which the reader turns into a hard error (fail closed) carrying the captured stderr.
  - Docker backend can execute probe matrices (multiple packages with their current and baseline versions) in one container session.
  - build_runner_from_env selects backend mode (`docker` default, `host` fallback).
- Anomaly decision:
  - find_new_connections returns endpoints seen in current but not in baseline.
  - The `domain_allowlist` uses forward-confirmed reverse DNS (FCrDNS): reverse_dns_domain resolves the PTR hostname and only trusts it if its forward A/AAAA resolution includes the original IP (decision extracted into forward_confirmed_hostname for deterministic testing). A spoofed PTR record pointing at an allowlisted domain therefore cannot bypass the allowlist. New IPs remain fail-closed regardless.
  - install-time git clone signatures are diffed across current and baseline versions; newly introduced clone behavior is fail-closed unless allowlisted.
  - watched-process execution signatures (default bun/deno) are diffed across versions; a newly introduced or changed/extra invocation is fail-closed unless allowlisted (process_exec_allowlist). This targets the Shai-Hulud "download Bun and run a hidden payload" class of attack.
- In-run optimization:
  - run keeps an in-memory cache keyed by manager/package/version to avoid repeating identical scans in one execution.

## Decision Model
For each scanned package:
1. Determine current target version (explicit, or `latest` resolved via semantic ordering).
2. Resolve baseline versions (v-1 and v-2 where available, ordered semantically).
3. Collect behavior signals for current and baseline installs (network endpoints, install-time git clone signatures, and watched-process execution signatures).
4. Compute set differences current minus baseline for each signal type.
5. Apply allowlists (`ip_allowlist`, `domain_allowlist`, `git_clone_allowlist`, `process_exec_allowlist`).
6. If non-allowlisted differences remain, block command.

## Fail-Closed Policy
gyrseek fails closed in the following situations:
- Unrecognized manager: the first argument is not one of `pip`, `pip3`, `uv`, `poetry`, `npm`. Any other value (e.g. `ls`, `curl`, `sh`) exits 1 with a diagnostic. The only built-in exception is `sandbox runtimes`. Previously, unrecognized managers were silently forwarded unscanned, which violated the tool's "I scanned this before forwarding it" contract.
- Package detection is expected for a supported install or sync flow but no package entries are detected.
- Trace is empty or missing (strace produced no output — e.g. ptrace blocked).
- Sandbox initialization fails.

## Current Limitations
- Version ordering is semantic-version aware (semver for npm, PEP 440 for Python); unparseable versions fall back to sorting below parseable ones.
- Version pinning of the forwarded command applies only to explicit unpinned install targets; lockfile-driven flows rely on the lockfile's own pins.
- Direct runtime interception for standalone `git clone ...` commands is not enabled yet.
- Docker mode assumes Docker CLI availability; host mode assumes strace availability and is less safe. The unprivileged-payload (`strace -u`) trace-integrity protection applies to the Docker/microvm backends. Docker mode requires `CAP_SYS_PTRACE` (added via `--cap-add`) for cross-UID tracing; environments that strip it (some K8s/seccomp setups) will fail closed rather than pass silently.
- Trace extraction still assumes current strace output patterns.
- Behavioral signals (network, git clone, watched-process execution) are only captured for what executes during the sandbox install. Payloads that fire outside the install window (e.g. the PyPI `*-setup.pth` startup-execution variant) may not detonate during the scan.
- Watched-process detection covers a curated runtime set (default bun/deno) rather than all process execution, to keep false positives low.

## Main Files
- src/main.rs: binary entrypoint
- src/lib.rs: routing and enforcement orchestration
- src/parsing.rs: command, lockfile, and requirements parsing
- src/scanning.rs: registry history lookup and behavior scanning
- src/sandbox.rs: sandbox backend abstraction and mode selection
- tests/parser_tests.rs: parser behavior coverage
- tests/behavior_tests.rs: anomaly decision simulation coverage
- tests/git_clone_behavior_tests.rs: git-clone simulation coverage
- tests/git_clone_scan_tests.rs: install-time git-clone signature diff coverage
- tests/forward_fail_closed_tests.rs: fail-closed coverage when the host command cannot be spawned, plus host exit-status propagation (non-zero and success)
- tests/bun_exec_scan_tests.rs: watched-process (bun/deno) execution diff coverage (new bun, bun+extra, identical, allowlisted)
- src/scanning.rs (unit tests): semantic version ordering, IPv4/IPv6 trace extraction, npm time-map release-burst filtering, watched-process signature extraction/diff/allowlist, bracketed-argv preservation, FCrDNS forward-confirmation decision
- src/sandbox.rs (unit tests): strace no-truncation flags, unprivileged-payload trace integrity, docker arg construction, SYS_PTRACE capability, strace-stderr capture
- src/parsing.rs (unit tests): PEP 508 extras stripping, extras-aware version pinning, poetry local directory-source exclusion (develop and non-develop)
- tests/parser_tests.rs also covers forwarded-command version pinning (rewrite_args_with_pinned_versions)
