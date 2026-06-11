# Agents Memory and Workflow

## Purpose
This file stores persistent working memory and agent instructions for this repository.

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- Dirty graphify-out/ files are expected after hooks or incremental updates; dirty graph files are not a reason to skip graphify. Only skip graphify if the task is about stale or incorrect graph output, or the user explicitly says not to use it.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- When the user types `/graphify`, invoke the `skill` tool with `skill: "graphify"` before doing anything else.
- Always rerun `/graphify` via `graphify update .` after every code change to keep graph artifacts current before handing off or committing (AST-only, no API cost).

## Repository Memory
- Project name: gyrseek
- Language: Rust
- Entry points:
  - src/main.rs (binary entrypoint)
  - src/lib.rs (command routing and orchestration)
  - src/parsing.rs (parsing helpers)
  - src/scanning.rs (registry lookup and anomaly scanning)
  - src/sandbox.rs (sandbox runner backends and mode selection)
- Build and scripts:
  - Justfile is the task runner entrypoint; run `just --list` to see recipes
  - just build — release build (cargo build --release)
  - just install — install gyrseek with cargo install --path . --locked
  - just fmt — format Rust code
  - just lint — cargo test --all-features --locked + clippy all targets/features + format check; run before committing
  - just test-{npm,pip,uv,poetry} — end-to-end tests per manager using the release binary; require Docker
- Test strategy:
  - All unit and integration tests that do not require spawning the compiled binary live inline in their src/ module under `#[cfg(test)]` — this follows Rust convention and lets tests access private items directly
  - Only tests that need to spawn the real binary (CLI exit-code checks, forward behavior) remain in tests/ as integration test files
  - Run with cargo test or just lint
  - src/scanning.rs (inline) — version ordering, IPv4/IPv6 trace extraction (sandbox-local IP filtering, IPv4-mapped `::ffff:` collapse, cloud-metadata-IP preservation), burst filtering, FCrDNS (forward_confirmed_hostname), bracketed-argv preservation, watched-process (bun/deno) detection and allowlisting, git-clone signature diffing, network anomaly detection, DNS enrichment, IP/domain allowlist filtering (including IPv4-mapped/bare-IPv4 equivalence), internal-package-exemption skip, git-clone simulation; test RAII via `EnvVarGuard` (holds `env_lock` + sets/removes env var on drop, recovers from poison)
  - src/sandbox.rs (inline) — SYS_PTRACE capability in docker args, strace-stderr capture, no-truncation flags, unprivileged-payload integrity
  - src/parsing.rs (inline) — PEP 508 extras stripping (strip_pep508_extras), extras-aware pinning, poetry local directory-source exclusion, rewrite_args_with_pinned_versions (including the `latest`-pin guard so a skipped internal package is not rewritten to an invalid `name==latest`/`name@latest`), lockfile/requirements/npm parsing for all managers
  - src/lib.rs (inline) — GyrSeek::parse_package_details for all supported managers and subcommands; config parsing for new_package_exemptions and internal_package_exemptions; `run()` refactored with `bulk_scan!` macro (four explicit-list branches), `ForwardMode` enum, `scan_targets` wrapper, `exit_with(msg) -> !` helper
  - tests/cli_burst_exit_tests.rs — release burst threshold and minimum_release_age_package CLI exit-code behavior (spawns binary)
  - tests/forward_fail_closed_tests.rs — fail-closed when forwarding to a missing host binary, host exit-status propagation (spawns binary; uses a fake `uv venv` passthrough vehicle in a temp dir)
  - tests/lock_routing_tests.rs — bare `poetry lock` and `uv lock` reach the lockfile-scan branch (fail closed with no lockfile), and `uv venv` stays an unscanned passthrough (spawns binary)
  - tests/version_flag_tests.rs — `--version`/`-V` prints the crate version and exits 0; a forwarded command's own trailing `--version` is not intercepted (spawns binary)
- Collaboration docs:
  - docs/ARCHITECTURE.md
  - docs/DEV_GUIDE.md
  - docs/ROADMAP.md
- Current behavior highlights:
  - Supports uv add, uv pip install, uv pip sync, uv sync, uv lock (bare and update flags), pip/pip3 install, poetry add/update/install/lock, npm install/i/update
  - `--version`/`-V` is handled as a leading top-level flag before config load or sandbox init: prints `gyrseek <CARGO_PKG_VERSION>` and exits 0 (works with no config file / no Docker). Only the first arg is matched, so a forwarded command's own `--version` (e.g. `gyrseek pip install foo --version`) is passed through, not intercepted
  - Behavioral anomaly detection compares observed network endpoints across versions
  - Behavioral anomaly detection also compares install-time git clone command signatures across versions and fails closed when new clone behavior appears
  - Behavioral anomaly detection also compares install-time execution of watched runtimes (default `bun`, `deno`) across versions and fails closed when a version newly executes one, or executes it with new/additional arguments (catches the Shai-Hulud "Hades/miasma" class: download Bun and run an obfuscated stealer via `bun run`). Signatures are `exe|arg1|arg2|...` so both "didn't run bun before, now does" and "ran bun before, now runs bun plus extra" are detected. See extract_process_exec_signatures in src/scanning.rs (inline tests: flags_newly_introduced_bun_execution, flags_existing_bun_with_additional_invocation, etc.)
  - watched_executables config entries are unioned onto the built-in defaults (bun, deno are always watched); node/sh/python are intentionally NOT watched to avoid false positives
  - process_exec_allowlist allows specific watched-process signatures (`bun|run|build`) or bare executables (`bun`) even when newly introduced (case-insensitive)
  - Scope caveat: watched-process/network/git-clone detection only observes execution during the sandbox install; the PyPI `*-setup.pth` variant that fires on next interpreter startup may execute outside the install window
  - Direct runtime interception for standalone `git clone ...` commands is still not enabled; only install-time clone behavior inside package scan traces is currently enforced
  - Install-time git clone behavior comparison is covered by inline tests in src/scanning.rs (scan_flags_new_install_time_git_clone_behavior, git_clone_allowlist_matches_recursive_clone_of_allowed_url, etc.)
  - Version ordering is semantic-version aware: npm uses semver, Python managers (pip/pip3/uv/poetry) use PEP 440; unparseable version strings sort below any parseable version so malformed entries are never selected as `latest` (see compare_version_strings/sort_versions_ascending in src/scanning.rs)
  - After a clear scan of an explicit unpinned (`latest`) install target, the forwarded command is rewritten to pin the exact resolved version that was scanned (npm `pkg@x.y.z`, Python `pkg==x.y.z`) via rewrite_args_with_pinned_versions; lockfile/manifest-driven flows (uv sync, uv pip sync, uv lock, poetry install/update) forward verbatim because the lockfile already pins versions
  - scan_packages_versions/scan_package_versions return a ScanReport { allowed, resolved_version }; policy knobs are passed as a single PolicyConfig struct rather than positional args
  - New IPs remain fail-closed anomalies (both IPv4 and IPv6 connection endpoints are captured from trace output); warning output includes reverse-DNS domain context as informational enrichment
  - extract_connection_ips normalizes endpoints via normalize_ip_string (canonical IPv6 plus IPv4-mapped IPv6 `::ffff:1.2.3.4` collapsed to bare IPv4) and drops sandbox-local addresses via is_sandbox_local_ip (loopback, link-local `fe80::/10` + `169.254/16`, and private/RFC1918 incl. the Docker bridge `172.17/16` and Docker Desktop gateway `192.168.65/24`) at capture time, before the baseline diff and on both current and baseline traces — this removed a whole class of harness-nondeterminism false positives where the container's own gateway/DNS showed up as a "new" endpoint. The cloud metadata IP `169.254.169.254` is exempt (kept) as a real SSRF/credential-theft signal. The ip_allowlist matcher also compares on the collapsed form, so `172.17.0.2` and `::ffff:172.17.0.2` match interchangeably
  - domain_allowlist matching now requires forward-confirmed reverse DNS (FCrDNS): reverse_dns_domain resolves the PTR hostname and only trusts it if its forward A/AAAA resolution includes the original IP (pure decision extracted into forward_confirmed_hostname for deterministic unit tests). A spoofed PTR record set on an attacker's C2 IP can no longer bypass the allowlist (was FINDINGS.md #2)
  - execve argv parsing uses a balanced-bracket-aware regex, so arguments containing `]` (PEP 508 extras like `requests[security]`, paths like `script[obf].js`) are captured intact instead of truncated at the first `]` — prevents both truncated-signature false positives and truncation-based bypass (was FINDINGS.md #3)
  - PEP 508 extras are stripped from the canonical package name (strip_pep508_extras) for PyPI/registry lookups and the version-pin map key, while the forwarded install command keeps the full extras-qualified spec; fixes the `requests[security]` PyPI-404/zero-baseline path and the extras-key pin miss in one normalization (was FINDINGS.md #6 and #7)
  - When a forwarded host command exits non-zero, gyrseek now exits with the same code (forward_args propagates child status; also fails closed if wait() errors) instead of discarding it and exiting 0 (was FINDINGS.md #8)
  - Only recognized managers are accepted: pip, pip3, uv, poetry, npm. Any other first argument is rejected with a clear error listing supported managers (fail closed). The sole built-in exception is `sandbox runtimes` (diagnostic subcommand). Previously, unrecognized managers were silently forwarded unscanned.
  - Behavior tests include deterministic DNS-enrichment coverage (match and unresolved lookup paths)
  - YAML policy config is supported (`gyrseek.yaml` by default, overridable via `--config` or `GYRSEEK_CONFIG`) using `ip_allowlist`, `domain_allowlist`, `git_clone_allowlist` (allowlist for install-time git clone targets), optional package `baseline_overrides` (`baseline-1`/`baseline-2`), `baseline_count` (default 2), per-package `min_baseline_age_hours` (default effective age gate 2 hours), `new_package_exemptions` (temporary bypass when <2 eligible baselines), `internal_package_exemptions` (skip a package entirely — no registry fetch, no sandbox install, no diff; for first-party/private-index packages e.g. Nexus that public-registry lookups can't resolve; forwarded unscanned at the requested version), optional `minimum_release_age_package` (disabled by default; when set, fails closed if current release age in days is below threshold), optional `release_burst_threshold` (disabled by default), and optional `release_burst_window_hours` (default 24h; when threshold is set, fails closed if version publish count in the configured window meets threshold), `watched_executables` (unioned onto built-in defaults bun/deno), and `process_exec_allowlist` (allow specific watched-process signatures or bare executables); IPs are canonicalized so equivalent IPv6 representations match
  - uv sync scans all packages from uv.lock
  - uv lock parsing excludes local editable/path/workspace project entries to avoid scanning the application under development
  - uv lock --upgrade and bare uv lock both scan all packages from uv.lock; -P/--upgrade-package scans explicit update targets. A bare uv lock (no -U/-P) previously forwarded unscanned and now scans the resolved lockfile (fails closed if uv.lock is missing/empty)
  - uv pip sync scans packages from requirements-style files and pylock.toml
  - pip/pip3 install scans multi-package inputs, including `-r/--requirements` files
  - poetry install, poetry update, and bare poetry lock scan all locked packages from poetry.lock (poetry lock previously forwarded unscanned; now scans the resolved lockfile and fails closed if poetry.lock is missing/empty)
  - poetry lock parsing excludes ALL local directory-source project entries regardless of the `develop` flag (previously only `develop = true` editable entries were excluded, so a non-develop local path leaked into registry scanning) — to avoid scanning the application under development (was FINDINGS.md #5)
  - npm install/npm i/npm update scans multi-package inputs and package.json dependencies when no explicit package args are given
  - npm package.json fallback excludes local/non-registry dependency specs (file/workspace/git/url/link) from scanning
  - npm CLI arg parsing also excludes non-registry specs (`link:`, `file:`, `git+`, URL) — previously only the package.json fallback path filtered these; a `link:../local-pkg` CLI arg would leak through as a package name (fixed)
  - uv lock -P upgrade target parsing: when the value after -P starts with `-`, only one token is consumed (not two), so the next real package argument is not silently swallowed (fixed)
  - Sandbox execution mode is selected via GYRSEEK_SANDBOX (`docker` default, `host` fallback)
  - Host sandbox mode prioritizes speed over isolation; a malicious latest package can execute on the host while gyrseek only emits warnings/signals
  - GYRSEEK_SANDBOX supports `microvm` mode via Docker runtime selection
  - GYRSEEK_MICROVM_RUNTIME selects the runtime for microvm mode (default `kata-runtime`), and initialization fails closed if runtime is unavailable
  - `./target/release/gyrseek sandbox runtimes` lists Docker runtimes to help choose GYRSEEK_MICROVM_RUNTIME
  - GYRSEEK_NPM_SCANNER_IMAGE and GYRSEEK_PY_SCANNER_IMAGE override scanner images; prebuilt fast path can be enabled via GYRSEEK_PREBUILT_SCANNER_IMAGES or per-manager prebuilt env vars
  - README includes step-by-step Dockerfile/build/use guidance for prebuilt npm and python scanner images
  - README includes digest-pinning examples for scanner images to avoid tag drift and improve reproducibility
  - Roadmap now includes staged no-execution-first milestones (artifact fetch/unpack, static diff scoring, pre-runtime policy gate)
  - Roadmap now explicitly tracks direct `git clone` runtime interception phases (parser, interception pipeline, policy gates, and integration tests)
  - Roadmap now includes generated-file comparison phases across package versions (inventory diff, hash first-pass, normalization, semantic diff, and policy gating)
  - MicroVM mode requires a Linux environment with a MicroVM-capable Docker runtime; macOS Docker Desktop typically does not expose Kata runtime directly
  - README includes a platform support matrix for `docker`, `host`, and `microvm` modes across macOS and Linux
  - Sandbox initialization failures fail closed (non-zero exit)
  - Docker sandbox batches package-version probe matrices (multiple packages and baselines) in one container session while preserving package-version attribution
  - strace invocations use `-s 4096 -v` so long argv strings (e.g. git clone URLs) and addresses are not truncated to the 32-byte default
  - The traced install payload is dropped to an unprivileged in-container user (`strace -u gyrseek`) while strace and the trace log files stay root-owned in the bind-mounted /out, so a malicious install/postinstall script cannot overwrite or delete its own trace before gyrseek reads it
  - Docker runner adds `--cap-add SYS_PTRACE`: strace runs as root but attaches to the install running as the unprivileged scanner user, and cross-UID ptrace needs CAP_SYS_PTRACE (not granted by Docker default). Scoped to the container PID namespace; cannot trace host processes. Without it strace fails `ptrace(PTRACE_SEIZE): Operation not permitted` and the scan fails closed. This was surfaced by the empty-trace fix below (FINDINGS.md #1)
  - An empty/whitespace sandbox trace is now a hard error (block the whole batch) rather than an empty-but-clean pass: trace_install_docker_matrix_with_runtime returns Err on a blank matrix log + failed single-probe fallback, and the single-probe fallback checks docker exit status. Previously unwrap_or_default() returned "" → empty TraceSignals → allowed:true on any strace failure (was FINDINGS.md #1)
  - strace's own stderr is captured per-probe to `/out/gyrseek_err_N.log` instead of `>/dev/null 2>&1`; `|| true` is kept only so one failing install does not abort sibling probes — a genuine attach failure leaves a blank trace which the empty-trace check turns into a block (was FINDINGS.md #4; deliberately did NOT use `set -e` to abort on strace exit, since strace returns the tracee's exit code and a legitimately failing baseline install would otherwise DoS the whole batch)
  - If the host command cannot be spawned after a clear scan, gyrseek fails closed (non-zero exit) instead of panicking
  - Docker runner currently avoids read-only rootfs because apt-based probe tooling setup requires writable root filesystem
  - Docker runner executes setup as root and uses `APT::Sandbox::User=root` to avoid setgroups failures under capability restrictions
  - Docker runner does not drop all Linux capabilities (apt-based setup fails under full drop) and explicitly adds SYS_PTRACE as above
  - README documents current Docker hardening limitations and the prebuilt-image path to restore stricter isolation controls
  - In-run cache reuses scan results for repeated manager/package/version probes within the same execution
  - Fail-closed when package detection is expected but missing

## Mandatory Update Policy (After Every Change)
After every code or behavior change in this repository:
1. Update this file (AGENTS.md) with the new behavior, scope, or constraints.
2. Update README.md so user-facing documentation matches the current implementation.
3. Rerun `/graphify` with `graphify update .` so `graphify-out/` stays in sync with the latest code.
4. Ensure these updates happen in the same change set whenever possible.
5. If architecture, workflow, or future plan changes, update docs/ARCHITECTURE.md, docs/DEV_GUIDE.md, and docs/ROADMAP.md.

## Quick Post-Change Checklist
- [ ] Code updated
- [ ] Tests updated and run
- [ ] graphify update . run
- [ ] AGENTS.md updated
- [ ] README.md updated
- [ ] docs/ARCHITECTURE.md updated if needed
- [ ] docs/DEV_GUIDE.md updated if needed
- [ ] docs/ROADMAP.md updated if needed
