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

## Mandatory Pre-Session Setup

All skills below only apply to code changes within this branch/session,
not the entire codebase.

1. **Load ponytail** — Enforces the lazy engineering ladder: does it need to
   exist? Does stdlib cover it? Can it be one line? The shortest path to done
   is the right path. Default intensity: full. Override with `/ponytail lite|ultra`
   or `stop ponytail` for normal mode.
   **Note:** Rust idioms take precedence over ponytail recommendations when
   they conflict. The shortest path is idiomatic Rust, not necessarily the
   fewest lines.
2. **Load interrogation** — Available on demand via `/grill`, `/interrogate`,
   "grill me", "stress-test this plan", or "pick this apart". See
   `.agents/skills/interrogation/SKILL.md` for full details.
3. **Load code-security** — Active for all code writing and review. Automatically
   checks for vulnerabilities relevant to the language and patterns in use.
   See `.agents/skills/code-security/SKILL.md` for full details.

## Agent Portability Symlinks
- `.claude/skills` → `.agents/skills` (folder-level symlink; auto-picks up new skills)
- `.github/skills` → `.agents/skills` (same)
- `CLAUDE.md` → `AGENTS.md` (changes to AGENTS.md propagate instantly to Claude Code)
- `skills-lock.json` at repo root tracks 6 external skills: 3 from `semgrep/skills` (code-security, llm-security, semgrep) and 3 from `DietrichGebert/ponytail` (ponytail, ponytail-help, ponytail-review). See `docs/DEV_GUIDE.md` for details.

## Repository Memory
- Project name: gyrseek
- Language: Rust
- Entry points:
  - src/main.rs (binary entrypoint)
  - src/lib.rs (command routing and orchestration)
  - src/parsing.rs (parsing helpers)
  - src/scanning.rs (registry lookup and anomaly scanning)
  - src/sandbox.rs (sandbox runner backends and mode selection)
- CI:
  - `.github/workflows/ci.yml` — Runs all untrusted PR code with strictly `contents: read` permissions. Includes `rust-checks` (lint, test, and read-only AI code review via opencode generating an artifact), and test matrices (`linux-docker-uv-test`, etc.).
  - `.github/workflows/post_review.yml` — Triggered via `workflow_run`. Runs in a trusted context with `pull-requests: write` to safely download the AI review artifact and post it to the PR. **Rule:** Any new jobs requiring write permissions MUST be placed in a separate `workflow_run` file like this, NEVER in `ci.yml`.
- Build and scripts:
  - Justfile is the task runner entrypoint; run `just --list` to see recipes
  - just build — release build (cargo build --release)
  - just install — install gyrseek with cargo install --path . --locked
  - just uninstall — uninstall gyrseek with cargo uninstall gyrseek
  - just docker-build-python — build Python scanner image from docker/Dockerfile.python
  - just docker-build-npm — build npm/pnpm scanner image from docker/Dockerfile.npm
  - just tag — tag HEAD with version from Cargo.toml (e.g. v1.2.3), force-delete existing local/remote tag, push to origin
  - just fmt — format Rust code
  - just test — run cargo test --all-features --locked
  - just lint — cargo check + clippy all targets/features + format check; run before committing (does NOT run cargo test — use just test for that)
  - just test-{npm,pnpm,pip,uv,poetry} — end-to-end tests per manager using the release binary; require Docker
- Test strategy:
  - All unit and integration tests that do not require spawning the compiled binary live inline in their src/ module under `#[cfg(test)]` — this follows Rust convention and lets tests access private items directly
  - Only tests that need to spawn the real binary (CLI exit-code checks, forward behavior) remain in tests/ as integration test files
  - Run with cargo test (or just test)
     - src/scanning.rs (inline) — version ordering, IPv4/IPv6 trace extraction (sandbox-local IP filtering, IPv4-mapped `::ffff:` collapse, cloud-metadata-IP preservation), burst filtering, FCrDNS (forward_confirmed_hostname), bracketed-argv preservation, process-execution detection and allowlisting (with harness-command filtering via `is_harness_command` to exclude sandbox's own `uv pip install`, `npm install`, `pnpm add`, `python get_interpreter_info`, and `env HOME=/work` wrappers from exec signatures), git-clone signature diffing, network anomaly detection, DNS enrichment, IP/domain allowlist filtering (including IPv4-mapped/bare-IPv4 equivalence), internal-package-exemption skip, git-clone simulation; DNS wire-format parser (unescape_strace_string, decode_dns_name with 0xc0 compression pointer support, parse_dns_response, extract_dns_map) with strace `-xx` hex-escape flag requirement; artifact scan (classify_inventory_lines, extract_artifact_findings, strip_artifact_section, inventory-based artifact scan with Rust-side classification for binary, suspicious_pth, unexpected_runtime, large_file signals; inline tests: classify_inventory_binary_elf, classify_inventory_unexpected_runtime, classify_inventory_suspicious_pth, classify_inventory_benign_pth, classify_inventory_large_file, classify_inventory_skips_malformed_lines, classify_inventory_empty_input, classify_inventory_mixed_findings, artifact_delimiter_pipe_in_path_is_not_injected, artifact_delimiter_injection_attack_defeated_end_to_end, artifact_delimiter_injection_does_not_block_clean_package); artifact allowlist (filter_allowlisted_artifact_findings — exact and prefix matching; inline tests: artifact_allowlist_matches_exact_finding_and_prefix); integration tests for artifact allowlist unblocking (artifact_allowlist_unblocks_new_findings) and fail-closed on new artifacts (flags_new_artifact_findings_across_versions); test RAII via `EnvVarGuard` (holds `env_lock` + sets/removes env var on drop, recovers from poison)
  - src/sandbox.rs (inline) — SYS_PTRACE capability in docker args, strace-stderr capture, no-truncation flags, unprivileged-payload integrity, post-install artifact scan (build_artifact_scan_steps — single file inventory pipeline — embedded in matrix script; inline test: artifact_scan_steps_uses_null_byte_delimiter); seccomp profile toggle and content tests; AppArmor profile content and env-var toggle tests
  - src/parsing.rs (inline) — PEP 508 extras stripping (strip_pep508_extras), extras-aware pinning, poetry local directory-source exclusion, rewrite_args_with_pinned_versions (including the `latest`-pin guard so a skipped internal package is not rewritten to an invalid `name==latest`/`name@latest`), lockfile/requirements/npm parsing for all managers
   - src/lib.rs (inline) — GyrSeek::parse_package_details for all supported managers and subcommands; config parsing for new_package_exemptions and internal_package_exemptions; `run()` refactored with `bulk_scan!` macro (four explicit-list branches), `ForwardMode` enum, `scan_targets` wrapper, `exit_with(msg) -> !` helper
  - tests/cli_burst_exit_tests.rs — release burst threshold and minimum_release_age_package CLI exit-code behavior (spawns binary)
  - tests/forward_fail_closed_tests.rs — fail-closed when forwarding to a missing host binary, host exit-status propagation (spawns binary; uses a fake `uv venv` passthrough vehicle in a temp dir)
  - tests/lock_routing_tests.rs — bare `poetry lock` and `uv lock` reach the lockfile-scan branch (fail closed with no lockfile), `pnpm install` is recognized and reaches package-scan routing, and `uv venv` stays an unscanned passthrough (spawns binary)
  - tests/pnpm_routing_tests.rs — `pnpm add` and `pnpm install` package.json fallback reach the package-scan branch without Docker/network by forcing registry metadata and bypassing runner init (spawns binary)
  - tests/version_flag_tests.rs — `--version`/`-V` prints the crate version and exits 0; a forwarded command's own trailing `--version` is not intercepted (spawns binary)
- Collaboration docs:
  - docs/ARCHITECTURE.md
  - docs/DEV_GUIDE.md
  - docs/ROADMAP.md
  - docs/OPEN_FINDINGS.md
  - docs/FIXED_FINDINGS.md
  - docs/WONT_FIX_FINDINGS.md
  - docs/DOCKER_SECURITY.md
  - docs/TESTS.md
- Current behavior highlights:
  - Supports uv add, uv pip install, uv pip sync, uv sync, uv lock (bare and update flags), pip/pip3 install, poetry add/update/install/lock, npm install/i/update, pnpm add/install/i/update
  - `--version`/`-V` is handled as a leading top-level flag before config load or sandbox init: prints `gyrseek <CARGO_PKG_VERSION>` and exits 0 (works with no config file / no Docker). Only the first arg is matched, so a forwarded command's own `--version` (e.g. `gyrseek pip install foo --version`) is passed through, not intercepted
  - Behavioral anomaly detection compares observed network endpoints across versions
  - Behavioral anomaly detection also compares install-time git clone command signatures across versions and fails closed when new clone behavior appears
  - Behavioral anomaly detection traces `open` and `openat` system calls via `strace` to monitor for attempts to read highly sensitive credential or configuration files (e.g., `~/.aws/credentials`, `~/.npmrc`, `.env`). If a package accesses sensitive files that older versions did not touch, the install is immediately flagged.
  - If any of the 5 behavioral anomaly checks (network, git clone, process exec, sensitive file read, or suspicious artifact) are triggered, the install is blocked. **Importantly**, the scan does not short-circuit on the first failure. All anomaly checks run to completion and aggregate their failure reasons, ensuring comprehensive reporting on exactly what the malicious package attempted to do.
  - Behavioral anomaly detection also compares install-time process execution signatures across versions and fails closed when a version newly executes a program, or executes it with new/additional arguments (catches the Shai-Hulud "Hades/miasma" class: download Bun and run an obfuscated stealer via `bun run`). Signatures are `exe|arg1|arg2|...` so both "didn't run bun before, now does" and "ran bun before, now runs bun plus extra" are detected. Sandbox-internal commands (the install probe itself, interpreter discovery) are excluded via `is_harness_command` to prevent version-string false positives. See extract_process_exec_signatures in src/scanning.rs (inline tests: flags_newly_introduced_bun_execution, flags_existing_bun_with_additional_invocation, etc.)
  - Post-install artifact scan runs in the Docker container after each install probe: a single `find /work -type f` pipeline inventories every installed file (path, size, file type via `file -b`, first 300 bytes of content). The raw inventory is written to `/out/gyrseek_artifacts_N.log`, embedded into the probe trace via a delimiter, and classified in Rust by `classify_inventory_lines` in scanning.rs. The classifier emits structured findings: `binary` (ELF/Mach-O/PE), `suspicious_pth` (.pth with executable import/call patterns), `unexpected_runtime` (bun/deno binaries), and `large_file` (>10 MB). New signals (not seen in baselines) fail closed. This catches the Hades/Miasma `.pth` write-to-disk gap and ELF-based payloads (cryptominers, compiled malware) and large data exfiltration stages — all without container script changes for new patterns. The inventory log uses null-byte (`\0`) field delimiters (not `|`), preventing filename-based delimiter-injection attacks (FIXED_FINDINGS.md #20).
  - All executables are watched by default (least-privilege approach); `process_exec_allowlist` is the only escape hatch
  - process_exec_allowlist allows specific watched-process signatures (`bun|run|build`) or bare executables (`bun`) even when newly introduced (case-insensitive)
  - **Transitive dependencies** are inherently covered: single-package installs trace the full installation tree (catching any malicious transitive install scripts), while lockfile and bulk installs parse the manifest to individually sandbox and scan every transitive dependency against its own baselines.
  - Scope caveat: watched-process/network/git-clone detection only observes execution during the sandbox install; the PyPI `*-setup.pth` variant that fires on next interpreter startup may execute outside the install window. Post-install artifact scan (suspicious .pth files, unexpected runtime binaries) closes part of this gap by scanning the installed file tree before the container exits
  - Direct runtime interception for standalone `git clone ...` commands is still not enabled; only install-time clone behavior inside package scan traces is currently enforced
  - Install-time git clone behavior comparison is covered by inline tests in src/scanning.rs (scan_flags_new_install_time_git_clone_behavior, git_clone_allowlist_matches_recursive_clone_of_allowed_url, etc.)
  - Version ordering is semantic-version aware: npm/pnpm uses semver, Python managers (pip/pip3/uv/poetry) use PEP 440; unparseable version strings sort below any parseable version so malformed entries are never selected as `latest` (see compare_version_strings/sort_versions_ascending in src/scanning.rs)
  - After a clear scan of an explicit unpinned (`latest`) install target, the forwarded command is rewritten to pin the exact resolved version that was scanned (npm/pnpm `pkg@x.y.z`, Python `pkg==x.y.z`) via rewrite_args_with_pinned_versions; lockfile/manifest-driven flows (uv sync, uv pip sync, uv lock, poetry install/update) forward verbatim because the lockfile already pins versions
  - scan_packages_versions/scan_package_versions return a ScanReport { allowed, resolved_version }; policy knobs are passed as a single PolicyConfig struct rather than positional args
  - New IPs remain fail-closed anomalies (both IPv4 and IPv6 connection endpoints are captured from trace output); warning output shows each IP enriched with its FCrDNS domain inline (e.g. `203.0.113.42 -> suspicious-c2.example`), rather than as a separate informational footnote
   - extract_connection_ips normalizes endpoints via normalize_ip_string (canonical IPv6 plus IPv4-mapped IPv6 `::ffff:1.2.3.4` collapsed to bare IPv4) and drops sandbox-local addresses via is_sandbox_local_ip (loopback, link-local `fe80::/10` + `169.254/16`, and private/RFC1918 incl. the Docker bridge `172.17/16` and Docker Desktop gateway `192.168.65/24`) at capture time, before the baseline diff and on both current and baseline traces — this removed a whole class of harness-nondeterminism false positives where the container's own gateway/DNS showed up as a "new" endpoint. The cloud metadata IP `169.254.169.254` is exempt (kept) as a real SSRF/credential-theft signal. The ip_allowlist matcher also compares on the collapsed form, so `172.17.0.2` and `::ffff:172.17.0.2` match interchangeably.
   - DNS wire-format parser (unescape_strace_string, decode_dns_name with recursive 0xc0 compression pointer support; circular pointer detection via pointer_count limit of 5 hops; parse_dns_response, extract_dns_map) in scanning.rs. Requires strace `-xx` flag for deterministic hex-escape parsing. 244 inline tests total.
  - domain_allowlist matching now requires forward-confirmed reverse DNS (FCrDNS): reverse_dns_domain resolves the PTR hostname and only trusts it if its forward A/AAAA resolution includes the original IP (pure decision extracted into forward_confirmed_hostname for deterministic unit tests). A spoofed PTR record set on an attacker's C2 IP can no longer bypass the allowlist (was FIXED_FINDINGS.md #2)
   - Domain-aware IP diff: find_new_connections_domain_aware resolves each IP via FCrDNS and diffs at the domain level rather than the IP level. If a current IP resolves to a domain already seen in baseline traffic (e.g. a rotated Fastly CDN edge IP for files.pythonhosted.org), it is silently discarded — no registry_domains config needed. This handles benign CDN edge rotations for any infrastructure automatically, without requiring a hardcoded list of "known" domains. Unresolvable IPs fall back to DNS interceptor: the strace-parsed DNS response map is consulted to find which domain the container resolved the IP under. If that domain was also observed in baseline DNS traces and host-side forward resolution confirms the domain→IP binding, the IP is treated as benign. This closes the PTR-less CDN edge rotation gap (e.g. Fastly, Cloudflare edge IPs without PTR records). When FCrDNS and DNS interceptor both fail, the diff falls back to plain IP membership so the diff stays fail-closed for genuinely new or spoofed endpoints.
  - execve argv parsing uses a balanced-bracket-aware regex, so arguments containing `]` (PEP 508 extras like `requests[security]`, paths like `script[obf].js`) are captured intact instead of truncated at the first `]` — prevents both truncated-signature false positives and truncation-based bypass (was FIXED_FINDINGS.md #3)
  - PEP 508 extras are stripped from the canonical package name (strip_pep508_extras) for PyPI/registry lookups and the version-pin map key, while the forwarded install command keeps the full extras-qualified spec; fixes the `requests[security]` PyPI-404/zero-baseline path and the extras-key pin miss in one normalization (was FIXED_FINDINGS.md #6 and #7)
  - When a forwarded host command exits non-zero, gyrseek now exits with the same code (forward_args propagates child status; also fails closed if wait() errors) instead of discarding it and exiting 0 (was FIXED_FINDINGS.md #8)
  - Only recognized managers are accepted: pip, pip3, uv, poetry, npm, pnpm. Any other first argument is rejected with a clear error listing supported managers (fail closed). The sole built-in exception is `sandbox runtimes` (diagnostic subcommand). Previously, unrecognized managers were silently forwarded unscanned.
  - Behavior tests include deterministic DNS-enrichment coverage (match and unresolved lookup paths)
  - YAML policy config is supported (`gyrseek.yaml` by default, overridable via `--config`/`-c` or `GYRSEEK_CONFIG`) using `ip_allowlist`, `domain_allowlist`, `git_clone_allowlist` (allowlist for install-time git clone targets), `artifact_allowlist` (exact `type|path|details` or prefix `type|path` to unblock known artifact findings), `sensitive_file_access_allowlist` (allowlist specific paths that packages are allowed to read, e.g., for AWS SDKs to read credentials), optional package `baseline_overrides` (`baseline-1`/`baseline-2`), `baseline_count` (default 2), per-package `min_baseline_age_hours` (default effective age gate 2 hours), `new_package_exemptions` (temporary bypass when <2 eligible baselines), `internal_package_exemptions` (skip a package entirely — no registry fetch, no sandbox install, no diff; for first-party/private-index packages e.g. Nexus that public-registry lookups can't resolve; forwarded unscanned at the requested version), optional `minimum_release_age_package` (disabled by default; when set, fails closed if current release age in days is below threshold), optional `release_burst_threshold` (disabled by default), and optional `release_burst_window_hours` (default 24h; when threshold is set, fails closed if version publish count in the configured window meets threshold), `process_exec_allowlist` (allow specific watched-process signatures or bare executables); IPs are canonicalized so equivalent IPv6 representations match
  - uv sync scans all packages from uv.lock
  - uv lock parsing excludes local editable/path/workspace project entries to avoid scanning the application under development
  - uv lock --upgrade and bare uv lock both scan all packages from uv.lock; -P/--upgrade-package scans explicit update targets. A bare uv lock (no -U/-P) previously forwarded unscanned and now scans the resolved lockfile (fails closed if uv.lock is missing/empty)
  - uv pip sync scans packages from requirements-style files and pylock.toml
  - pip/pip3 install scans multi-package inputs, including `-r/--requirements` files
  - poetry install, poetry update, and bare poetry lock scan all locked packages from poetry.lock (poetry lock previously forwarded unscanned; now scans the resolved lockfile and fails closed if poetry.lock is missing/empty)
  - poetry lock parsing excludes ALL local directory-source project entries regardless of the `develop` flag (previously only `develop = true` editable entries were excluded, so a non-develop local path leaked into registry scanning) — to avoid scanning the application under development (was FIXED_FINDINGS.md #5)
  - npm install/npm i/npm update scans multi-package inputs and package.json dependencies when no explicit package args are given
  - pnpm add/pnpm install/pnpm i/pnpm update scan multi-package inputs and package.json dependencies when no explicit package args are given; sandbox probes use `pnpm add <pkg>@<version> --dir /work --lockfile=false` in the npm scanner image path, enabling pnpm via corepack (or global install fallback) when the scanner image is not prebuilt
  - npm package.json fallback excludes local/non-registry dependency specs (file/workspace/git/url/link) from scanning
  - npm CLI arg parsing also excludes non-registry specs (`link:`, `file:`, `git+`, URL) — previously only the package.json fallback path filtered these; a `link:../local-pkg` CLI arg would leak through as a package name (fixed)
  - uv lock -P upgrade target parsing: when the value after -P starts with `-`, only one token is consumed (not two), so the next real package argument is not silently swallowed (fixed)
  - Sandbox execution mode is selected via GYRSEEK_SANDBOX (`docker` default, `host` fallback)
  - Host sandbox mode prioritizes speed over isolation; a malicious latest package can execute on the host while gyrseek only emits warnings/signals
  - GYRSEEK_SANDBOX supports `microvm` mode via Docker runtime selection
  - GYRSEEK_MICROVM_RUNTIME selects the runtime for microvm mode (default `kata-runtime`), and initialization fails closed if runtime is unavailable
  - `./target/release/gyrseek sandbox runtimes` lists Docker runtimes to help choose GYRSEEK_MICROVM_RUNTIME
  - GYRSEEK_NPM_SCANNER_IMAGE and GYRSEEK_PY_SCANNER_IMAGE override scanner images (empty string treated as unset and falls back to the default digest-pinned image); prebuilt fast path can be enabled via GYRSEEK_PREBUILT_SCANNER_IMAGES or per-manager prebuilt env vars
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
  - Docker runner adds `--cap-add SYS_PTRACE`: strace runs as root but attaches to the install running as the unprivileged scanner user, and cross-UID ptrace needs CAP_SYS_PTRACE (not granted by Docker default). Scoped to the container PID namespace; cannot trace host processes. Without it strace fails `ptrace(PTRACE_SEIZE): Operation not permitted` and the scan fails closed. This was surfaced by the empty-trace fix below (FIXED_FINDINGS.md #1)
  - An empty/whitespace sandbox trace is now a hard error (block the whole batch) rather than an empty-but-clean pass: trace_install_docker_matrix_with_runtime returns Err on a blank matrix log + failed single-probe fallback, and the single-probe fallback checks docker exit status. Previously unwrap_or_default() returned "" → empty TraceSignals → allowed:true on any strace failure (was FIXED_FINDINGS.md #1)
  - strace's own stderr is captured per-probe to `/out/gyrseek_err_N.log` instead of `>/dev/null 2>&1`; `|| true` is kept only so one failing install does not abort sibling probes — a genuine attach failure leaves a blank trace which the empty-trace check turns into a block (was FIXED_FINDINGS.md #4; deliberately did NOT use `set -e` to abort on strace exit, since strace returns the tracee's exit code and a legitimately failing baseline install would otherwise DoS the whole batch)
  - Docker sandbox security (see [`docs/DOCKER_SECURITY.md`](docs/DOCKER_SECURITY.md) for full reference): embedded seccomp + AppArmor profiles in `src/sandbox.rs`; `--cap-add SYS_PTRACE` for cross-UID strace; `--security-opt no-new-privileges`; unprivileged payload via `strace -u gyrseek` with root-owned trace logs; probe batching in single container sessions; strace stderr captured per-probe; empty-trace fail-closed
  - Seccomp: enabled by default (disable with `--danger-disable-seccomp`); conservative profile that avoids denying networking syscalls but strictly blocks `io_uring` syscalls to prevent async file I/O bypass of strace monitoring
  - AppArmor: disabled by default (`GYRSEEK_DOCKER_APPARMOR_PROFILE`, default `false`); loaded via `apparmor_parser --cache-loc <tmpdir>`; requires `apparmor-utils` + prebuilt scanner image on Linux; falls back with warning on macOS. Recommended to enable on Linux hosts with prebuilt images for stronger path-based protection.
  - Capabilities not fully dropped; read-only rootfs not enabled (both blocked by runtime apt setup; prebuilt images unblock tighter defaults)
  - Network access enabled for registry access during probes; egress controls planned for future phases
  - In-run cache reuses scan results for repeated manager/package/version probes within the same execution
  - Fail-closed when package detection is expected but missing
  - README detection coverage table now includes four new TeamPCP attack waves: Telnyx Python SDK T26 (import-time, ❌ gap), Namastex/CanisterSprawl T27 (npm postinstall, ✅), SAP CAP T28 (npm preinstall+Bun, ✅), Bitwarden CLI T29 (npm CI/CD pipeline compromise, ✅), TanStack/Mini-Shai-Hulud T31 (npm CI/CD hijack, ✅), T32 (PyPI mistralai import-time, ❌ gap), T33 (OIDC propagation, ⚠️), and Deep Specter T34 (GitHub platform evasions, ✅ unaffected)

## Mandatory Post-Change Policy
After every code or behavior change in this repository:
1. Update this file (AGENTS.md) with the new behavior, scope, or constraints.
2. Confirm the code is efficient and fast (no unnecessary work, no wasted I/O, caching where beneficial) and idiomatic — prefer iterator adaptors (`.filter_map()`, `.partition()`, `.map().collect()`) over explicit `Vec::new()` + push loops.
3. Run `ponytail review` on the changes and address any over-engineering findings.
4. Run tests and confirm they pass.
5. Rerun `/graphify` with `graphify update .` so `graphify-out/` stays in sync with the latest code.
6. Ensure these updates happen in the same change set whenever possible.
7. If architecture, workflow, or future plan changes, update docs/ARCHITECTURE.md, docs/DEV_GUIDE.md, docs/ROADMAP.md, and docs/DOCKER_SECURITY.md.
8. If test structure or coverage changes significantly, update docs/TESTS.md.
 9. If a new finding is identified, add it to `docs/OPEN_FINDINGS.md` and its detailed rationale to `docs/OPEN_FINDINGS_DETAILED.md`. When a finding is fixed, move it to `docs/FIXED_FINDINGS.md` and `docs/FIXED_FINDINGS_DETAILED.md`. If it is excluded from fixing, move it to the `WONT_FIX` equivalents. Remember to keep the summary tables synced across both the main and detailed files. All finding IDs use a single flat numeric namespace (no category prefixes). When adding new findings, choose the next available number across all three categories to avoid collisions.
10. Load `understand-code` skill for end-of-session teaching and verification.

## Quick Post-Change Checklist
- [ ] Code updated
- [ ] Code is efficient and fast (no unnecessary work, no wasted I/O)
- [ ] Tests updated and run
- [ ] ponytail review run
- [ ] graphify update . run
- [ ] AGENTS.md updated
- [ ] README.md updated if needed
- [ ] docs/ARCHITECTURE.md updated if needed
- [ ] docs/DEV_GUIDE.md updated if needed
- [ ] docs/ROADMAP.md updated if needed
- [ ] docs/OPEN_FINDINGS.md / FIXED_FINDINGS.md / WONT_FIX_FINDINGS.md (and their `_DETAILED.md` counterparts) updated if needed
- [ ] docs/DOCKER_SECURITY.md updated if needed
- [ ] docs/TESTS.md updated if needed
