# Developer Guide

## Local Setup
1. Install Rust toolchain.
2. Install just.
3. Ensure required package managers are available for your target flows: uv, pip or pip3, poetry, npm, pnpm.
4. Ensure Docker CLI is available in PATH for default sandbox mode.
5. If using host mode (`GYRSEEK_SANDBOX=host`), ensure strace is available in PATH.

## Sandbox Mode
- Default: `GYRSEEK_SANDBOX=docker`
- Fallback: `GYRSEEK_SANDBOX=host` (reduced safety)
- Initialization failure is fail-closed (process exits non-zero).

## Sandbox Security & Hardening
- Docker/microvm sandbox runs use:
  - `--network none` for complete network isolation (inbound/outbound blocked)
  - `--cap-add SYS_PTRACE` for cross-UID tracing (required for `strace -u`)
  - `--security-opt no-new-privileges`
  - Embedded seccomp profile (opt-in via `GYRSEEK_DOCKER_SECCOMP_PROFILE=true|false`, default true)
- Seccomp profile source: `src/sandbox.rs` (`EMBEDDED_SECCOMP_PROFILE_JSON` constant)
- To disable seccomp: `GYRSEEK_DOCKER_SECCOMP_PROFILE=false ./target/release/gyrseek ...`
- Startup logs announce seccomp status to stderr (`[gyrseek][INFO]` or `[gyrseek][WARN]`)

## Build and Test
- Build debug: cargo build
- Build release: just build
- Install locally: just install
- Uninstall locally: just uninstall
- Run tests: just test (or cargo test directly)
- Run lint checks: just lint
- Format code: just fmt
- Run inline tests for one module: cargo test --lib sandbox / cargo test --lib scanning / cargo test --lib parsing / cargo test --lib
  - `cargo test --lib sandbox` includes docker arg construction, seccomp profile toggle, network isolation, and strace setup tests
- Run CLI integration tests (spawn binary): cargo test --test cli_burst_exit_tests / cargo test --test forward_fail_closed_tests / cargo test --test lock_routing_tests / cargo test --test pnpm_routing_tests / cargo test --test version_flag_tests

## Policy Config Surface
- Primary policy file: gyrseek.yaml (or override with --config / GYRSEEK_CONFIG).
- Current policy keys include:
	- ip_allowlist
	- domain_allowlist
	- git_clone_allowlist
	- baseline_overrides (`baseline-1` / `baseline-2`)
	- baseline_count
	- min_baseline_age_hours
	- new_package_exemptions
	- internal_package_exemptions (skip first-party/private-index packages entirely — no fetch/probe/diff)
	- minimum_release_age_package
	- release_burst_threshold
	- release_burst_window_hours
	- artifact_allowlist (exact `type|path` or `type|path|details` to unblock known artifacts)
	- process_exec_allowlist

## Adding a New Supported Command
1. Add command detection in run routing logic.
2. Decide if command is single-target or bulk-target.
3. Reuse or extend parser helpers.
4. Reuse scan_package_versions (single) or scan_packages_versions (bulk) for resolved targets; both take a single &PolicyConfig and return a ScanReport per target (allowed + resolved_version).
5. For explicit unpinned install targets, forward via forward_pinned_command(&pins) using the resolved_version values so the host installs exactly what was scanned; lockfile/manifest-driven flows forward verbatim with forward_original_command.
6. Enforce fail-closed when detection is expected but unresolved.
7. Add parser tests and behavior tests.

## Version Ordering Notes
- npm/pnpm versions are ordered with the semver crate; Python managers (pip/pip3/uv/poetry) use PEP 440 (pep440_rs).
- Unparseable version strings deliberately sort below any parseable version so malformed entries are never chosen as `latest`.

## Test Locations
- Follow Rust convention: unit tests for private/internal functions live inline in the module's `#[cfg(test)] mod tests` (they can see private items); integration tests that exercise the public API or need a real subprocess live under tests/.
- Pure-function unit tests live inline in their src/ module (version ordering, trace extraction including sandbox-local IP filtering / `::ffff:` collapse / metadata-IP preservation, FCrDNS, bracketed-argv parsing, docker arg construction, SYS_PTRACE, PEP 508 extras stripping, poetry/uv local-source exclusion, npm/pnpm non-registry filtering, git-clone allowlist matching, IP allowlist IPv4-mapped/bare equivalence, internal-package-exemption skip, missing-baseline fail-closed, uv lock upgrade arg edge cases, harness-command filtering via `is_harness_command`); keep these alongside the code they cover.
- Anything that can only be observed from outside the process belongs in tests/ — e.g. host exit-status propagation (`std::process::exit`) in tests/forward_fail_closed_tests.rs, command routing (bare `poetry lock`/`uv lock` and pnpm scan routing) in tests/lock_routing_tests.rs and tests/pnpm_routing_tests.rs, and the `--version` short-circuit in tests/version_flag_tests.rs, because these are only visible to a spawning parent.

## Required Change Hygiene
After every repository change:
1. Update AGENTS.md (repository memory).
2. Update README.md (user-facing docs).
3. Update docs/ files (ARCHITECTURE.md, DEV_GUIDE.md, ROADMAP.md, FINDINGS.md) if architecture or workflow changed.
4. Run `graphify update .` to refresh graph artifacts (or `graphify update . --force` if guard warns).
5. Run `just test` before finishing.
6. Run `just lint` to check formatting and clippy.

## Practical Review Checklist
- Command path is correctly recognized.
- Package extraction is deterministic.
- Unknown or ambiguous input does not silently bypass protections.
- Bulk operations scan all intended package targets.
- Non-target commands still passthrough when appropriate.
- Tests cover positive and negative parse cases.
- Sandbox hardening (seccomp, no-network, SYS_PTRACE) does not break trace capture.
- Empty/whitespace traces fail closed (not silently passed).
- strace capability failures are reported in captured stderr logs.
