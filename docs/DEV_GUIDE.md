# Developer Guide

## Local Setup
1. Install Rust toolchain.
2. Ensure required package managers are available for your target flows: uv, pip or pip3, poetry, npm.
3. Ensure Docker CLI is available in PATH for default sandbox mode.
4. If using host mode (`GYRSEEK_SANDBOX=host`), ensure strace is available in PATH.

## Sandbox Mode
- Default: `GYRSEEK_SANDBOX=docker`
- Fallback: `GYRSEEK_SANDBOX=host` (reduced safety)
- Initialization failure is fail-closed (process exits non-zero).

## Build and Test
- Build debug: cargo build
- Build release: ./auto/cargo-build
- Run tests: ./auto/cargo-checks (or cargo test directly)
- Run inline tests for one module: cargo test --lib scanning / cargo test --lib parsing / cargo test --lib
- Run CLI integration tests (spawn binary): cargo test --test cli_burst_exit_tests / cargo test --test forward_fail_closed_tests / cargo test --test lock_routing_tests / cargo test --test version_flag_tests

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
	- watched_executables (unioned onto built-in defaults bun/deno)
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
- npm versions are ordered with the semver crate; Python managers (pip/pip3/uv/poetry) use PEP 440 (pep440_rs).
- Unparseable version strings deliberately sort below any parseable version so malformed entries are never chosen as `latest`.

## Test Locations
- Follow Rust convention: unit tests for private/internal functions live inline in the module's `#[cfg(test)] mod tests` (they can see private items); integration tests that exercise the public API or need a real subprocess live under tests/.
- Pure-function unit tests live inline in their src/ module (version ordering, trace extraction including sandbox-local IP filtering / `::ffff:` collapse / metadata-IP preservation, FCrDNS, bracketed-argv parsing, docker arg construction, SYS_PTRACE, PEP 508 extras stripping, poetry/uv local-source exclusion, npm non-registry filtering, git-clone allowlist matching, IP allowlist IPv4-mapped/bare equivalence, internal-package-exemption skip, missing-baseline fail-closed, uv lock upgrade arg edge cases); keep these alongside the code they cover.
- Anything that can only be observed from outside the process belongs in tests/ — e.g. host exit-status propagation (`std::process::exit`) in tests/forward_fail_closed_tests.rs, command routing (bare `poetry lock`/`uv lock` reaching the scan branch) in tests/lock_routing_tests.rs, and the `--version` short-circuit in tests/version_flag_tests.rs, because these are only visible to a spawning parent.

## Required Change Hygiene
After every repository change:
1. Update .copilot/AGENTS.md.
2. Update README.md.
3. Keep docs in docs/ in sync if architecture or workflow changed.
4. Run cargo test before finishing.

## Practical Review Checklist
- Command path is correctly recognized.
- Package extraction is deterministic.
- Unknown or ambiguous input does not silently bypass protections.
- Bulk operations scan all intended package targets.
- Non-target commands still passthrough when appropriate.
- Tests cover positive and negative parse cases.
