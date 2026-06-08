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
- Build release: cargo build --release
- Run tests: cargo test
- Run one test file: cargo test --test parser_tests

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
	- minimum_release_age_package
	- release_burst_threshold
	- release_burst_window_hours

## Adding a New Supported Command
1. Add command detection in run routing logic.
2. Decide if command is single-target or bulk-target.
3. Reuse or extend parser helpers.
4. Reuse scan_package_versions for each resolved package target.
5. Enforce fail-closed when detection is expected but unresolved.
6. Add parser tests and behavior tests.

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
