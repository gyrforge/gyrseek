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
5. If anomaly or required detection failure occurs, execution exits non-zero (fail-closed). If the host command itself cannot be spawned after a clear scan, gyrseek also fails closed.

## Core Components
- Command parsing:
  - parse_package_details extracts package and optional version for single-target commands.
- Bulk source parsing:
  - parse_uv_lock_packages_from_content parses uv.lock package entries.
  - parse_poetry_lock_packages_from_content parses poetry.lock package entries.
  - parse_requirements_packages_from_content parses requirements-style entries.
  - parse_pylock_packages_from_content parses pylock package entries.
  - parse_pip_install_packages_from_args resolves package targets from pip or pip3 install args, including -r or --requirements files.
  - parse_npm_install_packages_from_args resolves npm targets from explicit args or package.json when no explicit target is given.
  - parse_uv_lock_upgrade_packages_from_args resolves update targets from uv lock -P or --upgrade-package arguments.
- Version history lookup:
  - fetch_history_with_baselines queries PyPI for Python packages and the npm registry for npm packages.
  - Version lists are ordered semantically: semver for npm, PEP 440 for Python managers (compare_version_strings / sort_versions_ascending). Unparseable strings sort below any parseable version, so junk is never resolved as `latest`.
  - npm `time` map parsing (npm_published_times) excludes the `created`/`modified` bookkeeping keys and any non-version key, so the release-burst counter is not inflated.
- Behavior capture:
  - trace_sandbox_install_matrix runs via SandboxRunner backend and captures per package-version connection IPs (IPv4 via inet_addr and IPv6 via inet_pton, normalized to canonical form by extract_connection_ips) and install-time git clone command signatures from trace output.
  - strace runs with `-s 4096 -v` (no argv/address truncation) and `-u <scanner-user>` so the traced install payload runs unprivileged while strace and its root-owned /out trace logs remain tamper-resistant.
  - Docker backend can execute probe matrices (multiple packages with their current and baseline versions) in one container session.
  - build_runner_from_env selects backend mode (`docker` default, `host` fallback).
- Anomaly decision:
  - find_new_connections returns endpoints seen in current but not in baseline.
  - install-time git clone signatures are diffed across current and baseline versions; newly introduced clone behavior is fail-closed unless allowlisted.
- In-run optimization:
  - run keeps an in-memory cache keyed by manager/package/version to avoid repeating identical scans in one execution.

## Decision Model
For each scanned package:
1. Determine current target version (explicit, or `latest` resolved via semantic ordering).
2. Resolve baseline versions (v-1 and v-2 where available, ordered semantically).
3. Collect behavior signals for current and baseline installs (network endpoints and install-time git clone signatures).
4. Compute set differences current minus baseline for each signal type.
5. Apply allowlists (`ip_allowlist`, `domain_allowlist`, `git_clone_allowlist`).
6. If non-allowlisted differences remain, block command.

## Fail-Closed Policy
gyrseek blocks instead of passthrough when package detection is expected for supported install or sync flows but no package entries are detected.

## Current Limitations
- Version ordering is semantic-version aware (semver for npm, PEP 440 for Python); unparseable versions fall back to sorting below parseable ones.
- Version pinning of the forwarded command applies only to explicit unpinned install targets; lockfile-driven flows rely on the lockfile's own pins.
- Direct runtime interception for standalone `git clone ...` commands is not enabled yet.
- Docker mode assumes Docker CLI availability; host mode assumes strace availability and is less safe. The unprivileged-payload (`strace -u`) trace-integrity protection applies to the Docker/microvm backends.
- Trace extraction still assumes current strace output patterns.

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
- tests/forward_fail_closed_tests.rs: fail-closed coverage when the host command cannot be spawned
- src/scanning.rs (unit tests): semantic version ordering, IPv4/IPv6 trace extraction, npm time-map release-burst filtering
- src/sandbox.rs (unit tests): strace no-truncation flags, unprivileged-payload trace integrity, docker arg construction
- tests/parser_tests.rs also covers forwarded-command version pinning (rewrite_args_with_pinned_versions)
