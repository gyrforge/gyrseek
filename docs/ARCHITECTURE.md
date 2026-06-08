# Architecture

## Goal
gyrseek is a command-wrapper CLI that evaluates dependency installation network behavior before allowing the original package-manager command to proceed.

## Runtime Entry Flow
1. The binary entrypoint in src/main.rs collects CLI args and calls run in src/lib.rs.
2. The run function in src/lib.rs routes by manager and subcommand.
3. Supported command paths are either:
   - single-target scans (for example uv add pkg)
  - bulk scans (for example uv sync, uv pip sync, uv lock update flags, poetry install or poetry update, pip or pip3 install with multiple targets, npm install or npm i or npm update)
4. If detection and scanning pass, the original command is forwarded.
5. If anomaly or required detection failure occurs, execution exits non-zero (fail-closed).

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
  - fetch_history queries PyPI for Python packages.
  - fetch_history queries npm registry for npm packages.
- Behavior capture:
  - trace_sandbox_install_batch runs via SandboxRunner backend and captures per-version connection IPs from trace output.
  - Docker backend can execute current and baseline probes in one container session for a package.
  - build_runner_from_env selects backend mode (`docker` default, `host` fallback).
- Anomaly decision:
  - find_new_connections returns endpoints seen in current but not in baseline.
- In-run optimization:
  - run keeps an in-memory cache keyed by manager/package/version to avoid repeating identical scans in one execution.

## Decision Model
For each scanned package:
1. Determine current target version (explicit or latest).
2. Resolve baseline versions (v-1 and v-2 where available).
3. Collect network endpoint sets for current and baseline installs.
4. Compute set difference current minus baseline.
5. If difference is non-empty, block command.

## Fail-Closed Policy
gyrseek blocks instead of passthrough when package detection is expected for supported install or sync flows but no package entries are detected.

## Current Limitations
- Version ordering is lexicographic, not semantic-version aware.
- git clone runtime interception is not enabled yet (simulation tests only).
- Docker mode assumes Docker CLI availability; host mode assumes strace availability and is less safe.
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
