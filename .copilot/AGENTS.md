# Agents Memory and Workflow

## Purpose
This file stores persistent working memory and agent instructions for this repository.

## Repository Memory
- Project name: gyrseek
- Language: Rust
- Entry points:
  - src/main.rs (binary entrypoint)
  - src/lib.rs (command routing and orchestration)
  - src/parsing.rs (parsing helpers)
  - src/scanning.rs (registry lookup and anomaly scanning)
  - src/sandbox.rs (sandbox runner backends and mode selection)
- Test strategy:
  - Integration tests under tests/ (preferred for command-path and behavior coverage)
  - Pure-function unit tests live inline in src/ modules (src/scanning.rs, src/sandbox.rs) where they cover internal, non-exported helpers
  - Run with cargo test
- Collaboration docs:
  - docs/ARCHITECTURE.md
  - docs/DEV_GUIDE.md
  - docs/ROADMAP.md
- Current behavior highlights:
  - Supports uv add, uv pip install, uv pip sync, uv sync, uv lock update flags, pip/pip3 install, poetry add/update/install, npm install/i/update
  - Behavioral anomaly detection compares observed network endpoints across versions
  - Behavioral anomaly detection also compares install-time git clone command signatures across versions and fails closed when new clone behavior appears
  - Direct runtime interception for standalone `git clone ...` commands is still not enabled; only install-time clone behavior inside package scan traces is currently enforced
  - Install-time git clone behavior comparison is covered by integration tests in tests/git_clone_scan_tests.rs
  - Version ordering is semantic-version aware: npm uses semver, Python managers (pip/pip3/uv/poetry) use PEP 440; unparseable version strings sort below any parseable version so malformed entries are never selected as `latest` (see compare_version_strings/sort_versions_ascending in src/scanning.rs)
  - After a clear scan of an explicit unpinned (`latest`) install target, the forwarded command is rewritten to pin the exact resolved version that was scanned (npm `pkg@x.y.z`, Python `pkg==x.y.z`) via rewrite_args_with_pinned_versions; lockfile/manifest-driven flows (uv sync, uv pip sync, uv lock, poetry install/update) forward verbatim because the lockfile already pins versions
  - scan_packages_versions/scan_package_versions return a ScanReport { allowed, resolved_version }; policy knobs are passed as a single PolicyConfig struct rather than positional args
  - New IPs remain fail-closed anomalies (both IPv4 and IPv6 connection endpoints are captured from trace output and IPv6 is normalized to canonical form); warning output now includes reverse-DNS domain context as informational enrichment
  - Behavior tests include deterministic DNS-enrichment coverage (match and unresolved lookup paths)
  - YAML policy config is supported (`gyrseek.yaml` by default, overridable via `--config` or `GYRSEEK_CONFIG`) using `ip_allowlist`, `domain_allowlist`, `git_clone_allowlist` (allowlist for install-time git clone targets), optional package `baseline_overrides` (`baseline-1`/`baseline-2`), `baseline_count` (default 2), per-package `min_baseline_age_hours` (default effective age gate 2 hours), `new_package_exemptions` (temporary bypass when <2 eligible baselines), optional `minimum_release_age_package` (disabled by default; when set, fails closed if current release age in days is below threshold), optional `release_burst_threshold` (disabled by default), and optional `release_burst_window_hours` (default 24h; when threshold is set, fails closed if version publish count in the configured window meets threshold); IPs are canonicalized so equivalent IPv6 representations match
  - uv sync scans all packages from uv.lock
  - uv lock parsing excludes local editable/path/workspace project entries to avoid scanning the application under development
  - uv lock --upgrade scans all packages from uv.lock, and -P/--upgrade-package scans explicit update targets
  - uv pip sync scans packages from requirements-style files and pylock.toml
  - pip/pip3 install scans multi-package inputs, including `-r/--requirements` files
  - poetry install and poetry update scan all locked packages from poetry.lock
  - poetry lock parsing excludes local directory/path/editable project entries to avoid scanning the application under development
  - npm install/npm i/npm update scans multi-package inputs and package.json dependencies when no explicit package args are given
  - npm package.json fallback excludes local/non-registry dependency specs (file/workspace/git/url/link) from scanning
  - Sandbox execution mode is selected via GYRSEEK_SANDBOX (`docker` default, `host` fallback)
  - Host sandbox mode prioritizes speed over isolation; a malicious latest package can execute on the host while gyrseek only emits warnings/signals
  - GYRSEEK_SANDBOX supports `microvm` mode via Docker runtime selection
  - GYRSEEK_MICROVM_RUNTIME selects the runtime for microvm mode (default `kata-runtime`), and initialization fails closed if runtime is unavailable
  - `cargo run -- sandbox runtimes` lists Docker runtimes to help choose GYRSEEK_MICROVM_RUNTIME
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
  - If the host command cannot be spawned after a clear scan, gyrseek fails closed (non-zero exit) instead of panicking
  - Docker runner currently avoids read-only rootfs because apt-based probe tooling setup requires writable root filesystem
  - Docker runner executes setup as root and uses `APT::Sandbox::User=root` to avoid setgroups failures under capability restrictions
  - Docker runner currently does not drop all Linux capabilities because apt-based setup fails under full capability drop
  - README documents current Docker hardening limitations and the prebuilt-image path to restore stricter isolation controls
  - In-run cache reuses scan results for repeated manager/package/version probes within the same execution
  - Fail-closed when package detection is expected but missing

## Mandatory Update Policy (After Every Change)
After every code or behavior change in this repository:
1. Update this file (.copilot/AGENTS.md) with the new behavior, scope, or constraints.
2. Update README.md so user-facing documentation matches the current implementation.
3. Ensure both updates happen in the same change set whenever possible.
4. If architecture, workflow, or future plan changes, update docs/ARCHITECTURE.md, docs/DEV_GUIDE.md, and docs/ROADMAP.md.

## Quick Post-Change Checklist
- [ ] Code updated
- [ ] Tests updated and run
- [ ] .copilot/AGENTS.md updated
- [ ] README.md updated
- [ ] docs/ARCHITECTURE.md updated if needed
- [ ] docs/DEV_GUIDE.md updated if needed
- [ ] docs/ROADMAP.md updated if needed
