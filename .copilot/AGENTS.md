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
  - Integration tests under tests/
  - Run with cargo test
- Collaboration docs:
  - docs/ARCHITECTURE.md
  - docs/DEV_GUIDE.md
  - docs/ROADMAP.md
- Current behavior highlights:
  - Supports uv add, uv pip install, uv pip sync, uv sync, uv lock update flags, pip/pip3 install, poetry add/update/install, npm install/i/update
  - Behavioral anomaly detection compares observed network endpoints across versions
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
  - GYRSEEK_SANDBOX supports `microvm` mode via Docker runtime selection
  - GYRSEEK_MICROVM_RUNTIME selects the runtime for microvm mode (default `kata-runtime`), and initialization fails closed if runtime is unavailable
  - `cargo run -- sandbox runtimes` lists Docker runtimes to help choose GYRSEEK_MICROVM_RUNTIME
  - GYRSEEK_NPM_SCANNER_IMAGE and GYRSEEK_PY_SCANNER_IMAGE override scanner images; prebuilt fast path can be enabled via GYRSEEK_PREBUILT_SCANNER_IMAGES or per-manager prebuilt env vars
  - README includes step-by-step Dockerfile/build/use guidance for prebuilt npm and python scanner images
  - README includes digest-pinning examples for scanner images to avoid tag drift and improve reproducibility
  - MicroVM mode requires a Linux environment with a MicroVM-capable Docker runtime; macOS Docker Desktop typically does not expose Kata runtime directly
  - README includes a platform support matrix for `docker`, `host`, and `microvm` modes across macOS and Linux
  - Sandbox initialization failures fail closed (non-zero exit)
  - Docker sandbox batches package-version probe matrices (multiple packages and baselines) in one container session while preserving package-version attribution
  - Docker runner currently avoids read-only rootfs because apt-based probe tooling setup requires writable root filesystem
  - Docker runner executes setup as root and uses `APT::Sandbox::User=root` to avoid setgroups failures under capability restrictions
  - Docker runner currently does not drop all Linux capabilities because apt-based setup fails under full capability drop
  - README documents current Docker hardening limitations and the prebuilt-image path to restore stricter isolation controls
  - In-run cache reuses scan results for repeated manager/package/version probes within the same execution
  - Fail-closed when package detection is expected but missing

## Mandatory Update Policy (After Every Change)
After every code or behavior change in this repository:
1. Update this file (.copilot/Agents.md) with the new behavior, scope, or constraints.
2. Update README.md so user-facing documentation matches the current implementation.
3. Ensure both updates happen in the same change set whenever possible.
4. If architecture, workflow, or future plan changes, update docs/ARCHITECTURE.md, docs/DEV_GUIDE.md, and docs/ROADMAP.md.

## Quick Post-Change Checklist
- [ ] Code updated
- [ ] Tests updated and run
- [ ] .copilot/Agents.md updated
- [ ] README.md updated
- [ ] docs/ARCHITECTURE.md updated if needed
- [ ] docs/DEV_GUIDE.md updated if needed
- [ ] docs/ROADMAP.md updated if needed
