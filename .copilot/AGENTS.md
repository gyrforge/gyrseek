# Agents Memory and Workflow

## Purpose
This file stores persistent working memory and agent instructions for this repository.

## Repository Memory
- Project name: gyrseek
- Language: Rust
- Entry points:
  - src/main.rs (binary entrypoint)
  - src/lib.rs (core logic)
- Test strategy:
  - Integration tests under tests/
  - Run with cargo test
- Collaboration docs:
  - docs/ARCHITECTURE.md
  - docs/DEV_GUIDE.md
  - docs/ROADMAP.md
- Current behavior highlights:
  - Supports uv add, uv pip install, uv pip sync, uv sync, pip/pip3 install, poetry add/update/install, npm install/i
  - Behavioral anomaly detection compares observed network endpoints across versions
  - uv sync scans all packages from uv.lock
  - uv pip sync scans packages from requirements-style files and pylock.toml
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
- [ ] .copilot/AGENTS.md updated
- [ ] README.md updated
- [ ] docs/ARCHITECTURE.md updated if needed
- [ ] docs/DEV_GUIDE.md updated if needed
- [ ] docs/ROADMAP.md updated if needed
