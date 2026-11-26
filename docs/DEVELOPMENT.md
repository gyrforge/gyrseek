# Development: Recipes and Testing

Architecture and the change workflow are in [ARCHITECTURE.md](ARCHITECTURE.md). Run `just --list` for the current recipes.

## Just Recipes

The `Justfile` contains convenience recipes for common tasks. All recipes run from the repo root regardless of where you call them from.

| Recipe | What it does |
|---|---|
| `just build` | Builds the release binary (`target/release/gyrseek`). |
| `just install` | Installs `gyrseek` into Cargo's bin directory with `cargo install --path . --locked`. |
| `just uninstall` | Uninstalls `gyrseek` with `cargo uninstall gyrseek`. |
| `just tag` | Tags the current `HEAD` with the version string from `Cargo.toml` (e.g. `v1.2.3`), requires `HEAD` to be `origin/main` and waits for its CI run to pass (needs `gh`), refuses a version `origin` already has, and pushes the tag to `origin`, which starts the release workflow. |
| `just fmt` | Formats the Rust code. |
| `just test` | Runs `cargo test --all-features --locked`. |
| `just lint` | Runs `cargo check`, clippy for all targets/features, and a format check. Use this before committing. |
| `just test-npm` | End-to-end test (Docker): scans and installs `lodash`, then runs `npm update` and `npm i` against the test fixture in `tests/npm/`. Builds the release binary first. |
| `just test-pnpm` | End-to-end test (Docker): scans and adds `lodash`, then runs `pnpm update` and `pnpm i` against the test fixture in `tests/pnpm/`. Builds the release binary first. |
| `just test-pip` | End-to-end test (Docker): creates a venv, then scans and installs `black`, the packages from `tests/pip/requirements.txt`, and runs `pip3 install --upgrade pip` via `pip3`. Builds the release binary first. |
| `just test-poetry` | End-to-end test (Docker): scans `poetry add black`, `poetry install --no-root`, `poetry update`, and `poetry lock` from the `tests/poetry/` fixture. Builds the release binary first. |
| `just test-uv` | End-to-end test (Docker): scans `uv add black`, `uv pip install`, `uv sync`, and `uv lock` from the `tests/uv/` fixture. Builds the release binary first. |
| `just test-docker` | Runs all Docker end-to-end tests (`test-npm`, `test-pnpm`, `test-pip`, `test-poetry`, `test-uv`). |
| `just docker-build-python` | Builds the Python scanner image from `docker/Dockerfile.python` as `gyrseek-python-scanner:latest`. |
| `just docker-build-npm` | Builds the npm/pnpm scanner image from `docker/Dockerfile.npm` as `gyrseek-npm-scanner:latest`. |
| `just image-pins` | Compares the digest-pinned Python and Node sandbox base images built into `gyrseek` (`src/runtime_image.rs`) with the registry and prints `ok` or `DRIFT` for each. Needs Docker; run it before a release (see `AGENTS.md` for the refresh steps). |

**Typical workflow:**

```bash
# Build once
just build

# Install into Cargo's bin directory
just install

# Uninstall from Cargo's bin directory
just uninstall

# Tag HEAD with the Cargo.toml version and push to origin
just tag

# Run tests
just test

# Check everything is healthy before pushing
just lint

# Run a live end-to-end test for the manager you changed
just test-npm
just test-pnpm
just test-pip
just test-uv
just test-poetry
```

> The end-to-end recipes use the Docker sandbox. Make sure Docker is running before executing them.

## Testing

Tests follow Rust convention: everything that doesn't need to spawn the compiled binary lives inline in its `src/` module under `#[cfg(test)]`, giving tests direct access to private items. Only CLI-level exit-code tests that must spawn the real binary remain in `tests/`.

**Unit and integration tests** (no Docker required):

```bash
# Run everything
just test
just lint

# Or directly:
cargo test

# Run tests from a specific source module
cargo test --lib scanning
cargo test --lib parsing
cargo test --lib

# Run the CLI exit-code integration tests (spawn the binary)
cargo test --test cli_burst_exit_tests
cargo test --test forward_fail_closed_tests
cargo test --test lock_routing_tests
cargo test --test pnpm_routing_tests
cargo test --test version_flag_tests
cargo test --test sandbox_startup_exit_tests

# Run one specific test case by name
cargo test parses_npm_install_with_pinned_version
cargo test detects_anomalous_new_connection
cargo test flags_newly_introduced_bun_execution

# Show println! output while testing
cargo test -- --nocapture
```

**End-to-end tests** (requires Docker and the release binary):

```bash
just test-npm
just test-pnpm
just test-pip
just test-uv
just test-poetry
```

Behavior test coverage includes deterministic DNS-enrichment checks, FCrDNS forward-confirmation, bracketed-argv preservation, process-execution detection, git-clone signature diffing, and release-burst policy enforcement.
