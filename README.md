# gyrseek

`gyrseek` is a Rust CLI wrapper that intercepts package install/update commands, compares network behavior across package versions, and then forwards the original command if no anomaly is detected.

It currently supports:
- `uv add`
- `uv pip install`
- `uv pip sync <SRC_FILE>...`
- `uv sync`
- `uv lock --upgrade` / `uv lock -P|--upgrade-package`
- `pip install`
- `pip3 install`
- `poetry add|update|install`
- `npm install` / `npm i`
- `npm update`
- git clone behavior simulation tests

## How It Works

1. Parse package name and optional version from your command.
2. If no version is provided, treat it as `latest`.
3. Fetch version history:
   - PyPI for Python packages
   - npm registry for npm packages
4. Run sandbox installs for:
   - current version
   - previous version (`baseline-1`)
   - two versions back (`baseline-2`)
   - probes may run in one sandbox session across multiple packages and versions, while preserving package-version trace attribution
   - for bulk commands (`uv sync`, `uv pip sync`), apply this per detected package
5. Compare observed network endpoints:
   - New endpoints found: block and exit with error
   - No new endpoints: forward your original command
6. Fail-closed behavior:
   - if package detection is expected but no package entries are detected, block and exit

## Network Behavior Detection

`gyrseek` uses syscall tracing (`strace`) during sandbox installs to observe outbound network connection behavior.

- It captures connection target IPs from trace output.
- It computes the difference between:
   - current version endpoints
   - baseline endpoints from previous versions
- Any endpoint that appears only in the current version is treated as a behavioral anomaly.
- New IPs are always treated as anomalies (fail-closed), even if reverse DNS suggests domain overlap.
- Reverse DNS domain context is included in warning output as informational enrichment to help triage IP-rotation cases.

This gives you a behavioral signal rather than relying only on package metadata.

## Stable Allowlist Config

You can define allowlisted IPs and domains that should be ignored before anomaly blocking.

Default config file path:

```text
gyrseek.yaml
```

Config format:

```yaml
ip_allowlist:
   - 151.101.0.223
   - 151.101.64.223
domain_allowlist:
   - pypi.org
   - files.pythonhosted.org
baseline_overrides:
   requests:
      baseline-1: "2.30.0"
      baseline-2: "2.29.0"
   lodash:
      baseline-1: "4.17.20"
baseline_count: 2
min_baseline_age_hours:
   requests: 6
   lodash: 12
new_package_exemptions:
   - newly-published-package
```

Override config path:

```bash
cargo run -- --config ./security-policy.yaml npm install
```

You can also set an environment variable:

```bash
GYRSEEK_CONFIG=./security-policy.yaml cargo run -- npm install
```

Behavior:

- If `gyrseek.yaml` is missing, `gyrseek` runs with an empty allowlist.
- If a custom config path is provided and cannot be read, `gyrseek` fails closed.
- Invalid `ip_allowlist` entries are ignored with a warning.
- `ip_allowlist` entries are canonicalized (for example, equivalent IPv6 forms normalize to the same value).
- `domain_allowlist` entries are normalized to lowercase and trailing `.` is removed.
- Subdomains match allowlisted parent domains (for example, `cdn.example.com` matches `example.com`).
- `baseline_overrides` is optional and lets you pin baseline versions per package.
- Each package can set either or both `baseline-1` and `baseline-2`; missing keys continue using registry-derived baselines.
- `baseline_count` controls how many historical baselines are compared; default is `2`.
- Baselines are age-gated: by default, a version must be at least `2` hours old before it is used for comparison.
- `min_baseline_age_hours` lets you override that age gate per package (package not listed uses the default `2` hours).
- `new_package_exemptions` lets you exempt specific new packages when fewer than 2 eligible baseline versions exist.
- If an exempted package later has 2 or more eligible baseline versions, `gyrseek` warns so you can remove the exemption.

## Git Clone Behavior

The repository includes safe simulation tests for git clone-style network anomaly detection in:

- `tests/git_clone_behavior_tests.rs`

Current scope:

- You can test detection logic for clone scenarios through integration tests.
- Runtime command interception for `git clone ...` is not enabled yet in the CLI command parser.

## Prerequisites

- Rust toolchain (`cargo`, `rustc`)
- Network access to package registries
- Package managers you want to wrap (`uv`, `pip`, `poetry`, `npm`)
- Docker CLI available on your system PATH (default sandbox mode)
- `strace` available in host mode (`GYRSEEK_SANDBOX=host`)

## Sandbox Modes

`gyrseek` now runs scan probes through a `SandboxRunner` backend selected by environment variable:

- Default: `GYRSEEK_SANDBOX=docker`
- MicroVM runtime mode: `GYRSEEK_SANDBOX=microvm`
- Alternative (reduced safety): `GYRSEEK_SANDBOX=host`

Behavior:

- If sandbox initialization fails, `gyrseek` exits non-zero (fail-closed).
- Docker mode is intended as the safer default.
- Host mode exists for local development or environments without Docker.
- MicroVM mode is implemented through Docker runtime selection and requires a MicroVM-capable Docker runtime.

MicroVM configuration:

- `GYRSEEK_MICROVM_RUNTIME` selects the Docker runtime used for MicroVM mode.
- Default runtime: `kata-runtime`.
- If the configured runtime is not available in `docker info`, startup fails closed with an explicit message.
- To inspect available runtimes quickly, run: `cargo run -- sandbox runtimes`
- MicroVM mode requires a Linux environment where the selected runtime is installed and exposed through Docker runtimes.
- On macOS Docker Desktop, MicroVM runtimes like Kata are typically not available directly; use a Linux VM or Linux host.

Scanner image configuration (Docker and MicroVM modes):

- `GYRSEEK_NPM_SCANNER_IMAGE` overrides the npm scanner image (default: `node:22-bookworm-slim`).
- `GYRSEEK_PY_SCANNER_IMAGE` overrides the Python scanner image (default: `python:3.12-bookworm`).
- `GYRSEEK_PREBUILT_SCANNER_IMAGES=true` enables prebuilt fast path for both managers.
- `GYRSEEK_NPM_SCANNER_PREBUILT=true` and `GYRSEEK_PY_SCANNER_PREBUILT=true` can override prebuilt mode per manager.
- In prebuilt mode, runtime setup (`apt-get` and Python `uv` bootstrapping) is skipped to reduce hot-path latency.

### Prebuild Scanner Images (Recommended)

If you want faster probe startup and fewer runtime setup failures, prebuild scanner images with required tools already installed.

#### 1) Build an npm scanner image

Create a Dockerfile, for example `Dockerfile.npm-scanner`:

```dockerfile
FROM node:22-bookworm-slim
RUN apt-get update \
   && apt-get install -y --no-install-recommends strace ca-certificates \
   && rm -rf /var/lib/apt/lists/*
```

Build it:

```bash
docker build -f Dockerfile.npm-scanner -t gyrseek/npm-scanner:latest .
```

Use it:

```bash
GYRSEEK_NPM_SCANNER_IMAGE=gyrseek/npm-scanner:latest \
GYRSEEK_NPM_SCANNER_PREBUILT=true \
cargo run -- npm update
```

#### 2) Build a Python scanner image

Create a Dockerfile, for example `Dockerfile.py-scanner`:

```dockerfile
FROM python:3.12-bookworm
RUN apt-get update \
   && apt-get install -y --no-install-recommends strace ca-certificates \
   && rm -rf /var/lib/apt/lists/*
RUN python -m pip install --no-cache-dir uv
```

Build it:

```bash
docker build -f Dockerfile.py-scanner -t gyrseek/py-scanner:latest .
```

Use it:

```bash
GYRSEEK_PY_SCANNER_IMAGE=gyrseek/py-scanner:latest \
GYRSEEK_PY_SCANNER_PREBUILT=true \
cargo run -- uv sync
```

#### 3) Enable prebuilt mode globally (optional)

If both scanner images are prebuilt, you can enable one global toggle:

```bash
GYRSEEK_PREBUILT_SCANNER_IMAGES=true \
GYRSEEK_NPM_SCANNER_IMAGE=gyrseek/npm-scanner:latest \
GYRSEEK_PY_SCANNER_IMAGE=gyrseek/py-scanner:latest \
cargo run -- npm update
```

#### 4) Verify images are usable

Quick checks:

```bash
docker run --rm gyrseek/npm-scanner:latest sh -lc 'strace -V'
docker run --rm gyrseek/py-scanner:latest sh -lc 'strace -V && uv --version'
```

If these checks pass, `GYRSEEK_*_SCANNER_PREBUILT=true` should work without runtime tool installation.

#### 5) Use pinned image digests (recommended for reproducibility)

To avoid tag drift, pin scanner images by digest.

Example (replace digest values with real ones from your registry):

```bash
GYRSEEK_NPM_SCANNER_IMAGE=gyrseek/npm-scanner@sha256:REPLACE_WITH_REAL_DIGEST \
GYRSEEK_PY_SCANNER_IMAGE=gyrseek/py-scanner@sha256:REPLACE_WITH_REAL_DIGEST \
GYRSEEK_PREBUILT_SCANNER_IMAGES=true \
cargo run -- npm update
```

Tip:

- Build and push your scanner images once in CI.
- Resolve and publish immutable digests.
- Reference only digest-pinned images in production or shared CI environments.

Examples:

```bash
GYRSEEK_SANDBOX=docker cargo run -- npm install
GYRSEEK_SANDBOX=host cargo run -- pip3 install -r requirements.txt
```

### Platform Support Matrix

| Mode | macOS (Docker Desktop) | Linux host/VM |
| --- | --- | --- |
| `docker` | Supported | Supported |
| `host` | Supported (requires local `strace`) | Supported (requires local `strace`) |
| `microvm` | Usually unavailable (Kata/runtime typically not exposed) | Supported when a MicroVM-capable Docker runtime is installed |

## Build

```bash
cargo build --release
```

Binary path:

```bash
target/release/gyrseek
```

## Usage

General pattern:

```bash
cargo run -- <manager> <subcommand> <package>
```

or with release binary:

```bash
./target/release/gyrseek <manager> <subcommand> <package>
```

### Python examples

```bash
cargo run -- uv add pytest
cargo run -- uv pip install requests==2.31.0
cargo run -- uv pip sync requirements.txt
cargo run -- uv pip sync pylock.toml
cargo run -- uv sync
cargo run -- uv lock --upgrade
cargo run -- uv lock -P pytest -P requests
cargo run -- pip install flask
cargo run -- pip3 install django==5.0.6
cargo run -- pip3 install -r requirements.txt
cargo run -- poetry install
cargo run -- poetry update pytest
```

### npm examples

```bash
cargo run -- npm install lodash
cargo run -- npm install lodash express
cargo run -- npm i lodash@4.17.21
cargo run -- npm install
cargo run -- npm update
cargo run -- npm update lodash typescript
```

## Important Notes

- `gyrseek` forwards your command in the current working directory.
- Scanning now runs via a sandbox backend; default mode is Docker.
- Repeated package-version probes within the same CLI execution are cached in-memory and reused.
- Docker mode batches probe matrices (multiple packages x versions) into a single sandbox/container run when possible.
- Docker mode keeps resource limits, but currently relaxes rootfs and capability hardening because probe setup installs sandbox tooling in-container.
- Docker setup currently runs as root in-container with apt sandbox user disabled to allow installing probe tooling under restrictive container flags.
- For tools like `poetry` or `npm`, run it inside a project directory containing the expected project files (`pyproject.toml`, `package.json`, etc.).
- `uv sync` scans all packages found in `uv.lock` before forwarding.
- `uv sync` and `uv lock --upgrade` exclude local project entries (for example editable/path/workspace package blocks) from anomaly comparison.
- `uv pip sync` scans all parseable packages found in its source files before forwarding.
- `uv pip sync` currently supports requirements-style files and dedicated `pylock.toml` parsing.
- `uv lock --upgrade` scans all packages found in `uv.lock` before forwarding.
- `uv lock -P/--upgrade-package` scans all explicitly targeted update packages before forwarding.
- `pip install` and `pip3 install` scan all parseable package entries, including requirements files passed with `-r/--requirements`.
- `poetry install` and `poetry update` scan all packages found in `poetry.lock` before forwarding.
- `poetry install` and `poetry update` exclude local project entries (for example directory/path/editable source blocks) from anomaly comparison.
- `npm install`, `npm i`, and `npm update` scan all explicit package targets; when no targets are provided, they scan dependencies declared in `package.json`.
- For npm package.json fallback scanning, local source dependencies (`file:`, `workspace:`, `git+`, direct URL/link sources) are excluded from anomaly comparison.
- Version selection is currently sorted lexicographically, not semantic-version aware.
- If baseline versions are unavailable, output may show `baseline-1=n/a` and `baseline-2=n/a`.
- For supported install/sync command paths, package-detection failures are fail-closed (non-zero exit) instead of passthrough.

## Docker Hardening Limitations

Current Docker sandbox mode is designed for practical compatibility and throughput, not maximum isolation.

Current limitations:

- Container setup installs probe tooling at runtime (`apt-get` and, for Python, `uv`).
- Container setup currently runs as root.
- Full `--read-only` rootfs is not enabled in this mode.
- Full capability dropping is not enabled in this mode.
- Outbound network remains generally available so package manager traffic can proceed.

Performance note:

- You can avoid runtime setup overhead by using prebuilt scanner images and enabling prebuilt mode (`GYRSEEK_PREBUILT_SCANNER_IMAGES=true` or per-manager prebuilt env vars).

Why these limits currently exist:

- Earlier stricter configurations (read-only rootfs + full capability drop + non-root runtime setup) caused apt/setup failures and prevented scans from running.
- The current configuration is the stable path that allows matrix probes (multiple packages and versions) to complete in one sandbox run.

Recommended hardening direction:

- Use prebuilt scanner images that already include required tooling (`strace`, certs, and `uv` where needed).
- After prebuilt images are in place, re-enable non-root runtime, read-only rootfs, and full capability drop.
- Add seccomp/apparmor policies and image digest pinning.
- Consider tighter egress controls (allowlist or proxy model) for stronger containment.
- Add no-execution-first checks (artifact diff/static heuristics/provenance gates) before runtime execution paths.
- Evolve no-execution-first checks in phases: artifact fetch/unpack, static diff scoring, then pre-runtime policy gating.

## Manual Test Runs

Run all tests:

```bash
cargo test
```

Run one integration test file:

```bash
cargo test --test parser_tests
cargo test --test behavior_tests
cargo test --test git_clone_behavior_tests
```

Run one specific test case:

```bash
cargo test parses_npm_install_with_pinned_version
cargo test detects_anomalous_new_connection
```

Show test output (`println!`) while running tests:

```bash
cargo test -- --nocapture
```

Behavior test coverage includes deterministic DNS-enrichment checks for reverse-DNS context handling (including unresolved-IP scenarios).

## Collaboration and Handoff

For multi-developer and multi-LLM collaboration, use these docs together:

- docs/ARCHITECTURE.md: control-flow and component map
- docs/DEV_GUIDE.md: contributor workflow and change hygiene
- docs/ROADMAP.md: planned improvements and known next steps
- .copilot/Agents.md: repository memory and mandatory update policy

Repository policy: after each change, update both `.copilot/Agents.md` and `README.md`.

## Project Layout

- `src/main.rs`: binary entrypoint
- `src/lib.rs`: command routing and orchestration
- `src/parsing.rs`: command and lock or requirements parsing helpers
- `src/scanning.rs`: registry lookup and behavior scanning engine
- `src/sandbox.rs`: sandbox backends and mode selection
- `tests/parser_tests.rs`: command parsing tests
- `tests/behavior_tests.rs`: behavior anomaly simulation tests
- `tests/git_clone_behavior_tests.rs`: git clone behavior simulation tests
