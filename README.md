# gyrseek

`gyrseek` is a Rust CLI wrapper that sits in front of your package manager. Before it lets an install or update run, it installs the target version (and a couple of older "baseline" versions) inside a sandbox, traces their behavior with `strace`, and **blocks the command if the new version does something the older ones never did** — like contacting a new network endpoint or running a hidden `git clone`.

Think of it as a behavioral diff between "the version you're about to install" and "versions that were already trusted."

```bash
# Instead of:        npm install lodash
# You run:           cargo run -- npm install lodash
```

If nothing suspicious is found, your original command is forwarded and runs normally. If something new shows up, `gyrseek` aborts and tells you why.

## Table of Contents

- [Introduction](#introduction)
- [Quick Start](#quick-start)
- [Supported Commands](#supported-commands)
- [How It Works](#how-it-works)
- [Usage](#usage)
- [Network Behavior Detection](#network-behavior-detection)
- [Git Clone Behavior](#git-clone-behavior)
- [Watched-Process Detection (Shai-Hulud / Bun)](#watched-process-detection-shai-hulud--bun)
- [Configuration](#configuration)
- [Sandbox Modes](#sandbox-modes)
- [Prebuilt Scanner Images](#prebuilt-scanner-images)
- [Behavior Reference](#behavior-reference)
- [Docker Hardening Limitations](#docker-hardening-limitations)
- [Testing](#testing)
- [Project Layout & Docs](#project-layout--docs)
- [License](#license)

## Introduction

This tool was created by [Brandon Chuah](https://www.linkedin.com/in/brandonccl/) and [David Craggs](https://www.linkedin.com/in/david-craggs-37851793/), who were working in internal product security roles when we began building this open source CLI.

Our goal is not to compete with existing vendors. Instead, we want to give open source maintainers and small businesses, especially those that cannot afford expensive commercial software supply chain tooling, a practical way to address the kinds of supply chain issues highlighted by incidents such as Shai-Hulud.

The tool works out of the box and requires no proxy configuration, as long as Docker is installed. It can be run in host mode, but it is primarily intended for isolated sandbox environments where secrets and environment variables are not present, making it better suited for testing and validation.

We welcome feedback and suggestions to this repository.

## Quick Start

### 1. Prerequisites

- Rust toolchain (`cargo`, `rustc`)
- Network access to package registries (PyPI, npm)
- The package managers you want to wrap (`uv`, `pip`, `poetry`, `npm`)
- **Docker CLI** on your `PATH` (the default, safer sandbox mode)
- `strace` on your `PATH` only if you use the reduced-safety `host` mode

### 2. Build

```bash
cargo build --release
# binary is produced at: target/release/gyrseek
```

### 3. Run your first scan

```bash
# Scan + (if clean) install lodash via npm:
cargo run -- npm install lodash

# Or with the release binary:
./target/release/gyrseek npm install lodash
```

That's it. `gyrseek` resolves the version, runs the sandbox behavioral diff, and either forwards your command or blocks it with an explanation.

## Supported Commands

| Ecosystem  | Commands                                                                                                                 |
| ---------- | ------------------------------------------------------------------------------------------------------------------------ |
| **uv**     | `uv add`, `uv pip install`, `uv pip sync <SRC_FILE>...`, `uv sync`, `uv lock --upgrade`, `uv lock -P\|--upgrade-package` |
| **pip**    | `pip install`, `pip3 install` (including `-r/--requirements` files)                                                      |
| **poetry** | `poetry add`, `poetry update`, `poetry install`                                                                          |
| **npm**    | `npm install`, `npm i`, `npm update`                                                                                     |

> Standalone `git clone` runtime interception is not enabled yet — only install-time clone behavior _inside_ package scans is enforced today (see [Git Clone Behavior](#git-clone-behavior)).

## How It Works

1. **Parse** the package name and optional version from your command. If no version is given, it's treated as `latest`.
2. **Fetch version history** from PyPI (Python) or the npm registry (npm) and order it semantically (semver for npm, PEP 440 for Python).
3. **Run sandbox installs** for:
   - the current/target version
   - the previous version (`baseline-1`)
   - two versions back (`baseline-2`)

   Multiple packages and versions may run in one sandbox session while keeping per-package, per-version trace attribution. Bulk commands (`uv sync`, `uv pip sync`, etc.) apply this to every detected package.

4. **Compare behavior signals** between the target and its baselines:
   - **Network**: endpoints contacted during install.
   - **Git clone**: install-time `git clone` command signatures.
   - **Watched-process execution**: invocations of risky runtimes like `bun`/`deno` during install (see [Watched-Process Detection](#watched-process-detection-shai-hulud--bun)).
5. **Decide**:
   - New endpoint or clone behavior found → **block and exit non-zero**.
   - Nothing new → **forward your original command**.
6. **Fail closed**: if a package target was expected but couldn't be detected — _or if the sandbox produced no trace at all_ (e.g. `strace` could not attach) — `gyrseek` blocks rather than letting the command through. A blank trace is never treated as a clean, zero-activity install.
7. **Propagate the host exit code**: when the original command is forwarded, `gyrseek` exits with the package manager's own status. A failed install (non-zero) surfaces as non-zero, so agents and CI `$?` checks are not misled into thinking a broken install succeeded.

This gives you a _behavioral_ signal, rather than relying only on package metadata.

> **PEP 508 extras** (e.g. `requests[security]`) are handled correctly: the extras are stripped for registry lookups and version-pin bookkeeping (so the PyPI lookup hits `requests`, not a 404), while the forwarded install command keeps the full `requests[security]==<scanned version>` spec.

## Usage

General pattern:

```bash
cargo run -- <manager> <subcommand> <package>
# or, with the release binary:
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

> For project-aware tools like `poetry` or `npm`, run inside a directory containing the expected project files (`pyproject.toml`, `package.json`, etc.).

## Network Behavior Detection

`gyrseek` uses syscall tracing (`strace`) during sandbox installs to observe outbound network connections.

- It captures connection target IPs — **both IPv4 and IPv6**, normalized to canonical form — from the trace output.
- It computes the difference between **current version endpoints** and **baseline endpoints** from previous versions.
- Any endpoint that appears _only_ in the current version is treated as a behavioral anomaly.
- Install-time `git clone` command signatures (e.g. clone target and recursive-clone usage) are also diffed across versions.
- Install-time execution of watched runtimes (`bun`, `deno` by default) is diffed across versions to catch download-and-run payloads — see [Watched-Process Detection](#watched-process-detection-shai-hulud--bun).
- New IPs are **always** treated as anomalies (fail-closed), even if reverse DNS suggests domain overlap.
- Reverse DNS context is included in warnings as informational enrichment to help triage IP-rotation cases.
- The `domain_allowlist` uses **forward-confirmed reverse DNS (FCrDNS)**: a PTR hostname is only trusted if it resolves _forward_ back to the original IP. An attacker who sets their C2 server's PTR record to an allowlisted domain cannot bypass the allowlist, because the allowlisted domain's real A/AAAA record does not point back at the C2 IP.

Example — abnormal network behavior detected:

```text
❌ [gyrseek] CRITICAL WARNING: Behavioral anomaly flagged!
Package 'left-pad', version '1.3.0' contacted new endpoints not seen in baseline versions (1.2.0, 1.1.3): ["203.0.113.42"]
ℹ️ [gyrseek] Reverse DNS context for new IPs (informational only): ["203.0.113.42 -> suspicious-c2.example"]
Aborting host operation securely.
```

Example — a new hidden install-time `git clone` detected:

```text
❌ [gyrseek] CRITICAL WARNING: Behavioral anomaly flagged!
Package 'left-pad', version '1.3.0' introduced new git clone behavior not seen in baseline versions (1.2.0, 1.1.3): ["https://github.com/unknown/repo.git|non-recursive"]
Aborting host operation securely.
```

## Git Clone Behavior

- **Install-time clones** (e.g. hidden `git clone` calls inside package scripts) are compared across package versions during scanning, and new behavior is fail-closed unless allowlisted.
- Clone-detection logic can also be exercised for standalone scenarios via integration tests (`tests/git_clone_behavior_tests.rs`).
- **Runtime interception of direct `git clone ...` shell commands is not enabled yet** in the CLI parser.

Example warning (simulation/test context):

```text
❌ [gyrseek] CRITICAL WARNING: Behavioral anomaly flagged!
git clone simulation contacted new endpoints not seen in baseline clone behavior: ["185.199.108.133"]
Aborting host operation securely.
```

## Watched-Process Detection (Shai-Hulud / Bun)

Some supply-chain attacks don't assume a runtime is present — they **download one and use it to run the payload**. The Shai-Hulud "Hades/miasma" PyPI wave downloads the **Bun** JavaScript runtime during install/startup and runs an obfuscated stealer with `bun run _index.js`.

`gyrseek` watches for execution of risky runtimes during the sandbox install and diffs those invocations against the baseline versions. By default it watches **`bun`** and **`deno`** — runtimes that essentially never appear in a normal `npm`/`pip` install, so flagging a newly introduced invocation has a very low false-positive rate. (Common interpreters like `node`, `sh`, and `python` are intentionally _not_ watched, since they appear constantly in legitimate installs.)

> **`bun` and `deno` are detection targets, not supported package managers.** gyrseek watches for them being _executed inside a scanned install_ (e.g. `gyrseek npm install some-pkg`, where the package secretly runs `bun`). You **cannot** wrap them directly — `gyrseek deno ...` or `gyrseek bun ...` is not supported and the command would simply be forwarded unscanned. The package managers gyrseek actually wraps are listed under [Supported Commands](#supported-commands): `uv`, `pip`/`pip3`, `poetry`, and `npm`.

Two cases are detected:

1. **Newly introduced execution** — a baseline version never ran `bun`, but the target version does. The `bun` invocation is "new" and is **fail-closed**.
2. **Existing execution with additions/changes** — a baseline already runs `bun run build`, but the target version _also_ runs `bun run _index.js` (or changes the arguments). Each invocation is recorded as a distinct signature (`bun|run|<args>`), so the extra/changed call is "new" and is **fail-closed**.

Example warning:

```text
❌ [gyrseek] CRITICAL WARNING: Behavioral anomaly flagged!
Package 'left-pad', version '1.3.0' introduced new watched-process execution (for example bun/deno) not seen in baseline versions (1.2.0, 1.1.3): ["bun|run|_index.js"]
This matches the Shai-Hulud class of attack (download a runtime like Bun and execute a hidden payload).
Aborting host operation securely.
```

Tune this with the `watched_executables` and `process_exec_allowlist` config keys (see [Configuration](#configuration)).

> **Scope:** this observes processes executed _inside the sandbox during install_ (where the Bun loader fires for npm-style hooks and where Python install-time execution can occur). The PyPI `*-setup.pth` variant that triggers on the _next interpreter startup_ rather than at install time may execute outside the install window; see [Limitations](#docker-hardening-limitations).

## Configuration

`gyrseek` reads a YAML policy file to allowlist known-good endpoints and tune its release gates.

**Config path:** defaults to `gyrseek.yaml` in the working directory. Override it with `--config` or the `GYRSEEK_CONFIG` environment variable:

```bash
cargo run -- --config ./security-policy.yaml npm install
GYRSEEK_CONFIG=./security-policy.yaml cargo run -- npm install
```

### Config keys

| Key                           | Default       | Purpose                                                                                                                                                                                                                                                        |
| ----------------------------- | ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ip_allowlist`                | empty         | IPs to ignore before anomaly blocking. Canonicalized (equivalent IPv6 forms match); invalid entries are skipped with a warning.                                                                                                                                |
| `domain_allowlist`            | empty         | Domains to ignore. Lowercased, trailing `.` stripped. Subdomains match parents (`cdn.example.com` matches `example.com`). Only **forward-confirmed** PTR hostnames (FCrDNS) are matched, so a spoofed reverse-DNS record cannot bypass the allowlist.          |
| `git_clone_allowlist`         | empty         | Git clone targets to allow when new install-time clone behavior appears (case-insensitive exact URL match).                                                                                                                                                    |
| `baseline_overrides`          | none          | Pin baseline versions per package via `baseline-1` / `baseline-2`. Missing keys fall back to registry-derived baselines.                                                                                                                                       |
| `baseline_count`              | `2`           | How many historical baselines to compare against.                                                                                                                                                                                                              |
| `min_baseline_age_hours`      | `2`           | Per-package minimum age (hours) before a version is eligible as a baseline. Packages not listed use the default.                                                                                                                                               |
| `new_package_exemptions`      | none          | Exempt specific new packages when fewer than 2 eligible baselines exist. `gyrseek` warns once 2+ baselines exist so you can remove the exemption.                                                                                                              |
| `minimum_release_age_package` | off           | Minimum release age in **days**. When set, runs before burst/anomaly checks and fails closed if the current release is younger.                                                                                                                                |
| `release_burst_threshold`     | off           | Fails closed if a package published at least this many versions within the burst window.                                                                                                                                                                       |
| `release_burst_window_hours`  | `24`          | Lookback window (hours) for the burst checker.                                                                                                                                                                                                                 |
| `watched_executables`         | `bun`, `deno` | Executable basenames to flag if **executed inside a scanned install** and diffed across versions (these are detection targets, not package managers gyrseek wraps). Config entries are **added to** the built-in defaults, so `bun`/`deno` are always watched. |
| `process_exec_allowlist`      | empty         | Watched-process signatures (`bun\|run\|build`) or bare executables (`bun`) that are allowed even when newly introduced.                                                                                                                                        |

### Example config

```yaml
ip_allowlist:
  - 151.101.0.223
  - 151.101.64.223
domain_allowlist:
  - pypi.org
  - files.pythonhosted.org
git_clone_allowlist:
  - https://github.com/acme/approved-build-scripts.git
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
minimum_release_age_package: 3
release_burst_threshold: 3
release_burst_window_hours: 24
# Executables to watch for execution *inside* a scanned install (not managers to wrap).
# bun and deno are always watched; entries here are added on top.
watched_executables:
  - bun
  - deno
process_exec_allowlist:
  - bun|run|build
  - deno
```

### Config loading behavior

- If `gyrseek.yaml` is **missing**, `gyrseek` runs with an empty allowlist.
- If a **custom** config path is provided and can't be read, `gyrseek` **fails closed**.

## Sandbox Modes

`gyrseek` runs scan probes through a `SandboxRunner` backend selected by environment variable:

| Mode                 | `GYRSEEK_SANDBOX` | Notes                                                                |
| -------------------- | ----------------- | -------------------------------------------------------------------- |
| **Docker** (default) | `docker`          | Safer default. Requires Docker CLI.                                  |
| **MicroVM**          | `microvm`         | Strongest isolation; needs a MicroVM-capable Docker runtime (Linux). |
| **Host**             | `host`            | Fastest, **reduced safety** — see warning below.                     |

```bash
GYRSEEK_SANDBOX=docker cargo run -- npm install
GYRSEEK_SANDBOX=host  cargo run -- pip3 install -r requirements.txt
```

- If sandbox initialization fails, `gyrseek` exits non-zero (fail-closed).
- ⚠️ **Host mode does not provide meaningful isolation.** If the package is malicious, you are effectively running it directly on your machine and only getting a warning from `gyrseek`. Use it only for local development or environments without Docker.

### MicroVM configuration

- `GYRSEEK_MICROVM_RUNTIME` selects the Docker runtime (default: `kata-runtime`).
- If the runtime isn't present in `docker info`, startup fails closed with an explicit message.
- List available runtimes: `cargo run -- sandbox runtimes`
- Requires a Linux environment with the runtime installed and exposed through Docker. On macOS Docker Desktop, Kata-style runtimes are typically unavailable — use a Linux VM or host.

### Platform support matrix

| Mode      | macOS (Docker Desktop)                                   | Linux host/VM                                                |
| --------- | -------------------------------------------------------- | ------------------------------------------------------------ |
| `docker`  | Supported                                                | Supported                                                    |
| `host`    | Supported (requires local `strace`)                      | Supported (requires local `strace`)                          |
| `microvm` | Usually unavailable (Kata/runtime typically not exposed) | Supported when a MicroVM-capable Docker runtime is installed |

### Scanner image configuration

| Variable                                                       | Default                 | Purpose                                      |
| -------------------------------------------------------------- | ----------------------- | -------------------------------------------- |
| `GYRSEEK_NPM_SCANNER_IMAGE`                                    | `node:22-bookworm-slim` | npm scanner image.                           |
| `GYRSEEK_PY_SCANNER_IMAGE`                                     | `python:3.12-bookworm`  | Python scanner image.                        |
| `GYRSEEK_PREBUILT_SCANNER_IMAGES`                              | `false`                 | Enable prebuilt fast path for both managers. |
| `GYRSEEK_NPM_SCANNER_PREBUILT` / `GYRSEEK_PY_SCANNER_PREBUILT` | `false`                 | Per-manager prebuilt override.               |

In prebuilt mode, runtime setup (`apt-get` and Python `uv` bootstrapping) is skipped to reduce hot-path latency.

## Prebuilt Scanner Images

For faster probe startup and fewer runtime setup failures, prebuild scanner images with the required tools already installed.

### 1) Build an npm scanner image

`Dockerfile.npm-scanner`:

```dockerfile
FROM node:22-bookworm-slim
RUN apt-get update \
   && apt-get install -y --no-install-recommends strace ca-certificates \
   && rm -rf /var/lib/apt/lists/*
```

```bash
docker build -f Dockerfile.npm-scanner -t gyrseek/npm-scanner:latest .

GYRSEEK_NPM_SCANNER_IMAGE=gyrseek/npm-scanner:latest \
GYRSEEK_NPM_SCANNER_PREBUILT=true \
cargo run -- npm update
```

### 2) Build a Python scanner image

`Dockerfile.py-scanner`:

```dockerfile
FROM python:3.12-bookworm
RUN apt-get update \
   && apt-get install -y --no-install-recommends strace ca-certificates \
   && rm -rf /var/lib/apt/lists/*
RUN python -m pip install --no-cache-dir uv
```

```bash
docker build -f Dockerfile.py-scanner -t gyrseek/py-scanner:latest .

GYRSEEK_PY_SCANNER_IMAGE=gyrseek/py-scanner:latest \
GYRSEEK_PY_SCANNER_PREBUILT=true \
cargo run -- uv sync
```

### 3) Enable prebuilt mode globally (optional)

```bash
GYRSEEK_PREBUILT_SCANNER_IMAGES=true \
GYRSEEK_NPM_SCANNER_IMAGE=gyrseek/npm-scanner:latest \
GYRSEEK_PY_SCANNER_IMAGE=gyrseek/py-scanner:latest \
cargo run -- npm update
```

### 4) Verify images are usable

```bash
docker run --rm gyrseek/npm-scanner:latest sh -lc 'strace -V'
docker run --rm gyrseek/py-scanner:latest sh -lc 'strace -V && uv --version'
```

If these pass, `GYRSEEK_*_SCANNER_PREBUILT=true` should work without runtime tool installation.

### 5) Use pinned image digests (recommended for reproducibility)

To avoid tag drift, pin scanner images by digest (replace with real digests from your registry):

```bash
GYRSEEK_NPM_SCANNER_IMAGE=gyrseek/npm-scanner@sha256:REPLACE_WITH_REAL_DIGEST \
GYRSEEK_PY_SCANNER_IMAGE=gyrseek/py-scanner@sha256:REPLACE_WITH_REAL_DIGEST \
GYRSEEK_PREBUILT_SCANNER_IMAGES=true \
cargo run -- npm update
```

> **Tip:** Build and push scanner images once in CI, resolve immutable digests, and reference only digest-pinned images in production or shared CI.

## Behavior Reference

Details worth knowing once you're past the basics.

**Execution & caching**

- `gyrseek` forwards your command in the current working directory.
- Repeated package-version probes within the same CLI execution are cached in-memory and reused.
- Docker mode batches probe matrices (multiple packages × versions) into a single container run when possible.

**Version handling**

- Version selection is semantic-version aware: npm uses semver, Python (pip/uv/poetry) uses PEP 440. Unparseable version strings sort below any parseable version, so malformed entries are never chosen as `latest`.
- After a clean scan of an unpinned (`latest`) **explicit install target**, the forwarded command is rewritten to pin the exact version that was examined, so the host installs the same version `gyrseek` scanned. Lockfile-driven flows (`uv sync`, `poetry install`, etc.) already carry pinned versions and are forwarded verbatim.
- If baseline versions are unavailable, output may show `baseline-1=n/a` and `baseline-2=n/a`.

**Per-command scanning scope**

- `uv sync` scans all packages found in `uv.lock` before forwarding.
- `uv sync` and `uv lock --upgrade` exclude local project entries (editable/path/workspace blocks) from comparison.
- `uv pip sync` scans all parseable packages from its source files (requirements-style files and `pylock.toml`).
- `uv lock --upgrade` scans all packages in `uv.lock`; `uv lock -P/--upgrade-package` scans the explicitly targeted packages.
- `pip install` / `pip3 install` scan all parseable entries, including `-r/--requirements` files.
- `poetry install` / `poetry update` scan all packages in `poetry.lock`, excluding local directory/path/editable source blocks.
- `npm install`, `npm i`, `npm update` scan explicit targets; with no targets they scan `package.json` dependencies, excluding local/non-registry specs (`file:`, `workspace:`, `git+`, URL/link).

**Fail-closed guarantees**

- For supported install/sync paths, package-detection failures are fail-closed (non-zero exit) instead of passthrough.
- If the host command itself cannot be launched after a clean scan, `gyrseek` also fails closed.
- A sandbox probe that produces an **empty/whitespace trace** (e.g. `strace` could not attach) is a hard error: every package in that batch is blocked. Blank traces are never interpreted as clean.
- When a forwarded command exits non-zero, `gyrseek` **exits with the same code** rather than masking the failure as success.

## Docker Hardening Limitations

The Docker sandbox is currently tuned for practical compatibility and throughput, not maximum isolation.

**Current limitations:**

- Container setup installs probe tooling at runtime (`apt-get`, and `uv` for Python).
- Container setup and `strace` run as root so the trace logs are root-owned — but the **traced install payload itself runs unprivileged** (`strace -u`), so a malicious install script cannot overwrite or delete its own trace before `gyrseek` reads it.
- The container is granted **`CAP_SYS_PTRACE`** (`--cap-add SYS_PTRACE`). `strace` runs as root but attaches to the install running as the unprivileged scanner user, and cross-UID `ptrace` needs this capability — Docker does not grant it by default. It is scoped to the container's own PID namespace and **cannot** trace host processes. Without it, `strace` fails with `ptrace(PTRACE_SEIZE): Operation not permitted`, which (correctly) fails the scan closed: no trace means the package is blocked, not passed.
- Full `--read-only` rootfs is not enabled.
- Capabilities are not fully dropped, and `SYS_PTRACE` is explicitly added (see above).
- Outbound network remains generally available so package-manager traffic can proceed.
- Behavioral detection (network, git clone, watched-process execution) observes what runs **during the sandbox install**. Payloads designed to fire _outside_ the install window — e.g. the PyPI `*-setup.pth` variant that executes on the next `python`/`pip`/CI interpreter startup rather than at install — may not detonate during the scan, so their behavior may not be captured.

**Why:** earlier stricter configs (read-only rootfs + full capability drop + non-root setup) caused apt/setup failures that prevented scans from running. The current config is the stable path that lets matrix probes complete in one sandbox run.

**Recommended hardening direction:**

- Use prebuilt scanner images that already include required tooling (`strace`, certs, and `uv` where needed).
- With prebuilt images in place, re-enable non-root runtime, read-only rootfs, and drop all capabilities except `SYS_PTRACE` (which tracing requires).
- Add seccomp/apparmor policies and image digest pinning.
- Consider tighter egress controls (allowlist or proxy model).
- Add no-execution-first checks (artifact diff / static heuristics / provenance gates) before runtime execution, in phases: artifact fetch/unpack → static diff scoring → pre-runtime policy gating.

> **Performance note:** prebuilt images + prebuilt mode (`GYRSEEK_PREBUILT_SCANNER_IMAGES=true` or per-manager vars) avoid runtime setup overhead.

## Testing

```bash
# Run everything
cargo test

# Run one integration test file
cargo test --test parser_tests
cargo test --test behavior_tests
cargo test --test cli_burst_exit_tests
cargo test --test git_clone_behavior_tests
cargo test --test git_clone_scan_tests
cargo test --test bun_exec_scan_tests

# Run one specific test case
cargo test parses_npm_install_with_pinned_version
cargo test detects_anomalous_new_connection

# Show println! output while testing
cargo test -- --nocapture
```

Behavior test coverage includes deterministic DNS-enrichment checks for reverse-DNS context handling (including unresolved-IP scenarios).

## Project Layout & Docs

**Source & tests**

- `src/main.rs` — binary entrypoint
- `src/lib.rs` — command routing and orchestration
- `src/parsing.rs` — command, lockfile, and requirements parsing helpers
- `src/scanning.rs` — registry lookup and behavior scanning engine
- `src/sandbox.rs` — sandbox backends and mode selection
- `tests/parser_tests.rs` — command parsing tests
- `tests/behavior_tests.rs` — behavior anomaly simulation tests
- `tests/git_clone_behavior_tests.rs` — git clone behavior simulation tests
- `tests/git_clone_scan_tests.rs` — install-time git-clone signature diff tests
- `tests/bun_exec_scan_tests.rs` — watched-process (bun/deno) execution diff tests

**Collaboration docs** (for multi-developer / multi-LLM work)

- `docs/ARCHITECTURE.md` — control-flow and component map
- `docs/DEV_GUIDE.md` — contributor workflow and change hygiene
- `docs/ROADMAP.md` — planned improvements and next steps
- `.copilot/AGENTS.md` — repository memory and mandatory update policy

> **Repository policy:** after each change, update both `.copilot/AGENTS.md` and `README.md`.

## License

See [LICENSE](LICENSE).
