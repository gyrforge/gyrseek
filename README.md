# gyrseek

[![CI](https://github.com/gyrforge/gyrseek/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/gyrforge/gyrseek/actions/workflows/ci.yml?query=branch%3Amain)

`gyrseek` is a Rust CLI wrapper that sits in front of your package manager. Before it lets an install or update run, it installs the target version (and a couple of older "baseline" versions) inside a sandbox, traces their behavior with `strace`, and **blocks the command if the new version does something the older ones never did** — like contacting a new network endpoint or running a hidden `git clone`.

Think of it as a behavioral diff between "the version you're about to install" and "versions that were already trusted."

```bash
# Instead of:        npm install lodash
# You run:           ./target/release/gyrseek npm install lodash
```

If nothing suspicious is found, your original command is forwarded and runs normally. If something new shows up, `gyrseek` aborts and tells you why.

> [!WARNING]
> **Scope: supply chain malware only.** `gyrseek` is built specifically to catch malware that infects packages and acts at install time, in the style of Shai-Hulud: credential theft, new network endpoints, downloaded or dropped executables, and similar behavior changes between versions. It is **not suitable for protecting against other types of sophisticated malware**, such as targeted or anti-analysis malware, malware that evades tracing or detects it is being scanned, or anything that tries to escape the sandbox. For **second-stage payloads**, `gyrseek` detects the behavior of a second stage happening during the install (for example a new network endpoint, a downloaded or dropped executable, or a newly started process), but it does **not analyze the payload itself**: it never inspects what the downloaded code does or contains. A loader that fetches or runs its real payload outside the install window (after a delay, on first import, on a later run, or only under conditions the sandbox does not reproduce) will not show that behavior during the scan at all. A clear result means no new install-time behavior was observed compared with the baseline versions. It does not mean the package is safe. See [Package Related Supply Chain Attack Detection Coverage](docs/DETECTION_COVERAGE.md#package-related-supply-chain-attack-detection-coverage) for what is and is not covered.

## Table of Contents

- [Introduction](#introduction)
- [Quick Start](#quick-start)
- [Supported Commands](#supported-commands)
- [Usage](#usage)
- [How It Works](#how-it-works)
- [Configuration](docs/CONFIGURATION.md#configuration)
- [Sandbox Modes](docs/SANDBOX.md#sandbox-modes)
- [Docker Security](#docker-security)
- [Documentation](#documentation)
- [License](#license)

## Introduction

This tool was created by [Brandon Chuah](https://www.linkedin.com/in/brandonccl/) and [David Craggs](https://www.linkedin.com/in/david-craggs-37851793/), who were working in internal product security roles when we began building this open source CLI. Both gyrforge and gyrseek are maintained solely by individuals rather than by any company.

Our goal is not to compete with existing vendors. Instead, we want to give open source maintainers and small businesses, especially those that might not be able to afford expensive commercial software supply chain tooling, a practical way to address the kinds of supply chain issues highlighted by incidents such as Shai-Hulud.

The tool works out of the box and requires no proxy configuration, as long as Docker is installed. A `host` mode exists, but it provides **no protection, only detection**: every probe, including the candidate version being vetted, runs the package's install scripts directly on your machine with your user's files, credentials and environment variables, before `gyrseek` can say anything. A block only stops the follow-up real install; it cannot undo what the probe already ran. Run it only in a **very isolated** situation: a disposable environment (throwaway VM or ephemeral CI runner) that holds no secrets or credentials and has no route to internal networks, where that environment itself is the sandbox. Never on a developer laptop or any machine with real credentials.

We welcome feedback and suggestions to this repository. For anything that is not a public issue or pull request, reach us at **gyrforge@outlook.com**; for a suspected vulnerability in gyrseek itself, use that address rather than an issue and see [SECURITY.md](SECURITY.md).

## Quick Start

### 1. Prerequisites

Check these before your first scan. If Docker is missing or not running, `gyrseek` stops at startup with exit code 1 and tells you which. (In host mode there is no startup check for `strace`; a missing `strace` fails at the first probe.)

| Requirement | Needed for | Notes |
|---|---|---|
| **Docker, installed and running** | Every scan (the default and only sandbox) | The `docker` CLI must be on your `PATH` and the daemon must be running (Docker Desktop on macOS, the Docker service on Linux). Your user needs permission to talk to it (on Linux, usually the `docker` group). The first scan pulls the scanner image for the package manager you use, so it needs access to Docker Hub or your mirror. |
| **Linux, macOS, or Windows via WSL2** | Running `gyrseek` | Native Windows is not supported: run `gyrseek` inside a WSL2 distro that has Docker. |
| **The package manager you wrap** | The forwarded install | `uv`, `pip`/`pip3`, `poetry`, `npm`, or `pnpm`, installed on the machine where you run `gyrseek`. The scan itself runs inside the container, but a clear scan forwards your command to the real tool. |
| **Network access to the package registries** | Registry lookups and the probes | PyPI and/or npm (or your configured registries). |
| **Rust toolchain** (`cargo`, `rustc`) and [`just`](https://github.com/casey/just) | Building from source only | Not needed if you already have a built `gyrseek` binary. |
| `strace` and GNU `timeout` on your `PATH` | Host mode only | Only for `--no-sandbox` (no isolation, detection only), and only on Linux or WSL2. `timeout` comes with coreutils and enforces `probe_timeout_seconds`. Not needed for the default Docker mode. |

Quick check:

```bash
docker --version   # Docker CLI is installed
docker info        # the daemon is running and you may use it
```

### 2. Build

```bash
just build
# binary is produced at: target/release/gyrseek
```

Or, with only a Rust toolchain and no checkout, build a tagged release from source (the crate versions in `Cargo.lock` are used as committed):

```bash
cargo install --locked --git https://github.com/gyrforge/gyrseek --tag v1.4.3
# installs gyrseek into ~/.cargo/bin; make sure that directory is on your PATH
```

On Linux this also needs `pkg-config` and the OpenSSL development headers (`libssl-dev` on Debian and Ubuntu). On macOS nothing else is needed.

### 2b. Or download a release (Linux and macOS)

Each release (`vX.Y.Z`) on the [Releases page](https://github.com/gyrforge/gyrseek/releases) has an archive for each platform below, a `.deb` for each Linux architecture from `v1.4.5` onward (see [2c](#2c-or-install-the-debian-package-debian-and-ubuntu)), and a `SHA256SUMS` file covering all of them. There is no Windows build: on Windows, use WSL2 with the Linux archive.

| Archive | For |
|---|---|
| `gyrseek-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz` | Linux on Intel/AMD (`uname -m` prints `x86_64`) |
| `gyrseek-vX.Y.Z-aarch64-unknown-linux-gnu.tar.gz` | Linux on ARM (`uname -m` prints `aarch64`) |
| `gyrseek-vX.Y.Z-aarch64-apple-darwin.tar.gz` | macOS on Apple Silicon (`uname -m` prints `arm64`) |
| `gyrseek-vX.Y.Z-x86_64-apple-darwin.tar.gz` | macOS on Intel (`uname -m` prints `x86_64`) |

(`unknown` is the vendor field of the Rust target name, which Linux has none of; it is not a missing value. `apple-darwin` is macOS.)

**Prerequisites for the binary:** Ubuntu 22.04 or newer, or another distribution with glibc 2.35+ and OpenSSL 3 (it links both dynamically), plus everything in [Prerequisites](#1-prerequisites) above, Docker above all. Run `ldd gyrseek` to see a missing library. **On macOS:** macOS 13 or newer, with Docker Desktop running; the binary uses only system frameworks, so there is nothing else to install. It is signed ad hoc, not notarized: downloading with `gh` or `curl` is fine, but a file saved by a browser carries a quarantine flag that makes macOS refuse to open it, which `xattr -d com.apple.quarantine "gyrseek-vX.Y.Z-TARGET/gyrseek"` clears, run from the directory where you extracted the archive.

**Where to run it:** use an Ubuntu 22.04 or 24.04 runner, which has Docker preinstalled on GitHub-hosted runners (`ubuntu-22.04`, `ubuntu-24.04`, `ubuntu-latest`; for the ARM archive `ubuntu-22.04-arm` or `ubuntu-24.04-arm`, there is no `ubuntu-latest-arm`). The release is built and smoke-tested on `ubuntu-22.04`. For a self-hosted runner or your own image, start from `ubuntu:22.04` or newer (Debian 12 also meets the glibc and OpenSSL 3 requirements) and add `libssl3` and `ca-certificates`. Alpine and other musl-based images are not supported: the binary needs glibc. gyrseek starts its own sandbox containers, so a job that itself runs in a container needs access to a Docker daemon (for example the host's socket); that setup is not tested here.

GitHub-hosted macOS runners have no Docker, so they cannot run a scan.

**Keep secrets out of the job.** A clear scan is evidence, not a guarantee (see [the coverage table](docs/DETECTION_COVERAGE.md) and the open findings): after it, the forwarded install runs on the runner itself, as the runner user, with the job's environment. Do not put cloud credentials, registry or publish tokens, SSH keys or other secrets in the environment of a job that installs packages through gyrseek, and do not run it on a runner that holds any. Install in a job of its own with the read-only `GITHUB_TOKEN` permissions it needs (`contents: read`), no `secrets.*` and `persist-credentials: false` on checkout, and hand the result to later jobs as an artifact. `--no-sandbox` is worse: it runs every probe on the host with no isolation, so use it only in a disposable environment that has no secrets.

Verify, then install (replace the version and architecture):

```bash
v=1.4.3; t=x86_64-unknown-linux-gnu   # or aarch64-unknown-linux-gnu, aarch64-apple-darwin, x86_64-apple-darwin
gh release download "v$v" --repo gyrforge/gyrseek -p "gyrseek-v$v-$t.tar.gz" -p SHA256SUMS
# the archive matches the published hash (macOS has no sha256sum, so it uses shasum)
if command -v sha256sum >/dev/null; then sha256sum --ignore-missing -c SHA256SUMS
else grep "gyrseek-v$v-$t.tar.gz" SHA256SUMS | shasum -a 256 -c -; fi
gh attestation verify "gyrseek-v$v-$t.tar.gz" --repo gyrforge/gyrseek   # built by this repository's release workflow
tar -xzf "gyrseek-v$v-$t.tar.gz"
sudo install -m 0755 "gyrseek-v$v-$t/gyrseek" /usr/local/bin/gyrseek
# or, without root, into a directory on your PATH that you own:
# mkdir -p "$HOME/.local/bin" && install -m 0755 "gyrseek-v$v-$t/gyrseek" "$HOME/.local/bin/gyrseek"
gyrseek --version                                                  # prints: gyrseek 1.4.3
```

Without `gh`, download the same files from the Releases page; the hash check works without it. For a CI runner, pin the version and the expected SHA-256 in your own pipeline instead of trusting whatever the download returns. The archive holds `gyrseek`, `LICENSE`, `NOTICE` and `README.md`.

### 2c. Or install the Debian package (Debian and Ubuntu)

Releases from `v1.4.5` onward also have a `.deb` for each Linux architecture, built from the same binary as the archive above and listed in the same `SHA256SUMS`. Earlier releases are immutable and have archives only.

Verify, then install (replace the version):

```bash
v=1.4.5
a=$(dpkg --print-architecture)          # amd64 or arm64
gh release download "v$v" --repo gyrforge/gyrseek -p "gyrseek_${v}-1_${a}.deb" -p SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS                           # matches the published hash
gh attestation verify "gyrseek_${v}-1_${a}.deb" --repo gyrforge/gyrseek   # built by this repository's release workflow
sudo apt install "./gyrseek_${v}-1_${a}.deb"
gyrseek --version                                                  # prints: gyrseek 1.4.5
```

Without `gh`, download the same files from the Releases page; the hash check works without it.

`apt` resolves the glibc and OpenSSL dependencies, which is the difference from unpacking the archive by hand, and `apt` also pulls in `docker.io` because the package recommends it; pass `--no-install-recommends` if you already run Docker from another source (Docker CE, rootless, or a remote daemon). Same platform requirements as the archives: glibc 2.35 or newer with OpenSSL 3, so Ubuntu 22.04, Debian 12 or newer.

This is a package *file*, not an apt repository: `apt upgrade` will not update it, so repeat the command for a new version. gyrseek is **not** in the official Debian or Ubuntu archives, so `apt install gyrseek` with no path will not find it.

### 2d. Or install with Homebrew (macOS and Linux)

```bash
brew tap gyrforge/gyrseek
brew trust gyrforge/gyrseek   # Homebrew 7 and newer; skip on an older Homebrew
brew install gyrseek
gyrseek --version
```

`brew trust` is a deliberate step: Homebrew 7 and newer will not load a third-party tap's formula until you trust it, so read [the formula](https://github.com/gyrforge/homebrew-gyrseek/blob/main/Formula/gyrseek.rb) first. It installs the same release archives as step 2b and checks each against the SHA-256 in the formula, which is generated from the release's `SHA256SUMS` after its build attestation is verified. The requirements are the same as for the archives: Docker running, and on Linux glibc 2.35 or newer with OpenSSL 3 (Ubuntu 22.04 or newer). See [homebrew-gyrseek](https://github.com/gyrforge/homebrew-gyrseek).

### 3. Run your first scan

```bash
# Scan + (if clean) install lodash via npm:
./target/release/gyrseek npm install lodash
```

That's it. `gyrseek` resolves the version, runs the sandbox behavioral diff, and either forwards your command or blocks it with an explanation.

## Supported Commands

| Ecosystem  | Commands                                                                                                                              |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| **uv**     | `uv add`, `uv pip install`, `uv pip sync <SRC_FILE>...`, `uv sync`, `uv lock`, `uv lock --upgrade`, `uv lock -P\|--upgrade-package`  |
| **pip**    | `pip install`, `pip3 install` (including `-r/--requirements` files)                                                                   |
| **poetry** | `poetry add`, `poetry update`, `poetry install`, `poetry lock`                                                                        |
| **npm**    | `npm install`, `npm i`, `npm update`                                                                                                  |
| **pnpm**   | `pnpm add`, `pnpm install`, `pnpm i`, `pnpm update`                                                                                   |

> Standalone `git clone` runtime interception is not enabled yet — only install-time clone behavior _inside_ package scans is enforced today (see [Git Clone Behavior](docs/DETECTION.md#git-clone-behavior-detection)).

> **`--version` / `-V`:** pass either flag as the first argument to print `gyrseek <version>` and exit 0. This works with no config file or Docker present. A forwarded command's own trailing `--version` (e.g. `gyrseek pip install foo --version`) is passed through unchanged.

## Usage

General pattern:

```bash
cargo run npm install lodash
# or, with the release binary:
./target/release/gyrseek npm install lodash
```

### Python examples

```bash
./target/release/gyrseek uv add pytest
./target/release/gyrseek uv pip install requests==2.31.0
./target/release/gyrseek uv pip sync requirements.txt
./target/release/gyrseek uv pip sync pylock.toml
./target/release/gyrseek uv sync
./target/release/gyrseek uv lock --upgrade
./target/release/gyrseek uv lock -P pytest -P requests
./target/release/gyrseek pip install flask
./target/release/gyrseek pip3 install django==5.0.6
./target/release/gyrseek pip3 install -r requirements.txt
./target/release/gyrseek poetry install
./target/release/gyrseek poetry update pytest
```

### npm examples

```bash
./target/release/gyrseek npm install lodash
./target/release/gyrseek npm install lodash express
./target/release/gyrseek npm i lodash@4.17.21
./target/release/gyrseek npm install
./target/release/gyrseek npm update
./target/release/gyrseek npm update lodash typescript
```

### pnpm examples

```bash
./target/release/gyrseek pnpm add lodash
./target/release/gyrseek pnpm add lodash express
./target/release/gyrseek pnpm add lodash@4.17.21
./target/release/gyrseek pnpm install
./target/release/gyrseek pnpm update
./target/release/gyrseek pnpm update lodash typescript
```

> For project-aware tools like `poetry` or `npm`, run inside a directory containing the expected project files (`pyproject.toml`, `package.json`, etc.).

## How It Works

1. **Parse** the package name and optional version from your command. If no version is given, it's treated as `latest`.
2. **Fetch version history** from PyPI (Python) or the npm registry (npm/pnpm) and order it semantically (semver for npm-family packages, PEP 440 for Python).
3. **Run sandbox installs** for:
   - the current/target version
   - the previous version (`baseline-1`)
   - two versions back (`baseline-2`)

   Multiple packages and versions may run in one sandbox session while keeping per-package, per-version trace attribution. Bulk commands (`uv sync`, `uv pip sync`, etc.) apply this to every detected package.

4. **Compare behavior signals** between the target and its baselines:
   - **Network**: endpoints contacted during install (see [Network Behavior Detection](docs/DETECTION.md#network-behavior-detection)).
   - **Git clone**: install-time `git clone` command signatures (see [Git Clone Behavior Detection](docs/DETECTION.md#git-clone-behavior-detection)).
   - **Process execution**: all programs executed during install — the payload's own commands plus the sandbox's internal setup (see [Process-Execution Detection](docs/DETECTION.md#process-execution-behavior-detection)).
   - **Sensitive files**: attempts to read sensitive credentials or configuration files (see [Sensitive File Access Behavior Detection](docs/DETECTION.md#sensitive-file-access-behavior-detection)).
   - **Artifacts**: post-install file inventory of every installed file — binary executables, suspicious `.pth` files, unexpected runtimes, and large files (see [Post-Install Artifact Detection](docs/DETECTION.md#post-install-artifact-behavior-detection)).
5. **Decide**:
   - If one or more behavioral anomalies are found (e.g., new endpoint, clone behavior, process execution, sensitive file read, or artifact finding) → **all findings are aggregated, reported together, and the install is blocked (exits non-zero)**. It does not short-circuit on the first failure.
   - Nothing new → **forward your original command**.
6. **Fail closed**: if a package target was expected but couldn't be detected — _or if the sandbox produced no trace at all_ (e.g. `strace` could not attach) — `gyrseek` blocks rather than letting the command through. A blank trace is never treated as a clean, zero-activity install. New artifact findings across versions also fail closed.
7. **Propagate the host exit code**: when the original command is forwarded, `gyrseek` exits with the package manager's own status. A failed install (non-zero) surfaces as non-zero, so agents and CI `$?` checks are not misled into thinking a broken install succeeded.

This gives you a _behavioral_ signal, rather than relying only on package metadata.

> **Transitive Dependencies:** `gyrseek` natively covers transitive dependencies in two ways:
> 1. **Explicit single-package installs** (e.g., `npm install express`): The sandbox runs the complete package manager install process. Because `strace` monitors the entire process tree, any network connections or process executions triggered by a transitive dependency's install scripts are captured in the trace. If a transitive dependency introduces new malicious behavior not present in the top-level package's baseline, the install is blocked. The import-time scan (below) also loads the dependencies the install brought, so their module-scope code runs under strace too (npm and Python; pnpm loads only the package itself, OPEN #502).
> 2. **Lockfile and bulk syncs** (e.g., `uv sync`, `poetry install`, `npm install`): `gyrseek` parses the lockfile or manifest directly. It extracts every package in the dependency tree—including all transitive dependencies—and runs isolated sandbox tests for each one against its own historical baselines before proceeding.

> **PEP 508 extras** (e.g. `requests[security]`) are handled correctly: the extras are stripped for registry lookups and version-pin bookkeeping (so the PyPI lookup hits `requests`, not a 404), while the forwarded install command keeps the full `requests[security]==<scanned version>` spec.

The detail of each check is in [docs/DETECTION.md](docs/DETECTION.md); known attack waves and the verdict on each are in [docs/DETECTION_COVERAGE.md](docs/DETECTION_COVERAGE.md).

Per-command behavior, version handling and lockfile rules: [docs/BEHAVIOR_REFERENCE.md](docs/BEHAVIOR_REFERENCE.md).

## Configuration

`gyrseek` reads a YAML policy file (`gyrseek.yaml` by default, or `--config <path>`, or `GYRSEEK_CONFIG`) to allowlist known-good endpoints and tune its release gates.

```yaml
ip_allowlist:
  - 151.101.0.223        # global: applies to all packages
  - my-private-pkg:      # per-package: only applies to my-private-pkg
    - 10.0.0.1
baseline_count: 2
release_burst_threshold: 20
```

Every key, the CLI arguments, a full example and the loading rules are in [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

## Sandbox Modes

`gyrseek` runs scan probes through a `SandboxRunner` backend. Docker is the default; host mode is selected only with the `--no-sandbox` flag:

| Mode                 | Selected by       | Notes                                                                |
| -------------------- | ----------------- | -------------------------------------------------------------------- |
| **Docker** (default) | (default)         | Safer default. Requires the Docker CLI and a running daemon; if either is missing, `gyrseek` stops at startup with exit code 1 and says which. |
| **Host**             | `--no-sandbox`    | Fastest, **no isolation and zero protection (detection only)**. This mode exists purely for running in isolated environments — see warning below. |

Docker is the default and the only sandbox that isolates anything. Host mode must be requested explicitly with `--no-sandbox`, runs the package directly on your machine with your environment, and detects but does not protect: use it only in a disposable environment that holds no secrets. Platform support, scanner images (including Python and Node version selection), prebuilt images and digest pinning are in [docs/SANDBOX.md](docs/SANDBOX.md); hardening of the container is in [docs/DOCKER_SECURITY.md](docs/DOCKER_SECURITY.md).

## Docker Security

See [docs/DOCKER_SECURITY.md](docs/DOCKER_SECURITY.md) for the canonical reference on how the sandbox container is hardened (seccomp, AppArmor, capabilities, unprivileged payload, trace integrity) and what it does not cover.

## Documentation

| Document | What it covers |
|---|---|
| [docs/DETECTION.md](docs/DETECTION.md) | Each behavior check in detail: network, git clone, process execution, sensitive files, artifacts |
| [docs/DETECTION_COVERAGE.md](docs/DETECTION_COVERAGE.md) | Known supply chain attack waves, gyrseek's verdict on each, and the gaps |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | CLI arguments, every config key, a full example |
| [docs/BEHAVIOR_REFERENCE.md](docs/BEHAVIOR_REFERENCE.md) | Per-command scanning scope, version handling, lockfiles and edge cases |
| [docs/SANDBOX.md](docs/SANDBOX.md) | Sandbox modes, platform support, scanner images, prebuilt images |
| [docs/DOCKER_SECURITY.md](docs/DOCKER_SECURITY.md) | Container hardening: seccomp, AppArmor, capabilities, validation |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | `just` recipes and how to run the tests |
| [docs/RELEASING.md](docs/RELEASING.md) | Step by step: version bump, PR, tag, publish, verify, and the action and Homebrew follow-ups |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Control flow, components, CI/CD, threat model, contributor workflow |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Planned improvements |
| [SECURITY.md](SECURITY.md) | How to report a vulnerability in gyrseek, and what is in and out of scope |
| [AGENTS.md](AGENTS.md) | Repository memory and the mandatory update policy for contributors and agents |

> **Repository policy:** after each change, update both `AGENTS.md` and `README.md`.

## License

Copyright 2026 Gyrforge. gyrseek is licensed under the [Apache License 2.0](LICENSE); the attribution is in [NOTICE](NOTICE). Releases up to and including v1.4.2 were published under the LGPL-2.1 and stay under it for anyone who already has them; v1.4.2 was tagged just before the relicensing was merged, so its archives carry the LGPL `LICENSE`. From v1.4.3 on, the archives carry the Apache-2.0 `LICENSE` and `NOTICE`.
