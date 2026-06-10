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
- [How It Works](#how-it-works)
- [Usage](#usage)
- [Network Behavior Detection](#network-behavior-detection)
- [Git Clone Behavior Detection](#git-clone-behavior-detection)
- [Watched-Process Detection (Shai-Hulud / Bun)](#watched-process-detection-shai-hulud--bun)
  - [Shai-Hulud detection coverage](#shai-hulud-detection-coverage)
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

Our goal is not to compete with existing vendors. Instead, we want to give open source maintainers and small businesses, especially those that might not be able to afford expensive commercial software supply chain tooling, a practical way to address the kinds of supply chain issues highlighted by incidents such as Shai-Hulud.

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
| `just fmt` | Formats the Rust code. |
| `just test` | Runs `cargo test --all-features --locked`. |
| `just lint` | Runs clippy for all targets/features and a format check. Use this before committing. |
| `just test-npm` | End-to-end test: scans and installs `lodash`, then runs `npm update` and `npm i` against the test fixture in `tests/npm/`. Builds the release binary first. |
| `just test-pip` | End-to-end test: creates a venv, then scans and installs `black` and the packages from `tests/pip/requirements.txt` via `pip3`. Builds the release binary first. |
| `just test-poetry` | End-to-end test: scans `poetry add black`, `poetry install --no-root`, `poetry update`, and `poetry lock` from the `tests/poetry/` fixture. Builds the release binary first. |
| `just test-uv` | End-to-end test: scans `uv add black`, `uv pip install`, `uv sync`, and `uv lock` from the `tests/uv/` fixture. Builds the release binary first. |

**Typical workflow:**

```bash
# Build once
just build

# Install into Cargo's bin directory
just install

# Uninstall from Cargo's bin directory
just uninstall

# Run tests
just test

# Check everything is healthy before pushing
just lint

# Run a live end-to-end test for the manager you changed
just test-npm
just test-pip
just test-uv
just test-poetry
```

> The end-to-end recipes use `GYRSEEK_SANDBOX=docker` by default (inherited from your environment). Make sure Docker is running before executing them.

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

## Git Clone Behavior Detection

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

> **`bun` and `deno` are detection targets, not supported package managers.** gyrseek watches for them being _executed inside a scanned install_ (e.g. `gyrseek npm install some-pkg`, where the package secretly runs `bun`). You **cannot** wrap them directly — `gyrseek deno ...` or `gyrseek bun ...` will be **rejected with a non-zero exit** because gyrseek only accepts the managers it can actually scan. The package managers gyrseek wraps are listed under [Supported Commands](#supported-commands): `uv`, `pip`/`pip3`, `poetry`, and `npm`.

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
### Shai-Hulud detection coverage

The Shai-Hulud campaign has produced several named attack waves across different ecosystems, each using different execution techniques. The table below maps each wave to gyrseek's verdict and — where the attack fires during install — the specific IoCs gyrseek would have captured.

> **Key:** ✅ Caught during install · ❌ Missed (deferred or out of scope) · ⚠️ Partial

| Attack wave | Ecosystem | Technique | gyrseek | IoCs gyrseek captures (✅) / Why missed (❌) |
|---|---|---|---|---|
| **Hades / Miasma PyPI wave** | PyPI | T1: `*-setup.pth` auto-executes on next Python startup | ❌ | Fires outside the install window — `.pth` is written to disk during `pip install` but not executed until the next interpreter invocation. No anomalous network or execve during install. |
| **Bioinformatics & MCP wave** | PyPI | T2: `__init__.py` import hook fires on package import | ❌ | Deferred to import — outside the sandbox window. |
| | PyPI | T3: compiled `.abi3.so` executes payload via `dlopen()` on import | ❌ | Deferred to import — outside the sandbox window. |
| | PyPI | T4: split loader/payload across two packages, both needed at Python startup | ❌ | Neither package alone triggers during install; deferred like T1. |
| **gpt-pilot GitHub source compromise** | Python (source repo) | T8: injected telemetry `__init__.py` spawns daemon on application import | ❌ | Fires on import, not `pip install`. The registry wheel is clean; the malicious code is in the source tree. |
| **Red Hat Cloud Services npm** | npm | T5: `preinstall` hook runs `node index.js` during `npm install` | ✅ | **Network:** new outbound connection to `github.com/oven-sh/bun/releases` (Bun download). **Bun execve:** `bun\|run\|_index.js`. Both flagged vs. baseline. |
| | npm | T13: fake `api.anthropic.com` traffic during exfiltration | ✅ | If exfiltration fires during the `npm install` step, the new IP is flagged as a new network connection. |
| | npm | T21: LLM prompt injection in `_index.js` to defeat static scanners | ✅ (unaffected) | gyrseek uses runtime behavioral diffing, not LLM analysis — prompt injection in the payload has no effect on gyrseek's detection. |
| **@antv ecosystem worm** (639 versions, 323 packages) | npm | T5: `preinstall` hook on each worm-republished package | ✅ | **Network:** new outbound connection to `github.com/oven-sh/bun/releases`. **Bun execve:** `bun\|run\|_index.js`. Each worm-injected package triggers the same signals inside the sandbox. |
| | npm | T15: worm self-propagation via stolen npm tokens (republishes 639 versions) | ⚠️ | The initial install of any worm-injected package is caught (T5 above). The downstream worm propagation — using stolen tokens to republish further packages — is not blocked by gyrseek. **Release burst signal:** 639 versions published in 60 minutes would trip `release_burst_threshold` if configured. |
| **Intercom npm compromise** | npm | T6: `preinstall` runs `node setup.mjs`, downloads `router_runtime.js` | ✅ | **Network:** new outbound connection to `github.com/oven-sh/bun/releases` for `bun-linux-x64.zip`. **Bun execve:** `bun\|run\|router_runtime.js`. |
| | npm | T22: git tag force-update — malicious commit pushed under existing version tag | ⚠️ | If the force-pushed tag introduces new behavioral signals (network, bun execve), the diff catches them. A tag update with no install-time behavioral change is not caught. |
| **Intercom PHP / Packagist** | PHP | T7: Composer plugin `post-install-cmd` runs shell script, downloads Bun | ❌ | PHP/Packagist is not a supported manager. Outside gyrseek's scope. Network IoC if it were in scope: `zero.masscan.cloud:443`. |
| **Post-compromise — CI/CD** | Any | T9: GitHub Actions workflow injection (push-triggered) | ❌ | Fires after the malicious package already ran. Outside gyrseek's install-window scope. |
| | Any | T10: GitHub Actions workflow injection (deployment API, no `workflow` scope needed) | ❌ | Same — post-compromise CI/CD persistence. |
| **Post-compromise — C2 & exfiltration** | Any | T11: steganographic C2 via GitHub commit messages (RSA-PSS signed commands) | ❌ | Post-compromise polling — not install-time. |
| | Any | T12: GitHub repo dead-drop exfiltration (encrypted credentials committed to attacker repo) | ❌ | Post-compromise — not install-time. |
| | Any | T14: cross-platform process memory scraping (`/proc/mem`, Mach APIs, `ReadProcessMemory`) | ❌ | Payload runs outside the sandbox window. |
| **Post-compromise — persistence** | Any | T16: IDE/AI tool config hijacking (`.claude/settings.json`, `.vscode/tasks.json`, Cursor, Copilot) | ❌ | Fires on workspace/session open — post-compromise persistence. |
| | Any | T17: systemd / LaunchAgent persistence (`update-monitor.service`, `gh-token-monitor.service`) | ❌ | OS-level persistence installed post-compromise. |
| | Any | T19: SSH lateral movement via `~/.ssh/known_hosts` | ❌ | Post-compromise — not install-time. |
| **Post-compromise — anti-forensics** | Any | T18: wiper (`rm -rf ~/`) triggered on token revocation | ❌ | Retaliatory destruction fires when incident responders revoke the token — post-compromise. |
| **Trust-chain bypass** | npm / PyPI | T20: SLSA provenance forgery via Sigstore/OIDC (attacker mints valid BL3 attestations) | ❌ | Trust-chain bypass — not a behavioral signal. gyrseek's sandbox diffing is independent of provenance metadata. |

**What gyrseek catches, stated plainly**

gyrseek reliably catches Shai-Hulud attacks where the malicious behaviour fires *during* `npm install` — specifically the `preinstall` hook variants used in the Red Hat, @antv, and Intercom npm waves. The two IoC classes that trigger detection are:

- **New network connection** to GitHub Releases (`github.com/oven-sh/bun/releases/...`) — the Bun download
- **Watched-process execve** `bun|run|_index.js` or `bun|run|router_runtime.js` — the payload invocation

Either signal alone is sufficient to block the install before it completes.

**The core gap — deferred Python execution**

The original Hades/Miasma PyPI wave and the Bioinformatics/MCP wave use `.pth` files and import hooks specifically to survive install-time scanners. The sequence:

1. `pip install evil-pkg` runs inside gyrseek's sandbox — the `.pth` file is written to `site-packages` as ordinary file I/O. No network calls, no bun execve, nothing anomalous. **gyrseek sees a clean install and allows it.**
2. The next time *any* Python interpreter starts on the host, `.pth` fires, downloads Bun from GitHub, and runs the stealer.

gyrseek's sandbox window ends when `pip install` exits.

**What would close this gap**

After the sandbox install, gyrseek could run a second strace-covered step — start a fresh Python interpreter with the installed package on `sys.path` to force `.pth` execution — and capture the Bun download and `bun run` execve the same way npm hooks are caught today. A complementary approach is static wheel diffing: comparing wheel contents between versions would surface a newly appearing `.pth` or `_index.js` file before any code runs. Both are on the roadmap.

## Configuration

`gyrseek` reads a YAML policy file to allowlist known-good endpoints and tune its release gates.

**Config path:** defaults to `gyrseek.yaml` in the working directory. Override it with `--config` or the `GYRSEEK_CONFIG` environment variable:

```bash
./target/release/gyrseek --config ./security-policy.yaml npm install
GYRSEEK_CONFIG=./security-policy.yaml ./target/release/gyrseek npm install
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
| `internal_package_exemptions` | none          | Skip specific packages **entirely** — no registry history fetch, no sandbox install, no diff. For first-party / internal packages served from a private index (e.g. Nexus) that `gyrseek`'s public-registry lookups can't resolve, so scanning only yields noise. The package is forwarded unscanned at its requested version.            |
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
internal_package_exemptions:
  - internal-pkg-logger          # first-party package served from a private Nexus index
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
./target/release/gyrseek npm update
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
./target/release/gyrseek uv sync
```

### 3) Enable prebuilt mode globally (optional)

```bash
GYRSEEK_PREBUILT_SCANNER_IMAGES=true \
GYRSEEK_NPM_SCANNER_IMAGE=gyrseek/npm-scanner:latest \
GYRSEEK_PY_SCANNER_IMAGE=gyrseek/py-scanner:latest \
./target/release/gyrseek npm update
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
- `uv sync` and `uv lock --upgrade` exclude local project entries (editable/path/workspace blocks) from comparison.
- `uv pip sync` scans all parseable packages from its source files (requirements-style files and `pylock.toml`).
- `uv lock --upgrade` scans all packages in `uv.lock`; `uv lock -P/--upgrade-package` scans the explicitly targeted packages. When `-P` is followed by a flag (e.g. `-P --dry-run`), the flag is not consumed as a package name and the next real `-P pkg` argument is not silently skipped.
- `pip install` / `pip3 install` scan all parseable entries, including `-r/--requirements` files.
- `poetry install` / `poetry update` scan all packages in `poetry.lock`, excluding local directory/path/editable source blocks.
- `npm install`, `npm i`, `npm update` scan explicit targets; with no targets they scan `package.json` dependencies. Both paths exclude non-registry specs (`file:`, `workspace:`, `git+`, URL, `link:`) — previously `link:` was filtered in the `package.json` fallback but passed through as a package name on the CLI arg path.

**Fail-closed guarantees**

- **Unrecognized manager:** any first argument other than `pip`, `pip3`, `uv`, `poetry`, or `npm` is rejected with a non-zero exit and a clear error message listing the supported managers. The only exception is `sandbox runtimes` (a built-in diagnostic). Previously, unrecognized managers were silently forwarded unscanned.
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
just test-pip
just test-uv
just test-poetry
```

Behavior test coverage includes deterministic DNS-enrichment checks, FCrDNS forward-confirmation, bracketed-argv preservation, watched-process detection, git-clone signature diffing, and release-burst policy enforcement.

## Project Layout & Docs

**Source & tests**

Tests follow Rust convention — inline in their module under `#[cfg(test)]`, only CLI-level exit-code tests remain in `tests/`.

- `src/main.rs` — binary entrypoint
- `src/lib.rs` — command routing, orchestration, config loading; inline tests for `GyrSeek::parse_package_details`
- `src/parsing.rs` — command, lockfile, and requirements parsing; inline tests for all parsers and `rewrite_args_with_pinned_versions`
- `src/scanning.rs` — registry lookup and behavior scanning engine; inline tests for version ordering, trace extraction, network/git-clone/watched-process detection, FCrDNS, and full scan pipeline
- `src/sandbox.rs` — sandbox backends and mode selection; inline tests for docker args, strace flags, and unprivileged-payload integrity
- `tests/cli_burst_exit_tests.rs` — release burst and minimum release age CLI exit-code tests (spawn binary)
- `tests/forward_fail_closed_tests.rs` — fail-closed forwarding and exit-status propagation tests (spawn binary)

**Just recipes**

- `just build` — release build
- `just install` / `just uninstall` — install or remove the local Cargo binary
- `just fmt` — format Rust code
- `just test` — run Rust tests
- `just lint` — run clippy and format checks
- `just test-{npm,pip,uv,poetry}` — end-to-end tests per manager

**Collaboration docs** (for multi-developer / multi-LLM work)

- `docs/ARCHITECTURE.md` — control-flow and component map
- `docs/DEV_GUIDE.md` — contributor workflow and change hygiene
- `docs/ROADMAP.md` — planned improvements and next steps
- `.copilot/AGENTS.md` — repository memory and mandatory update policy

> **Repository policy:** after each change, update both `.copilot/AGENTS.md` and `README.md`.

## License

See [LICENSE](LICENSE).
