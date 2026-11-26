# Sandbox Modes and Scanner Images

How gyrseek runs its scan probes, which platforms and modes are supported, and how to choose, prebuild and pin the scanner images. Hardening of the container itself is in [DOCKER_SECURITY.md](DOCKER_SECURITY.md).

## Sandbox Modes

`gyrseek` runs scan probes through a `SandboxRunner` backend. Docker is the default; host mode is selected only with the `--no-sandbox` flag:

| Mode                 | Selected by       | Notes                                                                |
| -------------------- | ----------------- | -------------------------------------------------------------------- |
| **Docker** (default) | (default)         | Safer default. Requires the Docker CLI and a running daemon; if either is missing, `gyrseek` stops at startup with exit code 1 and says which. |
| **Host**             | `--no-sandbox`    | Fastest, **no isolation and zero protection (detection only)**. This mode exists purely for running in isolated environments — see warning below. |

```bash
./target/release/gyrseek npm install
./target/release/gyrseek --no-sandbox pip3 install -r requirements.txt
```

- If sandbox initialization fails, `gyrseek` exits non-zero (fail-closed).
- Host mode does not load installed packages, so there is no import-time scan there either (OPEN #490).
- Host mode runs no post-install artifact scan, so the `binary`, `suspicious_pth`, `unexpected_runtime` and `large_file` findings are only produced in Docker mode.
- The retired `GYRSEEK_SANDBOX` environment variable is ignored.
- ⚠️ **Host mode has to be requested explicitly with `--no-sandbox`.** There is no environment variable that selects it, so a stray or inherited setting cannot switch isolation off. Like `--danger-disable-seccomp`, the flag is consumed wherever it appears and is never forwarded to the package manager.
- ⚠️ **Host mode provides no protection, only detection.** There is no sandbox at all: the probe runs the package (the unvetted candidate included) directly on your machine as your user, with your filesystem, network and environment. If the package is malicious it has already executed by the time `gyrseek` reports it; the block only stops the follow-up install. The trace has no integrity protection either, since the payload runs as the same user that reads it. Run it only in a very isolated, disposable environment with no secrets, no credentials and no access to internal networks; the environment itself must be the sandbox. Never on a developer laptop or any machine holding real credentials.

### Platform support matrix

| Mode               | macOS (Docker Desktop)                                   | Linux host/VM                                                |
| --------- | -------------------------------------------------------- | ------------------------------------------------------------ |
| Docker (default)   | Supported                                                | Supported                                                    |
| Host (`--no-sandbox`) | **Not supported** (`strace` has no macOS build; fails at the first probe) | Supported (requires local `strace`)               |

CI covers macOS only in part: the `(macOS) Build and test without Docker` job builds the release binary on a macOS runner, runs every test that does not need a Docker daemon (a test that starts a real container is skipped) and checks `gyrseek --version`. GitHub's macOS runners have no Docker, so the sandbox itself (Docker Desktop's VM, seccomp there, trace streaming) is verified by hand on macOS, not in CI (open finding #513).

### Scanner image configuration

| Variable                                                       | Default                 | Purpose                                      |
| -------------------------------------------------------------- | ----------------------- | -------------------------------------------- |
| `GYRSEEK_NPM_SCANNER_IMAGE`                                    | `node:26.3-bookworm-slim@sha256:9898...` | npm/pnpm scanner image.                      |
| `GYRSEEK_PY_SCANNER_IMAGE`                                     | `python:3.13-slim-bookworm@sha256:a5a7...` | Python scanner image (pip/uv/poetry).     |
| `GYRSEEK_PREBUILT_SCANNER_IMAGES`                              | `false`                 | Enable prebuilt fast path for both managers. |
| `GYRSEEK_NPM_SCANNER_PREBUILT` / `GYRSEEK_PY_SCANNER_PREBUILT` | `false`                 | Per-manager prebuilt override.               |
| `GYRSEEK_DOCKER_APPARMOR_PROFILE`                               | `false`                 | Boolean toggle (`true`/`false`) for embedded AppArmor profile use in Docker sandbox runs. Loaded via `apparmor_parser` at runtime. On macOS (where `apparmor_parser` is unavailable) nothing is printed and no AppArmor profile applies. Requires `apparmor-utils` + prebuilt scanner image on native Linux hosts (runtime apt setup conflicts with profile). Defaults to `false` because the prerequisites are not always met. Recommended to enable on Linux hosts with prebuilt images for stronger path-based protection. |
| `GYRSEEK_MEM_LIMIT`                                            | `2g`                    | Container memory limit and `/work` tmpfs size for probes. |
| `GYRSEEK_TRACE_LIMIT`                                          | `1024m`                 | Size of the root-only tmpfs that holds one probe's trace (the largest trace accepted); a probe that fills it is blocked. Overrides `trace_limit` in `gyrseek.yaml`. |
| `GYRSEEK_MAX_PROCESSES`                                        | `256`                   | Container process limit for probes. `GYRSEEK_PIDS_LIMIT` is accepted as a fallback. |

In prebuilt mode, runtime setup (`apt-get`, Python `uv` bootstrapping, `corepack enable pnpm`) is skipped to reduce hot-path latency.

#### Python and Node version for the sandbox

The sandbox runs on the Python or Node your project uses, so the wheels, dependency markers and `engines` checks it sees match your real install. gyrseek picks the version in this order and prints the choice (for example `Sandbox Python 3.11 (from .../.python-version)`):

1. `GYRSEEK_PY_SCANNER_IMAGE` / `GYRSEEK_NPM_SCANNER_IMAGE`, if set (your own image; nothing else is consulted).
2. `python_version` / `node_version` in the gyrseek config.
3. The nearest project file, searched from the current directory upwards, first match wins:

   | Runtime | Exact version files (read first, in one directory) | Version ranges (read if the directory has no exact file) |
   | --- | --- | --- |
   | Python (pip, uv, poetry) | `.python-version` | `[project] requires-python`, else Poetry's `[tool.poetry.dependencies] python` in `pyproject.toml` |
   | Node (npm, pnpm) | `.nvmrc`, `.node-version` | `engines.node` in `package.json` |

4. The default: Python 3.13, Node 26.

A file naming one version (`3.11`, `3.11.4`, `cpython-3.11.4`, `v22.1.0`, `22`) selects that Python minor or Node major. A range (`>=3.9,<3.13`, Poetry's `^3.9` / `~3.10` / `3.11.*` / `^3.9 || ^3.10`, npm's `>=18 <23` / `^20.9.0 || ^22` / `20.x`) selects the **default if it fits, otherwise the closest supported version below it, otherwise the closest above**. For example `>=3.9` gives 3.13, `>=3.9,<3.13` gives 3.12 and `<3.11` gives 3.10. Newer Pythons have fewer wheels for older releases, so staying near the default is the safer choice.

Supported versions: **Python 3.10, 3.11, 3.12, 3.13, 3.14** and **Node 20, 22, 24, 26**. Each is a digest-pinned image built into gyrseek, so a project file can only choose from this list, never name an arbitrary image. Anything unusable (`pypy3.10`, `system`, `lts/*`, `3.8`, a range that allows none of the supported versions, a hyphen range such as `16 - 18`, or a range gyrseek cannot parse) is ignored with a warning and the default is used. An unsupported value in the config file is an error instead. Only the runtime being scanned is read: an npm run ignores `.python-version` and the reverse. To build a prebuilt image for a version, pass `--build-arg PYTHON_BASE=<image>` to `docker/Dockerfile.python` or `--build-arg NODE_BASE=<image>` to `docker/Dockerfile.npm`.

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
