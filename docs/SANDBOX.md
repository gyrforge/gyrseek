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
| `GYRSEEK_MEM_LIMIT`                                            | `2g`                    | Container memory limit and `/work` tmpfs size for probes. Validated as a size: an unusable value (including `0`, which docker reads as unlimited) is ignored with a warning and `2g` is used, rather than reaching `docker run --memory`. |
| `GYRSEEK_TRACE_LIMIT`                                          | `512m`                 | Size of the root-only tmpfs that holds one probe's trace (the largest trace accepted); a probe that fills it is blocked. Overrides `trace_limit` in `gyrseek.yaml`. The tmpfs is memory-backed and counts against `GYRSEEK_MEM_LIMIT`, so an effective value above a quarter of that limit is capped to it with a warning: a larger trace would leave the install too little memory and risk the whole batch being OOM-killed instead of one package blocked. Raise `GYRSEEK_MEM_LIMIT` to allow a larger trace. |
| `GYRSEEK_MAX_PROCESSES`                                        | `256`                   | Container process limit for probes. `GYRSEEK_PIDS_LIMIT` is accepted as a fallback. |

In prebuilt mode, runtime setup (`apt-get`, Python `uv` bootstrapping, `corepack enable pnpm`) is skipped to reduce hot-path latency. Setting an image variable does **not** imply prebuilt mode; the two are independent. If you supply your own image, read [Custom scanner images](#custom-scanner-images) for what it must contain.

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

## Custom scanner images

`GYRSEEK_NPM_SCANNER_IMAGE` and `GYRSEEK_PY_SCANNER_IMAGE` replace the digest-pinned default image
for that manager. Use them for an internal base image, a runtime version the built-in table does not
offer, or a registry your network can actually reach. The image must be able to install packages
*and* to be traced while it does.

### The bare minimum

| Needed | Why | Checked? |
| --- | --- | --- |
| `node`, or `python3`/`python` | Runs the package manager and the file inventory after each install | ✅ exit 126, names the runtime |
| `strace` | Produces every trace; without it gyrseek observes nothing | ✅ exit 126, names the program |
| `timeout` (GNU coreutils) | Enforces `probe_timeout_seconds` and `import_timeout_seconds` | ✅ exit 126 |
| `base64`, `df`, `tr`, `cut` | Stream each probe's files out of the root-only trace tmpfs | ✅ exit 126 |
| The **probe installer**: `npm`, `pnpm`, or `uv` | Performs the install being traced | ✅ exit 126, names the program |
| A `gyrseek` user, or `useradd`/`adduser` to create one | The traced install is dropped to it (`strace -u gyrseek`) | ✅ exit 126 — checked by outcome, so an image that already ships the user needs neither tool |
| Network access to the registry | Resolves and downloads the versions being probed | ❌ not checked — surfaces as `install_failed` carrying the package manager's own network error, and blocks only that package |

A failure in any of the checked rows stops the container with **exit 126** and a message naming what
is missing and the variable that selected the image, rather than producing a trace-less probe whose
cause has to be guessed. Exit 126 aborts the **whole batch**, not one package, which is right for
these: an image that cannot be traced in fails every probe identically, so blocking packages one at
a time would just repeat the same fault N times with advice to report a bug.

Network access is deliberately **not** prechecked. A package manager reports a network failure
clearly and attributes it correctly (`ENOTFOUND registry.npmjs.org`, `Could not connect`), and
`install_failed` prints that output verbatim, so a gyrseek-level "no network" message would restate
it less precisely. A precheck would also be worse than it looks: it aborts the whole container, so one
blip would block an entire lockfile batch instead of a single package; connectivity at setup says
nothing about connectivity during probe twelve; and it would mean adding `curl` or `wget` to the list
above, invalidating more images for no detection gain.

**The host needs registry access too.** Before any container starts, gyrseek fetches each package's
version history from the public registry to pick the baselines. A network policy that permits the
host but not the probe container is the one setup where the failure is genuinely confusing: the scan
gets as far as choosing versions, then every probe fails to install. If you run gyrseek behind a
proxy or an allowlisted egress, make sure the container's network can reach the same registries
(`registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org`), not just the host.

**The probe installer is not always the manager you typed.** gyrseek probes every Python manager with
`uv pip install`, so a Python scanner image needs `uv` and needs **neither `pip` nor `poetry`** — the
manager you run on the host is a separate thing from the one the sandbox installs with:

| Your command | Probe installs with | The image needs |
| --- | --- | --- |
| `pip`, `pip3`, `uv`, `poetry` | `uv pip install --target /work` | `uv` (and `python3`/`python`) |
| `npm` | `npm install --prefix /work` | `npm` (and `node`) |
| `pnpm` | `pnpm add --dir /work` | `pnpm` (and `node`) |

On the non-prebuilt path gyrseek supplies `uv` (`python -m pip install uv`) and `pnpm`
(`corepack enable pnpm`, falling back to `npm install -g pnpm`) itself, so only a prebuilt image has
to ship them. That is also why the check runs after setup rather than before it.

### The part people get wrong

**Setting a custom image does not imply prebuilt mode.** `GYRSEEK_*_SCANNER_IMAGE` and
`GYRSEEK_*_SCANNER_PREBUILT` are independent. With the image set and prebuilt *unset* (the default),
gyrseek still runs its own setup inside your image on every container:

```sh
apt-get update
apt-get install -y --no-install-recommends strace ca-certificates
# plus, per manager:
python -m pip install --quiet uv          # pip, uv, poetry
corepack enable pnpm || npm install -g pnpm   # pnpm
```

So a Debian- or Ubuntu-based image needs nothing but the interpreter and the package manager —
gyrseek installs `strace` for you. In exchange every probe container pays an `apt-get` run and needs
network access to the Debian archive.

An image that is **not** Debian-based (Alpine, RHEL/UBI, distroless, or anything without `apt-get`)
cannot take that path: the setup aborts. Build those as prebuilt images instead, with everything in
the table already present:

```sh
export GYRSEEK_NPM_SCANNER_IMAGE=registry.example.com/gyrseek-npm@sha256:...
export GYRSEEK_NPM_SCANNER_PREBUILT=true
```

Prebuilt mode skips the setup entirely, which is also why it is the faster path. Note that
`musl`-based images (Alpine) are a poor fit for the Python side regardless: many wheels are built for
`manylinux` and will be compiled from source or fail.

### Checking an image before you rely on it

```sh
img=registry.example.com/gyrseek-npm:latest
docker run --rm "$img" sh -c '
  for p in strace timeout base64 df tr cut node npm; do
    command -v "$p" >/dev/null 2>&1 || echo "MISSING: $p"
  done; echo checked'
```

Then run one real scan of a package you know is clean and confirm it is cleared rather than blocked.
A trace-less probe blocks only the package it belongs to, so a deficient image shows up as every
package being blocked, not as a silent pass — gyrseek fails closed either way.

### Pin it by digest

A custom image selected by a mutable tag can change under you between probes, which shows up as
baseline drift rather than as an image problem. Pin the digest, as the built-in defaults do, and see
[5) Use pinned image digests](#5-use-pinned-image-digests-recommended-for-reproducibility).

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
