# Docker Security

This document is the canonical reference for Docker sandbox security in gyrseek. It covers what hardening is applied, how to configure it, platform notes, validation steps, and current limitations.

## Overview

gyrseek runs install probes inside Docker containers using `strace` to capture behavioral signals (network endpoints, process execution, git clones, installed artifacts). The Docker sandbox is tuned for practical compatibility with package managers and throughput, not maximum isolation — though seccomp and AppArmor profiles add defense-in-depth.

Sandbox mode is selected via `GYRSEEK_SANDBOX` (`docker` default, `host` fallback, `microvm` via Docker runtime selection).

## Sandbox Infrastructure

### Capabilities and privileges

- **`--cap-add SYS_PTRACE`** — `strace` runs as root but attaches to the install process running as an unprivileged scanner user (`strace -u gyrseek`). Cross-UID ptrace requires `CAP_SYS_PTRACE`, which Docker does not grant by default. Scoped to the container's own PID namespace; cannot trace host processes. Without it, `strace` fails with `ptrace(PTRACE_SEIZE): Operation not permitted`, which produces an empty trace and the scan fails closed.
- **`--security-opt no-new-privileges`** — prevents the container process from gaining additional privileges.
- **Read-only rootfs not enabled** — the runtime apt-based probe tooling setup requires a writable root filesystem. Prebuilt scanner images unblock `--read-only` rootfs (see [Prebuilt Scanner Images](#prebuilt-scanner-images)).
- **Capabilities not fully dropped** — apt-based setup (used in the non-prebuilt path) fails under a full capability drop.

### Unprivileged payload integrity

The traced install payload runs as an unprivileged in-container user (`strace -u gyrseek`). The trace log files in `/out` are root-owned (written by `strace` running as root), so a malicious install or postinstall script cannot overwrite or delete its own trace before gyrseek reads it.

### Probe batching

The Docker backend batches multiple package-version probes (current + baselines for each package) into a single container session while preserving per-package, per-version trace attribution.

### strace configuration

- `-s 4096 -v` — long argv strings (git clone URLs, etc.) and socket addresses are not truncated from the default 32 bytes.
- `-f` — follows child processes (default since a package manager's install step can spawn subprocesses).
- stderr captured per-probe to `/out/gyrseek_err_N.log` (not discarded).
- `|| true` is kept only so one failing baseline install does not abort sibling probes. A genuine attach failure produces a blank trace, which the reader turns into a hard error.

## Seccomp

An embedded seccomp profile is stored in `src/sandbox.rs` as `EMBEDDED_SECCOMP_PROFILE_JSON` and materialized to a temp file at runtime.

### Configuration

| Variable | Default | Notes |
|---|---|---|
| `GYRSEEK_DOCKER_SECCOMP_PROFILE` | `true` | Boolean toggle (`true`/`false`). |

```bash
# Disable seccomp
GYRSEEK_DOCKER_SECCOMP_PROFILE=false \
./target/release/gyrseek npm install lodash
```

### Profile behavior

The profile is intentionally conservative: tracing compatibility comes first. It denies a focused set of high-risk kernel syscalls while leaving networking syscalls available so DNS, apt, and package-manager registry access keep working inside the sandbox.

An early version of the profile denied core networking syscalls (`socket`, `connect`, `sendto`, `recvfrom`), which broke DNS and apt. This was fixed so the profile is compatible with package-manager probe workflows.

### Status output

- Enabled: `ℹ️ [gyrseek] Seccomp profile enabled: seccomp.gyrseek-tracing.json (embedded)`
- Disabled: `⚠️ [gyrseek] Seccomp profile not in use. Set GYRSEEK_DOCKER_SECCOMP_PROFILE=true to enable it.`

### Platform note

Seccomp policy applies in the Linux container runtime (including Docker Desktop's Linux VM). It does not depend on host-side kernel modules beyond what Docker already requires.

## AppArmor

An embedded AppArmor profile is stored in `src/sandbox.rs` as `EMBEDDED_APPARMOR_PROFILE_TEXT` and loaded via `apparmor_parser` at runtime.

### Configuration

| Variable | Default | Notes |
|---|---|---|
| `GYRSEEK_DOCKER_APPARMOR_PROFILE` | `false` | Boolean toggle. Profile only loads with `apparmor-utils` + prebuilt scanner image on Linux (see requirements below). Defaults to `false` because prerequisites are not always met. |

```bash
# Disable AppArmor
GYRSEEK_DOCKER_APPARMOR_PROFILE=false \
./target/release/gyrseek npm install lodash
```

### Requirements

The `GYRSEEK_DOCKER_APPARMOR_PROFILE` env var defaults to `false`. When set to `true`, the embedded profile only actually loads when **all** of the following are met:

1. **Linux host** with the `apparmor` kernel module enabled.
2. **`apparmor-utils`** package installed (provides `apparmor_parser`).
3. **Prebuilt scanner image** — the runtime apt-based setup conflicts with the AppArmor profile's filesystem restrictions, so a prebuilt image is required.

Without these, gyrseek emits a warning and falls back to Docker's default AppArmor profile.

### Allowed operations

- **Outbound networking** (TCP, UDP, IPv4, IPv6, netlink) — package registries and DNS
- **ptrace** — cross-UID tracing for strace
- **Filesystem access** — `/work` (install probes), `/out` (trace logs), `/tmp` (temp), `/var` (apt cache), plus standard paths for binaries, libraries, and configuration

### Setup

Install `apparmor-utils` on Linux hosts:

```bash
sudo apt-get install apparmor-utils   # Debian/Ubuntu
sudo dnf install apparmor-utils       # Fedora
```

Build a prebuilt scanner image (required for AppArmor to work during scans):

```bash
just docker-build-python   # Python scanner (pip/uv/poetry)
just docker-build-npm      # npm/pnpm scanner
```

Run with prebuilt images and AppArmor enabled:

```bash
GYRSEEK_DOCKER_APPARMOR_PROFILE=true \
GYRSEEK_PREBUILT_SCANNER_IMAGES=true \
./target/release/gyrseek npm install lodash
```

### Status output

- Loaded: `ℹ️ [gyrseek] AppArmor profile loaded: gyrseek-tracing (embedded)`
- Not available: `⚠️ [gyrseek] AppArmor profile not available: {apparmor_parser stderr}. Container uses Docker's default AppArmor profile. Set GYRSEEK_DOCKER_APPARMOR_PROFILE=false to silence this warning.`
- Disabled: `ℹ️ [gyrseek] AppArmor profile disabled via GYRSEEK_DOCKER_APPARMOR_PROFILE=false`

### Platform note

Custom AppArmor profiles require native Linux host control over AppArmor profile loading (`apparmor-utils` package). On macOS Docker Desktop, AppArmor is not available — gyrseek emits a warning and falls back to Docker's default profile.

### Recommendation

Enable AppArmor for stronger path-based protection on Linux hosts. It adds defense-in-depth beyond seccomp's syscall-level filtering, restricting file access patterns (e.g. `/etc/shadow` writes) that seccomp alone cannot express. Use the prebuilt scanner image workflow for best compatibility.

## Platform support matrix

| Mode | macOS (Docker Desktop) | Linux host/VM |
|---|---|---|
| `docker` | Supported | Supported |
| `host` | Supported (requires local `strace`) | Supported (requires local `strace`) |
| `microvm` | Usually unavailable (Kata runtime typically not exposed) | Supported when a MicroVM-capable Docker runtime is installed |

- Seccomp works in all Docker environments (including Docker Desktop's Linux VM).
- AppArmor requires a native Linux host with `apparmor_parser` available. Not available on macOS Docker Desktop.

## Prebuilt scanner images

Prebuilt scanner images avoid runtime apt-based setup, enabling faster probe startup, fewer setup failures, and stricter container hardening (read-only rootfs, tighter capability drops, AppArmor compatibility).

Build:

```bash
just docker-build-python   # from docker/Dockerfile.python
just docker-build-npm      # from docker/Dockerfile.npm
```

Enable:

```bash
GYRSEEK_PREBUILT_SCANNER_IMAGES=true \
GYRSEEK_NPM_SCANNER_IMAGE=gyrseek-npm-scanner:latest \
GYRSEEK_PY_SCANNER_IMAGE=gyrseek-python-scanner:latest \
./target/release/gyrseek npm install lodash
```

Digest pinning is recommended for reproducibility and supply-chain integrity.

## Current hardening limitations

- Container setup installs probe tooling at runtime (apt-get, uv) when not using prebuilt images.
- Container setup and `strace` run as root (though the traced payload runs unprivileged via `strace -u`).
- Full `--read-only` rootfs is not enabled.
- Capabilities are not fully dropped, and `SYS_PTRACE` is explicitly added.
- Outbound network is enabled so package managers can reach registries during probes. A malicious package running during the probe could theoretically exfiltrate data.
- Behavioral detection observes what runs during the sandbox install. Payloads designed to fire outside the install window (e.g. import-time Python hooks) may not detonate during the scan.

**Why:** earlier stricter configs (read-only rootfs + full capability drop + non-root setup + network isolation) caused apt/setup failures and prevented package downloads during probes, rendering scans unable to run. Prebuilt scanner images are the path to restoring stricter defaults.

See [`ROADMAP.md`](ROADMAP.md) for the planned hardening direction (prebuilt image default path, read-only rootfs, tighter capability drops, egress controls).

## Validation checklist

Use these steps to validate seccomp/AppArmor hardening without breaking traces or package-manager network access.

### Step 1: Baseline sanity (no custom seccomp/apparmor)

```bash
just build
./target/release/gyrseek npm install left-pad
```

Expected: scan runs, no "empty trace" error, package downloads from npm registry.

### Step 2: Validate seccomp profile syntax

```bash
cat > /tmp/test_seccomp.json <<'EOF'
{
    "defaultAction": "SCMP_ACT_ALLOW",
    "syscalls": [
        {
            "names": ["bpf"],
            "action": "SCMP_ACT_ERRNO",
            "errnoRet": 1
        }
    ]
}
EOF

docker run --rm \
  --security-opt "seccomp=/tmp/test_seccomp.json" \
  alpine:latest \
  echo 'Seccomp load OK'
```

Expected: exit code 0, message prints.

### Step 3: Smoke test ptrace with network access

```bash
docker run --rm \
  --cap-add SYS_PTRACE \
  node:26.3-bookworm-slim \
  sh -lc "apt-get update >/dev/null && apt-get install -y strace >/dev/null && useradd -m -d /home/gyrseek -s /bin/sh gyrseek 2>/dev/null || true; strace -f -e trace=network,execve -u gyrseek -o /tmp/trace.log sh -lc 'echo ok' && test -s /tmp/trace.log"
```

Expected: exit code 0, `/tmp/trace.log` non-empty, apt registry reachable.

### Step 4: Run gyrseek e2e with seccomp

Test with and without seccomp:

```bash
GYRSEEK_DOCKER_SECCOMP_PROFILE=true just test-npm
GYRSEEK_DOCKER_SECCOMP_PROFILE=false just test-npm
```

Expected: no widespread "empty trace" failures; normal fail-closed behavior only for genuine findings.

### Step 5: AppArmor validation (Linux hosts)

Build prebuilt images and run with AppArmor enabled:

```bash
just docker-build-python
just docker-build-npm
GYRSEEK_DOCKER_APPARMOR_PROFILE=true \
GYRSEEK_PREBUILT_SCANNER_IMAGES=true \
just test-npm
GYRSEEK_DOCKER_APPARMOR_PROFILE=true \
GYRSEEK_PREBUILT_SCANNER_IMAGES=true \
just test-pip
```

Test with AppArmor disabled for baseline comparison:

```bash
GYRSEEK_DOCKER_APPARMOR_PROFILE=false just test-npm
```

Expected: scan results and behavior are identical with or without AppArmor.

### Step 5a: Troubleshooting

- **macOS:** AppArmor is unavailable in Docker Desktop — gyrseek warns and falls back; no action needed.
- **Linux:** If scans fail with "AppArmor profile not available", install `apparmor-utils` and verify the kernel module: `cat /sys/module/apparmor/parameters/enabled` should print `Y`.

## Regression signals

- `ptrace(PTRACE_SEIZE): Operation not permitted`
- `empty trace ... strace produced no output`
- Abrupt package-manager setup failures or network timeouts in the sandbox container

## Backout plan

If scans regress:

1. Remove custom seccomp (`GYRSEEK_DOCKER_SECCOMP_PROFILE=false`) and retest.
2. Remove custom AppArmor profile and retest.
3. Keep only `no-new-privileges` + `SYS_PTRACE` + resource limits until a narrower policy is validated.

## Related env vars

| Variable | Default | Notes |
|---|---|---|
| `GYRSEEK_SANDBOX` | `docker` | Sandbox mode: `docker`, `host`, or `microvm`. |
| `GYRSEEK_MICROVM_RUNTIME` | `kata-runtime` | Docker runtime for microvm mode. |
| `GYRSEEK_DOCKER_SECCOMP_PROFILE` | `true` | Boolean toggle for embedded seccomp profile. |
| `GYRSEEK_DOCKER_APPARMOR_PROFILE` | `false` | Boolean toggle for embedded AppArmor profile. Requires `apparmor-utils` + prebuilt scanner image on Linux. Defaults to `false` because prerequisites are not always met. |
| `GYRSEEK_PREBUILT_SCANNER_IMAGES` | `false` | Enable prebuilt fast path for all managers. |
| `GYRSEEK_NPM_SCANNER_PREBUILT` | `false` | Prebuilt override for npm/pnpm. |
| `GYRSEEK_PY_SCANNER_PREBUILT` | `false` | Prebuilt override for Python. |
| `GYRSEEK_NPM_SCANNER_IMAGE` | `node:26.3-bookworm-slim@sha256:...` | npm/pnpm scanner image tag or digest. |
| `GYRSEEK_PY_SCANNER_IMAGE` | `python:3.13-slim-bookworm@sha256:...` | Python scanner image tag or digest. |

## Related source files

- **Seccomp profile**: `src/sandbox.rs` (`EMBEDDED_SECCOMP_PROFILE_JSON`)
- **AppArmor profile**: `src/sandbox.rs` (`EMBEDDED_APPARMOR_PROFILE_TEXT`)
- **Docker runner**: `src/sandbox.rs` (`build_docker_command`, `trace_install_docker_matrix_with_runtime`)
- **seccomp toggle tests**: `src/sandbox.rs` (`docker_seccomp_profile_content`, `docker_apparmor_profile_content`, etc.)
