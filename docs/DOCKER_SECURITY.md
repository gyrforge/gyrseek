# Docker Security

This document is the canonical reference for Docker sandbox security in gyrseek. It covers what hardening is applied, how to configure it, platform notes, validation steps, and current limitations.

## Overview

gyrseek runs install probes inside Docker containers using `strace` to capture behavioral signals (network endpoints, process execution, git clones, installed artifacts). The Docker sandbox is tuned for practical compatibility with package managers and throughput, not maximum isolation — though an embedded seccomp profile (active on every platform) and an optional AppArmor profile (native Linux hosts only) add defense-in-depth. The two are not interchangeable: see [Is seccomp enough, or is AppArmor required?](#is-seccomp-enough-or-is-apparmor-required) for which layer actually carries weight.

Docker is the sandbox. Host mode, which has no isolation and only detects, must be requested with `--no-sandbox`; there is no environment variable for it.

## Sandbox Infrastructure

### Capabilities and privileges

- **`--cap-add SYS_PTRACE`** — `strace` runs as root but attaches to the install process running as an unprivileged scanner user (`strace -u gyrseek`). Cross-UID ptrace requires `CAP_SYS_PTRACE`, which Docker does not grant by default. Scoped to the container's own PID namespace; cannot trace host processes. Without it, `strace` fails with `ptrace(PTRACE_SEIZE): Operation not permitted`, which produces an empty trace and the scan fails closed.
- **`--security-opt no-new-privileges`** — prevents the container process from gaining additional privileges.
- **Resource and filesystem limits** — `--network bridge`, `--pids-limit` (`GYRSEEK_MAX_PROCESSES`, default 256), `--memory` (`GYRSEEK_MEM_LIMIT`, default `2g`), `--cpus 1`, and `noexec,nosuid` tmpfs mounts for `/tmp` (128m) and `/work` (sized like the memory limit). The container runs as `--user root`; the traced install is dropped to the unprivileged `gyrseek` user by `strace -u`.
- **Read-only rootfs not enabled** — the runtime apt-based probe tooling setup requires a writable root filesystem. Prebuilt scanner images unblock `--read-only` rootfs (see [Prebuilt Scanner Images](#prebuilt-scanner-images)).
- **Capabilities not fully dropped** — apt-based setup (used in the non-prebuilt path) fails under a full capability drop.

### Unprivileged payload integrity

The traced install payload runs as an unprivileged in-container user (`strace -u gyrseek`). **Nothing from the host is mounted into the container.** While a probe runs, its files (the strace log, strace's stderr, the artifact inventory, the exit code and the timeout marker) are written to `/gyrseek-trace`, a root-only (mode 700) tmpfs of a fixed size (`GYRSEEK_TRACE_LIMIT`, default `1024m`), so the payload can neither read, write nor delete them and cannot fill the host's disk. When the probe is done, root prints each file on the container's stdout (`GYRSEEK-FILE <name>`, base64 lines, `GYRSEEK-END`) and deletes it, so the tmpfs only ever holds the probe that is running; gyrseek reads the stream line by line (no line over 1 KiB inside a frame, no file over the limit, names checked against what the script writes) and writes the files to its own temporary directory. Only root writes to the container's stdout (the payload's stdout goes to `/dev/null` and its stderr to a log), so a payload cannot forge a frame. A frame that does not end, or any malformed data, stops the container and fails the scan.

If a probe fills the tmpfs (under 1% or 16 KiB left), its trace is incomplete: the script prints `GYRSEEK-LIMIT <idx>` instead of its files and that package is blocked on its own, with a message naming `GYRSEEK_TRACE_LIMIT` (the next probe gets an empty tmpfs). Traces in practice are a few MB (an npm install) to about 40 MB (a failing source build of a large Python package). The tmpfs counts against the container's memory limit (`GYRSEEK_MEM_LIMIT`).

This replaced writing the logs straight into a bind-mounted `/out` (OPEN_FINDINGS #411, #434 and #461, all fixed): on Docker Desktop for macOS that mount does not enforce in-container ownership, so a payload (uid 1000, no capabilities) deleted and rewrote its trace and an earlier probe's, and could write as much as it liked to the host's disk. `just test-trace-integrity` runs a real container with a payload that tries to write, truncate, delete and symlink over the traces (also an earlier probe's and the directory itself) and to print a forged frame on stdout, next to a failing probe and a timed-out one, and a payload that floods its trace; with the logs put back in a bind mount the first test fails on macOS. It checks every trace and marker arrives intact and that only the flooding probe is blocked.

### Probe batching

The Docker backend batches multiple package-version probes (current + baselines for each package) into a single container session while preserving per-package, per-version trace attribution.

Each probe writes its own trace, strace stderr and artifact inventory to the trace tmpfs and streams them out when it is done. The probes share one container, so `/work` and `/tmp` are wiped after each probe's artifact scan; otherwise a later probe's scan would list files left by earlier ones. The wipe never touches the trace directory. Leftover background processes are not killed: `strace -f` waits for the traced process tree, so they show up as a hang, which `probe_timeout_seconds` now turns into a blocked scan (FIXED #413), rather than as noise in a later probe.

### strace configuration

- `-s 4096 -v -xx` — long argv strings (git clone URLs, etc.) and socket addresses are not truncated from the default 32 bytes.
- `-f` — follows child processes (default since a package manager's install step can spawn subprocesses).
- stderr captured per-probe to `gyrseek_err_N.log` in the trace tmpfs and streamed out (not discarded).
- `|| true` is kept only so one failing baseline install does not abort sibling probes. A genuine attach failure produces a blank trace, which the reader turns into a hard error.

## Seccomp

An embedded seccomp profile is stored in `src/sandbox.rs` as `EMBEDDED_SECCOMP_PROFILE_JSON` and materialized to a temp file at runtime.

### Configuration
The profile can be disabled via the `--danger-disable-seccomp` CLI flag.

```bash
# Disable seccomp
./target/release/gyrseek npm install lodash --danger-disable-seccomp
```

### Profile behavior

The profile is intentionally conservative: tracing compatibility comes first. It denies a focused set of high-risk kernel syscalls while leaving outbound client networking syscalls (`socket`, `connect`, `sendto`, `recvfrom`) available so DNS, apt, and package-manager registry access keep working inside the sandbox. Inbound `listen`, `accept` and `accept4` are denied.

An early version of the profile denied core networking syscalls (`socket`, `connect`, `sendto`, `recvfrom`), which broke DNS and apt. This was fixed so the profile is compatible with package-manager probe workflows.

### Status output

- Enabled: `ℹ️ [gyrseek] Seccomp profile enabled: seccomp.gyrseek-tracing.json (embedded)`
- Disabled: `⚠️ [gyrseek] Embedded seccomp profile disabled via --danger-disable-seccomp. Omit the flag to re-enable.`

### Platform note

Seccomp policy applies in the Linux container runtime (including Docker Desktop's Linux VM and the WSL2 kernel). It does not depend on host-side kernel modules beyond what Docker already requires, because it is enforced by the kernel the container runs on rather than by the host OS. Seccomp is also all-or-nothing — it is compiled into that kernel or absent, with no enable step — so if a container starts under the profile at all, the profile is being enforced.

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
- **Filesystem access** — `/work` (install probes), `/gyrseek-trace` (trace logs, root only), `/tmp` (temp), `/var` (apt cache), plus standard paths for binaries, libraries, and configuration

### Setup

Install `apparmor-utils` on Linux hosts:

```bash
sudo apt-get install apparmor-utils   # Debian/Ubuntu
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
- Not available: `⚠️ [gyrseek] AppArmor profile not available: {apparmor_parser stderr}. Container will use Docker's default AppArmor profile. Set GYRSEEK_DOCKER_APPARMOR_PROFILE=false to silence this warning.`
- Disabled: `ℹ️ [gyrseek] AppArmor profile disabled via GYRSEEK_DOCKER_APPARMOR_PROFILE=false`

### Platform note

Custom AppArmor profiles require native Linux host control over AppArmor profile loading (`apparmor-utils` package). On macOS Docker Desktop, AppArmor is not available — gyrseek prints no AppArmor status line there, and no AppArmor profile (embedded or Docker's default) applies because the VM kernel lacks the AppArmor LSM.

### Recommendation

Enable AppArmor for stronger path-based protection on Linux hosts. It adds defense-in-depth beyond seccomp's syscall-level filtering, restricting file access patterns (e.g. `/etc/shadow` writes) that seccomp alone cannot express. Use the prebuilt scanner image workflow for best compatibility.

## Is seccomp enough, or is AppArmor required?

For gyrseek's threat model, **seccomp is the load-bearing layer and AppArmor is marginal
defense-in-depth.** The two are not interchangeable, and the distinction decides whether a macOS or
WSL2 host without AppArmor should be considered deficient.

### Trace integrity — seccomp only

gyrseek's entire detection rests on `strace` observing the install's syscalls. A package that performs
file or network I/O through a channel `strace` cannot see produces a clean trace and is then forwarded
to the host. This is why the seccomp profile blocks the `io_uring` syscalls: work submitted through an
`io_uring` ring is not visible as ordinary syscalls, so it would bypass the observation the behavioral
diff depends on.

**AppArmor cannot express this.** It is path-based mandatory access control, not a syscall filter;
nothing in an AppArmor profile substitutes for that block. Seccomp is therefore not merely a
containment measure — `--danger-disable-seccomp` degrades *detection integrity*, which is why it is
named the way it is.

### Containment — mostly neither profile

The isolation that limits blast radius during a probe comes from the container boundary, not from
either profile: an ephemeral root filesystem, a tmpfs `/work`, no host mounts at all, an unprivileged payload via `strace -u gyrseek`, `no-new-privileges`, and — on macOS and
WSL2 — an additional VM boundary. AppArmor adds path-based `deny` rules *inside* that already
ephemeral container, where there is little of value to protect: no host path is mounted, and the
traces are guarded by a root-only tmpfs rather than by MAC.

### What this means for supply-chain malware

The dominant risks in the attack classes gyrseek is built to catch are not container escapes, and
neither profile addresses them:

- **Execution outside the install window** — a PyPI `*-setup.pth` or import-time hook that fires on
  the next interpreter start rather than during the probe (Open Finding 25; waves T26 and T32). The
  package simply never misbehaves while it is being watched.
- **Open egress during the probe** — in Docker mode the container reaches the network so package
  managers can resolve dependencies, so a probe-time exfiltration packet does reach the internet even
  though gyrseek then blocks the host install.

Hardening the container does nothing for either. The marginal security for this threat model comes from
egress control and from covering the execution window — what the post-install artifact scan
partly addresses and a future egress proxy would (OPEN_FINDINGS #412) — not from adding AppArmor.

### Practical guidance

- **Never disable seccomp.** It is the only layer protecting the observation that every gyrseek verdict
  rests on.
- **Enable AppArmor on native Linux hosts** with prebuilt scanner images. It is real defense-in-depth
  and costs nothing once `apparmor-utils` is installed.
- **Do not treat its absence on macOS as a gap in supply-chain coverage.** A macOS Docker Desktop host
  keeps seccomp, namespace isolation and a VM boundary; what it loses is a path-confinement layer over
  an ephemeral filesystem. Detection coverage is identical.

## Platform support matrix

| Mode | Linux host/VM | macOS (Docker Desktop) | Windows (WSL2) | Windows (native) |
|---|---|---|---|---|
| Docker (default) | Supported | Supported | Supported — run gyrseek inside a WSL2 distro | Not supported |
| Host (`--no-sandbox`) | Supported (requires `strace`) | **Not supported** (`strace` is Linux-only) | Supported (requires `strace`) | Not supported |

`host` mode on macOS cannot work: `HostRunner` invokes `strace`, which has no macOS build. The nearest
equivalent, `dtruss`, is a different tool and SIP blocks it against system binaries.

### Hardening availability per platform

| Layer | Linux host | macOS (Docker Desktop) | Windows (WSL2) |
|---|---|---|---|
| Seccomp | Enabled by default | Enabled by default | Enabled by default |
| AppArmor | Opt-in (`GYRSEEK_DOCKER_APPARMOR_PROFILE=true`) | **Unavailable** (permanent) | **Unreliable** — verify before relying on it |

- **Seccomp works wherever a Linux container kernel does.** On macOS that kernel is Docker Desktop's
  LinuxKit VM; under WSL2 it is Microsoft's WSL kernel. Both are built with `CONFIG_SECCOMP_FILTER`.
- **AppArmor needs a native Linux host.** Loading the profile requires `apparmor_parser` to install it
  into the kernel that runs the container. On macOS that binary does not exist on the host, and Docker
  Desktop's LinuxKit kernel does not carry the AppArmor LSM — so this is a permanent platform
  limitation, not a setup problem. gyrseek prints no AppArmor status line there, and no AppArmor profile (embedded or Docker's default) applies.
- **WSL2 is a Linux target, not a Windows one.** gyrseek built and run inside a WSL2 distro reports
  `linux` for `std::env::consts::OS`, so the AppArmor path is attempted rather than skipped. The WSL
  kernel does ship AppArmor support, but it must be an active LSM (kernel cmdline `lsm=`/`security=`,
  set via `.wslconfig`) with securityfs mounted, which has not historically been the default. Treat it
  as unverified until checked on the specific kernel in use:

```bash
docker info --format '{{json .SecurityOptions}}'   # is "apparmor" listed?
cat /sys/module/apparmor/parameters/enabled        # Y means the LSM is active
ls /sys/kernel/security/apparmor/.load             # must exist to load profiles
```

- **Native Windows is not supported** in any mode: Docker mode needs WSL2, and `host` mode has no
  `strace`.

## macOS vs Linux (Docker mode)

Docker mode is not "weaker on macOS because it lacks seccomp and AppArmor". Seccomp applies on both. AppArmor is off by default on both, and unavailable on macOS. The real differences are trace integrity, how much has been tested, and one extra isolation layer on macOS. The last column says how well each statement is established: **measured** (observed with the real `docker run` flags), **documented** (follows from how the layer works) or **not tested**.

| Aspect | Native Linux | macOS (Docker Desktop) | Basis |
|---|---|---|---|
| Seccomp profile (blocks `io_uring`) | Enforced by the host kernel | Enforced by Docker Desktop's Linux VM kernel | Documented |
| AppArmor | Opt-in (`GYRSEEK_DOCKER_APPARMOR_PROFILE=true`), needs `apparmor-utils` | Unavailable (no host `apparmor_parser`, VM kernel has no AppArmor LSM). Not a coverage gap, since it is off by default on Linux too | Documented |
| Payload privileges | Unprivileged user, no capabilities, `no-new-privileges` | Same (payload `CapEff` 0, no `docker.sock`) | Measured on macOS, same flags on Linux |
| Trace integrity | Traces live in a root-only, size-limited tmpfs and reach the host on stdout, with no host mount | Same | Measured on macOS (`just test-trace-integrity`); the CI Docker job runs it on Linux |
| Container escape blast radius | The container shares the host kernel, so an escape lands on the host | An escape lands in Docker Desktop's VM first, which is an extra boundary | Documented, not measured |
| `noexec` on `/work` and `/tmp` | Same | Works there, but a dropped binary can still run from `/home/gyrseek` or `/var/tmp` (measured: a copied ELF and a shebang script both ran). The artifact inventory therefore also lists `/home/gyrseek`, `/var/tmp`, `/run/lock` and `/dev/shm`, reports any file found there as `dropped_file`, and the reset between probes empties them (FIXED #471) | Measured on macOS |
| Network egress during the probe | Open | Open. Private-address reach is unmeasured on both (OPEN_FINDINGS #412) | Measured (open), not tested (private addresses) |
| Probe time limit | 300s per probe, `probe_timeout_seconds` (FIXED #413) | 300s per probe, `probe_timeout_seconds` (FIXED #413) | Measured on macOS; not run on native Linux |
| CI coverage | Yes (`ubuntu-latest` jobs) | None. GitHub-hosted macOS runners cannot run Docker. Tested by hand only | Documented |

What this means in practice:

- Treat the macOS trace as less trustworthy than the Linux one until #411 is fixed. A malicious package that knows about gyrseek could hide earlier events.
- Containment of the host is at least as good on macOS as on Linux, probably better, because of the VM.
- Neither platform restricts what the payload can reach over the network during the probe.
- WSL2 is a Linux target for gyrseek and has not been tested (see "Hardening availability per platform").

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
- Outbound network is enabled so package managers can reach registries during probes. A malicious package running during the probe can download and run a 2nd stage, or send data to any host, from inside the container; only decoy secrets are present, but the container acts from the host's IP. Whether the container can reach private addresses (LAN, `host.docker.internal`) is unmeasured (OPEN_FINDINGS #412).
- The Python (3.10–3.14) and Node (20, 22, 24, 26) sandbox images are chosen from built-in tables of digest-pinned images using the config or the project's version files; a project file cannot name an arbitrary image. See the README section "Python and Node version for the sandbox".
- The probe container's `/tmp` is `noexec` and 128 MB, so packages that must be built from source cannot build in it and are blocked as `install_failed` (OPEN_FINDINGS #425).
- Each probe is limited to `probe_timeout_seconds` (default 300) of wall-clock time; an expired probe blocks only that package (FIXED_FINDINGS #413, #422). The limit does not cover the setup phase (`apt-get` when the image is not prebuilt) or a hung Docker daemon. The container is `--rm`, so nothing survives the probe.
- Trace integrity is not guaranteed on macOS Docker Desktop (OPEN_FINDINGS #411, see "Unprivileged payload integrity").
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
just test-npm
just test-npm --danger-disable-seccomp
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

- **macOS:** AppArmor is unavailable in Docker Desktop — nothing is printed and no AppArmor profile applies (seccomp still does); no action needed.
- **Linux:** If scans fail with "AppArmor profile not available", install `apparmor-utils` and verify the kernel module: `cat /sys/module/apparmor/parameters/enabled` should print `Y`.

## Regression signals

- `ptrace(PTRACE_SEIZE): Operation not permitted`
- `empty trace ... strace produced no output`
- Abrupt package-manager setup failures or network timeouts in the sandbox container

## Backout plan

If scans regress:

1. Remove custom seccomp (`--danger-disable-seccomp`) and retest.
2. Remove custom AppArmor profile and retest.
3. Keep only `no-new-privileges` + `SYS_PTRACE` + resource limits until a narrower policy is validated.

## Related env vars

| Variable | Default | Notes |
|---|---|---|
| `GYRSEEK_CONFIG` | `gyrseek.yaml` | Path to the policy file (overridden by `--config`/`-c`). |
| `GYRSEEK_MEM_LIMIT` | `2g` | Container `--memory` and the size of the `/work` tmpfs. |
| `GYRSEEK_TRACE_LIMIT` | `1024m` | Overrides `trace_limit` in `gyrseek.yaml`. Size of the root-only tmpfs that holds one probe's logs, and so the largest trace accepted for a probe; a probe that fills it is blocked. Counts against the memory limit. |
| `GYRSEEK_MAX_PROCESSES` | `256` | Container `--pids-limit`. `GYRSEEK_PIDS_LIMIT` is accepted as a fallback. |
| `GYRSEEK_DOCKER_SECCOMP_PROFILE` | — | Deprecated and ignored (a warning is printed). Use `--danger-disable-seccomp`. |
| `GYRSEEK_DOCKER_APPARMOR_PROFILE` | `false` | Boolean toggle for embedded AppArmor profile. Requires `apparmor-utils` + prebuilt scanner image on Linux. Defaults to `false` because prerequisites are not always met. |
| `GYRSEEK_PREBUILT_SCANNER_IMAGES` | `false` | Enable prebuilt fast path for all managers. |
| `GYRSEEK_NPM_SCANNER_PREBUILT` | `false` | Prebuilt override for npm/pnpm. |
| `GYRSEEK_PY_SCANNER_PREBUILT` | `false` | Prebuilt override for Python. |
| `GYRSEEK_NPM_SCANNER_IMAGE` | `node:26.3-bookworm-slim@sha256:...` | npm/pnpm scanner image tag or digest. |
| `GYRSEEK_PY_SCANNER_IMAGE` | `python:3.13-slim-bookworm@sha256:...` | Python scanner image tag or digest. |

## Related source files

- **Seccomp profile**: `src/sandbox.rs` (`EMBEDDED_SECCOMP_PROFILE_JSON`)
- **AppArmor profile**: `src/sandbox.rs` (`EMBEDDED_APPARMOR_PROFILE_TEXT`)
- **Docker runner**: `src/sandbox.rs` (`build_docker_run_args`, `trace_install_docker_matrix`)
- **seccomp toggle tests**: `src/sandbox.rs` (`docker_args_adds_seccomp_profile_by_default`, `docker_args_disables_seccomp_when_danger_flag_true`, `embedded_seccomp_profile_keeps_networking_available`, `embedded_apparmor_profile_*`, `apparmor_env_var_default_false`, etc.)
