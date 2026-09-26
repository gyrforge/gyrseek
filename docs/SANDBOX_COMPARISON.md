# Sandbox Comparison: Docker vs. Nono

This document provides a technical analysis of the architectural differences, security boundaries, telemetry mechanisms, and detection nuances between gyrseek's default **Docker** sandbox runner and the experimental **nono** kernel capability runner.

---

## 1. Overview & Core Philosophy

gyrseek's primary objective is to **detect and block malicious packages** before they are installed onto the host system. To achieve this, it executes candidate packages and their historical baselines inside an isolated environment, records behavioral signals (network egress, process execution, sensitive file access, and filesystem artifacts), and fails closed if anomalous behavior is observed.

| Attribute | Docker Backend (`GYRSEEK_SANDBOX=docker`) | Nono Backend (`GYRSEEK_SANDBOX=nono`) |
|---|---|---|
| **Status** | Production Default | **Experimental (Use at your own risk)** |
| **Isolation Model** | Namespace virtualization & container isolation | Native kernel capability confinement (LSM) |
| **Enforcement Layer** | Linux namespaces (PID, mount, net, IPC) + cgroups | Linux Landlock (kernel 5.13+ fs, 6.7+ net) / macOS Seatbelt |
| **Execution Context** | Dedicated container with isolated `/work` tmpfs | Host filesystem in temporary directory with caller UID |
| **Primary Telemetry** | `strace` syscall interception (`ptrace`) | Kernel audit events + PATH shims + FIFO canary traps |
| **Daemon Requirement** | Requires Docker CLI and dockerd | Zero daemon requirement; standalone binary |

---

## 2. Isolation Boundaries & Blast Radius

### Docker: Namespace Virtualization

* **Filesystem:** The probe runs inside an isolated root filesystem with a dedicated tmpfs mounted at `/work`. The host filesystem is never mounted into the container except for a root-owned trace directory (`/out`). Even if malware attempts to execute destructive commands (e.g. `rm -rf /` or encrypting disk contents), damage is constrained to the ephemeral container.
* **Process Namespace:** The container has an isolated PID namespace. The traced process cannot inspect, signal, or trace host processes.
* **User Identity:** The install payload runs as an unprivileged container user (`strace -u gyrseek`), while `strace` and the output logs are owned by root inside the container. This prevents the payload from modifying or deleting its own trace before gyrseek inspects it.
* **Kernel Attack Surface:** Protected by embedded seccomp and AppArmor profiles that restrict high-risk kernel syscalls (including blocking `io_uring` to prevent unmonitored async file I/O).

### Nono: Kernel LSM Capability Confinement

* **Filesystem:** The probe runs directly on the host OS inside a temporary directory. Isolation relies on kernel Landlock LSM (Linux) or Seatbelt (macOS).
  * **macOS:** An ephemeral Seatbelt profile explicitly denies `/tmp`, `/private/tmp`, and user application cache directories (`/var/folders/.../C/`). This blocks malicious install scripts from harvesting session tokens or credential caches from Chrome, VSCode, Slack, or 1Password.
  * **Linux:** Landlock drops the `system_write_linux` group, denying write access to host `/tmp` while preserving pseudo-devices (`/dev/null`, `/dev/zero`, `/dev/urandom`).
* **Process Namespace:** The probe shares the host process namespace. It is restricted from tracing or interfering with other processes via OS sandbox rules, but process-level isolation is not as strict as container namespace separation.
* **Blast Radius Consideration:** Because code executes directly on the host kernel under the caller's user account, an unhandled Landlock/Seatbelt bypass or misconfiguration could expose host files. This is why `nono` is classified as **experimental**.

---

## 3. Network Confinement & Anomaly Detection

A critical nuance between the two backends is **passive detection** vs. **active prevention**:

```
Docker: [Package] ---> [Open Docker Bridge] ---> [External Network / C2]
                             |
                             v
                  [strace logs connect()] ---> [Post-Probe Behavioral Diff Blocks Host]

Nono:   [Package] ---> [Kernel / nono Network Filter] ---> [BLOCKED in-flight]
                             |
                             v
                  [Audit Log / Diagnostics] ---> [Synthetic Trace Diff Blocks Host]
```

### Docker: Open Egress + Post-Hoc Syscall Diffing

* **Mechanism:** Outbound traffic from the container passes through the Docker bridge network. `strace` intercepts every `connect()` syscall, recording both IPv4 (`AF_INET`) and IPv6 (`AF_INET6`) target addresses.
* **Detection Behavior:** gyrseek collects all connection endpoints and performs a domain-aware IP diff against clean baseline versions using Forward-Confirmed Reverse DNS (FCrDNS) and an strace wire-format DNS interceptor.
* **Nuance:** 
  * The network connection is permitted to complete during the probe. If an attacker downloads a second-stage payload (e.g., Bun or a compiled RAT) during `postinstall`, gyrseek observes both the network connection *and* the subsequent process executions/dropped files.
  * If a package attempts rapid blind exfiltration (e.g., sending an environment variable via UDP/DNS before the scan concludes), the egress packet actually reaches the internet, even though gyrseek subsequently catches the IP and aborts host forwarding.

### Nono: Phased Domain Lockdown + Active Prevention

* **Mechanism:** `nono` enforces network egress policies using `--allow-domain`. On Linux, scoped network egress filtering uses Landlock network rules on kernel 6.7+ (Landlock ABI v4+). On older kernels (5.13+), filesystem isolation remains active, and `nono` can use a seccomp-notification supervisor for proxy-only network enforcement when seccomp-notify is available. Kernels without that facility cannot provide this fallback. Domain filtering is disabled by default on WSL2.
* **Phased Matrix Execution:** In `trace_install_matrix`, `NonoRunner` executes probes in coordinated phases:
  1. **Baseline Phase:** Probes for older, vetted baseline versions run unconstrained (`--allow-domain "*"`) through `nono-proxy` to discover all legitimate network endpoints and CDNs used by known-good versions.
  2. **Candidate Phase:** The candidate version probe executes with its network strictly confined to:
     * Official registry domains (`registry.npmjs.org`, `files.pythonhosted.org`, etc.)
     * Custom registry domains discovered in the user's environment
     * Any legitimate domains observed and merged from the baseline phase
* **Detection Behavior:** Direct raw socket connections to unauthorized endpoints (e.g. raw C2 IPs or cloud metadata `169.254.169.254`) are blocked by Nono's kernel controls. On Linux, proxy mode uses seccomp to force traffic through `nono-proxy`, while Landlock applies port-level network restrictions. Undeclared domain requests (e.g. `github.com/oven-sh/bun/releases`) are rejected in-flight by `nono-proxy`. Denied and allowed connection events are captured in `nono`'s audit logs (`audit-events.ndjson`), which gyrseek parses to synthesize DNS and `connect(...)` events for the behavioral diff.
* **Nuance:**
  * Active blocking prevents malicious second-stage droppers from ever reaching the host or sending exfiltrated data.
  * Because the network download fails in-flight, downstream malicious stages (e.g. executing the downloaded Bun binary) might not execute unless the package includes offline fallbacks. However, the initial network anomaly alone is sufficient to fail closed.
  * Baseline probes run unconstrained through `nono-proxy` so legitimate dependencies/CDNs are audited and harvested into the candidate's allowed domain set, while candidate probes remain locked down to that effective allowlist.

---

## 4. Process Execution & Dropper Tracking

Both backends detect unauthorized process execution (e.g. Shai-Hulud waves downloading Bun and executing `bun run _index.js`), but gather execution telemetry through different channels:

### Docker: Kernel Syscall Tracing (`ptrace`)

* Traces `execve` and `execveat` across the entire container.
* Uses balanced-bracket parsing to capture full, untruncated argument lists (`exe|arg1|arg2|...`).
* Captures all process invocations unconditionally, whether spawned by the package manager, shell scripts, or binary loaders.
* Harness commands (the probe's own `npm install`, `uv pip install`, etc.) are filtered out via `is_harness_command`.

### Nono: PATH Shims & Supervisor Audit Logs

* Because `nono` avoids `ptrace` context-switching, process execution is captured via two complementary mechanisms:
  1. **PATH Shims (`PathShims`):** A dedicated shims directory is prepended to `$PATH` containing wrappers for common attack tools and droppers: `bun`, `deno`, `git`, `curl`, and `wget`. When an install script executes any of these commands, the shim records the full, null-delimited argv to `gyrseek_exec.log` and forwards to the real executable.
  2. **Supervisor Audit Logging:** `nono` logs `exec`, `process`, and `command_policy` events in its audit log.
* [`parse_nono_audit_log`](../src/sandbox.rs) and `trace_install_with_domains` synthesize these into standard `execve(...)` trace lines, which feed directly into gyrseek's [`extract_process_exec_signatures`](../src/scanning.rs).
* **Nuance:** If malware executes a binary not covered by `$PATH` shims or supervisor process logs, Docker's comprehensive `ptrace` tracing provides a broader safety net.

---

## 5. Sensitive File Access & Credential Harvesting

Attackers frequently inspect local configuration files (`.env`, `~/.aws/credentials`, `~/.ssh/id_rsa`, `~/.npmrc`) to harvest secrets during installation.

### Docker: `openat` Syscall Auditing

* `strace` traces `open`, `openat`, and `creat` syscalls.
* Return codes are verified (`ret_val >= 0`) so failed attempts never populate baseline traces (preventing baseline poisoning).
* Inside the container, host credential files do not exist; any attempt by an install script to read `/root/.aws/credentials` or `/home/gyrseek/.env` results in an `openat(...) = -1 ENOENT` (or success if dummy files are provisioned).

### Nono: Decoy Canary Traps & Supervisor Denials

* Because `nono` executes with host file visibility, reading real host credential files represents a high-severity risk.
* **Canary Traps (`CanaryTrap`):** gyrseek provisions POSIX Named Pipes (FIFOs) at bait locations in both the working directory and simulated home directory:
  * `.env`
  * `.aws/credentials`
  * `.ssh/id_rsa`
  * `.npmrc` (automatically skipped for npm-family managers to prevent trapping package manager startup reads)
* A background thread monitors the FIFOs. When a malicious script attempts to open or read any canary file:
  1. The trap unblocks and writes canary bait tokens (`KEY=gyrseek-canary-trap`).
  2. The trap records the access event and continuously services repeated opens so subsequent reads cannot block.
  3. `trace_install_with_domains` synthesizes `openat(AT_FDCWD, "<path>", O_RDONLY) = 3` into the trace.
* In addition, any attempts to access denied host directories are caught by [`parse_nono_diagnostics_denials`](../src/sandbox.rs) from `nono`'s stderr diagnostics and synthesized into failed `openat` lines (`-1 EACCES`).

---

## 6. Post-Install Artifact Scanning

Both backends inspect installed filesystem artifacts to detect files written to disk during `npm install` or `pip install` that bypass syscall tracing (such as Hades/Miasma `*-setup.pth` files or compiled ELF payloads):

### Docker: In-Container `find` Pipeline

* Runs inside the container before exit:
  ```bash
  find /work -type f -exec ...
  ```
* Emits a null-delimited (`\0`) inventory: `virtual_path\0size\0file_type\0first_300_bytes`.
* Encoded into `/out/gyrseek_artifacts_N.log` and embedded into the trace stream under `=== gyrseek_artifacts ===`.

### Nono: Host-Side `scan_target_artifacts`

* Implemented natively in Rust via [`scan_target_artifacts`](../src/sandbox.rs).
* Recursively inspects the isolated target installation directory on the host.
* Reads file magic bytes:
  * `\x7fELF` -> `ELF 64-bit LSB executable`
  * Mach-O magic numbers (`\xfe\xed\xfa\xce`, `\xca\xfe\xba\xbe`, `\xca\xfe\xba\xbf` for 64-bit universal binaries, and byte-swapped forms) -> `Mach-O executable`
  * `MZ` -> `PE32 executable`
  * `.pth` file extension -> `Python script text`
* Reads the first 300 bytes of content and formats lines with identical null delimiters.
* Both streams feed into the same classifier ([`classify_inventory_lines`](../src/scanning.rs)), achieving artifact detection parity across ELF, PE32, 32-bit and 64-bit universal Mach-O binaries, and suspicious `.pth` files.

---

## 7. Comparative Technical Nuances

| Category | Docker Backend | Nono Backend | Detection Impact |
|---|---|---|---|
| **Egress Enforcement** | Permissive during probe; detected post-hoc | Strictly enforced in-flight (`--allow-domain`) | **Nono prevents exfiltration in real-time**; Docker captures downstream stages |
| **DNS Resolution** | Captured via strace `-xx` hex packets; wire-format decoded | Captured via `nono` audit log; synthetic DNS responses generated | **Parity** (both map domains to IPs for FCrDNS diffing) |
| **Process Tracking** | Global `ptrace` intercepting all `execve`/`execveat` | `$PATH` shims for droppers + audit log command events | Docker has broader catch-all for unknown binaries |
| **Credential Probing** | Passive syscall trace (`openat` with `ret >= 0`) | Active FIFO `CanaryTrap` decoys + supervisor denial logs | **Parity** (both trip `sensitive_file_read` anomaly check) |
| **Artifact Scanning** | In-container shell pipeline using `file -b` | Host-side Rust walker reading binary magic bytes | **Parity** (identical classifier output) |
| **Resource Limits** | Container memory limit via `GYRSEEK_MEM_LIMIT` (default 2GB) | Linux cgroups v2 (`--memory 2g --max-processes 256`) on Linux; OS defaults on macOS | Both prevent fork-bombs and native build OOMs on Linux |
| **Host Exposure** | Zero host exposure (isolated container namespaces) | Host-level execution gated by kernel capabilities | **Docker provides stronger containment** if sandbox fails |

---

## 8. Summary & Recommendation

* **Use Docker (`GYRSEEK_SANDBOX=docker`) by default:** It remains the recommended backend for production pipelines and untrusted package evaluation. Its multi-layered namespace isolation, root-owned trace logs, and comprehensive `ptrace` coverage provide the strongest containment against unknown exploits.
* **Use Nono (`GYRSEEK_SANDBOX=nono`) with awareness of experimental status:** It is ideal for environments where Docker cannot run (e.g., bare-metal Linux hosts or macOS workstations without Docker Desktop). Its active network lockdown and canary trapping provide strong detection parity, but users must accept the inherent risks of host-level kernel capability sandboxing.
