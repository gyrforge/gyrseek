# Architecture

## Goal
gyrseek is a command-wrapper CLI that evaluates dependency installation network behavior before allowing the original package-manager command to proceed.

## Runtime Entry Flow
1. The binary entrypoint in src/main.rs collects CLI args and calls run in src/lib.rs.
2. The run function in src/lib.rs routes by manager and subcommand. A leading `--version`/`-V` is handled first and prints `gyrseek <CARGO_PKG_VERSION>` then exits 0, before any config load or sandbox init (so it works without a config file or Docker); only the first argument is matched, so a forwarded command's own `--version` flag is left untouched.
3. Supported command paths are either:
   - single-target scans (for example `uv add pkg`). The full installation process runs in the sandbox, meaning any transitive dependencies installed are inherently traced and evaluated alongside the target package.
   - bulk scans (for example `uv sync`, `uv pip sync`, `uv lock` (bare and update flags), `poetry install` or `poetry update` or `poetry lock`, `pip` or `pip3 install` with multiple targets, `npm install` or `npm i` or `npm update`, `pnpm add` or `pnpm install` or `pnpm i` or `pnpm update`). In bulk modes, the lockfile or manifest is parsed, and *every* package in the entire dependency tree (including all transitive dependencies) is isolated and scanned individually against its own historical baselines. A bare `uv lock` (no `-U`/`-P`) and a bare `poetry lock` both scan every package in the resolved lockfile, mirroring `uv lock --upgrade` and `poetry install`/`update`; they fail closed if the lockfile is missing or empty.
4. If detection and scanning pass, the command is forwarded. For explicit unpinned install targets (for example npm install pkg, pip install pkg) the forwarded command is rewritten to pin the exact version that was scanned; lockfile/manifest-driven flows (uv sync, uv pip sync, uv lock, poetry install/update/lock) are forwarded verbatim because the lockfile already pins versions.
5. If an anomaly or required detection failure occurs, execution exits non-zero (fail-closed). Note that all anomaly checks run to completion and aggregate their failure reasons rather than short-circuiting on the first failure. If the host command itself cannot be spawned after a clear scan, gyrseek also fails closed. If a sandbox probe yields an empty/whitespace trace (e.g. strace could not attach), that is a hard error and the whole batch is blocked — a blank trace is never treated as a clean install.
6. When the host command is forwarded, gyrseek waits on the child and exits with the child's own status, so a non-zero host install is reported as non-zero rather than masked as success.

## Core Components
- Command parsing:
  - parse_package_details extracts package and optional version for single-target commands.
- Bulk source parsing:
  - parse_uv_lock_packages_from_content parses uv.lock package entries.
  - parse_poetry_lock_packages_from_content parses poetry.lock package entries.
  - parse_requirements_packages_from_content parses requirements-style entries. PEP 508 extras are stripped from the canonical package name (strip_pep508_extras) so registry lookups and the version-pin map key use `requests`, not `requests[security]`; the forwarded install command still carries the full extras-qualified spec.
  - parse_pylock_packages_from_content parses pylock package entries.
  - parse_pip_install_packages_from_args resolves package targets from pip or pip3 install args, including -r or --requirements files.
  - parse_npm_install_packages_from_args resolves npm/pnpm targets from explicit args or package.json when no explicit target is given. Non-registry specs (`link:`, `file:`, `git+`, URL) are excluded in both the CLI-arg and the package.json fallback paths.
  - parse_uv_lock_upgrade_packages_from_args resolves update targets from uv lock -P or --upgrade-package arguments. When the value after -P starts with `-` (i.e. it is a flag, not a package), only one token is consumed so the next real argument is not silently dropped.
- Version history lookup:
  - fetch_history_with_baselines queries PyPI for Python packages and the npm registry for npm/pnpm packages.
  - Version lists are ordered semantically: semver for npm-family managers, PEP 440 for Python managers (compare_version_strings / sort_versions_ascending). Unparseable strings sort below any parseable version, so junk is never resolved as `latest`.
  - npm `time` map parsing (npm_published_times) excludes the `created`/`modified` bookkeeping keys and any non-version key, so the release-burst counter is not inflated.
- Behavior capture:
   - trace_sandbox_install_matrix runs via SandboxRunner backend and captures, per package-version: connection IPs (IPv4 via inet_addr and IPv6 via inet_pton, normalized by extract_connection_ips), install-time git clone command signatures, and process-execution signatures (extract_process_exec_signatures: `exe|arg1|...` for every execve). Sandbox-internal commands (the install probe itself, interpreter discovery) are excluded via `is_harness_command` so version-specific command strings do not cause false positives.
  - extract_connection_ips normalizes via normalize_ip_string (canonical IPv6 plus IPv4-mapped IPv6 `::ffff:1.2.3.4` collapsed to bare IPv4 `1.2.3.4`) and drops sandbox-local addresses via is_sandbox_local_ip — loopback, link-local (`fe80::/10`, `169.254/16`), and private/RFC1918 ranges (including the Docker bridge `172.17/16` and Docker Desktop gateway `192.168.65/24`). This happens at extraction, before the baseline diff and on both current and baseline traces, so the container's own plumbing (gateway, DNS resolver) never registers as a "new" endpoint. The cloud instance metadata endpoint `169.254.169.254` is deliberately exempt (kept) because a package reaching for it is a real SSRF/credential-theft signal.
  - strace runs with `-s 4096 -v` (no argv/address truncation) and `-u <scanner-user>` so the traced install payload runs unprivileged while strace and its root-owned /out trace logs remain tamper-resistant.
  - execve argv parsing (extract_process_exec_signatures / git-clone signature extraction) uses a balanced-bracket-aware regex so arguments containing `]` (e.g. PEP 508 extras `requests[security]`, paths like `script[obf].js`) are captured intact rather than truncated at the first `]`.
  - The Docker container is run with `--cap-add SYS_PTRACE`: strace runs as root but attaches to the install running as the unprivileged scanner user, and cross-UID ptrace requires CAP_SYS_PTRACE (not in Docker's default capability set). The capability is scoped to the container PID namespace and cannot trace host processes.
  - strace's own stderr is captured to a per-probe `/out/gyrseek_err_N.log` (not `>/dev/null 2>&1`); `|| true` is retained only so a single failing install does not abort sibling probes. A genuine attach failure produces a blank trace log, which the reader turns into a hard error (fail closed) carrying the captured stderr.
  - Docker backend can execute probe matrices (multiple packages with their current and baseline versions) in one container session.
  - build_runner_from_env selects backend mode (`docker` default, `host` fallback).
- Anomaly decision:
  - Packages listed in `internal_package_exemptions` are skipped entirely before the registry fetch and sandbox install (no history lookup, no probe, no diff) and forwarded unscanned at their requested version. This is for first-party/internal packages on a private index (e.g. Nexus) that the public-registry lookups cannot resolve, where scanning only produces `(n/a)`-baseline noise. Distinct from `new_package_exemptions`, which still fetches and probes and only relaxes the under-2-baselines block.
   - find_new_connections_domain_aware resolves each IP via FCrDNS and diffs at the domain level rather than the IP level. If a current IP resolves to a domain already seen in baseline traffic, it is silently discarded (benign CDN edge rotation). Unresolvable IPs fall back to plain IP membership so the diff stays fail-closed for genuinely new or spoofed endpoints.
   - Unresolvable IPs also get a second chance via the **DNS interceptor**: the strace trace is scanned for `recvfrom` syscalls to port 53 (DNS), and raw response bytes are parsed by a wire-format DNS parser (`extract_dns_map` / `parse_dns_response` / `decode_dns_name` in `scanning.rs`). If the current IP appears in the container's observed DNS map under a domain that was also seen in baseline DNS traces, host-side `lookup_host` re-verifies the binding before trusting it. This handles CDN edge rotations that lack PTR records (e.g. Fastly, Cloudflare) without any hardcoded domain allowlist.
   - **Two-layer anti-spoofing:** The domain→IP binding is verified twice. First, FCrDNS confirms the PTR record's hostname resolves forward back to the original IP (attackers who set a fake PTR on their C2 cannot bypass because the allowlisted domain's real DNS doesn't point to their C2). Second, when FCrDNS fails (no PTR), the DNS interceptor fallback re-verifies the binding on the **host** via `std::net::lookup_host` — container-side DNS poisoning cannot influence the host's resolver, so a forged DNS response in the strace trace is rejected. An attacker would need to compromise the host's DNS resolver to bypass both layers.
   - **Circular compression pointer protection:** `decode_dns_name` limits compression pointer hops to 5. RFC 1035 names are bounded at 255 wire-format bytes; each pointer consumes 2 bytes and saves at least 1 byte versus the literal label. A 5-hop ceiling therefore accommodates every legitimate name — the worst-case nested subdomain (e.g. `a.b.c.d.e.f.g.pypi.org`) typically needs only 1–2 hops to compress a shared suffix. The limit prevents a maliciously crafted self-referencing pointer (e.g. `\xc0\x00` at offset 0 targeting offset 0) from hanging the scanner indefinitely (DoS). When exceeded, the parser returns `None`, and the diff falls back to plain IP membership (fail-closed).
  - The `ip_allowlist` matcher compares on the IPv4-mapped-collapsed canonical form, so an entry of `172.17.0.2` matches a `::ffff:172.17.0.2` hit and vice versa.
  - The `domain_allowlist` uses forward-confirmed reverse DNS (FCrDNS): reverse_dns_domain resolves the PTR hostname and only trusts it if its forward A/AAAA resolution includes the original IP (decision extracted into forward_confirmed_hostname for deterministic testing). A spoofed PTR record pointing at an allowlisted domain therefore cannot bypass the allowlist. New IPs that survive domain-aware diffing and remain unallowlisted are fail-closed.
   - install-time git clone signatures are diffed across current and baseline versions; newly introduced clone behavior is fail-closed unless allowlisted.
   - process-execution signatures (all executables captured, least-privilege approach) are diffed across versions; a newly introduced or changed/extra invocation is fail-closed unless allowlisted (process_exec_allowlist). Sandbox-internal commands (install probe, interpreter discovery) are automatically excluded via `is_harness_command` to prevent version-string false positives. This targets the Shai-Hulud "download Bun and run a hidden payload" class of attack.
- In-run optimization:
  - run keeps an in-memory cache keyed by manager/package/version to avoid repeating identical scans in one execution.

## Decision Model
For each scanned package:
0. If the package is in `internal_package_exemptions`, skip it entirely (no fetch/probe/diff) and allow it through at the requested version.
1. Determine current target version (explicit, or `latest` resolved via semantic ordering).
2. Resolve baseline versions (v-1 and v-2 where available, ordered semantically).
3. Collect behavior signals for current and baseline installs (network endpoints, install-time git clone signatures, and process-execution signatures). Network endpoints are normalized and have sandbox-local addresses (loopback/link-local/private, except the cloud metadata IP) filtered at capture time.
4. Compute set differences current minus baseline for each signal type.
5. Apply allowlists (`ip_allowlist`, `domain_allowlist`, `git_clone_allowlist`, `process_exec_allowlist`).
6. If non-allowlisted differences remain, block command.

## Fail-Closed Policy
gyrseek fails closed in the following situations:
- Unrecognized manager: the first argument is not one of `pip`, `pip3`, `uv`, `poetry`, `npm`, `pnpm`. Any other value (e.g. `ls`, `curl`, `sh`) exits 1 with a diagnostic. The only built-in exception is `sandbox runtimes`. Previously, unrecognized managers were silently forwarded unscanned, which violated the tool's "I scanned this before forwarding it" contract.
- Package detection is expected for a supported install or sync flow but no package entries are detected.
- Trace is empty or missing (strace produced no output — e.g. ptrace blocked).
- Sandbox initialization fails.

## Docker Sandbox Security

See [`docs/DOCKER_SECURITY.md`](DOCKER_SECURITY.md) for the full reference. In brief:

- Seccomp (enabled by default, can be disabled via `--danger-disable-seccomp`) and AppArmor (disabled by default) profiles are embedded in `src/sandbox.rs` and loaded at runtime.
- `SYS_PTRACE` is added for cross-UID strace; the traced payload runs unprivileged.
- Network access is enabled for package-manager registry access during probes.
- Egress controls are planned for future phases once prebuilt scanner images and no-execution-first detection are stable.

## Current Limitations
- Version ordering is semantic-version aware (semver for npm, PEP 440 for Python); unparseable versions fall back to sorting below parseable ones.
- Version pinning of the forwarded command applies only to explicit unpinned install targets; lockfile-driven flows rely on the lockfile's own pins.
- Direct runtime interception for standalone `git clone ...` commands is not enabled yet.
- Docker mode assumes Docker CLI availability; host mode assumes strace availability and is less safe. The unprivileged-payload (`strace -u`) trace-integrity protection applies to the Docker/microvm backends. Docker mode requires `CAP_SYS_PTRACE` (added via `--cap-add`) for cross-UID tracing; environments that strip it (some K8s/seccomp setups) will fail closed rather than pass silently.
- Trace extraction still assumes current strace output patterns.
- Behavioral signals (network, git clone, process execution) are only captured for what executes during the sandbox install. Payloads that fire outside the install window (e.g. the PyPI `*-setup.pth` startup-execution variant) may not detonate during the scan. Post-install artifact scan (file inventory, classifier for binary/suspicious/.pth/unexpected runtime/large files) partially mitigates this gap.
- Process-execution detection captures all executables by default (least-privilege). Sandbox-internal commands (install probes, interpreter discovery) are automatically excluded via `is_harness_command` to keep the diff clean. `process_exec_allowlist` is the user-facing escape hatch for expected new behavior.
- Environment variable reads (`getenv`) are invisible to `strace` as they do not trigger syscalls. However, `gyrseek` traces `open` and `openat` syscalls to detect attempts to read highly sensitive credential or configuration files (e.g., `~/.aws/credentials`, `~/.npmrc`, `.env`). Additionally, if a package attempts to exfiltrate an environment variable, the resulting network connection or process execution (e.g., `curl`) will be caught by the respective behavior detections.
- Egress is currently unrestricted for package manager registry access; future phases will add optional egress allowlists/proxy controls.

## Main Files
- src/main.rs: binary entrypoint
- src/lib.rs: routing and enforcement orchestration (including the `--version`/`-V` short-circuit); inline tests for GyrSeek::parse_package_details, parse_global_options edge cases, and config parsing (new_package_exemptions, internal_package_exemptions)
- src/parsing.rs: command, lockfile, and requirements parsing; inline tests for all parsers, rewrite_args_with_pinned_versions (including the `latest`-pin guard for skipped internal packages), PEP 508 extras, local-source exclusions, npm non-registry filtering, uv lock upgrade arg parsing
- src/scanning.rs: registry history lookup and behavior scanning; inline tests for version ordering, trace extraction (sandbox-local IP filtering, `::ffff:` collapse, metadata-IP preserved), anomaly detection, git-clone and watched-process diffing, FCrDNS, allowlist matching (including IPv4-mapped/bare equivalence), internal-package-exemption skip, missing-baseline fail-closed
- src/sandbox.rs: sandbox backend abstraction and mode selection; inline seccomp profile (embedded JSON, materialized at runtime); inline tests for docker args, strace flags, SYS_PTRACE, seccomp toggle, strace-stderr capture, network isolation, sandbox constraints enforcement
- tests/cli_burst_exit_tests.rs: release burst and minimum release age CLI exit-code tests (spawn binary)
- tests/forward_fail_closed_tests.rs: fail-closed forwarding and host exit-status propagation (spawn binary; uses a fake `uv venv` passthrough vehicle)
- tests/lock_routing_tests.rs: routing checks that bare `poetry lock` and `uv lock` reach the lockfile-scan branch, and that `uv venv` stays an unscanned passthrough (spawn binary)
- tests/version_flag_tests.rs: `--version`/`-V` prints the crate version and exits 0, and a forwarded command's own `--version` is not intercepted (spawn binary)
