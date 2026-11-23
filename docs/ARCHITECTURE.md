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
  - parse_python_install_packages_from_args resolves every package target from pip/pip3 install, uv pip install, uv add and poetry add args, including -r/--requirement(s) files, skipping the values of flags such as `--group dev`; `parse_package_details` (first package only) remains the fallback for other commands.
  - parse_npm_install_targets resolves npm/pnpm targets: specs named on the command line (`classify_npm_spec`: exact version, bare name or `@latest`, or a range that is recorded as a `RangeRequest` and scanned at the latest version; dist-tags and aliases exit 1), or with none named the lockfile (`parse_npm_lock_packages_from_content` for `package-lock.json`/`npm-shrinkwrap.json` v1–v3, `parse_pnpm_lock_packages_from_content` for `pnpm-lock.yaml` v5/v6/v9). After the scan `check_ranges_against_scanned` requires the scanned version to satisfy each range and `rewrite_args_with_pinned_versions_and_ranges` replaces the range argument with the scanned version; the Python parsers (`parse_python_install_targets`) do the same. `package.json` is never scanned because its dependencies are ranges. A missing lockfile and a bare `update` fail closed with the `--package-lock-only` / `--lockfile-only` route, and lockfile-only commands are forwarded unscanned because they install nothing. Non-registry specs (`link:`, `file:`, `git+`, URL) are excluded.
  - parse_uv_lock_upgrade_packages_from_args resolves update targets from uv lock -P or --upgrade-package arguments. When the value after -P starts with `-` (i.e. it is a flag, not a package), only one token is consumed so the next real argument is not silently dropped.
- Version history lookup:
  - fetch_history_with_baselines queries PyPI for Python packages and the npm registry for npm/pnpm packages.
  - Version lists are ordered semantically: semver for npm-family managers, PEP 440 for Python managers (compare_version_strings / sort_versions_ascending). Unparseable strings sort below any parseable version, so junk is never resolved as `latest`.
  - npm `time` map parsing (npm_published_times) excludes the `created`/`modified` bookkeeping keys and any non-version key, so the release-burst counter is not inflated.
- Behavior capture:
   - trace_sandbox_install_matrix runs via SandboxRunner backend and captures, per package-version: connection IPs (IPv4 via inet_addr and IPv6 via inet_pton, normalized by extract_connection_ips), install-time git clone command signatures, and process-execution signatures (extract_process_exec_signatures: `exe|arg1|...` for every execve). Sandbox-internal commands (the install probe itself, interpreter discovery) are excluded via `is_harness_command` so version-specific command strings do not cause false positives.
  - extract_connection_ips normalizes via normalize_ip_string (canonical IPv6 plus IPv4-mapped IPv6 `::ffff:1.2.3.4` collapsed to bare IPv4 `1.2.3.4`) and drops sandbox-local addresses via is_sandbox_local_ip — loopback, link-local (`fe80::/10`, `169.254/16`), and private/RFC1918 ranges (including the Docker bridge `172.17/16` and Docker Desktop gateway `192.168.65/24`). This happens at extraction, before the baseline diff and on both current and baseline traces, so the container's own plumbing (gateway, DNS resolver) never registers as a "new" endpoint. The cloud instance metadata endpoint `169.254.169.254` is deliberately exempt (kept) because a package reaching for it is a real SSRF/credential-theft signal.
  - In Docker mode strace runs with `-s 4096 -v -xx` (no argv/address truncation, hex-escaped strings) and `-u <scanner-user>` so the traced install payload runs unprivileged while strace's logs stay in a root-only, size-limited tmpfs (`/gyrseek-trace`, `GYRSEEK_TRACE_LIMIT`) and are streamed to gyrseek on stdout per probe, with no host mount (FIXED #411, #434, #461). Host mode runs plain `strace -f -e trace=...` without these flags, so it truncates argv at 32 bytes.
  - execve argv parsing (extract_process_exec_signatures / git-clone signature extraction) uses a balanced-bracket-aware regex so arguments containing `]` (e.g. PEP 508 extras `requests[security]`, paths like `script[obf].js`) are captured intact rather than truncated at the first `]`.
  - The Docker container is run with `--cap-add SYS_PTRACE`: strace runs as root but attaches to the install running as the unprivileged scanner user, and cross-UID ptrace requires CAP_SYS_PTRACE (not in Docker's default capability set). The capability is scoped to the container PID namespace and cannot trace host processes.
  - strace's own stderr is captured to a per-probe `gyrseek_err_N.log` (trace tmpfs, streamed out) (not `>/dev/null 2>&1`); `|| true` is retained only so a single failing install does not abort sibling probes. A genuine attach failure produces a blank trace log, which the reader turns into a hard error (fail closed) carrying the captured stderr.
  - Docker backend can execute probe matrices (multiple packages with their current and baseline versions) in one container session (at most 32 probes per container, a bigger batch runs in several, FIXED #494), wiping `/work` and `/tmp` between probes.
  - The sandbox image follows the project (`src/runtime_image.rs`): the `*_SCANNER_IMAGE` variable, then `python_version`/`node_version` in the config, then the nearest `.python-version`/`pyproject.toml` (Python) or `.nvmrc`/`.node-version`/`package.json` `engines.node` (Node), then the defaults (Python 3.13, Node 26). Ranges pick the default if it fits, else the closest supported version. Only digest-pinned images from the built-in tables can be selected, so project files never name an image. The chosen runtime is printed and repeated in `install_failed` messages.
  - A probe whose install exits non-zero (other than a timeout) is blocked as `install_failed`, for the candidate or any baseline: the script saves the exit code, the host adds the install's own error output, and `scanning.rs` prints which versions failed. Failed installs are never diffed as if they were normal.
  - After a timed-out probe the script kills payload processes until none is left (up to ten passes over `/proc`, zombies ignored) and exits 124 if any survive, aborting the batch rather than letting an untraced process share the next probe's workspace; a host-mode probe that times out is omitted like in Docker mode, and only the last 64 KiB of a failed install's stderr is read.
  - `collect_probe_traces` turns the files that `read_frames` wrote from the container's stdout into per-probe results (trace plus artifact inventory, timeout and limit markers, exit-code files; a missing or blank trace is an error and nothing is re-run) and is unit-tested without Docker.
  - **Import step (FIXED #25).** After each probe's install and artifact inventory, unless the install failed or timed out, `import_steps` (`src/sandbox.rs`) loads the installed package under a second strace with the same flags and the same unprivileged user, bounded by `import_timeout_seconds` (default 300; `0` falls back to 300): `IMPORT_PYTHON` imports the distribution's own modules (from the recorded files, the first real package or module below a namespace directory, `top_level.txt` only as a fallback, under `PYTHONPATH=/work`), `IMPORT_NODE` loads the package with `import()` and, only when it exports no `import` entry, `require()` (a package with no entry point is skipped). Both end the process as soon as the load settles. A second inventory is taken, and `read_import_run` keeps only the files the install inventory did not have. The files are `itrace`/`ierr`/`iartifacts`/`irc`/`itimeout` and stream out like the install's; `ProbeTrace.import` carries an `ImportRun` (trace, failure, timed-out); with the step on, a probe that installed but left no import files is dropped like a probe with no trace (`collect_probe_traces_expecting`, FIXED #501). `scanning.rs` runs the same `check_phase` for the install and the import (`Phase`, `AllowlistRefs`), a load being compared with the baselines' loads; the `import_*` allowlists (`PolicyConfig.import_allowlists`) are separate from the install-time ones. `check_import` decides what a failed or timed-out load means: a timeout anywhere, or the candidate failing while a baseline loaded, blocks as `import_failed`; the candidate and every baseline failing to load (whatever the errors) warns; no clean baseline for a candidate that loads means no comparison; the new-package exemption (fewer baselines than wanted) skips the anomaly checks but not these failure decisions (`check_import` with `compare` false). The import scripts are excluded from the exec diff by comparing their whole text (`is_import_probe`). The inventory program, the import program and the payload-kill block are shell variables/a function defined once at the top of the script (`script_variable_steps`), because the whole script is one `docker run` argument with a 128 KiB limit, so a batch is also split over containers of at most 32 probes (`probe_chunks`, FIXED #494). `--no-import-scan` / `import_scan: false` (`DockerRunner.import_timeout_secs` is `None`) leave the step out of the script; host mode never runs it.
  - Every probe runs under GNU `timeout` (`probe_timeout_seconds`, default 300). `timeout -k 5` sends SIGTERM and then SIGKILL, because a payload that ignores SIGTERM keeps `strace` alive. In Docker an expired probe leaves a `gyrseek_timeout_N.log` marker (streamed to the host like the other per-probe files), the payload's leftover processes are killed, and the remaining probes continue; the host leaves that probe's trace out so the scanner blocks only that package. Host mode wraps `strace` the same way.
  - `build_runner_from_env` selects backend mode (`docker` default, or `host` — no isolation, detection only — selected only by the `--no-sandbox` flag).
- Anomaly decision:
   - Packages listed in `internal_package_exemptions` are skipped entirely before the registry fetch and sandbox install (no history lookup, no probe, no diff) and forwarded unscanned at their requested version. This is for first-party/internal packages on a private index (e.g. Nexus) that the public-registry lookups cannot resolve, where scanning only produces `(n/a)`-baseline noise. Distinct from `new_package_exemptions`, which still fetches and probes and only relaxes the under-2-baselines block.
   - `new_package_exemptions` is a per-package map (`pkg: "version"`) that exempts a specific pinned version from the insufficient-baselines block. The `List` variant in the untagged `NewPkgExemptions` enum now returns `Err(serde::de::Error::custom(...))` with a clear message telling the user to migrate to map format. The YAML config parse fails with a hard error that includes the config file path and the migration instruction. (Note: an empty list `[]` is explicitly handled as an exception and silently maps to no exemptions without error). Empty version values in maps are rejected with a warning at parse time. The exemption only matches the resolved `v_curr` — the former `tgt_version` comparison was removed to prevent a bypass where `"latest"` as an exemption value matched unpinned installs (`new_package_exemption_tgt_version_no_longer_checked` regression test).
   - find_new_connections_domain_aware resolves each IP via FCrDNS and diffs at the domain level rather than the IP level. If a current IP resolves to a domain already seen in baseline traffic, it is silently discarded (benign CDN edge rotation). Unresolvable IPs fall back to plain IP membership so the diff stays fail-closed for genuinely new or spoofed endpoints.
   - Unresolvable IPs also get a second chance via the **DNS interceptor**: the strace trace is scanned for `recvfrom` (UDP) and `read`/`recvmsg` (TCP) syscalls to port 53 (DNS) across both IPv4 (`sin_port`) and IPv6 (`sin6_port`) sockets, and raw response bytes are parsed by a wire-format DNS parser (`extract_dns_map` / `parse_dns_response` / `decode_dns_name` in `scanning.rs`). If the current IP appears in the container's observed DNS map under a domain that was also seen in baseline DNS traces, host-side `lookup_host` re-verifies the binding before trusting it. This handles CDN edge rotations that lack PTR records (e.g. Fastly, Cloudflare) without any hardcoded domain allowlist. It skips short TCP reads (< 3 bytes) without crashing, but lacks full TCP reassembly (fragmented responses are dropped).
   - **Two-layer anti-spoofing:** The domain→IP binding is verified twice. First, FCrDNS confirms the PTR record's hostname resolves forward back to the original IP (attackers who set a fake PTR on their C2 cannot bypass because the allowlisted domain's real DNS doesn't point to their C2). Second, when FCrDNS fails (no PTR), the DNS interceptor fallback re-verifies the binding on the **host** via `std::net::lookup_host` — container-side DNS poisoning cannot influence the host's resolver, so a forged DNS response in the strace trace is rejected. An attacker would need to compromise the host's DNS resolver to bypass both layers.
   - **Circular compression pointer protection:** `decode_dns_name` limits compression pointer hops to 5. RFC 1035 names are bounded at 255 wire-format bytes; each pointer consumes 2 bytes and saves at least 1 byte versus the literal label. A 5-hop ceiling therefore accommodates every legitimate name — the worst-case nested subdomain (e.g. `a.b.c.d.e.f.g.pypi.org`) typically needs only 1–2 hops to compress a shared suffix. The limit prevents a maliciously crafted self-referencing pointer (e.g. `\xc0\x00` at offset 0 targeting offset 0) from hanging the scanner indefinitely (DoS). When exceeded, the parser returns `None`, and the diff falls back to plain IP membership (fail-closed).
  - The `ip_allowlist` and `domain_allowlist` support a mixed **global / per-package** syntax: bare entries (`- "1.2.3.4"`) apply to all packages; map entries (`- pkg: ["1.2.3.4"]`) scope the entry to one package. The effective allowlist for a scan is global ∪ per-package; per-package entries never reduce global protection. The `ip_allowlist` matcher compares on the IPv4-mapped-collapsed canonical form (`::ffff:1.2.3.4` → `1.2.3.4`), so equivalent IPv6 and IPv4 forms match interchangeably.
  - The `domain_allowlist` uses forward-confirmed reverse DNS (FCrDNS): `reverse_dns_domain` resolves the PTR hostname and only trusts it if its forward A/AAAA resolution includes the original IP (decision extracted into `forward_confirmed_hostname` for deterministic testing). A spoofed PTR record pointing at an allowlisted domain therefore cannot bypass the allowlist. New IPs that survive domain-aware diffing and remain unallowlisted are fail-closed.
  - Lockfile trust and input tracking: `parse_npm_lock`/`parse_pnpm_lock` fail closed on entries not resolved from `registry.npmjs.org`, and `parse_uv_lock`/`parse_poetry_lock`/`parse_pylock` on entries not from PyPI; in all five parsers a package listed in `internal_package_exemptions` is let through (and not scanned), which is how private npm, pnpm and Python packages are configured; URLs in refusals are reduced to host and file name (`redact_urls`); lockfile installs are forwarded frozen (`npm ci`, `pnpm --frozen-lockfile`, `uv sync --locked`); `read_input`/`changed_inputs` re-check every scanned input file before forwarding (TOCTOU). With both `npm-shrinkwrap.json` and `package-lock.json` present, both are scanned (npm 11 reads the shrinkwrap first, npm 12 ignores it). Index and registry redirects (`src/index_settings.rs`) are checked on the first scan and refused unless the host is public or in `trusted_index_hosts`. Download URLs are also matched to the package they are listed under (`npm_tarball_matches`, `python_artifact_matches`). `tests/lockfile-guards.sh` (`just test-lockfile-guards`, CI `rust-checks`) exercises these refusals with the real binary, and `tests/e2e/redirects.sh` (`just test-redirects-<manager>`, the Docker CI jobs) runs the redirect, trusted-mirror, tampered-hash and drifted-lockfile cases with the real package managers and the Docker sandbox. `src/lock_verify.rs` runs first in `scan_targets`: it takes the lockfile contents `read_input` recorded and requires every locked hash to be a hash the public registry publishes for that version (FIXED #447, #452), so the install is pinned to a public file whichever host serves it. Install-time git clone signatures carry risky options (`config:`, `upload-pack:`, `template:`, `reference:`) so a plain URL allowlist entry does not cover them.
  - `git_clone_allowlist`, `process_exec_allowlist`, `artifact_allowlist`, and `sensitive_file_access_allowlist` are **per-package only** (no global `"*"` key); they are loaded via `parse_list_map` which rejects `"*"` as a key with a warning.
   - install-time git clone signatures are diffed across current and baseline versions; newly introduced clone behavior is fail-closed unless allowlisted.
   - process-execution signatures (all executables captured, least-privilege approach) are diffed across versions; a newly introduced or changed/extra invocation is fail-closed unless allowlisted (process_exec_allowlist). Sandbox-internal commands (install probe, interpreter discovery) are automatically excluded via `is_harness_command` to prevent version-string false positives. This targets the Shai-Hulud "download Bun and run a hidden payload" class of attack.
- Config-loading helpers (src/lib.rs):
  - `parse_list()` converts a YAML sequence of strings into a `HashSet<String>`, optionally lowercasing.
  - `parse_list_map(map, lowercase, name)` converts a YAML mapping of `pkg → [values]` into a `HashMap<String, HashSet<String>>`. Calls `validate_allowlist_pkg_key` for every key. Duplicate or whitespace-variant keys are merged (not overwritten) with a warning; a package key whose entire value set is empty after filtering emits a warning and is dropped so the operator knows they have no protection for that key. Used by `git_clone_allowlist`, `artifact_allowlist`, `sensitive_file_access_allowlist`, and `process_exec_allowlist`.
  - `validate_allowlist_pkg_key(pkg_raw, allowlist_name, existing, has_global_variant)` centralises per-package key hygiene: trims whitespace, rejects empty keys, rejects `"*"` with context-sensitive guidance (ip/domain variant: "use a bare global entry instead"; parse_list_map variant: "this allowlist does not support a global wildcard"), and warns on whitespace-variant collisions (e.g. `" boto3"` and `"boto3"` merge instead of silently overwriting). Returns `Some(trimmed_key)` or `None`.
  - `option_zero_to_none(val, warn_msg)` maps `Some(0)` to `None` with a warning and passes other values through. Used for `release_burst_threshold`, `minimum_release_age_package`, and `release_burst_window_hours` so that a zero config value silently disables the feature rather than triggering undefined threshold behaviour.
- In-run optimization:
  - run keeps an in-memory cache keyed by manager/package/version to avoid repeating identical scans in one execution.

## Decision Model
For each scanned package:
0. If the package is in `internal_package_exemptions`, skip it entirely (no fetch/probe/diff) and allow it through at the requested version.
1. Determine current target version (explicit, or `latest` resolved via semantic ordering).
2. Baseline candidates are fetched from the registry and filtered by a configurable age gate (`min_baseline_age_hours`, default 72). Any per-package value below the hard floor of 24 hours (`HARD_MINIMUM_AGE_HOURS`) is clamped with a warning. Baseline overrides let the operator pin specific versions; overrides younger than 24h are rejected with a warning in the production path (enforced by `check_override_ages` at `src/scanning.rs`).
3. Collect behavior signals for current and baseline installs (network endpoints, install-time git clone signatures, and process-execution signatures). Network endpoints are normalized and have sandbox-local addresses (loopback/link-local/private, except the cloud metadata IP) filtered at capture time.
4. Compute set differences current minus baseline for each signal type.
5. Apply allowlists (`ip_allowlist`, `domain_allowlist`, `git_clone_allowlist`, `process_exec_allowlist`, `artifact_allowlist`, `sensitive_file_access_allowlist`). Each allowlist computes an effective set of global ∪ per-package entries for the scanned package.
6. If non-allowlisted differences remain, block command.

## Fail-Closed Policy
gyrseek fails closed in the following situations:
- Unrecognized manager: the first argument is not one of `pip`, `pip3`, `uv`, `poetry`, `npm`, `pnpm`. Any other value (e.g. `ls`, `curl`, `sh`) exits 1 with a diagnostic. Previously, unrecognized managers were silently forwarded unscanned, which violated the tool's "I scanned this before forwarding it" contract.
- Package detection is expected for a supported install or sync flow but no package entries are detected.
- Trace is empty or missing (strace produced no output — e.g. ptrace blocked).
- Sandbox initialization fails, including the Docker preflight (`docker_preflight`): a missing `docker` CLI, a stopped daemon, or no permission on the Docker socket each exit 1 with a cause-specific message before any registry lookup.

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
- Docker mode assumes Docker CLI availability; host mode assumes strace availability and provides no isolation (packages run directly on the host; gyrseek can only detect, not contain, and the trace has no integrity protection); run it only in very isolated, disposable, secret-free environments. The unprivileged-payload (`strace -u`) trace-integrity protection applies to the Docker backend. Docker mode requires `CAP_SYS_PTRACE` (added via `--cap-add`) for cross-UID tracing; environments that strip it (some K8s/seccomp setups) will fail closed rather than pass silently.
- Trace extraction still assumes current strace output patterns.
- Behavioral signals (network, git clone, process execution) are only captured for what executes during the sandbox install and the import step that follows it (the package's own top-level modules are loaded, FIXED #25). Payloads that fire outside both (the PyPI `*-setup.pth` startup-execution variant, OPEN #489; code in a submodule nobody imports or behind a condition, OPEN #488) may not detonate during the scan. The post-install artifact scan runs in Docker mode only; host mode (`--no-sandbox`) performs no artifact scan. Post-install artifact scan (file inventory, classifier for binary/suspicious/.pth/unexpected runtime/large files) partially mitigates this gap.
- Process-execution detection captures all executables by default (least-privilege). Sandbox-internal commands (install probes, interpreter discovery) are automatically excluded via `is_harness_command` to keep the diff clean. `process_exec_allowlist` is the user-facing escape hatch for expected new behavior.
- Environment variable reads (`getenv`) are invisible to `strace` as they do not trigger syscalls. However, `gyrseek` traces `open` and `openat` syscalls to detect attempts to read highly sensitive credential or configuration files (e.g., `~/.aws/credentials`, `~/.npmrc`, `.env`). Exfiltrating an environment variable is only detected if it surfaces as a new public network endpoint or a newly executed program (e.g., `curl`) that the baselines did not show. It is not detected when the package sends the value from its own process to a loopback, link-local or private address (these are filtered out as sandbox-local, except the cloud metadata address `169.254.169.254`), or to an endpoint that already appears in the baseline traffic.
- Egress is currently unrestricted for package manager registry access in Docker mode; future phases will add optional egress allowlists/proxy controls.

## Main Files
- src/main.rs: binary entrypoint
- src/lib.rs: routing and enforcement orchestration (including the `--version`/`-V` short-circuit); inline tests for GyrSeek::parse_package_details, parse_global_options edge cases, and config parsing (new_package_exemptions, internal_package_exemptions)
- src/parsing.rs: command, lockfile, and requirements parsing; inline tests for all parsers, rewrite_args_with_pinned_versions (including the `latest`-pin guard for skipped internal packages), PEP 508 extras, local-source exclusions, npm non-registry filtering, uv lock upgrade arg parsing
- src/scanning.rs: registry history lookup and behavior scanning; inline tests for version ordering, trace extraction (sandbox-local IP filtering, `::ffff:` collapse, metadata-IP preserved), anomaly detection, git-clone and watched-process diffing, FCrDNS, allowlist matching (including IPv4-mapped/bare equivalence), internal-package-exemption skip, missing-baseline fail-closed
- src/runtime_image.rs: picks the Python/Node sandbox image from config and project version files (`.python-version`, `pyproject.toml`, `.nvmrc`, `.node-version`, `package.json` `engines.node`) out of digest-pinned built-in tables
- src/sandbox.rs: sandbox backends (`DockerRunner`, `HostRunner`), `build_runner_from_env` mode selection (host mode only via `--no-sandbox`), `docker_preflight`, matrix probe script and scanner image config; inline seccomp profile (embedded JSON, materialized at runtime); inline tests for docker args, strace flags, SYS_PTRACE, seccomp toggle, strace-stderr capture, seccomp syscall enforcement
- tests/cli_burst_exit_tests.rs: release burst and minimum release age CLI exit-code tests (spawn binary)
- tests/forward_fail_closed_tests.rs: fail-closed forwarding and host exit-status propagation (spawn binary; uses a fake `uv venv` passthrough vehicle)
- tests/lock_routing_tests.rs: routing checks that bare `poetry lock` and `uv lock` reach the lockfile-scan branch, and that `uv venv` stays an unscanned passthrough (spawn binary)
- tests/pnpm_routing_tests.rs: `pnpm add` and `pnpm install` reach the package-scan branch (lockfile scan) without Docker or network (spawn binary)
- tests/npm_lockfile_tests.rs: `npm install` / `i` / `ci` scan the lockfile, no-lockfile and `update` fail closed, ranges exit 1, lockfile-only commands forward unscanned (spawn binary)
- tests/sandbox_startup_exit_tests.rs: sandbox startup failures (Docker missing or daemon down, an unscanned passthrough never initializing the sandbox, the retired `GYRSEEK_SANDBOX` variable being ignored) exit 1 with a cause-specific message (spawn binary with a fake `docker`)
- tests/version_flag_tests.rs: `--version`/`-V` prints the crate version and exits 0, and a forwarded command's own `--version` is not intercepted (spawn binary)

## CI/CD Pipeline Architecture
The CI pipeline (`ci.yml`) runs on `pull_request` and push events with workflow-level `contents: read` permissions (with a scoped job-level `checks: write` grant restricted strictly to the `cargo-audit` job). It executes formatting, static analysis (yamllint, hadolint, shellcheck, clippy), unit/integration test suites, dependency advisory audits (`cargo-audit`), and containerized runtime test matrices. Automated AI code reviews are handled externally via CodeRabbit (`.coderabbit.yaml`).

**Rule:** Never add write permissions (like `pull-requests: write` or `contents: write`) to `ci.yml`. Any future automation requiring write access must be placed in a separate `workflow_run` triggered YAML file to prevent token exfiltration.

## Threat Model & Accepted Risks
Based on our static analysis and architectural reviews, the following risks are explicitly accepted by design:

### 1. External AI Code Review
AI code reviews are delegated to CodeRabbit (`.coderabbit.yaml`). Review feedback runs in an isolated external SaaS environment with appropriate webhook permissions, removing the need for privileged in-repo runner jobs (`post_review.yml`) or unpinned third-party review binaries in CI.

### 2. Sandbox Syscall Permissiveness
- **`process_vm_readv` Allowed:** `strace` intrinsically requires `process_vm_readv` to read strings and data structures (like arguments to `execve` or file paths in `open`) from the target process's memory space. Blocking it would blind our behavioral telemetry.
- **Integrity Protection:** Because we explicitly block `process_vm_writev`, the primary cross-process memory write vector through ptrace is neutralized. Other write paths (e.g., `/proc/pid/mem`) remain open and are accepted risks. Read-only sibling access poses no threat to the integrity of the root-owned trace logs.

### 3. CI/CD Architecture Trade-offs
- **Fragmented Permissions:** `checks: write` is intentionally fragmented and granted strictly to the `cargo-audit` job, never at the workflow top-level. This limits token privilege to the minimum required.

### 4. DNS Exfiltration Boundaries
- **DNS Query Exfiltration:** The DNS interceptor parses DNS *responses* (from the strace `recvfrom`), not DNS queries. An attacker encoding secrets into DNS query names sent to an allowed domain bypasses the network diff. This is explicitly accepted as out-of-scope for the install-time behavioral detection.

## Development

### Local Setup
1. Install Rust toolchain.
2. Install just.
3. Ensure required package managers are available for your target flows: uv, pip or pip3, poetry, npm, pnpm.
4. Ensure Docker is installed and running (the only sandbox; see the README prerequisites).
5. If using host mode (`--no-sandbox`), ensure strace is available in PATH.

### Agent Portability Symlinks

The repo uses symlinks so multiple AI coding tools share the same skills and instructions without duplication:

| Symlink | Target | Purpose |
|---|---|---|
| `.claude/skills` | `../.agents/skills` | Claude Code skill discovery |
| `.github/skills` | `../.agents/skills` | GitHub Copilot skill discovery |
| `CLAUDE.md` | `AGENTS.md` | Claude Code instruction alias (looks for `CLAUDE.md`, not `AGENTS.md`) |

New skills added under `.agents/skills/` are automatically picked up by all tools. Because `CLAUDE.md` → `AGENTS.md`, any instruction changes in `AGENTS.md` are instantly reflected for Claude Code with no extra step. If you add support for another agent (Cursor, Windsurf, etc.), create a similar symlink here instead of copying files.

### Build and Test
- Build debug: cargo build
- Build release: just build
- Install locally: just install
- Uninstall locally: just uninstall
- Run tests: just test (or cargo test directly)
- Run lint checks: just lint (cargo check + clippy + format check)
- Format code: just fmt
- Run inline tests for one module: cargo test --lib sandbox / cargo test --lib scanning / cargo test --lib parsing / cargo test --lib
  - `cargo test --lib sandbox` includes docker arg construction, seccomp/apparmor profile toggle, profile content, and strace setup tests
- Run CLI integration tests (spawn binary): cargo test --test cli_burst_exit_tests / cargo test --test forward_fail_closed_tests / cargo test --test lock_routing_tests / cargo test --test pnpm_routing_tests / cargo test --test version_flag_tests / cargo test --test sandbox_startup_exit_tests

### Adding a New Supported Command
1. Add command detection in run routing logic.
2. Decide if command is single-target or bulk-target.
3. Reuse or extend parser helpers.
4. Reuse scan_package_versions (single) or scan_packages_versions (bulk) for resolved targets; both take a single &PolicyConfig and return a ScanReport per target (allowed + resolved_version).
5. For explicit unpinned install targets, forward via forward_pinned_command(&pins) using the resolved_version values so the host installs exactly what was scanned; lockfile/manifest-driven flows forward verbatim with forward_original_command.
6. Enforce fail-closed when detection is expected but unresolved.
7. Add parser tests and behavior tests.

### Test Locations
- Follow Rust convention: unit tests for private/internal functions live inline in the module's `#[cfg(test)] mod tests` (they can see private items); integration tests that exercise the public API or need a real subprocess live under tests/.
- Pure-function unit tests live inline in their src/ module (version ordering, trace extraction including sandbox-local IP filtering / `::ffff:` collapse / metadata-IP preservation, FCrDNS, bracketed-argv parsing, docker arg construction, SYS_PTRACE, PEP 508 extras stripping, poetry/uv local-source exclusion, npm/pnpm non-registry filtering, git-clone allowlist matching, IP allowlist IPv4-mapped/bare equivalence, internal-package-exemption skip, missing-baseline fail-closed, uv lock upgrade arg edge cases, harness-command filtering via `is_harness_command`); keep these alongside the code they cover.
- Anything that can only be observed from outside the process belongs in tests/ — e.g. host exit-status propagation (`std::process::exit`) in tests/forward_fail_closed_tests.rs, command routing (bare `poetry lock`/`uv lock` and pnpm scan routing) in tests/lock_routing_tests.rs and tests/pnpm_routing_tests.rs, and the `--version` short-circuit in tests/version_flag_tests.rs, because these are only visible to a spawning parent.

### Required Change Hygiene
After every repository change:
1. Update AGENTS.md (repository memory).
2. Update README.md (user-facing docs).
3. Update docs/ files (ARCHITECTURE.md, ROADMAP.md, OPEN_FINDINGS.md, FIXED_FINDINGS.md, WONT_FIX_FINDINGS.md, DOCKER_SECURITY.md) if architecture or workflow changed.
4. Run `graphify update .` to refresh graph artifacts (or `graphify update . --force` if guard warns).
5. Run `just test` before finishing.
6. Run `just lint` — cargo check, formatting, and clippy.

### Practical Review Checklist
- Command path is correctly recognized.
- Package extraction is deterministic.
- Unknown or ambiguous input does not silently bypass protections.
- Bulk operations scan all intended package targets.
- Non-target commands still passthrough when appropriate.
- Tests cover positive and negative parse cases.
- Sandbox hardening (seccomp, SYS_PTRACE) does not break trace capture or registry access.
- Empty/whitespace traces fail closed (not silently passed).
- strace capability failures are reported in captured stderr logs.
