# Roadmap

## Completed
- **External AI Code Review Migration** — Replaced in-repository AI review workflows and privileged `workflow_run` comment publishers with external CodeRabbit reviews (`.coderabbit.yaml`), isolating review feedback from runner execution contexts.
- Release archives for Linux and macOS (Apple Silicon and Intel) with a `SHA256SUMS` file and build attestations, and the `gyrseek-action` GitHub Action that installs a pinned release after checking its hash and attestation. CI installs gyrseek through the published action, pinned by commit, on Linux x86_64, Linux ARM64 and macOS. The sandbox on macOS is still verified by hand (OPEN #513).
- Per-probe wall-clock limit (`probe_timeout_seconds`, default 300) that blocks only the package that timed out, and `install_failed` blocking with the package manager's own error output when a probe's install fails.
- Sandbox Python and Node versions follow the project: `python_version`/`node_version` config, `.python-version`, `requires-python`/Poetry ranges, `.nvmrc`/`.node-version` and `engines.node`, selecting from built-in tables of digest-pinned images (Python 3.10–3.14, Node 20/22/24/26).
- Install-time git clone behavior diffing across package versions, plus `git_clone_allowlist` support.
- Process-execution diffing for all observed `execve` calls by default, with `process_exec_allowlist` as the only escape hatch.
- Post-install artifact inventory and diffing (`binary`, `suspicious_pth`, `unexpected_runtime`, `large_file`) with `artifact_allowlist` support.
- Semantic version ordering for npm/pnpm (semver) and Python managers (PEP 440), with safe fallback for unparseable versions.
- Exact-version pinning for forwarded explicit unpinned install targets, closing the scan-vs-install version gap.
- Expanded lockfile routing and fail-closed coverage for `uv sync`, bare `uv lock`, `uv lock --upgrade`, `uv lock -P/--upgrade-package`, `poetry install`, `poetry update`, and bare `poetry lock`.
- Top-level `--version`/`-V` support that works before config load or sandbox initialization and does not intercept a forwarded command's own trailing flag.
- Fail-closed manager handling: unsupported managers are rejected instead of being silently forwarded unscanned.
- Embedded seccomp (enabled by default) and AppArmor (opt-in via `GYRSEEK_DOCKER_APPARMOR_PROFILE`, Linux only) profiles in `src/sandbox.rs`, with runtime status announcements and per-platform fallback.
- Empty/whitespace traces now fail closed; strace stderr is captured; Docker tracing is hardened with `-s 4096 -v`, unprivileged payload execution, and `--cap-add SYS_PTRACE`.
- IPv6 capture and canonicalization, IPv4-mapped IPv6 collapse, sandbox-local IP filtering, and cloud-metadata IP preservation.
- FCrDNS-backed `domain_allowlist`, balanced-bracket exec parsing, and correct PEP 508 extras normalization for registry lookup plus forwarded pinning.
- Mixed global/per-package allowlist syntax across all six allowlist types (`ip_allowlist`, `domain_allowlist`, `git_clone_allowlist`, `artifact_allowlist`, `sensitive_file_access_allowlist`, `process_exec_allowlist`); effective set is global ∪ per-package for ip/domain; per-package only for the other four. Config-load-time key and value validation with actionable warnings.
- `internal_package_exemptions` support for first-party/private-index packages that should bypass registry lookup and sandbox scanning entirely.
- Docker and host sandbox modes.
- Prebuilt scanner image support and documented digest-pinning workflow for faster, more reproducible scans.
- In-run scan-result caching and Docker matrix batching for multiple package/version probes in one container session.
- Integration coverage for CLI exit-code behavior, lockfile routing, pnpm routing, version flags, artifact allowlisting, and fail-closed forwarding; inline tests cover parsing, scanning, and sandbox internals.
- Domain-aware IP diff using FCrDNS — resolves each IP at the domain level rather than the IP level, silently discarding CDN edge IPs whose domain was already seen in baseline traffic. No hardcoded registry domain list needed.
- Strace-based DNS interceptor fallback: `extract_dns_map` / `parse_dns_response` / `decode_dns_name` parse raw DNS wire-format from strace `recvfrom` output (requires strace `-xx` flag). When FCrDNS fails for a PTR-less IP (e.g. Fastly, Cloudflare), the container's own DNS responses are consulted; host-side `lookup_host` verifies the binding before trusting it. Circular pointer protection (5-hop limit) prevents crafted DNS packets from hanging the scanner.
- `-xx` strace flag added for deterministic hex-escape output; `extract_process_exec_signatures` unescapes hex-escaped argv so `is_harness_command` filtering continues to work correctly.
- Strict baseline comparison enforced: aggressively fail closed (`insufficient_baselines`) if the registry does not contain enough historical versions to satisfy `baseline_count` (unless the package is in `new_package_exemptions`).
- Default baseline age gate set to 72 hours (`DEFAULT_MIN_BASELINE_AGE_HOURS`) with a hard floor of 24 (`HARD_MINIMUM_AGE_HOURS`); per-package values below the floor are clamped with a warning. Override versions younger than the hard floor are rejected in `check_override_ages`.
- `new_package_exemptions` redesigned from a flat list (`Vec<String>`) to a version-pinned map (`HashMap<String, String>`) with a custom serde deserializer that accepts both formats for backward compatibility. Empty version values produce a warning and are dropped. The `tgt_version` branch in the exemption match was removed to prevent `"latest"` string bypass.
- The "safe to remove" exemption message is now gated on `new_package_exempt` so it only fires when the exemption version actually matched the current install, not just because baselines happen to suffice.

## Near Term
- Fetch and analyze registry metadata (npm and Python package indices) prior to executing the sandbox to fast-fail on obvious static anomalies (e.g. newly introduced suspicious dependencies or scripts).
- Add richer requirements and constraints parsing coverage, especially environment markers and line continuations.
- Add end-to-end command-path tests for pinned forwarding and lockfile-flow verbatim forwarding with a stub manager.
- Add executable (not just script-text) validation of Docker matrix batching so multi-package and multi-version paths are pinned end to end; today the inline tests only check the generated script text.
- Tighten user-facing error taxonomy and remediation guidance so fail-closed outcomes are easier to triage in CI and local workflows.

## Mid Term

### Detection & Analysis

- **Post-install interpreter trigger** — exercise the package's import/startup path inside the sandbox to catch deferred payloads. Covers two patterns:
  - Module-scope code (Telnyx T26, `mistralai` T32): **done** (FIXED #25, `import_scan`): the package's top-level modules are loaded after the install and diffed against the baselines' loads, for Python and Node.
  - `.pth`-based (Hades/Miasma T1, LiteLLM T25): `*-setup.pth` auto-executes on next Python interpreter startup. Still open (OPEN #489): call `site.addsitedir` before the import so `.pth` files run under strace.
  - Further import-time coverage: every submodule of the distribution (OPEN #488, #493), a static diff of the installed source (OPEN #491), host mode (OPEN #490).
- **Direct git clone runtime interception** — parse `git clone` commands, trace install-time clone behavior, and fail closed on new targets. Phases: command parser support → interception pipeline → baseline model → policy controls → test coverage.
- **Enhanced generated-file comparison** — layer SHA-256 hashing then semantic-aware diff on top of the current artifact inventory for high-risk file types (shell scripts, JS/TS, Python, lockfiles, manifests). Phases: file inventory diff → content-hash comparison → deterministic normalization → semantic diff → policy controls → integration tests.

### Hardening & Infrastructure

- Prebuilt scanner images as the default path — unblocks read-only rootfs, tighter capability drops, and stronger seccomp/apparmor defaults (see [`DOCKER_SECURITY.md`](DOCKER_SECURITY.md)).
- Improve resilience to strace output variations.
- Optional egress mediation/proxy mode for runtime scans (after no-execution-first stable) — logs full URLs (path-level visibility across registries) with allow/block policy, and checks Docker bridge reach into private ranges (OPEN_FINDINGS #412).
- Provenance and integrity gates — trusted registry policy, digest/signature verification where available.

### Reliability & UX

- Scan the highest version that satisfies a range, not only the latest: ranges typed on the command line are scanned at the latest version today and exit 1 when the latest is outside the range (`npm install lodash@^3` when 4.x is out). Needs a range-aware target in the scanner. Ranges inside `-r` files and `package.json` still need exact pins or a lockfile.
- Improve baseline selection strategy when fewer historical versions exist.
- Add structured logging mode for CI and machine parsing.
- Add configurable timeout and retry controls for registry lookups (probe execution already has `probe_timeout_seconds`).

## Long Term

### Hardening & Infrastructure

- **Migrate to default-deny seccomp architecture** — Currently, the sandbox uses a default-allow architecture (`SCMP_ACT_ALLOW`) which requires playing whack-a-mole with dangerous syscalls. Transition the seccomp profile to `SCMP_ACT_ERRNO` by default, combined with an exhaustive allowlist of POSIX syscalls required for typical package manager execution (based on Docker's default ~350 syscall allowlist). This will close any blind spots from future kernel additions or obscure exotic syscalls.
