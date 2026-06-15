# Roadmap

## Completed
- Install-time git clone behavior diffing across package versions, plus `git_clone_allowlist` support.
- Process-execution diffing for all observed `execve` calls by default, with `process_exec_allowlist` as the only escape hatch.
- Post-install artifact inventory and diffing (`binary`, `suspicious_pth`, `unexpected_runtime`, `large_file`) with `artifact_allowlist` support.
- Semantic version ordering for npm/pnpm (semver) and Python managers (PEP 440), with safe fallback for unparseable versions.
- Exact-version pinning for forwarded explicit unpinned install targets, closing the scan-vs-install version gap.
- Expanded lockfile routing and fail-closed coverage for `uv sync`, bare `uv lock`, `uv lock --upgrade`, `uv lock -P/--upgrade-package`, `poetry install`, `poetry update`, and bare `poetry lock`.
- Top-level `--version`/`-V` support that works before config load or sandbox initialization and does not intercept a forwarded command's own trailing flag.
- Fail-closed manager handling: unsupported managers are rejected instead of being silently forwarded unscanned; the built-in exception is `sandbox runtimes`.
- Embedded seccomp and AppArmor profiles in `src/sandbox.rs`, enabled by default with runtime status announcements and per-platform fallback.
- Empty/whitespace traces now fail closed; strace stderr is captured; Docker tracing is hardened with `-s 4096 -v`, unprivileged payload execution, and `--cap-add SYS_PTRACE`.
- IPv6 capture and canonicalization, IPv4-mapped IPv6 collapse, sandbox-local IP filtering, and cloud-metadata IP preservation.
- FCrDNS-backed `domain_allowlist`, balanced-bracket exec parsing, and correct PEP 508 extras normalization for registry lookup plus forwarded pinning.
- `internal_package_exemptions` support for first-party/private-index packages that should bypass registry lookup and sandbox scanning entirely.
- Docker, host, and MicroVM sandbox modes, including runtime selection via `GYRSEEK_MICROVM_RUNTIME` and the `sandbox runtimes` diagnostic command.
- Prebuilt scanner image support and documented digest-pinning workflow for faster, more reproducible scans.
- In-run scan-result caching and Docker matrix batching for multiple package/version probes in one container session.
- Integration coverage for CLI exit-code behavior, lockfile routing, pnpm routing, version flags, artifact allowlisting, and fail-closed forwarding; inline tests cover parsing, scanning, and sandbox internals.
- Domain-aware IP diff using FCrDNS — resolves each IP at the domain level rather than the IP level, silently discarding CDN edge IPs whose domain was already seen in baseline traffic. No hardcoded registry domain list needed.
- Strace-based DNS interceptor fallback: `extract_dns_map` / `parse_dns_response` / `decode_dns_name` parse raw DNS wire-format from strace `recvfrom` output (requires strace `-xx` flag). When FCrDNS fails for a PTR-less IP (e.g. Fastly, Cloudflare), the container's own DNS responses are consulted; host-side `lookup_host` verifies the binding before trusting it. Circular pointer protection (5-hop limit) prevents crafted DNS packets from hanging the scanner.
- `-xx` strace flag added for deterministic hex-escape output; `extract_process_exec_signatures` unescapes hex-escaped argv so `is_harness_command` filtering continues to work correctly.

## Near Term
- Add richer requirements and constraints parsing coverage, especially environment markers and line continuations.
- Add end-to-end command-path tests for pinned forwarding and lockfile-flow verbatim forwarding with a stub manager.
- Add focused tests for Docker matrix batching behavior so multi-package and multi-version paths are pinned by executable validation, not just inline helpers.
- Tighten user-facing error taxonomy and remediation guidance so fail-closed outcomes are easier to triage in CI and local workflows.

## Mid Term

### Detection & Analysis

- **Post-install interpreter trigger** — exercise the package's import/startup path inside the sandbox to catch deferred payloads. Covers two patterns:
  - `.pth`-based (Hades/Miasma T1, LiteLLM T25): `*-setup.pth` auto-executes on next Python interpreter startup
  - Module-scope code (Telnyx T26): `FetchAudio()` / `setup()` calls at `_client.py` module scope fire on `import telnyx` — no postinstall hook, no `.pth` file, just base64 blobs embedded in a legitimate SDK source file
- **Direct git clone runtime interception** — parse `git clone` commands, trace install-time clone behavior, and fail closed on new targets. Phases: command parser support → interception pipeline → baseline model → policy controls → test coverage.
- **Enhanced generated-file comparison** — layer SHA-256 hashing then semantic-aware diff on top of the current artifact inventory for high-risk file types (shell scripts, JS/TS, Python, lockfiles, manifests). Phases: file inventory diff → content-hash comparison → deterministic normalization → semantic diff → policy controls → integration tests.

### Hardening & Infrastructure

- Prebuilt scanner images as the default path — unblocks read-only rootfs, tighter capability drops, and stronger seccomp/apparmor defaults (see [`DOCKER_SECURITY.md`](DOCKER_SECURITY.md)).
- Improve resilience to strace output variations.
- Optional egress mediation/proxy mode for runtime scans (after no-execution-first stable).
- Provenance and integrity gates — trusted registry policy, digest/signature verification where available.

### Reliability & UX

- Improve baseline selection strategy when fewer historical versions exist.
- Add structured logging mode for CI and machine parsing.
- Add configurable timeout and retry controls for registry lookups and slow probe execution.
