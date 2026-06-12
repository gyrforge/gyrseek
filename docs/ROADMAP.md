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
- Empty/whitespace traces now fail closed; strace stderr is captured; Docker tracing is hardened with `-s 4096 -v`, unprivileged payload execution, and `--cap-add SYS_PTRACE`.
- IPv6 capture and canonicalization, IPv4-mapped IPv6 collapse, sandbox-local IP filtering, and cloud-metadata IP preservation.
- FCrDNS-backed `domain_allowlist`, balanced-bracket exec parsing, and correct PEP 508 extras normalization for registry lookup plus forwarded pinning.
- `internal_package_exemptions` support for first-party/private-index packages that should bypass registry lookup and sandbox scanning entirely.
- Docker, host, and MicroVM sandbox modes, including runtime selection via `GYRSEEK_MICROVM_RUNTIME` and the `sandbox runtimes` diagnostic command.
- Prebuilt scanner image support and documented digest-pinning workflow for faster, more reproducible scans.
- In-run scan-result caching and Docker matrix batching for multiple package/version probes in one container session.
- Integration coverage for CLI exit-code behavior, lockfile routing, pnpm routing, version flags, artifact allowlisting, and fail-closed forwarding; inline tests cover parsing, scanning, and sandbox internals.

## Near Term
- Add richer requirements and constraints parsing coverage, especially environment markers and line continuations.
- Add end-to-end command-path tests for pinned forwarding and lockfile-flow verbatim forwarding with a stub manager.
- Add focused tests for Docker matrix batching behavior so multi-package and multi-version paths are pinned by executable validation, not just inline helpers.
- Tighten user-facing error taxonomy and remediation guidance so fail-closed outcomes are easier to triage in CI and local workflows.

## Mid Term
- Detect post-install / startup-triggered payloads that fire outside the install window: exercise the package's import/startup path inside the sandbox and diff that behavior too. Covers two patterns:
  - `.pth`-based (Hades/Miasma T1, LiteLLM T25): `*-setup.pth` auto-executes on next Python interpreter startup
  - Module-scope code (Telnyx T26): `FetchAudio()` / `setup()` calls at `_client.py` module scope fire on `import telnyx` — no postinstall hook, no `.pth` file, just base64 blobs embedded in a legitimate SDK source file
- Add direct runtime git clone interception path with safe heuristics.
- Improve baseline selection strategy when fewer historical versions exist.
- Add structured logging mode for CI and machine parsing.
- Add configurable timeout and retry controls for registry lookups and slow probe execution.

## Direct Git Clone Runtime Support
- Phase 1: command parser support for direct `git clone` targets (HTTPS/SSH URL forms, optional branch/ref flags).
- Phase 2: runtime interception pipeline for direct git clone commands with fail-closed behavior on parser or trace failures.
- Phase 3: baseline model for direct git clone behavior (known-safe clone signatures and first-seen repo gating).
- Phase 4: expand policy controls for direct runtime clone gating (strict mode, optional pinned-ref requirement, and first-seen-repo policy actions).
- Phase 5: test coverage for direct runtime clone paths (unit + integration + hostile fixture scenarios).

## Hardening
- ✅ Embed seccomp profile in Rust (opt-in via `GYRSEEK_DOCKER_SECCOMP_PROFILE` boolean, default true).
- ✅ Runtime seccomp status announcements (`[gyrseek][INFO]` / `[gyrseek][WARN]`).
- ⏳ AppArmor profile rollout (Linux hosts).
- ⏳ Improve resilience to strace output variations.
- ⏳ Add optional strict egress mediation/proxy mode for runtime scans (after no-execution-first stable).
- ⏳ Add provenance and integrity gates (trusted registry policy, digest/signature verification where available).
- ⏳ Revisit stricter container controls once prebuilt scanner images are the normal path: read-only rootfs, tighter capability drop, and stronger seccomp/apparmor defaults.

## Generated File Comparison Across Versions
- Add artifact extraction stage to compare generated output files between current and baseline package versions.
- Phase 1: file inventory diff (added/removed/renamed files) with risk scoring for executable/script paths.
- Phase 2: content-hash comparison as a fast first-pass signal (SHA-256 per file, plus aggregate package digest).
- Phase 3: deterministic normalization before hashing (line endings, timestamps, archive metadata stripping) to reduce false positives.
- Phase 4: semantic-aware diff for high-risk file types (shell scripts, JS/TS, Python, lockfiles, manifests) instead of hash-only checks.
- Phase 5: policy controls for acceptable generated-file drift (allowlist patterns, size deltas, new executable flags, threshold-based fail-closed).
- Phase 6: integration tests with benign and malicious fixtures to validate true-positive/false-positive tradeoffs.

### Best Practices
- Use layered detection: normalized hash comparison for broad coverage, then semantic diffing for high-risk files.
- Treat hash mismatch as a triage signal, not a final verdict; gate enforcement on risk-scored change context.
- Normalize all deterministic noise sources before diffing (timestamps, archive ordering, file mode drift when non-security-relevant).
- Keep strict fail-closed defaults for new executable content, new network-capable scripts, and suspicious install-hook changes.
- Maintain explicit allowlist and suppression policies with expiry/review windows to avoid permanent blind spots.

## Collaboration
- Keep AGENTS.md and README.md updated on every change.
- Keep docs/ARCHITECTURE.md, docs/DEV_GUIDE.md aligned with control-flow and workflow changes.
- Keep docs/FINDINGS.md updated when a new security or correctness issue is identified and fixed.
- Rerun `graphify update .` (or `graphify update . --force`) after code changes to keep graphify-out artifacts in sync.
