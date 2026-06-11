# Roadmap

## Completed
- Added install/build-time git clone behavior diffing across package versions.
- Added `git_clone_allowlist` policy support for install-time clone targets.
- Added integration coverage for install-time git clone scan behavior under `tests/git_clone_scan_tests.rs`.
- Replaced lexicographic version ordering with semantic ordering (semver for npm, PEP 440 for Python), with safe fallback for unparseable versions.
- Pinned the forwarded command to the exact scanned version for explicit unpinned install targets (closes the scan-vs-install version gap).
- Captured IPv6 connection endpoints (not just IPv4) and normalized them to canonical form.
- Hardened trace capture: `strace -s 4096 -v` (no truncation) and `-u` to run the install payload unprivileged so it cannot tamper with its own trace.
- Excluded npm `created`/`modified` bookkeeping keys from the release-burst counter.
- Made host-command forwarding fail closed when the manager binary cannot be spawned.
- Folded policy knobs into a single PolicyConfig struct and scan results into ScanReport.
- Added unit/integration coverage for all of the above (version ordering, IPv4/IPv6 extraction, burst filtering, version pinning, strace hardening, fail-closed forwarding).
- Added watched-process execution detection (all executables captured by default, least-privilege approach) diffed across versions to catch the Shai-Hulud "download a runtime and run a hidden payload" class, with `process_exec_allowlist` config and coverage in tests/bun_exec_scan_tests.rs. `watched_executables` was later removed (always capture all execve).
- Resolved the 8 findings in docs/FINDINGS.md (re-verified accurate, then fixed):
  - Empty/whitespace sandbox traces now fail closed (no more silent clean-pass on strace failure); strace stderr is captured per-probe instead of discarded.
  - Granted `--cap-add SYS_PTRACE` so cross-UID tracing actually works under Docker (surfaced once empty traces stopped passing silently).
  - `domain_allowlist` now uses forward-confirmed reverse DNS (FCrDNS), closing the spoofed-PTR bypass.
  - Balanced-bracket-aware execve argv regex so `]`-containing arguments (PEP 508 extras, bracketed paths) are no longer truncated.
  - Poetry parser excludes all local directory-source packages regardless of `develop`.
  - PEP 508 extras stripped from the canonical name for registry lookups and the pin key, while the forwarded command keeps the full spec (fixes both the PyPI 404/zero-baseline path and the broken version pinning).
  - Forwarded host command exit status is propagated instead of discarded.
- Extended lockfile scanning to bare `uv lock` and bare `poetry lock` (previously forwarded unscanned); both now scan the resolved lockfile and fail closed if it is missing/empty. Routing covered by tests/lock_routing_tests.rs.
- Added `--version`/`-V` as a leading top-level flag (prints crate version, exits 0, works without config/Docker; does not intercept a forwarded command's own flag). Covered by tests/version_flag_tests.rs.
- Filtered sandbox-local IPs (loopback, link-local, private/RFC1918 incl. Docker bridge and Docker Desktop gateway) at trace-extraction time, before the baseline diff, removing a class of harness-nondeterminism false positives; the cloud metadata IP `169.254.169.254` is exempt. Normalized IPv4-mapped IPv6 (`::ffff:1.2.3.4`) to bare IPv4 everywhere so diffs and the ip_allowlist match either form.
- Added `internal_package_exemptions` config: skip first-party/private-index packages (e.g. Nexus) entirely — no registry fetch, no sandbox install, no diff — forwarding them unscanned at the requested version (with a `latest`-pin guard so the forwarded command is not corrupted).
- Added post-install artifact scan: single `find /work -type f` pipeline inventories every installed file; Rust-side `classify_inventory_lines` emits structured findings (`binary`, `suspicious_pth`, `unexpected_runtime`, `large_file`); new signals fail closed. Replaced ad-hoc `.pth`/`bun-*`/`deno-*` shell scanners.
- Added `artifact_allowlist` config: exact `type|path|details` or prefix `type|path` matching to unblock known artifacts (e.g. a team's expected binary).
- Removed `watched_executables` config: all executables are now captured by default (least-privilege). `process_exec_allowlist` is the single escape hatch.
- Added `is_harness_command` filter: excludes sandbox-internal execve calls (`uv pip install`, `npm install`, `pnpm add`, interpreter discovery) from process-execution signatures so version-specific command strings do not cause false positives. Covers all three supported manager types.

## Near Term
- Add richer requirements parsing (environment markers, line continuations). (PEP 508 extras handling is now done.)
- Add end-to-end command-path tests covering pinned forwarding and lockfile-flow verbatim forwarding (e.g. uv sync) with a stub manager.

## Mid Term
- Detect post-install / startup-triggered payloads that fire outside the install window (e.g. PyPI `*-setup.pth` startup execution): exercise the package's import/startup path inside the sandbox and diff that behavior too.
- Make the watched-executable set extensible per-ecosystem and consider an opt-in "watch all unexpected process execution" strict mode.
- Add direct runtime git clone interception path with safe heuristics.
- Improve baseline selection strategy when fewer historical versions exist.
- Add structured logging mode for CI and machine parsing.
- Add dedicated tests for matrix batch execution paths (multi-package, multi-version in one sandbox run).

## Direct Git Clone Runtime Support
- Phase 1: command parser support for direct `git clone` targets (HTTPS/SSH URL forms, optional branch/ref flags).
- Phase 2: runtime interception pipeline for direct git clone commands with fail-closed behavior on parser or trace failures.
- Phase 3: baseline model for direct git clone behavior (known-safe clone signatures and first-seen repo gating).
- Phase 4: expand policy controls for direct runtime clone gating (strict mode, optional pinned-ref requirement, and first-seen-repo policy actions).
- Phase 5: test coverage for direct runtime clone paths (unit + integration + hostile fixture scenarios).

## Hardening
- ✅ **Post-install artifact scan** — in-container shell scan after each probe catches `.pth` files with executable content and unexpected runtime binaries (bun/deno), diffed across versions, fail-closed.
- Improve resilience to strace output variations.
- Improve error taxonomy and actionable user messages.
- Add timeout and retry controls for registry lookups.
- Add microVM sandbox backend (strict mode) beyond Docker and host modes.
- Add a no-execution-first comparison stage (tarball diff, install-hook/static rule checks) before runtime detonation.
- Add provenance and integrity gates (trusted registry policy, digest/signature verification where available).
- Add optional strict egress mediation/proxy mode for runtime scans.
- Implement no-execution-first Phase 1: fetch and unpack target/baseline artifacts without install execution.
- Implement no-execution-first Phase 2: static diff scoring (file tree deltas, install hooks, suspicious payload indicators).
- Implement no-execution-first Phase 3: policy gate to block high-risk packages before runtime sandbox stage.

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
- Keep docs/ARCHITECTURE.md aligned with control-flow changes.
