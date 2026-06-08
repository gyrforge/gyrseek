# Roadmap

## Completed
- Added install/build-time git clone behavior diffing across package versions.
- Added `git_clone_allowlist` policy support for install-time clone targets.
- Added integration coverage for install-time git clone scan behavior under `tests/git_clone_scan_tests.rs`.

## Near Term
- Add semantic version ordering to replace lexicographic sorting.
- Add richer requirements parsing (environment markers, extras, line continuations).
- Add end-to-end command-path tests for fail-closed enforcement behavior.

## Mid Term
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
- Keep .copilot/Agents.md and README.md updated on every change.
- Keep docs/ARCHITECTURE.md aligned with control-flow changes.
