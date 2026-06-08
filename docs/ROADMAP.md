# Roadmap

## Near Term
- Add semantic version ordering to replace lexicographic sorting.
- Add richer requirements parsing (environment markers, extras, line continuations).
- Add end-to-end command-path tests for fail-closed enforcement behavior.

## Mid Term
- Add runtime git clone interception path with safe heuristics.
- Improve baseline selection strategy when fewer historical versions exist.
- Add structured logging mode for CI and machine parsing.
- Add dedicated tests for matrix batch execution paths (multi-package, multi-version in one sandbox run).

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

## Collaboration
- Keep .copilot/Agents.md and README.md updated on every change.
- Keep docs/ARCHITECTURE.md aligned with control-flow changes.
