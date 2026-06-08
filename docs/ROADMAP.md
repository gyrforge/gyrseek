# Roadmap

## Near Term
- Add semantic version ordering to replace lexicographic sorting.
- Add richer requirements parsing (environment markers, extras, line continuations).
- Add end-to-end command-path tests for fail-closed enforcement behavior.

## Mid Term
- Add runtime git clone interception path with safe heuristics.
- Improve baseline selection strategy when fewer historical versions exist.
- Add structured logging mode for CI and machine parsing.

## Hardening
- Improve resilience to strace output variations.
- Improve error taxonomy and actionable user messages.
- Add timeout and retry controls for registry lookups.

## Collaboration
- Keep .copilot/Agents.md and README.md updated on every change.
- Keep docs/ARCHITECTURE.md aligned with control-flow changes.
