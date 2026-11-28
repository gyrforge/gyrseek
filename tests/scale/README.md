# Lockfile scale fixture

A frozen 84-package `package-lock.json`, resolved from three declared dependencies
(`express`, `axios`, `lodash`). It exists so one test exercises what users actually run: a
lockfile scan whose probe count spans several containers.

At `baseline_count: 2` it is **252 probes** across **8 containers** (`MAX_PROBES_PER_CONTAINER`
is 32), which is the only end-to-end coverage of multi-container batching, the `probe_chunks`
split and sequential trace streaming against real packages. The next largest lockfile in the
suite is `tests/uv/uv.lock` at 29 entries, and `tests/npm/package-lock.json` has 2.

## Why the versions are committed

A lockfile pins exact versions, and a pinned version's baselines are its fixed predecessors, so
the result does not move when new releases appear. That makes this more deterministic than
`tests/e2e/native.sh` and `import.sh`, which resolve dependencies on the day they run (the
live-registry caveat in OPEN #459). Regenerating the lockfile re-opens that door, so do not
refresh it casually.

## Why `gyrseek.yaml` has exemptions

Eight packages in this tree have fewer published versions than `baseline_count`, so without an
exemption the run fails closed with `insufficient_baselines` — intended behaviour, since too
little history leaves nothing to diff against (see
[Scanning a whole lockfile](../../docs/BEHAVIOR_REFERENCE.md#scanning-a-whole-lockfile)).

**These exemptions were generated mechanically from the lockfile, not vetted.** They exist so the
test reaches the probe phase instead of aborting in the metadata phase. That is acceptable *here*
because of what the exemption does and what this test measures: an exemption suppresses the
anomaly checks for that package, but the package is still installed and probed, and install and
import failures still block. So all 84 packages exercise the batching, the `probe_chunks` split
and the trace streaming that this test exists to cover — only anomaly *blocking* is skipped, for
8 of them.

**Do not copy this file into a real configuration.** `new_package_exemptions` is documented as a
map of package names to a *specifically vetted* version, and nobody has vetted these. In a real
project each entry is a decision you make after looking at the package.

If a refresh adds a package with too little history, add it here with the version it resolved to,
and keep this caveat accurate.

## What the script checks about the fixture

Only that no package has an install script, because the forwarded install runs on the machine
running the test. Integrity hashes are left to gyrseek: `lock_verify` refuses a lockfile entry
that records no hash and names the package, so checking it here would duplicate that less
clearly.
