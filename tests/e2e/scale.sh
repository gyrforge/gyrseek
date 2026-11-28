#!/usr/bin/env bash
# Scans the frozen 84-package lockfile in tests/scale: 252 probes over 8 containers at
# baseline_count=2. The only end-to-end exercise of multi-container batching, the probe_chunks
# split and sequential trace streaming against real packages.
#
# It also reports where the time goes. The metadata phase (one registry fetch per package,
# sequential) and the probe phase (containers, also sequential) have very different costs, and
# a local run suggested the probe phase was implausibly cheap. Printing both means a CI run
# settles that with real numbers instead of inference.
set -euo pipefail

bin=${GYRSEEK_BIN:-target/release/gyrseek}
[ -x "$bin" ] || { echo "no gyrseek binary at $bin (run: just build)" >&2; exit 1; }
bin=$(cd "$(dirname "$bin")" && pwd)/$(basename "$bin")

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp tests/scale/package.json tests/scale/package-lock.json tests/scale/gyrseek.yaml "$work/"

packages=$(python3 -c "
import json,sys
d=json.load(open('$work/package-lock.json'))
print(len([k for k in d.get('packages',{}) if k]))")
probes=$((packages * 3))
echo "fixture: $packages packages -> $probes probes -> $(( (probes + 31) / 32 )) containers"

# The forwarded install runs on this machine, as this user, once the scan clears (the README says
# so), so the fixture must stay script-free: a refresh that introduces an install script should
# fail here rather than surprise a CI runner. Integrity hashes are deliberately NOT checked here
# — gyrseek refuses a lockfile entry that records no hash itself (lock_verify), with a message
# that names the package, so a second check would only duplicate it less clearly.
python3 - "$work/package-lock.json" <<'PY'
import json, sys
pk = json.load(open(sys.argv[1])).get("packages", {})
scripted = [k for k, v in pk.items() if k and v.get("hasInstallScript")]
if scripted:
    sys.exit("FAIL: fixture packages have install scripts: %s" % scripted)
PY

log=$work/scan.log
start=$SECONDS
set +e
( cd "$work" && "$bin" npm ci --ignore-scripts ) >"$log" 2>&1
status=$?
set -e
elapsed=$((SECONDS - start))

# The metadata phase is one "Comparing versions" line per package; the probe phase is whatever
# is left before the forward. `Checks completed in Ns` covers both.
fetched=$(grep -c "Fetching version matrix" "$log" || true)
checks=$(grep -oE "Checks completed in [0-9.]+s" "$log" | tail -1 || true)
echo "elapsed: ${elapsed}s | metadata fetches: $fetched | $checks"

if [ "$status" -ne 0 ]; then
  echo "FAIL: the scan did not complete (exit $status)" >&2
  tail -25 "$log" >&2
  exit 1
fi
if ! grep -q "Clear behavioral report" "$log"; then
  echo "FAIL: the scan completed but did not clear" >&2
  tail -25 "$log" >&2
  exit 1
fi
if [ "$fetched" -lt $((packages - 10)) ]; then
  echo "FAIL: only $fetched of $packages packages were scanned" >&2
  exit 1
fi
# A probe that cannot be traced blocks its package; none of these should.
for bad in "insufficient_baselines" "trace limit" "GYRSEEK-LIMIT" "left no trace file"; do
  if grep -qi "$bad" "$log"; then
    echo "FAIL: '$bad' in the scan output" >&2
    grep -i -m3 "$bad" "$log" >&2
    exit 1
  fi
done

echo "ok:   $packages packages cleared in ${elapsed}s ($probes probes)"
