#!/usr/bin/env bash
# Scans real, heavy packages at pinned versions through the real binary and the Docker sandbox with
# the import-time scan on (FIXED #25, #496, #499), and requires the outcome each one is chosen for.
# Every version is compared with its two fixed predecessors, so the result does not move when newer
# releases appear. Each package is scanned on its own so a failure names it.
#
# The packages are the ones that broke the import step while it was built:
#   npm  vite        native `.node` addons (@rolldown/binding-*, lightningcss-*) that `import()` refuses
#        typescript  a platform binary package with no root entry
#        express     dependencies that export only subpaths (dunder-proto, math-intrinsics)
#        axios       the same subpath-only dependencies, a different tree
#        jest        a big tree, and `@jest/globals`, which refuses to load outside jest in every version
#   pip  black       `blackd`, a module that needs an optional extra (aiohttp) in every version
#        boto3       a deep dependency tree (botocore, s3transfer, jmespath, urllib3, ...)
#        pandas      numpy as a dependency, thousands of modules behind the top-level import
#        cryptography, pydantic   native extensions loaded at import (cffi, pydantic-core)
#
# usage: tests/e2e/import.sh <pip|npm> path/to/gyrseek [gyrseek options...]
set -euo pipefail

manager=$1
bin=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
shift 2
work=$(mktemp -d)
cleanup() {
  chmod -R u+w "$work" 2>/dev/null || true
  rm -rf "$work" || true
}
trap cleanup EXIT

# A fresh home: no personal registry settings or caches (Docker keeps its real configuration).
export DOCKER_CONFIG="${DOCKER_CONFIG:-$HOME/.docker}"
export HOME="$work/home"
mkdir -p "$HOME"
unset XDG_CONFIG_HOME XDG_CACHE_HOME XDG_DATA_HOME VIRTUAL_ENV PIP_INDEX_URL PIP_EXTRA_INDEX_URL \
  PIP_CONFIG_FILE UV_INDEX_URL UV_EXTRA_INDEX_URL npm_config_registry NPM_CONFIG_REGISTRY

# `package expect`: `clear` = cleared with nothing said about a module that could not be loaded;
# `warn` = cleared, and the load of every version is reported as failing the same way, which also
# shows that the import step ran (a package that fails to load in every version only warns).
case "$manager" in
  pip)
    cases=(
      "black==26.5.1 warn"
      "boto3==1.43.93 clear"
      "pandas==3.0.5 clear"
      "cryptography==50.0.1 clear"
      "pydantic==2.13.5 clear"
    )
    python3 -m venv "$work/venv"
    export PATH="$work/venv/bin:$PATH"
    ;;
  npm)
    cases=(
      "vite@8.3.0 clear"
      "typescript@7.0.2 clear"
      "express@5.2.1 clear"
      "axios@1.20.0 clear"
      "jest@30.5.1 warn"
    )
    echo '{"name":"t","version":"1.0.0","private":true}' >"$work/package.json"
    ;;
  *) echo "unknown manager: $manager" && exit 2 ;;
esac

failed=0
for entry in "${cases[@]}"; do
  read -r package expect <<<"$entry"
  out=$(cd "$work" && "$bin" "$@" "$manager" install "$package" 2>&1) && code=0 || code=$?
  loaded=ok
  if grep -q "could not be loaded in the sandbox" <<<"$out"; then
    loaded=failed_everywhere
  elif grep -q "could not load some module" <<<"$out"; then
    loaded=candidate_only
  fi
  if [ "$code" -ne 0 ] || ! grep -q "Clear behavioral report" <<<"$out"; then
    echo "FAIL: $package was not cleared (exit $code)"
    grep -E "introduced new|install_failed|import_failed|gyrseek import error" <<<"$out" | cut -c1-400 || true
    echo "$out" | tail -8
    failed=1
  elif [ "$expect" = clear ] && [ "$loaded" != ok ]; then
    echo "FAIL: $package was cleared but a module could not be loaded ($loaded)"
    grep -E "gyrseek import error" <<<"$out" | cut -c1-400 || true
    failed=1
  elif [ "$expect" = warn ] && [ "$loaded" != failed_everywhere ]; then
    echo "FAIL: $package should warn that it cannot be loaded in any version, which also shows the import step ran ($loaded)"
    echo "$out" | tail -8
    failed=1
  else
    echo "ok:   $package cleared (import-time scan: $loaded)"
  fi
done
# the script ends with this test, so its status is the result
[ "$failed" -eq 0 ]
