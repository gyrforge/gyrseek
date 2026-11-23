#!/usr/bin/env bash
# Scans real native-heavy packages, at pinned versions, through the real binary and the Docker
# sandbox, and requires them to be cleared (FIXED #468). These packages vendor shared libraries
# whose file names carry a hash or a version that changes in every release, and so were blocked
# as having "new executables" until the comparison normalised those names. Each version is
# compared with its two fixed predecessors, so the result does not move when newer releases appear.
#
# usage: tests/e2e/native.sh <pip|npm> path/to/gyrseek [gyrseek options...]
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

case "$manager" in
  pip)
    # numpy: numpy.libs/libscipy_openblas64_-<hash>.so; pillow: pillow.libs/libtiff-<hash>.so.6.3.0;
    # psycopg2-binary: psycopg2_binary.libs/libkrb5support-<hash>.so.0.1
    packages=(numpy==2.5.5 pillow==13.0.0 psycopg2-binary==2.9.13)
    python3 -m venv "$work/venv"
    export PATH="$work/venv/bin:$PATH"
    ;;
  npm)
    # sharp: lib/sharp-linux-<arch>-<version>.node with release candidates as baselines;
    # @swc/core: a large file in the content-addressed npm cache
    packages=(sharp@0.35.5 @swc/core@1.16.22)
    echo '{"name":"t","version":"1.0.0","private":true}' >"$work/package.json"
    ;;
  *) echo "unknown manager: $manager" && exit 2 ;;
esac

out=$(cd "$work" && "$bin" "$@" "$manager" install "${packages[@]}" 2>&1) && code=0 || code=$?
if [ "$code" -ne 0 ] || ! grep -q "Clear behavioral report" <<<"$out"; then
  echo "FAIL: ${packages[*]} was not cleared (exit $code)"
  grep -E "introduced new|install_failed" <<<"$out" | cut -c1-400 || true
  echo "$out" | tail -8
  exit 1
fi
echo "ok:   ${packages[*]} cleared (their vendored libraries and platform binaries are not 'new' executables)"
