#!/usr/bin/env bash
# Lockfile guards, end to end with the real binary and no Docker: a lockfile entry that does not
# come from the public registry must be refused (exit 1) BEFORE anything is scanned or forwarded.
# A fake package manager first on PATH records whether the command was ever forwarded.
#
# usage: tests/lockfile-guards.sh path/to/gyrseek
# Set GYRSEEK_REQUIRE_NPM=1 (CI does) to fail instead of skipping the npm checks when npm is missing.
set -euo pipefail

bin=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
failures=0

# refused <label> <expected text> <manager> <file> <content> [args...]
refused() {
  local label=$1 expected=$2 manager=$3 file=$4 content=$5
  shift 5
  local dir out code
  dir=$(mktemp -d)
  mkdir "$dir/shim"
  printf '#!/bin/sh\ntouch "%s/forwarded"\n' "$dir" >"$dir/shim/$manager"
  chmod +x "$dir/shim/$manager"
  printf '%s\n' "$content" >"$dir/$file"
  code=0
  out=$(cd "$dir" && PATH="$dir/shim:$PATH" "$bin" "$manager" "$@" 2>&1) || code=$?
  if [ "$code" -ne 1 ] || [ -e "$dir/forwarded" ] || ! grep -qF -- "$expected" <<<"$out"; then
    echo "FAIL: $label (exit $code, forwarded: $([ -e "$dir/forwarded" ] && echo yes || echo no))"
    echo "$out" | head -5
    failures=$((failures + 1))
  else
    echo "ok:   $label"
  fi
  rm -rf "$dir"
}

npm_lock() { # <name> <version> <resolved>
  printf '{"lockfileVersion":3,"packages":{"node_modules/%s":{"version":"%s","resolved":"%s"}}}' "$1" "$2" "$3"
}

refused "npm: other host" "do not come from the npm registry" npm package-lock.json \
  "$(npm_lock left-pad 1.3.0 https://evil.example/left-pad-1.3.0.tgz)" ci
refused "npm: userinfo host trick" "do not come from the npm registry" npm package-lock.json \
  "$(npm_lock left-pad 1.3.0 https://registry.npmjs.org@evil.example/left-pad/-/left-pad-1.3.0.tgz)" install
refused "npm: git source" "do not come from the npm registry" npm package-lock.json \
  "$(npm_lock left-pad 1.3.0 git+ssh://git@github.com/x/y.git#abc)" install
refused "npm: tarball of another package" "a tarball of another package" npm package-lock.json \
  "$(npm_lock left-pad 1.3.0 https://registry.npmjs.org/evil/-/evil-1.0.0.tgz)" ci
refused "npm: lockfile switched off" "lockfile it scanned" npm package-lock.json \
  "$(npm_lock left-pad 1.3.0 https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz)" install --no-package-lock

refused "pnpm: other host" "do not come from the npm registry" pnpm pnpm-lock.yaml \
  "lockfileVersion: '9.0'
packages:
  left-pad@1.3.0:
    resolution: {tarball: 'https://evil.example/left-pad-1.3.0.tgz'}
snapshots: {}" install
refused "pnpm: git source" "do not come from the npm registry" pnpm pnpm-lock.yaml \
  "lockfileVersion: '9.0'
packages:
  left-pad@1.3.0:
    resolution: {type: git, repo: 'https://github.com/x/y.git', commit: abc}
snapshots: {}" install
refused "pnpm: frozen lockfile switched off" "lockfile it scanned" pnpm pnpm-lock.yaml \
  "lockfileVersion: '9.0'
packages:
  left-pad@1.3.0:
    resolution: {integrity: sha512-a}
snapshots: {}" install --no-frozen-lockfile

refused "uv.lock: other index" "do not come from PyPI" uv uv.lock \
  '[[package]]
name = "six"
version = "1.16.0"
source = { registry = "https://nexus.corp.example/simple" }' sync
refused "uv.lock: wheel on another host" "do not come from PyPI" uv uv.lock \
  '[[package]]
name = "six"
version = "1.16.0"
source = { registry = "https://pypi.org/simple" }
wheels = [{ url = "https://evil.example/six-1.16.0-py2.py3-none-any.whl" }]' sync
refused "uv.lock: file of another project" "a file of another package" uv uv.lock \
  '[[package]]
name = "six"
version = "1.16.0"
source = { registry = "https://pypi.org/simple" }
wheels = [{ url = "https://files.pythonhosted.org/packages/evil-1.0.0-py3-none-any.whl" }]' sync
refused "uv.lock: source hidden in a sub-table" "do not come from PyPI" uv uv.lock \
  '[[package]]
name = "six"
version = "1.16.0"
[package.source]
registry = "https://evil.example/simple"' sync
refused "poetry.lock: private index" "do not come from PyPI" poetry poetry.lock \
  '[[package]]
name = "six"
version = "1.16.0"

[package.source]
type = "legacy"
url = "https://nexus.corp.example/simple"' install
refused "poetry.lock: git source" "do not come from PyPI" poetry poetry.lock \
  '[[package]]
name = "six"
version = "1.16.0"

[package.source]
type = "git"
url = "https://github.com/x/y.git"' install
refused "pylock.toml: git source" "do not come from PyPI" uv pylock.toml \
  '[[packages]]
name = "six"
version = "1.16.0"
[packages.vcs]
type = "git"
url = "https://github.com/x/y"' pip sync pylock.toml

# What the frozen forward relies on: npm itself refuses a lockfile that disagrees with package.json
# (and says why), and accepts one that agrees, so a failure for another reason is not mistaken for
# the refusal. A local `file:` dependency keeps both runs offline.
if command -v npm >/dev/null 2>&1; then
  npm_check() { # <lockfile root dependencies> <lockfile extra packages> -> npm's output, npm's exit code
    local dir out code=0
    dir=$(mktemp -d)
    mkdir "$dir/dep"
    echo '{"name":"dep","version":"1.0.0"}' >"$dir/dep/package.json"
    echo '{"name":"t","version":"1.0.0","dependencies":{"dep":"file:./dep"}}' >"$dir/package.json"
    printf '{"name":"t","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"t","version":"1.0.0"%s}%s}}' "$1" "$2" >"$dir/package-lock.json"
    out=$(cd "$dir" && npm ci --dry-run --ignore-scripts --offline 2>&1) || code=$?
    rm -rf "$dir"
    echo "$out"
    return "$code"
  }
  code=0
  out=$(npm_check '' '') || code=$?
  if [ "$code" -ne 0 ] && grep -q "in sync" <<<"$out"; then
    echo "ok:   npm ci refuses a lockfile that is out of sync with package.json"
  else
    echo "FAIL: npm ci did not refuse an out-of-sync lockfile for the expected reason (exit $code)"
    echo "$out" | head -5
    failures=$((failures + 1))
  fi
  code=0
  out=$(npm_check ',"dependencies":{"dep":"file:./dep"}' ',"dep":{"version":"1.0.0"},"node_modules/dep":{"resolved":"dep","link":true}') || code=$?
  if [ "$code" -eq 0 ]; then
    echo "ok:   npm ci accepts a lockfile that is in sync with package.json"
  else
    echo "FAIL: npm ci rejected a lockfile that is in sync (exit $code), so the check above proves nothing"
    echo "$out" | head -5
    failures=$((failures + 1))
  fi
elif [ -n "${GYRSEEK_REQUIRE_NPM:-}" ]; then
  echo "FAIL: npm is not installed but GYRSEEK_REQUIRE_NPM is set, so the npm consistency checks cannot be skipped"
  failures=$((failures + 1))
else
  echo "SKIP: npm is not installed, so the npm consistency checks did not run"
fi

if [ "$failures" -ne 0 ]; then
  echo "$failures lockfile guard check(s) failed"
  exit 1
fi
echo "all lockfile guard checks passed"
