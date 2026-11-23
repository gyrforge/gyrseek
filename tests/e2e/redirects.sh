#!/usr/bin/env bash
# End-to-end checks of the lockfile and redirect guards with the real binary, real package
# managers and the Docker sandbox. For one manager it checks that
#   1. an install that a setting sends to another registry is refused, and the setting really is
#      one the package manager reads (so the check is not guarding a setting nobody uses),
#   2. the same install goes through once the host is in `trusted_index_hosts` (and, where the
#      package manager downloads from the index, really goes through the mirror), and
#   3. a lockfile that has drifted from the manifest is not re-resolved: the install fails and
#      nothing is installed.
#
# usage: tests/e2e/redirects.sh <npm|pnpm|pip|uv|poetry> path/to/gyrseek [gyrseek options...]
set -euo pipefail

manager=$1
bin=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
shift 2
extra=("$@")
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
work=$(mktemp -d)
proxy_pid=
cleanup() {
  [ -n "$proxy_pid" ] && kill "$proxy_pid" 2>/dev/null || true
  # Caches that tools write under the run's home (virtualenv's wheel cache) are read-only, and a
  # failing cleanup must not turn a passing run into a failed one.
  chmod -R u+w "$work" 2>/dev/null || true
  rm -rf "$work" || true
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*"
  [ -n "${OUT:-}" ] && echo "$OUT" | tail -15
  exit 1
}
ok() { echo "ok:   $*"; }

# The package managers must not pick up settings, caches or stores from the machine running the
# checks: a personal ~/.npmrc or pip.conf would change what is refused or trusted, and a warm pnpm or
# npm store would let an install succeed without a single request to the mirror. So the whole run
# gets its own home. Docker keeps its real configuration (contexts, credentials) through
# DOCKER_CONFIG.
export DOCKER_CONFIG="${DOCKER_CONFIG:-$HOME/.docker}"
export HOME="$work/home"
mkdir -p "$HOME"
unset XDG_CONFIG_HOME XDG_CACHE_HOME XDG_DATA_HOME XDG_STATE_HOME VIRTUAL_ENV
for name in $(compgen -e); do
  case "$name" in
    PIP_* | UV_* | POETRY_* | npm_config_* | NPM_CONFIG_* | PNPM_*) unset "$name" ;;
  esac
done
export npm_config_store_dir="$work/pnpm-store"

start_proxy() { # <upstream>
  python3 "$root/tests/e2e/mirror_proxy.py" "$1" "$work/proxy.log" "$work/proxy.port" &
  proxy_pid=$!
  for _ in $(seq 100); do
    [ -s "$work/proxy.port" ] && break
    sleep 0.1
  done
  port=$(cat "$work/proxy.port")
  : >"$work/proxy.log"
}

# gyrseek <dir> <args...>: sets OUT and CODE.
gyrseek() {
  local dir=$1
  shift
  CODE=0
  OUT=$(cd "$dir" && "$bin" ${extra[@]+"${extra[@]}"} "$@" 2>&1) || CODE=$?
}

trust_mirror() { printf 'trusted_index_hosts:\n  - 127.0.0.1\n' >"$1/gyrseek.yaml"; }

expect_refused() { # <what> <must not exist...>
  local what=$1
  shift
  [ "$CODE" -eq 1 ] || fail "$what: expected exit 1, got $CODE"
  grep -q "trusted_index_hosts" <<<"$OUT" || fail "$what: the refusal does not mention trusted_index_hosts"
  grep -q "127.0.0.1" <<<"$OUT" || fail "$what: the refusal does not name the host"
  for path in "$@"; do
    [ ! -e "$path" ] || fail "$what: the package manager ran anyway ($path exists)"
  done
  ok "$what is refused before anything is installed"
}

expect_mirror_used() {
  [ -s "$work/proxy.log" ] || fail "$1: the install did not go through the mirror (no requests)"
  ok "$1 went through the mirror"
}

# A hash in a lockfile or requirements file that the public registry does not publish for that
# version (what a compromised mirror pins, FIXED #447, #452) is refused before anything is
# installed. The file's first hash has its last character changed.
expect_tampered_hash_refused() { # <dir> <file> <what> <nothing installed here> <gyrseek args...>
  local d=$1 file=$2 what=$3 nothing=$4
  shift 4
  rm -rf "$nothing"
  cp "$d/$file" "$d/$file.orig"
  python3 - "$d/$file" <<'PY'
import re, sys
path = sys.argv[1]
text = open(path).read()
m = re.search(r"sha512-[A-Za-z0-9+/]{20}|sha256:[0-9a-f]{20}", text)
assert m, "no hash in the file"
token = m.group(0)
last = "0" if token.startswith("sha256:") else "A"
last = last if token[-1] != last else "1" if last == "0" else "B"
open(path, "w").write(text[: m.start()] + token[:-1] + last + text[m.end() :])
PY
  gyrseek "$d" "$@"
  mv "$d/$file.orig" "$d/$file"
  [ "$CODE" -eq 1 ] || fail "$what: expected exit 1, got $CODE"
  grep -q "does not publish for this version" <<<"$OUT" || fail "$what: not refused for its hash"
  [ ! -e "$nothing" ] || fail "$what: the package manager ran anyway"
  ok "$what is refused before anything is installed"
}

# ------------------------------------------------------------------ npm

npm_checks() {
  start_proxy https://registry.npmjs.org
  local d=$work/npm
  mkdir -p "$d"
  echo '{"name":"t","version":"1.0.0","private":true}' >"$d/package.json"
  (cd "$d" && npm install left-pad@1.3.0 --package-lock-only --ignore-scripts >/dev/null)

  echo "registry=http://127.0.0.1:$port/" >"$d/.npmrc"
  [ "$(cd "$d" && npm config get registry)" = "http://127.0.0.1:$port/" ] ||
    fail "npm does not read the .npmrc that gyrseek is told to refuse"
  mkdir -p "$d/sub"
  [ "$(cd "$d/sub" && npm config get registry)" = "http://127.0.0.1:$port/" ] ||
    fail "npm does not use the project root's .npmrc from a subdirectory"
  ok "npm reads that .npmrc, also from a subdirectory"
  gyrseek "$d/sub" npm install left-pad@1.3.0
  expect_refused "npm install with the project's .npmrc registry (run from a subdirectory)" "$d/sub/node_modules"
  gyrseek "$d" npm ci
  expect_refused "npm ci with a redirecting .npmrc" "$d/node_modules"
  gyrseek "$d" npm ci --registry "http://127.0.0.1:$port/"
  expect_refused "npm ci --registry <url> (the URL is not read as a package)" "$d/node_modules"

  trust_mirror "$d"
  gyrseek "$d" npm install
  [ "$CODE" -eq 0 ] || fail "npm install through the trusted mirror exited $CODE"
  [ -d "$d/node_modules/left-pad" ] || fail "left-pad was not installed"
  ok "npm install through the trusted mirror installs left-pad"
  expect_mirror_used "npm install"
  expect_tampered_hash_refused "$d" package-lock.json "npm ci with a lockfile hash the registry does not publish" "$d/node_modules" npm ci

  rm -rf "$d/node_modules" "$d/.npmrc" "$d/gyrseek.yaml"
  (cd "$d" && npm pkg set dependencies.is-odd=^3.0.1 >/dev/null)
  gyrseek "$d" npm install
  [ "$CODE" -ne 0 ] || fail "npm install with a drifted lockfile succeeded"
  grep -q "in sync" <<<"$OUT" || fail "npm did not refuse the drifted lockfile for the expected reason"
  [ ! -e "$d/node_modules" ] || fail "something was installed from a drifted lockfile"
  ok "a lockfile that drifted from package.json is not re-resolved (npm ci refuses it)"
}

# ------------------------------------------------------------------ pnpm

pnpm_checks() {
  start_proxy https://registry.npmjs.org
  local d=$work/pnpm
  mkdir -p "$d"
  echo '{"name":"t","version":"1.0.0","private":true,"dependencies":{"left-pad":"1.3.0"}}' >"$d/package.json"
  (cd "$d" && pnpm install --lockfile-only --ignore-scripts >/dev/null)

  echo "registry=http://127.0.0.1:$port/" >"$d/.npmrc"
  [ "$(cd "$d" && pnpm config get registry)" = "http://127.0.0.1:$port/" ] ||
    fail "pnpm does not read the .npmrc that gyrseek is told to refuse"
  ok "pnpm reads that .npmrc"
  gyrseek "$d" pnpm install
  expect_refused "pnpm install with a redirecting .npmrc" "$d/node_modules"

  trust_mirror "$d"
  gyrseek "$d" pnpm install
  [ "$CODE" -eq 0 ] || fail "pnpm install through the trusted mirror exited $CODE"
  [ -e "$d/node_modules/left-pad" ] || fail "left-pad was not installed"
  ok "pnpm install through the trusted mirror installs left-pad"
  expect_mirror_used "pnpm install"
  expect_tampered_hash_refused "$d" pnpm-lock.yaml "pnpm install with a lockfile hash the registry does not publish" "$d/node_modules" pnpm install

  rm -rf "$d/node_modules" "$d/.npmrc" "$d/gyrseek.yaml"
  python3 - "$d/package.json" <<'PY'
import json, sys
path = sys.argv[1]
manifest = json.load(open(path))
manifest["dependencies"]["is-odd"] = "^3.0.1"
json.dump(manifest, open(path, "w"))
PY
  gyrseek "$d" pnpm install
  [ "$CODE" -ne 0 ] || fail "pnpm install with a drifted lockfile succeeded"
  [ ! -e "$d/node_modules" ] || fail "something was installed from a drifted lockfile"
  ok "a lockfile that drifted from package.json is not re-resolved (pnpm --frozen-lockfile refuses it)"
}

# ------------------------------------------------------------------ pip

pip_checks() {
  start_proxy https://pypi.org
  local d=$work/pip
  mkdir -p "$d"
  python3 -m venv "$d/venv"
  export PATH="$d/venv/bin:$PATH"
  printf '[global]\nindex-url = http://127.0.0.1:%s/simple\ntrusted-host = 127.0.0.1\n' "$port" >"$d/pip.conf"
  export PIP_CONFIG_FILE="$d/pip.conf"
  local config
  config=$(pip config list)
  grep -q "127.0.0.1:$port" <<<"$config" || fail "pip does not read the pip.conf that gyrseek is told to refuse"
  ok "pip reads that pip.conf"
  gyrseek "$d" pip install six==1.16.0
  expect_refused "pip install with a redirecting pip.conf"
  pip show six >/dev/null 2>&1 && fail "six was installed although the install was refused"
  gyrseek "$d" pip install six==1.16.0 --index-url "http://127.0.0.1:$port/simple"
  expect_refused "pip install --index-url <mirror>"

  trust_mirror "$d"
  gyrseek "$d" pip install six==1.16.0
  [ "$CODE" -eq 0 ] || fail "pip install through the trusted mirror exited $CODE"
  pip show six >/dev/null 2>&1 || fail "six was not installed"
  ok "pip install through the trusted mirror installs six"
  expect_mirror_used "pip install"

  # A requirements file with the real hash goes through, one with another hash does not.
  local sha
  sha=$(python3 - <<'PY'
import json, urllib.request
doc = json.load(urllib.request.urlopen("https://pypi.org/pypi/six/1.16.0/json"))
print(next(f["digests"]["sha256"] for f in doc["urls"] if f["packagetype"] == "bdist_wheel"))
PY
)
  printf 'six==1.16.0 \\\n    --hash=sha256:%s\n' "$sha" >"$d/requirements.txt"
  pip uninstall -y six >/dev/null 2>&1
  gyrseek "$d" pip install -r requirements.txt
  [ "$CODE" -eq 0 ] || fail "pip install -r with the real hash exited $CODE"
  ok "pip install -r with the registry's own hash goes through"
  expect_tampered_hash_refused "$d" requirements.txt "pip install -r with a hash the registry does not publish" "$d/.none" pip install -r requirements.txt
}

# ------------------------------------------------------------------ uv

uv_checks() {
  local d=$work/uv
  mkdir -p "$d"
  cat >"$d/pyproject.toml" <<'TOML'
[project]
name = "t"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = ["six==1.16.0"]
TOML
  (cd "$d" && uv lock >/dev/null 2>&1)
  local mirror="http://127.0.0.1:1/simple" # nothing listens there: the refusal is about the host

  UV_EXTRA_INDEX_URL=$mirror gyrseek "$d" uv sync
  expect_refused "uv sync with UV_EXTRA_INDEX_URL" "$d/.venv"
  printf 'extra-index-url = ["%s"]\n' "$mirror" >"$d/uv.toml"
  gyrseek "$d" uv sync
  expect_refused "uv sync with a redirecting uv.toml" "$d/.venv"
  rm "$d/uv.toml"

  printf 'trusted_index_hosts:\n  - 127.0.0.1\n' >"$d/gyrseek.yaml"
  UV_EXTRA_INDEX_URL=$mirror gyrseek "$d" uv sync
  [ "$CODE" -eq 0 ] || fail "uv sync with a trusted host exited $CODE"
  "$d/.venv/bin/python" -c "import six" || fail "six was not installed"
  ok "uv sync with a trusted host installs six, forwarded as 'uv sync --locked'"
  UV_EXTRA_INDEX_URL=$mirror expect_tampered_hash_refused "$d" uv.lock "uv sync with a lockfile hash the registry does not publish" "$d/.venv" uv sync
  rm -rf "$d/.venv" "$d/gyrseek.yaml"

  gyrseek "$d" uv sync --upgrade
  [ "$CODE" -eq 1 ] || fail "uv sync --upgrade was not refused (exit $CODE)"
  grep -q "uv.lock it scanned" <<<"$OUT" || fail "uv sync --upgrade: unexpected refusal"
  [ ! -e "$d/.venv" ] || fail "uv ran for a refused command"
  ok "uv sync --upgrade is refused before anything is scanned or installed"

  local before
  before=$(cksum <"$d/uv.lock")
  sed -i.bak 's/dependencies = \["six==1.16.0"\]/dependencies = ["six==1.16.0", "attrs==24.2.0"]/' "$d/pyproject.toml"
  rm -f "$d/pyproject.toml.bak"
  gyrseek "$d" uv sync
  [ "$CODE" -ne 0 ] || fail "uv sync with a drifted lockfile succeeded"
  [ "$(cksum <"$d/uv.lock")" = "$before" ] || fail "uv re-locked a drifted lockfile"
  # uv creates the empty environment before it checks the lockfile; nothing may be installed in it.
  if [ -x "$d/.venv/bin/python" ]; then
    "$d/.venv/bin/python" -c "import attrs" 2>/dev/null && fail "the dependency that is only in pyproject.toml was installed"
    "$d/.venv/bin/python" -c "import six" 2>/dev/null && fail "something was installed from a drifted lockfile"
  fi
  grep -q "needs to be updated" <<<"$OUT" || fail "uv did not refuse the drifted lockfile for the expected reason"
  ok "a lockfile that drifted from pyproject.toml is not re-locked (uv sync --locked refuses it)"
}

# `expect_refused` for a mirror at port 1 (nothing listens there; the check is on the host).
expect_refused_host() { expect_refused "$@"; }

# ------------------------------------------------------------------ poetry

poetry_checks() {
  local d=$work/poetry
  mkdir -p "$d"
  cat >"$d/pyproject.toml" <<'TOML'
[tool.poetry]
name = "t"
version = "0.1.0"
description = ""
authors = ["t <t@example.com>"]
package-mode = false

[tool.poetry.dependencies]
python = ">=3.10"
six = "1.16.0"

[build-system]
requires = ["poetry-core"]
build-backend = "poetry.core.masonry.api"
TOML
  (cd "$d" && poetry lock >/dev/null 2>&1)
  local mirror="http://127.0.0.1:1/simple" # nothing listens there: the refusal is about the host

  POETRY_REPOSITORIES_MIRROR_URL=$mirror gyrseek "$d" poetry install --no-root
  expect_refused "poetry install with POETRY_REPOSITORIES_MIRROR_URL" "$d/.venv"
  cat >>"$d/pyproject.toml" <<TOML

[[tool.poetry.source]]
name = "mirror"
url = "$mirror"
priority = "supplemental"
TOML
  gyrseek "$d" poetry install --no-root
  expect_refused "poetry install with a [[tool.poetry.source]] on another host"
  python3 - "$d/pyproject.toml" <<'PY'
import re, sys
path = sys.argv[1]
text = open(path).read()
open(path, "w").write(text[: text.index("\n[[tool.poetry.source]]")] + "\n")
PY

  printf 'trusted_index_hosts:\n  - 127.0.0.1\n' >"$d/gyrseek.yaml"
  POETRY_REPOSITORIES_MIRROR_URL=$mirror gyrseek "$d" poetry install --no-root
  [ "$CODE" -eq 0 ] || fail "poetry install with a trusted host exited $CODE"
  (cd "$d" && poetry run python -c "import six") || fail "six was not installed"
  ok "poetry install with a trusted host installs six"
  POETRY_REPOSITORIES_MIRROR_URL=$mirror expect_tampered_hash_refused "$d" poetry.lock "poetry install with a lockfile hash the registry does not publish" "$d/.none" poetry install --no-root
  rm -f "$d/gyrseek.yaml"

  local before
  before=$(cksum <"$d/poetry.lock")
  sed -i.bak 's/^six = "1.16.0"/six = "1.16.0"\nattrs = "24.2.0"/' "$d/pyproject.toml"
  rm -f "$d/pyproject.toml.bak"
  gyrseek "$d" poetry install --no-root
  [ "$CODE" -ne 0 ] || fail "poetry install with a drifted lockfile succeeded"
  [ "$(cksum <"$d/poetry.lock")" = "$before" ] || fail "poetry re-locked a drifted lockfile"
  ok "a lockfile that drifted from pyproject.toml is not re-locked (poetry install refuses it)"
}

case "$manager" in
  npm) npm_checks ;;
  pnpm) pnpm_checks ;;
  pip) pip_checks ;;
  uv) uv_checks ;;
  poetry) poetry_checks ;;
  *) echo "unknown manager: $manager" && exit 2 ;;
esac
echo "all $manager redirect, lockfile and hash checks passed"
