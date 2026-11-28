root := justfile_directory()
bin := root / "target/release/gyrseek"
pip_venv_bin := root / "tests/pip/.venv/bin"

default:
    @just --list

# Release build
build:
    cargo build --release

# Scan the frozen 84-package lockfile in tests/scale (252 probes, 8 containers; needs Docker and the network)
test-scale: build
    tests/e2e/scale.sh

# Build the Debian package for this host (Linux only; needs `cargo install cargo-deb`)
deb:
    cargo deb

# Auto format code
fmt:
    cargo fmt

# Run cargo tests
test:
    cargo test --all-features --locked

# Test for linting errors
lint:
    cargo check --all-targets --all-features --locked
    cargo clippy --all-targets --all-features --locked
    cargo fmt --all --check

# Lockfile guards with the real binary and real npm, no Docker: foreign-source lockfiles are refused before anything is forwarded
test-lockfile-guards:
    cargo build --locked
    tests/lockfile-guards.sh "{{root}}/target/debug/gyrseek"

# End-to-end tests for npm
[working-directory: 'tests/npm']
test-npm +args='': build
    "{{bin}}" {{args}} npm install lodash
    "{{bin}}" {{args}} npm ci
    "{{bin}}" {{args}} npm i

# End-to-end tests for pnpm
[working-directory: 'tests/pnpm']
test-pnpm +args='': build
    "{{bin}}" {{args}} pnpm add lodash
    "{{bin}}" {{args}} pnpm install --frozen-lockfile
    "{{bin}}" {{args}} pnpm i

# End-to-end tests for pip
[working-directory: 'tests/pip']
test-pip +args='': build
    python3 -m venv .venv
    PATH="{{pip_venv_bin}}:$PATH" "{{bin}}" {{args}} pip3 install black
    PATH="{{pip_venv_bin}}:$PATH" "{{bin}}" {{args}} pip3 install -r ./requirements.txt
    PATH="{{pip_venv_bin}}:$PATH" "{{bin}}" {{args}} pip3 install --upgrade pip

# End-to-end tests for poetry
[working-directory: 'tests/poetry']
test-poetry +args='': build
    "{{bin}}" {{args}} poetry add black
    "{{bin}}" {{args}} poetry install --no-root
    "{{bin}}" {{args}} poetry update
    "{{bin}}" {{args}} poetry lock

# End-to-end tests for uv
[working-directory: 'tests/uv']
test-uv +args='': build
    "{{bin}}" {{args}} uv add black
    "{{bin}}" {{args}} uv pip install -r ./requirements.txt
    "{{bin}}" {{args}} uv sync
    "{{bin}}" {{args}} uv lock

# End-to-end redirect and lockfile guards for one manager (real package manager, real Docker sandbox, local stand-in mirror)
[private]
test-redirects manager +args='': build
    tests/e2e/redirects.sh {{manager}} "{{bin}}" {{args}}

test-redirects-npm +args='': (test-redirects "npm" args)

test-redirects-pnpm +args='': (test-redirects "pnpm" args)

test-redirects-pip +args='': (test-redirects "pip" args)

test-redirects-poetry +args='': (test-redirects "poetry" args)

test-redirects-uv +args='': (test-redirects "uv" args)

# A payload cannot rewrite its own or an earlier probe's trace (needs Docker and the network)
test-trace-integrity:
    cargo test --lib --locked -- --ignored a_payload_cannot_tamper a_probe_that_floods the_artifact_inventory_reports a_scanner_image_without files_dropped_outside_work an_install_can_run_a_binary_from_work a_python_package_is_loaded a_node_package_is_loaded a_pnpm_package_is_loaded a_package_that_cannot_be_loaded an_import_that_never_returns a_process_started_when_the_package_loads a_module_the_package_leaves a_package_under_a_namespace node_reports_an_esm a_python_dependency_the_package python_tells_a_missing_name node_decides_the_entry a_node_native_addon a_node_package_with_no_root_entry a_node_dependency_the_package

# Real native-heavy packages at pinned versions must scan clear (vendored libraries renamed in every release; needs Docker and the network)
test-native-pip +args='': build
    tests/e2e/native.sh pip "{{bin}}" {{args}}

test-native-npm +args='': build
    tests/e2e/native.sh npm "{{bin}}" {{args}}

# Heavy real packages at pinned versions with the import-time scan on: native addons, subpath-only dependencies, deep trees, a module that needs an optional extra (needs Docker and the network)
test-import-pip +args='': build
    tests/e2e/import.sh pip "{{bin}}" {{args}}

test-import-npm +args='': build
    tests/e2e/import.sh npm "{{bin}}" {{args}}

# Run all Docker end-to-end tests
test-docker: test-npm test-pnpm test-pip test-poetry test-uv test-redirects-npm test-redirects-pnpm test-redirects-pip test-redirects-poetry test-redirects-uv test-native-pip test-native-npm test-import-pip test-import-npm

# Install to local machine
install:
    cargo install --path . --locked

# Uninstall from local machine
uninstall:
    cargo uninstall gyrseek

# Build Docker image for Python scanning
docker-build-python:
    docker build -f docker/Dockerfile.python -t gyrseek-python-scanner:latest .

# Build Docker image for npm/pnpm scanning
docker-build-npm:
    docker build -f docker/Dockerfile.npm -t gyrseek-npm-scanner:latest .

# Lint the Dockerfiles with the hadolint version CI runs (hadolint-action v3.1.0 uses v2.12.0)
lint-dockerfiles:
    #!/usr/bin/env sh
    for f in docker/Dockerfile.*; do docker run --rm -i hadolint/hadolint:v2.12.0-debian hadolint - < "$f" || exit 1; done

# Compare the digest-pinned sandbox base images in src/runtime_image.rs with the registry (needs Docker)
image-pins:
    #!/usr/bin/env sh
    grep -oE '(python|node):[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}' src/runtime_image.rs | while IFS=@ read -r ref pinned; do
        now=$(docker buildx imagetools inspect "$ref" | awk '/^Digest:/{print $2}')
        if [ "$now" = "$pinned" ]; then echo "ok     $ref"; else echo "DRIFT  $ref  pinned=$pinned  now=$now"; fi
    done

# Tag HEAD with the version from Cargo.toml and push it, which starts the release workflow. HEAD must be origin/main and its CI run must pass first (waited for with gh). Never replaces a tag that origin already has: raise the version instead.
tag:
    version=$(grep '^version' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/v\1/'); \
    git fetch --quiet origin main || { echo "cannot fetch origin/main, so nothing was tagged" >&2; exit 1; }; \
    if [ "$(git rev-parse HEAD)" != "$(git rev-parse origin/main)" ]; then \
      echo "HEAD is not origin/main: check out main and pull first, so the tag is on the commit that passed CI" >&2; exit 1; \
    fi; \
    sha=$(git rev-parse HEAD); \
    id=$(gh run list --workflow ci.yml --commit "$sha" --limit 1 --json databaseId --jq '.[0].databaseId // empty') || { echo "cannot read CI runs with gh, so nothing was tagged" >&2; exit 1; }; \
    [ -n "$id" ] || { echo "no CI run found for $sha yet: wait for it to start, then run again" >&2; exit 1; }; \
    echo "waiting for CI run $id on $sha"; \
    gh run watch "$id" --exit-status >/dev/null || { echo "CI did not pass on $sha, so nothing was tagged" >&2; exit 1; }; \
    rc=0; git ls-remote --exit-code --tags origin "refs/tags/$version" >/dev/null 2>&1 || rc=$?; \
    if [ "$rc" -eq 0 ]; then \
      echo "$version is already on origin. A released version is never replaced: raise the version in Cargo.toml." >&2; exit 1; \
    elif [ "$rc" -ne 2 ]; then \
      echo "cannot read the tags of origin (git ls-remote exited $rc), so nothing was tagged" >&2; exit 1; \
    fi; \
    if git rev-parse -q --verify "refs/tags/$version" >/dev/null; then \
      if [ "$(git rev-parse "$version^{commit}")" != "$(git rev-parse HEAD)" ]; then \
        echo "the local tag $version points at another commit than HEAD: delete it (git tag -d $version) or check out that commit" >&2; exit 1; \
      fi; \
      echo "the local tag $version already points at HEAD (an earlier push did not finish); pushing it"; \
    else \
      git tag "$version"; \
    fi; \
    git push origin "$version"
