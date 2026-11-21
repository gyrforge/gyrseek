root := justfile_directory()
bin := root / "target/release/gyrseek"
pip_venv_bin := root / "tests/pip/.venv/bin"

default:
    @just --list

# Release build
build:
    cargo build --release

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

# Run all Docker end-to-end tests
test-docker: test-npm test-pnpm test-pip test-poetry test-uv

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

# Tag current HEAD with version from Cargo.toml (force-update)
tag:
    version=$(grep '^version' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/v\1/'); \
    git tag --delete "$version" 2>/dev/null || true; \
    git push --delete origin "$version" 2>/dev/null || true; \
    git tag "$version" && \
    git push origin "$version"
