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
test-npm: build
    "{{bin}}" npm install lodash
    "{{bin}}" npm update
    "{{bin}}" npm i

[working-directory: 'tests/npm']
test-live-malicious-npm-package: build
    "{{bin}}" npm install rstreams-shard-util@1.0.1

# End-to-end tests for pnpm
[working-directory: 'tests/pnpm']
test-pnpm: build
    "{{bin}}" pnpm add lodash
    "{{bin}}" pnpm update
    "{{bin}}" pnpm i

# End-to-end tests for pip
[working-directory: 'tests/pip']
test-pip: build
    python3 -m venv .venv
    PATH="{{pip_venv_bin}}:$PATH" "{{bin}}" pip3 install black
    PATH="{{pip_venv_bin}}:$PATH" "{{bin}}" pip3 install -r ./requirements.txt
    PATH="{{pip_venv_bin}}:$PATH" "{{bin}}" pip3 install --upgrade pip

# End-to-end tests for poetry
[working-directory: 'tests/poetry']
test-poetry: build
    "{{bin}}" poetry add black
    "{{bin}}" poetry install --no-root
    "{{bin}}" poetry update
    "{{bin}}" poetry lock

# End-to-end tests for uv
[working-directory: 'tests/uv']
test-uv: build
    "{{bin}}" uv add black
    "{{bin}}" uv pip install -r ./pyproject.toml
    "{{bin}}" uv sync
    "{{bin}}" uv lock

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

# Tag current HEAD with version from Cargo.toml (force-update)
tag:
    version=$(grep '^version' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/v\1/'); \
    git tag --delete "$version" 2>/dev/null || true; \
    git push --delete origin "$version" 2>/dev/null || true; \
    git tag "$version" && \
    git push origin "$version"
