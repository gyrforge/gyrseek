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
    cargo clippy --all-targets --all-features --locked
    cargo fmt --all --check

# End-to-end tests for npm
[working-directory: 'tests/npm']
test-npm: build
    "{{bin}}" npm install lodash
    "{{bin}}" npm update
    "{{bin}}" npm i

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

