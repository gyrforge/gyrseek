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

# Install release binary locally (macOS)
local-mac: build
    @version=$(awk -F'"' '/^version = / { print $2; exit }' Cargo.toml); \
    version_suffix=""; \
    [ -n "$version" ] && version_suffix="-v$version"; \
    bin_name="gyrseek"; \
    versioned_bin_name="${bin_name}${version_suffix}"; \
    src_bin="target/release/$bin_name"; \
    dest_dir=""; \
    for dir in /opt/homebrew/bin /usr/local/bin; do \
        if [ -d "$dir" ] && [ -w "$dir" ]; then \
            dest_dir="$dir"; \
            break; \
        fi; \
    done; \
    [ -z "$dest_dir" ] && dest_dir="$HOME/.local/bin" && mkdir -p "$dest_dir"; \
    cp "$src_bin" "$dest_dir/$versioned_bin_name" && \
    cp "$src_bin" "$dest_dir/$bin_name" && \
    chmod +x "$dest_dir/$versioned_bin_name" "$dest_dir/$bin_name"; \
    echo "Installed $versioned_bin_name to $dest_dir/$versioned_bin_name"; \
    echo "Updated callable binary at $dest_dir/$bin_name"; \
    stale_found=0; \
    for dir in /opt/homebrew/bin /usr/local/bin "$HOME/.local/bin"; do \
        [ "$dir" = "$dest_dir" ] && continue; \
        if [ -e "$dir/$bin_name" ]; then \
            echo "⚠️  Stale gyrseek found at $dir/$bin_name (shadows $dest_dir/$bin_name)."; \
            echo "    Remove it with: rm -f $dir/$bin_name $dir/${bin_name}-v*"; \
            echo "    (prefix with sudo if it is owned by root)"; \
            stale_found=1; \
        fi; \
    done; \
    [ "$stale_found" -eq 1 ] && echo "    Then run 'hash -r' to clear your shell's cached command path."; true

# Tag current HEAD with version from Cargo.toml (force-update)
tag:
    version=$(grep '^version' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/v\1/'); \
    git tag --delete "$version" 2>/dev/null || true; \
    git push --delete origin "$version" 2>/dev/null || true; \
    git tag "$version" && \
    git push origin "$version"
