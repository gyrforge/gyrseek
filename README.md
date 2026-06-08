# gyrseek

`gyrseek` is a Rust CLI wrapper that intercepts package install/update commands, compares network behavior across package versions, and then forwards the original command if no anomaly is detected.

It currently supports:
- `uv add`
- `uv pip install`
- `pip install`
- `pip3 install`
- `poetry add|update|install`
- `npm install` / `npm i`
- git clone behavior simulation tests

## How It Works

1. Parse package name and optional version from your command.
2. If no version is provided, treat it as `latest`.
3. Fetch version history:
   - PyPI for Python packages
   - npm registry for npm packages
4. Run sandbox installs for:
   - current version
   - previous version (`baseline-1`)
   - two versions back (`baseline-2`)
5. Compare observed network endpoints:
   - New endpoints found: block and exit with error
   - No new endpoints: forward your original command

## Network Behavior Detection

`gyrseek` uses syscall tracing (`strace`) during sandbox installs to observe outbound network connection behavior.

- It captures connection target IPs from trace output.
- It computes the difference between:
   - current version endpoints
   - baseline endpoints from previous versions
- Any endpoint that appears only in the current version is treated as a behavioral anomaly.

This gives you a behavioral signal rather than relying only on package metadata.

## Git Clone Behavior

The repository includes safe simulation tests for git clone-style network anomaly detection in:

- `tests/git_clone_behavior_tests.rs`

Current scope:

- You can test detection logic for clone scenarios through integration tests.
- Runtime command interception for `git clone ...` is not enabled yet in the CLI command parser.

## Prerequisites

- Rust toolchain (`cargo`, `rustc`)
- Network access to package registries
- Package managers you want to wrap (`uv`, `pip`, `poetry`, `npm`)
- `strace` available on your system PATH (used for network syscall tracing)

## Build

```bash
cargo build --release
```

Binary path:

```bash
target/release/gyrseek
```

## Usage

General pattern:

```bash
cargo run -- <manager> <subcommand> <package>
```

or with release binary:

```bash
./target/release/gyrseek <manager> <subcommand> <package>
```

### Python examples

```bash
cargo run -- uv add pytest
cargo run -- uv pip install requests==2.31.0
cargo run -- pip install flask
cargo run -- pip3 install django==5.0.6
cargo run -- poetry update pytest
```

### npm examples

```bash
cargo run -- npm install lodash
cargo run -- npm i lodash@4.17.21
```

## Important Notes

- `gyrseek` forwards your command in the current working directory.
- For tools like `poetry` or `npm`, run it inside a project directory containing the expected project files (`pyproject.toml`, `package.json`, etc.).
- Version selection is currently sorted lexicographically, not semantic-version aware.
- If baseline versions are unavailable, output may show `baseline-1=n/a` and `baseline-2=n/a`.

## Manual Test Runs

Run all tests:

```bash
cargo test
```

Run one integration test file:

```bash
cargo test --test parser_tests
cargo test --test behavior_tests
cargo test --test git_clone_behavior_tests
```

Run one specific test case:

```bash
cargo test parses_npm_install_with_pinned_version
cargo test detects_anomalous_new_connection
```

Show test output (`println!`) while running tests:

```bash
cargo test -- --nocapture
```

## Project Layout

- `src/main.rs`: binary entrypoint
- `src/lib.rs`: core CLI logic
- `tests/parser_tests.rs`: command parsing tests
- `tests/behavior_tests.rs`: behavior anomaly simulation tests
- `tests/git_clone_behavior_tests.rs`: git clone behavior simulation tests
