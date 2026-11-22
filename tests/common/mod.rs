//! Shared by the binary-level tests.
#![allow(dead_code)]

use std::process::Command;

/// `gyrseek` as a child process that cannot see the developer's own package-manager settings
/// (`~/.npmrc`, `pip.conf`, `PIP_INDEX_URL`, ...): gyrseek refuses an install that a setting sends
/// to another registry, so a test that is not about that must not depend on the machine.
pub fn gyrseek() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gyrseek"));
    for (key, _) in std::env::vars() {
        let lower = key.to_ascii_lowercase();
        if lower.starts_with("pip_")
            || lower.starts_with("uv_")
            || lower.starts_with("poetry_")
            || lower.starts_with("npm_config_")
            || key == "VIRTUAL_ENV"
        {
            command.env_remove(key);
        }
    }
    command
        .env("HOME", "/nonexistent-gyrseek-test-home")
        .env("XDG_CONFIG_HOME", "/nonexistent-gyrseek-test-home/.config");
    command
}
