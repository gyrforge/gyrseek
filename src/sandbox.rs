use std::process::{Command, Stdio};

pub trait SandboxRunner {
    fn trace_install(&self, manager: &str, package: &str, version: &str) -> Result<String, String>;

    fn trace_install_batch(
        &self,
        manager: &str,
        package: &str,
        versions: &[String],
    ) -> Result<Vec<(String, String)>, String> {
        let mut results = Vec::new();
        for version in versions {
            let trace = self.trace_install(manager, package, version)?;
            results.push((version.clone(), trace));
        }
        Ok(results)
    }
}

pub fn build_runner_from_env() -> Result<Box<dyn SandboxRunner>, String> {
    let mode = std::env::var("GYRSEEK_SANDBOX").unwrap_or_else(|_| "docker".to_string());

    match mode.as_str() {
        "docker" => {
            if !docker_available() {
                return Err(
                    "Docker sandbox requested but `docker` is not available. Set GYRSEEK_SANDBOX=host only if you accept reduced safety.".to_string(),
                );
            }
            Ok(Box::new(DockerRunner))
        }
        "host" => Ok(Box::new(HostRunner)),
        _ => Err(format!(
            "Unsupported GYRSEEK_SANDBOX mode '{}'. Supported values: docker, host",
            mode
        )),
    }
}

struct HostRunner;

impl SandboxRunner for HostRunner {
    fn trace_install(&self, manager: &str, package: &str, version: &str) -> Result<String, String> {
        let temp_dir = tempfile::tempdir().map_err(|e| format!("failed to create temp dir: {e}"))?;
        let target_path = temp_dir.path().to_string_lossy().to_string();

        let cmd_args = if manager == "npm" {
            vec![
                "-f".to_string(),
                "-e".to_string(),
                "trace=network,execve".to_string(),
                "npm".to_string(),
                "install".to_string(),
                format!("{}@{}", package, version),
                "--prefix".to_string(),
                target_path,
                "--no-save".to_string(),
            ]
        } else {
            vec![
                "-f".to_string(),
                "-e".to_string(),
                "trace=network,execve".to_string(),
                "uv".to_string(),
                "pip".to_string(),
                "install".to_string(),
                format!("{}=={}", package, version),
                "--target".to_string(),
                target_path,
                "--no-cache".to_string(),
            ]
        };

        let output = Command::new("strace")
            .args(&cmd_args)
            .stderr(Stdio::piped())
            .stdout(Stdio::null())
            .output()
            .map_err(|e| format!("failed to execute host strace: {e}"))?;

        Ok(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

struct DockerRunner;

impl SandboxRunner for DockerRunner {
    fn trace_install(&self, manager: &str, package: &str, version: &str) -> Result<String, String> {
        let versions = vec![version.to_string()];
        let mut batch = self.trace_install_batch(manager, package, &versions)?;
        Ok(batch.remove(0).1)
    }

    fn trace_install_batch(
        &self,
        manager: &str,
        package: &str,
        versions: &[String],
    ) -> Result<Vec<(String, String)>, String> {
        if versions.is_empty() {
            return Ok(Vec::new());
        }

        let image = if manager == "npm" {
            "node:22-bookworm-slim"
        } else {
            "python:3.12-bookworm"
        };

        let mut install_steps = Vec::new();
        for (idx, version) in versions.iter().enumerate() {
            let pkg_spec = if manager == "npm" {
                format!("{}@{}", package, version)
            } else {
                format!("{}=={}", package, version)
            };
            let run_cmd = if manager == "npm" {
                format!(
                    "strace -f -e trace=network,execve -o /tmp/gyrseek_trace_{}.log npm install {} --prefix /work --no-save >/dev/null 2>&1 || true",
                    idx,
                    shell_single_quoted(&pkg_spec)
                )
            } else {
                format!(
                    "strace -f -e trace=network,execve -o /tmp/gyrseek_trace_{}.log uv pip install {} --target /work --no-cache >/dev/null 2>&1 || true",
                    idx,
                    shell_single_quoted(&pkg_spec)
                )
            };

            let emit_cmd = format!(
                "echo __GYRSEEK_TRACE_BEGIN_{}__ 1>&2; cat /tmp/gyrseek_trace_{}.log 1>&2; echo __GYRSEEK_TRACE_END_{}__ 1>&2",
                idx, idx, idx
            );

            install_steps.push(run_cmd);
            install_steps.push(emit_cmd);
        }

        let mut setup_steps = vec![
            "set -e".to_string(),
            "apt-get update >/dev/null".to_string(),
            "apt-get install -y --no-install-recommends strace ca-certificates >/dev/null".to_string(),
        ];
        if manager != "npm" {
            setup_steps.push("python -m pip install --quiet uv >/dev/null".to_string());
        }
        setup_steps.extend(install_steps);

        let script = setup_steps.join("; ");

        let output = Command::new("docker")
            .args([
                "run",
                "--rm",
                "--network",
                "bridge",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "256",
                "--memory",
                "512m",
                "--cpus",
                "1",
                "--read-only",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=128m",
                "--tmpfs",
                "/work:rw,noexec,nosuid,size=512m",
                "--workdir",
                "/work",
                image,
                "sh",
                "-lc",
                &script,
            ])
            .stderr(Stdio::piped())
            .stdout(Stdio::null())
            .output()
            .map_err(|e| format!("failed to execute docker sandbox: {e}"))?;

        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let mut results = Vec::new();

        for (idx, version) in versions.iter().enumerate() {
            let begin = format!("__GYRSEEK_TRACE_BEGIN_{}__", idx);
            let end = format!("__GYRSEEK_TRACE_END_{}__", idx);
            let start_pos = stderr
                .find(&begin)
                .ok_or_else(|| format!("missing trace begin marker for version '{}'", version))?;
            let trace_start = start_pos + begin.len();
            let rel_end = stderr[trace_start..]
                .find(&end)
                .ok_or_else(|| format!("missing trace end marker for version '{}'", version))?;
            let trace_end = trace_start + rel_end;

            let trace = stderr[trace_start..trace_end].trim().to_string();
            results.push((version.clone(), trace));
        }

        Ok(results)
    }
}

fn docker_available() -> bool {
    Command::new("docker")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn shell_single_quoted(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}
