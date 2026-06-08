use std::process::{Command, Stdio};

pub trait SandboxRunner {
    fn trace_install(&self, manager: &str, package: &str, version: &str) -> Result<String, String>;

    fn trace_install_matrix(
        &self,
        manager: &str,
        probes: &[(String, String)],
    ) -> Result<Vec<((String, String), String)>, String> {
        let mut results = Vec::new();
        for (package, version) in probes {
            let trace = self.trace_install(manager, package, version)?;
            results.push(((package.clone(), version.clone()), trace));
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
        let probes = vec![(package.to_string(), version.to_string())];
        let mut results = self.trace_install_matrix(manager, &probes)?;
        if results.is_empty() {
            return Err("docker matrix tracing returned no results".to_string());
        }
        Ok(results.remove(0).1)
    }

    fn trace_install_matrix(
        &self,
        manager: &str,
        probes: &[(String, String)],
    ) -> Result<Vec<((String, String), String)>, String> {
        trace_install_docker_matrix(manager, probes)
    }

}

fn trace_install_docker_matrix(
    manager: &str,
    probes: &[(String, String)],
) -> Result<Vec<((String, String), String)>, String> {
    if probes.is_empty() {
        return Ok(Vec::new());
    }

    let image = if manager == "npm" {
        "node:22-bookworm-slim"
    } else {
        "python:3.12-bookworm"
    };

    let out_dir = tempfile::tempdir().map_err(|e| format!("failed to create temp dir: {e}"))?;
    let out_dir_path = out_dir.path().to_string_lossy().to_string();

    let mut install_steps = Vec::new();
    for (idx, (package, version)) in probes.iter().enumerate() {
        let pkg_spec = if manager == "npm" {
            format!("{}@{}", package, version)
        } else {
            format!("{}=={}", package, version)
        };

        let run_cmd = if manager == "npm" {
            format!(
                "strace -f -e trace=network,execve -o /out/gyrseek_trace_{}.log npm install {} --prefix /work --no-save >/dev/null 2>&1 || true",
                idx,
                shell_single_quoted(&pkg_spec)
            )
        } else {
            format!(
                "strace -f -e trace=network,execve -o /out/gyrseek_trace_{}.log uv pip install {} --target /work --no-cache >/dev/null 2>&1 || true",
                idx,
                shell_single_quoted(&pkg_spec)
            )
        };

        install_steps.push(run_cmd);
    }

    let mut setup_steps = vec![
        "set -e".to_string(),
        "apt-get -o APT::Sandbox::User=root update >/dev/null".to_string(),
        "apt-get -o APT::Sandbox::User=root install -y --no-install-recommends strace ca-certificates >/dev/null".to_string(),
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
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "256",
            "--memory",
            "512m",
            "--cpus",
            "1",
            "--user",
            "root",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=128m",
            "--tmpfs",
            "/work:rw,noexec,nosuid,size=512m",
            "-v",
            &format!("{}:/out", out_dir_path),
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

    if !output.status.success() {
        return Err(format!(
            "docker sandbox command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let mut results = Vec::new();
    for (idx, (package, version)) in probes.iter().enumerate() {
        let trace_path = out_dir.path().join(format!("gyrseek_trace_{}.log", idx));
        let trace = std::fs::read_to_string(&trace_path)
            .unwrap_or_else(|_| trace_install_docker_single(manager, package, version).unwrap_or_default());
        results.push(((package.clone(), version.clone()), trace));
    }

    Ok(results)
}

fn trace_install_docker_single(manager: &str, package: &str, version: &str) -> Result<String, String> {
    let image = if manager == "npm" {
        "node:22-bookworm-slim"
    } else {
        "python:3.12-bookworm"
    };

    let install_cmd = if manager == "npm" {
        format!(
            "strace -f -e trace=network,execve npm install {} --prefix /work --no-save",
            shell_single_quoted(&format!("{}@{}", package, version))
        )
    } else {
        format!(
            "python -m pip install --quiet uv && strace -f -e trace=network,execve uv pip install {} --target /work --no-cache",
            shell_single_quoted(&format!("{}=={}", package, version))
        )
    };

    let script = format!(
        "set -e; apt-get -o APT::Sandbox::User=root update >/dev/null; apt-get -o APT::Sandbox::User=root install -y --no-install-recommends strace ca-certificates >/dev/null; {}",
        install_cmd
    );

    let output = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--network",
            "bridge",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "256",
            "--memory",
            "512m",
            "--cpus",
            "1",
            "--user",
            "root",
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

    Ok(String::from_utf8_lossy(&output.stderr).to_string())
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
