use std::process::{Command, Stdio};

struct ScannerImageConfig {
    image: String,
    prebuilt: bool,
}

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
        "microvm" => {
            if !docker_available() {
                return Err(
                    "MicroVM sandbox requested but `docker` is not available. Set GYRSEEK_SANDBOX=host only if you accept reduced safety.".to_string(),
                );
            }
            let runtime = std::env::var("GYRSEEK_MICROVM_RUNTIME")
                .unwrap_or_else(|_| "kata-runtime".to_string());
            if !docker_runtime_available(&runtime) {
                return Err(format!(
                    "MicroVM runtime '{}' is not available in Docker. Configure GYRSEEK_MICROVM_RUNTIME to an installed runtime (for example kata-runtime).",
                    runtime
                ));
            }
            Ok(Box::new(MicroVmRunner { runtime }))
        }
        "host" => Ok(Box::new(HostRunner)),
        _ => Err(format!(
            "Unsupported GYRSEEK_SANDBOX mode '{}'. Supported values: docker, microvm, host",
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

struct MicroVmRunner {
    runtime: String,
}

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
        trace_install_docker_matrix_with_runtime(manager, probes, None)
    }

}

impl SandboxRunner for MicroVmRunner {
    fn trace_install(&self, manager: &str, package: &str, version: &str) -> Result<String, String> {
        let probes = vec![(package.to_string(), version.to_string())];
        let mut results = self.trace_install_matrix(manager, &probes)?;
        if results.is_empty() {
            return Err("microvm matrix tracing returned no results".to_string());
        }
        Ok(results.remove(0).1)
    }

    fn trace_install_matrix(
        &self,
        manager: &str,
        probes: &[(String, String)],
    ) -> Result<Vec<((String, String), String)>, String> {
        trace_install_docker_matrix_with_runtime(manager, probes, Some(&self.runtime))
    }
}

fn trace_install_docker_matrix_with_runtime(
    manager: &str,
    probes: &[(String, String)],
    runtime: Option<&str>,
) -> Result<Vec<((String, String), String)>, String> {
    if probes.is_empty() {
        return Ok(Vec::new());
    }

    let image_config = scanner_image_config(manager);

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

    let mut setup_steps = vec!["set -e".to_string()];
    if !image_config.prebuilt {
        setup_steps.push("apt-get -o APT::Sandbox::User=root update >/dev/null".to_string());
        setup_steps.push(
            "apt-get -o APT::Sandbox::User=root install -y --no-install-recommends strace ca-certificates >/dev/null"
                .to_string(),
        );
        if manager != "npm" {
            setup_steps.push("python -m pip install --quiet uv >/dev/null".to_string());
        }
    }
    setup_steps.extend(install_steps);
    let script = setup_steps.join("; ");

    let mut args = vec![
        "run".to_string(),
        "--rm".to_string(),
        "--network".to_string(),
        "bridge".to_string(),
        "--security-opt".to_string(),
        "no-new-privileges".to_string(),
        "--pids-limit".to_string(),
        "256".to_string(),
        "--memory".to_string(),
        "512m".to_string(),
        "--cpus".to_string(),
        "1".to_string(),
        "--user".to_string(),
        "root".to_string(),
        "--tmpfs".to_string(),
        "/tmp:rw,noexec,nosuid,size=128m".to_string(),
        "--tmpfs".to_string(),
        "/work:rw,noexec,nosuid,size=512m".to_string(),
        "-v".to_string(),
        format!("{}:/out", out_dir_path),
        "--workdir".to_string(),
        "/work".to_string(),
    ];
    if let Some(runtime_name) = runtime {
        args.push("--runtime".to_string());
        args.push(runtime_name.to_string());
    }
    args.push(image_config.image.clone());
    args.push("sh".to_string());
    args.push("-lc".to_string());
    args.push(script);

    let output = Command::new("docker")
        .args(&args)
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
        let trace = std::fs::read_to_string(&trace_path).unwrap_or_else(|_| {
            trace_install_docker_single_with_runtime(manager, package, version, runtime)
                .unwrap_or_default()
        });
        results.push(((package.clone(), version.clone()), trace));
    }

    Ok(results)
}

fn trace_install_docker_single_with_runtime(
    manager: &str,
    package: &str,
    version: &str,
    runtime: Option<&str>,
) -> Result<String, String> {
    let image_config = scanner_image_config(manager);

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

    let script = if image_config.prebuilt {
        format!("set -e; {}", install_cmd)
    } else {
        format!(
            "set -e; apt-get -o APT::Sandbox::User=root update >/dev/null; apt-get -o APT::Sandbox::User=root install -y --no-install-recommends strace ca-certificates >/dev/null; {}",
            install_cmd
        )
    };

    let mut args = vec![
        "run".to_string(),
        "--rm".to_string(),
        "--network".to_string(),
        "bridge".to_string(),
        "--security-opt".to_string(),
        "no-new-privileges".to_string(),
        "--pids-limit".to_string(),
        "256".to_string(),
        "--memory".to_string(),
        "512m".to_string(),
        "--cpus".to_string(),
        "1".to_string(),
        "--user".to_string(),
        "root".to_string(),
        "--tmpfs".to_string(),
        "/tmp:rw,noexec,nosuid,size=128m".to_string(),
        "--tmpfs".to_string(),
        "/work:rw,noexec,nosuid,size=512m".to_string(),
        "--workdir".to_string(),
        "/work".to_string(),
    ];
    if let Some(runtime_name) = runtime {
        args.push("--runtime".to_string());
        args.push(runtime_name.to_string());
    }
    args.push(image_config.image);
    args.push("sh".to_string());
    args.push("-lc".to_string());
    args.push(script);

    let output = Command::new("docker")
        .args(&args)
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

fn docker_runtime_available(runtime: &str) -> bool {
    list_docker_runtimes()
        .map(|runtimes| runtimes.iter().any(|r| r == runtime))
        .unwrap_or(false)
}

fn scanner_image_config(manager: &str) -> ScannerImageConfig {
    let (image_var, prebuilt_var, default_image) = if manager == "npm" {
        (
            "GYRSEEK_NPM_SCANNER_IMAGE",
            "GYRSEEK_NPM_SCANNER_PREBUILT",
            "node:22-bookworm-slim",
        )
    } else {
        (
            "GYRSEEK_PY_SCANNER_IMAGE",
            "GYRSEEK_PY_SCANNER_PREBUILT",
            "python:3.12-bookworm",
        )
    };

    let image = std::env::var(image_var).unwrap_or_else(|_| default_image.to_string());

    let global_prebuilt = std::env::var("GYRSEEK_PREBUILT_SCANNER_IMAGES")
        .ok()
        .map(|v| parse_bool_env(&v))
        .unwrap_or(false);

    let prebuilt = std::env::var(prebuilt_var)
        .ok()
        .map(|v| parse_bool_env(&v))
        .unwrap_or(global_prebuilt);

    ScannerImageConfig { image, prebuilt }
}

fn parse_bool_env(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

pub fn list_docker_runtimes() -> Result<Vec<String>, String> {
    let output = Command::new("docker")
        .args(["info", "--format", "{{json .Runtimes}}"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("failed to query docker runtimes: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "docker info failed while querying runtimes: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).map_err(|e| format!("failed to parse docker runtimes JSON: {e}"))?;

    let mut runtimes = Vec::new();
    if let Some(obj) = parsed.as_object() {
        runtimes.extend(obj.keys().cloned());
    }

    runtimes.sort();
    Ok(runtimes)
}

fn shell_single_quoted(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}
