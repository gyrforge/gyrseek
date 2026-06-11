use std::process::{Command, Stdio};

struct ScannerImageConfig {
    image: String,
    prebuilt: bool,
}

/// A single traced probe: `((package, version), raw_strace_output)`.
pub(crate) type ProbeTrace = ((String, String), String);

pub(crate) trait SandboxRunner {
    fn trace_install(&self, manager: &str, package: &str, version: &str) -> Result<String, String>;

    fn trace_install_matrix(
        &self,
        manager: &str,
        probes: &[(String, String)],
    ) -> Result<Vec<ProbeTrace>, String> {
        let mut results = Vec::new();
        for (package, version) in probes {
            let trace = self.trace_install(manager, package, version)?;
            results.push(((package.clone(), version.clone()), trace));
        }
        Ok(results)
    }
}

pub(crate) fn build_runner_from_env() -> Result<Box<dyn SandboxRunner>, String> {
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
        let temp_dir =
            tempfile::tempdir().map_err(|e| format!("failed to create temp dir: {e}"))?;
        let target_path = temp_dir.path().to_string_lossy().to_string();

        let cmd_args = if is_npm_family_manager(manager) {
            let mut args = vec![
                "-f".to_string(),
                "-e".to_string(),
                "trace=network,execve".to_string(),
                manager.to_string(),
                npm_family_install_subcommand(manager).to_string(),
                format!("{}@{}", package, version),
                npm_family_install_dir_flag(manager).to_string(),
                target_path,
            ];
            if manager == "pnpm" {
                args.push("--lockfile=false".to_string());
            } else {
                args.push("--no-save".to_string());
            }
            args
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
    ) -> Result<Vec<ProbeTrace>, String> {
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
    ) -> Result<Vec<ProbeTrace>, String> {
        trace_install_docker_matrix_with_runtime(manager, probes, Some(&self.runtime))
    }
}

fn trace_install_docker_matrix_with_runtime(
    manager: &str,
    probes: &[(String, String)],
    runtime: Option<&str>,
) -> Result<Vec<ProbeTrace>, String> {
    if probes.is_empty() {
        return Ok(Vec::new());
    }

    let image_config = scanner_image_config(manager);

    let out_dir = tempfile::tempdir().map_err(|e| format!("failed to create temp dir: {e}"))?;
    let out_dir_path = out_dir.path().to_string_lossy().to_string();

    let script = build_matrix_script(manager, probes, image_config.prebuilt);
    let args = build_docker_run_args(&image_config.image, &out_dir_path, runtime, &script);

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
        // Prefer the matrix log; if it is missing/unreadable, retry the probe in
        // isolation. Either way, a blank trace means strace produced no data and
        // MUST NOT be treated as a clean zero-connection scan — fail closed.
        let trace = match std::fs::read_to_string(&trace_path) {
            Ok(contents) if !contents.trim().is_empty() => contents,
            _ => trace_install_docker_single_with_runtime(manager, package, version, runtime)?,
        };
        if trace.trim().is_empty() {
            let err_path = out_dir.path().join(format!("gyrseek_err_{}.log", idx));
            let strace_err = std::fs::read_to_string(&err_path).unwrap_or_default();
            return Err(format!(
                "empty trace for '{}@{}': strace produced no output (ptrace likely unavailable in this environment). strace stderr: {}",
                package,
                version,
                strace_err.trim()
            ));
        }
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
    let script = build_single_script(manager, package, version, image_config.prebuilt);
    // No /out bind mount here: the single-probe fallback captures strace output
    // from stderr rather than a log file.
    let args = build_docker_run_args(&image_config.image, "", runtime, &script);

    let output = Command::new("docker")
        .args(&args)
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .output()
        .map_err(|e| format!("failed to execute docker sandbox: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "single-probe docker sandbox failed for '{}@{}': {}",
            package,
            version,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(String::from_utf8_lossy(&output.stderr).to_string())
}

/// Unprivileged in-container user the untrusted install payload runs as. The
/// container itself runs as root so strace can own the trace logs in /out, but
/// `strace -u` drops the *traced* process to this user — which has no write
/// access to the root-owned /out bind mount, so a malicious package can't
/// overwrite or delete its own trace.
const SCANNER_USER: &str = "gyrseek";

fn is_npm_family_manager(manager: &str) -> bool {
    manager == "npm" || manager == "pnpm"
}

fn npm_family_install_subcommand(manager: &str) -> &str {
    if manager == "pnpm" { "add" } else { "install" }
}

fn npm_family_install_dir_flag(manager: &str) -> &str {
    if manager == "pnpm" {
        "--dir"
    } else {
        "--prefix"
    }
}

/// The `pkg@version` (npm) / `pkg==version` (pip/uv) spec passed to the installer.
fn package_spec(manager: &str, package: &str, version: &str) -> String {
    if is_npm_family_manager(manager) {
        format!("{}@{}", package, version)
    } else {
        format!("{}=={}", package, version)
    }
}

/// Shell steps that create the unprivileged scanner user (idempotently, across
/// both Debian `useradd` and BusyBox `adduser`) and hand it ownership of /work.
fn scanner_user_setup_steps() -> Vec<String> {
    vec![
        format!(
            "id -u {u} >/dev/null 2>&1 || useradd -m -d /home/{u} -s /bin/sh {u} >/dev/null 2>&1 || adduser -D -h /home/{u} -s /bin/sh {u} >/dev/null 2>&1 || true",
            u = SCANNER_USER
        ),
        "mkdir -p /work".to_string(),
        format!(
            "chown -R {u} /work >/dev/null 2>&1 || true",
            u = SCANNER_USER
        ),
    ]
}

/// The actual `npm install` / `uv pip install` invocation, with HOME pinned to
/// the scanner-writable /work so the dropped-privilege user has a usable cache.
fn install_invocation(manager: &str, pkg_spec: &str) -> String {
    if manager == "pnpm" {
        format!(
            "env HOME=/work pnpm add {} --dir /work --lockfile=false",
            shell_single_quoted(pkg_spec)
        )
    } else if manager == "npm" {
        format!(
            "env HOME=/work npm install {} --prefix /work --no-save",
            shell_single_quoted(pkg_spec)
        )
    } else {
        format!(
            "env HOME=/work uv pip install {} --target /work --no-cache",
            shell_single_quoted(pkg_spec)
        )
    }
}

/// A single strace-wrapped install. `-s 4096 -v` stop strace truncating argv
/// strings (e.g. long git-clone URLs) and addresses to the 32-byte default;
/// `-u` runs the payload unprivileged for trace integrity. When `out_log` is
/// set the trace is written there, otherwise it goes to stderr.
fn strace_install_command(manager: &str, pkg_spec: &str, out_log: Option<&str>) -> String {
    let mut cmd = format!(
        "strace -f -s 4096 -v -u {u} -e trace=network,execve",
        u = SCANNER_USER
    );
    if let Some(path) = out_log {
        cmd.push_str(&format!(" -o {}", path));
    }
    format!("{} {}", cmd, install_invocation(manager, pkg_spec))
}

/// Shared image-setup steps (install strace/ca-certs and, for Python, uv) used
/// when the scanner image is not prebuilt.
fn image_setup_steps(manager: &str, prebuilt: bool) -> Vec<String> {
    let mut steps = vec!["set -e".to_string()];
    if !prebuilt {
        steps.push("apt-get -o APT::Sandbox::User=root update >/dev/null".to_string());
        steps.push(
            "apt-get -o APT::Sandbox::User=root install -y --no-install-recommends strace ca-certificates >/dev/null"
                .to_string(),
        );
        if manager == "pnpm" {
            steps.push(
                "corepack enable pnpm >/dev/null 2>&1 || npm install -g pnpm >/dev/null"
                    .to_string(),
            );
        } else if manager != "npm" {
            steps.push("python -m pip install --quiet uv >/dev/null".to_string());
        }
    }
    steps
}

/// Builds the full `sh -lc` script for the matrix (multi-probe) run: per-probe
/// strace logs written to /out, payload dropped to the scanner user.
fn build_matrix_script(manager: &str, probes: &[(String, String)], prebuilt: bool) -> String {
    let mut steps = image_setup_steps(manager, prebuilt);
    steps.extend(scanner_user_setup_steps());

    for (idx, (package, version)) in probes.iter().enumerate() {
        let spec = package_spec(manager, package, version);
        let log = format!("/out/gyrseek_trace_{}.log", idx);
        let err = format!("/out/gyrseek_err_{}.log", idx);
        // Drop the install's own stdout, but capture strace's stderr to a per-probe
        // file instead of discarding it with `>/dev/null 2>&1`. `|| true` keeps a
        // single failing install (e.g. a yanked baseline) from aborting sibling
        // probes; a genuine strace-attach failure leaves an empty trace log, which
        // the reader treats as a hard error (fail closed) using the captured stderr.
        steps.push(format!(
            "{} >/dev/null 2>{} || true",
            strace_install_command(manager, &spec, Some(&log)),
            err
        ));
    }

    steps.join("; ")
}

/// Builds the `sh -lc` script for the single-probe fallback (trace to stderr).
fn build_single_script(manager: &str, package: &str, version: &str, prebuilt: bool) -> String {
    let mut steps = image_setup_steps(manager, prebuilt);
    steps.extend(scanner_user_setup_steps());

    let spec = package_spec(manager, package, version);
    steps.push(strace_install_command(manager, &spec, None));

    steps.join("; ")
}

/// Builds the `docker run` argument vector. When `out_dir_path` is non-empty it
/// is bind-mounted at /out (root-owned) to receive trace logs.
fn build_docker_run_args(
    image: &str,
    out_dir_path: &str,
    runtime: Option<&str>,
    script: &str,
) -> Vec<String> {
    let mut args = vec![
        "run".to_string(),
        "--rm".to_string(),
        "--network".to_string(),
        "bridge".to_string(),
        "--security-opt".to_string(),
        "no-new-privileges".to_string(),
        // strace runs as root but drops the traced install to the unprivileged
        // `gyrseek` user (`strace -u`). Attaching to a process of a different UID
        // requires CAP_SYS_PTRACE, which is NOT in Docker's default capability
        // set — without it `PTRACE_SEIZE` fails with EPERM and no trace is ever
        // produced. The capability is scoped to this container's PID namespace,
        // so it cannot trace host processes.
        "--cap-add".to_string(),
        "SYS_PTRACE".to_string(),
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
    ];
    if !out_dir_path.is_empty() {
        args.push("-v".to_string());
        args.push(format!("{}:/out", out_dir_path));
    }
    args.push("--workdir".to_string());
    args.push("/work".to_string());
    if let Some(runtime_name) = runtime {
        args.push("--runtime".to_string());
        args.push(runtime_name.to_string());
    }
    args.push(image.to_string());
    args.push("sh".to_string());
    args.push("-lc".to_string());
    args.push(script.to_string());
    args
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
    let (image_var, prebuilt_var, default_image) = if is_npm_family_manager(manager) {
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

pub(crate) fn list_docker_runtimes() -> Result<Vec<String>, String> {
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
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .map_err(|e| format!("failed to parse docker runtimes JSON: {e}"))?;

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

#[cfg(test)]
mod tests {
    use super::{
        SCANNER_USER, build_docker_run_args, build_matrix_script, build_single_script,
        strace_install_command,
    };

    // --- #4 strace must not truncate argv/addresses ---

    #[test]
    fn strace_command_disables_string_truncation() {
        let cmd = strace_install_command("npm", "left-pad@1.3.0", Some("/out/gyrseek_trace_0.log"));
        // -s 4096 lifts the 32-byte argv string cap; -v expands addresses.
        assert!(cmd.contains("-s 4096"), "missing -s flag: {cmd}");
        assert!(cmd.contains(" -v "), "missing -v flag: {cmd}");
        assert!(cmd.contains("trace=network,execve"));
    }

    #[test]
    fn matrix_and_single_scripts_disable_truncation() {
        let matrix = build_matrix_script(
            "npm",
            &[("left-pad".to_string(), "1.3.0".to_string())],
            true,
        );
        assert!(matrix.contains("-s 4096"));
        assert!(matrix.contains(" -v "));

        let single = build_single_script("pip", "requests", "2.31.0", true);
        assert!(single.contains("-s 4096"));
        assert!(single.contains(" -v "));
    }

    // --- #5 the traced payload runs unprivileged so it can't rewrite its trace ---

    #[test]
    fn strace_drops_payload_to_unprivileged_user() {
        let cmd = strace_install_command("npm", "left-pad@1.3.0", Some("/out/gyrseek_trace_0.log"));
        // strace itself runs as root (owns the log) but -u runs the install as
        // the scanner user, which has no write access to root-owned /out.
        assert!(
            cmd.contains(&format!("-u {}", SCANNER_USER)),
            "missing -u: {cmd}"
        );
        // The log path is owned by strace (root), written before the payload runs.
        assert!(cmd.contains("-o /out/gyrseek_trace_0.log"));
    }

    #[test]
    fn matrix_script_creates_scanner_user_before_install() {
        let script = build_matrix_script(
            "npm",
            &[("left-pad".to_string(), "1.3.0".to_string())],
            true,
        );
        let user_setup = script
            .find(SCANNER_USER)
            .expect("script should reference scanner user");
        let install = script.find("npm install").expect("script should install");
        // User creation must precede the install step.
        assert!(
            user_setup < install,
            "scanner user must be created before install"
        );
        assert!(script.contains("chown -R gyrseek /work"));
    }

    #[test]
    fn pnpm_install_invocation_uses_pnpm_add() {
        let cmd =
            strace_install_command("pnpm", "left-pad@1.3.0", Some("/out/gyrseek_trace_0.log"));
        assert!(cmd.contains("pnpm add 'left-pad@1.3.0' --dir /work --lockfile=false"));
    }

    #[test]
    fn pnpm_non_prebuilt_image_enables_pnpm() {
        let script = build_matrix_script(
            "pnpm",
            &[("left-pad".to_string(), "1.3.0".to_string())],
            false,
        );
        assert!(script.contains("corepack enable pnpm"));
        assert!(script.contains("pnpm add"));
    }

    #[test]
    fn docker_args_keep_out_mount_when_provided_and_omit_when_empty() {
        let with_out = build_docker_run_args("img:latest", "/tmp/out", None, "echo hi");
        assert!(with_out.iter().any(|a| a == "/tmp/out:/out"));
        assert!(with_out.iter().any(|a| a == "no-new-privileges"));

        let without_out = build_docker_run_args("img:latest", "", None, "echo hi");
        assert!(!without_out.iter().any(|a| a.ends_with(":/out")));
    }

    #[test]
    fn docker_args_pass_runtime_when_set() {
        let args = build_docker_run_args("img:latest", "/tmp/out", Some("kata-runtime"), "echo hi");
        let pos = args
            .iter()
            .position(|a| a == "--runtime")
            .expect("runtime flag present");
        assert_eq!(args.get(pos + 1).map(String::as_str), Some("kata-runtime"));
    }

    #[test]
    fn docker_args_grant_sys_ptrace_capability() {
        // strace -u drops the install to an unprivileged user; attaching across
        // UIDs needs CAP_SYS_PTRACE, which Docker does not grant by default.
        // Without this the sandbox can never produce a trace.
        let args = build_docker_run_args("img:latest", "/tmp/out", None, "echo hi");
        let pos = args
            .iter()
            .position(|a| a == "--cap-add")
            .expect("--cap-add flag present");
        assert_eq!(args.get(pos + 1).map(String::as_str), Some("SYS_PTRACE"));
    }

    // --- #4 strace stderr must be captured, not discarded ---

    #[test]
    fn matrix_script_captures_strace_stderr_not_devnull() {
        let script = build_matrix_script(
            "npm",
            &[("left-pad".to_string(), "1.3.0".to_string())],
            true,
        );
        // strace's stderr must land in a per-probe error log so an attach
        // failure is diagnosable, never silently routed to /dev/null.
        assert!(
            script.contains("2>/out/gyrseek_err_0.log"),
            "strace stderr must be captured to a log: {script}"
        );
        // The strace install step specifically must not merge its stderr away.
        let strace_step = script
            .split("; ")
            .find(|s| s.contains("strace -f"))
            .expect("script should contain a strace step");
        assert!(
            !strace_step.contains("2>&1"),
            "strace stderr must not be merged into /dev/null: {strace_step}"
        );
    }
}
