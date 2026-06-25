use std::process::{Command, Stdio};
use std::sync::OnceLock;
use tempfile::TempDir;

const EMBEDDED_SECCOMP_PROFILE_NAME: &str = "seccomp.gyrseek-tracing.json";
const EMBEDDED_SECCOMP_PROFILE_JSON: &str = r#"{
    "defaultAction": "SCMP_ACT_ALLOW",
    "defaultErrnoRet": 1,
    "archMap": [
        {
            "architecture": "SCMP_ARCH_X86_64",
            "subArchitectures": [
                "SCMP_ARCH_X86",
                "SCMP_ARCH_X32"
            ]
        },
        {
            "architecture": "SCMP_ARCH_AARCH64",
            "subArchitectures": [
                "SCMP_ARCH_ARM"
            ]
        },
        {
            "architecture": "SCMP_ARCH_MIPS64",
            "subArchitectures": [
                "SCMP_ARCH_MIPS",
                "SCMP_ARCH_MIPS64N32"
            ]
        },
        {
            "architecture": "SCMP_ARCH_MIPS64N32",
            "subArchitectures": [
                "SCMP_ARCH_MIPS",
                "SCMP_ARCH_MIPS64"
            ]
        },
        {
            "architecture": "SCMP_ARCH_MIPSEL64",
            "subArchitectures": [
                "SCMP_ARCH_MIPSEL",
                "SCMP_ARCH_MIPSEL64N32"
            ]
        },
        {
            "architecture": "SCMP_ARCH_MIPSEL64N32",
            "subArchitectures": [
                "SCMP_ARCH_MIPSEL",
                "SCMP_ARCH_MIPSEL64"
            ]
        },
        {
            "architecture": "SCMP_ARCH_S390X",
            "subArchitectures": [
                "SCMP_ARCH_S390"
            ]
        },
        {
            "architecture": "SCMP_ARCH_RISCV64",
            "subArchitectures": []
        }
    ],
    "syscalls": [
        {
            "names": [
                "accept",
                "accept4",
                "bpf",
                "delete_module",
                "finit_module",
                "fsconfig",
                "fsmount",
                "fspick",
                "fsopen",
                "init_module",
                "io_uring_enter",
                "io_uring_register",
                "io_uring_setup",
                "kexec_file_load",
                "kexec_load",
                "listen",
                "mount",
                "move_mount",
                "name_to_handle_at",
                "nfsservctl",
                "open_by_handle_at",
                "open_tree",
                "perf_event_open",
                "pivot_root",
                "process_vm_writev",
                "umount2",
                "userfaultfd"
            ],
            "action": "SCMP_ACT_ERRNO",
            "errnoRet": 1
        }
    ]
}"#;

const EMBEDDED_APPARMOR_PROFILE_NAME: &str = "gyrseek-tracing";
/// Embedded AppArmor profile for Docker sandbox containers. Allows outbound
/// networking (package registries), ptrace (strace), and file access for
/// install probes (apt, uv, npm, pnpm). Loaded into the kernel via
/// apparmor_parser at runtime when GYRSEEK_DOCKER_APPARMOR_PROFILE=true.
/// Falls back to Docker's default profile if apparmor_parser is unavailable.
const EMBEDDED_APPARMOR_PROFILE_TEXT: &str = r#"#include <tunables/global>

profile gyrseek-tracing flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/consoles>

  capability chown,
  capability sys_ptrace,
  capability dac_override,
  capability dac_read_search,
  capability fowner,
  capability fsetid,
  capability kill,
  capability setgid,
  capability setuid,
  capability sys_chroot,
  capability mknod,
  capability setpcap,
  capability sys_resource,

  ptrace (trace,read,tracedby,readby),
  signal (send,receive),

  network inet tcp,
  network inet udp,
  network inet6 tcp,
  network inet6 udp,

  / r,
  /etc/** r,
  /usr/** rix,
  /bin/** rix,
  /sbin/** rix,
  /lib/** rix,
  /opt/** rix,
  /work/ rw,
  /work/** rwixk,
  /out/ rw,
  /out/** rwk,
  /tmp/ rw,
  /tmp/** rwixk,
  /var/** r,
  /root/ r,
  /root/** r,
  /home/ rw,
  /home/** rwixk,
  /proc/ r,
  /proc/** r,
  /dev/ rw,
  /dev/** rw,
  /sys/ r,
  /sys/** r,
  /run/ r,
  /run/** rw,
}"#;

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
        probes
            .iter()
            .map(|(package, version)| {
                let trace = self.trace_install(manager, package, version)?;
                Ok(((package.clone(), version.clone()), trace))
            })
            .collect()
    }
}

pub(crate) fn build_runner_from_env(
    danger_disable_seccomp: bool,
) -> Result<Box<dyn SandboxRunner>, String> {
    let mode = std::env::var("GYRSEEK_SANDBOX").unwrap_or_else(|_| "docker".to_string());

    let runner: Result<Box<dyn SandboxRunner>, String> = match mode.as_str() {
        "docker" => {
            if !docker_available() {
                return Err("docker is not available but GYRSEEK_SANDBOX=docker".to_string());
            }
            Ok(Box::new(DockerRunner {
                danger_disable_seccomp,
            }))
        }
        "microvm" => {
            if !docker_available() {
                return Err("docker is not available but GYRSEEK_SANDBOX=microvm".to_string());
            }
            let runtime = std::env::var("GYRSEEK_MICROVM_RUNTIME")
                .unwrap_or_else(|_| "kata-runtime".to_string());
            if !docker_runtime_available(&runtime) {
                return Err(format!(
                    "MicroVM runtime '{}' is not available in Docker. Configure GYRSEEK_MICROVM_RUNTIME to an installed runtime (for example kata-runtime).",
                    runtime
                ));
            }
            Ok(Box::new(MicroVmRunner {
                runtime,
                danger_disable_seccomp,
            }))
        }
        "host" => {
            eprintln!(
                "⚠️ [gyrseek] CRITICAL WARNING: Running in HOST mode (GYRSEEK_SANDBOX=host). Container isolation is completely INACTIVE. Packages will execute directly on your machine!"
            );
            if danger_disable_seccomp {
                eprintln!(
                    "⚠️ [gyrseek] Warning: --danger-disable-seccomp has no effect in host mode."
                );
            }
            Ok(Box::new(HostRunner))
        }
        _ => Err(format!(
            "Unsupported GYRSEEK_SANDBOX mode '{}'. Supported values: docker, microvm, host",
            mode
        )),
    };

    if runner.is_ok() && mode != "host" {
        announce_seccomp_status(danger_disable_seccomp);
        announce_apparmor_status();
    }

    runner
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
                "trace=network,execve,open,openat,openat2,openat64,link,linkat,symlink,symlinkat,clone,clone3,fork,vfork,dup,dup2,dup3,fcntl".to_string(),
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
                "trace=network,execve,open,openat,openat2,openat64,link,linkat,symlink,symlinkat,clone,clone3,fork,vfork,dup,dup2,dup3,fcntl".to_string(),
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

struct DockerRunner {
    danger_disable_seccomp: bool,
}

struct MicroVmRunner {
    runtime: String,
    danger_disable_seccomp: bool,
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
        trace_install_docker_matrix_with_runtime(manager, probes, None, self.danger_disable_seccomp)
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
        trace_install_docker_matrix_with_runtime(
            manager,
            probes,
            Some(&self.runtime),
            self.danger_disable_seccomp,
        )
    }
}

fn trace_install_docker_matrix_with_runtime(
    manager: &str,
    probes: &[(String, String)],
    runtime: Option<&str>,
    danger_disable_seccomp: bool,
) -> Result<Vec<ProbeTrace>, String> {
    if probes.is_empty() {
        return Ok(Vec::new());
    }

    let image_config = scanner_image_config(manager);

    let out_dir = tempfile::tempdir().map_err(|e| format!("failed to create temp dir: {e}"))?;
    let out_dir_path = out_dir.path().to_string_lossy().to_string();

    let script = build_matrix_script(manager, probes, image_config.prebuilt);
    let args = build_docker_run_args(
        &image_config.image,
        &out_dir_path,
        runtime,
        &script,
        danger_disable_seccomp,
    )?;

    let output = Command::new("docker")
        .args(&args)
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()
        .map_err(|e| format!("failed to execute docker sandbox: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut tail_lines: Vec<_> = stdout.lines().rev().take(20).collect();
        tail_lines.reverse();
        let tail = tail_lines.join("\n");
        return Err(format!(
            "docker sandbox command failed (exit code: {}).\nstderr:\n{}\nstdout (last 20 lines):\n{}",
            output.status.code().unwrap_or(-1),
            stderr,
            tail,
        ));
    }

    let mut results = Vec::new();
    for (idx, (package, version)) in probes.iter().enumerate() {
        let trace_path = out_dir.path().join(format!("gyrseek_trace_{}.log", idx));
        // Prefer the matrix log; if it is missing/unreadable, retry the probe in
        // isolation. Either way, a blank trace means strace produced no data and
        // MUST NOT be treated as a clean zero-connection scan — fail closed.
        let mut trace = match std::fs::read_to_string(&trace_path) {
            Ok(contents) if !contents.trim().is_empty() => contents,
            _ => trace_install_docker_single_with_runtime(
                manager,
                package,
                version,
                runtime,
                danger_disable_seccomp,
            )?,
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
        // Append post-install artifact scan findings to the trace, separated by
        // a marker so the scanner can split them during signal extraction.
        let artifact_path = out_dir
            .path()
            .join(format!("gyrseek_artifacts_{}.log", idx));
        if let Ok(artifact_content) = std::fs::read_to_string(&artifact_path) {
            let trimmed = artifact_content.trim();
            if !trimmed.is_empty() {
                trace.push_str("\n=== gyrseek_artifacts ===\n");
                trace.push_str(trimmed);
            }
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
    danger_disable_seccomp: bool,
) -> Result<String, String> {
    let image_config = scanner_image_config(manager);
    let script = build_single_script(manager, package, version, image_config.prebuilt);
    // No /out bind mount here: the single-probe fallback captures strace output
    // from stderr rather than a log file.
    let args = build_docker_run_args(
        &image_config.image,
        "",
        runtime,
        &script,
        danger_disable_seccomp,
    )?;

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
/// `-xx` forces all bytes to hex-escape format (`\xNN`) for deterministic DNS
/// payload parsing; `-u` runs the payload unprivileged for trace integrity.
/// When `out_log` is set the trace is written there, otherwise it goes to
/// stderr.
fn strace_install_command(manager: &str, pkg_spec: &str, out_log: Option<&str>) -> String {
    let mut cmd = format!(
        "strace -f -s 4096 -v -xx -u {u} -e trace=network,execve,open,openat,?openat2,?openat64,link,linkat,symlink,symlinkat,clone,?clone3,fork,vfork,dup,dup2,?dup3,fcntl",
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
        steps.push(
            "env DEBIAN_FRONTEND=noninteractive apt-get -o APT::Sandbox::User=root update >&2"
                .to_string(),
        );
        steps.push(
            "env DEBIAN_FRONTEND=noninteractive apt-get -o APT::Sandbox::User=root install -y --no-install-recommends strace ca-certificates >&2"
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

/// Shell commands that scan the installed file tree for class-specific IoCs:
/// `.pth` files with executable content (Hades/Miasma pattern), unexpected
/// runtime binaries (bun/deno), and other suspicious artifacts. The scan is
/// per-probe so faulty findings are attributed to a specific package-version.
fn build_artifact_scan_steps(idx: usize) -> Vec<String> {
    let out = format!("/out/gyrseek_artifacts_{}.log", idx);
    vec![
        // Initialize/clear the artifact log for this probe.
        format!("true > {}", out),
        // Single inventory pipeline: record path, size (bytes), file type, and
        // first 300 bytes of content for every installed file. Null byte (\0)
        // is used as the field delimiter because it cannot appear in POSIX
        // file paths, making delimiter-injection attacks impossible. Pipe
        // characters in content are still replaced with spaces as a defence-
        // in-depth measure.
        format!(
            "find /work -type f 2>/dev/null | while IFS= read -r f; do \
             size=$(stat -c%s \"$f\" 2>/dev/null || wc -c < \"$f\" 2>/dev/null); \
             type=$(file -b \"$f\" 2>/dev/null | head -c 100); \
             content=$(head -c 300 \"$f\" 2>/dev/null | tr '|' ' '); \
             printf '%s\\0%s\\0%s\\0%s\\n' \"$f\" \"$size\" \"$type\" \"$content\" >> {}; done || true",
            out
        ),
    ]
}

/// Builds the full `sh -lc` script for the matrix (multi-probe) run: per-probe
/// strace logs written to /out, payload dropped to the scanner user, followed
/// by a targeted artifact scan of the installed file tree.
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
        // After each install, scan the installed tree for suspicious artifacts.
        steps.extend(build_artifact_scan_steps(idx));
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
    danger_disable_seccomp: bool,
) -> Result<Vec<String>, String> {
    let mut args = vec![
        "run".to_string(),
        "--rm".to_string(),
        "--network".to_string(),
        "bridge".to_string(),
        "--security-opt".to_string(),
        "no-new-privileges".to_string(),
    ];

    // strace runs as root but drops the traced install to the unprivileged
    // `gyrseek` user (`strace -u`). Attaching to a process of a different UID
    // requires CAP_SYS_PTRACE, which is NOT in Docker's default capability
    // set — without it `PTRACE_SEIZE` fails with EPERM and no trace is ever
    // produced. The capability is scoped to this container's PID namespace,
    // so it cannot trace host processes.
    args.push("--cap-add".to_string());
    args.push("SYS_PTRACE".to_string());

    args.extend(vec![
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
    ]);
    if !danger_disable_seccomp {
        let profile_path = embedded_seccomp_profile_path()?;
        args.push("--security-opt".to_string());
        args.push(format!("seccomp={profile_path}"));
    }
    if let Some(apparmor_profile) = docker_apparmor_profile_name() {
        args.push("--security-opt".to_string());
        args.push(format!("apparmor={}", apparmor_profile));
    }
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
    Ok(args)
}

fn docker_apparmor_enabled_from_env() -> bool {
    std::env::var("GYRSEEK_DOCKER_APPARMOR_PROFILE")
        .ok()
        .map(|v| parse_bool_env(&v))
        .unwrap_or(false)
}

/// Stores the stderr from the last failed `apparmor_parser` invocation so
/// `announce_apparmor_status` can include it in the warning message.
static APPARMOR_LOAD_ERR: OnceLock<String> = OnceLock::new();

/// Runs `apparmor_parser -r -W --cache-loc <cache_dir> <profile>`, writing
/// the binary cache to a writable location instead of `/var/cache/apparmor`.
/// If the direct invocation lacks permissions and `GITHUB_ACTIONS=true` (GitHub
/// Actions runners are non-root with passwordless sudo), retries with `sudo -n`.
/// Returns `Ok(())` on success or the captured stderr on failure.
fn try_load_apparmor(
    profile_path: &std::path::Path,
    cache_dir: &std::path::Path,
) -> Result<(), String> {
    let cache_loc = cache_dir.to_string_lossy();
    let profile_loc = profile_path.to_string_lossy();

    let run = |use_sudo: bool| -> Result<String, String> {
        let mut cmd = if use_sudo {
            let mut c = Command::new("sudo");
            c.arg("-n").arg("apparmor_parser");
            c
        } else {
            Command::new("apparmor_parser")
        };
        let output = cmd
            .args(["-r", "-W", "--cache-loc"])
            .arg(cache_loc.as_ref())
            .arg(profile_loc.as_ref())
            .stderr(Stdio::piped())
            .stdout(Stdio::null())
            .output()
            .map_err(|e| format!("failed to execute: {e}"))?;

        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if output.status.success() {
            Ok(stderr)
        } else {
            Err(stderr)
        }
    };
    match run(false) {
        Ok(_) => Ok(()),
        Err(stderr)
            if (stderr.contains("Access denied") || stderr.contains("policy admin privileges"))
                && std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true") =>
        {
            eprintln!(
                "ℹ️ [gyrseek] GitHub Actions runner detected — retrying with sudo to load AppArmor profile"
            );
            run(true).map(|_| ())
        }
        Err(stderr) => Err(stderr),
    }
}

/// Loads the embedded AppArmor profile into the kernel via `apparmor_parser`
/// and returns the profile name on success, `None` if disabled by env var or
/// if loading fails (silent — the caller should announce status). The profile
/// is loaded once and cached for the process lifetime.
///
/// Uses `--cache-loc` to write the binary cache to the same writable temp dir
/// as the profile text, avoiding permission errors on `/var/cache/apparmor`
/// (common in containers/CI).
fn docker_apparmor_profile_name() -> Option<String> {
    if !docker_apparmor_enabled_from_env() {
        return None;
    }
    static PROFILE_LOADED: OnceLock<Option<String>> = OnceLock::new();
    PROFILE_LOADED
        .get_or_init(|| {
            let dir = TempDir::new().ok()?;
            let profile_path = dir.path().join(EMBEDDED_APPARMOR_PROFILE_NAME);
            std::fs::write(&profile_path, EMBEDDED_APPARMOR_PROFILE_TEXT).ok()?;

            match try_load_apparmor(&profile_path, dir.path()) {
                Ok(()) => {
                    Box::leak(Box::new(dir));
                    Some(EMBEDDED_APPARMOR_PROFILE_NAME.to_string())
                }
                Err(e) => {
                    let _ = APPARMOR_LOAD_ERR.set(e);
                    None
                }
            }
        })
        .clone()
}

fn embedded_seccomp_profile_path() -> Result<String, String> {
    static PROFILE: OnceLock<Result<String, String>> = OnceLock::new();
    PROFILE
        .get_or_init(|| {
            let dir = TempDir::new()
                .map_err(|e| format!("failed to create temp dir for seccomp profile: {e}"))?;
            let profile_path = dir.path().join(EMBEDDED_SECCOMP_PROFILE_NAME);
            std::fs::write(&profile_path, EMBEDDED_SECCOMP_PROFILE_JSON).map_err(|e| {
                format!(
                    "failed to write embedded seccomp profile to '{}': {e}",
                    profile_path.to_string_lossy()
                )
            })?;
            let path = profile_path.to_string_lossy().to_string();
            // Keep the random-named temp dir alive for the process lifetime
            // so Docker can read the seccomp file. The random name prevents
            // symlink attacks and TOCTOU races (see semgrep finding).
            Box::leak(Box::new(dir));
            Ok(path)
        })
        .clone()
}

fn announce_seccomp_status(danger_disable_seccomp: bool) {
    if !danger_disable_seccomp {
        eprintln!(
            "ℹ️ [gyrseek] Seccomp profile enabled: {} (embedded)",
            EMBEDDED_SECCOMP_PROFILE_NAME
        );
    } else {
        eprintln!(
            "⚠️ [gyrseek] Embedded seccomp profile disabled via --danger-disable-seccomp. Omit the flag to re-enable."
        );
    }
}

fn announce_apparmor_status() {
    if !cfg!(target_os = "linux") {
        return;
    }
    match docker_apparmor_profile_name() {
        Some(name) => eprintln!("ℹ️ [gyrseek] AppArmor profile loaded: {} (embedded)", name),
        None if !docker_apparmor_enabled_from_env() => {
            eprintln!(
                "ℹ️ [gyrseek] AppArmor profile disabled via GYRSEEK_DOCKER_APPARMOR_PROFILE=false"
            )
        }
        None => {
            let detail = APPARMOR_LOAD_ERR
                .get()
                .map(|s| s.as_str())
                .unwrap_or("apparmor_parser not found or failed");
            eprintln!(
                "⚠️ [gyrseek] AppArmor profile not available: {detail}\n\
                 Container will use Docker's default AppArmor profile. \
                 Set GYRSEEK_DOCKER_APPARMOR_PROFILE=false to silence this warning."
            )
        }
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
            "node:26.3-bookworm-slim@sha256:3fe807a03a4436e7bc76b7e84e6861899cd75c9028ae99bc00581940141ae150",
        )
    } else {
        (
            "GYRSEEK_PY_SCANNER_IMAGE",
            "GYRSEEK_PY_SCANNER_PREBUILT",
            "python:3.13-slim-bookworm@sha256:05b95397cac02b060ff1251afaa78087d92d7034369afbc8eb765631cada8257",
        )
    };

    let image = std::env::var(image_var)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default_image.to_string());

    let global_prebuilt = std::env::var("GYRSEEK_PREBUILT_SCANNER_IMAGES")
        .ok()
        .map(|v| parse_bool_env(&v))
        .unwrap_or(false);

    let prebuilt = std::env::var(prebuilt_var)
        .ok()
        .map(|v| parse_bool_env(&v))
        .unwrap_or(global_prebuilt);

    if prebuilt {
        eprintln!("ℹ️ [gyrseek] Using prebuilt scanner image: {}", image);
    }

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
        EMBEDDED_APPARMOR_PROFILE_NAME, EMBEDDED_APPARMOR_PROFILE_TEXT,
        EMBEDDED_SECCOMP_PROFILE_JSON, SCANNER_USER, build_artifact_scan_steps,
        build_docker_run_args, build_matrix_script, build_single_script, docker_apparmor_enabled_from_env, docker_apparmor_profile_name,
        strace_install_command,
    };
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        ENV_LOCK.get_or_init(|| Mutex::new(()))
    }

    // --- #4 strace must not truncate argv/addresses ---

    #[test]
    fn strace_command_disables_string_truncation() {
        let cmd = strace_install_command("npm", "left-pad@1.3.0", Some("/out/gyrseek_trace_0.log"));
        // -s 4096 lifts the 32-byte argv string cap; -v expands addresses;
        // -xx forces all bytes to \xNN hex-escape for deterministic parsing.
        assert!(cmd.contains("-s 4096"), "missing -s flag: {cmd}");
        assert!(cmd.contains(" -v "), "missing -v flag: {cmd}");
        assert!(cmd.contains(" -xx "), "missing -xx flag: {cmd}");
        assert!(
            cmd.contains("trace=network,execve,open,openat,?openat2,?openat64,link,linkat,symlink,symlinkat,clone,?clone3,fork,vfork,dup,dup2,?dup3,fcntl"),
            "strace must trace exactly the required syscalls, found: {cmd}"
        );
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
        assert!(matrix.contains(" -xx "));

        let single = build_single_script("pip", "requests", "2.31.0", true);
        assert!(single.contains("-s 4096"));
        assert!(single.contains(" -v "));
        assert!(single.contains(" -xx "));
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
        let with_out = build_docker_run_args("img:latest", "/tmp/out", None, "echo hi", false)
            .expect("docker args should build");
        assert!(with_out.iter().any(|a| a == "/tmp/out:/out"));
        assert!(with_out.iter().any(|a| a == "no-new-privileges"));

        let without_out = build_docker_run_args("img:latest", "", None, "echo hi", false)
            .expect("docker args should build");
        assert!(!without_out.iter().any(|a| a.ends_with(":/out")));
    }

    #[test]
    fn docker_args_pass_runtime_when_set() {
        let args = build_docker_run_args(
            "img:latest",
            "/tmp/out",
            Some("kata-runtime"),
            "echo hi",
            false,
        )
        .expect("docker args should build");
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

        let args = build_docker_run_args("img:latest", "/tmp/out", None, "echo hi", false)
            .expect("docker args should build");

        let pos = args
            .iter()
            .position(|a| a == "--cap-add")
            .expect("--cap-add flag present");
        assert_eq!(args.get(pos + 1).map(String::as_str), Some("SYS_PTRACE"));
    }

    #[test]
    fn docker_args_adds_seccomp_profile_by_default() {
        let args = build_docker_run_args("img:latest", "/tmp/out", None, "echo hi", false)
            .expect("docker args should build");

        let mut found = false;
        for window in args.windows(2) {
            if window[0] == "--security-opt" && window[1].starts_with("seccomp=") {
                found = true;
                break;
            }
        }
        assert!(
            found,
            "expected seccomp security-opt to be present by default"
        );
    }

    #[test]
    fn docker_args_disables_seccomp_when_danger_flag_true() {
        let args = build_docker_run_args("img:latest", "/tmp/out", None, "echo hi", true)
            .expect("docker args should build");
        assert!(
            !args.iter().any(|a| a.starts_with("seccomp=")),
            "danger flag must disable seccomp profile"
        );
    }

    #[test]
    fn embedded_seccomp_profile_keeps_networking_available() {
        let profile: serde_json::Value = serde_json::from_str(EMBEDDED_SECCOMP_PROFILE_JSON)
            .expect("embedded seccomp profile should be valid JSON");
        let syscalls = profile["syscalls"]
            .as_array()
            .expect("profile syscalls should be an array");

        for syscall in syscalls {
            let names = syscall["names"]
                .as_array()
                .expect("syscall names should be an array");
            let denied_networking = names.iter().any(|name| {
                matches!(
                    name.as_str(),
                    Some("socket" | "socketpair" | "connect" | "sendto" | "recvfrom")
                )
            });
            assert!(
                !denied_networking,
                "embedded seccomp profile must not block container networking: {syscall:?}"
            );
        }
    }

    // --- AppArmor profile ---

    #[test]
    fn embedded_apparmor_profile_mentions_cap_sys_ptrace() {
        assert!(
            EMBEDDED_APPARMOR_PROFILE_TEXT.contains("capability sys_ptrace"),
            "AppArmor profile must allow sys_ptrace for strace cross-UID tracing"
        );
    }

    #[test]
    fn embedded_apparmor_profile_allows_network() {
        assert!(
            EMBEDDED_APPARMOR_PROFILE_TEXT.contains("network inet tcp"),
            "AppArmor profile must allow TCP for package registries: {}",
            EMBEDDED_APPARMOR_PROFILE_TEXT
        );
        assert!(
            EMBEDDED_APPARMOR_PROFILE_TEXT.contains("network inet6 tcp"),
            "AppArmor profile must allow TCP6 for package registries"
        );
    }

    #[test]
    fn embedded_apparmor_profile_allows_ptrace() {
        assert!(
            EMBEDDED_APPARMOR_PROFILE_TEXT.contains("ptrace (trace,read,tracedby,readby)"),
            "AppArmor profile must allow ptrace for strace"
        );
    }

    #[test]
    fn embedded_apparmor_profile_allows_work_out_tmp_writes() {
        assert!(
            EMBEDDED_APPARMOR_PROFILE_TEXT.contains("/work/ rw"),
            "profile must grant rw to /work"
        );
        assert!(
            EMBEDDED_APPARMOR_PROFILE_TEXT.contains("/out/ rw"),
            "profile must grant rw to /out"
        );
        assert!(
            EMBEDDED_APPARMOR_PROFILE_TEXT.contains("/tmp/ rw"),
            "profile must grant rw to /tmp"
        );
    }

    #[test]
    fn embedded_apparmor_profile_valid_profile_name() {
        assert_eq!(EMBEDDED_APPARMOR_PROFILE_NAME, "gyrseek-tracing");
    }

    #[test]
    fn apparmor_env_var_default_false() {
        let _guard = env_lock().lock().expect("env lock poisoned");
        unsafe {
            std::env::remove_var("GYRSEEK_DOCKER_APPARMOR_PROFILE");
        }

        assert!(
            !docker_apparmor_enabled_from_env(),
            "default should be false"
        );

        unsafe {
            std::env::set_var("GYRSEEK_DOCKER_APPARMOR_PROFILE", "true");
        }
        assert!(docker_apparmor_enabled_from_env());

        unsafe {
            std::env::set_var("GYRSEEK_DOCKER_APPARMOR_PROFILE", "false");
        }
        assert!(!docker_apparmor_enabled_from_env());

        unsafe {
            std::env::remove_var("GYRSEEK_DOCKER_APPARMOR_PROFILE");
        }
    }

    #[test]
    fn apparmor_disabled_wont_call_apparmor_parser() {
        let _guard = env_lock().lock().expect("env lock poisoned");
        unsafe {
            std::env::set_var("GYRSEEK_DOCKER_APPARMOR_PROFILE", "false");
        }

        let result = docker_apparmor_profile_name();
        assert!(result.is_none(), "disabled profile should return None");

        unsafe {
            std::env::remove_var("GYRSEEK_DOCKER_APPARMOR_PROFILE");
        }
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

    // --- post-install artifact scan ---

    #[test]
    fn artifact_scan_steps_inventory_all_files() {
        let steps = build_artifact_scan_steps(0);
        let combined = steps.join(" ");
        assert!(
            combined.contains("find /work -type f"),
            "should inventory every file: {combined}"
        );
        assert!(
            combined.contains("file -b"),
            "should capture file type via file(1): {combined}"
        );
        assert!(
            combined.contains("stat -c%s"),
            "should capture file size: {combined}"
        );
        assert!(
            combined.contains("head -c 300"),
            "should capture content prefix: {combined}"
        );
    }

    #[test]
    fn artifact_scan_steps_pipe_char_in_content_replaced() {
        let steps = build_artifact_scan_steps(0);
        let combined = steps.join(" ");
        assert!(
            combined.contains("tr '|' ' '"),
            "should replace pipe in content to preserve delimiter: {combined}"
        );
    }

    #[test]
    fn artifact_scan_steps_uses_null_byte_delimiter() {
        // Finding 20 fix: the shell script must use printf with \0 delimiter
        // to prevent pipe-in-filename injection attacks.
        let steps = build_artifact_scan_steps(0);
        let cmd = &steps[1];
        assert!(
            cmd.contains("printf "),
            "must use printf for null-byte delimiters: {cmd}"
        );
        assert!(
            cmd.contains("\\0"),
            "must use \\0 null-byte field delimiter: {cmd}"
        );
        // Ensure the old echo-based pipe-delimiter approach is gone.
        assert!(
            !cmd.contains("echo \"$f|"),
            "must not use echo with pipe delimiter: {cmd}"
        );
    }

    #[test]
    fn artifact_scan_steps_output_to_correct_log() {
        let steps0 = build_artifact_scan_steps(0);
        let steps1 = build_artifact_scan_steps(1);
        assert!(steps0[1].contains("/out/gyrseek_artifacts_0.log"));
        assert!(steps1[1].contains("/out/gyrseek_artifacts_1.log"));
    }

    #[test]
    fn matrix_script_includes_artifact_scan_after_each_probe() {
        let script = build_matrix_script(
            "pip",
            &[
                ("pkg-a".to_string(), "1.0.0".to_string()),
                ("pkg-b".to_string(), "2.0.0".to_string()),
            ],
            true,
        );
        // After the first probe's install, expect the artifact scan log for idx 0.
        let probe0_install = script.find("gyrseek_trace_0.log").expect("trace 0 log");
        let probe0_artifacts = script
            .find("gyrseek_artifacts_0.log")
            .expect("artifacts 0 log");
        assert!(
            probe0_artifacts > probe0_install,
            "artifact scan must follow install for probe 0"
        );
        // Same for probe 1.
        let probe1_artifacts = script
            .find("gyrseek_artifacts_1.log")
            .expect("artifacts 1 log");
        let probe1_install = script.find("gyrseek_trace_1.log").expect("trace 1 log");
        assert!(
            probe1_artifacts > probe1_install,
            "artifact scan must follow install for probe 1"
        );
    }

    #[test]
    fn embedded_seccomp_profile_structurally_blocks_dangerous_syscalls() {
        let profile: serde_json::Value = serde_json::from_str(EMBEDDED_SECCOMP_PROFILE_JSON)
            .expect("embedded seccomp profile should be valid JSON");

        let syscalls = profile["syscalls"]
            .as_array()
            .expect("profile syscalls should be an array");

        let mut found_setup = false;
        let mut found_enter = false;
        let mut found_register = false;
        let mut found_vm_writev = false;

        for rule in syscalls {
            if rule["action"] == "SCMP_ACT_ERRNO" {
                let Some(names) = rule["names"].as_array() else {
                    continue;
                };
                for name in names {
                    if let Some(s) = name.as_str() {
                        match s {
                            "io_uring_setup" => found_setup = true,
                            "io_uring_enter" => found_enter = true,
                            "io_uring_register" => found_register = true,
                            "process_vm_writev" => found_vm_writev = true,
                            _ => {}
                        }
                    }
                }
            }
        }

        assert!(found_setup, "io_uring_setup must be blocked");
        assert!(found_enter, "io_uring_enter must be blocked");
        assert!(found_register, "io_uring_register must be blocked");
        assert!(found_vm_writev, "process_vm_writev must be blocked");
    }

    #[test]
    fn docker_enforces_sandbox_constraints() {
        use std::process::Command;

        if Command::new("docker").arg("info").output().is_err() {
            if std::env::var("CI").is_ok() {
                panic!("Docker must be available in CI environments for enforcement testing!");
            }
            eprintln!("Docker not available, skipping sandbox enforcement test");
            return;
        }

        let arch = std::env::consts::ARCH;
        if arch != "x86_64" && arch != "aarch64" {
            if std::env::var("CI").is_ok() {
                panic!("CI must run on x86_64 or aarch64 to test seccomp constraints!");
            }
            eprintln!(
                "Unsupported architecture '{}' for syscall test, skipping",
                arch
            );
            return;
        }

        let python_script = r#"import sys, ctypes, platform
success = True

libc = ctypes.CDLL("libc.so.6", use_errno=True)
machine = platform.machine()
if machine in ("x86_64", "amd64"):
    SYS_process_vm_writev = 311
elif machine in ("aarch64", "arm64"):
    SYS_process_vm_writev = 271
else:
    print("Unknown architecture:", machine, file=sys.stderr)
    sys.exit(1)

ctypes.set_errno(0)
res = libc.syscall(SYS_process_vm_writev, 0, 0, 0, 0, 0, 0)
err = ctypes.get_errno()

if res == -1 and err == 1:
    print("PASS: process_vm_writev blocked with EPERM", file=sys.stderr)
else:
    print(f"FAIL: process_vm_writev returned {res}, errno {err} (expected EPERM=1)", file=sys.stderr)
    success = False

sys.exit(0 if success else 1)"#;

        let command_str = format!("python3 -c '{}'", python_script);

        let image = match arch {
            "x86_64" => {
                "python@sha256:129f9f5d5729767916d79f0021ba4fe56ff113332b08ef1213ecf529a9da7ebb"
            } // python:3.13-slim-bookworm (amd64)
            "aarch64" => {
                "python@sha256:f2c0cbd763245b6de85ecbbf17b07a4802e847cecd9b9e2807a2cef330bd8245"
            } // python:3.13-slim-bookworm (arm64/v8)
            _ => unreachable!(),
        };
        let protected_args = build_docker_run_args(image, "", None, &command_str, false).unwrap();

        let protected_run = Command::new("docker")
            .args(&protected_args)
            .output()
            .expect("docker command should run");

        assert!(
            protected_run.status.success(),
            "Protected sandbox test failed (constraints violated)!
Stdout: {}
Stderr: {}",
            String::from_utf8_lossy(&protected_run.stdout),
            String::from_utf8_lossy(&protected_run.stderr)
        );
    }
}
