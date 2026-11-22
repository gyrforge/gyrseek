use crate::runtime_image::ImageChoice;
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
                "pidfd_getfd",
                "pidfd_open",
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
  /gyrseek-trace/ rw,
  /gyrseek-trace/** rwk,
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

/// The package manager's install command exited non-zero inside the probe, so the
/// trace covers a failed install rather than a normal one.
#[derive(Clone, Debug)]
pub(crate) struct InstallFailure {
    pub exit_code: i32,
    /// Tail of the install's own error output (empty when it could not be captured).
    pub output: String,
}

/// A single traced probe.
#[derive(Debug)]
pub(crate) struct ProbeTrace {
    pub probe: (String, String),
    /// Raw strace output, with the post-install artifact inventory appended.
    pub trace: String,
    pub install_failure: Option<InstallFailure>,
}

pub(crate) trait SandboxRunner {
    fn trace_install(&self, manager: &str, package: &str, version: &str) -> Result<String, String>;

    /// What the probes run on, for error messages (for example `Python 3.11 (from
    /// .python-version)`). `None` when there is nothing useful to say.
    fn sandbox_description(&self, _manager: &str) -> Option<String> {
        None
    }

    fn trace_install_matrix(
        &self,
        manager: &str,
        probes: &[(String, String)],
    ) -> Result<Vec<ProbeTrace>, String> {
        probes
            .iter()
            .map(|(package, version)| {
                let trace = self.trace_install(manager, package, version)?;
                Ok(ProbeTrace {
                    probe: (package.clone(), version.clone()),
                    trace,
                    install_failure: None,
                })
            })
            .collect()
    }
}

/// Wall-clock limit for a single install probe unless `probe_timeout_seconds` overrides it.
pub(crate) const DEFAULT_PROBE_TIMEOUT_SECS: usize = 300;

/// `timeout` exits 124 when it had to stop the command it wrapped, or 137 when it
/// then had to SIGKILL it (`-k`). A payload that ignores SIGTERM keeps strace
/// alive, so without the follow-up SIGKILL the limit could hang forever.
const TIMEOUT_EXIT_CODES: [i32; 2] = [124, 137];

fn is_timeout_exit(code: Option<i32>) -> bool {
    code.is_some_and(|c| TIMEOUT_EXIT_CODES.contains(&c))
}

/// Seconds `timeout` waits after SIGTERM before sending SIGKILL.
const TIMEOUT_KILL_AFTER_SECS: u32 = 5;

pub(crate) fn build_runner_from_env(
    danger_disable_seccomp: bool,
    no_sandbox: bool,
    probe_timeout_secs: usize,
    image: ImageChoice,
) -> Result<Box<dyn SandboxRunner>, String> {
    let runner: Result<Box<dyn SandboxRunner>, String> = if no_sandbox {
        eprintln!(
            "⚠️ [gyrseek] CRITICAL WARNING: Running in HOST mode (--no-sandbox). Container isolation is completely INACTIVE: packages (including the version being vetted) execute directly on your machine with your credentials and environment, and gyrseek can only detect, not prevent!"
        );
        if danger_disable_seccomp {
            eprintln!("⚠️ [gyrseek] Warning: --danger-disable-seccomp has no effect in host mode.");
        }
        Ok(Box::new(HostRunner { probe_timeout_secs }))
    } else {
        docker_preflight("docker", std::env::consts::OS)?;
        Ok(Box::new(DockerRunner {
            danger_disable_seccomp,
            probe_timeout_secs,
            image,
        }))
    };

    if runner.is_ok() && !no_sandbox {
        announce_seccomp_status(danger_disable_seccomp);
        announce_apparmor_status();
    }

    runner
}

struct HostRunner {
    probe_timeout_secs: usize,
}

impl SandboxRunner for HostRunner {
    fn trace_install(&self, manager: &str, package: &str, version: &str) -> Result<String, String> {
        match self.probe(manager, package, version)? {
            Some((trace, _)) => Ok(trace),
            None => Err(probe_timeout_message(
                self.probe_timeout_secs,
                package,
                version,
            )),
        }
    }

    fn trace_install_matrix(
        &self,
        manager: &str,
        probes: &[(String, String)],
    ) -> Result<Vec<ProbeTrace>, String> {
        // Like Docker mode, a probe that timed out is left out so the scanner blocks just
        // that package (its trace is missing); the rest of the batch is still scanned.
        let mut traces = Vec::new();
        let mut timed_out = Vec::new();
        for (package, version) in probes {
            match self.probe(manager, package, version)? {
                Some((trace, install_failure)) => traces.push(ProbeTrace {
                    probe: (package.clone(), version.clone()),
                    trace,
                    install_failure,
                }),
                None => timed_out.push(probe_timeout_message(
                    self.probe_timeout_secs,
                    package,
                    version,
                )),
            }
        }
        if traces.is_empty() && !timed_out.is_empty() {
            return Err(timed_out.join("; "));
        }
        Ok(traces)
    }
}

impl HostRunner {
    /// `Ok(None)` means the probe exceeded `probe_timeout_seconds`.
    fn probe(
        &self,
        manager: &str,
        package: &str,
        version: &str,
    ) -> Result<Option<(String, Option<InstallFailure>)>, String> {
        let temp_dir =
            tempfile::tempdir().map_err(|e| format!("failed to create temp dir: {e}"))?;
        let target_path = temp_dir.path().to_string_lossy().to_string();

        let cmd_args = if is_npm_family_manager(manager) {
            let mut args = vec![
                "-f".to_string(),
                "-e".to_string(),
                "trace=network,execve,?execveat,open,openat,openat2,openat64,link,linkat,symlink,symlinkat,clone,clone3,fork,vfork,dup,dup2,dup3,fcntl".to_string(),
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
                "trace=network,execve,?execveat,open,openat,openat2,openat64,link,linkat,symlink,symlinkat,clone,clone3,fork,vfork,dup,dup2,dup3,fcntl".to_string(),
                "uv".to_string(),
                "pip".to_string(),
                "install".to_string(),
                format!("{}=={}", package, version),
                "--target".to_string(),
                target_path,
                "--no-cache".to_string(),
            ]
        };

        // GNU `timeout` signals its whole process group, so strace and the
        // package manager it traces are stopped together.
        let output = Command::new("timeout")
            .arg("-k")
            .arg(TIMEOUT_KILL_AFTER_SECS.to_string())
            .arg(self.probe_timeout_secs.to_string())
            .arg("strace")
            .args(&cmd_args)
            .stderr(Stdio::piped())
            .stdout(Stdio::null())
            .output()
            .map_err(|e| format!("failed to execute host strace (needs GNU `timeout`): {e}"))?;

        if is_timeout_exit(output.status.code()) {
            eprintln!(
                "⚠️ [gyrseek] {}",
                probe_timeout_message(self.probe_timeout_secs, package, version)
            );
            return Ok(None);
        }

        // The trace and the install's own stderr share this stream in host mode, so
        // only the exit code can be reported here, not the install's error text.
        let install_failure = match output.status.code() {
            Some(0) => None,
            code => Some(InstallFailure {
                exit_code: code.unwrap_or(-1),
                output: String::new(),
            }),
        };
        Ok(Some((
            String::from_utf8_lossy(&output.stderr).to_string(),
            install_failure,
        )))
    }
}

struct DockerRunner {
    danger_disable_seccomp: bool,
    probe_timeout_secs: usize,
    image: ImageChoice,
}

impl SandboxRunner for DockerRunner {
    fn sandbox_description(&self, manager: &str) -> Option<String> {
        let image_var = if is_npm_family_manager(manager) {
            "GYRSEEK_NPM_SCANNER_IMAGE"
        } else {
            "GYRSEEK_PY_SCANNER_IMAGE"
        };
        match std::env::var(image_var) {
            Ok(image) if !image.is_empty() => Some(format!("your custom image {image}")),
            _ => Some(self.image.description.clone()),
        }
    }

    fn trace_install(&self, manager: &str, package: &str, version: &str) -> Result<String, String> {
        let probes = vec![(package.to_string(), version.to_string())];
        let mut results = self.trace_install_matrix(manager, &probes)?;
        if results.is_empty() {
            return Err("docker matrix tracing returned no results".to_string());
        }
        Ok(results.remove(0).trace)
    }

    fn trace_install_matrix(
        &self,
        manager: &str,
        probes: &[(String, String)],
    ) -> Result<Vec<ProbeTrace>, String> {
        trace_install_docker_matrix(
            manager,
            probes,
            self.danger_disable_seccomp,
            self.probe_timeout_secs,
            &self.image.image,
        )
    }
}

pub(crate) fn sandbox_mem_limit() -> String {
    std::env::var("GYRSEEK_MEM_LIMIT")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "2g".to_string())
}

pub(crate) fn sandbox_max_processes() -> String {
    std::env::var("GYRSEEK_MAX_PROCESSES")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .or_else(|| {
            std::env::var("GYRSEEK_PIDS_LIMIT")
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        })
        .unwrap_or_else(|| "256".to_string())
}

fn trace_install_docker_matrix(
    manager: &str,
    probes: &[(String, String)],
    danger_disable_seccomp: bool,
    probe_timeout_secs: usize,
    default_image: &str,
) -> Result<Vec<ProbeTrace>, String> {
    if probes.is_empty() {
        return Ok(Vec::new());
    }

    let image_config = scanner_image_config(manager, default_image);

    let out_dir = tempfile::tempdir().map_err(|e| format!("failed to create temp dir: {e}"))?;
    let out_dir_path = out_dir.path().to_string_lossy().to_string();

    let script = build_matrix_script(manager, probes, image_config.prebuilt, probe_timeout_secs);
    let args = build_docker_run_args(
        &image_config.image,
        &out_dir_path,
        &script,
        danger_disable_seccomp,
    )?;

    let output = Command::new("docker")
        .args(&args)
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()
        .map_err(|e| format!("failed to execute docker sandbox: {e}"))?;

    if output.status.code() == Some(124) {
        // Only the cleanup after a timed-out probe exits 124 (see KILL_PAYLOAD_PROCESSES_STEP).
        return Err(format!(
            "a probe exceeded probe_timeout_seconds={probe_timeout_secs} and left processes running that could not be stopped, so the whole batch was aborted"
        ));
    }

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

    collect_probe_traces(
        out_dir.path(),
        probes,
        probe_timeout_secs,
        &|package, version| {
            trace_install_docker_single(
                manager,
                package,
                version,
                danger_disable_seccomp,
                probe_timeout_secs,
                default_image,
            )
        },
    )
}

/// Reads what the container script left in `out_dir` for each probe: the trace, the
/// artifact inventory, an exit-code file for a failed install and a marker for a probe that
/// timed out. `retry_single` re-runs one probe on its own when its trace in the batch is
/// missing.
fn collect_probe_traces(
    out_dir: &std::path::Path,
    probes: &[(String, String)],
    probe_timeout_secs: usize,
    retry_single: &dyn Fn(&str, &str) -> Result<String, String>,
) -> Result<Vec<ProbeTrace>, String> {
    let mut results = Vec::new();
    let mut timed_out: Vec<String> = Vec::new();
    for (idx, (package, version)) in probes.iter().enumerate() {
        // A probe the script stopped for exceeding the limit has no usable trace.
        // Leave it out so the scanner blocks just that package ("trace missing"),
        // and do not retry it: that would only wait out the limit a second time.
        if out_dir
            .join(format!("gyrseek_timeout_{}.log", idx))
            .exists()
        {
            let msg = probe_timeout_message(probe_timeout_secs, package, version);
            eprintln!("⚠️ [gyrseek] {msg}");
            timed_out.push(msg);
            continue;
        }
        let trace_path = out_dir.join(format!("gyrseek_trace_{}.log", idx));
        // Prefer the matrix log; if it is missing/unreadable, retry the probe in
        // isolation. Either way, a blank trace means strace produced no data and
        // MUST NOT be treated as a clean zero-connection scan — fail closed.
        let mut trace = match std::fs::read_to_string(&trace_path) {
            Ok(contents) if !contents.trim().is_empty() => contents,
            _ => retry_single(package, version)?,
        };
        if trace.trim().is_empty() {
            let err_path = out_dir.join(format!("gyrseek_err_{}.log", idx));
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
        let artifact_path = out_dir.join(format!("gyrseek_artifacts_{}.log", idx));
        if let Ok(artifact_content) = std::fs::read_to_string(&artifact_path) {
            let trimmed = artifact_content.trim();
            if !trimmed.is_empty() {
                trace.push_str("\n=== gyrseek_artifacts ===\n");
                trace.push_str(trimmed);
            }
        }
        let install_failure = read_install_failure(out_dir, idx);
        results.push(ProbeTrace {
            probe: (package.clone(), version.clone()),
            trace,
            install_failure,
        });
    }

    if results.is_empty() && !timed_out.is_empty() {
        return Err(timed_out.join("; "));
    }

    Ok(results)
}

fn trace_install_docker_single(
    manager: &str,
    package: &str,
    version: &str,
    danger_disable_seccomp: bool,
    probe_timeout_secs: usize,
    default_image: &str,
) -> Result<String, String> {
    let image_config = scanner_image_config(manager, default_image);
    let script = build_single_script(
        manager,
        package,
        version,
        image_config.prebuilt,
        probe_timeout_secs,
    );
    // No /out bind mount here: the single-probe fallback captures strace output
    // from stderr rather than a log file.
    let args = build_docker_run_args(&image_config.image, "", &script, danger_disable_seccomp)?;

    let output = Command::new("docker")
        .args(&args)
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .output()
        .map_err(|e| format!("failed to execute docker sandbox: {e}"))?;

    if is_timeout_exit(output.status.code()) {
        return Err(probe_timeout_message(probe_timeout_secs, package, version));
    }

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

/// Reads the exit code the matrix script saved for a probe whose install failed
/// (`gyrseek_rc_N.log` exists only then) plus the tail of its error output.
fn read_install_failure(out_dir: &std::path::Path, idx: usize) -> Option<InstallFailure> {
    let rc = std::fs::read_to_string(out_dir.join(format!("gyrseek_rc_{idx}.log"))).ok()?;
    let output = read_file_tail(&out_dir.join(format!("gyrseek_err_{idx}.log")))
        .map(|raw| install_output_tail(&raw))
        .unwrap_or_default();
    Some(InstallFailure {
        // A marker we cannot parse is still a failure: fail closed.
        exit_code: rc.trim().parse().unwrap_or(-1),
        output,
    })
}

/// How much of a failed install's stderr is read. The file is written by the package under
/// test and can be arbitrarily large, so only its end is ever loaded into memory.
const INSTALL_OUTPUT_READ_BYTES: u64 = 64 * 1024;

fn read_file_tail(path: &std::path::Path) -> std::io::Result<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    file.seek(SeekFrom::Start(
        len.saturating_sub(INSTALL_OUTPUT_READ_BYTES),
    ))?;
    let mut bytes = Vec::new();
    file.take(INSTALL_OUTPUT_READ_BYTES)
        .read_to_end(&mut bytes)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

const INSTALL_OUTPUT_MAX_LINES: usize = 15;
const INSTALL_OUTPUT_MAX_LINE_CHARS: usize = 300;

/// The last lines of a failed install's output, safe to print. The text comes from
/// the package under test, so control characters (terminal escape sequences) are
/// dropped, and strace's own `Process N attached` chatter is removed.
fn install_output_tail(raw: &str) -> String {
    let lines: Vec<String> = raw
        .lines()
        .filter(|l| !l.starts_with("strace: Process "))
        .map(|l| {
            l.chars()
                .filter(|c| !c.is_control() || *c == '\t')
                .take(INSTALL_OUTPUT_MAX_LINE_CHARS)
                .collect::<String>()
        })
        .filter(|l| !l.trim().is_empty())
        .collect();
    let start = lines.len().saturating_sub(INSTALL_OUTPUT_MAX_LINES);
    lines[start..].join("\n")
}

fn probe_timeout_message(secs: usize, package: &str, version: &str) -> String {
    format!(
        "sandbox probe for '{package}@{version}' exceeded probe_timeout_seconds={secs}; treating it as a block. \
If this is a slow but legitimate build, raise the limit in your gyrseek.yaml (for example `probe_timeout_seconds: {}`)",
        secs.saturating_mul(2)
    )
}

pub(crate) fn is_npm_family_manager(manager: &str) -> bool {
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
/// The syscalls every gyrseek strace records.
const STRACE_SYSCALL_FILTER: &str = "network,execve,?execveat,open,openat,?openat2,?openat64,link,linkat,symlink,symlinkat,clone,?clone3,fork,vfork,dup,dup2,?dup3,fcntl";

fn strace_install_command(
    manager: &str,
    pkg_spec: &str,
    out_log: Option<&str>,
    timeout_secs: usize,
) -> String {
    strace_command(
        &install_invocation(manager, pkg_spec),
        out_log,
        timeout_secs,
    )
}

/// `install` (a shell command) run under strace, dropped to the scanner user and bounded by the
/// probe timeout.
fn strace_command(install: &str, out_log: Option<&str>, timeout_secs: usize) -> String {
    let mut cmd = format!(
        "timeout -k {TIMEOUT_KILL_AFTER_SECS} {timeout_secs} strace -f -s 4096 -v -xx -u {u} -e trace={STRACE_SYSCALL_FILTER}",
        u = SCANNER_USER
    );
    if let Some(path) = out_log {
        cmd.push_str(&format!(" -o {}", path));
    }
    format!("{cmd} {install}")
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
    let out = probe_file("artifacts", idx);
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

/// Where the matrix script keeps what each probe leaves behind (strace log, strace stderr,
/// artifact inventory, exit code, timeout marker) while the batch runs: a directory on the
/// container's own filesystem that only root can enter. The payload runs as the scanner user, so
/// it cannot read, change or delete it, on any platform. The bind-mounted `/out` is not used for
/// this: on Docker Desktop for macOS it does not enforce the in-container ownership, and a
/// payload could erase or rewrite its own earlier events, or a baseline's trace, there
/// (FIXED #411). `/out` is written only after the last probe, by `PUBLISH_TRACES_STEP`.
const TRACE_DIR: &str = "/gyrseek-trace";

/// `/gyrseek-trace/gyrseek_<kind>_<idx>.log`; the host reads the same name from `/out`.
fn probe_file(kind: &str, idx: usize) -> String {
    format!("{TRACE_DIR}/gyrseek_{kind}_{idx}.log")
}

/// Run as root when the script exits (also when it aborts): empties `/out`, which the payload may
/// have written to on a platform where the bind mount does not protect it (a planted symlink
/// would otherwise be followed by the copy), then copies the logs there. Never fails the script.
const PUBLISH_TRACES_STEP: &str =
    "find /out -mindepth 1 -delete 2>/dev/null; cp /gyrseek-trace/* /out/ 2>/dev/null; true";

/// Creates the root-only trace directory and arranges for it to be published on exit.
fn trace_dir_setup_steps() -> Vec<String> {
    vec![
        format!("rm -rf {TRACE_DIR}; mkdir -m 700 {TRACE_DIR}"),
        format!("trap '{PUBLISH_TRACES_STEP}' EXIT"),
    ]
}

/// Empties the shared install tree (and `/tmp`) between probes. Traces and
/// artifact inventories live in `/out`, so they are untouched. The trailing
/// `|| true` is needed because the script runs under `set -e` and a failed
/// cleanup must not abort the remaining probes.
const WORK_RESET_STEP: &str =
    "find /work /tmp -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null || true";

/// SIGKILLs every process owned by the scanner user, repeating until none is left (a
/// survivor can fork between a scan of `/proc` and its kill; zombies are already dead and
/// are skipped). Walks `/proc` because `pkill` is not in the slim scanner images. If
/// processes are still alive after ten passes the script exits 124, which stops the
/// container and with it everything in it: the next probe must never share a workspace
/// with an untraced survivor. Runs only after a probe timed out.
const KILL_PAYLOAD_PROCESSES_STEP: &str = "n=1; for _ in 1 2 3 4 5 6 7 8 9 10; do n=0; for p in /proc/[0-9]*; do [ \"$(stat -c %U \"$p\" 2>/dev/null)\" = gyrseek ] || continue; case \"$(sed -n 's/^State:[[:space:]]*//p' \"$p/status\" 2>/dev/null)\" in Z*) continue;; esac; kill -9 \"${p#/proc/}\" 2>/dev/null || true; n=1; done; [ $n -eq 0 ] && break; done; [ $n -eq 0 ] || exit 124";

/// Builds the full `sh -lc` script for the matrix (multi-probe) run: per-probe
/// strace logs kept in the root-only `TRACE_DIR`, payload dropped to the scanner
/// user, followed by a targeted artifact scan of the installed file tree. The logs
/// reach `/out` only when the script exits.
fn build_matrix_script(
    manager: &str,
    probes: &[(String, String)],
    prebuilt: bool,
    timeout_secs: usize,
) -> String {
    build_matrix_script_with(manager, probes, prebuilt, timeout_secs, &|spec| {
        install_invocation(manager, spec)
    })
}

/// `build_matrix_script` with the install command of each probe supplied by the caller (the
/// trace-integrity test runs a payload that tries to tamper with its trace).
fn build_matrix_script_with(
    manager: &str,
    probes: &[(String, String)],
    prebuilt: bool,
    timeout_secs: usize,
    install: &dyn Fn(&str) -> String,
) -> String {
    let mut steps = image_setup_steps(manager, prebuilt);
    steps.extend(scanner_user_setup_steps());
    steps.extend(trace_dir_setup_steps());

    for (idx, (package, version)) in probes.iter().enumerate() {
        let spec = package_spec(manager, package, version);
        let log = probe_file("trace", idx);
        let err = probe_file("err", idx);
        let timeout_marker = probe_file("timeout", idx);
        let rc_file = probe_file("rc", idx);
        // Drop the install's own stdout, but capture strace's stderr to a per-probe
        // file instead of discarding it with `>/dev/null 2>&1`. Only a timeout aborts
        // the script, so a single failing install (e.g. a yanked baseline) cannot abort
        // its sibling probes; a genuine strace-attach failure leaves an empty trace log, which
        // the reader treats as a hard error (fail closed) using the captured stderr.
        // A probe stopped by `timeout` (exit 124, or 137 after its SIGKILL) leaves a
        // marker; the host blocks only that package. A payload can ignore SIGTERM, so
        // whatever it left running is killed before the next probe starts. Any other
        // non-zero exit is a failed install: its exit code is saved for the host, which
        // blocks the package and shows the install's own error output.
        steps.push(format!(
            "{} >/dev/null 2>{err} || {{ rc=$?; if [ $rc -eq 124 ] || [ $rc -eq 137 ]; then : > {timeout_marker}; {KILL_PAYLOAD_PROCESSES_STEP}; else echo $rc > {rc_file}; fi; true; }}",
            strace_command(&install(&spec), Some(&log), timeout_secs),
        ));
        // After each install, scan the installed tree for suspicious artifacts.
        steps.extend(build_artifact_scan_steps(idx));
        // Then wipe the install tree so the next probe starts from the same
        // empty state and its scan cannot see this probe's files.
        steps.push(WORK_RESET_STEP.to_string());
    }

    steps.join("; ")
}

/// Builds the `sh -lc` script for the single-probe fallback (trace to stderr).
fn build_single_script(
    manager: &str,
    package: &str,
    version: &str,
    prebuilt: bool,
    timeout_secs: usize,
) -> String {
    let mut steps = image_setup_steps(manager, prebuilt);
    steps.extend(scanner_user_setup_steps());

    let spec = package_spec(manager, package, version);
    steps.push(strace_install_command(manager, &spec, None, timeout_secs));

    steps.join("; ")
}

/// Builds the `docker run` argument vector. When `out_dir_path` is non-empty it
/// is bind-mounted at /out, where the matrix script publishes the trace logs when it exits.
fn build_docker_run_args(
    image: &str,
    out_dir_path: &str,
    script: &str,
    danger_disable_seccomp: bool,
) -> Result<Vec<String>, String> {
    let mem_limit = sandbox_mem_limit();
    let max_procs = sandbox_max_processes();
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
        max_procs,
        "--memory".to_string(),
        mem_limit.clone(),
        "--cpus".to_string(),
        "1".to_string(),
        "--user".to_string(),
        "root".to_string(),
        "--tmpfs".to_string(),
        "/tmp:rw,noexec,nosuid,size=128m".to_string(),
        "--tmpfs".to_string(),
        format!("/work:rw,noexec,nosuid,size={mem_limit}"),
    ];
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

/// Fails fast, before any registry lookup, with a message that says which Docker problem
/// the user has: CLI missing, daemon not running, or no permission on the daemon socket.
fn docker_preflight(program: &str, os: &str) -> Result<(), String> {
    match Command::new(program)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(status) if status.success() => {}
        Ok(status) => {
            return Err(format!(
                "`{program} --version` failed ({status}); the Docker CLI looks broken"
            ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!(
                "Docker is not installed: `{program}` was not found on PATH. Install Docker (https://docs.docker.com/get-docker/)"
            ));
        }
        Err(e) => return Err(format!("failed to run `{program}`: {e}")),
    }

    let output = Command::new(program)
        .args(["info", "--format", "{{.ServerVersion}}"])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("failed to run `{program} info`: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(docker_daemon_error_message(
            &String::from_utf8_lossy(&output.stderr),
            os,
        ))
    }
}

/// Turns the stderr of a failed `docker info` into an actionable message for `os`.
fn docker_daemon_error_message(stderr: &str, os: &str) -> String {
    let detail = stderr
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("no error output");
    let hint = if stderr.to_ascii_lowercase().contains("permission denied") {
        "Docker is installed but this user cannot access the Docker daemon socket. On Linux, add your user to the `docker` group and log in again"
    } else if os == "linux" {
        "Docker is installed but its daemon is not running or not reachable. Start it, for example `sudo systemctl start docker`"
    } else {
        "Docker is installed but its daemon is not running or not reachable. Start Docker Desktop (or your Docker-compatible runtime) and retry"
    };
    format!("{hint}. Docker said: {detail}")
}

fn scanner_image_config(manager: &str, default_image: &str) -> ScannerImageConfig {
    let (image_var, prebuilt_var, default_image) = if is_npm_family_manager(manager) {
        (
            "GYRSEEK_NPM_SCANNER_IMAGE",
            "GYRSEEK_NPM_SCANNER_PREBUILT",
            default_image,
        )
    } else {
        (
            "GYRSEEK_PY_SCANNER_IMAGE",
            "GYRSEEK_PY_SCANNER_PREBUILT",
            default_image,
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

fn shell_single_quoted(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

#[cfg(test)]
mod tests {
    use super::{
        DockerRunner, INSTALL_OUTPUT_READ_BYTES, PUBLISH_TRACES_STEP, collect_probe_traces,
        is_timeout_exit, read_file_tail,
    };
    use super::{
        EMBEDDED_APPARMOR_PROFILE_NAME, EMBEDDED_APPARMOR_PROFILE_TEXT,
        EMBEDDED_SECCOMP_PROFILE_JSON, KILL_PAYLOAD_PROCESSES_STEP, SCANNER_USER, WORK_RESET_STEP,
        build_artifact_scan_steps, build_docker_run_args, build_matrix_script,
        build_runner_from_env, build_single_script, docker_apparmor_enabled_from_env,
        docker_apparmor_profile_name, install_output_tail, probe_timeout_message,
        read_install_failure, sandbox_max_processes, strace_install_command,
    };
    use crate::sandbox::SandboxRunner;
    use std::sync::Mutex;

    fn env_lock() -> &'static Mutex<()> {
        static ENV_LOCK: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
        ENV_LOCK.get_or_init(|| Mutex::new(()))
    }

    struct SandboxEnvVarGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        keys: Vec<&'static str>,
    }

    impl SandboxEnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let guard = env_lock()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            unsafe {
                std::env::set_var(key, value);
            }
            Self {
                _lock: guard,
                keys: vec![key],
            }
        }

        fn set_many(vars: &[(&'static str, &str)]) -> Self {
            let guard = env_lock()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut keys = Vec::new();
            for (key, val) in vars {
                unsafe {
                    std::env::set_var(key, val);
                }
                keys.push(*key);
            }
            Self { _lock: guard, keys }
        }

        fn remove(key: &'static str) -> Self {
            let guard = env_lock()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            unsafe {
                std::env::remove_var(key);
            }
            Self {
                _lock: guard,
                keys: vec![key],
            }
        }
    }

    impl Drop for SandboxEnvVarGuard {
        fn drop(&mut self) {
            for key in &self.keys {
                unsafe {
                    std::env::remove_var(key);
                }
            }
        }
    }

    // --- #4 strace must not truncate argv/addresses ---

    #[test]
    fn strace_command_disables_string_truncation() {
        let cmd = strace_install_command(
            "npm",
            "left-pad@1.3.0",
            Some("/out/gyrseek_trace_0.log"),
            300,
        );
        // -s 4096 lifts the 32-byte argv string cap; -v expands addresses;
        // -xx forces all bytes to \xNN hex-escape for deterministic parsing.
        assert!(cmd.contains("-s 4096"), "missing -s flag: {cmd}");
        assert!(cmd.contains(" -v "), "missing -v flag: {cmd}");
        assert!(cmd.contains(" -xx "), "missing -xx flag: {cmd}");
        assert!(
            cmd.contains("trace=network,execve,?execveat,open,openat,?openat2,?openat64,link,linkat,symlink,symlinkat,clone,?clone3,fork,vfork,dup,dup2,?dup3,fcntl"),
            "strace must trace exactly the required syscalls, found: {cmd}"
        );
    }

    #[test]
    fn matrix_and_single_scripts_disable_truncation() {
        let matrix = build_matrix_script(
            "npm",
            &[("left-pad".to_string(), "1.3.0".to_string())],
            true,
            300,
        );
        assert!(matrix.contains("-s 4096"));
        assert!(matrix.contains(" -v "));
        assert!(matrix.contains(" -xx "));

        let single = build_single_script("pip", "requests", "2.31.0", true, 300);
        assert!(single.contains("-s 4096"));
        assert!(single.contains(" -v "));
        assert!(single.contains(" -xx "));
    }

    // --- #5 the traced payload runs unprivileged so it can't rewrite its trace ---

    #[test]
    fn strace_drops_payload_to_unprivileged_user() {
        let cmd = strace_install_command(
            "npm",
            "left-pad@1.3.0",
            Some("/out/gyrseek_trace_0.log"),
            300,
        );
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
            300,
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
        let cmd = strace_install_command(
            "pnpm",
            "left-pad@1.3.0",
            Some("/out/gyrseek_trace_0.log"),
            300,
        );
        assert!(cmd.contains("pnpm add 'left-pad@1.3.0' --dir /work --lockfile=false"));
    }

    #[test]
    fn pnpm_non_prebuilt_image_enables_pnpm() {
        let script = build_matrix_script(
            "pnpm",
            &[("left-pad".to_string(), "1.3.0".to_string())],
            false,
            300,
        );
        assert!(script.contains("corepack enable pnpm"));
        assert!(script.contains("pnpm add"));
    }

    #[test]
    fn docker_args_keep_out_mount_when_provided_and_omit_when_empty() {
        let with_out = build_docker_run_args("img:latest", "/tmp/out", "echo hi", false)
            .expect("docker args should build");
        assert!(with_out.iter().any(|a| a == "/tmp/out:/out"));
        assert!(with_out.iter().any(|a| a == "no-new-privileges"));

        let without_out = build_docker_run_args("img:latest", "", "echo hi", false)
            .expect("docker args should build");
        assert!(!without_out.iter().any(|a| a.ends_with(":/out")));
    }

    #[test]
    fn docker_args_memory_limit_defaults_to_2g_and_is_configurable() {
        {
            let _env = SandboxEnvVarGuard::remove("GYRSEEK_MEM_LIMIT");
            let args = build_docker_run_args("img:latest", "/tmp/out", "echo hi", false)
                .expect("docker args should build");
            let mem_pos = args
                .iter()
                .position(|a| a == "--memory")
                .expect("--memory flag present");
            assert_eq!(args.get(mem_pos + 1).map(String::as_str), Some("2g"));
            assert!(args.iter().any(|a| a == "/work:rw,noexec,nosuid,size=2g"));
        }

        {
            let _guard = SandboxEnvVarGuard::set("GYRSEEK_MEM_LIMIT", "4g");
            let args_custom = build_docker_run_args("img:latest", "/tmp/out", "echo hi", false)
                .expect("docker args should build");
            let mem_pos_custom = args_custom
                .iter()
                .position(|a| a == "--memory")
                .expect("--memory flag present");
            assert_eq!(
                args_custom.get(mem_pos_custom + 1).map(String::as_str),
                Some("4g")
            );
            assert!(
                args_custom
                    .iter()
                    .any(|a| a == "/work:rw,noexec,nosuid,size=4g")
            );
        }
    }

    #[test]
    fn docker_args_grant_sys_ptrace_capability() {
        // strace -u drops the install to an unprivileged user; attaching across
        // UIDs needs CAP_SYS_PTRACE, which Docker does not grant by default.
        // Without this the sandbox can never produce a trace.

        let args = build_docker_run_args("img:latest", "/tmp/out", "echo hi", false)
            .expect("docker args should build");
        let pos = args
            .iter()
            .position(|a| a == "--cap-add")
            .expect("--cap-add flag present");
        assert_eq!(args.get(pos + 1).map(String::as_str), Some("SYS_PTRACE"));
    }

    #[test]
    fn docker_args_adds_seccomp_profile_by_default() {
        let args = build_docker_run_args("img:latest", "/tmp/out", "echo hi", false)
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
        let args = build_docker_run_args("img:latest", "/tmp/out", "echo hi", true)
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
        let _env = SandboxEnvVarGuard::remove("GYRSEEK_DOCKER_APPARMOR_PROFILE");

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
    }

    #[test]
    fn apparmor_disabled_wont_call_apparmor_parser() {
        let _env = SandboxEnvVarGuard::set("GYRSEEK_DOCKER_APPARMOR_PROFILE", "false");

        let result = docker_apparmor_profile_name();
        assert!(result.is_none(), "disabled profile should return None");
    }

    // --- #4 strace stderr must be captured, not discarded ---

    #[test]
    fn matrix_script_captures_strace_stderr_not_devnull() {
        let script = build_matrix_script(
            "npm",
            &[("left-pad".to_string(), "1.3.0".to_string())],
            true,
            300,
        );
        // strace's stderr must land in a per-probe error log so an attach
        // failure is diagnosable, never silently routed to /dev/null.
        assert!(
            script.contains("2>/gyrseek-trace/gyrseek_err_0.log"),
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
        assert!(steps0[1].contains("/gyrseek-trace/gyrseek_artifacts_0.log"));
        assert!(steps1[1].contains("/gyrseek-trace/gyrseek_artifacts_1.log"));
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
            300,
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
    fn every_probe_runs_under_the_configured_timeout() {
        let probes = [
            ("pkg-a".to_string(), "1.0.0".to_string()),
            ("pkg-b".to_string(), "2.0.0".to_string()),
        ];
        let matrix = build_matrix_script("pip", &probes, true, 45);
        assert_eq!(matrix.matches("timeout -k 5 45 strace -f").count(), 2);
        assert!(!matrix.contains("timeout -k 5 300"));
        let single = build_single_script("pip", "pkg-a", "1.0.0", true, 45);
        assert!(single.contains("timeout -k 5 45 strace -f"));
    }

    #[test]
    fn matrix_script_marks_a_timed_out_probe_and_keeps_going() {
        let script = build_matrix_script(
            "pip",
            &[("pkg-a".to_string(), "1.0.0".to_string())],
            true,
            45,
        );
        // Exit 124 or 137 (timeout, then SIGKILL) leaves a marker and kills the payload's leftovers; the
        // script must not exit, so sibling probes still run.
        assert!(script.contains("gyrseek_timeout_0.log"));
        assert!(script.contains(KILL_PAYLOAD_PROCESSES_STEP));
        assert!(KILL_PAYLOAD_PROCESSES_STEP.contains(SCANNER_USER));
        // The only `exit 124` is the cleanup's last resort, after ten kill passes.
        assert_eq!(script.matches("exit 124").count(), 1);
        assert!(script.contains("for _ in 1 2 3 4 5 6 7 8 9 10"));
        // The non-timeout path must still end in success so `set -e` does not abort.
        assert!(script.contains("; true; }"));
    }

    #[test]
    fn the_matrix_script_keeps_every_probe_log_in_a_root_only_directory_until_it_exits() {
        let probes = [
            ("pkg-a".to_string(), "1.0.0".to_string()),
            ("pkg-b".to_string(), "2.0.0".to_string()),
        ];
        let script = build_matrix_script("pip", &probes, true, 300);
        // The directory exists, is only for root and is published on exit, before any payload runs.
        let mkdir = script
            .find("mkdir -m 700 /gyrseek-trace")
            .expect("root-only directory");
        let trap = script
            .find(&format!("trap '{PUBLISH_TRACES_STEP}' EXIT"))
            .expect("publish on exit");
        let first_payload = script.find("strace").expect("first probe");
        assert!(mkdir < first_payload && trap < first_payload, "{script}");
        // The only mention of the bind mount is the publish step: the payload never has a log
        // there to rewrite, and a probe cannot reach an earlier probe's files.
        assert!(
            !script.replace(PUBLISH_TRACES_STEP, "").contains("/out"),
            "{script}"
        );
        // Publishing empties /out first (a payload may have planted a symlink there) and never
        // fails the script.
        let wipe = PUBLISH_TRACES_STEP
            .find("find /out -mindepth 1 -delete")
            .expect("wipe");
        let copy = PUBLISH_TRACES_STEP
            .find("cp /gyrseek-trace/* /out/")
            .expect("copy");
        assert!(wipe < copy && PUBLISH_TRACES_STEP.ends_with("; true"));
        // The AppArmor profile lets root use the directory.
        assert!(EMBEDDED_APPARMOR_PROFILE_TEXT.contains("/gyrseek-trace/** rwk"));
    }

    /// A payload that tries every way to rewrite what was recorded: write, truncate, delete and
    /// replace by a symlink, in the bind mount, in the trace directory and in an earlier probe's file.
    const TAMPERING_PAYLOAD: &str = r#"sh -c 'echo FORGED >> /out/gyrseek_trace_0.log; echo FORGED > /out/gyrseek_trace_1.log; ln -s /etc/hostname /out/gyrseek_err_1.log; : > /out/gyrseek_artifacts_0.log; rm -f /out/gyrseek_trace_0.log; echo FORGED >> /gyrseek-trace/gyrseek_trace_0.log; : > /gyrseek-trace/gyrseek_trace_1.log; rm -f /gyrseek-trace/gyrseek_trace_0.log; rm -rf /gyrseek-trace; ls /gyrseek-trace; echo tamper-attempted'"#;

    /// Needs Docker and the network (the image's strace comes from apt): run it with
    /// `just test-trace-integrity`, which CI does in a Docker job. FIXED #411: on Docker Desktop
    /// for macOS the payload could rewrite or delete a trace kept in the bind mount.
    #[test]
    #[ignore = "needs Docker; run with `just test-trace-integrity`"]
    fn a_payload_cannot_tamper_with_its_own_or_another_probes_trace() {
        let image =
            crate::runtime_image::select_for_manager("pip", None, None, std::path::Path::new("."))
                .image;
        let probes = vec![
            ("benign".to_string(), "1.0.0".to_string()),
            ("evil".to_string(), "1.0.0".to_string()),
            ("failing".to_string(), "1.0.0".to_string()),
            ("slow".to_string(), "1.0.0".to_string()),
        ];
        // A short limit so the slow probe times out; the others finish well inside it.
        let script = super::build_matrix_script_with("pip", &probes, false, 10, &|spec| {
            if spec.contains("evil") {
                TAMPERING_PAYLOAD.to_string()
            } else if spec.contains("failing") {
                "sh -c 'echo boom >&2; exit 7'".to_string()
            } else if spec.contains("slow") {
                "sh -c 'sleep 120'".to_string()
            } else {
                "sh -c 'echo benign-marker'".to_string()
            }
        });
        let out = tempfile::tempdir().unwrap();
        let args =
            super::build_docker_run_args(&image, &out.path().to_string_lossy(), &script, false)
                .unwrap();
        let output = std::process::Command::new("docker")
            .args(&args)
            .output()
            .expect("docker");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );

        let read = |name: &str| {
            std::fs::read_to_string(out.path().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
        };
        // strace writes every string as `\xNN` escapes (`-xx`), so look for both spellings.
        let seen = |trace: &str, text: &str| {
            let hex: String = text.bytes().map(|b| format!("\\x{b:02x}")).collect();
            trace.contains(text) || trace.contains(&hex)
        };
        let benign = read("gyrseek_trace_0.log");
        assert!(
            seen(&benign, "benign-marker"),
            "the benign probe's trace is intact: {benign}"
        );
        assert!(
            !seen(&benign, "FORGED"),
            "a later payload wrote into an earlier probe's trace: {benign}"
        );
        let evil = read("gyrseek_trace_1.log");
        assert!(
            !evil.starts_with("FORGED"),
            "the payload replaced its own trace: {evil}"
        );
        assert!(
            seen(&evil, "tamper-attempted"),
            "the payload's own actions are recorded: {evil}"
        );
        assert!(
            seen(&evil, "/gyrseek-trace"),
            "the attempts on the trace directory are recorded: {evil}"
        );
        for entry in std::fs::read_dir(out.path()).unwrap() {
            let entry = entry.unwrap();
            assert!(
                !entry.file_type().unwrap().is_symlink(),
                "{:?} is a symlink the payload planted",
                entry.file_name()
            );
        }
        assert!(
            out.path().join("gyrseek_artifacts_0.log").exists(),
            "every probe's artifact log is published"
        );
        // What the other probes left (exit code, timeout marker, trace) travels the same way.
        assert_eq!(
            read("gyrseek_rc_2.log").trim(),
            "7",
            "a failed install's exit code is published"
        );
        assert!(
            out.path().join("gyrseek_timeout_3.log").exists(),
            "a timed-out probe's marker is published"
        );
        assert!(
            !out.path().join("gyrseek_rc_0.log").exists(),
            "a probe whose install succeeded leaves no exit-code file"
        );
    }

    #[test]
    fn matrix_script_saves_the_exit_code_of_a_failed_install() {
        let script = build_matrix_script(
            "pip",
            &[("pkg-a".to_string(), "1.0.0".to_string())],
            true,
            45,
        );
        // Only a non-timeout failure writes the exit-code file the host reads.
        assert!(script.contains("echo $rc > /gyrseek-trace/gyrseek_rc_0.log"));
        assert!(script.contains("; else echo $rc"));
    }

    #[test]
    fn install_output_tail_is_printable_and_drops_strace_noise() {
        let raw = "strace: Process 12 attached\n\x1b[31merror: build failed\x1b[0m\n\nstrace: Process 13 attached\nhint: use a compiler\n";
        let tail = install_output_tail(raw);
        assert_eq!(tail, "[31merror: build failed[0m\nhint: use a compiler");
        assert!(!tail.contains('\x1b'));
        let many: String = (0..40).map(|i| format!("line {i}\n")).collect();
        let tail = install_output_tail(&many);
        assert_eq!(tail.lines().count(), 15);
        assert!(tail.ends_with("line 39"));
    }

    #[test]
    fn install_failure_output_is_read_from_the_end_of_a_huge_log() {
        let dir = tempfile::tempdir().unwrap();
        let mut f = std::fs::File::create(dir.path().join("gyrseek_err_0.log")).unwrap();
        for i in 0..40_000 {
            std::io::Write::write_all(&mut f, format!("noise line {i}\n").as_bytes()).unwrap();
        }
        std::io::Write::write_all(&mut f, b"error: the real failure\n").unwrap();
        drop(f);
        std::fs::write(dir.path().join("gyrseek_rc_0.log"), "1\n").unwrap();
        let big = std::fs::metadata(dir.path().join("gyrseek_err_0.log"))
            .unwrap()
            .len();
        assert!(
            big > 4 * INSTALL_OUTPUT_READ_BYTES,
            "the fixture must dwarf the read limit"
        );
        let tail = read_file_tail(&dir.path().join("gyrseek_err_0.log")).unwrap();
        assert!(
            tail.len() as u64 <= INSTALL_OUTPUT_READ_BYTES + 4,
            "{}",
            tail.len()
        );
        let failure = read_install_failure(dir.path(), 0).unwrap();
        assert!(
            failure.output.ends_with("error: the real failure"),
            "{}",
            failure.output
        );
        assert_eq!(failure.output.lines().count(), 15);
    }

    // ---- collect_probe_traces: what the container script leaves behind -------------------

    fn probe(name: &str, version: &str) -> (String, String) {
        (name.to_string(), version.to_string())
    }

    fn put(dir: &std::path::Path, file: &str, content: &str) {
        std::fs::write(dir.join(file), content).unwrap();
    }

    fn no_retry(_: &str, _: &str) -> Result<String, String> {
        panic!("the probe's trace was present, so it must not be re-run");
    }

    #[test]
    fn collects_each_probes_trace_in_order_and_appends_the_artifact_inventory() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        put(d, "gyrseek_trace_0.log", "execve(\"/bin/a\") = 0\n");
        put(d, "gyrseek_trace_1.log", "execve(\"/bin/b\") = 0\n");
        put(d, "gyrseek_artifacts_1.log", "  /work/x\0\0\0  \n");
        let probes = [probe("a", "1.0.0"), probe("b", "2.0.0")];
        let got = collect_probe_traces(d, &probes, 300, &no_retry).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].probe, probe("a", "1.0.0"));
        assert_eq!(got[0].trace, "execve(\"/bin/a\") = 0\n");
        assert!(got[0].install_failure.is_none());
        assert_eq!(got[1].probe, probe("b", "2.0.0"));
        assert!(
            got[1].trace.contains("=== gyrseek_artifacts ===\n/work/x"),
            "{}",
            got[1].trace
        );
    }

    #[test]
    fn empty_or_whitespace_artifact_inventories_add_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        put(d, "gyrseek_trace_0.log", "trace\n");
        put(d, "gyrseek_artifacts_0.log", " \n\n");
        let got = collect_probe_traces(d, &[probe("a", "1")], 300, &no_retry).unwrap();
        assert_eq!(got[0].trace, "trace\n");
    }

    #[test]
    fn a_missing_or_blank_batch_trace_is_re_run_on_its_own() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        put(d, "gyrseek_trace_1.log", "  \n"); // blank
        let probes = [probe("a", "1.0.0"), probe("b", "2.0.0")];
        let calls = std::cell::RefCell::new(Vec::new());
        let retry = |p: &str, v: &str| -> Result<String, String> {
            calls.borrow_mut().push(format!("{p}@{v}"));
            Ok(format!("retried {p}\n"))
        };
        let got = collect_probe_traces(d, &probes, 300, &retry).unwrap();
        assert_eq!(*calls.borrow(), ["a@1.0.0", "b@2.0.0"]);
        assert_eq!(got[0].trace, "retried a\n");
        assert_eq!(got[1].trace, "retried b\n");
    }

    #[test]
    fn a_failed_re_run_is_an_error_not_a_clean_scan() {
        let dir = tempfile::tempdir().unwrap();
        let retry = |_: &str, _: &str| -> Result<String, String> { Err("docker exploded".into()) };
        let err = collect_probe_traces(dir.path(), &[probe("a", "1")], 300, &retry).unwrap_err();
        assert!(err.contains("docker exploded"), "{err}");
    }

    #[test]
    fn a_blank_trace_even_after_the_re_run_fails_closed_with_the_strace_error() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        put(
            d,
            "gyrseek_err_0.log",
            "strace: ptrace(PTRACE_SEIZE): Operation not permitted\n",
        );
        let retry = |_: &str, _: &str| -> Result<String, String> { Ok("  \n".into()) };
        let err = collect_probe_traces(d, &[probe("a", "1.0.0")], 300, &retry).unwrap_err();
        assert!(err.contains("empty trace for 'a@1.0.0'"), "{err}");
        assert!(err.contains("Operation not permitted"), "{err}");
    }

    #[test]
    fn a_timed_out_probe_is_omitted_and_never_re_run() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        put(d, "gyrseek_trace_0.log", "partial trace\n"); // exists, but the marker wins
        put(d, "gyrseek_timeout_0.log", "");
        put(d, "gyrseek_trace_1.log", "good\n");
        let probes = [probe("slow", "1.0.0"), probe("fast", "1.0.0")];
        let got = collect_probe_traces(d, &probes, 300, &no_retry).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].probe, probe("fast", "1.0.0"));
    }

    #[test]
    fn when_every_probe_timed_out_the_batch_is_an_error_naming_them() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        put(d, "gyrseek_timeout_0.log", "");
        put(d, "gyrseek_timeout_1.log", "");
        let probes = [probe("a", "1.0.0"), probe("b", "2.0.0")];
        let err = collect_probe_traces(d, &probes, 45, &no_retry).unwrap_err();
        assert!(err.contains("a@1.0.0") && err.contains("b@2.0.0"), "{err}");
        assert!(err.contains("probe_timeout_seconds=45"), "{err}");
    }

    #[test]
    fn an_exit_code_file_marks_only_that_probe_as_a_failed_install() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        put(d, "gyrseek_trace_0.log", "t0\n");
        put(d, "gyrseek_trace_1.log", "t1\n");
        put(d, "gyrseek_rc_1.log", "2\n");
        put(
            d,
            "gyrseek_err_1.log",
            "strace: Process 7 attached\nerror: no solution\n",
        );
        let probes = [probe("ok", "1"), probe("bad", "1")];
        let got = collect_probe_traces(d, &probes, 300, &no_retry).unwrap();
        assert!(got[0].install_failure.is_none());
        let failure = got[1].install_failure.as_ref().expect("probe 1 failed");
        assert_eq!(failure.exit_code, 2);
        assert_eq!(failure.output, "error: no solution");
    }

    #[test]
    fn files_are_matched_to_probes_by_index_beyond_nine() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let probes: Vec<_> = (0..13).map(|i| probe(&format!("p{i}"), "1")).collect();
        for i in 0..13 {
            put(
                d,
                &format!("gyrseek_trace_{i}.log"),
                &format!("trace of p{i}\n"),
            );
        }
        put(d, "gyrseek_timeout_11.log", "");
        put(d, "gyrseek_rc_12.log", "1\n");
        let got = collect_probe_traces(d, &probes, 300, &no_retry).unwrap();
        assert_eq!(got.len(), 12, "probe 11 timed out");
        assert!(
            got.iter()
                .all(|g| g.trace == format!("trace of {}\n", g.probe.0))
        );
        assert!(
            got.iter()
                .find(|g| g.probe.0 == "p1")
                .unwrap()
                .install_failure
                .is_none()
        );
        assert!(
            got.iter()
                .find(|g| g.probe.0 == "p12")
                .unwrap()
                .install_failure
                .is_some()
        );
        assert!(got.iter().all(|g| g.probe.0 != "p11"));
    }

    #[test]
    fn no_probes_means_no_results() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            collect_probe_traces(dir.path(), &[], 300, &no_retry)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn timeout_exit_codes_cover_term_and_kill_only() {
        for (code, expected) in [
            (Some(124), true),
            (Some(137), true),
            (Some(0), false),
            (Some(1), false),
            (Some(143), false),
            (None, false),
        ] {
            assert_eq!(is_timeout_exit(code), expected, "{code:?}");
        }
    }

    #[test]
    fn custom_scanner_images_are_named_in_the_description() {
        use crate::runtime_image::ImageChoice;
        let runner = DockerRunner {
            danger_disable_seccomp: false,
            probe_timeout_secs: 300,
            image: ImageChoice {
                image: "python:3.12-slim-bookworm@sha256:x".into(),
                description: "Python 3.12 (from .python-version)".into(),
            },
        };
        let _lock = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var("GYRSEEK_PY_SCANNER_IMAGE").ok();
        // SAFETY: the env lock serialises every test that touches this variable.
        unsafe { std::env::remove_var("GYRSEEK_PY_SCANNER_IMAGE") };
        assert_eq!(
            runner.sandbox_description("uv").as_deref(),
            Some("Python 3.12 (from .python-version)")
        );
        unsafe { std::env::set_var("GYRSEEK_PY_SCANNER_IMAGE", "myorg/py@sha256:y") };
        assert_eq!(
            runner.sandbox_description("pip").as_deref(),
            Some("your custom image myorg/py@sha256:y")
        );
        // The npm variable is separate: the Python override does not describe an npm run.
        assert_ne!(
            runner.sandbox_description("npm").as_deref(),
            Some("your custom image myorg/py@sha256:y")
        );
        unsafe {
            match prev {
                Some(v) => std::env::set_var("GYRSEEK_PY_SCANNER_IMAGE", v),
                None => std::env::remove_var("GYRSEEK_PY_SCANNER_IMAGE"),
            }
        }
    }

    #[test]
    fn shell_quoting_neutralises_quotes_and_metacharacters() {
        assert_eq!(super::shell_single_quoted("plain"), "'plain'");
        assert_eq!(super::shell_single_quoted("it's"), "'it'\"'\"'s'");
        for nasty in [
            "a; rm -rf /",
            "$(id)",
            "`id`",
            "a && b",
            "a\nb",
            "a b",
            "$HOME",
            "*",
            "\"q\"",
        ] {
            let quoted = super::shell_single_quoted(nasty);
            assert!(
                quoted.starts_with('\'') && quoted.ends_with('\''),
                "{nasty}"
            );
            // Nothing inside the quotes can end them except the escaped form of `'`.
            assert_eq!(
                quoted[1..quoted.len() - 1].matches('\'').count(),
                0,
                "{nasty}"
            );
        }
    }

    #[test]
    fn matrix_script_for_many_probes_numbers_every_file_and_quotes_the_spec() {
        let probes: Vec<_> = (0..12)
            .map(|i| (format!("pkg{i}"), format!("1.0.{i}")))
            .collect();
        let script = build_matrix_script("pip", &probes, true, 300);
        for i in 0..12 {
            for stem in [
                "gyrseek_trace",
                "gyrseek_err",
                "gyrseek_artifacts",
                "gyrseek_rc",
                "gyrseek_timeout",
            ] {
                assert!(
                    script.contains(&format!("/gyrseek-trace/{stem}_{i}.log")),
                    "{stem}_{i}"
                );
            }
            assert!(script.contains(&format!("'pkg{i}==1.0.{i}'")), "probe {i}");
        }
        assert_eq!(script.matches(WORK_RESET_STEP).count(), 12);
        // An empty batch is an empty install section, not a crash.
        let empty = build_matrix_script("npm", &[], true, 300);
        assert!(!empty.contains("strace"));
    }

    #[test]
    fn scripts_differ_by_manager_but_always_drop_privileges_and_set_the_timeout() {
        for manager in ["pip", "uv", "poetry", "npm", "pnpm"] {
            let script = build_matrix_script(manager, &[("p".into(), "1.0.0".into())], true, 77);
            assert!(script.contains("timeout -k 5 77 strace"), "{manager}");
            assert!(script.contains("-u gyrseek"), "{manager}");
            assert!(script.contains("-xx"), "{manager}");
        }
        let npm = build_matrix_script("npm", &[("p".into(), "1.0.0".into())], true, 5);
        assert!(
            npm.contains("npm install 'p@1.0.0'") && npm.contains("--no-save"),
            "{npm}"
        );
        let pnpm = build_matrix_script("pnpm", &[("p".into(), "1.0.0".into())], true, 5);
        assert!(
            pnpm.contains("pnpm add 'p@1.0.0'") && pnpm.contains("--lockfile=false"),
            "{pnpm}"
        );
        let py = build_matrix_script("uv", &[("p".into(), "1.0.0".into())], true, 5);
        assert!(py.contains("uv pip install 'p==1.0.0'"), "{py}");
        // Prebuilt images skip the runtime apt setup; others run it.
        assert!(!py.contains("apt-get"));
        assert!(
            build_matrix_script("uv", &[("p".into(), "1".into())], false, 5).contains("apt-get")
        );
    }

    #[test]
    fn read_install_failure_needs_the_exit_code_marker() {
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::write(dir.path().join("gyrseek_err_0.log"), "error: boom\n").unwrap();
        assert!(read_install_failure(dir.path(), 0).is_none());
        std::fs::write(dir.path().join("gyrseek_rc_0.log"), "2\n").unwrap();
        let failure = read_install_failure(dir.path(), 0).expect("failure");
        assert_eq!(failure.exit_code, 2);
        assert_eq!(failure.output, "error: boom");
        // An unreadable marker still counts as a failure.
        std::fs::write(dir.path().join("gyrseek_rc_1.log"), "??").unwrap();
        assert_eq!(read_install_failure(dir.path(), 1).unwrap().exit_code, -1);
    }

    #[test]
    fn timeout_message_names_the_probe_and_the_setting() {
        let msg = probe_timeout_message(300, "left-pad", "1.3.0");
        assert!(msg.contains("left-pad@1.3.0"));
        assert!(msg.contains("probe_timeout_seconds=300"));
        // The message tells the operator how to raise the limit, with a larger example.
        assert!(msg.contains("gyrseek.yaml"));
        assert!(msg.contains("probe_timeout_seconds: 600"));
    }

    #[test]
    fn matrix_script_wipes_work_between_probes_after_the_artifact_scan() {
        let script = build_matrix_script(
            "pip",
            &[
                ("pkg-a".to_string(), "1.0.0".to_string()),
                ("pkg-b".to_string(), "2.0.0".to_string()),
            ],
            true,
            300,
        );
        let scan0 = script.find("gyrseek_artifacts_0.log").expect("artifacts 0");
        let install1 = script.find("gyrseek_trace_1.log").expect("trace 1");
        let wipe = script.find(WORK_RESET_STEP).expect("work reset step");
        assert!(wipe > scan0, "wipe must come after probe 0's artifact scan");
        assert!(wipe < install1, "wipe must come before probe 1's install");
        assert_eq!(script.matches(WORK_RESET_STEP).count(), 2);
        assert!(
            !WORK_RESET_STEP.contains("/out"),
            "the wipe must never touch the trace logs"
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
        let mut found_pidfd_open = false;
        let mut found_pidfd_getfd = false;

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
                            "pidfd_open" => found_pidfd_open = true,
                            "pidfd_getfd" => found_pidfd_getfd = true,
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
        assert!(found_pidfd_open, "pidfd_open must be blocked");
        assert!(found_pidfd_getfd, "pidfd_getfd must be blocked");
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
        let protected_args = build_docker_run_args(image, "", &command_str, false).unwrap();

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

    #[test]
    fn test_sandbox_max_processes_env_fallback() {
        let _guard = SandboxEnvVarGuard::set_many(&[
            ("GYRSEEK_MAX_PROCESSES", ""),
            ("GYRSEEK_PIDS_LIMIT", "512"),
        ]);
        assert_eq!(sandbox_max_processes(), "512");
    }

    /// Writes an executable `#!/bin/sh` script `name` with `body` into `dir`.
    #[cfg(unix)]
    fn write_fake_exe(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[test]
    #[cfg(unix)]
    fn docker_preflight_distinguishes_daemon_down_permission_and_broken_cli() {
        let dir = tempfile::tempdir().unwrap();
        let ok = write_fake_exe(dir.path(), "ok", "exit 0");
        assert!(super::docker_preflight(&ok.to_string_lossy(), "linux").is_ok());

        let down = write_fake_exe(
            dir.path(),
            "down",
            r#"case "$1" in --version) exit 0;; info) echo "Cannot connect to the Docker daemon. Is the docker daemon running?" >&2; exit 1;; esac"#,
        );
        let err = super::docker_preflight(&down.to_string_lossy(), "macos").expect_err("down");
        assert!(
            err.contains("Start Docker Desktop") && err.contains("Cannot connect"),
            "{err}"
        );

        let denied = write_fake_exe(
            dir.path(),
            "denied",
            r#"case "$1" in --version) exit 0;; info) echo "permission denied while trying to connect to the Docker daemon socket" >&2; exit 1;; esac"#,
        );
        let err = super::docker_preflight(&denied.to_string_lossy(), "linux").expect_err("denied");
        assert!(err.contains("`docker` group"), "{err}");

        let broken = write_fake_exe(dir.path(), "broken", "exit 3");
        let err = super::docker_preflight(&broken.to_string_lossy(), "linux").expect_err("broken");
        assert!(err.contains("looks broken"), "{err}");
    }

    #[test]
    fn docker_preflight_reports_missing_cli() {
        let err =
            super::docker_preflight("gyrseek-no-such-docker-binary", "macos").expect_err("missing");
        assert!(err.contains("not installed"), "{err}");
        assert!(err.contains("Install Docker"), "{err}");
    }

    #[test]
    fn docker_daemon_error_message_is_actionable_per_cause() {
        let down = "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?";
        let mac = super::docker_daemon_error_message(down, "macos");
        assert!(
            mac.contains("Docker Desktop") && mac.contains("Cannot connect"),
            "{mac}"
        );
        let linux = super::docker_daemon_error_message(down, "linux");
        assert!(linux.contains("systemctl start docker"), "{linux}");

        let denied = "permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock";
        assert!(super::docker_daemon_error_message(denied, "linux").contains("`docker` group"));

        assert!(super::docker_daemon_error_message("", "linux").contains("no error output"));
    }

    #[test]
    fn no_sandbox_builds_the_host_runner_without_docker() {
        assert!(
            build_runner_from_env(
                false,
                true,
                300,
                crate::runtime_image::select_for_manager(
                    "uv",
                    None,
                    None,
                    std::path::Path::new("/nonexistent"),
                )
            )
            .is_ok()
        );
    }
}
