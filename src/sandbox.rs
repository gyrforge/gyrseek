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
    trace_limit: Option<String>,
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
            trace_limit,
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
    /// `trace_limit` from the config; `GYRSEEK_TRACE_LIMIT` overrides it.
    trace_limit: Option<String>,
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
            &sandbox_trace_limit(self.trace_limit.as_deref()),
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

/// Size of the root-only tmpfs that holds one probe's logs, and so the largest trace gyrseek
/// accepts for a probe. Traces seen in practice are a few MB (an npm install) to about 40 MB (a
/// failing source build of a large Python package); the tmpfs counts against the container's
/// memory limit (so a limit near `GYRSEEK_MEM_LIMIT` can get a flooding probe OOM-killed instead of
/// blocked on its own). A probe that fills it is blocked, not scanned from a partial trace.
pub(crate) const DEFAULT_TRACE_LIMIT: &str = "1024m";

/// A valid size: `256m`, `1g`, `65536k` (or a plain number of bytes), greater than zero.
pub(crate) fn is_valid_trace_limit(size: &str) -> bool {
    size_to_bytes(size.trim()).is_some_and(|b| b > 0)
}

/// The trace limit in effect: `GYRSEEK_TRACE_LIMIT` when it is set to a valid size, otherwise
/// `trace_limit` from `gyrseek.yaml` (`configured`, already validated), otherwise the default.
/// A value in the environment that is not a size is ignored with a warning.
pub(crate) fn sandbox_trace_limit(configured: Option<&str>) -> String {
    let fallback = || {
        configured
            .map(str::trim)
            .filter(|c| is_valid_trace_limit(c))
            .unwrap_or(DEFAULT_TRACE_LIMIT)
            .to_string()
    };
    match std::env::var("GYRSEEK_TRACE_LIMIT") {
        Ok(v) if is_valid_trace_limit(&v) => v.trim().to_string(),
        Ok(v) if !v.trim().is_empty() => {
            let used = fallback();
            eprintln!(
                "⚠️ [gyrseek] Ignoring GYRSEEK_TRACE_LIMIT='{v}': it must be a size such as 256m, 1g or 65536k. Using {used}."
            );
            used
        }
        _ => fallback(),
    }
}

/// `256m` -> bytes (`k`, `m`, `g` suffixes, or a plain number of bytes).
fn size_to_bytes(size: &str) -> Option<u64> {
    let size = size.trim().to_ascii_lowercase();
    let (digits, unit) = match size.chars().last()? {
        'k' => (&size[..size.len() - 1], 1024),
        'm' => (&size[..size.len() - 1], 1024 * 1024),
        'g' => (&size[..size.len() - 1], 1024 * 1024 * 1024),
        _ => (size.as_str(), 1),
    };
    digits.parse::<u64>().ok()?.checked_mul(unit)
}

/// A name for the container, so a run that has to be abandoned can be stopped with `docker kill`.
fn container_name() -> String {
    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!(
        "gyrseek-probe-{}-{}-{nanos}",
        std::process::id(),
        COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    )
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
    trace_limit: &str,
    default_image: &str,
) -> Result<Vec<ProbeTrace>, String> {
    if probes.is_empty() {
        return Ok(Vec::new());
    }

    let image_config = scanner_image_config(manager, default_image);

    // Where the files that the container streams out are written; the container itself gets no
    // host mount at all.
    let out_dir = tempfile::tempdir().map_err(|e| format!("failed to create temp dir: {e}"))?;

    let script = build_matrix_script(manager, probes, image_config.prebuilt, probe_timeout_secs);
    let name = container_name();
    let args = build_docker_run_args(
        &image_config.image,
        &script,
        danger_disable_seccomp,
        Some(trace_limit),
        &name,
    )?;

    let file_cap = size_to_bytes(trace_limit).unwrap_or(0) + MAX_FRAME_SLACK_BYTES;
    let (code, stderr) = run_matrix_container(&args, &name, out_dir.path(), file_cap)?;

    if code == Some(124) {
        // Only the cleanup after a timed-out probe exits 124 (see KILL_PAYLOAD_PROCESSES_STEP).
        return Err(format!(
            "a probe exceeded probe_timeout_seconds={probe_timeout_secs} and left processes running that could not be stopped, so the whole batch was aborted"
        ));
    }

    if code != Some(0) {
        return Err(format!(
            "docker sandbox command failed (exit code: {}).\nstderr:\n{}",
            code.unwrap_or(-1),
            stderr,
        ));
    }

    collect_probe_traces(out_dir.path(), probes, probe_timeout_secs, trace_limit)
}

/// Allowed growth of a decoded file beyond the tmpfs size (the tmpfs counts pages, not bytes).
const MAX_FRAME_SLACK_BYTES: u64 = 1024 * 1024;
/// The longest line accepted inside a frame (base64 lines are 76 characters).
const MAX_FRAME_LINE_BYTES: usize = 1024;
/// How much of docker's own stderr is kept for an error message.
const DOCKER_STDERR_KEEP_BYTES: u64 = 256 * 1024;

/// Runs the matrix container and writes the files it streams out into `out_dir`. Returns the exit
/// code and the head of docker's stderr. A stream that cannot be trusted (a malformed or
/// truncated frame, a file over `file_cap`) stops the container and is an error.
fn run_matrix_container(
    args: &[String],
    name: &str,
    out_dir: &std::path::Path,
    file_cap: u64,
) -> Result<(Option<i32>, String), String> {
    use std::io::Read;
    let mut child = Command::new("docker")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to execute docker sandbox: {e}"))?;
    let stdout = child.stdout.take().expect("piped stdout");
    let mut stderr = child.stderr.take().expect("piped stderr");
    let stderr_reader = std::thread::spawn(move || {
        let mut kept = Vec::new();
        let _ = (&mut stderr)
            .take(DOCKER_STDERR_KEEP_BYTES)
            .read_to_end(&mut kept);
        let _ = std::io::copy(&mut stderr, &mut std::io::sink());
        String::from_utf8_lossy(&kept).to_string()
    });

    let parsed = read_frames(std::io::BufReader::new(stdout), out_dir, file_cap);
    if parsed.is_err() {
        // Stop the container, not just the client: `docker run` leaves it running otherwise.
        let _ = Command::new("docker").args(["kill", name]).output();
        let _ = child.kill();
    }
    let status = child
        .wait()
        .map_err(|e| format!("failed to wait for docker: {e}"))?;
    let stderr = stderr_reader.join().unwrap_or_default();
    parsed?;
    Ok((status.code(), stderr))
}

/// The container's stdout as the matrix script writes it (see `TRACE_FUNCTIONS`): files framed
/// as `GYRSEEK-FILE <name>`, base64 lines, `GYRSEEK-END`, and `GYRSEEK-LIMIT <idx>` for a probe
/// whose logs did not fit. Everything else is ordinary container output and is ignored. Every file
/// is written into `out_dir` under a name checked against what the script can produce, never
/// larger than `file_cap`, and a frame that does not end is an error: a partial trace must not be
/// read as a whole one.
fn read_frames(
    mut reader: impl std::io::BufRead,
    out_dir: &std::path::Path,
    file_cap: u64,
) -> Result<(), String> {
    use std::io::Write;
    let mut current: Option<(std::fs::File, u64)> = None;
    let mut line = Vec::new();
    loop {
        line.clear();
        let n = read_line_capped(&mut reader, &mut line, MAX_FRAME_LINE_BYTES)
            .map_err(|e| format!("cannot read the sandbox output: {e}"))?;
        if n == LineRead::End {
            break;
        }
        let too_long = n == LineRead::TooLong;
        while matches!(line.last(), Some(b'\n' | b'\r')) {
            line.pop();
        }
        if let Some((file, written)) = current.as_mut() {
            if too_long {
                return Err("a line of the sandbox output is too long to be a trace".to_string());
            }
            if line == b"GYRSEEK-END" {
                current = None;
                continue;
            }
            let bytes = base64_decode(&line)
                .ok_or("the sandbox output holds a malformed trace file".to_string())?;
            *written += bytes.len() as u64;
            if *written > file_cap {
                return Err(format!(
                    "a trace file from the sandbox is larger than the {file_cap} bytes allowed"
                ));
            }
            file.write_all(&bytes)
                .map_err(|e| format!("cannot write a trace file: {e}"))?;
        } else if let Some(name) = line.strip_prefix(b"GYRSEEK-FILE ") {
            let name = std::str::from_utf8(name).unwrap_or("");
            if !is_probe_file_name(name) {
                return Err(format!(
                    "the sandbox output names an unexpected file '{name}'"
                ));
            }
            let file = std::fs::File::create(out_dir.join(name))
                .map_err(|e| format!("cannot create {name}: {e}"))?;
            current = Some((file, 0));
        } else if let Some(idx) = line.strip_prefix(b"GYRSEEK-LIMIT ") {
            let idx = std::str::from_utf8(idx).unwrap_or("");
            if idx.is_empty() || idx.len() > 6 || !idx.bytes().all(|b| b.is_ascii_digit()) {
                return Err("the sandbox output holds a malformed limit marker".to_string());
            }
            std::fs::write(out_dir.join(format!("gyrseek_limit_{idx}.log")), b"")
                .map_err(|e| format!("cannot write the limit marker: {e}"))?;
        }
    }
    if current.is_some() {
        return Err("the sandbox output ended inside a trace file".to_string());
    }
    Ok(())
}

/// `gyrseek_<kind>_<digits>.log` for the kinds the matrix script writes.
fn is_probe_file_name(name: &str) -> bool {
    let Some(rest) = name
        .strip_prefix("gyrseek_")
        .and_then(|r| r.strip_suffix(".log"))
    else {
        return false;
    };
    let Some((kind, idx)) = rest.split_once('_') else {
        return false;
    };
    ["trace", "err", "artifacts", "rc", "timeout"].contains(&kind)
        && !idx.is_empty()
        && idx.len() <= 6
        && idx.bytes().all(|b| b.is_ascii_digit())
}

#[derive(PartialEq, Eq, Debug)]
enum LineRead {
    End,
    Line,
    /// The line was longer than allowed; the rest of it has been skipped.
    TooLong,
}

/// Reads one line of at most `max` bytes (a longer one is skipped to its end, never buffered).
fn read_line_capped(
    reader: &mut impl std::io::BufRead,
    buf: &mut Vec<u8>,
    max: usize,
) -> std::io::Result<LineRead> {
    use std::io::{BufRead, Read};
    let n = reader
        .by_ref()
        .take(max as u64 + 1)
        .read_until(b'\n', buf)?;
    if n == 0 {
        return Ok(LineRead::End);
    }
    if buf.ends_with(b"\n") || buf.len() <= max {
        return Ok(LineRead::Line);
    }
    // Over the limit without a newline: discard the rest of the line.
    buf.clear();
    loop {
        let chunk = reader.fill_buf()?;
        if chunk.is_empty() {
            break;
        }
        match chunk.iter().position(|b| *b == b'\n') {
            Some(at) => {
                reader.consume(at + 1);
                break;
            }
            None => {
                let len = chunk.len();
                reader.consume(len);
            }
        }
    }
    Ok(LineRead::TooLong)
}

/// Standard base64 (padding required); `None` on any other character.
pub(crate) fn base64_decode(input: &[u8]) -> Option<Vec<u8>> {
    if !input.len().is_multiple_of(4) {
        return None;
    }
    let value = |c: u8| -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a') as u32 + 26),
            b'0'..=b'9' => Some((c - b'0') as u32 + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    for (i, quad) in input.chunks(4).enumerate() {
        let last = (i + 1) * 4 == input.len();
        let pad = quad.iter().rev().take_while(|c| **c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for c in &quad[..4 - pad] {
            n = (n << 6) | value(*c)?;
        }
        n <<= 6 * pad as u32;
        let bytes = n.to_be_bytes();
        out.extend_from_slice(&bytes[1..4 - pad]);
    }
    Some(out)
}

/// Reads what the container script left in `out_dir` for each probe: the trace, the
/// artifact inventory, an exit-code file for a failed install and a marker for a probe that
/// timed out or filled the trace tmpfs. A probe is never re-run (a second run would have its own
/// artifact inventory, and mixing the two would describe two different installs, FIXED #418): one
/// with no trace file is left out and named, one with a blank trace is an error.
fn collect_probe_traces(
    out_dir: &std::path::Path,
    probes: &[(String, String)],
    probe_timeout_secs: usize,
    trace_limit: &str,
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
        // A probe whose logs did not fit in the trace tmpfs has an incomplete trace: block it,
        // and do not retry it (it would fill the limit again).
        if out_dir.join(format!("gyrseek_limit_{}.log", idx)).exists() {
            let msg = trace_limit_message(trace_limit, package, version);
            eprintln!("⚠️ [gyrseek] {msg}");
            timed_out.push(msg);
            continue;
        }
        let trace_path = out_dir.join(format!("gyrseek_trace_{}.log", idx));
        // A probe that left no trace file at all (the install never reached strace) cannot be
        // scanned, but it says nothing about the other probes: leave it out so the scanner
        // blocks just that package, as for a timeout (FIXED #469).
        let mut trace = match std::fs::read_to_string(&trace_path) {
            Ok(trace) => trace,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let msg = trace_missing_message(package, version);
                eprintln!("⚠️ [gyrseek] {msg}");
                timed_out.push(msg);
                continue;
            }
            Err(_) => String::new(),
        };
        // A blank (or unreadable) trace means strace produced no data and MUST NOT be treated as
        // a clean zero-connection scan: fail closed, with strace's own error. Unlike a missing
        // file it points at ptrace not working at all, which affects every probe.
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

/// Unprivileged in-container user the untrusted install payload runs as. The
/// container itself runs as root so strace can own the trace logs in the root-only
/// `TRACE_DIR`, but `strace -u` drops the *traced* process to this user, which cannot enter
/// that directory, so a malicious package can't overwrite or delete its own trace.
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

fn trace_missing_message(package: &str, version: &str) -> String {
    format!(
        "sandbox probe for '{package}@{version}' left no trace file, so it cannot be scanned; treating it as a block. \
This is not expected: re-run the scan, and report it if it keeps happening"
    )
}

fn trace_limit_message(limit: &str, package: &str, version: &str) -> String {
    format!(
        "sandbox probe for '{package}@{version}' produced more than the trace limit of {limit} (GYRSEEK_TRACE_LIMIT), so its trace is incomplete; treating it as a block. \
A package that does this is very large or hostile: raise `trace_limit` in your gyrseek.yaml (or GYRSEEK_TRACE_LIMIT) only if you trust it"
    )
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

#[cfg(test)]
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
///
/// One `find` and one interpreter process inventory the whole tree (a `node_modules` of 10,000
/// files used to cost tens of thousands of processes, FIXED #24). The interpreter is the one the
/// package manager needs anyway, so a custom scanner image has it too: Python for pip, uv and
/// poetry, Node for npm and pnpm. The executable formats are recognised from the files' magic
/// bytes, because the scanner images have no `file` command: with the old per-file `file -b` the
/// type was always empty, so ELF, Mach-O and PE payloads and a dropped `bun` or `deno` were never
/// reported (FIXED #467). If the interpreter is missing or fails, the script stops with a message
/// (exit 126) instead of carrying on with an empty inventory, unless the trace tmpfs is full, in
/// which case the probe is reported as over the limit.
fn build_artifact_scan_steps(manager: &str, idx: usize) -> Vec<String> {
    let out = probe_file("artifacts", idx);
    let (find_interpreter, script, runtime) = if is_npm_family_manager(manager) {
        (
            "INTERP=$(command -v node || true)",
            format!("\"$INTERP\" -e '{ARTIFACT_INVENTORY_NODE}'"),
            "node",
        )
    } else {
        (
            "INTERP=$(command -v python3 || command -v python || true)",
            format!("\"$INTERP\" -c '{ARTIFACT_INVENTORY_PYTHON}'"),
            "python3 or python",
        )
    };
    vec![
        // Initialize/clear the artifact log for this probe. The trace tmpfs may be full by now
        // (the probe is then reported as over the limit), and the script runs under `set -e`.
        format!("{{ true > {out}; }} 2>/dev/null || true"),
        format!(
            "{find_interpreter}; \
             if [ -n \"$INTERP\" ] && find /work {OUTSIDE_WORK_DIRS} -type f -print0 2>/dev/null | {script} > {out} 2>/dev/null; \
             then true; elif gyrseek_full; then true; \
             else echo \"gyrseek: cannot inventory the installed files: the scanner image has no working {runtime}\" >&2; exit 126; fi"
        ),
    ]
}

/// Reads the NUL-separated file names `find` prints and writes one inventory line per file:
/// `path \0 size \0 type \0 content \n`. The type is `ELF …`, `Mach-O …` or `PE32[+] executable`
/// (what the classifier looks for) from the file's first bytes, empty otherwise; the content
/// (first 300 bytes, with `|`, NUL and line breaks replaced by spaces, trailing space trimmed) is
/// kept for `.pth` files only, the one place it is used. A line break in a path is replaced by
/// `?` so a file name cannot split its own record. It contains no single quote and no apostrophe:
/// the shell wraps it in single quotes. `ARTIFACT_INVENTORY_NODE` does the same in Node.
const ARTIFACT_INVENTORY_PYTHON: &str = r#"import os, struct, sys
def kind(f):
    try:
        with open(f, "rb") as h:
            b = h.read(64)
            if len(b) < 4:
                return ""
            m = b[:4]
            if m == b"\x7fELF":
                return "ELF %s-bit %s executable" % ("64" if b[4:5] == b"\x02" else "32", "MSB" if b[5:6] == b"\x02" else "LSB")
            if m in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
                return "Mach-O binary"
            if m == b"\xca\xfe\xba\xbe" and len(b) >= 8 and struct.unpack(">I", b[4:8])[0] < 45:
                return "Mach-O universal binary"
            if b[:2] == b"MZ" and len(b) >= 64:
                h.seek(struct.unpack("<I", b[60:64])[0])
                if h.read(4) == b"PE\0\0":
                    h.read(20)
                    opt = h.read(2)
                    if len(opt) == 2:
                        return "PE32+ executable" if struct.unpack("<H", opt)[0] == 0x20b else "PE32 executable"
    except (OSError, ValueError, struct.error):
        pass
    return ""
out = sys.stdout.buffer
for f in sys.stdin.buffer.read().split(b"\0"):
    if not f:
        continue
    try:
        size = os.stat(f).st_size
    except OSError:
        size = 0
    content = b""
    if f.endswith(b".pth"):
        try:
            with open(f, "rb") as h:
                content = h.read(300)
        except OSError:
            pass
        content = content.translate(bytes(32 if c in (0, 10, 13, 124) else c for c in range(256))).rstrip()
    out.write(f.replace(b"\n", b"?") + b"\0" + str(size).encode() + b"\0" + kind(f).encode() + b"\0" + content + b"\n")"#;

const ARTIFACT_INVENTORY_NODE: &str = r#"const fs = require("fs");
const data = fs.readFileSync("/dev/stdin");
const names = [];
for (let start = 0, i = 0; i < data.length; i++) {
  if (data[i] === 0) { if (i > start) names.push(data.subarray(start, i)); start = i + 1; }
}
function kind(f) {
  let fd;
  try {
    fd = fs.openSync(f, "r");
    const b = Buffer.alloc(64);
    const n = fs.readSync(fd, b, 0, 64, 0);
    if (n < 4) return "";
    const m = b.subarray(0, 4).toString("latin1");
    if (m === "\x7fELF") return "ELF " + (b[4] === 2 ? "64" : "32") + "-bit " + (b[5] === 2 ? "MSB" : "LSB") + " executable";
    if (["\xfe\xed\xfa\xce", "\xfe\xed\xfa\xcf", "\xce\xfa\xed\xfe", "\xcf\xfa\xed\xfe"].includes(m)) return "Mach-O binary";
    if (m === "\xca\xfe\xba\xbe" && n >= 8 && b.readUInt32BE(4) < 45) return "Mach-O universal binary";
    if (b[0] === 0x4d && b[1] === 0x5a && n >= 64) {
      const sig = Buffer.alloc(26);
      if (fs.readSync(fd, sig, 0, 26, b.readUInt32LE(60)) === 26 && sig.subarray(0, 4).toString("latin1") === "PE\0\0") {
        return sig.readUInt16LE(24) === 0x20b ? "PE32+ executable" : "PE32 executable";
      }
    }
  } catch (e) {
  } finally {
    if (fd !== undefined) { try { fs.closeSync(fd); } catch (e) {} }
  }
  return "";
}
const parts = [];
for (const f of names) {
  let size = 0;
  try { size = fs.statSync(f).size; } catch (e) {}
  let content = Buffer.alloc(0);
  if (f.length >= 4 && f.subarray(f.length - 4).toString("latin1") === ".pth") {
    try {
      const fd = fs.openSync(f, "r");
      const b = Buffer.alloc(300);
      content = Buffer.from(b.subarray(0, fs.readSync(fd, b, 0, 300, 0)));
      fs.closeSync(fd);
    } catch (e) {}
    for (let i = 0; i < content.length; i++) if ([0, 10, 13, 124].includes(content[i])) content[i] = 32;
    let end = content.length;
    while (end > 0 && [32, 9, 11, 12].includes(content[end - 1])) end--;
    content = content.subarray(0, end);
  }
  const path = Buffer.from(f);
  for (let i = 0; i < path.length; i++) if (path[i] === 10) path[i] = 63;
  parts.push(path, Buffer.from("\0" + size + "\0" + kind(f) + "\0"), content, Buffer.from("\n"));
}
process.stdout.write(Buffer.concat(parts));"#;

/// Where the matrix script keeps what each probe leaves behind (strace log, strace stderr,
/// artifact inventory, exit code, timeout marker) while that probe runs: a size-limited tmpfs that
/// only root can enter (`--tmpfs ... mode=700,size=<GYRSEEK_TRACE_LIMIT>`). The payload runs as
/// the scanner user, so it cannot read, change or delete it, on any platform, and it cannot fill
/// the host: nothing from the host is mounted into the container at all. (Logs in a bind-mounted
/// directory could be rewritten or deleted by the payload on Docker Desktop for macOS, FIXED #411,
/// and could fill the host's disk, FIXED #434 and #461.)
const TRACE_DIR: &str = "/gyrseek-trace";

/// `/gyrseek-trace/gyrseek_<kind>_<idx>.log`; the host rebuilds the same name from the stream.
fn probe_file(kind: &str, idx: usize) -> String {
    format!("{TRACE_DIR}/gyrseek_{kind}_{idx}.log")
}

/// How a probe's files leave the container: root prints each one on stdout as
/// `GYRSEEK-FILE <name>`, its base64 lines, `GYRSEEK-END`, then deletes it, so the tmpfs only ever
/// holds the probe that is running. Only root writes to stdout (the payload's own output goes to
/// /dev/null and its stderr to a log), so the payload cannot forge a frame. When the tmpfs is
/// full (under 1% or 16 KiB free) the probe's trace is incomplete: `GYRSEEK-LIMIT <idx>` is printed instead of its files
/// and the host blocks that package. The functions never fail (`return 0`) because the script
/// runs under `set -e`.
const TRACE_FUNCTIONS: &str = "gyrseek_emit() { echo \"GYRSEEK-FILE ${1##*/}\"; base64 < \"$1\"; echo GYRSEEK-END; rm -f \"$1\"; }; \
gyrseek_full() { set -- $(df -Pk /gyrseek-trace 2>/dev/null | tail -n 1 | tr -s ' ' | cut -d' ' -f2,4); [ \"${2:-0}\" -lt 16 ] || [ $(( ${2:-0} * 100 )) -lt \"${1:-0}\" ]; }; \
gyrseek_publish() { if gyrseek_full; then echo \"GYRSEEK-LIMIT $1\"; rm -f /gyrseek-trace/gyrseek_*_$1.log; return 0; fi; \
for kind in trace err artifacts rc timeout; do f=/gyrseek-trace/gyrseek_${kind}_$1.log; if [ -f \"$f\" ]; then gyrseek_emit \"$f\"; fi; done; return 0; }; \
gyrseek_publish_rest() { for f in /gyrseek-trace/gyrseek_*.log; do if [ -f \"$f\" ]; then gyrseek_emit \"$f\"; fi; done; return 0; }";

/// Defines the publishing functions and arranges for whatever a probe left behind to be
/// published when the script exits, also when it aborts.
fn trace_dir_setup_steps() -> Vec<String> {
    vec![
        TRACE_FUNCTIONS.to_string(),
        "trap gyrseek_publish_rest EXIT".to_string(),
    ]
}

/// The places the unprivileged scanner user can write to apart from `/work` and `/tmp`, which
/// legitimate installs do not use (they run with `HOME=/work`, and temporary files go to `/tmp`).
/// Measured in the default image: `/home/gyrseek` and `/var/tmp` are writable and executable (a
/// copied ELF and a shebang script both ran from them, unlike `/work` and `/tmp`, which are
/// `noexec`), `/run/lock` and `/dev/shm` are writable. The artifact inventory lists them, so
/// anything dropped there is reported (`dropped_file`), and the reset below empties them, so one
/// probe cannot leave something behind for the next (FIXED #471).
const OUTSIDE_WORK_DIRS: &str = "/home/gyrseek /var/tmp /run/lock /dev/shm";

/// Empties the shared install tree, `/tmp` and the other places the scanner user can write
/// (`OUTSIDE_WORK_DIRS`) between probes, and once before the first. Traces and
/// artifact inventories live in the trace tmpfs, so they are untouched. The trailing
/// `|| true` is needed because the script runs under `set -e` and a failed
/// cleanup must not abort the remaining probes.
const WORK_RESET_STEP: &str = "find /work /tmp /home/gyrseek /var/tmp /run/lock /dev/shm -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null || true";

/// SIGKILLs every process owned by the scanner user, repeating until none is left (a
/// survivor can fork between a scan of `/proc` and its kill; zombies are already dead and
/// are skipped). Walks `/proc` because `pkill` is not in the slim scanner images. If
/// processes are still alive after ten passes the script exits 124, which stops the
/// container and with it everything in it: the next probe must never share a workspace
/// with an untraced survivor. Runs only after a probe timed out.
const KILL_PAYLOAD_PROCESSES_STEP: &str = "n=1; for _ in 1 2 3 4 5 6 7 8 9 10; do n=0; for p in /proc/[0-9]*; do [ \"$(stat -c %U \"$p\" 2>/dev/null)\" = gyrseek ] || continue; case \"$(sed -n 's/^State:[[:space:]]*//p' \"$p/status\" 2>/dev/null)\" in Z*) continue;; esac; kill -9 \"${p#/proc/}\" 2>/dev/null || true; n=1; done; [ $n -eq 0 ] && break; done; [ $n -eq 0 ] || exit 124";

/// Builds the full `sh -lc` script for the matrix (multi-probe) run: per-probe
/// strace logs kept in the size-limited, root-only `TRACE_DIR`, payload dropped to the scanner
/// user, followed by a targeted artifact scan of the installed file tree. Each probe's files
/// are streamed to the host on stdout when the probe is done.
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
    // Every probe, the first included, starts from the same empty directories: `useradd` leaves
    // the skeleton dotfiles in the home directory, which would make probe 0 differ from the rest.
    steps.push(WORK_RESET_STEP.to_string());

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
            "{} >/dev/null 2>{err} || {{ rc=$?; if [ $rc -eq 124 ] || [ $rc -eq 137 ]; then {{ true > {timeout_marker}; }} 2>/dev/null || true; {KILL_PAYLOAD_PROCESSES_STEP}; else {{ echo $rc > {rc_file}; }} 2>/dev/null || true; fi; true; }}",
            strace_command(&install(&spec), Some(&log), timeout_secs),
        ));
        // After each install, scan the installed tree for suspicious artifacts.
        steps.extend(build_artifact_scan_steps(manager, idx));
        // Send this probe's files to the host and free the tmpfs for the next probe.
        steps.push(format!("gyrseek_publish {idx}"));
        // Then wipe the install tree so the next probe starts from the same
        // empty state and its scan cannot see this probe's files.
        steps.push(WORK_RESET_STEP.to_string());
    }

    steps.join("; ")
}

/// Builds the `docker run` argument vector. Nothing from the host is mounted. With a
/// `trace_limit` the root-only tmpfs `TRACE_DIR` of that size is added (the matrix probes keep
/// their logs there); `name` lets the host stop the container.
fn build_docker_run_args(
    image: &str,
    script: &str,
    danger_disable_seccomp: bool,
    trace_limit: Option<&str>,
    name: &str,
) -> Result<Vec<String>, String> {
    let mem_limit = sandbox_mem_limit();
    let max_procs = sandbox_max_processes();
    let mut args = vec![
        "run".to_string(),
        "--rm".to_string(),
        "--name".to_string(),
        name.to_string(),
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
        // `/tmp` stays `noexec` but is as large as `/work` (a 128 MB `/tmp` could not hold scipy's
        // wheel while uv extracted it). `/work` allows execution: install scripts run the binaries
        // their package ships (esbuild, bcrypt) and C extensions are loaded from it, as in a real
        // install; with `noexec` those installs failed and could not be scanned (FIXED #425).
        // `nosuid` and `nodev` stay.
        format!("/tmp:rw,noexec,nosuid,nodev,size={mem_limit}"),
        "--tmpfs".to_string(),
        // Docker mounts a tmpfs `noexec` unless `exec` is asked for.
        format!("/work:rw,exec,nosuid,nodev,size={mem_limit}"),
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
    if let Some(limit) = trace_limit {
        args.push("--tmpfs".to_string());
        args.push(format!(
            "{TRACE_DIR}:rw,noexec,nosuid,nodev,mode=700,size={limit}"
        ));
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
        ARTIFACT_INVENTORY_NODE, ARTIFACT_INVENTORY_PYTHON, EMBEDDED_APPARMOR_PROFILE_NAME,
        EMBEDDED_APPARMOR_PROFILE_TEXT, EMBEDDED_SECCOMP_PROFILE_JSON, KILL_PAYLOAD_PROCESSES_STEP,
        OUTSIDE_WORK_DIRS, SCANNER_USER, TRACE_FUNCTIONS, WORK_RESET_STEP, base64_decode,
        build_artifact_scan_steps, build_docker_run_args, build_matrix_script,
        build_runner_from_env, docker_apparmor_enabled_from_env, docker_apparmor_profile_name,
        install_output_tail, probe_timeout_message, read_frames, read_install_failure,
        sandbox_max_processes, sandbox_trace_limit, size_to_bytes, strace_install_command,
    };
    use super::{
        DockerRunner, INSTALL_OUTPUT_READ_BYTES, collect_probe_traces, is_timeout_exit,
        read_file_tail,
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
    fn docker_args_mount_nothing_from_the_host_and_size_the_trace_tmpfs() {
        let with_traces =
            build_docker_run_args("img:latest", "echo hi", false, Some("256m"), "probe-1")
                .expect("docker args should build");
        // Nothing from the host is mounted: a payload cannot write to the host's disk.
        for flag in ["-v", "--volume", "--mount"] {
            assert!(
                !with_traces.iter().any(|a| a == flag),
                "{flag}: {with_traces:?}"
            );
        }
        assert!(with_traces.iter().any(|a| a == "no-new-privileges"));
        // The probe logs live in a root-only, size-limited tmpfs.
        assert!(
            with_traces
                .iter()
                .any(|a| a == "/gyrseek-trace:rw,noexec,nosuid,nodev,mode=700,size=256m"),
            "{with_traces:?}"
        );
        // The container has a name so an abandoned run can be stopped.
        let at = with_traces
            .iter()
            .position(|a| a == "--name")
            .expect("--name");
        assert_eq!(with_traces[at + 1], "probe-1");

        let without = build_docker_run_args("img:latest", "echo hi", false, None, "probe-2")
            .expect("docker args should build");
        assert!(!without.iter().any(|a| a.contains("gyrseek-trace")));
    }

    #[test]
    fn trace_limits_are_read_from_the_environment_and_validated() {
        // One guard holds the environment lock (and removes the variable again on drop).
        let _guard = SandboxEnvVarGuard::remove("GYRSEEK_TRACE_LIMIT");
        assert_eq!(sandbox_trace_limit(None), "1024m");
        // The config value applies when the environment says nothing, and so does the default
        // when the config value is not a size.
        assert_eq!(sandbox_trace_limit(Some("512m")), "512m");
        assert_eq!(sandbox_trace_limit(Some(" 1g ")), "1g");
        for bad in ["abc", "0", "12x", ""] {
            assert_eq!(sandbox_trace_limit(Some(bad)), "1024m", "{bad:?}");
        }
        // The environment wins over the config; an invalid environment value falls back to the
        // config (then the default) with a warning.
        for (value, configured, expected) in [
            ("512m", None, "512m"),
            (" 1g ", None, "1g"),
            ("65536k", None, "65536k"),
            ("1g", Some("512m"), "1g"),
            ("not-a-size", None, "1024m"),
            ("not-a-size", Some("512m"), "512m"),
            ("0", Some("2g"), "2g"),
            ("", Some("512m"), "512m"),
            ("", None, "1024m"),
        ] {
            unsafe { std::env::set_var("GYRSEEK_TRACE_LIMIT", value) };
            assert_eq!(
                sandbox_trace_limit(configured),
                expected,
                "{value:?} {configured:?}"
            );
        }
        assert_eq!(size_to_bytes("256m"), Some(256 * 1024 * 1024));
        assert_eq!(size_to_bytes("2G"), Some(2 * 1024 * 1024 * 1024));
        assert_eq!(size_to_bytes("10k"), Some(10 * 1024));
        assert_eq!(size_to_bytes("1000"), Some(1000));
        assert_eq!(size_to_bytes("12x"), None);
        assert_eq!(size_to_bytes(""), None);
        assert_eq!(size_to_bytes("m"), None);
    }

    #[test]
    fn work_allows_execution_and_tmp_does_not_and_both_are_as_large_as_the_memory_limit() {
        let _env = SandboxEnvVarGuard::remove("GYRSEEK_MEM_LIMIT");
        let args =
            build_docker_run_args("img:latest", "echo hi", false, None, "probe-test").unwrap();
        let mount = |dir: &str| -> String {
            let at = args
                .iter()
                .position(|a| a.starts_with(&format!("{dir}:")))
                .unwrap_or_else(|| panic!("{dir}"));
            assert_eq!(args[at - 1], "--tmpfs");
            args[at].clone()
        };
        // Install scripts run the binaries their package ships from /work (FIXED #425).
        let work = mount("/work");
        assert!(
            work.contains(",exec,") && !work.contains("noexec"),
            "{work}"
        );
        assert!(work.contains("nosuid") && work.contains("nodev"), "{work}");
        // /tmp holds extracted wheels and temporary files: large, but nothing runs from it.
        let tmp = mount("/tmp");
        assert!(
            tmp.contains("noexec") && tmp.contains("nosuid") && tmp.contains("nodev"),
            "{tmp}"
        );
        assert!(
            tmp.ends_with("size=2g") && work.ends_with("size=2g"),
            "{tmp} {work}"
        );
    }

    #[test]
    fn docker_args_memory_limit_defaults_to_2g_and_is_configurable() {
        {
            let _env = SandboxEnvVarGuard::remove("GYRSEEK_MEM_LIMIT");
            let args = build_docker_run_args("img:latest", "echo hi", false, None, "probe-test")
                .expect("docker args should build");
            let mem_pos = args
                .iter()
                .position(|a| a == "--memory")
                .expect("--memory flag present");
            assert_eq!(args.get(mem_pos + 1).map(String::as_str), Some("2g"));
            assert!(
                args.iter()
                    .any(|a| a == "/work:rw,exec,nosuid,nodev,size=2g")
            );
            assert!(
                args.iter()
                    .any(|a| a == "/tmp:rw,noexec,nosuid,nodev,size=2g")
            );
        }

        {
            let _guard = SandboxEnvVarGuard::set("GYRSEEK_MEM_LIMIT", "4g");
            let args_custom =
                build_docker_run_args("img:latest", "echo hi", false, None, "probe-test")
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
                    .any(|a| a == "/work:rw,exec,nosuid,nodev,size=4g")
            );
        }
    }

    #[test]
    fn docker_args_grant_sys_ptrace_capability() {
        // strace -u drops the install to an unprivileged user; attaching across
        // UIDs needs CAP_SYS_PTRACE, which Docker does not grant by default.
        // Without this the sandbox can never produce a trace.

        let args = build_docker_run_args("img:latest", "echo hi", false, None, "probe-test")
            .expect("docker args should build");
        let pos = args
            .iter()
            .position(|a| a == "--cap-add")
            .expect("--cap-add flag present");
        assert_eq!(args.get(pos + 1).map(String::as_str), Some("SYS_PTRACE"));
    }

    #[test]
    fn docker_args_adds_seccomp_profile_by_default() {
        let args = build_docker_run_args("img:latest", "echo hi", false, None, "probe-test")
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
        let args = build_docker_run_args("img:latest", "echo hi", true, None, "probe-test")
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
            EMBEDDED_APPARMOR_PROFILE_TEXT.contains("/gyrseek-trace/ rw"),
            "profile must grant rw to the trace directory"
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
        for manager in ["pip", "npm"] {
            let combined = build_artifact_scan_steps(manager, 0).join(" ");
            assert!(
                combined.contains(
                    "find /work /home/gyrseek /var/tmp /run/lock /dev/shm -type f -print0"
                ),
                "should inventory every file where the payload can write, names NUL-separated: {combined}"
            );
        }
    }

    #[test]
    fn the_inventory_runs_in_the_language_the_package_manager_needs() {
        // The image must have it for the package manager to run at all, custom images included.
        for manager in ["pip", "pip3", "uv", "poetry"] {
            let scan = &build_artifact_scan_steps(manager, 0)[1];
            assert!(
                scan.contains("command -v python3 || command -v python"),
                "{manager}: {scan}"
            );
            assert!(scan.contains("\"$INTERP\" -c '"), "{manager}: {scan}");
            assert!(
                !scan.contains("node") && !scan.contains("perl"),
                "{manager}: {scan}"
            );
        }
        for manager in ["npm", "pnpm"] {
            let scan = &build_artifact_scan_steps(manager, 0)[1];
            assert!(scan.contains("command -v node"), "{manager}: {scan}");
            assert!(scan.contains("\"$INTERP\" -e '"), "{manager}: {scan}");
            assert!(
                !scan.contains("python") && !scan.contains("perl"),
                "{manager}: {scan}"
            );
        }
    }

    #[test]
    fn a_missing_or_failing_interpreter_stops_the_script_instead_of_leaving_an_empty_inventory() {
        // The only quiet exit is a full trace tmpfs, which is reported as over the limit.
        for (manager, runtime) in [("pip", "python3 or python"), ("npm", "node")] {
            let scan = &build_artifact_scan_steps(manager, 0)[1];
            assert!(scan.contains("[ -n \"$INTERP\" ] && find /work"), "{scan}");
            assert!(
                scan.contains("; then true; elif gyrseek_full; then true; else echo"),
                "{scan}"
            );
            assert!(
                scan.contains(&format!(
                    "the scanner image has no working {runtime}\" >&2; exit 126; fi"
                )),
                "{scan}"
            );
            // No fallback that would carry on without executable types.
            assert!(
                !scan.contains("file -b") && !scan.contains("stat -c"),
                "{scan}"
            );
        }
        assert!(TRACE_FUNCTIONS.contains("gyrseek_full() {"));
    }

    #[test]
    fn the_inventory_scripts_have_no_quote_the_shell_would_trip_on_and_start_no_process() {
        // They are wrapped in single quotes by the shell.
        for script in [ARTIFACT_INVENTORY_PYTHON, ARTIFACT_INVENTORY_NODE] {
            assert!(!script.contains('\''), "{script}");
        }
        for spawn in [
            "subprocess",
            "os.system",
            "os.popen",
            "child_process",
            "execSync",
            "spawn(",
        ] {
            assert!(
                !ARTIFACT_INVENTORY_PYTHON.contains(spawn)
                    && !ARTIFACT_INVENTORY_NODE.contains(spawn),
                "{spawn}"
            );
        }
        // The executable formats come from the file's own bytes, not from a `file` command that
        // the scanner images do not have; `|`, NUL and line breaks never reach the content field.
        for script in [ARTIFACT_INVENTORY_PYTHON, ARTIFACT_INVENTORY_NODE] {
            for magic in [
                "\\x7fELF",
                "\\xfe\\xed\\xfa\\xce",
                "\\xca\\xfe\\xba\\xbe",
                "PE\\0\\0",
                "PE32+",
                "Mach-O universal binary",
            ] {
                assert!(script.contains(magic), "{magic}");
            }
            assert!(script.contains("\\0"), "NUL field delimiter");
        }
    }

    #[test]
    fn artifact_scan_steps_output_to_correct_log() {
        let steps0 = build_artifact_scan_steps("pip", 0);
        let steps1 = build_artifact_scan_steps("npm", 1);
        assert!(steps0[1].contains("> /gyrseek-trace/gyrseek_artifacts_0.log"));
        assert!(steps1[1].contains("> /gyrseek-trace/gyrseek_artifacts_1.log"));
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
    }

    #[test]
    fn writes_into_the_trace_tmpfs_cannot_abort_the_script_when_it_is_full() {
        // The script runs under `set -e`, and a probe that fills the tmpfs makes every later write
        // into it fail: each such write must be tolerated so the probe is reported as over the
        // limit instead of the whole batch dying with a generic error.
        let script = build_matrix_script(
            "pip",
            &[("pkg-a".to_string(), "1.0.0".to_string())],
            true,
            45,
        );
        for write in [
            "{ true > /gyrseek-trace/gyrseek_timeout_0.log; } 2>/dev/null || true",
            "{ echo $rc > /gyrseek-trace/gyrseek_rc_0.log; } 2>/dev/null || true",
            "{ true > /gyrseek-trace/gyrseek_artifacts_0.log; } 2>/dev/null || true",
        ] {
            assert!(script.contains(write), "{write}: {script}");
        }
        // `:` is a special builtin, whose failed redirection ends a non-interactive shell even
        // after `|| true`, so it must not be used for these writes.
        assert!(!script.contains(": > /gyrseek-trace"), "{script}");
    }

    #[test]
    fn the_places_the_scanner_user_can_write_are_inventoried_and_wiped_alike() {
        // One list drives both: whatever is looked at is also emptied between probes.
        let home = format!("/home/{SCANNER_USER}");
        for dir in OUTSIDE_WORK_DIRS.split_whitespace() {
            assert!(WORK_RESET_STEP.contains(dir), "{dir} is not reset");
            assert!(
                build_artifact_scan_steps("pip", 0)[1].contains(dir),
                "{dir} is not inventoried"
            );
        }
        assert!(
            OUTSIDE_WORK_DIRS.contains(&home),
            "the scanner user's home is part of it"
        );
        // /work and /tmp are reset too, but only /work is inventoried (/tmp is noexec and busy).
        assert!(WORK_RESET_STEP.contains("/work /tmp "));
        assert!(
            !build_artifact_scan_steps("pip", 0)[1]
                .split_whitespace()
                .any(|word| word == "/tmp"),
            "/tmp is not inventoried"
        );
        // The reset empties the directories without removing them.
        assert!(WORK_RESET_STEP.contains("-mindepth 1 -maxdepth 1"));
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
    fn the_matrix_script_keeps_probe_logs_in_a_root_only_tmpfs_and_streams_them_out() {
        let probes = [
            ("pkg-a".to_string(), "1.0.0".to_string()),
            ("pkg-b".to_string(), "2.0.0".to_string()),
        ];
        let script = build_matrix_script("pip", &probes, true, 300);
        // The publishing functions exist and are published on exit before any payload runs.
        let functions = script
            .find("gyrseek_publish() {")
            .expect("publish function");
        let trap = script
            .find("trap gyrseek_publish_rest EXIT")
            .expect("publish on exit");
        let first_payload = script.find("strace").expect("first probe");
        assert!(
            functions < first_payload && trap < first_payload,
            "{script}"
        );
        // Nothing is read from or written to a host mount.
        assert!(!script.contains("/out"), "{script}");
        // Each probe is published after its artifact scan and before the next probe's reset.
        for idx in 0..2 {
            let scan = script
                .find(&format!("gyrseek_artifacts_{idx}.log"))
                .expect("scan");
            let publish = script
                .find(&format!("gyrseek_publish {idx}"))
                .expect("publish");
            let reset = script[publish..].find(WORK_RESET_STEP).expect("reset") + publish;
            assert!(scan < publish && publish < reset, "probe {idx}: {script}");
        }
        // A full tmpfs is reported instead of publishing an incomplete trace, and the functions
        // never fail the script (it runs under `set -e`).
        assert!(TRACE_FUNCTIONS.contains("GYRSEEK-LIMIT"));
        assert!(TRACE_FUNCTIONS.contains("return 0"));
        // The AppArmor profile lets root use the directory.
        assert!(EMBEDDED_APPARMOR_PROFILE_TEXT.contains("/gyrseek-trace/** rwk"));
        assert!(!EMBEDDED_APPARMOR_PROFILE_TEXT.contains("/out"));
    }

    fn frame(name: &str, content: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut text = String::new();
        for chunk in content.chunks(57) {
            for quad in chunk.chunks(3) {
                let n = (quad[0] as u32) << 16
                    | (*quad.get(1).unwrap_or(&0) as u32) << 8
                    | *quad.get(2).unwrap_or(&0) as u32;
                for k in 0..4 {
                    if k <= quad.len() {
                        text.push(ALPHABET[(n >> (18 - 6 * k) & 63) as usize] as char);
                    } else {
                        text.push('=');
                    }
                }
            }
            text.push('\n');
        }
        format!("GYRSEEK-FILE {name}\n{text}GYRSEEK-END\n")
    }

    #[test]
    fn base64_decoding_matches_the_standard_alphabet_and_rejects_anything_else() {
        for (input, expected) in [
            ("", &b""[..]),
            ("Zg==", b"f"),
            ("Zm8=", b"fo"),
            ("Zm9v", b"foo"),
            ("Zm9vYg==", b"foob"),
            ("Zm9vYmE=", b"fooba"),
            ("Zm9vYmFy", b"foobar"),
            ("AAECAw==", &[0, 1, 2, 3]),
            ("+/+/", &[0xfb, 0xff, 0xbf]),
        ] {
            assert_eq!(
                base64_decode(input.as_bytes()).as_deref(),
                Some(expected),
                "{input}"
            );
        }
        for bad in [
            "Zg=", "Zg", "Z===", "Zm9v=A==", "Zm 9", "Zm9\n", "Zm9*", "=Zm9",
        ] {
            assert_eq!(base64_decode(bad.as_bytes()), None, "{bad:?}");
        }
        // Round trip through the test encoder, including bytes a payload may write (NUL, newline).
        let data: Vec<u8> = (0..=255u8).chain(0..=255u8).collect();
        let text = frame("gyrseek_err_0.log", &data);
        let dir = tempfile::tempdir().unwrap();
        read_frames(text.as_bytes(), dir.path(), 1 << 20).unwrap();
        assert_eq!(
            std::fs::read(dir.path().join("gyrseek_err_0.log")).unwrap(),
            data
        );
    }

    #[test]
    fn frames_from_the_container_become_files_and_everything_else_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let stream = format!(
            "some ordinary output\n{}{}GYRSEEK-LIMIT 3\n{}{}trailing noise\n",
            frame("gyrseek_trace_0.log", b"execve(\"/bin/a\") = 0\n"),
            frame("gyrseek_artifacts_0.log", b"/work/a\x00100\x00text\x00hi\n"),
            frame("gyrseek_rc_1.log", b"7\n"),
            frame("gyrseek_timeout_2.log", b""),
        );
        read_frames(stream.as_bytes(), dir.path(), 1 << 20).unwrap();
        let read = |n: &str| std::fs::read(dir.path().join(n)).unwrap();
        assert_eq!(read("gyrseek_trace_0.log"), b"execve(\"/bin/a\") = 0\n");
        assert_eq!(
            read("gyrseek_artifacts_0.log"),
            b"/work/a\x00100\x00text\x00hi\n"
        );
        assert_eq!(read("gyrseek_rc_1.log"), b"7\n");
        assert_eq!(read("gyrseek_timeout_2.log"), b"");
        assert_eq!(read("gyrseek_limit_3.log"), b"");
        // A line far longer than a frame line is ordinary output, skipped without being buffered.
        let long = format!(
            "{}\n{}",
            "x".repeat(100_000),
            frame("gyrseek_trace_4.log", b"ok")
        );
        read_frames(long.as_bytes(), dir.path(), 1 << 20).unwrap();
        assert_eq!(read("gyrseek_trace_4.log"), b"ok");
    }

    #[test]
    fn a_frame_that_cannot_be_trusted_is_an_error_not_a_partial_trace() {
        let dir = tempfile::tempdir().unwrap();
        let run = |stream: &str, cap: u64| read_frames(stream.as_bytes(), dir.path(), cap);
        // Names outside what the script writes: no path traversal, no other kinds, no huge index.
        for name in [
            "../gyrseek_trace_0.log",
            "gyrseek_trace_0.log/../../x",
            "gyrseek_trace_.log",
            "gyrseek_other_0.log",
            "gyrseek_trace_0.txt",
            "gyrseek_trace_1234567.log",
            "/etc/passwd",
            "",
        ] {
            let err = run(&format!("GYRSEEK-FILE {name}\nGYRSEEK-END\n"), 1024).unwrap_err();
            assert!(err.contains("unexpected file"), "{name:?}: {err}");
        }
        // Malformed data, a stream that stops inside a file, a file over the cap, a long line
        // inside a frame, a malformed limit marker.
        assert!(
            run(
                "GYRSEEK-FILE gyrseek_trace_0.log\nnot base64!\nGYRSEEK-END\n",
                1024
            )
            .unwrap_err()
            .contains("malformed")
        );
        assert!(
            run("GYRSEEK-FILE gyrseek_trace_0.log\nZm9v\n", 1024)
                .unwrap_err()
                .contains("ended inside")
        );
        assert!(
            run(&frame("gyrseek_trace_0.log", &[b'a'; 500]), 100)
                .unwrap_err()
                .contains("larger than")
        );
        let long = format!(
            "GYRSEEK-FILE gyrseek_trace_0.log\n{}\nGYRSEEK-END\n",
            "A".repeat(5000)
        );
        assert!(run(&long, 1 << 20).unwrap_err().contains("too long"));
        for bad in ["GYRSEEK-LIMIT x", "GYRSEEK-LIMIT ", "GYRSEEK-LIMIT 1234567"] {
            assert!(
                run(&format!("{bad}\n"), 1024)
                    .unwrap_err()
                    .contains("limit marker"),
                "{bad}"
            );
        }
        // The size is the decoded size, so base64 padding cannot sneak a file past the cap.
        assert!(run(&frame("gyrseek_trace_0.log", &[b'a'; 100]), 100).is_ok());
    }

    #[test]
    fn a_probe_that_filled_the_trace_tmpfs_is_blocked_alone() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        std::fs::write(d.join("gyrseek_limit_0.log"), b"").unwrap();
        std::fs::write(d.join("gyrseek_trace_0.log"), b"partial").unwrap();
        std::fs::write(d.join("gyrseek_trace_1.log"), b"execve(\"/bin/b\") = 0\n").unwrap();
        let probes = [
            ("big".to_string(), "1".to_string()),
            ("ok".to_string(), "2".to_string()),
        ];
        let got = collect_probe_traces(d, &probes, 300, "64m").unwrap();
        // Only the second probe is returned, and the first is never read or re-run.
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].probe.0, "ok");
        // When every probe filled it, the batch is an error that names the limit.
        std::fs::write(d.join("gyrseek_limit_1.log"), b"").unwrap();
        let err = collect_probe_traces(d, &probes, 300, "64m").unwrap_err();
        assert!(
            err.contains("trace limit of 64m") && err.contains("GYRSEEK_TRACE_LIMIT"),
            "{err}"
        );
    }

    /// A payload that tries every way to rewrite what was recorded or to forge what the host
    /// receives: write, truncate, delete and symlink over the trace files (its own and an earlier
    /// probe's), remove the directory, and print a fake frame on the container's stdout.
    const TAMPERING_PAYLOAD: &str = r#"sh -c 'echo FORGED >> /gyrseek-trace/gyrseek_trace_0.log; : > /gyrseek-trace/gyrseek_trace_1.log; ln -s /etc/hostname /gyrseek-trace/gyrseek_err_1.log; rm -f /gyrseek-trace/gyrseek_trace_0.log; rm -rf /gyrseek-trace; ls /gyrseek-trace; echo GYRSEEK-LIMIT 0 > /proc/1/fd/1; echo FORGED-FRAME > /proc/1/fd/1; echo tamper-attempted'"#;

    /// Runs `script` in a container built like the real one (`limit` is the trace tmpfs size) and
    /// returns the files it streamed out.
    fn run_in_container(script: &str, limit: &str) -> tempfile::TempDir {
        let image =
            crate::runtime_image::select_for_manager("pip", None, None, std::path::Path::new("."))
                .image;
        let name = super::container_name();
        let args = build_docker_run_args(&image, script, false, Some(limit), &name).unwrap();
        let out = tempfile::tempdir().unwrap();
        let cap = size_to_bytes(limit).unwrap() + super::MAX_FRAME_SLACK_BYTES;
        let (code, stderr) = super::run_matrix_container(&args, &name, out.path(), cap).unwrap();
        assert_eq!(code, Some(0), "{stderr}");
        out
    }

    /// Needs Docker and the network (the image's strace comes from apt): run it with
    /// `just test-trace-integrity`, which CI does in a Docker job. FIXED #411: on Docker Desktop
    /// for macOS a payload could rewrite or delete a trace kept in a bind mount.
    #[test]
    #[ignore = "needs Docker; run with `just test-trace-integrity`"]
    fn a_payload_cannot_tamper_with_its_own_or_another_probes_trace() {
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
        let out = run_in_container(&script, "256m");

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
        // The payload could not print a frame or a limit marker on the container's stdout.
        assert!(
            !out.path().join("gyrseek_limit_0.log").exists(),
            "a forged limit marker arrived"
        );
        for entry in std::fs::read_dir(out.path()).unwrap() {
            let entry = entry.unwrap();
            assert!(
                !entry.file_type().unwrap().is_symlink(),
                "{:?} is a symlink",
                entry.file_name()
            );
        }
        assert!(
            out.path().join("gyrseek_artifacts_0.log").exists(),
            "every probe's artifact log is streamed"
        );

        // What the other probes left (exit code, timeout marker) travels the same way.
        assert_eq!(
            read("gyrseek_rc_2.log").trim(),
            "7",
            "a failed install's exit code arrives"
        );
        assert!(
            out.path().join("gyrseek_timeout_3.log").exists(),
            "a timed-out probe's marker arrives"
        );
        assert!(
            !out.path().join("gyrseek_rc_0.log").exists(),
            "a probe whose install succeeded leaves no exit-code file"
        );
    }

    /// FIXED #24 and #467. Runs the artifact inventory (the Python script in the Python image, the
    /// Node script in the Node image) on a tree of every executable format the classifier knows
    /// plus names that try to confuse it, and checks what is reported and how long it takes.
    /// Needs Docker and the two scanner images (no network otherwise).
    #[test]
    #[ignore = "needs Docker; run with `just test-trace-integrity`"]
    fn the_artifact_inventory_reports_executables_without_file_and_is_fast() {
        use std::collections::HashSet;
        // PE32+: "MZ", padding, e_lfanew = 0x40, "PE\0\0", a 20 byte COFF header, magic 0x020b.
        // Mach-O thin (64-bit, little endian), Mach-O universal (2 architectures) and a Java class
        // file, which shares the universal magic (major version 52).
        let fixture = r#"mkdir -p /work/sp; cd /work
cp /bin/ls bun; cp /bin/ls native-elf; cp /bin/ls "trailing "; cp /bin/ls "$(printf 'new\nline')"
printf 'import os; os.system(1)\n' > sp/evil.pth; printf 'plain\n' > sp/ok.pth
head -c 11000000 /dev/zero > big.bin
{ printf 'MZ'; head -c 58 /dev/zero; printf '\100\0\0\0PE\0\0'; head -c 20 /dev/zero; printf '\013\002'; } > win.exe
printf '\317\372\355\376\0\0\0\0' > mac-thin; printf '\312\376\272\276\0\0\0\002' > mac-fat; printf '\312\376\272\276\0\0\0\064' > Foo.class
i=0; while [ $i -lt 3000 ]; do echo x > small$i; i=$((i+1)); done"#;
        for manager in ["pip", "npm"] {
            let image = crate::runtime_image::select_for_manager(
                manager,
                None,
                None,
                std::path::Path::new("."),
            )
            .image;
            let steps = build_artifact_scan_steps(manager, 0).join("; ");
            let script = format!(
                r#"{TRACE_FUNCTIONS}
{fixture}
t0=$(date +%s%N); {steps}; t1=$(date +%s%N)
echo "MS=$(( (t1 - t0) / 1000000 ))"; echo BEGIN; base64 < /gyrseek-trace/gyrseek_artifacts_0.log; echo END"#
            );
            let name = super::container_name();
            let args = build_docker_run_args(&image, &script, false, Some("64m"), &name).unwrap();
            let output = std::process::Command::new("docker")
                .args(&args)
                .output()
                .expect("docker");
            assert!(
                output.status.success(),
                "{manager}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let text = String::from_utf8_lossy(&output.stdout).to_string();
            let ms: u64 = text
                .lines()
                .find_map(|l| l.strip_prefix("MS="))
                .expect("MS")
                .trim()
                .parse()
                .unwrap();
            let body: String = text
                .split("BEGIN\n")
                .nth(1)
                .and_then(|r| r.split("END").next())
                .expect("log")
                .lines()
                .collect();
            let log = base64_decode(body.as_bytes()).expect("base64");
            let lines = String::from_utf8_lossy(&log)
                .lines()
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect();
            let fast: HashSet<String> = crate::scanning::classify_inventory_lines(lines);
            eprintln!("{manager}: artifact inventory of ~3000 files took {ms} ms");
            let has = |prefix: &str| fast.iter().any(|f| f.starts_with(prefix));
            // Executables of every format, recognised from their bytes.
            for path in [
                "/work/native-elf",
                "/work/bun",
                "/work/trailing ",
                "/work/new?line",
                "/work/win.exe",
                "/work/mac-thin",
                "/work/mac-fat",
            ] {
                assert!(
                    has(&format!("binary|{path}|")),
                    "{manager}: binary {path:?}: {fast:#?}"
                );
            }
            assert!(
                fast.iter()
                    .any(|f| f.starts_with("binary|/work/win.exe|PE32+")),
                "{manager}: {fast:#?}"
            );
            assert!(has("unexpected_runtime|/work/bun|"), "{manager}: {fast:#?}");
            // A Java class file shares the universal Mach-O magic and must not be reported.
            assert!(
                !fast.iter().any(|f| f.contains("Foo.class")),
                "{manager}: {fast:#?}"
            );
            // The other classes of finding.
            assert!(
                has("suspicious_pth|/work/sp/evil.pth|import os; os.system(1)"),
                "{manager}: {fast:#?}"
            );
            assert!(
                !has("suspicious_pth|/work/sp/ok.pth|"),
                "{manager}: {fast:#?}"
            );
            assert!(
                has("large_file|/work/big.bin|11000000"),
                "{manager}: {fast:#?}"
            );
            // A single pass, not a process per file (the old loop needed several seconds here).
            assert!(ms < 3000, "{manager}: {ms} ms");
        }
    }

    /// A scanner image without the interpreter, or with one that fails, must stop the scan with a
    /// message (exit 126) and never carry on with an empty inventory that would pass for clean.
    /// Needs Docker and the network for the tiny `busybox` image.
    #[test]
    #[ignore = "needs Docker; run with `just test-trace-integrity`"]
    fn a_scanner_image_without_a_working_interpreter_fails_the_scan_with_a_message() {
        let python_image =
            crate::runtime_image::select_for_manager("pip", None, None, std::path::Path::new("."))
                .image;
        // (image, manager, set-up that breaks the interpreter, runtime named in the message)
        let cases = [
            ("busybox:1.36.1", "pip", "", "python3 or python"),
            ("busybox:1.36.1", "npm", "", "node"),
            (
                python_image.as_str(),
                "pip",
                "mkdir /fake; printf '#!/bin/sh\\nexit 1\\n' > /fake/python3; chmod +x /fake/python3; PATH=/fake:$PATH;",
                "python3 or python",
            ),
        ];
        for (image, manager, setup, runtime) in cases {
            let steps = build_artifact_scan_steps(manager, 0).join("; ");
            let script = format!(
                "{TRACE_FUNCTIONS}; mkdir -p /work; echo x > /work/f; {setup} {steps}; echo REACHED-THE-END"
            );
            let args =
                build_docker_run_args(image, &script, false, Some("64m"), &super::container_name())
                    .unwrap();
            let output = std::process::Command::new("docker")
                .args(&args)
                .output()
                .expect("docker");
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            assert_eq!(
                output.status.code(),
                Some(126),
                "{image} {manager}: {stderr}"
            );
            assert!(
                stderr.contains(&format!("no working {runtime}")),
                "{image} {manager}: {stderr}"
            );
            assert!(
                !String::from_utf8_lossy(&output.stdout).contains("REACHED-THE-END"),
                "{image} {manager}: the script carried on"
            );
        }
    }

    /// FIXED #471. The scanner user can write, and run what it writes, in `/home/gyrseek` and
    /// `/var/tmp`, and can write in `/dev/shm` and `/run/lock`. A payload that drops files there is
    /// reported, the next probe starts clean, and the probe before it (which starts right after the
    /// skeleton dotfiles `useradd` creates) reports nothing. Needs Docker.
    #[test]
    #[ignore = "needs Docker; run with `just test-trace-integrity`"]
    fn files_dropped_outside_work_are_reported_and_do_not_reach_the_next_probe() {
        use std::collections::HashSet;
        let probes = vec![
            ("first".to_string(), "1.0.0".to_string()),
            ("dropper".to_string(), "1.0.0".to_string()),
            ("last".to_string(), "1.0.0".to_string()),
        ];
        let dropper = "sh -c 'cp /bin/true /home/gyrseek/payload; cp /bin/true /var/tmp/miner; echo x > /dev/shm/note; echo x > /run/lock/mark; echo x > /home/gyrseek/.hidden; echo x > /work/legit'";
        let script = super::build_matrix_script_with("pip", &probes, false, 120, &|spec| {
            if spec.contains("dropper") {
                dropper.to_string()
            } else {
                "sh -c 'echo ok'".to_string()
            }
        });
        let out = run_in_container(&script, "64m");
        let findings = |idx: usize| -> HashSet<String> {
            let log = std::fs::read(out.path().join(format!("gyrseek_artifacts_{idx}.log")))
                .expect("artifacts log");
            let lines = String::from_utf8_lossy(&log)
                .lines()
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect();
            crate::scanning::classify_inventory_lines(lines)
        };
        let dropped = findings(1);
        for path in [
            "/home/gyrseek/payload",
            "/var/tmp/miner",
            "/dev/shm/note",
            "/run/lock/mark",
            "/home/gyrseek/.hidden",
        ] {
            assert!(
                dropped
                    .iter()
                    .any(|f| f.starts_with(&format!("dropped_file|{path}|"))),
                "{path}: {dropped:#?}"
            );
        }
        // An executable dropped where it can run is also reported as one.
        assert!(
            dropped
                .iter()
                .any(|f| f.starts_with("binary|/home/gyrseek/payload|ELF")),
            "{dropped:#?}"
        );
        assert!(
            dropped
                .iter()
                .any(|f| f.starts_with("binary|/var/tmp/miner|ELF")),
            "{dropped:#?}"
        );
        // A file under /work is an ordinary install file, not a dropped one.
        assert!(
            !dropped.iter().any(|f| f.contains("/work/legit")),
            "{dropped:#?}"
        );
        // The probes around it see nothing outside /work: nothing leaked forward, and probe 0 does
        // not see the skeleton dotfiles `useradd` creates.
        for idx in [0, 2] {
            let seen = findings(idx);
            assert!(
                !seen.iter().any(|f| f.starts_with("dropped_file|")),
                "probe {idx}: {seen:#?}"
            );
        }
    }

    /// FIXED #425. An install script can run a binary its package ships from `/work` (esbuild,
    /// bcrypt) and `/tmp` holds a large wheel (scipy), while nothing can run from `/tmp`. Checked
    /// as the unprivileged scanner user in a container built from the real arguments. Needs Docker.
    #[test]
    #[ignore = "needs Docker; run with `just test-trace-integrity`"]
    fn an_install_can_run_a_binary_from_work_and_extract_a_large_wheel_into_tmp() {
        let image =
            crate::runtime_image::select_for_manager("pip", None, None, std::path::Path::new("."))
                .image;
        let probe = r#"cat > /tmp/probe.sh <<'EOS'
cp /bin/true /work/prog && /work/prog && echo "WORK-EXEC-OK"
cp /bin/true /tmp/prog 2>/dev/null; /tmp/prog 2>/dev/null && echo "TMP-EXEC-OK" || echo "TMP-EXEC-BLOCKED"
head -c 300000000 /dev/zero > /tmp/large-wheel && echo "TMP-300MB-OK"
chmod u+s /work/prog; grep -E " /(work|tmp) " /proc/mounts | cut -d" " -f2,4
EOS
useradd -m -d /home/gyrseek -s /bin/sh gyrseek; chown gyrseek /work; runuser -u gyrseek -- sh /tmp/probe.sh"#;
        let args =
            build_docker_run_args(&image, probe, false, None, &super::container_name()).unwrap();
        let output = std::process::Command::new("docker")
            .args(&args)
            .output()
            .expect("docker");
        let text = String::from_utf8_lossy(&output.stdout).to_string();
        assert!(
            text.contains("WORK-EXEC-OK"),
            "{text} {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            text.contains("TMP-EXEC-BLOCKED") && !text.contains("TMP-EXEC-OK"),
            "{text}"
        );
        assert!(
            text.contains("TMP-300MB-OK"),
            "a 300 MB file must fit in /tmp: {text}"
        );
        // Both mounts are nosuid and nodev; only /tmp is noexec.
        let flags = |dir: &str| -> String {
            text.lines()
                .find(|l| l.starts_with(&format!("{dir} ")))
                .unwrap_or_else(|| panic!("{dir}: {text}"))
                .to_string()
        };
        assert!(
            flags("/work").contains("nosuid")
                && flags("/work").contains("nodev")
                && !flags("/work").contains("noexec"),
            "{text}"
        );
        assert!(
            flags("/tmp").contains("nosuid") && flags("/tmp").contains("noexec"),
            "{text}"
        );
    }

    /// FIXED #434: a package that produces more trace than the tmpfs holds blocks only itself;
    /// the next probe still gets a whole tmpfs. Needs Docker and the network.
    #[test]
    #[ignore = "needs Docker; run with `just test-trace-integrity`"]
    fn a_probe_that_floods_its_trace_is_blocked_and_the_next_probe_is_unaffected() {
        let probes = vec![
            ("flood".to_string(), "1.0.0".to_string()),
            ("after".to_string(), "1.0.0".to_string()),
        ];
        // About twenty thousand forks and execs: far more than the tiny tmpfs below holds, so every
        // write the script itself makes into it (exit code, markers, inventory) fails too.
        let flood = "sh -c 'i=0; while [ $i -lt 20000 ]; do /bin/true; i=$((i+1)); done'";
        let script = super::build_matrix_script_with("pip", &probes, false, 120, &|spec| {
            if spec.contains("flood") {
                flood.to_string()
            } else {
                "sh -c 'echo after-marker'".to_string()
            }
        });
        let out = run_in_container(&script, "64k");
        assert!(
            out.path().join("gyrseek_limit_0.log").exists(),
            "the flooding probe is marked"
        );
        assert!(
            !out.path().join("gyrseek_trace_0.log").exists(),
            "its partial trace is not sent"
        );
        let after = std::fs::read_to_string(out.path().join("gyrseek_trace_1.log"))
            .expect("next probe's trace");
        assert!(
            after.contains("after-marker") || after.contains("\\x61\\x66\\x74\\x65\\x72"),
            "{after}"
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
        assert!(script.contains("; else { echo $rc"));
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

    #[test]
    fn collects_each_probes_trace_in_order_and_appends_the_artifact_inventory() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        put(d, "gyrseek_trace_0.log", "execve(\"/bin/a\") = 0\n");
        put(d, "gyrseek_trace_1.log", "execve(\"/bin/b\") = 0\n");
        put(d, "gyrseek_artifacts_1.log", "  /work/x\0\0\0  \n");
        let probes = [probe("a", "1.0.0"), probe("b", "2.0.0")];
        let got = collect_probe_traces(d, &probes, 300, "256m").unwrap();
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
        let got = collect_probe_traces(d, &[probe("a", "1")], 300, "256m").unwrap();
        assert_eq!(got[0].trace, "trace\n");
    }

    #[test]
    fn a_probe_with_no_trace_file_is_left_out_and_named_and_nothing_is_re_run() {
        // A second run would come with its own artifact inventory, and the two would describe
        // different installs (FIXED #418); a missing file only blocks its own package (FIXED #469).
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        put(d, "gyrseek_artifacts_0.log", "/work/x\0\0\0\n");
        put(d, "gyrseek_trace_1.log", "execve(\"/bin/b\") = 0\n");
        let probes = [probe("a", "1.0.0"), probe("b", "2.0.0")];
        let got = collect_probe_traces(d, &probes, 300, "256m").unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].probe, probe("b", "2.0.0"));
        // When no probe has a trace the batch is an error that names each of them.
        let only_missing = tempfile::tempdir().unwrap();
        let err = collect_probe_traces(only_missing.path(), &probes, 300, "256m").unwrap_err();
        assert!(
            err.contains("'a@1.0.0' left no trace file") && err.contains("'b@2.0.0'"),
            "{err}"
        );
    }

    #[test]
    fn a_blank_trace_fails_the_batch_because_strace_does_not_work() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        put(d, "gyrseek_trace_0.log", "  \n");
        put(d, "gyrseek_trace_1.log", "good\n");
        let probes = [probe("a", "1.0.0"), probe("b", "2.0.0")];
        let err = collect_probe_traces(d, &probes, 300, "256m").unwrap_err();
        assert!(err.contains("empty trace for 'a@1.0.0'"), "{err}");
    }

    #[test]
    fn a_blank_trace_fails_closed_with_the_strace_error() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        put(d, "gyrseek_trace_0.log", "\n");
        put(
            d,
            "gyrseek_err_0.log",
            "strace: ptrace(PTRACE_SEIZE): Operation not permitted\n",
        );
        let err = collect_probe_traces(d, &[probe("a", "1.0.0")], 300, "256m").unwrap_err();
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
        let got = collect_probe_traces(d, &probes, 300, "256m").unwrap();
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
        let err = collect_probe_traces(d, &probes, 45, "256m").unwrap_err();
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
        let got = collect_probe_traces(d, &probes, 300, "256m").unwrap();
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
        let got = collect_probe_traces(d, &probes, 300, "256m").unwrap();
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
            collect_probe_traces(dir.path(), &[], 300, "256m")
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
            trace_limit: None,
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
        assert_eq!(script.matches(WORK_RESET_STEP).count(), 13);
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
        let install0 = script.find("gyrseek_trace_0.log").expect("trace 0");
        let scan0 = script.find("gyrseek_artifacts_0.log").expect("artifacts 0");
        let install1 = script.find("gyrseek_trace_1.log").expect("trace 1");
        // Once before the first probe, so probe 0 starts as empty as the rest, and after each.
        let before_first = script
            .find(WORK_RESET_STEP)
            .expect("reset before the first probe");
        assert!(
            before_first < install0,
            "the first reset must come before probe 0's install"
        );
        let after_first = script[scan0..]
            .find(WORK_RESET_STEP)
            .expect("reset after probe 0")
            + scan0;
        assert!(
            after_first > scan0,
            "wipe must come after probe 0's artifact scan"
        );
        assert!(
            after_first < install1,
            "wipe must come before probe 1's install"
        );
        assert_eq!(script.matches(WORK_RESET_STEP).count(), 3);
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
        let protected_args =
            build_docker_run_args(image, &command_str, false, None, "probe-test").unwrap();

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
                None,
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
