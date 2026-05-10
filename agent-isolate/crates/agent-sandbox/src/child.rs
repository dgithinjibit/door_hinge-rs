//! Child process initialization for sandbox-init mode.
//!
//! This module runs inside the re-exec'd child process and applies all
//! containment layers before executing the target command.

#![cfg(target_os = "linux")]

use crate::caps::drop_all_capabilities;
use crate::launcher::{is_no_netns, is_strict_mode};
use crate::netns::configure_loopback;
use crate::seccomp::{apply_seccomp, set_no_new_privs};
use crate::{apply_landlock, Policy, SandboxError};
use std::env;
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{exit, Command};

/// Entry point for sandbox-init child process.
///
/// This function applies all containment layers and then execs the target
/// command. It does not return on success (exec replaces the process).
pub fn run_init() -> ! {
    if let Err(e) = run_init_inner() {
        eprintln!("[sandbox] initialization failed: {}", e);
        exit(1);
    }
    // If we get here, exec failed but didn't return an error
    eprintln!("[sandbox] exec returned unexpectedly");
    exit(1);
}

fn run_init_inner() -> Result<(), SandboxError> {
    let strict = is_strict_mode();
    let no_netns = is_no_netns();

    // Create PID namespace if we have other namespaces
    // This must be done AFTER re-exec to avoid making the agent binary PID 1
    if !no_netns {
        // We're in a user namespace, so we can create a PID namespace
        // But we need to fork to enter it
        match unsafe { libc::unshare(libc::CLONE_NEWPID) } {
            0 => {
                // Success - now fork to enter the PID namespace
                match unsafe { libc::fork() } {
                    -1 => {
                        if strict {
                            eprintln!("[sandbox] PID namespace fork failed");
                            exit(1);
                        } else {
                            eprintln!("[sandbox] PID namespace: DEGRADED (fork failed)");
                        }
                    }
                    0 => {
                        // Child: we're now in the PID namespace as PID 1
                        // Fork again to avoid being PID 1
                        match unsafe { libc::fork() } {
                            -1 => {
                                eprintln!("[sandbox] double-fork failed");
                                exit(1);
                            }
                            0 => {
                                // Grandchild: continue with initialization (PID 2)
                                // Mount a fresh /proc for this PID namespace so the
                                // sandboxed process only sees its own processes
                                let proc_mounted = mount_proc();
                                if proc_mounted {
                                    eprintln!("[sandbox] pid: ACTIVE (PID {}, isolated namespace, /proc remounted)", std::process::id());
                                } else {
                                    eprintln!(
                                        "[sandbox] pid: ACTIVE (PID {}, isolated namespace)",
                                        std::process::id()
                                    );
                                }
                            }
                            grandchild_pid => {
                                // Child (PID 1): wait for grandchild and forward exit status
                                let mut status: libc::c_int = 0;
                                loop {
                                    let ret =
                                        unsafe { libc::waitpid(grandchild_pid, &mut status, 0) };
                                    if ret == grandchild_pid {
                                        if libc::WIFEXITED(status) {
                                            exit(libc::WEXITSTATUS(status));
                                        } else if libc::WIFSIGNALED(status) {
                                            exit(128 + libc::WTERMSIG(status));
                                        }
                                    } else if ret == -1 {
                                        let errno = std::io::Error::last_os_error();
                                        if errno.raw_os_error() != Some(libc::EINTR) {
                                            exit(1);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    child_pid => {
                        // Parent: wait for child and exit with its status
                        let mut status: libc::c_int = 0;
                        loop {
                            let ret = unsafe { libc::waitpid(child_pid, &mut status, 0) };
                            if ret == child_pid {
                                if libc::WIFEXITED(status) {
                                    exit(libc::WEXITSTATUS(status));
                                } else if libc::WIFSIGNALED(status) {
                                    exit(128 + libc::WTERMSIG(status));
                                }
                            } else if ret == -1 {
                                let errno = std::io::Error::last_os_error();
                                if errno.raw_os_error() != Some(libc::EINTR) {
                                    exit(1);
                                }
                            }
                        }
                    }
                }
            }
            _ => {
                if strict {
                    eprintln!("[sandbox] PID namespace creation failed");
                    exit(1);
                } else {
                    eprintln!("[sandbox] pid: DEGRADED (unshare failed)");
                }
            }
        }
    }

    // Read configuration from environment
    let workspace = env::var("__PIPELOCK_SANDBOX_WORKSPACE")
        .map_err(|_| SandboxError::InvalidPolicy("missing workspace env".to_string()))?;
    let command_str = env::var("__PIPELOCK_SANDBOX_COMMAND")
        .map_err(|_| SandboxError::InvalidPolicy("missing command env".to_string()))?;

    let command: Vec<String> = command_str.split('\x1f').map(|s| s.to_string()).collect();
    let extra_env: Vec<String> = env::var("__PIPELOCK_SANDBOX_EXTRA_ENV")
        .ok()
        .map(|s| s.split('\x1f').map(|s| s.to_string()).collect())
        .unwrap_or_default();

    // Create per-process temp directory
    let sandbox_dir = format!("/tmp/agent-sandbox-{}", std::process::id());
    fs::create_dir_all(&sandbox_dir).map_err(|e| {
        SandboxError::Io(std::io::Error::new(
            e.kind(),
            format!("creating sandbox temp dir: {}", e),
        ))
    })?;

    // Build synthetic environment
    let mut new_env = Vec::new();
    new_env.push(format!("PATH={}", env::var("PATH").unwrap_or_default()));
    new_env.push(format!("HOME={}", env::var("HOME").unwrap_or_default()));
    new_env.push(format!("USER={}", env::var("USER").unwrap_or_default()));
    new_env.push(format!("TMPDIR={}", sandbox_dir));

    // Preserve proxy settings
    if let Ok(val) = env::var("HTTP_PROXY") {
        new_env.push(format!("HTTP_PROXY={}", val));
    }
    if let Ok(val) = env::var("HTTPS_PROXY") {
        new_env.push(format!("HTTPS_PROXY={}", val));
    }
    if let Ok(val) = env::var("NO_PROXY") {
        new_env.push(format!("NO_PROXY={}", val));
    }

    // Add extra env vars
    new_env.extend(extra_env);

    // Drop all capabilities (inside user namespace)
    if let Err(e) = drop_all_capabilities() {
        if strict {
            eprintln!("[sandbox] capability drop: FAILED: {}", e);
            exit(1);
        } else {
            eprintln!("[sandbox] capability drop: DEGRADED: {}", e);
        }
    } else {
        eprintln!("[sandbox] capabilities: DROPPED");
    }

    // Configure loopback interface if in network namespace
    if !no_netns {
        if let Err(e) = configure_loopback() {
            eprintln!("[sandbox] loopback config: WARNING: {}", e);
            // Non-fatal - continue
        } else {
            eprintln!("[sandbox] loopback: CONFIGURED");
        }
    }

    // Mount private /dev/shm if we have mount namespace
    // This is safe because we're in a mount namespace (CLONE_NEWNS)
    if !no_netns {
        if let Err(e) = mount_private_shm() {
            if strict {
                eprintln!("[sandbox] private /dev/shm: FAILED: {}", e);
                exit(1);
            } else {
                eprintln!("[sandbox] private /dev/shm: WARNING: {}", e);
            }
        } else {
            eprintln!("[sandbox] /dev/shm: PRIVATE");
        }
    }

    // Apply Landlock
    let mut policy = resolve_policy(&workspace)?;
    policy.read_write_paths.push(PathBuf::from(&sandbox_dir));

    eprintln!(
        "[sandbox] policy: {} read-only, {} read-write, {} exec paths",
        policy.read_only_paths.len(),
        policy.read_write_paths.len(),
        policy.exec_paths.len()
    );

    match apply_landlock(&policy) {
        Ok(_) => eprintln!("[sandbox] filesystem: ACTIVE (Landlock)"),
        Err(e) => {
            if strict {
                eprintln!("[sandbox] filesystem: FAILED: {}", e);
                exit(1);
            } else {
                eprintln!("[sandbox] filesystem: DEGRADED: {}", e);
            }
        }
    }

    // Apply resource limits
    if let Err(e) = apply_rlimits() {
        eprintln!("[sandbox] rlimits: {}", e);
    } else {
        eprintln!("[sandbox] rlimits: ACTIVE");
    }

    // Set no_new_privs
    if let Err(e) = set_no_new_privs() {
        eprintln!("[sandbox] no_new_privs: {}", e);
    }

    // Apply seccomp
    match apply_seccomp(strict) {
        Ok(_) => eprintln!("[sandbox] syscall: ACTIVE (seccomp)"),
        Err(e) => {
            if strict {
                eprintln!("[sandbox] syscall: FAILED: {}", e);
                exit(1);
            } else {
                eprintln!("[sandbox] syscall: DEGRADED: {}", e);
            }
        }
    }

    // Report network namespace status
    if no_netns {
        eprintln!("[sandbox] network: DEGRADED (no namespace, best-effort mode)");
        eprintln!(
            "[sandbox] WARNING: best-effort network mode relies on HTTP(S)_PROXY env; \
             a child process that clears those can bypass agent."
        );
        eprintln!("[sandbox] mount: DEGRADED (no mount namespace isolation)");
        eprintln!("[sandbox] pid: DEGRADED (no PID namespace isolation)");
    } else {
        eprintln!("[sandbox] network: ACTIVE (isolated namespace)");
        eprintln!("[sandbox] mount: ACTIVE (isolated mount namespace)");
        eprintln!("[sandbox] pid: ACTIVE (isolated PID namespace, double-fork)");
    }

    // Report summary
    let active_layers = if no_netns { 3 } else { 6 }; // Landlock, seccomp, rlimits + (network, mount, PID)
    let total_layers = 6;
    eprintln!(
        "[sandbox] containment: {}/{} layers active",
        active_layers, total_layers
    );

    if strict && active_layers < total_layers {
        eprintln!(
            "[sandbox] FATAL: strict mode requires all {} layers active, got {}",
            total_layers, active_layers
        );
        exit(1);
    }

    // Change to workspace directory
    env::set_current_dir(&workspace).map_err(|e| {
        SandboxError::Io(std::io::Error::new(
            e.kind(),
            format!("chdir to workspace: {}", e),
        ))
    })?;

    // Exec the target command
    let binary = match which::which(&command[0]) {
        Ok(path) => path,
        Err(e) => {
            // If which fails, try common paths
            let common_paths = [
                format!("/usr/bin/{}", command[0]),
                format!("/bin/{}", command[0]),
                format!("/usr/local/bin/{}", command[0]),
            ];

            let mut found = None;
            for path in &common_paths {
                if std::path::Path::new(path).exists() {
                    found = Some(PathBuf::from(path));
                    break;
                }
            }

            found.ok_or_else(|| {
                SandboxError::InvalidPolicy(format!("command not found: {}: {}", command[0], e))
            })?
        }
    };

    eprintln!(
        "[sandbox] executing: {} with {} args",
        binary.display(),
        command.len() - 1
    );

    let err = Command::new(binary)
        .args(&command[1..])
        .env_clear()  // Clear all inherited environment variables
        .envs(
            new_env
                .iter()
                .filter_map(|s| s.split_once('=')),
        )
        .exec();

    // If exec returns, it failed
    eprintln!(
        "[sandbox] exec error: {} (errno: {:?})",
        err,
        err.raw_os_error()
    );
    Err(SandboxError::Io(std::io::Error::new(
        err.kind(),
        format!("exec failed: {}", err),
    )))
}

/// Resolve policy from environment or use default.
fn resolve_policy(workspace: &str) -> Result<Policy, SandboxError> {
    if let Ok(policy_json) = env::var("__PIPELOCK_SANDBOX_POLICY") {
        serde_json::from_str(&policy_json)
            .map_err(|e| SandboxError::InvalidPolicy(format!("parsing policy: {}", e)))
    } else {
        Ok(default_policy(workspace))
    }
}

/// Default sandbox policy.
fn default_policy(workspace: &str) -> Policy {
    // Note: exec_paths are separate from read_only_paths to make the policy explicit
    // but Landlock will grant both read and execute permissions to exec_paths
    let mut read_only = vec![
        PathBuf::from("/usr"),
        PathBuf::from("/lib"),
        PathBuf::from("/lib64"),
        PathBuf::from("/etc/ssl"),
        PathBuf::from("/etc/pki"),
        // /proc is always included. In PID namespace mode, /proc is remounted as a
        // fresh procfs BEFORE Landlock is applied, so the Landlock rule covers the
        // new mount and restricts it to the PID namespace's process view.
        PathBuf::from("/proc"),
    ];

    // Add architecture-specific lib paths if they exist
    for arch_lib in &[
        "/lib/x86_64-linux-gnu",
        "/lib64",
        "/usr/lib",
        "/usr/lib64",
        "/usr/lib/x86_64-linux-gnu",
    ] {
        let path = PathBuf::from(arch_lib);
        if path.exists() && !read_only.contains(&path) {
            read_only.push(path);
        }
    }

    Policy {
        read_only_paths: read_only,
        read_write_paths: vec![
            PathBuf::from(workspace),
            PathBuf::from("/dev/shm"),
            PathBuf::from("/dev/null"), // Allow /dev/null for shell redirections
        ],
        exec_paths: vec![
            PathBuf::from("/bin"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/usr/local/bin"),
            PathBuf::from("/sbin"),
            PathBuf::from("/usr/sbin"),
            PathBuf::from("/lib64"), // Dynamic linker needs exec permission
            PathBuf::from("/lib"),   // Dynamic linker needs exec permission
        ],
        deny_network: false,
    }
}

/// Mount private /dev/shm (strict mode only).
fn mount_private_shm() -> Result<(), SandboxError> {
    use nix::mount::{mount, umount, MsFlags};

    // Unmount host /dev/shm
    umount("/dev/shm")
        .map_err(|e| SandboxError::Io(std::io::Error::other(format!("umount /dev/shm: {}", e))))?;

    // Mount private tmpfs
    mount(
        Some("tmpfs"),
        "/dev/shm",
        Some("tmpfs"),
        MsFlags::empty(),
        Some("size=64m"),
    )
    .map_err(|e| SandboxError::Io(std::io::Error::other(format!("mount /dev/shm: {}", e))))?;

    Ok(())
}

/// Mount a fresh /proc for the current PID namespace.
///
/// After creating a PID namespace, /proc still shows the host's processes.
/// Remounting it gives the sandboxed process a view of only its own PID namespace.
/// Returns true on success, false if mount failed (non-fatal).
///
/// NOTE: This must be called BEFORE apply_landlock() so the new /proc mount
/// is covered by the Landlock policy.
fn mount_proc() -> bool {
    use nix::mount::{mount, MsFlags};
    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .is_ok()
}

/// Apply resource limits.
fn apply_rlimits() -> Result<(), SandboxError> {
    use nix::sys::resource::{setrlimit, Resource};

    // Limit number of processes (prevent fork bombs)
    // Set to 4096 to allow shell commands with fork/exec chains
    setrlimit(Resource::RLIMIT_NPROC, 4096, 4096)
        .map_err(|e| SandboxError::Io(std::io::Error::other(format!("setrlimit NPROC: {}", e))))?;

    // Limit file size (prevent disk exhaustion)
    setrlimit(
        Resource::RLIMIT_FSIZE,
        10 * 1024 * 1024 * 1024,
        10 * 1024 * 1024 * 1024,
    )
    .map_err(|e| SandboxError::Io(std::io::Error::other(format!("setrlimit FSIZE: {}", e))))?;

    Ok(())
}
