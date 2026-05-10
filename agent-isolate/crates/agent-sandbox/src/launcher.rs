//! Re-exec launcher for namespace-based process isolation.
//!
//! This module implements the parent-side fork+namespace+re-exec pattern.
//! The parent creates user and network namespaces, then re-execs itself
//! in sandbox-init mode. The child applies Landlock, seccomp, and capability
//! restrictions before executing the target command.

#![cfg(target_os = "linux")]

use crate::{Policy, SandboxError};
use nix::sched::{unshare, CloneFlags};
use nix::unistd::{Gid, Uid};
use std::env;
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Configuration for launching a sandboxed process.
#[derive(Debug, Clone)]
pub struct LaunchConfig {
    /// Command and arguments to execute inside the sandbox
    pub command: Vec<String>,

    /// Workspace directory (absolute path)
    pub workspace: PathBuf,

    /// Custom sandbox policy (if None, uses default)
    pub policy: Option<Policy>,

    /// Strict mode: fail-closed if any layer unavailable
    pub strict: bool,

    /// Best-effort mode: continue with degraded isolation
    pub best_effort: bool,

    /// Extra environment variables (KEY=VALUE)
    pub extra_env: Vec<String>,
}

/// Prepare a sandboxed command for execution.
///
/// Returns a `Command` configured to re-exec the current binary in
/// sandbox-init mode with namespace isolation. The caller must call
/// `.spawn()` or `.status()` to start the process.
pub fn prepare_sandbox_cmd(cfg: LaunchConfig) -> Result<Command, SandboxError> {
    if cfg.strict && cfg.best_effort {
        return Err(SandboxError::InvalidPolicy(
            "strict and best_effort are mutually exclusive".to_string(),
        ));
    }

    // Validate workspace
    validate_workspace(&cfg.workspace)?;

    // Note: We don't probe namespace support here because probing in the parent
    // process can contaminate it. Instead, we attempt namespace creation in pre_exec
    // and handle failure gracefully based on strict/best_effort mode.

    // Get current binary path for re-exec
    let self_exe = fs::read_link("/proc/self/exe").map_err(|e| {
        SandboxError::Io(std::io::Error::new(
            e.kind(),
            format!("reading /proc/self/exe: {}", e),
        ))
    })?;

    let mut cmd = Command::new(self_exe);

    // Set environment variables for child
    cmd.env("__PIPELOCK_SANDBOX_INIT", "1");
    cmd.env("__PIPELOCK_SANDBOX_WORKSPACE", &cfg.workspace);
    cmd.env(
        "__PIPELOCK_SANDBOX_COMMAND",
        cfg.command.join("\x1f"), // unit separator
    );

    if cfg.strict {
        cmd.env("__PIPELOCK_SANDBOX_STRICT", "1");
    }

    if !cfg.extra_env.is_empty() {
        cmd.env("__PIPELOCK_SANDBOX_EXTRA_ENV", cfg.extra_env.join("\x1f"));
    }

    // Serialize policy if provided
    if let Some(policy) = &cfg.policy {
        let policy_json = serde_json::to_string(policy)
            .map_err(|e| SandboxError::InvalidPolicy(format!("serializing policy: {}", e)))?;
        cmd.env("__PIPELOCK_SANDBOX_POLICY", policy_json);
    }

    // Attempt namespace creation in pre_exec (runs in child after fork, before exec)
    // Note: PID namespace is NOT created here because it would make the agent binary
    // itself PID 1, which breaks Tokio. Instead, we create PID namespace after re-exec
    // in the child initialization code.
    let clone_flags =
        CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWNS; // Mount namespace isolation

    let uid = Uid::current();
    let gid = Gid::current();
    let strict = cfg.strict;

    unsafe {
        cmd.pre_exec(move || {
            // Try to create namespaces (runs in child process after fork)
            match unshare(clone_flags) {
                Ok(_) => {
                    // Success - write UID/GID mappings
                    write_uid_map(uid)?;
                    write_gid_map(gid)?;
                    Ok(())
                }
                Err(e) => {
                    // Namespace creation failed
                    if strict {
                        // Strict mode: fail immediately
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            format!("namespace creation failed (strict mode): {}", e),
                        ));
                    } else {
                        // Best-effort mode: continue without namespaces
                        // Set flag so child knows namespaces are unavailable
                        std::env::set_var("__PIPELOCK_SANDBOX_NO_NETNS", "1");
                        Ok(())
                    }
                }
            }
        });
    }

    // Inherit stdio
    cmd.stdin(Stdio::inherit());
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());

    Ok(cmd)
}

/// Launch a sandboxed process and wait for completion.
pub fn launch_sandboxed(cfg: LaunchConfig) -> Result<std::process::ExitStatus, SandboxError> {
    let mut cmd = prepare_sandbox_cmd(cfg)?;
    let status = cmd.status().map_err(|e| {
        SandboxError::Io(std::io::Error::new(
            e.kind(),
            format!("starting sandbox child: {}", e),
        ))
    })?;
    Ok(status)
}

/// Validate workspace path.
fn validate_workspace(workspace: &PathBuf) -> Result<(), SandboxError> {
    if !workspace.exists() {
        return Err(SandboxError::InvalidPolicy(format!(
            "workspace does not exist: {}",
            workspace.display()
        )));
    }

    if !workspace.is_dir() {
        return Err(SandboxError::InvalidPolicy(format!(
            "workspace is not a directory: {}",
            workspace.display()
        )));
    }

    // Check for dangerous roots
    let dangerous = ["/", "/tmp", "/home", "/etc", "/usr", "/var"];
    let canonical = workspace
        .canonicalize()
        .map_err(|e| SandboxError::InvalidPolicy(format!("canonicalizing workspace: {}", e)))?;

    for root in &dangerous {
        if canonical == PathBuf::from(root) {
            return Err(SandboxError::InvalidPolicy(format!(
                "workspace must not be {}",
                root
            )));
        }
    }

    Ok(())
}

/// Write UID mapping for user namespace.
fn write_uid_map(uid: Uid) -> std::io::Result<()> {
    let mapping = format!("0 {} 1\n", uid);
    fs::write("/proc/self/uid_map", mapping)?;
    Ok(())
}

/// Write GID mapping for user namespace.
fn write_gid_map(gid: Gid) -> std::io::Result<()> {
    // Disable setgroups first (required for unprivileged GID mapping)
    fs::write("/proc/self/setgroups", "deny\n")?;
    let mapping = format!("0 {} 1\n", gid);
    fs::write("/proc/self/gid_map", mapping)?;
    Ok(())
}

/// Check if we're running in sandbox-init mode.
pub fn is_sandbox_init() -> bool {
    env::var("__PIPELOCK_SANDBOX_INIT").is_ok()
}

/// Check if strict mode is enabled.
pub(crate) fn is_strict_mode() -> bool {
    env::var("__PIPELOCK_SANDBOX_STRICT").is_ok()
}

/// Check if network namespace is unavailable.
pub(crate) fn is_no_netns() -> bool {
    env::var("__PIPELOCK_SANDBOX_NO_NETNS").is_ok()
}
