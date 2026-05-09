//! Process isolation: Landlock + seccomp + namespaces (Linux),
//! sandbox-exec (macOS).
//!
//! This crate implements unprivileged process containment using Linux kernel
//! primitives: Landlock (filesystem), seccomp (syscall restriction), and
//! user/network namespaces (isolation). The sandbox is applied via a re-exec
//! launcher pattern, ensuring the parent process remains unrestricted while
//! child processes are fully contained.
//!
//! ## Why Rust beats Go here (PORT_PLAN §1)

#![allow(unsafe_code)] // Required for syscalls (seccomp, prctl, fork, unshare, etc.)
#![allow(clippy::vec_init_then_push)] // BPF program construction is clearer with explicit pushes
#![allow(clippy::needless_return)] // Explicit returns improve readability in error paths
#![allow(clippy::ptr_arg)] // PathBuf references are intentional for API consistency
#![cfg_attr(test, allow(clippy::unwrap_used))] // Tests can use unwrap for clarity
//!
//! - `landlock` crate handles Landlock ABI v1/v2/v3/v4 negotiation as data,
//!   so we never speak the raw `landlock_create_ruleset(2)` syscall numbers.
//! - Direct BPF filter construction with type-safe instruction builders.
//! - `nix::sched::unshare` + safe syscall wrappers give us deterministic
//!   ordering between "create namespace", "drop caps", "apply seccomp",
//!   "exec child" without fighting the Go runtime's clone(2).
//!
//! ## Re-exec ordering
//!
//! 1. Parent computes `Policy`, validates paths, opens any FDs the child
//!    will need.
//! 2. Parent `unshare(CLONE_NEWUSER | CLONE_NEWNS | ...)` then forks a child.
//! 3. Child:
//!    a. Drops capabilities (inside user namespace).
//!    b. Applies Landlock ruleset (this crate's [`apply`]).
//!    c. Installs seccomp filter.
//!    d. `execve` into the actual agent binary, passing a sentinel env var
//!       (e.g. `__PIPELOCK_SANDBOX_INIT=1`) so the re-execed self skips re-init.
//! 4. Parent waits and forwards exit status.
//!
//! Steps b/c MUST come after fork and before exec. Going before fork pins
//! the parent. Going after exec is too late — the child's image controls.

#![allow(clippy::doc_overindented_list_items)]

use std::path::PathBuf;

#[cfg(target_os = "linux")]
mod seccomp;

#[cfg(target_os = "linux")]
mod launcher;

#[cfg(target_os = "linux")]
mod child;

#[cfg(target_os = "linux")]
mod netns;

#[cfg(target_os = "linux")]
mod caps;

#[cfg(target_os = "linux")]
pub use launcher::{is_sandbox_init, launch_sandboxed, prepare_sandbox_cmd, LaunchConfig};

#[cfg(target_os = "linux")]
pub use child::run_init;

#[derive(thiserror::Error, Debug)]
pub enum SandboxError {
    #[error("sandbox unsupported on this platform")]
    Unsupported,
    #[error("policy invalid: {0}")]
    InvalidPolicy(String),
    #[error("landlock: {0}\nRemediation: Ensure kernel >= 5.13 and CONFIG_SECURITY_LANDLOCK=y")]
    Landlock(String),
    #[error(
        "seccomp: {0}\nRemediation: Ensure CONFIG_SECCOMP=y and CONFIG_SECCOMP_FILTER=y in kernel"
    )]
    Seccomp(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// What the agent under sandbox is allowed to do.
///
/// The defaults are restrictive on purpose: an empty `Policy` denies all
/// filesystem access except read-only on `read_only_paths`, no execve, and
/// (eventually) a tight seccomp filter. Operators opt in to capabilities,
/// not out of them.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Policy {
    /// Paths the sandboxed process may read.
    #[serde(default)]
    pub read_only_paths: Vec<PathBuf>,

    /// Paths the sandboxed process may read **and** write.
    #[serde(default)]
    pub read_write_paths: Vec<PathBuf>,

    /// Paths the sandboxed process may execute binaries from. Empty by
    /// default — agents typically don't need to execve.
    #[serde(default)]
    pub exec_paths: Vec<PathBuf>,

    /// Whether to deny network access. Skeleton: not yet enforced; the
    /// seccomp filter (next phase) will block `socket(AF_INET*)` family.
    #[serde(default)]
    pub deny_network: bool,
}

impl Policy {
    /// Validate paths exist before we hand them to Landlock — Landlock
    /// silently ignores nonexistent paths in some kernel versions, which
    /// would create a confusing "policy applied but doesn't restrict
    /// anything" situation.
    pub fn validate(&self) -> Result<(), SandboxError> {
        for p in self
            .read_only_paths
            .iter()
            .chain(self.read_write_paths.iter())
            .chain(self.exec_paths.iter())
        {
            if !p.exists() {
                return Err(SandboxError::InvalidPolicy(format!(
                    "path does not exist: {}",
                    p.display()
                )));
            }
        }
        Ok(())
    }
}

/// Apply the policy to the **current** process. Used by re-execed children
/// (the child path of the parent/child split documented in the module docs).
///
/// On Linux this currently applies Landlock filesystem rules. Seccomp + caps
/// land in the next sandbox phase.
///
/// **Warning:** Landlock is a one-way trip — once applied, this process and
/// every child it forks are restricted for the rest of their lifetime. Tests
/// that exercise this must run in a forked subprocess.
pub fn apply(policy: &Policy) -> Result<(), SandboxError> {
    policy.validate()?;
    apply_platform(policy)
}

#[cfg(target_os = "linux")]
fn apply_platform(policy: &Policy) -> Result<(), SandboxError> {
    apply_landlock(policy)
}

#[cfg(not(target_os = "linux"))]
fn apply_platform(_policy: &Policy) -> Result<(), SandboxError> {
    // macOS will shell out to `sandbox-exec` (parent-side) in a later phase;
    // there's nothing to do in-process here. Other unixes: unsupported.
    Err(SandboxError::Unsupported)
}

#[cfg(target_os = "linux")]
fn apply_landlock(policy: &Policy) -> Result<(), SandboxError> {
    use landlock::{
        Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
        RulesetStatus, ABI,
    };

    // ABI::V1 is the lowest common denominator — kernel 5.13+. The crate
    // upgrades to higher ABIs automatically when available; we declare the
    // set of access rights we care about up front.
    let abi = ABI::V1;
    let all_fs = AccessFs::from_all(abi);

    let mut ruleset = Ruleset::default()
        .handle_access(all_fs)
        .map_err(|e| SandboxError::Landlock(format!("handle_access: {e}")))?
        .create()
        .map_err(|e| SandboxError::Landlock(format!("create: {e}")))?;

    let ro = AccessFs::ReadDir | AccessFs::ReadFile;
    for path in &policy.read_only_paths {
        let fd = PathFd::new(path)
            .map_err(|e| SandboxError::Landlock(format!("open {}: {e}", path.display())))?;
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, ro))
            .map_err(|e| SandboxError::Landlock(format!("add ro {}: {e}", path.display())))?;
    }

    for path in &policy.read_write_paths {
        let fd = PathFd::new(path)
            .map_err(|e| SandboxError::Landlock(format!("open {}: {e}", path.display())))?;
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, all_fs))
            .map_err(|e| SandboxError::Landlock(format!("add rw {}: {e}", path.display())))?;
    }

    // Exec paths need both read and execute permissions
    let exec_perms = AccessFs::ReadDir | AccessFs::ReadFile | AccessFs::Execute;
    for path in &policy.exec_paths {
        let fd = PathFd::new(path)
            .map_err(|e| SandboxError::Landlock(format!("open {}: {e}", path.display())))?;
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, exec_perms))
            .map_err(|e| SandboxError::Landlock(format!("add exec {}: {e}", path.display())))?;
    }

    let status = ruleset
        .restrict_self()
        .map_err(|e| SandboxError::Landlock(format!("restrict_self: {e}")))?;

    match status.ruleset {
        RulesetStatus::FullyEnforced => {
            tracing::info!(target: "pipelock.sandbox", "Landlock fully enforced");
        }
        RulesetStatus::PartiallyEnforced => {
            tracing::warn!(
                target: "pipelock.sandbox",
                "Landlock partially enforced — kernel ABI lower than requested",
            );
        }
        RulesetStatus::NotEnforced => {
            return Err(SandboxError::Landlock(
                "Landlock not enforced (kernel < 5.13 or LSM disabled)".into(),
            ));
        }
    }

    if policy.deny_network {
        tracing::warn!(
            target: "pipelock.sandbox",
            "deny_network requested but seccomp filter not yet implemented (skeleton)",
        );
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
fn apply_landlock(_policy: &Policy) -> Result<(), SandboxError> {
    Err(SandboxError::Unsupported)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn empty_policy_validates() {
        Policy::default().validate().unwrap();
    }

    #[test]
    fn missing_path_rejected() {
        let p = Policy {
            read_only_paths: vec!["/this/does/not/exist".into()],
            ..Default::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn existing_path_accepted() {
        let d = tempdir().unwrap();
        let p = Policy {
            read_only_paths: vec![d.path().to_path_buf()],
            ..Default::default()
        };
        p.validate().unwrap();
    }

    // Note: we deliberately do NOT call `apply()` from unit tests — it
    // would lock down the running test process irreversibly (Landlock is a
    // one-way trip per process). End-to-end coverage lands in Phase 3
    // alongside the `unshare`+exec wrapper, which forks a child for each
    // assertion.
}
