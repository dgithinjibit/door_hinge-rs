//! Capability dropping for privilege reduction.
//!
//! After creating a user namespace, the child process has all capabilities
//! inside that namespace. This module drops them to prevent privileged
//! operations.

#![cfg(target_os = "linux")]

use crate::SandboxError;
use std::io;

/// Drop all capabilities from the current process.
///
/// This removes capabilities from:
/// - Effective set
/// - Permitted set
/// - Inheritable set
/// - Bounding set (via PR_CAPBSET_DROP)
pub(crate) fn drop_all_capabilities() -> Result<(), SandboxError> {
    // List of all capabilities (0-40 covers all current Linux capabilities)
    // CAP_CHOWN=0, CAP_DAC_OVERRIDE=1, ..., CAP_BPF=39, CAP_PERFMON=40
    for cap in 0..=40 {
        // Drop from bounding set (requires no capabilities, works in user namespace)
        let ret = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) };
        if ret != 0 {
            let errno = io::Error::last_os_error();
            // EINVAL means capability doesn't exist (newer kernel), ignore
            // EPERM means we don't have permission (already dropped or in restricted namespace)
            if errno.raw_os_error() != Some(libc::EINVAL)
                && errno.raw_os_error() != Some(libc::EPERM)
            {
                return Err(SandboxError::Io(io::Error::new(
                    errno.kind(),
                    format!("PR_CAPBSET_DROP cap {}: {}", cap, errno),
                )));
            }
        }
    }

    // Drop from effective, permitted, and inheritable sets using capset
    // This may fail with EPERM in some namespace configurations, which is acceptable
    // because the bounding set drops above already provide significant protection
    if let Err(e) = drop_capability_sets() {
        // Check if it's a permission error (expected in some configurations)
        if let SandboxError::Io(ref io_err) = e {
            if io_err.raw_os_error() == Some(libc::EPERM) {
                // Acceptable - bounding set is already restricted
                tracing::debug!(target: "agent.sandbox", "capset returned EPERM (acceptable in user namespace)");
                return Ok(());
            }
        }
        return Err(e);
    }

    tracing::debug!(target: "agent.sandbox", "All capabilities dropped");
    Ok(())
}

/// Drop capabilities from effective, permitted, and inheritable sets.
fn drop_capability_sets() -> Result<(), SandboxError> {
    // Use capset(2) to clear all capability sets
    // This is a simplified version - in production you'd use the `caps` crate

    #[repr(C)]
    struct CapUserHeader {
        version: u32,
        pid: i32,
    }

    #[repr(C)]
    struct CapUserData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    let mut header = CapUserHeader {
        version: 0x20080522, // _LINUX_CAPABILITY_VERSION_3
        pid: 0,              // current process
    };

    // Two data structures for 64-bit capability sets
    let data = [
        CapUserData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        CapUserData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];

    let ret = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &mut header as *mut CapUserHeader,
            &data as *const CapUserData,
        )
    };

    if ret != 0 {
        let errno = io::Error::last_os_error();
        return Err(SandboxError::Io(io::Error::new(
            errno.kind(),
            format!("capset failed: {}", errno),
        )));
    }

    Ok(())
}
