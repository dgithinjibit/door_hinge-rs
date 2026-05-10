//! Network namespace loopback configuration.
//!
//! This module brings up the loopback interface (127.0.0.1) inside a
//! network namespace so sandboxed processes can make localhost connections.

#![cfg(target_os = "linux")]

use crate::SandboxError;
use std::io;

/// Bring up the loopback interface in the current network namespace.
///
/// This is required after creating a network namespace because the loopback
/// interface starts in a DOWN state. Without this, localhost connections fail.
pub(crate) fn configure_loopback() -> Result<(), SandboxError> {
    // Use ip command as a simple fallback - more reliable than netlink in practice
    let output = std::process::Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .output();

    match output {
        Ok(result) if result.status.success() => {
            tracing::debug!(target: "agent.sandbox", "Loopback interface configured");
            Ok(())
        }
        Ok(result) => {
            let stderr = String::from_utf8_lossy(&result.stderr);
            Err(SandboxError::Io(io::Error::other(format!(
                "ip link set lo up failed: {}",
                stderr
            ))))
        }
        Err(e) => {
            // Non-fatal - log warning and continue
            tracing::warn!(
                target: "agent.sandbox",
                "Failed to configure loopback (ip command not found): {}. Localhost connections may fail.",
                e
            );
            Ok(())
        }
    }
}
