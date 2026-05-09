//! Shared types used across every pipelock-rs crate.
//!
//! Kept dependency-light on purpose: every other crate depends on this one,
//! so anything pulled in here lands in the whole graph.

use serde::{Deserialize, Serialize, Serializer};
use zeroize::Zeroize;

/// What the firewall decided to do with a request, response, or tool call.
///
/// `Block` is the fail-closed default: any unrecoverable error on the scan
/// path collapses to `Block` at the proxy edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Block,
    Warn,
    Strip,
    Ask,
    Redirect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// An owned secret captured by a scanner.
///
/// Invariants enforced by the type system, not by convention:
///   - Bytes are zeroized on drop (`zeroize` crate).
///   - `Debug` and `Display` print the placeholder, **never** the bytes.
///   - `Serialize` writes the placeholder string, never the bytes.
///   - There is no public accessor for the raw bytes from outside this module.
///
/// This is the Rust counterpart of the Go redact package's `<pl:class:n>`
/// placeholder system, but lifted into a real type so the compiler — not a
/// reviewer — proves no path leaks the secret to a recorder, log, or wire.
///
/// To inspect the bytes (e.g., for a hash, length check, allowlist match) use
/// [`RedactedSecret::with_bytes`], which hands a `&[u8]` to a closure but
/// never returns it. Callers cannot stash the slice past the closure body.
#[derive(Clone)]
pub struct RedactedSecret {
    bytes: Vec<u8>,
    class: String,
}

impl RedactedSecret {
    /// Wrap matched bytes under a class label (e.g., `"aws_access_id"`).
    pub fn new(bytes: impl Into<Vec<u8>>, class: impl Into<String>) -> Self {
        Self {
            bytes: bytes.into(),
            class: class.into(),
        }
    }

    /// Class tag (e.g., `"github_pat"`).
    pub fn class(&self) -> &str {
        &self.class
    }

    /// Length in bytes — safe to expose; reveals nothing about contents.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The redaction placeholder used in logs, audit records, and serde:
    /// `<pl:class:len>`.
    pub fn placeholder(&self) -> String {
        format!("<pl:{}:{}>", self.class, self.bytes.len())
    }

    /// Borrow the secret bytes inside a closure. The slice cannot escape.
    /// Use only for hashing / comparison / verification — never for logging.
    pub fn with_bytes<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        f(&self.bytes)
    }
}

impl Drop for RedactedSecret {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl std::fmt::Debug for RedactedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Intentionally identical to Display — Debug must not leak bytes.
        f.write_str(&self.placeholder())
    }
}

impl std::fmt::Display for RedactedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.placeholder())
    }
}

impl Serialize for RedactedSecret {
    fn serialize<S: Serializer>(&self, ser: S) -> std::result::Result<S::Ok, S::Error> {
        ser.serialize_str(&self.placeholder())
    }
}

// We deliberately do NOT implement Deserialize. A redacted secret should never
// round-trip back into bytes from JSON — once placeholdered, it stays that way.

/// A single thing a scanner found. Many findings can attach to one verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub scanner: String,
    pub rule_id: String,
    pub severity: Severity,
    pub message: String,
    /// Any secrets the rule captured. Serialized as placeholders only.
    #[serde(default, skip_deserializing)]
    pub secrets: Vec<RedactedSecret>,
}

impl Finding {
    pub fn new(
        scanner: impl Into<String>,
        rule_id: impl Into<String>,
        severity: Severity,
        message: impl Into<String>,
    ) -> Self {
        Self {
            scanner: scanner.into(),
            rule_id: rule_id.into(),
            severity,
            message: message.into(),
            secrets: Vec::new(),
        }
    }

    /// Builder-style: attach a captured secret to this finding.
    pub fn with_secret(mut self, secret: RedactedSecret) -> Self {
        self.secrets.push(secret);
        self
    }
}

/// The verdict returned from a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub action: Action,
    pub findings: Vec<Finding>,
}

impl Verdict {
    pub fn allow() -> Self {
        Self {
            action: Action::Allow,
            findings: Vec::new(),
        }
    }

    pub fn block(finding: Finding) -> Self {
        Self {
            action: Action::Block,
            findings: vec![finding],
        }
    }

    pub fn block_many(findings: Vec<Finding>) -> Self {
        Self {
            action: Action::Block,
            findings,
        }
    }

    pub fn is_blocked(&self) -> bool {
        matches!(self.action, Action::Block)
    }
}

/// What gets handed to a scanner.
#[derive(Debug, Clone)]
pub enum ScanInput<'a> {
    Url(&'a str),
    Text(&'a str),
    Bytes(&'a [u8]),
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("scan error: {0}")]
    Scan(String),
    #[error("config error: {0}")]
    Config(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_format() {
        let s = RedactedSecret::new(b"AKIAIOSFODNN7EXAMPLE".to_vec(), "aws_access_id");
        assert_eq!(s.placeholder(), "<pl:aws_access_id:20>");
    }

    #[test]
    fn debug_and_display_never_leak_bytes() {
        let s = RedactedSecret::new(b"sk-ant-supersecret".to_vec(), "anthropic");
        let d = format!("{s:?}");
        let p = format!("{s}");
        assert_eq!(d, "<pl:anthropic:18>");
        assert_eq!(p, "<pl:anthropic:18>");
        assert!(!d.contains("supersecret"));
        assert!(!p.contains("supersecret"));
    }

    #[test]
    fn serde_writes_placeholder_not_bytes() {
        let s = RedactedSecret::new(b"ghp_secret_token_123".to_vec(), "github_pat");
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, "\"<pl:github_pat:20>\"");
        assert!(!json.contains("ghp_secret_token_123"));
    }

    #[test]
    fn finding_with_secret_serializes_placeholder() {
        let f = Finding::new(
            "url",
            "dlp.aws_access_id",
            Severity::Critical,
            "AWS key in URL",
        )
        .with_secret(RedactedSecret::new(
            b"AKIAIOSFODNN7EXAMPLE",
            "aws_access_id",
        ));
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("<pl:aws_access_id:20>"));
        assert!(!json.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn with_bytes_can_inspect_but_not_return() {
        let s = RedactedSecret::new(b"abc", "test");
        let len = s.with_bytes(|b| b.len());
        assert_eq!(len, 3);
        // Compile-fail check (commented since it's the point):
        //   let leaked: &[u8] = s.with_bytes(|b| b);  // borrow does not outlive closure
    }
}
