//! Audit event emitter.
//!
//! Thin wrapper around `tracing` (structured JSON logs) plus the JSONL
//! recorder. Every audit call goes to BOTH sinks, so observability stays in
//! sync with the on-disk evidence chain.

use agent_core::Verdict;
use agent_recorder::Recorder;

#[derive(Clone)]
pub struct Auditor {
    recorder: Option<Recorder>,
}

impl Auditor {
    pub fn new(recorder: Option<Recorder>) -> Self {
        Self { recorder }
    }

    /// Emit one request decision. Failures to write to the recorder are
    /// logged at ERROR but never panic — fail-closed lives at the proxy
    /// edge, not here. The proxy already decided to block/allow before
    /// calling us.
    pub fn emit_request(
        &self,
        host: Option<&str>,
        method: Option<&str>,
        path: Option<&str>,
        verdict: &Verdict,
    ) {
        let action = format!("{:?}", verdict.action);
        if verdict.is_blocked() {
            tracing::warn!(
                target: "agent.audit",
                kind = "request",
                host = host.unwrap_or(""),
                method = method.unwrap_or(""),
                path = path.unwrap_or(""),
                action = %action,
                findings = verdict.findings.len(),
                "blocked",
            );
        } else {
            tracing::info!(
                target: "agent.audit",
                kind = "request",
                host = host.unwrap_or(""),
                method = method.unwrap_or(""),
                path = path.unwrap_or(""),
                action = %action,
                "allowed",
            );
        }

        if let Some(rec) = &self.recorder {
            if let Err(e) = rec.append("request", host, method, path, verdict) {
                tracing::error!(target: "agent.audit", error = %e, "recorder append failed");
            }
        }
    }
}
