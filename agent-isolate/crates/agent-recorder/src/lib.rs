//! Append-only JSONL evidence log with a BLAKE3 hash chain.
//!
//! Each record carries `prev_hash` = BLAKE3 of the previous serialized record
//! (or 64 zeros for the genesis line). On rotation/restart the chain
//! continues by re-reading the last line. Ed25519 checkpoints are deferred
//! to Phase 3 (see `agent-signing`).

use parking_lot::Mutex;
use agent_core::Verdict;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Record {
    pub id: String,
    pub timestamp_ms: u64,
    pub kind: String,
    pub host: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub verdict: Verdict,
    pub prev_hash: String,
}

#[derive(thiserror::Error, Debug)]
pub enum RecorderError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

struct Inner {
    file: File,
    last_hash: String,
}

#[derive(Clone)]
pub struct Recorder {
    inner: Arc<Mutex<Inner>>,
    path: PathBuf,
}

impl Recorder {
    /// Open or create a JSONL file. Reads the last line to recover the chain
    /// tail; if the file is empty or missing, starts from the genesis hash.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RecorderError> {
        let path = path.as_ref().to_path_buf();
        let last_hash = recover_tail_hash(&path)?;
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(Inner { file, last_hash })),
            path,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one record. Fills in `id`, `timestamp_ms`, and `prev_hash`.
    pub fn append(
        &self,
        kind: &str,
        host: Option<&str>,
        method: Option<&str>,
        path: Option<&str>,
        verdict: &Verdict,
    ) -> Result<String, RecorderError> {
        let mut inner = self.inner.lock();

        let record = Record {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp_ms: now_ms(),
            kind: kind.into(),
            host: host.map(str::to_string),
            method: method.map(str::to_string),
            path: path.map(str::to_string),
            verdict: verdict.clone(),
            prev_hash: inner.last_hash.clone(),
        };

        let line = serde_json::to_string(&record)?;
        let next_hash = hex::encode(blake3::hash(line.as_bytes()).as_bytes());

        inner.file.write_all(line.as_bytes())?;
        inner.file.write_all(b"\n")?;
        inner.file.flush()?;
        inner.last_hash = next_hash;

        Ok(record.id)
    }

    /// Read the file back into memory (for tests + audit verification).
    pub fn read_all(&self) -> Result<Vec<Record>, RecorderError> {
        let path = self.path.clone();
        let f = match File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut out = Vec::new();
        for line in BufReader::new(f).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            out.push(serde_json::from_str(&line)?);
        }
        Ok(out)
    }
}

fn recover_tail_hash(path: &Path) -> Result<String, RecorderError> {
    let f = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(GENESIS_HASH.to_string());
        }
        Err(e) => return Err(e.into()),
    };
    let mut last_line = String::new();
    for line in BufReader::new(f).lines() {
        let line = line?;
        if !line.trim().is_empty() {
            last_line = line;
        }
    }
    if last_line.is_empty() {
        return Ok(GENESIS_HASH.to_string());
    }
    Ok(hex::encode(blake3::hash(last_line.as_bytes()).as_bytes()))
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Verify a chain end-to-end. Returns the index of the first broken link, or
/// `None` if the chain is intact.
pub fn verify_chain(records: &[Record]) -> Option<usize> {
    let mut prev = GENESIS_HASH.to_string();
    for (i, rec) in records.iter().enumerate() {
        if rec.prev_hash != prev {
            return Some(i);
        }
        let Ok(line) = serde_json::to_string(rec) else {
            return Some(i);
        };
        prev = hex::encode(blake3::hash(line.as_bytes()).as_bytes());
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use agent_core::{Finding, Severity, Verdict};
    use tempfile::tempdir;

    fn block_v() -> Verdict {
        Verdict::block(Finding::new("url", "dlp.test", Severity::High, "test"))
    }

    #[test]
    fn appends_and_chains() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("evidence.jsonl");
        let rec = Recorder::open(&path).unwrap();

        rec.append(
            "request",
            Some("evil.com"),
            Some("GET"),
            Some("/"),
            &block_v(),
        )
        .unwrap();
        rec.append(
            "request",
            Some("ok.com"),
            Some("GET"),
            Some("/"),
            &Verdict::allow(),
        )
        .unwrap();
        rec.append(
            "request",
            Some("ok.com"),
            Some("GET"),
            Some("/2"),
            &Verdict::allow(),
        )
        .unwrap();

        let records = rec.read_all().unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].prev_hash, GENESIS_HASH);
        assert_ne!(records[1].prev_hash, GENESIS_HASH);
        assert!(verify_chain(&records).is_none(), "chain should verify");
    }

    #[test]
    fn detects_tampering() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("evidence.jsonl");
        let rec = Recorder::open(&path).unwrap();
        rec.append("request", Some("a.com"), None, None, &Verdict::allow())
            .unwrap();
        rec.append("request", Some("b.com"), None, None, &Verdict::allow())
            .unwrap();

        let mut records = rec.read_all().unwrap();
        records[0].host = Some("tampered.com".into());
        assert!(
            verify_chain(&records).is_some(),
            "tampering record 0 should break chain at record 1"
        );
    }

    #[test]
    fn recovers_chain_across_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("evidence.jsonl");
        {
            let r1 = Recorder::open(&path).unwrap();
            r1.append("request", Some("a.com"), None, None, &Verdict::allow())
                .unwrap();
        }
        let r2 = Recorder::open(&path).unwrap();
        r2.append("request", Some("b.com"), None, None, &Verdict::allow())
            .unwrap();
        let records = r2.read_all().unwrap();
        assert_eq!(records.len(), 2);
        assert!(verify_chain(&records).is_none());
    }
}
