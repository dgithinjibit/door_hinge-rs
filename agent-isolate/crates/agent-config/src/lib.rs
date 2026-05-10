//! Minimal YAML config for the MVP.
//!
//! Hot-reload (`notify` + `arc-swap`) lands in Phase 3. For now this is a
//! single-shot loader that reads a `agent.yaml` and returns a `Config`.

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_listen")]
    pub listen: String,

    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Domain allowlist. If non-empty, only these hosts (exact match or
    /// suffix-match for `.example.com`) are permitted.
    #[serde(default)]
    pub allowlist: Vec<String>,

    /// Domain blocklist. Always denied.
    #[serde(default)]
    pub blocklist: Vec<String>,

    #[serde(default)]
    pub dlp: DlpConfig,

    #[serde(default = "default_max_url_length")]
    pub max_url_length: usize,

    /// Path to the JSONL evidence log. `None` disables on-disk recording.
    #[serde(default)]
    pub recorder_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            log_level: default_log_level(),
            allowlist: Vec::new(),
            blocklist: Vec::new(),
            dlp: DlpConfig::default(),
            max_url_length: default_max_url_length(),
            recorder_path: None,
        }
    }
}

impl Default for DlpConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

fn default_listen() -> String {
    "127.0.0.1:9999".into()
}
fn default_log_level() -> String {
    "info".into()
}
fn default_max_url_length() -> usize {
    8192
}
fn default_true() -> bool {
    true
}

#[derive(thiserror::Error, Debug)]
pub enum ConfigError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("yaml: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

pub fn load_default() -> Config {
    Config::default()
}

pub fn load_from_path(path: impl AsRef<Path>) -> Result<Config, ConfigError> {
    let bytes = std::fs::read(path)?;
    let cfg: Config = serde_yaml::from_slice(&bytes)?;
    Ok(cfg)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let cfg = Config::default();
        assert_eq!(cfg.listen, "127.0.0.1:9999");
        assert!(cfg.dlp.enabled);
        assert_eq!(cfg.max_url_length, 8192);
    }

    #[test]
    fn parses_minimal_yaml() {
        let yaml = "listen: 0.0.0.0:8080\nblocklist: [evil.com]\n";
        let cfg: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.listen, "0.0.0.0:8080");
        assert_eq!(cfg.blocklist, vec!["evil.com"]);
        assert!(
            cfg.dlp.enabled,
            "dlp.enabled defaults to true when section omitted"
        );
    }

    #[test]
    fn parses_empty_yaml_with_defaults() {
        let cfg: Config = serde_yaml::from_str("{}").unwrap();
        assert_eq!(cfg.listen, "127.0.0.1:9999");
        assert!(cfg.allowlist.is_empty());
    }
}
