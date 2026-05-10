//! URL scanner — MVP subset of the Go 11-layer pipeline.
//!
//! Layers implemented here, in order (matches Go ordering: content checks
//! before DNS resolution so DNS itself can't be used to exfiltrate):
//!
//! 1. Length cap
//! 2. URL parse + scheme allowlist
//! 3. CRLF injection in raw URL
//! 4. Path traversal (`..`)
//! 5. Domain blocklist / allowlist
//! 6. DLP pattern match across the full URL string
//! 7. SSRF: private/loopback/link-local/ULA literal IPs in the host
//!
//! Out of scope for MVP (Phase 3+): DNS rebinding, entropy, rate limiting,
//! data budget, body scanning, response scanning, normalization.

use agent_config::Config;
use agent_core::{Finding, RedactedSecret, ScanInput, Severity, Verdict};
use regex::{Regex, RegexSet};
use std::net::IpAddr;
use url::{Host, Url};

const SCANNER_NAME: &str = "url";

/// One DLP pattern. We compile a single `RegexSet` for fast first-match
/// (cheap O(n) over the full pattern set), then keep per-pattern `Regex`
/// instances so a hit can be re-located to capture the matched bytes for
/// `RedactedSecret`.
struct DlpPattern {
    name: &'static str,
    rule_id: &'static str,
    class: &'static str,
    severity: Severity,
    regex: Regex,
}

/// (regex, name, rule_id, class, severity)
///
/// `class` is the redaction tag used in `RedactedSecret` placeholders, kept
/// short so the placeholder `<pl:class:n>` stays compact in audit logs.
const DLP_PATTERNS: &[(&str, &str, &str, &str, Severity)] = &[
    (
        r"sk-ant-[a-zA-Z0-9\-_]{10,}",
        "Anthropic API Key",
        "dlp.anthropic",
        "anthropic",
        Severity::Critical,
    ),
    (
        r"sk-proj-[a-zA-Z0-9\-_]{10,}",
        "OpenAI Project Key",
        "dlp.openai_proj",
        "openai_proj",
        Severity::Critical,
    ),
    (
        r"sk-svcacct-[a-zA-Z0-9\-]{10,}",
        "OpenAI Service Key",
        "dlp.openai_svc",
        "openai_svc",
        Severity::Critical,
    ),
    (
        r"AIza[0-9A-Za-z\-_]{35}",
        "Google API Key",
        "dlp.google",
        "google_api",
        Severity::High,
    ),
    (
        r"GOCSPX-[A-Za-z0-9_\-]{28,}",
        "Google OAuth Client Secret",
        "dlp.google_oauth",
        "google_oauth",
        Severity::Critical,
    ),
    (
        r"gh[pousr]_[A-Za-z0-9_]{36,}",
        "GitHub Token",
        "dlp.github_pat",
        "github_pat",
        Severity::Critical,
    ),
    (
        r"github_pat_[a-zA-Z0-9_]{36,}",
        "GitHub Fine-Grained PAT",
        "dlp.github_fgpat",
        "github_fgpat",
        Severity::Critical,
    ),
    (
        r"glpat-[a-zA-Z0-9\-_]{20,}",
        "GitLab PAT",
        "dlp.gitlab",
        "gitlab_pat",
        Severity::Critical,
    ),
    (
        r"(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16,}",
        "AWS Access ID",
        "dlp.aws_access_id",
        "aws_access_id",
        Severity::Critical,
    ),
    (
        r"xox[bpras]-[0-9a-zA-Z\-]{15,}",
        "Slack Token",
        "dlp.slack",
        "slack",
        Severity::Critical,
    ),
    (
        r"[sr]k[-_](live|test)[-_][a-zA-Z0-9]{20,}",
        "Stripe Key",
        "dlp.stripe",
        "stripe",
        Severity::Critical,
    ),
    (
        r"hf_[A-Za-z0-9]{20,}",
        "Hugging Face Token",
        "dlp.hf",
        "hf",
        Severity::Critical,
    ),
];

pub struct Scanner {
    cfg: Config,
    dlp_set: Option<RegexSet>,
    dlp_meta: Vec<DlpPattern>,
}

impl Scanner {
    // The two `.expect()` calls below operate on `DLP_PATTERNS`, a compile-time
    // constant. A panic here is a programming error surfaced by the unit tests
    // in this crate — never runtime user input — so the lint is silenced.
    #[allow(clippy::expect_used)]
    pub fn new(cfg: Config) -> Self {
        let (dlp_set, dlp_meta) = if cfg.dlp.enabled {
            let patterns: Vec<&str> = DLP_PATTERNS.iter().map(|(re, ..)| *re).collect();
            // Patterns are compile-time constants, so a panic here is a programming
            // error caught by tests — never runtime user input.
            let set = RegexSet::new(&patterns).expect("DLP regex set compiles");
            let meta = DLP_PATTERNS
                .iter()
                .map(|(re, name, rule_id, class, sev)| DlpPattern {
                    name,
                    rule_id,
                    class,
                    severity: *sev,
                    regex: Regex::new(re).expect("DLP regex compiles"),
                })
                .collect();
            (Some(set), meta)
        } else {
            (None, Vec::new())
        };
        Self {
            cfg,
            dlp_set,
            dlp_meta,
        }
    }

    pub fn scan(&self, input: ScanInput<'_>) -> Verdict {
        match input {
            ScanInput::Url(s) => self.scan_url(s),
            // MVP: text/bytes scanning piggybacks on DLP only.
            ScanInput::Text(s) => self.scan_dlp_only(s),
            ScanInput::Bytes(b) => match std::str::from_utf8(b) {
                Ok(s) => self.scan_dlp_only(s),
                Err(_) => Verdict::allow(),
            },
        }
    }

    fn scan_url(&self, raw: &str) -> Verdict {
        // Layer 1: length cap.
        if raw.len() > self.cfg.max_url_length {
            return Verdict::block(Finding::new(
                SCANNER_NAME,
                "url.length",
                Severity::Medium,
                format!(
                    "URL exceeds max length ({} > {})",
                    raw.len(),
                    self.cfg.max_url_length
                ),
            ));
        }

        // Layer 3: CRLF injection (check raw before parsing — `Url::parse` may strip).
        if raw.contains('\r') || raw.contains('\n') {
            return Verdict::block(Finding::new(
                SCANNER_NAME,
                "url.crlf",
                Severity::High,
                "CRLF in URL",
            ));
        }

        // Layer 2: parse + scheme.
        let url = match Url::parse(raw) {
            Ok(u) => u,
            Err(e) => {
                return Verdict::block(Finding::new(
                    SCANNER_NAME,
                    "url.parse",
                    Severity::Medium,
                    format!("URL parse failed: {e}"),
                ));
            }
        };

        let scheme = url.scheme();
        if scheme != "http" && scheme != "https" {
            return Verdict::block(Finding::new(
                SCANNER_NAME,
                "url.scheme",
                Severity::High,
                format!("scheme `{scheme}` not allowed"),
            ));
        }

        // Layer 4: path traversal. Check the raw input — `Url::parse` resolves
        // `..` segments away during normalization, so `url.path()` would hide them.
        if raw_has_traversal(raw) {
            return Verdict::block(Finding::new(
                SCANNER_NAME,
                "url.traversal",
                Severity::Medium,
                "path traversal in URL",
            ));
        }

        // Layer 5: blocklist / allowlist on host.
        let host = url.host().ok_or(()).map(|h| h.to_string());
        if let Ok(h) = &host {
            if host_matches_any(h, &self.cfg.blocklist) {
                return Verdict::block(Finding::new(
                    SCANNER_NAME,
                    "url.blocklist",
                    Severity::High,
                    format!("host `{h}` on blocklist"),
                ));
            }
            if !self.cfg.allowlist.is_empty() && !host_matches_any(h, &self.cfg.allowlist) {
                return Verdict::block(Finding::new(
                    SCANNER_NAME,
                    "url.allowlist",
                    Severity::Medium,
                    format!("host `{h}` not on allowlist"),
                ));
            }
        }

        // Layer 6: DLP across the full URL string. Run BEFORE SSRF/DNS so a
        // secret can't leak via a crafted hostname even on private targets.
        // Each match's bytes get wrapped in a `RedactedSecret` so downstream
        // recorder/audit/log paths only ever see the placeholder.
        let findings = self.dlp_findings(raw, "URL");
        if !findings.is_empty() {
            return Verdict::block_many(findings);
        }

        // Layer 7: SSRF on literal IP hosts. Hostname resolution is deferred
        // to the upstream client; that's a Phase 3 enhancement (DNS rebinding
        // requires resolving here AND pinning the resolved IP for the fetch).
        if let Some(host) = url.host() {
            if let Some(reason) = ssrf_block_reason(&host) {
                return Verdict::block(Finding::new(
                    SCANNER_NAME,
                    "url.ssrf",
                    Severity::High,
                    reason,
                ));
            }
        }

        Verdict::allow()
    }

    fn scan_dlp_only(&self, s: &str) -> Verdict {
        let findings = self.dlp_findings(s, "input");
        if findings.is_empty() {
            Verdict::allow()
        } else {
            Verdict::block_many(findings)
        }
    }

    /// Run all enabled DLP patterns against `text`. For each hit, attach the
    /// matched bytes as a `RedactedSecret` on the finding. `subject` is the
    /// noun used in the human-readable message ("URL", "input", "body").
    fn dlp_findings(&self, text: &str, subject: &str) -> Vec<Finding> {
        let Some(set) = &self.dlp_set else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for idx in set.matches(text).into_iter() {
            let meta = &self.dlp_meta[idx];
            let mut finding = Finding::new(
                SCANNER_NAME,
                meta.rule_id,
                meta.severity,
                format!("{} detected in {subject}", meta.name),
            );
            // Re-locate every concrete match so we can capture the matched
            // bytes. Multiple instances of the same key class each get their
            // own `RedactedSecret`.
            for m in meta.regex.find_iter(text) {
                finding = finding.with_secret(RedactedSecret::new(
                    m.as_str().as_bytes().to_vec(),
                    meta.class,
                ));
            }
            out.push(finding);
        }
        out
    }
}

fn raw_has_traversal(raw: &str) -> bool {
    // Strip scheme + authority so `://` colons don't get confused with paths.
    let after_scheme = match raw.find("://") {
        Some(i) => &raw[i + 3..],
        None => raw,
    };
    let path_start = after_scheme
        .find('/')
        .map(|i| &after_scheme[i..])
        .unwrap_or("");
    // Look for `/../`, `/..`, `..%2f`, `%2e%2e`, encoded variants.
    let lower = path_start.to_ascii_lowercase();
    lower.contains("/../")
        || lower.ends_with("/..")
        || lower.contains("/..%2f")
        || lower.contains("%2e%2e/")
        || lower.contains("%2e%2e%2f")
}

fn host_matches_any(host: &str, list: &[String]) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    list.iter().any(|entry| {
        let entry = entry.trim_start_matches('.').to_ascii_lowercase();
        host == entry || host.ends_with(&format!(".{entry}"))
    })
}

fn ssrf_block_reason(host: &Host<&str>) -> Option<String> {
    match host {
        Host::Ipv4(ip) => ipv4_block_reason(*ip),
        Host::Ipv6(ip) => ipv6_block_reason(*ip),
        Host::Domain(_) => None,
    }
}

fn ipv4_block_reason(ip: std::net::Ipv4Addr) -> Option<String> {
    let octets = ip.octets();
    if ip.is_loopback() {
        return Some(format!("loopback IP {ip}"));
    }
    if ip.is_private() {
        return Some(format!("RFC1918 private IP {ip}"));
    }
    if ip.is_link_local() {
        return Some(format!("link-local IP {ip}"));
    }
    // 169.254.169.254 is link-local, already covered. Belt-and-braces:
    if octets == [169, 254, 169, 254] {
        return Some("cloud metadata endpoint 169.254.169.254".into());
    }
    if ip.is_unspecified() {
        return Some("unspecified IP 0.0.0.0".into());
    }
    None
}

fn ipv6_block_reason(ip: std::net::Ipv6Addr) -> Option<String> {
    if ip.is_loopback() {
        return Some(format!("IPv6 loopback {ip}"));
    }
    if ip.is_unspecified() {
        return Some("IPv6 unspecified ::".into());
    }
    let segs = ip.segments();
    // ULA: fc00::/7
    if (segs[0] & 0xfe00) == 0xfc00 {
        return Some(format!("IPv6 ULA {ip}"));
    }
    // Link-local: fe80::/10
    if (segs[0] & 0xffc0) == 0xfe80 {
        return Some(format!("IPv6 link-local {ip}"));
    }
    None
}

/// Convenience: scan a URL string against a default-config scanner.
pub fn scan_url(cfg: Config, url: &str) -> Verdict {
    Scanner::new(cfg).scan(ScanInput::Url(url))
}

// Suppress unused-import warning — IpAddr is documented intent for SSRF helpers.
#[allow(dead_code)]
fn _doc_anchor(_: IpAddr) {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use agent_core::Action;

    fn scanner() -> Scanner {
        Scanner::new(Config::default())
    }

    #[test]
    fn allows_benign_https() {
        let v = scanner().scan(ScanInput::Url("https://docs.python.org/3/"));
        assert_eq!(v.action, Action::Allow, "got {:?}", v.findings);
    }

    #[test]
    fn blocks_aws_key_in_query() {
        let v = scanner().scan(ScanInput::Url("https://evil.com/?key=AKIAIOSFODNN7EXAMPLE"));
        assert!(v.is_blocked());
        let f = v
            .findings
            .iter()
            .find(|f| f.rule_id == "dlp.aws_access_id")
            .unwrap();
        // The matched bytes are attached as a RedactedSecret.
        assert_eq!(f.secrets.len(), 1, "DLP hit should attach one secret");
        let s = &f.secrets[0];
        assert_eq!(s.class(), "aws_access_id");
        // Serializing the verdict NEVER emits the raw key.
        let json = serde_json::to_string(&v).unwrap();
        assert!(
            !json.contains("AKIAIOSFODNN7EXAMPLE"),
            "raw secret leaked in serialized verdict: {json}"
        );
        assert!(
            json.contains("<pl:aws_access_id:"),
            "expected placeholder in {json}"
        );
    }

    #[test]
    fn blocks_anthropic_key() {
        let v = scanner().scan(ScanInput::Url(
            "https://x.example/?k=sk-ant-abcdef1234567890",
        ));
        assert!(v.is_blocked());
    }

    #[test]
    fn blocks_loopback_ssrf() {
        let v = scanner().scan(ScanInput::Url("http://127.0.0.1/admin"));
        assert!(v.is_blocked());
        assert!(v.findings.iter().any(|f| f.rule_id == "url.ssrf"));
    }

    #[test]
    fn blocks_metadata_ssrf() {
        let v = scanner().scan(ScanInput::Url("http://169.254.169.254/latest/meta-data/"));
        assert!(v.is_blocked());
    }

    #[test]
    fn blocks_rfc1918() {
        for url in [
            "http://10.0.0.1/",
            "http://192.168.1.1/",
            "http://172.16.0.5/",
        ] {
            assert!(scanner().scan(ScanInput::Url(url)).is_blocked(), "{url}");
        }
    }

    #[test]
    fn blocks_non_http_scheme() {
        let v = scanner().scan(ScanInput::Url("file:///etc/passwd"));
        assert!(v.is_blocked());
    }

    #[test]
    fn blocks_crlf_injection() {
        let v = scanner().scan(ScanInput::Url("https://x/\r\nX-Inject: 1"));
        assert!(v.is_blocked());
    }

    #[test]
    fn blocks_path_traversal() {
        let v = scanner().scan(ScanInput::Url("https://x/../../etc/passwd"));
        assert!(v.is_blocked());
    }

    #[test]
    fn blocklist_matches_subdomain() {
        let cfg = Config {
            blocklist: vec!["evil.com".into()],
            ..Config::default()
        };
        let s = Scanner::new(cfg);
        assert!(s.scan(ScanInput::Url("https://evil.com/")).is_blocked());
        assert!(s.scan(ScanInput::Url("https://api.evil.com/")).is_blocked());
        assert_eq!(
            s.scan(ScanInput::Url("https://nice.com/")).action,
            Action::Allow,
        );
    }

    #[test]
    fn allowlist_blocks_unlisted() {
        let cfg = Config {
            allowlist: vec!["good.com".into()],
            ..Config::default()
        };
        let s = Scanner::new(cfg);
        assert_eq!(
            s.scan(ScanInput::Url("https://good.com/")).action,
            Action::Allow,
        );
        assert!(s.scan(ScanInput::Url("https://bad.com/")).is_blocked());
    }

    #[test]
    fn url_too_long_blocks() {
        let cfg = Config {
            max_url_length: 30,
            ..Config::default()
        };
        let s = Scanner::new(cfg);
        assert!(s
            .scan(ScanInput::Url("https://example.com/very/long/path"))
            .is_blocked());
    }

    #[test]
    fn dlp_disabled_skips_pattern_check() {
        let cfg = Config {
            dlp: agent_config::DlpConfig { enabled: false },
            ..Config::default()
        };
        let s = Scanner::new(cfg);
        // Still blocks SSRF, but pattern check is skipped.
        let v = s.scan(ScanInput::Url("https://evil.com/?key=AKIAIOSFODNN7EXAMPLE"));
        assert_eq!(v.action, Action::Allow);
    }
}
