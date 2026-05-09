//! pipelock — AI agent firewall (Rust port).
//!
//! Subcommand surface mirrors the Go `cmd/pipelock` CLI. Most subcommands
//! print "not implemented" until the matching crate lands in a later phase.

use clap::{Parser, Subcommand};
use pipelock_audit::Auditor;
use pipelock_config::{load_from_path, Config};
use pipelock_core::ScanInput;
use pipelock_recorder::Recorder;
use pipelock_scanner::Scanner;

#[cfg(target_os = "linux")]
use pipelock_sandbox::{is_sandbox_init, run_init};

#[derive(Parser, Debug)]
#[command(name = "pipelock", version, about, long_about = None)]
struct Cli {
    /// Path to pipelock.yaml.
    #[arg(short, long, global = true)]
    config: Option<String>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Start the proxy.
    Run,
    /// Run a single scan check (URL or text).
    Check {
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        text: Option<String>,
    },
    /// Initialize config and IDE integrations.
    Init,
    /// Verify local install and detection paths.
    VerifyInstall,
    /// Run a command inside the sandbox.
    Sandbox {
        /// Command to run inside sandbox
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
        /// Workspace directory
        #[arg(long)]
        workspace: Option<String>,
        /// Enable strict mode (fail-closed)
        #[arg(long)]
        strict: bool,
    },
    /// MCP proxy (stdio / HTTP / SSE / WS).
    Mcp,
    /// Inspect, query, or sign audit logs.
    Audit,
    /// Manage policies.
    Policy,
    /// Manage rules.
    Rules,
    /// Generate canary tokens, configs, certs.
    Generate,
    /// Run security assessment.
    Assess,
    /// Diagnose local setup.
    Diagnose,
    /// Verify a signed receipt.
    VerifyReceipt,
    /// Generate an audit/risk report.
    Report,
    /// Manage signing keys.
    Signing,
    /// Manage agent sessions.
    Session,
}

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).with_target(false).init();
}

fn load_config(path: Option<&str>) -> anyhow::Result<Config> {
    match path {
        Some(p) => Ok(load_from_path(p)?),
        None => Ok(Config::default()),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Check if we're in sandbox-init mode (re-exec'd child)
    #[cfg(target_os = "linux")]
    {
        if is_sandbox_init() {
            run_init(); // Does not return
        }
    }

    init_tracing();
    let cli = Cli::parse();

    match cli.cmd {
        Cmd::Run => {
            let cfg = load_config(cli.config.as_deref())?;
            let recorder = match cfg.recorder_path.as_deref() {
                Some(p) => Some(Recorder::open(p)?),
                None => None,
            };
            let auditor = Auditor::new(recorder);
            let addr: std::net::SocketAddr = cfg
                .listen
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid listen addr `{}`: {e}", cfg.listen))?;
            tracing::info!(target: "pipelock", %addr, "starting proxy");
            pipelock_proxy::serve(addr, cfg, auditor).await?;
        }
        Cmd::Check { url, text } => {
            let cfg = load_config(cli.config.as_deref())?;
            let scanner = Scanner::new(cfg);
            let verdict = match (url.as_deref(), text.as_deref()) {
                (Some(u), _) => scanner.scan(ScanInput::Url(u)),
                (None, Some(t)) => scanner.scan(ScanInput::Text(t)),
                (None, None) => {
                    eprintln!("pipelock check: pass --url or --text");
                    std::process::exit(2);
                }
            };
            println!("{}", serde_json::to_string_pretty(&verdict)?);
            if verdict.is_blocked() {
                std::process::exit(1);
            }
        }
        #[cfg(target_os = "linux")]
        Cmd::Sandbox {
            command,
            workspace,
            strict,
        } => {
            use pipelock_sandbox::{launch_sandboxed, LaunchConfig};
            use std::path::PathBuf;

            if command.is_empty() {
                eprintln!("pipelock sandbox: no command specified");
                std::process::exit(2);
            }

            let workspace = workspace
                .map(PathBuf::from)
                .or_else(|| std::env::current_dir().ok())
                .ok_or_else(|| anyhow::anyhow!("could not determine workspace"))?;

            let config = LaunchConfig {
                command,
                workspace,
                policy: None, // Use default policy
                strict,
                best_effort: !strict,
                extra_env: vec![],
            };

            let status = launch_sandboxed(config)?;
            std::process::exit(status.code().unwrap_or(1));
        }
        #[cfg(not(target_os = "linux"))]
        Cmd::Sandbox { .. } => {
            eprintln!("pipelock sandbox: only supported on Linux");
            std::process::exit(1);
        }
        Cmd::Init => println!("pipelock init: not implemented"),
        Cmd::VerifyInstall => println!("pipelock verify-install: not implemented"),
        Cmd::Mcp => println!("pipelock mcp: not implemented"),
        Cmd::Audit => println!("pipelock audit: not implemented"),
        Cmd::Policy => println!("pipelock policy: not implemented"),
        Cmd::Rules => println!("pipelock rules: not implemented"),
        Cmd::Generate => println!("pipelock generate: not implemented"),
        Cmd::Assess => println!("pipelock assess: not implemented"),
        Cmd::Diagnose => println!("pipelock diagnose: not implemented"),
        Cmd::VerifyReceipt => println!("pipelock verify-receipt: not implemented"),
        Cmd::Report => println!("pipelock report: not implemented"),
        Cmd::Signing => println!("pipelock signing: not implemented"),
        Cmd::Session => println!("pipelock session: not implemented"),
    }

    Ok(())
}
