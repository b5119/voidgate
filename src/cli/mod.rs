//! Command-line interface: `voidgate run | update-lists | stats`.
//!
//! Exit codes: `0` success, `1` configuration error, `2` runtime error.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use thiserror::Error;

use crate::blocklists::cache;
use crate::config::AppConfig;

/// Parsed command line.
#[derive(Debug, Parser)]
#[command(
    name = "voidgate",
    version,
    about = "DNS sinkhole ad blocker with per-device and per-network policies"
)]
pub struct Cli {
    /// Path to the configuration file.
    #[arg(short, long, global = true, default_value = "config.yaml")]
    pub config: PathBuf,

    /// The subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// The three operations voidgate exposes.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the DNS server (UDP + TCP listeners).
    Run,
    /// Fetch blocklists into the cache directory (atomic temp + rename).
    UpdateLists,
    /// Show query statistics from the SQLite log.
    Stats,
}

/// Errors surfaced by [`run`], mapped onto process exit codes.
#[derive(Debug, Error)]
enum CliError {
    /// Invalid or unreadable configuration → exit code 1.
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),

    /// A fatal blocklist/cache failure → exit code 2.
    #[error(transparent)]
    Blocklist(#[from] crate::blocklists::BlocklistError),

    /// Anything that went wrong at runtime → exit code 2.
    #[error(transparent)]
    Runtime(#[from] anyhow::Error),
}

/// Parses the command line, runs the selected subcommand, and returns the
/// process exit code.
#[must_use]
pub fn run() -> ExitCode {
    let cli = Cli::parse();
    match execute(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(CliError::Config(err)) => {
            eprintln!("config error: {err}");
            ExitCode::from(1)
        }
        Err(CliError::Blocklist(err)) => {
            eprintln!("blocklist error: {err}");
            ExitCode::from(2)
        }
        Err(CliError::Runtime(err)) => {
            eprintln!("error: {err}");
            ExitCode::from(2)
        }
    }
}

/// Loads config, installs logging, then dispatches to the subcommand.
fn execute(cli: &Cli) -> Result<(), CliError> {
    let loaded = AppConfig::load(&cli.config)?;
    init_tracing(&loaded.config.log_level);
    for warning in &loaded.warnings {
        tracing::warn!("{warning}");
    }

    match cli.command {
        Command::Run => Err(not_implemented("voidgate run", "M5b: UDP/TCP DNS server")),
        Command::UpdateLists => update_lists(&loaded.config),
        Command::Stats => Err(not_implemented("voidgate stats", "M6: stats reporting")),
    }
}

/// Refreshes every `url` blocklist into the cache and prints a per-list
/// report (updated / kept previous cache / local file).
///
/// Exit code stays `0` even when individual lists are rejected — the report
/// explains each outcome; only fatal errors (e.g. an unusable cache
/// directory) yield exit code 2.
fn update_lists(config: &AppConfig) -> Result<(), CliError> {
    let runtime = tokio::runtime::Runtime::new().map_err(|source| {
        CliError::Runtime(anyhow::anyhow!("failed to start async runtime: {source}"))
    })?;
    let reports = runtime.block_on(cache::refresh_all(&config.blocklists))?;
    if reports.is_empty() {
        println!("no blocklists configured");
        return Ok(());
    }
    for report in &reports {
        println!("{report}");
    }
    Ok(())
}

/// Builds the placeholder error used until a subcommand is implemented.
fn not_implemented(command: &str, milestone: &str) -> CliError {
    CliError::Runtime(anyhow::anyhow!(
        "`{command}` is not implemented yet; scheduled for {milestone}"
    ))
}

/// Installs the `tracing` subscriber described by `log_level`.
///
/// An unusable filter cannot occur (config validation rejects it) but is
/// tolerated here rather than unwrapped.
fn init_tracing(log_level: &str) {
    let filter = match tracing_subscriber::EnvFilter::try_new(log_level) {
        Ok(filter) => filter,
        Err(_) => tracing_subscriber::EnvFilter::new("info"),
    };
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}
