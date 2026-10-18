//! Command-line interface: `voidgate run | update-lists | stats`.
//!
//! Exit codes: `0` success, `1` configuration error, `2` runtime error.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use arc_swap::ArcSwap;
use clap::{Parser, Subcommand};
use thiserror::Error;

use crate::blocklists::{cache, BlocklistStore};
use crate::config::AppConfig;
use crate::server::{Server, ServerError};
use crate::storage::QueryLog;

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
        Command::Run => run_server(&loaded.config),
        Command::UpdateLists => update_lists(&loaded.config),
        Command::Stats => Err(not_implemented("voidgate stats", "M6: stats reporting")),
    }
}

/// Serves DNS until `ctrl-c`/`SIGTERM`: loads the cached blocklists, starts the
/// query log, binds the listener, and runs the receive loop.
///
/// Cached blocklists are loaded fail-soft (missing/partial cache yields an
/// empty store plus a warning per list), so the server always starts.
fn run_server(config: &AppConfig) -> Result<(), CliError> {
    let runtime = tokio::runtime::Runtime::new().map_err(|source| {
        CliError::Runtime(anyhow::anyhow!("failed to start async runtime: {source}"))
    })?;
    runtime.block_on(serve(config))
}

/// The async body of [`run_server`].
async fn serve(config: &AppConfig) -> Result<(), CliError> {
    let store = BlocklistStore::load_from_cache(&config.blocklists);
    let counts: Vec<(String, usize)> = config
        .blocklists
        .lists
        .iter()
        .map(|source| (source.name.clone(), store.domain_count(&source.name)))
        .collect();
    for (name, domains) in &counts {
        tracing::info!(list = %name, domains, "blocklist loaded from cache");
    }
    let total: usize = counts.iter().map(|(_, domains)| domains).sum();
    tracing::info!(lists = counts.len(), domains = total, "blocklists ready");

    let query_log = QueryLog::start(&config.storage).map_err(|error| {
        CliError::Runtime(anyhow::anyhow!("failed to start the query log: {error}"))
    })?;

    let blocklists = Arc::new(ArcSwap::from_pointee(store));
    let server = Server::bind(config, blocklists, query_log)
        .map_err(|error| CliError::Runtime(anyhow::anyhow!("{}", format_bind_error(&error))))?;

    let addr = server.local_addr().map_err(|source| {
        CliError::Runtime(anyhow::anyhow!("listener has no address: {source}"))
    })?;
    tracing::info!(%addr, "voidgate DNS server listening (ctrl-c to stop)");

    server
        .run(shutdown_signal())
        .await
        .map_err(|error| CliError::Runtime(anyhow::anyhow!("server error: {error}")))?;

    tracing::info!("voidgate shut down cleanly");
    Ok(())
}

/// Resolves on `ctrl-c` or, on Unix, `SIGTERM` (sent by `systemd stop`).
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "failed to listen for ctrl-c");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::error!(%error, "failed to listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}

/// Expands a bind failure with an actionable hint; any other error is shown
/// as-is.
fn format_bind_error(error: &ServerError) -> String {
    let ServerError::Bind { addr, source } = error else {
        return error.to_string();
    };
    let hint = match source.kind() {
        std::io::ErrorKind::PermissionDenied => {
            "port 53 needs root or CAP_NET_BIND_SERVICE; use a high port (e.g. 5353) for testing"
        }
        std::io::ErrorKind::AddrInUse => {
            "something already owns the address; on many Linux systems systemd-resolved \
             holds 127.0.0.53:53, so bind a different address or port"
        }
        _ => "check server.listen and server.port in config.yaml",
    };
    format!("cannot bind UDP listener on {addr}: {source} (hint: {hint})")
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
