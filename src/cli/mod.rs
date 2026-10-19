//! Command-line interface: `voidgate run | update-lists | stats | check-config`.
//!
//! Exit codes: `0` success, `1` configuration/usage error, `2` runtime error.

mod stats;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use arc_swap::ArcSwap;
use clap::error::ErrorKind;
use clap::{Parser, Subcommand};
use thiserror::Error;

use crate::blocklists::{cache, BlocklistStore};
use crate::config::{AppConfig, ConfigError};
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

/// The operations voidgate exposes.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the DNS server (UDP + TCP listeners).
    Run,
    /// Fetch blocklists into the cache directory (atomic temp + rename).
    UpdateLists,
    /// Show query statistics from the SQLite log.
    Stats {
        /// How many blocked domains to list.
        #[arg(long, default_value_t = 10)]
        top: usize,
        /// Only count queries newer than this window (e.g. 1h, 24h, 7d).
        #[arg(long)]
        since: Option<String>,
        /// Print the report as JSON instead of text tables.
        #[arg(long)]
        json: bool,
    },
    /// Validate the configuration file and print any warnings.
    CheckConfig,
}

/// Errors surfaced by [`run`], mapped onto process exit codes.
#[derive(Debug, Error)]
enum CliError {
    /// Invalid or unreadable configuration → exit code 1.
    #[error(transparent)]
    Config(#[from] ConfigError),

    /// A user-actionable problem that stops a subcommand before it runs —
    /// logging disabled, nothing to read, a bad `--since` window → exit
    /// code 1. The message already carries an actionable hint.
    #[error("{0}")]
    Unavailable(String),

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
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => return clap_exit(&error),
    };
    match execute(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(CliError::Config(err)) => {
            eprintln!("config error: {err} (hint: {})", config_hint(&err));
            ExitCode::from(1)
        }
        Err(CliError::Unavailable(message)) => {
            eprintln!("{message}");
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

/// Maps a clap parse result onto an exit code: help/version are successes,
/// every other usage error is exit code 1 (clap's default is 2).
fn clap_exit(error: &clap::Error) -> ExitCode {
    let _ = error.print();
    match error.kind() {
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => ExitCode::SUCCESS,
        _ => ExitCode::from(1),
    }
}

/// A one-line, actionable hint for a configuration error.
fn config_hint(error: &ConfigError) -> &'static str {
    match error {
        ConfigError::Read { .. } => "check the path passed to --config",
        ConfigError::Parse { .. } => "compare the file against config.example.yaml",
        _ => "compare the named field against config.example.yaml",
    }
}

/// Loads config, installs logging, then dispatches to the subcommand.
fn execute(cli: &Cli) -> Result<(), CliError> {
    // check-config reports on the config itself, so it runs before logging is
    // installed and prints warnings itself rather than via `tracing`.
    if let Command::CheckConfig = cli.command {
        return check_config(&cli.config);
    }

    let loaded = AppConfig::load(&cli.config)?;
    init_tracing(&loaded.config.log_level);
    for warning in &loaded.warnings {
        tracing::warn!("{warning}");
    }

    match &cli.command {
        Command::Run => run_server(&loaded.config),
        Command::UpdateLists => update_lists(&loaded.config),
        Command::Stats { top, since, json } => stats(&loaded.config, *top, since.as_deref(), *json),
        // Handled before the config was loaded.
        Command::CheckConfig => Ok(()),
    }
}

/// Prints every validation warning plus a confirmation line; exit code stays
/// `0` because a warning is not an error. Touches no sockets and no database.
fn check_config(path: &Path) -> Result<(), CliError> {
    let loaded = AppConfig::load(path)?;
    for warning in &loaded.warnings {
        println!("warning: {warning}");
    }
    println!("config OK: {}", path.display());
    Ok(())
}

/// Reads the query-log aggregates and prints them as text tables or JSON.
fn stats(config: &AppConfig, top: usize, since: Option<&str>, json: bool) -> Result<(), CliError> {
    let report = stats::collect(config, top, since)?;
    if json {
        print!("{}", report.render_json());
    } else {
        print!("{}", report.render_text());
    }
    Ok(())
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
    tracing::info!(
        %addr,
        tcp = config.server.tcp_enabled,
        "voidgate DNS server listening (ctrl-c to stop)"
    );

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
            "port 53 needs root or CAP_NET_BIND_SERVICE; use a high port (e.g. 15353) for testing"
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

/// Installs the `tracing` subscriber described by `log_level`.
///
/// Logs go to stderr so stdout stays reserved for subcommand data (the
/// `update-lists` report, the `stats` tables/JSON). An unusable filter cannot
/// occur (config validation rejects it) but is tolerated here rather than
/// unwrapped.
fn init_tracing(log_level: &str) {
    let filter = match tracing_subscriber::EnvFilter::try_new(log_level) {
        Ok(filter) => filter,
        Err(_) => tracing_subscriber::EnvFilter::new("info"),
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}
