//! Batched, non-blocking query-log writer.
//!
//! [`QueryLog`] is a cheap-to-clone handle around a bounded
//! [`std::sync::mpsc::SyncSender`]. Handlers call [`QueryLog::log`], which uses
//! `try_send`: if the queue is full the row is dropped and an internal counter
//! ticks, so a slow disk can never stall DNS. A dedicated OS thread owns the
//! `rusqlite::Connection`, drains rows, and commits them in transactions —
//! either once `storage.flush_rows` rows are pending or every
//! `storage.flush_interval_ms`, whichever comes first. The same thread prunes
//! expired rows at startup and on the `storage.prune_interval_secs` schedule.
//!
//! When every handle is dropped the channel disconnects and the writer drains
//! whatever is buffered, flushes, and exits. [`QueryLog::shutdown`] forces the
//! same path explicitly (for `ctrl-c`), then joins the thread.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};

use super::action::Action;
use super::error::StorageError;
use super::schema;
use crate::config::StorageConfig;

/// Milliseconds in a day, for converting `retention_days` to a cutoff.
const MILLIS_PER_DAY: i64 = 86_400_000;

/// The statement used for every insert; prepared once per batch.
const INSERT_ROW: &str = "INSERT INTO queries \
     (ts, client_ip, domain, action, upstream_latency_ms) VALUES (?1, ?2, ?3, ?4, ?5)";

/// One query-log row, ready to be written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryRow {
    /// Event time, milliseconds since the Unix epoch (UTC).
    pub ts_ms: i64,
    /// Client address the query came from.
    pub client_ip: IpAddr,
    /// Query name (normalised by the handler).
    pub domain: String,
    /// How the query was decided.
    pub action: Action,
    /// Upstream round-trip time; `None` for sinkholed or failed queries.
    pub upstream_latency_ms: Option<u32>,
}

/// Milliseconds since the Unix epoch (UTC), for stamping rows.
#[must_use]
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as i64)
}

/// A row on its way to the writer thread.
#[derive(Debug)]
enum Message {
    /// Append one row to the current batch.
    Row(QueryRow),
    /// Drain what remains, flush, and stop.
    Shutdown,
}

/// Shared state behind a [`QueryLog`] handle.
#[derive(Debug)]
struct Writer {
    tx: SyncSender<Message>,
    /// Shared with the writer thread so flush failures count as drops too.
    dropped: Arc<AtomicU64>,
    /// Taken by [`QueryLog::shutdown`]; `None` once the thread is joined.
    join: Mutex<Option<JoinHandle<()>>>,
}

/// A cheap, cloneable handle for recording queries.
///
/// Clones share the same queue, drop counter, and writer thread. Dropping all
/// handles shuts the writer down; [`QueryLog::shutdown`] does so explicitly and
/// waits for the final flush.
#[derive(Clone, Debug)]
pub struct QueryLog {
    /// `None` when `storage.log_queries` is `false`.
    inner: Option<Arc<Writer>>,
}

impl QueryLog {
    /// A disabled handle: no database, no thread, and `log` is a no-op.
    #[must_use]
    pub fn disabled() -> Self {
        Self { inner: None }
    }

    /// Starts the writer thread, or returns a disabled handle when
    /// `config.log_queries` is `false`.
    ///
    /// The database file is created and the schema applied on the calling
    /// thread so setup errors surface immediately; the `Connection` is then
    /// moved into the writer thread.
    ///
    /// # Errors
    ///
    /// Propagates [`schema::initialize`] failures and
    /// [`StorageError::ThreadSpawn`].
    pub fn start(config: &StorageConfig) -> Result<Self, StorageError> {
        if !config.log_queries {
            return Ok(Self::disabled());
        }
        let conn = schema::initialize(&config.db_path, config.busy_timeout_ms)?;
        let (tx, rx) = sync_channel(config.queue_capacity);
        let dropped = Arc::new(AtomicU64::new(0));

        let writer_dropped = Arc::clone(&dropped);
        let flush_rows = config.flush_rows;
        let flush_interval = Duration::from_millis(config.flush_interval_ms);
        let retention_days = config.retention_days;
        let prune_interval = Duration::from_secs(config.prune_interval_secs);
        let join = thread::Builder::new()
            .name("voidgate-query-log".to_owned())
            .spawn(move || {
                writer_loop(
                    conn,
                    rx,
                    flush_rows,
                    flush_interval,
                    retention_days,
                    prune_interval,
                    &writer_dropped,
                );
            })
            .map_err(|source| StorageError::ThreadSpawn { source })?;

        Ok(Self {
            inner: Some(Arc::new(Writer {
                tx,
                dropped,
                join: Mutex::new(Some(join)),
            })),
        })
    }

    /// Whether this handle writes rows (i.e. `storage.log_queries` is true).
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.inner.is_some()
    }

    /// Queues `row` without blocking; a full queue drops the row and counts it.
    pub fn log(&self, row: QueryRow) {
        let Some(writer) = &self.inner else {
            return;
        };
        match writer.tx.try_send(Message::Row(row)) {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                writer.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Rows dropped so far because the queue was full (or the writer had
    /// already stopped). Always `0` for a disabled handle.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.inner
            .as_ref()
            .map_or(0, |writer| writer.dropped.load(Ordering::Relaxed))
    }

    /// Flushes pending rows and joins the writer thread.
    ///
    /// Idempotent: a second call (or a disabled handle) is a no-op. The
    /// shutdown request uses a blocking `send`, so it is delivered even when
    /// the queue is full; it never blocks indefinitely because the writer
    /// drains the queue and stops.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::WriterPanicked`] if the writer thread died.
    pub fn shutdown(&self) -> Result<(), StorageError> {
        let Some(writer) = &self.inner else {
            return Ok(());
        };
        if writer.tx.send(Message::Shutdown).is_err() {
            // The writer already exited; nothing left to flush.
            return Ok(());
        }
        let handle = writer
            .join
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        match handle {
            Some(handle) => handle.join().map_err(|_| StorageError::WriterPanicked),
            None => Ok(()),
        }
    }
}

/// Deletes rows older than `retention_days`; returns how many were removed.
///
/// `retention_days == 0` disables pruning and returns `0`.
///
/// # Errors
///
/// Propagates SQLite failures.
pub fn prune(conn: &Connection, retention_days: u32) -> Result<usize, StorageError> {
    if retention_days == 0 {
        return Ok(0);
    }
    let cutoff = now_ms() - i64::from(retention_days) * MILLIS_PER_DAY;
    let deleted = conn.execute("DELETE FROM queries WHERE ts < ?1", params![cutoff])?;
    Ok(deleted)
}

/// The writer thread's main loop.
fn writer_loop(
    mut conn: Connection,
    rx: Receiver<Message>,
    flush_rows: usize,
    flush_interval: Duration,
    retention_days: u32,
    prune_interval: Duration,
    dropped: &AtomicU64,
) {
    let mut batch: Vec<QueryRow> = Vec::with_capacity(flush_rows);
    let mut next_prune = Instant::now() + prune_interval;

    if retention_days > 0 {
        run_prune(&conn, retention_days);
    }

    loop {
        match rx.recv_timeout(flush_interval) {
            Ok(Message::Row(row)) => {
                batch.push(row);
                if batch.len() >= flush_rows {
                    flush(&mut conn, &mut batch, dropped);
                }
            }
            Ok(Message::Shutdown) => {
                // Rows may still be buffered behind the shutdown request.
                drain(&rx, &mut batch);
                break;
            }
            Err(RecvTimeoutError::Timeout) => flush(&mut conn, &mut batch, dropped),
            Err(RecvTimeoutError::Disconnected) => break,
        }

        if retention_days > 0 && Instant::now() >= next_prune {
            run_prune(&conn, retention_days);
            next_prune = Instant::now() + prune_interval;
        }
    }

    flush(&mut conn, &mut batch, dropped);
}

/// Moves every row still queued into `batch`.
fn drain(rx: &Receiver<Message>, batch: &mut Vec<QueryRow>) {
    loop {
        match rx.try_recv() {
            Ok(Message::Row(row)) => batch.push(row),
            Ok(Message::Shutdown) | Err(_) => return,
        }
    }
}

/// Commits `batch` in one transaction; on failure the rows are counted as
/// dropped (the transaction rolls back) and the error is logged.
fn flush(conn: &mut Connection, batch: &mut Vec<QueryRow>, dropped: &AtomicU64) {
    if batch.is_empty() {
        return;
    }
    let pending = batch.len() as u64;
    if let Err(error) = insert_batch(conn, batch) {
        dropped.fetch_add(pending, Ordering::Relaxed);
        tracing::error!(
            rows = pending,
            error = %error,
            "failed to write query-log batch; rows dropped"
        );
    }
    batch.clear();
}

/// Inserts `rows` inside a single transaction.
fn insert_batch(conn: &mut Connection, rows: &[QueryRow]) -> Result<(), StorageError> {
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare_cached(INSERT_ROW)?;
        for row in rows {
            stmt.execute(params![
                row.ts_ms,
                row.client_ip.to_string(),
                row.domain,
                row.action.as_str(),
                row.upstream_latency_ms,
            ])?;
        }
    }
    tx.commit()?;
    Ok(())
}

/// Prunes, logging how many rows were removed or why it failed.
fn run_prune(conn: &Connection, retention_days: u32) {
    match prune(conn, retention_days) {
        Ok(0) => {}
        Ok(deleted) => tracing::info!(deleted, "pruned expired query-log rows"),
        Err(error) => tracing::error!(error = %error, "failed to prune query-log rows"),
    }
}
