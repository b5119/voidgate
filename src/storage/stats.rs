//! Read-only aggregate queries for `voidgate stats`.
//!
//! [`Stats`] holds a separate read-only connection, so reporting never
//! contends with the writer thread for the write lock (WAL lets readers run
//! while a writer commits). The in-process dropped-row count lives on
//! [`QueryLog::dropped`](super::QueryLog::dropped), not in the database.

use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags};

use super::action::Action;
use super::error::StorageError;

/// Per-client aggregate: total queries and how many were blocked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientStat {
    /// Client address as stored (`client_ip` column).
    pub client_ip: String,
    /// Queries recorded for this client.
    pub total: u64,
    /// Of those, how many were blocked.
    pub blocked: u64,
}

/// A read-only view of the query log.
#[derive(Debug)]
pub struct Stats {
    conn: Connection,
}

impl Stats {
    /// Opens `path` read-only.
    ///
    /// # Errors
    ///
    /// [`StorageError::Open`] when the file is missing or unreadable (including
    /// a WAL database whose directory is not writable).
    pub fn open(path: &Path, busy_timeout_ms: u64) -> Result<Self, StorageError> {
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(
            |source| StorageError::Open {
                path: path.to_path_buf(),
                source,
            },
        )?;
        conn.busy_timeout(Duration::from_millis(busy_timeout_ms))?;
        Ok(Self { conn })
    }

    /// Total number of logged queries.
    ///
    /// # Errors
    ///
    /// Propagates SQLite failures.
    pub fn total(&self) -> Result<u64, StorageError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM queries", [], |row| row.get(0))?;
        Ok(count as u64)
    }

    /// Query counts per action, ordered `allowed, blocked, forwarded,
    /// servfail`.
    ///
    /// # Errors
    ///
    /// Propagates SQLite failures and [`StorageError::UnknownAction`] for a
    /// corrupted `action` column.
    pub fn counts_by_action(&self) -> Result<Vec<(Action, u64)>, StorageError> {
        let mut stmt = self
            .conn
            .prepare("SELECT action, COUNT(*) FROM queries GROUP BY action")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        let mut counts = Vec::new();
        for row in rows {
            let (action, count) = row?;
            counts.push((Action::parse(&action)?, count as u64));
        }
        counts.sort_by_key(|(action, _)| *action);
        Ok(counts)
    }

    /// The `limit` most-blocked domains, most frequent first (ties broken
    /// alphabetically).
    ///
    /// # Errors
    ///
    /// Propagates SQLite failures.
    pub fn top_blocked_domains(&self, limit: usize) -> Result<Vec<(String, u64)>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT domain, COUNT(*) AS n FROM queries \
             WHERE action = ?1 GROUP BY domain ORDER BY n DESC, domain ASC LIMIT ?2",
        )?;
        let rows = stmt.query_map(
            rusqlite::params![Action::Blocked.as_str(), limit as i64],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )?;
        let mut domains = Vec::new();
        for row in rows {
            let (domain, count) = row?;
            domains.push((domain, count as u64));
        }
        Ok(domains)
    }

    /// Per-client totals, busiest client first (ties broken by address).
    ///
    /// # Errors
    ///
    /// Propagates SQLite failures.
    pub fn per_client(&self) -> Result<Vec<ClientStat>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT client_ip, COUNT(*), \
             SUM(CASE WHEN action = ?1 THEN 1 ELSE 0 END) \
             FROM queries GROUP BY client_ip \
             ORDER BY COUNT(*) DESC, client_ip ASC",
        )?;
        let rows = stmt.query_map(rusqlite::params![Action::Blocked.as_str()], |row| {
            Ok(ClientStat {
                client_ip: row.get(0)?,
                total: row.get::<_, i64>(1)? as u64,
                blocked: row.get::<_, i64>(2)? as u64,
            })
        })?;
        let mut clients = Vec::new();
        for row in rows {
            clients.push(row?);
        }
        Ok(clients)
    }
}
