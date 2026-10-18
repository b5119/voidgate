//! Idempotent SQLite schema and connection setup for the query log.
//!
//! [`initialize`] creates the database file (owner-only permissions on Unix),
//! opens it in WAL mode with a busy timeout, and applies the schema with
//! `CREATE ... IF NOT EXISTS`, stamping [`SCHEMA_VERSION`] into
//! `PRAGMA user_version`. Running it twice is a no-op.

use std::path::Path;
use std::time::Duration;

use rusqlite::Connection;

use super::error::StorageError;

/// `PRAGMA user_version` written once the schema matches this module.
pub const SCHEMA_VERSION: i32 = 1;

/// The query log table.
const CREATE_QUERIES: &str = "\
CREATE TABLE IF NOT EXISTS queries (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    client_ip TEXT NOT NULL,
    domain TEXT NOT NULL,
    action TEXT NOT NULL,
    upstream_latency_ms INTEGER
)";

/// Timestamp index (prune and time-range scans).
const CREATE_TS_INDEX: &str = "CREATE INDEX IF NOT EXISTS idx_queries_ts ON queries(ts)";

/// Domain index (top-domains aggregation).
const CREATE_DOMAIN_INDEX: &str =
    "CREATE INDEX IF NOT EXISTS idx_queries_domain ON queries(domain)";

/// Opens (creating if necessary) the query-log database and applies the
/// schema and pragmas.
///
/// `journal_mode=WAL` and `busy_timeout` are set on every open; the writer
/// thread and the read-only stats connection both go through here for the
/// writable case.
///
/// # Errors
///
/// [`StorageError::CreateDir`]/[`StorageError::Permissions`] for filesystem
/// failures and [`StorageError::Sqlite`] for schema/pragma failures.
pub fn initialize(path: &Path, busy_timeout_ms: u64) -> Result<Connection, StorageError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|source| StorageError::CreateDir {
                path: parent.to_path_buf(),
                source,
            })?;
        }
    }
    create_private_file(path)?;
    let conn = Connection::open(path).map_err(|source| StorageError::Open {
        path: path.to_path_buf(),
        source,
    })?;
    conn.busy_timeout(Duration::from_millis(busy_timeout_ms))?;

    // journal_mode returns a row, so read it instead of using pragma_update.
    let _mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
    conn.execute_batch(&format!(
        "{CREATE_QUERIES};\n{CREATE_TS_INDEX};\n{CREATE_DOMAIN_INDEX};"
    ))?;
    conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;

    restrict_permissions(path)?;
    Ok(conn)
}

/// Creates the database file with `0600` if it does not exist yet.
#[cfg(unix)]
fn create_private_file(path: &Path) -> Result<(), StorageError> {
    use std::os::unix::fs::OpenOptionsExt;

    if path.exists() {
        return Ok(());
    }
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|source| StorageError::Permissions {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(())
}

/// Non-Unix platforms have no mode bits to set: let SQLite create the file.
#[cfg(not(unix))]
fn create_private_file(_path: &Path) -> Result<(), StorageError> {
    Ok(())
}

/// Tightens the database file to `0600` (it is a browsing log).
#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<(), StorageError> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|source| {
        StorageError::Permissions {
            path: path.to_path_buf(),
            source,
        }
    })
}

/// Non-Unix platforms keep their default permissions.
#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<(), StorageError> {
    Ok(())
}
