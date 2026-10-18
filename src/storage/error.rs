//! Errors produced by the query log.

use std::path::PathBuf;

use thiserror::Error;

/// Every way the query log can fail to open, write, or read.
#[derive(Debug, Error)]
pub enum StorageError {
    /// A parent directory of the database path could not be created.
    #[error("failed to create query log directory `{path}`: {source}")]
    CreateDir {
        /// Directory that could not be created.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// The database could not be opened (missing file for a read, locking,
    /// permissions, …).
    #[error("failed to open query log database `{path}`: {source}")]
    Open {
        /// Database path that could not be opened.
        path: PathBuf,
        /// Underlying SQLite error.
        source: rusqlite::Error,
    },

    /// The database file could not be restricted to owner-only permissions.
    #[error("failed to set permissions on `{path}`: {source}")]
    Permissions {
        /// File whose permissions could not be tightened.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// Any other SQLite failure (schema, insert, prune, aggregate query).
    #[error("query log database error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// The `action` column held a value outside the known labels.
    #[error("unknown query-log action `{value}`")]
    UnknownAction {
        /// The unrecognised stored value.
        value: String,
    },

    /// The dedicated writer thread could not be spawned.
    #[error("failed to spawn the query-log writer thread: {source}")]
    ThreadSpawn {
        /// Underlying thread-spawn error.
        source: std::io::Error,
    },

    /// The writer thread panicked while the log was being shut down.
    #[error("query-log writer thread panicked")]
    WriterPanicked,
}
