//! Errors produced while parsing, fetching, or writing blocklists.

use std::path::PathBuf;

use thiserror::Error;

/// Every way blocklist handling can fail.
#[derive(Debug, Error)]
pub enum BlocklistError {
    /// The HTTP request itself failed (connect, timeout, truncated body…).
    #[error("request to {url} failed: {source}")]
    Fetch {
        /// URL that failed.
        url: String,
        /// Underlying reqwest error.
        source: Box<reqwest::Error>,
    },

    /// The server answered with a non-2xx status.
    #[error("request to {url} returned HTTP {status}")]
    HttpStatus {
        /// URL that returned the status.
        url: String,
        /// The HTTP status code.
        status: reqwest::StatusCode,
    },

    /// The response body exceeds `max_fetch_bytes` (declared or streamed).
    #[error("response from {url} exceeds the {limit} byte limit")]
    TooLarge {
        /// URL that was too large.
        url: String,
        /// Configured `blocklists.max_fetch_bytes`.
        limit: u64,
    },

    /// A cache file operation failed (create/write/rename/read).
    #[error("failed to {operation} `{path}`: {source}")]
    Io {
        /// What was being attempted (`write temporary cache file`, …).
        operation: &'static str,
        /// Filesystem path involved.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// The blocklist name is not safe to use as a cache filename.
    #[error("invalid blocklist name `{name}`: only a-z, 0-9, _ and - are allowed")]
    InvalidName {
        /// The rejected name.
        name: String,
    },

    /// The reqwest client could not be constructed.
    #[error("failed to build HTTP client: {0}")]
    HttpClient(String),
}
