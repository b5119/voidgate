//! Errors produced while binding and running the DNS listeners.

use std::net::SocketAddr;

use thiserror::Error;

/// Every way starting or running a listener can fail.
#[derive(Debug, Error)]
pub enum ServerError {
    /// The UDP socket could not be bound to the configured address.
    #[error("failed to bind listener on {addr}: {source}")]
    Bind {
        /// The address that could not be bound.
        addr: SocketAddr,
        /// Underlying I/O error (e.g. `PermissionDenied`, `AddrInUse`).
        source: std::io::Error,
    },

    /// I/O failed after the socket was bound (runtime socket conversion,
    /// shutdown).
    #[error("listener I/O failed: {source}")]
    Io {
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// The query log failed to flush during shutdown.
    #[error(transparent)]
    Storage(#[from] crate::storage::StorageError),
}
