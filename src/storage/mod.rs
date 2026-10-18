//! SQLite query log.
//!
//! Design (M4): a single writer thread owns the `rusqlite::Connection`; every
//! caller sends rows over an `mpsc` channel (best-effort — a full channel
//! drops the row rather than stalling DNS). The connection sets
//! `busy_timeout` before any writes, and the schema is created idempotently
//! (`schema` module). Rows are pruned by `storage.retention_days` at startup
//! and hourly; `storage.log_queries: false` disables inserts entirely.

pub mod error;
pub mod schema;
