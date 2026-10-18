//! SQLite query log.
//!
//! - [`schema`] — connection setup (WAL, busy timeout, `user_version`) and the
//!   idempotent `queries` table with `ts`/`domain` indexes; on Unix the
//!   database file is created `0600` (it is a browsing log).
//! - [`action`] — the four logged outcomes (allowed/blocked/forwarded/
//!   servfail) with their stable string mapping. `REFUSED` queries are not
//!   representable, so they can never be logged.
//! - [`log`] — `QueryLog`, a cheap cloneable handle over a bounded channel,
//!   plus the dedicated writer thread that batches inserts (flush at
//!   `storage.flush_rows` or `storage.flush_interval_ms`) and prunes expired
//!   rows. A full queue drops rows instead of blocking DNS.
//! - [`stats`] — read-only aggregates (counts by action, top blocked domains,
//!   per-client breakdown) for `voidgate stats`.
//!
//! `storage.log_queries: false` means no database file is touched, no thread
//! is spawned, and every log call is a no-op.

pub mod action;
pub mod error;
pub mod log;
pub mod schema;
pub mod stats;

pub use action::Action;
pub use error::StorageError;
pub use log::{now_ms, prune, QueryLog, QueryRow};
pub use stats::{ClientStat, Stats};
