//! Idempotent SQLite schema for the query log.
//!
//! TODO(M4): `CREATE TABLE IF NOT EXISTS queries (id, ts, client_ip, domain,
//! action, upstream_latency_ms)` with WAL journal mode; `action` is one of
//! `allowed | blocked | forwarded | servfail`.
