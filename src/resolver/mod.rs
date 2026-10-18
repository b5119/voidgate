//! Upstream resolution: forwarding queries to the configured recursive
//! resolver.
//!
//! Contract (implemented in M5a):
//! - one **ephemeral UDP socket per query** (OS-assigned source port),
//! - replies validated for **source address**, **transaction ID**, and
//!   **question section** before being accepted,
//! - in-flight concurrency capped by a `tokio::sync::Semaphore`
//!   (`server.max_concurrent_queries`),
//! - per-query timeout from `server.timeout_ms`, surfaced as
//!   [`ResolverError::Timeout`](error::ResolverError) — never a panic.

pub mod error;
