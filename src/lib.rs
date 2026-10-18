//! Voidgate: a DNS sinkhole ad blocker with per-device and per-network policies.
//!
//! The crate is organised into focused modules:
//!
//! - [`config`] — `config.yaml` parsing, defaults, and validation
//! - [`blocklists`] — hosts/domain list parsing, caching, and matching
//! - [`policy`] — per-client policies (CIDR longest-prefix, allow/deny lists)
//! - [`resolver`] — forwarding queries to the upstream resolver
//! - [`handler`] — the per-query decision pipeline
//! - [`server`] — UDP/TCP listeners and lifecycle (SIGHUP, refresh timer)
//! - [`storage`] — SQLite query log (single writer thread over mpsc)
//! - [`cli`] — `voidgate run | update-lists | stats`
pub mod blocklists;
pub mod cli;
pub mod config;
pub mod handler;
pub mod policy;
pub mod resolver;
pub mod server;
pub mod storage;
