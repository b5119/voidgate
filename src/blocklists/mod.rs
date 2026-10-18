//! Blocklist handling: parsing, on-disk cache, and membership matching.
//!
//! Layout:
//! - [`parser`] — hosts-format / plain domain list text → domain set (M2)
//! - [`cache`] — atomic `update-lists` writes and the refresh loop (M2)
//! - [`store`] — load-from-cache at startup, `ArcSwap` hot reload, subdomain
//!   matching (M2)
//!
//! Cache semantics: `voidgate update-lists` fetches each source and renames it
//! into `cache_dir` (temp file + `rename`, same filesystem). The server reads
//! only from the cache at startup and fails soft (warning + empty set) when a
//! list is unavailable; `SIGHUP` reloads the cache offline, while the
//! `refresh_interval_secs` timer re-fetches, renames, then reloads.

pub mod cache;
pub mod error;
pub mod parser;
pub mod store;
