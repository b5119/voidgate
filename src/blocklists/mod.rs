//! Blocklist handling: parsing, on-disk cache, and membership matching.
//!
//! - [`parser`] — hosts-format / plain domain list text → normalised domain
//!   set (comments, header entries, junk, and IP tokens dropped)
//! - [`cache`] — `update-lists` refresh: HTTP fetch with timeout and size
//!   cap, empty/shrink rejection (previous file kept), atomic
//!   `<name>.tmp` + rename writes
//! - [`store`] — server-side load (cache for `url` lists, source path for
//!   `file` lists, fail-soft per list), label-boundary matching that never
//!   matches a bare TLD, and whole-store hot-swaps via `ArcSwap`
//!
//! Cache semantics: `voidgate update-lists` fetches each `url` source and
//! renames it into `cache_dir`; the server reads only from the cache at
//! startup. `SIGHUP` reloads the cache offline, while the
//! `refresh_interval_secs` timer fetches → renames → reloads.

pub mod cache;
pub mod error;
pub mod parser;
pub mod store;

pub use error::BlocklistError;
pub use store::{BlocklistStore, ListSet};
