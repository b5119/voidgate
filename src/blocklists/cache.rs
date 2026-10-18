//! On-disk blocklist cache and the periodic refresh loop.
//!
//! TODO(M2): implement `write_atomic` (write `cache_dir/<name>.tmp`, then
//! `rename` over `cache_dir/<name>`) and `refresh_all` (fetch every URL list,
//! atomic-rename, then hand the caller the new data for `ArcSwap::store`).
