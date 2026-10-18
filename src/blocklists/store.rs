//! In-memory blocklist store: startup load from cache, subdomain matching,
//! and hot-swapping via `ArcSwap`.
//!
//! TODO(M2): implement `BlocklistStore::load_from_cache` (fail-soft per list),
//! `matches(list, domain)` (walk `a.b.c.com` → `b.c.com` → `c.com`, stopping
//! before the TLD), and `install` for `ArcSwap` swaps driven by `SIGHUP`
//! (reload cache only) and the refresh timer (fetch + rename + reload).
