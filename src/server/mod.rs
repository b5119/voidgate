//! DNS listeners and process lifecycle.
//!
//! TODO(M5b): UDP listener + graceful shutdown (ctrl-c).
//! TODO(M5c): TCP listener with 2-byte length framing, idle timeout and
//! connection cap (same handler as UDP); `#[cfg(unix)]` `SIGHUP` handler that
//! reloads the cache **offline** (no network); `refresh_interval_secs` timer
//! that fetches → atomic-renames → reloads via `ArcSwap`.
