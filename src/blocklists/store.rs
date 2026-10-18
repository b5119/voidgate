//! In-memory blocklist store: startup load from cache, label-boundary
//! matching, and hot-swapping via `ArcSwap`.
//!
//! The store is immutable once built: the server keeps an
//! `arc_swap::ArcSwap<BlocklistStore>` and swaps in a freshly loaded store on
//! `SIGHUP` (cache reload only, offline) or after the refresh timer
//! (fetch → atomic rename → reload).
//!
//! Matching walks parent labels **on label boundaries** (`a.b.example` →
//! `b.example`, then stops) and never matches a bare TLD: the final label is
//! never tested, so a poisoned `com` entry cannot block `example.com`, and a
//! single-label query never matches at all. `notads.example` never matches a
//! stored `ads.example` because candidates are built by splitting on `.`,
//! never by suffix comparison.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::blocklists::{cache, parser};
use crate::config::{BlocklistKind, BlocklistsConfig};

/// One list's normalised domains, shareable across hot-swaps.
pub type ListSet = Arc<HashSet<String>>;

/// Immutable name → domains map for all loaded blocklists.
#[derive(Debug, Clone, Default)]
pub struct BlocklistStore {
    /// Lists keyed by their config name.
    lists: HashMap<String, ListSet>,
}

impl BlocklistStore {
    /// An empty store (no lists).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts (or replaces) one list's domains.
    pub fn insert(
        &mut self,
        name: impl Into<String>,
        domains: impl IntoIterator<Item = impl Into<String>>,
    ) {
        let set: HashSet<String> = domains.into_iter().map(Into::into).collect();
        self.lists.insert(name.into(), Arc::new(set));
    }

    /// Number of domains stored for `list` (0 for unknown lists).
    #[must_use]
    pub fn domain_count(&self, list: &str) -> usize {
        self.lists.get(list).map_or(0, |set| set.len())
    }

    /// Does `domain` (or any of its subdomains) appear in `list`?
    ///
    /// Matching is case-insensitive, tolerates a trailing dot, and stops
    /// before the TLD so bare TLD entries never match.
    #[must_use]
    pub fn matches(&self, list: &str, domain: &str) -> bool {
        self.lists
            .get(list)
            .is_some_and(|set| suffix_match(set, domain))
    }

    /// Does `domain` match any of `lists`?
    #[must_use]
    pub fn matches_any(&self, lists: &[String], domain: &str) -> bool {
        lists.iter().any(|list| self.matches(list, domain))
    }

    /// Loads every configured list.
    ///
    /// URL lists come from `cache_dir` (the server never fetches at startup);
    /// `file` lists are read from their source path. Failures are **fail-soft
    /// per list**: a warning is logged and the list loads empty, so one bad
    /// list never keeps the server from starting.
    #[must_use]
    pub fn load_from_cache(config: &BlocklistsConfig) -> Self {
        let mut store = Self::new();
        for source in &config.lists {
            let domains = match source.kind {
                BlocklistKind::Url => load_url_from_cache(config, source),
                BlocklistKind::File => load_file_from_source(source),
            };
            store.insert(source.name.clone(), domains);
        }
        store
    }
}

/// Reads a URL list from the cache; warns and yields an empty set if absent
/// or unreadable.
fn load_url_from_cache(
    config: &BlocklistsConfig,
    source: &crate::config::BlocklistSource,
) -> HashSet<String> {
    let path = match cache::cache_path(&config.cache_dir, &source.name) {
        Ok(path) => path,
        Err(error) => {
            tracing::warn!(
                list = %source.name,
                error = %error,
                "blocklist name is not cache-safe; loading empty set"
            );
            return HashSet::new();
        }
    };
    match std::fs::read(&path) {
        Ok(bytes) => parser::parse_bytes(&bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!(
                list = %source.name,
                path = %path.display(),
                "no cached copy of URL list; run `voidgate update-lists`"
            );
            HashSet::new()
        }
        Err(error) => {
            tracing::warn!(
                list = %source.name,
                path = %path.display(),
                error = %error,
                "failed to read cached list; loading empty set"
            );
            HashSet::new()
        }
    }
}

/// Reads a local `file` list from its source path; warns and yields an empty
/// set on failure.
fn load_file_from_source(source: &crate::config::BlocklistSource) -> HashSet<String> {
    match std::fs::read(&source.source) {
        Ok(bytes) => parser::parse_bytes(&bytes),
        Err(error) => {
            tracing::warn!(
                list = %source.name,
                path = %source.source,
                error = %error,
                "failed to read local blocklist file; loading empty set"
            );
            HashSet::new()
        }
    }
}

/// Walks `domain`'s parent labels on label boundaries, excluding the TLD.
fn suffix_match(set: &ListSet, domain: &str) -> bool {
    let normalized = domain.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = normalized.split('.').collect();
    // A single label is either a bare TLD or unresolvable junk: never match.
    if labels.len() < 2 {
        return false;
    }
    for start in 0..labels.len() - 1 {
        let candidate = labels[start..].join(".");
        if set.contains(&candidate) {
            return true;
        }
    }
    false
}
