#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Tests for the blocklist store: label-boundary matching, bare-TLD guard,
//! fail-soft cache loading, and ArcSwap hot-swaps.

use std::collections::HashSet;
use std::fs;
use std::sync::Arc;

use arc_swap::ArcSwap;
use voidgate::blocklists::BlocklistStore;
use voidgate::config::{BlocklistKind, BlocklistSource, BlocklistsConfig};

fn store_with(entries: &[(&str, &str)]) -> BlocklistStore {
    let mut store = BlocklistStore::new();
    for (list, domain) in entries {
        store.insert(*list, [*domain]);
    }
    store
}

fn list(name: &str, kind: BlocklistKind, source: &str) -> BlocklistSource {
    BlocklistSource {
        name: name.to_owned(),
        kind,
        source: source.to_owned(),
    }
}

#[test]
fn matches_exact_domain_and_subdomains_on_label_boundaries() {
    let store = store_with(&[("ads", "ads.example.com")]);
    assert!(store.matches("ads", "ads.example.com"));
    assert!(store.matches("ads", "sub.ads.example.com"));
    assert!(store.matches("ads", "a.b.ads.example.com"));
    // Boundary: "notads.example.com" ends_with "ads.example.com" but is NOT
    // a subdomain — must not match.
    assert!(!store.matches("ads", "notads.example.com"));
    assert!(!store.matches("ads", "www.notads.example.com"));
    // Boundary: "badads.example.com" also ends_with "ads.example.com".
    assert!(!store.matches("ads", "badads.example.com"));
}

#[test]
fn bare_tld_never_matches() {
    let mut store = BlocklistStore::new();
    store.insert("tld", ["com".to_owned(), "co.uk".to_owned()]);
    // The TLD label is never tested during a walk.
    assert!(!store.matches("tld", "ads.example.com"));
    assert!(!store.matches("tld", "example.com"));
    // A single-label query is never matched either.
    assert!(!store.matches("tld", "com"));
    // co.uk is two labels, so a walk for foo.co.uk legitimately tests it.
    assert!(store.matches("tld", "foo.co.uk"));
}

#[test]
fn matching_is_case_insensitive_and_tolerates_trailing_dot() {
    let store = store_with(&[("ads", "ads.example.com")]);
    assert!(store.matches("ads", "ADS.EXAMPLE.COM"));
    assert!(store.matches("ads", "Sub.Ads.Example.COM."));
    assert!(store.matches("ads", "ads.example.com."));
}

#[test]
fn unknown_list_and_empty_domain_never_match() {
    let store = store_with(&[("ads", "ads.example.com")]);
    assert!(!store.matches("nope", "ads.example.com"));
    assert!(!store.matches("ads", ""));
    assert!(!store.matches("ads", "."));
}

#[test]
fn matches_any_checks_all_referenced_lists() {
    let mut store = BlocklistStore::new();
    store.insert("one", ["first.example"]);
    store.insert("two", ["second.example"]);
    let lists = vec!["one".to_owned(), "two".to_owned()];
    assert!(store.matches_any(&lists, "www.first.example"));
    assert!(store.matches_any(&lists, "second.example"));
    assert!(!store.matches_any(&lists, "third.example"));
    assert!(!store.matches_any(&[], "first.example"));
}

#[test]
fn domain_count_reports_sizes() {
    let mut store = BlocklistStore::new();
    store.insert("l", ["a.example", "b.example"]);
    assert_eq!(store.domain_count("l"), 2);
    assert_eq!(store.domain_count("missing"), 0);
}

#[test]
fn load_from_cache_reads_url_cache_and_file_source() {
    let dir = tempfile::tempdir().unwrap();
    let cache_dir = dir.path().join("cache");
    fs::create_dir_all(&cache_dir).unwrap();

    // URL list served from the cache file.
    fs::write(cache_dir.join("urllist"), "0.0.0.0 cached.example.com\n").unwrap();
    // File list read from its source path (never cached).
    let source = dir.path().join("local.txt");
    fs::write(&source, "0.0.0.0 local.example.com\n").unwrap();

    let config = BlocklistsConfig {
        cache_dir: cache_dir.clone(),
        lists: vec![
            list(
                "urllist",
                BlocklistKind::Url,
                "https://unused.invalid/hosts",
            ),
            list("filelist", BlocklistKind::File, source.to_str().unwrap()),
        ],
        ..BlocklistsConfig::default()
    };

    let store = BlocklistStore::load_from_cache(&config);
    assert!(store.matches("urllist", "www.cached.example.com"));
    assert!(store.matches("filelist", "local.example.com"));
    // Nothing was written to the cache for the file list.
    assert!(!cache_dir.join("filelist").exists());
}

#[test]
fn load_from_cache_fails_soft_per_list() {
    let dir = tempfile::tempdir().unwrap();
    let cache_dir = dir.path().join("cache");
    fs::create_dir_all(&cache_dir).unwrap();
    // One healthy cached list next to two broken ones.
    fs::write(cache_dir.join("good"), "0.0.0.0 good.example.com\n").unwrap();

    let config = BlocklistsConfig {
        cache_dir,
        lists: vec![
            list("good", BlocklistKind::Url, "https://unused.invalid/a"),
            // No cache file yet:
            list("nocache", BlocklistKind::Url, "https://unused.invalid/b"),
            // Missing local file:
            list("missingfile", BlocklistKind::File, "/nonexistent/list.txt"),
        ],
        ..BlocklistsConfig::default()
    };

    let store = BlocklistStore::load_from_cache(&config);
    assert!(store.matches("good", "good.example.com"));
    assert_eq!(store.domain_count("nocache"), 0);
    assert_eq!(store.domain_count("missingfile"), 0);
}

#[test]
fn hot_swap_via_arc_swap_replaces_the_whole_store() {
    let before = store_with(&[("ads", "old.example.com")]);
    let mut after = BlocklistStore::new();
    after.insert("ads", ["new.example.com"]);

    let shared = ArcSwap::from_pointee(before);
    assert!(shared.load().matches("ads", "old.example.com"));

    shared.store(Arc::new(after));
    assert!(!shared.load().matches("ads", "old.example.com"));
    assert!(shared.load().matches("ads", "sub.new.example.com"));
}

#[test]
fn insert_accepts_hashsets_and_string_lists_alike() {
    let mut store = BlocklistStore::new();
    let set: HashSet<String> = ["hash.example".to_owned()].into_iter().collect();
    store.insert("hashlist", set);
    store.insert("veclist", ["vec.example".to_owned()]);
    assert!(store.matches("hashlist", "hash.example"));
    assert!(store.matches("veclist", "vec.example"));
}
