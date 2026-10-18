#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Tests for the blocklist cache: atomic writes, fetch caps, empty/shrink
//! rejection, and "keep the old file" behaviour. HTTP servers are local
//! tokio listeners on 127.0.0.1 — no real network access.

mod common;

use std::fs;
use std::time::Duration;

use voidgate::blocklists::cache::{self, KeepReason, RefreshOutcome};
use voidgate::blocklists::BlocklistError;
use voidgate::config::{BlocklistKind, BlocklistSource, BlocklistsConfig};

use crate::common::{spawn_http_server, HttpBehavior};

/// `count` unique domains, one per line (StevenBlack style).
fn domains_text(count: usize) -> String {
    (0..count).map(|i| format!("domain{i}.example\n")).collect()
}

fn url_list(name: &str, url: String) -> BlocklistSource {
    BlocklistSource {
        name: name.to_owned(),
        kind: BlocklistKind::Url,
        source: url,
    }
}

fn config_for(dir: &std::path::Path, list: BlocklistSource) -> BlocklistsConfig {
    BlocklistsConfig {
        cache_dir: dir.join("cache"),
        lists: vec![list],
        ..BlocklistsConfig::default()
    }
}

async fn refresh(config: &BlocklistsConfig) -> voidgate::blocklists::cache::RefreshReport {
    let mut reports = cache::refresh_all(config)
        .await
        .expect("refresh should run");
    reports.pop().expect("one report per list")
}

#[test]
fn write_atomic_replaces_content_and_leaves_no_temp_file() {
    let dir = tempfile::tempdir().unwrap();
    let cache_dir = dir.path().join("cache");
    fs::create_dir_all(&cache_dir).unwrap();

    cache::write_atomic(&cache_dir, "list1", b"old payload").unwrap();
    let path = cache::write_atomic(&cache_dir, "list1", b"new payload").unwrap();

    assert_eq!(fs::read(&path).unwrap(), b"new payload");
    assert!(!cache_dir.join("list1.tmp").exists());
    assert_eq!(
        fs::read_dir(&cache_dir).unwrap().count(),
        1,
        "cache dir must contain only the final file"
    );
}

#[test]
fn write_atomic_rejects_unsafe_names_without_touching_disk() {
    let dir = tempfile::tempdir().unwrap();
    let cache_dir = dir.path().join("cache");
    fs::create_dir_all(&cache_dir).unwrap();

    for name in ["../evil", "a/b", "UPPER", "with space", ""] {
        let err = cache::write_atomic(&cache_dir, name, b"x").unwrap_err();
        assert!(
            matches!(err, BlocklistError::InvalidName { .. }),
            "expected InvalidName for {name:?}, got {err:?}"
        );
    }
    assert_eq!(
        fs::read_dir(&cache_dir).unwrap().count(),
        0,
        "no file may be written for unsafe names"
    );
}

#[tokio::test]
async fn successful_download_updates_cache() {
    let body = domains_text(5);
    let addr = spawn_http_server(HttpBehavior::Respond, body.clone().into_bytes()).await;
    let dir = tempfile::tempdir().unwrap();
    let config = config_for(dir.path(), url_list("good", format!("http://{addr}/hosts")));

    let report = refresh(&config).await;
    assert_eq!(
        report.outcome,
        RefreshOutcome::Updated { domains: 5 },
        "report: {report}"
    );
    let cached = fs::read(config.cache_dir.join("good")).unwrap();
    assert_eq!(String::from_utf8(cached).unwrap(), body);
    assert!(!config.cache_dir.join("good.tmp").exists());
}

#[tokio::test]
async fn unreachable_url_keeps_old_cache() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_for(
        dir.path(),
        url_list("keepme", "http://placeholder.invalid/".to_owned()),
    );
    fs::create_dir_all(&config.cache_dir).unwrap();
    let old = domains_text(20);
    fs::write(config.cache_dir.join("keepme"), &old).unwrap();

    // Server accepts and closes without responding → fetch failure.
    let addr = spawn_http_server(HttpBehavior::CloseWithoutResponse, Vec::new()).await;
    let mut failing = config.clone();
    failing.lists[0].source = format!("http://{addr}/hosts");

    let report = refresh(&failing).await;
    match &report.outcome {
        RefreshOutcome::KeptOld {
            reason: KeepReason::FetchFailed { message },
        } => assert!(!message.is_empty()),
        other => panic!("expected KeptOld(FetchFailed), got {other:?}"),
    }
    assert_eq!(
        fs::read_to_string(config.cache_dir.join("keepme")).unwrap(),
        old,
        "old cache must be untouched"
    );
}

#[tokio::test]
async fn empty_download_keeps_old_cache() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_for(
        dir.path(),
        url_list("list", "http://placeholder.invalid/".to_owned()),
    );
    fs::create_dir_all(&config.cache_dir).unwrap();
    let old = domains_text(20);
    fs::write(config.cache_dir.join("list"), &old).unwrap();

    let addr = spawn_http_server(HttpBehavior::Respond, Vec::new()).await;
    let mut empty_body = config.clone();
    empty_body.lists[0].source = format!("http://{addr}/hosts");

    let report = refresh(&empty_body).await;
    assert_eq!(
        report.outcome,
        RefreshOutcome::KeptOld {
            reason: KeepReason::Empty
        }
    );
    assert_eq!(
        fs::read_to_string(config.cache_dir.join("list")).unwrap(),
        old
    );
}

#[tokio::test]
async fn shrunk_download_keeps_old_cache() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_for(
        dir.path(),
        url_list("list", "http://placeholder.invalid/".to_owned()),
    );
    fs::create_dir_all(&config.cache_dir).unwrap();
    let old = domains_text(100);
    fs::write(config.cache_dir.join("list"), &old).unwrap();

    // 5 of 100 domains retained (5%) < 10% floor → reject.
    let addr = spawn_http_server(HttpBehavior::Respond, domains_text(5).into_bytes()).await;
    let mut shrunk = config.clone();
    shrunk.lists[0].source = format!("http://{addr}/hosts");

    let report = refresh(&shrunk).await;
    assert_eq!(
        report.outcome,
        RefreshOutcome::KeptOld {
            reason: KeepReason::Shrink {
                previous: 100,
                current: 5,
            }
        }
    );
    assert_eq!(
        fs::read_to_string(config.cache_dir.join("list")).unwrap(),
        old
    );
}

#[tokio::test]
async fn exact_ninety_percent_shrink_is_accepted() {
    // 10 of 100 retained = exactly 90% smaller; only *more* than 90% is
    // rejected.
    let dir = tempfile::tempdir().unwrap();
    let config = config_for(
        dir.path(),
        url_list("list", "http://placeholder.invalid/".to_owned()),
    );
    fs::create_dir_all(&config.cache_dir).unwrap();
    fs::write(config.cache_dir.join("list"), domains_text(100)).unwrap();

    let addr = spawn_http_server(HttpBehavior::Respond, domains_text(10).into_bytes()).await;
    let mut refresh_config = config.clone();
    refresh_config.lists[0].source = format!("http://{addr}/hosts");

    let report = refresh(&refresh_config).await;
    assert_eq!(report.outcome, RefreshOutcome::Updated { domains: 10 });
}

#[tokio::test]
async fn oversized_download_is_rejected_and_keeps_old_cache() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = config_for(
        dir.path(),
        url_list("list", "http://placeholder.invalid/".to_owned()),
    );
    config.max_fetch_bytes = 64;
    fs::create_dir_all(&config.cache_dir).unwrap();
    let old = domains_text(10);
    fs::write(config.cache_dir.join("list"), &old).unwrap();

    let big_body = domains_text(500); // far over 64 bytes
    let addr = spawn_http_server(HttpBehavior::Respond, big_body.into_bytes()).await;
    config.lists[0].source = format!("http://{addr}/hosts");

    let report = refresh(&config).await;
    match &report.outcome {
        RefreshOutcome::KeptOld {
            reason: KeepReason::FetchFailed { message },
        } => assert!(message.contains("exceeds"), "message: {message}"),
        other => panic!("expected KeptOld(FetchFailed too large), got {other:?}"),
    }
    assert_eq!(
        fs::read_to_string(config.cache_dir.join("list")).unwrap(),
        old
    );
}

#[tokio::test]
async fn request_timeout_keeps_old_cache() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = config_for(
        dir.path(),
        url_list("list", "http://placeholder.invalid/".to_owned()),
    );
    config.fetch_timeout_secs = 1;
    fs::create_dir_all(&config.cache_dir).unwrap();
    let old = domains_text(10);
    fs::write(config.cache_dir.join("list"), &old).unwrap();

    let addr = spawn_http_server(HttpBehavior::Hang, Vec::new()).await;
    config.lists[0].source = format!("http://{addr}/hosts");

    let started = std::time::Instant::now();
    let report = refresh(&config).await;
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "fetch must respect fetch_timeout_secs"
    );
    match &report.outcome {
        RefreshOutcome::KeptOld {
            reason: KeepReason::FetchFailed { .. },
        } => {}
        other => panic!("expected KeptOld(FetchFailed), got {other:?}"),
    }
    assert_eq!(
        fs::read_to_string(config.cache_dir.join("list")).unwrap(),
        old
    );
}

#[tokio::test]
async fn refresh_creates_cache_dir_and_reports_local_files() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("local.txt");
    fs::write(&source, "0.0.0.0 local.example.com\n").unwrap();

    let config = BlocklistsConfig {
        cache_dir: dir.path().join("fresh-cache"),
        lists: vec![BlocklistSource {
            name: "local".to_owned(),
            kind: BlocklistKind::File,
            source: source.to_str().unwrap().to_owned(),
        }],
        ..BlocklistsConfig::default()
    };

    let report = refresh(&config).await;
    assert_eq!(report.outcome, RefreshOutcome::LocalFile);
    assert!(config.cache_dir.is_dir(), "cache dir must be created");
    assert!(
        !config.cache_dir.join("local").exists(),
        "file lists are never cached"
    );
}

#[tokio::test]
async fn report_display_is_human_readable() {
    let updated = voidgate::blocklists::cache::RefreshReport {
        name: "stevenblack".to_owned(),
        outcome: RefreshOutcome::Updated { domains: 42 },
    };
    assert_eq!(updated.to_string(), "stevenblack: updated (42 domains)");

    let kept = voidgate::blocklists::cache::RefreshReport {
        name: "ads".to_owned(),
        outcome: RefreshOutcome::KeptOld {
            reason: KeepReason::Empty,
        },
    };
    assert_eq!(
        kept.to_string(),
        "ads: kept previous cache (download parsed to 0 domains)"
    );
}
