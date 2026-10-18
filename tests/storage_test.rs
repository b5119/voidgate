#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Integration tests for the SQLite query log: round-trip, batching,
//! non-blocking drops, pruning, disabled mode, and read-only stats.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use rusqlite::{params, Connection};
use voidgate::config::StorageConfig;
use voidgate::storage::{now_ms, prune, schema, Action, QueryLog, QueryRow, Stats};

/// Storage config pointing at `db`, with pruning disabled unless overridden.
fn log_config(db: PathBuf, queue_capacity: usize, flush_rows: usize) -> StorageConfig {
    StorageConfig {
        db_path: db,
        queue_capacity,
        flush_rows,
        retention_days: 0,
        ..StorageConfig::default()
    }
}

/// A row with `client_ip`/`action` spelled out for readability.
fn row(ts: i64, ip: &str, domain: &str, action: Action, latency: Option<u32>) -> QueryRow {
    QueryRow {
        ts_ms: ts,
        client_ip: ip.parse().unwrap(),
        domain: domain.to_owned(),
        action,
        upstream_latency_ms: latency,
    }
}

#[test]
fn round_trip_persists_every_column() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("queries.db");
    let log = QueryLog::start(&log_config(db.clone(), 32, 1)).unwrap();

    let stamp = now_ms();
    log.log(row(
        stamp,
        "192.168.1.5",
        "ads.example",
        Action::Blocked,
        None,
    ));
    log.log(row(
        stamp + 1,
        "::1",
        "safe.example",
        Action::Allowed,
        Some(12),
    ));
    log.shutdown().unwrap();

    let conn = Connection::open(&db).unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT ts, client_ip, domain, action, upstream_latency_ms \
             FROM queries ORDER BY id",
        )
        .unwrap();
    let rows: Vec<(i64, String, String, String, Option<i64>)> = stmt
        .query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect();

    assert_eq!(
        rows,
        vec![
            (
                stamp,
                "192.168.1.5".to_owned(),
                "ads.example".to_owned(),
                "blocked".to_owned(),
                None,
            ),
            (
                stamp + 1,
                "::1".to_owned(),
                "safe.example".to_owned(),
                "allowed".to_owned(),
                Some(12),
            ),
        ]
    );
}

#[test]
fn aggregation_counts_top_domains_and_clients() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("queries.db");
    let log = QueryLog::start(&log_config(db.clone(), 64, 1)).unwrap();

    let ts = now_ms();
    let entries = [
        row(ts, "10.0.0.1", "ads.example", Action::Blocked, None),
        row(ts, "10.0.0.1", "ads.example", Action::Blocked, None),
        row(ts, "10.0.0.1", "tracker.example", Action::Blocked, None),
        row(ts, "10.0.0.1", "other.example", Action::Forwarded, Some(4)),
        row(ts, "10.0.0.2", "ads.example", Action::Blocked, None),
        row(ts, "10.0.0.2", "safe.example", Action::Allowed, Some(9)),
        row(ts, "10.0.0.2", "bad.example", Action::Servfail, None),
    ];
    for entry in entries {
        log.log(entry);
    }
    log.shutdown().unwrap();

    let stats = Stats::open(&db, 5000).unwrap();
    assert_eq!(stats.total().unwrap(), 7);
    assert_eq!(
        stats.counts_by_action().unwrap(),
        vec![
            (Action::Allowed, 1),
            (Action::Blocked, 4),
            (Action::Forwarded, 1),
            (Action::Servfail, 1),
        ]
    );
    assert_eq!(
        stats.top_blocked_domains(2).unwrap(),
        vec![
            ("ads.example".to_owned(), 3),
            ("tracker.example".to_owned(), 1),
        ]
    );
    assert_eq!(
        stats.per_client().unwrap(),
        vec![
            voidgate::storage::ClientStat {
                client_ip: "10.0.0.1".to_owned(),
                total: 4,
                blocked: 3,
            },
            voidgate::storage::ClientStat {
                client_ip: "10.0.0.2".to_owned(),
                total: 3,
                blocked: 1,
            },
        ]
    );
}

#[test]
fn schema_init_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    // Nested, not-yet-existing directory: initialize must create it.
    let db = dir.path().join("nested/deeper/queries.db");

    let first = schema::initialize(&db, 5000).unwrap();
    let version: i32 = first
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, schema::SCHEMA_VERSION);
    let tables: i64 = first
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'queries'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(tables, 1);
    drop(first);

    // Second initialise on the existing file is a no-op, not an error.
    let second = schema::initialize(&db, 5000).unwrap();
    let version: i32 = second
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, schema::SCHEMA_VERSION);
}

#[test]
fn full_channel_drops_without_blocking() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("queries.db");

    // Tiny queue; the writer commits one row at a time, so it will stall on
    // the lock we hold below and the queue fills immediately.
    let config = log_config(db.clone(), 1, 1);
    let log = QueryLog::start(&config).unwrap();

    // Hold the write lock so every insert the writer attempts is busy.
    let blocker = Connection::open(&db).unwrap();
    blocker.busy_timeout(Duration::from_millis(0)).unwrap();
    blocker.execute_batch("BEGIN EXCLUSIVE").unwrap();

    let start = Instant::now();
    let ts = now_ms();
    for i in 0..200 {
        log.log(row(
            ts + i,
            "10.0.0.1",
            "ads.example",
            Action::Blocked,
            None,
        ));
    }
    let elapsed = start.elapsed();

    // Logging never blocks, even though the writer is stuck.
    assert!(elapsed < Duration::from_secs(2), "logging took {elapsed:?}");
    // Most rows had nowhere to go and were counted as dropped.
    assert!(
        log.dropped() >= 100,
        "expected many drops, got {}",
        log.dropped()
    );

    blocker.execute_batch("ROLLBACK").unwrap();
    drop(blocker);
    log.shutdown().unwrap();
}

#[test]
fn prune_deletes_only_rows_older_than_cutoff() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("queries.db");
    let conn = schema::initialize(&db, 5000).unwrap();

    let now = now_ms();
    let old = now - 2 * 86_400_000;
    for (ts, domain) in [(old, "old.example"), (now, "new.example")] {
        conn.execute(
            "INSERT INTO queries (ts, client_ip, domain, action) VALUES (?1, '10.0.0.1', ?2, 'blocked')",
            params![ts, domain],
        )
        .unwrap();
    }

    // 0 disables pruning entirely.
    assert_eq!(prune(&conn, 0).unwrap(), 0);
    // 1 day keeps only the fresh row.
    assert_eq!(prune(&conn, 1).unwrap(), 1);
    let remaining: i64 = conn
        .query_row("SELECT COUNT(*) FROM queries", [], |r| r.get(0))
        .unwrap();
    assert_eq!(remaining, 1);
    let domain: String = conn
        .query_row("SELECT domain FROM queries", [], |r| r.get(0))
        .unwrap();
    assert_eq!(domain, "new.example");
}

#[test]
fn log_queries_false_touches_no_file() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("nested/queries.db");

    let config = StorageConfig {
        log_queries: false,
        db_path: db.clone(),
        ..StorageConfig::default()
    };
    let log = QueryLog::start(&config).unwrap();

    assert!(!log.is_enabled());
    log.log(row(
        now_ms(),
        "10.0.0.1",
        "ads.example",
        Action::Blocked,
        None,
    ));
    assert_eq!(log.dropped(), 0);
    log.shutdown().unwrap();

    assert!(!db.exists(), "disabled logging must not create a database");
    assert!(
        !db.parent().unwrap().exists(),
        "disabled logging must not create directories"
    );
}

#[test]
fn shutdown_flushes_pending_rows() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("queries.db");

    // Nothing flushes on its own: a huge row threshold and a long interval.
    let mut config = log_config(db.clone(), 64, 1000);
    config.flush_interval_ms = 60_000;
    let log = QueryLog::start(&config).unwrap();

    let ts = now_ms();
    for i in 0..3 {
        log.log(row(
            ts + i,
            "10.0.0.1",
            "ads.example",
            Action::Blocked,
            None,
        ));
    }
    log.shutdown().unwrap();

    let stats = Stats::open(&db, 5000).unwrap();
    assert_eq!(stats.total().unwrap(), 3);
}

#[test]
fn stats_are_readable_while_the_writer_is_active() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("queries.db");
    let log = QueryLog::start(&log_config(db.clone(), 64, 1)).unwrap();

    let ts = now_ms();
    for i in 0..5 {
        log.log(row(
            ts + i,
            "10.0.0.1",
            "ads.example",
            Action::Blocked,
            None,
        ));
    }

    let stats = Stats::open(&db, 5000).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if stats.total().unwrap() == 5 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "rows were not visible while the writer was running"
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    log.shutdown().unwrap();
}

#[test]
fn action_labels_round_trip() {
    for action in [
        Action::Allowed,
        Action::Blocked,
        Action::Forwarded,
        Action::Servfail,
    ] {
        assert_eq!(Action::parse(action.as_str()).unwrap(), action);
    }
    assert_eq!(Action::Allowed.as_str(), "allowed");
    assert_eq!(Action::Blocked.as_str(), "blocked");
    assert_eq!(Action::Forwarded.as_str(), "forwarded");
    assert_eq!(Action::Servfail.as_str(), "servfail");
    // REFUSED is deliberately not a loggable action.
    assert!(Action::parse("refused").is_err());
}

#[cfg(unix)]
#[test]
fn database_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("queries.db");
    let log = QueryLog::start(&log_config(db.clone(), 8, 1)).unwrap();
    log.shutdown().unwrap();

    let mode = std::fs::metadata(&db).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "query log must be owner-only, got {mode:o}");
}
