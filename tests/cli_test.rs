#![allow(clippy::unwrap_used, clippy::expect_used)]
//! CLI smoke tests: help output, exit codes (0 ok, 1 config/usage, 2 runtime),
//! the `update-lists` report against local loopback listeners only, the `stats`
//! tables/JSON against a temp database seeded through the storage API, and
//! `check-config`.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use assert_cmd::cargo::cargo_bin;
use voidgate::config::StorageConfig;
use voidgate::storage::{now_ms, Action, QueryLog, QueryRow};

use crate::common::{spawn_http_server, write_config, HttpBehavior};

/// A finished voidgate invocation.
struct Output {
    /// Process exit code.
    code: Option<i32>,
    /// Captured stdout.
    stdout: String,
    /// Captured stderr.
    stderr: String,
}

/// Runs the built `voidgate` binary with `args`.
fn run_voidgate(args: &[&str]) -> Output {
    let output = Command::new(cargo_bin("voidgate"))
        .args(args)
        .output()
        .expect("voidgate should run");
    Output {
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

#[test]
fn help_lists_all_subcommands() {
    let output = run_voidgate(&["--help"]);
    assert_eq!(output.code, Some(0), "stderr: {}", output.stderr);
    assert!(output.stdout.contains("run"), "{}", output.stdout);
    assert!(output.stdout.contains("update-lists"), "{}", output.stdout);
    assert!(output.stdout.contains("stats"), "{}", output.stdout);
    assert!(output.stdout.contains("check-config"), "{}", output.stdout);
    assert!(output.stdout.contains("--config"), "{}", output.stdout);
}

#[test]
fn missing_config_file_exits_with_1() {
    let output = run_voidgate(&["run", "--config", "/nonexistent/voidgate.yaml"]);
    assert_eq!(output.code, Some(1), "stderr: {}", output.stderr);
    assert!(output.stderr.contains("config error"), "{}", output.stderr);
    assert!(
        output.stderr.contains("/nonexistent/voidgate.yaml"),
        "{}",
        output.stderr
    );
}

#[test]
fn run_with_port_in_use_exits_with_2_and_a_hint() {
    // Hold a loopback UDP port so the child's bind fails with EADDRINUSE.
    let occupied = std::net::UdpSocket::bind("127.0.0.1:0").expect("port should bind");
    let port = occupied.local_addr().unwrap().port();

    let dir = tempfile::tempdir().expect("tempdir should be creatable");
    let yaml = format!(
        "server: {{ listen: \"127.0.0.1\", port: {port}, allowed_clients: [\"127.0.0.0/8\"] }}\nstorage: {{ log_queries: false }}\ndefault_policy: {{}}\n"
    );
    let path = write_config(dir.path(), &yaml);

    let output = run_voidgate(&["run", "--config", path.to_str().unwrap()]);
    assert_eq!(output.code, Some(2), "stderr: {}", output.stderr);
    assert!(output.stderr.contains("hint"), "{}", output.stderr);
    assert!(
        output.stderr.contains(&format!("127.0.0.1:{port}")),
        "{}",
        output.stderr
    );
}

#[test]
fn stats_table_reports_counts_and_percentages() {
    let dir = tempfile::tempdir().expect("tempdir should be creatable");
    let db = dir.path().join("voidgate.db");
    seed_db(&db, &seven_rows(now_ms()));
    let path = config_with_db(dir.path(), &db);
    let path = path.to_str().unwrap();

    let output = run_voidgate(&["stats", "--config", path]);
    assert_eq!(output.code, Some(0), "stderr: {}", output.stderr);
    assert!(
        output.stdout.contains("Total queries: 7"),
        "{}",
        output.stdout
    );
    assert!(
        output.stdout.contains("Top 10 blocked domains"),
        "{}",
        output.stdout
    );
    assert!(output.stdout.contains("ads.example"), "{}", output.stdout);
    // 4 of 7 blocked → 57.1%.
    assert!(output.stdout.contains("57.1%"), "{}", output.stdout);
    assert!(output.stdout.contains("10.0.0.1"), "{}", output.stdout);
    assert!(output.stdout.contains("10.0.0.2"), "{}", output.stdout);
    // Every action is listed, including the zero-count ones.
    assert!(output.stdout.contains("servfail"), "{}", output.stdout);
}

#[test]
fn stats_top_limits_the_domain_table() {
    let dir = tempfile::tempdir().expect("tempdir should be creatable");
    let db = dir.path().join("voidgate.db");
    seed_db(&db, &seven_rows(now_ms()));
    let path = config_with_db(dir.path(), &db);
    let path = path.to_str().unwrap();

    let output = run_voidgate(&["stats", "--top", "1", "--config", path]);
    assert_eq!(output.code, Some(0), "stderr: {}", output.stderr);
    assert!(
        output.stdout.contains("Top 1 blocked domains"),
        "{}",
        output.stdout
    );
    assert!(output.stdout.contains("ads.example"), "{}", output.stdout);
    assert!(
        !output.stdout.contains("tracker.example"),
        "top 1 should hide the runner-up: {}",
        output.stdout
    );
}

#[test]
fn stats_since_window_excludes_old_rows() {
    let dir = tempfile::tempdir().expect("tempdir should be creatable");
    let db = dir.path().join("voidgate.db");
    let now = now_ms();
    let day = 86_400_000;
    seed_db(
        &db,
        &[
            ("10.0.0.1", "fresh.example", Action::Blocked, now),
            (
                "10.0.0.1",
                "fresh.example",
                Action::Blocked,
                now - 3_600_000,
            ),
            ("10.0.0.2", "old.example", Action::Blocked, now - 2 * day),
        ],
    );
    let path = config_with_db(dir.path(), &db);
    let path = path.to_str().unwrap();

    // No window: everything.
    let all = run_voidgate(&["stats", "--config", path]);
    assert_eq!(all.code, Some(0), "stderr: {}", all.stderr);
    assert!(all.stdout.contains("Total queries: 3"), "{}", all.stdout);

    // One-day window drops the two-day-old row.
    let windowed = run_voidgate(&["stats", "--since", "1d", "--config", path]);
    assert_eq!(windowed.code, Some(0), "stderr: {}", windowed.stderr);
    assert!(
        windowed.stdout.contains("Period: last 1d"),
        "{}",
        windowed.stdout
    );
    assert!(
        windowed.stdout.contains("Total queries: 2"),
        "{}",
        windowed.stdout
    );
    assert!(
        !windowed.stdout.contains("old.example"),
        "{}",
        windowed.stdout
    );
    assert!(
        windowed.stdout.contains("fresh.example"),
        "{}",
        windowed.stdout
    );
}

#[test]
fn stats_json_parses_and_matches_the_totals() {
    let dir = tempfile::tempdir().expect("tempdir should be creatable");
    let db = dir.path().join("voidgate.db");
    seed_db(&db, &seven_rows(now_ms()));
    let path = config_with_db(dir.path(), &db);
    let path = path.to_str().unwrap();

    let output = run_voidgate(&["stats", "--json", "--config", path]);
    assert_eq!(output.code, Some(0), "stderr: {}", output.stderr);
    // JSON is valid YAML (a superset), so the existing parser validates it.
    let parsed: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(&output.stdout).expect("stats --json must be valid JSON");
    assert_eq!(parsed["total"].as_u64(), Some(7));
    assert_eq!(parsed["by_action"].as_sequence().unwrap().len(), 4);
    assert_eq!(
        parsed["top_blocked"][0]["domain"].as_str(),
        Some("ads.example")
    );
    assert_eq!(parsed["clients"].as_sequence().unwrap().len(), 2);
    // Tables and JSON never mix.
    assert!(
        !output.stdout.contains("Total queries:"),
        "{}",
        output.stdout
    );
}

#[test]
fn stats_missing_db_exits_1_without_creating_it() {
    let dir = tempfile::tempdir().expect("tempdir should be creatable");
    let db = dir.path().join("voidgate.db");
    let path = config_with_db(dir.path(), &db);
    let path = path.to_str().unwrap();

    let output = run_voidgate(&["stats", "--config", path]);
    assert_eq!(output.code, Some(1), "stderr: {}", output.stderr);
    assert!(output.stderr.contains("no query log"), "{}", output.stderr);
    assert!(output.stderr.contains("hint"), "{}", output.stderr);
    assert!(!db.exists(), "stats must never create the database");
}

#[test]
fn stats_with_logging_disabled_exits_1() {
    let dir = tempfile::tempdir().expect("tempdir should be creatable");
    let db = dir.path().join("voidgate.db");
    let yaml = format!(
        "server: {{ allowed_clients: [\"127.0.0.0/8\"] }}\nstorage: {{ log_queries: false, db_path: \"{}\" }}\ndefault_policy: {{}}\n",
        db.display()
    );
    let path = write_config(dir.path(), &yaml);
    let path = path.to_str().unwrap();

    let output = run_voidgate(&["stats", "--config", path]);
    assert_eq!(output.code, Some(1), "stderr: {}", output.stderr);
    assert!(output.stderr.contains("log_queries"), "{}", output.stderr);
    assert!(!db.exists(), "stats must never create the database");
}

#[test]
fn stats_invalid_since_exits_1() {
    let dir = tempfile::tempdir().expect("tempdir should be creatable");
    let db = dir.path().join("voidgate.db");
    seed_db(&db, &seven_rows(now_ms()));
    let path = config_with_db(dir.path(), &db);
    let path = path.to_str().unwrap();

    let output = run_voidgate(&["stats", "--since", "2w", "--config", path]);
    assert_eq!(output.code, Some(1), "stderr: {}", output.stderr);
    assert!(
        output.stderr.contains("invalid --since"),
        "{}",
        output.stderr
    );
    assert!(output.stderr.contains("hint"), "{}", output.stderr);
}

#[test]
fn check_config_valid_exits_0() {
    let dir = tempfile::tempdir().expect("tempdir should be creatable");
    let yaml = r#"
server:
  listen: "127.0.0.1"
  allowed_clients: ["127.0.0.0/8"]
blocklists:
  lists:
    - name: l
      type: file
      source: "l.txt"
policies:
  - name: p
    match: ["127.0.0.1/32"]
    blocklists: [l]
default_policy:
  blocklists: [l]
"#;
    let path = write_config(dir.path(), yaml);
    let path = path.to_str().unwrap();

    let output = run_voidgate(&["check-config", "--config", path]);
    assert_eq!(output.code, Some(0), "stderr: {}", output.stderr);
    assert!(output.stdout.contains("config OK"), "{}", output.stdout);
    assert!(
        !output.stdout.contains("warning:"),
        "a clean config should not warn: {}",
        output.stdout
    );
}

#[test]
fn check_config_warns_but_still_exits_0() {
    let dir = tempfile::tempdir().expect("tempdir should be creatable");
    let path = write_config(dir.path(), &common::minimal_config_yaml());
    let path = path.to_str().unwrap();

    let output = run_voidgate(&["check-config", "--config", path]);
    assert_eq!(output.code, Some(0), "stderr: {}", output.stderr);
    assert!(output.stdout.contains("warning:"), "{}", output.stdout);
    assert!(output.stdout.contains("config OK"), "{}", output.stdout);
}

#[test]
fn check_config_invalid_exits_1() {
    let dir = tempfile::tempdir().expect("tempdir should be creatable");
    let path = write_config(
        dir.path(),
        "server: { allowed_clients: [] }\ndefault_policy: {}\n",
    );
    let path = path.to_str().unwrap();

    let output = run_voidgate(&["check-config", "--config", path]);
    assert_eq!(output.code, Some(1), "stderr: {}", output.stderr);
    assert!(output.stderr.contains("config error"), "{}", output.stderr);
    assert!(output.stderr.contains("hint"), "{}", output.stderr);
    assert!(
        output.stderr.contains("server.allowed_clients"),
        "{}",
        output.stderr
    );
}

#[test]
fn check_config_reads_the_given_config_path() {
    let dir = tempfile::tempdir().expect("tempdir should be creatable");
    // A non-default filename proves --config is honoured.
    let custom = dir.path().join("other.yaml");
    let yaml = "server: { listen: \"127.0.0.1\", allowed_clients: [\"127.0.0.0/8\"] }\ndefault_policy: {}\n";
    std::fs::write(&custom, yaml).unwrap();

    let output = run_voidgate(&["check-config", "--config", custom.to_str().unwrap()]);
    assert_eq!(output.code, Some(0), "stderr: {}", output.stderr);
    assert!(
        output.stdout.contains(custom.to_str().unwrap()),
        "{}",
        output.stdout
    );
}

#[test]
fn unknown_flag_is_a_usage_error_exit_1() {
    let output = run_voidgate(&["--definitely-not-a-flag"]);
    assert_eq!(output.code, Some(1), "stderr: {}", output.stderr);
    assert!(
        !output.stderr.is_empty(),
        "a usage error should explain itself"
    );
}

/// Seeds a query-log database through the storage API (never raw SQL), so the
/// rows are exactly what the server would have written.
fn seed_db(db: &Path, rows: &[(&str, &str, Action, i64)]) {
    let config = StorageConfig {
        db_path: db.to_path_buf(),
        retention_days: 0,
        flush_rows: 1,
        ..StorageConfig::default()
    };
    let log = QueryLog::start(&config).expect("query log should start");
    for (client, domain, action, ts) in rows {
        log.log(QueryRow {
            ts_ms: *ts,
            client_ip: client.parse().expect("client ip should parse"),
            domain: (*domain).to_owned(),
            action: *action,
            upstream_latency_ms: None,
        });
    }
    log.shutdown().expect("query log should flush");
}

/// Writes a valid config whose query log lives at `db`.
fn config_with_db(dir: &Path, db: &Path) -> PathBuf {
    let yaml = format!(
        "server: {{ allowed_clients: [\"127.0.0.0/8\"] }}\nstorage: {{ db_path: \"{}\" }}\ndefault_policy: {{}}\n",
        db.display()
    );
    write_config(dir, &yaml)
}

/// The seven-row fixture shared by the stats table/JSON tests.
fn seven_rows(ts: i64) -> Vec<(&'static str, &'static str, Action, i64)> {
    vec![
        ("10.0.0.1", "ads.example", Action::Blocked, ts),
        ("10.0.0.1", "ads.example", Action::Blocked, ts),
        ("10.0.0.1", "tracker.example", Action::Blocked, ts),
        ("10.0.0.1", "other.example", Action::Forwarded, ts),
        ("10.0.0.2", "ads.example", Action::Blocked, ts),
        ("10.0.0.2", "safe.example", Action::Allowed, ts),
        ("10.0.0.2", "bad.example", Action::Servfail, ts),
    ]
}

#[test]
fn invalid_config_exits_with_1_and_names_the_field() {
    let dir = tempfile::tempdir().expect("tempdir should be creatable");
    let yaml = "server: { allowed_clients: [] }\ndefault_policy: {}\n";
    let path = write_config(dir.path(), yaml);
    let path = path.to_str().unwrap();

    let output = run_voidgate(&["stats", "--config", path]);
    assert_eq!(output.code, Some(1), "stderr: {}", output.stderr);
    assert!(
        output.stderr.contains("server.allowed_clients"),
        "{}",
        output.stderr
    );
}

#[test]
fn version_flag_reports_the_package_version() {
    let output = run_voidgate(&["--version"]);
    assert_eq!(output.code, Some(0));
    assert!(
        output.stdout.contains(env!("CARGO_PKG_VERSION")),
        "{}",
        output.stdout
    );
}

#[test]
fn update_lists_with_local_file_lists_exits_0_and_reports() {
    let dir = tempfile::tempdir().expect("tempdir should be creatable");
    let source = dir.path().join("local.txt");
    std::fs::write(&source, "0.0.0.0 local.example.com\n").unwrap();

    let yaml = format!(
        r#"server: {{ allowed_clients: ["127.0.0.0/8"] }}
blocklists:
  cache_dir: "{}"
  lists:
    - name: local-ads
      type: file
      source: "{}"
default_policy: {{}}
"#,
        dir.path().join("cache").display(),
        source.display()
    );
    let path = write_config(dir.path(), &yaml);

    let output = run_voidgate(&["update-lists", "--config", path.to_str().unwrap()]);
    assert_eq!(output.code, Some(0), "stderr: {}", output.stderr);
    assert!(
        output.stdout.contains("local-ads: local file"),
        "stdout: {}",
        output.stdout
    );
}

#[test]
fn update_lists_keeps_old_cache_when_url_unreachable() {
    let dir = tempfile::tempdir().expect("tempdir should be creatable");
    let cache_dir = dir.path().join("cache");
    std::fs::create_dir_all(&cache_dir).unwrap();

    // Local one-shot server that closes without responding → fetch fails.
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let addr = runtime.block_on(spawn_http_server(
        HttpBehavior::CloseWithoutResponse,
        Vec::new(),
    ));

    let yaml = format!(
        r#"server: {{ allowed_clients: ["127.0.0.0/8"] }}
blocklists:
  cache_dir: "{}"
  lists:
    - name: unreachable
      type: url
      source: "http://{addr}/hosts"
default_policy: {{}}
"#,
        cache_dir.display()
    );
    let path = write_config(dir.path(), &yaml);

    let output = run_voidgate(&["update-lists", "--config", path.to_str().unwrap()]);
    assert_eq!(output.code, Some(0), "stderr: {}", output.stderr);
    assert!(
        output
            .stdout
            .contains("unreachable: kept previous cache (fetch failed:"),
        "stdout: {}",
        output.stdout
    );
    drop(runtime);
}
