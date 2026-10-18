#![allow(clippy::unwrap_used, clippy::expect_used)]
//! CLI smoke tests: help output, exit codes (0 ok, 1 config, 2 runtime), and
//! the `update-lists` report against local loopback listeners only.

mod common;

use std::process::Command;

use assert_cmd::cargo::cargo_bin;

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
fn stats_reports_milestone_m6() {
    let dir = tempfile::tempdir().expect("tempdir should be creatable");
    let path = write_config(dir.path(), &common::minimal_config_yaml());
    let path = path.to_str().unwrap();

    let output = run_voidgate(&["stats", "--config", path]);
    assert_eq!(output.code, Some(2), "stderr: {}", output.stderr);
    assert!(output.stderr.contains("M6"), "{}", output.stderr);
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
