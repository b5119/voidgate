#![allow(clippy::unwrap_used, clippy::expect_used)]
//! CLI smoke tests: help output and the documented exit codes
//! (0 success, 1 config error, 2 runtime error).

mod common;

use std::process::Command;

use assert_cmd::cargo::cargo_bin;

use crate::common::write_config;

/// Runs the built `voidgate` binary with `args`, returning `(code, stderr)`.
fn run_voidgate(args: &[&str]) -> (Option<i32>, String) {
    let output = Command::new(cargo_bin("voidgate"))
        .args(args)
        .output()
        .expect("voidgate should run");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn help_lists_all_subcommands() {
    let output = Command::new(cargo_bin("voidgate"))
        .arg("--help")
        .output()
        .expect("voidgate should run");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("run"), "{stdout}");
    assert!(stdout.contains("update-lists"), "{stdout}");
    assert!(stdout.contains("stats"), "{stdout}");
    assert!(stdout.contains("--config"), "{stdout}");
}

#[test]
fn missing_config_file_exits_with_1() {
    let (code, stderr) = run_voidgate(&["run", "--config", "/nonexistent/voidgate.yaml"]);
    assert_eq!(code, Some(1), "stderr: {stderr}");
    assert!(stderr.contains("config error"), "{stderr}");
    assert!(stderr.contains("/nonexistent/voidgate.yaml"), "{stderr}");
}

#[test]
fn run_with_valid_config_exits_with_2_until_m5b() {
    let dir = tempfile::tempdir().expect("tempdir should be creatable");
    let path = write_config(dir.path(), &common::minimal_config_yaml());
    let path = path.to_str().unwrap();

    let (code, stderr) = run_voidgate(&["run", "--config", path]);
    assert_eq!(code, Some(2), "stderr: {stderr}");
    assert!(stderr.contains("not implemented yet"), "{stderr}");
    assert!(stderr.contains("M5b"), "{stderr}");
}

#[test]
fn update_lists_and_stats_report_their_milestones() {
    let dir = tempfile::tempdir().expect("tempdir should be creatable");
    let path = write_config(dir.path(), &common::minimal_config_yaml());
    let path = path.to_str().unwrap();

    let (code, stderr) = run_voidgate(&["update-lists", "--config", path]);
    assert_eq!(code, Some(2), "stderr: {stderr}");
    assert!(stderr.contains("M2"), "{stderr}");

    let (code, stderr) = run_voidgate(&["stats", "--config", path]);
    assert_eq!(code, Some(2), "stderr: {stderr}");
    assert!(stderr.contains("M6"), "{stderr}");
}

#[test]
fn invalid_config_exits_with_1_and_names_the_field() {
    let dir = tempfile::tempdir().expect("tempdir should be creatable");
    let yaml = "server: { allowed_clients: [] }\ndefault_policy: {}\n";
    let path = write_config(dir.path(), yaml);
    let path = path.to_str().unwrap();

    let (code, stderr) = run_voidgate(&["stats", "--config", path]);
    assert_eq!(code, Some(1), "stderr: {stderr}");
    assert!(stderr.contains("server.allowed_clients"), "{stderr}");
}

#[test]
fn version_flag_reports_the_package_version() {
    let output = Command::new(cargo_bin("voidgate"))
        .arg("--version")
        .output()
        .expect("voidgate should run");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")), "{stdout}");
}
