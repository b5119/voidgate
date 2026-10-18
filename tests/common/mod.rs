#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Shared fixtures for voidgate integration tests.

use std::fs;
use std::path::{Path, PathBuf};

/// Writes `yaml` to `dir/config.yaml` and returns the path.
///
/// The directory must outlive the returned path's use (callers load the file
/// immediately).
pub fn write_config(dir: &Path, yaml: &str) -> PathBuf {
    let path = dir.join("config.yaml");
    fs::write(&path, yaml).expect("test config should be writable");
    path
}

/// A valid minimal configuration: loopback client, one named blocklist.
///
/// `AppConfig::load` on this text succeeds (with warnings about the empty
/// default policy unless overridden by the caller).
pub fn minimal_config_yaml() -> String {
    r#"
server:
  listen: "127.0.0.1"
  port: 5353
  allowed_clients:
    - "127.0.0.0/8"
blocklists:
  lists:
    - name: testlist
      type: file
      source: "lists/test.txt"
policies: []
default_policy: {}
storage:
  db_path: "voidgate.db"
"#
    .to_owned()
}
