#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(dead_code)] // shared across test binaries; each binary uses a subset
//! Shared fixtures for voidgate integration tests.

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

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

/// How a one-shot test HTTP server treats the first connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpBehavior {
    /// Answer with HTTP 200 and the configured body.
    Respond,
    /// Accept, read the request, then close without responding.
    CloseWithoutResponse,
    /// Accept and hang (never respond) until the runtime shuts down.
    Hang,
}

/// Starts a one-shot HTTP server on an ephemeral loopback port.
///
/// Never touches the real network: everything stays on `127.0.0.1`.
pub async fn spawn_http_server(behavior: HttpBehavior, body: Vec<u8>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test listener should bind");
    let addr = listener
        .local_addr()
        .expect("bound listener should have an address");
    tokio::spawn(async move {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        match behavior {
            HttpBehavior::CloseWithoutResponse => {
                let mut buffer = [0u8; 4096];
                let _ = socket.read(&mut buffer).await;
                drop(socket);
            }
            HttpBehavior::Hang => {
                tokio::time::sleep(Duration::from_secs(300)).await;
            }
            HttpBehavior::Respond => {
                let mut buffer = [0u8; 4096];
                let _ = socket.read(&mut buffer).await;
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(header.as_bytes()).await;
                let _ = socket.write_all(&body).await;
                let _ = socket.shutdown().await;
            }
        }
    });
    addr
}
