#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Integration tests for the UDP listener: end-to-end query handling, the
//! in-flight cap, graceful shutdown + log flush, and bind failures.
//!
//! Everything stays on loopback: real UDP sockets and a fake loopback upstream.

mod common;

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{RData, RecordType};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use voidgate::blocklists::BlocklistStore;
use voidgate::config::AppConfig;
use voidgate::server::{Server, ServerError};
use voidgate::storage::{Action, QueryLog, Stats};

use common::UpstreamBehavior;

/// Base config: loopback ACL, one policy blocking the `ads` list, an ephemeral
/// port, and short timeouts so tests stay fast.
fn base_config() -> AppConfig {
    let yaml = r#"
server:
  listen: "127.0.0.1"
  port: 0
  allowed_clients: ["127.0.0.0/8"]
  timeout_ms: 500
  max_inflight: 256
  shutdown_grace_ms: 300
blocklists:
  lists:
    - { name: ads, type: file, source: "ads.txt" }
policies:
  - name: lan
    match: ["127.0.0.0/8"]
    blocklists: ["ads"]
    allowlist: ["allowed.example"]
    denylist: ["denied.example"]
default_policy: {}
storage: { log_queries: false }
"#;
    serde_yaml_ng::from_str(yaml).expect("base config should parse")
}

/// Config pointing at a freshly spawned fake upstream.
async fn config_with_upstream(behavior: UpstreamBehavior) -> AppConfig {
    let upstream = common::spawn_udp_upstream(behavior).await;
    let mut config = base_config();
    config.server.upstream = upstream.ip();
    config.server.upstream_port = upstream.port();
    config
}

/// A hand-built blocklist store behind the hot-swappable handle.
fn blocklists(entries: &[(&str, &[&str])]) -> Arc<ArcSwap<BlocklistStore>> {
    let mut store = BlocklistStore::new();
    for (name, domains) in entries {
        store.insert(*name, domains.to_vec());
    }
    Arc::new(ArcSwap::from_pointee(store))
}

/// A running listener plus the handle needed to stop it.
struct Running {
    addr: SocketAddr,
    shutdown: oneshot::Sender<()>,
    join: tokio::task::JoinHandle<Result<(), ServerError>>,
}

/// Binds and serves in a background task; the returned handle owns shutdown.
async fn start(config: &AppConfig, entries: &[(&str, &[&str])], log: QueryLog) -> Running {
    let server = Server::bind(config, blocklists(entries), log).expect("bind should succeed");
    let addr = server
        .local_addr()
        .expect("listener should have an address");
    let (shutdown, rx) = oneshot::channel();
    let join = tokio::spawn(server.run(async move {
        let _ = rx.await;
    }));
    Running {
        addr,
        shutdown,
        join,
    }
}

impl Running {
    /// Sends the shutdown signal and waits for the run loop to finish.
    async fn stop(self) {
        let _ = self.shutdown.send(());
        self.join
            .await
            .expect("run task should not panic")
            .expect("run should return cleanly");
    }
}

/// Sends one query from a fresh socket and decodes the reply.
async fn ask(addr: SocketAddr, packet: &[u8]) -> Message {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(packet, addr).await.unwrap();
    let mut buffer = [0u8; 4096];
    let (len, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buffer))
        .await
        .expect("reply should arrive")
        .expect("recv should succeed");
    common::parse_response(&buffer[..len])
}

#[tokio::test]
async fn blocked_query_is_sinkholed_to_zero() {
    let config = config_with_upstream(UpstreamBehavior::Valid).await;
    let running = start(&config, &[("ads", &["ads.example"])], QueryLog::disabled()).await;

    let packet = common::build_query(0x0042, "ads.example.", RecordType::A);
    let reply = ask(running.addr, &packet).await;

    assert_eq!(reply.metadata.id, 0x0042);
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert_eq!(reply.answers.len(), 1);
    assert_eq!(
        reply.answers[0].data,
        RData::A(Ipv4Addr::UNSPECIFIED.into())
    );

    running.stop().await;
}

#[tokio::test]
async fn forwarded_query_returns_the_upstream_answer() {
    let config = config_with_upstream(UpstreamBehavior::Valid).await;
    let running = start(&config, &[], QueryLog::disabled()).await;

    let packet = common::build_query(0x1234, "example.com.", RecordType::A);
    let reply = ask(running.addr, &packet).await;

    assert_eq!(reply.metadata.id, 0x1234);
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert!(reply.metadata.recursion_available);
    assert_eq!(
        reply.answers[0].data,
        RData::A(Ipv4Addr::new(1, 2, 3, 4).into())
    );

    running.stop().await;
}

#[tokio::test]
async fn handles_one_hundred_concurrent_queries() {
    let config = config_with_upstream(UpstreamBehavior::Valid).await;
    let running = start(&config, &[], QueryLog::disabled()).await;

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for id in 0..100u16 {
        let packet = common::build_query(id, "example.com.", RecordType::A);
        socket.send_to(&packet, running.addr).await.unwrap();
    }

    let mut answered = HashSet::new();
    let mut buffer = [0u8; 4096];
    for _ in 0..100 {
        let (len, _) = tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut buffer))
            .await
            .expect("all 100 replies should arrive")
            .unwrap();
        let reply = common::parse_response(&buffer[..len]);
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        answered.insert(reply.metadata.id);
    }
    assert_eq!(answered.len(), 100);

    running.stop().await;
}

#[tokio::test]
async fn in_flight_cap_drops_excess_packets() {
    let mut config = config_with_upstream(UpstreamBehavior::Silent).await;
    config.server.max_inflight = 1;
    config.server.timeout_ms = 500;
    let running = start(&config, &[], QueryLog::disabled()).await;

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for id in 0..100u16 {
        let packet = common::build_query(id, "example.com.", RecordType::A);
        socket.send_to(&packet, running.addr).await.unwrap();
    }

    // Only the query holding the sole permit is ever answered (with SERVFAIL
    // once the silent upstream times out); the other 99 are dropped.
    let deadline = Instant::now() + Duration::from_millis(800);
    let mut replies = 0_u32;
    let mut buffer = [0u8; 4096];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, socket.recv_from(&mut buffer)).await {
            Ok(Ok(_)) => replies += 1,
            _ => break,
        }
    }
    assert_eq!(replies, 1, "only one in-flight query should be answered");

    running.stop().await;
}

#[tokio::test]
async fn shutdown_flushes_the_query_log() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = config_with_upstream(UpstreamBehavior::Valid).await;
    config.storage.log_queries = true;
    config.storage.db_path = dir.path().join("queries.db");
    config.storage.flush_rows = 1;
    config.storage.flush_interval_ms = 20;

    let log = QueryLog::start(&config.storage).unwrap();
    let running = start(&config, &[], log).await;

    let packet = common::build_query(1, "example.com.", RecordType::A);
    let reply = ask(running.addr, &packet).await;
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);

    running.stop().await;

    let stats = Stats::open(&config.storage.db_path, 1_000).unwrap();
    assert_eq!(stats.total().unwrap(), 1);
    assert_eq!(
        stats.counts_by_action().unwrap(),
        vec![(Action::Forwarded, 1)]
    );
}

#[test]
fn bind_fails_when_the_port_is_in_use() {
    let occupied = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = occupied.local_addr().unwrap();

    let mut config = base_config();
    config.server.listen = addr.ip();
    config.server.port = addr.port();

    let Err(error) = Server::bind(&config, blocklists(&[]), QueryLog::disabled()) else {
        panic!("binding an occupied port must fail");
    };
    assert!(matches!(error, ServerError::Bind { .. }), "{error:?}");
}
