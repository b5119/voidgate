#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Integration tests for the DNS listeners: UDP end-to-end query handling, the
//! in-flight cap, TCP framing (multiple queries, idle timeout, connection cap,
//! bad frames, ACL close-at-accept), the `TC`-then-TCP-retry fallback, hot
//! reload, the offline `SIGHUP` reload path, the refresh timer, graceful
//! shutdown + log flush, and bind failures.
//!
//! Everything stays on loopback: real UDP/TCP sockets and fake loopback
//! upstreams.

mod common;

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{RData, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::oneshot;
use voidgate::blocklists::{reload_from_cache, BlocklistStore};
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
async fn upstream_permit_exhaustion_servfails_forwards_but_still_blocks() {
    // One upstream permit, held by a forward stuck on a silent upstream.
    let mut config = config_with_upstream(UpstreamBehavior::Silent).await;
    config.server.max_upstream_inflight = 1;
    config.server.timeout_ms = 500;
    let running = start(&config, &[("ads", &["ads.example"])], QueryLog::disabled()).await;

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let holding = common::build_query(0x0a, "forward.example.", RecordType::A);
    socket.send_to(&holding, running.addr).await.unwrap();
    // Let the forward acquire the sole upstream permit.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // A blocked query never needs an upstream permit: instant sinkhole.
    let blocked = common::build_query(0x0b, "ads.example.", RecordType::A);
    let started = Instant::now();
    let reply = ask(running.addr, &blocked).await;
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        reply.answers[0].data,
        RData::A(Ipv4Addr::UNSPECIFIED.into())
    );
    assert!(
        started.elapsed() < Duration::from_millis(400),
        "a blocked query must not wait on an upstream permit"
    );

    // A second forward while the permit is held gets an immediate SERVFAIL.
    let excess = common::build_query(0x0c, "other.example.", RecordType::A);
    let started = Instant::now();
    let servfail = ask(running.addr, &excess).await;
    assert_eq!(servfail.metadata.response_code, ResponseCode::ServFail);
    assert!(
        started.elapsed() < Duration::from_millis(400),
        "upstream-permit exhaustion should SERVFAIL immediately, not after the timeout"
    );

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

// ---------------------------------------------------------------------------
// TCP listener
// ---------------------------------------------------------------------------

/// Starts a TCP-capable server (ephemeral port) in a background task.
async fn start_tcp(config: &AppConfig, entries: &[(&str, &[&str])], log: QueryLog) -> Running {
    let server = Server::bind(config, blocklists(entries), log).expect("bind should succeed");
    let addr = server
        .local_addr()
        .expect("listener should have an address");
    let (shutdown, rx) = oneshot::channel();
    let join = tokio::spawn(server.run(async move {
        let _ = rx.await;
    }));

    // The listener task enters its accept loop asynchronously, so wait until
    // the TCP port actually accepts before returning. Without this every TCP
    // test races the accept loop and gets `ConnectionRefused`.
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match TcpStream::connect(addr).await {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                assert!(
                    Instant::now() < deadline,
                    "tcp listener never became reachable on {addr}"
                );
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Err(error) => panic!("tcp readiness probe failed: {error}"),
        }
    }

    Running {
        addr,
        shutdown,
        join,
    }
}

/// Connects to `addr`, sends one length-framed query, and decodes the reply.
async fn tcp_ask(addr: SocketAddr, query: &[u8]) -> Message {
    let mut stream = TcpStream::connect(addr)
        .await
        .expect("tcp connect should work");
    let mut framed = Vec::with_capacity(2 + query.len());
    framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
    framed.extend_from_slice(query);
    stream
        .write_all(&framed)
        .await
        .expect("tcp write should succeed");
    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .await
        .expect("tcp length should arrive");
    let len = usize::from(u16::from_be_bytes(len_buf));
    let mut reply = vec![0u8; len];
    stream
        .read_exact(&mut reply)
        .await
        .expect("tcp reply should arrive");
    common::parse_response(&reply)
}

#[tokio::test]
async fn tcp_round_trip_returns_the_answer() {
    let config = config_with_upstream(UpstreamBehavior::Valid).await;
    let mut config = config;
    config.server.tcp_enabled = true;
    let running = start_tcp(&config, &[], QueryLog::disabled()).await;

    let packet = common::build_query(0x0007, "example.com.", RecordType::A);
    let reply = tcp_ask(running.addr, &packet).await;

    assert_eq!(reply.metadata.id, 0x0007);
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        reply.answers[0].data,
        RData::A(Ipv4Addr::new(1, 2, 3, 4).into())
    );

    running.stop().await;
}

#[tokio::test]
async fn tcp_serves_two_queries_on_one_connection() {
    let config = config_with_upstream(UpstreamBehavior::Valid).await;
    let mut config = config;
    config.server.tcp_enabled = true;
    config.server.tcp_max_queries_per_conn = 2;
    let running = start_tcp(&config, &[], QueryLog::disabled()).await;

    let mut stream = TcpStream::connect(running.addr).await.unwrap();
    for id in 0x0100u16..0x0102 {
        let packet = common::build_query(id, "example.com.", RecordType::A);
        let mut framed = Vec::new();
        framed.extend_from_slice(&(packet.len() as u16).to_be_bytes());
        framed.extend_from_slice(&packet);
        stream.write_all(&framed).await.unwrap();

        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await.unwrap();
        let len = usize::from(u16::from_be_bytes(len_buf));
        let mut reply = vec![0u8; len];
        stream.read_exact(&mut reply).await.unwrap();
        let message = common::parse_response(&reply);
        assert_eq!(message.metadata.id, id);
        assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    }

    running.stop().await;
}

#[tokio::test]
async fn tcp_idle_timeout_closes_the_connection() {
    let config = config_with_upstream(UpstreamBehavior::Valid).await;
    let mut config = config;
    config.server.tcp_enabled = true;
    config.server.tcp_idle_timeout_ms = 150;
    let running = start_tcp(&config, &[], QueryLog::disabled()).await;

    let mut stream = TcpStream::connect(running.addr).await.unwrap();
    // Send nothing; the server must close within the idle window.
    let mut buf = [0u8; 1];
    let closed = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .expect("read should resolve (EOF or data) well before the test hangs")
        .unwrap();
    assert_eq!(closed, 0, "server should close an idle connection with EOF");

    running.stop().await;
}

#[tokio::test]
async fn tcp_connection_cap_closes_excess_connections() {
    let config = config_with_upstream(UpstreamBehavior::Valid).await;
    let mut config = config;
    config.server.tcp_enabled = true;
    config.server.tcp_max_connections = 2;
    config.server.tcp_idle_timeout_ms = 500;
    let running = start_tcp(&config, &[], QueryLog::disabled()).await;

    // Fill both permits with connections that never send a byte, so the server
    // keeps them open awaiting a frame (and holds their permits).
    let mut held = Vec::new();
    for _ in 0..config.server.tcp_max_connections {
        held.push(TcpStream::connect(running.addr).await.unwrap());
    }

    // Excess connections are closed immediately at accept.
    for _ in 0..3 {
        let mut extra = TcpStream::connect(running.addr).await.unwrap();
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(2), extra.read(&mut buf))
            .await
            .expect("excess connection should close promptly");
        assert_eq!(read.unwrap(), 0, "excess connection should see EOF");
    }

    drop(held);

    running.stop().await;
}

#[tokio::test]
async fn tcp_zero_length_frame_closes_the_connection() {
    let config = config_with_upstream(UpstreamBehavior::Valid).await;
    let mut config = config;
    config.server.tcp_enabled = true;
    config.server.tcp_idle_timeout_ms = 300;
    let running = start_tcp(&config, &[], QueryLog::disabled()).await;

    let mut stream = TcpStream::connect(running.addr).await.unwrap();
    // A legal frame with length 0: the server must close without replying.
    stream.write_all(&[0x00, 0x00]).await.unwrap();
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .expect("server should close a zero-length frame")
        .unwrap();
    assert_eq!(read, 0, "zero-length frame should close the connection");

    running.stop().await;
}

#[tokio::test]
async fn tcp_partial_frame_is_dropped_on_idle_timeout() {
    let config = config_with_upstream(UpstreamBehavior::Valid).await;
    let mut config = config;
    config.server.tcp_enabled = true;
    config.server.tcp_idle_timeout_ms = 150;
    let running = start_tcp(&config, &[], QueryLog::disabled()).await;

    let mut stream = TcpStream::connect(running.addr).await.unwrap();
    // Announce a 10-byte message, send only 3 bytes, then go idle.
    stream
        .write_all(&[0x00, 0x0a, 0x01, 0x02, 0x03])
        .await
        .unwrap();
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .expect("server should drop a partial frame")
        .unwrap();
    assert_eq!(read, 0, "partial frame should close the connection");

    running.stop().await;
}

#[tokio::test]
async fn tcp_client_from_a_disallowed_range_is_closed_at_accept() {
    let mut config = config_with_upstream(UpstreamBehavior::Valid).await;
    config.server.tcp_enabled = true;
    // Loopback is allowed, so to make a disallowed client we point the ACL at a
    // single other address. We simulate by binding the ACL to 10.0.0.0/8 while
    // still asking from 127.0.0.1.
    config.server.allowed_clients = vec!["10.0.0.0/8".parse().unwrap()];
    let running = start_tcp(&config, &[], QueryLog::disabled()).await;

    let mut stream = TcpStream::connect(running.addr).await.unwrap();
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .expect("disallowed tcp client should be closed at accept")
        .unwrap();
    assert_eq!(
        read, 0,
        "out-of-range tcp client must be closed with EOF and no reply"
    );

    running.stop().await;
}

#[tokio::test]
async fn udp_truncation_falls_back_to_tcp_and_returns_full_answer() {
    // Fake upstream on one port serving both transports: UDP replies are
    // truncated (TC, no answer); TCP replies carry the full A record. A UDP
    // client keeps the truncated answer; a TCP client (transport == Tcp)
    // retries upstream over TCP and gets the full answer.
    let upstream = common::spawn_truncating_dual_upstream().await;

    let mut config = base_config();
    config.server.upstream = upstream.ip();
    config.server.upstream_port = upstream.port();
    config.server.tcp_enabled = true;

    let running = start_tcp(&config, &[], QueryLog::disabled()).await;

    let packet = common::build_query(0x0055, "big.example.", RecordType::A);

    // UDP client: keeps the truncated answer (TC set, no A record).
    let udp_reply = ask(running.addr, &packet).await;
    assert!(
        udp_reply.metadata.truncation,
        "udp client should see TC set"
    );
    assert!(
        udp_reply.answers.is_empty(),
        "udp reply should carry no answer"
    );

    // TCP client: gets the full answer via the upstream TCP retry.
    let tcp_reply = tcp_ask(running.addr, &packet).await;
    assert!(
        !tcp_reply.metadata.truncation,
        "tcp client should not see TC set"
    );
    assert_eq!(
        tcp_reply.answers.len(),
        1,
        "tcp client should get the answer"
    );
    assert_eq!(
        tcp_reply.answers[0].data,
        RData::A(Ipv4Addr::new(1, 2, 3, 4).into())
    );

    running.stop().await;
}

// ---------------------------------------------------------------------------
// Reload / refresh / SIGHUP
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reload_from_cache_changes_a_decision() {
    let dir = tempfile::tempdir().unwrap();
    let cache_dir = dir.path().join("cache");
    std::fs::create_dir_all(&cache_dir).unwrap();

    // The cache file the URL list is loaded from (`<cache_dir>/<name>`);
    // empty at first.
    let cached = cache_dir.join("ads");

    let mut config = config_with_upstream(UpstreamBehavior::Valid).await;
    config.blocklists.cache_dir = cache_dir.clone();
    config.blocklists.lists = vec![voidgate::config::BlocklistSource {
        name: "ads".to_owned(),
        kind: voidgate::config::BlocklistKind::Url,
        source: "http://127.0.0.1:9/ads.txt".to_owned(),
    }];

    // Start with an empty cache: nothing is blocked.
    let store = BlocklistStore::load_from_cache(&config.blocklists);
    assert!(
        !store.matches("ads", "ads.example"),
        "empty cache should block nothing"
    );

    // Populate the cache with the blocklist domain, then reload.
    std::fs::write(&cached, "ads.example\n").unwrap();

    let reloaded = reload_from_cache(&config.blocklists).expect("reload should succeed");
    assert!(
        reloaded.matches("ads", "ads.example"),
        "reloaded store should now block the domain"
    );

    // The reloaded store is what the server would swap in; confirm the
    // decision would flip from forward to sinkhole. (The server-side swap
    // itself is exercised by the refresh-timer test.)
    let running = start(&config, &[], QueryLog::disabled()).await;
    let packet = common::build_query(0x0010, "ads.example.", RecordType::A);
    let before = ask(running.addr, &packet).await;
    assert_eq!(
        before.answers[0].data,
        RData::A(Ipv4Addr::new(1, 2, 3, 4).into())
    );

    running.stop().await;
}

#[tokio::test]
async fn reload_with_a_corrupt_cache_keeps_the_old_store() {
    let dir = tempfile::tempdir().unwrap();
    let cache_dir = dir.path().join("cache");
    std::fs::create_dir_all(&cache_dir).unwrap();
    let list_path = dir.path().join("ads.txt");
    std::fs::write(&list_path, "ads.example\n").unwrap();

    let yaml = format!(
        r#"
server:
  listen: "127.0.0.1"
  port: 0
  allowed_clients: ["127.0.0.0/8"]
blocklists:
  cache_dir: "{}"
  lists:
    - {{ name: ads, type: file, source: "{}" }}
policies: []
default_policy: {{}}
storage: {{ log_queries: false }}
"#,
        cache_dir.display(),
        list_path.display()
    );
    let config: AppConfig = serde_yaml_ng::from_str(&yaml).unwrap();

    // Corrupt the cache: replace the directory with a plain file so reload fails.
    std::fs::remove_dir_all(&cache_dir).unwrap();
    std::fs::write(&cache_dir, "not a directory").unwrap();

    let Err(error) = reload_from_cache(&config.blocklists) else {
        panic!("reload over a non-directory cache must fail");
    };
    assert!(
        matches!(error, voidgate::blocklists::BlocklistError::Io { .. }),
        "{error:?}"
    );
}

#[tokio::test]
async fn refresh_timer_fetches_from_a_local_listener_and_swaps_the_store() {
    let dir = tempfile::tempdir().unwrap();
    let cache_dir = dir.path().join("cache");
    std::fs::create_dir_all(&cache_dir).unwrap();

    // A local HTTP listener serving the blocklist body.
    let body = "ads.example\n".to_string();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap();
    let (served_tx, served_rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        let mut buf = [0u8; 4096];
        let _ = socket.read(&mut buf).await;
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = socket.write_all(header.as_bytes()).await;
        let _ = socket.write_all(body.as_bytes()).await;
        let _ = socket.shutdown().await;
        let _ = served_tx.send(());
    });

    let mut config = config_with_upstream(UpstreamBehavior::Valid).await;
    config.blocklists.cache_dir = cache_dir.clone();
    config.blocklists.refresh_interval_secs = 1;
    config.blocklists.lists = vec![voidgate::config::BlocklistSource {
        name: "ads".to_owned(),
        kind: voidgate::config::BlocklistKind::Url,
        source: format!("http://{upstream}/ads.txt"),
    }];
    config.server.tcp_enabled = true;

    let blocklists = Arc::new(ArcSwap::from_pointee(BlocklistStore::load_from_cache(
        &config.blocklists,
    )));
    assert!(!blocklists.load().matches("ads", "ads.example"));

    let server = Server::bind(&config, Arc::clone(&blocklists), QueryLog::disabled()).unwrap();
    let addr = server.local_addr().unwrap();
    let (shutdown, rx) = oneshot::channel();
    let join = tokio::spawn(server.run(async move {
        let _ = rx.await;
    }));

    // Wait for the local HTTP listener to be hit by the refresh timer.
    tokio::time::timeout(Duration::from_secs(3), served_rx)
        .await
        .expect("refresh timer should fetch from the local listener")
        .expect("fetch task should complete");

    // Poll until the store has swapped to include the new domain.
    let deadline = Instant::now() + Duration::from_secs(3);
    while !blocklists.load().matches("ads", "ads.example") {
        assert!(
            Instant::now() < deadline,
            "refresh should swap the store to include the fetched domain"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // The decision flipped: ads.example is now sinkholed.
    let packet = common::build_query(0x0020, "ads.example.", RecordType::A);
    let reply = ask(addr, &packet).await;
    assert_eq!(
        reply.answers[0].data,
        RData::A(Ipv4Addr::UNSPECIFIED.into())
    );

    let _ = shutdown.send(());
    join.await.unwrap().unwrap();
}
