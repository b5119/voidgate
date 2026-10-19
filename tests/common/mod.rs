#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(dead_code)] // shared across test binaries; each binary uses a subset
//! Shared fixtures for voidgate integration tests.

use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

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

/// How a fake UDP upstream answers (or fails to answer) each query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamBehavior {
    /// Well-formed reply echoing the question with an `A 1.2.3.4` answer.
    Valid,
    /// Receive the query and never reply: forces a resolver timeout.
    Silent,
    /// Reply with bytes that are not a DNS message.
    Garbage,
    /// Reply with a valid message but a mismatched transaction ID.
    WrongId,
    /// Reply with a valid message but a different question section.
    WrongQuestion,
    /// Reply with `SERVFAIL`.
    ServFail,
    /// Reply with a valid message whose `TC` bit is set. A TCP client that
    /// retried would still receive only this truncated UDP answer from a
    /// UDP-only fake upstream (no TCP listener is started).
    Truncated,
    /// Send a wrong-ID reply, then the correct one.
    BadThenGood,
    /// Send a good reply from a *different* socket (wrong source), then the
    /// correct one from the real upstream.
    WrongSourceThenGood,
}

/// Starts a one-shot-per-query fake UDP upstream on an ephemeral loopback port.
///
/// Never touches the real network: everything stays on `127.0.0.1`.
pub async fn spawn_udp_upstream(behavior: UpstreamBehavior) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("fake upstream should bind");
    let addr = socket
        .local_addr()
        .expect("bound upstream should have an address");
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 65_537];
        loop {
            let Ok((len, from)) = socket.recv_from(&mut buffer).await else {
                return;
            };
            let request = &buffer[..len];
            match behavior {
                UpstreamBehavior::Silent => {}
                UpstreamBehavior::Garbage => {
                    let _ = socket.send_to(b"this is not a dns message", from).await;
                }
                UpstreamBehavior::BadThenGood => {
                    let query = Message::from_vec(request).expect("valid query");
                    let mut bad = valid_reply(&query);
                    bad.metadata.id = query.metadata.id.wrapping_add(1);
                    let _ = socket
                        .send_to(&bad.to_vec().expect("serialize"), from)
                        .await;
                    let _ = socket
                        .send_to(&valid_reply(&query).to_vec().expect("serialize"), from)
                        .await;
                }
                UpstreamBehavior::WrongSourceThenGood => {
                    let query = Message::from_vec(request).expect("valid query");
                    let stray = UdpSocket::bind("127.0.0.1:0")
                        .await
                        .expect("stray socket should bind");
                    let _ = stray
                        .send_to(&valid_reply(&query).to_vec().expect("serialize"), from)
                        .await;
                    let _ = socket
                        .send_to(&valid_reply(&query).to_vec().expect("serialize"), from)
                        .await;
                }
                other => {
                    let query = Message::from_vec(request).expect("valid query");
                    if let Some(bytes) = reply_for(&query, other) {
                        let _ = socket.send_to(&bytes, from).await;
                    }
                }
            }
        }
    });
    addr
}

/// Serialises the reply `behavior` sends for `query`, if it sends one.
fn reply_for(query: &Message, behavior: UpstreamBehavior) -> Option<Vec<u8>> {
    let reply = match behavior {
        UpstreamBehavior::Valid => valid_reply(query),
        UpstreamBehavior::WrongId => {
            let mut reply = valid_reply(query);
            reply.metadata.id = query.metadata.id.wrapping_add(1);
            reply
        }
        UpstreamBehavior::WrongQuestion => {
            let mut reply = valid_reply(query);
            let name = Name::from_ascii("wrong.example.").expect("name should parse");
            reply.queries = vec![Query::query(name, RecordType::A)];
            reply
        }
        UpstreamBehavior::ServFail => {
            let mut reply =
                Message::error_msg(query.metadata.id, OpCode::Query, ResponseCode::ServFail);
            reply.queries = query.queries.clone();
            reply
        }
        UpstreamBehavior::Truncated => {
            let mut reply = valid_reply(query);
            reply.metadata.truncation = true;
            reply.answers.clear();
            reply
        }
        UpstreamBehavior::Silent
        | UpstreamBehavior::Garbage
        | UpstreamBehavior::BadThenGood
        | UpstreamBehavior::WrongSourceThenGood => return None,
    };
    Some(reply.to_vec().expect("reply should serialize"))
}

/// A `NOERROR` reply echoing the question; `A` queries get `1.2.3.4`.
fn valid_reply(query: &Message) -> Message {
    let mut reply = Message::response(query.metadata.id, OpCode::Query);
    reply.queries = query.queries.clone();
    reply.metadata.recursion_available = true;
    if let Some(question) = query.queries.first() {
        if question.query_type() == RecordType::A {
            reply.add_answer(Record::from_rdata(
                question.name().clone(),
                30,
                RData::A(Ipv4Addr::new(1, 2, 3, 4).into()),
            ));
        }
    }
    reply
}

/// Builds a standard recursive query packet (RD set) for tests.
pub fn build_query(id: u16, name: &str, query_type: RecordType) -> Vec<u8> {
    let name = Name::from_ascii(name).expect("test name should parse");
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name, query_type));
    message.to_vec().expect("query should serialize")
}

/// Decodes a response packet produced by the handler.
pub fn parse_response(bytes: &[u8]) -> Message {
    Message::from_vec(bytes).expect("response should decode")
}

/// Starts a fake upstream serving both UDP and TCP on **one** port.
///
/// The resolver uses a single `upstream:upstream_port` for both transports, so
/// a `TC`-then-TCP-retry test needs one listener reachable over both. UDP
/// replies are truncated (TC set, no answer); TCP replies are full `A 1.2.3.4`
/// answers. Never touches the real network: `127.0.0.1` only.
pub async fn spawn_truncating_dual_upstream() -> SocketAddr {
    let udp = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("udp upstream should bind");
    let addr = udp
        .local_addr()
        .expect("udp upstream should have an address");

    let tcp = TcpListener::bind(addr)
        .await
        .expect("tcp upstream should bind the same port");

    tokio::spawn(async move {
        let mut buffer = vec![0u8; 65_537];
        loop {
            let Ok((len, from)) = udp.recv_from(&mut buffer).await else {
                return;
            };
            let Ok(query) = Message::from_vec(&buffer[..len]) else {
                continue;
            };
            let mut truncated = Message::response(query.metadata.id, OpCode::Query);
            truncated.queries = query.queries.clone();
            truncated.metadata.truncation = true;
            let bytes = truncated
                .to_vec()
                .expect("truncated reply should serialize");
            let _ = udp.send_to(&bytes, from).await;
        }
    });

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = tcp.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut len_buf = [0u8; 2];
                while stream.read_exact(&mut len_buf).await.is_ok() {
                    let len = usize::from(u16::from_be_bytes(len_buf));
                    let mut message = vec![0u8; len];
                    if stream.read_exact(&mut message).await.is_err() {
                        return;
                    }
                    let Ok(query) = Message::from_vec(&message) else {
                        return;
                    };
                    let reply = valid_reply(&query);
                    let bytes = reply.to_vec().expect("reply should serialize");
                    let mut framed = Vec::with_capacity(2 + bytes.len());
                    framed.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                    framed.extend_from_slice(&bytes);
                    if stream.write_all(&framed).await.is_err() {
                        return;
                    }
                }
            });
        }
    });

    addr
}
