#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Integration tests for the per-query decision pipeline (ACL, policy
//! decisions, sinkholing, upstream forwarding, and query logging).
//!
//! Everything stays on loopback: the fake upstream is a local UDP socket.

mod common;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use arc_swap::ArcSwap;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use voidgate::blocklists::BlocklistStore;
use voidgate::config::{AclAction, AppConfig};
use voidgate::handler::{handle_query, AppState};
use voidgate::storage::{Action, QueryLog, Stats};

use common::UpstreamBehavior;

/// A client inside the default `127.0.0.0/8` ACL.
fn client() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 40_000))
}

/// Base config: one policy for loopback with an allow and a deny entry.
fn base_config() -> AppConfig {
    let yaml = r#"
server:
  allowed_clients: ["127.0.0.0/8"]
  timeout_ms: 500
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

/// Builds pipeline state with a hand-built blocklist store.
fn make_state(config: &AppConfig, entries: &[(&str, &[&str])]) -> AppState {
    let mut store = BlocklistStore::new();
    for (name, domains) in entries {
        store.insert(*name, domains.to_vec());
    }
    AppState::new(
        config,
        Arc::new(ArcSwap::from_pointee(store)),
        QueryLog::disabled(),
    )
}

/// Config pointing at a freshly spawned fake upstream.
async fn config_with_upstream(behavior: UpstreamBehavior) -> AppConfig {
    let upstream = common::spawn_udp_upstream(behavior).await;
    let mut config = base_config();
    config.server.upstream = upstream.ip();
    config.server.upstream_port = upstream.port();
    config
}

#[tokio::test]
async fn forwarded_query_returns_the_upstream_answer() {
    let config = config_with_upstream(UpstreamBehavior::Valid).await;
    let state = make_state(&config, &[]);

    let request = common::build_query(0x1234, "example.com.", RecordType::A);
    let bytes = handle_query(&state, client(), &request)
        .await
        .expect("forwarded query should get a reply");
    let reply = common::parse_response(&bytes);

    assert_eq!(reply.metadata.id, 0x1234);
    assert_eq!(reply.metadata.message_type, MessageType::Response);
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert!(reply.metadata.recursion_available);
    assert_eq!(reply.answers.len(), 1);
    assert_eq!(
        reply.answers[0].data,
        RData::A(Ipv4Addr::new(1, 2, 3, 4).into())
    );
}

#[tokio::test]
async fn blocked_a_query_is_sinkholed_to_zero() {
    let config = config_with_upstream(UpstreamBehavior::Valid).await;
    let state = make_state(&config, &[("ads", &["ads.example"])]);

    let request = common::build_query(0x0042, "ads.example.", RecordType::A);
    let bytes = handle_query(&state, client(), &request)
        .await
        .expect("blocked query should still get a reply");
    let reply = common::parse_response(&bytes);

    assert_eq!(reply.metadata.id, 0x0042);
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert_eq!(reply.answers.len(), 1);
    // The sinkhole address, not the upstream's 1.2.3.4: blocked names are
    // answered locally and never forwarded.
    assert_eq!(
        reply.answers[0].data,
        RData::A(Ipv4Addr::UNSPECIFIED.into())
    );
}

#[tokio::test]
async fn blocked_aaaa_query_is_sinkholed_to_ipv6_unspecified() {
    let config = config_with_upstream(UpstreamBehavior::Valid).await;
    let state = make_state(&config, &[("ads", &["ads.example"])]);

    let request = common::build_query(7, "ads.example.", RecordType::AAAA);
    let bytes = handle_query(&state, client(), &request).await.unwrap();
    let reply = common::parse_response(&bytes);

    assert_eq!(reply.answers.len(), 1);
    assert_eq!(
        reply.answers[0].data,
        RData::AAAA(Ipv6Addr::UNSPECIFIED.into())
    );
}

#[tokio::test]
async fn blocked_https_query_gets_empty_noerror() {
    let config = config_with_upstream(UpstreamBehavior::Valid).await;
    let state = make_state(&config, &[("ads", &["ads.example"])]);

    let request = common::build_query(9, "ads.example.", RecordType::HTTPS);
    let bytes = handle_query(&state, client(), &request).await.unwrap();
    let reply = common::parse_response(&bytes);

    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert!(reply.answers.is_empty());
}

#[tokio::test]
async fn blocked_mx_query_gets_empty_noerror() {
    let config = config_with_upstream(UpstreamBehavior::Valid).await;
    let state = make_state(&config, &[("ads", &["ads.example"])]);

    let request = common::build_query(11, "ads.example.", RecordType::MX);
    let bytes = handle_query(&state, client(), &request).await.unwrap();
    let reply = common::parse_response(&bytes);

    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert!(reply.answers.is_empty());
}

#[tokio::test]
async fn denylist_sinkholes_without_a_blocklist_hit() {
    let config = config_with_upstream(UpstreamBehavior::Valid).await;
    let state = make_state(&config, &[("ads", &["ads.example"])]);

    let request = common::build_query(5, "denied.example.", RecordType::A);
    let bytes = handle_query(&state, client(), &request).await.unwrap();
    let reply = common::parse_response(&bytes);

    assert_eq!(reply.answers.len(), 1);
    assert_eq!(
        reply.answers[0].data,
        RData::A(Ipv4Addr::UNSPECIFIED.into())
    );
}

#[tokio::test]
async fn allowlist_forwards_even_when_nothing_else_matches() {
    let config = config_with_upstream(UpstreamBehavior::Valid).await;
    let state = make_state(&config, &[("ads", &["ads.example"])]);

    let request = common::build_query(3, "allowed.example.", RecordType::A);
    let bytes = handle_query(&state, client(), &request).await.unwrap();
    let reply = common::parse_response(&bytes);

    assert_eq!(reply.answers.len(), 1);
    assert_eq!(
        reply.answers[0].data,
        RData::A(Ipv4Addr::new(1, 2, 3, 4).into())
    );
}

#[tokio::test]
async fn silent_upstream_becomes_servfail() {
    let config = config_with_upstream(UpstreamBehavior::Silent).await;
    let state = make_state(&config, &[]);

    let request = common::build_query(0xabcd, "example.com.", RecordType::A);
    let bytes = handle_query(&state, client(), &request).await.unwrap();
    let reply = common::parse_response(&bytes);

    assert_eq!(reply.metadata.id, 0xabcd);
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    assert!(reply.answers.is_empty());
}

#[tokio::test]
async fn wrong_id_then_valid_reply_is_accepted() {
    let config = config_with_upstream(UpstreamBehavior::BadThenGood).await;
    let state = make_state(&config, &[]);

    let request = common::build_query(0x1111, "example.com.", RecordType::A);
    let bytes = handle_query(&state, client(), &request).await.unwrap();
    let reply = common::parse_response(&bytes);

    // The spoofed first reply is discarded; the second is accepted.
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        reply.answers[0].data,
        RData::A(Ipv4Addr::new(1, 2, 3, 4).into())
    );
}

#[tokio::test]
async fn wrong_source_then_valid_reply_is_accepted() {
    let config = config_with_upstream(UpstreamBehavior::WrongSourceThenGood).await;
    let state = make_state(&config, &[]);

    let request = common::build_query(0x2222, "example.com.", RecordType::A);
    let bytes = handle_query(&state, client(), &request).await.unwrap();
    let reply = common::parse_response(&bytes);

    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        reply.answers[0].data,
        RData::A(Ipv4Addr::new(1, 2, 3, 4).into())
    );
}

#[tokio::test]
async fn garbage_reply_is_discarded_and_times_out() {
    let config = config_with_upstream(UpstreamBehavior::Garbage).await;
    let state = make_state(&config, &[]);

    let request = common::build_query(0x3333, "example.com.", RecordType::A);
    let bytes = handle_query(&state, client(), &request).await.unwrap();
    let reply = common::parse_response(&bytes);

    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
}

#[tokio::test]
async fn wrong_question_reply_is_discarded() {
    let config = config_with_upstream(UpstreamBehavior::WrongQuestion).await;
    let state = make_state(&config, &[]);

    let request = common::build_query(0x4444, "example.com.", RecordType::A);
    let bytes = handle_query(&state, client(), &request).await.unwrap();
    let reply = common::parse_response(&bytes);

    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
}

#[tokio::test]
async fn truncated_upstream_reply_is_passed_through() {
    let config = config_with_upstream(UpstreamBehavior::Truncated).await;
    let state = make_state(&config, &[]);

    let request = common::build_query(0x5555, "example.com.", RecordType::A);
    let bytes = handle_query(&state, client(), &request).await.unwrap();
    let reply = common::parse_response(&bytes);

    assert!(reply.metadata.truncation);
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
}

#[tokio::test]
async fn upstream_servfail_is_forwarded_unchanged() {
    let config = config_with_upstream(UpstreamBehavior::ServFail).await;
    let state = make_state(&config, &[]);

    let request = common::build_query(0x6666, "example.com.", RecordType::A);
    let bytes = handle_query(&state, client(), &request).await.unwrap();
    let reply = common::parse_response(&bytes);

    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
}

#[tokio::test]
async fn acl_refuse_answers_refused_without_decoding_the_rest() {
    let mut config = config_with_upstream(UpstreamBehavior::Valid).await;
    config.server.allowed_clients = vec!["10.0.0.0/8".parse().unwrap()];
    let state = make_state(&config, &[]);

    // Deliberately junk after the header: an ACL refusal only needs the ID.
    let mut request = vec![0x12, 0x34];
    request.extend_from_slice(&[0u8; 16]);

    let bytes = handle_query(&state, client(), &request)
        .await
        .expect("refused query should get a reply");
    let reply = common::parse_response(&bytes);

    assert_eq!(reply.metadata.id, 0x1234);
    assert_eq!(reply.metadata.response_code, ResponseCode::Refused);
}

#[tokio::test]
async fn acl_refuse_drops_packets_too_short_for_an_id() {
    let mut config = config_with_upstream(UpstreamBehavior::Valid).await;
    config.server.allowed_clients = vec!["10.0.0.0/8".parse().unwrap()];
    let state = make_state(&config, &[]);

    assert!(handle_query(&state, client(), &[0x12]).await.is_none());
}

#[tokio::test]
async fn acl_drop_is_silent() {
    let mut config = config_with_upstream(UpstreamBehavior::Valid).await;
    config.server.allowed_clients = vec!["10.0.0.0/8".parse().unwrap()];
    config.server.acl_action = AclAction::Drop;
    let state = make_state(&config, &[]);

    let request = common::build_query(1, "example.com.", RecordType::A);
    assert!(handle_query(&state, client(), &request).await.is_none());
}

#[tokio::test]
async fn non_query_opcode_gets_notimp() {
    let config = config_with_upstream(UpstreamBehavior::Valid).await;
    let state = make_state(&config, &[]);

    let mut message = Message::new(0x7777, MessageType::Query, OpCode::Status);
    message.add_query(Query::query(
        Name::from_ascii("example.com.").unwrap(),
        RecordType::A,
    ));
    let request = message.to_vec().unwrap();

    let bytes = handle_query(&state, client(), &request).await.unwrap();
    let reply = common::parse_response(&bytes);
    assert_eq!(reply.metadata.response_code, ResponseCode::NotImp);
}

#[tokio::test]
async fn zero_questions_get_formerr() {
    let config = config_with_upstream(UpstreamBehavior::Valid).await;
    let state = make_state(&config, &[]);

    let request = Message::new(0x8888, MessageType::Query, OpCode::Query)
        .to_vec()
        .unwrap();
    let bytes = handle_query(&state, client(), &request).await.unwrap();
    let reply = common::parse_response(&bytes);
    assert_eq!(reply.metadata.response_code, ResponseCode::FormErr);
}

#[tokio::test]
async fn multiple_questions_get_formerr() {
    let config = config_with_upstream(UpstreamBehavior::Valid).await;
    let state = make_state(&config, &[]);

    let mut message = Message::new(0x9999, MessageType::Query, OpCode::Query);
    message.add_query(Query::query(
        Name::from_ascii("a.example.").unwrap(),
        RecordType::A,
    ));
    message.add_query(Query::query(
        Name::from_ascii("b.example.").unwrap(),
        RecordType::A,
    ));
    let request = message.to_vec().unwrap();

    let bytes = handle_query(&state, client(), &request).await.unwrap();
    let reply = common::parse_response(&bytes);
    assert_eq!(reply.metadata.response_code, ResponseCode::FormErr);
}

#[tokio::test]
async fn non_in_class_is_refused() {
    let config = config_with_upstream(UpstreamBehavior::Valid).await;
    let state = make_state(&config, &[]);

    let mut question = Query::query(Name::from_ascii("example.com.").unwrap(), RecordType::A);
    question.set_query_class(DNSClass::CH);
    let mut message = Message::new(0xaaaa, MessageType::Query, OpCode::Query);
    message.add_query(question);
    let request = message.to_vec().unwrap();

    let bytes = handle_query(&state, client(), &request).await.unwrap();
    let reply = common::parse_response(&bytes);
    assert_eq!(reply.metadata.response_code, ResponseCode::Refused);
}

#[tokio::test]
async fn malformed_packet_is_dropped() {
    let config = config_with_upstream(UpstreamBehavior::Valid).await;
    let state = make_state(&config, &[]);

    assert!(handle_query(&state, client(), b"").await.is_none());
    assert!(handle_query(&state, client(), b"\x00\x01\x02")
        .await
        .is_none());
    assert!(
        handle_query(&state, client(), b"definitely not a dns packet")
            .await
            .is_none()
    );
}

#[tokio::test]
async fn handle_query_never_panics_on_odd_input() {
    let config = config_with_upstream(UpstreamBehavior::Valid).await;
    let state = make_state(&config, &[("ads", &["ads.example"])]);

    let mut inputs: Vec<Vec<u8>> = Vec::new();
    // Truncations of a valid query exercise every prefix length.
    let valid = common::build_query(1, "ads.example.", RecordType::A);
    for len in 0..valid.len() {
        inputs.push(valid[..len].to_vec());
    }
    // A deterministic slice of byte soup, including bogus headers.
    for seed in 0u32..64 {
        let mut bytes = Vec::with_capacity(32);
        let mut value = seed.wrapping_mul(2_654_435_761);
        for _ in 0..32 {
            value = value.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            bytes.push((value >> 16) as u8);
        }
        inputs.push(bytes);
    }

    for input in inputs {
        // Must not panic; either a reply or a silent drop is acceptable.
        let _ = handle_query(&state, client(), &input).await;
    }
}

#[tokio::test]
async fn actions_are_written_to_the_query_log() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = config_with_upstream(UpstreamBehavior::Valid).await;
    config.storage.log_queries = true;
    config.storage.db_path = dir.path().join("queries.db");
    config.storage.flush_rows = 1;
    config.storage.flush_interval_ms = 20;

    let log = QueryLog::start(&config.storage).unwrap();
    let mut store = BlocklistStore::new();
    store.insert("ads", ["ads.example"]);
    let state = AppState::new(&config, Arc::new(ArcSwap::from_pointee(store)), log.clone());

    // forwarded, blocked, and allowed, in that order.
    for (id, name) in [
        (1, "example.com."),
        (2, "ads.example."),
        (3, "allowed.example."),
    ] {
        let request = common::build_query(id, name, RecordType::A);
        assert!(handle_query(&state, client(), &request).await.is_some());
    }

    log.shutdown().unwrap();
    let stats = Stats::open(&config.storage.db_path, 1_000).unwrap();
    assert_eq!(stats.total(None).unwrap(), 3);
    assert_eq!(
        stats.counts_by_action(None).unwrap(),
        vec![
            (Action::Allowed, 1),
            (Action::Blocked, 1),
            (Action::Forwarded, 1),
        ]
    );
    assert_eq!(
        stats.top_blocked_domains(None, 5).unwrap(),
        vec![("ads.example".to_owned(), 1)]
    );
}

/// The client IP used in the logging test is a plain IPv4 address; make sure
/// the helpers agree on it.
#[test]
fn client_helper_is_ipv4_loopback() {
    assert_eq!(client().ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
}
