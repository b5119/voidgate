//! The per-query decision pipeline: one decoded packet in, one response out.
//!
//! Steps:
//! 1. enforce `server.allowed_clients` → `REFUSED` (or silence for
//!    `acl_action: drop`) **before** decoding; such queries are never logged,
//! 2. reject non-query opcodes (`NOTIMP`), zero/multiple questions
//!    (`FORMERR`), and non-`IN` classes (`REFUSED`) without forwarding,
//! 3. normalise the qname once (lowercase, strip trailing dot), resolve the
//!    client's policy (CIDR longest prefix),
//! 4. decide **allowlist > denylist > blocklist > forward**,
//! 5. synthesise sinkhole answers for blocked names — `A` → `0.0.0.0`,
//!    `AAAA` → `::`, **every other qtype (including HTTPS/SVCB, type 65) →
//!    NOERROR with an empty answer**; blocked names are never forwarded,
//! 6. forward allowed/unmatched names upstream under a concurrency permit, and
//!    log the action (`allowed` | `blocked` | `forwarded` | `servfail`) with
//!    upstream latency.
//!
//! Malformed packets are dropped; upstream failures and permit exhaustion
//! become SERVFAIL. Neither path may panic.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{DNSClass, RData, Record, RecordType};
use tokio::sync::Semaphore;

use crate::blocklists::BlocklistStore;
use crate::config::{AclAction, AppConfig, ServerConfig};
use crate::policy::{decide, Decision, PolicyEngine};
use crate::resolver::Resolver;
use crate::storage::{now_ms, Action, QueryLog, QueryRow};

/// Shared, cheaply cloneable state for the query pipeline.
///
/// The blocklist store sits behind an [`ArcSwap`] so the server can hot-swap
/// it on `SIGHUP`/refresh while queries are in flight.
#[derive(Clone)]
pub struct AppState {
    server: Arc<ServerConfig>,
    policies: Arc<PolicyEngine>,
    blocklists: Arc<ArcSwap<BlocklistStore>>,
    resolver: Arc<Resolver>,
    query_log: QueryLog,
    permits: Arc<Semaphore>,
}

impl AppState {
    /// Builds the pipeline state from a validated config, the current
    /// blocklist store (hot-swappable), and the query-log handle.
    #[must_use]
    pub fn new(
        config: &AppConfig,
        blocklists: Arc<ArcSwap<BlocklistStore>>,
        query_log: QueryLog,
    ) -> Self {
        let upstream = SocketAddr::new(config.server.upstream, config.server.upstream_port);
        let timeout = Duration::from_millis(config.server.timeout_ms);
        Self {
            server: Arc::new(config.server.clone()),
            policies: Arc::new(PolicyEngine::from_config(config)),
            blocklists,
            resolver: Arc::new(Resolver::new(upstream, timeout)),
            query_log,
            permits: Arc::new(Semaphore::new(config.server.max_concurrent_queries)),
        }
    }
}

/// Handles one received DNS message.
///
/// Returns the bytes to send back, or `None` to stay silent (dropped ACL
/// client, malformed packet, or a non-query message). Never panics: any
/// unexpected input becomes a silent drop or an error response.
pub async fn handle_query(state: &AppState, client: SocketAddr, request: &[u8]) -> Option<Vec<u8>> {
    if !state.server.client_allowed(&client.ip()) {
        return match state.server.acl_action {
            AclAction::Drop => None,
            AclAction::Refuse => refused_from_raw(request),
        };
    }

    let Ok(query) = Message::from_vec(request) else {
        tracing::warn!(%client, "dropping undecodable query");
        return None;
    };

    if query.metadata.message_type != MessageType::Query {
        tracing::debug!(%client, "dropping non-query message");
        return None;
    }
    if query.metadata.op_code != OpCode::Query {
        return error_response(&query, ResponseCode::NotImp);
    }
    if query.queries.len() != 1 {
        return error_response(&query, ResponseCode::FormErr);
    }
    let question = &query.queries[0];
    if question.query_class() != DNSClass::IN {
        return error_response(&query, ResponseCode::Refused);
    }

    let domain = normalize_name(question.name().to_lowercase().to_utf8());
    let client_ip = client.ip();
    let store = state.blocklists.load();
    let policy = state.policies.resolve(client_ip);

    match decide(policy, &domain, &store) {
        Decision::Blocked { .. } | Decision::Denied => {
            let reply = sinkhole_response(&query, state.server.sinkhole_ttl_secs);
            log_row(state, client_ip, &domain, Action::Blocked, None);
            to_bytes(reply)
        }
        Decision::Allowed => forward(state, client_ip, &domain, Action::Allowed, &query).await,
        Decision::Forward => forward(state, client_ip, &domain, Action::Forwarded, &query).await,
    }
}

/// Forwards `query` upstream under a permit, returning the reply or SERVFAIL.
async fn forward(
    state: &AppState,
    client_ip: IpAddr,
    domain: &str,
    action: Action,
    query: &Message,
) -> Option<Vec<u8>> {
    let Ok(_permit) = state.permits.try_acquire() else {
        tracing::warn!(%client_ip, "in-flight query limit reached; answering SERVFAIL");
        log_row(state, client_ip, domain, Action::Servfail, None);
        return error_response(query, ResponseCode::ServFail);
    };

    let started = Instant::now();
    match state.resolver.forward(query).await {
        Ok(reply) => {
            log_row(state, client_ip, domain, action, Some(elapsed_ms(started)));
            to_bytes(reply)
        }
        Err(error) => {
            tracing::warn!(
                %client_ip,
                domain,
                %error,
                "upstream lookup failed; answering SERVFAIL"
            );
            log_row(state, client_ip, domain, Action::Servfail, None);
            error_response(query, ResponseCode::ServFail)
        }
    }
}

/// Records one query-log row (a no-op when `storage.log_queries` is false).
fn log_row(
    state: &AppState,
    client_ip: IpAddr,
    domain: &str,
    action: Action,
    upstream_latency_ms: Option<u32>,
) {
    state.query_log.log(QueryRow {
        ts_ms: now_ms(),
        client_ip,
        domain: domain.to_owned(),
        action,
        upstream_latency_ms,
    });
}

/// Normalises a decoded qname once: lowercase and no trailing dot.
fn normalize_name(name: String) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// Builds a response skeleton that echoes the query's ID, opcode, RD and CD
/// bits, advertises recursion, and carries the question section.
fn base_response(query: &Message) -> Message {
    let mut reply = Message::new(
        query.metadata.id,
        MessageType::Response,
        query.metadata.op_code,
    );
    reply.metadata.recursion_desired = query.metadata.recursion_desired;
    reply.metadata.checking_disabled = query.metadata.checking_disabled;
    reply.metadata.recursion_available = true;
    reply.queries = query.queries.clone();
    reply
}

/// A base response carrying `code`, serialised for the wire.
fn error_response(query: &Message, code: ResponseCode) -> Option<Vec<u8>> {
    let mut reply = base_response(query);
    reply.metadata.response_code = code;
    to_bytes(reply)
}

/// A `NOERROR` response for a blocked name: `0.0.0.0` for `A`, `::` for
/// `AAAA`, and an empty answer for everything else (HTTPS/SVCB included).
fn sinkhole_response(query: &Message, ttl: u32) -> Message {
    let mut reply = base_response(query);
    let question = &query.queries[0];
    let name = question.name().clone();
    match question.query_type() {
        RecordType::A => {
            reply.add_answer(Record::from_rdata(
                name,
                ttl,
                RData::A(Ipv4Addr::UNSPECIFIED.into()),
            ));
        }
        RecordType::AAAA => {
            reply.add_answer(Record::from_rdata(
                name,
                ttl,
                RData::AAAA(Ipv6Addr::UNSPECIFIED.into()),
            ));
        }
        _ => {}
    }
    reply
}

/// Builds a `REFUSED` reply from a raw packet without decoding it.
///
/// Only the header is read (ID, opcode, RD): an ACL-rejected client gets its
/// answer even when the rest of the packet is junk. Returns `None` for a
/// packet too short to carry an ID.
fn refused_from_raw(request: &[u8]) -> Option<Vec<u8>> {
    let first = request.first().copied()?;
    let second = request.get(1).copied()?;
    let id = u16::from_be_bytes([first, second]);
    let flags = request.get(2).copied().unwrap_or(0);
    let op_code = OpCode::from_u8((flags & 0b0111_1000) >> 3);

    let mut reply = Message::new(id, MessageType::Response, op_code);
    reply.metadata.recursion_desired = flags & 0b0000_0001 != 0;
    reply.metadata.recursion_available = true;
    reply.metadata.response_code = ResponseCode::Refused;
    to_bytes(reply)
}

/// Serialises a response, returning `None` rather than panicking on failure.
fn to_bytes(message: Message) -> Option<Vec<u8>> {
    message.to_vec().ok()
}

/// Whole milliseconds elapsed, saturating at [`u32::MAX`].
fn elapsed_ms(started: Instant) -> u32 {
    u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX)
}
