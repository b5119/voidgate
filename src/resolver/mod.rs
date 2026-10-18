//! Upstream resolution: forwarding queries to the configured recursive
//! resolver.
//!
//! Contract:
//! - one **ephemeral UDP socket per query** (OS-assigned source port),
//! - the query ID is rewritten to a fresh random value on the wire and
//!   restored on the reply,
//! - replies validated for **source address**, **transaction ID**, and
//!   **question section** before being accepted; a datagram that fails any
//!   check is discarded and we keep waiting,
//! - per-query timeout from `server.timeout_ms`, surfaced as
//!   [`ResolverError::Timeout`] — never a panic.
//!
//! In-flight concurrency is capped by the listener's `tokio::sync::Semaphore`
//! (`server.max_inflight`), not here.

pub mod error;

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use hickory_proto::op::Message;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use error::ResolverError;

/// Largest DNS message on the wire: the protocol's 16-bit length field, plus
/// TCP's two length octets. A protocol bound, not a tunable.
const MAX_MESSAGE_BYTES: usize = 65_537;

/// Forwards queries to a single configured upstream resolver over UDP.
#[derive(Debug, Clone)]
pub struct Resolver {
    upstream: SocketAddr,
    timeout: Duration,
}

impl Resolver {
    /// Creates a resolver that sends to `upstream` and waits up to `timeout`.
    #[must_use]
    pub fn new(upstream: SocketAddr, timeout: Duration) -> Self {
        Self { upstream, timeout }
    }

    /// The upstream address every query is sent to.
    #[must_use]
    pub fn upstream(&self) -> SocketAddr {
        self.upstream
    }

    /// Sends `query` upstream and returns the validated reply.
    ///
    /// The query's transaction ID is rewritten to a fresh random value for the
    /// wire and restored on the returned reply, so a client cannot correlate
    /// (or poison) our upstream traffic. Replies from any other source, with a
    /// wrong ID, or with a mismatched question are logged and discarded while
    /// time remains — the off-path spoofing defence — and only a reply that
    /// passes all three checks is returned. A truncated (`TC`) reply is passed
    /// through unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`ResolverError::Timeout`] when no valid reply arrives within
    /// the configured timeout, [`ResolverError::Io`] for socket failures, and
    /// [`ResolverError::MalformedReply`] when the query cannot be serialised.
    ///
    /// # Panics
    ///
    /// Never.
    pub async fn forward(&self, query: &Message) -> Result<Message, ResolverError> {
        let bind = match self.upstream {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        };
        let socket = UdpSocket::bind(bind)
            .await
            .map_err(|source| ResolverError::Io { source })?;

        let mut outgoing = query.clone();
        outgoing.metadata.id = rand::random();
        let sent_id = outgoing.metadata.id;
        let request = outgoing
            .to_vec()
            .map_err(|_| ResolverError::MalformedReply)?;

        socket
            .send_to(&request, self.upstream)
            .await
            .map_err(|source| ResolverError::Io { source })?;

        let deadline = Instant::now() + self.timeout;
        let mut buffer = vec![0u8; MAX_MESSAGE_BYTES];
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err(ResolverError::Timeout);
            }
            let remaining = deadline - now;
            let (len, from) = match timeout(remaining, socket.recv_from(&mut buffer)).await {
                Ok(Ok(received)) => received,
                Ok(Err(source)) => return Err(ResolverError::Io { source }),
                Err(_) => return Err(ResolverError::Timeout),
            };

            match validate(&buffer[..len], from, self.upstream, sent_id, query) {
                Ok(mut reply) => {
                    reply.metadata.id = query.metadata.id;
                    return Ok(reply);
                }
                Err(error) => {
                    tracing::debug!(%from, %error, "discarding upstream datagram");
                }
            }
        }
    }
}

/// Validates one datagram against the query we sent.
///
/// The three checks (source, ID, question) together are what stop an off-path
/// attacker from injecting an answer on our ephemeral port.
fn validate(
    datagram: &[u8],
    from: SocketAddr,
    expected: SocketAddr,
    sent_id: u16,
    query: &Message,
) -> Result<Message, ResolverError> {
    if from != expected {
        return Err(ResolverError::WrongSource);
    }
    let reply = Message::from_vec(datagram).map_err(|_| ResolverError::MalformedReply)?;
    if reply.metadata.id != sent_id {
        return Err(ResolverError::IdMismatch);
    }
    if reply.queries != query.queries {
        return Err(ResolverError::QuestionMismatch);
    }
    Ok(reply)
}
