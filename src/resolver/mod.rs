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
//!   [`ResolverError::Timeout`] — never a panic,
//! - for a **TCP client** whose upstream UDP answer is truncated (`TC` set),
//!   the same query is retried over upstream TCP (2-byte length framing) and
//!   the full answer returned; a UDP client keeps the truncated answer.
//!
//! In-flight concurrency is capped by the resolver-level
//! `tokio::sync::Semaphore` (`server.max_upstream_inflight`) in the handler,
//! not here.

pub mod error;

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use hickory_proto::op::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use error::ResolverError;

/// Largest DNS message on the wire: the protocol's 16-bit length field, plus
/// TCP's two length octets. A protocol bound, not a tunable.
const MAX_MESSAGE_BYTES: usize = 65_537;

/// The transport the client used to reach us.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Plain UDP query: truncated answers are passed through as-is.
    Udp,
    /// TCP query: a truncated upstream answer is retried over upstream TCP.
    Tcp,
}

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
    /// through unchanged for a [`Transport::Udp`] client; for a
    /// [`Transport::Tcp`] client it is retried over upstream TCP within the
    /// same overall deadline and the full answer is returned.
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
    pub async fn forward(
        &self,
        query: &Message,
        transport: Transport,
    ) -> Result<Message, ResolverError> {
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
                    if reply.metadata.truncation && transport == Transport::Tcp {
                        // Truncated answer for a TCP client: retry over TCP
                        // within the same overall deadline.
                        return self.forward_tcp(query, deadline).await;
                    }
                    return Ok(reply);
                }
                Err(error) => {
                    tracing::debug!(%from, %error, "discarding upstream datagram");
                }
            }
        }
    }

    /// Sends `query` over upstream TCP and returns the validated reply.
    ///
    /// Shares the caller's overall `deadline`: a TCP retry that would overrun
    /// it times out rather than stalling past `server.timeout_ms`.
    async fn forward_tcp(
        &self,
        query: &Message,
        deadline: Instant,
    ) -> Result<Message, ResolverError> {
        let mut stream = TcpStream::connect(self.upstream)
            .await
            .map_err(|source| ResolverError::Io { source })?;

        let mut outgoing = query.clone();
        outgoing.metadata.id = rand::random();
        let sent_id = outgoing.metadata.id;
        let request = outgoing
            .to_vec()
            .map_err(|_| ResolverError::MalformedReply)?;
        let len = u16::try_from(request.len()).map_err(|_| ResolverError::MalformedReply)?;

        stream
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|source| ResolverError::Io { source })?;
        stream
            .write_all(&request)
            .await
            .map_err(|source| ResolverError::Io { source })?;

        let mut len_buf = [0u8; 2];
        self.read_exact_within(&mut stream, &mut len_buf, deadline)
            .await?;
        let reply_len = usize::from(u16::from_be_bytes(len_buf));
        let mut buf = vec![0u8; reply_len];
        self.read_exact_within(&mut stream, &mut buf, deadline)
            .await?;

        let mut reply = Message::from_vec(&buf).map_err(|_| ResolverError::MalformedReply)?;
        if reply.metadata.id != sent_id {
            return Err(ResolverError::IdMismatch);
        }
        if reply.queries != query.queries {
            return Err(ResolverError::QuestionMismatch);
        }
        reply.metadata.id = query.metadata.id;
        Ok(reply)
    }

    /// Reads `buf` exactly, giving up at `deadline`.
    async fn read_exact_within(
        &self,
        stream: &mut TcpStream,
        buf: &mut [u8],
        deadline: Instant,
    ) -> Result<(), ResolverError> {
        let now = Instant::now();
        if now >= deadline {
            return Err(ResolverError::Timeout);
        }
        let remaining = deadline - now;
        match timeout(remaining, stream.read_exact(buf)).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(source)) => Err(ResolverError::Io { source }),
            Err(_) => Err(ResolverError::Timeout),
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
