//! Errors produced while forwarding a query upstream.

use std::io;

use thiserror::Error;

/// Why a query could not be answered from upstream.
///
/// The source/ID/question variants only ever surface for an individual
/// datagram: [`Resolver::forward`](super::Resolver::forward) logs them at
/// `debug` and keeps waiting for a valid reply until the timeout expires, so
/// they never reach the handler directly.
#[derive(Debug, Error)]
pub enum ResolverError {
    /// No valid reply arrived before `server.timeout_ms` elapsed.
    #[error("upstream did not answer within the configured timeout")]
    Timeout,
    /// The socket could not be created, sent on, or read from.
    #[error("upstream socket error: {source}")]
    Io {
        /// The underlying I/O failure.
        #[source]
        source: io::Error,
    },
    /// A datagram arrived from an address other than the configured upstream.
    #[error("reply came from an unexpected source address")]
    WrongSource,
    /// The reply's transaction ID did not match the query we sent.
    #[error("reply transaction id did not match the query")]
    IdMismatch,
    /// The reply's question section did not match the query we sent.
    #[error("reply question section did not match the query")]
    QuestionMismatch,
    /// The datagram was not a decodable DNS message (or the query could not
    /// be serialised for the wire).
    #[error("upstream sent a malformed reply")]
    MalformedReply,
}
