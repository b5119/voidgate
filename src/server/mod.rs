//! DNS listeners and process lifecycle.
//!
//! M5b implements the UDP listener. Each received datagram is handled in its
//! own task, but only while a permit from the listener's in-flight semaphore
//! (`server.max_inflight`) is available; packets that arrive when the cap is
//! reached are dropped (with a rate-limited warning) instead of queueing, so a
//! burst or flood cannot grow memory without bound. On a shutdown signal the
//! listener stops accepting, waits up to `server.shutdown_grace_ms` for
//! in-flight queries to finish, then flushes the query log.
//!
//! TODO(M5c): TCP listener with 2-byte length framing, idle timeout and
//! connection cap (same handler as UDP); `#[cfg(unix)]` `SIGHUP` handler that
//! reloads the cache **offline** (no network); `refresh_interval_secs` timer
//! that fetches → atomic-renames → reloads via `ArcSwap`.

pub mod error;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::net::UdpSocket;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;

use crate::blocklists::BlocklistStore;
use crate::config::AppConfig;
use crate::handler::{handle_query, AppState};
use crate::storage::QueryLog;

pub use self::error::ServerError;

/// Receive buffer size in bytes. One UDP datagram never exceeds 65535 bytes;
/// 4096 comfortably covers every DNS message a real client sends on UDP, and
/// truncation is signalled to the client rather than read here.
const RECV_BUFFER_BYTES: usize = 4096;

/// Consecutive receive errors before the loop pauses, so a persistent error
/// (e.g. an interface going away) does not spin the CPU.
const RECV_ERROR_BACKOFF_AFTER: u32 = 16;

/// The pause taken after [`RECV_ERROR_BACKOFF_AFTER`] consecutive errors.
const RECV_ERROR_BACKOFF: Duration = Duration::from_millis(50);

/// A bound UDP DNS listener, ready to serve.
///
/// [`Server::bind`] performs the (synchronous) socket bind so callers learn
/// about `EADDRINUSE`/`EACCES` before entering the async runtime;
/// [`Server::run`] drives the receive loop until shutdown.
pub struct Server {
    socket: std::net::UdpSocket,
    state: AppState,
    permits: Arc<Semaphore>,
    grace: Duration,
}

impl Server {
    /// Binds the UDP listener described by `config`.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Bind`] if the address cannot be bound (address
    /// in use, permission denied) or put in non-blocking mode.
    pub fn bind(
        config: &AppConfig,
        blocklists: Arc<ArcSwap<BlocklistStore>>,
        query_log: QueryLog,
    ) -> Result<Self, ServerError> {
        let addr = SocketAddr::new(config.server.listen, config.server.port);
        let socket =
            std::net::UdpSocket::bind(addr).map_err(|source| ServerError::Bind { addr, source })?;
        socket
            .set_nonblocking(true)
            .map_err(|source| ServerError::Bind { addr, source })?;

        Ok(Self {
            socket,
            state: AppState::new(config, blocklists, query_log),
            permits: Arc::new(Semaphore::new(config.server.max_inflight)),
            grace: Duration::from_millis(config.server.shutdown_grace_ms),
        })
    }

    /// The address the listener is bound to (useful after binding port 0).
    ///
    /// # Errors
    ///
    /// Propagates the underlying `getsockname` failure.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Serves queries until `shutdown` resolves, then drains in-flight work
    /// and flushes the query log.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Io`] if the socket cannot be registered with the
    /// runtime and [`ServerError::Storage`] if the final log flush fails.
    pub async fn run<F>(self, shutdown: F) -> Result<(), ServerError>
    where
        F: std::future::Future<Output = ()>,
    {
        let Self {
            socket,
            state,
            permits,
            grace,
        } = self;

        let socket =
            Arc::new(UdpSocket::from_std(socket).map_err(|source| ServerError::Io { source })?);

        let mut tasks: JoinSet<()> = JoinSet::new();
        let dropped = AtomicU64::new(0);
        let mut buffer = vec![0u8; RECV_BUFFER_BYTES];
        let mut consecutive_errors: u32 = 0;

        tokio::pin!(shutdown);

        loop {
            // Reap finished tasks so the set does not grow across the run.
            while tasks.try_join_next().is_some() {}

            tokio::select! {
                () = &mut shutdown => break,
                received = socket.recv_from(&mut buffer) => {
                    match received {
                        Ok((len, source)) => {
                            consecutive_errors = 0;
                            let permit = match Arc::clone(&permits).try_acquire_owned() {
                                Ok(permit) => permit,
                                Err(_) => {
                                    let total = dropped.fetch_add(1, Ordering::Relaxed) + 1;
                                    warn_dropped(total);
                                    continue;
                                }
                            };
                            let packet = buffer[..len].to_vec();
                            let state = state.clone();
                            let socket = Arc::clone(&socket);
                            tasks.spawn(serve(state, socket, source, packet, permit));
                        }
                        Err(error) => {
                            consecutive_errors = consecutive_errors.saturating_add(1);
                            tracing::debug!(%error, "transient udp receive error");
                            if consecutive_errors >= RECV_ERROR_BACKOFF_AFTER {
                                consecutive_errors = 0;
                                tokio::time::sleep(RECV_ERROR_BACKOFF).await;
                            }
                        }
                    }
                }
            }
        }

        drain_tasks(&mut tasks, grace).await;
        state.query_log().shutdown()?;
        Ok(())
    }
}

/// Handles one datagram and sends its reply, holding the in-flight permit for
/// the whole exchange.
async fn serve(
    state: AppState,
    socket: Arc<UdpSocket>,
    source: SocketAddr,
    packet: Vec<u8>,
    permit: OwnedSemaphorePermit,
) {
    let _permit = permit;
    if let Some(reply) = handle_query(&state, source, &packet).await {
        if let Err(error) = socket.send_to(&reply, source).await {
            tracing::debug!(%source, %error, "failed to send udp reply");
        }
    }
}

/// Waits up to `grace` for spawned tasks to finish, then aborts the rest.
async fn drain_tasks(tasks: &mut JoinSet<()>, grace: Duration) {
    let deadline = tokio::time::Instant::now() + grace;
    let drain = async { while tasks.join_next().await.is_some() {} };
    if tokio::time::timeout_at(deadline, drain).await.is_err() {
        tracing::warn!("shutdown grace elapsed; abandoning in-flight queries");
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
}

/// Warns about dropped-over-cap packets, but only on the first drop and on
/// powers of two, so a sustained overload does not flood the log.
fn warn_dropped(total: u64) {
    if total == 1 || total.is_power_of_two() {
        tracing::warn!(
            dropped = total,
            "in-flight query limit reached; dropping packets"
        );
    }
}
