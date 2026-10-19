//! DNS listeners and process lifecycle.
//!
//! Two listeners share one port: UDP (per-datagram) and TCP (RFC 1035
//! 2-byte length framing, multiple sequential queries per connection). Both
//! drive the same [`handle_query`] pipeline. Work is bounded at three levels:
//!
//! - the listener cap `server.max_inflight` (UDP packets accepted concurrently),
//! - the connection cap `server.tcp_max_connections` (TCP sockets open at once),
//! - the resolver cap `server.max_upstream_inflight` (in the handler; when it
//!   is full, new forwards get an instant SERVFAIL while sinkholed and ACL
//!   answers keep flowing).
//!
//! Lifecycle extras, all cancelled on shutdown:
//! - `SIGHUP` (Unix) reloads the blocklists from cache **offline**;
//! - a timer re-fetches URL lists every `blocklists.refresh_interval_secs`
//!   (fetch → atomic rename → reload via `ArcSwap`).
//!
//! On shutdown both listeners stop accepting, in-flight work drains within
//! `server.shutdown_grace_ms`, then the query log is flushed.

pub mod error;

use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;

use crate::blocklists::{cache, reload_from_cache, BlocklistStore};
use crate::config::{AppConfig, BlocklistsConfig};
use crate::handler::{handle_query, handle_query_with_transport, AppState};
use crate::resolver::Transport;
use crate::storage::QueryLog;

pub use self::error::ServerError;

/// UDP receive buffer size in bytes. One datagram never exceeds 65535 bytes;
/// 4096 covers every real UDP query; larger messages are a TCP fallback.
const RECV_BUFFER_BYTES: usize = 4096;

/// Consecutive receive errors before the loop pauses, so a persistent error
/// does not spin the CPU.
const RECV_ERROR_BACKOFF_AFTER: u32 = 16;

/// The pause taken after [`RECV_ERROR_BACKOFF_AFTER`] consecutive errors.
const RECV_ERROR_BACKOFF: Duration = Duration::from_millis(50);

/// Largest DNS message a TCP client may send (the 16-bit length field).
const MAX_TCP_MESSAGE_BYTES: usize = 65_535;

/// A bound DNS listener (UDP + optional TCP), ready to serve.
///
/// [`Server::bind`] performs the synchronous socket binds so callers learn
/// about `EADDRINUSE`/`EACCES` before entering the async runtime;
/// [`Server::run`] drives both listeners until shutdown.
pub struct Server {
    udp: Arc<UdpSocket>,
    tcp: Option<TcpListener>,
    state: AppState,
    permits: Arc<Semaphore>,
    tcp_conns: Arc<Semaphore>,
    grace: Duration,
    tcp_idle_timeout: Duration,
    tcp_max_queries_per_conn: u32,
    blocklists_config: BlocklistsConfig,
    blocklists: Arc<ArcSwap<BlocklistStore>>,
    refresh_interval: Duration,
}

impl Server {
    /// Binds the UDP listener (and TCP when `tcp_enabled`) described by
    /// `config`.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Bind`] if either address cannot be bound or put
    /// in non-blocking mode.
    pub fn bind(
        config: &AppConfig,
        blocklists: Arc<ArcSwap<BlocklistStore>>,
        query_log: QueryLog,
    ) -> Result<Self, ServerError> {
        let addr = SocketAddr::new(config.server.listen, config.server.port);
        let udp =
            std::net::UdpSocket::bind(addr).map_err(|source| ServerError::Bind { addr, source })?;
        udp.set_nonblocking(true)
            .map_err(|source| ServerError::Bind { addr, source })?;
        // Resolve the concrete port before binding TCP so that an ephemeral
        // `port: 0` gives both listeners the *same* port. Binding TCP on the
        // requested `addr` would hand it a second, unrelated ephemeral port.
        let bound = udp
            .local_addr()
            .map_err(|source| ServerError::Io { source })?;
        let udp = Arc::new(UdpSocket::from_std(udp).map_err(|source| ServerError::Io { source })?);

        let tcp = if config.server.tcp_enabled {
            let listener =
                std::net::TcpListener::bind(bound).map_err(|source| ServerError::Bind {
                    addr: bound,
                    source,
                })?;
            listener
                .set_nonblocking(true)
                .map_err(|source| ServerError::Bind {
                    addr: bound,
                    source,
                })?;
            Some(TcpListener::from_std(listener).map_err(|source| ServerError::Io { source })?)
        } else {
            None
        };

        Ok(Self {
            udp,
            tcp,
            state: AppState::new(config, Arc::clone(&blocklists), query_log),
            permits: Arc::new(Semaphore::new(config.server.max_inflight)),
            tcp_conns: Arc::new(Semaphore::new(config.server.tcp_max_connections)),
            grace: Duration::from_millis(config.server.shutdown_grace_ms),
            tcp_idle_timeout: Duration::from_millis(config.server.tcp_idle_timeout_ms),
            tcp_max_queries_per_conn: config.server.tcp_max_queries_per_conn,
            blocklists_config: config.blocklists.clone(),
            blocklists,
            refresh_interval: Duration::from_secs(config.blocklists.refresh_interval_secs),
        })
    }

    /// The address the UDP listener is bound to (useful after binding port 0).
    ///
    /// # Errors
    ///
    /// Propagates the underlying `getsockname` failure.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.udp.local_addr()
    }

    /// Serves queries until `shutdown` resolves, then drains in-flight work
    /// and flushes the query log.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Io`] if the sockets cannot be registered with the
    /// runtime and [`ServerError::Storage`] if the final log flush fails.
    pub async fn run<F>(self, shutdown: F) -> Result<(), ServerError>
    where
        F: Future<Output = ()>,
    {
        let Self {
            udp,
            tcp,
            state,
            permits,
            tcp_conns,
            grace,
            tcp_idle_timeout,
            tcp_max_queries_per_conn,
            blocklists_config,
            blocklists,
            refresh_interval,
        } = self;

        let mut tasks: JoinSet<()> = JoinSet::new();
        let mut background: JoinSet<()> = JoinSet::new();

        // Refresh timer: fetch URL lists then reload from cache, cancelled on
        // shutdown. The first tick is delayed by a full interval, not immediate.
        if !refresh_interval.is_zero() {
            let blocklists = Arc::clone(&blocklists);
            let config = blocklists_config.clone();
            background.spawn(async move {
                let mut timer = tokio::time::interval(refresh_interval);
                timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                timer.tick().await; // consume the immediate first tick
                loop {
                    timer.tick().await;
                    refresh_and_reload(&config, &blocklists).await;
                }
            });
        }

        // SIGHUP: reload from cache offline.
        #[cfg(unix)]
        background.spawn(sighup_reload(
            blocklists_config.clone(),
            Arc::clone(&blocklists),
        ));

        let dropped = AtomicU64::new(0);
        let mut buffer = vec![0u8; RECV_BUFFER_BYTES];
        let mut consecutive_errors: u32 = 0;

        tokio::pin!(shutdown);

        loop {
            while tasks.try_join_next().is_some() {}

            tokio::select! {
                () = &mut shutdown => break,
                received = udp.recv_from(&mut buffer) => {
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
                            let udp = Arc::clone(&udp);
                            tasks.spawn(async move {
                                let _permit = permit;
                                if let Some(reply) = handle_query(&state, source, &packet).await {
                                    if let Err(error) = udp.send_to(&reply, source).await {
                                        tracing::debug!(%source, %error, "failed to send udp reply");
                                    }
                                }
                            });
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
                accepted = accept_tcp(&tcp) => {
                    if let Some((stream, peer)) = accepted {
                        // ACL: an out-of-range TCP client is closed at accept
                        // with no read, for both acl_action values.
                        if !state.client_allowed(&peer.ip()) {
                            tracing::debug!(%peer, "closing tcp connection from disallowed client");
                            continue;
                        }
                        let permit = match Arc::clone(&tcp_conns).try_acquire_owned() {
                            Ok(permit) => permit,
                            Err(_) => {
                                tracing::debug!(%peer, "tcp connection cap reached; closing");
                                continue;
                            }
                        };
                        let state = state.clone();
                        tasks.spawn(async move {
                            serve_tcp(
                                stream,
                                state,
                                peer,
                                permit,
                                tcp_idle_timeout,
                                tcp_max_queries_per_conn,
                            )
                            .await;
                        });
                    }
                }
            }
        }

        background.abort_all();
        drain_tasks(&mut tasks, grace).await;
        state.query_log().shutdown()?;
        Ok(())
    }
}

/// Accepts the next TCP connection, or never resolves when TCP is disabled.
async fn accept_tcp(tcp: &Option<TcpListener>) -> Option<(TcpStream, SocketAddr)> {
    match tcp {
        Some(listener) => match listener.accept().await {
            Ok(connection) => Some(connection),
            Err(error) => {
                tracing::debug!(%error, "transient tcp accept error");
                None
            }
        },
        None => std::future::pending().await,
    }
}

/// Serves one TCP connection: RFC 1035 length-framed queries, sequentially.
///
/// Closes on idle/partial-frame timeout, a zero-length frame, a read/write
/// error, or once `max_queries` have been answered. The connection permit is
/// held for the whole lifetime.
async fn serve_tcp(
    mut stream: TcpStream,
    state: AppState,
    peer: SocketAddr,
    permit: OwnedSemaphorePermit,
    idle: Duration,
    max_queries: u32,
) {
    let _permit = permit;
    let mut len_buf = [0u8; 2];
    for _ in 0..max_queries {
        match tokio::time::timeout(idle, stream.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                tracing::debug!(%peer, %error, "tcp read failed; closing");
                return;
            }
            Err(_) => {
                tracing::debug!(%peer, "tcp idle timeout; closing");
                return;
            }
        }
        let len = usize::from(u16::from_be_bytes(len_buf));
        if len == 0 || len > MAX_TCP_MESSAGE_BYTES {
            tracing::debug!(%peer, len, "invalid tcp frame length; closing");
            return;
        }
        let mut message = vec![0u8; len];
        match tokio::time::timeout(idle, stream.read_exact(&mut message)).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                tracing::debug!(%peer, %error, "tcp partial frame; closing");
                return;
            }
            Err(_) => {
                tracing::debug!(%peer, "tcp idle timeout; closing");
                return;
            }
        }

        if let Some(reply) =
            handle_query_with_transport(&state, peer, &message, Transport::Tcp).await
        {
            let mut framed = Vec::with_capacity(2 + reply.len());
            framed.extend_from_slice(&(reply.len() as u16).to_be_bytes());
            framed.extend_from_slice(&reply);
            if let Err(error) = stream.write_all(&framed).await {
                tracing::debug!(%peer, %error, "tcp write failed; closing");
                return;
            }
        }
    }
    tracing::debug!(%peer, "tcp query budget reached; closing");
}

/// Fetches URL lists into cache, then reloads the store from cache.
async fn refresh_and_reload(config: &BlocklistsConfig, blocklists: &Arc<ArcSwap<BlocklistStore>>) {
    match cache::refresh_all(config).await {
        Ok(reports) => {
            for report in &reports {
                tracing::info!(report = %report, "blocklist refresh");
            }
        }
        Err(error) => {
            tracing::warn!(%error, "blocklist refresh failed; keeping previous cache");
            return;
        }
    }
    reload(blocklists, config);
}

/// Reloads the store from cache, keeping the old store on failure.
fn reload(blocklists: &Arc<ArcSwap<BlocklistStore>>, config: &BlocklistsConfig) {
    match reload_from_cache(config) {
        Ok(store) => {
            tracing::info!("reloaded blocklists from cache");
            blocklists.store(Arc::new(store));
        }
        Err(error) => {
            tracing::warn!(%error, "blocklist reload failed; keeping previous store");
        }
    }
}

/// Waits for `SIGHUP` and reloads the blocklists from cache (offline).
#[cfg(unix)]
async fn sighup_reload(config: BlocklistsConfig, blocklists: Arc<ArcSwap<BlocklistStore>>) {
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
        Ok(mut signal) => loop {
            signal.recv().await;
            reload(&blocklists, &config);
        },
        Err(error) => {
            tracing::error!(%error, "failed to listen for SIGHUP");
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
