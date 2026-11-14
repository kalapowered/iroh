//! The serve loop of the HTTP and HTTPS listeners.
//!
//! The loop accepts connections on one listener and serves each on a task of its own, with the
//! settings of the connection builder it is given. Acceptors, handshakes and the connection cap
//! run inside the connection's task, so a slow handshake holds nothing but its own task.
//!
//! A connection that has read the lifetime figure of `idle` is shut down gracefully from its own
//! task, and ended after [`DRAIN_TIMEOUT`] if it is still open: see [`drive`].
//!
//! The loop is written for the make-service that axum builds from a router with the peer's
//! address: it is always ready and it cannot fail, which the bound `MakeError = Infallible`
//! states, so the loop has no branch for a make-service that is not ready or that fails.

use std::{
    convert::Infallible, future::Future, io, net::SocketAddr, pin::Pin, sync::Arc, time::Duration,
};

use axum_server::{
    accept::Accept,
    service::{MakeService, SendService},
};
use http::Request;
use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
    service::TowerToHyperService,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    task::JoinSet,
};
use tracing::{debug, warn};

use super::idle::{DRAIN_TIMEOUT, Shared, Watched};
use crate::metrics::Metrics;

/// How long the loop waits after a failed accept before it accepts again. A descriptor limit
/// that the server has reached is retried at most 20 times a second.
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(50);

/// A listener with the acceptor and the connection settings that serve its connections.
pub(super) struct Server<A> {
    listener: TcpListener,
    acceptor: A,
    builder: auto::Builder<TokioExecutor>,
    metrics: Arc<Metrics>,
}

impl<A> Server<A> {
    pub(super) fn new(
        listener: TcpListener,
        acceptor: A,
        builder: auto::Builder<TokioExecutor>,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            listener,
            acceptor,
            builder,
            metrics,
        }
    }

    /// Accept connections and serve them, for as long as the future is polled. The loop never
    /// returns: an accept that fails is tried again after [`ACCEPT_RETRY_DELAY`], whatever the
    /// error. When the future is dropped, the tasks of the connections are aborted with it.
    pub(super) async fn serve<M>(self, mut make_service: M) -> io::Result<()>
    where
        M: MakeService<SocketAddr, Request<Incoming>, MakeError = Infallible>,
        A: Accept<TcpStream, M::Service> + Clone + Send + Sync + 'static,
        A::Stream: AsyncRead + AsyncWrite + Unpin + Send + Watched + 'static,
        A::Service: SendService<Request<Incoming>> + Send,
        A::Future: Send,
    {
        let Self {
            listener,
            acceptor,
            builder,
            metrics,
        } = self;
        let builder = Arc::new(builder);
        let mut connections = JoinSet::new();
        loop {
            // One accept future stands until it yields a connection. The delay after a failed
            // accept is inside it, so a connection task that ends meanwhile does not cut it short.
            let accepted = accept(&listener);
            tokio::pin!(accepted);
            let (tcp, peer) = loop {
                tokio::select! {
                    biased;
                    Some(ended) = connections.join_next() => {
                        if let Err(error) = ended
                            && error.is_panic()
                        {
                            warn!(%error, "a connection task panicked");
                        }
                    }
                    accepted = &mut accepted => break accepted,
                }
            };
            let Ok(()) = std::future::poll_fn(|cx| make_service.poll_ready(cx)).await;
            let Ok(service) = make_service.make_service(peer).await;
            connections.spawn(connection(
                tcp,
                service,
                acceptor.clone(),
                builder.clone(),
                metrics.clone(),
            ));
        }
    }
}

/// The next connection of `listener`. An error ends no loop: it is logged and the accept is tried
/// again after [`ACCEPT_RETRY_DELAY`].
async fn accept(listener: &TcpListener) -> (TcpStream, SocketAddr) {
    loop {
        match listener.accept().await {
            Ok(accepted) => return accepted,
            Err(error) => {
                debug!(%error, "accepting a connection failed");
                tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
            }
        }
    }
}

/// Serve one connection: the acceptor's handshake and the connection cap come first, and a
/// connection that the acceptor refuses is dropped with nothing served.
async fn connection<A, S>(
    tcp: TcpStream,
    service: S,
    acceptor: A,
    builder: Arc<auto::Builder<TokioExecutor>>,
    metrics: Arc<Metrics>,
) where
    A: Accept<TcpStream, S>,
    A::Stream: AsyncRead + AsyncWrite + Unpin + Send + Watched + 'static,
    A::Service: SendService<Request<Incoming>>,
{
    let Ok((stream, service)) = acceptor.accept(tcp, service).await else {
        return;
    };
    let shared = stream.shared();
    let service = TowerToHyperService::new(service.into_service());
    let conn = builder.serve_connection_with_upgrades(TokioIo::new(stream), service);
    drive(conn, |conn| conn.graceful_shutdown(), &shared, &metrics).await;
}

/// Drive a connection to its end. When the connection's drain signal is raised, from any task, the
/// connection's own task calls the graceful shutdown with `graceful_shutdown` and polls it on for
/// at most [`DRAIN_TIMEOUT`], timed from the call. A connection that is still open then is dropped
/// and counted in `http_connections_drain_timeouts`, whatever kept it open.
pub(super) async fn drive<C, E>(
    conn: C,
    graceful_shutdown: impl FnOnce(Pin<&mut C>),
    shared: &Shared,
    metrics: &Metrics,
) where
    C: Future<Output = Result<(), E>>,
{
    tokio::pin!(conn);
    // The signal is polled first, so that one raised before the connection's first poll, or at the
    // moment the connection ends, is not lost. The outcome of a connection that ends with an
    // error is of no use to the loop.
    tokio::select! {
        biased;
        () = shared.drain.notified() => {}
        _ = conn.as_mut() => return,
    }
    graceful_shutdown(conn.as_mut());
    if tokio::time::timeout(DRAIN_TIMEOUT, conn).await.is_err() {
        metrics.http_connections_drain_timeouts.inc();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        task::{Context, Poll},
    };

    use super::*;

    /// A connection that does not end by itself and wakes no one: it only counts the calls of its
    /// graceful shutdown.
    struct Fake;

    impl Future for Fake {
        type Output = Result<(), io::Error>;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Pending
        }
    }

    /// Lets the ready tasks run until `calls` is above zero, for at most 1,000 turns.
    async fn wait_for_a_call(calls: &AtomicUsize) {
        for _ in 0..1_000 {
            if calls.load(Ordering::SeqCst) > 0 {
                return;
            }
            tokio::task::yield_now().await;
        }
    }

    /// Waits for the task of a drive to end, for at most 5 seconds of the clock.
    async fn ends(task: tokio::task::JoinHandle<()>) {
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the drive did not end at the drain time")
            .expect("the drive's task ended with an error");
    }

    /// `drive` over a fake connection on a task of its own: the task, the number of times the
    /// graceful shutdown was called, the connection's shared state and the metrics.
    fn driven() -> (
        tokio::task::JoinHandle<()>,
        Arc<AtomicUsize>,
        Arc<Shared>,
        Arc<Metrics>,
    ) {
        let calls = Arc::new(AtomicUsize::new(0));
        let shared = Shared::new();
        let metrics: Arc<Metrics> = Arc::default();
        let task = tokio::spawn({
            let (calls, shared, metrics) = (calls.clone(), shared.clone(), metrics.clone());
            async move {
                drive(
                    Fake,
                    move |_| {
                        calls.fetch_add(1, Ordering::SeqCst);
                    },
                    &shared,
                    &metrics,
                )
                .await;
            }
        });
        (task, calls, shared, metrics)
    }

    /// C7. A signal raised from another task after the connection has parked makes the
    /// connection's own task call the graceful shutdown, with no other wake; the timer starts at
    /// the call, so the connection is cut 20 seconds after it and not after the 5 seconds that
    /// came before.
    #[tokio::test(start_paused = true)]
    async fn a_signal_from_another_task_reaches_a_parked_connection_and_starts_the_timer() {
        let (task, calls, shared, metrics) = driven();
        tokio::time::advance(Duration::from_secs(5)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        tokio::spawn(async move { shared.drain.notify_one() });
        wait_for_a_call(&calls).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "no call of the graceful shutdown"
        );
        tokio::time::advance(DRAIN_TIMEOUT - Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(!task.is_finished(), "cut before the drain time");
        assert_eq!(metrics.http_connections_drain_timeouts.get(), 0);
        tokio::time::advance(Duration::from_secs(2)).await;
        ends(task).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(metrics.http_connections_drain_timeouts.get(), 1);
    }

    /// C7. A signal raised before the first poll is kept: the call is made at once.
    #[tokio::test(start_paused = true)]
    async fn a_signal_raised_before_the_first_poll_is_kept() {
        let calls = Arc::new(AtomicUsize::new(0));
        let shared = Shared::new();
        let metrics: Arc<Metrics> = Arc::default();
        shared.drain.notify_one();
        let counted = calls.clone();
        let task = tokio::spawn({
            let (shared, metrics) = (shared.clone(), metrics.clone());
            async move {
                drive(
                    Fake,
                    move |_| {
                        counted.fetch_add(1, Ordering::SeqCst);
                    },
                    &shared,
                    &metrics,
                )
                .await;
            }
        });
        wait_for_a_call(&calls).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "no call of the graceful shutdown"
        );
        tokio::time::advance(DRAIN_TIMEOUT + Duration::from_secs(1)).await;
        ends(task).await;
        assert_eq!(metrics.http_connections_drain_timeouts.get(), 1);
    }

    /// C7. A connection that ends by itself is not shut down and is not counted, and the drive
    /// returns with no further poll.
    #[tokio::test(start_paused = true)]
    async fn a_connection_that_ends_is_not_shut_down_or_counted() {
        let calls = Arc::new(AtomicUsize::new(0));
        let shared = Shared::new();
        let metrics: Arc<Metrics> = Arc::default();
        let counted = calls.clone();
        drive(
            std::future::ready(Ok::<(), io::Error>(())),
            move |_| {
                counted.fetch_add(1, Ordering::SeqCst);
            },
            &shared,
            &metrics,
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(metrics.http_connections_drain_timeouts.get(), 0);
    }
}
