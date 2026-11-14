//! The serve loop of the HTTP and HTTPS listeners.
//!
//! The loop accepts connections on one listener and serves each on a task of its own, with the
//! settings of the connection builder it is given. Acceptors, handshakes and the connection cap
//! run inside the connection's task, so a slow handshake holds nothing but its own task.
//!
//! The loop is written for the make-service that axum builds from a router with the peer's
//! address: it is always ready and it cannot fail, which the bound `MakeError = Infallible`
//! states, so the loop has no branch for a make-service that is not ready or that fails.

use std::{convert::Infallible, io, net::SocketAddr, sync::Arc, time::Duration};

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

/// How long the loop waits after a failed accept before it accepts again. A descriptor limit
/// that the server has reached is retried at most 20 times a second.
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(50);

/// A listener with the acceptor and the connection settings that serve its connections.
pub(super) struct Server<A> {
    listener: TcpListener,
    acceptor: A,
    builder: auto::Builder<TokioExecutor>,
}

impl<A> Server<A> {
    pub(super) fn new(
        listener: TcpListener,
        acceptor: A,
        builder: auto::Builder<TokioExecutor>,
    ) -> Self {
        Self {
            listener,
            acceptor,
            builder,
        }
    }

    /// Accept connections and serve them, for as long as the future is polled. The loop never
    /// returns: an accept that fails is tried again after [`ACCEPT_RETRY_DELAY`], whatever the
    /// error. When the future is dropped, the tasks of the connections are aborted with it.
    pub(super) async fn serve<M>(self, mut make_service: M) -> io::Result<()>
    where
        M: MakeService<SocketAddr, Request<Incoming>, MakeError = Infallible>,
        A: Accept<TcpStream, M::Service> + Clone + Send + Sync + 'static,
        A::Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        A::Service: SendService<Request<Incoming>> + Send,
        A::Future: Send,
    {
        let Self {
            listener,
            acceptor,
            builder,
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
            connections.spawn(connection(tcp, service, acceptor.clone(), builder.clone()));
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
) where
    A: Accept<TcpStream, S>,
    A::Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    A::Service: SendService<Request<Incoming>>,
{
    let Ok((stream, service)) = acceptor.accept(tcp, service).await else {
        return;
    };
    let service = TowerToHyperService::new(service.into_service());
    // The outcome of a connection that ends with an error is of no use to the loop.
    let _ = builder
        .serve_connection_with_upgrades(TokioIo::new(stream), service)
        .await;
}
