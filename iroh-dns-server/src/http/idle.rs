//! A bound on how long a connection may stand with no request in progress.
//!
//! hyper bounds the header read of an HTTP/1 request, but a connection that sends nothing after
//! its handshake, and an HTTP/2 connection that has no request open, are never closed by it.
//! [`IdleBound`] wraps an acceptor and closes a connection that has had no request in progress
//! for [`IDLE_TIMEOUT`], counted from the end of the handshake or from the end of the last
//! request. Bytes that arrive without starting a request, such as the pings of an idle HTTP/2
//! connection, do not extend it. A request in progress is bounded by its own deadline.

use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

use axum_server::accept::Accept;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{Instant, Sleep},
};
use tower_service::Service;

/// How long a connection may stand with no request in progress.
pub(super) const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// What a connection's stream and its service both see.
#[derive(Debug)]
struct Shared {
    /// The requests that have been handed to the service and have not been answered.
    in_flight: AtomicUsize,
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    /// When the connection last had no request in progress.
    idle_since: Instant,
    /// The task that waits for the connection's last request to end.
    waker: Option<Waker>,
}

impl Shared {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            in_flight: AtomicUsize::new(0),
            state: Mutex::new(State {
                idle_since: Instant::now(),
                waker: None,
            }),
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A request in progress. The connection counts as busy until this is dropped.
struct InFlight(Arc<Shared>);

impl InFlight {
    fn begin(shared: &Arc<Shared>) -> Self {
        shared.in_flight.fetch_add(1, Ordering::SeqCst);
        Self(shared.clone())
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        if self.0.in_flight.fetch_sub(1, Ordering::SeqCst) == 1 {
            let mut state = self.0.state();
            state.idle_since = Instant::now();
            // The stream is not polled while it waits for a request to end, so wake it to start
            // its clock.
            if let Some(waker) = state.waker.take() {
                drop(state);
                waker.wake();
            }
        }
    }
}

/// An acceptor that closes connections which stand with no request in progress.
#[derive(Clone, Debug)]
pub(super) struct IdleBound<A>(pub(super) A);

impl<A, I, S> Accept<I, S> for IdleBound<A>
where
    A: Accept<I, S> + Clone + Send + Sync + 'static,
    A::Future: Send + 'static,
    A::Stream: Send + 'static,
    A::Service: Send + 'static,
    I: Send + 'static,
    S: Send + 'static,
{
    type Stream = IdleStream<A::Stream>;
    type Service = Tracked<A::Service>;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let accepted = self.0.accept(stream, service);
        Box::pin(async move {
            let (stream, service) = accepted.await?;
            let shared = Shared::new();
            Ok((
                IdleStream {
                    inner: stream,
                    shared: shared.clone(),
                    timer: Box::pin(tokio::time::sleep_until(Instant::now() + IDLE_TIMEOUT)),
                    armed: None,
                },
                Tracked {
                    inner: service,
                    shared,
                },
            ))
        })
    }
}

/// A connection's service, which tells the connection's stream when a request starts and ends.
#[derive(Clone, Debug)]
pub(super) struct Tracked<S> {
    inner: S,
    shared: Arc<Shared>,
}

impl<S, R> Service<R> for Tracked<S>
where
    S: Service<R>,
    S::Future: Send + 'static,
    S::Response: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<S::Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: R) -> Self::Future {
        let in_flight = InFlight::begin(&self.shared);
        let answer = self.inner.call(request);
        Box::pin(async move {
            let _in_flight = in_flight;
            answer.await
        })
    }
}

/// A connection's stream, which fails once the connection has stood idle for too long.
pub(super) struct IdleStream<T> {
    inner: T,
    shared: Arc<Shared>,
    timer: Pin<Box<Sleep>>,
    /// The deadline the timer is set to, or `None` while a request is in progress.
    armed: Option<Instant>,
}

impl<T> IdleStream<T> {
    /// Fails with a time-out once the connection has had no request in progress for
    /// [`IDLE_TIMEOUT`]. Otherwise arranges for the task to be polled again at that time, or when
    /// the request in progress ends.
    fn check(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if self.shared.in_flight.load(Ordering::SeqCst) > 0 {
            self.shared.state().waker = Some(cx.waker().clone());
            // The request may have ended before the waker was in place.
            if self.shared.in_flight.load(Ordering::SeqCst) > 0 {
                self.armed = None;
                return Ok(());
            }
        }
        let deadline = self.shared.state().idle_since + IDLE_TIMEOUT;
        if self.armed != Some(deadline) {
            self.timer.as_mut().reset(deadline);
            self.armed = Some(deadline);
        }
        match self.timer.as_mut().poll(cx) {
            Poll::Ready(()) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "connection idle with no request in progress",
            )),
            Poll::Pending => Ok(()),
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for IdleStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        this.check(cx)?;
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for IdleStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        this.check(cx)?;
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        this.check(cx)?;
        Pin::new(&mut this.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        this.check(cx)?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use axum_server::accept::DefaultAcceptor;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
        sync::Notify,
        time::{advance, timeout},
    };

    use super::*;

    /// A service whose answers wait for a signal.
    #[derive(Clone)]
    struct Gated(Arc<Notify>);

    impl Service<()> for Gated {
        type Response = ();
        type Error = Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<(), Infallible>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _request: ()) -> Self::Future {
            let gate = self.0.clone();
            Box::pin(async move {
                gate.notified().await;
                Ok(())
            })
        }
    }

    async fn accepted() -> (
        DuplexStream,
        IdleStream<DuplexStream>,
        Tracked<Gated>,
        Arc<Notify>,
    ) {
        let (client, server) = tokio::io::duplex(1024);
        let gate = Arc::new(Notify::new());
        let (stream, service): (IdleStream<DuplexStream>, Tracked<Gated>) =
            IdleBound(DefaultAcceptor)
                .accept(server, Gated(gate.clone()))
                .await
                .expect("the acceptor passes the connection on");
        (client, stream, service, gate)
    }

    /// The error a read of the stream ends with, or `None` if it is still waiting after a short
    /// stretch of the clock.
    async fn read_ends(stream: &mut IdleStream<DuplexStream>) -> Option<io::Error> {
        let mut byte = [0u8; 1];
        timeout(Duration::from_millis(50), stream.read(&mut byte))
            .await
            .ok()
            .and_then(Result::err)
    }

    #[tokio::test(start_paused = true)]
    async fn a_connection_with_no_request_is_closed_at_the_bound() {
        let (_client, mut stream, _service, _gate) = accepted().await;

        advance(IDLE_TIMEOUT - Duration::from_secs(1)).await;
        assert!(
            read_ends(&mut stream).await.is_none(),
            "closed before the bound"
        );

        advance(Duration::from_secs(2)).await;
        let error = read_ends(&mut stream)
            .await
            .expect("not closed at the bound");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test(start_paused = true)]
    async fn bytes_that_start_no_request_do_not_extend_the_bound() {
        let (mut client, mut stream, _service, _gate) = accepted().await;

        // A peer that sends a byte every ten seconds, as a ping of an idle connection or the
        // drip of a header that never ends.
        for _ in 0..2 {
            advance(Duration::from_secs(10)).await;
            client.write_all(b"x").await.expect("write");
            let mut byte = [0u8; 1];
            stream
                .read_exact(&mut byte)
                .await
                .expect("the byte arrives before the bound");
        }
        advance(Duration::from_secs(11)).await;
        let error = read_ends(&mut stream)
            .await
            .expect("not closed at the bound");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test(start_paused = true)]
    async fn a_request_in_progress_keeps_the_connection_open_until_it_ends() {
        let (_client, mut stream, mut service, gate) = accepted().await;

        let answer = tokio::spawn(service.call(()));
        advance(IDLE_TIMEOUT * 4).await;
        assert!(
            read_ends(&mut stream).await.is_none(),
            "closed during a request"
        );

        // The bound runs from the end of the request, not from the start of the connection.
        gate.notify_one();
        answer
            .await
            .expect("the answer task ends")
            .expect("the answer");
        advance(IDLE_TIMEOUT - Duration::from_secs(1)).await;
        assert!(
            read_ends(&mut stream).await.is_none(),
            "closed before the bound"
        );
        advance(Duration::from_secs(2)).await;
        let error = read_ends(&mut stream)
            .await
            .expect("not closed at the bound");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test(start_paused = true)]
    async fn a_request_that_is_dropped_ends_like_one_that_is_answered() {
        let (_client, mut stream, mut service, _gate) = accepted().await;

        let answer = service.call(());
        advance(IDLE_TIMEOUT * 2).await;
        assert!(
            read_ends(&mut stream).await.is_none(),
            "closed during a request"
        );
        drop(answer);

        advance(IDLE_TIMEOUT + Duration::from_secs(1)).await;
        assert!(
            read_ends(&mut stream).await.is_some(),
            "not closed after a dropped request"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_write_after_the_bound_fails() {
        let (_client, mut stream, _service, _gate) = accepted().await;

        advance(IDLE_TIMEOUT + Duration::from_secs(1)).await;
        let error = stream
            .write_all(b"x")
            .await
            .expect_err("the write succeeded after the bound");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }
}
