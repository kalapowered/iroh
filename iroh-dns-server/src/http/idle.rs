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

use crate::metrics::Metrics;

/// How long a connection may stand with no request in progress.
pub(super) const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// The connections that the server holds at once, from the accept to the close, across its
/// listeners. A connection that would be one more than `max` is closed at once.
#[derive(Debug)]
pub(super) struct Connections {
    held: AtomicUsize,
    max: usize,
    metrics: Arc<Metrics>,
}

impl Connections {
    pub(super) fn new(max: usize, metrics: Arc<Metrics>) -> Arc<Self> {
        Arc::new(Self {
            held: AtomicUsize::new(0),
            max,
            metrics,
        })
    }

    /// A place for one more connection, or `None` if the server already holds `max`. The count
    /// guards no other data, so only its atomicity matters; the update is one compare and swap, so
    /// it can never pass `max`.
    fn take(self: &Arc<Self>) -> Option<Slot> {
        self.held
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |held| {
                (held < self.max).then_some(held + 1)
            })
            .ok()?;
        Some(Slot(self.clone()))
    }

    #[cfg(test)]
    fn held(&self) -> usize {
        self.held.load(Ordering::SeqCst)
    }
}

/// A connection's place among the connections the server holds. It is given back when this is
/// dropped, whichever way the connection ends: its handshake fails or is cancelled, its task
/// panics, or it closes.
#[derive(Debug)]
struct Slot(Arc<Connections>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.held.fetch_sub(1, Ordering::SeqCst);
    }
}

/// What a connection's stream and its service both see. The count of requests in progress and the
/// time the connection last had none change together, under one lock, so that a reader never sees
/// the count at zero with the time from before the request.
#[derive(Debug)]
struct Shared {
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    /// The requests that have been handed to the service and have not been answered.
    in_flight: usize,
    /// When the connection last had no request in progress.
    idle_since: Instant,
    /// The task that waits for the connection's last request to end.
    waker: Option<Waker>,
}

impl Shared {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                in_flight: 0,
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
        shared.state().in_flight += 1;
        Self(shared.clone())
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        let mut state = self.0.state();
        state.in_flight -= 1;
        if state.in_flight == 0 {
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

/// An acceptor that closes connections which stand with no request in progress, and the ones
/// that would pass the most the server holds.
#[derive(Clone, Debug)]
pub(super) struct IdleBound<A> {
    inner: A,
    connections: Arc<Connections>,
}

impl<A> IdleBound<A> {
    pub(super) fn new(inner: A, connections: Arc<Connections>) -> Self {
        Self { inner, connections }
    }
}

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
        let Some(slot) = self.connections.take() else {
            self.connections.metrics.http_connections_refused.inc();
            // The connection is closed as the stream is dropped here, before any handshake, and
            // no task is left behind.
            return Box::pin(std::future::ready(Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "the server holds the most connections it allows",
            ))));
        };
        let accepted = self.inner.accept(stream, service);
        Box::pin(async move {
            // The slot is held through the handshake, and by the stream after it.
            let (stream, service) = accepted.await?;
            let shared = Shared::new();
            Ok((
                IdleStream {
                    inner: stream,
                    shared: shared.clone(),
                    timer: Box::pin(tokio::time::sleep_until(Instant::now() + IDLE_TIMEOUT)),
                    armed: None,
                    _slot: slot,
                    #[cfg(test)]
                    after_read: None,
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

/// A connection's stream, which fails once the connection has stood idle for too long. Every
/// operation that can stay pending, a close included, checks the clock first, so an expired
/// deadline ends the connection whatever the inner stream is doing.
pub(super) struct IdleStream<T> {
    inner: T,
    shared: Arc<Shared>,
    timer: Pin<Box<Sleep>>,
    /// The deadline the timer is set to, or `None` while a request is in progress.
    armed: Option<Instant>,
    /// The connection's place among the connections the server holds.
    _slot: Slot,
    /// Runs once, in the first `check`, after the state is read and before the timer is polled, so
    /// that a case can place a change of the state between the two.
    #[cfg(test)]
    after_read: Option<Box<dyn FnOnce() + Send>>,
}

impl<T> IdleStream<T> {
    /// Fails with a time-out once the connection has had no request in progress for
    /// [`IDLE_TIMEOUT`]. Otherwise arranges for the task to be polled again at that time, or when
    /// the request in progress ends.
    ///
    /// The state is not held while the timer is polled, so a request can start or end between the
    /// read and the poll. When the timer reports that the deadline has passed, the state is read
    /// again under the lock, and the connection ends only if it still has no request in progress
    /// and the deadline it read is still its deadline.
    fn check(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        loop {
            let deadline = {
                let mut state = self.shared.state();
                if state.in_flight > 0 {
                    // The waker is in place before the request can end, since the end takes the
                    // lock.
                    state.waker = Some(cx.waker().clone());
                    self.armed = None;
                    return Ok(());
                }
                state.idle_since + IDLE_TIMEOUT
            };
            #[cfg(test)]
            if let Some(after_read) = self.after_read.take() {
                after_read();
            }
            if self.armed != Some(deadline) {
                self.timer.as_mut().reset(deadline);
                self.armed = Some(deadline);
            }
            if self.timer.as_mut().poll(cx).is_pending() {
                return Ok(());
            }
            let state = self.shared.state();
            if state.in_flight == 0 && state.idle_since + IDLE_TIMEOUT == deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "connection idle with no request in progress",
                ));
            }
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
        let this = &mut *self;
        this.check(cx)?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
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
            IdleBound::new(DefaultAcceptor, Connections::new(1_000, Default::default()))
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

    /// A request that starts near the bound and ends inside its own deadline gives the connection
    /// a whole new idle period, even when a poll of the stream falls between the two changes that
    /// the end of a request makes: the count of requests going to zero and the clock restarting.
    /// The request's old idle time has long run out, so a poll that sees the count at zero and the
    /// old time ends the connection. The connection is polled from another thread, as the
    /// connection's task is, while the request ends.
    #[tokio::test]
    async fn a_request_that_ends_is_never_met_with_the_idle_time_from_before_it() {
        use std::{
            sync::{Barrier, atomic::AtomicBool},
            thread,
        };

        for _ in 0..5_000 {
            let (_client, mut stream, _service, _gate) = accepted().await;
            let request = InFlight::begin(&stream.shared);
            stream.shared.state().idle_since = Instant::now() - IDLE_TIMEOUT * 2;

            let start = Arc::new(Barrier::new(2));
            let ended = Arc::new(AtomicBool::new(false));
            let ends = {
                let (start, ended) = (start.clone(), ended.clone());
                thread::spawn(move || {
                    start.wait();
                    drop(request);
                    ended.store(true, Ordering::SeqCst);
                })
            };
            let polls = thread::spawn(move || -> io::Result<()> {
                let mut cx = Context::from_waker(Waker::noop());
                start.wait();
                loop {
                    let done = ended.load(Ordering::SeqCst);
                    stream.check(&mut cx)?;
                    if done {
                        return Ok(());
                    }
                }
            });
            ends.join().expect("the request ends");
            polls
                .join()
                .expect("the polls end")
                .expect("a poll met the idle time from before the request");
        }
    }

    /// A request that starts after the connection's state is read and before its timer is polled
    /// is a request in progress, even when the timer reports that the deadline has passed: the
    /// connection is not closed inside the request's own deadline, and its idle time then runs from
    /// the end of the request. The request may also end between the read and the poll, which gives
    /// the connection a new idle time as well.
    async fn a_request_starts_as_the_deadline_passes(ends_before_the_poll: bool) {
        type Answer = <Tracked<Gated> as Service<()>>::Future;

        let (_client, mut stream, service, _gate) = accepted().await;
        let request: Arc<Mutex<Option<Answer>>> = Arc::default();
        stream.after_read = Some(Box::new({
            let (mut service, request) = (service, request.clone());
            move || {
                let answer = service.call(());
                if !ends_before_the_poll {
                    *request.lock().unwrap() = Some(answer);
                }
            }
        }));

        advance(IDLE_TIMEOUT + Duration::from_secs(1)).await;
        let mut cx = Context::from_waker(Waker::noop());
        stream
            .check(&mut cx)
            .expect("a connection with a request was met with the idle time-out");

        // The request ends 31 seconds after the connection opened, and the bound runs from there.
        drop(request.lock().unwrap().take());
        advance(IDLE_TIMEOUT - Duration::from_secs(1)).await;
        stream
            .check(&mut cx)
            .expect("closed before the bound ran from the end of the request");
        advance(Duration::from_secs(2)).await;
        let error = stream.check(&mut cx).expect_err("not closed at the bound");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test(start_paused = true)]
    async fn a_request_that_starts_as_the_deadline_passes_keeps_the_connection() {
        a_request_starts_as_the_deadline_passes(false).await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_request_that_starts_and_ends_as_the_deadline_passes_gives_a_new_idle_time() {
        a_request_starts_as_the_deadline_passes(true).await;
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

    /// A stream that never completes a read, a write, a flush or a shutdown, as one whose peer has
    /// stopped reading while its send buffer is full. It never wakes the task either, so only the
    /// idle bound's own timer can end an operation on it.
    struct Blocked;

    impl AsyncRead for Blocked {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for Blocked {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _bufs: &[io::IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }

        fn is_write_vectored(&self) -> bool {
            true
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    /// Runs `operation` on a stream whose inner stream never completes it. The operation stays
    /// pending until the bound, and then ends with a time-out whatever the inner stream is doing.
    async fn a_blocked_operation_ends_at_the_bound<Operation, Output>(operation: Operation)
    where
        Operation: FnOnce(IdleStream<Blocked>) -> Output,
        Output: Future<Output = io::Result<()>> + Send + 'static,
    {
        let (stream, _service) =
            IdleBound::new(DefaultAcceptor, Connections::new(1, Default::default()))
                .accept(Blocked, ())
                .await
                .expect("the acceptor passes the connection on");
        let operation = tokio::spawn(operation(stream));

        advance(IDLE_TIMEOUT - Duration::from_secs(1)).await;
        assert!(!operation.is_finished(), "ended before the bound");

        advance(Duration::from_secs(2)).await;
        let error = timeout(Duration::from_secs(1), operation)
            .await
            .expect("still pending after the bound")
            .expect("the operation's task ends")
            .expect_err("the operation succeeded");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test(start_paused = true)]
    async fn a_read_that_stays_pending_ends_at_the_bound() {
        a_blocked_operation_ends_at_the_bound(|mut stream| async move {
            stream.read(&mut [0u8; 1]).await.map(drop)
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_write_that_stays_pending_ends_at_the_bound() {
        a_blocked_operation_ends_at_the_bound(|mut stream| async move {
            stream.write(b"x").await.map(drop)
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_vectored_write_that_stays_pending_ends_at_the_bound() {
        a_blocked_operation_ends_at_the_bound(|mut stream| async move {
            stream
                .write_vectored(&[io::IoSlice::new(b"x")])
                .await
                .map(drop)
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_flush_that_stays_pending_ends_at_the_bound() {
        a_blocked_operation_ends_at_the_bound(|mut stream| async move { stream.flush().await })
            .await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_shutdown_that_stays_pending_ends_at_the_bound() {
        a_blocked_operation_ends_at_the_bound(|mut stream| async move { stream.shutdown().await })
            .await;
    }

    /// An acceptor whose handshake never ends.
    #[derive(Clone)]
    struct Stalled;

    impl<I: Send + 'static, S: Send + 'static> Accept<I, S> for Stalled {
        type Stream = DuplexStream;
        type Service = S;
        type Future = Pin<Box<dyn Future<Output = io::Result<(DuplexStream, S)>> + Send>>;

        fn accept(&self, _stream: I, _service: S) -> Self::Future {
            Box::pin(std::future::pending())
        }
    }

    /// An acceptor whose handshake fails.
    #[derive(Clone)]
    struct Failing;

    impl<I: Send + 'static, S: Send + 'static> Accept<I, S> for Failing {
        type Stream = DuplexStream;
        type Service = S;
        type Future = Pin<Box<dyn Future<Output = io::Result<(DuplexStream, S)>> + Send>>;

        fn accept(&self, _stream: I, _service: S) -> Self::Future {
            Box::pin(std::future::ready(Err(io::Error::other(
                "handshake failed",
            ))))
        }
    }

    fn connections(most: usize) -> (Arc<Connections>, Arc<Metrics>) {
        let metrics = Arc::new(Metrics::default());
        (Connections::new(most, metrics.clone()), metrics)
    }

    #[tokio::test]
    async fn the_connection_past_the_most_is_refused_and_the_others_stay() {
        let (connections, metrics) = connections(2);
        let bound = IdleBound::new(DefaultAcceptor, connections.clone());

        let mut held = Vec::new();
        for _ in 0..2 {
            let (client, server) = tokio::io::duplex(64);
            let accepted = bound.accept(server, ()).await;
            assert!(accepted.is_ok(), "a connection under the most was refused");
            held.push((client, accepted));
        }
        let (mut client, server) = tokio::io::duplex(64);
        let refused = bound.accept(server, ()).await;
        assert_eq!(
            refused.err().map(|error| error.kind()),
            Some(io::ErrorKind::ConnectionRefused)
        );
        assert_eq!(connections.held(), 2);
        assert_eq!(metrics.http_connections_refused.get(), 1);

        // The refused connection is closed: its peer reads the end of the stream.
        let mut byte = [0u8; 1];
        assert_eq!(client.read(&mut byte).await.expect("read"), 0);
    }

    #[tokio::test]
    async fn a_slot_comes_free_when_a_held_connection_ends() {
        let (connections, metrics) = connections(1);
        let bound = IdleBound::new(DefaultAcceptor, connections.clone());

        let (_client, server) = tokio::io::duplex(64);
        let first = bound.accept(server, ()).await.expect("the first");
        let (_client, server) = tokio::io::duplex(64);
        assert!(bound.accept(server, ()).await.is_err());

        drop(first);
        assert_eq!(connections.held(), 0);
        let (_client, server) = tokio::io::duplex(64);
        assert!(bound.accept(server, ()).await.is_ok());
        assert_eq!(metrics.http_connections_refused.get(), 1);
    }

    #[tokio::test]
    async fn a_handshake_that_fails_or_is_cancelled_gives_its_slot_back() {
        let (connections, _metrics) = connections(1);

        let (_client, server) = tokio::io::duplex(64);
        let failed = IdleBound::new(Failing, connections.clone()).accept(server, ());
        assert_eq!(connections.held(), 1, "the handshake holds a slot");
        assert!(failed.await.is_err());
        assert_eq!(connections.held(), 0, "a failed handshake kept its slot");

        let (_client, server) = tokio::io::duplex(64);
        let stalled = tokio::spawn(IdleBound::new(Stalled, connections.clone()).accept(server, ()));
        tokio::task::yield_now().await;
        assert_eq!(connections.held(), 1, "the handshake holds a slot");
        stalled.abort();
        let ended = stalled.await.err().expect("the task was aborted");
        assert!(ended.is_cancelled());
        assert_eq!(connections.held(), 0, "a cancelled handshake kept its slot");
    }
}
