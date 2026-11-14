//! A bound on how long a connection may stand with no request in progress.
//!
//! hyper bounds the header read of an HTTP/1 request, but a connection that sends nothing after
//! its handshake, and an HTTP/2 connection that has no request open, are never closed by it.
//! [`IdleBound`] wraps an acceptor and closes a connection that has had no request in progress
//! for [`IDLE_TIMEOUT`], counted from the end of the handshake or from the end of the last
//! request. Bytes that arrive without starting a request, such as the pings of an idle HTTP/2
//! connection, do not extend it. A request in progress is bounded by its own deadline. A connection
//! may also read only [`READ_BOUND`] bytes between two request starts, counted after its handshake,
//! and [`LIFETIME_READ_BOUND`] in its life, after which it is shut down gracefully and ended within
//! [`DRAIN_TIMEOUT`].

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
use http::{
    Request, Response, Version,
    header::{CONNECTION, HeaderValue},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::Notify,
    time::{Instant, Sleep},
};
use tower_service::Service;

use crate::metrics::Metrics;

/// How long a connection may stand with no request in progress.
pub(super) const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// The most bytes a connection may read between two request starts, and before its first, whatever
/// requests are in progress: 24,576, three times the head allowance. The bytes are those that the
/// connection reads after its handshake, decrypted ones on a TLS listener; the handshake has a
/// figure of its own, `tls::HANDSHAKE_READ_BOUND`. A request starts when the service is first
/// polled, which for HTTP/2 is after hyper has spawned the task of the stream, and the count begins
/// again there. So the bytes that hyper has read ahead of a start count towards the interval before
/// it: the body of the same request, and the heads of the next two requests, which HTTP/2 allows
/// open at once.
///
/// An honest interval at the largest sizes is two HTTP/2 heads of 8,192 bytes read ahead (16,400),
/// the tail of the body before them (4,096 and its frame headers, about 4,100) and the first
/// settings and window frames, about 20.6 kB, so the figure leaves about 4 kB over; on HTTP/1 it is
/// at most 4,096 + 8,192 + 4,096, about 16.4 kB, and ordinary traffic is near 13 to 16 kB. A legal
/// shape does not fit: two POSTs at once, each with a head near 8,191 bytes and a body of 4,096,
/// come to about 24.6 kB, and the connection that sends them is closed, as a POST's head is a few
/// hundred bytes in practice.
///
/// It is a threshold at which the connection is closed, not a ceiling on what the server holds.
/// Bytes read before a start stay in what hyper has buffered for the other requests; no read takes
/// more than the one byte that passes the threshold, which ends the connection; and the socket's
/// buffers and those of the TLS and HTTP libraries lie outside it. What it bounds is what hyper keeps raw for a
/// request that has not started: HTTP/2 keeps a header block as it arrives until its last frame,
/// and `HEADERS` with five `CONTINUATION` frames of 16,384 bytes that do not end the block is not
/// a stream, so the limit on streams and the header list limit do not count it. A connection that
/// reads more is closed, and its client meets a connection that ends with no status, as with the
/// idle bound.
pub(super) const READ_BOUND: usize = 3 * super::REQUEST_HEAD_LIMIT;

/// The most bytes a connection may read in its life before it is shut down gracefully: 65,536,
/// counted as [`READ_BOUND`] counts them. It bounds what a connection may send in its life, so that
/// nothing that a connection makes the server keep can grow with the connection's age: what the
/// server keeps for a connection came in the bytes that the peer sent, and the peer may send this
/// many, and the bytes after it that the rules below allow. The figure was taken from the group's
/// peak with the cap of connections, each of them in the shapes that held the most (the table in
/// `FORK.md`).
///
/// When the count passes this figure the connection's own task calls the graceful shutdown of the
/// HTTP library (`serve::drive`) at the first moment a request is in progress: at the crossing if
/// one is, otherwise when the next request starts. The library tells the client and ends the
/// connection once the answers are out: over HTTP/2 with a `GOAWAY`, a `PING` and a second
/// `GOAWAY` that names the last stream it accepted, over HTTP/1 with `Connection: close` on the
/// answer, which [`Tracked`] adds. The requests in progress, and those that start before the client
/// has read the news, are served and their answers sent; none is refused. A head in transit when
/// the figure is passed, with no request in progress, is not cut: it completes under the ordinary
/// times and is the first request after the figure. The bytes that carried the figure make no
/// difference: it may be passed in the head of a request, in its body, or in bytes that start no
/// request.
///
/// - **Time.** The call starts a timer of [`DRAIN_TIMEOUT`]. A connection that is still open when
///   it ends is dropped, with no `close_notify`, and is counted in
///   `http_connections_drain_timeouts`. The counter holds the connections that reached the 20
///   seconds, whatever the cause: an answer that the client holds back through its flow-control
///   window or a slow link, a body or a handler that runs on, a request accepted late in the
///   drain, a head that stays in transit, and a client that never acknowledges the `PING`, which
///   leaves the connection standing until the timer. The byte stop below is not counted.
/// - **Bytes.** The read that carries the figure ends at the byte that passes it, the 65,537th of
///   the connection's life, and the connection reads at most [`READ_BOUND`] bytes in all from the
///   figure's first byte: 24,575 more, and the 90,113th byte ends it with no further notice. The
///   count is that of the connection's life, so a request start does not begin it again. Every byte
///   that the wrapper reads counts, control frames after the first `GOAWAY` included.
/// - **Time after the figure.** A connection that passed the figure with no request in progress
///   stands under the ordinary idle time, [`IDLE_TIMEOUT`] from its last request, until a request
///   starts, and then for [`DRAIN_TIMEOUT`] from the call.
///
/// What the rules do not promise, each with a case in `http.rs`:
///
/// - **Requests that cannot finish in the 20 seconds.** A request that the service accepted and
///   that is not finished by then is cut with its connection. That holds for an answer that the
///   client's window or a slow link holds back, a body or a handler that runs on, and a request
///   accepted late in the drain, with its body and its handler. Over HTTP/2 the library goes on
///   accepting streams until the client has acknowledged the `PING`. The client meets a connection
///   that ends with no `close_notify`. A `GOAWAY` that the protocol sends is not a promise about the
///   result of such a request: a replay that the protocol authorises is one thing, and an
///   application's retry after an uncertain result is another, and it depends on whether the
///   operation tolerates being repeated. The byte stop can leave an uncertain result in the same way.
/// - **A head in transit.** A head that stays in transit for more than 20 seconds after the call,
///   beside a request in progress, is cut with the connection.
/// - **Bytes after the figure.** More than 24,575 bytes after the byte that passes the figure end
///   the connection, whatever they carry, including control frames after the first `GOAWAY`.
/// - **Two cuts that are not new.** An answer that the client's window blocks and that is not
///   delivered ends at the idle bound of 30 seconds after its handler has returned. Over HTTP/1 a
///   request that the client pipelined behind the closing answer is not answered.
///
/// A client that keeps one connection for many requests is told, after about this many bytes of
/// requests, to continue on a new one. A client that has more requests waiting than a connection's
/// 2 streams can get an error for a waiting request when the connection reaches the figure, and it
/// sends the request again. The product's own client speaks HTTP/1 and reads `Connection: close`.
pub(super) const LIFETIME_READ_BOUND: usize = 64 * 1024;

/// How long a connection may stand after its graceful shutdown has begun: 20 seconds from the
/// call. A request that starts just before the client reads the shutdown has its own deadline of
/// 10 seconds, and 10 seconds remain for the acknowledgement and the delivery.
pub(super) const DRAIN_TIMEOUT: Duration = Duration::from_secs(20);

/// The most bytes a connection may read in its life: [`LIFETIME_READ_BOUND`] and the interval
/// that follows it.
pub(super) const HARD_READ_BOUND: usize = LIFETIME_READ_BOUND + READ_BOUND;

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

    /// The server's metrics, which the connections of this cap report to.
    pub(super) fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
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

/// What a connection's stream and its service both see. The count of requests in progress, the
/// time the connection last had none, the bytes read since a request last started and the note that
/// the drain signal was raised change together, under one lock, so that a reader never sees the
/// count at zero with the time from before the request, or a count of bytes that a start has not
/// yet cleared.
#[derive(Debug)]
pub(super) struct Shared {
    state: Mutex<State>,
    /// Raised once, when the connection is to begin its graceful shutdown. It is raised after the
    /// state's lock is released, and `notify_one` leaves a permit if the connection's task has not
    /// parked on it yet.
    pub(super) drain: Notify,
}

#[derive(Debug)]
struct State {
    /// The requests that have been handed to the service and have not been answered.
    in_flight: usize,
    /// When the connection last had no request in progress.
    idle_since: Instant,
    /// The bytes read since the last request started, or since the connection began.
    read: usize,
    /// The bytes read in the connection's life.
    lifetime: usize,
    /// The drain signal has been raised: once, at the crossing of [`LIFETIME_READ_BOUND`] with a
    /// request in progress, or at the first request that starts after it.
    drain_raised: bool,
    /// The task that waits for the connection's last request to end.
    waker: Option<Waker>,
}

impl State {
    /// Whether the connection has read more than [`LIFETIME_READ_BOUND`].
    fn spent(&self) -> bool {
        self.lifetime > LIFETIME_READ_BOUND
    }

    /// When the connection ends if no request starts: after [`IDLE_TIMEOUT`] of having none in
    /// progress.
    fn deadline(&self) -> Instant {
        self.idle_since + IDLE_TIMEOUT
    }

    /// Whether the signal is due and has not been raised, and notes it as raised if so. The caller
    /// raises it once it has released the lock.
    fn take_raise(&mut self) -> bool {
        let due = self.spent() && self.in_flight > 0 && !self.drain_raised;
        self.drain_raised |= due;
        due
    }
}

impl Shared {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            drain: Notify::new(),
            state: Mutex::new(State {
                in_flight: 0,
                idle_since: Instant::now(),
                read: 0,
                lifetime: 0,
                drain_raised: false,
                waker: None,
            }),
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// How many bytes the next read may take: up to the byte that passes [`READ_BOUND`] since the
    /// last start, and up to the byte that passes the stop of the connection's life, which is
    /// [`LIFETIME_READ_BOUND`] until it is passed and [`HARD_READ_BOUND`] after. The byte that
    /// passes either is the one that ends the connection, so a read that carries the figure ends
    /// at it. At least one, so that a read always makes progress towards the end.
    fn read_room(&self) -> usize {
        let state = self.state();
        let stop = if state.spent() {
            HARD_READ_BOUND
        } else {
            LIFETIME_READ_BOUND
        };
        (READ_BOUND + 1)
            .saturating_sub(state.read)
            .min((stop + 1).saturating_sub(state.lifetime))
            .max(1)
    }

    /// Counts `bytes` read, and fails once more than [`READ_BOUND`] have been read since the last
    /// request started or more than [`HARD_READ_BOUND`] in the connection's life. The read that
    /// takes the connection past [`LIFETIME_READ_BOUND`] while requests are in progress raises the
    /// drain signal, after the lock is released.
    fn count_read(&self, bytes: usize) -> io::Result<()> {
        let mut state = self.state();
        state.read = state.read.saturating_add(bytes);
        state.lifetime = state.lifetime.saturating_add(bytes);
        let raise = state.take_raise();
        let over = state.read > READ_BOUND || state.lifetime > HARD_READ_BOUND;
        drop(state);
        if raise {
            self.drain.notify_one();
        }
        if over {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "connection read more than it may",
            ));
        }
        Ok(())
    }
}

/// A request in progress. The connection counts as busy until this is dropped.
struct InFlight(Arc<Shared>);

impl InFlight {
    /// Counts the request that starts now. The first request that starts once the figure has been
    /// passed raises the drain signal, after the lock is released; the request is served.
    fn begin(shared: &Arc<Shared>) -> Self {
        let mut state = shared.state();
        state.in_flight += 1;
        state.read = 0;
        let raise = state.take_raise();
        drop(state);
        if raise {
            shared.drain.notify_one();
        }
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

/// A connection's service, which tells the connection's stream when a request starts and ends, and
/// starts the drain when a request starts after the connection has read its
/// [`LIFETIME_READ_BOUND`]. It refuses no request: the library's graceful shutdown tells the client.
/// Over HTTP/1 it adds `Connection: close` to the answer of a request that is answered once the
/// figure is passed, because a connection with no request in progress is closed by the library at
/// once, and an answer that starts and ends before that call would not carry it. HTTP/2 has no
/// connection header: the `GOAWAY` frames of the shutdown carry the news.
#[derive(Clone, Debug)]
pub(super) struct Tracked<S> {
    inner: S,
    shared: Arc<Shared>,
}

impl<S, B, ResBody> Service<Request<B>> for Tracked<S>
where
    S: Service<Request<B>, Response = Response<ResBody>>,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ResBody: Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response<ResBody>, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let in_flight = InFlight::begin(&self.shared);
        let says_close = request.version() != Version::HTTP_2;
        let shared = self.shared.clone();
        let answer = self.inner.call(request);
        Box::pin(async move {
            let _in_flight = in_flight;
            let mut response = answer.await?;
            if says_close && shared.state().spent() {
                response
                    .headers_mut()
                    .insert(CONNECTION, HeaderValue::from_static("close"));
            }
            Ok(response)
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
    /// The state is not held while the timer is polled. hyper starts a request from the
    /// connection's own task, the task that runs this check, and a request can end only after one
    /// has started, so in a real run nothing changes the state between the read and the poll. When
    /// the timer reports that the deadline has passed, the state is read again under the lock all
    /// the same, as a safeguard: the connection ends only if it still has no request in progress
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
                state.deadline()
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
            if state.in_flight == 0 && state.deadline() == deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "connection idle with no request in progress",
                ));
            }
        }
    }
}

/// A stream that shares its connection's state with the connection's service, so that whoever
/// drives the connection can wait for the signal to begin its graceful shutdown.
pub(super) trait Watched {
    fn shared(&self) -> Arc<Shared>;
}

impl<T> Watched for IdleStream<T> {
    fn shared(&self) -> Arc<Shared> {
        self.shared.clone()
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
        // The read takes no more than the byte that ends the connection, whatever the reader
        // offers, so the bytes that a connection reads past its bounds are exact.
        let room = this.shared.read_room().min(buf.remaining());
        let mut offered = ReadBuf::new(buf.initialize_unfilled_to(room));
        let polled = Pin::new(&mut this.inner).poll_read(cx, &mut offered);
        let taken = offered.filled().len();
        buf.advance(taken);
        if let Poll::Ready(Ok(())) = polled {
            this.shared.count_read(taken)?;
        }
        polled
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

    use http::{Request, Response, header::CONNECTION};

    use super::*;

    /// A service whose answers wait for a signal, and which counts the requests that it is given.
    #[derive(Clone)]
    struct Gated {
        gate: Arc<Notify>,
        calls: Arc<AtomicUsize>,
    }

    impl Gated {
        fn new(gate: Arc<Notify>) -> Self {
            Self {
                gate,
                calls: Arc::default(),
            }
        }
    }

    impl Service<Request<()>> for Gated {
        type Response = Response<()>;
        type Error = Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Response<()>, Infallible>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _request: Request<()>) -> Self::Future {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let gate = self.gate.clone();
            Box::pin(async move {
                gate.notified().await;
                Ok(Response::new(()))
            })
        }
    }

    fn a_request() -> Request<()> {
        Request::new(())
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
                .accept(server, Gated::new(gate.clone()))
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

        let answer = tokio::spawn(service.call(a_request()));
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

        let answer = service.call(a_request());
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
        type Answer = <Tracked<Gated> as Service<Request<()>>>::Future;

        let (_client, mut stream, service, _gate) = accepted().await;
        let request: Arc<Mutex<Option<Answer>>> = Arc::default();
        stream.after_read = Some(Box::new({
            let (mut service, request) = (service, request.clone());
            move || {
                let answer = service.call(a_request());
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

    /// Reads `count` bytes from the stream, a kilobyte at a time, as a client's bytes arrive.
    async fn read_bytes(
        client: &mut DuplexStream,
        stream: &mut IdleStream<DuplexStream>,
        count: usize,
    ) -> io::Result<()> {
        let mut left = count;
        while left > 0 {
            let chunk = left.min(1_024);
            client.write_all(&vec![0; chunk]).await?;
            stream.read_exact(&mut vec![0; chunk]).await?;
            left -= chunk;
        }
        Ok(())
    }

    /// A connection reads up to the bound between two request starts and is closed past it,
    /// with no request in progress and with one that is held open.
    #[tokio::test]
    async fn a_connection_that_reads_past_the_bound_is_closed() {
        for requests_held in [0, 1] {
            let (mut client, mut stream, mut service, _gate) = accepted().await;
            let held: Vec<_> = (0..requests_held)
                .map(|_| service.call(a_request()))
                .collect();
            read_bytes(&mut client, &mut stream, READ_BOUND)
                .await
                .expect("the bound's own bytes were refused");
            let error = read_bytes(&mut client, &mut stream, 1)
                .await
                .expect_err("a byte past the bound was read");
            assert_eq!(
                error.kind(),
                io::ErrorKind::InvalidData,
                "with {requests_held} requests held"
            );
            drop(held);
        }
    }

    /// The count begins again when a request starts: a connection may read the bound's worth of
    /// bytes before each start, so long as it stays under the figure of its life.
    #[tokio::test]
    async fn the_count_of_bytes_begins_again_at_each_request_start() {
        let (mut client, mut stream, mut service, _gate) = accepted().await;
        for _ in 0..2 {
            read_bytes(&mut client, &mut stream, READ_BOUND)
                .await
                .expect("the bytes before a start were refused");
            drop(service.call(a_request()));
        }
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

    /// A request that reads 1,024 bytes of the connection, starts, and is answered.
    /// Reads the bytes of a small request, runs the request to its answer, and gives the answer.
    async fn small_request(
        client: &mut DuplexStream,
        stream: &mut IdleStream<DuplexStream>,
        service: &mut Tracked<Gated>,
        gate: &Notify,
    ) -> io::Result<Response<()>> {
        read_bytes(client, stream, 1_024).await?;
        let answer = tokio::spawn(service.call(a_request()));
        gate.notify_one();
        Ok(answer
            .await
            .expect("the answer task ends")
            .expect("the request was not answered"))
    }

    /// Whether an answer tells its client that the connection closes after it.
    fn closes(answer: &Response<()>) -> bool {
        answer
            .headers()
            .get(CONNECTION)
            .is_some_and(|value| value == "close")
    }

    /// Puts a connection 100 bytes short of its budget, where the cases below start.
    fn near_the_budget(stream: &IdleStream<DuplexStream>) {
        stream.shared.state().lifetime = LIFETIME_READ_BOUND - 100;
    }

    fn calls(service: &Tracked<Gated>) -> usize {
        service.inner.calls.load(Ordering::SeqCst)
    }

    /// Small requests one after another across the connection's figure: the answers to the
    /// requests that start once the figure is passed say that the connection closes, the ones
    /// before it do not, and every request is served, the handler of each run once.
    #[tokio::test]
    async fn the_answers_after_the_figure_say_that_the_connection_closes() {
        let (mut client, mut stream, mut service, gate) = accepted().await;
        let mut answered = 0;
        loop {
            let answer = small_request(&mut client, &mut stream, &mut service, &gate)
                .await
                .expect("a request was not answered");
            answered += 1;
            let spent = stream.shared.state().spent();
            assert_eq!(
                closes(&answer),
                spent,
                "answer {answered}, with the figure passed: {spent}"
            );
            if spent {
                break;
            }
            assert!(answered < 10_000, "the figure was never passed");
        }
        assert_eq!(answered, LIFETIME_READ_BOUND / 1_024 + 1);

        // A request after the figure is served too: nothing is refused, and its answer says so.
        read_bytes(&mut client, &mut stream, 1_024)
            .await
            .expect("the bytes of the next request were refused");
        let next = tokio::spawn(service.call(a_request()));
        gate.notify_one();
        let answer = next
            .await
            .expect("the answer task ends")
            .expect("a request after the figure was not answered");
        assert!(closes(&answer));
        assert_eq!(calls(&service), answered + 1, "a handler did not run");

        let (mut client, mut stream, mut service, gate) = accepted().await;
        small_request(&mut client, &mut stream, &mut service, &gate)
            .await
            .expect("a new connection refused its first request");
    }

    /// A connection that has passed its figure, whose last request has ended and that sends
    /// nothing more stands under the ordinary idle time, and gives back its place when it ends.
    #[tokio::test(start_paused = true)]
    async fn a_silent_connection_that_has_passed_its_figure_ends_at_the_idle_time() {
        let (mut client, server) = tokio::io::duplex(1024);
        let connections = Connections::new(1, Default::default());
        let bound = IdleBound::new(DefaultAcceptor, connections.clone());
        let gate = Arc::new(Notify::new());
        let (mut stream, mut service): (IdleStream<DuplexStream>, Tracked<Gated>) = bound
            .accept(server, Gated::new(gate.clone()))
            .await
            .expect("the acceptor passes the connection on");
        near_the_budget(&stream);
        read_bytes(&mut client, &mut stream, 200)
            .await
            .expect("the head that passes the figure was refused");
        let first = tokio::spawn(service.call(a_request()));
        gate.notify_one();
        first
            .await
            .expect("the answer task ends")
            .expect("the request that passes the figure was refused");

        advance(IDLE_TIMEOUT - Duration::from_secs(1)).await;
        assert!(
            read_ends(&mut stream).await.is_none(),
            "closed before the idle time"
        );
        advance(Duration::from_secs(2)).await;
        let error = read_ends(&mut stream)
            .await
            .expect("not closed at the idle time");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        drop((stream, client));
        assert_eq!(connections.held(), 0);
        let (_client, server) = tokio::io::duplex(1024);
        bound
            .accept(server, Gated::new(Arc::new(Notify::new())))
            .await
            .expect("the place was not given back");
    }

    /// A read is cut at the bound: whatever size the reader offers, the connection takes one byte
    /// past [`READ_BOUND`] between two starts, the byte that ends it, and no more.
    #[tokio::test]
    async fn a_read_takes_no_more_than_one_byte_past_the_bound() {
        let (mut client, server) = tokio::io::duplex(4 * READ_BOUND);
        let (mut stream, _service): (IdleStream<DuplexStream>, Tracked<Gated>) =
            IdleBound::new(DefaultAcceptor, Connections::new(1, Default::default()))
                .accept(server, Gated::new(Arc::new(Notify::new())))
                .await
                .expect("the acceptor passes the connection on");
        client
            .write_all(&vec![0; 2 * READ_BOUND])
            .await
            .expect("the write of the peer");
        let error = stream
            .read(&mut vec![0; 2 * READ_BOUND])
            .await
            .expect_err("a read past the bound was answered");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let mut left = Vec::new();
        drop(client);
        stream.inner.read_to_end(&mut left).await.unwrap();
        assert_eq!(
            left.len(),
            READ_BOUND - 1,
            "bytes left unread by the stream"
        );
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

    /// Whether the connection's drain signal has been raised, taking it if so.
    async fn drain_raised(shared: &Shared) -> bool {
        tokio::select! {
            biased;
            () = shared.drain.notified() => true,
            () = std::future::ready(()) => false,
        }
    }

    /// The read that carries the lifetime figure ends at the byte that passes it, and from there a
    /// connection reads at most [`READ_BOUND`] bytes in all, 24,575 more than that byte, however
    /// many requests start meanwhile.
    #[tokio::test]
    async fn the_read_that_carries_the_figure_ends_at_it_and_the_hard_bound_holds_across_starts() {
        let (mut client, mut stream, mut service, _gate) = accepted().await;
        stream.shared.state().lifetime = LIFETIME_READ_BOUND - 100;
        client
            .write_all(&[0; 1_024])
            .await
            .expect("the client writes");
        let mut buf = [0u8; 1_024];
        let taken = stream.read(&mut buf).await.expect("the crossing read");
        assert_eq!(
            taken, 101,
            "the read that carries the figure ends at the byte that passes it"
        );
        let mut left = HARD_READ_BOUND - (LIFETIME_READ_BOUND + 1);
        assert_eq!(left, 24_575);
        // The rest of what the client wrote is in the pipe, and counts as well.
        stream
            .read_exact(&mut vec![0; 1_024 - 101])
            .await
            .expect("the rest of the crossing write was refused");
        left -= 1_024 - 101;
        while left > 0 {
            let chunk = left.min(8_191);
            read_bytes(&mut client, &mut stream, chunk)
                .await
                .expect("a byte within the hard bound was refused");
            drop(service.call(a_request()));
            left -= chunk;
        }
        let error = read_bytes(&mut client, &mut stream, 1)
            .await
            .expect_err("a byte past the hard bound was read");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    /// A crossing with a request in progress raises the drain signal at the crossing, and not
    /// before it.
    #[tokio::test]
    async fn a_crossing_with_a_request_in_progress_raises_the_drain_signal_at_the_crossing() {
        let (mut client, mut stream, mut service, _gate) = accepted().await;
        stream.shared.state().lifetime = LIFETIME_READ_BOUND - 10;
        let held = service.call(a_request());
        let shared = stream.shared.clone();
        assert!(!drain_raised(&shared).await);
        read_bytes(&mut client, &mut stream, 10)
            .await
            .expect("bytes under the figure");
        assert!(
            !drain_raised(&shared).await,
            "raised before the figure was passed"
        );
        read_bytes(&mut client, &mut stream, 1)
            .await
            .expect("the byte that passes the figure");
        assert!(drain_raised(&shared).await, "not raised at the crossing");
        drop(held);
    }

    /// A crossing with no request in progress raises it at the next start.
    #[tokio::test]
    async fn a_crossing_with_no_request_in_progress_raises_the_drain_signal_at_the_next_start() {
        let (mut client, mut stream, mut service, _gate) = accepted().await;
        stream.shared.state().lifetime = LIFETIME_READ_BOUND - 10;
        read_bytes(&mut client, &mut stream, 11)
            .await
            .expect("bytes across the figure");
        let shared = stream.shared.clone();
        assert!(!drain_raised(&shared).await, "raised with no request");
        let held = service.call(a_request());
        assert!(
            drain_raised(&shared).await,
            "not raised at the start after the crossing"
        );
        drop(held);
    }

    /// Bytes that start no request never raise it.
    #[tokio::test]
    async fn bytes_that_start_no_request_never_raise_the_drain_signal() {
        let (mut client, mut stream, _service, _gate) = accepted().await;
        stream.shared.state().lifetime = LIFETIME_READ_BOUND - 10;
        let shared = stream.shared.clone();
        for _ in 0..3 {
            read_bytes(&mut client, &mut stream, 3_000)
                .await
                .expect("bytes");
            assert!(!drain_raised(&shared).await, "raised with no request");
        }
    }

    /// It is raised once, whatever starts after it.
    #[tokio::test]
    async fn the_drain_signal_is_raised_once() {
        let (mut client, mut stream, mut service, _gate) = accepted().await;
        stream.shared.state().lifetime = LIFETIME_READ_BOUND - 10;
        let held = service.call(a_request());
        let shared = stream.shared.clone();
        read_bytes(&mut client, &mut stream, 11)
            .await
            .expect("bytes across the figure");
        assert!(drain_raised(&shared).await, "not raised at the crossing");
        let second = service.call(a_request());
        assert!(
            !drain_raised(&shared).await,
            "raised again by a later start"
        );
        drop((held, second));
    }
}
