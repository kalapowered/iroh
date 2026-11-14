//! A bound on how long a connection may stand with no request in progress.
//!
//! hyper bounds the header read of an HTTP/1 request, but a connection that sends nothing after
//! its handshake, and an HTTP/2 connection that has no request open, are never closed by it.
//! [`IdleBound`] wraps an acceptor and closes a connection that has had no request in progress
//! for [`IDLE_TIMEOUT`], counted from the end of the handshake or from the end of the last
//! request. Bytes that arrive without starting a request, such as the pings of an idle HTTP/2
//! connection, do not extend it. A request in progress is bounded by its own deadline. A connection
//! may also read only [`READ_BOUND`] bytes between two request starts, counted after its handshake,
//! and [`LIFETIME_READ_BOUND`] in its life, after which it takes no further request.

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

/// The most bytes a connection may read in its life, counted as [`READ_BOUND`] counts them:
/// 65,536. It bounds what a connection may send in its life, so that nothing that a connection
/// makes the server keep can grow with the connection's age: what the server keeps for a
/// connection came in the bytes that the peer sent, and the peer may send this many, and the
/// bytes after it that the rules below allow. The figure was taken from the group's peak with the
/// cap of connections, each of them in the shapes that held the most (the table in `FORK.md`).
///
/// When the count passes this figure the connection serves the requests that are in progress at
/// that moment or, when none is, the first request that starts, and refuses every request that
/// starts after those. The bytes that carried the figure make no difference: it may be passed in
/// the head of a request, in its body, or in bytes that start no request.
///
/// - **Refusal.** A refused request does not reach its handler. Over HTTP/2 its stream is reset
///   with `REFUSED_STREAM`, which tells the client that the request was not processed and may be
///   sent again; over HTTP/1 the answer to the last request served says `Connection: close`, so
///   the client opens a new connection for its next request. A connection that refuses a request
///   with no other in progress ends at the first flush that follows the next write after the
///   refusal. That write is usually the reset, but the state does not tell it from another
///   write, and a client whose reset did not come first meets a closed connection. With others
///   in progress the connection stands until they have ended, and a request sent again before
///   then is refused again.
/// - **Time.** A connection that takes no further request stands for [`SPENT_IDLE_TIMEOUT`] at
///   most when it has no request in progress, in place of [`IDLE_TIMEOUT`]. The allowance is not
///   zero, because an answer is written after the request that made it has ended. Until then, a
///   connection that passed the figure with no request in progress stands under the ordinary
///   times, as one whose head is in transit does: the stream cannot tell a head from other bytes.
///   So a connection ends at most [`IDLE_TIMEOUT`], then the request deadline (10 seconds), then
///   [`SPENT_IDLE_TIMEOUT`] after the figure is passed, 41 seconds, and gives back its place among
///   the connections.
/// - **Bytes.** The bound between starts ([`READ_BOUND`]) holds as before, counted from the last
///   request served, and no read takes more than the byte that passes it. After the figure a
///   connection reads at most `2 * (READ_BOUND + 1)`, 49,154 bytes: the interval in which the
///   figure was passed, and, when no request was in progress then, the interval of the last
///   request served.
/// - **Limits.** A request counts as in progress until its handler has returned the response,
///   not until the response has been sent whole, so a refusal that comes between the two can end
///   the connection first. A head in transit beside a request in progress when the figure is
///   passed has the ordinary times only until that request ends, and then the allowance. The
///   server sends no `GOAWAY` of its own at the figure.
///
/// A client that keeps one connection for many requests meets a refusal after about this many
/// bytes of requests. Whether it then reaches a new connection without an error depends on its
/// library and on the order of its requests.
pub(super) const LIFETIME_READ_BOUND: usize = 64 * 1024;

/// How long a connection that takes no further request may stand with no request in progress, in
/// place of [`IDLE_TIMEOUT`]. An answer is written after the request that made it has ended.
pub(super) const SPENT_IDLE_TIMEOUT: Duration = Duration::from_secs(1);

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

/// What a connection's stream and its service both see. The count of requests in progress, the
/// time the connection last had none and the bytes read since a request last started change
/// together, under one lock, so that a reader never sees the count at zero with the time from
/// before the request, or a count of bytes that a start has not yet cleared.
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
    /// The bytes read since the last request that was served started, or since the connection
    /// began.
    read: usize,
    /// The bytes read in the connection's life.
    lifetime: usize,
    /// The connection takes no further request: the requests in progress when the budget was
    /// passed are the last ones served, or, if none was in progress, the first one that started
    /// after it is.
    closing: bool,
    /// Where a request that was refused stands, from its answer to the end of the connection.
    refusal: Refusal,
    /// The task that waits for the connection's last request to end.
    waker: Option<Waker>,
}

/// Where a refusal that was made with no other request in progress leads: the connection ends at
/// the first flush that follows the next write after the refusal.
///
/// The state counts that write and that flush, not the reset's own write. The reset is made by
/// the HTTP library from the error that the service returns, and the connection's task writes it
/// after the refusal, so the next write is usually the reset. Any other write that comes first, a
/// response or a control frame, moves the state in its place, and the connection can then end
/// before the reset is written, so that its client meets a closed connection. If no write
/// follows, the connection ends at its allowance. A refusal with other requests in progress does
/// not enter the state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    /// No request was refused with none other in progress.
    None,
    /// A request was refused and no write has been made since.
    Refused,
    /// A write has been made since.
    Written,
    /// That write has been flushed: the connection ends at its next operation.
    Flushed,
}

impl State {
    /// Whether the connection has read more than [`LIFETIME_READ_BOUND`].
    fn spent(&self) -> bool {
        self.lifetime > LIFETIME_READ_BOUND
    }

    /// When the connection ends if no request starts: after [`IDLE_TIMEOUT`] of having none in
    /// progress, or after [`SPENT_IDLE_TIMEOUT`] once it takes no further request.
    fn deadline(&self) -> Instant {
        self.idle_since
            + if self.closing {
                SPENT_IDLE_TIMEOUT
            } else {
                IDLE_TIMEOUT
            }
    }
}

impl Shared {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                in_flight: 0,
                idle_since: Instant::now(),
                read: 0,
                lifetime: 0,
                closing: false,
                refusal: Refusal::None,
                waker: None,
            }),
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// How many bytes the next read may take: one past [`READ_BOUND`] since the last start, which
    /// is the byte that ends the connection.
    fn read_room(&self) -> usize {
        (READ_BOUND + 1).saturating_sub(self.state().read).max(1)
    }

    /// Notes that `bytes` were written: the first write after a refusal moves the state, whatever
    /// it carries. It is usually the refusal's reset.
    fn wrote(&self, bytes: usize) {
        let mut state = self.state();
        if bytes > 0 && state.refusal == Refusal::Refused {
            state.refusal = Refusal::Written;
        }
    }

    /// Notes a flush that has completed. One that follows that write ends the connection at its
    /// next operation, so the task is woken to make one.
    fn flushed(&self, cx: &Context<'_>) {
        let mut state = self.state();
        if state.refusal == Refusal::Written {
            state.refusal = Refusal::Flushed;
            cx.waker().wake_by_ref();
        }
    }

    /// Counts `bytes` read, and fails once more than [`READ_BOUND`] have been read since the last
    /// request started. The read that takes the connection past [`LIFETIME_READ_BOUND`] while
    /// requests are in progress makes them the last ones served.
    fn count_read(&self, bytes: usize) -> io::Result<()> {
        let mut state = self.state();
        state.read = state.read.saturating_add(bytes);
        let spent = state.spent();
        state.lifetime = state.lifetime.saturating_add(bytes);
        if !spent && state.spent() && state.in_flight > 0 {
            state.closing = true;
        }
        if state.read > READ_BOUND {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "connection read more than it may between two requests",
            ));
        }
        Ok(())
    }
}

/// What the connection does with a request that starts.
enum Start {
    /// The request is served: the connection counts as busy until the guard is dropped.
    Served(InFlight),
    /// The request is refused.
    Refused(Refused),
}

/// A request in progress. The connection counts as busy until this is dropped.
struct InFlight(Arc<Shared>);

impl InFlight {
    /// Serves the request that starts now, or refuses it once the connection takes no further
    /// request. The request that starts with the budget passed is the last one served.
    fn begin(shared: &Arc<Shared>) -> Start {
        let mut state = shared.state();
        if state.closing {
            let alone = state.in_flight == 0;
            drop(state);
            return Start::Refused(Refused {
                shared: shared.clone(),
                alone,
            });
        }
        state.in_flight += 1;
        state.read = 0;
        if state.spent() {
            state.closing = true;
        }
        drop(state);
        Start::Served(Self(shared.clone()))
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

/// A request that was refused. It is not in progress and does not hold the connection open. It is
/// dropped when the service's future returns its error, which is before the HTTP library makes
/// the reset from that error. When no other request is in progress then, the connection ends at
/// the first flush that follows the next write.
struct Refused {
    shared: Arc<Shared>,
    /// No other request was in progress when it was refused.
    alone: bool,
}

impl Drop for Refused {
    fn drop(&mut self) {
        let mut state = self.shared.state();
        if self.alone && state.in_flight == 0 && state.refusal == Refusal::None {
            state.refusal = Refusal::Refused;
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

/// The error of a service that refuses a request.
pub(super) type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A connection's service, which tells the connection's stream when a request starts and ends,
/// and refuses the requests that start once the connection has used its budget
/// ([`LIFETIME_READ_BOUND`]).
///
/// A request that is refused does not reach the handlers. Over HTTP/2 the stream is reset with
/// `REFUSED_STREAM`: the client is told that the request was not processed, and it may send it
/// again. The spent connection ends by the rules of [`LIFETIME_READ_BOUND`], so the retry can meet
/// it again. Over HTTP/1 a request is never refused in practice: the answer of
/// the last request served says `Connection: close`, so the client does not send another on that
/// connection.
#[derive(Clone, Debug)]
pub(super) struct Tracked<S> {
    inner: S,
    shared: Arc<Shared>,
}

impl<S, B, ResBody> Service<Request<B>> for Tracked<S>
where
    S: Service<Request<B>, Response = Response<ResBody>>,
    S::Future: Send + 'static,
    S::Error: Into<BoxError>,
    ResBody: Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Response<ResBody>, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        match InFlight::begin(&self.shared) {
            Start::Served(in_flight) => {
                // HTTP/2 has no connection header: the server's library drops it, and the
                // refused streams that follow carry the news.
                let says_close = request.version() != Version::HTTP_2;
                let shared = self.shared.clone();
                let answer = self.inner.call(request);
                Box::pin(async move {
                    let _in_flight = in_flight;
                    let mut response = answer.await.map_err(Into::into)?;
                    if says_close && shared.state().closing {
                        response
                            .headers_mut()
                            .insert(CONNECTION, HeaderValue::from_static("close"));
                    }
                    Ok(response)
                })
            }
            Start::Refused(refused) => Box::pin(async move {
                let _refused = refused;
                Err(h2::Error::from(h2::Reason::REFUSED_STREAM).into())
            }),
        }
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
                if state.refusal == Refusal::Flushed && state.in_flight == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "connection refused a request and its reset has been written",
                    ));
                }
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
        let polled = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = &polled {
            this.shared.wrote(*written);
        }
        polled
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        this.check(cx)?;
        let polled = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(written)) = &polled {
            this.shared.wrote(*written);
        }
        polled
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        this.check(cx)?;
        let polled = Pin::new(&mut this.inner).poll_flush(cx);
        if let Poll::Ready(Ok(())) = polled {
            this.shared.flushed(cx);
        }
        polled
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
    /// bytes before each start, however many bytes it has read in all.
    #[tokio::test]
    async fn the_count_of_bytes_begins_again_at_each_request_start() {
        let (mut client, mut stream, mut service, _gate) = accepted().await;
        for _ in 0..4 {
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
            .expect("the request was refused"))
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

    /// Small requests one after another across the connection's budget: the request that starts
    /// once the budget is passed is answered with the note that the connection closes, the ones
    /// before it are not, and the next request is refused without its handler running.
    #[tokio::test]
    async fn the_last_request_served_says_that_the_connection_closes() {
        let (mut client, mut stream, mut service, gate) = accepted().await;
        let mut answered = 0;
        loop {
            let answer = small_request(&mut client, &mut stream, &mut service, &gate)
                .await
                .expect("a request before the last one was refused");
            answered += 1;
            let spent = stream.shared.state().spent();
            assert_eq!(
                closes(&answer),
                spent,
                "answer {answered}, with the budget passed: {spent}"
            );
            if spent {
                break;
            }
            assert!(answered < 10_000, "the budget was never passed");
        }
        assert_eq!(answered, LIFETIME_READ_BOUND / 1_024 + 1);

        read_bytes(&mut client, &mut stream, 1_024)
            .await
            .expect("the bytes of the next request were refused");
        let refused = service.call(a_request());
        assert_eq!(
            calls(&service),
            answered,
            "the handler of a refused request ran"
        );
        assert!(
            refused.await.is_err(),
            "a request after the last one was answered"
        );

        let (mut client, mut stream, mut service, gate) = accepted().await;
        small_request(&mut client, &mut stream, &mut service, &gate)
            .await
            .expect("a new connection refused its first request");
    }

    /// The head that passes the budget starts a request that is still in progress when the next
    /// request starts and is refused. The first is answered whole: the connection takes reads and
    /// writes while it is in progress, and ends at the allowance after it.
    #[tokio::test(start_paused = true)]
    async fn a_request_in_progress_is_not_cut_by_the_refusal_of_a_later_one() {
        let (mut client, mut stream, mut service, gate) = accepted().await;
        near_the_budget(&stream);
        read_bytes(&mut client, &mut stream, 200)
            .await
            .expect("the head that passes the budget was refused");
        assert!(stream.shared.state().spent());
        let first = tokio::spawn(service.call(a_request()));
        let second = service.call(a_request());
        assert_eq!(calls(&service), 1, "the handler of a refused request ran");
        assert!(second.await.is_err(), "the second request was not refused");

        read_bytes(&mut client, &mut stream, 100)
            .await
            .expect("a read while a request is in progress was refused");
        stream
            .write_all(b"headers")
            .await
            .expect("a write while a request is in progress was refused");
        gate.notify_one();
        let answer = first
            .await
            .expect("the answer task ends")
            .expect("the request in progress was not answered");
        assert!(closes(&answer));
        stream
            .write_all(b"body")
            .await
            .expect("the write of the answer's body was refused");
        stream.flush().await.expect("the flush of the answer");
        assert!(read_ends(&mut stream).await.is_none(), "closed at once");
        advance(SPENT_IDLE_TIMEOUT + Duration::from_secs(1)).await;
        let error = read_ends(&mut stream).await.expect("not closed");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    /// The budget is passed in the body of the request in progress, which is answered. The request
    /// that starts after that is refused: the last request served is the one in progress when the
    /// budget is passed.
    #[tokio::test(start_paused = true)]
    async fn a_request_that_starts_after_the_budget_was_passed_in_a_body_is_refused() {
        let (mut client, mut stream, mut service, gate) = accepted().await;
        near_the_budget(&stream);
        let first = tokio::spawn(service.call(a_request()));
        read_bytes(&mut client, &mut stream, 200)
            .await
            .expect("the body that passes the budget was refused");
        assert!(stream.shared.state().spent());
        let second = service.call(a_request());
        assert_eq!(calls(&service), 1, "the handler of a refused request ran");
        assert!(second.await.is_err(), "the second request was not refused");
        gate.notify_one();
        let answer = first
            .await
            .expect("the answer task ends")
            .expect("the request in progress was not answered");
        assert!(closes(&answer));
    }

    /// A head whose first bytes pass the budget has no request in progress and may be partly
    /// read: the connection stands under the ordinary idle time, not the allowance of one that has
    /// used its budget, and the request is answered when the rest of the head comes.
    #[tokio::test(start_paused = true)]
    async fn a_head_in_transit_when_the_budget_is_passed_completes_under_the_ordinary_idle_time() {
        let (mut client, mut stream, mut service, gate) = accepted().await;
        near_the_budget(&stream);
        read_bytes(&mut client, &mut stream, 200)
            .await
            .expect("the first part of the head was refused");
        assert!(stream.shared.state().spent());
        advance(Duration::from_secs(2)).await;
        assert!(
            read_ends(&mut stream).await.is_none(),
            "a head in transit was cut"
        );
        read_bytes(&mut client, &mut stream, 50)
            .await
            .expect("the rest of the head was refused");
        let answer = tokio::spawn(service.call(a_request()));
        gate.notify_one();
        let answer = answer
            .await
            .expect("the answer task ends")
            .expect("the request whose head passed the budget was not answered");
        assert!(closes(&answer));
        assert!(read_ends(&mut stream).await.is_none(), "closed at once");
        advance(SPENT_IDLE_TIMEOUT + Duration::from_secs(1)).await;
        let error = read_ends(&mut stream).await.expect("not closed");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    /// Two requests in progress when the budget is passed are both answered, and the connection
    /// ends at the idle time of one that has used its budget, from the end of the last of them.
    #[tokio::test(start_paused = true)]
    async fn requests_in_progress_when_the_lifetime_budget_is_passed_are_answered() {
        let (mut client, mut stream, mut service, gate) = accepted().await;
        near_the_budget(&stream);
        let first = tokio::spawn(service.call(a_request()));
        let second = tokio::spawn(service.call(a_request()));
        read_bytes(&mut client, &mut stream, 2_048)
            .await
            .expect("the bytes that pass the budget were refused");
        assert!(stream.shared.state().spent());
        // Let the two tasks reach the gate, then open it for both.
        tokio::task::yield_now().await;
        gate.notify_waiters();
        for answer in [first, second] {
            let answer = answer
                .await
                .expect("the answer task ends")
                .expect("a request in progress when the budget was passed was not answered");
            assert!(closes(&answer));
        }
        assert!(read_ends(&mut stream).await.is_none(), "closed at once");
        advance(SPENT_IDLE_TIMEOUT + Duration::from_secs(1)).await;
        let error = read_ends(&mut stream).await.expect("not closed");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    /// A request refused with no other request in progress ends the connection at the first flush
    /// that follows the next write, which here is the reset that answers it, without the
    /// allowance, and the place comes back.
    #[tokio::test(start_paused = true)]
    async fn a_refused_request_ends_the_connection_once_the_reset_has_been_written() {
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
            .expect("the head that passes the budget was refused");
        let first = tokio::spawn(service.call(a_request()));
        gate.notify_one();
        first
            .await
            .expect("the answer task ends")
            .expect("the last request served was refused");
        stream
            .write_all(b"answer")
            .await
            .expect("the answer's write");
        stream.flush().await.expect("the answer's flush");
        assert!(read_ends(&mut stream).await.is_none(), "closed at once");

        // The next request is refused, and the reset that says so is the next thing written.
        let second = service.call(a_request());
        assert_eq!(calls(&service), 1, "the handler of a refused request ran");
        assert!(second.await.is_err(), "the second request was not refused");
        stream.write_all(b"reset").await.expect("the reset's write");
        stream.flush().await.expect("the reset's flush");
        assert!(
            read_ends(&mut stream).await.is_some(),
            "the connection stood on after the reset was written"
        );
        drop((stream, client));
        assert_eq!(connections.held(), 0);
        let (_client, server) = tokio::io::duplex(1024);
        bound
            .accept(server, Gated::new(Arc::new(Notify::new())))
            .await
            .expect("the place was not given back");
    }

    /// A connection that has used its budget, whose last request has ended and that sends nothing
    /// more is closed at the allowance, and gives back its place.
    #[tokio::test(start_paused = true)]
    async fn a_silent_connection_that_has_used_its_budget_is_closed_and_gives_back_its_place() {
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
            .expect("the head that passes the budget was refused");
        let first = tokio::spawn(service.call(a_request()));
        gate.notify_one();
        first
            .await
            .expect("the answer task ends")
            .expect("the last request served was refused");
        assert!(read_ends(&mut stream).await.is_none(), "closed at once");

        advance(SPENT_IDLE_TIMEOUT).await;
        let error = read_ends(&mut stream)
            .await
            .expect("not closed at the allowance");
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
}
