//! The server-side representation of an ongoing client relaying connection.

use std::{collections::HashSet, sync::Arc, time::Duration};

use iroh_base::EndpointId;
use n0_error::{e, stack_error};
use n0_future::{Sink, SinkExt, StreamExt};
use rand::RngExt;
use time::{Date, OffsetDateTime};
use tokio::{
    sync::{
        mpsc::{self, error::TrySendError},
        watch,
    },
    time::MissedTickBehavior,
};
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
use tracing::{Instrument, debug, trace, warn};

use crate::{
    PingTracker,
    defaults::timeouts::SERVER_WRITE_TIMEOUT,
    http::ProtocolVersion,
    protos::{
        relay::{
            ClientToRelayMsg, Datagrams, PER_CLIENT_SEND_QUEUE_DEPTH, PING_INTERVAL,
            RelayToClientMsg, Status,
        },
        streams::BytesStreamSink,
    },
    server::{
        ConnectionId, Forward, ForwardBoundary, ForwardOutcome, ForwardPermit, ForwardPolicy,
        ForwardRequest, OnDisconnectGuard,
        clients::Clients,
        metrics::Metrics,
        streams::{RecvError as RelayRecvError, RelayedStream, SendError as RelaySendError},
    },
};

/// A request to write a dataframe to a Client
#[derive(Debug, Clone)]
pub(super) struct Packet {
    /// The sender of the packet
    src: EndpointId,
    /// The data packet bytes.
    data: Datagrams,
    /// What the forwarding policy issued when it admitted this packet at the sending connection.
    permit: ForwardPermit,
    /// The sending connection, so whoever finally disposes of the packet can report the outcome
    /// against the admission that let it in rather than against its own side of the relay.
    src_connection_id: ConnectionId,
}

/// Configuration for a client connection.
///
/// Generic over the stream type to support different WebSocket implementations.
#[derive(Debug)]
#[non_exhaustive]
pub struct Config<S> {
    /// Reports the disconnect once the connection ends.
    ///
    /// Also the owner of this connection's [`EndpointId`] and [`ConnectionId`].
    pub guard: OnDisconnectGuard,
    /// The relayed stream connection
    pub stream: RelayedStream<S>,
    /// Write timeout for the client connection
    pub write_timeout: Duration,
    /// Channel capacity for internal message queues
    pub channel_capacity: usize,
    /// Protocol version negotiated for this client
    pub protocol_version: ProtocolVersion,
    /// Decides each relayed payload at this connection's two forwarding boundaries.
    pub forward: Arc<dyn ForwardPolicy>,
    /// Optional signal to inform the client when it is being rate-limited.
    ///
    /// When set, the connection actor notifies the client once with a
    /// [`Status::RateLimited`] message when the rate-limited counter first
    /// becomes non-zero.
    pub(crate) rate_limited: Option<watch::Receiver<u64>>,
}

impl<S> Config<S> {
    /// Creates a new config with sensible default values for `write_timeout` and `channel_capacity`.
    ///
    /// The endpoint and connection ids are taken from `guard`.
    pub fn new(
        guard: OnDisconnectGuard,
        stream: RelayedStream<S>,
        protocol_version: ProtocolVersion,
    ) -> Self {
        Self {
            guard,
            stream,
            protocol_version,
            write_timeout: SERVER_WRITE_TIMEOUT,
            channel_capacity: PER_CLIENT_SEND_QUEUE_DEPTH,
            rate_limited: None,
            forward: Arc::new(crate::server::ForwardAll),
        }
    }
}

/// The [`Server`] side representation of a [`Client`]'s connection.
///
/// [`Server`]: crate::server::Server
/// [`Client`]: crate::client::Client
#[derive(Debug)]
pub(super) struct Client {
    /// Identity of the connected peer.
    endpoint_id: EndpointId,
    /// Connection identifier.
    connection_id: ConnectionId,
    /// Used to close the connection loop.
    done: CancellationToken,
    /// Actor handle.
    handle: AbortOnDropHandle<()>,
    /// Channel to send packets intended for the client.
    packet_queue: mpsc::Sender<Packet>,
    /// Channel to send non-packet messages to the client.
    message_queue: mpsc::Sender<RelayToClientMsg>,
    /// Relay protocol version negotiated for this client.
    protocol_version: ProtocolVersion,
}

impl Client {
    /// Creates a client from a connection & starts a read and write loop to handle io to and from
    /// the client
    ///
    /// The `guard` is moved into the connection actor and reports the disconnect to access
    /// control once the connection ends.
    ///
    /// Call [`Client::shutdown`] to close the read and write loops before dropping the [`Client`]
    pub(super) fn new<S>(config: Config<S>, clients: &Clients, metrics: Arc<Metrics>) -> Client
    where
        S: BytesStreamSink + Send + 'static,
    {
        let Config {
            guard,
            stream,
            write_timeout,
            channel_capacity,
            protocol_version,
            rate_limited,
            forward,
        } = config;
        let endpoint_id = guard.endpoint_id;
        let connection_id = guard.connection_id;

        let (packet_send_queue_s, packet_send_queue_r) = mpsc::channel(channel_capacity);
        let (message_send_queue_s, message_send_queue_r) = mpsc::channel(channel_capacity);
        let done = CancellationToken::new();

        let actor = Actor {
            stream,
            timeout: write_timeout,
            packet_send_queue: packet_send_queue_r,
            message_send_queue: message_send_queue_r,
            guard,
            clients: clients.clone(),
            client_counter: ClientCounter::default(),
            ping_tracker: PingTracker::default(),
            protocol_version,
            rate_limited,
            forward,
            metrics,
        };

        // start io loop
        let io_done = done.clone();
        let handle = tokio::task::spawn(actor.run(io_done).instrument(tracing::info_span!(
            "client-connection-actor",
            remote_endpoint = %endpoint_id.fmt_short(),
            connection_id = %connection_id
        )));

        Client {
            endpoint_id,
            connection_id,
            handle: AbortOnDropHandle::new(handle),
            done,
            packet_queue: packet_send_queue_s,
            message_queue: message_send_queue_s,
            protocol_version,
        }
    }

    pub(super) fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }

    /// Shutdown the reader and writer loops and closes the connection.
    ///
    /// Any shutdown errors will be logged as warnings.
    pub(super) async fn shutdown(self) {
        self.start_shutdown();
        if let Err(e) = self.handle.await {
            warn!(
                remote_endpoint = %self.endpoint_id.fmt_short(),
                "error closing actor loop: {e:#?}",
            );
        };
    }

    /// Starts the process of shutdown.
    pub(super) fn start_shutdown(&self) {
        self.done.cancel();
    }

    pub(super) fn try_send_packet(
        &self,
        src: EndpointId,
        data: Datagrams,
        permit: ForwardPermit,
        src_connection_id: ConnectionId,
    ) -> Result<(), TrySendError<Packet>> {
        self.packet_queue.try_send(Packet {
            src,
            data,
            permit,
            src_connection_id,
        })
    }

    pub(super) fn try_send_peer_gone(
        &self,
        key: EndpointId,
    ) -> Result<(), TrySendError<RelayToClientMsg>> {
        self.message_queue
            .try_send(RelayToClientMsg::EndpointGone(key))
    }

    pub(super) fn try_send_health(
        &self,
        status: Status,
    ) -> Result<(), TrySendError<RelayToClientMsg>> {
        let message = match self.protocol_version {
            ProtocolVersion::V2 => RelayToClientMsg::Status(status),
            ProtocolVersion::V1 => RelayToClientMsg::Health {
                problem: status.to_string(),
            },
        };
        self.message_queue.try_send(message)
    }
}

/// Completes when `rx` observes the connection being rate-limited.
///
/// Pends forever when `rx` is `None`, i.e. when no rate-limit signal is configured.
async fn rate_limited_signal(rx: &mut Option<watch::Receiver<u64>>) -> bool {
    match rx {
        Some(rx) => match rx.changed().await {
            Ok(()) => *rx.borrow_and_update() > 0,
            // The sender lives inside this actor's stream, so it cannot drop while
            // the actor runs. Report not limited to be safe.
            Err(_) => false,
        },
        None => std::future::pending().await,
    }
}

/// Error when handling an incoming frame from a client.
#[stack_error(derive, add_meta, from_sources)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum HandleFrameError {
    #[error("the forwarding policy closed the connection")]
    ForwardRefused {},
    #[error(transparent)]
    ForwardPacket { source: ForwardPacketError },
    #[error("Stream terminated")]
    StreamTerminated {},
    #[error(transparent)]
    Recv { source: RelayRecvError },
    #[error(transparent)]
    Send { source: WriteFrameError },
}

/// Error when writing a frame to a client.
#[stack_error(derive, add_meta, from_sources)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum WriteFrameError {
    #[error("the forwarding policy closed the connection")]
    ForwardRefused {},
    #[error(transparent)]
    Stream { source: RelaySendError },
    #[error(transparent)]
    Timeout {
        #[error(std_err)]
        source: tokio::time::error::Elapsed,
    },
}

/// Run error
#[stack_error(derive, add_meta)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum RunError {
    #[error(transparent)]
    ForwardPacket {
        #[error(from)]
        source: ForwardPacketError,
    },
    #[error("Flush")]
    Flush {},
    #[error(transparent)]
    HandleFrame {
        #[error(from)]
        source: HandleFrameError,
    },
    #[error("Failed to send packet")]
    PacketSend { source: WriteFrameError },
    #[error("Handle was dropped")]
    HandleDropped {},
    #[error("Writing a frame failed")]
    WriteFrame { source: WriteFrameError },
    #[error("Tick flush")]
    TickFlush {},
}

/// Manages all the reads and writes to this client. It periodically sends a `KEEP_ALIVE`
/// message to the client to keep the connection alive.
///
/// Call `run` to manage the input and output to and from the connection and the server.
/// Once it hits its first write error or error receiving off a channel,
/// it errors on return.
/// If writes do not complete in the given `timeout`, it will also error.
///
/// On the "write" side, the [`Actor`] can send the client:
///  - a KEEP_ALIVE frame
///  - a PEER_GONE frame to inform the client that a peer they have previously sent messages to
///    is gone from the network
///  - packets from other peers
///
/// On the "read" side, it can:
///     - receive a ping and write a pong back
///     to speak to the endpoint ID associated with that client.
#[derive(Debug)]
struct Actor<S> {
    /// IO Stream to talk to the client
    stream: RelayedStream<S>,
    /// Maximum time we wait to complete a write to the client
    timeout: Duration,
    /// Receiver for packets to be sent to the client.
    packet_send_queue: mpsc::Receiver<Packet>,
    /// Receiver for non-packet messages to be sent to the client.
    message_send_queue: mpsc::Receiver<RelayToClientMsg>,
    /// Reports the disconnect to access control when dropped.
    ///
    /// Also the owner of this connection's [`EndpointId`] and [`ConnectionId`].
    guard: OnDisconnectGuard,
    /// Reference to the other connected clients.
    clients: Clients,
    /// Statistics about the connected clients
    client_counter: ClientCounter,
    ping_tracker: PingTracker,
    /// Relay protocol version negotiated for this client.
    protocol_version: ProtocolVersion,
    /// Optional signal counting how often the connection has been rate-limited.
    rate_limited: Option<watch::Receiver<u64>>,
    /// Decides each relayed payload at this connection's two forwarding boundaries.
    forward: Arc<dyn ForwardPolicy>,
    metrics: Arc<Metrics>,
}

impl<S> Actor<S>
where
    S: BytesStreamSink,
{
    async fn run(mut self, done: CancellationToken) {
        // Note the accept and disconnects metrics must be in a pair.  Technically the
        // connection is accepted long before this in the HTTP server, but it is clearer to
        // handle the metric here.
        self.metrics.accepts.inc();
        if self.client_counter.update(self.guard.endpoint_id()) {
            self.metrics.unique_client_keys.inc();
        }
        match self.run_inner(done).await {
            Err(e) => {
                warn!("actor errored {e:#}, exiting");
            }
            Ok(()) => {
                debug!("actor finished, exiting");
            }
        }

        // Whatever is still queued for this client will never be written. Each of those payloads
        // was admitted at its sender's boundary and is still outstanding as far as the policy
        // knows, so each one is settled as dropped: a connection that goes away must not leave a
        // debit behind it.
        //
        // The queue is closed and then drained to its end rather than sampled. A sender that has
        // taken a permit but not yet inserted its packet is between the two halves of `try_send`,
        // and `try_recv` would report the queue empty while that packet was still on its way in;
        // awaiting the receiver waits those senders out and returns `None` only once no packet can
        // arrive.
        self.packet_send_queue.close();
        while let Some(packet) = self.packet_send_queue.recv().await {
            self.metrics.send_packets_dropped.inc();
            self.settle(&packet, ForwardOutcome::Dropped);
        }

        self.clients.unregister(self.guard, &self.metrics);
        self.metrics.disconnects.inc();
    }

    async fn run_inner(&mut self, done: CancellationToken) -> Result<(), RunError> {
        // Add some jitter to ping pong interactions, to avoid all pings being sent at the same time
        let next_interval = || {
            let random_secs = rand::rng().random_range(1..=5);
            Duration::from_secs(random_secs) + PING_INTERVAL
        };

        let mut ping_interval = tokio::time::interval(next_interval());
        // ticks immediately
        ping_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        ping_interval.tick().await;

        let mut rate_limit_notified = false;

        loop {
            tokio::select! {
                biased;

                _ = done.cancelled() => {
                    trace!("actor loop cancelled, exiting");
                    // final flush
                    self.stream.flush().await.map_err(|_| e!(RunError::Flush))?;
                    break;
                }
                limited = rate_limited_signal(&mut self.rate_limited), if !rate_limit_notified => {
                    // Notify the client once per connection.
                    // V1 clients are not notified.
                    rate_limit_notified = true;
                    if limited && self.protocol_version == ProtocolVersion::V2 {
                        debug!("connection is rate-limited, notifying client");
                        self.write_frame(RelayToClientMsg::Status(Status::RateLimited))
                            .await
                            .map_err(|err| e!(RunError::WriteFrame, err))?;
                    }
                }
                maybe_frame = self.stream.next() => {
                    self
                        .handle_frame(maybe_frame)
                        .await?;
                    // reset the ping interval, we just received a message
                    ping_interval.reset();
                }
                // Second priority, sending regular packets
                packet = self.packet_send_queue.recv() => {
                    let packet = packet.ok_or_else(|| e!(RunError::HandleDropped))?;
                    self.send_packet(packet)
                        .await
                        .map_err(|err| e!(RunError::PacketSend, err))?;
                }
                // Last priority, sending other message
                message = self.message_send_queue.recv() => {
                    let message = message.ok_or_else(|| e!(RunError::HandleDropped))?;
                    trace!("send {message:?}");
                    self.write_frame(message)
                        .await
                        .map_err(|err| e!(RunError::WriteFrame, err))?;
                }
                _ = self.ping_tracker.timeout() => {
                    trace!("pong timed out");
                    break;
                }
                _ = ping_interval.tick() => {
                    trace!("keep alive ping");
                    // new interval
                    ping_interval.reset_after(next_interval());
                    let data = self.ping_tracker.new_ping();
                    self.write_frame(RelayToClientMsg::Ping(data))
                        .await
                        .map_err(|err| e!(RunError::WriteFrame, err))?;
                }
            }

            self.stream
                .flush()
                .await
                .map_err(|_| e!(RunError::TickFlush))?;
        }
        Ok(())
    }

    /// Writes the given frame to the connection.
    ///
    /// Errors if the send does not happen within the `timeout` duration
    async fn write_frame(&mut self, frame: RelayToClientMsg) -> Result<(), WriteFrameError> {
        tokio::time::timeout(self.timeout, self.stream.send(frame)).await??;
        Ok(())
    }

    /// Writes one relayed payload to the client, once the forwarding policy has admitted it.
    ///
    /// Errors if the connection does not become ready, or the write does not complete, within the
    /// `timeout` duration.
    async fn send_packet(&mut self, packet: Packet) -> Result<(), WriteFrameError> {
        trace!("send packet");

        // Wait for the connection to be able to take a frame *before* asking the policy. A payload
        // can sit here for as long as the client is slow, and a lease can be revoked or expire
        // while it does, so a decision taken before the wait would be a decision about a moment
        // that has passed. After this, writing is synchronous: nothing can change between the
        // answer and the frame going out.
        let ready = tokio::time::timeout(
            self.timeout,
            n0_future::future::poll_fn(|context| {
                std::pin::Pin::new(&mut self.stream).poll_ready(context)
            }),
        )
        .await;
        match ready {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                self.metrics.send_packets_dropped.inc();
                self.settle(&packet, ForwardOutcome::Dropped);
                return Err(err.into());
            }
            Err(elapsed) => {
                self.metrics.send_packets_dropped.inc();
                self.settle(&packet, ForwardOutcome::Dropped);
                return Err(e!(WriteFrameError::Timeout, elapsed));
            }
        }

        // The egress boundary. The permit the payload arrived with is what the policy issued when
        // it admitted the payload, so a capability replaced while the payload waited is caught. A
        // refusal here is the payload's end, and it is reported as such.
        let mut refused = None;
        {
            let request = ForwardRequest::new(
                ForwardBoundary::Egress,
                packet.src,
                self.guard.endpoint_id(),
                self.guard.connection_id(),
                Some(packet.permit),
                &packet.data,
            );
            match self.forward.on_forward(&request) {
                Forward::Allow { .. } => {}
                Forward::Drop => {
                    self.metrics.send_packets_dropped.inc();
                    refused = Some(None);
                }
                Forward::Close { reason } => {
                    self.metrics.send_packets_dropped.inc();
                    debug!(?reason, "forwarding policy closed the connection");
                    refused = Some(Some(()));
                }
            }
        }
        if let Some(closes) = refused {
            self.settle(&packet, ForwardOutcome::Dropped);
            return if closes.is_some() {
                Err(e!(WriteFrameError::ForwardRefused))
            } else {
                Ok(())
            };
        }

        // Handing the frame over is synchronous, so nothing can change between the policy's answer
        // and the bytes leaving. The flush afterwards is not: it can fail with some, all or none of
        // them already given to the transport, and nobody can say which, so that outcome is
        // reported as the uncertainty it is rather than as a refund.
        match self.start_send_packet(&packet) {
            Err(err) => {
                self.metrics.send_packets_dropped.inc();
                // Uncertain, not dropped. A sink is free to write during the hand-off, and the
                // embedded adapters do: the error says the hand-off failed, not that nothing left
                // the machine, and refunding bytes that may have moved is how an unreported
                // allowance is created.
                self.settle(&packet, ForwardOutcome::Uncertain);
                Err(err)
            }
            Ok(()) => match self.flush().await {
                Ok(()) => {
                    self.metrics.send_packets_sent.inc();
                    self.settle(&packet, ForwardOutcome::Committed);
                    Ok(())
                }
                Err(err) => {
                    self.metrics.send_packets_dropped.inc();
                    self.settle(&packet, ForwardOutcome::Uncertain);
                    Err(err)
                }
            },
        }
    }

    /// Tells the policy what finally became of a payload it admitted at the sending connection.
    ///
    /// The request describes that admission rather than this connection, because the policy issued
    /// the permit there and that is what it correlates the outcome with. This is the only
    /// settlement a queued payload gets, whichever way it ends.
    fn settle(&self, packet: &Packet, outcome: ForwardOutcome) {
        self.forward.on_settled(
            &ForwardRequest::new(
                ForwardBoundary::Ingress,
                packet.src,
                self.guard.endpoint_id(),
                packet.src_connection_id,
                Some(packet.permit),
                &packet.data,
            ),
            outcome,
        );
    }

    /// Pushes whatever has been handed to the stream out to the client.
    async fn flush(&mut self) -> Result<(), WriteFrameError> {
        tokio::time::timeout(
            self.timeout,
            n0_future::future::poll_fn(|context| {
                std::pin::Pin::new(&mut self.stream).poll_flush(context)
            }),
        )
        .await??;
        Ok(())
    }

    /// Hands one packet to a stream that has already said it is ready.
    ///
    /// Synchronous on purpose: this is the step the policy's answer applies to, and nothing may
    /// happen between the two. A failure here is not proof that nothing was written: the sink is
    /// an embedder's, and some write bytes as they take them.
    fn start_send_packet(&mut self, packet: &Packet) -> Result<(), WriteFrameError> {
        if let Ok(len) = packet.data.contents.len().try_into() {
            self.metrics.bytes_sent.inc_by(len);
        }
        std::pin::Pin::new(&mut self.stream).start_send(RelayToClientMsg::Datagrams {
            remote_endpoint_id: packet.src,
            datagrams: packet.data.clone(),
        })?;
        Ok(())
    }

    /// Handles frame read results.
    async fn handle_frame(
        &mut self,
        maybe_frame: Option<Result<ClientToRelayMsg, RelayRecvError>>,
    ) -> Result<(), HandleFrameError> {
        trace!(?maybe_frame, "handle incoming frame");
        let frame = match maybe_frame {
            Some(frame) => frame?,
            None => return Err(e!(HandleFrameError::StreamTerminated)),
        };

        match frame {
            ClientToRelayMsg::Datagrams {
                dst_endpoint_id: dst_key,
                datagrams,
            } => {
                let packet_len = datagrams.contents.len();
                match self.handle_frame_send_packet(dst_key, datagrams) {
                    Ok(()) => {}
                    // A policy that refuses a payload outright is refusing the connection, not
                    // just the payload, so it ends the actor loop rather than being logged and
                    // forgotten like a full queue.
                    Err(err) if matches!(err.reason, SendError::Refused) => {
                        return Err(e!(HandleFrameError::ForwardRefused));
                    }
                    Err(err) => {
                        warn!("failed to handle send packet frame: {err:#}");
                    }
                }
                self.metrics.bytes_recv.inc_by(packet_len as u64);
            }
            ClientToRelayMsg::Ping(data) => {
                self.metrics.got_ping.inc();
                // TODO: add rate limiter
                self.write_frame(RelayToClientMsg::Pong(data)).await?;
                self.metrics.sent_pong.inc();
            }
            ClientToRelayMsg::Pong(data) => {
                self.ping_tracker.pong_received(data);
            }
        }
        Ok(())
    }

    fn handle_frame_send_packet(
        &self,
        dst: EndpointId,
        data: Datagrams,
    ) -> Result<(), ForwardPacketError> {
        self.metrics.send_packets_recv.inc();
        // The ingress boundary: the payload has been read from this client and is about to be
        // queued for its destination. Nothing has admitted it yet, so there is no permit to show.
        let permit = {
            let request = ForwardRequest::new(
                ForwardBoundary::Ingress,
                self.guard.endpoint_id(),
                dst,
                self.guard.connection_id(),
                None,
                &data,
            );
            match self.forward.on_forward(&request) {
                Forward::Allow { permit } => permit,
                Forward::Drop => {
                    self.metrics.send_packets_dropped.inc();
                    return Ok(());
                }
                Forward::Close { reason } => {
                    self.metrics.send_packets_dropped.inc();
                    debug!(?reason, "forwarding policy closed the connection");
                    return Err(ForwardPacketError::new(SendError::Refused));
                }
            }
        };

        let settled = data.clone();
        let queued = self.clients.send_packet(
            dst,
            data,
            self.guard.endpoint_id(),
            permit,
            self.guard.connection_id(),
            &self.metrics,
        );

        // A payload that reached the destination's queue is settled by the destination, when its
        // fate is actually known. One that did not is settled here, because nothing else will ever
        // see it: the destination was not connected, its queue was full, or it had closed.
        if !matches!(queued, Ok(true)) {
            self.forward.on_settled(
                &ForwardRequest::new(
                    ForwardBoundary::Ingress,
                    self.guard.endpoint_id(),
                    dst,
                    self.guard.connection_id(),
                    Some(permit),
                    &settled,
                ),
                ForwardOutcome::Dropped,
            );
        }
        queued?;

        Ok(())
    }
}

#[derive(Debug)]
pub(crate) enum SendError {
    Full,
    Closed,
    Refused,
}

/// Error returned when forwarding a packet to a client fails.
///
/// This error occurs when the relay server cannot deliver a packet to its intended
/// recipient, typically due to the client's send queue being full or the client
/// disconnecting.
#[stack_error(derive, add_meta)]
#[error("failed to forward packet: {reason:?}")]
pub struct ForwardPacketError {
    reason: SendError,
}

/// Tracks how many unique endpoints have been seen during the last day.
#[derive(Debug)]
struct ClientCounter {
    clients: HashSet<EndpointId>,
    last_clear_date: Date,
}

impl Default for ClientCounter {
    fn default() -> Self {
        Self {
            clients: HashSet::new(),
            last_clear_date: OffsetDateTime::now_utc().date(),
        }
    }
}

impl ClientCounter {
    fn check_and_clear(&mut self) {
        let today = OffsetDateTime::now_utc().date();
        if today != self.last_clear_date {
            self.clients.clear();
            self.last_clear_date = today;
        }
    }

    /// Marks this endpoint as seen, returns whether it is new today or not.
    fn update(&mut self, client: EndpointId) -> bool {
        self.check_and_clear();
        self.clients.insert(client)
    }
}

#[cfg(test)]
mod tests {
    use iroh_base::SecretKey;
    use n0_error::{Result, StdResultExt, bail_any};
    use n0_future::Stream;
    use n0_tracing_test::traced_test;
    use rand::SeedableRng;
    use tracing::info;

    use super::*;
    use crate::{
        client::conn::Conn,
        http::ProtocolVersion,
        protos::{common::FrameType, relay::Status, streams::WsBytesFramed},
        server::streams::{MaybeTlsStream, RateLimited, ServerRelayedStream},
    };

    async fn recv_frame<
        E: std::error::Error + Sync + Send + 'static,
        S: Stream<Item = Result<RelayToClientMsg, E>> + Unpin,
    >(
        frame_type: FrameType,
        mut stream: S,
    ) -> Result<RelayToClientMsg> {
        match stream.next().await {
            Some(Ok(frame)) => {
                if frame_type != frame.typ() {
                    bail_any!(
                        "Unexpected frame, got {:?}, but expected {:?}",
                        frame.typ(),
                        frame_type
                    );
                }
                Ok(frame)
            }
            Some(Err(err)) => Err(err).anyerr(),
            None => bail_any!("Unexpected EOF, expected frame {frame_type:?}"),
        }
    }

    #[tokio::test]
    #[traced_test]
    async fn test_client_actor_basic() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

        let (send_queue_s, send_queue_r) = mpsc::channel(10);
        let (message_s, message_r) = mpsc::channel(10);

        let endpoint_id = SecretKey::from_bytes(&rng.random()).public();
        let (io, io_rw) = tokio::io::duplex(1024);
        let mut io_rw = Conn::test(io_rw, Default::default());
        let stream = RelayedStream::test(io);

        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());
        let actor = Actor {
            stream,
            timeout: Duration::from_secs(1),
            packet_send_queue: send_queue_r,
            message_send_queue: message_r,
            guard: OnDisconnectGuard::empty(endpoint_id),
            clients: clients.clone(),
            client_counter: ClientCounter::default(),
            ping_tracker: PingTracker::default(),
            protocol_version: ProtocolVersion::V2,
            rate_limited: None,
            forward: Arc::new(crate::server::ForwardAll),
            metrics,
        };

        let done = CancellationToken::new();
        let io_done = done.clone();
        let handle = tokio::task::spawn(async move { actor.run(io_done).await });

        // Write tests
        println!("-- write");
        let data = b"hello world!";

        // send packet
        println!("  send packet");
        let packet = Packet {
            src: endpoint_id,
            data: Datagrams::from(&data[..]),
            permit: ForwardPermit::default(),
            src_connection_id: OnDisconnectGuard::empty(endpoint_id).connection_id(),
        };
        send_queue_s
            .send(packet.clone())
            .await
            .std_context("send")?;
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut io_rw)
            .await
            .anyerr()?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: endpoint_id,
                datagrams: data.to_vec().into()
            }
        );

        // send peer_gone
        println!("send peer gone");
        message_s
            .send(RelayToClientMsg::EndpointGone(endpoint_id))
            .await
            .std_context("send")?;
        let frame = recv_frame(FrameType::EndpointGone, &mut io_rw)
            .await
            .anyerr()?;
        assert_eq!(frame, RelayToClientMsg::EndpointGone(endpoint_id));

        // Read tests
        println!("--read");

        // send ping, expect pong
        let data = b"pingpong";
        io_rw.send(ClientToRelayMsg::Ping(*data)).await?;

        // recv pong
        println!(" recv pong");
        let frame = recv_frame(FrameType::Pong, &mut io_rw).await?;
        assert_eq!(frame, RelayToClientMsg::Pong(*data));

        let target = SecretKey::from_bytes(&rng.random()).public();

        // send packet
        println!("  send packet");
        let data = b"hello world!";
        io_rw
            .send(ClientToRelayMsg::Datagrams {
                dst_endpoint_id: target,
                datagrams: Datagrams::from(data),
            })
            .await
            .std_context("send")?;

        done.cancel();
        handle.await.std_context("join")?;
        Ok(())
    }

    fn test_client_builder(
        key: EndpointId,
        protocol_version: ProtocolVersion,
    ) -> (Config<WsBytesFramed<RateLimited<MaybeTlsStream>>>, Conn) {
        let (server, client) = tokio::io::duplex(1024);
        let guard = OnDisconnectGuard::empty(key);
        let mut config = Config::new(guard, ServerRelayedStream::test(server), protocol_version);
        config.write_timeout = Duration::from_secs(1);
        config.channel_capacity = 10;
        (config, Conn::test(client, protocol_version))
    }

    #[tokio::test]
    #[traced_test]
    async fn test_client_v1_protocol() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42u64);
        let a_key = SecretKey::from_bytes(&rng.random()).public();
        let b_key = SecretKey::from_bytes(&rng.random()).public();

        let (builder_a, mut a_rw) = test_client_builder(a_key, ProtocolVersion::V1);

        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());
        clients.register(builder_a, metrics.clone());

        // Verify basic packet delivery works with V1.
        let data = b"hello world v1!";
        clients.send_packet(
            a_key,
            Datagrams::from(&data[..]),
            b_key,
            ForwardPermit::default(),
            OnDisconnectGuard::empty(b_key).connection_id(),
            &metrics,
        )?;
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut a_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: b_key,
                datagrams: data.to_vec().into(),
            }
        );

        clients.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_client_v2_protocol() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42u64);
        let a_key = SecretKey::from_bytes(&rng.random()).public();
        let b_key = SecretKey::from_bytes(&rng.random()).public();

        let (builder_a, mut a_rw) = test_client_builder(a_key, ProtocolVersion::V2);

        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());
        clients.register(builder_a, metrics.clone());

        // Verify basic packet delivery works with V2.
        let data = b"hello world v2!";
        clients.send_packet(
            a_key,
            Datagrams::from(&data[..]),
            b_key,
            ForwardPermit::default(),
            OnDisconnectGuard::empty(b_key).connection_id(),
            &metrics,
        )?;
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut a_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: b_key,
                datagrams: data.to_vec().into(),
            }
        );

        clients.shutdown().await;
        Ok(())
    }

    /// Test for versioned protocol: v1 client should receive V1Health frame.
    #[tokio::test]
    #[traced_test]
    async fn test_duplicate_endpoint_v1_receives_v1health() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42u64);
        let key = SecretKey::from_bytes(&rng.random()).public();

        let (builder_first, mut first_rw) = test_client_builder(key, ProtocolVersion::V1);

        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());
        clients.register(builder_first, metrics.clone());

        // Register a second client with the same endpoint ID.
        // The first client should receive a V1Health message.
        let (builder_second, _second_rw) = test_client_builder(key, ProtocolVersion::V1);
        clients.register(builder_second, metrics.clone());

        let frame = recv_frame(FrameType::Health, &mut first_rw).await?;
        assert!(
            matches!(frame, RelayToClientMsg::Health { .. }),
            "expected V1Health frame for V1 client, got {frame:?}"
        );

        clients.shutdown().await;
        Ok(())
    }

    /// Test for versioned protocol: v2 client should receive V2Health frame.
    #[tokio::test]
    #[traced_test]
    async fn test_duplicate_endpoint_v2_receives_health() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42u64);
        let key = SecretKey::from_bytes(&rng.random()).public();

        let (builder_first, mut first_rw) = test_client_builder(key, ProtocolVersion::V2);

        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());
        clients.register(builder_first, metrics.clone());

        // Register a second client with the same endpoint ID.
        // The first client should receive a Health message (V2 frame).
        let (builder_second, _second_rw) = test_client_builder(key, ProtocolVersion::V2);
        clients.register(builder_second, metrics.clone());

        let frame = recv_frame(FrameType::Status, &mut first_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Status(Status::SameEndpointIdConnected)
        );

        clients.shutdown().await;
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    #[traced_test]
    async fn test_rate_limit() -> Result {
        const LIMIT: u32 = 50;
        const MAX_FRAMES: u32 = 100;

        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

        // Build the rate limited stream.
        let (io_read, io_write) = tokio::io::duplex((LIMIT * MAX_FRAMES) as _);
        let mut frame_writer = Conn::test(io_write, Default::default());
        // Rate limiter allowing LIMIT bytes/s
        let (mut stream, _limited) = RelayedStream::test_limited(io_read, LIMIT / 10, LIMIT)?;

        // Prepare a frame to send, assert its size.
        let data = Datagrams::from(b"hello world!!!!!");
        let target = SecretKey::from_bytes(&rng.random()).public();
        let frame = ClientToRelayMsg::Datagrams {
            dst_endpoint_id: target,
            datagrams: data.clone(),
        };
        let frame_len = frame.to_bytes().len();
        assert_eq!(frame_len, LIMIT as usize);

        // Send a frame, it should arrive.
        info!("-- send packet");
        frame_writer.send(frame.clone()).await.std_context("send")?;
        frame_writer.flush().await.std_context("flush")?;
        let recv_frame = tokio::time::timeout(Duration::from_millis(500), stream.next())
            .await
            .expect("timeout")
            .expect("option")
            .expect("ok");
        assert_eq!(recv_frame, frame);

        // Next frame does not arrive.
        info!("-- send packet");
        frame_writer.send(frame.clone()).await.std_context("send")?;
        frame_writer.flush().await.std_context("flush")?;
        let res = tokio::time::timeout(Duration::from_millis(100), stream.next()).await;
        assert!(res.is_err(), "expecting a timeout");
        info!("-- timeout happened");

        // Wait long enough.
        info!("-- sleep");
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Frame arrives.
        let recv_frame = tokio::time::timeout(Duration::from_millis(500), stream.next())
            .await
            .expect("timeout")
            .expect("option")
            .expect("ok");
        assert_eq!(recv_frame, frame);

        Ok(())
    }

    /// A client whose connection is rate-limited receives a [`Status::RateLimited`] notice.
    #[tokio::test(start_paused = true)]
    #[traced_test]
    async fn test_rate_limit_notice() -> Result {
        const LIMIT: u32 = 50;

        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let key = SecretKey::from_bytes(&rng.random()).public();
        let target = SecretKey::from_bytes(&rng.random()).public();

        let (server_io, client_io) = tokio::io::duplex(4096);
        // Rate limiter allowing LIMIT bytes/s with a burst size below a single frame.
        let (stream, limited) = ServerRelayedStream::test_limited(server_io, LIMIT / 10, LIMIT)?;
        let mut config = Config::new(OnDisconnectGuard::empty(key), stream, ProtocolVersion::V2);
        config.write_timeout = Duration::from_secs(1);
        config.channel_capacity = 10;
        config.rate_limited = Some(limited);
        let mut conn = Conn::test(client_io, ProtocolVersion::V2);

        let clients = Clients::default();
        clients.register(config, Arc::new(Metrics::default()));

        // A single frame larger than the burst size trips the rate limiter.
        conn.send(ClientToRelayMsg::Datagrams {
            dst_endpoint_id: target,
            datagrams: Datagrams::from(b"hello world!!!!!"),
        })
        .await?;

        let frame = recv_frame(FrameType::Status, &mut conn).await?;
        assert_eq!(frame, RelayToClientMsg::Status(Status::RateLimited));

        clients.shutdown().await;
        Ok(())
    }
}
