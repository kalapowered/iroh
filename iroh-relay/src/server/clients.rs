//! The "Server" side of the client. Uses the `ClientConnManager`.
// Based on tailscale/derp/derp_server.go

use std::{collections::HashSet, sync::Arc};

use dashmap::DashMap;
use iroh_base::EndpointId;
use n0_future::IterExt;
use tokio::sync::mpsc::error::TrySendError;
use tracing::{debug, trace};

use super::{
    ConnectionId, ForwardPermit, OnDisconnectGuard,
    client::{Client, Config, ForwardPacketError},
};
use crate::{
    protos::{
        relay::{Datagrams, Status},
        streams::BytesStreamSink,
    },
    server::{client::SendError, metrics::Metrics},
};

/// Registry of connected relay clients.
///
/// This type manages the collection of active client connections and
/// handles routing messages between them.
#[derive(Debug, Clone, Default)]
pub struct Clients(Arc<Inner>);

#[derive(Debug, Default)]
struct Inner {
    /// The list of all currently connected clients.
    clients: DashMap<EndpointId, ClientState>,
    /// Map of which client has sent where
    sent_to: DashMap<EndpointId, HashSet<EndpointId>>,
}

#[derive(Debug)]
struct ClientState {
    active: Client,
    inactive: Vec<Client>,
}

impl ClientState {
    async fn shutdown_all(mut self) {
        [self.active]
            .into_iter()
            .chain(self.inactive.drain(..))
            .map(Client::shutdown)
            .join_all()
            .await;
    }
}

impl Clients {
    /// Shuts down all connected clients.
    ///
    /// This method gracefully disconnects all active client connections managed by
    /// this registry. It will wait for all clients to complete their shutdown before
    /// returning.
    pub async fn shutdown(&self) {
        let keys: Vec<_> = self.0.clients.iter().map(|x| *x.key()).collect();
        trace!("shutting down {} clients", keys.len());
        let clients = keys.into_iter().filter_map(|k| self.0.clients.remove(&k));
        n0_future::join_all(clients.map(|(_, state)| state.shutdown_all())).await;
    }

    /// Builds the client handler and starts the read & write loops for the connection.
    ///
    /// Once the client disconnects, the [`OnDisconnectGuard`] set in `config` will be dropped,
    /// allowing callers to be notified of the disconnect.
    pub fn register<S>(&self, client_config: Config<S>, metrics: Arc<Metrics>)
    where
        S: BytesStreamSink + Send + 'static,
    {
        let endpoint_id = client_config.guard.endpoint_id;
        trace!(remote_endpoint = %endpoint_id.fmt_short(), "registering client");

        let client = Client::new(client_config, self, metrics.clone());
        match self.0.clients.entry(endpoint_id) {
            dashmap::Entry::Occupied(mut entry) => {
                let state = entry.get_mut();
                let old_client = std::mem::replace(&mut state.active, client);
                debug!(
                    remote_endpoint = %endpoint_id.fmt_short(),
                    "multiple connections found, deactivating old connection",
                );
                old_client
                    .try_send_health(Status::SameEndpointIdConnected)
                    .ok();
                state.inactive.push(old_client);
                metrics.clients_inactive_added.inc();
            }
            dashmap::Entry::Vacant(entry) => {
                entry.insert(ClientState {
                    active: client,
                    inactive: Vec::new(),
                });
            }
        }
    }

    /// Removes the client from the map of clients, & sends a notification
    /// to each client that peers has sent data to, to let them know that
    /// peer is gone from the network.
    ///
    /// Must be passed a matching connection_id.
    pub(super) fn unregister(&self, guard: OnDisconnectGuard, metrics: &Metrics) {
        let endpoint_id = guard.endpoint_id;
        let connection_id = guard.connection_id;
        trace!(
            endpoint_id = %endpoint_id.fmt_short(),
            %connection_id, "unregistering client"
        );

        let mut notify_peers = None;

        self.0.clients.remove_if_mut(&endpoint_id, |_id, state| {
            if state.active.connection_id() == connection_id {
                // The unregistering client is the currently active client
                if let Some(last_inactive_client) = state.inactive.pop() {
                    metrics.clients_inactive_removed.inc();
                    // There is an inactive client, promote to active again.
                    state.active = last_inactive_client;
                    // Inform the old client that it is healthy again.
                    state.active.try_send_health(Status::Healthy).ok();
                    // Don't remove the entry from client map.
                    false
                } else {
                    // No inactive clients: collect sent_to set for peer-gone notifications.
                    notify_peers = self.0.sent_to.remove(&endpoint_id).map(|(_, peers)| peers);
                    // Remove entry from the client map.
                    true
                }
            } else {
                // The unregistering client is already inactive. Remove from the list of inactive clients.
                state
                    .inactive
                    .retain(|client| client.connection_id() != connection_id);
                metrics.clients_inactive_removed.inc();
                // Active client is unmodified: keep entry in map.
                false
            }
        });

        // Inform peers that this endpoint is gone.
        // Done outside the remove_if_mut closure to avoid DashMap deadlocks.
        if let Some(peers) = notify_peers {
            for peer_id in peers {
                if let Some(peer) = self.0.clients.get(&peer_id) {
                    match peer.active.try_send_peer_gone(endpoint_id) {
                        Ok(_) => {}
                        Err(TrySendError::Full(_)) => {
                            debug!(
                                dst = %peer_id.fmt_short(),
                                "client too busy to receive peer gone notification, dropping"
                            );
                        }
                        Err(TrySendError::Closed(_)) => {
                            debug!(
                                dst = %peer_id.fmt_short(),
                                "can no longer write to client, dropping peer gone notification"
                            );
                        }
                    }
                }
            }
        }
    }

    /// Disconnects connections registered for `endpoint_id`.
    ///
    /// With `Some(connection_id)`, disconnects only that connection (active or
    /// an inactive duplicate). With `None`, disconnects every connection for the
    /// endpoint. Returns `true` if a matching connection was found, or `false`
    /// otherwise.
    ///
    /// Shutdown happens asynchronously: each per-connection actor exits its run
    /// loop and unregisters itself after this call returns.
    pub fn disconnect(&self, endpoint_id: EndpointId, connection_id: Option<ConnectionId>) -> bool {
        let Some(state) = self.0.clients.get(&endpoint_id) else {
            return false;
        };
        let mut clients = state.inactive.iter().chain([&state.active]);
        if let Some(id) = connection_id {
            let Some(client) = clients.find(|c| c.connection_id() == id) else {
                return false;
            };
            client.start_shutdown();
        } else {
            for client in clients {
                client.start_shutdown();
            }
        }
        true
    }

    /// Attempt to send a packet to client with [`EndpointId`] `dst`.
    ///
    /// `permit` is what the forwarding policy issued when it admitted this payload at the sending
    /// connection. It travels with the packet so the destination's boundary can show the policy
    /// what admitted it, however long the payload waited in the queue.
    ///
    /// Returns whether the payload was queued. A destination that is not connected is not an
    /// error, because the sender may simply be ahead of it, but it is not a delivery either: the
    /// payload is gone, and a caller that meters has to know the difference.
    pub(super) fn send_packet(
        &self,
        dst: EndpointId,
        data: Datagrams,
        src: EndpointId,
        permit: ForwardPermit,
        src_connection_id: ConnectionId,
        metrics: &Metrics,
    ) -> Result<bool, ForwardPacketError> {
        let Some(client) = self.0.clients.get(&dst) else {
            debug!(dst = %dst.fmt_short(), "no connected client, dropped packet");
            metrics.send_packets_dropped.inc();
            return Ok(false);
        };
        match client
            .active
            .try_send_packet(src, data, permit, src_connection_id)
        {
            Ok(_) => {
                // Record sent_to relationship
                self.0.sent_to.entry(src).or_default().insert(dst);
                Ok(true)
            }
            Err(TrySendError::Full(_)) => {
                debug!(
                    dst = %dst.fmt_short(),
                    "client too busy to receive packet, dropping packet"
                );
                Err(ForwardPacketError::new(SendError::Full))
            }
            Err(TrySendError::Closed(_)) => {
                debug!(
                    dst = %dst.fmt_short(),
                    "can no longer write to client, dropping message and pruning connection"
                );
                client.active.start_shutdown();
                Err(ForwardPacketError::new(SendError::Closed))
            }
        }
    }

    #[cfg(test)]
    fn active_connection_id(&self, endpoint_id: EndpointId) -> Option<ConnectionId> {
        self.0
            .clients
            .get(&endpoint_id)
            .map(|s| s.active.connection_id())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use iroh_base::SecretKey;
    use n0_error::{Result, StdResultExt};
    use n0_future::{Stream, StreamExt};
    use n0_tracing_test::traced_test;
    use rand::{RngExt, SeedableRng};

    use super::*;
    use crate::{
        client::conn::Conn,
        http::ProtocolVersion,
        protos::{common::FrameType, relay::RelayToClientMsg, streams::WsBytesFramed},
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
                    n0_error::bail_any!(
                        "Unexpected frame, got {:?}, but expected {:?}",
                        frame.typ(),
                        frame_type
                    );
                }
                Ok(frame)
            }
            Some(Err(err)) => Err(err).anyerr(),
            None => n0_error::bail_any!("Unexpected EOF, expected frame {frame_type:?}"),
        }
    }

    fn test_client_builder(
        key: EndpointId,
    ) -> (Config<WsBytesFramed<RateLimited<MaybeTlsStream>>>, Conn) {
        let (server, client) = tokio::io::duplex(1024);
        let guard = OnDisconnectGuard::empty(key);
        let protocol_version = ProtocolVersion::default();
        let mut config = Config::new(guard, ServerRelayedStream::test(server), protocol_version);
        config.write_timeout = Duration::from_secs(1);
        config.channel_capacity = 10;
        (config, Conn::test(client, protocol_version))
    }

    #[tokio::test]
    #[traced_test]
    async fn test_clients() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let a_key = SecretKey::from_bytes(&rng.random()).public();
        let b_key = SecretKey::from_bytes(&rng.random()).public();

        let (builder_a, mut a_rw) = test_client_builder(a_key);

        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());
        clients.register(builder_a, metrics.clone());

        // send packet
        let data = b"hello world!";
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

        {
            let client = clients.0.clients.get(&a_key).unwrap();
            // shutdown client a, this should trigger the removal from the clients list
            client.active.start_shutdown();
        }

        // need to wait a moment for the removal to be processed
        let c = clients.clone();
        tokio::time::timeout(Duration::from_secs(1), async move {
            loop {
                if !c.0.clients.contains_key(&a_key) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .std_context("timeout")?;
        clients.shutdown().await;

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_clients_same_endpoint_id() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let a_key = SecretKey::from_bytes(&rng.random()).public();
        let b_key = SecretKey::from_bytes(&rng.random()).public();

        let (a1_builder, mut a1_rw) = test_client_builder(a_key);

        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());

        // register client a
        clients.register(a1_builder, metrics.clone());
        let a1_conn_id = clients.active_connection_id(a_key).unwrap();

        // send packet and verify it is send to a1
        let data = b"hello world!";
        clients.send_packet(
            a_key,
            Datagrams::from(&data[..]),
            b_key,
            ForwardPermit::default(),
            OnDisconnectGuard::empty(b_key).connection_id(),
            &metrics,
        )?;
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut a1_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: b_key,
                datagrams: data.to_vec().into(),
            }
        );

        // register new client with same endpoint id
        let (a2_builder, mut a2_rw) = test_client_builder(a_key);
        clients.register(a2_builder, metrics.clone());
        let a2_conn_id = clients.active_connection_id(a_key).unwrap();
        assert!(a2_conn_id != a1_conn_id);

        // a1 is marked inactive and should receive a health frame
        let frame = recv_frame(FrameType::Status, &mut a1_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Status(Status::SameEndpointIdConnected)
        );

        // send packet and verify it is send to a2
        clients.send_packet(
            a_key,
            Datagrams::from(&data[..]),
            b_key,
            ForwardPermit::default(),
            OnDisconnectGuard::empty(b_key).connection_id(),
            &metrics,
        )?;
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut a2_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: b_key,
                datagrams: data.to_vec().into(),
            }
        );

        // disconnect a2
        clients
            .0
            .clients
            .get(&a_key)
            .unwrap()
            .active
            .start_shutdown();

        // need to wait a moment for the removal to be processed
        tokio::time::timeout(Duration::from_secs(1), {
            let clients = clients.clone();
            async move {
                // wait until the active connection is no longer a2 (which we unregistered)
                while clients.active_connection_id(a_key) == Some(a2_conn_id) {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        })
        .await
        .std_context("timeout")?;

        // a1 should be marked active again now
        assert_eq!(clients.active_connection_id(a_key), Some(a1_conn_id));

        // a1 is marked active again and should receive a health frame
        let frame = recv_frame(FrameType::Status, &mut a1_rw).await?;
        assert_eq!(frame, RelayToClientMsg::Status(Status::Healthy));

        // a1 should receive packets
        clients.send_packet(
            a_key,
            Datagrams::from(&data[..]),
            b_key,
            ForwardPermit::default(),
            OnDisconnectGuard::empty(b_key).connection_id(),
            &metrics,
        )?;
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut a1_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: b_key,
                datagrams: data.to_vec().into(),
            }
        );

        // after shutting down the now-active client, there should no longer be an entry for that endpoint id
        clients
            .0
            .clients
            .get(&a_key)
            .unwrap()
            .active
            .start_shutdown();

        // need to wait a moment for the removal to be processed
        tokio::time::timeout(Duration::from_secs(1), {
            let clients = clients.clone();
            async move {
                // wait until the active connection is no longer a2 (which we unregistered)
                while clients.0.clients.contains_key(&a_key) {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        })
        .await
        .std_context("timeout")?;

        clients.shutdown().await;

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_peer_gone_notification() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let a_key = SecretKey::from_bytes(&rng.random()).public();
        let b_key = SecretKey::from_bytes(&rng.random()).public();

        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());

        // Register both clients
        let (builder_a, _a_rw) = test_client_builder(a_key);
        let (builder_b, mut b_rw) = test_client_builder(b_key);
        clients.register(builder_a, metrics.clone());
        clients.register(builder_b, metrics.clone());

        // A sends a packet to B (records sent_to[A] = {B})
        let data = b"hello b!";
        clients.send_packet(
            b_key,
            Datagrams::from(&data[..]),
            a_key,
            ForwardPermit::default(),
            OnDisconnectGuard::empty(b_key).connection_id(),
            &metrics,
        )?;

        // B receives the packet
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut b_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: a_key,
                datagrams: data.to_vec().into(),
            }
        );

        // Disconnect A
        {
            let client = clients.0.clients.get(&a_key).unwrap();
            client.active.start_shutdown();
        }

        // Wait for A to unregister
        tokio::time::timeout(Duration::from_secs(1), {
            let clients = clients.clone();
            async move {
                while clients.0.clients.contains_key(&a_key) {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        })
        .await
        .std_context("timeout waiting for A to unregister")?;

        // B should receive EndpointGone(a_key): notifying B that A is gone
        let frame = recv_frame(FrameType::EndpointGone, &mut b_rw).await?;
        assert_eq!(frame, RelayToClientMsg::EndpointGone(a_key));

        clients.shutdown().await;
        Ok(())
    }
}

#[cfg(test)]
mod forwarding_policy_tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use iroh_base::SecretKey;
    use n0_error::Result;
    use n0_future::{SinkExt, StreamExt};
    use n0_tracing_test::traced_test;
    use rand::{RngExt, SeedableRng};

    use super::*;
    use crate::client::conn::Conn;
    use crate::http::ProtocolVersion;
    use crate::protos::{common::FrameType, streams::WsBytesFramed};
    use crate::server::{
        Forward, ForwardBoundary, ForwardOutcome, ForwardPermit, ForwardPolicy, ForwardRequest,
        streams::{MaybeTlsStream, RateLimited, ServerRelayedStream},
    };

    /// A policy that records what it admitted and what it was told became of each payload.
    ///
    /// The point of these tests is the settlement contract, and the only way to see it is to be
    /// the policy: exactly one outcome per admitted payload, describing the admission rather than
    /// whichever side of the relay disposed of it.
    #[derive(Debug, Default)]
    struct RecordingPolicy {
        /// Payloads admitted at the sending connection, by the permit issued for each.
        admitted: Mutex<Vec<u64>>,
        /// Outcomes, as (permit, boundary the request described, outcome).
        settled: Mutex<Vec<(u64, ForwardBoundary, ForwardOutcome)>>,
        /// Whether the destination's own boundary refuses what reaches it.
        refuse_at_egress: bool,
    }

    impl RecordingPolicy {
        fn shared(refuse_at_egress: bool) -> Arc<Self> {
            Arc::new(Self {
                refuse_at_egress,
                ..Self::default()
            })
        }

        fn settled(&self) -> Vec<(u64, ForwardBoundary, ForwardOutcome)> {
            self.settled.lock().expect("the recorder").clone()
        }
    }

    impl ForwardPolicy for RecordingPolicy {
        fn on_forward(&self, request: &ForwardRequest<'_>) -> Forward {
            match request.boundary() {
                ForwardBoundary::Ingress => {
                    let mut admitted = self.admitted.lock().expect("the recorder");
                    let permit = admitted.len() as u64 + 1;
                    admitted.push(permit);
                    Forward::Allow {
                        permit: ForwardPermit {
                            admission: permit,
                            allocation: 7,
                        },
                    }
                }
                ForwardBoundary::Egress if self.refuse_at_egress => Forward::Drop,
                ForwardBoundary::Egress => Forward::Allow {
                    permit: request.permit().unwrap_or_default(),
                },
            }
        }

        fn on_settled(&self, request: &ForwardRequest<'_>, outcome: ForwardOutcome) {
            self.settled.lock().expect("the recorder").push((
                request.permit().unwrap_or_default().admission,
                request.boundary(),
                outcome,
            ));
        }
    }

    fn client_with(
        key: EndpointId,
        policy: Arc<RecordingPolicy>,
    ) -> (Config<WsBytesFramed<RateLimited<MaybeTlsStream>>>, Conn) {
        let (server, client) = tokio::io::duplex(1024);
        let protocol_version = ProtocolVersion::default();
        let mut config = Config::new(
            OnDisconnectGuard::empty(key),
            ServerRelayedStream::test(server),
            protocol_version,
        );
        config.write_timeout = Duration::from_secs(1);
        config.channel_capacity = 10;
        config.forward = policy;
        (config, Conn::test(client, protocol_version))
    }

    #[tokio::test]
    #[traced_test]
    async fn a_payload_with_nowhere_to_go_is_settled_as_dropped() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(7u64);
        let sender = SecretKey::from_bytes(&rng.random()).public();
        let absent = SecretKey::from_bytes(&rng.random()).public();

        let policy = RecordingPolicy::shared(false);
        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());
        let (config, mut sender_rw) = client_with(sender, policy.clone());
        let connection = config.guard.connection_id();
        clients.register(config, metrics.clone());

        sender_rw
            .send(crate::protos::relay::ClientToRelayMsg::Datagrams {
                dst_endpoint_id: absent,
                datagrams: Datagrams::from(&b"nowhere"[..]),
            })
            .await?;

        // The sending connection admitted it and nothing else will ever see it, so the sending
        // connection is what reports the outcome.
        let settled = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let seen = policy.settled();
                if !seen.is_empty() {
                    return seen;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("an outcome");

        assert_eq!(settled.len(), 1, "exactly one outcome per admitted payload");
        assert_eq!(
            settled[0],
            (1, ForwardBoundary::Ingress, ForwardOutcome::Dropped)
        );
        let _ = connection;
        clients.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn a_delivered_payload_is_settled_once_as_committed() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(9u64);
        let sender = SecretKey::from_bytes(&rng.random()).public();
        let receiver = SecretKey::from_bytes(&rng.random()).public();

        let policy = RecordingPolicy::shared(false);
        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());
        let (sender_config, mut sender_rw) = client_with(sender, policy.clone());
        let (receiver_config, mut receiver_rw) = client_with(receiver, policy.clone());
        clients.register(sender_config, metrics.clone());
        clients.register(receiver_config, metrics.clone());

        sender_rw
            .send(crate::protos::relay::ClientToRelayMsg::Datagrams {
                dst_endpoint_id: receiver,
                datagrams: Datagrams::from(&b"through"[..]),
            })
            .await?;

        let frame = receiver_rw.next().await.expect("a frame")?;
        assert_eq!(frame.typ(), FrameType::RelayToClientDatagram);

        let settled = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let seen = policy.settled();
                if !seen.is_empty() {
                    return seen;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("an outcome");

        // One outcome, carrying the permit the sending connection was given and describing that
        // admission, although it was the receiving connection that wrote the payload out.
        assert_eq!(settled.len(), 1);
        assert_eq!(
            settled[0],
            (1, ForwardBoundary::Ingress, ForwardOutcome::Committed)
        );

        clients.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn a_payload_the_destination_refuses_is_settled_as_dropped() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(11u64);
        let sender = SecretKey::from_bytes(&rng.random()).public();
        let receiver = SecretKey::from_bytes(&rng.random()).public();

        // The capability was replaced while the payload sat in the queue, so the destination's own
        // boundary refuses it. That is the payload's end, and it is reported as such rather than
        // quietly disappearing with a debit behind it.
        let policy = RecordingPolicy::shared(true);
        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());
        let (sender_config, mut sender_rw) = client_with(sender, policy.clone());
        let (receiver_config, _receiver_rw) = client_with(receiver, policy.clone());
        clients.register(sender_config, metrics.clone());
        clients.register(receiver_config, metrics.clone());

        sender_rw
            .send(crate::protos::relay::ClientToRelayMsg::Datagrams {
                dst_endpoint_id: receiver,
                datagrams: Datagrams::from(&b"fenced"[..]),
            })
            .await?;

        let settled = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let seen = policy.settled();
                if !seen.is_empty() {
                    return seen;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("an outcome");

        assert_eq!(settled.len(), 1);
        assert_eq!(
            settled[0],
            (1, ForwardBoundary::Ingress, ForwardOutcome::Dropped)
        );

        clients.shutdown().await;
        Ok(())
    }
}
