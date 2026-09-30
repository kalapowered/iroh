//! Pkarr packet store used to resolve DNS queries.

use std::{collections::BTreeMap, num::NonZeroUsize, path::Path, sync::Arc, time::Duration};

use hickory_server::proto::{
    ProtoError,
    rr::{Name, RecordSet, RecordType, RrKey},
};
use iroh_dns::pkarr::{SignedPacket, SignedPacketVerifyError, Timestamp};
use lru::LruCache;
use n0_error::{Result, StdResultExt};
use n0_mainline::{Dht, DhtBuilder, MutableItem};
pub(crate) use signed_packets::Options;
use tokio::sync::Mutex;
use tracing::{debug, trace, warn};
use ttl_cache::TtlCache;

use self::signed_packets::SignedPacketStore;
use crate::{
    config::BootstrapOption,
    metrics::Metrics,
    util::{PublicKeyBytes, signed_packet_to_hickory_records_without_origin},
};

mod signed_packets;

/// Cache up to 1 million pkarr zones by default
const DEFAULT_CACHE_CAPACITY: usize = 1024 * 1024;
/// Default TTL for DHT cache entries
const DHT_CACHE_TTL: Duration = Duration::from_secs(300);

/// Where a new pkarr packet comes from
pub(crate) enum PacketSource {
    /// Received via HTTPS relay PUT
    PkarrPublish,
}

/// A store for pkarr signed packets.
///
/// Packets are stored in the persistent `SignedPacketStore`, and cached on-demand in an in-memory LRU
/// cache used for resolving DNS queries.
#[derive(Debug, Clone)]
pub(crate) struct ZoneStore {
    cache: Arc<Mutex<ZoneCache>>,
    store: Arc<SignedPacketStore>,
    dht: Option<Dht>,
    metrics: Arc<Metrics>,
    #[cfg(test)]
    read_gate: Arc<std::sync::Mutex<Option<Arc<ReadGate>>>>,
}

impl ZoneStore {
    /// Create a persistent store
    pub(crate) fn persistent(
        path: impl AsRef<Path>,
        options: Options,
        metrics: Arc<Metrics>,
    ) -> Result<Self> {
        let packet_store = SignedPacketStore::persistent(path, options, metrics.clone())?;
        Ok(Self::new(packet_store, metrics))
    }

    /// Create an in-memory store.
    #[cfg(test)]
    pub(crate) fn in_memory(options: Options, metrics: Arc<Metrics>) -> Result<Self> {
        let packet_store = SignedPacketStore::in_memory(options, metrics.clone())?;
        Ok(Self::new(packet_store, metrics))
    }

    /// Create an in-memory store that evicts only when [`Self::evict_expired`] is called.
    #[cfg(test)]
    pub(crate) fn in_memory_manual_eviction(
        options: Options,
        metrics: Arc<Metrics>,
    ) -> Result<Self> {
        let packet_store = SignedPacketStore::in_memory_manual_eviction(options, metrics.clone())?;
        Ok(Self::new(packet_store, metrics))
    }

    /// Configure a mainline DHT client for resolution of packets as a fallback.
    ///
    /// This will be used only as a fallback if there is no local info available.
    ///
    /// Optionally set custom bootstrap nodes. If `bootstrap` is empty it will use the default
    /// mainline bootstrap nodes.
    pub(crate) fn with_mainline_fallback(self, bootstrap: BootstrapOption) -> Self {
        let mut builder = DhtBuilder::default();
        if let BootstrapOption::Custom(ref nodes) = bootstrap {
            builder.bootstrap(nodes);
        }
        let dht = builder.build().expect("failed to build DHT node");
        Self {
            dht: Some(dht),
            ..self
        }
    }

    /// Create a new zone store.
    fn new(store: SignedPacketStore, metrics: Arc<Metrics>) -> Self {
        let zone_cache = ZoneCache::new(DEFAULT_CACHE_CAPACITY, metrics.clone());
        Self {
            store: Arc::new(store),
            cache: Arc::new(Mutex::new(zone_cache)),
            dht: None,
            metrics,
            #[cfg(test)]
            read_gate: Default::default(),
        }
    }

    /// Resolve a DNS query.
    #[tracing::instrument("resolve", skip_all, fields(pubkey=%pubkey,name=%name,typ=%record_type))]
    pub(crate) async fn resolve(
        &self,
        pubkey: &PublicKeyBytes,
        name: &Name,
        record_type: RecordType,
    ) -> Result<Option<Arc<RecordSet>>> {
        trace!("store resolve");

        // Check cache first (short lock scope)
        {
            let mut cache = self.cache.lock().await;
            if let Some(rset) = cache.resolve(pubkey, name, record_type) {
                debug!(
                    len = rset.records_without_rrsigs().count(),
                    "resolved from cache"
                );
                return Ok(Some(rset));
            }
        }

        // Check persistent store
        if let Some(packet) = self.store.get(pubkey).await? {
            trace!(packet_timestamp = ?packet.timestamp(), "store hit");
            #[cfg(test)]
            self.pause_after_store_read().await;
            let mut cache = self.cache.lock().await;
            let result = cache.insert_and_resolve(&packet, name, record_type);
            return match result {
                Ok(Some(rset)) => {
                    debug!(
                        len = rset.records_without_rrsigs().count(),
                        "resolved from store"
                    );
                    Ok(Some(rset))
                }
                Ok(None) => {
                    debug!("resolved to zone, but no matching records in zone");
                    Ok(None)
                }
                Err(err) => {
                    warn!("failed to retrieve zone after inserting in cache: {err:#?}");
                    Err(err)
                }
            };
        };

        if let Some(dht) = self.dht.as_ref() {
            debug!("DHT resolve {}", pubkey.to_z32());
            let maybe_item = dht.get_mutable_most_recent(pubkey.as_bytes(), None).await?;
            if let Some(item) = maybe_item
                && let Ok(packet) = mutable_item_to_signed_packet(&item)
            {
                debug!("DHT resolve successful {:?}", packet);
                return self
                    .cache
                    .lock()
                    .await
                    .insert_and_resolve_dht(&packet, name, record_type);
            }
            debug!("DHT resolve failed");
        }
        Ok(None)
    }

    /// Get the latest signed packet for a pubkey.
    // allow unused async: this will be async soon.
    #[allow(clippy::unused_async)]
    pub(crate) async fn get_signed_packet(
        &self,
        pubkey: &PublicKeyBytes,
    ) -> Result<Option<SignedPacket>> {
        self.store.get(pubkey).await
    }

    /// Insert a signed packet into the cache and the store.
    ///
    /// Returns whether this produced an update, i.e. whether the packet is the newest for its
    /// pubkey.
    // allow unused async: this will be async soon.
    #[allow(clippy::unused_async)]
    pub(crate) async fn insert(
        &self,
        signed_packet: SignedPacket,
        _source: PacketSource,
    ) -> Result<bool> {
        let pubkey = PublicKeyBytes::from_signed_packet(&signed_packet);
        if self.store.upsert(signed_packet).await? {
            self.metrics.pkarr_publish_update.inc();
            self.cache.lock().await.remove(&pubkey);
            Ok(true)
        } else {
            self.metrics.pkarr_publish_noop.inc();
            Ok(false)
        }
    }
}

#[cfg(test)]
impl ZoneStore {
    /// Run one eviction pass and return once the store has handled it.
    pub(crate) async fn evict_expired(&self) -> Result<()> {
        self.store.evict_expired().await
    }

    /// Whether the cache holds a zone for this key.
    pub(crate) fn cached(&self, pubkey: &PublicKeyBytes) -> bool {
        self.cache
            .try_lock()
            .expect("the cache is not in use")
            .cache
            .contains(pubkey)
    }

    /// Pause the next lookup that finds a packet in the store, after it has read the packet and
    /// before it caches it, until the returned gate is opened.
    pub(crate) fn pause_next_lookup(&self) -> Arc<ReadGate> {
        let gate = Arc::new(ReadGate::new());
        *self.read_gate.lock().expect("gate slot") = Some(gate.clone());
        gate
    }

    async fn pause_after_store_read(&self) {
        let gate = self.read_gate.lock().expect("gate slot").take();
        if let Some(gate) = gate {
            gate.arrived.add_permits(1);
            gate.open.acquire().await.expect("gate is open").forget();
        }
    }
}

/// Holds one lookup between its store read and its cache insert.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct ReadGate {
    /// A permit is added when a lookup has read the store and waits.
    pub(crate) arrived: tokio::sync::Semaphore,
    /// Adding a permit lets the waiting lookup go on.
    pub(crate) open: tokio::sync::Semaphore,
}

#[cfg(test)]
impl ReadGate {
    fn new() -> Self {
        Self {
            arrived: tokio::sync::Semaphore::new(0),
            open: tokio::sync::Semaphore::new(0),
        }
    }
}

/// Convert a mainline [`MutableItem`] to a [`SignedPacket`].
fn mutable_item_to_signed_packet(
    item: &MutableItem,
) -> Result<SignedPacket, SignedPacketVerifyError> {
    SignedPacket::from_parts_unchecked(
        item.key(),
        item.signature(),
        Timestamp::from_micros(item.seq() as u64),
        item.value(),
    )
}

#[derive(derive_more::Debug)]
struct ZoneCache {
    /// Cache for explicitly added entries
    cache: LruCache<PublicKeyBytes, CachedZone>,
    /// Cache for DHT entries, this must have a finite TTL
    /// so we don't cache stale entries indefinitely.
    #[debug("dht_cache")]
    dht_cache: TtlCache<PublicKeyBytes, CachedZone>,
    #[debug("metrics")]
    metrics: Arc<Metrics>,
}

impl ZoneCache {
    fn new(cap: usize, metrics: Arc<Metrics>) -> Self {
        let cache = LruCache::new(NonZeroUsize::new(cap).expect("capacity must be larger than 0"));
        let dht_cache = TtlCache::new(cap);
        Self {
            cache,
            dht_cache,
            metrics,
        }
    }

    fn resolve(
        &mut self,
        pubkey: &PublicKeyBytes,
        name: &Name,
        record_type: RecordType,
    ) -> Option<Arc<RecordSet>> {
        let zone = if let Some(zone) = self.cache.get(pubkey) {
            trace!("cache hit {}", pubkey.to_z32());
            zone
        } else {
            let zone = self.dht_cache.get(pubkey)?;
            trace!("dht cache hit {}", pubkey.to_z32());
            zone
        };
        zone.resolve(name, record_type)
    }

    fn insert_and_resolve(
        &mut self,
        signed_packet: &SignedPacket,
        name: &Name,
        record_type: RecordType,
    ) -> Result<Option<Arc<RecordSet>>> {
        let pubkey = PublicKeyBytes::from_signed_packet(signed_packet);
        self.insert(signed_packet)?;
        Ok(self.resolve(&pubkey, name, record_type))
    }

    fn insert_and_resolve_dht(
        &mut self,
        signed_packet: &SignedPacket,
        name: &Name,
        record_type: RecordType,
    ) -> Result<Option<Arc<RecordSet>>> {
        let pubkey = PublicKeyBytes::from_signed_packet(signed_packet);
        let zone = CachedZone::from_signed_packet(signed_packet).anyerr()?;
        let res = zone.resolve(name, record_type);
        self.dht_cache.insert(pubkey, zone, DHT_CACHE_TTL);
        self.metrics
            .cache_zones_dht
            .set(self.dht_cache.iter().count() as i64);
        Ok(res)
    }

    fn insert(&mut self, signed_packet: &SignedPacket) -> Result<()> {
        let pubkey = PublicKeyBytes::from_signed_packet(signed_packet);
        if self
            .cache
            .peek(&pubkey)
            .map(|old| old.is_newer_than(signed_packet))
            .unwrap_or(false)
        {
            trace!("insert skip: cached is newer");
            Ok(())
        } else {
            self.cache.put(
                pubkey,
                CachedZone::from_signed_packet(signed_packet).anyerr()?,
            );
            self.metrics.cache_zones.set(self.cache.len() as i64);
            trace!("inserted into cache");
            Ok(())
        }
    }

    fn remove(&mut self, pubkey: &PublicKeyBytes) {
        self.cache.pop(pubkey);
        self.dht_cache.remove(pubkey);
        self.metrics.cache_zones.set(self.cache.len() as i64);
        self.metrics
            .cache_zones_dht
            .set(self.dht_cache.iter().count() as i64);
    }
}

#[derive(Debug)]
struct CachedZone {
    timestamp: Timestamp,
    records: BTreeMap<RrKey, Arc<RecordSet>>,
}

impl CachedZone {
    fn from_signed_packet(signed_packet: &SignedPacket) -> Result<Self, ProtoError> {
        let (_label, records) =
            signed_packet_to_hickory_records_without_origin(signed_packet, |_| true)?;
        Ok(Self {
            records,
            timestamp: signed_packet.timestamp(),
        })
    }

    fn is_newer_than(&self, signed_packet: &SignedPacket) -> bool {
        self.timestamp > signed_packet.timestamp()
    }

    fn resolve(&self, name: &Name, record_type: RecordType) -> Option<Arc<RecordSet>> {
        trace!(name=%name, typ=%record_type, "resolve in zone");
        let key = RrKey::new(name.into(), record_type);
        self.records.get(&key).cloned()
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use hickory_server::proto::rr::{Name, RData, RecordSet, RecordType};
    use iroh_base::SecretKey;
    use iroh_dns::pkarr::SignedPacket;
    use n0_error::Result;

    use super::{Options, PacketSource, ZoneStore};
    use crate::{
        testing::{DAY_MICROS, now_micros, signed_packet_at},
        util::PublicKeyBytes,
    };

    /// A store that evicts a packet a day after its signed time, and only when a test asks.
    ///
    /// One packet per write transaction, and a transaction that never times out: a message the
    /// writer answers is one whose predecessors have all been committed.
    fn store() -> Result<ZoneStore> {
        let options = Options {
            max_batch_size: 1,
            max_batch_time: Duration::from_secs(3600),
            eviction: Duration::from_secs(24 * 3600),
            eviction_interval: Duration::from_secs(3600),
        };
        ZoneStore::in_memory_manual_eviction(options, Default::default())
    }

    /// The name the DNS handler passes for `_iroh.<endpoint>.<origin>`: the labels between the
    /// endpoint and the query's start, with no origin and not fully qualified.
    fn name() -> Name {
        Name::from_labels([b"_iroh".as_slice()]).expect("a name")
    }

    fn key(secret_key: &SecretKey) -> PublicKeyBytes {
        PublicKeyBytes::new_unchecked(*secret_key.public().as_bytes())
    }

    async fn publish(store: &ZoneStore, packet: SignedPacket) -> Result<bool> {
        store.insert(packet, PacketSource::PkarrPublish).await
    }

    async fn lookup(store: &ZoneStore, secret_key: &SecretKey) -> Result<Option<String>> {
        let rset = store
            .resolve(&key(secret_key), &name(), RecordType::TXT)
            .await?;
        Ok(rset.as_deref().map(relay_of))
    }

    /// The relay a `_iroh` TXT record set names.
    fn relay_of(rset: &RecordSet) -> String {
        let record = rset.records_without_rrsigs().next().expect("a record");
        match &record.data {
            RData::TXT(txt) => txt
                .txt_data
                .iter()
                .map(|part| String::from_utf8_lossy(part).into_owned())
                .collect::<String>(),
            other => panic!("not a TXT record: {other:?}"),
        }
    }

    /// A packet signed two days ago, which the store's one-day retention has expired.
    fn expired_packet(secret_key: &SecretKey, relay: &str) -> SignedPacket {
        signed_packet_at(secret_key, now_micros() - 2 * DAY_MICROS, relay)
    }

    #[tokio::test]
    async fn an_evicted_record_is_not_answered_from_the_cache() -> Result {
        let store = store()?;
        let endpoint = SecretKey::generate();
        publish(&store, expired_packet(&endpoint, "old")).await?;

        // The first lookup fills the cache.
        assert_eq!(
            lookup(&store, &endpoint).await?.as_deref(),
            Some("relay=old")
        );
        assert!(store.cached(&key(&endpoint)));

        store.evict_expired().await?;

        assert!(store.get_signed_packet(&key(&endpoint)).await?.is_none());
        assert_eq!(lookup(&store, &endpoint).await?, None);
        Ok(())
    }

    #[tokio::test]
    async fn a_record_that_has_not_expired_stays_cached_through_an_eviction_pass() -> Result {
        let store = store()?;
        let endpoint = SecretKey::generate();
        publish(&store, signed_packet_at(&endpoint, now_micros(), "live")).await?;
        assert_eq!(
            lookup(&store, &endpoint).await?.as_deref(),
            Some("relay=live")
        );

        store.evict_expired().await?;

        assert!(store.cached(&key(&endpoint)));
        assert_eq!(
            lookup(&store, &endpoint).await?.as_deref(),
            Some("relay=live")
        );
        Ok(())
    }

    #[tokio::test]
    async fn evicting_one_endpoint_leaves_another_endpoints_zone_cached() -> Result {
        let store = store()?;
        let stale = SecretKey::generate();
        let live = SecretKey::generate();
        publish(&store, expired_packet(&stale, "old")).await?;
        publish(&store, signed_packet_at(&live, now_micros(), "live")).await?;
        assert_eq!(lookup(&store, &stale).await?.as_deref(), Some("relay=old"));
        assert_eq!(lookup(&store, &live).await?.as_deref(), Some("relay=live"));
        assert!(store.cached(&key(&stale)) && store.cached(&key(&live)));

        store.evict_expired().await?;

        assert!(store.get_signed_packet(&key(&stale)).await?.is_none());
        assert!(store.get_signed_packet(&key(&live)).await?.is_some());
        assert!(!store.cached(&key(&stale)));
        assert!(store.cached(&key(&live)));
        Ok(())
    }

    #[tokio::test]
    async fn a_lookup_that_overlaps_a_publication_cannot_restore_the_older_packet() -> Result {
        let store = store()?;
        let endpoint = SecretKey::generate();
        let now = now_micros();
        publish(&store, signed_packet_at(&endpoint, now, "older")).await?;

        // The lookup misses the cache, reads the older packet and stops before it caches it.
        let gate = store.pause_next_lookup();
        let overlapping = tokio::spawn({
            let store = store.clone();
            let endpoint = endpoint.clone();
            async move { lookup(&store, &endpoint).await }
        });
        gate.arrived.acquire().await.expect("gate").forget();

        // A newer packet is published while it waits.
        publish(&store, signed_packet_at(&endpoint, now + 1, "newer")).await?;
        gate.open.add_permits(1);
        let answered = overlapping.await.expect("the lookup task")?;
        assert!(answered.is_some(), "the overlapping lookup still answers");

        // Whatever the overlapping lookup did, the next lookup answers the newer packet.
        assert_eq!(
            lookup(&store, &endpoint).await?.as_deref(),
            Some("relay=newer")
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_lookup_that_overlaps_an_eviction_cannot_restore_the_evicted_packet() -> Result {
        let store = store()?;
        let endpoint = SecretKey::generate();
        publish(&store, expired_packet(&endpoint, "old")).await?;

        let gate = store.pause_next_lookup();
        let overlapping = tokio::spawn({
            let store = store.clone();
            let endpoint = endpoint.clone();
            async move { lookup(&store, &endpoint).await }
        });
        gate.arrived.acquire().await.expect("gate").forget();

        store.evict_expired().await?;
        gate.open.add_permits(1);
        let answered = overlapping.await.expect("the lookup task")?;
        assert!(answered.is_some(), "the overlapping lookup still answers");

        assert!(!store.cached(&key(&endpoint)));
        assert_eq!(lookup(&store, &endpoint).await?, None);
        Ok(())
    }

    #[tokio::test]
    async fn a_lookup_with_no_overlap_caches_the_packet_it_read() -> Result {
        let store = store()?;
        let endpoint = SecretKey::generate();
        publish(&store, signed_packet_at(&endpoint, now_micros(), "current")).await?;
        assert!(!store.cached(&key(&endpoint)));

        assert_eq!(
            lookup(&store, &endpoint).await?.as_deref(),
            Some("relay=current")
        );

        assert!(store.cached(&key(&endpoint)));
        Ok(())
    }

    #[tokio::test]
    async fn a_lookup_never_changes_the_packet_store() -> Result {
        let metrics = Arc::new(crate::metrics::Metrics::default());
        let options = Options {
            max_batch_size: 1,
            max_batch_time: Duration::from_secs(3600),
            ..Default::default()
        };
        let store = ZoneStore::in_memory_manual_eviction(options, metrics.clone())?;
        let endpoint = SecretKey::generate();
        let packet = signed_packet_at(&endpoint, now_micros(), "current");
        publish(&store, packet.clone()).await?;
        let inserted = metrics.store_packets_inserted.get();
        let updated = metrics.store_packets_updated.get();

        // A lookup that fills the cache, one served from it, and one for an endpoint the store
        // does not hold: none writes the store.
        assert!(lookup(&store, &endpoint).await?.is_some());
        assert!(lookup(&store, &endpoint).await?.is_some());
        let unknown = SecretKey::generate();
        assert_eq!(lookup(&store, &unknown).await?, None);

        assert_eq!(metrics.store_packets_inserted.get(), inserted);
        assert_eq!(metrics.store_packets_updated.get(), updated);
        let stored = store
            .get_signed_packet(&key(&endpoint))
            .await?
            .expect("stored");
        assert_eq!(stored.as_bytes(), packet.as_bytes());
        Ok(())
    }
}
