//! Pkarr packet store used to resolve DNS queries.

use std::{
    collections::BTreeMap,
    num::NonZeroUsize,
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, SystemTime},
};

use hickory_server::proto::{
    ProtoError,
    rr::{Name, RecordSet, RecordType, RrKey},
};
use iroh_dns::pkarr::{SignedPacket, SignedPacketVerifyError, Timestamp};
use lru::LruCache;
use n0_error::{AnyError, Result, StdResultExt, e, stack_error};
use n0_mainline::{Dht, DhtBuilder, MutableItem};
pub(crate) use signed_packets::Options;
use tracing::{debug, info, trace, warn};
use ttl_cache::TtlCache;

use self::signed_packets::{OnChange, SignedPacketStore};
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
/// The number of change counters the zone cache keeps. A key shares its counter with one in
/// `CHANGE_COUNTERS` others on average, so a change to one key rarely makes a lookup of another
/// skip its cache fill.
const CHANGE_COUNTERS: usize = 1024;

/// The furthest ahead of the server's clock a packet may be signed.
///
/// The store keeps a packet for a retention period counted from its signed time, so a packet
/// signed far in the future would stay long after the period it was meant for. A publisher whose
/// clock is a little fast is still served.
pub(crate) const MAX_TIMESTAMP_AHEAD: Duration = Duration::from_secs(10 * 60);

/// Why a packet was not inserted.
#[stack_error(derive, add_meta)]
pub(crate) enum InsertError {
    /// The packet is signed too far ahead of the server's clock.
    #[error(
        "the packet is signed {} seconds ahead of the server's clock, more than the {} seconds allowed",
        ahead.as_secs(),
        MAX_TIMESTAMP_AHEAD.as_secs()
    )]
    TimestampAhead { ahead: Duration },
    /// The packet store failed.
    #[error("the packet store failed")]
    Store { source: AnyError },
}

/// Check that a packet signed at `timestamp` is not too far ahead of `now`, the server's clock in
/// microseconds since the UNIX epoch.
fn check_timestamp_ahead(timestamp: Timestamp, now: u64) -> Result<(), InsertError> {
    let signed = timestamp.as_micros();
    let latest_allowed = now.saturating_add(MAX_TIMESTAMP_AHEAD.as_micros() as u64);
    if signed > latest_allowed {
        return Err(e!(InsertError::TimestampAhead {
            ahead: Duration::from_micros(signed - now)
        }));
    }
    Ok(())
}

/// The server's wall clock in microseconds since the UNIX epoch, read once for each check.
///
/// Not [`Timestamp::now`]: that one never goes back, so after the clock is set back it stays
/// ahead of the wall clock and would let a packet through that is ahead of it.
fn wall_clock_micros() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|since| since.as_micros() as u64)
        .unwrap_or(0)
}

/// Where a new pkarr packet comes from
pub(crate) enum PacketSource {
    /// Received via HTTPS relay PUT
    PkarrPublish,
}

/// A store for pkarr signed packets.
///
/// Packets are stored in the persistent `SignedPacketStore`, and cached on-demand in an in-memory LRU
/// cache used for resolving DNS queries.
///
/// The packet store's writer is the only thing that changes a stored packet, and it tells the
/// cache about every change (a publication that replaces a packet, an eviction) before it takes
/// its next message. So once a publication or an eviction is done, no lookup that starts later
/// answers from the packet it replaced or removed, and no lookup that started earlier caches it.
#[derive(Debug, Clone)]
pub(crate) struct ZoneStore {
    cache: Arc<Mutex<ZoneCache>>,
    store: Arc<SignedPacketStore>,
    dht: Option<Dht>,
    metrics: Arc<Metrics>,
    #[cfg(test)]
    read_gate: Arc<Mutex<Option<Arc<ReadGate>>>>,
}

impl ZoneStore {
    /// Create a persistent store
    pub(crate) fn persistent(
        path: impl AsRef<Path>,
        options: Options,
        metrics: Arc<Metrics>,
    ) -> Result<Self> {
        let cache = new_cache(&metrics);
        let packet_store =
            SignedPacketStore::persistent(path, options, metrics.clone(), invalidator(&cache))?;
        Ok(Self::new(packet_store, cache, metrics))
    }

    /// Create an in-memory store.
    #[cfg(test)]
    pub(crate) fn in_memory(options: Options, metrics: Arc<Metrics>) -> Result<Self> {
        let cache = new_cache(&metrics);
        let packet_store =
            SignedPacketStore::in_memory(options, metrics.clone(), invalidator(&cache))?;
        Ok(Self::new(packet_store, cache, metrics))
    }

    /// Create an in-memory store that evicts only when [`Self::evict_expired`] is called.
    #[cfg(test)]
    pub(crate) fn in_memory_manual_eviction(
        options: Options,
        metrics: Arc<Metrics>,
    ) -> Result<Self> {
        let cache = new_cache(&metrics);
        let packet_store = SignedPacketStore::in_memory_manual_eviction(
            options,
            metrics.clone(),
            invalidator(&cache),
        )?;
        Ok(Self::new(packet_store, cache, metrics))
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
    fn new(store: SignedPacketStore, cache: Arc<Mutex<ZoneCache>>, metrics: Arc<Metrics>) -> Self {
        Self {
            store: Arc::new(store),
            cache,
            dht: None,
            metrics,
            #[cfg(test)]
            read_gate: Default::default(),
        }
    }

    /// Lock the zone cache.
    ///
    /// The cache is never held across an await: the guard is not `Send`, so a handler that did
    /// would not compile, and the packet store's writer takes the same lock from its own thread.
    fn lock_cache(&self) -> MutexGuard<'_, ZoneCache> {
        lock_cache(&self.cache)
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

        // Check cache first (short lock scope). A miss also notes the key's change counter: a
        // packet read from the store below is cached only if the counter has not moved by then.
        let changes = {
            let mut cache = self.lock_cache();
            if let Some(rset) = cache.resolve(pubkey, name, record_type) {
                debug!(
                    len = rset.records_without_rrsigs().count(),
                    "resolved from cache"
                );
                return Ok(Some(rset));
            }
            cache.changes(pubkey)
        };

        // Check persistent store
        if let Some(packet) = self.store.get(pubkey).await? {
            trace!(packet_timestamp = ?packet.timestamp(), "store hit");
            #[cfg(test)]
            self.pause_after_store_read().await;
            let result = match CachedZone::from_signed_packet(&packet).anyerr() {
                Ok(zone) => Ok(self.lock_cache().insert_and_resolve(
                    pubkey,
                    zone,
                    changes,
                    name,
                    record_type,
                )),
                Err(err) => Err(err),
            };
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
                let zone = CachedZone::from_signed_packet(&packet).anyerr()?;
                return Ok(self.lock_cache().insert_and_resolve_dht(
                    pubkey,
                    zone,
                    changes,
                    name,
                    record_type,
                ));
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

    /// Insert a signed packet into the store.
    ///
    /// Refuses a packet signed more than [`MAX_TIMESTAMP_AHEAD`] ahead of the server's clock.
    /// This is the only way a packet reaches the store: a packet from the DHT fallback goes to
    /// the cache only.
    ///
    /// Returns whether this produced an update, i.e. whether the packet is the newest for its
    /// pubkey. The cache drops its zone for the key when the store's writer applies the update,
    /// not when this call returns, so a publication whose request is dropped half way still
    /// reaches the cache.
    // allow unused async: this will be async soon.
    #[allow(clippy::unused_async)]
    pub(crate) async fn insert(
        &self,
        signed_packet: SignedPacket,
        _source: PacketSource,
    ) -> Result<bool, InsertError> {
        if let Err(err) = check_timestamp_ahead(signed_packet.timestamp(), wall_clock_micros()) {
            self.metrics.pkarr_publish_timestamp_ahead.inc();
            let key = signed_packet.public_key().to_z32();
            info!(
                key = key.get(..10).unwrap_or(&key),
                "publication refused: {err}"
            );
            return Err(err);
        }
        let updated = self
            .store
            .upsert(signed_packet)
            .await
            .map_err(|source| e!(InsertError::Store, source))?;
        if updated {
            self.metrics.pkarr_publish_update.inc();
            Ok(true)
        } else {
            self.metrics.pkarr_publish_noop.inc();
            Ok(false)
        }
    }
}

fn new_cache(metrics: &Arc<Metrics>) -> Arc<Mutex<ZoneCache>> {
    Arc::new(Mutex::new(ZoneCache::new(
        DEFAULT_CACHE_CAPACITY,
        metrics.clone(),
    )))
}

/// What the packet store's writer calls when it has changed a key's stored packet.
fn invalidator(cache: &Arc<Mutex<ZoneCache>>) -> OnChange {
    let cache = cache.clone();
    Arc::new(move |pubkey| lock_cache(&cache).remove(pubkey))
}

/// Lock the zone cache, and start it over if a panic under the lock left it in doubt.
fn lock_cache(cache: &Mutex<ZoneCache>) -> MutexGuard<'_, ZoneCache> {
    cache.lock().unwrap_or_else(|poisoned| {
        let mut guard = poisoned.into_inner();
        guard.reset();
        cache.clear_poison();
        guard
    })
}

#[cfg(test)]
impl ZoneStore {
    /// Run one eviction pass and return once the store has handled it.
    pub(crate) async fn evict_expired(&self) -> Result<()> {
        self.store.evict_expired().await
    }

    /// Whether the cache holds a zone for this key.
    pub(crate) fn cached(&self, pubkey: &PublicKeyBytes) -> bool {
        self.lock_cache().cache.contains(pubkey)
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
    /// Counts the changes made to the stored packets, one counter for each group of keys.
    ///
    /// A lookup that reads the store notes its key's counter first and caches what it read only
    /// if the counter is the same afterwards: a change in between is one the lookup may have
    /// missed, and what it read may be older than the store.
    #[debug("changes")]
    changes: Box<[u64; CHANGE_COUNTERS]>,
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
            changes: Box::new([0; CHANGE_COUNTERS]),
            metrics,
        }
    }

    fn counter(pubkey: &PublicKeyBytes) -> usize {
        let bytes = pubkey.as_bytes();
        usize::from(u16::from_be_bytes([bytes[0], bytes[1]])) % CHANGE_COUNTERS
    }

    /// The change counter of the group `pubkey` belongs to.
    fn changes(&self, pubkey: &PublicKeyBytes) -> u64 {
        self.changes[Self::counter(pubkey)]
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

    /// Cache a zone built from the store's packet and answer from the cache, unless the key's
    /// stored packet changed since `changes` was noted: then answer from the zone alone.
    fn insert_and_resolve(
        &mut self,
        pubkey: &PublicKeyBytes,
        zone: CachedZone,
        changes: u64,
        name: &Name,
        record_type: RecordType,
    ) -> Option<Arc<RecordSet>> {
        if self.changes(pubkey) != changes {
            trace!("insert skip: the stored packet changed during the lookup");
            return zone.resolve(name, record_type);
        }
        self.insert(*pubkey, zone);
        self.resolve(pubkey, name, record_type)
    }

    fn insert_and_resolve_dht(
        &mut self,
        pubkey: &PublicKeyBytes,
        zone: CachedZone,
        changes: u64,
        name: &Name,
        record_type: RecordType,
    ) -> Option<Arc<RecordSet>> {
        let res = zone.resolve(name, record_type);
        if self.changes(pubkey) != changes {
            trace!("dht insert skip: the stored packet changed during the lookup");
            return res;
        }
        self.dht_cache.insert(*pubkey, zone, DHT_CACHE_TTL);
        self.metrics
            .cache_zones_dht
            .set(self.dht_cache.iter().count() as i64);
        res
    }

    fn insert(&mut self, pubkey: PublicKeyBytes, zone: CachedZone) {
        if self
            .cache
            .peek(&pubkey)
            .map(|old| old.is_newer_than(&zone))
            .unwrap_or(false)
        {
            trace!("insert skip: cached is newer");
        } else {
            self.cache.put(pubkey, zone);
            self.metrics.cache_zones.set(self.cache.len() as i64);
            trace!("inserted into cache");
        }
    }

    /// Drop the zones cached for a key whose stored packet changed, and count the change.
    ///
    /// Runs on the packet store's writer thread, so it does no work that grows with the cache:
    /// the gauge of DHT zones is refreshed when a DHT zone is cached, not here.
    fn remove(&mut self, pubkey: &PublicKeyBytes) {
        let counter = Self::counter(pubkey);
        self.changes[counter] = self.changes[counter].wrapping_add(1);
        self.cache.pop(pubkey);
        self.dht_cache.remove(pubkey);
        self.metrics.cache_zones.set(self.cache.len() as i64);
    }

    /// Forget everything cached and count a change for every key.
    fn reset(&mut self) {
        self.cache.clear();
        self.dht_cache.clear();
        for counter in self.changes.iter_mut() {
            *counter = counter.wrapping_add(1);
        }
        self.metrics.cache_zones.set(0);
        self.metrics.cache_zones_dht.set(0);
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

    fn is_newer_than(&self, other: &CachedZone) -> bool {
        self.timestamp > other.timestamp
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

    use iroh_dns::pkarr::Timestamp;

    use super::{
        InsertError, MAX_TIMESTAMP_AHEAD, Options, PacketSource, ZoneStore, check_timestamp_ahead,
    };
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
        Ok(store.insert(packet, PacketSource::PkarrPublish).await?)
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
    async fn a_publication_the_store_applied_reaches_the_cache_without_its_caller() -> Result {
        let store = store()?;
        let endpoint = SecretKey::generate();
        let now = now_micros();
        publish(&store, signed_packet_at(&endpoint, now, "older")).await?;
        assert_eq!(
            lookup(&store, &endpoint).await?.as_deref(),
            Some("relay=older")
        );
        assert!(store.cached(&key(&endpoint)));

        // A request that is dropped after its packet reached the store never runs the code after
        // `ZoneStore::insert`'s store call. Applying the packet to the store alone stands for it.
        assert!(
            store
                .store
                .upsert(signed_packet_at(&endpoint, now + 1, "newer"))
                .await?
        );

        assert!(!store.cached(&key(&endpoint)));
        assert_eq!(
            lookup(&store, &endpoint).await?.as_deref(),
            Some("relay=newer")
        );
        Ok(())
    }

    #[test]
    fn a_timestamp_exactly_at_the_allowed_margin_is_accepted_and_one_microsecond_more_is_not() {
        let now = 1_800_000_000_000_000u64;
        let margin = MAX_TIMESTAMP_AHEAD.as_micros() as u64;
        assert_eq!(margin, 600_000_000);

        assert!(check_timestamp_ahead(Timestamp::from_micros(now + margin), now).is_ok());
        let refused = check_timestamp_ahead(Timestamp::from_micros(now + margin + 1), now)
            .expect_err("one microsecond past the margin");
        match refused {
            InsertError::TimestampAhead { ahead, .. } => {
                assert_eq!(ahead, Duration::from_micros(margin + 1));
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn timestamps_in_the_past_and_at_the_clock_are_accepted_and_the_largest_is_not() {
        let now = 1_800_000_000_000_000u64;
        assert!(check_timestamp_ahead(Timestamp::from_micros(0), now).is_ok());
        assert!(check_timestamp_ahead(Timestamp::from_micros(now - 1), now).is_ok());
        assert!(check_timestamp_ahead(Timestamp::from_micros(now), now).is_ok());
        assert!(check_timestamp_ahead(Timestamp::from_micros(u64::MAX), now).is_err());
        // A clock so late that the margin would overflow does not wrap.
        assert!(check_timestamp_ahead(Timestamp::from_micros(u64::MAX), u64::MAX - 1).is_ok());
    }

    #[tokio::test]
    async fn a_refused_publication_changes_neither_the_store_nor_the_cache() -> Result {
        let store = store()?;
        let endpoint = SecretKey::generate();
        let now = now_micros();
        publish(&store, signed_packet_at(&endpoint, now, "current")).await?;
        assert_eq!(
            lookup(&store, &endpoint).await?.as_deref(),
            Some("relay=current")
        );

        let ahead = signed_packet_at(&endpoint, now + 3600 * 1_000_000, "ahead");
        let err = publish(&store, ahead).await.expect_err("refused");
        assert!(
            err.to_string().contains("ahead of the server's clock"),
            "{err}"
        );

        assert!(store.cached(&key(&endpoint)));
        assert_eq!(
            lookup(&store, &endpoint).await?.as_deref(),
            Some("relay=current")
        );
        Ok(())
    }

    fn zone_of(secret_key: &SecretKey, relay: &str) -> super::CachedZone {
        super::CachedZone::from_signed_packet(&signed_packet_at(secret_key, now_micros(), relay))
            .expect("a zone")
    }

    #[test]
    fn a_cache_left_in_doubt_by_a_panic_starts_over_and_counts_a_change_for_every_key() {
        let cache = std::sync::Mutex::new(super::ZoneCache::new(16, Default::default()));
        let endpoint = SecretKey::generate();
        let pubkey = key(&endpoint);
        let noted = {
            let mut cache = cache.lock().expect("lock");
            cache.insert(pubkey, zone_of(&endpoint, "cached"));
            assert!(cache.cache.contains(&pubkey));
            cache.changes(&pubkey)
        };

        // A thread panics while it holds the lock.
        let panicked = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let _guard = cache.lock().expect("lock");
                    panic!("a panic under the cache lock");
                })
                .join()
        });
        assert!(panicked.is_err());
        assert!(cache.is_poisoned());

        let guard = super::lock_cache(&cache);
        assert!(
            !guard.cache.contains(&pubkey),
            "what was cached is forgotten"
        );
        assert_ne!(
            guard.changes(&pubkey),
            noted,
            "a lookup in flight caches nothing"
        );
        drop(guard);
        assert!(!cache.is_poisoned(), "the lock works again");
    }

    #[test]
    fn a_dht_zone_is_not_cached_if_the_stored_packet_changed_during_the_lookup() {
        let mut cache = super::ZoneCache::new(16, Default::default());
        let endpoint = SecretKey::generate();
        let pubkey = key(&endpoint);

        // No change since the lookup began: the zone is answered and cached.
        let noted = cache.changes(&pubkey);
        let answer = cache.insert_and_resolve_dht(
            &pubkey,
            zone_of(&endpoint, "first"),
            noted,
            &name(),
            RecordType::TXT,
        );
        assert_eq!(
            answer.as_deref().map(relay_of).as_deref(),
            Some("relay=first")
        );
        assert!(cache.dht_cache.contains_key(&pubkey));

        // A change since the lookup began: answered from the zone, and not cached.
        cache.remove(&pubkey);
        assert!(!cache.dht_cache.contains_key(&pubkey));
        let answer = cache.insert_and_resolve_dht(
            &pubkey,
            zone_of(&endpoint, "second"),
            noted,
            &name(),
            RecordType::TXT,
        );
        assert_eq!(
            answer.as_deref().map(relay_of).as_deref(),
            Some("relay=second")
        );
        assert!(!cache.dht_cache.contains_key(&pubkey));
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
