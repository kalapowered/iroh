use std::{
    hash::{BuildHasher, RandomState},
    net::{IpAddr, Ipv6Addr},
    num::{NonZeroU32, NonZeroUsize},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{body::Body, extract::State, middleware::Next, response::Response};
use governor::{
    Quota as GovernorQuota, RateLimiter,
    clock::{Clock, DefaultClock, QuantaInstant},
    middleware::NoOpMiddleware,
    nanos::Nanos,
    state::{StateStore, keyed::ShrinkableKeyedStateStore},
};
use http::{HeaderMap, Request};
use iroh_metrics::Gauge;
use lru::LruCache;
use serde::{Deserialize, Serialize};
use tower_governor::{
    GovernorError,
    key_extractor::{KeyExtractor, PeerIpKeyExtractor, SmartIpKeyExtractor},
};

use crate::metrics::Metrics;

/// Rate limiting strategy for the HTTP server.
#[derive(Debug, Deserialize, Default, Serialize, Clone)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum RateLimitConfig {
    /// Disables rate limiting entirely.
    Disabled,
    /// Rate limits by the connection's peer IP address.
    ///
    /// For publications and lookups alike the key is the peer address's network: an IPv4 address
    /// (an IPv4 address that arrives IPv6-mapped counts as IPv4), or the /64 of an IPv6 address.
    #[default]
    Simple,
    /// Rate limits by the client IP, extracted from reverse-proxy headers.
    ///
    /// For lookups this uses the headers commonly set by reverse proxies (for example
    /// `X-Forwarded-For`) to extract the original client IP, falling back to the connection's
    /// peer IP address, and then maps it to its network as `Simple` does. See
    /// [`SmartIpKeyExtractor`]. For publications the headers are not read and this keys on the
    /// peer address's network, as `Simple` does.
    ///
    /// [`SmartIpKeyExtractor`]: https://docs.rs/tower_governor/latest/tower_governor/key_extractor/struct.SmartIpKeyExtractor.html
    Smart,
}

impl Default for &RateLimitConfig {
    fn default() -> Self {
        &RateLimitConfig::Simple
    }
}

/// The rate limit settings of the HTTP server.
#[derive(Debug, Clone)]
pub(crate) struct RateLimits {
    /// The limit on `PUT /pkarr`.
    pub(crate) pkarr_put: RateLimitConfig,
    /// The limit on the lookups: `GET /pkarr/{key}` and `/dns-query`.
    pub(crate) lookup: RateLimitConfig,
}

/// How fast a source may send requests: one is replenished every `replenish`, and a source that
/// has been quiet may send `burst` at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Quota {
    pub(super) replenish: Duration,
    pub(super) burst: u32,
}

/// One publication every four seconds, two at once.
pub(super) const PUT_QUOTA: Quota = Quota {
    replenish: Duration::from_secs(4),
    burst: 2,
};

/// Fifty lookups a second, a hundred at once. Many endpoints can sit behind one address, so the
/// quota is far above what one endpoint needs.
pub(super) const LOOKUP_QUOTA: Quota = Quota {
    replenish: Duration::from_millis(20),
    burst: 100,
};

/// How many shards a limiter's store has. Each has a lock of its own, so that requests from
/// different sources do not wait for one another.
const SHARDS: usize = 64;

/// The most entries a limiter's store holds, one for each source network: 131,072, which is
/// [`SHARD_CAPACITY`] in each of the [`SHARDS`] shards.
const STORE_CAPACITY: usize = 131_072;

/// The most entries one shard holds: 2,048.
const SHARD_CAPACITY: usize = STORE_CAPACITY / SHARDS;

/// The state of the sources of one limiter, with a cap.
///
/// Each of the [`SHARDS`] shards holds the most recently used [`SHARD_CAPACITY`] sources, and a
/// source that arrives at a full shard removes the one that was used least recently. A source is
/// used when it sends a request, whether the limiter lets the request through or refuses it, so a
/// source that keeps sending, a refused one included, goes only if [`SHARD_CAPACITY`] other sources
/// reach its shard between two of its requests.
///
/// The shard of a source is chosen by a hash with a key that is made when the store is, and each
/// shard's table has a hash with a key of its own. A sender cannot see either key, so it cannot
/// choose the shard its sources fall in, and what it can do to the one shard that its sources reach
/// is the same as what it can do to any other: to remove one given entry from its shard it needs
/// [`SHARD_CAPACITY`] other sources that reach that shard after the entry's last use, which are
/// about [`STORE_CAPACITY`] distinct source networks in all. When an entry is removed, its source
/// is met as a source that has not been seen: it may send one burst, which is at most one fresh
/// burst for each entry removed.
///
/// A shard's table is made for [`SHARD_CAPACITY`] entries, and under churn (entries that come and
/// go) it may grow to a table of 8,192 buckets before it is made again. From that rule a full
/// store comes to at most about 16.5 MiB: 131,072 entries of about 64 bytes, and up to 64 tables
/// of 8,192 buckets of 17 bytes. That is an upper figure for one limit's store, taken from the
/// rule and not measured; the code enforces the cap on entries and no limit on resident memory.
/// The growth of the whole process was measured beside it, as a separate fact: with both limits'
/// stores full, 20.81 MiB over its size after a warm-up. The count of entries is exported
/// (`rate_limit_lookup_entries` and `rate_limit_put_entries`).
///
/// There is no sweep that removes the entries of sources that have gone quiet: when a shard is
/// full the entry that goes is the one used least recently, which is not always the one that has
/// expired. An entry that is indebted can go before a newer entry that has expired.
#[derive(Clone)]
pub(super) struct Store {
    inner: Arc<StoreInner>,
}

struct StoreInner {
    shards: Vec<Mutex<LruCache<IpAddr, Nanos, RandomState>>>,
    /// Chooses the shard of a source.
    chooser: RandomState,
    /// The entries of all shards.
    len: AtomicUsize,
}

impl Store {
    /// A store of the size that the limiters use.
    pub(super) fn new() -> Self {
        Self::with_shards(SHARDS, SHARD_CAPACITY)
    }

    /// A store of `shards` shards that hold `capacity` entries each.
    fn with_shards(shards: usize, capacity: usize) -> Self {
        let capacity = NonZeroUsize::new(capacity).expect("a shard holds at least one entry");
        Self {
            inner: Arc::new(StoreInner {
                shards: (0..shards)
                    .map(|_| Mutex::new(LruCache::with_hasher(capacity, RandomState::new())))
                    .collect(),
                chooser: RandomState::new(),
                len: AtomicUsize::new(0),
            }),
        }
    }

    fn shard(&self, key: &IpAddr) -> &Mutex<LruCache<IpAddr, Nanos, RandomState>> {
        let hash = self.inner.chooser.hash_one(key);
        &self.inner.shards[(hash % self.inner.shards.len() as u64) as usize]
    }
}

impl StateStore for Store {
    type Key = IpAddr;

    fn measure_and_replace<T, F, E>(&self, key: &IpAddr, f: F) -> Result<T, E>
    where
        F: Fn(Option<Nanos>) -> Result<(T, Nanos), E>,
    {
        let mut shard = self
            .shard(key)
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // `get` makes the entry the most recently used, whether or not the request is refused.
        let before = shard.get(key).copied();
        let (outcome, after) = f(before)?;
        let held = shard.len();
        shard.put(*key, after);
        if shard.len() > held {
            self.inner.len.fetch_add(1, Ordering::Relaxed);
        }
        Ok(outcome)
    }
}

impl ShrinkableKeyedStateStore<IpAddr> for Store {
    /// Nothing is removed by age: the store's own cap bounds it.
    fn retain_recent(&self, _drop_below: Nanos) {}

    fn len(&self) -> usize {
        self.inner.len.load(Ordering::Relaxed)
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A request limit: the key of a request, the quota of its source and the state of the sources.
pub(super) struct Limiter {
    source: SourceNetwork,
    limiter: RateLimiter<IpAddr, Store, DefaultClock, NoOpMiddleware<QuantaInstant>>,
    metrics: Arc<Metrics>,
    /// The gauge of the number of entries of this limiter's store.
    entries: fn(&Metrics) -> &Gauge,
}

impl Limiter {
    fn new(
        source: SourceNetwork,
        quota: Quota,
        metrics: Arc<Metrics>,
        entries: fn(&Metrics) -> &Gauge,
    ) -> Arc<Self> {
        let quota = GovernorQuota::with_period(quota.replenish)
            .expect("a period above zero")
            .allow_burst(NonZeroU32::new(quota.burst).expect("a burst above zero"));
        Arc::new(Self {
            source,
            limiter: RateLimiter::new(quota, Store::new(), DefaultClock::default()),
            metrics,
            entries,
        })
    }
}

/// Create the rate limit for publications, which keys on the network of the connection's peer
/// address and never reads forwarding headers.
pub(super) fn create(
    rate_limit_config: &RateLimitConfig,
    quota: Quota,
    metrics: &Arc<Metrics>,
) -> Option<Arc<Limiter>> {
    match rate_limit_config {
        RateLimitConfig::Disabled => {
            tracing::info!("Rate limiting disabled");
            None
        }
        RateLimitConfig::Simple | RateLimitConfig::Smart => {
            tracing::info!("Rate limiting enabled ({rate_limit_config:?})");
            Some(Limiter::new(
                SourceNetwork {
                    trust_forwarding_headers: false,
                },
                quota,
                metrics.clone(),
                |metrics| &metrics.rate_limit_put_entries,
            ))
        }
    }
}

/// Create the rate limit for lookups, which keys on the source's network.
pub(super) fn create_lookup(
    rate_limit_config: &RateLimitConfig,
    quota: Quota,
    metrics: &Arc<Metrics>,
) -> Option<Arc<Limiter>> {
    let trust_forwarding_headers = match rate_limit_config {
        RateLimitConfig::Disabled => {
            tracing::info!("Lookup rate limiting disabled");
            return None;
        }
        RateLimitConfig::Simple => false,
        RateLimitConfig::Smart => true,
    };
    tracing::info!("Lookup rate limiting enabled ({rate_limit_config:?})");
    Some(Limiter::new(
        SourceNetwork {
            trust_forwarding_headers,
        },
        quota,
        metrics.clone(),
        |metrics| &metrics.rate_limit_lookup_entries,
    ))
}

/// The limit as a layer: a request from a source that is within its quota goes on, and one from a
/// source that is over it is answered `429` with the headers `x-ratelimit-after` and `retry-after`
/// that say how many whole seconds to wait. A request whose source cannot be found is answered
/// `500`.
pub(super) async fn limit(
    State(limiter): State<Arc<Limiter>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let key = match limiter.source.extract(&request) {
        Ok(key) => key,
        Err(error) => return error.into(),
    };
    let checked = limiter.limiter.check_key(&key);
    (limiter.entries)(&limiter.metrics).set(limiter.limiter.len() as i64);
    match checked {
        Ok(()) => next.run(request).await,
        Err(negative) => {
            let wait_time = negative
                .wait_time_from(limiter.limiter.clock().now())
                .as_secs();
            let mut headers = HeaderMap::new();
            headers.insert("x-ratelimit-after", wait_time.into());
            headers.insert("retry-after", wait_time.into());
            GovernorError::TooManyRequests {
                wait_time,
                headers: Some(headers),
            }
            .into()
        }
    }
}

/// A key extractor that puts every address of one network in the same bucket: an IPv4 address is
/// its own network, and an IPv6 address belongs to its /64, which is what one subscriber is
/// given. An IPv4 address that arrives IPv6-mapped, as it does on a dual-stack listener, is an
/// IPv4 address.
///
/// Keying on the full IPv6 address would let one subscriber use a fresh key for every request,
/// and so a fresh quota.
#[derive(Debug, Clone, Copy)]
pub(super) struct SourceNetwork {
    /// Take the client address from the headers a reverse proxy sets, when there are any, and
    /// from the connection otherwise.
    trust_forwarding_headers: bool,
}

impl SourceNetwork {
    /// The address every source in the same network shares.
    fn network_of(address: IpAddr) -> IpAddr {
        match address {
            IpAddr::V4(_) => address,
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & (!0u128 << 64))),
            },
        }
    }
}

impl KeyExtractor for SourceNetwork {
    type Key = IpAddr;

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        let address = if self.trust_forwarding_headers {
            SmartIpKeyExtractor.extract(req)?
        } else {
            PeerIpKeyExtractor.extract(req)?
        };
        Ok(Self::network_of(address))
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use axum::extract::ConnectInfo;
    use governor::clock::FakeRelativeClock;
    use tower_service::Service;

    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("an address")
    }

    fn request(peer: &str, forwarded_for: Option<&str>) -> Request<()> {
        let mut request = Request::builder().uri("/pkarr/x");
        if let Some(forwarded_for) = forwarded_for {
            request = request.header("x-forwarded-for", forwarded_for);
        }
        let mut request = request.body(()).expect("a request");
        let peer: SocketAddr = peer.parse().expect("a socket address");
        request.extensions_mut().insert(ConnectInfo(peer));
        request
    }

    #[test]
    fn the_quotas_are_fifty_lookups_a_second_with_a_burst_of_a_hundred() {
        assert_eq!(LOOKUP_QUOTA.replenish, Duration::from_millis(20));
        assert_eq!(LOOKUP_QUOTA.burst, 100);
        // Publications keep the quota they always had.
        assert_eq!(PUT_QUOTA.replenish, Duration::from_secs(4));
        assert_eq!(PUT_QUOTA.burst, 2);
    }

    #[test]
    fn an_ipv4_address_is_its_own_network() {
        assert_eq!(
            SourceNetwork::network_of(ip("203.0.113.7")),
            ip("203.0.113.7")
        );
        assert_ne!(
            SourceNetwork::network_of(ip("203.0.113.7")),
            SourceNetwork::network_of(ip("203.0.113.8"))
        );
    }

    #[test]
    fn the_addresses_of_one_ipv6_slash_64_share_a_network() {
        let network = SourceNetwork::network_of(ip("2001:db8:1:2::1"));
        assert_eq!(network, ip("2001:db8:1:2::"));
        assert_eq!(
            SourceNetwork::network_of(ip("2001:db8:1:2:ffff:ffff:ffff:ffff")),
            network
        );
        assert_eq!(
            SourceNetwork::network_of(ip("2001:db8:1:2:a:b:c:d")),
            network
        );
        // The next /64 is another network.
        assert_ne!(SourceNetwork::network_of(ip("2001:db8:1:3::1")), network);
    }

    #[test]
    fn an_ipv4_address_that_arrives_ipv6_mapped_is_an_ipv4_address() {
        assert_eq!(
            SourceNetwork::network_of(ip("::ffff:203.0.113.7")),
            ip("203.0.113.7")
        );
        // Two IPv4 clients on a dual-stack listener are not one network.
        assert_ne!(
            SourceNetwork::network_of(ip("::ffff:203.0.113.7")),
            SourceNetwork::network_of(ip("::ffff:203.0.113.8"))
        );
    }

    #[test]
    fn the_key_comes_from_the_connection_unless_forwarding_headers_are_trusted() {
        let request = request("[2001:db8:1:2::9]:5000", Some("198.51.100.4"));

        let direct = SourceNetwork {
            trust_forwarding_headers: false,
        };
        assert_eq!(
            direct.extract(&request).expect("a key"),
            ip("2001:db8:1:2::")
        );

        let behind_a_proxy = SourceNetwork {
            trust_forwarding_headers: true,
        };
        assert_eq!(
            behind_a_proxy.extract(&request).expect("a key"),
            ip("198.51.100.4")
        );
    }

    type FakeLimiter = RateLimiter<IpAddr, Store, FakeRelativeClock, NoOpMiddleware<Nanos>>;

    /// A limiter with two requests at once and one more each second, on a store of `shards` shards
    /// of `capacity` entries, and its clock, which only moves when a case moves it.
    fn limiter(shards: usize, capacity: usize) -> (FakeLimiter, FakeRelativeClock) {
        let clock = FakeRelativeClock::default();
        let quota = GovernorQuota::with_period(Duration::from_secs(1))
            .expect("a period")
            .allow_burst(NonZeroU32::new(2).expect("a burst"));
        (
            RateLimiter::new(quota, Store::with_shards(shards, capacity), clock.clone()),
            clock,
        )
    }

    /// The `n`th source of a run of distinct IPv4 networks.
    fn source(n: usize) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + n as u32))
    }

    fn allowed(limiter: &FakeLimiter, key: &IpAddr) -> bool {
        limiter.check_key(key).is_ok()
    }

    /// The store holds at most its capacity, however many sources send.
    #[test]
    fn the_store_holds_at_most_its_capacity_however_many_sources_send() {
        let limiter: FakeLimiter = RateLimiter::new(
            GovernorQuota::with_period(Duration::from_secs(1)).expect("a period"),
            Store::new(),
            FakeRelativeClock::default(),
        );
        for n in 0..3 * STORE_CAPACITY {
            assert!(limiter.check_key(&source(n)).is_ok());
            assert!(limiter.len() <= STORE_CAPACITY, "{} entries", limiter.len());
        }
        // Three times the capacity of sources fill every shard.
        assert_eq!(limiter.len(), STORE_CAPACITY);
    }

    /// A source that is refused is still a source in use: while others come and go it stays in
    /// the store, indebted, as long as it sends before a shard's capacity of other sources has
    /// reached its shard.
    #[test]
    fn a_refused_source_stays_indebted_while_others_come_and_go() {
        let (limiter, _clock) = limiter(64, 2_048);
        let refused = source(1_000_000);
        assert!(allowed(&limiter, &refused));
        assert!(allowed(&limiter, &refused));
        assert!(!allowed(&limiter, &refused));
        for n in 0..3 * STORE_CAPACITY {
            assert!(allowed(&limiter, &source(n)));
            if n % 1_000 == 0 {
                assert!(!allowed(&limiter, &refused), "forgotten after {n} sources");
            }
        }
        assert!(!allowed(&limiter, &refused));
    }

    /// The source that goes is the one used least recently, and it meets a store that has not seen
    /// it: one burst, and no more.
    #[test]
    fn an_entry_that_goes_gives_its_source_one_fresh_burst_and_no_more() {
        let (limiter, _clock) = limiter(1, 3);
        let first = source(1);
        assert!(allowed(&limiter, &first));
        assert!(allowed(&limiter, &first));
        assert!(!allowed(&limiter, &first));
        for n in 2..5 {
            assert!(allowed(&limiter, &source(n)));
        }
        assert!(allowed(&limiter, &first), "its entry was not removed");
        assert!(allowed(&limiter, &first));
        assert!(!allowed(&limiter, &first), "more than one fresh burst");
    }

    /// Without a sweep, the entry that goes is the one used least recently, even when it is
    /// indebted and a newer one has expired.
    #[test]
    fn the_entry_used_least_recently_goes_even_when_a_newer_one_has_expired() {
        let (limiter, clock) = limiter(1, 3);
        let (indebted, expired) = (source(1), source(2));
        assert!(allowed(&limiter, &indebted));
        assert!(allowed(&limiter, &indebted));
        assert!(!allowed(&limiter, &indebted));
        assert!(allowed(&limiter, &expired));
        // The expired source's debt is over, the other's is not: one request more is let through
        // and the next is not.
        clock.advance(Duration::from_secs(1));
        assert!(allowed(&limiter, &source(3)));
        assert!(allowed(&limiter, &source(4)));
        // `indebted` was the oldest of the entries that were in the store, so it was removed and
        // starts again, with a whole burst.
        assert!(allowed(&limiter, &indebted), "its entry was not removed");
        assert!(allowed(&limiter, &indebted), "it did not get a whole burst");
    }

    fn metrics() -> Arc<Metrics> {
        Arc::default()
    }

    async fn status_and_body(
        router: &mut axum::Router,
        request: Request<Body>,
    ) -> (u16, HeaderMap, String) {
        let response =
            std::future::poll_fn(|cx| Service::<Request<Body>>::poll_ready(router, cx)).await;
        assert!(response.is_ok());
        let response = Service::call(router, request).await.expect("an answer");
        let (parts, body) = response.into_parts();
        let body = axum::body::to_bytes(body, usize::MAX)
            .await
            .expect("a body");
        (
            parts.status.as_u16(),
            parts.headers,
            String::from_utf8(body.to_vec()).expect("a text"),
        )
    }

    /// A request from `peer` to the route `/`, with no body.
    fn request_from(peer: &str) -> Request<Body> {
        let mut request = Request::builder()
            .uri("/")
            .body(Body::empty())
            .expect("a request");
        request.extensions_mut().insert(ConnectInfo(
            peer.parse::<std::net::SocketAddr>().expect("an address"),
        ));
        request
    }

    /// A router with one route, behind `limiter`.
    fn router_behind(limiter: Arc<Limiter>) -> axum::Router {
        axum::Router::new()
            .route("/", axum::routing::get(|| async { "through" }))
            .route_layer(axum::middleware::from_fn_with_state(limiter, limit))
    }

    /// The limit lets a source within its quota through and answers one over it as the library's
    /// own layer did: `429`, the two headers with the same whole number of seconds, and the
    /// body that names it. The number of seconds is the one that the library's own limiter,
    /// asked in the same order with the same quota, gives for its refusal. The two limiters read
    /// the system clock at their own moments, a few microseconds apart, and a wait counts whole
    /// seconds, so the two numbers differ by one if a whole second falls between the readings,
    /// which takes a stall of the process of about a second. The limiter of this server keeps the
    /// system clock and the case cannot set one; a failure with the two numbers one apart can be
    /// that stall, and a failure with any other difference is a wrong wait. A request whose
    /// source is unknown is answered `500`.
    #[tokio::test]
    async fn the_limit_answers_a_refusal_with_the_libraries_headers_and_body() {
        let metrics = metrics();
        let quota = Quota {
            replenish: Duration::from_secs(4),
            burst: 1,
        };
        let limiter =
            create(&RateLimitConfig::Simple, quota, &metrics).expect("rate limiting is enabled");
        let mut router = router_behind(limiter);
        let library = RateLimiter::keyed(
            GovernorQuota::with_period(quota.replenish)
                .expect("a period above zero")
                .allow_burst(NonZeroU32::new(quota.burst).expect("a burst above zero")),
        );
        let source = ip("203.0.113.9");

        let (status, _, body) =
            status_and_body(&mut router, request_from("203.0.113.9:1000")).await;
        assert_eq!((status, body.as_str()), (200, "through"));
        assert!(library.check_key(&source).is_ok());
        assert_eq!(metrics.rate_limit_put_entries.get(), 1);

        let (status, headers, body) =
            status_and_body(&mut router, request_from("203.0.113.9:1001")).await;
        assert_eq!(status, 429);
        let refusal = library
            .check_key(&source)
            .expect_err("the library refuses the second request too");
        let expected = refusal
            .wait_time_from(DefaultClock::default().now())
            .as_secs();
        assert!((1..=4).contains(&expected), "{expected}");
        let after = headers.get("x-ratelimit-after").expect("a header");
        assert_eq!(headers.get("retry-after"), Some(after));
        let wait: u64 = after.to_str().expect("a text").parse().expect("a number");
        assert_eq!(
            wait, expected,
            "the wait is not the library's own (the header says {wait}, the library {expected})"
        );
        assert_eq!(body, format!("Too Many Requests! Wait for {wait}s"));

        // Another source is not held back by it.
        let (status, _, _) = status_and_body(&mut router, request_from("203.0.113.10:1000")).await;
        assert_eq!(status, 200);
        assert_eq!(metrics.rate_limit_put_entries.get(), 2);

        // A request with no peer address has no source.
        let request = Request::builder()
            .uri("/")
            .body(Body::empty())
            .expect("a request");
        let (status, _, body) = status_and_body(&mut router, request).await;
        assert_eq!((status, body.as_str()), (500, "Unable To Extract Key!"));
    }

    /// Each limiter sets the gauge of the entries of its own store and no other: the lookup
    /// limiter the lookup gauge, the publication limiter the publication gauge.
    #[tokio::test]
    async fn each_limiter_reports_the_entries_of_its_own_store() {
        let metrics = metrics();
        let quota = Quota {
            replenish: Duration::from_secs(4),
            burst: 5,
        };
        let lookup =
            create_lookup(&RateLimitConfig::Simple, quota, &metrics).expect("lookups are limited");
        let put = create(&RateLimitConfig::Simple, quota, &metrics).expect("puts are limited");
        let (mut lookups, mut puts) = (router_behind(lookup), router_behind(put));
        assert_eq!(metrics.rate_limit_lookup_entries.get(), 0);
        assert_eq!(metrics.rate_limit_put_entries.get(), 0);

        for peer in ["203.0.113.1:1", "203.0.113.2:1", "203.0.113.3:1"] {
            let (status, _, _) = status_and_body(&mut lookups, request_from(peer)).await;
            assert_eq!(status, 200);
        }
        assert_eq!(metrics.rate_limit_lookup_entries.get(), 3);
        assert_eq!(metrics.rate_limit_put_entries.get(), 0);

        let (status, _, _) = status_and_body(&mut puts, request_from("203.0.113.1:1")).await;
        assert_eq!(status, 200);
        assert_eq!(metrics.rate_limit_lookup_entries.get(), 3);
        assert_eq!(metrics.rate_limit_put_entries.get(), 1);
    }
}
