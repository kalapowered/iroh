use std::{
    net::{IpAddr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};

use governor::{clock::QuantaInstant, middleware::NoOpMiddleware};
use http::Request;
use serde::{Deserialize, Serialize};
use tower_governor::{
    GovernorError, GovernorLayer,
    governor::GovernorConfigBuilder,
    key_extractor::{KeyExtractor, PeerIpKeyExtractor, SmartIpKeyExtractor},
};

/// Rate limiting strategy for the HTTP server.
#[derive(Debug, Deserialize, Default, Serialize, Clone)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum RateLimitConfig {
    /// Disables rate limiting entirely.
    Disabled,
    /// Rate limits by the connection's peer IP address.
    ///
    /// For publications the key is the peer address itself, see [`PeerIpKeyExtractor`]. For
    /// lookups it is the peer address's network: an IPv4 address, or the /64 of an IPv6 address.
    ///
    /// [`PeerIpKeyExtractor`]: https://docs.rs/tower_governor/latest/tower_governor/key_extractor/struct.PeerIpKeyExtractor.html
    #[default]
    Simple,
    /// Rate limits by the client IP, extracted from reverse-proxy headers.
    ///
    /// For lookups this uses the headers commonly set by reverse proxies (for example
    /// `X-Forwarded-For`) to extract the original client IP, falling back to the connection's
    /// peer IP address, and then maps it to its network as `Simple` does. See
    /// [`SmartIpKeyExtractor`]. For publications the headers are not read and this keys on the
    /// peer address, as `Simple` does.
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

/// Create the rate-limiting layer for publications, which keys on the connection's peer address.
///
/// This spawns a background thread to clean up the rate limiting cache.
pub(super) fn create<RespBody>(
    rate_limit_config: &RateLimitConfig,
    quota: Quota,
) -> Option<GovernorLayer<PeerIpKeyExtractor, NoOpMiddleware<QuantaInstant>, RespBody>> {
    match rate_limit_config {
        RateLimitConfig::Disabled => {
            tracing::info!("Rate limiting disabled");
            None
        }
        RateLimitConfig::Simple | RateLimitConfig::Smart => {
            tracing::info!("Rate limiting enabled ({rate_limit_config:?})");
            Some(layer(PeerIpKeyExtractor, quota))
        }
    }
}

/// Create the rate-limiting layer for lookups, which keys on the source's network.
///
/// This spawns a background thread to clean up the rate limiting cache.
pub(super) fn create_lookup<RespBody>(
    rate_limit_config: &RateLimitConfig,
    quota: Quota,
) -> Option<GovernorLayer<SourceNetwork, NoOpMiddleware<QuantaInstant>, RespBody>> {
    let trust_forwarding_headers = match rate_limit_config {
        RateLimitConfig::Disabled => {
            tracing::info!("Lookup rate limiting disabled");
            return None;
        }
        RateLimitConfig::Simple => false,
        RateLimitConfig::Smart => true,
    };
    tracing::info!("Lookup rate limiting enabled ({rate_limit_config:?})");
    Some(layer(
        SourceNetwork {
            trust_forwarding_headers,
        },
        quota,
    ))
}

fn layer<K, RespBody>(
    key_extractor: K,
    quota: Quota,
) -> GovernorLayer<K, NoOpMiddleware<QuantaInstant>, RespBody>
where
    K: KeyExtractor,
    K::Key: Send + Sync + 'static,
{
    let mut builder = GovernorConfigBuilder::default();
    builder.period(quota.replenish);
    builder.burst_size(quota.burst);
    let governor_conf = builder
        .key_extractor(key_extractor)
        .finish()
        .expect("failed to build rate-limiting governor");

    let governor_conf = Arc::new(governor_conf);

    // The governor needs a background task for garbage collection (to clear expired records)
    let gc_interval = Duration::from_secs(60);
    let governor_limiter = governor_conf.limiter().clone();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(gc_interval);
            tracing::debug!("rate limiting storage size: {}", governor_limiter.len());
            governor_limiter.retain_recent();
        }
    });

    GovernorLayer::new(governor_conf)
}

/// A key extractor that puts every address of one network in the same bucket: an IPv4 address is
/// its own network, and an IPv6 address belongs to its /64, which is what one subscriber is
/// given. An IPv4 address that arrives IPv6-mapped, as it does on a dual-stack listener, is an
/// IPv4 address.
///
/// Keying on the full IPv6 address would let one subscriber use a fresh key for every request.
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
}
