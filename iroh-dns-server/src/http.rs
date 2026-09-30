//! HTTP server part of iroh-dns-server

use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{Method, StatusCode},
    middleware::{self, Next},
    response::IntoResponse,
    routing::{get, put},
};
use n0_error::{Result, StdResultExt, anyerr, bail_any};
use serde::{Deserialize, Serialize};
use socket2::{SockRef, TcpKeepalive};
use tokio::{net::TcpListener, task::JoinSet};
use tower_http::{
    cors::{self, CorsLayer},
    trace::TraceLayer,
};
use tracing::{Level, info, span, warn};

mod doh;
mod error;
mod pkarr;
mod rate_limiting;
mod tls;

pub(crate) use self::rate_limiting::RateLimits;
use self::rate_limiting::{LOOKUP_QUOTA, PUT_QUOTA, Quota};
pub use self::{rate_limiting::RateLimitConfig, tls::CertMode};
use crate::state::AppState;

/// How long a connection may be idle before keepalive probing starts.
const TCP_KEEPALIVE_TIME: Duration = Duration::from_mins(1);

/// Interval between keepalive probes once probing starts.
const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Enable TCP keepalive on `listener`, which accepted connections inherit.
///
/// Without it, connections whose peer vanished without closing are never
/// reaped: they accumulate for the lifetime of the process until it is
/// OOM-killed.
fn set_keepalive(listener: &std::net::TcpListener) -> std::io::Result<()> {
    let keepalive = TcpKeepalive::new()
        .with_time(TCP_KEEPALIVE_TIME)
        .with_interval(TCP_KEEPALIVE_INTERVAL);
    SockRef::from(listener).set_tcp_keepalive(&keepalive)
}

/// Configuration for the HTTP listener.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[non_exhaustive]
pub struct HttpConfig {
    /// Port to bind the HTTP listener to.
    pub port: u16,
    /// Address to bind the HTTP listener to (defaults to `::`, i.e. IPv6 wildcard which also covers IPv4).
    pub bind_addr: Option<IpAddr>,
}

/// Configuration for the HTTPS listener.
///
/// Certificates are obtained according to [`Self::cert_mode`].
#[derive(Debug, Serialize, Deserialize, Clone)]
#[non_exhaustive]
pub struct HttpsConfig {
    /// Port to bind the HTTPS listener to.
    pub port: u16,
    /// Address to bind the HTTPS listener to (defaults to `::`, i.e. IPv6 wildcard which also covers IPv4).
    pub bind_addr: Option<IpAddr>,
    /// Domains for which TLS certificates are issued or loaded.
    pub domains: Vec<String>,
    /// Strategy used to obtain TLS certificates.
    pub cert_mode: CertMode,
    /// Contact email address passed to Let's Encrypt.
    ///
    /// Required when [`Self::cert_mode`] is [`CertMode::LetsEncrypt`]; ignored
    /// otherwise.
    pub letsencrypt_contact: Option<String>,
    /// Whether to use the Let's Encrypt production endpoint instead of staging.
    ///
    /// Only applies when [`Self::cert_mode`] is [`CertMode::LetsEncrypt`]. When
    /// unset, the ACME staging endpoint is used.
    pub letsencrypt_prod: Option<bool>,
}

/// The HTTP(S) server part of iroh-dns-server
#[derive(Debug)]
pub(crate) struct HttpServer {
    tasks: JoinSet<std::io::Result<()>>,
    http_addr: Option<SocketAddr>,
    https_addr: Option<SocketAddr>,
}

impl HttpServer {
    /// Spawn the server
    pub(crate) async fn spawn(
        http_config: Option<HttpConfig>,
        https_config: Option<HttpsConfig>,
        rate_limits: RateLimits,
        state: AppState,
        cert_cache_dir: PathBuf,
    ) -> Result<HttpServer> {
        if http_config.is_none() && https_config.is_none() {
            bail_any!("Either http or https config is required");
        }

        let app = create_app(state, &rate_limits);

        let mut tasks = JoinSet::new();

        // launch http
        let http_addr = if let Some(config) = http_config {
            let bind_addr = SocketAddr::new(
                config.bind_addr.unwrap_or(Ipv6Addr::UNSPECIFIED.into()),
                config.port,
            );
            let app = app.clone();
            let listener = TcpListener::bind(bind_addr)
                .await
                .anyerr()?
                .into_std()
                .anyerr()?;
            let bound_addr = listener.local_addr().anyerr()?;
            set_keepalive(&listener).anyerr()?;
            let fut = axum_server::from_tcp(listener)?
                .serve(app.into_make_service_with_connect_info::<SocketAddr>());
            info!("HTTP server listening on {bind_addr}");
            tasks.spawn(fut);
            Some(bound_addr)
        } else {
            None
        };

        // launch https
        let https_addr = if let Some(config) = https_config {
            let bind_addr = SocketAddr::new(
                config.bind_addr.unwrap_or(Ipv6Addr::UNSPECIFIED.into()),
                config.port,
            );
            let acceptor = {
                tokio::fs::create_dir_all(&cert_cache_dir)
                    .await
                    .with_std_context(|_| {
                        format!(
                            "failed to create cert cache dir at {}",
                            cert_cache_dir.display()
                        )
                    })?;
                config
                    .cert_mode
                    .build(
                        config.domains,
                        cert_cache_dir,
                        config.letsencrypt_contact,
                        config.letsencrypt_prod.unwrap_or(false),
                    )
                    .await?
            };
            let listener = TcpListener::bind(bind_addr)
                .await
                .anyerr()?
                .into_std()
                .anyerr()?;
            let bound_addr = listener.local_addr().anyerr()?;
            set_keepalive(&listener).anyerr()?;
            let fut = axum_server::from_tcp(listener)?
                .acceptor(acceptor)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>());
            info!("HTTPS server listening on {bind_addr}");
            tasks.spawn(fut);
            Some(bound_addr)
        } else {
            None
        };

        Ok(HttpServer {
            tasks,
            http_addr,
            https_addr,
        })
    }

    /// Get the bound address of the HTTP socket.
    pub(crate) fn http_addr(&self) -> Option<SocketAddr> {
        self.http_addr
    }

    /// Get the bound address of the HTTPS socket.
    pub(crate) fn https_addr(&self) -> Option<SocketAddr> {
        self.https_addr
    }

    /// Shutdown the server and wait for all tasks to complete.
    pub(crate) async fn shutdown(mut self) -> Result<()> {
        // TODO: Graceful cancellation.
        self.tasks.abort_all();
        self.run_until_done().await?;
        Ok(())
    }

    /// Wait for all tasks to complete.
    ///
    /// Runs forever unless tasks fail.
    pub(crate) async fn run_until_done(mut self) -> Result<()> {
        let mut final_res: Result<()> = Ok(());
        while let Some(res) = self.tasks.join_next().await {
            match res {
                Ok(Ok(())) => {}
                Err(err) if err.is_cancelled() => {}
                Ok(Err(err)) => {
                    warn!(?err, "task failed");
                    final_res = Err(anyerr!(err, "task"));
                }
                Err(err) => {
                    warn!(?err, "task panicked");
                    final_res = Err(anyerr!(err, "join"));
                }
            }
        }
        final_res
    }
}

/// Health check response
#[derive(Serialize)]
struct Health {
    status: &'static str,
    version: &'static str,
    git_hash: &'static str,
}

async fn healthz() -> Json<Health> {
    Json(Health {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        git_hash: "unknown",
    })
}

pub(crate) fn create_app(state: AppState, rate_limits: &RateLimits) -> Router {
    create_app_with_quotas(state, rate_limits, PUT_QUOTA, LOOKUP_QUOTA)
}

/// [`create_app`] with the quotas named, so a test can use one that only a count of requests can
/// exhaust.
fn create_app_with_quotas(
    state: AppState,
    rate_limits: &RateLimits,
    put_quota: Quota,
    lookup_quota: Quota,
) -> Router {
    // configure cors middleware
    let cors = CorsLayer::new()
        // allow `GET` and `POST` when accessing the resource
        .allow_methods([Method::GET, Method::POST, Method::PUT])
        // allow requests from any origin
        .allow_origin(cors::Any);

    // configure tracing middleware
    let trace = TraceLayer::new_for_http().make_span_with(|request: &http::Request<_>| {
        let conn_info = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .expect("connectinfo extension to be present");
        let span = span!(
        Level::DEBUG,
            "http_request",
            method = ?request.method(),
            uri = ?request.uri(),
            src = %conn_info.0,
            );
        span
    });

    // configure rate limiting middleware
    let put_limit = rate_limiting::create(&rate_limits.pkarr_put, put_quota);
    let lookup_limit = rate_limiting::create_lookup::<Body>(&rate_limits.lookup, lookup_quota);

    // configure routes
    //
    // Lookups share one quota for each source, and a lookup refused for it is counted.
    // Publications have a quota of their own.
    let mut lookups = Router::new()
        .route("/dns-query", get(doh::get).post(doh::post))
        .route("/pkarr/{key}", get(pkarr::get));
    if let Some(limit) = lookup_limit {
        lookups = lookups.layer(limit).layer(middleware::from_fn_with_state(
            state.clone(),
            count_refused_lookups,
        ));
    }
    let mut publications = Router::new().route("/pkarr/{key}", put(pkarr::put));
    if let Some(limit) = put_limit {
        publications = publications.layer(limit);
    }
    let router = lookups
        .merge(publications)
        // Deprecated: use /healthz instead
        .route("/healthcheck", get(|| async { "OK" }))
        .route("/healthz", get(healthz))
        .route("/", get(|| async { "Hi!" }))
        .with_state(state.clone());

    // configure app
    router
        .layer(cors)
        .layer(trace)
        .route_layer(middleware::from_fn_with_state(state, metrics_middleware))
}

/// Count the lookups the request limit refused.
async fn count_refused_lookups(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> impl IntoResponse {
    let response = next.run(req).await;
    if response.status() == StatusCode::TOO_MANY_REQUESTS {
        state.metrics.lookup_rate_limited.inc();
    }
    response
}

/// Record request metrics.
// TODO:
// * Request duration would be much better tracked as a histogram.
// * It would be great to attach labels to the metrics, so that the recorded metrics
// can filter by method etc.
//
// See also
// https://github.com/tokio-rs/axum/blob/main/examples/prometheus-metrics/src/main.rs#L114
async fn metrics_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> impl IntoResponse {
    let start = Instant::now();
    let response = next.run(req).await;
    let latency = start.elapsed().as_millis();
    let status = response.status();
    state
        .metrics
        .http_requests_duration_ms
        .inc_by(latency as u64);
    state.metrics.http_requests.inc();
    if status.is_success() {
        state.metrics.http_requests_success.inc();
    } else {
        state.metrics.http_requests_error.inc();
    }
    response
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use iroh::{
        RelayUrl, SecretKey,
        address_lookup::{EndpointInfo, PkarrRelayClient},
        dns::{DNS_TIMEOUT, DnsResolver, NameserverConfig},
        tls::{CaTlsConfig, default_provider},
    };
    use n0_error::StdResultExt;
    use n0_tracing_test::traced_test;
    use rand::{RngExt, SeedableRng};

    use crate::{http::HttpsConfig, server::Server};

    #[tokio::test]
    #[traced_test]
    async fn test_doh() -> n0_error::Result {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(0);
        let dir = tempfile::tempdir()?;
        let https_config = HttpsConfig {
            port: 0,
            bind_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            domains: vec!["localhost".to_string()],
            cert_mode: crate::http::CertMode::SelfSigned,
            letsencrypt_contact: None,
            letsencrypt_prod: None,
        };
        let server =
            Server::spawn_for_tests_with_options(dir.path(), None, None, Some(https_config))
                .await?;

        const RELAY_URL: &str = "https://relay.example./";
        let (name_z32, signed_packet) = {
            let secret_key = SecretKey::from_bytes(&rng.random());
            let endpoint_id = secret_key.public();
            let relay_url: RelayUrl = RELAY_URL.parse().expect("valid url");
            let endpoint_info = EndpointInfo::new(endpoint_id).with_relay_url(relay_url.clone());
            (
                secret_key.public().to_z32(),
                endpoint_info.to_pkarr_signed_packet(&secret_key, 30)?,
            )
        };

        let http_url = server.http_url().expect("http is bound");
        let tls_config = CaTlsConfig::default()
            .client_config(default_provider())
            .expect("infallible");
        let pkarr = PkarrRelayClient::new(
            format!("{http_url}pkarr").parse().anyerr()?,
            tls_config,
            DnsResolver::default(),
        );
        pkarr.publish(&signed_packet).await?;

        // Create a reqwest client that does not verify certificates.
        let client = reqwest::Client::builder()
            .http2_prior_knowledge()
            .use_preconfigured_tls(self::tls::insecure_tls_config())
            .build()
            .anyerr()?;

        // Fetch as JSON via HTTP.
        let url = format!(
            "{http_url}dns-query?name={}&type=txt",
            format_args!("_iroh.{name_z32}."),
        );
        let res = client
            .get(url)
            .header("accept", "application/dns-json")
            .send()
            .await
            .anyerr()?
            .json::<super::doh::response::DnsResponse>()
            .await
            .anyerr()?;
        assert_eq!(res.answer.len(), 1);
        assert_eq!(res.answer[0].name, format!("_iroh.{name_z32}."));
        assert_eq!(res.answer[0].data, format!("relay={RELAY_URL}"));

        // Fetch as JSON via HTTPS.
        let https_url = server.https_url().expect("https is bound");
        let url = format!(
            "{https_url}dns-query?name={}&type=txt",
            format_args!("_iroh.{name_z32}."),
        );
        let res = client
            .get(url)
            .header("accept", "application/dns-json")
            .send()
            .await
            .anyerr()?
            .json::<super::doh::response::DnsResponse>()
            .await
            .anyerr()?;
        assert_eq!(res.answer.len(), 1);
        assert_eq!(res.answer[0].name, format!("_iroh.{name_z32}."));
        assert_eq!(res.answer[0].data, format!("relay={RELAY_URL}"));

        // Fetch over DNS-over-HTTPS.
        let resolver = {
            let https_addr = server.https_addr().expect("https is bound");
            DnsResolver::builder()
                .add_nameserver_config(
                    NameserverConfig::https(https_addr.ip())
                        .with_port(https_addr.port())
                        .with_tls_server_name("localhost"),
                )
                .tls_client_config(self::tls::insecure_tls_config())
                .disable_fallback()
                .build()
        };

        let records: Vec<_> = resolver
            .lookup_txt(format!("_iroh.{name_z32}."), DNS_TIMEOUT)
            .await?
            .collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].to_string(), format!("relay={RELAY_URL}"));

        server.shutdown().await?;
        Ok(())
    }

    /// The request limits, on a server that is answering on a local port.
    mod rate_limits {
        use std::{net::SocketAddr, sync::Arc, time::Duration};

        use http::StatusCode;
        use iroh::SecretKey;
        use n0_error::{Result, StdResultExt};

        use super::tls;
        use crate::{
            config::Config,
            dns::DnsHandler,
            http::{RateLimitConfig, RateLimits, create_app_with_quotas, rate_limiting::Quota},
            metrics::Metrics,
            state::AppState,
            store::{Options, ZoneStore},
        };

        /// A quota that replenishes so slowly that only how many requests came decides.
        fn quota(burst: u32) -> Quota {
            Quota {
                replenish: Duration::from_secs(3600),
                burst,
            }
        }

        pub(super) struct Served {
            addr: SocketAddr,
            pub(super) metrics: Arc<Metrics>,
            pub(super) store: ZoneStore,
            client: reqwest::Client,
            task: tokio::task::JoinHandle<()>,
        }

        impl Drop for Served {
            fn drop(&mut self) {
                self.task.abort();
            }
        }

        pub(super) async fn serve(
            limits: RateLimits,
            put_burst: u32,
            lookup_burst: u32,
        ) -> Result<Served> {
            let metrics = Arc::new(Metrics::default());
            let store = ZoneStore::in_memory(Options::default(), metrics.clone())?;
            let state_store = store.clone();
            let state = AppState {
                dns_handler: DnsHandler::new(
                    store.clone(),
                    &Config::default().dns,
                    metrics.clone(),
                )?,
                store,
                metrics: metrics.clone(),
            };
            let app = create_app_with_quotas(state, &limits, quota(put_burst), quota(lookup_burst));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .anyerr()?;
            let addr = listener.local_addr().anyerr()?;
            let task = tokio::spawn(async move {
                axum::serve(
                    listener,
                    app.into_make_service_with_connect_info::<SocketAddr>(),
                )
                .await
                .ok();
            });
            let client = reqwest::Client::builder()
                .use_preconfigured_tls(tls::insecure_tls_config())
                .build()
                .anyerr()?;
            Ok(Served {
                addr,
                metrics,
                store: state_store,
                client,
                task,
            })
        }

        impl Served {
            async fn get_pkarr(&self) -> Result<StatusCode> {
                let key = SecretKey::generate().public().to_z32();
                let res = self
                    .client
                    .get(format!("http://{}/pkarr/{key}", self.addr))
                    .send()
                    .await
                    .anyerr()?;
                Ok(res.status())
            }

            async fn get_doh(&self) -> Result<StatusCode> {
                let res = self
                    .client
                    .get(format!(
                        "http://{}/dns-query?name=x.example.&type=txt",
                        self.addr
                    ))
                    .header("accept", "application/dns-json")
                    .send()
                    .await
                    .anyerr()?;
                Ok(res.status())
            }

            async fn post_doh(&self) -> Result<StatusCode> {
                let res = self
                    .client
                    .post(format!("http://{}/dns-query", self.addr))
                    .header("content-type", "application/dns-message")
                    .body(Vec::<u8>::new())
                    .send()
                    .await
                    .anyerr()?;
                Ok(res.status())
            }

            /// Publish a packet, and return the status and the body of the answer.
            pub(super) async fn put_packet(
                &self,
                packet: &iroh_dns::pkarr::SignedPacket,
            ) -> Result<(StatusCode, String)> {
                let key = packet.public_key().to_z32();
                let res = self
                    .client
                    .put(format!("http://{}/pkarr/{key}", self.addr))
                    .body(packet.to_relay_payload())
                    .send()
                    .await
                    .anyerr()?;
                let status = res.status();
                Ok((status, res.text().await.anyerr()?))
            }

            /// A publication whose body is not a packet: the handler refuses it with a 400, so
            /// any other status is the limit's.
            async fn put_pkarr(&self) -> Result<StatusCode> {
                let key = SecretKey::generate().public().to_z32();
                let res = self
                    .client
                    .put(format!("http://{}/pkarr/{key}", self.addr))
                    .body("not a packet")
                    .send()
                    .await
                    .anyerr()?;
                Ok(res.status())
            }
        }

        pub(super) fn limits(pkarr_put: RateLimitConfig, lookup: RateLimitConfig) -> RateLimits {
            RateLimits { pkarr_put, lookup }
        }

        #[tokio::test]
        async fn lookups_are_refused_after_the_burst_whichever_route_they_take() -> Result {
            let served = serve(
                limits(RateLimitConfig::Simple, RateLimitConfig::Simple),
                2,
                3,
            )
            .await?;

            // Under the burst every route answers, and each request spends the one quota.
            assert_ne!(served.get_pkarr().await?, StatusCode::TOO_MANY_REQUESTS);
            assert_ne!(served.get_doh().await?, StatusCode::TOO_MANY_REQUESTS);
            assert_ne!(served.post_doh().await?, StatusCode::TOO_MANY_REQUESTS);

            // Past it every route refuses.
            assert_eq!(served.get_pkarr().await?, StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(served.get_doh().await?, StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(served.post_doh().await?, StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(served.metrics.lookup_rate_limited.get(), 3);
            Ok(())
        }

        #[tokio::test]
        async fn publications_keep_their_own_quota() -> Result {
            let served = serve(
                limits(RateLimitConfig::Simple, RateLimitConfig::Simple),
                2,
                3,
            )
            .await?;

            // Spend the lookup quota: publications are still answered by their handler.
            for _ in 0..3 {
                served.get_pkarr().await?;
            }
            assert_eq!(served.get_pkarr().await?, StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(served.put_pkarr().await?, StatusCode::BAD_REQUEST);
            assert_eq!(served.put_pkarr().await?, StatusCode::BAD_REQUEST);

            // The publication quota is its own and is spent as it was: two, then refused.
            assert_eq!(served.put_pkarr().await?, StatusCode::TOO_MANY_REQUESTS);
            Ok(())
        }

        #[tokio::test]
        async fn publications_do_not_spend_the_lookup_quota() -> Result {
            let served = serve(
                limits(RateLimitConfig::Simple, RateLimitConfig::Simple),
                2,
                3,
            )
            .await?;

            served.put_pkarr().await?;
            served.put_pkarr().await?;
            assert_eq!(served.put_pkarr().await?, StatusCode::TOO_MANY_REQUESTS);

            for _ in 0..3 {
                assert_ne!(served.get_pkarr().await?, StatusCode::TOO_MANY_REQUESTS);
            }
            Ok(())
        }

        #[tokio::test]
        async fn a_disabled_lookup_limit_refuses_nothing_and_leaves_publications_limited() -> Result
        {
            let served = serve(
                limits(RateLimitConfig::Simple, RateLimitConfig::Disabled),
                2,
                3,
            )
            .await?;

            for _ in 0..20 {
                assert_ne!(served.get_pkarr().await?, StatusCode::TOO_MANY_REQUESTS);
                assert_ne!(served.get_doh().await?, StatusCode::TOO_MANY_REQUESTS);
            }
            assert_eq!(served.metrics.lookup_rate_limited.get(), 0);

            served.put_pkarr().await?;
            served.put_pkarr().await?;
            assert_eq!(served.put_pkarr().await?, StatusCode::TOO_MANY_REQUESTS);
            Ok(())
        }
    }

    /// What a publication is checked against before it is stored.
    mod publication {
        use http::StatusCode;
        use iroh::SecretKey;
        use n0_error::Result;

        use super::rate_limits::{limits, serve};
        use crate::{
            http::RateLimitConfig,
            testing::{now_micros, signed_packet_at},
            util::PublicKeyBytes,
        };

        const SECOND: u64 = 1_000_000;

        fn unlimited() -> crate::http::RateLimits {
            limits(RateLimitConfig::Disabled, RateLimitConfig::Disabled)
        }

        #[tokio::test]
        async fn a_packet_signed_far_ahead_of_the_server_clock_is_refused_and_says_so() -> Result {
            let served = serve(unlimited(), 1, 1).await?;
            let endpoint = SecretKey::generate();
            let key = PublicKeyBytes::new_unchecked(*endpoint.public().as_bytes());
            let now = now_micros();

            let current = signed_packet_at(&endpoint, now, "current");
            let (status, _) = served.put_packet(&current).await?;
            assert_eq!(status, StatusCode::NO_CONTENT);

            // A device whose clock is an hour fast.
            let ahead = signed_packet_at(&endpoint, now + 3600 * SECOND, "ahead");
            let (status, body) = served.put_packet(&ahead).await?;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert!(body.contains("ahead"), "the answer says why: {body}");
            assert_eq!(served.metrics.pkarr_publish_timestamp_ahead.get(), 1);

            // The stored packet is the one it replaced nothing of, and the device's next
            // publication, signed by a corrected clock, replaces it.
            let stored = served.store.get_signed_packet(&key).await?.expect("stored");
            assert_eq!(stored.as_bytes(), current.as_bytes());
            let corrected = signed_packet_at(&endpoint, now + SECOND, "corrected");
            let (status, _) = served.put_packet(&corrected).await?;
            assert_eq!(status, StatusCode::NO_CONTENT);
            let stored = served.store.get_signed_packet(&key).await?.expect("stored");
            assert_eq!(stored.as_bytes(), corrected.as_bytes());
            Ok(())
        }

        #[tokio::test]
        async fn a_packet_signed_within_the_allowed_margin_is_stored() -> Result {
            let served = serve(unlimited(), 1, 1).await?;
            let now = now_micros();

            // Signed now, and signed five minutes ahead (a clock that is a little fast).
            for signed in [now, now + 300 * SECOND] {
                let endpoint = SecretKey::generate();
                let key = PublicKeyBytes::new_unchecked(*endpoint.public().as_bytes());
                let packet = signed_packet_at(&endpoint, signed, "relay");
                let (status, _) = served.put_packet(&packet).await?;
                assert_eq!(status, StatusCode::NO_CONTENT);
                let stored = served.store.get_signed_packet(&key).await?.expect("stored");
                assert_eq!(stored.as_bytes(), packet.as_bytes());
            }
            assert_eq!(served.metrics.pkarr_publish_timestamp_ahead.get(), 0);
            Ok(())
        }
    }

    mod tls {
        use std::sync::Arc;

        use rustls::{
            DigitallySignedStruct, RootCertStore,
            client::{
                ClientConfig,
                danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
            },
            crypto::{
                CryptoProvider, ring::default_provider, verify_tls12_signature,
                verify_tls13_signature,
            },
            pki_types::{CertificateDer, ServerName, UnixTime},
        };

        #[derive(Debug)]
        struct NoCertificateVerification(CryptoProvider);

        impl Default for NoCertificateVerification {
            fn default() -> Self {
                Self(default_provider())
            }
        }

        impl ServerCertVerifier for NoCertificateVerification {
            fn verify_server_cert(
                &self,
                _end_entity: &CertificateDer<'_>,
                _intermediates: &[CertificateDer<'_>],
                _server_name: &ServerName<'_>,
                _ocsp: &[u8],
                _now: UnixTime,
            ) -> Result<ServerCertVerified, rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }

            fn verify_tls12_signature(
                &self,
                message: &[u8],
                cert: &CertificateDer<'_>,
                dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                verify_tls12_signature(
                    message,
                    cert,
                    dss,
                    &self.0.signature_verification_algorithms,
                )
            }

            fn verify_tls13_signature(
                &self,
                message: &[u8],
                cert: &CertificateDer<'_>,
                dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                verify_tls13_signature(
                    message,
                    cert,
                    dss,
                    &self.0.signature_verification_algorithms,
                )
            }

            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                self.0.signature_verification_algorithms.supported_schemes()
            }
        }

        pub(super) fn insecure_tls_config() -> ClientConfig {
            let mut cfg = ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
            cfg.dangerous()
                .set_certificate_verifier(Arc::new(NoCertificateVerification::default()));
            cfg
        }
    }
}
