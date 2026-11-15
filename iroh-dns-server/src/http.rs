//! HTTP server part of iroh-dns-server

use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    extract::{ConnectInfo, DefaultBodyLimit, Request, State},
    http::{Method, StatusCode},
    middleware::{self, Next},
    response::IntoResponse,
    routing::{get, put},
};
use axum_server::accept::DefaultAcceptor;
use hyper_util::{
    rt::{TokioExecutor, TokioTimer},
    server::conn::auto,
};
use iroh_base::PublicKey;
use iroh_dns::pkarr::SignedPacket;
use n0_error::{Result, StdResultExt, anyerr, bail_any};
use serde::{Deserialize, Serialize};
use socket2::{SockRef, TcpKeepalive};
use tokio::{
    net::{TcpListener, TcpSocket},
    task::JoinSet,
};
use tower_http::{
    cors::{self, CorsLayer},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use tracing::{Level, info, span, warn};

mod doh;
mod error;
mod idle;
mod pkarr;
mod rate_limiting;
#[cfg(test)]
mod raw_h2;
mod serve;
mod tls;

use self::idle::{Connections, IdleBound};
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

/// Listen backlog when none is configured.
/// Tokio and std default to 128, which
/// overflows under bursts of slow handshakes.
const DEFAULT_LISTEN_BACKLOG: u32 = 1024;

/// The size that every accepted connection asks of the kernel for its receive buffer: 4,096
/// bytes. Without it, a connection on the build box starts with a send buffer of 2.5 MiB and a
/// receive buffer that the kernel tunes up to 32 MiB. A buffer set before `listen` is the accepted
/// sockets' too, and the kernel does not tune it, so the receive queue of each connection has the
/// size set here. It is the least at which the largest honest request that comes in one flight,
/// the TLS `ClientHello` of 2,035 bytes, arrives whole before the server reads: with an
/// Ethernet segment size the receive queue took 4,308 bytes of one write at this figure, and
/// 2,048 at half of it. A larger request is read as the server takes it in, one round trip for
/// each window, and the largest honest request, a head of 8,192 bytes with a body of 4,096, is
/// answered. The kernel keeps twice the figure, and no more than `net.core.rmem_max`.
const SOCKET_RECV_BUFFER: u32 = 4 * 1024;

/// The size that every accepted connection asks of the kernel for its send buffer: 8,192 bytes.
/// The largest answer that an honest client waits for is the server's handshake flight, about 5
/// kB with a certificate chain and a post-quantum key share; one send took 9,412 bytes at this
/// figure and 5,068 at half of it, before the client has read any. The kernel keeps twice the
/// figure, and no more than `net.core.wmem_max`. Beside it the send queue holds one buffer of the
/// kernel's own, of up to 64 KiB, which this figure does not set.
const SOCKET_SEND_BUFFER: u32 = 8 * 1024;

/// Bind a TCP listener on `addr` with a listen queue of `backlog`. The buffers of the sockets that
/// it accepts are the fixed sizes above.
fn bind_listener(addr: SocketAddr, backlog: u32) -> std::io::Result<std::net::TcpListener> {
    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };

    #[cfg(not(windows))]
    socket.set_reuseaddr(true)?;
    socket.set_recv_buffer_size(SOCKET_RECV_BUFFER)?;
    socket.set_send_buffer_size(SOCKET_SEND_BUFFER)?;
    socket.bind(addr)?;
    socket.listen(backlog)?.into_std()
}

/// How long a connection may take to send the headers of its next request.
///
/// This also closes keep-alive connections that stay idle after a request.
const HTTP1_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Enable hyper's HTTP/1 header read timeout.
///
/// hyper ignores its default timeout unless a timer is set and
/// idle connections then stay open forever.
fn set_header_read_timeout(builder: &mut auto::Builder<TokioExecutor>) {
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(HTTP1_HEADER_READ_TIMEOUT);
}

/// The most that the head of a request may be: 8,192 bytes, counted in the unit of each protocol
/// below. The largest head that the server's routes call for is a DNS query of the largest size by
/// GET, which is `/dns-query?dns=` and 5,462 characters of base64url, 5,477 bytes of path. The
/// other fields take what is left, and a client that adds a large cookie to such a query can pass
/// the figure (see the end):
///
/// - HTTP/1: the request line is 4 + 5,477 + 11 = 5,492 bytes and the final empty line 2, which
///   leaves 2,698 bytes for the `host` field and all others; with a name of 253 characters in
///   `host` (261 bytes), 2,437 bytes.
/// - HTTP/2: the largest accepted list is 8,191 (a list as large as the setting is refused), and the fields `:method`
///   (42 bytes), `:scheme` (44, for `https`) and `:path` (5 + 5,477 + 32 = 5,514) take 5,600; that
///   leaves 2,591 bytes for `:authority` and all other fields; with a name of 253 characters in
///   `:authority` (295 bytes), 2,296 bytes.
///
/// A head past the figure, such as a large cookie beside a query of the largest size, is answered
/// `431`.
const REQUEST_HEAD_LIMIT: usize = 8_192;

/// The most an HTTP/1 connection buffers while it reads the head of a request, which is the head
/// allowance above. It is the lowest value hyper accepts (its default is 417,792). A head that
/// does not fit is answered `431` and the connection is closed.
const HTTP1_MAX_BUFFER_SIZE: usize = REQUEST_HEAD_LIMIT;

/// The most streams an HTTP/2 connection has open at once: 2 (hyper's default is 200; it has no
/// lowest value). An open request with a full header list and a body of 4 kB measured about 15 kB
/// more than the same connection without it on the build box: the peak less the memory of the
/// connections before their streams opened (the table of shapes in `FORK.md`). So the figure sets
/// how much an open connection holds for requests that are not complete. The server announces it
/// in its settings: a client that has read them waits for a stream to end before it opens
/// another, and one that opens a third stream before they arrive has that stream refused with
/// `REFUSED_STREAM`, which it may retry.
const HTTP2_MAX_CONCURRENT_STREAMS: u32 = 2;

/// The header list of an HTTP/2 request is held to the head allowance above, as HTTP/2 counts it
/// (a name, a value and 32 bytes for each field), against hyper's 16,384; hyper has no lowest
/// value. A list as large as the setting is refused, so the largest accepted is one byte under it,
/// and a request with a larger list is answered `431`. The server applies it as soon as the
/// connection opens, whether or not the client acknowledges the server's settings.
const HTTP2_MAX_HEADER_LIST_SIZE: u32 = REQUEST_HEAD_LIMIT as u32;

/// The window of an HTTP/2 stream for the request body the server has not yet read: 4,096 bytes,
/// the largest body any route takes (hyper's default is 1 MiB; it has no lowest value). A body of
/// that size without padding fits the first window; padding in a `DATA` frame counts against the
/// window too. The server applies it once the client has acknowledged the server's settings; the
/// connection window below bounds what a client that never does can send.
const HTTP2_STREAM_WINDOW_SIZE: u32 = 4_096;

/// The window of an HTTP/2 connection for body bytes the server has not yet read: 65,535 bytes,
/// the size the protocol starts every connection with and the least it can be. hyper raises it to
/// 1 MiB unless told otherwise.
const HTTP2_CONNECTION_WINDOW_SIZE: u32 = 65_535;

/// Set the limits on what a connection holds for a request that is not complete: the head that
/// HTTP/1 buffers, and the streams, the header list and the two windows of HTTP/2.
fn set_protocol_limits(builder: &mut auto::Builder<TokioExecutor>) {
    builder.http1().max_buf_size(HTTP1_MAX_BUFFER_SIZE);
    builder
        .http2()
        .max_concurrent_streams(HTTP2_MAX_CONCURRENT_STREAMS)
        .max_header_list_size(HTTP2_MAX_HEADER_LIST_SIZE)
        .initial_stream_window_size(HTTP2_STREAM_WINDOW_SIZE)
        .initial_connection_window_size(HTTP2_CONNECTION_WINDOW_SIZE);
}

/// A server on `listener` whose connections are bounded: by the idle bound, by the header read
/// timeout and by the protocol limits. The HTTP and HTTPS listeners are both made here, so that
/// they cannot differ.
fn bounded_server<A>(
    listener: std::net::TcpListener,
    acceptor: A,
    connections: Arc<Connections>,
) -> Result<serve::Server<IdleBound<A>>> {
    let mut builder = auto::Builder::new(TokioExecutor::new());
    set_header_read_timeout(&mut builder);
    set_protocol_limits(&mut builder);
    let listener = TcpListener::from_std(listener).anyerr()?;
    let metrics = connections.metrics().clone();
    Ok(serve::Server::new(
        listener,
        IdleBound::new(acceptor, connections),
        builder,
        metrics,
    ))
}

/// The most connections the HTTP and HTTPS listeners hold at once, together: 8,192. A connection
/// past it is closed at once, before its handshake, and its request is not queued; the
/// connections already held stay usable. The figure was taken from what a connection costs in the
/// heaviest shape measured, on the build box inside a control group: 16,384 connections in that
/// shape held 1,642 MiB at the group's peak, 102.1 KiB each, and 8,192 held 857 MiB, 106 KiB each;
/// with an empty server of 9 MiB, 8,192 times 102.1 KiB is 826 MiB, from which the figure was
/// taken. The lightest shape measured held 227 MiB at 8,192 connections. Each figure measures its
/// own workload, and no heavier shape has been measured.
pub(crate) const MAX_CONNECTIONS: usize = 8_192;

/// How long a request may take from its headers until the server has made its answer, its body
/// included. Delivering the answer is not part of it: a connection that does not take its answer
/// is closed by the idle bound once it has no request in progress.
///
/// A signed packet and a lookup are a kilobyte or two, so a request that takes longer is a
/// sender that is holding the connection.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// The largest body of `PUT /pkarr/{key}`: a signed packet without the public key the path names.
const PKARR_PUT_BODY_LIMIT: usize = SignedPacket::MAX_BYTES - PublicKey::LENGTH;

/// The largest DNS message of a request to `/dns-query`: the most the server's own UDP path reads
/// of a request. `POST` takes it as the body and `GET` as the `dns=` value, and both refuse a
/// larger one with `413`.
const DOH_MESSAGE_LIMIT: usize = hickory_server::net::udp::MAX_RECEIVE_BUFFER_SIZE;

/// The longest `dns=` value of `GET /dns-query`: a message of the largest size as base64url
/// without padding, 5,462 characters.
const DOH_GET_VALUE_LIMIT: usize = (DOH_MESSAGE_LIMIT * 4).div_ceil(3);

/// Configuration for the HTTP listener.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[non_exhaustive]
pub struct HttpConfig {
    /// Port to bind the HTTP listener to.
    pub port: u16,
    /// Address to bind the HTTP listener to (defaults to `::`, i.e. IPv6 wildcard which also covers IPv4).
    pub bind_addr: Option<IpAddr>,
    /// Listen queue length (defaults to 1024, capped by `net.core.somaxconn` on Linux).
    pub listen_backlog: Option<u32>,
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
    /// Listen queue length (defaults to 1024, capped by `net.core.somaxconn` on Linux).
    pub listen_backlog: Option<u32>,
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
        max_connections: usize,
    ) -> Result<HttpServer> {
        if http_config.is_none() && https_config.is_none() {
            bail_any!("Either http or https config is required");
        }

        let connections = Connections::new(max_connections, state.metrics.clone());
        let app = create_app(state, &rate_limits);

        let mut tasks = JoinSet::new();

        // launch http
        let http_addr = if let Some(config) = http_config {
            let bind_addr = SocketAddr::new(
                config.bind_addr.unwrap_or(Ipv6Addr::UNSPECIFIED.into()),
                config.port,
            );
            let app = app.clone();
            let backlog = config.listen_backlog.unwrap_or(DEFAULT_LISTEN_BACKLOG);
            let listener = bind_listener(bind_addr, backlog).anyerr()?;
            let bound_addr = listener.local_addr().anyerr()?;
            set_keepalive(&listener).anyerr()?;
            let server = bounded_server(listener, DefaultAcceptor::new(), connections.clone())?;
            let fut = server.serve(app.into_make_service_with_connect_info::<SocketAddr>());
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
            let backlog = config.listen_backlog.unwrap_or(DEFAULT_LISTEN_BACKLOG);
            let listener = bind_listener(bind_addr, backlog).anyerr()?;
            let bound_addr = listener.local_addr().anyerr()?;
            set_keepalive(&listener).anyerr()?;
            let server = bounded_server(listener, acceptor, connections)?;
            let fut = server.serve(app.into_make_service_with_connect_info::<SocketAddr>());
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
    /// The revision the build was made from: the fork's commit, set in `KR_FORK_REV` when the
    /// server is built, or `unknown` for a build that was given none.
    git_hash: &'static str,
}

fn health(revision: Option<&'static str>) -> Json<Health> {
    Json(Health {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        git_hash: revision.unwrap_or("unknown"),
    })
}

pub(crate) fn create_app(state: AppState, rate_limits: &RateLimits) -> Router {
    create_app_with_quotas(
        state,
        rate_limits,
        PUT_QUOTA,
        LOOKUP_QUOTA,
        option_env!("KR_FORK_REV"),
    )
}

/// [`create_app`] with the quotas named, so a test can use one that only a count of requests can
/// exhaust.
fn create_app_with_quotas(
    state: AppState,
    rate_limits: &RateLimits,
    put_quota: Quota,
    lookup_quota: Quota,
    revision: Option<&'static str>,
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
    let put_limit = rate_limiting::create(&rate_limits.pkarr_put, put_quota, &state.metrics);
    let lookup_limit =
        rate_limiting::create_lookup(&rate_limits.lookup, lookup_quota, &state.metrics);

    // configure routes
    //
    // Lookups share one quota for each source, and a lookup refused for it is counted.
    // Publications have a quota of their own. A limit is a route layer on a method router, which
    // wraps the method handlers and not the answers for a method the route lacks, so a request no
    // handler answers (an unknown path, a `DELETE`) spends neither quota.
    let mut dns_query = get(doh::get).post(doh::post);
    let mut pkarr_get = get(pkarr::get);
    if let Some(limit) = lookup_limit {
        let limit = middleware::from_fn_with_state(limit, rate_limiting::limit);
        let count = middleware::from_fn_with_state(state.clone(), count_refused_lookups);
        dns_query = dns_query
            .route_layer(limit.clone())
            .route_layer(count.clone());
        pkarr_get = pkarr_get.route_layer(limit).route_layer(count);
    }
    let mut pkarr_put = put(pkarr::put);
    if let Some(limit) = put_limit {
        pkarr_put =
            pkarr_put.route_layer(middleware::from_fn_with_state(limit, rate_limiting::limit));
    }
    // The bodies are read whole, so each route that takes one says how large it may be. The
    // default of axum is 2 MiB, which a sender could make the server hold for every connection.
    let dns_query = dns_query.layer(DefaultBodyLimit::max(DOH_MESSAGE_LIMIT));
    let pkarr_put = pkarr_put.layer(DefaultBodyLimit::max(PKARR_PUT_BODY_LIMIT));
    let router = Router::new()
        .route("/dns-query", dns_query)
        .route("/pkarr/{key}", pkarr_get.merge(pkarr_put))
        // Deprecated: use /healthz instead
        .route("/healthcheck", get(|| async { "OK" }))
        .route("/healthz", get(move || async move { health(revision) }))
        .route("/", get(|| async { "Hi!" }))
        .with_state(state.clone());

    // configure app
    router
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
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
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
        time::Duration,
    };

    use iroh::{
        RelayUrl, SecretKey,
        address_lookup::{EndpointInfo, PkarrRelayClient},
        dns::{DNS_TIMEOUT, DnsResolver, NameserverConfig},
        tls::{CaTlsConfig, default_provider},
    };
    use n0_error::StdResultExt;
    use n0_tracing_test::traced_test;
    use rand::{RngExt, SeedableRng};
    use rustls::{
        DigitallySignedStruct, SignatureScheme,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, ServerName, UnixTime},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
    };
    use tokio_rustls::client::TlsStream;

    use crate::{
        http::{HttpsConfig, raw_h2, tls::partial_client_hello},
        server::Server,
    };

    /// Linux completes at most `backlog + 1` handshakes that are not yet accepted,
    /// then drops further SYNs, so a sequential connect beyond that times out.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[traced_test]
    async fn test_listen_backlog() -> n0_error::Result {
        const BACKLOG: u32 = 4;
        const MAX_CLIENTS: u32 = 64;

        let listener = super::bind_listener((Ipv4Addr::LOCALHOST, 0).into(), BACKLOG).anyerr()?;
        let addr = listener.local_addr().anyerr()?;

        let mut streams = Vec::new();
        while streams.len() < MAX_CLIENTS as usize {
            let connect = tokio::net::TcpStream::connect(addr);
            match tokio::time::timeout(std::time::Duration::from_millis(250), connect).await {
                Ok(stream) => streams.push(stream.anyerr()?),
                Err(_elapsed) => break,
            }
        }
        assert!(
            (BACKLOG..=BACKLOG + 1).contains(&(streams.len() as u32)),
            "accept queue held {} connections for backlog {BACKLOG}",
            streams.len()
        );
        Ok(())
    }

    /// Real time the server gets to close a connection once its clock has been advanced.
    const CLOSE_DEADLINE: Duration = Duration::from_secs(2);

    async fn assert_closed_after(stream: &mut TcpStream, timeout: Duration) -> n0_error::Result {
        assert_open(stream).await;

        advance(timeout - Duration::from_secs(1)).await;
        assert_open(stream).await;

        advance(Duration::from_secs(2)).await;
        let mut buf = [0; 1];
        let read = tokio::time::timeout(CLOSE_DEADLINE, stream.read(&mut buf))
            .await
            .std_context("server did not close the connection")?;
        match read {
            Ok(0) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::ConnectionReset => Ok(()),
            other => panic!("expected the server to close the connection: {other:?}"),
        }
    }

    async fn assert_open(stream: &mut TcpStream) {
        let mut buf = [0; 1];
        assert!(
            tokio::time::timeout(Duration::from_millis(50), stream.read(&mut buf))
                .await
                .is_err(),
            "connection closed before its timeout"
        );
    }

    async fn advance(duration: Duration) {
        tokio::time::pause();
        tokio::time::advance(duration).await;
        tokio::time::resume();
    }

    #[tokio::test]
    #[traced_test]
    async fn test_idle_connection_closed() -> n0_error::Result {
        let dir = tempfile::tempdir()?;
        let server = Server::spawn_for_tests(dir.path()).await?;
        let addr = server.http_addr().expect("http is bound");

        let mut stream = TcpStream::connect(addr).await.anyerr()?;
        stream
            .write_all(b"GET /healthcheck HTTP/1.1\r\nhost: localhost\r\n\r\n")
            .await
            .anyerr()?;
        let mut response = Vec::new();
        while !response.ends_with(b"\r\n\r\nOK") {
            let mut chunk = [0; 1024];
            let n = tokio::time::timeout(CLOSE_DEADLINE, stream.read(&mut chunk))
                .await
                .std_context("no response from server")?
                .anyerr()?;
            assert!(n > 0, "connection closed before the response");
            response.extend_from_slice(&chunk[..n]);
        }
        assert!(response.starts_with(b"HTTP/1.1 200 OK"));
        assert_closed_after(&mut stream, super::HTTP1_HEADER_READ_TIMEOUT).await?;

        server.shutdown().await?;
        Ok(())
    }

    /// The status of the answer to `request`, sent whole on a new connection.
    async fn status_of(addr: SocketAddr, request: &[u8]) -> n0_error::Result<u16> {
        let mut stream = TcpStream::connect(addr).await.anyerr()?;
        stream.write_all(request).await.anyerr()?;
        let mut status_line = [0; 12];
        tokio::time::timeout(CLOSE_DEADLINE, stream.read_exact(&mut status_line))
            .await
            .std_context("no answer from server")?
            .anyerr()?;
        std::str::from_utf8(&status_line[9..12])
            .anyerr()?
            .parse()
            .anyerr()
    }

    /// A `PUT /pkarr/{key}` request with a body of `body_len` bytes, of which `sent` are sent.
    fn put_request(body_len: usize, sent: usize) -> Vec<u8> {
        let key = SecretKey::from_bytes(&[7; 32]).public().to_z32();
        let mut request = format!(
            "PUT /pkarr/{key} HTTP/1.1\r\nhost: localhost\r\ncontent-length: {body_len}\r\n\r\n"
        )
        .into_bytes();
        request.extend(std::iter::repeat_n(b'x', sent));
        request
    }

    /// A valid DNS query for `x.example.` of exactly `len` bytes: the EDNS padding option (RFC 7830)
    /// fills the message up to `len`.
    fn dns_query(len: usize) -> Vec<u8> {
        let mut message = vec![
            0, 1, // the id
            1, 0, // the flags: recursion desired
            0, 1, 0, 0, 0, 0, 0, 1, // one question and one additional record
            1, b'x', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0, // the name
            0, 16, 0, 1, // TXT, IN
            0, 0, 41, 4, 208, 0, 0, 0,
            0, // the OPT record: the root name, OPT, a payload size, no flags
        ];
        let padding = len - message.len() - 6;
        message.extend((4 + padding as u16).to_be_bytes());
        message.extend([0, 12]);
        message.extend((padding as u16).to_be_bytes());
        message.extend(std::iter::repeat_n(0, padding));
        assert_eq!(message.len(), len);
        message
    }

    /// The path of `GET /dns-query` for `message`: base64url without padding, as RFC 8484 writes it.
    fn dns_get_path(message: &[u8]) -> String {
        format!(
            "/dns-query?dns={}",
            data_encoding::BASE64URL_NOPAD.encode(message)
        )
    }

    /// The HTTP/1 request `GET /dns-query` for `message`, with a `cookie` field that makes the head
    /// `head_len` bytes long, if one is given.
    fn dns_get_request(message: &[u8], head_len: Option<usize>) -> Vec<u8> {
        let head = format!(
            "GET {} HTTP/1.1\r\nhost: localhost\r\naccept: application/dns-message\r\n",
            dns_get_path(message)
        );
        let Some(head_len) = head_len else {
            return format!("{head}\r\n").into_bytes();
        };
        let (name, end) = ("cookie: ", "\r\n\r\n");
        let fill = "a".repeat(head_len - head.len() - name.len() - end.len());
        format!("{head}{name}{fill}{end}").into_bytes()
    }

    /// The status of the answer to a request over HTTP/2 on a connection of its own.
    async fn status_over_h2(
        addr: SocketAddr,
        method: &str,
        path: &str,
        extra: &[(&str, String)],
    ) -> n0_error::Result<u16> {
        let mut peer = raw_h2::Peer::connect(addr).await?;
        let stream = peer.request(method, path, extra, true).await?;
        loop {
            let frame = peer.next_frame().await.std_context("no answer")?;
            if frame.stream == stream {
                if let Some(status) = frame.status() {
                    return Ok(status);
                }
                assert_eq!(frame.reset_code(), None, "the request was reset");
            }
        }
    }

    /// The fields of `GET /dns-query` for `message` over HTTP/2: `accept` and, if `list_size` is
    /// given, a `cookie` that makes the header list that long.
    fn dns_get_over_h2(
        message: &[u8],
        list_size: Option<usize>,
    ) -> (String, Vec<(&'static str, String)>) {
        let path = dns_get_path(message);
        let mut extra = vec![("accept", "application/dns-message".to_string())];
        if let Some(list_size) = list_size {
            let used = raw_h2::header_list_size("GET", &path, &extra) + "cookie".len() + 32;
            extra.push(("cookie", "a".repeat(list_size - used)));
        }
        (path, extra)
    }

    /// A connection that completes its handshake, or on the plain listener just connects, and then
    /// sends nothing holds the server's task and socket for as long as the sender likes unless the
    /// server closes it.
    #[tokio::test]
    #[traced_test]
    async fn test_silent_connection_closed() -> n0_error::Result {
        let dir = tempfile::tempdir()?;
        let server = Server::spawn_for_tests(dir.path()).await?;
        let addr = server.http_addr().expect("http is bound");

        let mut stream = TcpStream::connect(addr).await.anyerr()?;
        assert_closed_after(&mut stream, super::idle::IDLE_TIMEOUT).await?;

        server.shutdown().await?;
        Ok(())
    }

    /// Accepts the server's self-signed certificate.
    #[derive(Debug)]
    struct AcceptAnyCertificate;

    impl ServerCertVerifier for AcceptAnyCertificate {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    /// The configuration of an HTTPS listener on loopback with a self-signed certificate.
    fn https_config() -> HttpsConfig {
        HttpsConfig {
            port: 0,
            bind_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            listen_backlog: None,
            domains: vec!["localhost".to_string()],
            cert_mode: crate::http::CertMode::SelfSigned,
            letsencrypt_contact: None,
            letsencrypt_prod: None,
        }
    }

    /// The configuration of a TLS client that takes any certificate.
    fn tls_client_config() -> n0_error::Result<Arc<rustls::ClientConfig>> {
        Ok(Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .anyerr()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate))
            .with_no_client_auth(),
        ))
    }

    /// A client of the HTTPS listener at `addr` whose first requests, `batch`, leave in the
    /// flight of its last handshake message with no wait between: the TLS library holds what is
    /// written before the handshake is done and sends it after the `Finished` message.
    async fn tls_client_with_first_batch(
        addr: SocketAddr,
        batch: &[u8],
    ) -> n0_error::Result<TlsStream<TcpStream>> {
        let tcp = TcpStream::connect(addr).await.anyerr()?;
        tokio_rustls::TlsConnector::from(tls_client_config()?)
            .connect_with(ServerName::try_from("localhost").anyerr()?, tcp, |client| {
                std::io::Write::write_all(&mut client.writer(), batch)
                    .expect("the library buffers what is written before the handshake is done");
            })
            .await
            .anyerr()
    }

    /// A client of the HTTPS listener at `addr` that has finished the TLS handshake.
    async fn tls_client(addr: SocketAddr) -> n0_error::Result<TlsStream<TcpStream>> {
        let tcp = TcpStream::connect(addr).await.anyerr()?;
        let stream = tokio_rustls::TlsConnector::from(tls_client_config()?)
            .connect(ServerName::try_from("localhost").anyerr()?, tcp)
            .await
            .anyerr()?;
        // The client is done once it has sent its last handshake message; give the server the
        // time to take it in, so that its own clock for the handshake has ended.
        tokio::time::sleep(Duration::from_millis(200)).await;
        Ok(stream)
    }

    /// The same on the TLS listener, which is the one the deployment serves: a client that
    /// completes the TLS handshake and sends nothing is closed.
    #[tokio::test]
    #[traced_test]
    async fn test_silent_tls_connection_closed() -> n0_error::Result {
        let dir = tempfile::tempdir()?;
        let server =
            Server::spawn_for_tests_with_options(dir.path(), None, None, Some(https_config()))
                .await?;
        let addr = server.https_addr().expect("https is bound");
        let mut stream = tls_client(addr).await?;

        let mut buf = [0; 1];
        let open = |read: Result<std::io::Result<usize>, _>| read.is_err();
        advance(super::idle::IDLE_TIMEOUT - Duration::from_secs(1)).await;
        assert!(
            open(tokio::time::timeout(Duration::from_millis(50), stream.read(&mut buf)).await),
            "closed before the bound"
        );
        advance(Duration::from_secs(2)).await;
        let read = tokio::time::timeout(CLOSE_DEADLINE, stream.read(&mut buf))
            .await
            .std_context("server did not close the connection")?;
        assert!(
            !matches!(read, Ok(n) if n > 0),
            "the server sent data to a client that sent nothing"
        );

        server.shutdown().await?;
        Ok(())
    }

    /// A connection that is still in its TLS handshake may send 32,768 bytes and no more: the
    /// TLS library holds a message that it is sent in pieces, up to 64 KiB, until the message
    /// ends, and the handshake's time limit alone would let every held connection hold that for 30
    /// seconds. With the figure sent the connection stays open; one byte more and it is closed.
    #[tokio::test]
    #[traced_test]
    async fn test_tls_handshake_past_the_bound_is_closed() -> n0_error::Result {
        let dir = tempfile::tempdir()?;
        let server =
            Server::spawn_for_tests_with_options(dir.path(), None, None, Some(https_config()))
                .await?;
        let addr = server.https_addr().expect("https is bound");

        let mut stream = TcpStream::connect(addr).await.anyerr()?;
        stream
            .write_all(&partial_client_hello(32_768))
            .await
            .anyerr()?;
        assert_open(&mut stream).await;
        // The first byte of the next record, which the TLS library would wait on.
        stream.write_all(&[0x16]).await.anyerr()?;
        let mut buf = [0; 1];
        let read = tokio::time::timeout(CLOSE_DEADLINE, stream.read(&mut buf))
            .await
            .std_context("a connection that sent past the handshake's bound was held")?;
        assert!(
            matches!(&read, Ok(0))
                || read
                    .as_ref()
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::ConnectionReset),
            "expected the server to close the connection: {read:?}"
        );

        server.shutdown().await?;
        Ok(())
    }

    /// A client whose first requests arrive in the flight of its last handshake message, with no
    /// wait between them, is answered. The TLS acceptor reads on past the `Finished` message until
    /// it has decrypted one application record, so those bytes are counted by the handshake's
    /// bound, and a figure with no room for a valid first batch closes a valid connection. The
    /// batches are the largest honest ones that fill the first record (16,384 bytes): over HTTP/1
    /// two heads of 8,192 bytes and a query of 4,096 bytes, over HTTP/2 two heads whose lists are
    /// 8,191 bytes, one with a body of 4,096 bytes.
    #[tokio::test]
    #[traced_test]
    async fn test_a_first_batch_with_the_last_handshake_message_is_answered() -> n0_error::Result {
        let dir = tempfile::tempdir()?;
        let server =
            Server::spawn_for_tests_with_options(dir.path(), None, None, Some(https_config()))
                .await?;
        let addr = server.https_addr().expect("https is bound");

        let most = super::HTTP1_MAX_BUFFER_SIZE;
        let head = |len: usize| {
            let start = "GET /healthcheck HTTP/1.1\r\nhost: localhost\r\nx-fill: ";
            let end = "\r\n\r\n";
            let fill = "a".repeat(len - start.len() - end.len());
            format!("{start}{fill}{end}").into_bytes()
        };
        let largest = super::DOH_MESSAGE_LIMIT;
        let mut post = format!(
            "POST /dns-query HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/dns-message\r\ncontent-length: {largest}\r\n\r\n"
        )
        .into_bytes();
        post.extend(dns_query(largest));
        let batch = [head(most), post, head(most)].concat();
        assert!(batch.len() > 16_384, "the batch does not fill a record");
        let mut stream = tls_client_with_first_batch(addr, &batch).await?;
        for _ in 0..3 {
            assert_eq!(read_answer(&mut stream).await?, 200);
        }
        drop(stream);

        let list = |method: &str, path: &str, mut extra: Vec<(&'static str, String)>| {
            let used = raw_h2::header_list_size(method, path, &extra) + "cookie".len() + 32;
            extra.push((
                "cookie",
                "a".repeat(super::HTTP2_MAX_HEADER_LIST_SIZE as usize - 1 - used),
            ));
            extra
        };
        let post_fields = list(
            "POST",
            "/dns-query",
            vec![
                ("content-length", largest.to_string()),
                ("content-type", "application/dns-message".to_string()),
            ],
        );
        let get_fields = list("GET", "/healthcheck", Vec::new());
        let mut batch = raw_h2::PREFACE.to_vec();
        batch.extend(raw_h2::frame(raw_h2::SETTINGS, 0, 0, &[]));
        batch.extend(raw_h2::frame(
            raw_h2::HEADERS,
            0x4,
            1,
            &raw_h2::request_block("POST", "/dns-query", &post_fields),
        ));
        batch.extend(raw_h2::frame(
            raw_h2::DATA,
            raw_h2::END_STREAM,
            1,
            &dns_query(largest),
        ));
        batch.extend(raw_h2::frame(
            raw_h2::HEADERS,
            0x4 | raw_h2::END_STREAM,
            3,
            &raw_h2::request_block("GET", "/healthcheck", &get_fields),
        ));
        assert!(batch.len() > 16_384, "the batch does not fill a record");
        let mut peer = raw_h2::Peer::resumed(tls_client_with_first_batch(addr, &batch).await?);
        let mut answered = Vec::new();
        while answered.len() < 2 {
            let frame = peer.next_frame().await?;
            if frame.status().is_some() {
                answered.push((frame.stream, frame.status()));
            }
        }
        for stream in [1, 3] {
            assert!(answered.contains(&(stream, Some(200))), "{answered:?}");
        }

        server.shutdown().await?;
        Ok(())
    }

    /// An HTTP/2 connection with no request open is closed, whatever its peer sends.
    #[tokio::test]
    #[traced_test]
    async fn test_http2_connection_with_no_request_closed() -> n0_error::Result {
        const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        const EMPTY_SETTINGS: [u8; 9] = [0, 0, 0, 4, 0, 0, 0, 0, 0];
        const PING: [u8; 17] = [0, 0, 8, 6, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8];

        let dir = tempfile::tempdir()?;
        let server = Server::spawn_for_tests(dir.path()).await?;
        let addr = server.http_addr().expect("http is bound");

        let mut stream = TcpStream::connect(addr).await.anyerr()?;
        stream.write_all(PREFACE).await.anyerr()?;
        stream.write_all(&EMPTY_SETTINGS).await.anyerr()?;
        let mut buf = [0; 256];
        let n = tokio::time::timeout(CLOSE_DEADLINE, stream.read(&mut buf))
            .await
            .std_context("no settings from server")?
            .anyerr()?;
        assert!(n > 0, "connection closed before the settings");

        // A ping every few seconds keeps the peer's side of the connection busy, and starts no request.
        for _ in 0..3 {
            advance(Duration::from_secs(8)).await;
            stream.write_all(&PING).await.anyerr()?;
            while let Ok(read) =
                tokio::time::timeout(Duration::from_millis(50), stream.read(&mut buf)).await
            {
                assert!(read.anyerr()? > 0, "closed before the bound");
            }
        }
        advance(Duration::from_secs(8)).await;
        loop {
            let read = tokio::time::timeout(CLOSE_DEADLINE, stream.read(&mut buf))
                .await
                .std_context("server did not close the connection")?;
            match read {
                Ok(0) => break,
                Err(err) if err.kind() == std::io::ErrorKind::ConnectionReset => break,
                Ok(_) => continue,
                Err(err) => panic!("expected the server to close the connection: {err:?}"),
            }
        }

        server.shutdown().await?;
        Ok(())
    }

    /// A request in progress on an HTTP/2 connection suspends the idle bound, which then runs from
    /// the end of the request and not from the start of the connection.
    #[tokio::test]
    #[traced_test]
    async fn test_http2_connection_with_a_request_open_is_held_until_it_ends() -> n0_error::Result {
        let dir = tempfile::tempdir()?;
        let server = Server::spawn_for_tests(dir.path()).await?;
        let mut peer = raw_h2::Peer::connect(server.http_addr().expect("http is bound")).await?;

        // A publication whose body never arrives keeps its stream open until the request's
        // deadline, which ends the request with an answer.
        let key = SecretKey::from_bytes(&[7; 32]).public().to_z32();
        let length = [("content-length", "1000".to_string())];
        let stream = peer
            .request("PUT", &format!("/pkarr/{key}"), &length, false)
            .await?;
        // The server has the request before the clock moves.
        assert!(!peer.ended_within(Duration::from_millis(50)).await);
        advance(Duration::from_secs(9)).await;
        assert!(!peer.ended_within(Duration::from_millis(50)).await);
        advance(Duration::from_secs(2)).await;
        loop {
            let frame = peer
                .next_frame()
                .await
                .std_context("the request was not answered at its deadline")?;
            if frame.kind == raw_h2::HEADERS && frame.stream == stream {
                assert_eq!(frame.status(), Some(408), "the request's answer");
                break;
            }
        }

        // 35 seconds after the connection opened, which is past the bound counted from then, but
        // 24 after the request ended.
        advance(Duration::from_secs(24)).await;
        assert!(
            !peer.ended_within(Duration::from_millis(50)).await,
            "closed before the bound ran from the end of the request"
        );
        advance(Duration::from_secs(8)).await;
        assert!(
            peer.ended_within(CLOSE_DEADLINE).await,
            "not closed at the bound"
        );

        server.shutdown().await?;
        Ok(())
    }

    /// A connection that the server answers with a request, for as long as the connection stands.
    async fn answers(stream: &mut TcpStream) -> n0_error::Result {
        stream
            .write_all(b"GET /healthcheck HTTP/1.1\r\nhost: localhost\r\n\r\n")
            .await
            .anyerr()?;
        let mut response = Vec::new();
        while !response.ends_with(b"\r\n\r\nOK") {
            let mut chunk = [0; 1024];
            let n = tokio::time::timeout(CLOSE_DEADLINE, stream.read(&mut chunk))
                .await
                .std_context("no answer from server")?
                .anyerr()?;
            assert!(n > 0, "connection closed before the answer");
            response.extend_from_slice(&chunk[..n]);
        }
        Ok(())
    }

    /// A connection past the most the server holds is closed without an answer.
    async fn assert_refused(stream: &mut TcpStream) -> n0_error::Result {
        let mut buf = [0; 1];
        let read = tokio::time::timeout(CLOSE_DEADLINE, stream.read(&mut buf))
            .await
            .std_context("a connection past the most was not closed")?;
        assert!(
            matches!(read, Ok(0))
                || read.is_err_and(|e| e.kind() == std::io::ErrorKind::ConnectionReset),
            "a connection past the most was answered"
        );
        Ok(())
    }

    /// The most connections of the deployment is 8,192. The figure is taken from the measured
    /// cost of a connection in the heaviest shape measured, against the share of the memory
    /// limit that the connections have, and it changes only with a new measure: the cases that
    /// hold a few connections do not show which figure the server runs with.
    #[test]
    fn test_the_most_connections_is_the_measured_figure() {
        assert_eq!(super::MAX_CONNECTIONS, 8_192);
    }

    /// The sockets that a listener accepts have the buffers that the server sets, and the kernel
    /// does not tune them: Linux gives an accepted socket the buffers of the listening socket and
    /// keeps twice the size that was set. The sizes are written out here so that a change of a
    /// figure, or no figure, fails this case. (macOS does not carry the sizes to the accepted
    /// socket and tunes it.)
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_accepted_sockets_have_the_fixed_buffers() -> n0_error::Result {
        let listener = super::bind_listener((Ipv4Addr::LOCALHOST, 0).into(), 16).anyerr()?;
        let listener = tokio::net::TcpListener::from_std(listener).anyerr()?;
        let _client = TcpStream::connect(listener.local_addr().anyerr()?)
            .await
            .anyerr()?;
        let (accepted, _) = listener.accept().await.anyerr()?;
        let socket = socket2::SockRef::from(&accepted);
        assert_eq!(socket.recv_buffer_size().anyerr()?, 2 * 4_096);
        assert_eq!(socket.send_buffer_size().anyerr()?, 2 * 8_192);
        Ok(())
    }

    /// The connection past the most the server holds is closed at once, the ones held still
    /// answer, a place comes free when one of them ends, and a refused connection leaves no task.
    /// The figure of the deployment is 8,192; this case holds four, and the figure itself is
    /// measured on a server with its real limits.
    #[tokio::test]
    #[traced_test]
    async fn test_connections_past_the_most_are_closed_at_once() -> n0_error::Result {
        const MOST: usize = 4;
        let dir = tempfile::tempdir()?;
        let server =
            Server::spawn_for_tests_with_connection_cap(dir.path(), None, None, None, MOST).await?;
        let addr = server.http_addr().expect("http is bound");

        let mut held = Vec::new();
        for _ in 0..MOST {
            let mut stream = TcpStream::connect(addr).await.anyerr()?;
            answers(&mut stream).await?;
            held.push(stream);
        }

        let tasks = tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks();
        for _ in 0..20 {
            let mut refused = TcpStream::connect(addr).await.anyerr()?;
            assert_refused(&mut refused).await?;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            tokio::runtime::Handle::current()
                .metrics()
                .num_alive_tasks(),
            tasks,
            "a refused connection left a task"
        );

        for stream in &mut held {
            answers(stream).await?;
        }

        // A place comes free once the server has seen a held connection close.
        drop(held.pop());
        let mut freed = false;
        for _ in 0..40 {
            let mut stream = TcpStream::connect(addr).await.anyerr()?;
            if answers(&mut stream).await.is_ok() {
                freed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(freed, "no place came free after a held connection closed");

        server.shutdown().await?;
        Ok(())
    }

    /// The most connections is one count for the HTTP and the HTTPS listener together: with the
    /// most held between them, a new connection on either is closed at once.
    #[tokio::test]
    #[traced_test]
    async fn test_connection_cap_is_one_count_over_both_listeners() -> n0_error::Result {
        const MOST: usize = 4;
        let dir = tempfile::tempdir()?;
        let server = Server::spawn_for_tests_with_connection_cap(
            dir.path(),
            None,
            None,
            Some(https_config()),
            MOST,
        )
        .await?;
        let http = server.http_addr().expect("http is bound");
        let https = server.https_addr().expect("https is bound");

        let mut held = Vec::new();
        let mut held_tls = Vec::new();
        for _ in 0..MOST / 2 {
            let mut stream = TcpStream::connect(http).await.anyerr()?;
            answers(&mut stream).await?;
            held.push(stream);
            held_tls.push(tls_client(https).await?);
        }

        let mut refused = TcpStream::connect(http).await.anyerr()?;
        assert_refused(&mut refused).await?;
        assert!(
            tls_client(https).await.is_err(),
            "a TLS connection past the most was accepted"
        );

        server.shutdown().await?;
        Ok(())
    }

    /// A request whose body arrives slowly is answered at the request's deadline, counted from its
    /// start, and not held: a byte every two seconds is no sign that the body is on its way.
    #[tokio::test]
    #[traced_test]
    async fn test_slow_request_body_gets_408() -> n0_error::Result {
        let dir = tempfile::tempdir()?;
        let server = Server::spawn_for_tests(dir.path()).await?;
        let addr = server.http_addr().expect("http is bound");

        let mut stream = TcpStream::connect(addr).await.anyerr()?;
        stream.write_all(&put_request(1000, 10)).await.anyerr()?;
        // A byte every two seconds, until the next would come at the deadline.
        let step = Duration::from_secs(2);
        let mut elapsed = Duration::ZERO;
        while elapsed + step < super::REQUEST_TIMEOUT {
            assert_open(&mut stream).await;
            advance(step).await;
            stream.write_all(b"x").await.anyerr()?;
            elapsed += step;
        }
        assert_open(&mut stream).await;
        advance(super::REQUEST_TIMEOUT + Duration::from_secs(1) - elapsed).await;
        let mut status_line = [0; 12];
        tokio::time::timeout(CLOSE_DEADLINE, stream.read_exact(&mut status_line))
            .await
            .std_context("no answer at the deadline")?
            .anyerr()?;
        assert_eq!(&status_line[9..12], b"408");

        server.shutdown().await?;
        Ok(())
    }

    /// A body is read whole, so a request may not hold more than the largest thing the route takes.
    #[tokio::test]
    #[traced_test]
    async fn test_body_limits() -> n0_error::Result {
        let dir = tempfile::tempdir()?;
        let server = Server::spawn_for_tests(dir.path()).await?;
        let addr = server.http_addr().expect("http is bound");

        let largest = super::PKARR_PUT_BODY_LIMIT;
        // Past the limit is refused as too large; at the limit the body is read and then judged.
        assert_eq!(
            status_of(addr, &put_request(largest + 1, largest + 1)).await?,
            413
        );
        assert_eq!(status_of(addr, &put_request(largest, largest)).await?, 400);

        let post = |len: usize| {
            let mut request = format!(
                "POST /dns-query HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/dns-message\r\ncontent-length: {len}\r\n\r\n"
            )
            .into_bytes();
            request.extend(std::iter::repeat_n(0, len));
            request
        };
        let largest = super::DOH_MESSAGE_LIMIT;
        assert_eq!(status_of(addr, &post(largest + 1)).await?, 413);
        // A body of the largest size is read whole, and a message of zeros is an empty query.
        assert_eq!(status_of(addr, &post(largest)).await?, 200);

        server.shutdown().await?;
        Ok(())
    }

    /// A request whose head does not fit the buffer that hyper reads it into is answered `431`. The
    /// allowance holds the largest DNS query by GET with other fields beside it.
    #[tokio::test]
    #[traced_test]
    async fn test_http1_head_limit() -> n0_error::Result {
        let dir = tempfile::tempdir()?;
        let server = Server::spawn_for_tests(dir.path()).await?;
        let addr = server.http_addr().expect("http is bound");

        // A head of `len` bytes: a request for the health check and a header that fills it.
        let head = |len: usize| {
            let start = "GET /healthcheck HTTP/1.1\r\nhost: localhost\r\nx-fill: ";
            let end = "\r\n\r\n";
            let fill = "a".repeat(len - start.len() - end.len());
            format!("{start}{fill}{end}").into_bytes()
        };
        let most = super::HTTP1_MAX_BUFFER_SIZE;
        assert_eq!(status_of(addr, &head(1_000)).await?, 200);
        assert_eq!(status_of(addr, &head(most)).await?, 200);
        assert_eq!(status_of(addr, &head(most + 1)).await?, 431);

        // The largest query takes most of the head, and a cookie fills the rest.
        let query = dns_query(super::DOH_MESSAGE_LIMIT);
        assert_eq!(status_of(addr, &dns_get_request(&query, None)).await?, 200);
        assert_eq!(
            status_of(addr, &dns_get_request(&query, Some(most))).await?,
            200
        );
        assert_eq!(
            status_of(addr, &dns_get_request(&query, Some(most + 1))).await?,
            431
        );

        server.shutdown().await?;
        Ok(())
    }

    /// A peer that opens a stream past the most the server allows has that stream refused, and
    /// the streams within the limit go on and are answered.
    #[tokio::test]
    #[traced_test]
    async fn test_http2_stream_limit() -> n0_error::Result {
        let dir = tempfile::tempdir()?;
        let server = Server::spawn_for_tests(dir.path()).await?;
        let mut peer = raw_h2::Peer::connect(server.http_addr().expect("http is bound")).await?;

        // A request whose body has not arrived keeps its stream open.
        let length = [("content-length", "100".to_string())];
        let mut open = Vec::new();
        for _ in 0..super::HTTP2_MAX_CONCURRENT_STREAMS {
            open.push(peer.request("POST", "/dns-query", &length, false).await?);
        }
        let refused = peer.request("POST", "/dns-query", &length, false).await?;
        loop {
            let frame = peer
                .next_frame()
                .await
                .std_context("the stream past the limit was not refused")?;
            if let Some(code) = frame.reset_code() {
                assert_eq!(frame.stream, refused, "a stream within the limit was reset");
                assert_eq!(code, raw_h2::REFUSED_STREAM);
                break;
            }
        }

        peer.data(open[0], &[b'x'; 100], true).await?;
        loop {
            let frame = peer
                .next_frame()
                .await
                .std_context("a stream within the limit was not answered")?;
            assert_eq!(
                frame.reset_code(),
                None,
                "a stream within the limit was reset"
            );
            if frame.kind == raw_h2::HEADERS && frame.stream == open[0] {
                break;
            }
        }

        server.shutdown().await?;
        Ok(())
    }

    /// A request whose header list is as large as the setting is answered `431`, and one a byte
    /// under it is answered. The allowance holds the largest DNS query by GET with other fields
    /// beside it.
    #[tokio::test]
    #[traced_test]
    async fn test_http2_header_list_limit() -> n0_error::Result {
        let dir = tempfile::tempdir()?;
        let server = Server::spawn_for_tests(dir.path()).await?;
        let addr = server.http_addr().expect("http is bound");

        let most = super::HTTP2_MAX_HEADER_LIST_SIZE as usize;
        // A list of `size`: a request for the health check and a field that fills it.
        let fill = |size: usize| {
            let used = raw_h2::header_list_size("GET", "/healthcheck", &[]) + "x-fill".len() + 32;
            [("x-fill", "a".repeat(size - used))]
        };
        let status = |size: usize| {
            let extra = fill(size);
            async move { status_over_h2(addr, "GET", "/healthcheck", &extra).await }
        };
        assert_eq!(status(most / 2).await?, 200);
        assert_eq!(status(most - 1).await?, 200);
        assert_eq!(status(most).await?, 431);

        let query = dns_query(super::DOH_MESSAGE_LIMIT);
        let status = |list_size: Option<usize>| {
            let (path, extra) = dns_get_over_h2(&query, list_size);
            async move { status_over_h2(addr, "GET", &path, &extra).await }
        };
        assert_eq!(status(None).await?, 200);
        assert_eq!(status(Some(most - 1)).await?, 200);
        assert_eq!(status(Some(most)).await?, 431);

        server.shutdown().await?;
        Ok(())
    }

    /// A request head that never ends is cut off at the bound on what a connection reads between
    /// two request starts, with no request in progress and with one held open beside it. The
    /// client meets a connection that ends.
    #[tokio::test]
    #[traced_test]
    async fn test_http2_unfinished_request_head_closes_the_connection() -> n0_error::Result {
        let dir = tempfile::tempdir()?;
        let server = Server::spawn_for_tests(dir.path()).await?;
        let addr = server.http_addr().expect("http is bound");

        let mut peer = raw_h2::Peer::connect(addr).await?;
        peer.unfinished_block(5).await;
        assert!(
            peer.ended_within(CLOSE_DEADLINE).await,
            "an unfinished request head, with no request in progress, was held"
        );

        let mut peer = raw_h2::Peer::connect(addr).await?;
        let length = [("content-length", "100".to_string())];
        peer.request("POST", "/dns-query", &length, false).await?;
        peer.unfinished_block(5).await;
        assert!(
            peer.ended_within(CLOSE_DEADLINE).await,
            "an unfinished request head, with a request held open, was held"
        );

        server.shutdown().await?;
        Ok(())
    }

    /// The bytes that `Peer` has sent when it has connected: the preface of HTTP/2 (24), its own
    /// settings (9) and the acknowledgement of the server's (9).
    const PEER_CONNECT_BYTES: usize = 42;

    /// Brings the count of bytes that the server has read from the connection to `total`, the
    /// last 17 of them a ping, and waits for the ping's answer, which shows that the server has
    /// read them all and kept the connection open.
    async fn read_exactly<S>(peer: &mut raw_h2::Peer<S>, total: usize) -> n0_error::Result
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let mut left = total - PEER_CONNECT_BYTES - (9 + 8);
        while left > 0 {
            let payload = (left - 9).min(16_384);
            peer.send(raw_h2::UNDEFINED, 0, 0, &vec![0; payload])
                .await?;
            left -= 9 + payload;
        }
        peer.send(raw_h2::PING, 0, 0, &[0; 8]).await?;
        loop {
            let frame = peer.next_frame().await?;
            if frame.kind == raw_h2::PING && frame.flags & raw_h2::ACK != 0 {
                return Ok(());
            }
        }
    }

    /// A connection may read 24,576 bytes between two request starts, and before its first, after
    /// its handshake: with exactly that many read it is open, and one byte more closes it. The
    /// figure is written out here so that a change of it fails this case. The bytes are counted
    /// as the connection's own bytes, which on the TLS listener are the decrypted bytes: the
    /// handshake's bound of 32,768 raw bytes does not apply to them.
    #[tokio::test]
    #[traced_test]
    async fn test_read_bound_is_exact_over_http_and_tls() -> n0_error::Result {
        let dir = tempfile::tempdir()?;
        let server =
            Server::spawn_for_tests_with_options(dir.path(), None, None, Some(https_config()))
                .await?;

        let mut peer = raw_h2::Peer::connect(server.http_addr().expect("http is bound")).await?;
        read_exactly(&mut peer, 24_576).await?;
        peer.send_raw(&[0]).await?;
        assert!(
            peer.ended_within(CLOSE_DEADLINE).await,
            "over HTTP: a byte past the bound was read"
        );

        let tls = tls_client(server.https_addr().expect("https is bound")).await?;
        let mut peer = raw_h2::Peer::over(tls).await?;
        read_exactly(&mut peer, 24_576).await?;
        peer.send_raw(&[0]).await?;
        assert!(
            peer.ended_within(CLOSE_DEADLINE).await,
            "over TLS: a byte past the bound was read"
        );

        server.shutdown().await?;
        Ok(())
    }

    /// A connection that the server closes by either bound gives its place back: with the most at
    /// one, a connection that the bound closed is followed by one that is answered.
    #[tokio::test]
    #[traced_test]
    async fn test_a_close_by_either_bound_gives_the_place_back() -> n0_error::Result {
        let dir = tempfile::tempdir()?;
        let server = Server::spawn_for_tests_with_connection_cap(
            dir.path(),
            None,
            None,
            Some(https_config()),
            1,
        )
        .await?;
        let http = server.http_addr().expect("http is bound");
        let https = server.https_addr().expect("https is bound");

        let mut peer = raw_h2::Peer::connect(http).await?;
        let mut refused = TcpStream::connect(http).await.anyerr()?;
        assert_refused(&mut refused).await?;
        // Two sends of bytes that start no request take the connection past 24,576 bytes.
        for payload in [16_384, 8_200] {
            let _ = peer.send(raw_h2::UNDEFINED, 0, 0, &vec![0; payload]).await;
        }
        assert!(
            peer.ended_within(CLOSE_DEADLINE).await,
            "the bound did not close the connection"
        );
        let mut freed = false;
        for _ in 0..40 {
            let mut stream = TcpStream::connect(http).await.anyerr()?;
            if answers(&mut stream).await.is_ok() {
                freed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(freed, "no place came free after the read bound closed one");

        // A handshake that has sent the most it may stands open and holds the only place: the
        // place that the probe above gave back is taken in a moment, so the connection is made
        // again until one stands open.
        let mut hello = None;
        for _ in 0..40 {
            let mut stream = TcpStream::connect(https).await.anyerr()?;
            stream
                .write_all(&partial_client_hello(32_768))
                .await
                .anyerr()?;
            let mut buf = [0; 1];
            if tokio::time::timeout(Duration::from_millis(50), stream.read(&mut buf))
                .await
                .is_err()
            {
                hello = Some(stream);
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let mut hello = hello.expect("no handshake stood open: the place did not come free");
        let mut second = TcpStream::connect(http).await.anyerr()?;
        assert_refused(&mut second).await?;
        // Only now the byte past the figure, which the handshake's bound closes.
        hello.write_all(&[0x16]).await.anyerr()?;
        assert_refused(&mut hello).await?;
        let mut freed = false;
        for _ in 0..40 {
            if tls_client(https).await.is_ok() {
                freed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            freed,
            "no place came free after the handshake bound closed one"
        );

        server.shutdown().await?;
        Ok(())
    }

    /// The bound on what a connection reads between two request starts leaves honest requests of
    /// the largest sizes alone, over HTTP/2: a POST and then a GET one after another on one
    /// connection, and two at once.
    #[tokio::test]
    #[traced_test]
    async fn test_http2_largest_requests_are_answered_one_after_another_and_at_once()
    -> n0_error::Result {
        let dir = tempfile::tempdir()?;
        let server = Server::spawn_for_tests(dir.path()).await?;
        let mut peer = raw_h2::Peer::connect(server.http_addr().expect("http is bound")).await?;

        let largest = super::DOH_MESSAGE_LIMIT;
        let message = dns_query(largest);
        let post_fields = [
            ("content-length", largest.to_string()),
            ("content-type", "application/dns-message".to_string()),
        ];
        let (get_path, get_fields) = dns_get_over_h2(
            &message,
            Some(super::HTTP2_MAX_HEADER_LIST_SIZE as usize - 1),
        );

        let post = peer
            .request("POST", "/dns-query", &post_fields, false)
            .await?;
        peer.data(post, &message, true).await?;
        let get = peer.request("GET", &get_path, &get_fields, true).await?;
        // Both at once, the second pair after the first pair is answered.
        let (mut answered, mut at_once) = (Vec::new(), Vec::new());
        while answered.len() < 2 {
            let frame = peer.next_frame().await?;
            if frame.status().is_some() {
                answered.push((frame.stream, frame.status()));
            }
        }
        for stream in [post, get] {
            assert!(answered.contains(&(stream, Some(200))), "{answered:?}");
        }
        let post = peer
            .request("POST", "/dns-query", &post_fields, false)
            .await?;
        peer.data(post, &message, true).await?;
        let get = peer.request("GET", &get_path, &get_fields, true).await?;
        while at_once.len() < 2 {
            let frame = peer.next_frame().await?;
            if frame.status().is_some() {
                at_once.push((frame.stream, frame.status()));
            }
        }
        for stream in [post, get] {
            assert!(at_once.contains(&(stream, Some(200))), "{at_once:?}");
        }

        server.shutdown().await?;
        Ok(())
    }

    /// The TLS handshake of a connection is done by the task of that connection, so a client
    /// that stalls in its handshake delays no other: a second client completes its handshake and
    /// is answered while the first still stands.
    #[tokio::test]
    #[traced_test]
    async fn test_a_stalled_handshake_does_not_delay_another_connection() -> n0_error::Result {
        let dir = tempfile::tempdir()?;
        let server =
            Server::spawn_for_tests_with_options(dir.path(), None, None, Some(https_config()))
                .await?;
        let addr = server.https_addr().expect("https is bound");

        let _stalled = TcpStream::connect(addr).await.anyerr()?;
        let mut stream = tokio::time::timeout(CLOSE_DEADLINE, tls_client(addr))
            .await
            .std_context("the second handshake waited for the first")??;
        let request = b"GET /healthcheck HTTP/1.1\r\nhost: localhost\r\n\r\n";
        assert_eq!(exchange(&mut stream, request).await?, 200);

        server.shutdown().await?;
        Ok(())
    }

    /// Shutting the server down ends the connections that stand on its listeners, plain and TLS,
    /// not only the listeners. The sockets are read for a short stretch of real time, which is
    /// below the time an idle connection would stand.
    #[tokio::test]
    #[traced_test]
    async fn test_shutdown_ends_standing_connections() -> n0_error::Result {
        let dir = tempfile::tempdir()?;
        let server =
            Server::spawn_for_tests_with_options(dir.path(), None, None, Some(https_config()))
                .await?;
        let request = b"GET /healthcheck HTTP/1.1\r\nhost: localhost\r\n\r\n";
        let mut plain = TcpStream::connect(server.http_addr().expect("http is bound"))
            .await
            .anyerr()?;
        assert_eq!(exchange(&mut plain, request).await?, 200);
        let mut secure = tls_client(server.https_addr().expect("https is bound")).await?;
        assert_eq!(exchange(&mut secure, request).await?, 200);

        server.shutdown().await?;

        let mut byte = [0; 1];
        let read = tokio::time::timeout(CLOSE_DEADLINE, plain.read(&mut byte))
            .await
            .std_context("the plain connection stood after the shutdown")?;
        assert!(!matches!(read, Ok(n) if n > 0), "{read:?}");
        let read = tokio::time::timeout(CLOSE_DEADLINE, secure.read(&mut byte))
            .await
            .std_context("the TLS connection stood after the shutdown")?;
        assert!(!matches!(read, Ok(n) if n > 0), "{read:?}");
        Ok(())
    }

    /// The status of the answer to `request` on a connection that is kept, whose answer is read
    /// whole.
    async fn exchange<S: AsyncReadExt + AsyncWriteExt + Unpin>(
        stream: &mut S,
        request: &[u8],
    ) -> n0_error::Result<u16> {
        stream.write_all(request).await.anyerr()?;
        read_answer(stream).await
    }

    /// The status of the next answer on a connection that is kept, read whole.
    async fn read_answer<S: AsyncReadExt + Unpin>(stream: &mut S) -> n0_error::Result<u16> {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            let n = tokio::time::timeout(CLOSE_DEADLINE, stream.read(&mut byte))
                .await
                .std_context("no answer from server")?
                .anyerr()?;
            n0_error::ensure_any!(n > 0, "the connection ended before the answer");
            head.push(byte[0]);
        }
        let head = String::from_utf8_lossy(&head).to_ascii_lowercase();
        let length = head
            .lines()
            .find_map(|line| line.strip_prefix("content-length: "))
            .map_or(Ok(0), str::parse)
            .anyerr()?;
        stream.read_exact(&mut vec![0; length]).await.anyerr()?;
        head[9..12].parse().anyerr()
    }

    /// The bound on what a connection reads between two request starts leaves honest requests of
    /// the largest sizes alone, over HTTP/1: heads of the largest size one after another, a
    /// publication of the largest size and a query of the largest size, on one connection.
    #[tokio::test]
    #[traced_test]
    async fn test_http1_largest_requests_are_answered_on_one_connection() -> n0_error::Result {
        let dir = tempfile::tempdir()?;
        let server = Server::spawn_for_tests(dir.path()).await?;
        let mut stream = TcpStream::connect(server.http_addr().expect("http is bound"))
            .await
            .anyerr()?;

        let most = super::HTTP1_MAX_BUFFER_SIZE;
        let head = |len: usize| {
            let start = "GET /healthcheck HTTP/1.1\r\nhost: localhost\r\nx-fill: ";
            let end = "\r\n\r\n";
            let fill = "a".repeat(len - start.len() - end.len());
            format!("{start}{fill}{end}").into_bytes()
        };
        let largest = super::DOH_MESSAGE_LIMIT;
        let query = dns_query(largest);
        let mut post = format!(
            "POST /dns-query HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/dns-message\r\ncontent-length: {largest}\r\n\r\n"
        )
        .into_bytes();
        post.extend(&query);
        let publication = super::PKARR_PUT_BODY_LIMIT;
        let requests = [
            (head(most), 200),
            (head(most), 200),
            (head(most), 200),
            (put_request(publication, publication), 400),
            (dns_get_request(&query, Some(most)), 200),
            (post, 200),
            (head(most), 200),
        ];
        for (request, status) in requests {
            assert_eq!(exchange(&mut stream, &request).await?, status);
        }

        server.shutdown().await?;
        Ok(())
    }

    /// A DNS query by GET is taken up to the size of the largest message that POST takes, over HTTP/1
    /// and over HTTP/2, and refused with the status that POST gives past it.
    #[tokio::test]
    #[traced_test]
    async fn test_doh_get_takes_what_post_takes() -> n0_error::Result {
        let dir = tempfile::tempdir()?;
        let server = Server::spawn_for_tests(dir.path()).await?;
        let addr = server.http_addr().expect("http is bound");

        let largest = super::DOH_MESSAGE_LIMIT;
        for (len, status) in [(largest, 200), (largest + 1, 413)] {
            let query = dns_query(len);
            assert_eq!(
                status_of(addr, &dns_get_request(&query, None)).await?,
                status,
                "a query of {len} bytes by GET over HTTP/1"
            );
            let (path, extra) = dns_get_over_h2(&query, None);
            assert_eq!(
                status_over_h2(addr, "GET", &path, &extra).await?,
                status,
                "a query of {len} bytes by GET over HTTP/2"
            );
        }

        server.shutdown().await?;
        Ok(())
    }

    /// The connection's window for request bodies is the protocol's own 65,535 bytes: the server
    /// does not raise it, as hyper does by default.
    #[tokio::test]
    #[traced_test]
    async fn test_http2_connection_window_is_not_raised() -> n0_error::Result {
        let dir = tempfile::tempdir()?;
        let server = Server::spawn_for_tests(dir.path()).await?;
        let mut peer = raw_h2::Peer::connect(server.http_addr().expect("http is bound")).await?;

        while let Some(frame) = peer.frame_within(Duration::from_millis(200)).await? {
            assert!(
                !(frame.kind == raw_h2::WINDOW_UPDATE && frame.stream == 0),
                "the server raised the connection's window"
            );
        }

        server.shutdown().await?;
        Ok(())
    }

    /// A peer that announces a header table of 1 MiB does not get a table of that size for the
    /// answers: the library caps what the encoder takes at 4 KiB, which is its starting size, so
    /// the first answer carries no size update above it.
    #[tokio::test]
    #[traced_test]
    async fn test_http2_answers_keep_the_header_table_at_4_kib() -> n0_error::Result {
        let dir = tempfile::tempdir()?;
        let server = Server::spawn_for_tests(dir.path()).await?;
        let mut peer = raw_h2::Peer::connect_announcing_table_size(
            server.http_addr().expect("http is bound"),
            1 << 20,
        )
        .await?;

        let stream = peer.request("GET", "/healthcheck", &[], true).await?;
        loop {
            let frame = peer.next_frame().await?;
            if frame.kind == raw_h2::HEADERS && frame.stream == stream {
                let update = frame.table_size_update();
                assert!(
                    update.is_none_or(|size| size <= 4096),
                    "the answer's table size update is {update:?}"
                );
                break;
            }
        }

        server.shutdown().await?;
        Ok(())
    }

    /// A client that keeps one connection and sends small requests one after another is answered
    /// until the request in whose bytes the connection's budget is passed, answer included, and
    /// the next request meets a closed connection; a new connection answers it. Over HTTP/1 the
    /// figure is exact: every request has the same length.
    #[tokio::test]
    #[traced_test]
    async fn test_http1_connection_is_answered_up_to_its_lifetime_budget() -> n0_error::Result {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let dir = tempfile::tempdir()?;
        let server = Server::spawn_for_tests(dir.path()).await?;
        let addr = server.http_addr().expect("http is bound");
        let request = b"GET /healthcheck HTTP/1.1\r\nhost: localhost\r\n\r\n";

        // Whether the server answers `request` on `stream` with all of a `200` and its body.
        async fn answered(stream: &mut tokio::net::TcpStream, request: &[u8]) -> bool {
            if stream.write_all(request).await.is_err() {
                return false;
            }
            let mut answer = Vec::new();
            let mut buf = [0u8; 256];
            while !answer.ends_with(b"\r\n\r\nOK") {
                match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
                    Ok(Ok(n)) if n > 0 => answer.extend_from_slice(&buf[..n]),
                    _ => return false,
                }
            }
            answer.starts_with(b"HTTP/1.1 200")
        }

        let mut stream = tokio::net::TcpStream::connect(addr).await?;
        let mut count = 0;
        while answered(&mut stream, request).await {
            count += 1;
            assert!(count < 10_000, "the connection was never closed");
        }
        assert_eq!(
            count,
            super::idle::LIFETIME_READ_BOUND / request.len() + 1,
            "requests answered on one connection"
        );
        let mut stream = tokio::net::TcpStream::connect(addr).await?;
        assert!(answered(&mut stream, request).await, "a new connection");

        server.shutdown().await?;
        Ok(())
    }

    type Ran = Arc<std::sync::Mutex<Vec<(String, SocketAddr)>>>;

    /// The server's own listener, bounded as the server's are, with routes that record the
    /// requests that run and the peer that sent each: `GET /n/{id}`, `GET /big/{id}` with an
    /// answer of 3,000 bytes, `POST /hold`, which runs once its body is whole, and `GET
    /// /wait/{id}`, whose handler runs on only when the case releases it.
    struct Recording {
        addr: SocketAddr,
        ran: Ran,
        /// One permit for each handler of `/wait/{id}` that has started.
        started: Arc<tokio::sync::Semaphore>,
        /// A handler of `/wait/{id}` goes on when it takes a permit.
        release: Arc<tokio::sync::Semaphore>,
        metrics: Arc<crate::metrics::Metrics>,
        task: tokio::task::JoinHandle<std::io::Result<()>>,
        _dir: Option<tempfile::TempDir>,
    }

    impl Recording {
        fn start() -> n0_error::Result<Self> {
            let metrics: Arc<crate::metrics::Metrics> = Arc::default();
            let (app, ran, started, release) = Self::routes();
            let (listener, addr) = Self::listener()?;
            let server = super::bounded_server(
                listener,
                axum_server::accept::DefaultAcceptor::new(),
                super::idle::Connections::new(64, metrics.clone()),
            )?;
            let task =
                tokio::spawn(server.serve(app.into_make_service_with_connect_info::<SocketAddr>()));
            Ok(Self {
                addr,
                ran,
                started,
                release,
                metrics,
                task,
                _dir: None,
            })
        }

        /// The same listener with TLS and a certificate of its own.
        async fn start_tls() -> n0_error::Result<Self> {
            let dir = tempfile::tempdir()?;
            let acceptor = crate::http::CertMode::SelfSigned
                .build(
                    vec!["localhost".to_string()],
                    dir.path().to_owned(),
                    None,
                    false,
                )
                .await?;
            let metrics: Arc<crate::metrics::Metrics> = Arc::default();
            let (app, ran, started, release) = Self::routes();
            let (listener, addr) = Self::listener()?;
            let server = super::bounded_server(
                listener,
                acceptor,
                super::idle::Connections::new(64, metrics.clone()),
            )?;
            let task =
                tokio::spawn(server.serve(app.into_make_service_with_connect_info::<SocketAddr>()));
            Ok(Self {
                addr,
                ran,
                started,
                release,
                metrics,
                task,
                _dir: Some(dir),
            })
        }

        fn listener() -> n0_error::Result<(std::net::TcpListener, SocketAddr)> {
            let listener = super::bind_listener(
                SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
                super::DEFAULT_LISTEN_BACKLOG,
            )
            .anyerr()?;
            let addr = listener.local_addr().anyerr()?;
            Ok((listener, addr))
        }

        fn routes() -> (
            axum::Router,
            Ran,
            Arc<tokio::sync::Semaphore>,
            Arc<tokio::sync::Semaphore>,
        ) {
            use axum::{
                Router,
                body::Bytes,
                extract::{ConnectInfo, Path},
                routing::{get, post},
            };

            let ran: Ran = Arc::default();
            let started = Arc::new(tokio::sync::Semaphore::new(0));
            let release = Arc::new(tokio::sync::Semaphore::new(0));
            let recorder = ran.clone();
            let numbered = get(
                move |ConnectInfo(peer): ConnectInfo<SocketAddr>, Path(id): Path<String>| async move {
                    recorder.lock().unwrap().push((id, peer));
                    "OK"
                },
            );
            let recorder = ran.clone();
            let big = get(
                move |ConnectInfo(peer): ConnectInfo<SocketAddr>, Path(id): Path<String>| async move {
                    recorder.lock().unwrap().push((id, peer));
                    "x".repeat(BIG_ANSWER)
                },
            );
            let recorder = ran.clone();
            let held = post(
                move |ConnectInfo(peer): ConnectInfo<SocketAddr>, _body: Bytes| async move {
                    recorder.lock().unwrap().push(("hold".to_string(), peer));
                    "OK"
                },
            );
            let recorder = ran.clone();
            let (signal, gate) = (started.clone(), release.clone());
            let waiting = get(
                move |ConnectInfo(peer): ConnectInfo<SocketAddr>, Path(id): Path<String>| async move {
                    recorder.lock().unwrap().push((id, peer));
                    signal.add_permits(1);
                    if let Ok(permit) = gate.acquire().await {
                        permit.forget();
                    }
                    "OK"
                },
            );
            let app = Router::new()
                .route("/n/{id}", numbered)
                .route("/big/{id}", big)
                .route("/hold", held)
                .route("/wait/{id}", waiting);
            (app, ran, started, release)
        }

        fn ran(&self) -> Vec<(String, SocketAddr)> {
            self.ran.lock().unwrap().clone()
        }

        /// Waits until one more handler of `/wait/{id}` has started.
        async fn handler_started(&self) -> n0_error::Result {
            let permit = tokio::time::timeout(CLOSE_DEADLINE, self.started.acquire())
                .await
                .std_context("no handler started")?
                .anyerr()?;
            permit.forget();
            Ok(())
        }

        /// Lets `count` handlers of `/wait/{id}` go on.
        fn release(&self, count: usize) {
            self.release.add_permits(count);
        }

        /// How many connections the drain time has cut.
        fn drain_timeouts(&self) -> u64 {
            self.metrics.http_connections_drain_timeouts.get()
        }
    }

    impl Drop for Recording {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    /// The length of the body of `GET /big/{id}`.
    const BIG_ANSWER: usize = 3_000;

    /// The highest stream id that a first `GOAWAY` names: no stream is excluded by it.
    const NO_LIMIT: u32 = 0x7fff_ffff;

    /// How many bytes the peer can still send before the one that passes the lifetime figure.
    fn left_to_the_figure(peer: &raw_h2::Peer) -> usize {
        (super::idle::LIFETIME_READ_BOUND + 1).saturating_sub(peer.sent())
    }

    /// A raw HTTP/2 connection to `addr` that has sent requests until it is at most 6,000 bytes
    /// short of the lifetime figure.
    async fn h2_peer_near_the_figure(addr: SocketAddr) -> n0_error::Result<raw_h2::Peer> {
        let mut peer = raw_h2::Peer::connect(addr).await?;
        let extra = [("x-pad", "a".repeat(3_000))];
        while left_to_the_figure(&peer) > 6_000 {
            let stream = peer.request("GET", "/n/p", &extra, true).await?;
            h2_answer(&mut peer, stream).await?;
        }
        Ok(peer)
    }

    /// A request on a new stream whose head passes the lifetime figure.
    async fn h2_request_that_passes_the_figure(
        peer: &mut raw_h2::Peer,
        path: &str,
    ) -> n0_error::Result<u32> {
        let extra = [("x-pad", "a".repeat(left_to_the_figure(peer) + 50))];
        peer.request("GET", path, &extra, true).await
    }

    /// Bytes that start no request and pass the lifetime figure.
    async fn h2_pass_the_figure_with_no_request(peer: &mut raw_h2::Peer) -> n0_error::Result {
        let padding = vec![0; left_to_the_figure(peer) + 10];
        peer.send(raw_h2::UNDEFINED, 0, 0, &padding).await
    }

    /// The frames of the answer on `stream`, up to the one that ends it. A reset is an error.
    async fn h2_answer(
        peer: &mut raw_h2::Peer,
        stream: u32,
    ) -> n0_error::Result<Vec<raw_h2::Frame>> {
        let mut frames = Vec::new();
        loop {
            let frame = peer.next_frame().await?;
            if frame.stream != stream {
                continue;
            }
            if frame.kind == raw_h2::RST_STREAM {
                n0_error::bail_any!("stream {stream} was reset with {:?}", frame.reset_code());
            }
            let ends = frame.flags & raw_h2::END_STREAM != 0;
            frames.push(frame);
            if ends {
                return Ok(frames);
            }
        }
    }

    /// The frames from the server until one satisfies `done`: those read, that one last. An error
    /// if the connection ends or nothing comes for a while first.
    async fn frames_until(
        peer: &mut raw_h2::Peer,
        done: impl Fn(&raw_h2::Frame) -> bool,
    ) -> n0_error::Result<Vec<raw_h2::Frame>> {
        let mut frames = Vec::new();
        loop {
            let frame = peer.next_frame().await?;
            let found = done(&frame);
            frames.push(frame);
            if found {
                return Ok(frames);
            }
        }
    }

    /// The `PING` that the server sends to start its shutdown, and not an acknowledgement.
    fn is_ping(frame: &raw_h2::Frame) -> bool {
        frame.kind == raw_h2::PING && frame.flags & raw_h2::ACK == 0
    }

    /// The first `GOAWAY` of a graceful shutdown, which excludes no stream.
    fn is_first_goaway(frame: &raw_h2::Frame) -> bool {
        frame.kind == raw_h2::GOAWAY && frame.last_stream() == Some(NO_LIMIT)
    }

    /// The `GOAWAY` that names the last stream the server takes.
    fn is_cutoff(frame: &raw_h2::Frame) -> bool {
        frame.kind == raw_h2::GOAWAY && frame.last_stream().is_some_and(|id| id != NO_LIMIT)
    }

    /// The frames to the end of the connection, whose shutdown `PING` is acknowledged when it
    /// comes. An error if the connection stands on.
    async fn frames_to_the_end(peer: &mut raw_h2::Peer) -> n0_error::Result<Vec<raw_h2::Frame>> {
        let mut frames = Vec::new();
        loop {
            match peer.frame_within(CLOSE_DEADLINE).await {
                Ok(Some(frame)) => {
                    if is_ping(&frame) {
                        let _ = peer.ack_ping(&frame).await;
                    }
                    frames.push(frame);
                }
                Ok(None) => n0_error::bail_any!("the connection stood on after {frames:?}"),
                Err(_) => return Ok(frames),
            }
        }
    }

    /// The status and the body length of the answer to `stream` in `frames`, if the answer is
    /// whole: the last frame of the stream ends it, and no frame of it is a reset.
    fn whole_answer(frames: &[raw_h2::Frame], stream: u32) -> Option<(u16, usize)> {
        let of: Vec<_> = frames
            .iter()
            .filter(|frame| frame.stream == stream)
            .collect();
        if of.iter().any(|frame| frame.kind == raw_h2::RST_STREAM) {
            return None;
        }
        let status = of.iter().find_map(|frame| frame.status())?;
        let ends = of.last()?.flags & raw_h2::END_STREAM != 0;
        let body = of
            .iter()
            .filter(|frame| frame.kind == raw_h2::DATA)
            .map(|frame| frame.payload.len())
            .sum();
        ends.then_some((status, body))
    }

    /// The answer to one request on a raw HTTP/1 connection, up to its body `OK`.
    async fn h1_answer(stream: &mut TcpStream) -> n0_error::Result<String> {
        let mut answer = Vec::new();
        let mut buf = [0u8; 512];
        while !answer.ends_with(b"\r\n\r\nOK") {
            let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
                .await
                .std_context("no answer")?
                .anyerr()?;
            if n == 0 {
                n0_error::bail_any!("the connection ended with {answer:?}");
            }
            answer.extend_from_slice(&buf[..n]);
        }
        Ok(String::from_utf8_lossy(&answer).into_owned())
    }

    /// Whether an answer says that its connection closes after it.
    fn says_close(answer: &str) -> bool {
        answer.to_ascii_lowercase().contains("connection: close")
    }

    /// Whether the server has ended the connection: a read gives the end or an error within a
    /// short stretch of real time.
    async fn h1_ended(stream: &mut TcpStream) -> bool {
        let mut buf = [0u8; 64];
        matches!(
            tokio::time::timeout(CLOSE_DEADLINE, stream.read(&mut buf)).await,
            Ok(Ok(0) | Err(_))
        )
    }

    /// A raw HTTP/1 connection on which small requests have been sent and answered until at most
    /// 6,000 bytes are short of the lifetime figure, and the number of bytes that are left to the
    /// byte that passes it.
    async fn h1_near_the_figure(addr: SocketAddr) -> n0_error::Result<(TcpStream, usize)> {
        let mut stream = TcpStream::connect(addr).await.anyerr()?;
        let request = format!(
            "GET /n/p HTTP/1.1\r\nhost: localhost\r\nx-pad: {}\r\n\r\n",
            "a".repeat(3_000)
        );
        let mut sent = 0;
        while super::idle::LIFETIME_READ_BOUND + 1 - sent > 6_000 {
            stream.write_all(request.as_bytes()).await.anyerr()?;
            let answer = h1_answer(&mut stream).await?;
            assert!(
                !says_close(&answer),
                "an answer under the figure says that the connection closes"
            );
            sent += request.len();
        }
        Ok((stream, super::idle::LIFETIME_READ_BOUND + 1 - sent))
    }

    /// C1. An answer whose handler has returned and that the peer's window blocks is delivered
    /// whole after the figure is passed by a request that starts later: every `DATA` frame and
    /// its end arrive, then the connection ends.
    #[tokio::test]
    #[traced_test]
    async fn test_http2_answer_blocked_by_the_window_is_delivered_whole_in_the_drain()
    -> n0_error::Result {
        let server = Recording::start()?;
        let mut peer = h2_peer_near_the_figure(server.addr).await?;
        peer.set_initial_window(0).await?;
        let a = peer.request("GET", "/big/a", &[], true).await?;
        let mut seen = frames_until(&mut peer, |frame| {
            frame.stream == a && frame.status().is_some()
        })
        .await?;
        let b = h2_request_that_passes_the_figure(&mut peer, "/n/b").await?;
        seen.extend(frames_until(&mut peer, is_first_goaway).await?);
        let ping = frames_until(&mut peer, is_ping).await?;
        peer.ack_ping(ping.last().expect("a ping")).await?;
        seen.extend(ping);
        peer.window_update(a, 65_535).await?;
        peer.window_update(b, 65_535).await?;
        seen.extend(frames_to_the_end(&mut peer).await?);
        assert_eq!(whole_answer(&seen, a), Some((200, BIG_ANSWER)));
        assert_eq!(whole_answer(&seen, b), Some((200, 2)));
        Ok(())
    }

    /// C2. The figure falls inside the header block of a request while another is held: the first
    /// `GOAWAY` comes before the block is finished, the block is finished before the peer
    /// acknowledges the `PING` (a compliant peer cannot do otherwise), and both requests are
    /// answered whole, the final stream id being the second request's or later.
    #[tokio::test]
    #[traced_test]
    async fn test_http2_head_in_transit_when_the_figure_is_passed_is_answered() -> n0_error::Result
    {
        let server = Recording::start()?;
        let mut peer = h2_peer_near_the_figure(server.addr).await?;
        let a = peer.request("GET", "/wait/a", &[], true).await?;
        server.handler_started().await?;
        let left = left_to_the_figure(&peer);
        let extra = [("x-pad", "a".repeat(left + 50))];
        let (b, rest) = peer
            .request_in_parts("GET", "/n/b", &extra, left + 20)
            .await?;
        let mut seen = frames_until(&mut peer, is_first_goaway).await?;
        let goaway = seen.last().expect("a goaway");
        assert_eq!(goaway.goaway_code(), Some(raw_h2::NO_ERROR));
        let ping = frames_until(&mut peer, is_ping).await?;
        peer.finish_block(b, &rest).await?;
        peer.ack_ping(ping.last().expect("a ping")).await?;
        seen.extend(ping);
        server.release(1);
        seen.extend(frames_to_the_end(&mut peer).await?);
        assert_eq!(whole_answer(&seen, a), Some((200, 2)));
        assert_eq!(whole_answer(&seen, b), Some((200, 2)));
        let cutoff = seen
            .iter()
            .rfind(|frame| is_cutoff(frame))
            .expect("a cutoff");
        assert!(cutoff.last_stream() >= Some(b), "{cutoff:?}");
        Ok(())
    }

    /// C3. The shutdown's frames come in order: a `GOAWAY` that excludes no stream, a `PING`, and
    /// after its acknowledgement a `GOAWAY` that names the last stream, the connection ending
    /// after the answer is whole, with no reset. The request that passes the figure is the last
    /// one named.
    #[tokio::test]
    #[traced_test]
    async fn test_http2_shutdown_frames_come_in_order_and_no_stream_is_reset() -> n0_error::Result {
        let server = Recording::start()?;
        let mut peer = h2_peer_near_the_figure(server.addr).await?;
        assert!(peer.sent() <= super::idle::LIFETIME_READ_BOUND);
        let last = h2_request_that_passes_the_figure(&mut peer, "/n/last").await?;
        assert!(peer.sent() > super::idle::LIFETIME_READ_BOUND);
        let frames = frames_to_the_end(&mut peer).await?;
        let control: Vec<_> = frames
            .iter()
            .filter(|frame| frame.kind == raw_h2::GOAWAY || is_ping(frame))
            .collect();
        assert_eq!(control.len(), 3, "{control:?}");
        assert!(is_first_goaway(control[0]), "{control:?}");
        assert_eq!(control[0].goaway_code(), Some(raw_h2::NO_ERROR));
        assert!(
            is_ping(control[1]) && control[1].payload.len() == 8,
            "{control:?}"
        );
        assert!(is_cutoff(control[2]), "{control:?}");
        assert_eq!(control[2].last_stream(), Some(last));
        assert_eq!(control[2].goaway_code(), Some(raw_h2::NO_ERROR));
        assert!(
            frames.iter().all(|frame| frame.kind != raw_h2::RST_STREAM),
            "{frames:?}"
        );
        assert_eq!(whole_answer(&frames, last), Some((200, 2)));
        Ok(())
    }

    /// C3, the deliberate case. A peer that has acknowledged the server's `PING` and read nothing
    /// since, while the server finishes and closes, still reads the answer's last data with its
    /// end and the last `GOAWAY` before any reset. The case writes probes until a write fails, which is
    /// when the server's close has come back to it as a reset. It asserts that the failure is a
    /// reset and that the bytes the server sent are at that moment still unread in the peer's
    /// socket, which it counts without reading them, before it reads them.
    #[tokio::test]
    #[traced_test]
    async fn test_http2_peer_with_unread_input_at_the_close_reads_the_whole_answer()
    -> n0_error::Result {
        let server = Recording::start()?;
        let mut peer = h2_peer_near_the_figure(server.addr).await?;
        let last = h2_request_that_passes_the_figure(&mut peer, "/big/last").await?;
        let mut seen = frames_until(&mut peer, is_ping).await?;
        peer.ack_ping(seen.last().expect("a ping")).await?;
        peer.window_update(0, 1).await?;
        peer.window_update(last, 1).await?;
        let mut probes = 0;
        let failure = loop {
            match peer.probe().await {
                Ok(()) => {
                    probes += 1;
                    assert!(probes < 1_000, "the server did not close the connection");
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Err(error) => break error,
            }
        };
        assert!(
            matches!(
                failure.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
            ),
            "the write failed for another reason: {failure:?}"
        );
        // At the least the last `GOAWAY`, 17 bytes, stands unread.
        let unread = peer.unread().await.anyerr()?;
        assert!(
            unread >= 17,
            "the server's last frames were not unread in the peer's socket at the reset: {unread}"
        );
        while let Ok(Some(frame)) = peer.frame_within(CLOSE_DEADLINE).await {
            seen.push(frame);
        }
        assert_eq!(
            whole_answer(&seen, last),
            Some((200, BIG_ANSWER)),
            "{seen:?}"
        );
        assert!(seen.iter().any(is_cutoff), "{seen:?}");
        Ok(())
    }

    /// C4. A stream that opens after the second `GOAWAY` runs no handler and gets no frame, while
    /// an accepted request keeps the connection open.
    #[tokio::test]
    #[traced_test]
    async fn test_http2_stream_after_the_cutoff_runs_no_handler_and_gets_no_frame()
    -> n0_error::Result {
        let server = Recording::start()?;
        let mut peer = h2_peer_near_the_figure(server.addr).await?;
        let a = peer.request("GET", "/wait/a", &[], true).await?;
        server.handler_started().await?;
        let b = h2_request_that_passes_the_figure(&mut peer, "/n/b").await?;
        let mut seen = frames_until(&mut peer, is_first_goaway).await?;
        let ping = frames_until(&mut peer, is_ping).await?;
        peer.ack_ping(ping.last().expect("a ping")).await?;
        seen.extend(ping);
        seen.extend(frames_until(&mut peer, is_cutoff).await?);
        let c = peer.request("GET", "/n/c", &[], true).await?;
        while let Some(frame) = peer.frame_within(Duration::from_millis(300)).await? {
            assert_ne!(
                frame.stream, c,
                "a frame on the stream after the cutoff: {frame:?}"
            );
            seen.push(frame);
        }
        assert!(
            server.ran().iter().all(|(id, _)| id != "c"),
            "{:?}",
            server.ran()
        );
        server.release(1);
        seen.extend(frames_to_the_end(&mut peer).await?);
        assert_eq!(whole_answer(&seen, a), Some((200, 2)));
        assert_eq!(whole_answer(&seen, b), Some((200, 2)));
        assert!(seen.iter().all(|frame| frame.stream != c), "{seen:?}");
        Ok(())
    }

    /// C5. Two streams in progress when the figure is passed are both answered whole.
    #[tokio::test]
    #[traced_test]
    async fn test_http2_two_streams_in_progress_at_the_figure_are_both_answered() -> n0_error::Result
    {
        let server = Recording::start()?;
        let mut peer = h2_peer_near_the_figure(server.addr).await?;
        let a = peer.request("GET", "/wait/a", &[], true).await?;
        let b = peer.request("GET", "/wait/b", &[], true).await?;
        server.handler_started().await?;
        server.handler_started().await?;
        h2_pass_the_figure_with_no_request(&mut peer).await?;
        let mut seen = frames_until(&mut peer, is_first_goaway).await?;
        server.release(2);
        seen.extend(frames_to_the_end(&mut peer).await?);
        assert_eq!(whole_answer(&seen, a), Some((200, 2)));
        assert_eq!(whole_answer(&seen, b), Some((200, 2)));
        Ok(())
    }

    /// C6. A connection that has passed the figure with no request in progress begins its
    /// shutdown when the next request starts, from the task of that request: the first `GOAWAY`
    /// comes while the handler is held, with nothing more from the peer.
    #[tokio::test]
    #[traced_test]
    async fn test_http2_request_after_the_figure_starts_the_shutdown_while_it_is_held()
    -> n0_error::Result {
        let server = Recording::start()?;
        let mut peer = h2_peer_near_the_figure(server.addr).await?;
        h2_pass_the_figure_with_no_request(&mut peer).await?;
        let a = peer.request("GET", "/wait/a", &[], true).await?;
        server.handler_started().await?;
        let mut seen = frames_until(&mut peer, is_first_goaway).await?;
        server.release(1);
        seen.extend(frames_to_the_end(&mut peer).await?);
        assert_eq!(whole_answer(&seen, a), Some((200, 2)));
        Ok(())
    }

    /// C13. The peer withholds its window: the answer to an accepted request cannot go out, and
    /// the connection ends 20 seconds after the call of the shutdown, not before, and the counter
    /// counts one. The `PING` is acknowledged, so that the window is the only cause.
    #[tokio::test]
    #[traced_test]
    async fn test_http2_answer_that_the_window_blocks_ends_with_the_drain_time() -> n0_error::Result
    {
        let server = Recording::start()?;
        let mut peer = h2_peer_near_the_figure(server.addr).await?;
        peer.set_initial_window(0).await?;
        let a = peer.request("GET", "/big/a", &[], true).await?;
        frames_until(&mut peer, |frame| {
            frame.stream == a && frame.status().is_some()
        })
        .await?;
        h2_request_that_passes_the_figure(&mut peer, "/n/b").await?;
        frames_until(&mut peer, is_first_goaway).await?;
        let ping = frames_until(&mut peer, is_ping).await?;
        peer.ack_ping(ping.last().expect("a ping")).await?;
        advance(super::idle::DRAIN_TIMEOUT - Duration::from_secs(1)).await;
        while peer
            .frame_within(Duration::from_millis(50))
            .await?
            .is_some()
        {}
        assert_eq!(server.drain_timeouts(), 0);
        advance(Duration::from_secs(2)).await;
        assert!(
            peer.ended_within(CLOSE_DEADLINE).await,
            "the connection stood on"
        );
        assert_eq!(server.drain_timeouts(), 1);
        Ok(())
    }

    /// C13, the late request. A request that reaches the service 15 seconds after the call, before
    /// the shutdown is acknowledged, is accepted, and the drain time cuts it at 20 seconds
    /// whatever its own deadline: the counter counts one and no answer arrives.
    #[tokio::test]
    #[traced_test]
    async fn test_http2_request_accepted_late_in_the_drain_is_cut_at_the_drain_time()
    -> n0_error::Result {
        let server = Recording::start()?;
        let mut peer = h2_peer_near_the_figure(server.addr).await?;
        let a = peer.request("GET", "/wait/a", &[], true).await?;
        server.handler_started().await?;
        h2_request_that_passes_the_figure(&mut peer, "/n/b").await?;
        frames_until(&mut peer, is_first_goaway).await?;
        advance(Duration::from_secs(15)).await;
        let late = peer.request("GET", "/wait/late", &[], true).await?;
        server.handler_started().await?;
        advance(Duration::from_secs(6)).await;
        let mut seen = Vec::new();
        loop {
            match peer.frame_within(CLOSE_DEADLINE).await {
                Ok(Some(frame)) => seen.push(frame),
                Ok(None) => n0_error::bail_any!("the connection stood on after {seen:?}"),
                Err(_) => break,
            }
        }
        assert!(seen.iter().all(|frame| frame.stream != late), "{seen:?}");
        assert_eq!(server.drain_timeouts(), 1);
        assert!(server.ran().iter().any(|(id, _)| id == "late"));
        let _ = a;
        Ok(())
    }

    /// C13, the `PING` that is never acknowledged. The going-away id stays at the highest stream,
    /// so the connection does not close when its answers are out; the drain time ends it.
    #[tokio::test]
    #[traced_test]
    async fn test_http2_ping_that_is_never_acknowledged_ends_with_the_drain_time()
    -> n0_error::Result {
        let server = Recording::start()?;
        let mut peer = h2_peer_near_the_figure(server.addr).await?;
        let a = peer.request("GET", "/wait/a", &[], true).await?;
        server.handler_started().await?;
        let b = h2_request_that_passes_the_figure(&mut peer, "/n/b").await?;
        let mut seen = frames_until(&mut peer, is_first_goaway).await?;
        seen.extend(frames_until(&mut peer, is_ping).await?);
        server.release(1);
        seen.extend(
            frames_until(&mut peer, |frame| {
                frame.stream == a && frame.flags & raw_h2::END_STREAM != 0
            })
            .await?,
        );
        advance(super::idle::DRAIN_TIMEOUT - Duration::from_secs(1)).await;
        while peer
            .frame_within(Duration::from_millis(50))
            .await?
            .is_some()
        {}
        assert_eq!(server.drain_timeouts(), 0);
        advance(Duration::from_secs(2)).await;
        assert!(
            peer.ended_within(CLOSE_DEADLINE).await,
            "the connection stood on"
        );
        assert_eq!(server.drain_timeouts(), 1);
        let _ = b;
        Ok(())
    }

    /// C14. A request head that stays in transit more than 20 seconds after the call, beside a
    /// request in progress, ends with the drain time: the connection has ended at 20 seconds, and
    /// the counter counts one.
    #[tokio::test]
    #[traced_test]
    async fn test_http2_head_that_stays_in_transit_ends_with_the_drain_time() -> n0_error::Result {
        let server = Recording::start()?;
        let mut peer = h2_peer_near_the_figure(server.addr).await?;
        peer.request("GET", "/wait/a", &[], true).await?;
        server.handler_started().await?;
        let left = left_to_the_figure(&peer);
        let extra = [("x-pad", "a".repeat(left + 50))];
        peer.request_in_parts("GET", "/n/b", &extra, left + 20)
            .await?;
        frames_until(&mut peer, is_first_goaway).await?;
        advance(super::idle::DRAIN_TIMEOUT - Duration::from_secs(1)).await;
        while peer
            .frame_within(Duration::from_millis(50))
            .await?
            .is_some()
        {}
        assert_eq!(server.drain_timeouts(), 0);
        advance(Duration::from_secs(2)).await;
        assert!(
            peer.ended_within(CLOSE_DEADLINE).await,
            "the connection stood on"
        );
        assert_eq!(server.drain_timeouts(), 1);
        Ok(())
    }

    /// C15, on the wire. Bytes that the peer sends after the first `GOAWAY` count toward the
    /// stop, whatever they carry: a peer that goes on sending ends the connection at the hard
    /// stop, which is not a cut by the drain time and is not counted.
    #[tokio::test]
    #[traced_test]
    async fn test_http2_bytes_after_the_first_goaway_end_the_connection_at_the_stop()
    -> n0_error::Result {
        let server = Recording::start()?;
        let mut peer = h2_peer_near_the_figure(server.addr).await?;
        peer.request("GET", "/wait/a", &[], true).await?;
        server.handler_started().await?;
        h2_request_that_passes_the_figure(&mut peer, "/n/b").await?;
        frames_until(&mut peer, is_first_goaway).await?;
        let ping = frames_until(&mut peer, is_ping).await?;
        peer.ack_ping(ping.last().expect("a ping")).await?;
        let mut frames = 0;
        while frames < 3_000 && peer.window_update(0, 1).await.is_ok() {
            frames += 1;
        }
        assert!(peer.sent() > super::idle::HARD_READ_BOUND);
        assert!(
            peer.ended_within(CLOSE_DEADLINE).await,
            "the connection stood on"
        );
        assert_eq!(server.drain_timeouts(), 0);
        Ok(())
    }

    /// C11. A request in progress when the figure is passed is answered whole with
    /// `Connection: close`, and the connection ends; a request pipelined behind it is not answered
    /// and its handler does not run. A request that starts and ends in one poll, after the figure,
    /// says close too.
    #[tokio::test]
    #[traced_test]
    async fn test_http1_request_in_progress_at_the_figure_is_answered_with_close()
    -> n0_error::Result {
        let server = Recording::start()?;

        let (mut stream, left) = h1_near_the_figure(server.addr).await?;
        let head = format!(
            "GET /n/trivial HTTP/1.1\r\nhost: localhost\r\nx-pad: {}\r\n\r\n",
            "a".repeat(left + 50)
        );
        stream.write_all(head.as_bytes()).await.anyerr()?;
        let answer = h1_answer(&mut stream).await?;
        assert!(says_close(&answer), "{answer}");
        assert!(h1_ended(&mut stream).await, "the connection stood on");

        let (mut stream, left) = h1_near_the_figure(server.addr).await?;
        let head = format!(
            "POST /hold HTTP/1.1\r\nhost: localhost\r\ncontent-length: 4\r\nx-pad: {}\r\n\r\n",
            "a".repeat(left + 50)
        );
        stream.write_all(head.as_bytes()).await.anyerr()?;
        // The declared body, and behind it a whole second request.
        stream
            .write_all(b"abcdGET /n/second HTTP/1.1\r\nhost: localhost\r\n\r\n")
            .await
            .anyerr()?;
        let answer = h1_answer(&mut stream).await?;
        assert!(says_close(&answer), "{answer}");
        assert!(h1_ended(&mut stream).await, "the connection stood on");
        let ran = server.ran();
        assert_eq!(ran.iter().filter(|(id, _)| id == "hold").count(), 1);
        assert!(ran.iter().all(|(id, _)| id != "second"), "{ran:?}");
        Ok(())
    }

    /// C12. A head whose first part passes the figure on an idle connection and whose rest comes
    /// 20 seconds later is answered, with `Connection: close`, and not cut: the shutdown begins
    /// when the request starts, not when the figure is passed.
    #[tokio::test]
    #[traced_test]
    async fn test_http1_head_in_transit_when_the_figure_is_passed_is_answered() -> n0_error::Result
    {
        let server = Recording::start()?;
        let (mut stream, left) = h1_near_the_figure(server.addr).await?;
        let head = format!(
            "GET /n/slow HTTP/1.1\r\nhost: localhost\r\nx-pad: {}",
            "a".repeat(left + 50)
        );
        stream.write_all(head.as_bytes()).await.anyerr()?;
        // The server reads the first part, which passes the figure, before the clock moves.
        let mut buf = [0u8; 64];
        assert!(
            tokio::time::timeout(Duration::from_millis(50), stream.read(&mut buf))
                .await
                .is_err(),
            "the server answered a head that is not whole"
        );
        advance(Duration::from_secs(20)).await;
        stream.write_all(b"\r\n\r\n").await.anyerr()?;
        let answer = h1_answer(&mut stream).await?;
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
        assert!(says_close(&answer), "{answer}");
        Ok(())
    }

    /// The pad of a request: a header value that differs from request to request, so that no
    /// protocol compresses it away.
    fn pad_of(id: usize) -> String {
        use rand_chacha::ChaCha8Rng;

        const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let mut rng = ChaCha8Rng::seed_from_u64(id as u64);
        (0..PAD)
            .map(|_| char::from(ALPHABET[rng.random_range(0..ALPHABET.len())]))
            .collect()
    }

    /// The size of the pad of each request, and the least of the bytes that a request takes on the
    /// wire, in either protocol: HTTP/2's Huffman code spends at least 5 bits for each of these
    /// characters.
    const PAD: usize = 1_500;
    const LEAST_BYTES_PER_REQUEST: usize = PAD * 5 / 8;

    /// What each request of an ordinary client came back with: its id, the protocol of the answer
    /// and whether the answer says that the connection closes.
    type Answered = Vec<(usize, reqwest::Version, bool)>;

    /// The clients of an ordinary-client case, and the requests that each of them sends.
    const CLIENTS: usize = 8;
    const REQUESTS_PER_CLIENT: usize = 200;
    const _: () = assert!(
        REQUESTS_PER_CLIENT * LEAST_BYTES_PER_REQUEST > 2 * super::idle::HARD_READ_BOUND,
        "a client's requests must cost more than two connections' whole allowance"
    );

    /// The most times that a handler may run for one id: the request, and the two times that the
    /// client library sends a request again after the server's shutdown notice. The server handles
    /// each of those as a request of its own.
    const MOST_RUNS_OF_AN_ID: usize = 3;

    /// Eight clients, each on a task of its own and so with a connection of its own, send 200
    /// requests one at a time through `make_client`, each request with a pad of its own. The
    /// requests of one client cost more than twice what a connection may read in its life, so each
    /// client crosses the figure at least twice. The case holds that:
    /// - every caller gets its answer, with a whole body;
    /// - every id runs at least once and at most `MOST_RUNS_OF_AN_ID` times, and no id runs that
    ///   no caller sent (the failure's message names each id that ran more than once, with the
    ///   connections that carried its runs);
    /// - each client is served by at least three connections;
    /// - the server cuts none of the connections by the drain time.
    async fn ordinary_clients_cross_the_figure(
        server: &Recording,
        scheme: &str,
        make_client: impl Fn() -> reqwest::Client,
    ) -> n0_error::Result<Answered> {
        let tasks: Vec<_> = (0..CLIENTS)
            .map(|index| {
                let (client, addr) = (make_client(), server.addr);
                let scheme = scheme.to_string();
                tokio::spawn(async move {
                    let mut answered = Vec::new();
                    for id in index * REQUESTS_PER_CLIENT..(index + 1) * REQUESTS_PER_CLIENT {
                        let response = client
                            .get(format!("{scheme}://{addr}/n/{id}"))
                            .header("x-pad", pad_of(id))
                            .send()
                            .await
                            .anyerr()?;
                        assert_eq!(response.status(), 200, "request {id}");
                        let version = response.version();
                        let closes = response
                            .headers()
                            .get("connection")
                            .is_some_and(|value| value == "close");
                        assert_eq!(response.text().await.anyerr()?, "OK", "request {id}");
                        answered.push((id, version, closes));
                    }
                    n0_error::Ok(answered)
                })
            })
            .collect();
        let mut answered = Vec::new();
        for task in tasks {
            answered.extend(task.await.anyerr()??);
        }
        let ran = server.ran();
        let mut runs: std::collections::BTreeMap<usize, Vec<SocketAddr>> = Default::default();
        for (id, peer) in &ran {
            runs.entry(id.parse().expect("an id"))
                .or_default()
                .push(*peer);
        }
        let sent = 0..CLIENTS * REQUESTS_PER_CLIENT;
        let repeated: Vec<_> = runs.iter().filter(|(_, peers)| peers.len() > 1).collect();
        let repeats = format!(
            "ids that ran more than once, with the connections that carried them: {repeated:?}"
        );
        let unsent: Vec<_> = runs.keys().filter(|id| !sent.contains(id)).collect();
        assert!(
            unsent.is_empty(),
            "ids that ran and that no caller sent: {unsent:?}; {repeats}"
        );
        let missing: Vec<_> = sent.clone().filter(|id| !runs.contains_key(id)).collect();
        assert!(
            missing.is_empty(),
            "ids that did not run: {missing:?}; {repeats}"
        );
        let too_often: Vec<_> = repeated
            .iter()
            .filter(|(_, peers)| peers.len() > MOST_RUNS_OF_AN_ID)
            .collect();
        assert!(
            too_often.is_empty(),
            "ids that ran more than {MOST_RUNS_OF_AN_ID} times: {too_often:?}; {repeats}"
        );
        for index in 0..CLIENTS {
            let connections: std::collections::HashSet<_> = ran
                .iter()
                .filter(|(id, _)| {
                    id.parse::<usize>().expect("an id") / REQUESTS_PER_CLIENT == index
                })
                .map(|(_, peer)| *peer)
                .collect();
            assert!(
                connections.len() >= 3,
                "client {index}: {} connections for requests that cost more than two crossings",
                connections.len()
            );
        }
        assert_eq!(server.drain_timeouts(), 0);
        Ok(answered)
    }

    /// C8. Over HTTP/2 without TLS.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[traced_test]
    async fn test_http2_ordinary_clients_are_served_across_the_figure() -> n0_error::Result {
        let server = Recording::start()?;
        let client = || {
            reqwest::Client::builder()
                .http2_prior_knowledge()
                .use_preconfigured_tls(self::tls::insecure_tls_config())
                .build()
                .expect("a client")
        };
        let answered = ordinary_clients_cross_the_figure(&server, "http", client).await?;
        assert!(
            answered
                .iter()
                .all(|(_, version, _)| *version == reqwest::Version::HTTP_2)
        );
        Ok(())
    }

    /// C9. Over HTTP/2 with TLS, which is the one the deployment serves; the answers prove that
    /// HTTP/2 was negotiated.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[traced_test]
    async fn test_http2_over_tls_ordinary_clients_are_served_across_the_figure() -> n0_error::Result
    {
        let server = Recording::start_tls().await?;
        let client = || {
            reqwest::Client::builder()
                .http2_prior_knowledge()
                .use_preconfigured_tls(self::tls::insecure_tls_config())
                .build()
                .expect("a client")
        };
        let answered = ordinary_clients_cross_the_figure(&server, "https", client).await?;
        assert!(
            answered
                .iter()
                .all(|(_, version, _)| *version == reqwest::Version::HTTP_2)
        );
        Ok(())
    }

    /// C10. Over HTTP/1 only, which is what the product's own client speaks: `Connection: close`
    /// is on the answers that cross the figure, and each of those is the last that its connection
    /// carried.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[traced_test]
    async fn test_http1_ordinary_clients_are_served_across_the_figure() -> n0_error::Result {
        let server = Recording::start()?;
        let client = || {
            reqwest::Client::builder()
                .http1_only()
                .use_preconfigured_tls(self::tls::insecure_tls_config())
                .build()
                .expect("a client")
        };
        let answered = ordinary_clients_cross_the_figure(&server, "http", client).await?;
        let ran = server.ran();
        let peer_of = |id: usize| {
            ran.iter()
                .find(|(ran_id, _)| ran_id == &id.to_string())
                .map(|(_, peer)| *peer)
                .expect("a handler ran")
        };
        let closing: Vec<usize> = answered
            .iter()
            .filter(|(_, _, closes)| *closes)
            .map(|(id, _, _)| *id)
            .collect();
        assert!(
            !closing.is_empty(),
            "no answer says that its connection closes"
        );
        for id in &closing {
            let peer = peer_of(*id);
            let last = ran
                .iter()
                .rfind(|(_, ran_peer)| *ran_peer == peer)
                .expect("a request");
            assert_eq!(
                last.0,
                id.to_string(),
                "a request followed the answer that says close"
            );
        }
        let peers: std::collections::HashSet<_> = ran.iter().map(|(_, peer)| *peer).collect();
        assert!(
            peers.len() - closing.len() <= CLIENTS,
            "{} connections, {} answers that close",
            peers.len(),
            closing.len()
        );
        Ok(())
    }

    /// The text of an error and of every error that caused it.
    fn error_chain(error: &dyn std::error::Error) -> String {
        let mut text = error.to_string();
        let mut source = error.source();
        while let Some(cause) = source {
            text.push_str(" | ");
            text.push_str(&cause.to_string());
            source = cause.source();
        }
        text
    }

    /// C8, the named limit. Eight tasks share ONE HTTP/2 client across the figure, so more requests
    /// wait than the connection's 2 streams take. A request that waits can get an error when the
    /// connection reaches its figure, and the error is the one that the client library gives for a
    /// request that it dropped; the request sent again on the same client is answered. No answer
    /// is cut short, and no handler runs more often than its request was sent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[traced_test]
    async fn test_http2_requests_waiting_on_one_client_meet_at_most_one_error_at_the_figure()
    -> n0_error::Result {
        const REQUESTS: usize = 400;
        let server = Recording::start()?;
        let client = reqwest::Client::builder()
            .http2_prior_knowledge()
            .use_preconfigured_tls(self::tls::insecure_tls_config())
            .build()
            .anyerr()?;
        let next = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let (client, next, addr) = (client.clone(), next.clone(), server.addr);
                tokio::spawn(async move {
                    let mut sent = Vec::new();
                    loop {
                        let id = next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        if id >= REQUESTS {
                            return n0_error::Ok(sent);
                        }
                        let mut attempts = 0;
                        loop {
                            attempts += 1;
                            let sent_now = client
                                .get(format!("http://{addr}/n/{id}"))
                                .header("x-pad", pad_of(id))
                                .send()
                                .await;
                            match sent_now {
                                Ok(response) => {
                                    assert_eq!(response.status(), 200, "request {id}");
                                    assert_eq!(
                                        response.text().await.anyerr()?,
                                        "OK",
                                        "an answer to request {id} was cut short"
                                    );
                                    break;
                                }
                                Err(error) => {
                                    let chain = error_chain(&error);
                                    assert!(
                                        chain.contains("dispatch task is gone"),
                                        "request {id} met another error: {chain}"
                                    );
                                    assert_eq!(attempts, 1, "request {id} failed when sent again");
                                }
                            }
                        }
                        sent.push((id, attempts));
                    }
                })
            })
            .collect();
        let mut sent = Vec::new();
        for task in tasks {
            sent.extend(task.await.anyerr()??);
        }
        let ran = server.ran();
        for (id, attempts) in &sent {
            let runs = ran
                .iter()
                .filter(|(ran_id, _)| ran_id == &id.to_string())
                .count();
            assert!(
                (1..=*attempts).contains(&runs),
                "request {id} was sent {attempts} times and its handler ran {runs}"
            );
        }
        assert_eq!(sent.len(), REQUESTS);
        let peers: std::collections::HashSet<_> = ran.iter().map(|(_, peer)| *peer).collect();
        assert!(peers.len() > 1, "the figure was never passed");
        assert_eq!(server.drain_timeouts(), 0);
        let resent = sent.iter().filter(|(_, attempts)| *attempts > 1).count();
        eprintln!("{} connections, {resent} requests sent again", peers.len());
        Ok(())
    }

    /// A DNS query as large as the stream's window is read and answered `200`, and one frame past
    /// the window is a flow-control error on that stream.
    #[tokio::test]
    #[traced_test]
    async fn test_http2_stream_window() -> n0_error::Result {
        let dir = tempfile::tempdir()?;
        let server = Server::spawn_for_tests(dir.path()).await?;
        let mut peer = raw_h2::Peer::connect(server.http_addr().expect("http is bound")).await?;

        let window = super::HTTP2_STREAM_WINDOW_SIZE as usize;
        let length = |len: usize| [("content-length", len.to_string())];
        let fits = peer
            .request("POST", "/dns-query", &length(window), false)
            .await?;
        peer.data(fits, &dns_query(window), true).await?;
        let past = peer
            .request("POST", "/dns-query", &length(window + 1), false)
            .await?;
        peer.data(past, &vec![b'x'; window + 1], false).await?;

        let (mut answered, mut reset) = (false, false);
        while !(answered && reset) {
            let frame = peer
                .next_frame()
                .await
                .std_context("a body was neither answered nor refused")?;
            if frame.kind == raw_h2::HEADERS && frame.stream == fits {
                assert_eq!(
                    frame.status(),
                    Some(200),
                    "the answer to a query of {window} bytes"
                );
                answered = true;
            }
            match frame.reset_code() {
                Some(code) if frame.stream == past => {
                    assert_eq!(code, raw_h2::FLOW_CONTROL_ERROR);
                    reset = true;
                }
                Some(code) => assert_eq!(code, 0, "the body within the window was reset"),
                None => {}
            }
        }

        server.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_doh() -> n0_error::Result {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(0);
        let dir = tempfile::tempdir()?;
        let https_config = HttpsConfig {
            port: 0,
            bind_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            listen_backlog: None,
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

        use axum::{
            extract::{ConnectInfo, Request},
            middleware::{self, Next},
            response::Response,
        };
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

        /// Let a test name the address a request comes from, in the `x-test-peer` header: a
        /// local connection can only come from the loopback address, and the limits key on the
        /// source address.
        async fn peer_from_header(mut req: Request, next: Next) -> Response {
            let peer = req
                .headers()
                .get("x-test-peer")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<SocketAddr>().ok());
            if let Some(peer) = peer {
                req.extensions_mut().insert(ConnectInfo(peer));
            }
            next.run(req).await
        }

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
            serve_revision(limits, put_burst, lookup_burst, None).await
        }

        pub(super) async fn serve_revision(
            limits: RateLimits,
            put_burst: u32,
            lookup_burst: u32,
            revision: Option<&'static str>,
        ) -> Result<Served> {
            let metrics = Arc::new(Metrics::default());
            let store = ZoneStore::in_memory(Options::default(), metrics.clone())?;
            serve_store(limits, put_burst, lookup_burst, revision, store, metrics).await
        }

        /// Serve a store that the caller made, with the metrics it was made with.
        pub(super) async fn serve_store(
            limits: RateLimits,
            put_burst: u32,
            lookup_burst: u32,
            revision: Option<&'static str>,
            store: ZoneStore,
            metrics: Arc<Metrics>,
        ) -> Result<Served> {
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
            let app = create_app_with_quotas(
                state,
                &limits,
                quota(put_burst),
                quota(lookup_burst),
                revision,
            )
            .layer(middleware::from_fn(peer_from_header));
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

            /// The answer of `GET /healthz`.
            pub(super) async fn healthz(&self) -> Result<serde_json::Value> {
                self.client
                    .get(format!("http://{}/healthz", self.addr))
                    .send()
                    .await
                    .anyerr()?
                    .json()
                    .await
                    .anyerr()
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

            /// A request the server has no route for.
            async fn get_unknown(&self) -> Result<StatusCode> {
                let res = self
                    .client
                    .get(format!("http://{}/nothing-here", self.addr))
                    .send()
                    .await
                    .anyerr()?;
                Ok(res.status())
            }

            /// A `DELETE`, which no route answers.
            async fn delete_pkarr(&self) -> Result<StatusCode> {
                let key = SecretKey::generate().public().to_z32();
                let res = self
                    .client
                    .delete(format!("http://{}/pkarr/{key}", self.addr))
                    .send()
                    .await
                    .anyerr()?;
                Ok(res.status())
            }

            /// [`Self::put_pkarr`] from the source address `peer`, which the server takes as
            /// the address of the connection.
            async fn put_pkarr_from(&self, peer: &str) -> Result<StatusCode> {
                let key = SecretKey::generate().public().to_z32();
                let res = self
                    .client
                    .put(format!("http://{}/pkarr/{key}", self.addr))
                    .header("x-test-peer", peer)
                    .body("not a packet")
                    .send()
                    .await
                    .anyerr()?;
                Ok(res.status())
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
        async fn requests_no_route_answers_spend_neither_quota() -> Result {
            let served = serve(
                limits(RateLimitConfig::Simple, RateLimitConfig::Simple),
                2,
                3,
            )
            .await?;

            // More of them than either burst holds.
            for _ in 0..5 {
                assert_eq!(served.get_unknown().await?, StatusCode::NOT_FOUND);
                assert_eq!(served.delete_pkarr().await?, StatusCode::METHOD_NOT_ALLOWED);
            }

            // Both quotas are whole: two publications and three lookups still get through.
            assert_eq!(served.put_pkarr().await?, StatusCode::BAD_REQUEST);
            assert_eq!(served.put_pkarr().await?, StatusCode::BAD_REQUEST);
            for _ in 0..3 {
                assert_ne!(served.get_pkarr().await?, StatusCode::TOO_MANY_REQUESTS);
            }
            assert_eq!(served.metrics.lookup_rate_limited.get(), 0);
            Ok(())
        }

        #[tokio::test]
        async fn the_addresses_of_one_ipv6_network_share_one_publication_quota() -> Result {
            let served = serve(
                limits(RateLimitConfig::Simple, RateLimitConfig::Disabled),
                2,
                1,
            )
            .await?;

            // Three addresses of one /64: the quota of two is spent by the first two.
            assert_eq!(
                served.put_pkarr_from("[2001:db8:1:2::1]:5000").await?,
                StatusCode::BAD_REQUEST
            );
            assert_eq!(
                served
                    .put_pkarr_from("[2001:db8:1:2:aaaa:bbbb:cccc:dddd]:5000")
                    .await?,
                StatusCode::BAD_REQUEST
            );
            assert_eq!(
                served.put_pkarr_from("[2001:db8:1:2:ffff::7]:5000").await?,
                StatusCode::TOO_MANY_REQUESTS
            );

            // The next /64 has a quota of its own.
            assert_eq!(
                served.put_pkarr_from("[2001:db8:1:3::1]:5000").await?,
                StatusCode::BAD_REQUEST
            );
            Ok(())
        }

        #[tokio::test]
        async fn an_ipv4_address_has_its_own_publication_quota_whichever_way_it_arrives() -> Result
        {
            let served = serve(
                limits(RateLimitConfig::Simple, RateLimitConfig::Disabled),
                2,
                1,
            )
            .await?;

            // An IPv4 client on a dual-stack listener arrives IPv6-mapped. It is one source with
            // the same address in its plain form, and another IPv4 address is another source.
            for peer in ["[::ffff:203.0.113.7]:5000", "203.0.113.7:5000"] {
                assert_eq!(served.put_pkarr_from(peer).await?, StatusCode::BAD_REQUEST);
            }
            assert_eq!(
                served.put_pkarr_from("[::ffff:203.0.113.7]:5001").await?,
                StatusCode::TOO_MANY_REQUESTS
            );
            assert_eq!(
                served.put_pkarr_from("203.0.113.8:5000").await?,
                StatusCode::BAD_REQUEST
            );
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

    /// The health check names the build that answers.
    mod health {
        use n0_error::Result;

        use super::rate_limits::{limits, serve_revision};
        use crate::http::RateLimitConfig;

        fn unlimited() -> crate::http::RateLimits {
            limits(RateLimitConfig::Disabled, RateLimitConfig::Disabled)
        }

        #[tokio::test]
        async fn healthz_carries_the_revision_the_build_was_given() -> Result {
            let revision = "0123456789abcdef0123456789abcdef01234567";
            let served = serve_revision(unlimited(), 1, 1, Some(revision)).await?;

            let health = served.healthz().await?;

            assert_eq!(health["status"], "ok");
            assert_eq!(health["version"], env!("CARGO_PKG_VERSION"));
            assert_eq!(health["git_hash"], revision);
            Ok(())
        }

        #[tokio::test]
        async fn healthz_says_unknown_when_the_build_was_given_no_revision() -> Result {
            let served = serve_revision(unlimited(), 1, 1, None).await?;

            let health = served.healthz().await?;

            assert_eq!(health["status"], "ok");
            assert_eq!(health["git_hash"], "unknown");
            Ok(())
        }
    }

    /// What a publication is checked against before it is stored.
    mod publication {
        use std::{sync::Arc, time::Duration};

        use http::StatusCode;
        use iroh::SecretKey;
        use n0_error::Result;

        use super::rate_limits::{limits, serve, serve_store};
        use crate::{
            http::RateLimitConfig,
            metrics::Metrics,
            store::{Options, ZoneStore},
            testing::{DAY_MICROS, now_micros, signed_packet_at},
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
        async fn at_its_ceiling_a_new_endpoint_is_told_to_try_later_and_everything_else_goes_on()
        -> Result {
            let metrics = Arc::new(Metrics::default());
            let store = ZoneStore::in_memory_manual_eviction(
                Options {
                    max_batch_size: 1,
                    max_batch_time: Duration::from_secs(3600),
                    eviction: Duration::from_secs(24 * 3600),
                    max_packets: 2,
                    ..Options::default()
                },
                metrics.clone(),
            )?;
            let served = serve_store(unlimited(), 100, 100, None, store, metrics).await?;
            let now = now_micros();
            let stale = SecretKey::generate();
            let honest = SecretKey::generate();
            let stale_packet = signed_packet_at(&stale, now - 2 * DAY_MICROS, "stale");
            let honest_packet = signed_packet_at(&honest, now, "honest");
            for packet in [&stale_packet, &honest_packet] {
                let (status, _) = served.put_packet(packet).await?;
                assert_eq!(status, StatusCode::NO_CONTENT);
            }

            // A new endpoint is refused with a status that says to try later, and not stored.
            let newcomer = SecretKey::generate();
            let newcomer_packet = signed_packet_at(&newcomer, now, "newcomer");
            let (status, body) = served.put_packet(&newcomer_packet).await?;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert!(
                body.contains("try again later"),
                "the answer says so: {body}"
            );
            let newcomer_key = PublicKeyBytes::new_unchecked(*newcomer.public().as_bytes());
            assert!(
                served
                    .store
                    .get_signed_packet(&newcomer_key)
                    .await?
                    .is_none()
            );

            // A replacement is taken, a stored endpoint is read, and the refusal is not the
            // rate limit's.
            let replacement = signed_packet_at(&honest, now + SECOND, "replacement");
            let (status, _) = served.put_packet(&replacement).await?;
            assert_eq!(status, StatusCode::NO_CONTENT);
            let honest_key = PublicKeyBytes::new_unchecked(*honest.public().as_bytes());
            let stored = served.store.get_signed_packet(&honest_key).await?;
            assert_eq!(stored.expect("stored").as_bytes(), replacement.as_bytes());
            assert_eq!(served.metrics.lookup_rate_limited.get(), 0);

            // Once eviction has made room, the same endpoint is taken.
            served.store.evict_expired().await?;
            let (status, _) = served.put_packet(&newcomer_packet).await?;
            assert_eq!(status, StatusCode::NO_CONTENT);
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
