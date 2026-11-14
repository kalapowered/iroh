use std::{
    borrow::Cow,
    io,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll},
    time::Duration,
};

use axum_server::{
    accept::Accept,
    tls_rustls::{RustlsAcceptor, RustlsConfig},
};
use n0_error::{Result, StackResultExt, StdResultExt, bail_any};
use n0_future::{FutureExt, future::Boxed as BoxFuture};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls_acme::{AcmeConfig, axum::AxumAcceptor, caches::DirCache};
use tokio_stream::StreamExt;
use tracing::{Instrument, debug, error, info_span};

/// Strategy used to obtain TLS certificates for the HTTPS server.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, strum::Display)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CertMode {
    /// Load pre-existing certificates from the `cert_cache` directory.
    Manual,
    /// Obtain certificates from Let's Encrypt via the ACME protocol.
    LetsEncrypt,
    /// Generate self-signed certificates and cache them in `cert_cache`.
    SelfSigned,
}

impl CertMode {
    /// Build the [`TlsAcceptor`] for this mode.
    pub(crate) async fn build(
        &self,
        domains: Vec<String>,
        cert_cache: PathBuf,
        letsencrypt_contact: Option<String>,
        letsencrypt_prod: bool,
    ) -> Result<TlsAcceptor> {
        Ok(match self {
            CertMode::Manual => TlsAcceptor::manual(domains, cert_cache).await?,
            CertMode::SelfSigned => TlsAcceptor::self_signed(domains)?,
            CertMode::LetsEncrypt => {
                let contact =
                    letsencrypt_contact.context("contact is required for letsencrypt cert mode")?;
                TlsAcceptor::letsencrypt(domains, &contact, letsencrypt_prod, cert_cache)?
            }
        })
    }
}

/// How long a client may take to complete the TLS handshake.
///
/// Generous, so that clients on lossy high-latency links still get through.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// The most raw bytes that a connection may send before the TLS acceptor returns: 32,768. A
/// connection that sends more is closed. The TLS library keeps a handshake message that it is sent
/// in pieces until the message ends, up to 64 KiB of raw bytes, and the time limit above alone
/// lets every connection that stands in its handshake hold that for as long as the limit runs.
///
/// The count is of the bytes read from the socket, record headers included, and it ends when the
/// acceptor returns, not at the client's `Finished`: the acceptor goes on reading until it has
/// decrypted one application record, so the first bytes of a client's first requests, when they
/// arrive in the flight of its `Finished`, are counted here and not by `READ_BOUND`. What the
/// acceptor reads before it returns is the client's handshake flight and what its last read took
/// with the first application record.
///
/// The figure, by arithmetic. An honest flight is far under 4,096 bytes: a client on OpenSSL 3.5,
/// with key shares for X25519 and ML-KEM-768, sends a `ClientHello` of 1,546 bytes and 1,631 raw
/// bytes before its own handshake is done; with every cipher suite, five ALPN names and a server
/// name of 247 characters, 1,950 and 2,035; a second `ClientHello` after a `HelloRetryRequest`
/// doubles the first, 4,070. After it comes at most one application record that the acceptor
/// decrypts, 16,406 bytes at the largest (16,384 of plaintext and 22 of overhead), and the rest of
/// its last read. A read takes what the TLS library's buffer has free, and that buffer holds at
/// most 18,437 bytes (a record of 16,384 bytes with the library's allowance of 2,048 for its
/// encryption, and a record header) of what has not been taken in: 4,096 and 18,437 are 22,533,
/// and the figure leaves 10,235 over. A valid first batch of requests that fills the record, two
/// HTTP/2 heads of 8,191 bytes and a body of 4,096, is read by the acceptor and counted here. As
/// with `READ_BOUND`, it is a threshold at which the connection is closed: the read that crosses
/// it has been made.
pub(super) const HANDSHAKE_READ_BOUND: usize = 32_768;

/// A connection's socket as the TLS acceptor reads it: it counts the raw bytes read until the
/// acceptor returns, and fails once more than [`HANDSHAKE_READ_BOUND`] have been read.
#[derive(Debug)]
pub(crate) struct Handshaking<I> {
    inner: I,
    /// The bytes read so far, or `None` once the acceptor has returned.
    read: Option<usize>,
}

impl<I> Handshaking<I> {
    fn new(inner: I) -> Self {
        Self {
            inner,
            read: Some(0),
        }
    }

    /// Ends the count, when the acceptor has returned: the bytes read from now on are the
    /// connection's own.
    fn end_handshake(&mut self) {
        self.read = None;
    }
}

impl<I: AsyncRead + Unpin> AsyncRead for Handshaking<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let before = buf.filled().len();
        let polled = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let (Poll::Ready(Ok(())), Some(read)) = (&polled, &mut this.read) {
            *read = read.saturating_add(buf.filled().len().saturating_sub(before));
            if *read > HANDSHAKE_READ_BOUND {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "connection sent more than it may before its TLS handshake ended",
                )));
            }
        }
        polled
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for Handshaking<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// TLS Certificate Authority acceptor.
#[derive(Clone)]
pub(crate) enum TlsAcceptor {
    LetsEncrypt(AxumAcceptor),
    Manual(RustlsAcceptor),
}

impl<I: AsyncRead + AsyncWrite + Unpin + Send + 'static, S: Send + 'static> Accept<I, S>
    for TlsAcceptor
{
    type Stream = tokio_rustls::server::TlsStream<Handshaking<I>>;
    type Service = S;
    type Future = BoxFuture<io::Result<(Self::Stream, Self::Service)>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let stream = Handshaking::new(stream);
        let accept = match self {
            Self::LetsEncrypt(a) => a.accept(stream, service).boxed(),
            Self::Manual(a) => a.accept(stream, service).boxed(),
        };
        // The ACME acceptor has no handshake timeout of its own.
        async move {
            let accepted = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, accept)
                .await
                .unwrap_or_else(|_| {
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "TLS handshake timed out",
                    ))
                });
            let (mut stream, service) = accepted?;
            stream.get_mut().0.end_handshake();
            Ok((stream, service))
        }
        .boxed()
    }
}

impl TlsAcceptor {
    fn self_signed(domains: Vec<String>) -> Result<Self> {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(domains).anyerr()?;
        let key = PrivateKeyDer::try_from(signing_key.serialize_der())?;

        let mut config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .anyerr()?
                .with_no_client_auth()
                .with_single_cert(vec![cert.der().clone()], key)
                .anyerr()?;

        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let acceptor = RustlsAcceptor::new(RustlsConfig::from_config(Arc::new(config)));
        Ok(Self::Manual(acceptor))
    }

    async fn manual(domains: Vec<String>, dir: PathBuf) -> Result<Self> {
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .anyerr()?
        .with_no_client_auth();

        if domains.len() != 1 {
            bail_any!("Multiple domains in manual mode are not supported");
        }

        let keyname = escape_hostname(&domains[0]);
        let cert_path = dir.join(format!("{keyname}.crt"));
        let key_path = dir.join(format!("{keyname}.key"));

        let certs = load_certs(cert_path).await?;
        let secret_key = load_secret_key(key_path).await?;

        let config = config.with_single_cert(certs, secret_key).anyerr()?;
        let config = RustlsConfig::from_config(Arc::new(config));
        let acceptor = RustlsAcceptor::new(config);
        Ok(Self::Manual(acceptor))
    }

    fn letsencrypt(
        domains: Vec<String>,
        contact: &str,
        is_production: bool,
        dir: PathBuf,
    ) -> Result<Self> {
        let config = rustls::ServerConfig::builder().with_no_client_auth();
        let mut state = AcmeConfig::new(domains)
            .contact([format!("mailto:{contact}")])
            .cache_option(Some(DirCache::new(dir)))
            .directory_lets_encrypt(is_production)
            .state();

        let config = config.with_cert_resolver(state.resolver());
        let acceptor = state.acceptor();

        tokio::spawn(
            async move {
                loop {
                    match state.next().await.unwrap() {
                        Ok(ok) => debug!("acme event: {:?}", ok),
                        Err(err) => error!("error: {:?}", err),
                    }
                }
            }
            .instrument(info_span!("acme")),
        );
        let config = Arc::new(config);
        let acceptor = AxumAcceptor::new(acceptor, config);
        Ok(Self::LetsEncrypt(acceptor))
    }
}

async fn load_certs(filename: impl AsRef<Path>) -> Result<Vec<CertificateDer<'static>>> {
    let filename = filename.as_ref();
    let certfile = tokio::fs::read(filename)
        .await
        .with_std_context(|_| format!("cannot open certificate file at {}", filename.display()))?;
    CertificateDer::pem_slice_iter(&certfile)
        .collect::<Result<Vec<_>, _>>()
        .with_std_context(|_| format!("cannot parse certificates from {}", filename.display()))
}

async fn load_secret_key(filename: impl AsRef<Path>) -> Result<PrivateKeyDer<'static>> {
    let filename = filename.as_ref();
    let keyfile = tokio::fs::read(filename)
        .await
        .with_std_context(|_| format!("cannot open secret key file at {}", filename.display()))?;
    PrivateKeyDer::from_pem_slice(&keyfile)
        .with_std_context(|_| format!("cannot parse secret key from {}", filename.display()))
}

static UNSAFE_HOSTNAME_CHARACTERS: OnceLock<regex::Regex> = OnceLock::new();

fn escape_hostname(hostname: &str) -> Cow<'_, str> {
    let regex = UNSAFE_HOSTNAME_CHARACTERS
        .get_or_init(|| regex::Regex::new(r"[^a-zA-Z0-9-\.]").expect("valid regex"));
    regex.replace_all(hostname, "")
}

/// The start of a `ClientHello` of `raw` bytes in all, the record headers included: records of at
/// most 16,384 bytes of payload, the first with a handshake header that declares the largest
/// message, 65,535 bytes, so that the TLS library keeps what it is sent while it waits for the
/// rest.
#[cfg(test)]
pub(super) fn partial_client_hello(raw: usize) -> Vec<u8> {
    const RECORD_HEADER: usize = 5;
    const RECORD_PAYLOAD: usize = 16_384;
    let mut bytes = Vec::with_capacity(raw);
    while bytes.len() < raw {
        let payload = (raw - bytes.len() - RECORD_HEADER).min(RECORD_PAYLOAD);
        bytes.extend_from_slice(&[0x16, 0x03, 0x01]);
        bytes.extend_from_slice(&u16::try_from(payload).expect("one record").to_be_bytes());
        if bytes.len() == RECORD_HEADER {
            bytes.extend_from_slice(&[0x01, 0x00, 0xff, 0xff]);
            bytes.resize(RECORD_HEADER + payload, 0);
        } else {
            bytes.resize(bytes.len() + payload, 0);
        }
    }
    assert_eq!(bytes.len(), raw);
    bytes
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum_server::accept::Accept;
    use tokio::{io::AsyncWriteExt, time::Instant};

    use super::{AxumAcceptor, TLS_HANDSHAKE_TIMEOUT, TlsAcceptor, partial_client_hello};

    #[tokio::test(start_paused = true)]
    async fn test_handshake_timeout() {
        let TlsAcceptor::Manual(inner) =
            TlsAcceptor::self_signed(vec!["localhost".to_string()]).unwrap()
        else {
            unreachable!("self-signed mode uses the manual acceptor");
        };
        let acceptor = TlsAcceptor::Manual(inner.handshake_timeout(Duration::from_secs(3600)));
        let (_client, server_io) = tokio::io::duplex(1024);

        let start = Instant::now();
        let accept = acceptor.accept(server_io, ());
        let err = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT + Duration::from_secs(1), accept)
            .await
            .expect("handshake timeout did not fire")
            .expect_err("handshake cannot succeed without a client");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(start.elapsed() >= TLS_HANDSHAKE_TIMEOUT);
    }

    /// The Let's Encrypt acceptor as `letsencrypt` makes it, but with its state never polled, so
    /// that nothing reaches the network.
    fn lets_encrypt() -> TlsAcceptor {
        let state = tokio_rustls_acme::AcmeConfig::new(["localhost"]).state();
        let config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(state.resolver());
        TlsAcceptor::LetsEncrypt(AxumAcceptor::new(
            state.acceptor(),
            std::sync::Arc::new(config),
        ))
    }

    /// A connection in its handshake may send 32,768 raw bytes and is closed by the next byte,
    /// in both modes. The figure is written out here so that a change of it fails this case.
    #[tokio::test(start_paused = true)]
    async fn a_handshake_may_send_the_bound_and_no_more() {
        let manual = TlsAcceptor::self_signed(vec!["localhost".to_string()]).unwrap();
        for (mode, acceptor) in [("manual", manual), ("letsencrypt", lets_encrypt())] {
            let (mut client, server_io) = tokio::io::duplex(1 << 20);
            let mut accept = acceptor.accept(server_io, ());

            client
                .write_all(&partial_client_hello(32_768))
                .await
                .unwrap();
            // The acceptor reads all of it and waits for the rest, while the clock runs on.
            assert!(
                tokio::time::timeout(Duration::from_secs(1), &mut accept)
                    .await
                    .is_err(),
                "{mode}: ended at the bound"
            );

            // The first byte of the next record.
            client.write_all(&[0x16]).await.unwrap();
            let error = tokio::time::timeout(Duration::from_secs(1), accept)
                .await
                .unwrap_or_else(|_| panic!("{mode}: not closed past the bound"))
                .err()
                .unwrap_or_else(|| panic!("{mode}: a handshake of 32,769 bytes succeeded"));
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData, "{mode}");
        }
    }
}
