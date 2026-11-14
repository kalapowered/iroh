//! A peer that speaks HTTP/2 frame by frame, for cases that need one that breaks a limit, which a
//! compliant client never does.

use std::{net::SocketAddr, time::Duration};

use n0_error::{Result, StdResultExt};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

/// Real time the server gets to answer a frame.
const ANSWER_DEADLINE: Duration = Duration::from_secs(2);

pub(super) const DATA: u8 = 0;
pub(super) const HEADERS: u8 = 1;
pub(super) const RST_STREAM: u8 = 3;
pub(super) const SETTINGS: u8 = 4;
pub(super) const WINDOW_UPDATE: u8 = 8;

pub(super) const END_STREAM: u8 = 0x1;
pub(super) const ACK: u8 = 0x1;
const END_HEADERS: u8 = 0x4;

pub(super) const FLOW_CONTROL_ERROR: u32 = 3;
pub(super) const REFUSED_STREAM: u32 = 7;

#[derive(Debug)]
pub(super) struct Frame {
    pub(super) kind: u8,
    pub(super) flags: u8,
    pub(super) stream: u32,
    pub(super) payload: Vec<u8>,
}

impl Frame {
    /// The status that a `HEADERS` frame answers with. The server writes `:status` first, either as
    /// an entry of HPACK's static table (200, 204, 206, 304, 400, 404 and 500 are entries 8 to 14)
    /// or as a literal field whose name is entry 8 (RFC 7541, 6.1 and 6.2).
    pub(super) fn status(&self) -> Option<u16> {
        if self.kind != HEADERS {
            return None;
        }
        let first = *self.payload.first()?;
        if (0x88..=0x8e).contains(&first) {
            return Some([200, 204, 206, 304, 400, 404, 500][usize::from(first - 0x88)]);
        }
        if ![0x48, 0x08, 0x18].contains(&first) {
            return None;
        }
        let length = *self.payload.get(1)?;
        let value = self.payload.get(2..2 + usize::from(length & 0x7f))?;
        if length & 0x80 == 0 {
            std::str::from_utf8(value).ok()?.parse().ok()
        } else {
            huffman_digits(value)?.parse().ok()
        }
    }

    /// The error code of an `RST_STREAM` frame.
    pub(super) fn reset_code(&self) -> Option<u32> {
        (self.kind == RST_STREAM)
            .then(|| {
                self.payload
                    .as_slice()
                    .try_into()
                    .ok()
                    .map(u32::from_be_bytes)
            })
            .flatten()
    }
}

/// A connection to the server that has done the handshake of HTTP/2 and acknowledged the server's
/// settings, so that the server applies its own limits to what this peer sends next.
pub(super) struct Peer {
    stream: TcpStream,
    next_stream: u32,
}

impl Peer {
    pub(super) async fn connect(addr: SocketAddr) -> Result<Self> {
        let mut stream = TcpStream::connect(addr).await.anyerr()?;
        stream
            .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .await
            .anyerr()?;
        let mut peer = Self {
            stream,
            next_stream: 1,
        };
        peer.send(SETTINGS, 0, 0, &[]).await?;
        // The server's settings come first; they are acknowledged as a client does.
        loop {
            let frame = peer.next_frame().await?;
            if frame.kind == SETTINGS && frame.flags & ACK == 0 {
                break;
            }
        }
        peer.send(SETTINGS, ACK, 0, &[]).await?;
        Ok(peer)
    }

    pub(super) async fn send(
        &mut self,
        kind: u8,
        flags: u8,
        stream: u32,
        payload: &[u8],
    ) -> Result<()> {
        let mut frame = Vec::with_capacity(9 + payload.len());
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
        frame.extend([kind, flags]);
        frame.extend_from_slice(&stream.to_be_bytes());
        frame.extend_from_slice(payload);
        self.stream.write_all(&frame).await.anyerr()
    }

    /// The next frame from the server, which must come within a short stretch of real time.
    pub(super) async fn next_frame(&mut self) -> Result<Frame> {
        let read = async {
            let mut head = [0; 9];
            self.stream.read_exact(&mut head).await?;
            let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
            let mut payload = vec![0; len];
            self.stream.read_exact(&mut payload).await?;
            std::io::Result::Ok(Frame {
                kind: head[3],
                flags: head[4],
                stream: u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff,
                payload,
            })
        };
        tokio::time::timeout(ANSWER_DEADLINE, read)
            .await
            .std_context("no frame from the server")?
            .anyerr()
    }

    /// The next frame of the server within a short stretch of real time, or `None` if there is
    /// none, which for a connection that stays open means that the server sent nothing.
    pub(super) async fn frame_within(&mut self, wait: Duration) -> Option<Frame> {
        // A frame is read whole or not at all: the stretch ends only between two frames.
        let mut head = [0; 1];
        let peeked = tokio::time::timeout(wait, self.stream.peek(&mut head)).await;
        match peeked {
            Ok(Ok(n)) if n > 0 => self.next_frame().await.ok(),
            _ => None,
        }
    }

    /// Reads the frames that the server sends until the connection ends, which gives `true`, or
    /// until `wait` of real time passes with nothing more to read, which gives `false`.
    pub(super) async fn ended_within(&mut self, wait: Duration) -> bool {
        loop {
            let mut head = [0; 9];
            match tokio::time::timeout(wait, self.stream.read_exact(&mut head)).await {
                Err(_elapsed) => return false,
                Ok(Err(_)) => return true,
                Ok(Ok(_)) => {
                    let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
                    if self.stream.read_exact(&mut vec![0; len]).await.is_err() {
                        return true;
                    }
                }
            }
        }
    }

    /// Sends the headers of a request on a new stream and returns the stream's number. The header
    /// block is made of literal fields, `extra` among them; with `end_stream` the request has no
    /// body.
    pub(super) async fn request(
        &mut self,
        method: &str,
        path: &str,
        extra: &[(&str, String)],
        end_stream: bool,
    ) -> Result<u32> {
        let stream = self.next_stream;
        self.next_stream += 2;
        let mut block = Vec::new();
        for (name, value) in fields(method, path, extra) {
            literal(&mut block, name, value);
        }
        let flags = END_HEADERS | if end_stream { END_STREAM } else { 0 };
        self.send(HEADERS, flags, stream, &block).await?;
        Ok(stream)
    }

    /// Sends a `DATA` frame with `body`.
    pub(super) async fn data(&mut self, stream: u32, body: &[u8], end_stream: bool) -> Result<()> {
        let flags = if end_stream { END_STREAM } else { 0 };
        self.send(DATA, flags, stream, body).await
    }
}

/// The fields of a request that `Peer::request` sends: the four pseudo-header fields, then `extra`.
fn fields<'a>(
    method: &'a str,
    path: &'a str,
    extra: &'a [(&'a str, String)],
) -> impl Iterator<Item = (&'a str, &'a str)> {
    [
        (":method", method),
        (":scheme", "http"),
        (":path", path),
        (":authority", "localhost"),
    ]
    .into_iter()
    .chain(extra.iter().map(|(name, value)| (*name, value.as_str())))
}

/// The size of a request's header list as HTTP/2 counts it (RFC 9113, 6.5.2): a name, a value and
/// 32 bytes for each field.
pub(super) fn header_list_size(method: &str, path: &str, extra: &[(&str, String)]) -> usize {
    fields(method, path, extra)
        .map(|(name, value)| name.len() + value.len() + 32)
        .sum()
}

/// The decimal digits that HPACK's Huffman code (RFC 7541, appendix B) gives a string of digits:
/// 5 bits for 0 to 2, 6 bits for 3 to 9, and ones as padding after the last one.
fn huffman_digits(bytes: &[u8]) -> Option<String> {
    let bits: Vec<u8> = bytes
        .iter()
        .flat_map(|byte| (0..8).rev().map(move |shift| (byte >> shift) & 1))
        .collect();
    let read = |at: usize, len: usize| {
        let window = bits.get(at..at + len)?;
        Some(window.iter().fold(0u8, |value, bit| value << 1 | bit))
    };
    let (mut digits, mut at) = (String::new(), 0);
    while let Some(code) = read(at, 5) {
        if code <= 2 {
            digits.push(char::from(b'0' + code));
            at += 5;
        } else if let Some(code @ 0x19..=0x1f) = read(at, 6) {
            digits.push(char::from(b'3' + code - 0x19));
            at += 6;
        } else {
            break;
        }
    }
    (!digits.is_empty()).then_some(digits)
}

/// A header field that is neither indexed nor compressed, with a new name (RFC 7541, 6.2.2).
fn literal(block: &mut Vec<u8>, name: &str, value: &str) {
    block.push(0);
    string(block, name);
    string(block, value);
}

/// A string with a length of seven bits and more, as RFC 7541 (5.1) writes it, uncompressed.
fn string(block: &mut Vec<u8>, text: &str) {
    let mut len = text.len();
    if len < 127 {
        block.push(len as u8);
    } else {
        block.push(127);
        len -= 127;
        while len >= 128 {
            block.push((len % 128) as u8 | 128);
            len /= 128;
        }
        block.push(len as u8);
    }
    block.extend_from_slice(text.as_bytes());
}
