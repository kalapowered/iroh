//! Helpers shared by the tests.

use iroh_base::SecretKey;
use iroh_dns::pkarr::{SignedPacket, Timestamp};
use simple_dns::{CLASS, Name as DnsName, Packet, ResourceRecord, rdata};

/// Microseconds in a day.
pub(crate) const DAY_MICROS: u64 = 24 * 3600 * 1_000_000;

/// The current time as a packet timestamp reads it.
pub(crate) fn now_micros() -> u64 {
    Timestamp::now().as_micros()
}

/// Sign a packet with one TXT record `_iroh` carrying `relay=<relay>` and the given timestamp, the
/// way a publisher whose clock reads `micros` would.
pub(crate) fn signed_packet_at(secret_key: &SecretKey, micros: u64, relay: &str) -> SignedPacket {
    let origin = secret_key.public().to_z32();
    let value = format!("relay={relay}");
    let mut txt = rdata::TXT::new();
    txt.add_string(&value).expect("a short string");
    let mut packet = Packet::new_reply(0);
    packet.answers.push(ResourceRecord::new(
        DnsName::new_unchecked(&format!("_iroh.{origin}")).into_owned(),
        CLASS::IN,
        30,
        rdata::RData::TXT(txt.into_owned()),
    ));
    let encoded = packet
        .build_bytes_vec_compressed()
        .expect("the packet encodes");
    let mut signable = format!("3:seqi{micros}e1:v{}:", encoded.len()).into_bytes();
    signable.extend(&encoded);
    let signature = secret_key.sign(&signable);
    let mut raw = Vec::with_capacity(104 + encoded.len());
    raw.extend_from_slice(secret_key.public().as_bytes());
    raw.extend_from_slice(&signature.to_bytes());
    raw.extend_from_slice(&micros.to_be_bytes());
    raw.extend_from_slice(&encoded);
    SignedPacket::from_bytes(&raw).expect("a validly signed packet")
}

/// What a [`FullDisk`] does with a write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Disk {
    /// Every write works.
    Healthy,
    /// A write to a block that was never written is refused, as a file system with no free
    /// blocks refuses it, and a write over a block that was written works. A file that was grown
    /// before is full only where it was never written.
    NoNewBlocks,
    /// Every write and sync is refused.
    NoWrites,
    /// The file cannot grow: a file system that reserves the space of a file when it is
    /// extended refuses the extension.
    NoGrowth,
}

/// A database file in memory whose writes can be made to fail the way a full disk fails them.
/// Reads and growing the file always work.
#[derive(Debug, Clone)]
pub(crate) struct FullDisk {
    memory: std::sync::Arc<redb::backends::InMemoryBackend>,
    mode: std::sync::Arc<std::sync::Mutex<Disk>>,
    written: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<u64>>>,
    syncs: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl Default for FullDisk {
    fn default() -> Self {
        Self {
            memory: Default::default(),
            mode: std::sync::Arc::new(std::sync::Mutex::new(Disk::Healthy)),
            written: Default::default(),
            syncs: Default::default(),
        }
    }
}

impl FullDisk {
    const BLOCK: u64 = 4096;

    /// Change what writes do from now on.
    pub(crate) fn set(&self, mode: Disk) {
        *self.mode.lock().expect("mode") = mode;
    }

    /// How many times the database asked for its data to reach the disk.
    pub(crate) fn syncs(&self) -> usize {
        self.syncs.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn refused() -> std::io::Error {
        std::io::Error::from(std::io::ErrorKind::StorageFull)
    }
}

impl redb::StorageBackend for FullDisk {
    fn len(&self) -> std::io::Result<u64> {
        self.memory.len()
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> std::io::Result<()> {
        self.memory.read(offset, out)
    }

    fn set_len(&self, len: u64) -> std::io::Result<()> {
        let grows = len > self.memory.len()?;
        if grows && *self.mode.lock().expect("mode") == Disk::NoGrowth {
            return Err(Self::refused());
        }
        self.memory.set_len(len)
    }

    fn sync_data(&self) -> std::io::Result<()> {
        if *self.mode.lock().expect("mode") == Disk::NoWrites {
            return Err(Self::refused());
        }
        self.syncs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.memory.sync_data()
    }

    fn write(&self, offset: u64, data: &[u8]) -> std::io::Result<()> {
        let mode = *self.mode.lock().expect("mode");
        let blocks =
            offset / Self::BLOCK..=(offset + data.len() as u64).saturating_sub(1) / Self::BLOCK;
        let mut written = self.written.lock().expect("written");
        match mode {
            Disk::NoWrites => return Err(Self::refused()),
            Disk::NoNewBlocks if !blocks.clone().all(|block| written.contains(&block)) => {
                return Err(Self::refused());
            }
            _ => {}
        }
        written.extend(blocks);
        drop(written);
        self.memory.write(offset, data)
    }
}
