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
