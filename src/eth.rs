//! On-wire framing: Ethernet + IPv4 + UDP around a Vantablack frame.
//!
//! The mesh's wire frame (`net::WIRE_FRAME_LEN`, 576 bytes) is a sealed ShardSec record, not a
//! network packet: it has no addresses in it, because until now the only transport was an
//! in-RAM stand-in. This module is the adapter between the two worlds, and it is deliberately
//! the *only* place that knows about headers, so the framing can be checked against an
//! independent implementation (the pinned known-answer vector below comes from a Python
//! builder, and `dev-tools/wire_check.py` parses the same bytes a third time when they cross the
//! wire).
//!
//! Layout of one datagram:
//!
//! ```text
//!   0              14        34                  42                    42+n
//!   +--------------+---------+-------------------+---------------------+
//!   | Ethernet     | IPv4    | UDP               | Vantablack frame    |
//!   | dst,src,0800 | 20 B    | src,dst,len,csum  | (sealed shard)      |
//!   +--------------+---------+-------------------+---------------------+
//! ```
//!
//! **Address resolution.** One small piece of ARP exists, and only the piece that is needed to be
//! *reachable*: an ARP request for this endpoint's address is answered with this endpoint's MAC.
//! Without it a peer that has to learn the MAC cannot deliver anything at all — on QEMU's
//! user-mode network the guest's outbound datagrams produce replies that slirp then queues behind
//! an unanswered ARP request, so the segment looks healthy while nothing ever arrives. The rest of
//! ARP (proactive resolution, caching, gratuitous announcements) is still absent, because the
//! addresses on this profile are configured rather than discovered.
//!
//! What this layer deliberately does **not** do: DHCP, IPv4 options, fragmentation and
//! reassembly. The lab profile is QEMU's user-mode networking, where the guest is 10.0.2.15/24,
//! the gateway is 10.0.2.2, and the gateway's MAC is fixed by slirp — so the addresses can be
//! configured instead of discovered. A frame larger than the MTU cannot happen here: the wire
//! frame is 576 bytes, so a datagram is 618 bytes at most, and anything arriving fragmented or
//! with options is refused and counted rather than guessed at.

use crate::println;
use alloc::vec::Vec;

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const IP_PROTOCOL_UDP: u8 = 17;

/// ARP over Ethernet/IPv4: hardware type 1, protocol 0x0800, 6-byte hardware and 4-byte protocol
/// addresses.
const ARP_HARDWARE_ETHERNET: u16 = 1;
const ARP_OPCODE_REQUEST: u16 = 1;
const ARP_OPCODE_REPLY: u16 = 2;
const ARP_PACKET_LEN: usize = 28;
pub const ARP_FRAME_LEN: usize = ETHERNET_HEADER_LEN + ARP_PACKET_LEN;

pub const ETHERNET_HEADER_LEN: usize = 14;
pub const IPV4_HEADER_LEN: usize = 20;
pub const UDP_HEADER_LEN: usize = 8;
/// Bytes a datagram spends on headers before the first payload byte.
pub const HEADER_LEN: usize = ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN;

/// Largest payload this transport carries: exactly one Vantablack wire frame.
pub const MAX_PAYLOAD: usize = 576;
/// Largest datagram the builder will produce (618 bytes, well inside the 1500-byte MTU, so no
/// datagram from here can ever need fragmentation).
pub const MAX_FRAME: usize = HEADER_LEN + MAX_PAYLOAD;

/// UDP port the mesh runs on: `0x4B4C` spells "KL". Both ends use it, so the port is part of
/// the protocol rather than a dynamic allocation.
pub const MESH_PORT: u16 = 0x4B4C;
/// Port for the driver's own probe datagram, so a wire observer can tell a test packet from
/// sealed mesh traffic without decrypting either.
pub const PROBE_PORT: u16 = 0x4B4D;

/// The probe payload: fixed bytes, so the same 68-byte frame can be recognised on the wire.
pub const PROBE_PAYLOAD: &[u8] = b"KELLER-OS e1000 wire probe";

/// QEMU user-mode networking profile (slirp). Documented as a profile because it is configured
/// by hand: `10.0.2.15/24` is the guest address slirp expects, `10.0.2.2` is its gateway (and
/// the host's loopback, which is why a host socket can answer), and the gateway MAC is the one
/// slirp's virtual adapter uses.
pub const GUEST_IP: [u8; 4] = [10, 0, 2, 15];
pub const GATEWAY_IP: [u8; 4] = [10, 0, 2, 2];
pub const GATEWAY_MAC: [u8; 6] = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];
/// Broadcast destination, for frames that should reach whoever is listening.
pub const BROADCAST_MAC: [u8; 6] = [0xff; 6];

/// One end of a link: hardware address, protocol address and port.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Endpoint {
    pub mac: [u8; 6],
    pub ip: [u8; 4],
    pub port: u16,
}

pub const fn endpoint(mac: [u8; 6], ip: [u8; 4], port: u16) -> Endpoint {
    Endpoint { mac, ip, port }
}

/// Why a received frame was not handed on.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// Shorter than the headers it claims to have.
    TooShort,
    /// Not an IPv4 Ethernet frame.
    NotIpv4,
    /// IPv4 header options, or a version other than 4.
    UnsupportedHeader,
    /// A fragment: this transport has no reassembly, and none is needed at this MTU.
    Fragmented,
    /// Not UDP.
    NotUdp,
    /// Length fields that disagree with each other or with the frame.
    BadLength,
    /// The IPv4 header checksum does not validate.
    BadHeaderChecksum,
    /// The UDP checksum does not validate.
    BadChecksum,
}

impl Reject {
    pub fn as_str(self) -> &'static str {
        match self {
            Reject::TooShort => "truncated",
            Reject::NotIpv4 => "not-ipv4",
            Reject::UnsupportedHeader => "ipv4-options",
            Reject::Fragmented => "fragmented",
            Reject::NotUdp => "not-udp",
            Reject::BadLength => "bad-length",
            Reject::BadHeaderChecksum => "bad-ip-checksum",
            Reject::BadChecksum => "bad-udp-checksum",
        }
    }
}

/// A parsed datagram, borrowing its payload out of the received frame.
pub struct Datagram<'a> {
    pub source: Endpoint,
    pub destination: Endpoint,
    pub identification: u16,
    pub payload: &'a [u8],
}

/// Internet-style ones-complement checksum (RFC 1071) over an even-length view; an odd trailing
/// byte is padded with zero, which is what every implementation does for the pseudo-header.
pub fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut index = 0;
    while index + 1 < bytes.len() {
        sum += ((bytes[index] as u32) << 8) | bytes[index + 1] as u32;
        index += 2;
    }
    if index < bytes.len() {
        sum += (bytes[index] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// UDP checksum over the IPv4 pseudo-header, the UDP header and the payload (RFC 768).
fn udp_checksum(source: Endpoint, destination: Endpoint, udp_length: u16, payload: &[u8]) -> u16 {
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&source.ip);
    pseudo[4..8].copy_from_slice(&destination.ip);
    pseudo[8] = 0;
    pseudo[9] = IP_PROTOCOL_UDP;
    pseudo[10..12].copy_from_slice(&udp_length.to_be_bytes());
    let mut sum = ones_complement(&pseudo);
    let header = [
        (source.port >> 8) as u8,
        source.port as u8,
        (destination.port >> 8) as u8,
        destination.port as u8,
        (udp_length >> 8) as u8,
        udp_length as u8,
        0,
        0,
    ];
    sum = add_ones_complement(sum, ones_complement(&header));
    sum = add_ones_complement(sum, ones_complement(payload));
    let value = !sum;
    // A computed zero means "not computed" on the wire; RFC 768 requires all ones instead.
    if value == 0 {
        0xFFFF
    } else {
        value
    }
}

/// Checksum accumulator as a raw u16 sum (used only by `udp_checksum`, which needs to add
/// partial sums).
fn ones_complement(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut index = 0;
    while index + 1 < bytes.len() {
        sum += ((bytes[index] as u32) << 8) | bytes[index + 1] as u32;
        index += 2;
    }
    if index < bytes.len() {
        sum += (bytes[index] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum as u16
}

fn add_ones_complement(a: u16, b: u16) -> u16 {
    let mut sum = a as u32 + b as u32;
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum as u16
}

/// Builds one datagram. Returns the frame length, or `None` when the payload cannot fit or the
/// caller's buffer is too small.
///
/// `identification` is the IPv4 identification field; the caller passes a counter so a wire
/// observer can see that consecutive datagrams are distinct even when their payloads are equal.
pub fn build(
    source: Endpoint,
    destination: Endpoint,
    identification: u16,
    payload: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    if payload.len() > MAX_PAYLOAD || payload.len() > 0xFFFF - UDP_HEADER_LEN - IPV4_HEADER_LEN {
        return None;
    }
    let udp_length = (UDP_HEADER_LEN + payload.len()) as u16;
    let total_length = (IPV4_HEADER_LEN + UDP_HEADER_LEN + payload.len()) as u16;
    let frame_length = HEADER_LEN + payload.len();
    if out.len() < frame_length {
        return None;
    }

    // Ethernet.
    out[0..6].copy_from_slice(&destination.mac);
    out[6..12].copy_from_slice(&source.mac);
    out[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());

    // IPv4, with the checksum over its own header.
    let ip = &mut out[ETHERNET_HEADER_LEN..ETHERNET_HEADER_LEN + IPV4_HEADER_LEN];
    ip[0] = 0x45; // version 4, header length 5 words
    ip[1] = 0x00; // DSCP / ECN
    ip[2..4].copy_from_slice(&total_length.to_be_bytes());
    ip[4..6].copy_from_slice(&identification.to_be_bytes());
    ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // don't fragment
    ip[8] = 64; // TTL
    ip[9] = IP_PROTOCOL_UDP;
    ip[10..12].copy_from_slice(&[0, 0]);
    ip[12..16].copy_from_slice(&source.ip);
    ip[16..20].copy_from_slice(&destination.ip);
    let header_checksum = checksum(&out[ETHERNET_HEADER_LEN..ETHERNET_HEADER_LEN + IPV4_HEADER_LEN]);
    out[ETHERNET_HEADER_LEN + 10..ETHERNET_HEADER_LEN + 12]
        .copy_from_slice(&header_checksum.to_be_bytes());

    // UDP, with the checksum over the pseudo-header.
    let udp = ETHERNET_HEADER_LEN + IPV4_HEADER_LEN;
    out[udp..udp + 2].copy_from_slice(&source.port.to_be_bytes());
    out[udp + 2..udp + 4].copy_from_slice(&destination.port.to_be_bytes());
    out[udp + 4..udp + 6].copy_from_slice(&udp_length.to_be_bytes());
    out[udp + 6..udp + 8].copy_from_slice(&[0, 0]);
    let payload_checksum = udp_checksum(source, destination, udp_length, payload);
    out[udp + 6..udp + 8].copy_from_slice(&payload_checksum.to_be_bytes());

    out[HEADER_LEN..frame_length].copy_from_slice(payload);
    Some(frame_length)
}

/// Parses one received Ethernet frame. Strict on purpose: a frame that could mean two things is
/// refused and counted, because the payload is handed to the mesh's authenticated ingress and a
/// layout surprise there is exactly the kind of thing that turns into a spoofing bug.
pub fn parse(frame: &[u8]) -> Result<Datagram<'_>, Reject> {
    if frame.len() < HEADER_LEN {
        return Err(Reject::TooShort);
    }
    let ethertype = (frame[12] as u16) << 8 | frame[13] as u16;
    if ethertype != ETHERTYPE_IPV4 {
        return Err(Reject::NotIpv4);
    }
    let ip = &frame[ETHERNET_HEADER_LEN..];
    if ip[0] >> 4 != 4 || ip[0] & 0x0F != 5 {
        return Err(Reject::UnsupportedHeader);
    }
    let total_length = ((ip[2] as u16) << 8 | ip[3] as u16) as usize;
    if total_length < IPV4_HEADER_LEN + UDP_HEADER_LEN || total_length > ip.len() {
        return Err(Reject::BadLength);
    }
    // The fragment field is a flags nibble plus an offset, and the offset is not adjacent to the
    // flags: the top three bits of `ip[6]` are the flags, its low five bits are the *high* bits of
    // the offset, and `ip[7]` holds the rest. An offset that lives in `ip[7]` alone is still a
    // fragment, even though `ip[6]` then reads as a plain don't-fragment header - which is the
    // frame a check that only masked `ip[6]` would let through.
    let more_fragments = ip[6] & 0x20 != 0;
    let fragment_offset = ((ip[6] as u16) & 0x1F) << 8 | ip[7] as u16;
    if more_fragments || fragment_offset != 0 {
        return Err(Reject::Fragmented);
    }
    // Structural checks run before the checksum on purpose: a frame that is not UDP is not UDP
    // whatever its checksum says, and a caller that mutates one field to test one rejection
    // should see that rejection rather than a checksum complaint.
    if ip[9] != IP_PROTOCOL_UDP {
        return Err(Reject::NotUdp);
    }
    if checksum(&ip[..IPV4_HEADER_LEN]) != 0 {
        return Err(Reject::BadHeaderChecksum);
    }

    let udp = &ip[IPV4_HEADER_LEN..total_length];
    let udp_length = ((udp[4] as u16) << 8 | udp[5] as u16) as usize;
    if udp_length < UDP_HEADER_LEN || udp_length > udp.len() {
        return Err(Reject::BadLength);
    }
    let payload = &udp[UDP_HEADER_LEN..udp_length];

    let source = endpoint(
        [
            frame[6], frame[7], frame[8], frame[9], frame[10], frame[11],
        ],
        [ip[12], ip[13], ip[14], ip[15]],
        (udp[0] as u16) << 8 | udp[1] as u16,
    );
    let destination = endpoint(
        [
            frame[0], frame[1], frame[2], frame[3], frame[4], frame[5],
        ],
        [ip[16], ip[17], ip[18], ip[19]],
        (udp[2] as u16) << 8 | udp[3] as u16,
    );

    let transmitted = (udp[6] as u16) << 8 | udp[7] as u16;
    if transmitted != 0 {
        // Zero means "not computed" and is legal for IPv4; anything else has to validate.
        let expected = udp_checksum(source, destination, udp_length as u16, payload);
        if expected != transmitted {
            return Err(Reject::BadChecksum);
        }
    }

    Ok(Datagram {
        source,
        destination,
        identification: (ip[4] as u16) << 8 | ip[5] as u16,
        payload,
    })
}

/// A well-formed ARP request (or reply) for this Ethernet/IPv4 profile.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ArpMessage {
    pub opcode: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: [u8; 4],
    pub target_mac: [u8; 6],
    pub target_ip: [u8; 4],
}

/// Parses an ARP frame, or `None` when the frame is not ARP-over-Ethernet/IPv4 or is too short
/// to hold the message it claims.
pub fn parse_arp(frame: &[u8]) -> Option<ArpMessage> {
    if frame.len() < ARP_FRAME_LEN {
        return None;
    }
    let ethertype = (frame[12] as u16) << 8 | frame[13] as u16;
    if ethertype != ETHERTYPE_ARP {
        return None;
    }
    let arp = &frame[ETHERNET_HEADER_LEN..];
    let hardware = (arp[0] as u16) << 8 | arp[1] as u16;
    let protocol = (arp[2] as u16) << 8 | arp[3] as u16;
    if hardware != ARP_HARDWARE_ETHERNET || protocol != ETHERTYPE_IPV4 || arp[4] != 6 || arp[5] != 4 {
        return None;
    }
    Some(ArpMessage {
        opcode: (arp[6] as u16) << 8 | arp[7] as u16,
        sender_mac: [arp[8], arp[9], arp[10], arp[11], arp[12], arp[13]],
        sender_ip: [arp[14], arp[15], arp[16], arp[17]],
        target_mac: [arp[18], arp[19], arp[20], arp[21], arp[22], arp[23]],
        target_ip: [arp[24], arp[25], arp[26], arp[27]],
    })
}

/// True when `message` asks who holds `local_ip`.
pub fn is_request_for(message: &ArpMessage, local_ip: [u8; 4]) -> bool {
    message.opcode == ARP_OPCODE_REQUEST && message.target_ip == local_ip
}

/// Builds the reply to a request: this endpoint states its own mapping, addressed to whoever
/// asked. Returns the frame length, or `None` when the caller's buffer cannot hold 42 bytes.
pub fn build_arp_reply(
    local_mac: [u8; 6],
    local_ip: [u8; 4],
    request: &ArpMessage,
    out: &mut [u8],
) -> Option<usize> {
    if out.len() < ARP_FRAME_LEN {
        return None;
    }
    // A reply is the request's addresses with the two ends swapped, and a unicast destination:
    // the requester already told us its MAC, which is what makes the reply addressable at all.
    out[0..6].copy_from_slice(&request.sender_mac);
    out[6..12].copy_from_slice(&local_mac);
    out[12..14].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());
    let arp = &mut out[ETHERNET_HEADER_LEN..ARP_FRAME_LEN];
    arp[0..2].copy_from_slice(&ARP_HARDWARE_ETHERNET.to_be_bytes());
    arp[2..4].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    arp[4] = 6;
    arp[5] = 4;
    arp[6..8].copy_from_slice(&ARP_OPCODE_REPLY.to_be_bytes());
    arp[8..14].copy_from_slice(&local_mac);
    arp[14..18].copy_from_slice(&local_ip);
    arp[18..24].copy_from_slice(&request.sender_mac);
    arp[24..28].copy_from_slice(&request.sender_ip);
    Some(ARP_FRAME_LEN)
}

/// True when the frame is addressed to this endpoint (or broadcast), on the given port.
pub fn addressed_to(datagram: &Datagram<'_>, local: Endpoint, port: u16) -> bool {
    (datagram.destination.mac == local.mac || datagram.destination.mac == BROADCAST_MAC)
        && (datagram.destination.ip == local.ip || datagram.destination.ip == [0, 0, 0, 0])
        && datagram.destination.port == port
}

pub fn describe() {
    println!(
        "[ETH] framing: ethernet+ipv4+udp, headers={} bytes, payload<={} (a datagram is {}-{} bytes, so nothing here needs fragmentation)",
        HEADER_LEN,
        MAX_PAYLOAD,
        HEADER_LEN,
        MAX_FRAME
    );
    println!(
        "[ETH] profile: guest {}.{}.{}.{}, gateway {}.{}.{}.{} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, mesh-port={:#06x} probe-port={:#06x}",
        GUEST_IP[0],
        GUEST_IP[1],
        GUEST_IP[2],
        GUEST_IP[3],
        GATEWAY_IP[0],
        GATEWAY_IP[1],
        GATEWAY_IP[2],
        GATEWAY_IP[3],
        GATEWAY_MAC[0],
        GATEWAY_MAC[1],
        GATEWAY_MAC[2],
        GATEWAY_MAC[3],
        GATEWAY_MAC[4],
        GATEWAY_MAC[5],
        MESH_PORT,
        PROBE_PORT
    );
}

// --------------------------------------------------------------------------------------- tests

pub struct EthReport {
    pub passed: u32,
    pub failed: u32,
    pub failures: Vec<&'static str>,
}

impl EthReport {
    fn new() -> Self {
        Self {
            passed: 0,
            failed: 0,
            failures: Vec::new(),
        }
    }

    fn check(&mut self, condition: bool, failure: &'static str) {
        if condition {
            self.passed += 1;
        } else {
            self.failed += 1;
            self.failures.push(failure);
        }
    }
}

/// The known-answer vector for `PROBE_PAYLOAD` on the lab profile, byte for byte. It was
/// produced by an independent implementation (a Python builder in the harness tooling), so a
/// change to the header layout, a byte-order slip or a checksum regression cannot pass this
/// test by agreeing with itself.
const KAT_FRAME: [u8; 68] = [
    0x52, 0x55, 0x0a, 0x00, 0x02, 0x02, // destination MAC (slirp gateway)
    0x52, 0x54, 0x00, 0x12, 0x34, 0x56, // source MAC (this NIC)
    0x08, 0x00, // ethertype: IPv4
    0x45, 0x00, 0x00, 0x36, // version/IHL, DSCP, total length 54
    0x00, 0x01, 0x40, 0x00, // identification 1, don't fragment
    0x40, 0x11, 0x22, 0xa6, // TTL 64, UDP, header checksum
    0x0a, 0x00, 0x02, 0x0f, // source 10.0.2.15
    0x0a, 0x00, 0x02, 0x02, // destination 10.0.2.2
    0x4b, 0x4c, 0x4b, 0x4c, // source port, destination port
    0x00, 0x22, 0x4f, 0x18, // UDP length 34, UDP checksum
    0x4b, 0x45, 0x4c, 0x4c, 0x45, 0x52, 0x2d, 0x4f, // "KELLER-O"
    0x53, 0x20, 0x65, 0x31, 0x30, 0x30, 0x30, 0x20, // "S e1000 "
    0x77, 0x69, 0x72, 0x65, 0x20, 0x70, 0x72, 0x6f, // "wire pro"
    0x62, 0x65, // "be"
];

/// Framing self-test: the known-answer vector, a round-trip through `parse`, and one rejection
/// case per way a frame can be wrong. Every mutation below is applied to the *parsed* frame, so
/// the test cannot pass by rejecting on something else.
pub fn self_test() -> EthReport {
    let mut report = EthReport::new();
    let source = endpoint([0x52, 0x54, 0x00, 0x12, 0x34, 0x56], GUEST_IP, MESH_PORT);
    let destination = endpoint(GATEWAY_MAC, GATEWAY_IP, MESH_PORT);

    let mut frame = [0u8; MAX_FRAME];
    let length = match build(source, destination, 1, PROBE_PAYLOAD, &mut frame) {
        Some(length) => length,
        None => {
            report.check(false, "the builder refused a legal payload");
            return report;
        }
    };
    report.check(length == KAT_FRAME.len(), "the probe frame is not 68 bytes");
    report.check(
        frame[..length] == KAT_FRAME[..],
        "the built frame does not match the independent known-answer vector",
    );

    match parse(&KAT_FRAME) {
        Ok(datagram) => {
            report.check(datagram.payload == PROBE_PAYLOAD, "round-trip lost the payload");
            report.check(
                datagram.source == source && datagram.destination == destination,
                "round-trip lost the addresses",
            );
            report.check(datagram.identification == 1, "round-trip lost the identification");
        }
        Err(error) => {
            report.check(false, "the known-answer frame did not parse");
            println!("[ETH] parse rejected the KAT as {}", error.as_str());
        }
    }
    report.check(
        checksum(&KAT_FRAME[ETHERNET_HEADER_LEN..ETHERNET_HEADER_LEN + IPV4_HEADER_LEN]) == 0,
        "the IPv4 header checksum does not validate",
    );

    let mut corrupted = KAT_FRAME;
    corrupted[65] ^= 0xFF; // inside the payload
    report.check(
        matches!(parse(&corrupted), Err(Reject::BadChecksum)),
        "a corrupted payload was not refused by the UDP checksum",
    );

    let mut corrupted = KAT_FRAME;
    corrupted[24] ^= 0x01; // inside the IPv4 header
    report.check(
        matches!(parse(&corrupted), Err(Reject::BadHeaderChecksum)),
        "a corrupted header was not refused by the IPv4 checksum",
    );

    let mut wrong_ethertype = KAT_FRAME;
    wrong_ethertype[12] = 0x86;
    wrong_ethertype[13] = 0xDD;
    report.check(
        matches!(parse(&wrong_ethertype), Err(Reject::NotIpv4)),
        "a non-IPv4 ethertype was accepted",
    );

    // The structural checks all run before the checksum, so these mutations only have to change
    // the field under test (the checksum is deliberately left stale).
    // Two halves of the fragment field, because they live in different bytes: an offset whose
    // high bits are zero (so the flags nibble still looks like a plain don't-fragment header) and
    // a more-fragments flag with a zero offset.
    let mut fragmented = KAT_FRAME;
    fragmented[21] = 0x01; // offset 1: `ip[7]` only, `ip[6]` unchanged
    report.check(
        matches!(parse(&fragmented), Err(Reject::Fragmented)),
        "a fragment whose offset lives in ip[7] was accepted as a whole datagram",
    );

    let mut more_fragments = KAT_FRAME;
    more_fragments[20] = 0x60; // flags: don't-fragment *and* more-fragments, offset 0
    report.check(
        matches!(parse(&more_fragments), Err(Reject::Fragmented)),
        "a more-fragments frame was accepted for reassembly this transport cannot do",
    );

    let mut tcp = KAT_FRAME;
    tcp[23] = 6; // protocol: TCP
    report.check(
        matches!(parse(&tcp), Err(Reject::NotUdp)),
        "a non-UDP protocol was accepted",
    );

    report.check(
        matches!(parse(&KAT_FRAME[..HEADER_LEN - 1]), Err(Reject::TooShort)),
        "a truncated frame was accepted",
    );

    let mut options = KAT_FRAME;
    options[14] = 0x46; // IHL 6: IPv4 options, which this transport does not interpret
    report.check(
        matches!(parse(&options), Err(Reject::UnsupportedHeader)),
        "an IPv4 header with options was interpreted",
    );

    let mut lying = KAT_FRAME;
    lying[16] = 0x00;
    lying[17] = 0x10; // total length 16, less than the two headers
    report.check(
        matches!(parse(&lying), Err(Reject::BadLength)),
        "a frame whose IPv4 length lies was accepted",
    );

    // The real payload: a sealed Vantablack wire frame, at the size limit.
    let mesh = [0x5Au8; MAX_PAYLOAD];
    match build(source, destination, 0x1234, &mesh, &mut frame) {
        Some(length) => {
            report.check(length == MAX_FRAME, "a 576-byte payload does not build a 618-byte frame");
            report.check(
                matches!(parse(&frame[..length]), Ok(datagram) if datagram.payload == &mesh[..]),
                "a 576-byte payload did not survive the round trip",
            );
        }
        None => report.check(false, "the builder refused a full-size mesh frame"),
    }

    // ARP: the request the independent builder generated for this profile, and the reply it
    // generated for it. Both are compared byte for byte, because an ARP reply that is one field
    // out is a reply that puts two hosts on the segment and resolves nothing.
    const ARP_REQUEST: [u8; ARP_FRAME_LEN] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x52, 0x55, // broadcast, sender 52:55:0a:00:02:02
        0x0a, 0x00, 0x02, 0x02, 0x08, 0x06, 0x00, 0x01, // ethertype ARP, hardware type 1
        0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x52, 0x55, // IPv4, 6/4 bytes, opcode 1 (request)
        0x0a, 0x00, 0x02, 0x02, 0x0a, 0x00, 0x02, 0x02, // sender MAC again, sender 10.0.2.2
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, // target MAC unknown, target 10.0.2.15
        0x02, 0x0f,
    ];
    const ARP_REPLY: [u8; ARP_FRAME_LEN] = [
        0x52, 0x55, 0x0a, 0x00, 0x02, 0x02, 0x52, 0x54, // to the requester, from this NIC
        0x00, 0x12, 0x34, 0x56, 0x08, 0x06, 0x00, 0x01,
        0x08, 0x00, 0x06, 0x04, 0x00, 0x02, 0x52, 0x54, // opcode 2 (reply)
        0x00, 0x12, 0x34, 0x56, 0x0a, 0x00, 0x02, 0x0f, // sender is this NIC at 10.0.2.15
        0x52, 0x55, 0x0a, 0x00, 0x02, 0x02, 0x0a, 0x00, // target is the requester
        0x02, 0x02,
    ];

    match parse_arp(&ARP_REQUEST) {
        Some(message) => {
            report.check(message.opcode == ARP_OPCODE_REQUEST, "the ARP request opcode is wrong");
            report.check(
                message.sender_mac == GATEWAY_MAC && message.sender_ip == GATEWAY_IP,
                "the ARP request's sender does not match the independent vector",
            );
            report.check(
                is_request_for(&message, GUEST_IP),
                "a request for this endpoint's address was not taken as ours",
            );
            report.check(
                !is_request_for(&message, [10, 0, 2, 99]),
                "a request for another address was answered as if it were ours",
            );
            let mut reply = [0u8; ARP_FRAME_LEN];
            match build_arp_reply([0x52, 0x54, 0x00, 0x12, 0x34, 0x56], GUEST_IP, &message, &mut reply)
            {
                Some(length) => {
                    report.check(length == ARP_FRAME_LEN, "the ARP reply is not 42 bytes");
                    report.check(
                        reply[..length] == ARP_REPLY[..],
                        "the built ARP reply does not match the independent vector",
                    );
                }
                None => report.check(false, "the ARP reply builder refused a 42-byte buffer"),
            }
        }
        None => report.check(false, "the pinned ARP request did not parse"),
    }
    report.check(parse_arp(&KAT_FRAME).is_none(), "an IPv4 frame was accepted as ARP");
    report.check(
        parse_arp(&ARP_REQUEST[..ARP_FRAME_LEN - 1]).is_none(),
        "a truncated ARP frame was accepted",
    );

    report.check(
        checksum(&[]) == 0xFFFF,
        "the ones-complement checksum of an empty span is not the identity",
    );
    report
}
