//! Vantablack mesh layer (KOS-NET-VANTABLACK-2026 §2, §3.1).
//!
//! The kernel has no direct IP path: every outbound byte the shell or a subsystem produces
//! leaves through this module, which turns it into erasure-sharded, authenticated privacy
//! frames for the Ring-3 Vantablack daemon. This file implements the Ring-0 half:
//!
//! * **Quantized wire geometry.** Every frame this layer emits is exactly
//!   [`WIRE_FRAME_LEN`] (576) bytes: a 33-byte Shamir share, an 8-byte message counter, a
//!   ShardSec record and a 16..64-byte hardware-entropy tail. Constant size removes packet
//!   length as a signal, and the tail removes the "empty tail" signal inside it.
//! * **ShardSec (§2.2).** Each Reed-Solomon shard is sealed under its own HKDF subkey
//!   ([`crypto::shard_subkey`], info `KOS-SHARD-KEY`) with a ChaCha20-Poly1305 tag. The
//!   associated data binds the whole frame header (message id, length, share, counter), the
//!   shard index, the record length and the entire entropy tail, so a shard moved to
//!   another carrier position, replayed under a different counter, or edited in its padding
//!   fails to verify *before* reconstruction memory is touched.
//! * **Byzantine isolation (§2.3).** A carrier that holds the subkeys can still seal a
//!   wrong codeword with a valid tag. All three pairs `(0,1)`, `(0,2)`, `(1,2)` are
//!   therefore evaluated and re-encoded against the shard they leave out; the pair that
//!   reproduces the third shard identifies the compromised route, which is severed, while
//!   pristine plaintext is rebuilt from the honest pair.
//! * **Replay window (§3.2).** Each peer carries its own 128-bit sliding window
//!   ([`KernelSessionGuard`]); a message counter is consumed when its first shard arrives,
//!   and every shard riding that counter is folded into the same window slot.
//! * **Cover traffic (§2.4).** When the link is idle, decoy frames are injected at
//!   Poisson-distributed intervals (one Bernoulli trial per tick, `p = 1 / interval`), so
//!   silence itself carries no information.
//!
//! Frames are handed to the transport through [`IpcPacketSender`]; until the Ring-3 NIC
//! driver lands, [`CaptureSender`] is the local wire, which is byte-identical to the real
//! egress path.

use crate::clock;
use crate::crypto::{
    self, shard_subkey, CryptoError, HANDSHAKE_BLOB_LEN, HANDSHAKE_SHARD_LEN, KEY_LEN, NONCE_LEN,
    RS_DATA_SHARDS, RS_PARITY_SHARDS, SHAMIR_THRESHOLD, TAG_LEN,
};
use crate::session::{KernelSessionGuard, SessionVerdict, WINDOW_BITS};
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;

// ---------------------------------------------------------------------------------------
// Wire geometry (offsets fixed by VANTABLACK_INTEGRATION.md §3.1)
// ---------------------------------------------------------------------------------------

/// Header plus target shard block, before the entropy tail is added.
pub const BASE_SIZE: usize = 512;
/// Largest entropy tail a frame carries; `BASE_SIZE + JITTER_MAX` is the wire size.
pub const JITTER_MAX: usize = 64;
/// The only frame size this layer emits, in either direction.
pub const WIRE_FRAME_LEN: usize = BASE_SIZE + JITTER_MAX; // 576

/// Frame id of the GHOST handshake (960-byte blob in three 480-byte shards).
pub const HANDSHAKE_ID: u8 = 255;
/// Frame id of a synthetic decoy frame; receivers drop it without surfacing it.
pub const COVER_ID: u8 = 254;

pub const OFFSET_MSG_ID: usize = 0;
pub const OFFSET_ORIG_LEN: usize = 1;
pub const OFFSET_SHARE_START: usize = 2;
pub const OFFSET_SHARE_END: usize = 35;
pub const OFFSET_COUNTER_START: usize = 35;
pub const OFFSET_COUNTER_END: usize = 43;
/// First byte of the ShardSec record: `index || plain_len_be || nonce || ct || tag`.
pub const OFFSET_SHARD_START: usize = 43;

/// Shard index byte inside the ShardSec record.
const RECORD_INDEX: usize = 0;
/// Declared plaintext length (big-endian `u16`) inside the ShardSec record.
const RECORD_PLAIN_LEN: usize = 1;
/// Nonce inside the ShardSec record.
const RECORD_NONCE: usize = 3;
/// Record header: index (1) + plaintext length (2) + nonce (12).
pub const SHARD_HEADER_LEN: usize = RECORD_NONCE + NONCE_LEN; // 15
/// Record header plus the authentication tag.
pub const SHARD_OVERHEAD: usize = SHARD_HEADER_LEN + TAG_LEN; // 31

/// Smallest and largest authenticated entropy tail per frame.
pub const MIN_TAIL_LEN: usize = 16;
pub const MAX_TAIL_LEN: usize = JITTER_MAX;

/// Reed-Solomon geometry: two data shards plus one parity shard.
pub const SHARD_COUNT: usize = RS_DATA_SHARDS + RS_PARITY_SHARDS;

/// Data shard block. Sized so that `43 + SHARD_OVERHEAD + 448 + 54 = 576` exactly.
pub const DATA_SHARD_LEN: usize = 448;
/// Payload budget of one mesh message (both data shards).
pub const MESH_MESSAGE_MAX: usize = DATA_SHARD_LEN * RS_DATA_SHARDS; // 896
/// Per-message authentication tag carried inside the coded message, ahead of the payload.
/// ShardSec authenticates each shard; this tag authenticates the *message*, which is what
/// lets the combinatorial pairwise test tell an honest reconstruction from a poisoned one.
pub const MESSAGE_TAG_LEN: usize = TAG_LEN;
/// Largest payload one mesh message can carry once the tag has taken its bytes.
pub const MESH_PAYLOAD_MAX: usize = MESH_MESSAGE_MAX - MESSAGE_TAG_LEN; // 880
/// Domain separator for the message authentication key derived from the session secret.
const MESSAGE_MAC_INFO: &[u8] = b"KOS-MESH-MESSAGE-MAC";
const MESSAGE_MAC_SALT: &[u8] = b"KELLER-OS mesh message separation";
/// Magic every GHOST handshake blob starts with.
const GHOST_MAGIC: &[u8] = b"GHOST_HANDSHAKE_";
/// Body of a synthetic decoy frame.
pub const COVER_BODY_LEN: usize = 64;

/// Refusals from a peer are counted; at this many, the route is severed automatically.
pub const ISOLATION_REFUSAL_LIMIT: u64 = 3;

/// The kernel node itself and the local Ring-3 Vantablack daemon it talks to.
pub const SELF_NODE: u8 = 0x01;
pub const RELAY_NODE: u8 = 0x02;

/// Shard block carried by a frame of this id: 480 bytes for the handshake blob halves, the
/// quantized 448-byte block for everything else.
pub fn shard_payload_len(msg_id: u8) -> usize {
    if msg_id == HANDSHAKE_ID {
        HANDSHAKE_SHARD_LEN
    } else {
        DATA_SHARD_LEN
    }
}

/// Tail length for a shard block, or `None` when the block cannot reach 576 bytes with a
/// tail inside `MIN_TAIL_LEN..=MAX_TAIL_LEN`.
pub fn tail_len_for(payload_len: usize) -> Option<usize> {
    let tail = WIRE_FRAME_LEN.checked_sub(OFFSET_SHARD_START + SHARD_OVERHEAD + payload_len)?;
    if (MIN_TAIL_LEN..=MAX_TAIL_LEN).contains(&tail) {
        Some(tail)
    } else {
        None
    }
}

/// Expected shard block for a message; `0` marks an `original_len` the framing cannot carry.
pub fn shard_len_for(msg_id: u8, original_len: usize) -> usize {
    if original_len > MESH_MESSAGE_MAX && msg_id != HANDSHAKE_ID {
        0
    } else {
        shard_payload_len(msg_id)
    }
}

/// Sequence counter of a raw frame (big-endian, bytes 35..43).
pub fn parse_counter(buf: &[u8]) -> u64 {
    let mut counter = [0u8; 8];
    counter.copy_from_slice(&buf[OFFSET_COUNTER_START..OFFSET_COUNTER_END]);
    u64::from_be_bytes(counter)
}

/// Carrier position the sender sealed a shard for.
pub fn parse_shard_index(buf: &[u8]) -> u8 {
    buf[OFFSET_SHARD_START + RECORD_INDEX]
}

/// Declared plaintext length of the ShardSec record.
pub fn parse_plain_len(buf: &[u8]) -> usize {
    let high = buf[OFFSET_SHARD_START + RECORD_PLAIN_LEN] as usize;
    let low = buf[OFFSET_SHARD_START + RECORD_PLAIN_LEN + 1] as usize;
    (high << 8) | low
}

/// Entropy tail length implied by the declared record length.
pub fn parse_tail_len(buf: &[u8]) -> usize {
    WIRE_FRAME_LEN.saturating_sub(OFFSET_SHARD_START + SHARD_OVERHEAD + parse_plain_len(buf))
}

/// Nonce derived from the message counter and the shard position: unique per
/// (subkey, message, shard) triple, so no nonce is ever reused under one subkey.
fn shard_nonce(counter: u64, shard_index: u8) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[0..8].copy_from_slice(&counter.to_be_bytes());
    nonce[8] = shard_index;
    nonce[9..12].copy_from_slice(b"SHD");
    nonce
}

/// The associated data of a frame: `header(43) || shard_index || plain_len_be || tail_len_be
/// || tail`. Built from the bytes on the wire in both directions, so every field a receiver
/// parses — including the entropy tail — is covered by the tag that is checked over it.
fn build_aad(frame: &[u8], shard_index: u8, plain_len: usize, tail: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(OFFSET_SHARD_START + 5 + tail.len());
    aad.extend_from_slice(&frame[..OFFSET_SHARD_START]);
    aad.push(shard_index);
    aad.extend_from_slice(&(plain_len as u16).to_be_bytes());
    aad.extend_from_slice(&(tail.len() as u16).to_be_bytes());
    aad.extend_from_slice(tail);
    aad
}

/// A 33-byte channel filler for the share field. The field is authenticated, but carries no
/// new Shamir share outside the handshake, so it is drawn fresh per frame for uniformity.
fn frame_filler() -> Vec<u8> {
    let mut filler = vec![0u8; OFFSET_SHARE_END - OFFSET_SHARE_START];
    crypto::hardware_rand_bytes(&mut filler);
    filler
}

/// HMAC tag over the message header and payload, keyed with the session-derived MAC key.
/// A reconstructed message is only delivered when this tag verifies.
fn message_tag(
    mac_key: &[u8; KEY_LEN],
    msg_id: u8,
    counter: u64,
    original_len: usize,
    payload: &[u8],
) -> [u8; MESSAGE_TAG_LEN] {
    let mut input = Vec::with_capacity(11 + payload.len());
    input.push(msg_id);
    input.extend_from_slice(&counter.to_be_bytes());
    input.extend_from_slice(&(original_len as u16).to_be_bytes());
    input.extend_from_slice(payload);
    let digest = crypto::hmac_sha256(mac_key, &input);
    crypto::wipe(&mut input);
    let mut tag = [0u8; MESSAGE_TAG_LEN];
    tag.copy_from_slice(&digest[..MESSAGE_TAG_LEN]);
    tag
}

// ---------------------------------------------------------------------------------------
// ShardSec: per-shard keying
// ---------------------------------------------------------------------------------------

/// ShardSec keying context: one HKDF subkey per Reed-Solomon shard index.
///
/// The master key is the mesh session secret (drawn from the DRBG for the local node, or
/// reconstructed from Shamir shares by the GHOST handshake); the subkeys never leave this
/// struct, and `wipe` clears both levels with volatile writes.
pub struct ShardSec {
    master: [u8; KEY_LEN],
    subkeys: [[u8; KEY_LEN]; SHARD_COUNT],
    /// Message authentication key, derived from the session secret with its own info string
    /// so the shard subkeys and the message tag never share key material.
    mac_key: [u8; KEY_LEN],
}

impl ShardSec {
    pub fn from_master(master: &[u8; KEY_LEN]) -> Self {
        let mut subkeys = [[0u8; KEY_LEN]; SHARD_COUNT];
        for (index, subkey) in subkeys.iter_mut().enumerate() {
            *subkey = shard_subkey(master, index as u8);
        }
        let mut mac_key = [0u8; KEY_LEN];
        crypto::hkdf_sha256(MESSAGE_MAC_SALT, master, MESSAGE_MAC_INFO, &mut mac_key);
        Self {
            master: *master,
            subkeys,
            mac_key,
        }
    }

    fn mac_key(&self) -> &[u8; KEY_LEN] {
        &self.mac_key
    }

    /// 32-bit fingerprint of the master key (first four bytes of its SHA-256), printed by
    /// the shell so two nodes can compare session keys without revealing them.
    pub fn fingerprint(&self) -> u32 {
        let digest = crypto::sha256(&self.master);
        u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]])
    }

    /// Fingerprint of one per-shard subkey (used to prove key agreement in the probe).
    pub fn subkey_fingerprint(&self, shard_index: u8) -> u32 {
        if shard_index as usize >= SHARD_COUNT {
            return 0;
        }
        let digest = crypto::sha256(&self.subkeys[shard_index as usize]);
        u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]])
    }

    /// Seals one shard: `index || plain_len || nonce || ciphertext || tag`.
    pub fn seal(
        &self,
        shard_index: u8,
        counter: u64,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Option<Vec<u8>> {
        if shard_index as usize >= SHARD_COUNT || plaintext.len() > u16::MAX as usize {
            return None;
        }
        let nonce = shard_nonce(counter, shard_index);
        let sealed = crypto::aead_seal(&self.subkeys[shard_index as usize], &nonce, aad, plaintext);
        let mut record = Vec::with_capacity(SHARD_OVERHEAD + plaintext.len());
        record.push(shard_index);
        record.extend_from_slice(&(plaintext.len() as u16).to_be_bytes());
        record.extend_from_slice(&nonce);
        record.extend_from_slice(&sealed);
        Some(record)
    }

    /// Verifies and opens one shard record. A record whose own index, length or nonce
    /// disagrees with the frame it arrived in cannot produce the tag it carries: the index
    /// selects the subkey, the record supplies the nonce and the AAD (which carries the frame
    /// header and therefore the counter) is checked by the tag itself.
    pub fn open(&self, shard_index: u8, aad: &[u8], record: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if shard_index as usize >= SHARD_COUNT || record.len() < SHARD_OVERHEAD {
            return Err(CryptoError::BadLength);
        }
        if record[RECORD_INDEX] != shard_index {
            return Err(CryptoError::BadShardLayout);
        }
        let plain_len = ((record[RECORD_PLAIN_LEN] as usize) << 8)
            | record[RECORD_PLAIN_LEN + 1] as usize;
        if record.len() != SHARD_OVERHEAD + plain_len {
            return Err(CryptoError::BadLength);
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&record[RECORD_NONCE..RECORD_NONCE + NONCE_LEN]);
        crypto::aead_open(
            &self.subkeys[shard_index as usize],
            &nonce,
            aad,
            &record[SHARD_HEADER_LEN..],
        )
    }

    /// Irreversibly clears the master key, all three subkeys and the message MAC key.
    pub fn wipe(&mut self) {
        crypto::wipe(&mut self.master);
        for subkey in self.subkeys.iter_mut() {
            crypto::wipe(subkey);
        }
        crypto::wipe(&mut self.mac_key);
    }
}

// ---------------------------------------------------------------------------------------
// Frame construction and transmission
// ---------------------------------------------------------------------------------------

/// Transport contract implemented by the Ring-3 Vantablack daemon: hand a wire frame to the
/// packet ring of `target_node`. Returns false when the frame could not be queued.
pub trait IpcPacketSender {
    fn send_via_ipc(&self, packet: &[u8], target_node: u32) -> bool;
}

/// Builds one wire frame: header, ShardSec record, entropy tail — exactly 576 bytes.
fn build_frame(
    sec: &ShardSec,
    msg_id: u8,
    original_len: usize,
    share: &[u8],
    counter: u64,
    shard_index: u8,
    plaintext: &[u8],
) -> Option<Vec<u8>> {
    if shard_index as usize >= SHARD_COUNT {
        return None;
    }
    if plaintext.len() != shard_payload_len(msg_id) || original_len > u8::MAX as usize {
        return None;
    }
    let tail_len = tail_len_for(plaintext.len())?;
    let tail_start = OFFSET_SHARD_START + SHARD_OVERHEAD + plaintext.len();

    let mut frame = vec![0u8; WIRE_FRAME_LEN];
    frame[OFFSET_MSG_ID] = msg_id;
    frame[OFFSET_ORIG_LEN] = original_len as u8;
    let share_len = core::cmp::min(share.len(), OFFSET_SHARE_END - OFFSET_SHARE_START);
    frame[OFFSET_SHARE_START..OFFSET_SHARE_START + share_len]
        .copy_from_slice(&share[..share_len]);
    frame[OFFSET_COUNTER_START..OFFSET_COUNTER_END].copy_from_slice(&counter.to_be_bytes());

    // The tail is random *and* authenticated, so an observer cannot separate frame classes
    // by its contents and an editor cannot change it without failing the tag.
    let mut tail = vec![0u8; tail_len];
    crypto::hardware_rand_bytes(&mut tail);
    frame[tail_start..].copy_from_slice(&tail);

    let aad = build_aad(&frame, shard_index, plaintext.len(), &tail);
    let record = sec.seal(shard_index, counter, &aad, plaintext)?;
    if record.len() != SHARD_OVERHEAD + plaintext.len() {
        return None;
    }
    frame[OFFSET_SHARD_START..OFFSET_SHARD_START + record.len()].copy_from_slice(&record);
    Some(frame)
}

/// Reed-Solomon-splits `payload` into the quantized data blocks and transmits the three
/// ShardSec-sealed frames. Returns the number of frames actually queued.
pub fn send_data_packets(
    sec: &ShardSec,
    msg_id: u8,
    payload: &[u8],
    counter: u64,
    sender: &dyn IpcPacketSender,
    target_node: u32,
) -> usize {
    if payload.len() > MESH_PAYLOAD_MAX || msg_id == HANDSHAKE_ID {
        return 0;
    }
    let (frames, _) = match encode_frames(sec, msg_id, payload.len(), payload, counter) {
        Some(encoded) => encoded,
        None => return 0,
    };
    let mut sent = 0;
    for frame in frames.iter() {
        if sender.send_via_ipc(frame, target_node) {
            sent += 1;
        }
    }
    sent
}

/// Splits the 960-byte GHOST handshake blob (`GHOST_HANDSHAKE_`) into two 480-byte data
/// shards plus one parity shard and transmits them. Each frame also carries one Shamir
/// share of the session secret in its authenticated header, so any two arriving frames are
/// enough to recover the session key.
pub fn send_handshake_packets(
    sec: &ShardSec,
    blob: &[u8],
    shares: &[Vec<u8>],
    counter: u64,
    sender: &dyn IpcPacketSender,
    target_node: u32,
) -> usize {
    if blob.len() != HANDSHAKE_SHARD_LEN * RS_DATA_SHARDS || shares.len() < SHARD_COUNT {
        return 0;
    }
    let mut padded = Vec::from(blob);
    let shards = match crypto::rs_encode(&mut padded) {
        Ok(shards) => shards,
        Err(_) => return 0,
    };
    if shards.len() != SHARD_COUNT {
        return 0;
    }
    let mut sent = 0;
    for (index, shard) in shards.iter().enumerate() {
        let frame = match build_frame(
            sec,
            HANDSHAKE_ID,
            0,
            &shares[index],
            counter,
            index as u8,
            shard,
        ) {
            Some(frame) => frame,
            None => return sent,
        };
        if sender.send_via_ipc(&frame, target_node) {
            sent += 1;
        }
    }
    sent
}

/// Encodes a payload into the three quantized shard blocks and seals each one. The coded
/// message is `tag(16) || payload` zero-padded to the message budget, so the parity shard
/// covers the tag and every pair reconstruction can be authenticated as a whole message.
fn encode_frames(
    sec: &ShardSec,
    msg_id: u8,
    original_len: usize,
    payload: &[u8],
    counter: u64,
) -> Option<(Vec<Vec<u8>>, Vec<Vec<u8>>)> {
    if payload.len() > MESH_PAYLOAD_MAX || msg_id == HANDSHAKE_ID {
        return None;
    }
    let tag = message_tag(sec.mac_key(), msg_id, counter, original_len, payload);
    let mut padded = vec![0u8; MESH_MESSAGE_MAX];
    padded[..MESSAGE_TAG_LEN].copy_from_slice(&tag);
    padded[MESSAGE_TAG_LEN..MESSAGE_TAG_LEN + payload.len()].copy_from_slice(payload);
    let shards = crypto::rs_encode(&mut padded).ok()?;
    if shards.len() != SHARD_COUNT {
        return None;
    }
    let mut frames = Vec::with_capacity(SHARD_COUNT);
    for (index, shard) in shards.iter().enumerate() {
        let filler = frame_filler();
        frames.push(build_frame(
            sec,
            msg_id,
            original_len,
            &filler,
            counter,
            index as u8,
            shard,
        )?);
    }
    Some((frames, shards))
}

/// Local wire: captures frames instead of transmitting them. Until the Ring-3 NIC driver
/// lands this is the exact path a real packet ring takes, which is what lets the mesh loop
/// (egress -> wire -> ingress) be verified in QEMU without hardware.
pub struct CaptureSender {
    frames: RefCell<Vec<Vec<u8>>>,
}

/// Bound on captured frames, so a stalled drain cannot grow the kernel heap.
pub const CAPTURE_DEPTH: usize = 64;

impl CaptureSender {
    pub fn new() -> Self {
        Self {
            frames: RefCell::new(Vec::new()),
        }
    }

    /// Removes and returns every frame handed to the sender since the last call.
    pub fn take(&self) -> Vec<Vec<u8>> {
        core::mem::take(&mut *self.frames.borrow_mut())
    }

    pub fn count(&self) -> usize {
        self.frames.borrow().len()
    }
}

impl IpcPacketSender for CaptureSender {
    fn send_via_ipc(&self, packet: &[u8], target_node: u32) -> bool {
        let _ = target_node;
        let mut frames = self.frames.borrow_mut();
        while frames.len() >= CAPTURE_DEPTH {
            frames.remove(0);
        }
        frames.push(Vec::from(packet));
        true
    }
}

// ---------------------------------------------------------------------------------------
// Ingress: refusal reasons and results
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshRefusal {
    /// Not a quantized frame, or a field outside the geometry this layer defines.
    Malformed,
    /// The source node is not in the peer table.
    UnknownPeer,
    /// No shard master key installed (never provisioned, or wiped).
    Unprovisioned,
    /// ShardSec tag failure: a swapped, relocated or edited shard.
    ShardTampered,
    /// The same shard position arrived twice for one message.
    DuplicateShard,
    /// Counter already recorded in the peer's replay window.
    Replayed,
    /// Counter fell out of the 128-counter window.
    OutOfWindow,
    /// The peer's session hit the idle or hard timeout.
    Expired,
    /// Pairwise verification found no honest majority.
    Inconsistent,
}

impl MeshRefusal {
    pub fn as_str(self) -> &'static str {
        match self {
            MeshRefusal::Malformed => "malformed",
            MeshRefusal::UnknownPeer => "unknown-peer",
            MeshRefusal::Unprovisioned => "unprovisioned",
            MeshRefusal::ShardTampered => "shard-tampered",
            MeshRefusal::DuplicateShard => "duplicate-shard",
            MeshRefusal::Replayed => "replay",
            MeshRefusal::OutOfWindow => "out-of-window",
            MeshRefusal::Expired => "expired",
            MeshRefusal::Inconsistent => "inconsistent",
        }
    }
}

impl From<SessionVerdict> for MeshRefusal {
    fn from(verdict: SessionVerdict) -> Self {
        match verdict {
            SessionVerdict::Accepted => MeshRefusal::Malformed,
            SessionVerdict::Replay => MeshRefusal::Replayed,
            SessionVerdict::Expired => MeshRefusal::Expired,
            SessionVerdict::OutOfWindow => MeshRefusal::OutOfWindow,
        }
    }
}

/// Outcome of feeding one wire frame to the ingress pipeline.
pub enum Ingest {
    /// A complete message came out of reconstruction.
    Delivered {
        msg_id: u8,
        payload: Vec<u8>,
        /// Shard position the pairwise test identified as Byzantine, if any.
        bad_shard: Option<u8>,
        /// Session secret recovered from the authenticated Shamir shares of a handshake.
        session_key: Option<[u8; KEY_LEN]>,
    },
    /// One shard verified and was held for the rest of the message.
    ShardSealed { shard_index: u8, remaining: usize },
    /// The frame was dropped; see [`MeshRefusal`].
    Refused(MeshRefusal),
}

// ---------------------------------------------------------------------------------------
// Combinatorial pairwise verification (§2.3)
// ---------------------------------------------------------------------------------------

/// Rebuilds the coded message from a reconstructed shard set: the two data shards, in order.
fn assemble_candidate(codeword: &[Vec<u8>; SHARD_COUNT]) -> Vec<u8> {
    let mut message = codeword[0].clone();
    message.extend_from_slice(&codeword[1]);
    message
}

/// True when `blob` is a GHOST handshake blob whose Ed25519 signature over its Kyber key
/// verifies. Handshake shards carry no message tag: the blob is signed by the peer's
/// long-term identity instead, and that signature is the pairwise test's anchor.
fn blob_is_authentic(blob: &[u8]) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};
    if blob.len() != HANDSHAKE_BLOB_LEN || &blob[..GHOST_MAGIC.len()] != GHOST_MAGIC {
        return false;
    }
    let key_bytes: [u8; 32] = match blob[848..880].try_into() {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let signature = match Signature::from_slice(&blob[880..944]) {
        Ok(signature) => signature,
        Err(_) => return false,
    };
    match VerifyingKey::from_bytes(&key_bytes) {
        Ok(key) => key.verify_strict(&blob[48..848], &signature).is_ok(),
        Err(_) => false,
    }
}

/// Authenticates one reconstruction. Data frames must carry a valid message tag over
/// `counter`/`msg_id`/`original_len`/payload; a handshake must carry a valid GHOST signature.
/// Returns the payload the caller may hand over when it verifies.
fn authenticate_candidate(
    candidate: &[u8],
    msg_id: u8,
    original_len: usize,
    counter: u64,
    sec: &ShardSec,
) -> Option<Vec<u8>> {
    if msg_id == HANDSHAKE_ID {
        if !blob_is_authentic(candidate) {
            return None;
        }
        return Some(Vec::from(candidate));
    }
    if candidate.len() != MESH_MESSAGE_MAX || original_len > MESH_PAYLOAD_MAX {
        return None;
    }
    let tag = &candidate[..MESSAGE_TAG_LEN];
    let payload = &candidate[MESSAGE_TAG_LEN..MESSAGE_TAG_LEN + original_len];
    let expected = message_tag(sec.mac_key(), msg_id, counter, original_len, payload);
    if !crypto::ct_eq(tag, &expected) {
        return None;
    }
    Some(Vec::from(payload))
}

/// Combinatorial pairwise verification (§2.3): all three pairs `(0,1)`, `(0,2)`, `(1,2)` are
/// reconstructed on their own and the resulting message is authenticated as a whole.
///
/// A message tag (or the handshake's Ed25519 signature) covers the complete coded message, so
/// a pair containing a corrupted shard reconstructs a message that fails authentication while
/// the honest pair verifies. That yields two properties at once: the delivered plaintext is
/// authenticated end to end, and the identity of the compromised route — the shard excluded
/// by the only verifying pair — is pinned without trusting any single carrier.
///
/// `Ok((payload, None))` means two or three pairs agreed (the message is authentic and no
/// route can be singled out); `Ok((payload, Some(index)))` means exactly one pair verified and
/// the remaining position is Byzantine; `Err` means no pair produced an authentic message.
///
/// A divergence confined to the coding padding leaves the authenticated message untouched, so
/// no route is accused for it: identification fires on changes that actually reach the
/// message, which is what keeps an honest-but-noisy carrier from being severed.
pub fn pairwise_verify(
    shards: &[Option<Vec<u8>>; SHARD_COUNT],
    msg_id: u8,
    original_len: usize,
    counter: u64,
    sec: &ShardSec,
) -> Result<(Vec<u8>, Option<u8>), CryptoError> {
    const PAIRS: [(usize, usize); SHARD_COUNT] = [(0, 1), (0, 2), (1, 2)];
    let mut verifiers: Vec<usize> = Vec::new();
    let mut payloads: [Option<Vec<u8>>; SHARD_COUNT] = [None, None, None];

    for (slot, (a, b)) in PAIRS.iter().enumerate() {
        let (a, b) = (*a, *b);
        let (first, second) = match (&shards[a], &shards[b]) {
            (Some(first), Some(second)) => (first.clone(), second.clone()),
            _ => continue,
        };
        let mut layout: [Option<Vec<u8>>; SHARD_COUNT] = [None, None, None];
        layout[a] = Some(first);
        layout[b] = Some(second);
        if crypto::rs_reconstruct(&mut layout).is_err() {
            continue;
        }
        let mut codeword: [Vec<u8>; SHARD_COUNT] = [Vec::new(), Vec::new(), Vec::new()];
        let mut complete = true;
        for (index, slot_shard) in layout.iter_mut().enumerate() {
            match slot_shard.take() {
                Some(shard) => codeword[index] = shard,
                None => complete = false,
            }
        }
        if !complete {
            continue;
        }

        let candidate = assemble_candidate(&codeword);
        if let Some(payload) = authenticate_candidate(&candidate, msg_id, original_len, counter, sec)
        {
            verifiers.push(slot);
            payloads[slot] = Some(payload);
        }
    }

    let first = match verifiers.first() {
        Some(slot) => *slot,
        None => return Err(CryptoError::BadShardLayout),
    };
    let payload = payloads[first].take().ok_or(CryptoError::BadShardLayout)?;

    let bad_shard = if verifiers.len() == 1 {
        let (a, b) = PAIRS[first];
        (0..SHARD_COUNT)
            .find(|index| *index != a && *index != b)
            .map(|index| index as u8)
    } else {
        None
    };
    Ok((payload, bad_shard))
}

// ---------------------------------------------------------------------------------------
// Cover traffic: Poisson-distributed decoy frames (§2.4)
// ---------------------------------------------------------------------------------------

/// Mean number of ticks between decoys at the default rate (500 ticks = 5 s, λ = 0.2/s).
pub const COVER_INTERVAL_TICKS: u64 = 500;
/// Upper bound on decoys injected by a single poll, so a long stall cannot burst.
pub const MAX_COVER_BURST: u64 = 4;

/// Poisson cover traffic, sampled on the 100 Hz tick.
///
/// A Poisson process with rate λ has independent arrivals in disjoint intervals, so
/// sampling it at the tick boundary is exactly one Bernoulli trial per tick with
/// `p = 1 - e^(-λ·Δt)`. For the small `λ·Δt` a decoy stream uses, `p ≈ λ·Δt`, and with
/// `p = 1 / interval` the waiting time is geometric with mean `interval` ticks. That keeps
/// the kernel free of floating point (no FPU state to save in the packet path) while
/// preserving the memoryless property that removes the silence signal: the probability of a
/// frame in the next tick does not depend on how long the link has been quiet.
pub struct CoverTraffic {
    interval_ticks: u64,
    cursor_tick: u64,
    started: bool,
    enabled: bool,
    due: u64,
    emitted: u64,
}

impl CoverTraffic {
    pub const fn new() -> Self {
        Self {
            interval_ticks: COVER_INTERVAL_TICKS,
            cursor_tick: 0,
            started: false,
            enabled: true,
            due: 0,
            emitted: 0,
        }
    }

    /// Explicit rate, in ticks between decoys on average (the probe uses 1).
    pub fn with_interval_ticks(interval_ticks: u64) -> Self {
        let mut cover = Self::new();
        cover.set_interval_ticks(interval_ticks);
        cover
    }

    pub fn set_interval_ticks(&mut self, interval_ticks: u64) {
        self.interval_ticks = core::cmp::max(1, interval_ticks);
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub fn interval_ticks(&self) -> u64 {
        self.interval_ticks
    }

    pub fn due(&self) -> u64 {
        self.due
    }

    pub fn emitted(&self) -> u64 {
        self.emitted
    }

    /// Consumes exactly one trial per elapsed tick and returns how many decoys came due.
    /// Because the cursor advances by tick rather than by call, polling the loop faster or
    /// slower than 100 Hz cannot change the arrival rate.
    pub fn poll(&mut self, now_ticks: u64) -> u64 {
        if !self.enabled {
            self.cursor_tick = now_ticks;
            self.started = true;
            return 0;
        }
        if !self.started {
            self.started = true;
            self.cursor_tick = now_ticks;
            return 0;
        }
        let mut fired = 0u64;
        while self.cursor_tick < now_ticks {
            self.cursor_tick += 1;
            if crypto::random_u64() % self.interval_ticks == 0 {
                self.due += 1;
                fired += 1;
            }
        }
        fired
    }

    /// Records decoys that were actually put on the wire.
    pub fn note_emitted(&mut self, count: u64) {
        self.emitted += count;
    }

    pub fn describe(&self) {
        let hundredths = 100 * clock::TICKS_PER_SECOND / self.interval_ticks;
        crate::println!(
            "[NET] cover: enabled={} interval={} ticks ({} s, lambda={}.{:02}/s) due={} emitted={}",
            self.enabled,
            self.interval_ticks,
            self.interval_ticks / clock::TICKS_PER_SECOND,
            hundredths / 100,
            hundredths % 100,
            self.due,
            self.emitted
        );
    }
}

// ---------------------------------------------------------------------------------------
// Per-peer state
// ---------------------------------------------------------------------------------------

/// One remote mesh node: its identity fingerprint, its own replay window and its tamper
/// record. Isolation is an egress decision — frames are no longer scheduled onto a severed
/// route, while ingress keeps verifying (that is how a quarantined route is either pinned as
/// malignant or cleared).
pub struct PeerState {
    pub node_id: u8,
    pub fingerprint: u32,
    pub session: KernelSessionGuard,
    pub frames_accepted: u64,
    pub frames_refused: u64,
    pub shards_refused: u64,
    pub messages_delivered: u64,
    pub byzantine_shards: u64,
    pub isolated: bool,
}

impl PeerState {
    fn new(node_id: u8, fingerprint: u32) -> Self {
        Self {
            node_id,
            fingerprint,
            session: KernelSessionGuard::open(),
            frames_accepted: 0,
            frames_refused: 0,
            shards_refused: 0,
            messages_delivered: 0,
            byzantine_shards: 0,
            isolated: false,
        }
    }
}

/// One message being reassembled: the kernel holds a single 576-byte bounce budget, so an
/// interleaved stream abandons the partial instead of queuing unbounded state.
struct Assembly {
    node_id: u8,
    counter: u64,
    msg_id: u8,
    original_len: usize,
    shards: [Option<Vec<u8>>; SHARD_COUNT],
    shares: [Option<Vec<u8>>; SHARD_COUNT],
}

impl Assembly {
    fn new(node_id: u8, counter: u64, msg_id: u8, original_len: usize) -> Self {
        Self {
            node_id,
            counter,
            msg_id,
            original_len,
            shards: [None, None, None],
            shares: [None, None, None],
        }
    }

    fn matches(&self, node_id: u8, counter: u64, msg_id: u8, original_len: usize) -> bool {
        self.node_id == node_id
            && self.counter == counter
            && self.msg_id == msg_id
            && self.original_len == original_len
    }

    fn remaining(&self) -> usize {
        self.shards.iter().filter(|shard| shard.is_none()).count()
    }

    fn wipe(&mut self) {
        for shard in self.shards.iter_mut() {
            if let Some(bytes) = shard.as_mut() {
                crypto::wipe(bytes);
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// The mesh node
// ---------------------------------------------------------------------------------------

pub struct KellerNet {
    pub node_id: u8,
    sec: ShardSec,
    provisioned: bool,
    peers: Vec<PeerState>,
    assembly: Option<Assembly>,
    tx_counter: u64,
    frames_sent: u64,
    frames_received: u64,
    shards_sealed: u64,
    messages_delivered: u64,
    handshakes_delivered: u64,
    cover_delivered: u64,
    shards_refused: u64,
    replays: u64,
    out_of_window: u64,
    byzantine_shards: u64,
    abandoned: u64,
    cover: CoverTraffic,
}

impl KellerNet {
    pub fn new(node_id: u8) -> Self {
        Self {
            node_id,
            sec: ShardSec::from_master(&[0u8; KEY_LEN]),
            provisioned: false,
            peers: Vec::new(),
            assembly: None,
            tx_counter: 0,
            frames_sent: 0,
            frames_received: 0,
            shards_sealed: 0,
            messages_delivered: 0,
            handshakes_delivered: 0,
            cover_delivered: 0,
            shards_refused: 0,
            replays: 0,
            out_of_window: 0,
            byzantine_shards: 0,
            abandoned: 0,
            cover: CoverTraffic::new(),
        }
    }

    /// Draws the session master key from the kernel DRBG and derives the ShardSec subkeys.
    pub fn provision(&mut self) -> u32 {
        let master = crypto::random_key();
        self.adopt_master(&master)
    }

    /// Installs a session master key (from the DRBG, or reconstructed by the handshake) and
    /// derives the three per-shard subkeys.
    pub fn adopt_master(&mut self, master: &[u8; KEY_LEN]) -> u32 {
        self.sec = ShardSec::from_master(master);
        self.provisioned = true;
        self.sec.fingerprint()
    }

    /// Recovers the session secret from Shamir shares (any two of the three) and installs it,
    /// which is how a GHOST handshake converges both endpoints on the same subkey set.
    pub fn adopt_handshake_key(&mut self, shares: &[&[u8]]) -> bool {
        if shares.len() < SHAMIR_THRESHOLD {
            return false;
        }
        match crypto::shamir_join(shares) {
            Ok(secret) => {
                self.adopt_master(&secret);
                true
            }
            Err(_) => false,
        }
    }

    pub fn is_provisioned(&self) -> bool {
        self.provisioned
    }

    pub fn key_fingerprint(&self) -> u32 {
        self.sec.fingerprint()
    }

    /// Registers (or re-fingerprints) a peer. The fingerprint is the first four bytes of the
    /// SHA-256 of the peer's GHOST handshake blob; an empty blob registers it as unknown.
    pub fn register_peer(&mut self, node_id: u8, handshake_blob: &[u8]) -> u32 {
        let fingerprint = if handshake_blob.is_empty() {
            0
        } else {
            let digest = crypto::sha256(handshake_blob);
            u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]])
        };
        if let Some(peer) = self.peers.iter_mut().find(|peer| peer.node_id == node_id) {
            peer.fingerprint = fingerprint;
            return fingerprint;
        }
        self.peers.push(PeerState::new(node_id, fingerprint));
        fingerprint
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn isolated_peers(&self) -> usize {
        self.peers.iter().filter(|peer| peer.isolated).count()
    }

    pub fn peer_isolated(&self, node_id: u8) -> bool {
        self.peers
            .iter()
            .find(|peer| peer.node_id == node_id)
            .map(|peer| peer.isolated)
            .unwrap_or(false)
    }

    /// Severs a route: no further frames are scheduled onto it.
    pub fn isolate_peer(&mut self, node_id: u8) {
        if let Some(peer) = self.peers.iter_mut().find(|peer| peer.node_id == node_id) {
            peer.isolated = true;
        }
    }

    /// Route recalculation: clears a peer's isolation and its tamper budget, so a carrier
    /// that was hot-swapped in for a severed path starts from a clean slate.
    pub fn rehabilitate_peer(&mut self, node_id: u8) -> bool {
        match self.peers.iter_mut().find(|peer| peer.node_id == node_id) {
            Some(peer) => {
                peer.isolated = false;
                peer.shards_refused = 0;
                true
            }
            None => false,
        }
    }

    fn peer_state_mut(&mut self, node_id: u8) -> Option<&mut PeerState> {
        self.peers.iter_mut().find(|peer| peer.node_id == node_id)
    }

    pub fn frames_sent(&self) -> u64 {
        self.frames_sent
    }

    pub fn frames_received(&self) -> u64 {
        self.frames_received
    }

    pub fn messages_delivered(&self) -> u64 {
        self.messages_delivered
    }

    pub fn handshakes_delivered(&self) -> u64 {
        self.handshakes_delivered
    }

    pub fn cover_delivered(&self) -> u64 {
        self.cover_delivered
    }

    pub fn shards_refused(&self) -> u64 {
        self.shards_refused
    }

    pub fn replays(&self) -> u64 {
        self.replays
    }

    pub fn out_of_window(&self) -> u64 {
        self.out_of_window
    }

    pub fn byzantine_shards(&self) -> u64 {
        self.byzantine_shards
    }

    pub fn abandoned(&self) -> u64 {
        self.abandoned
    }

    pub fn cover(&self) -> &CoverTraffic {
        &self.cover
    }

    /// Next message counter. Monotonic, so no (subkey, nonce) pair is ever repeated.
    fn next_counter(&mut self) -> u64 {
        self.tx_counter += 1;
        self.tx_counter
    }

    /// Transmits one message: Reed-Solomon split, ShardSec seal, three quantized frames.
    pub fn send_message(
        &mut self,
        msg_id: u8,
        payload: &[u8],
        sender: &dyn IpcPacketSender,
        target_node: u8,
    ) -> usize {
        if !self.provisioned || payload.len() > MESH_PAYLOAD_MAX || msg_id == HANDSHAKE_ID {
            return 0;
        }
        // A severed route carries no egress traffic; an unregistered target is still framed,
        // because routing to a peer we have no state for is the daemon's decision, not ours.
        let routable = match self.peers.iter().find(|peer| peer.node_id == target_node) {
            Some(peer) => !peer.isolated,
            None => true,
        };
        if !routable {
            return 0;
        }
        let counter = self.next_counter();
        let sent = send_data_packets(
            &self.sec,
            msg_id,
            payload,
            counter,
            sender,
            target_node as u32,
        );
        self.frames_sent += sent as u64;
        sent
    }

    /// Transmits a GHOST handshake: the 960-byte blob in three sealed 480-byte shards, each
    /// frame carrying one Shamir share of the session secret.
    pub fn send_handshake(
        &mut self,
        blob: &[u8],
        shares: &[Vec<u8>],
        sender: &dyn IpcPacketSender,
        target_node: u8,
    ) -> usize {
        if !self.provisioned {
            return 0;
        }
        let counter = self.next_counter();
        let sent = send_handshake_packets(
            &self.sec,
            blob,
            shares,
            counter,
            sender,
            target_node as u32,
        );
        self.frames_sent += sent as u64;
        sent
    }

    /// Injects decoys for every arrival the Poisson sampler produced since the last poll and
    /// returns how many frames went out. Decoys are indistinguishable from data frames on
    /// the wire: same size, same sealing, same tail.
    pub fn cover_poll(
        &mut self,
        now_ticks: u64,
        sender: &dyn IpcPacketSender,
        target_node: u8,
    ) -> u64 {
        let due = self.cover.poll(now_ticks);
        if due == 0 || !self.provisioned {
            return 0;
        }
        let mut emitted = 0u64;
        let mut body = vec![0u8; COVER_BODY_LEN];
        for _ in 0..core::cmp::min(due, MAX_COVER_BURST) {
            crypto::hardware_rand_bytes(&mut body);
            if self.send_message(COVER_ID, &body, sender, target_node) == SHARD_COUNT {
                emitted += 1;
            }
        }
        crypto::wipe(&mut body);
        self.cover.note_emitted(emitted);
        emitted
    }

    /// Feeds one wire frame through the ingress pipeline: geometry, peer window, ShardSec
    /// tag, then combinatorial pairwise verification on the completed message.
    pub fn ingest_from(&mut self, node_id: u8, frame: &[u8]) -> Ingest {
        self.frames_received += 1;

        if !self.provisioned {
            return Ingest::Refused(MeshRefusal::Unprovisioned);
        }
        if frame.len() != WIRE_FRAME_LEN {
            return Ingest::Refused(MeshRefusal::Malformed);
        }
        let msg_id = frame[OFFSET_MSG_ID];
        let original_len = frame[OFFSET_ORIG_LEN] as usize;
        let counter = parse_counter(frame);
        let shard_index = parse_shard_index(frame);
        if shard_index as usize >= SHARD_COUNT {
            return Ingest::Refused(MeshRefusal::Malformed);
        }
        // One check covers both a shard block that is not the block this frame id uses and an
        // `original_len` the message budget cannot carry (`shard_len_for` reports 0 for it).
        let plain_len = parse_plain_len(frame);
        if shard_len_for(msg_id, original_len) != plain_len {
            return Ingest::Refused(MeshRefusal::Malformed);
        }
        let tail_start = OFFSET_SHARD_START + SHARD_OVERHEAD + plain_len;
        if tail_start + MIN_TAIL_LEN > WIRE_FRAME_LEN {
            return Ingest::Refused(MeshRefusal::Malformed);
        }

        let peer_index = match self.peers.iter().position(|peer| peer.node_id == node_id) {
            Some(index) => index,
            None => return Ingest::Refused(MeshRefusal::UnknownPeer),
        };

        // A shard of the message already in flight is folded into its window slot; the first
        // shard of a new message has to pass the peer's 128-bit sliding window. The window is
        // consulted before any decryption, so a replayed or stale message costs no AEAD work.
        let continuation = match &self.assembly {
            Some(assembly) => assembly.matches(node_id, counter, msg_id, original_len),
            None => false,
        };
        if !continuation {
            let verdict = self.peers[peer_index].session.accept(counter);
            if verdict != SessionVerdict::Accepted {
                let refusal = MeshRefusal::from(verdict);
                return self.refuse(peer_index, refusal);
            }
            if let Some(mut stale) = self.assembly.take() {
                stale.wipe();
                self.abandoned += 1;
            }
            self.assembly = Some(Assembly::new(node_id, counter, msg_id, original_len));
        }

        let aad = build_aad(
            frame,
            shard_index,
            plain_len,
            &frame[tail_start..WIRE_FRAME_LEN],
        );
        let record = &frame[OFFSET_SHARD_START..tail_start];
        let plaintext = match self.sec.open(shard_index, &aad, record) {
            Ok(plaintext) => plaintext,
            Err(_) => {
                self.shards_refused += 1;
                return self.refuse(peer_index, MeshRefusal::ShardTampered);
            }
        };
        self.shards_sealed += 1;

        let duplicate = match self.assembly.as_ref() {
            Some(assembly) => assembly.shards[shard_index as usize].is_some(),
            None => return Ingest::Refused(MeshRefusal::Malformed),
        };
        if duplicate {
            let mut discarded = plaintext;
            crypto::wipe(&mut discarded);
            return self.refuse(peer_index, MeshRefusal::DuplicateShard);
        }

        let complete = {
            let assembly = match self.assembly.as_mut() {
                Some(assembly) => assembly,
                None => return Ingest::Refused(MeshRefusal::Malformed),
            };
            assembly.shards[shard_index as usize] = Some(plaintext);
            // The Shamir share rides in the authenticated 43-byte header, so it is as
            // trustworthy as the shard it arrived with.
            assembly.shares[shard_index as usize] =
                Some(Vec::from(&frame[OFFSET_SHARE_START..OFFSET_SHARE_END]));
            assembly.remaining() == 0
        };

        if !complete {
            let remaining = self
                .assembly
                .as_ref()
                .map(|assembly| assembly.remaining())
                .unwrap_or(0);
            self.peers[peer_index].frames_accepted += 1;
            return Ingest::ShardSealed {
                shard_index,
                remaining,
            };
        }

        let mut assembly = match self.assembly.take() {
            Some(assembly) => assembly,
            None => return Ingest::Refused(MeshRefusal::Malformed),
        };
        let msg_id_out = assembly.msg_id;
        let verified = pairwise_verify(
            &assembly.shards,
            msg_id_out,
            assembly.original_len,
            counter,
            &self.sec,
        );
        let session_key = if msg_id_out == HANDSHAKE_ID {
            self.join_shares(&assembly.shares)
        } else {
            None
        };
        match verified {
            Ok((payload, bad_shard)) => {
                if let Some(index) = bad_shard {
                    if let Some(shard) = assembly.shards[index as usize].as_mut() {
                        crypto::wipe(shard);
                    }
                    self.byzantine_shards += 1;
                    if let Some(peer) = self.peers.get_mut(peer_index) {
                        peer.byzantine_shards += 1;
                        peer.shards_refused += 1;
                    }
                    self.isolate_peer(node_id);
                }
                assembly.wipe();
                if let Some(peer) = self.peers.get_mut(peer_index) {
                    peer.frames_accepted += 1;
                    peer.messages_delivered += 1;
                }
                if msg_id_out == HANDSHAKE_ID {
                    self.handshakes_delivered += 1;
                } else if msg_id_out == COVER_ID {
                    self.cover_delivered += 1;
                } else {
                    self.messages_delivered += 1;
                }
                Ingest::Delivered {
                    msg_id: msg_id_out,
                    payload,
                    bad_shard,
                    session_key,
                }
            }
            Err(_) => {
                assembly.wipe();
                self.refuse(peer_index, MeshRefusal::Inconsistent)
            }
        }
    }

    /// Counts a refusal against the peer and severs the route once the tamper budget is
    /// spent: an honest carrier loses no frames, so the budget is never reached by chance.
    fn refuse(&mut self, peer_index: usize, refusal: MeshRefusal) -> Ingest {
        if let Some(peer) = self.peers.get_mut(peer_index) {
            peer.frames_refused += 1;
            if refusal == MeshRefusal::ShardTampered {
                peer.shards_refused += 1;
            }
            if peer.shards_refused >= ISOLATION_REFUSAL_LIMIT {
                peer.isolated = true;
            }
        }
        match refusal {
            MeshRefusal::Replayed => self.replays += 1,
            MeshRefusal::OutOfWindow => self.out_of_window += 1,
            _ => {}
        }
        Ingest::Refused(refusal)
    }

    /// Recovers the session secret from the authenticated Shamir shares a handshake carried;
    /// any two of the three frames are enough, so one lost carrier does not break the key
    /// agreement (which is what the RS(2,1) sharding of the blob buys as well).
    fn join_shares(&self, shares: &[Option<Vec<u8>>; SHARD_COUNT]) -> Option<[u8; KEY_LEN]> {
        let mut present: Vec<&[u8]> = Vec::new();
        let share_len = OFFSET_SHARE_END - OFFSET_SHARE_START;
        for share in shares.iter().flatten() {
            if share.len() == share_len {
                present.push(share.as_slice());
            }
        }
        if present.len() < SHAMIR_THRESHOLD {
            return None;
        }
        crypto::shamir_join(&present).ok()
    }

    pub fn describe(&self) {
        crate::println!(
            "[NET] node={} provisioned={} master-fp={:#010x} peers={} isolated={} tx-counter={}",
            self.node_id,
            self.provisioned,
            self.sec.fingerprint(),
            self.peers.len(),
            self.isolated_peers(),
            self.tx_counter
        );
        crate::println!(
            "[NET] frames sent={} received={} sealed-shards={} messages={} handshakes={} cover-in={}",
            self.frames_sent,
            self.frames_received,
            self.shards_sealed,
            self.messages_delivered,
            self.handshakes_delivered,
            self.cover_delivered
        );
        crate::println!(
            "[NET] refused shards={} replays={} out-of-window={} byzantine={} abandoned={} wire={} bytes",
            self.shards_refused,
            self.replays,
            self.out_of_window,
            self.byzantine_shards,
            self.abandoned,
            WIRE_FRAME_LEN
        );
        self.cover.describe();
        for peer in self.peers.iter() {
            crate::println!(
                "[NET] peer {} fp={:#010x} accepted={} refused={} delivered={} byzantine={} isolated={} v_max={}",
                peer.node_id,
                peer.fingerprint,
                peer.frames_accepted,
                peer.frames_refused,
                peer.messages_delivered,
                peer.byzantine_shards,
                peer.isolated,
                peer.session.highest_counter()
            );
        }
    }

    /// Irreversibly clears the mesh: session key, subkeys, peer windows, partial assembly
    /// and counters. Registered as a panic scrub hook, next to the vault purge.
    pub fn wipe(&mut self) {
        self.sec.wipe();
        if let Some(mut assembly) = self.assembly.take() {
            assembly.wipe();
        }
        self.peers.clear();
        self.provisioned = false;
        self.tx_counter = 0;
        self.frames_sent = 0;
        self.frames_received = 0;
        self.shards_sealed = 0;
        self.messages_delivered = 0;
        self.handshakes_delivered = 0;
        self.cover_delivered = 0;
        self.shards_refused = 0;
        self.replays = 0;
        self.out_of_window = 0;
        self.byzantine_shards = 0;
        self.abandoned = 0;
        self.cover = CoverTraffic::new();
        unsafe {
            core::ptr::write_volatile(&mut self.node_id, 0);
        }
    }
}

// ---------------------------------------------------------------------------------------
// Mesh self-test
// ---------------------------------------------------------------------------------------

/// Node ids used by the probe; kept away from [`SELF_NODE`] and [`RELAY_NODE`].
pub const PROBE_NODE: u8 = 0xFE;
pub const PROBE_PEER: u8 = 0xFD;
pub const PROBE_PEER_ISOLATION: u8 = 0xFC;

pub struct MeshReport {
    pub passed: u32,
    pub failed: u32,
    pub failures: Vec<&'static str>,
}

impl MeshReport {
    fn new() -> Self {
        Self {
            passed: 0,
            failed: 0,
            failures: Vec::new(),
        }
    }

    fn record(&mut self, name: &'static str, ok: bool) {
        if ok {
            self.passed += 1;
        } else {
            self.failed += 1;
            self.failures.push(name);
        }
    }
}

/// Encodes and seals a probe message exactly the way the egress path does, returning the
/// three frames and the reused shard blocks so individual attacks can be mounted.
fn probe_frames(
    sec: &ShardSec,
    msg_id: u8,
    original_len: usize,
    payload: &[u8],
    counter: u64,
) -> Option<(Vec<Vec<u8>>, Vec<Vec<u8>>)> {
    encode_frames(sec, msg_id, original_len, payload, counter)
}

/// Runs the mesh pipeline on a scratch node (its own DRBG master key and peer table) so the
/// live node's state is untouched. Covers: round trip, shard swap, index swap, counter
/// swap, tail tamper, duplicate shard, replay, window boundary, Byzantine isolation,
/// handshake key agreement, Poisson cover traffic and the wipe path.
pub fn self_test() -> MeshReport {
    let mut report = MeshReport::new();
    let wire = CaptureSender::new();
    let mut node = KellerNet::new(PROBE_NODE);
    node.provision();
    node.register_peer(PROBE_PEER, b"KOS-VANTABLACK-PROBE-PEER");
    node.register_peer(PROBE_PEER_ISOLATION, b"KOS-VANTABLACK-PROBE-ISOLATION");

    let payload = b"KELLER-OS VANTABLACK MESH ROUND-TRIP PROBE";
    let probe_id = 0x11;
    let record_span = OFFSET_SHARD_START + SHARD_OVERHEAD + DATA_SHARD_LEN;

    // 1. Round trip: a message split, sealed, quantized and reassembled.
    let sent = node.send_message(probe_id, payload, &wire, PROBE_PEER);
    let frames = wire.take();
    let mut delivered: Option<Vec<u8>> = None;
    let mut refused = 0;
    for frame in frames.iter() {
        match node.ingest_from(PROBE_PEER, frame) {
            Ingest::Delivered { payload, .. } => delivered = Some(payload),
            Ingest::ShardSealed { .. } => {}
            Ingest::Refused(_) => refused += 1,
        }
    }
    report.record(
        "round-trip",
        sent == SHARD_COUNT
            && frames.len() == SHARD_COUNT
            && refused == 0
            && frames.iter().all(|frame| frame.len() == WIRE_FRAME_LEN)
            && frames.iter().all(|frame| parse_tail_len(frame) == 54)
            && delivered.as_deref() == Some(&payload[..]),
    );

    // 2. Shard swap: shard 0's sealed bytes placed at shard 1's carrier position. The
    //    position selects the subkey, the nonce and the AAD, so the tag cannot match.
    let second = node.next_counter();
    let (message, shards) = match probe_frames(&node.sec, probe_id, payload.len(), payload, second)
    {
        Some(encoded) => encoded,
        None => (Vec::new(), Vec::new()),
    };
    let swap_ok = message.len() == SHARD_COUNT && !shards.is_empty() && {
        let mut swapped = message[1].clone();
        let source = message[0][OFFSET_SHARD_START + SHARD_HEADER_LEN..record_span].to_vec();
        swapped[OFFSET_SHARD_START + SHARD_HEADER_LEN..record_span].copy_from_slice(&source);
        matches!(
            node.ingest_from(PROBE_PEER, &swapped),
            Ingest::Refused(MeshRefusal::ShardTampered)
        )
    };
    report.record("shard-swap", swap_ok);

    // 3. Index swap: the record's own index byte edited, so the frame claims another
    //    position (and therefore another subkey) than the one it was sealed for.
    let index_ok = message.len() == SHARD_COUNT && {
        let mut relocated = message[0].clone();
        relocated[OFFSET_SHARD_START + RECORD_INDEX] = 1;
        matches!(
            node.ingest_from(PROBE_PEER, &relocated),
            Ingest::Refused(MeshRefusal::ShardTampered)
        )
    };
    report.record("index-swap", index_ok);

    // 4. Counter swap: shard 2 of one message carried in the frame of another. The counter
    //    is inside the authenticated header, so a stale shard cannot be re-fenced.
    let third = node.next_counter();
    let counter_ok = match probe_frames(&node.sec, probe_id, payload.len(), payload, third) {
        Some((other, _)) => {
            let mut crossed = other[2].clone();
            let source = message[2][OFFSET_SHARD_START..record_span].to_vec();
            crossed[OFFSET_SHARD_START..record_span].copy_from_slice(&source);
            matches!(
                node.ingest_from(PROBE_PEER, &crossed),
                Ingest::Refused(MeshRefusal::ShardTampered)
            )
        }
        None => false,
    };
    report.record("counter-swap", counter_ok);

    // 5. Tail tamper: the entropy tail is associated data, so a flipped padding bit voids
    //    the frame (and the <<no empty tail>> uniformity cannot be stripped either).
    let tail_ok = match probe_frames(&node.sec, probe_id, payload.len(), payload, third) {
        Some((other, _)) => {
            let mut edited = other[1].clone();
            let tail_start = OFFSET_SHARD_START + SHARD_OVERHEAD + DATA_SHARD_LEN;
            edited[tail_start] ^= 0x80;
            matches!(
                node.ingest_from(PROBE_PEER, &edited),
                Ingest::Refused(MeshRefusal::ShardTampered)
            )
        }
        None => false,
    };
    report.record("tail-tamper", tail_ok);

    // 6. Duplicate shard: the same carrier position twice inside one message.
    let fourth = node.next_counter();
    let duplicate_ok = match probe_frames(&node.sec, probe_id, payload.len(), payload, fourth) {
        Some((other, _)) => {
            let _ = node.ingest_from(PROBE_PEER_ISOLATION, &other[0]);
            matches!(
                node.ingest_from(PROBE_PEER_ISOLATION, &other[0]),
                Ingest::Refused(MeshRefusal::DuplicateShard)
            )
        }
        None => false,
    };
    report.record("duplicate-shard", duplicate_ok);

    // 7. Replay: a delivered message replayed frame by frame hits the window.
    let fifth = node.next_counter();
    let replay_ok = match probe_frames(&node.sec, probe_id, payload.len(), payload, fifth) {
        Some((other, _)) => {
            let mut deliveries = 0;
            for frame in other.iter() {
                if let Ingest::Delivered { .. } = node.ingest_from(PROBE_PEER_ISOLATION, frame) {
                    deliveries += 1;
                }
            }
            deliveries == 1
                && matches!(
                    node.ingest_from(PROBE_PEER_ISOLATION, &other[0]),
                    Ingest::Refused(MeshRefusal::Replayed)
                )
        }
        None => false,
    };
    report.record("replay", replay_ok);

    // 8. Window boundary: 128 counters of later traffic push the replayed frame out.
    let window_ok = match probe_frames(&node.sec, probe_id, payload.len(), payload, fifth) {
        Some((stale, _)) => {
            let now = clock::uptime_ms();
            let jump = fifth + WINDOW_BITS;
            let advanced = match node.peer_state_mut(PROBE_PEER_ISOLATION) {
                Some(peer) => peer.session.accept_at(jump, now) == SessionVerdict::Accepted,
                None => false,
            };
            let behind = match node.peer_state_mut(PROBE_PEER_ISOLATION) {
                Some(peer) => peer.session.highest_counter().saturating_sub(fifth),
                None => 0,
            };
            advanced
                && behind == WINDOW_BITS
                && matches!(
                    node.ingest_from(PROBE_PEER_ISOLATION, &stale[2]),
                    Ingest::Refused(MeshRefusal::OutOfWindow)
                )
        }
        None => false,
    };
    report.record("window-boundary", window_ok);

    // 9. Byzantine isolation: a carrier that holds the shard subkeys can seal a wrong shard
    //    with a *valid* ShardSec tag, so per-shard authentication cannot see it. The
    //    combinatorial pairwise test must pin exactly that route and still deliver the
    //    pristine plaintext out of the honest pair — and must stay silent when the divergence
    //    cannot reach the authenticated message.
    let byzantine_ok = {
        // (a) The flipped byte is inside the message tag, so the message really changes: the
        //     honest pair is (1,2) and the accusation has to land on shard 0.
        let counter = node.next_counter();
        let accused = match probe_frames(&node.sec, probe_id, payload.len(), payload, counter) {
            Some((honest, shards)) => {
                let mut poisoned = shards[0].clone();
                poisoned[0] ^= 0x01;
                let share = Vec::from(&honest[0][OFFSET_SHARE_START..OFFSET_SHARE_END]);
                let forged = build_frame(
                    &node.sec,
                    probe_id,
                    payload.len(),
                    &share,
                    counter,
                    0,
                    &poisoned,
                )
                .unwrap_or_default();
                let combo = [forged, honest[1].clone(), honest[2].clone()];
                let mut verdict: Option<(Option<u8>, Vec<u8>)> = None;
                for frame in combo.iter() {
                    if let Ingest::Delivered {
                        bad_shard, payload, ..
                    } = node.ingest_from(PROBE_PEER_ISOLATION, frame)
                    {
                        verdict = Some((bad_shard, payload));
                    }
                }
                matches!(&verdict, Some((Some(0), bytes)) if bytes.as_slice() == &payload[..])
                    && node.byzantine_shards() == 1
                    && node.peer_isolated(PROBE_PEER_ISOLATION)
            }
            None => false,
        };

        // (b) The same shard position, but the flipped byte is coding padding: the
        //     authenticated message is byte-identical, so no route may be accused for it.
        let counter = node.next_counter();
        let padding_ok = match probe_frames(&node.sec, probe_id, payload.len(), payload, counter) {
            Some((honest, shards)) => {
                let mut poisoned = shards[2].clone();
                let last = poisoned.len() - 1;
                poisoned[last] ^= 0x01;
                let share = Vec::from(&honest[2][OFFSET_SHARE_START..OFFSET_SHARE_END]);
                let forged = build_frame(
                    &node.sec,
                    probe_id,
                    payload.len(),
                    &share,
                    counter,
                    2,
                    &poisoned,
                )
                .unwrap_or_default();
                let combo = [honest[0].clone(), honest[1].clone(), forged];
                let mut verdict: Option<(Option<u8>, Vec<u8>)> = None;
                for frame in combo.iter() {
                    if let Ingest::Delivered {
                        bad_shard, payload, ..
                    } = node.ingest_from(PROBE_PEER_ISOLATION, frame)
                    {
                        verdict = Some((bad_shard, payload));
                    }
                }
                matches!(&verdict, Some((None, bytes)) if bytes.as_slice() == &payload[..])
            }
            None => false,
        };

        accused && padding_ok && node.byzantine_shards() == 1
    };
    report.record("byzantine-isolation", byzantine_ok);

    // 10. Handshake key agreement: a real GHOST blob in 480-byte shards, with Shamir shares
    //     of the session secret in the authenticated headers. Both endpoints must converge
    //     on the same subkey set, and any two frames must be enough to do it.
    let handshake_ok = {
        let identity = crypto::PeerIdentity::generate();
        let blob = identity.build_handshake_blob();
        let secret = crypto::random_key();
        let shares = crypto::shamir_split(&secret, SHARD_COUNT).unwrap_or_default();
        let fingerprint = node.register_peer(PROBE_PEER, &blob);
        let sent = node.send_handshake(&blob, &shares, &wire, PROBE_PEER);
        let frames = wire.take();
        let mut blob_out: Option<Vec<u8>> = None;
        let mut session_key: Option<[u8; KEY_LEN]> = None;
        for frame in frames.iter() {
            if let Ingest::Delivered {
                payload,
                session_key: key,
                ..
            } = node.ingest_from(PROBE_PEER, frame)
            {
                blob_out = Some(payload);
                session_key = key;
            }
        }
        // Both endpoints must end up with identical subkeys: the sender derived them from the
        // Shamir secret, the receiver from the shares that rode in the authenticated headers.
        let peer_sec = ShardSec::from_master(&secret);
        let converged = match session_key {
            Some(key) => {
                node.adopt_master(&key);
                (0..SHARD_COUNT as u8).all(|index| {
                    peer_sec.subkey_fingerprint(index) == node.sec.subkey_fingerprint(index)
                })
            }
            None => false,
        };
        sent == SHARD_COUNT
            && frames.iter().all(|frame| frame.len() == WIRE_FRAME_LEN)
            && frames.iter().all(|frame| parse_tail_len(frame) == 22)
            && blob_out.as_deref() == Some(&blob[..])
            && session_key == Some(secret)
            && converged
            && fingerprint != 0
    };
    report.record("handshake-key-agreement", handshake_ok);

    // 11. Cover traffic: the sampler is Poisson on the tick grid and every due arrival is a
    //     real, sealed, exactly-576-byte frame that the peer accepts as a decoy.
    let cover_ok = {
        let mut sampler = CoverTraffic::new();
        sampler.poll(0);
        let mut arrivals = 0u64;
        for tick in 1..=20_000u64 {
            if sampler.poll(tick) != 0 {
                arrivals += 1;
            }
        }
        // Mean 20_000 / 500 = 40 arrivals, sigma ~ 6.3; the band is ~3.8 sigma.
        let rate_ok = (16..=80).contains(&arrivals) && sampler.due() == arrivals;

        // The tamper stages severed this route; route recalculation puts it back in service,
        // which is exactly the state a hot-swapped carrier starts from.
        let rehabilitated = node.rehabilitate_peer(PROBE_PEER) && !node.peer_isolated(PROBE_PEER);

        node.cover.set_interval_ticks(1);
        let now = clock::ticks();
        node.cover.poll(now); // arm the sampler; the next tick is the first trial
        let emitted = node.cover_poll(now + 1, &wire, PROBE_PEER);
        let frames = wire.take();
        let mut cover_deliveries = 0;
        for frame in frames.iter() {
            if let Ingest::Delivered {
                msg_id: COVER_ID, ..
            } = node.ingest_from(PROBE_PEER, frame)
            {
                cover_deliveries += 1;
            }
        }
        rate_ok
            && rehabilitated
            && emitted == 1
            && frames.len() == SHARD_COUNT
            && frames.iter().all(|frame| frame.len() == WIRE_FRAME_LEN)
            && cover_deliveries == 1
            && node.cover_delivered() == 1
            && node.cover().emitted() == 1
    };
    report.record("cover-traffic", cover_ok);

    // 12. Wipe: the panic scrub hook has to leave no mesh key, peer window or assembly.
    let wipe_ok = {
        let before = node.key_fingerprint();
        let relayed = PROBE_PEER;
        let stored = message.first().cloned().unwrap_or_default();
        node.wipe();
        let zero_master = node.sec.master == [0u8; KEY_LEN];
        let zero_subkeys = node
            .sec
            .subkeys
            .iter()
            .all(|subkey| subkey == &[0u8; KEY_LEN]);
        before != node.key_fingerprint() && zero_master && zero_subkeys && node.peer_count() == 0
            && !node.is_provisioned()
            && matches!(
                node.ingest_from(relayed, &stored),
                Ingest::Refused(MeshRefusal::Unprovisioned)
            )
    };
    report.record("wipe", wipe_ok);

    report
}
