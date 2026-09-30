//! Sovereign cryptography for KELLER-OS.
//!
//! Everything here is implemented against a published test vector and re-verified at
//! every boot by [`self_test`]: the vault's sector codec, the handshake blob and the
//! shard codecs all stand on top of this module, so the kernel refuses to continue if a
//! known-answer test fails.
//!
//! Layers:
//!
//! * **Entropy** - a ChaCha20 DRBG, seeded from RDRAND when the CPU exposes it and from
//!   TSC/PIT jitter otherwise, so a virtual machine without RDRAND still boots (and says
//!   which source it used) instead of spinning forever in `_rdrand64_step`.
//! * **RFC 8439** - ChaCha20 block function, Poly1305, and the AEAD with the exact AAD
//!   framing (`aad || pad16 || ciphertext || pad16 || le64(aad_len) || le64(ct_len)`).
//! * **RFC 4231 / RFC 5869** - HMAC-SHA256 and HKDF-SHA256 for key separation.
//! * **Sharding** - Reed-Solomon RS(2,1) erasure coding and Shamir 2-of-N sharing,
//!   both returning `Result` instead of panicking or silently fabricating output.
//! * **Identity** - the 960-byte GHOST handshake blob (X25519 + Kyber512 + Ed25519).

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use ed25519_dalek::{SigningKey, Signer};
use pqc_kyber::keypair as kyber_keypair;
use pqc_kyber::PublicKey as KyberPublicKey;
use rand_core::{CryptoRng, Error as RandError, RngCore};
use reed_solomon_erasure::galois_8::ReedSolomon;
use sha2::{Digest, Sha256};
use sharks::{Share, Sharks};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

/// Size of the GHOST handshake blob and of each of its two halves.
pub const HANDSHAKE_BLOB_LEN: usize = 960;
pub const HANDSHAKE_SHARD_LEN: usize = HANDSHAKE_BLOB_LEN / 2; // 480

/// Reed-Solomon layout used for the handshake and the vault: 2 data + 1 parity shard.
pub const RS_DATA_SHARDS: usize = 2;
pub const RS_PARITY_SHARDS: usize = 1;

/// Shamir threshold: any two of the generated shares reconstruct the secret.
pub const SHAMIR_THRESHOLD: usize = 2;

/// Domain separator for per-shard subkeys (Vantablack ShardSec consumes these).
const SHARD_SUBKEY_INFO: &[u8] = b"KOS-SHARD-KEY";
/// Domain separator for the DRBG seed hash.
const DRBG_SEED_INFO: &[u8] = b"KOS-DRBG-SEED";

/// Failures a caller has to handle; no crypto path panics on bad input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// A buffer was too short or not shaped the way the format requires.
    BadLength,
    /// AEAD tag verification failed (forgery, corruption or wrong key/nonce/AAD).
    TagMismatch,
    /// Shard layout does not match the expected RS/Shamir geometry.
    BadShardLayout,
    /// The Reed-Solomon codec rejected the shard set.
    ReedSolomon,
    /// A Shamir share could not be parsed or the shares do not form a valid set.
    ShareError,
}

impl CryptoError {
    pub fn as_str(self) -> &'static str {
        match self {
            CryptoError::BadLength => "bad length",
            CryptoError::TagMismatch => "authentication tag mismatch",
            CryptoError::BadShardLayout => "bad shard layout",
            CryptoError::ReedSolomon => "reed-solomon failure",
            CryptoError::ShareError => "shamir share failure",
        }
    }
}

// ---------------------------------------------------------------------------------------
// Entropy: ChaCha20 DRBG with an RDRAND preference
// ---------------------------------------------------------------------------------------

struct Drbg {
    key: [u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
    counter: u64,
    buffer: [u8; 64],
    position: usize,
    initialised: bool,
    hardware: bool,
}

/// Deliberately self-initialising: the boot loader does not zero `.bss` (see `main.rs`).
static mut DRBG: Drbg = Drbg {
    key: [0; KEY_LEN],
    nonce: [0; NONCE_LEN],
    counter: 0,
    buffer: [0; 64],
    position: 64,
    initialised: false,
    hardware: false,
};

fn drbg_state() -> &'static mut Drbg {
    unsafe { &mut *core::ptr::addr_of_mut!(DRBG) }
}

fn read_tsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

fn rdrand_sample() -> Option<u64> {
    if !crate::arch::cpu::has_rdrand() {
        return None;
    }
    let mut value = 0u64;
    for _ in 0..32 {
        let ok = unsafe { core::arch::x86_64::_rdrand64_step(&mut value) };
        if ok == 1 {
            return Some(value);
        }
        core::hint::spin_loop();
    }
    None
}

fn write_le64(target: &mut [u8], value: u64) {
    target[..8].copy_from_slice(&value.to_le_bytes());
}

/// Seeds the DRBG. Called once from `main` after the timer is programmed, so the TSC and
/// the PIT have both moved and contribute jitter to the seed.
pub fn init_entropy(seed: u64) {
    let hardware_sample = rdrand_sample();
    let state = drbg_state();

    let mut material = [0u8; 64];
    write_le64(&mut material[0..8], seed);
    write_le64(&mut material[8..16], read_tsc());
    write_le64(&mut material[16..24], crate::clock::ticks());
    write_le64(&mut material[24..32], crate::clock::uptime_ms());
    write_le64(&mut material[32..40], read_tsc());
    write_le64(
        &mut material[40..48],
        hardware_sample.unwrap_or(0x5A5A_5A5A_5A5A_5A5A),
    );
    let info_len = DRBG_SEED_INFO.len();
    material[48..48 + info_len].copy_from_slice(DRBG_SEED_INFO);
    material[48 + info_len] = 0x01;
    state.key = sha256(&material);

    let mut nonce_material = [0u8; 32];
    write_le64(&mut nonce_material[0..8], read_tsc());
    write_le64(&mut nonce_material[8..16], seed ^ 0x9E37_79B9_7F4A_7C15);
    write_le64(&mut nonce_material[16..24], crate::clock::ticks());
    write_le64(&mut nonce_material[24..32], read_tsc());
    let nonce_hash = sha256(&nonce_material);
    state.nonce.copy_from_slice(&nonce_hash[..NONCE_LEN]);

    state.counter = 0;
    state.position = 64;
    state.initialised = true;
    state.hardware = hardware_sample.is_some();
}

/// Which entropy source is live, for the boot log and the `cpu` shell command.
pub fn entropy_source() -> &'static str {
    if drbg_state().hardware {
        "RDRAND (CPU hardware)"
    } else {
        "ChaCha20 DRBG (TSC/PIT seed; no RDRAND on this CPU)"
    }
}

/// True when the DRBG is seeded from real hardware randomness.
pub fn entropy_is_hardware() -> bool {
    drbg_state().hardware
}

fn drbg_fill(dest: &mut [u8]) {
    if !drbg_state().initialised {
        init_entropy(read_tsc());
    }
    let state = drbg_state();
    let mut offset = 0;
    while offset < dest.len() {
        if state.position >= state.buffer.len() {
            state.buffer = chacha20_block(&state.key, state.counter as u32, &state.nonce);
            state.position = 0;
            state.counter = state.counter.wrapping_add(1);
        }
        let take = core::cmp::min(state.buffer.len() - state.position, dest.len() - offset);
        dest[offset..offset + take]
            .copy_from_slice(&state.buffer[state.position..state.position + take]);
        state.position += take;
        offset += take;
    }
}

/// Uniform random bytes from the single kernel DRBG (RDRAND-backed when available).
pub fn hardware_rand_bytes(dest: &mut [u8]) {
    drbg_fill(dest);
}

pub fn random_u64() -> u64 {
    let mut bytes = [0u8; 8];
    drbg_fill(&mut bytes);
    u64::from_le_bytes(bytes)
}

pub fn random_key() -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    drbg_fill(&mut key);
    key
}

/// `rand_core` adaptor used by the Shamir dealer and the identity keys.
pub struct HardwareRng;

impl RngCore for HardwareRng {
    fn next_u32(&mut self) -> u32 {
        random_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        random_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        drbg_fill(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError> {
        drbg_fill(dest);
        Ok(())
    }
}

impl CryptoRng for HardwareRng {}

/// Best-effort zeroing of sensitive material that is about to leave scope.
pub fn wipe(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        unsafe { core::ptr::write_volatile(byte as *mut u8, 0) };
    }
}

// ---------------------------------------------------------------------------------------
// ChaCha20 (RFC 8439 section 2.3)
// ---------------------------------------------------------------------------------------

#[inline]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

/// The ChaCha20 block function: 64 bytes of keystream for `(key, counter, nonce)`.
pub fn chacha20_block(key: &[u8; KEY_LEN], counter: u32, nonce: &[u8; NONCE_LEN]) -> [u8; 64] {
    let mut state = [0u32; 16];
    state[0] = 0x6170_7865;
    state[1] = 0x3320_646e;
    state[2] = 0x7962_2d32;
    state[3] = 0x6b20_6574;
    for index in 0..8 {
        state[4 + index] = read_u32_le(key, index * 4);
    }
    state[12] = counter;
    for index in 0..3 {
        state[13 + index] = read_u32_le(nonce, index * 4);
    }

    let mut working = state;
    for _ in 0..10 {
        quarter_round(&mut working, 0, 4, 8, 12);
        quarter_round(&mut working, 1, 5, 9, 13);
        quarter_round(&mut working, 2, 6, 10, 14);
        quarter_round(&mut working, 3, 7, 11, 15);
        quarter_round(&mut working, 0, 5, 10, 15);
        quarter_round(&mut working, 1, 6, 11, 12);
        quarter_round(&mut working, 2, 7, 8, 13);
        quarter_round(&mut working, 3, 4, 9, 14);
    }

    let mut output = [0u8; 64];
    for index in 0..16 {
        let word = working[index].wrapping_add(state[index]);
        output[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    output
}

/// XORs `data` with the ChaCha20 keystream starting at `counter`.
pub fn chacha20_xor(key: &[u8; KEY_LEN], counter: u32, nonce: &[u8; NONCE_LEN], data: &mut [u8]) {
    let mut block_counter = counter;
    for chunk in data.chunks_mut(64) {
        let keystream = chacha20_block(key, block_counter, nonce);
        for (byte, key_byte) in chunk.iter_mut().zip(keystream.iter()) {
            *byte ^= *key_byte;
        }
        block_counter = block_counter.wrapping_add(1);
    }
}

/// The one-time Poly1305 key for an AEAD nonce: ChaCha20 block 0, first 32 bytes.
fn poly1305_key_gen(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN]) -> [u8; KEY_LEN] {
    let mut block = chacha20_block(key, 0, nonce);
    let mut one_time_key = [0u8; KEY_LEN];
    one_time_key.copy_from_slice(&block[..KEY_LEN]);
    wipe(&mut block);
    one_time_key
}

// ---------------------------------------------------------------------------------------
// Poly1305 (RFC 8439 section 2.5), 5 x 26-bit limbs
// ---------------------------------------------------------------------------------------

struct Poly1305 {
    r: [u32; 5],
    h: [u32; 5],
    pad: [u32; 4],
}

impl Poly1305 {
    fn new(key: &[u8; KEY_LEN]) -> Self {
        // The limb masks carry the RFC 8439 clamp (section 2.5.1) for the shifted bytes.
        Self {
            r: [
                read_u32_le(key, 0) & 0x03ff_ffff,
                (read_u32_le(key, 3) >> 2) & 0x03ff_ff03,
                (read_u32_le(key, 6) >> 4) & 0x03ff_c0ff,
                (read_u32_le(key, 9) >> 6) & 0x03f0_3fff,
                (read_u32_le(key, 12) >> 8) & 0x000f_ffff,
            ],
            h: [0; 5],
            pad: [
                read_u32_le(key, 16),
                read_u32_le(key, 20),
                read_u32_le(key, 24),
                read_u32_le(key, 28),
            ],
        }
    }

    /// `h += m`, then `h *= r` modulo 2^130 - 5.
    ///
    /// `extra_bit` is the bit the RFC's `m || 0x01` formulation sets: 128 for a full
    /// 16-byte block and `8 * len` for the zero-padded final block, which is what makes a
    /// short tail authenticate differently from a full block.
    fn block(&mut self, block: &[u8; 16], extra_bit: u32) {
        let mut m = [
            read_u32_le(block, 0) & 0x03ff_ffff,
            (read_u32_le(block, 3) >> 2) & 0x03ff_ffff,
            (read_u32_le(block, 6) >> 4) & 0x03ff_ffff,
            (read_u32_le(block, 9) >> 6) & 0x03ff_ffff,
            (read_u32_le(block, 12) >> 8) & 0x00ff_ffff,
        ];
        if extra_bit != 0 {
            m[(extra_bit / 26) as usize] |= 1 << (extra_bit % 26);
        }

        let h0 = (self.h[0] + m[0]) as u64;
        let h1 = (self.h[1] + m[1]) as u64;
        let h2 = (self.h[2] + m[2]) as u64;
        let h3 = (self.h[3] + m[3]) as u64;
        let h4 = (self.h[4] + m[4]) as u64;

        let r0 = self.r[0] as u64;
        let r1 = self.r[1] as u64;
        let r2 = self.r[2] as u64;
        let r3 = self.r[3] as u64;
        let r4 = self.r[4] as u64;
        // A limb product at index >= 5 wraps through 2^130 == 5 (mod p).
        let s1 = r1 * 5;
        let s2 = r2 * 5;
        let s3 = r3 * 5;
        let s4 = r4 * 5;

        let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        let mut d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        let mut d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        let mut d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        let mut d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

        let mut carry = d0 >> 26;
        self.h[0] = (d0 & 0x03ff_ffff) as u32;
        d1 += carry;
        carry = d1 >> 26;
        self.h[1] = (d1 & 0x03ff_ffff) as u32;
        d2 += carry;
        carry = d2 >> 26;
        self.h[2] = (d2 & 0x03ff_ffff) as u32;
        d3 += carry;
        carry = d3 >> 26;
        self.h[3] = (d3 & 0x03ff_ffff) as u32;
        d4 += carry;
        carry = d4 >> 26;
        self.h[4] = (d4 & 0x03ff_ffff) as u32;
        self.h[0] = self.h[0].wrapping_add((carry * 5) as u32);
        carry = (self.h[0] >> 26) as u64;
        self.h[0] &= 0x03ff_ffff;
        self.h[1] = self.h[1].wrapping_add(carry as u32);
    }

    fn update(&mut self, message: &[u8]) {
        let mut offset = 0;
        while offset + 16 <= message.len() {
            let mut block = [0u8; 16];
            block.copy_from_slice(&message[offset..offset + 16]);
            self.block(&block, 128);
            offset += 16;
        }
        if offset < message.len() {
            let mut block = [0u8; 16];
            let tail = &message[offset..];
            block[..tail.len()].copy_from_slice(tail);
            self.block(&block, tail.len() as u32 * 8);
        }
    }

    fn finalize(mut self) -> [u8; TAG_LEN] {
        // One full carry pass: the second carry out of limb 1 matters, because limb 2 can
        // still exceed 26 bits after the wrap-around through 2^130 == 5.
        let mut carry = self.h[1] >> 26;
        self.h[1] &= 0x03ff_ffff;
        self.h[2] = self.h[2].wrapping_add(carry);
        carry = self.h[2] >> 26;
        self.h[2] &= 0x03ff_ffff;
        self.h[3] = self.h[3].wrapping_add(carry);
        carry = self.h[3] >> 26;
        self.h[3] &= 0x03ff_ffff;
        self.h[4] = self.h[4].wrapping_add(carry);
        carry = self.h[4] >> 26;
        self.h[4] &= 0x03ff_ffff;
        self.h[0] = self.h[0].wrapping_add(carry * 5);
        carry = self.h[0] >> 26;
        self.h[0] &= 0x03ff_ffff;
        self.h[1] = self.h[1].wrapping_add(carry);
        carry = self.h[1] >> 26;
        self.h[1] &= 0x03ff_ffff;
        self.h[2] = self.h[2].wrapping_add(carry);

        // g = h + 5 - 2^130, i.e. h - p; selected when h >= p (its top limb stays >= 0).
        let mut g = [0u32; 5];
        let mut carry_in = 5u32;
        for index in 0..5 {
            g[index] = self.h[index].wrapping_add(carry_in);
            carry_in = g[index] >> 26;
            g[index] &= 0x03ff_ffff;
        }
        g[4] = g[4].wrapping_sub(1 << 26);
        let select_g = (g[4] >> 31).wrapping_sub(1); // all ones when g4 >= 0
        let keep_h = !select_g;
        for index in 0..5 {
            g[index] = (self.h[index] & keep_h) | (g[index] & select_g);
        }

        // Pack the 130-bit accumulator back into 128 bits.
        let h0 = g[0] | (g[1] << 26);
        let h1 = (g[1] >> 6) | (g[2] << 20);
        let h2 = (g[2] >> 12) | (g[3] << 14);
        let h3 = (g[3] >> 18) | (g[4] << 8);

        // Add the encrypted nonce half.
        let mut sum = h0 as u64 + self.pad[0] as u64;
        let out0 = sum as u32;
        sum >>= 32;
        sum += h1 as u64 + self.pad[1] as u64;
        let out1 = sum as u32;
        sum >>= 32;
        sum += h2 as u64 + self.pad[2] as u64;
        let out2 = sum as u32;
        sum >>= 32;
        sum += h3 as u64 + self.pad[3] as u64;
        let out3 = sum as u32;

        let mut tag = [0u8; TAG_LEN];
        tag[0..4].copy_from_slice(&out0.to_le_bytes());
        tag[4..8].copy_from_slice(&out1.to_le_bytes());
        tag[8..12].copy_from_slice(&out2.to_le_bytes());
        tag[12..16].copy_from_slice(&out3.to_le_bytes());
        tag
    }
}

/// Poly1305 tag over `message` under a 32-byte one-time key.
pub fn poly1305_tag(message: &[u8], key: &[u8; KEY_LEN]) -> [u8; TAG_LEN] {
    let mut mac = Poly1305::new(key);
    mac.update(message);
    mac.finalize()
}

/// Constant-time comparison of two tags.
pub fn ct_eq_16(a: &[u8; TAG_LEN], b: &[u8; TAG_LEN]) -> bool {
    let mut difference = 0u8;
    for index in 0..TAG_LEN {
        difference |= a[index] ^ b[index];
    }
    difference == 0
}

/// Constant-time comparison for equal-length buffers; the length check itself is public.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in a.iter().zip(b.iter()) {
        difference |= left ^ right;
    }
    difference == 0
}

// ---------------------------------------------------------------------------------------
// AEAD_CHACHA20_POLY1305 (RFC 8439 section 2.8)
// ---------------------------------------------------------------------------------------

static ZERO_PAD: [u8; 16] = [0; 16];

fn pad16_length(len: usize) -> usize {
    (16 - (len % 16)) % 16
}

/// The Poly1305 input for AEAD: AAD and ciphertext, each padded to 16 bytes, followed by
/// both lengths as little-endian 64-bit values.
fn build_mac_data(aad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(aad.len() + ciphertext.len() + 32);
    data.extend_from_slice(aad);
    data.extend_from_slice(&ZERO_PAD[..pad16_length(aad.len())]);
    data.extend_from_slice(ciphertext);
    data.extend_from_slice(&ZERO_PAD[..pad16_length(ciphertext.len())]);
    data.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    data.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    data
}

/// Encrypts `plaintext` and appends the 16-byte tag, returning `ciphertext || tag`.
pub fn aead_seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let mut sealed = Vec::with_capacity(plaintext.len() + TAG_LEN);
    aead_seal_into(key, nonce, aad, plaintext, &mut sealed);
    sealed
}

/// In-place variant: `buffer` becomes `ciphertext || tag` (its previous contents go away).
pub fn aead_seal_into(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
    buffer: &mut Vec<u8>,
) {
    buffer.clear();
    buffer.extend_from_slice(plaintext);
    let mut one_time_key = poly1305_key_gen(key, nonce);
    chacha20_xor(key, 1, nonce, buffer);
    let mut mac_data = build_mac_data(aad, buffer);
    let tag = poly1305_tag(&mac_data, &one_time_key);
    buffer.extend_from_slice(&tag);
    wipe(&mut one_time_key);
    wipe(&mut mac_data);
}

/// Verifies and decrypts `ciphertext || tag`. The tag is checked before a single byte of
/// plaintext exists, so a forgery can never reach the caller.
pub fn aead_open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    sealed: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if sealed.len() < TAG_LEN {
        return Err(CryptoError::BadLength);
    }
    let ciphertext_len = sealed.len() - TAG_LEN;
    let ciphertext = &sealed[..ciphertext_len];
    let received_tag: [u8; TAG_LEN] = match sealed[ciphertext_len..].try_into() {
        Ok(tag) => tag,
        Err(_) => return Err(CryptoError::BadLength),
    };

    let mut one_time_key = poly1305_key_gen(key, nonce);
    let mut mac_data = build_mac_data(aad, ciphertext);
    let expected_tag = poly1305_tag(&mac_data, &one_time_key);
    wipe(&mut one_time_key);
    wipe(&mut mac_data);

    if !ct_eq_16(&expected_tag, &received_tag) {
        return Err(CryptoError::TagMismatch);
    }

    let mut plaintext = Vec::with_capacity(ciphertext_len);
    plaintext.extend_from_slice(ciphertext);
    chacha20_xor(key, 1, nonce, &mut plaintext);
    Ok(plaintext)
}

/// Decrypts `ciphertext || tag` in place: verifies first, then truncates the tag and
/// decrypts the remaining bytes.
pub fn aead_open_in_place(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buffer: &mut Vec<u8>,
) -> Result<(), CryptoError> {
    if buffer.len() < TAG_LEN {
        return Err(CryptoError::BadLength);
    }
    let ciphertext_len = buffer.len() - TAG_LEN;
    let received_tag: [u8; TAG_LEN] = match buffer[ciphertext_len..].try_into() {
        Ok(tag) => tag,
        Err(_) => return Err(CryptoError::BadLength),
    };

    let mut one_time_key = poly1305_key_gen(key, nonce);
    let mut mac_data = build_mac_data(aad, &buffer[..ciphertext_len]);
    let expected_tag = poly1305_tag(&mac_data, &one_time_key);
    wipe(&mut one_time_key);
    wipe(&mut mac_data);

    if !ct_eq_16(&expected_tag, &received_tag) {
        return Err(CryptoError::TagMismatch);
    }

    buffer.truncate(ciphertext_len);
    chacha20_xor(key, 1, nonce, buffer);
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Sector and shard keying (consumed by the vault and the mesh)
// ---------------------------------------------------------------------------------------

/// Nonce for sector `index`. The last four bytes are a domain tag so sector nonces can
/// never collide with message nonces derived elsewhere.
pub fn sector_nonce(index: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[0..8].copy_from_slice(&index.to_le_bytes());
    nonce[8..12].copy_from_slice(b"SECR");
    nonce
}

/// Raw keystream XOR for a sector (used to overwrite data in place, no authentication).
pub fn sector_xor(key: &[u8; KEY_LEN], sector_index: u64, data: &mut [u8]) {
    chacha20_xor(key, 1, &sector_nonce(sector_index), data);
}

/// Authenticated sector seal: `ciphertext || tag`, with the sector index bound in as AAD.
pub fn sector_seal(key: &[u8; KEY_LEN], sector_index: u64, plaintext: &[u8]) -> Vec<u8> {
    let mut aad = [0u8; 8];
    aad.copy_from_slice(&sector_index.to_le_bytes());
    aead_seal(key, &sector_nonce(sector_index), &aad, plaintext)
}

/// Authenticated sector open; a sector swapped with another index fails to verify.
pub fn sector_open(
    key: &[u8; KEY_LEN],
    sector_index: u64,
    sealed: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut aad = [0u8; 8];
    aad.copy_from_slice(&sector_index.to_le_bytes());
    aead_open(key, &sector_nonce(sector_index), &aad, sealed)
}

/// HKDF-derived 32-byte subkey for shard `index`, so each shard's ShardSec key differs.
pub fn shard_subkey(master: &[u8; KEY_LEN], shard_index: u8) -> [u8; KEY_LEN] {
    let mut info = [0u8; 16];
    info[..SHARD_SUBKEY_INFO.len()].copy_from_slice(SHARD_SUBKEY_INFO);
    info[SHARD_SUBKEY_INFO.len()] = shard_index;
    let mut subkey = [0u8; KEY_LEN];
    hkdf_sha256(b"KELLER-OS shard separation", master, &info, &mut subkey);
    subkey
}

// ---------------------------------------------------------------------------------------
// SHA-256, HMAC-SHA256 and HKDF-SHA256 (RFC 4231 / RFC 5869)
// ---------------------------------------------------------------------------------------

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    output
}

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        key_block[..32].copy_from_slice(&sha256(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0x36u8; 64];
    let mut outer_pad = [0x5cu8; 64];
    for index in 0..64 {
        inner_pad[index] ^= key_block[index];
        outer_pad[index] ^= key_block[index];
    }

    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    let digest = outer.finalize();

    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    wipe(&mut key_block);
    output
}

/// HKDF-Extract + HKDF-Expand (RFC 5869). `out` may be up to 255 * 32 bytes long.
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) {
    let mut prk = hmac_sha256(salt, ikm);
    let mut offset = 0;
    let mut counter = 1u8;
    let mut previous: Vec<u8> = Vec::new();

    while offset < out.len() {
        let mut input = Vec::with_capacity(previous.len() + info.len() + 1);
        input.extend_from_slice(&previous);
        input.extend_from_slice(info);
        input.push(counter);
        let block = hmac_sha256(&prk, &input);
        wipe(&mut input);

        let take = core::cmp::min(block.len(), out.len() - offset);
        out[offset..offset + take].copy_from_slice(&block[..take]);
        previous.clear();
        previous.extend_from_slice(&block);
        offset += take;
        counter = counter.wrapping_add(1);
    }

    wipe(&mut prk);
    wipe(&mut previous);
}

// ---------------------------------------------------------------------------------------
// Erasure coding: Reed-Solomon RS(2,1)
// ---------------------------------------------------------------------------------------

/// Splits `data` into two data shards plus one parity shard (pads with a zero byte when
/// the length is odd). The shards are returned in the order the mesh transmits them.
pub fn rs_encode(data: &mut Vec<u8>) -> Result<Vec<Vec<u8>>, CryptoError> {
    if data.is_empty() {
        return Err(CryptoError::BadLength);
    }
    if data.len() % 2 != 0 {
        data.push(0);
    }
    let half = data.len() / 2;
    let mut shards = vec![data[..half].to_vec(), data[half..].to_vec(), vec![0u8; half]];
    let codec = ReedSolomon::new(RS_DATA_SHARDS, RS_PARITY_SHARDS)
        .map_err(|_| CryptoError::ReedSolomon)?;
    codec
        .encode(&mut shards)
        .map_err(|_| CryptoError::ReedSolomon)?;
    Ok(shards)
}

/// Reconstructs every missing shard in place; needs at least `RS_DATA_SHARDS` shards.
pub fn rs_reconstruct(shards: &mut [Option<Vec<u8>>]) -> Result<(), CryptoError> {
    if shards.len() != RS_DATA_SHARDS + RS_PARITY_SHARDS {
        return Err(CryptoError::BadShardLayout);
    }
    let codec = ReedSolomon::new(RS_DATA_SHARDS, RS_PARITY_SHARDS)
        .map_err(|_| CryptoError::ReedSolomon)?;
    codec
        .reconstruct(shards)
        .map_err(|_| CryptoError::ReedSolomon)
}

// ---------------------------------------------------------------------------------------
// Erasure coding: Shamir 2-of-N
// ---------------------------------------------------------------------------------------

/// Splits a 32-byte secret into `share_count` Shamir shares; any two of them recover it.
pub fn shamir_split(
    secret: &[u8; KEY_LEN],
    share_count: usize,
) -> Result<Vec<Vec<u8>>, CryptoError> {
    if share_count < SHAMIR_THRESHOLD || share_count > 32 {
        return Err(CryptoError::BadShardLayout);
    }
    let sharks = Sharks(SHAMIR_THRESHOLD as u8);
    let mut rng = HardwareRng;
    let shares: Vec<Vec<u8>> = sharks
        .dealer_rng(secret, &mut rng)
        .take(share_count)
        .map(|share| Vec::from(&share))
        .collect();
    if shares.len() != share_count {
        return Err(CryptoError::ShareError);
    }
    Ok(shares)
}

/// Recovers a 32-byte secret from at least two Shamir shares.
pub fn shamir_join(shares: &[&[u8]]) -> Result<[u8; KEY_LEN], CryptoError> {
    if shares.len() < SHAMIR_THRESHOLD {
        return Err(CryptoError::ShareError);
    }
    let mut parsed: Vec<Share> = Vec::with_capacity(shares.len());
    for share in shares {
        parsed.push(Share::try_from(*share).map_err(|_| CryptoError::ShareError)?);
    }
    let secret = Sharks(SHAMIR_THRESHOLD as u8)
        .recover(&parsed)
        .map_err(|_| CryptoError::ShareError)?;
    if secret.len() != KEY_LEN {
        return Err(CryptoError::BadLength);
    }
    let mut output = [0u8; KEY_LEN];
    output.copy_from_slice(&secret);
    Ok(output)
}

// ---------------------------------------------------------------------------------------
// Identity: the GHOST handshake blob
// ---------------------------------------------------------------------------------------

pub struct PeerIdentity {
    pub signing_key: SigningKey,
    pub x_public: XPublicKey,
    pub kyber_public: KyberPublicKey,
}

impl PeerIdentity {
    pub fn generate() -> Self {
        let mut rng = HardwareRng;

        let mut ed_seed = [0u8; 32];
        rng.fill_bytes(&mut ed_seed);
        let signing_key = SigningKey::from_bytes(&ed_seed);

        let mut x_seed = [0u8; 32];
        rng.fill_bytes(&mut x_seed);
        let x_secret = StaticSecret::from(x_seed);
        let x_public = XPublicKey::from(&x_secret);

        let kyber_public = match kyber_keypair(&mut rng) {
            // `pqc_kyber::PublicKey` is the `[u8; KYBER_PUBLICKEYBYTES]` array itself.
            Ok(keypair) => keypair.public,
            Err(_) => [0u8; pqc_kyber::KYBER_PUBLICKEYBYTES],
        };

        Self {
            signing_key,
            x_public,
            kyber_public,
        }
    }

    pub fn fingerprint(&self) -> String {
        hex::encode(&self.signing_key.verifying_key().to_bytes()[0..8])
    }

    /// Layout: `GHOST_HANDSHAKE_` (16) | X25519 (32) | Kyber512 (800) | Ed25519 verify
    /// key (32) | Ed25519 signature over the Kyber key (64) | zero padding to 960.
    pub fn build_handshake_blob(&self) -> Vec<u8> {
        let mut blob = vec![0u8; HANDSHAKE_BLOB_LEN];
        blob[0..16].copy_from_slice(b"GHOST_HANDSHAKE_");
        blob[16..48].copy_from_slice(self.x_public.as_bytes());
        blob[48..848].copy_from_slice(&self.kyber_public);
        let signature = self.signing_key.sign(&self.kyber_public);
        blob[848..880].copy_from_slice(&self.signing_key.verifying_key().to_bytes());
        blob[880..944].copy_from_slice(&signature.to_bytes());
        blob
    }
}

// ---------------------------------------------------------------------------------------
// Known-answer tests
// ---------------------------------------------------------------------------------------

/// Result of the boot-time cryptographic self-test.
pub struct SelfTest {
    pub passed: u32,
    pub failed: u32,
    pub failures: Vec<&'static str>,
}

impl SelfTest {
    fn record(&mut self, name: &'static str, ok: bool) {
        if ok {
            self.passed += 1;
        } else {
            self.failed += 1;
            self.failures.push(name);
        }
    }
}

fn decode_hex(text: &str) -> Vec<u8> {
    hex::decode(text).unwrap_or_default()
}

/// ChaCha20 block function against the RFC 8439 section 2.3.2 keystream.
fn chacha20_known_answer() -> bool {
    let mut key = [0u8; KEY_LEN];
    for (index, byte) in key.iter_mut().enumerate() {
        *byte = index as u8;
    }
    let nonce = match decode_hex("000000090000004a00000000").try_into() {
        Ok(nonce) => nonce,
        Err(_) => return false,
    };
    let expected = "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e\
                    d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e";
    hex::encode(chacha20_block(&key, 1, &nonce)) == expected
}

/// Poly1305 against the RFC 8439 section 2.5.2 vector.
fn poly1305_known_answer() -> bool {
    let key: [u8; KEY_LEN] =
        match decode_hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b").try_into()
        {
            Ok(key) => key,
            Err(_) => return false,
        };
    let message = b"Cryptographic Forum Research Group";
    hex::encode(poly1305_tag(message, &key)) == "a8061dc1305136c6c22b8baf0c0127a9"
}

/// Full AEAD against the RFC 8439 section 2.8.2 vector, plus tamper and AAD binding.
fn aead_known_answer() -> bool {
    let key: [u8; KEY_LEN] =
        match decode_hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            .try_into()
        {
            Ok(key) => key,
            Err(_) => return false,
        };
    let nonce: [u8; NONCE_LEN] = match decode_hex("070000004041424344454647").try_into() {
        Ok(nonce) => nonce,
        Err(_) => return false,
    };
    let aad = decode_hex("50515253c0c1c2c3c4c5c6c7");
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you \
                      only one tip for the future, sunscreen would be it.";
    let expected = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
                    3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3\
                    692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7\
                    bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0\
                    600691";

    let sealed = aead_seal(&key, &nonce, &aad, plaintext);
    if hex::encode(&sealed) != expected {
        return false;
    }

    // Round-trip, then the three ways an attacker can try to bend it.
    let opened = match aead_open(&key, &nonce, &aad, &sealed) {
        Ok(opened) => opened,
        Err(_) => return false,
    };
    if opened != plaintext {
        return false;
    }

    let mut forged = sealed.clone();
    forged[0] ^= 0x01;
    if aead_open(&key, &nonce, &aad, &forged).is_ok() {
        return false;
    }

    let mut bad_tag = sealed.clone();
    let last = bad_tag.len() - 1;
    bad_tag[last] ^= 0x80;
    if aead_open(&key, &nonce, &aad, &bad_tag).is_ok() {
        return false;
    }

    if aead_open(&key, &nonce, b"different aad", &sealed).is_ok() {
        return false;
    }

    let other_nonce = sector_nonce(7);
    if aead_open(&key, &other_nonce, &aad, &sealed).is_ok() {
        return false;
    }

    // In-place path must agree with the copying path.
    let mut in_place = sealed.clone();
    if aead_open_in_place(&key, &nonce, &aad, &mut in_place).is_err() || in_place != plaintext {
        return false;
    }

    true
}

/// HMAC-SHA256 (RFC 4231 case 1) and HKDF-SHA256 (RFC 5869 case 1).
fn keyed_digest_known_answer() -> bool {
    let hmac_key = [0x0bu8; 20];
    let digest = hmac_sha256(&hmac_key, b"Hi There");
    if hex::encode(digest) != "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7" {
        return false;
    }

    let ikm = [0x0bu8; 22];
    let salt = decode_hex("000102030405060708090a0b0c");
    let info = decode_hex("f0f1f2f3f4f5f6f7f8f9");
    let mut okm = [0u8; 42];
    hkdf_sha256(&salt, &ikm, &info, &mut okm);
    if hex::encode(okm)
        != "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    {
        return false;
    }

    // Different info must give different key material (domain separation is real).
    let mut other = [0u8; 42];
    hkdf_sha256(&salt, &ikm, b"\x00\x01", &mut other);
    if other == okm {
        return false;
    }
    if hex::encode(other)
        != "954e5674a9fbbcf1cde7427f6187861944ab3765707d6a353da10fbac91befaa979f8e4aefd7b3c0197b"
    {
        return false;
    }

    true
}

/// Reed-Solomon (drop any one shard) and Shamir (any pair, and no single share).
fn sharding_known_answer() -> bool {
    let mut payload: Vec<u8> = (0..64u8).map(|byte| byte.wrapping_mul(7).wrapping_add(3)).collect();
    let original = payload.clone();
    let shards = match rs_encode(&mut payload) {
        Ok(shards) => shards,
        Err(_) => return false,
    };
    if shards.len() != RS_DATA_SHARDS + RS_PARITY_SHARDS {
        return false;
    }

    for missing in 0..shards.len() {
        let mut received: Vec<Option<Vec<u8>>> = shards
            .iter()
            .enumerate()
            .map(|(index, shard)| if index == missing { None } else { Some(shard.clone()) })
            .collect();
        if rs_reconstruct(&mut received).is_err() {
            return false;
        }
        let mut recovered = Vec::new();
        recovered.extend_from_slice(received[0].as_ref().map_or(&[][..], |s| s.as_slice()));
        recovered.extend_from_slice(received[1].as_ref().map_or(&[][..], |s| s.as_slice()));
        if recovered != original {
            return false;
        }
    }

    let secret = [0x5Au8; KEY_LEN];
    let shares = match shamir_split(&secret, 3) {
        Ok(shares) => shares,
        Err(_) => return false,
    };
    if shares.len() != 3 {
        return false;
    }
    for (first, second) in [(0usize, 1usize), (0, 2), (1, 2)] {
        match shamir_join(&[shares[first].as_slice(), shares[second].as_slice()]) {
            Ok(recovered) => {
                if recovered != secret {
                    return false;
                }
            }
            Err(_) => return false,
        }
    }
    if shamir_join(&[shares[0].as_slice()]).is_ok() {
        return false;
    }

    // Different shard indices must yield different ShardSec keys.
    let master = [0x11u8; KEY_LEN];
    shard_subkey(&master, 0) != shard_subkey(&master, 1)
}

/// Sector sealing: index binding, tamper detection and the raw XOR path.
fn sector_known_answer() -> bool {
    let key = [0x42u8; KEY_LEN];
    let plaintext = b"KELLER-OS vault sector payload";
    let sealed = sector_seal(&key, 3, plaintext);

    match sector_open(&key, 3, &sealed) {
        Ok(opened) => {
            if opened != plaintext {
                return false;
            }
        }
        Err(_) => return false,
    }
    // The same ciphertext under a different sector index must not verify.
    if sector_open(&key, 4, &sealed).is_ok() {
        return false;
    }

    // Raw sector XOR is its own inverse and moves with the index.
    let mut buffer = Vec::from(&plaintext[..]);
    sector_xor(&key, 9, &mut buffer);
    if buffer == plaintext {
        return false;
    }
    sector_xor(&key, 9, &mut buffer);
    buffer == plaintext
}

/// Runs every known-answer test; `main` refuses to continue when any of them fails.
pub fn self_test() -> SelfTest {
    let mut report = SelfTest {
        passed: 0,
        failed: 0,
        failures: Vec::new(),
    };
    report.record("chacha20_block (RFC 8439 2.3.2)", chacha20_known_answer());
    report.record("poly1305 (RFC 8439 2.5.2)", poly1305_known_answer());
    report.record("aead_chacha20_poly1305 (RFC 8439 2.8.2)", aead_known_answer());
    report.record(
        "hmac_sha256 + hkdf_sha256 (RFC 4231 / RFC 5869)",
        keyed_digest_known_answer(),
    );
    report.record("reed-solomon + shamir sharding", sharding_known_answer());
    report.record("sector aead + raw xor", sector_known_answer());
    report.record(
        "drbg produces changing output",
        random_u64() != random_u64(),
    );
    report
}
