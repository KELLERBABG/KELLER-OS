// crypto.rs
use alloc::vec::Vec;
use alloc::vec;
use alloc::string::String;

use reed_solomon_erasure::galois_8::ReedSolomon;
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use ed25519_dalek::{SigningKey, Signer};

// Externe Crates für Identität und Shamir
use x25519_dalek::{StaticSecret, PublicKey as XPublicKey};
use pqc_kyber::keypair as kyber_keypair;
use pqc_kyber::PublicKey as KyberPublicKey;
use sharks::{Sharks, Share};

// Für unseren Hardware RNG Wrapper
use rand_core::{RngCore, CryptoRng, Error as RandError};

pub const HANDSHAKE_BLOB_LEN: usize = 960;
pub const HANDSHAKE_SHARD_LEN: usize = HANDSHAKE_BLOB_LEN / 2; // 480

// ------------------------------------------------------------
// HARDWARE ENTROPIE (RDRAND)
// ------------------------------------------------------------

/// Nutzt den x86_64 RDRAND Befehl, um echten Zufall direkt aus der CPU zu ziehen.
pub fn hardware_rand_bytes(buf: &mut [u8]) {
    let mut i = 0;
    while i < buf.len() {
        let mut val: u64 = 0;
        unsafe {
            while core::arch::x86_64::_rdrand64_step(&mut val) != 1 {
                core::arch::asm!("pause");
            }
        }
        let chunk = val.to_ne_bytes();
        let copy_len = core::cmp::min(8, buf.len() - i);
        buf[i..i + copy_len].copy_from_slice(&chunk[..copy_len]);
        i += copy_len;
    }
}

pub struct HardwareRng;

impl RngCore for HardwareRng {
    fn next_u32(&mut self) -> u32 {
        let mut val: u64 = 0;
        unsafe { while core::arch::x86_64::_rdrand64_step(&mut val) != 1 { core::arch::asm!("pause"); } }
        val as u32
    }
    fn next_u64(&mut self) -> u64 {
        let mut val: u64 = 0;
        unsafe { while core::arch::x86_64::_rdrand64_step(&mut val) != 1 { core::arch::asm!("pause"); } }
        val
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) { hardware_rand_bytes(dest); }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for HardwareRng {}

pub fn random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    hardware_rand_bytes(&mut key);
    key
}

// ------------------------------------------------------------
// PURE-RUST POLY1305 (keine externe SIMD-abhängige Crate)
// Implementierung nach RFC 8439, Abschnitt 2.5
// Nutzt u32-Arithmetik für maximale Kompatibilität ohne SIMD
// ------------------------------------------------------------

struct Poly1305 {
    r: [u32; 5],   // r (geclampter Teil des Keys), als Limbs
    h: [u32; 5],   // Akkumulator
    pad: [u32; 4], // s (Additivteil des Keys)
}

impl Poly1305 {
    fn new(key: &[u8; 32]) -> Self {
        // r laden und clampen (RFC 8439 Sec. 2.5.1)
        let mut r = [0u32; 5];
        r[0] =  (u32::from_le_bytes(key[0..4].try_into().unwrap()))       & 0x3ffffff;
        r[1] = ((u32::from_le_bytes(key[3..7].try_into().unwrap())) >> 2)  & 0x3ffff03;
        r[2] = ((u32::from_le_bytes(key[6..10].try_into().unwrap())) >> 4) & 0x3ffc0ff;
        r[3] = ((u32::from_le_bytes(key[9..13].try_into().unwrap())) >> 6) & 0x3f03fff;
        r[4] = ((u32::from_le_bytes(key[12..16].try_into().unwrap())) >> 8) & 0x00fffff;

        // s laden (pad)
        let mut pad = [0u32; 4];
        pad[0] = u32::from_le_bytes(key[16..20].try_into().unwrap());
        pad[1] = u32::from_le_bytes(key[20..24].try_into().unwrap());
        pad[2] = u32::from_le_bytes(key[24..28].try_into().unwrap());
        pad[3] = u32::from_le_bytes(key[28..32].try_into().unwrap());

        Self { r, h: [0u32; 5], pad }
    }

    fn block(&mut self, msg: &[u8], final_block: bool) {
        let hibit: u32 = if final_block { 0 } else { 1 << 24 };

        let mut m = [0u32; 5];
        // Block als 130-bit Zahl (5x 26-bit Limbs) laden
        let mut tmp = [0u8; 16];
        let len = core::cmp::min(msg.len(), 16);
        tmp[..len].copy_from_slice(&msg[..len]);

        m[0] =  u32::from_le_bytes(tmp[0..4].try_into().unwrap())         & 0x3ffffff;
        m[1] = (u32::from_le_bytes(tmp[3..7].try_into().unwrap()) >> 2)   & 0x3ffffff;
        m[2] = (u32::from_le_bytes(tmp[6..10].try_into().unwrap()) >> 4)  & 0x3ffffff;
        m[3] = (u32::from_le_bytes(tmp[9..13].try_into().unwrap()) >> 6)  & 0x3ffffff;
        m[4] = (u32::from_le_bytes(tmp[12..16].try_into().unwrap()) >> 8) | hibit;

        // h += m
        let h0 = self.h[0].wrapping_add(m[0]);
        let h1 = self.h[1].wrapping_add(m[1]);
        let h2 = self.h[2].wrapping_add(m[2]);
        let h3 = self.h[3].wrapping_add(m[3]);
        let h4 = self.h[4].wrapping_add(m[4]);

        // h *= r (mod 2^130 - 5), vollständig in u64 um Overflow zu vermeiden
        let r0 = self.r[0] as u64;
        let r1 = self.r[1] as u64;
        let r2 = self.r[2] as u64;
        let r3 = self.r[3] as u64;
        let r4 = self.r[4] as u64;

        // 5 * r[i] Optimierung (mod 2^130-5 Eigenschaft)
        let s1 = r1 * 5;
        let s2 = r2 * 5;
        let s3 = r3 * 5;
        let s4 = r4 * 5;

        let h0 = h0 as u64;
        let h1 = h1 as u64;
        let h2 = h2 as u64;
        let h3 = h3 as u64;
        let h4 = h4 as u64;

        let mut d0 = h0*r0 + h1*s4 + h2*s3 + h3*s2 + h4*s1;
        let mut d1 = h0*r1 + h1*r0 + h2*s4 + h3*s3 + h4*s2;
        let mut d2 = h0*r2 + h1*r1 + h2*r0 + h3*s4 + h4*s3;
        let mut d3 = h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*s4;
        let mut d4 = h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0;

        // Carries propagieren (26-bit Limbs)
        let mut c: u64;
        c = d0 >> 26; self.h[0] = (d0 & 0x3ffffff) as u32; d1 += c;
        c = d1 >> 26; self.h[1] = (d1 & 0x3ffffff) as u32; d2 += c;
        c = d2 >> 26; self.h[2] = (d2 & 0x3ffffff) as u32; d3 += c;
        c = d3 >> 26; self.h[3] = (d3 & 0x3ffffff) as u32; d4 += c;
        c = d4 >> 26; self.h[4] = (d4 & 0x3ffffff) as u32;
        self.h[0] += (c * 5) as u32;
        c = (self.h[0] >> 26) as u64;
        self.h[0] &= 0x3ffffff;
        self.h[1] += c as u32;
    }

    fn update(&mut self, data: &[u8]) {
        let mut i = 0;
        while i + 16 <= data.len() {
            self.block(&data[i..i+16], false);
            i += 16;
        }
        if i < data.len() {
            self.block(&data[i..], true);
        }
    }

    fn finalize(mut self) -> [u8; 16] {
        // Vollständige Reduktion mod 2^130-5
        let mut c: u32;
        c = self.h[1] >> 26; self.h[1] &= 0x3ffffff; self.h[2] += c;
        c = self.h[2] >> 26; self.h[2] &= 0x3ffffff; self.h[3] += c;
        c = self.h[3] >> 26; self.h[3] &= 0x3ffffff; self.h[4] += c;
        c = self.h[4] >> 26; self.h[4] &= 0x3ffffff; self.h[0] += c * 5;
        c = self.h[0] >> 26; self.h[0] &= 0x3ffffff; self.h[1] += c;

        // h + (-p) berechnen
        let mut g = [0u32; 5];
        g[0] = self.h[0].wrapping_add(5);
        c = g[0] >> 26; g[0] &= 0x3ffffff;
        g[1] = self.h[1].wrapping_add(c);
        c = g[1] >> 26; g[1] &= 0x3ffffff;
        g[2] = self.h[2].wrapping_add(c);
        c = g[2] >> 26; g[2] &= 0x3ffffff;
        g[3] = self.h[3].wrapping_add(c);
        c = g[3] >> 26; g[3] &= 0x3ffffff;
        g[4] = self.h[4].wrapping_add(c).wrapping_sub(1 << 26);

        // Conditional select: g wenn h >= 2^130-5, sonst h
        let mask = (g[4] >> 31).wrapping_sub(1);
        let nmask = !mask;
        for i in 0..5 {
            self.h[i] = (self.h[i] & nmask) | (g[i] & mask);
        }

        // Zu 128-bit Wert zusammenbauen
        let h0 = self.h[0] | (self.h[1] << 26);
        let h1 = (self.h[1] >> 6) | (self.h[2] << 20);
        let h2 = (self.h[2] >> 12) | (self.h[3] << 14);
        let h3 = (self.h[3] >> 18) | (self.h[4] << 8);

        // + s (pad) addieren
        let (f0, carry) = (h0 as u64).overflowing_add(self.pad[0] as u64);
        let (f1, carry) = (h1 as u64).overflowing_add(self.pad[1] as u64 + carry as u64);
        let (f2, carry) = (h2 as u64).overflowing_add(self.pad[2] as u64 + carry as u64);
        let (f3, _)     = (h3 as u64).overflowing_add(self.pad[3] as u64 + carry as u64);

        let mut tag = [0u8; 16];
        tag[0..4].copy_from_slice(&(f0 as u32).to_le_bytes());
        tag[4..8].copy_from_slice(&(f1 as u32).to_le_bytes());
        tag[8..12].copy_from_slice(&(f2 as u32).to_le_bytes());
        tag[12..16].copy_from_slice(&(f3 as u32).to_le_bytes());
        tag
    }
}

// Konstanter Zeitvergleich (timing-safe)
fn ct_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// ------------------------------------------------------------
// CHACHA20-POLY1305 AEAD (RFC 8439)
// ------------------------------------------------------------

/// Generiert den Poly1305 Einmalschlüssel via ChaCha20 Block 0
fn poly1305_key_gen(key: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let mut block = [0u8; 64];
    // ChaCha20 mit Counter=0, ersten 32 Bytes = Poly1305 Key
    let mut cipher = ChaCha20::new(key.into(), nonce.into());
    cipher.apply_keystream(&mut block);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&block[0..32]);
    // Speicher sicher löschen
    for b in block.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0u8); }
    }
    poly_key
}

pub fn nonce_from_counter(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..8].copy_from_slice(&counter.to_be_bytes());
    nonce
}

/// Verschlüsselt `data` in-place und hängt den 16-Byte MAC an.
/// Layout danach: [ciphertext | 16-byte tag]
pub fn encrypt_message(key: &[u8; 32], counter: u64, data: &mut Vec<u8>) {
    let nonce = nonce_from_counter(counter);

    // 1. Poly1305 Schlüssel via Block 0 generieren
    let poly_key = poly1305_key_gen(key, &nonce);

    // 2. Plaintext verschlüsseln (ChaCha20, Counter startet bei 1)
    //    chacha20 crate: new() setzt Counter=0, aber Block 0 haben wir
    //    bereits für den Poly1305-Key genutzt. Wir nutzen seek() um
    //    Block 1 zu adressieren.
    use chacha20::cipher::StreamCipherSeek;
    let mut cipher = ChaCha20::new(key.into(), &nonce.into());
    cipher.seek(64u32); // Block 1 = Byte-Offset 64
    cipher.apply_keystream(data);

    // 3. MAC über Ciphertext berechnen
    let mut mac = Poly1305::new(&poly_key);
    mac.update(data);
    let tag = mac.finalize();

    // 4. Tag anhängen
    data.extend_from_slice(&tag);
}

/// Entschlüsselt `data` (Format: [ciphertext | 16-byte tag]) in-place.
/// Gibt Err(()) bei MAC-Fehler zurück (timing-safe Vergleich).
pub fn decrypt_message<'a>(key: &[u8; 32], counter: u64, data: &'a mut Vec<u8>) -> Result<&'a [u8], ()> {
    if data.len() < 16 {
        return Err(());
    }

    let nonce = nonce_from_counter(counter);
    let poly_key = poly1305_key_gen(key, &nonce);

    // Tag trennen
    let tag_start = data.len() - 16;
    let received_tag: [u8; 16] = data[tag_start..].try_into().unwrap();

    // MAC über Ciphertext verifizieren
    let mut mac = Poly1305::new(&poly_key);
    mac.update(&data[..tag_start]);
    let expected_tag = mac.finalize();

    // Timing-sicherer Vergleich VOR Entschlüsselung
    if !ct_eq(&expected_tag, &received_tag) {
        return Err(());
    }

    // Entschlüsseln
    use chacha20::cipher::StreamCipherSeek;
    data.truncate(tag_start);
    let mut cipher = ChaCha20::new(key.into(), &nonce.into());
    cipher.seek(64u32); // Block 1
    cipher.apply_keystream(data);

    Ok(data)
}

// ------------------------------------------------------------
// KRYPTOGRAFISCHE FUNKTIONEN (REED-SOLOMON)
// ------------------------------------------------------------

pub fn rs_encode(data: &mut Vec<u8>) -> Vec<Vec<u8>> {
    if data.len() % 2 != 0 { data.push(0); }
    let mid = data.len() / 2;
    let mut shards = vec![data[0..mid].to_vec(), data[mid..].to_vec(), vec![0u8; mid]];
    ReedSolomon::new(2, 1).unwrap().encode(&mut shards).unwrap();
    shards
}

pub fn rs_reconstruct(shards: &mut Vec<Option<Vec<u8>>>) -> Result<(), reed_solomon_erasure::Error> {
    ReedSolomon::new(2, 1).unwrap().reconstruct(shards)
}

// ------------------------------------------------------------
// SHAMIR SECRET SHARING (SHARKS IMPLEMENTATION)
// ------------------------------------------------------------

pub fn shamir_split(secret: &[u8; 32]) -> Vec<Vec<u8>> {
    let sharks = Sharks(2); // Threshold = 2
    let mut rng = HardwareRng;
    sharks.dealer_rng(secret, &mut rng)
        .take(3)
        .map(|s| Vec::from(&s))
        .collect()
}

pub fn shamir_join(share0: &[u8], share1: &[u8]) -> Vec<u8> {
    let sharks = Sharks(2);
    let shares = [
        Share::try_from(share0).expect("Invalid share 0"),
        Share::try_from(share1).expect("Invalid share 1"),
    ];
    sharks.recover(&shares).expect("Failed to reconstruct secret")
}

// ------------------------------------------------------------
// IDENTITÄTS-MANAGEMENT
// ------------------------------------------------------------

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

        let kyber_public = kyber_keypair(&mut rng).unwrap().public;
        Self { signing_key, x_public, kyber_public }
    }

    pub fn fingerprint(&self) -> String {
        hex::encode(&self.signing_key.verifying_key().to_bytes()[0..8])
    }

    pub fn build_handshake_blob(&self) -> Vec<u8> {
        let mut blob = vec![0u8; HANDSHAKE_BLOB_LEN];
        blob[0..16].copy_from_slice(b"GHOST_HANDSHAKE_");
        blob[16..48].copy_from_slice(self.x_public.as_bytes());
        blob[48..848].copy_from_slice(&self.kyber_public);

        let sig = self.signing_key.sign(&self.kyber_public);
        blob[848..880].copy_from_slice(&self.signing_key.verifying_key().to_bytes());
        blob[880..944].copy_from_slice(&sig.to_bytes());
        blob
    }
}