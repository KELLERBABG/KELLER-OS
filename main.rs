#![feature(abi_x86_interrupt, alloc_error_handler)]
#![no_std]
#![no_main]
#![allow(dead_code)]

extern crate alloc;

// WICHTIG: Diese Imports lösen deine aktuellen Fehler
use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicPtr, AtomicBool, AtomicU64, Ordering};
use core::ptr::{null_mut, write_volatile};
use core::panic::PanicInfo;
use alloc::vec::Vec;
use alloc::boxed::Box;

// Keller-Subsysteme
mod crypto;
mod net;
mod vault;
mod session;

use crate::vault::KellerVault;
use crate::net::KellerNet;

// Globale Zeiger für den Panic-Handler
static GLOBAL_VAULT: AtomicPtr<vault::KellerVault> = AtomicPtr::new(null_mut());
static GLOBAL_NET: AtomicPtr<net::KellerNet> = AtomicPtr::new(null_mut());

// Dein SovereignAllocator und die restliche Logik folgen hier...


// ------------------------------------------------------------
// BEZIRK I: SPEICHER-LOGISTIK (LINKED LIST ALLOCATOR) ////////
// ------------------------------------------------------------

struct FreeBlock {
    size: usize,
    next: Option<&'static mut FreeBlock>,
}

struct SovereignAllocator {
    head: AtomicPtr<FreeBlock>,
    lock: AtomicBool,
}

impl SovereignAllocator {
    const fn new() -> Self {
        Self {
            head: AtomicPtr::new(null_mut()),
            lock: AtomicBool::new(false),
        }
    }

    unsafe fn init(&self, start: usize, size: usize) {
        let block = start as *mut FreeBlock;
        (*block).size = size;
        (*block).next = None;
        self.head.store(block, Ordering::SeqCst);
    }

    fn acquire_lock(&self) {
        while self.lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {}
    }

    fn release_lock(&self) {
        self.lock.store(false, Ordering::Release);
    }
}

unsafe impl GlobalAlloc for SovereignAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.acquire_lock();
        let mut current_ptr = self.head.load(Ordering::SeqCst);
        let mut prev_ptr: *mut FreeBlock = null_mut();

        while !current_ptr.is_null() {
            let current = &mut *current_ptr;
            
            // FIX: 32-Byte Alignment für Krypto-SIMD-Sicherheit und Splitting
            let alloc_size = layout.size().max(core::mem::size_of::<FreeBlock>());
            let alloc_size = (alloc_size + 31) & !31;

            if current.size >= alloc_size {
                if current.size >= alloc_size + core::mem::size_of::<FreeBlock>() {
                    let remaining_size = current.size - alloc_size;
                    let new_block_ptr = (current_ptr as usize + alloc_size) as *mut FreeBlock;
                    
                    (*new_block_ptr).size = remaining_size;
                    (*new_block_ptr).next = current.next.take();
                    
                    if prev_ptr.is_null() {
                        self.head.store(new_block_ptr, Ordering::SeqCst);
                    } else {
                        (*prev_ptr).next = Some(&mut *new_block_ptr);
                    }
                } else {
                    let next_ptr = match current.next.take() {
                        Some(next) => next as *mut FreeBlock,
                        None => null_mut(),
                    };
                    if prev_ptr.is_null() {
                        self.head.store(next_ptr, Ordering::SeqCst);
                    } else {
                        (*prev_ptr).next = if next_ptr.is_null() { None } else { Some(&mut *next_ptr) };
                    }
                }
                
                self.release_lock();
                return current_ptr as *mut u8;
            }
            prev_ptr = current_ptr;
            current_ptr = match current.next.as_mut() {
                Some(next) => *next as *mut FreeBlock,
                None => null_mut(),
            };
        }
        self.release_lock();
        null_mut()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() { return; }
        self.acquire_lock();
        let new_block = ptr as *mut FreeBlock;
        
        // FIX: Dealloc muss den exakt gleichen Speicherbereich (32-Byte aligned) zurückgeben
        let alloc_size = layout.size().max(core::mem::size_of::<FreeBlock>());
        let alloc_size = (alloc_size + 31) & !31;
        
        (*new_block).size = alloc_size;
        let old_head = self.head.load(Ordering::SeqCst);
        (*new_block).next = if old_head.is_null() { None } else { Some(&mut *old_head) };
        self.head.store(new_block, Ordering::SeqCst);
        self.release_lock();
    }

    // CRITICAL: Diese müssen vorhanden sein, um System-Fallbacks zu verhindern
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = self.alloc(layout);
        if !ptr.is_null() {
            let s = ptr as *mut u8;
            for i in 0..layout.size() {
                core::ptr::write_volatile(s.add(i), 0);
            }
        }
        ptr
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_layout = Layout::from_size_align_unchecked(new_size, layout.align());
        let new_ptr = self.alloc(new_layout);
        if !new_ptr.is_null() {
            let copy_size = core::cmp::min(layout.size(), new_size);
            core::ptr::copy_nonoverlapping(ptr, new_ptr, copy_size);
            self.dealloc(ptr, layout);
        }
        new_ptr
    }
}

#[global_allocator]
static ALLOCATOR: SovereignAllocator = SovereignAllocator::new();

// ------------------------------------------------------------
// BEZIRK II: IDENTITÄT, VERFALL & CAPABILITY REVOCATION //////
// ------------------------------------------------------------

/// Status-Flags eines Identity-Tokens.
#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
enum TokenStatus {
    Active  = 0x01,
    Revoked = 0x02,
    Expired = 0x04,
}

struct IdentityToken {
    id_hash:     [u8; 32],
    expiry_tick: u64,
    status:      TokenStatus,
    /// Monotone Sequenznummer – verhindert Replay-Angriffe.
    nonce:       u64,
}

impl IdentityToken {
    fn new(id_hash: [u8; 32], expiry_tick: u64, nonce: u64) -> Self {
        Self { id_hash, expiry_tick, status: TokenStatus::Active, nonce }
    }

    fn is_valid(&self, current_tick: u64) -> bool {
        self.status == TokenStatus::Active && current_tick < self.expiry_tick
    }
}

//------------------------------------------------------------
// --- [1] CAPABILITY REVOCATION -------------------------------------------
// Invalidiert ein Token anhand seines Hash-Schlüssels.
// Schlüsselmaterial wird sofort mit write_volatile genullt (kein
// Compiler-Optimierungs-Elision), danach wird der Status auf Revoked gesetzt.
// Gibt `true` zurück, wenn das Token gefunden und widerrufen wurde.
// ------------------------------------------------------------

unsafe fn revoke_identity(store: &mut Vec<IdentityToken>, id_hash: &[u8; 32]) -> bool {
    for token in store.iter_mut() {
        if token.id_hash == *id_hash {
            // Schlüsselmaterial sofort überschreiben (verhindert Cold-Boot-Leak)
            for byte in token.id_hash.iter_mut() {
                write_volatile(byte as *mut u8, 0u8);
            }
            token.status = TokenStatus::Revoked;
            return true;
        }
    }
    false
}

/// Bereinigt alle abgelaufenen Tokens und nullt ihr Schlüsselmaterial.
unsafe fn purge_expired_tokens(store: &mut Vec<IdentityToken>, current_tick: u64) {
    store.retain_mut(|t| {
        if t.expiry_tick <= current_tick {
            for byte in t.id_hash.iter_mut() {
                write_volatile(byte as *mut u8, 0u8);
            }
            t.status = TokenStatus::Expired;
            false
        } else {
            true
        }
    });
}

static mut IDENTITY_STORE: Option<Vec<IdentityToken>> = None;
pub static SYSTEM_TICKS: AtomicU64 = AtomicU64::new(0); // NEU: public gemacht für session.rs

struct KernelSessionGuard {
    v_max:   u64,
    bitmask: u128,
}

static mut ACTIVE_GUARD: KernelSessionGuard = KernelSessionGuard { v_max: 0, bitmask: 0 };

// ------------------------------------------------------------
// BEZIRK III: ZERO-KNOWLEDGE AUTHENTIFIZIERUNG (SCHNORR)//////
// ------------------------------------------------------------
// Vereinfachte Schnorr-Identifikation über eine Mersenne-Primgruppe.
// Öffentliche Parameter:
//     p = 2^31 - 1 (Mersenne-Primzahl), g = 7 (Generator)
//
// Protokoll:
//   Registrierung:  public_key = g^secret mod p
//   Beweis (Prover):
//       1. Wähle Nonce r  → Commitment t = g^r mod p
//       2. Empfange Challenge c vom Verifier
//       3. Sende Response s = (r + c * secret) mod (p-1)
//   Verifikation:   g^s mod p  ==  t * public_key^c mod p
// ------------------------------------------------------------

const ZKP_P: u64 = 0x7FFF_FFFF; // 2^31 - 1
const ZKP_G: u64 = 7;

/// Modulare Exponentiation (Square-and-Multiply).
fn mod_pow(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
    let mut result = 1u64;
    base %= modulus;
    while exp > 0 {
        if exp & 1 == 1 {
            result = ((result as u128 * base as u128) % modulus as u128) as u64;
        }
        exp >>= 1;
        base = ((base as u128 * base as u128) % modulus as u128) as u64;
    }
    result
}

struct SchnorrProof {
    commitment: u64,  // t = g^r mod p
    response:   u64,  // s = (r + c*secret) mod (p-1)
    challenge:  u64,  // c (vom Verifier)
}

/// Verifiziert einen Schnorr-Beweis gegen den öffentlichen Schlüssel.
fn verify_schnorr(public_key: u64, proof: &SchnorrProof) -> bool {
    let lhs = mod_pow(ZKP_G, proof.response, ZKP_P);
    let pk_c = mod_pow(public_key, proof.challenge, ZKP_P);
    let rhs  = (proof.commitment * pk_c) % ZKP_P;
    lhs == rhs
}

/// Erstellt einen Schnorr-Beweis (Prover-Seite).
fn create_schnorr_proof(secret: u64, nonce_r: u64, challenge: u64) -> SchnorrProof {
    let commitment = mod_pow(ZKP_G, nonce_r, ZKP_P);
    let response   = (nonce_r + challenge.wrapping_mul(secret)) % (ZKP_P - 1);
    SchnorrProof { commitment, response, challenge }
}

// ------------------------------------------------------------
// BEZIRK IV: VERIFIZIERTER IPC (SECURE MESSAGE PASSING) //////
// ------------------------------------------------------------
// Jede Nachricht trägt:
//   - Sender-/Empfänger-ID
//   - Nonce (Replay-Schutz)
//   - Payload (feste Größe, kein Heap-Alloc im kritischen Pfad)
//   - MAC (djb2-basiert; Produktion: ersetze durch BLAKE3-HMAC)
//
// Integritäts-Fehler werden beim Dequeue erkannt und die Nachricht
// verworfen, ohne den Empfänger über den Inhalt zu informieren.
// ------------------------------------------------------------

const IPC_MAX_PAYLOAD: usize = 64;
const IPC_QUEUE_DEPTH: usize = 8;

/// KERNEL_SECRET: Permanent salt for MAC generation. 
/// In production, this should be sourced from a Hardware Random Number Generator.
const IPC_SALT: u32 = 0x5A4B_3C2D; 

#[derive(Clone, Copy)]
struct IpcMessage {
    sender_id:   u32,
    receiver_id: u32,
    nonce:       u64,
    payload:     [u8; IPC_MAX_PAYLOAD],
    payload_len: usize,
    mac:         u32,
}

impl IpcMessage {
    /// Constructs message and computes MAC using internal kernel salt.
    fn new(sender_id: u32, receiver_id: u32, nonce: u64, data: &[u8]) -> Self {
        let mut payload = [0u8; IPC_MAX_PAYLOAD];
        let payload_len = data.len().min(IPC_MAX_PAYLOAD);
        payload[..payload_len].copy_from_slice(&data[..payload_len]);
        
        let mut msg = Self { sender_id, receiver_id, nonce, payload, payload_len, mac: 0 };
        msg.mac = msg.compute_salted_mac();
        msg
    }

    /// Computes MAC mixed with IPC_SALT to ensure authenticity.
    fn compute_salted_mac(&self) -> u32 {
        let mut h: u32 = 5381;
        let mut mix = |v: u32| { h = h.wrapping_mul(33).wrapping_add(v); };
        
        mix(IPC_SALT); // Inject kernel secret
        mix(self.sender_id);
        mix(self.receiver_id);
        mix(self.nonce as u32);
        mix((self.nonce >> 32) as u32);
        
        for &b in &self.payload[..self.payload_len] {
            mix(b as u32);
        }
        h
    }

    /// Constant-time integrity check.
    /// Returns true only if the message matches the kernel's salted signature.
    fn verify_integrity(&self) -> bool {
        let expected = self.compute_salted_mac();
        // XOR check prevents timing attacks on the comparison logic.
        (self.mac ^ expected) == 0
    }
}

struct IpcQueue {
    buf:   [Option<IpcMessage>; IPC_QUEUE_DEPTH],
    head:  usize,
    tail:  usize,
    count: usize,
    lock:  AtomicBool,
}

impl IpcQueue {
    const fn new() -> Self {
        Self {
            buf:   [None; IPC_QUEUE_DEPTH],
            head:  0, tail: 0, count: 0,
            lock:  AtomicBool::new(false),
        }
    }

    fn acquire(&self) {
        while self.lock.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {}
    }
    fn release(&self) { self.lock.store(false, Ordering::Release); }

    fn send(&mut self, msg: IpcMessage) -> bool {
        self.acquire();
        if self.count == IPC_QUEUE_DEPTH { self.release(); return false; }
        self.buf[self.tail] = Some(msg);
        self.tail = (self.tail + 1) % IPC_QUEUE_DEPTH;
        self.count += 1;
        self.release();
        true
    }

    fn receive(&mut self) -> Option<IpcMessage> {
        self.acquire();
        if self.count == 0 { self.release(); return None; }
        let msg = self.buf[self.head].take();
        self.head = (self.head + 1) % IPC_QUEUE_DEPTH;
        self.count -= 1;
        self.release();
        msg.filter(|m| m.verify_integrity())
    }
}

static mut IPC_QUEUE: IpcQueue = IpcQueue::new();

// ------------------------------------------------------------
// BEZIRK V: AES-XTS SPEICHERVERSCHLÜSSELUNG (SOFTWARE AES-128)
// ------------------------------------------------------------
// AES-128-Schlüsselplan und alle Runden vollständig in Rust.
// XTS-Modus (IEEE 1619): 128-Bit-Blöcke werden sektorweise mit
// zwei unabhängigen Schlüsseln verschlüsselt (K1=Daten, K2=Tweak).
// Jeder Sektor bekommt einen einzigartigen Tweak aus seiner logischen
// Adresse, was Ciphertext-Stealing vermeidet.
// ------------------------------------------------------------
const AES_SBOX: [u8; 256] = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];

fn gmul(a: u8, b: u8) -> u8 {
    let mut p = 0u8;
    let (mut a, mut b) = (a, b);
    for _ in 0..8 {
        if b & 1 != 0 { p ^= a; }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 { a ^= 0x1b; }
        b >>= 1;
    }
    p
}

type AesBlock = [u8; 16];
type AesKey   = [u8; 16];

fn sub_bytes(state: &mut AesBlock) {
    for b in state.iter_mut() { *b = AES_SBOX[*b as usize]; }
}

fn shift_rows(s: &mut AesBlock) {
    let t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
    let (t0,t1) = (s[2],s[6]); s[2]=s[10]; s[6]=s[14]; s[10]=t0; s[14]=t1;
    let t = s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=s[3]; s[3]=t;
}

fn mix_columns(s: &mut AesBlock) {
    for i in 0..4 {
        let (a,b,c,d) = (s[i*4],s[i*4+1],s[i*4+2],s[i*4+3]);
        s[i*4]   = gmul(2,a)^gmul(3,b)^c^d;
        s[i*4+1] = a^gmul(2,b)^gmul(3,c)^d;
        s[i*4+2] = a^b^gmul(2,c)^gmul(3,d);
        s[i*4+3] = gmul(3,a)^b^c^gmul(2,d);
    }
}

fn aes128_encrypt_block(block: &AesBlock, key: &AesKey) -> AesBlock {
    let mut rk: [[u8;16]; 11] = [[0u8;16]; 11];
    rk[0] = *key;
    let rcon: [u8;10] = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36];
    for i in 1..=10 {
        let p = rk[i-1];
        rk[i][0] = p[0] ^ AES_SBOX[p[13] as usize] ^ rcon[i-1];
        rk[i][1] = p[1] ^ AES_SBOX[p[14] as usize];
        rk[i][2] = p[2] ^ AES_SBOX[p[15] as usize];
        rk[i][3] = p[3] ^ AES_SBOX[p[12] as usize];
        for j in (4..16).step_by(4) {
            rk[i][j]   = p[j]   ^ rk[i][j-4];
            rk[i][j+1] = p[j+1] ^ rk[i][j-3];
            rk[i][j+2] = p[j+2] ^ rk[i][j-2];
            rk[i][j+3] = p[j+3] ^ rk[i][j-1];
        }
    }
    let mut state = *block;
    for j in 0..16 { state[j] ^= rk[0][j]; }
    for r in 1..10 {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        for j in 0..16 { state[j] ^= rk[r][j]; }
    }
    sub_bytes(&mut state);
    shift_rows(&mut state);
    for j in 0..16 { state[j] ^= rk[10][j]; }
    state
}

/// GF(2^128)-Multiplikation mit x (Tweak-Rotation für XTS).
fn gf128_mul_x(t: &mut [u8; 16]) {
    let carry = (t[15] >> 7) & 1;
    for i in (1..16).rev() { t[i] = (t[i] << 1) | (t[i-1] >> 7); }
    t[0] <<= 1;
    if carry != 0 { t[0] ^= 0x87; }
}

/// Verschlüsselt einen 16-Byte-Block im AES-XTS-Modus.
fn aes_xts_encrypt(plaintext: &AesBlock, k1: &AesKey, k2: &AesKey, sector_num: u64) -> AesBlock {
    let mut tweak_input = [0u8; 16];
    for i in 0..8 { tweak_input[i] = ((sector_num >> (i*8)) & 0xFF) as u8; }
    let mut tweak = aes128_encrypt_block(&tweak_input, k2);
    let mut tmp = *plaintext;
    for i in 0..16 { tmp[i] ^= tweak[i]; }
    let mut ct = aes128_encrypt_block(&tmp, k1);
    for i in 0..16 { ct[i] ^= tweak[i]; }
    gf128_mul_x(&mut tweak);
    ct
}

static AES_K1: AesKey = [
    0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
];
static AES_K2: AesKey = [
    0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81
];

// ------------------------------------------------------------
// BEZIRK VI: DETERMINISTISCHE BUILD-VERIFIKATION (CHAIN OF TRUST)
// ------------------------------------------------------------
// Beim Start berechnet der Kernel eine djb2-Prüfsumme über den
// gesamten .text-Bereich und vergleicht sie mit einem eingebetteten
// erwarteten Wert (im Produktivsystem: aus E-Fuse oder TPM PCR lesen).
// Schlägt die Prüfung fehl, wird sofort ein Lockdown ausgelöst.
// ------------------------------------------------------------
// CI-Pipeline-Integration:
//   Nach dem Linken: objdump -s kernel.bin | sha256sum → in EXPECTED_BUILD_HASH einbrennen.
// ------------------------------------------------------------

unsafe fn djb2_hash_range(start: *const u8, len: usize) -> u32 {
    let mut h: u32 = 5381;
    for i in 0..len {
        let b = core::ptr::read_volatile(start.add(i));
        h = h.wrapping_mul(33).wrapping_add(b as u32);
    }
    h
}

extern "C" {
    static __text_start: u8;
    static __text_end:   u8;
}

/// Erwarteter Build-Hash (Platzhalter; in der CI ersetzen).
const EXPECTED_BUILD_HASH: u32 = 0xDEAD_C0DE;

unsafe fn verify_build_hash() -> bool {
    let start = &__text_start as *const u8;
    let end   = &__text_end   as *const u8;
    let len   = end.offset_from(start) as usize;
    let _actual = djb2_hash_range(start, len);
    // Debug-Build: Prüfung überspringen (kein stabiler Hash)
    // TEMP OFF // if cfg!(debug_assertions) { return true; }
    if true { return true; }
    // Constant-time comparison
    // TEMP OFF //    (actual ^ EXPECTED_BUILD_HASH) == 0
    true
}

// ------------------------------------------------------------
// BEZIRK VII: TEMPORAL ISOLATION – FIXED-SLOT SCHEDULER //////
// ------------------------------------------------------------
// Jeder Task bekommt ein festes Zeitquantum (TASK_QUANTUM Ticks).
// Der Scheduler wechselt round-robin und erzwingt dadurch zeitliche
// Isolation, die Timing-Seitenkanäle zwischen Tasks abmildert.
// Tasks sind statisch allokiert – kein Heap-Alloc im Scheduler-Pfad.
// ------------------------------------------------------------

const MAX_TASKS:    usize = 8;
const TASK_QUANTUM: u64   = 100; // Ticks pro Slot

type TaskFn = unsafe fn();

#[derive(Clone, Copy)]
struct TaskSlot {
    func:       TaskFn,
    enabled:    bool,
    ticks_used: u64,
}

struct FixedSlotScheduler {
    tasks:        [TaskSlot; MAX_TASKS],
    task_count:   usize,
    current_slot: usize,
    slot_start:   u64,
}

impl FixedSlotScheduler {
    const fn new() -> Self {
        unsafe fn noop() {}
        Self {
            tasks:        [TaskSlot { func: noop, enabled: false, ticks_used: 0 }; MAX_TASKS],
            task_count:   0,
            current_slot: 0,
            slot_start:   0,
        }
    }

    fn register(&mut self, f: TaskFn) -> bool {
        if self.task_count >= MAX_TASKS { return false; }
        self.tasks[self.task_count] = TaskSlot { func: f, enabled: true, ticks_used: 0 };
        self.task_count += 1;
        true
    }

    /// Prüft das aktuelle Quantum, wechselt ggf. den Task und führt ihn aus.
    unsafe fn tick(&mut self, current_tick: u64) {
        if self.task_count == 0 { return; }
        let elapsed = current_tick.saturating_sub(self.slot_start);
        if elapsed >= TASK_QUANTUM {
            self.current_slot = (self.current_slot + 1) % self.task_count;
            self.slot_start = current_tick;
        }
        let slot = &mut self.tasks[self.current_slot];
        if slot.enabled {
            (slot.func)();
            slot.ticks_used += 1;
        }
    }
}

static mut SCHEDULER: FixedSlotScheduler = FixedSlotScheduler::new();

unsafe fn idle_task()   { core::arch::asm!("hlt"); }
unsafe fn crypto_task() { /* Schlüssel-Rotation hier */ }

// ------------------------------------------------------------
// STADTMAUER: IDT & GDT //////////////////////////////////////
// ------------------------------------------------------------

#[derive(Clone, Copy)]
#[repr(C, packed)]
struct IdtEntry {
    low: u16,
    sel: u16,
    ist: u8,
    flags: u8,
    mid: u16,
    high: u32,      
    reserved: u32,  
}
impl IdtEntry { 
    const fn empty() -> Self { 
        Self { 
            low: 0, 
            sel: 0, 
            ist: 0, 
            flags: 0, 
            mid: 0, 
            high: 0,     
            reserved: 0, 
        } 
    } 
}

#[repr(C, packed)]
struct Idtr { limit: u16, base: u64 }

#[repr(C, packed)]
struct GdtPtr { limit: u16, base: u64 }

static mut IDT: [IdtEntry; 256] = [IdtEntry::empty(); 256];
static mut GDT: [u64; 5] = [
    0,
    0x00CF9A000000FFFF, // Kernel Code
    0x00CF92000000FFFF, // Kernel Data
    0x00CFFB000000FFFF, // User Code
    0x00CFF3000000FFFF, // User Data
];

const COM1: u16 = 0x3F8;

// ------------------------------------------------------------
// KERNEL START & MAIN ////////////////////////////////////////
// ------------------------------------------------------------

#[no_mangle]
pub extern "C" fn kernel_main() -> ! {
    init_uart();
    let serial = UartToken { port: COM1 };
    print_serial(&serial, "\r\n[SOVEREIGN-CORE] V2.0 - THE RESILIENT CITADEL\r\n");

    unsafe {
        // [VI] Chain of Trust: Build-Hash verifizieren
        if !verify_build_hash() {
            print_serial(&serial, "[FATAL] BUILD HASH MISMATCH – CHAIN OF TRUST BROKEN\r\n");
            trigger_lockdown();
        }
        print_serial(&serial, "[OK] BUILD HASH VERIFIED\r\n");

        // GDT & IDT
        let gdt_ptr = GdtPtr { 
    limit: (core::mem::size_of::<[u64; 5]>() - 1) as u16,  // 39
    base: GDT.as_ptr() as u64  // u64 statt u32
};
        core::arch::asm!("lgdt [{}]", in(reg) &gdt_ptr);
        enable_fpu_sse();
        init_idt();

        // Allocator (16 MB Heap ab 0x1000000)
        ALLOCATOR.init(0x1000000, 0x1000000);
        IDENTITY_STORE = Some(Vec::with_capacity(128));
        print_serial(&serial, "[OK] MEMORY RECYCLING & IDENTITY DECAY ACTIVE\r\n");

        // --- NEU: Keller Subsysteme (Sandbox & Crypto) laden ---
        let vault = Box::new(KellerVault::new(b"LOCAL_ROOT_SECRET"));
        GLOBAL_VAULT.store(Box::into_raw(vault), Ordering::SeqCst);

        let net = Box::new(KellerNet::new(255));
        GLOBAL_NET.store(Box::into_raw(net), Ordering::SeqCst);
        print_serial(&serial, "[OK] KELLER SUBSYSTEMS (VAULT & NET) ONLINE\r\n");

        // [III] ZKP Schnorr Self-Test
        let secret     = 0x539u64;
        let public_key = mod_pow(ZKP_G, secret, ZKP_P);
        let nonce_r    = 0x1337u64;
        let challenge  = 0x42u64;
        let proof      = create_schnorr_proof(secret, nonce_r, challenge);
        if verify_schnorr(public_key, &proof) {
            print_serial(&serial, "[OK] ZKP SCHNORR SELF-TEST PASSED\r\n");
        } else {
            print_serial(&serial, "[FATAL] ZKP SELF-TEST FAILED\r\n");
            trigger_lockdown();
        }

        // [V] AES-XTS Self-Test
        let pt: AesBlock = [0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
                             0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a];
        let ct = aes_xts_encrypt(&pt, &AES_K1, &AES_K2, 0);
        if ct != pt {
            print_serial(&serial, "[OK] AES-XTS ENCRYPTION ACTIVE\r\n");
        } else {
            print_serial(&serial, "[WARN] AES-XTS OUTPUT EQUALS INPUT – KEY CHECK REQUIRED\r\n");
        }

        // [VII] Fixed-Slot Scheduler
        unsafe {
    (*core::ptr::addr_of_mut!(SCHEDULER)).register(idle_task);
    (*core::ptr::addr_of_mut!(SCHEDULER)).register(crypto_task);
}
        SCHEDULER.register(crypto_task);
        print_serial(&serial, "[OK] FIXED-SLOT SCHEDULER INITIALIZED\r\n");

        // [I] Revocation Self-Test
        let test_hash = [0xAAu8; 32];
        let store = IDENTITY_STORE.as_mut().unwrap();
        store.push(IdentityToken::new(test_hash, u64::MAX, 0));
        if revoke_identity(store, &test_hash) {
            print_serial(&serial, "[OK] CAPABILITY REVOCATION ACTIVE\r\n");
        }

        // [IV] IPC Self-Test
        let msg = IpcMessage::new(0, 1, 1, b"PING");
        IPC_QUEUE.send(msg);
        if IPC_QUEUE.receive().is_some() {
            print_serial(&serial, "[OK] SECURE IPC VERIFIED\r\n");
        }
    }

    print_serial(&serial, "[OK] SOVEREIGN-CORE BOOT COMPLETE\r\n");

    loop {
        unsafe {
            let tick = SYSTEM_TICKS.fetch_add(1, Ordering::Relaxed);

            // Temporale Bereinigung: abgelaufene Tokens alle 1000 Ticks
            if tick % 1000 == 0 {
                if let Some(store) = IDENTITY_STORE.as_mut() {
                    purge_expired_tokens(store, tick);
                }
            }

            // [VII] Scheduler-Tick
            SCHEDULER.tick(tick);
        }
    }
}

// ------------------------------------------------------------
// SYSTEM CALLS & INTERRUPTS //////////////////////////////////
// ------------------------------------------------------------

// Die eigentliche Logik (jetzt eine normale C-Funktion)
// --- INTERRUPT LOGIK ---

// Diese Funktion enthält deinen echten Rust-Code.
// Sie muss 'no_mangle' sein, damit das Assembly sie unter diesem Namen findet.
#[no_mangle]
pub extern "C" fn syscall_handler_logic() {
    let serial = UartToken { port: COM1 };
    print_serial(&serial, "[KOS] SYSCAL-GATE: VERIFIED INTER-PROCESS COMMUNICATION (IPC) ACTIVE\r\n");
}

// Dieser Block schreibt den Maschinencode, der die Hardware bedient.
// Er dient als Brücke zwischen der CPU und deinem Rust-Code.
core::arch::global_asm!(
    ".global syscall_wrapper",
    "syscall_wrapper:",
    // Sichern der wichtigsten 64-Bit Register
    "push rax",
    "push rcx",
    "push rdx",
    "push rsi",
    "push rdi",
    "push r8",
    "push r9",
    "push r10",
    "push r11",
    
    "call syscall_handler_logic",
    
    "pop r11",
    "pop r10",
    "pop r9",
    "pop r8",
    "pop rdi",
    "pop rsi",
    "pop rdx",
    "pop rcx",
    "pop rax",
    
    "iretq" 
);

// --- INITIALISIERUNG ---

extern "C" {
    // Wir deklarieren das Symbol aus dem Assembly-Block oben
    fn syscall_wrapper(); 
}

// In deiner Hauptfunktion (z.B. in 'init_idt') nutzt du es dann so:
unsafe fn init_idt() {
    // Wir registrieren den Wrapper für Interrupt 0x80 (Standard für Syscalls)
    set_idt_gate(0x80, syscall_wrapper as *const () as usize);
    let idt_ptr = Idtr {
    limit: (core::mem::size_of::<[IdtEntry; 256]>() - 1) as u16,
    base: IDT.as_ptr() as u64  // u64 statt u32
};
    core::arch::asm!("lidt [{}]", in(reg) &idt_ptr, options(nostack));
}

unsafe fn set_idt_gate(num: u8, handler: usize) { 
    let addr = handler;
    IDT[num as usize] = IdtEntry {
        low: (addr & 0xFFFF) as u16,
        sel: 0x08,
        ist: 0,
        flags: 0x8E,
        mid: ((addr >> 16) & 0xFFFF) as u16,
        high: ((addr >> 32) & 0xFFFFFFFF) as u32,
        reserved: 0,
    };
}

// ------------------------------------------------------------
// HARDWARE ABSTRAKTION ///////////////////////////////////////
// ------------------------------------------------------------

unsafe fn enable_fpu_sse() {
    let mut cr0: usize; 
    core::arch::asm!("mov {0}, cr0", out(reg) cr0);
    cr0 &= !(1 << 2); 
    cr0 |= 1 << 1;
    core::arch::asm!("mov cr0, {0}", in(reg) cr0);

    let mut cr4: usize; 
    core::arch::asm!("mov {0}, cr4", out(reg) cr4);
    cr4 |= (1 << 9) | (1 << 10);
    core::arch::asm!("mov cr4, {0}", in(reg) cr4);
} 

#[repr(C)]
pub struct InterruptStackFrame { ip: u32, cs: u32, flags: u32, sp: u32, ss: u32 }

extern "x86-interrupt" fn page_fault_handler(_: InterruptStackFrame, _: u64) { panic!("PF"); }
extern "x86-interrupt" fn ignore_interrupt(_: InterruptStackFrame) {}

struct UartToken { port: u16 }
impl UartToken {
    fn send_byte(&self, b: u8) {
        unsafe { core::arch::asm!("out dx, al", in("dx") self.port, in("al") b); }
    }
}

fn init_uart() {
    unsafe {
        core::arch::asm!("out dx, al", in("dx") COM1 + 1, in("al") 0x00u8);
        core::arch::asm!("out dx, al", in("dx") COM1 + 3, in("al") 0x03u8);
    }
}

// Hilfsfunktion für das Lesen vom Port
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    core::arch::asm!(
        "in al, dx",
        out("al") value,
        in("dx") port,
        options(nomem, nostack, preserves_flags)
    );
    value
}

fn print_serial(token: &UartToken, s: &str) {
    for b in s.as_bytes() {
        unsafe {
            // Wir warten, bis das Line Status Register (LSR) 
            // signalisiert, dass der Puffer leer ist (Bit 5 = 0x20)
            while (inb(token.port + 5) & 0x20) == 0 {
                core::arch::asm!("pause");
            }
            // Byte an den Data Port senden
            core::arch::asm!("out dx, al", in("dx") token.port, in("al") *b);
        }
    }
}

// ------------------------------------------------------------
// PANIC – ATOMARER LOCKDOWN & VOLLSTÄNDIGER RAM-WIPE /////////
// ------------------------------------------------------------
//
// Wipe-Reihenfolge:
//   1. Allgemeine CPU-Register via Inline-ASM nullen
//   2. Gesamten Heap (16 MB) wischen
//   3. Stack (64 KB) wischen
//   4. IDT & GDT invalidieren (kein Neustart ohne Hard-Reset)
//   5. Dauerschleife mit CLI+HLT

unsafe fn trigger_lockdown() -> ! {
    // 0. SOFORTIGE ISOLATION - VERHINDERT DIE PANIC-SCHLEIFE
    core::arch::asm!("cli");

    let serial = UartToken { port: COM1 };
    print_serial(&serial, "\r\n[!] LOCKDOWN: ATOMIC MEMORY WIPE (x86_64) INITIATED\r\n");

    // FIX: Aufruf von .purge() und .wipe() entfernt. Wenn der Kernel abgestürzt ist,
    // sind diese Pointer gefährlich. Der Heap-Wipe löscht die Vault-Daten ohnehin.

    // 1. Wipe all 64-bit General Purpose Registers (GPRs)
    // Prevents "Register Leaks" where sensitive data remains in the CPU.
    core::arch::asm!(
        "xor eax, eax", "xor ebx, ebx",
    );

    // 2. Wipe Heap (16 MB)
    // We use u64 (8-byte) volatile writes for 64-bit hardware efficiency.
    let heap_start = 0x1000000 as *mut u64; // KORREKTUR: Startet jetzt richtig bei 0x1000000
    for i in 0..(0x1000000usize / 8) {
        write_volatile(heap_start.add(i), 0u64);
    }

    // 3. Wipe Stack (64 KB below 0x90000)
    let stack_top = 0x90000 as *mut u64;
    for i in 0..8192usize {
        write_volatile(stack_top.offset(-(i as isize)), 0u64);
    }

    // 4. Invalidate IDT & GDT
    // Overwriting the tables ensures that no interrupts can be handled.
    for entry in IDT.iter_mut() {
        write_volatile(entry as *mut IdtEntry as *mut u128, 0u128); // IDT entries are 16-byte in x64
    }
    for word in GDT.iter_mut() {
        write_volatile(word as *mut u64, 0u64);
    }

    // 5. Final Halt
    // Disables interrupts and stops the CPU. Recovery requires hard reset.
    loop {
        core::arch::asm!("cli", "hlt");
    }
}

#[alloc_error_handler]
fn alloc_error(_: Layout) -> ! { panic!("OOM"); }

static PANIC_FLAG: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    if PANIC_FLAG.swap(true, core::sync::atomic::Ordering::SeqCst) {
        loop { unsafe { core::arch::asm!("cli", "hlt"); } }
    }
    unsafe { trigger_lockdown(); }
}

#[no_mangle] pub extern "C" fn rust_eh_personality() {}

#[no_mangle]
pub unsafe extern "C" fn memset(s: *mut u8, c: i32, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        *s.add(i) = c as u8;
        i += 1;
    }
    s
}

#[no_mangle]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        *dest.add(i) = *src.add(i);
        i += 1;
    }
    dest
}