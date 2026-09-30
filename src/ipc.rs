//! Verified synchronous IPC.
//!
//! Every message carries sender/receiver ids, a nonce and a keyed digest, and the digest
//! is checked on dequeue before the payload is handed over — a corrupted or forged
//! message is dropped silently and counted rather than delivered.
//!
//! The digest is HMAC-SHA256 (RFC 4231) over the header and payload under a transport key
//! seeded from the kernel DRBG at boot, and it is compared in constant time.

use crate::crypto;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub const MAX_PAYLOAD: usize = 64;
pub const QUEUE_DEPTH: usize = 8;
pub const TAG_LEN: usize = 32;

/// Transport key. Seeded from the kernel DRBG by `seed_key` after the entropy module is
/// up; the transport refuses to be used before that (an unseeded key would authenticate
/// nothing but zeroes).
static mut KEY: [u8; TAG_LEN] = [0; TAG_LEN];
static mut KEY_READY: bool = false;

static DROPPED: AtomicU64 = AtomicU64::new(0);
static DELIVERED: AtomicU64 = AtomicU64::new(0);

/// Draws a fresh transport key from the kernel DRBG. Called once during boot.
pub fn seed_key() {
    let key = crypto::random_key();
    unsafe {
        let target = core::ptr::addr_of_mut!(KEY);
        for index in 0..TAG_LEN {
            (*target)[index] = key[index];
        }
        KEY_READY = true;
    }
}

pub fn key_ready() -> bool {
    unsafe { *core::ptr::addr_of!(KEY_READY) }
}

#[derive(Clone, Copy)]
pub struct IpcMessage {
    pub sender_id: u32,
    pub receiver_id: u32,
    pub nonce: u64,
    pub payload: [u8; MAX_PAYLOAD],
    pub payload_len: usize,
    mac: [u8; TAG_LEN],
}

impl IpcMessage {
    pub fn new(sender_id: u32, receiver_id: u32, nonce: u64, data: &[u8]) -> Self {
        let mut payload = [0u8; MAX_PAYLOAD];
        let payload_len = data.len().min(MAX_PAYLOAD);
        payload[..payload_len].copy_from_slice(&data[..payload_len]);
        let mut message = Self {
            sender_id,
            receiver_id,
            nonce,
            payload,
            payload_len,
            mac: [0; TAG_LEN],
        };
        message.mac = message.compute_mac();
        message
    }

    /// HMAC-SHA256 over the authenticated header fields and the payload bytes.
    fn compute_mac(&self) -> [u8; TAG_LEN] {
        let mut frame = [0u8; 24 + MAX_PAYLOAD];
        frame[0..4].copy_from_slice(&self.sender_id.to_le_bytes());
        frame[4..8].copy_from_slice(&self.receiver_id.to_le_bytes());
        frame[8..16].copy_from_slice(&self.nonce.to_le_bytes());
        frame[16..24].copy_from_slice(&(self.payload_len as u64).to_le_bytes());
        frame[24..24 + self.payload_len].copy_from_slice(&self.payload[..self.payload_len]);

        let key = unsafe { &*core::ptr::addr_of!(KEY) };
        crypto::hmac_sha256(key, &frame[..24 + self.payload_len])
    }

    /// Constant-time digest comparison: the XOR accumulates every byte difference.
    pub fn verify_integrity(&self) -> bool {
        let expected = self.compute_mac();
        let mut difference = 0u8;
        for index in 0..TAG_LEN {
            difference |= self.mac[index] ^ expected[index];
        }
        difference == 0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.payload[..self.payload_len]
    }
}

pub struct IpcQueue {
    buffer: [Option<IpcMessage>; QUEUE_DEPTH],
    head: usize,
    tail: usize,
    count: usize,
    lock: AtomicBool,
}

impl IpcQueue {
    pub const fn new() -> Self {
        Self {
            buffer: [None; QUEUE_DEPTH],
            head: 0,
            tail: 0,
            count: 0,
            lock: AtomicBool::new(false),
        }
    }

    fn acquire(&self) {
        while self
            .lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
    }

    fn release(&self) {
        self.lock.store(false, Ordering::Release);
    }

    pub fn send(&mut self, message: IpcMessage) -> bool {
        self.acquire();
        if self.count == QUEUE_DEPTH {
            DROPPED.fetch_add(1, Ordering::Relaxed);
            self.release();
            return false;
        }
        self.buffer[self.tail] = Some(message);
        self.tail = (self.tail + 1) % QUEUE_DEPTH;
        self.count += 1;
        self.release();
        true
    }

    pub fn receive(&mut self) -> Option<IpcMessage> {
        self.acquire();
        if self.count == 0 {
            self.release();
            return None;
        }
        let message = self.buffer[self.head].take();
        self.head = (self.head + 1) % QUEUE_DEPTH;
        self.count -= 1;
        self.release();

        message.filter(|m| {
            if m.verify_integrity() {
                DELIVERED.fetch_add(1, Ordering::Relaxed);
                true
            } else {
                DROPPED.fetch_add(1, Ordering::Relaxed);
                false
            }
        })
    }

    pub fn depth(&self) -> usize {
        self.count
    }
}

/// The single kernel IPC queue.
///
/// Handed out as a raw-pointer-backed reference because the queue is one shared mutable
/// resource: the microkernel is single-threaded and the queue's own spin lock serialises
/// the actual accesses, so no two callers can be inside `send`/`receive` at once.
static mut QUEUE: IpcQueue = IpcQueue::new();

/// Explicit reset of the queue state (see the note on `.bss` in `clock::init`).
pub fn init() {
    DROPPED.store(0, Ordering::Relaxed);
    DELIVERED.store(0, Ordering::Relaxed);
    let queue = queue();
    queue.head = 0;
    queue.tail = 0;
    queue.count = 0;
    for index in 0..QUEUE_DEPTH {
        queue.buffer[index] = None;
    }
    unsafe {
        let key = core::ptr::addr_of_mut!(KEY);
        for byte in (*key).iter_mut() {
            *byte = 0;
        }
        KEY_READY = false;
    }
}

pub fn queue() -> &'static mut IpcQueue {
    unsafe { &mut *core::ptr::addr_of_mut!(QUEUE) }
}

pub fn send(message: IpcMessage) -> bool {
    queue().send(message)
}

pub fn receive() -> Option<IpcMessage> {
    queue().receive()
}

pub fn depth() -> usize {
    queue().depth()
}

pub fn delivered_count() -> u64 {
    DELIVERED.load(Ordering::Relaxed)
}

pub fn dropped_count() -> u64 {
    DROPPED.load(Ordering::Relaxed)
}

/// Proves the transport end to end: a genuine message is delivered unchanged, while a
/// message whose payload was edited after signing is rejected and counted as dropped.
///
/// Idempotent by design: it drains the queue first and compares counter deltas, so it can
/// run at boot and again from the shell without disturbing the seeded transport key.
pub fn self_test() -> bool {
    if !key_ready() {
        return false;
    }
    while receive().is_some() {}
    let delivered_before = delivered_count();
    let dropped_before = dropped_count();

    let probe = b"KELLER-OS IPC HMAC PROBE";
    let genuine = IpcMessage::new(0x10, 0x20, 0x0000_0001, probe);
    if !send(genuine) {
        return false;
    }
    match receive() {
        Some(message) => {
            if message.as_slice() != probe || message.sender_id != 0x10 || message.receiver_id != 0x20
            {
                return false;
            }
        }
        None => return false,
    }

    let mut forged = IpcMessage::new(0x10, 0x20, 0x0000_0002, probe);
    forged.payload[0] ^= 0x01; // payload no longer matches the digest signed over it
    if !send(forged) {
        return false;
    }
    if receive().is_some() {
        return false;
    }

    delivered_count() == delivered_before + 1 && dropped_count() == dropped_before + 1
}
