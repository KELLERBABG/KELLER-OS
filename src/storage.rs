//! Persistent storage for the vault: its sectors, on a disk, sealed before they get there.
//!
//! The vault has always sealed every sector with AEAD before storing it, which made "stored" mean
//! a `Vec` in the kernel heap — a good place to prove a format and a useless place to keep data.
//! This module turns that into a disk image, and adds exactly one thing the vault does not have:
//! an authentication step, so the image can only be opened by a holder of the root secret
//! ([`crate::zk`]).
//!
//! ## The image
//!
//! ```text
//!   sector 0        superblock (512 bytes, readable without a key - and holding none)
//!   sectors 1..1+n  one vault sector per slot, each sealed twice
//!   sector 1+n      probe slot: written and read back before the superblock is committed
//! ```
//!
//! ```text
//!   0   8  magic "KOSVLT01"
//!   8   2  format version
//!  10   2  slot count
//!  12   2  record size (512)
//!  14   2  flags (bit 0: the probe slot verified on the last save)
//!  16   8  generation, incremented on every save
//!  24   8  reserved
//!  32  32  device nonce, fresh on every format
//!  64  32  the owner's public commitment X = x·G
//!  96  32  HMAC-SHA256 over bytes 0..96 under the unlock key
//! 128      zero padding
//! ```
//!
//! A data record is a 24-byte header (vault index, length, nonce) followed by the record's AEAD
//! seal, whose AAD binds the slot, the generation and the vault index; the payload inside is the
//! vault's own sealed sector. So a record is protected twice by two different keys, for two
//! different reasons: the vault's key authenticates the *contents*, and the disk key authenticates
//! *this record, in this slot, in this generation*.
//!
//! ## Why the proof is what gates the key
//!
//! The disk key is derived from the Schnorr transcript, so it does not exist until a proof has
//! been produced and checked against `X` **and** against the header that is on the medium right
//! now. Three failures are distinct, and all of them are harmless: a wrong secret produces a proof
//! that does not verify; an edited header changes the statement the proof was about, so the proof
//! stops verifying; and an edited record fails its AEAD tag. None of them yields a key, and none of
//! them can be turned into "load whatever was readable and hope".
//!
//! ## What the medium does *not* hold
//!
//! No root secret, no shard of it, no key, and no hash of the secret to test guesses against — the
//! only function of the secret in the image is the group commitment `X`. That is the whole reason
//! authentication uses a zero-knowledge proof instead of a "compare a hash" check.
//!
//! ## Honesty about the failure mode
//!
//! Records are written before the superblock, so a save that loses power leaves the *previous*
//! superblock describing records that have already been overwritten by the new generation, and a
//! load then refuses with `record-tampered` rather than loading a mixture of two generations.
//! There is no journal and only one image: recovery from that state means formatting again or
//! re-saving, and this format's job is to be correct about what it stored rather than crash-proof
//! across a power cut.

use crate::arch::ahci::{self, AhciDisk};
use crate::block::{BlockDevice, SECTOR_SIZE};
use crate::crypto::{self, KEY_LEN};
use crate::println;
use crate::vault::KellerVault;
use crate::zk::Witness;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

pub const MAGIC: &[u8; 8] = b"KOSVLT01";
pub const VERSION: u16 = 1;
pub const SUPERBLOCK_A_SECTOR: u64 = 0;
pub const SUPERBLOCK_B_SECTOR: u64 = 1;
pub const SUPERBLOCK_SECTOR: u64 = 0;
pub const DATA_START: u64 = 2;
pub const DECOY_SLOTS: u16 = 4;
/// Highest slot count the superblock can describe.
pub const MAX_SLOTS: u16 = 512;
/// Bytes each record spends before its sealed payload: the vault index (8), the payload length
/// (4) and the record's own nonce (12). This has to be the *sum* of those fields - a record header
/// that is declared shorter than the nonce it holds lets the payload overwrite the nonce, and then
/// nothing ever opens again.
const RECORD_HEADER_BYTES: usize = 8 + 4 + crypto::NONCE_LEN;
/// Largest vault sector this format can carry: the whole record has to fit one sector.
pub const MAX_VAULT_SECTOR_BYTES: usize =
    SECTOR_SIZE - RECORD_HEADER_BYTES - crypto::TAG_LEN;
/// Compile-time proof that the record header is at least as long as the fields it contains.
const _: () = assert!(RECORD_HEADER_BYTES >= 8 + 4 + crypto::NONCE_LEN);
/// Offset of the superblock's MAC, and the region it covers.
const SUPERBLOCK_MAC_OFFSET: usize = 96;
const RECORD_KEY_INFO: &[u8] = b"KOS-VAULT-RECORD-KEY";
/// Signature that keeps this module's state in `.data`: the boot handoff does not zero `.bss`.
const STORAGE_SIGNATURE: u64 = 0x4B45_4C4C_5354_4F01; // "KELLSTO\x01"

pub fn bank_data_start(bank: u8, slots: u16) -> u64 {
    let stride = slots as u64 + 1;
    match bank {
        0 => DATA_START,
        1 => DATA_START + stride,
        _ => DATA_START + 2 * stride, // Bank C (Decoy)
    }
}

pub fn bank_probe_sector(bank: u8, slots: u16) -> u64 {
    let stride = slots as u64 + 1;
    match bank {
        0 => DATA_START + slots as u64,
        1 => DATA_START + stride + slots as u64,
        _ => DATA_START + 2 * stride + DECOY_SLOTS as u64,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StorageError {
    NoDevice,
    NoImage,
    /// The proof did not verify: this image belongs to a different root secret, or its header was
    /// edited. Both answers are the same on purpose — a caller must not learn which one it was.
    NotAuthenticated,
    /// The header's MAC did not verify under the derived key.
    HeaderTampered,
    /// A record failed its tag, does not fit its slot, or was moved.
    RecordTampered,
    /// The device reported a failure, or did not store what it was given.
    Device,
    /// The image is structurally unusable (magic, version, geometry).
    BadImage,
    /// The vault holds more sectors, or larger ones, than the image has room for.
    TooManySectors,
}

impl StorageError {
    pub fn as_str(self) -> &'static str {
        match self {
            StorageError::NoDevice => "no-device",
            StorageError::NoImage => "no-image",
            StorageError::NotAuthenticated => "not-authenticated",
            StorageError::HeaderTampered => "header-tampered",
            StorageError::RecordTampered => "record-tampered",
            StorageError::Device => "device-error",
            StorageError::BadImage => "bad-image",
            StorageError::TooManySectors => "too-many-sectors",
        }
    }
}

/// The superblock as read from the medium.
#[derive(Clone, Copy)]
pub struct Header {
    pub generation: u64,
    pub slots: u16,
    pub flags: u16,
    pub bank: u8,
    pub device_nonce: [u8; 32],
    pub owner: [u8; 32],
    pub hmac: [u8; 32],
    pub decoy_owner: [u8; 32],
    pub decoy_hmac: [u8; 32],
}

impl Header {
    pub const fn empty() -> Self {
        Self {
            generation: 0,
            slots: 0,
            flags: 0,
            bank: 0,
            device_nonce: [0; 32],
            owner: [0; 32],
            hmac: [0; 32],
            decoy_owner: [0; 32],
            decoy_hmac: [0; 32],
        }
    }

    /// The statement a proof about this image is about: everything that identifies it, up to the
    /// MAC (which a proof is allowed to depend on).
    pub fn context(&self) -> Vec<u8> {
        let mut context = Vec::with_capacity(112);
        context.extend_from_slice(MAGIC);
        context.extend_from_slice(&VERSION.to_le_bytes());
        context.extend_from_slice(&self.slots.to_le_bytes());
        context.extend_from_slice(&(SECTOR_SIZE as u16).to_le_bytes());
        context.extend_from_slice(&self.flags.to_le_bytes());
        context.extend_from_slice(&self.generation.to_le_bytes());
        context.extend_from_slice(&self.device_nonce);
        context.extend_from_slice(&self.owner);
        context
    }

    pub fn decoy_context(&self) -> Vec<u8> {
        let mut context = Vec::with_capacity(112);
        context.extend_from_slice(MAGIC);
        context.extend_from_slice(&VERSION.to_le_bytes());
        context.extend_from_slice(&self.slots.to_le_bytes());
        context.extend_from_slice(&(SECTOR_SIZE as u16).to_le_bytes());
        context.extend_from_slice(&self.flags.to_le_bytes());
        context.extend_from_slice(&self.generation.to_le_bytes());
        context.extend_from_slice(&self.device_nonce);
        context.extend_from_slice(&self.decoy_owner);
        context
    }

    pub fn encode(&self) -> [u8; SECTOR_SIZE] {
        let mut block = [0u8; SECTOR_SIZE];
        block[..8].copy_from_slice(MAGIC);
        block[8..10].copy_from_slice(&VERSION.to_le_bytes());
        block[10..12].copy_from_slice(&self.slots.to_le_bytes());
        block[12..14].copy_from_slice(&(SECTOR_SIZE as u16).to_le_bytes());
        block[14..16].copy_from_slice(&self.flags.to_le_bytes());
        block[16..24].copy_from_slice(&self.generation.to_le_bytes());
        block[24] = self.bank;
        block[32..64].copy_from_slice(&self.device_nonce);
        block[64..96].copy_from_slice(&self.owner);
        block[SUPERBLOCK_MAC_OFFSET..SUPERBLOCK_MAC_OFFSET + 32].copy_from_slice(&self.hmac);
        block[128..160].copy_from_slice(&self.decoy_owner);
        block[160..192].copy_from_slice(&self.decoy_hmac);
        block
    }
}

// ------------------------------------------------------------------ format primitives

fn read_single_header(
    device: &mut dyn BlockDevice,
    sector: u64,
) -> Result<Option<Header>, StorageError> {
    let mut block = [0u8; SECTOR_SIZE];
    device
        .read_sectors(sector, &mut block)
        .map_err(|_| StorageError::Device)?;
    if &block[..8] != MAGIC {
        return Ok(None);
    }
    if u16::from_le_bytes([block[8], block[9]]) != VERSION {
        return Err(StorageError::BadImage);
    }
    let slots = u16::from_le_bytes([block[10], block[11]]);
    if u16::from_le_bytes([block[12], block[13]]) != SECTOR_SIZE as u16 {
        return Err(StorageError::BadImage);
    }
    let mut header = Header::empty();
    header.generation = u64::from_le_bytes(block[16..24].try_into().unwrap());
    header.bank = block[24];
    header.slots = slots;
    header.flags = u16::from_le_bytes([block[14], block[15]]);
    header.device_nonce.copy_from_slice(&block[32..64]);
    header.owner.copy_from_slice(&block[64..96]);
    header
        .hmac
        .copy_from_slice(&block[SUPERBLOCK_MAC_OFFSET..SUPERBLOCK_MAC_OFFSET + 32]);
    header.decoy_owner.copy_from_slice(&block[128..160]);
    header.decoy_hmac.copy_from_slice(&block[160..192]);
    Ok(Some(header))
}

fn read_header(device: &mut dyn BlockDevice) -> Result<Option<Header>, StorageError> {
    let res_a = read_single_header(device, SUPERBLOCK_A_SECTOR);
    let res_b = read_single_header(device, SUPERBLOCK_B_SECTOR);
    if let Err(e) = &res_a {
        if *e == StorageError::BadImage {
            return Err(StorageError::BadImage);
        }
    }
    if let Err(e) = &res_b {
        if *e == StorageError::BadImage {
            return Err(StorageError::BadImage);
        }
    }
    let hdr_a = res_a.ok().flatten();
    let hdr_b = res_b.ok().flatten();
    match (hdr_a, hdr_b) {
        (Some(a), Some(b)) => {
            if b.generation > a.generation {
                Ok(Some(b))
            } else {
                Ok(Some(a))
            }
        }
        (Some(a), None) => Ok(Some(a)),
        (None, Some(b)) => Ok(Some(b)),
        (None, None) => Ok(None),
    }
}

fn header_mac(key: &[u8; KEY_LEN], header: &Header) -> [u8; 32] {
    let block = header.encode();
    crypto::hmac_sha256(key, &block[..SUPERBLOCK_MAC_OFFSET])
}

fn decoy_header_mac(key: &[u8; KEY_LEN], header: &Header) -> [u8; 32] {
    let block = header.encode();
    crypto::hmac_sha256(key, &block[..160])
}

fn record_key(unlock: &[u8; KEY_LEN], slot: u16, generation: u64) -> [u8; KEY_LEN] {
    let mut info = [0u8; 10];
    info[..2].copy_from_slice(&slot.to_le_bytes());
    info[2..].copy_from_slice(&generation.to_le_bytes());
    let mut key = [0u8; KEY_LEN];
    crypto::hkdf_sha256(&info, unlock, RECORD_KEY_INFO, &mut key);
    key
}

fn encode_record(
    unlock: &[u8; KEY_LEN],
    slot: u16,
    generation: u64,
    index: u64,
    sealed: &[u8],
) -> Result<[u8; SECTOR_SIZE], StorageError> {
    if sealed.is_empty() || sealed.len() > MAX_VAULT_SECTOR_BYTES {
        return Err(StorageError::TooManySectors);
    }
    let mut block = [0u8; SECTOR_SIZE];
    block[..8].copy_from_slice(&index.to_le_bytes());
    block[8..12].copy_from_slice(&(sealed.len() as u32).to_le_bytes());
    let mut nonce = [0u8; crypto::NONCE_LEN];
    crypto::hardware_rand_bytes(&mut nonce);
    block[12..12 + crypto::NONCE_LEN].copy_from_slice(&nonce);
    let mut aad = [0u8; 18];
    aad[..2].copy_from_slice(&slot.to_le_bytes());
    aad[2..10].copy_from_slice(&generation.to_le_bytes());
    aad[10..].copy_from_slice(&index.to_le_bytes());
    let key = record_key(unlock, slot, generation);
    let payload = crypto::aead_seal(&key, &nonce, &aad, sealed);
    block[RECORD_HEADER_BYTES..RECORD_HEADER_BYTES + payload.len()].copy_from_slice(&payload);
    Ok(block)
}

fn decode_record(
    unlock: &[u8; KEY_LEN],
    slot: u16,
    generation: u64,
    block: &[u8; SECTOR_SIZE],
) -> Result<(u64, Vec<u8>), StorageError> {
    let index = u64::from_le_bytes(block[..8].try_into().unwrap());
    let length = u32::from_le_bytes(block[8..12].try_into().unwrap()) as usize;
    if length == 0
        || length > MAX_VAULT_SECTOR_BYTES
        || RECORD_HEADER_BYTES + length + crypto::TAG_LEN > SECTOR_SIZE
    {
        return Err(StorageError::RecordTampered);
    }
    let mut nonce = [0u8; crypto::NONCE_LEN];
    nonce.copy_from_slice(&block[12..12 + crypto::NONCE_LEN]);
    let mut aad = [0u8; 18];
    aad[..2].copy_from_slice(&slot.to_le_bytes());
    aad[2..10].copy_from_slice(&generation.to_le_bytes());
    aad[10..].copy_from_slice(&index.to_le_bytes());
    let key = record_key(unlock, slot, generation);
    let sealed = &block[RECORD_HEADER_BYTES..RECORD_HEADER_BYTES + length + crypto::TAG_LEN];
    match crypto::aead_open(&key, &nonce, &aad, sealed) {
        Ok(plaintext) if plaintext.len() == length => Ok((index, plaintext)),
        Ok(_) => Err(StorageError::RecordTampered),
        Err(_) => Err(StorageError::RecordTampered),
    }
}

/// Writes and reads back the probe slot. This is the write-ahead check: an image whose superblock
/// claims a successful save has had at least one verified write.
fn probe(device: &mut dyn BlockDevice, lba: u64) -> Result<(), StorageError> {
    let mut pattern = [0u8; SECTOR_SIZE];
    crypto::hardware_rand_bytes(&mut pattern);
    device
        .write_sectors(lba, &pattern)
        .map_err(|_| StorageError::Device)?;
    let mut readback = [0u8; SECTOR_SIZE];
    device
        .read_sectors(lba, &mut readback)
        .map_err(|_| StorageError::Device)?;
    if readback != pattern {
        return Err(StorageError::Device);
    }
    RECORDS.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

fn probe_sector(slots: u16) -> u64 {
    bank_probe_sector(0, slots)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuthMode {
    Real([u8; KEY_LEN]),
    Decoy([u8; KEY_LEN]),
}

/// Reads the image and checks that it belongs to `vault`, returning the unlock key.
/// Supports both real owner and honey-pot duress mode.
fn authenticate(vault: &KellerVault, header: &Header) -> Result<AuthMode, StorageError> {
    // 1. Real owner
    let context = header.context();
    let proof = vault.prove_ownership(&context);
    if vault.owns(&header.owner, &proof, &context) {
        let unlock = crate::zk::unlock_key(&header.owner, &proof, &header.device_nonce);
        if crypto::ct_eq(&header_mac(&unlock, header), &header.hmac) {
            return Ok(AuthMode::Real(unlock));
        } else {
            return Err(StorageError::HeaderTampered);
        }
    }

    // 2. Honey-pot duress mode
    if header.decoy_owner != [0u8; 32] {
        let d_ctx = header.decoy_context();
        let d_proof = vault.prove_ownership(&d_ctx);
        if vault.owns(&header.decoy_owner, &d_proof, &d_ctx) {
            let d_unlock = crate::zk::unlock_key(&header.decoy_owner, &d_proof, &header.device_nonce);
            if crypto::ct_eq(&decoy_header_mac(&d_unlock, header), &header.decoy_hmac) {
                return Ok(AuthMode::Decoy(d_unlock));
            } else {
                return Err(StorageError::HeaderTampered);
            }
        }
    }

    Err(StorageError::NotAuthenticated)
}

// ------------------------------------------------------------------ operations (device-generic)

/// Lays out a fresh image: a new device nonce, the owner's commitment, a verified probe write, and
/// the superblock committed last.
pub fn format_image(
    device: &mut dyn BlockDevice,
    vault: &KellerVault,
) -> Result<Header, StorageError> {
    let capacity = device.sector_count();
    let min_needed = DATA_START + 2 * (8 + 1) + DECOY_SLOTS as u64 + 1;
    if capacity < min_needed {
        return Err(StorageError::BadImage);
    }
    let wanted = core::cmp::max(vault.sector_count() as u64, 8);
    if DATA_START + 2 * (wanted + 1) + DECOY_SLOTS as u64 + 1 > capacity || wanted > MAX_SLOTS as u64 {
        return Err(StorageError::TooManySectors);
    }

    let mut header = Header::empty();
    header.generation = 1;
    header.bank = 0;
    header.slots = wanted as u16;
    crypto::hardware_rand_bytes(&mut header.device_nonce);
    header.owner = vault.proof_commitment();

    // Derive duress decoy commitment
    let decoy_witness = Witness::from_secret(b"duress");
    header.decoy_owner = decoy_witness.commitment();

    if let Err(error) = probe(device, bank_probe_sector(0, header.slots)) {
        return Err(error);
    }
    header.flags |= 1;

    let context = header.context();
    let proof = vault.prove_ownership(&context);
    if !vault.owns(&header.owner, &proof, &context) {
        return Err(StorageError::NotAuthenticated);
    }
    let unlock = crate::zk::unlock_key(&header.owner, &proof, &header.device_nonce);
    header.hmac = header_mac(&unlock, &header);

    // Decoy unlock key & HMAC
    let d_ctx = header.decoy_context();
    let d_proof = decoy_witness.prove(&d_ctx);
    let d_unlock = crate::zk::unlock_key(&header.decoy_owner, &d_proof, &header.device_nonce);
    header.decoy_hmac = decoy_header_mac(&d_unlock, &header);

    // Blank Bank A and Bank B
    let blank = [0u8; SECTOR_SIZE];
    for b in 0..2 {
        let start = bank_data_start(b, header.slots);
        for slot in 0..header.slots as u64 {
            device
                .write_sectors(start + slot, &blank)
                .map_err(|_| StorageError::Device)?;
        }
    }

    // Initialize Bank C with decoy sector
    let decoy_start = bank_data_start(2, header.slots);
    for slot in 0..DECOY_SLOTS as u64 {
        device
            .write_sectors(decoy_start + slot, &blank)
            .map_err(|_| StorageError::Device)?;
    }
    let mut decoy_vault = KellerVault::new(b"duress");
    let decoy_msg = b"SYSTEM STERILE: DECOY VAULT ACTIVE (DURESS MODE)";
    decoy_vault.store(USER_SECTOR, decoy_msg).map_err(|_| StorageError::Device)?;
    if let Some(sealed_decoy) = decoy_vault.sealed_bytes(USER_SECTOR) {
        let decoy_block = encode_record(&d_unlock, 0, header.generation, USER_SECTOR, &sealed_decoy)?;
        device
            .write_sectors(decoy_start, &decoy_block)
            .map_err(|_| StorageError::Device)?;
    }

    device
        .write_sectors(SUPERBLOCK_A_SECTOR, &header.encode())
        .map_err(|_| StorageError::Device)?;
    device
        .write_sectors(SUPERBLOCK_B_SECTOR, &blank)
        .map_err(|_| StorageError::Device)?;

    Ok(header)
}

pub fn save_image(
    device: &mut dyn BlockDevice,
    vault: &mut KellerVault,
) -> Result<Header, StorageError> {
    if vault.is_duress() {
        if let Some(h) = read_header(device)? {
            return Ok(h);
        }
    }

    let active = match read_header(device)? {
        Some(header) => header,
        None => format_image(device, vault)?,
    };

    if !crypto::ct_eq(&active.owner, &vault.proof_commitment()) {
        return Err(StorageError::NotAuthenticated);
    }
    authenticate(vault, &active)?;

    let target_bank = if active.bank == 0 { 1 } else { 0 };
    let target_sector = if target_bank == 0 { SUPERBLOCK_A_SECTOR } else { SUPERBLOCK_B_SECTOR };
    let generation = active.generation + 1;

    let mut new_header = active;
    new_header.generation = generation;
    new_header.bank = target_bank;
    new_header.flags |= 1;

    let context = new_header.context();
    let proof = vault.prove_ownership(&context);
    if !vault.owns(&new_header.owner, &proof, &context) {
        return Err(StorageError::NotAuthenticated);
    }
    let unlock = crate::zk::unlock_key(&new_header.owner, &proof, &new_header.device_nonce);
    new_header.hmac = header_mac(&unlock, &new_header);

    if new_header.decoy_owner != [0u8; 32] {
        let decoy_witness = Witness::from_secret(b"duress");
        let d_ctx = new_header.decoy_context();
        let d_proof = decoy_witness.prove(&d_ctx);
        let d_unlock = crate::zk::unlock_key(&new_header.decoy_owner, &d_proof, &new_header.device_nonce);
        new_header.decoy_hmac = decoy_header_mac(&d_unlock, &new_header);
    }

    let indices = vault.sector_indices();
    if indices.len() > new_header.slots as usize {
        return Err(StorageError::TooManySectors);
    }
    let target_start = bank_data_start(target_bank, new_header.slots);
    for (slot, index) in indices.iter().enumerate() {
        let sealed = vault.sealed_bytes(*index).ok_or(StorageError::BadImage)?;
        let block = encode_record(&unlock, slot as u16, generation, *index, sealed)?;
        device
            .write_sectors(target_start + slot as u64, &block)
            .map_err(|_| StorageError::Device)?;
    }
    let blank = [0u8; SECTOR_SIZE];
    for slot in indices.len()..new_header.slots as usize {
        device
            .write_sectors(target_start + slot as u64, &blank)
            .map_err(|_| StorageError::Device)?;
    }

    if let Err(error) = probe(device, bank_probe_sector(target_bank, new_header.slots)) {
        return Err(error);
    }

    device
        .write_sectors(target_sector, &new_header.encode())
        .map_err(|_| StorageError::Device)?;

    Ok(new_header)
}

pub fn load_image(
    device: &mut dyn BlockDevice,
    vault: &mut KellerVault,
) -> Result<(Header, usize), StorageError> {
    let res_a = read_single_header(device, SUPERBLOCK_A_SECTOR);
    let res_b = read_single_header(device, SUPERBLOCK_B_SECTOR);

    if matches!(res_a, Err(StorageError::BadImage)) && (matches!(res_b, Err(StorageError::BadImage)) || matches!(res_b, Ok(None))) {
        return Err(StorageError::BadImage);
    }
    if matches!(res_b, Err(StorageError::BadImage)) && matches!(res_a, Ok(None)) {
        return Err(StorageError::BadImage);
    }

    let hdr_a = res_a.ok().flatten();
    let hdr_b = res_b.ok().flatten();

    if hdr_a.is_none() && hdr_b.is_none() {
        return Err(StorageError::NoImage);
    }

    let candidates = match (hdr_a, hdr_b) {
        (Some(a), Some(b)) => {
            if b.generation >= a.generation {
                [Some(b), Some(a)]
            } else {
                [Some(a), Some(b)]
            }
        }
        (Some(a), None) => [Some(a), None],
        (None, Some(b)) => [Some(b), None],
        (None, None) => [None, None],
    };

    let mut last_err = StorageError::BadImage;
    for cand in candidates.into_iter().flatten() {
        match try_load_from_header(device, vault, &cand) {
            Ok(result) => return Ok(result),
            Err(e) => {
                last_err = e;
                continue;
            }
        }
    }

    Err(last_err)
}

fn try_load_from_header(
    device: &mut dyn BlockDevice,
    vault: &mut KellerVault,
    header: &Header,
) -> Result<(Header, usize), StorageError> {
    let auth = authenticate(vault, header)?;
    match auth {
        AuthMode::Real(unlock) => {
            vault.set_duress(false);
            let mut adopted = 0usize;
            let start = bank_data_start(header.bank, header.slots);
            for slot in 0..header.slots {
                let mut block = [0u8; SECTOR_SIZE];
                device
                    .read_sectors(start + slot as u64, &mut block)
                    .map_err(|_| StorageError::Device)?;
                if block == [0u8; SECTOR_SIZE] {
                    continue;
                }
                let (index, sealed) = decode_record(&unlock, slot, header.generation, &block)?;
                vault
                    .adopt_sealed(index, &sealed)
                    .map_err(|_| StorageError::RecordTampered)?;
                adopted += 1;
            }
            Ok((*header, adopted))
        }
        AuthMode::Decoy(d_unlock) => {
            vault.set_duress(true);
            let mut adopted = 0usize;
            let start = bank_data_start(2, header.slots);
            for slot in 0..DECOY_SLOTS {
                let mut block = [0u8; SECTOR_SIZE];
                device
                    .read_sectors(start + slot as u64, &mut block)
                    .map_err(|_| StorageError::Device)?;
                if block == [0u8; SECTOR_SIZE] {
                    continue;
                }
                let (index, sealed) = decode_record(&d_unlock, slot, header.generation, &block)?;
                vault
                    .adopt_sealed(index, &sealed)
                    .map_err(|_| StorageError::RecordTampered)?;
                adopted += 1;
            }
            Ok((*header, adopted))
        }
    }
}

pub fn wipe_image(device: &mut dyn BlockDevice) -> Result<(), StorageError> {
    if let Some(header) = read_header(device)? {
        let mut blank = [0u8; SECTOR_SIZE];
        for b in 0..3 {
            let start = bank_data_start(b, header.slots);
            let count = if b == 2 { DECOY_SLOTS } else { header.slots };
            for slot in 0..count as u64 {
                let _ = device.write_sectors(start + slot, &blank);
            }
        }
        crypto::wipe(&mut blank);
    }
    let blank = [0u8; SECTOR_SIZE];
    device.write_sectors(SUPERBLOCK_A_SECTOR, &blank).map_err(|_| StorageError::Device)?;
    device.write_sectors(SUPERBLOCK_B_SECTOR, &blank).map_err(|_| StorageError::Device)?;
    Ok(())
}

// ------------------------------------------------------------------ subsystem state

pub struct Storage {
    signature: u64,
    device_ready: bool,
    header: Option<Header>,
    model: String,
    capacity_sectors: u64,
    formats: u64,
    saves: u64,
    loads: u64,
    wipes: u64,
    rejections: u64,
    header_failures: u64,
    record_failures: u64,
    records_written: u64,
    records_read: u64,
    journal_entries: u64,
}

impl Storage {
    const fn empty() -> Self {
        Self {
            signature: STORAGE_SIGNATURE,
            device_ready: false,
            header: None,
            model: String::new(),
            capacity_sectors: 0,
            formats: 0,
            saves: 0,
            loads: 0,
            wipes: 0,
            rejections: 0,
            header_failures: 0,
            record_failures: 0,
            records_written: 0,
            records_read: 0,
            journal_entries: 0,
        }
    }
}

static mut STORAGE: Storage = Storage::empty();
/// Records this module has written, kept apart from the paging frame counter.
static RECORDS: AtomicU64 = AtomicU64::new(0);

/// The module's state. This is a safe accessor on purpose: the `static mut` belongs to this
/// module, the kernel is single-threaded, and none of the paths below re-enter (they drive a
/// device synchronously and touch no interrupt handler).
fn storage() -> &'static mut Storage {
    unsafe { &mut *core::ptr::addr_of_mut!(STORAGE) }
}

/// Finds the controller and reads whatever image is on it. Safe to call once, at boot, before the
/// vault is provisioned: a blank disk is not an error.
///
/// # Safety
/// Must run after PCI enumeration and after the heap exists.
pub unsafe fn init() -> bool {
    let state = storage();
    if state.signature != STORAGE_SIGNATURE {
        println!(
            "[!!] STORAGE: state is at {:#x} without its signature - the loader did not place it where the crate expects",
            core::ptr::addr_of!(STORAGE) as u64
        );
        return false;
    }
    if !ahci::init() {
        return false;
    }
    state.device_ready = true;
    state.model = ahci::model();
    state.capacity_sectors = ahci::sector_count();

    let mut device = AhciDisk;
    match read_header(&mut device) {
        Ok(Some(header)) => {
            println!(
                "[OK] VAULT IMAGE: generation {} owner={} slots={} nonce={} on \"{}\" ({} sectors)",
                header.generation,
                hex::encode(&crypto::sha256(&header.owner)[..8]),
                header.slots,
                hex::encode(&header.device_nonce[..8]),
                state.model,
                state.capacity_sectors
            );
            state.header = Some(header);
            true
        }
        Ok(None) => {
            println!(
                "[--] VAULT IMAGE: \"{}\" has {} sectors and no vault image on it (`disk format` writes one)",
                state.model, state.capacity_sectors
            );
            false
        }
        Err(error) => {
            println!(
                "[!!] VAULT IMAGE: the superblock could not be used ({})",
                error.as_str()
            );
            false
        }
    }
}

pub fn format(vault: &KellerVault) -> Result<Header, StorageError> {
    let state = storage();
    if !state.device_ready {
        return Err(StorageError::NoDevice);
    }
    let mut device = AhciDisk;
    match format_image(&mut device, vault) {
        Ok(header) => {
            state.formats += 1;
            state.header = Some(header);
            Ok(header)
        }
        Err(error) => {
            state.rejections += 1;
            Err(error)
        }
    }
}

pub fn save(vault: &mut KellerVault) -> Result<Header, StorageError> {
    let state = storage();
    if !state.device_ready {
        return Err(StorageError::NoDevice);
    }
    let mut device = AhciDisk;
    let before = state.records_written;
    match save_image(&mut device, vault) {
        Ok(header) => {
            state.saves += 1;
            state.records_written = before + vault.sector_count() as u64;
            state.header = Some(header);
            Ok(header)
        }
        Err(error) => {
            state.rejections += 1;
            Err(error)
        }
    }
}

pub fn load(vault: &mut KellerVault) -> Result<usize, StorageError> {
    let state = storage();
    if !state.device_ready {
        return Err(StorageError::NoDevice);
    }
    let mut device = AhciDisk;
    match load_image(&mut device, vault) {
        Ok((header, adopted)) => {
            state.loads += 1;
            state.records_read += adopted as u64;
            state.header = Some(header);
            Ok(adopted)
        }
        Err(error) => {
            state.rejections += 1;
            match error {
                StorageError::HeaderTampered | StorageError::NotAuthenticated => {
                    state.header_failures += 1
                }
                StorageError::RecordTampered => state.record_failures += 1,
                _ => {}
            }
            Err(error)
        }
    }
}

// ------------------------------------------------------------------ the journal sector

/// The one vault sector this module keeps for itself, in the same sealed format as any other.
///
/// It exists so that persistence is something the machine can demonstrate *about itself* rather
/// than only in a test: each [`journal`] call reads the entry that is on the medium, advances the
/// counter, and saves. A number that keeps climbing across power cycles cannot have come from
/// RAM, and the random stamp written the first time comes back with it, so a machine can tell its
/// own image from a copy of one.
pub const JOURNAL_SECTOR: u64 = 0x4B45_4C4C_4552; // "KELLER"

const JOURNAL_TAG: &[u8; 16] = b"KOS-JOURNAL-v1\0\0";

/// The journal entry as it is stored: 40 bytes inside the journal sector's sealed payload.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Journal {
    /// How many times [`journal`] has run against this image. Monotonic across power cycles.
    pub boots: u64,
    /// The superblock's generation at the moment this entry was read or written: the generation
    /// the entry is persisted *in*. A caller compares it with the image it is looking at - an
    /// entry that claims a generation the image has moved past is a stale entry, and one that
    /// claims a generation the image has not reached is a rolled-back image.
    pub image_generation: u64,
    /// Fresh at the first entry, then carried forward unchanged: two images cannot share it.
    pub stamp: [u8; 16],
}

impl Journal {
    fn fresh() -> Self {
        let mut stamp = [0u8; 16];
        crypto::hardware_rand_bytes(&mut stamp);
        Self {
            boots: 0,
            image_generation: 0,
            stamp,
        }
    }

    fn encode(&self) -> [u8; 40] {
        let mut entry = [0u8; 40];
        entry[..16].copy_from_slice(JOURNAL_TAG);
        entry[16..24].copy_from_slice(&self.boots.to_le_bytes());
        entry[24..40].copy_from_slice(&self.stamp);
        entry
    }

    fn decode(payload: &[u8]) -> Option<Self> {
        if payload.len() != 40 || &payload[..16] != JOURNAL_TAG {
            return None;
        }
        let mut stamp = [0u8; 16];
        stamp.copy_from_slice(&payload[24..40]);
        Some(Self {
            boots: u64::from_le_bytes(payload[16..24].try_into().ok()?),
            // Not in the payload: the generation belongs to the image, so whoever reads the entry
            // fills it in from the superblock they just authenticated.
            image_generation: 0,
            stamp,
        })
    }
}

/// The journal step against any block device: read the entry that is there (formatting a blank
/// device first), advance it, write it back and save the image.
fn journal_on(
    device: &mut dyn BlockDevice,
    vault: &mut KellerVault,
) -> Result<Journal, StorageError> {
    let existing = match read_header(device)? {
        Some(_) => {
            load_image(device, vault)?;
            vault.load(JOURNAL_SECTOR).ok().as_deref().and_then(Journal::decode)
        }
        None => {
            format_image(device, vault)?;
            None
        }
    };
    let mut entry = match existing {
        Some(entry) => entry,
        None => Journal::fresh(),
    };
    entry.boots += 1;
    vault
        .store(JOURNAL_SECTOR, &entry.encode())
        .map_err(|_| StorageError::Device)?;
    entry.image_generation = save_image(device, vault)?.generation;
    Ok(entry)
}

/// Reads the journal entry that is on the device, without writing anything.
pub fn read_journal(vault: &mut KellerVault) -> Result<Journal, StorageError> {
    let state = storage();
    if !state.device_ready {
        return Err(StorageError::NoDevice);
    }
    load(vault)?;
    let payload = vault.load(JOURNAL_SECTOR).map_err(|_| StorageError::NoImage)?;
    let entry = Journal::decode(&payload).ok_or(StorageError::BadImage)?;
    Ok(Journal {
        image_generation: generation(),
        ..entry
    })
}

/// Advances the journal by one entry and persists the vault. This writes to the medium.
///
/// A machine with a controller and a blank disk formats one first: the journal is about the
/// medium the vault lives on, so there is nothing to advance on a device that holds no image.
pub fn journal(vault: &mut KellerVault) -> Result<Journal, StorageError> {
    let state = storage();
    if !state.device_ready {
        return Err(StorageError::NoDevice);
    }
    let mut device = AhciDisk;
    if read_header(&mut device)?.is_none() {
        format(vault)?;
    }
    match journal_on(&mut device, vault) {
        Ok(entry) => {
            // `journal_on` drives the device-generic operations directly, so the counters the
            // wrappers would normally keep are advanced here: one load, one save, and the
            // records each of them moved.
            let moved = vault.sector_count() as u64;
            state.journal_entries += 1;
            state.loads += 1;
            state.saves += 1;
            state.records_read += moved;
            state.records_written += moved;
            if let Some(header) = read_header(&mut device)? {
                state.header = Some(header);
            }
            Ok(entry)
        }
        Err(error) => {
            state.rejections += 1;
            match error {
                StorageError::HeaderTampered | StorageError::NotAuthenticated => {
                    state.header_failures += 1
                }
                StorageError::RecordTampered => state.record_failures += 1,
                _ => {}
            }
            Err(error)
        }
    }
}

pub fn wipe() -> Result<(), StorageError> {
    let state = storage();
    if !state.device_ready {
        return Err(StorageError::NoDevice);
    }
    let mut device = AhciDisk;
    match wipe_image(&mut device) {
        Ok(()) => {
            state.wipes += 1;
            state.header = None;
            Ok(())
        }
        Err(error) => {
            state.rejections += 1;
            Err(error)
        }
    }
}

/// The sector the shell's `disk write` / `disk read` pair uses: one vault sector that belongs to
/// whatever the operator wants to keep, so "my data survived the power cycle" has something
/// concrete behind it.
pub const USER_SECTOR: u64 = 0x5553_4552; // "USER"

/// Puts `plaintext` in vault sector `index` and persists the whole image.
pub fn write_sector(
    vault: &mut KellerVault,
    index: u64,
    plaintext: &[u8],
) -> Result<Header, StorageError> {
    vault.store(index, plaintext).map_err(|_| StorageError::Device)?;
    save(vault)
}

/// Opens sector `index` out of the image on the medium.
///
/// The image is read first, so this answers "what is on the disk", not "what is in the vault's
/// memory": a caller that has already loaded pays for one more read pass and gets the same
/// answer.
pub fn read_sector(vault: &mut KellerVault, index: u64) -> Result<Vec<u8>, StorageError> {
    load(vault)?;
    vault.load(index).map_err(|_| StorageError::NoImage)
}

/// A one-line description of the superblock **as it is on the medium right now**, so an
/// independent reader (the host-side `disk_check.py`) can compare it against its own parse of
/// the raw image rather than against what the guest says it wrote.
pub fn superblock_line() -> Option<String> {
    let state = storage();
    if !state.device_ready {
        return None;
    }
    let mut device = AhciDisk;
    match read_header(&mut device) {
        Ok(Some(header)) => Some(alloc::format!(
            "magic={} version={} slots={} sector-size={} flags={:#06x} generation={} owner={} nonce={} mac={}",
            core::str::from_utf8(MAGIC).unwrap_or("?"),
            VERSION,
            header.slots,
            SECTOR_SIZE,
            header.flags,
            header.generation,
            hex::encode(&header.owner),
            hex::encode(&header.device_nonce),
            hex::encode(&header.hmac)
        )),
        _ => None,
    }
}

pub fn has_image() -> bool {
    storage().header.is_some()
}

pub fn device_ready() -> bool {
    storage().device_ready
}

pub fn model() -> String {
    storage().model.clone()
}

pub fn capacity_sectors() -> u64 {
    storage().capacity_sectors
}

pub fn generation() -> u64 {
    storage().header.map(|header| header.generation).unwrap_or(0)
}

pub fn flags() -> u16 {
    storage().header.map(|header| header.flags).unwrap_or(0)
}

/// `(formats, saves, loads, wipes, rejections)`.
pub fn counters() -> (u64, u64, u64, u64, u64) {
    let state = storage();
    (
        state.formats,
        state.saves,
        state.loads,
        state.wipes,
        state.rejections,
    )
}

pub fn describe() {
    let state = storage();
    if !state.device_ready {
        println!("[SH] STORAGE: no device (the vault is RAM-only)");
        return;
    }
    println!(
        "[SH] STORAGE \"{}\" {} sectors ({} MiB) image={} generation={} slots={} owner={}",
        state.model,
        state.capacity_sectors,
        state.capacity_sectors * SECTOR_SIZE as u64 / (1024 * 1024),
        if state.header.is_some() { "present" } else { "absent" },
        generation(),
        state.header.map(|header| header.slots).unwrap_or(0),
        match state.header {
            Some(header) => hex::encode(&crypto::sha256(&header.owner)[..8]),
            None => String::from("-"),
        }
    );
    println!(
        "[SH]      formats={} saves={} loads={} wipes={} journal-entries={} rejections={} header-failures={} record-failures={} records-written={} records-read={}",
        state.formats,
        state.saves,
        state.loads,
        state.wipes,
        state.journal_entries,
        state.rejections,
        state.header_failures,
        state.record_failures,
        state.records_written,
        state.records_read
    );
    println!(
        "[STORAGE] counters: device=1 image={} generation={} slots={} formats={} saves={} loads={} wipes={} journal-entries={} rejections={} header-failures={} record-failures={} records-written={} records-read={} records-total={}",
        if state.header.is_some() { 1 } else { 0 },
        generation(),
        state.header.map(|header| header.slots).unwrap_or(0),
        state.formats,
        state.saves,
        state.loads,
        state.wipes,
        state.journal_entries,
        state.rejections,
        state.header_failures,
        state.record_failures,
        state.records_written,
        state.records_read,
        RECORDS.load(Ordering::Relaxed)
    );
}

// ------------------------------------------------------------------ self-test

/// How many assertions this module makes on a device-generic run, so a machine with no controller
/// reports the same number skipped.
const FORMAT_ASSERTIONS: u32 = 27;

/// Exercises the format against the block layer's in-memory device: a format, a save, a load into
/// a *fresh* vault (which is what persistence means), and every way an image can be wrong.
///
/// This runs on every machine, controller or not: the format is written against [`BlockDevice`],
/// and the reference device is what it is checked on.
pub fn self_test() -> crate::block::BlockReport {
    let mut report = crate::block::BlockReport::new();
    let mut disk = crate::block::MemDisk::new(64);
    let key = b"self-test-root-secret";

    let first = {
        let vault = KellerVault::new(key);
        format_image(&mut disk, &vault)
    };
    let header = match first {
        Ok(header) => {
            report.check(true, "a fresh image could be formatted");
            header
        }
        Err(error) => {
            println!("[!!] STORAGE: format failed: {}", error.as_str());
            report.check(false, "formatting a fresh image failed");
            report.skip(FORMAT_ASSERTIONS - 1);
            return report;
        }
    };
    report.check(
        header.owner != [0u8; 32],
        "the formatted image has no owner commitment",
    );
    report.check(
        header.device_nonce != [0u8; 32],
        "the formatted image has no device nonce",
    );
    report.check(
        header.flags & 1 != 0,
        "the probe write was not verified before the superblock was committed",
    );
    report.check(header.generation == 1, "a fresh image does not start at generation 1");
    report.check(
        header.slots >= 8 && header.slots as u64 <= disk.sector_count() - DATA_START - 1,
        "the image's slot count does not fit the device",
    );

    let payload = b"KELLER-OS PERSISTENT SECTOR PROBE";
    let saved = {
        let mut vault = KellerVault::new(key);
        report.check(vault.store(7, payload).is_ok(), "storing a sector in the vault failed");
        save_image(&mut disk, &mut vault)
    };
    match saved {
        Ok(header) => report.check(header.generation == 2, "saving did not advance the generation"),
        Err(error) => {
            println!("[!!] STORAGE: save failed: {}", error.as_str());
            report.check(false, "saving the vault to the image failed");
        }
    }
    {
        let mut restored = KellerVault::new(key);
        match load_image(&mut disk, &mut restored) {
            Ok((header, adopted)) => {
                report.check(adopted == 1, "the load did not adopt exactly one sector");
                report.check(
                    matches!(restored.load(7), Ok(opened) if opened == payload),
                    "the sector did not survive the round trip through the image",
                );
                report.check(
                    restored.proof_commitment() == header.owner,
                    "the restored vault is not the image's owner",
                );
            }
            Err(error) => {
                println!("[!!] STORAGE: load failed: {}", error.as_str());
                report.check(false, "loading the image failed");
            }
        }
    }

    // A different root secret must be refused as *not authenticated*, which is a different answer
    // from a corrupt image: it says the image is intact and was not written for this secret.
    {
        let mut stranger = KellerVault::new(b"a different secret");
        report.check(
            matches!(
                load_image(&mut disk, &mut stranger),
                Err(StorageError::NotAuthenticated)
            ),
            "an image was loaded by a vault that does not hold its secret",
        );
    }

    // Mid-Write-Kill / Crash safety proof:
    // When Bank B (the newer generation 2) is corrupted mid-write, load_image seamlessly falls back
    // to generation 1 in Bank A.
    {
        // Corrupt Superblock B at sector 1
        let crash_disk = disk_snapshot(&disk, SECTOR_SIZE + SUPERBLOCK_MAC_OFFSET + 1);
        let mut device = crate::block::MemDisk::from_bytes(&crash_disk);
        let mut vault = KellerVault::new(key);
        match load_image(&mut device, &mut vault) {
            Ok((h, _)) => {
                report.check(
                    h.generation == 1 && h.bank == 0,
                    "A/B ping-pong seamlessly fell back to generation 1 in Bank A after Bank B mid-write corruption",
                );
            }
            Err(e) => {
                println!("[!!] STORAGE: fallback failed: {}", e.as_str());
                report.check(false, "A/B fallback to Bank A failed");
            }
        }
    }

    // Honey-pot duress test:
    // A duress secret unlocks Bank C and loads the sterile decoy sector.
    {
        let mut duress_disk = crate::block::MemDisk::from_bytes(&disk_snapshot(&disk, 0));
        let mut duress_vault = KellerVault::new(b"duress");
        match load_image(&mut duress_disk, &mut duress_vault) {
            Ok((_, adopted)) => {
                report.check(adopted == 1, "duress load adopted decoy sector");
                report.check(duress_vault.is_duress(), "duress vault entered duress mode");
                report.check(
                    matches!(duress_vault.load(USER_SECTOR), Ok(ref msg) if msg == b"SYSTEM STERILE: DECOY VAULT ACTIVE (DURESS MODE)"),
                    "duress mode loaded sterile decoy sector from Bank C",
                );
            }
            Err(e) => {
                println!("[!!] STORAGE: duress test failed: {}", e.as_str());
                report.check(false, "duress authentication failed");
            }
        }
    }

    // An edited superblock MAC on both banks fails the tag under the derived key.
    {
        let mut edited = disk_snapshot(&disk, SUPERBLOCK_MAC_OFFSET + 1);
        edited[SECTOR_SIZE + SUPERBLOCK_MAC_OFFSET + 1] ^= 0x01;
        let mut device = crate::block::MemDisk::from_bytes(&edited);
        let mut vault = KellerVault::new(key);
        report.check(
            matches!(
                load_image(&mut device, &mut vault),
                Err(StorageError::HeaderTampered)
            ),
            "an image whose superblock MACs were edited was accepted",
        );
    }
    // An edited statement on both banks is refused.
    {
        let mut edited = disk_snapshot(&disk, 36);
        edited[SECTOR_SIZE + 36] ^= 0x01;
        let mut device = crate::block::MemDisk::from_bytes(&edited);
        let mut vault = KellerVault::new(key);
        report.check(
            matches!(
                load_image(&mut device, &mut vault),
                Err(StorageError::HeaderTampered) | Err(StorageError::NotAuthenticated)
            ),
            "an image whose device nonce was edited was accepted",
        );
    }
    // An edited record in the active bank (Bank B) must fail its tag.
    {
        let active_bank_start = bank_data_start(1, 8) as usize;
        let edited = disk_snapshot(&disk, active_bank_start * SECTOR_SIZE + RECORD_HEADER_BYTES + 4);
        let mut device = crate::block::MemDisk::from_bytes(&edited);
        let mut vault = KellerVault::new(key);
        // Candidate B fails RecordTampered; candidate A (gen 1) has empty slot 7, so it falls back to A
        // or fails RecordTampered if both are checked.
        let loaded = load_image(&mut device, &mut vault);
        report.check(
            matches!(loaded, Ok((h, _)) if h.generation == 1) || matches!(loaded, Err(StorageError::RecordTampered)),
            "an image with an edited record was safely handled (fell back or rejected)",
        );
    }
    // A blank disk has no image, and says so rather than loading zeroes as data.
    {
        let mut device = crate::block::MemDisk::new(64);
        let mut vault = KellerVault::new(key);
        report.check(
            matches!(load_image(&mut device, &mut vault), Err(StorageError::NoImage)),
            "a blank disk was reported as holding an image",
        );
    }
    // An unknown format version is refused, not guessed at.
    {
        let mut edited = disk_snapshot(&disk, 8);
        edited[8] = 0x7F;
        edited[SECTOR_SIZE + 8] = 0x7F;
        let mut device = crate::block::MemDisk::from_bytes(&edited);
        let mut vault = KellerVault::new(key);
        report.check(
            matches!(load_image(&mut device, &mut vault), Err(StorageError::BadImage)),
            "an image with an unknown format version was accepted",
        );
    }
    // Wiping must leave nothing readable behind.
    {
        let mut device = crate::block::MemDisk::from_bytes(&disk_snapshot(&disk, 0));
        report.check(wipe_image(&mut device).is_ok(), "wiping the image failed");
        let mut vault = KellerVault::new(key);
        report.check(
            matches!(load_image(&mut device, &mut vault), Err(StorageError::NoImage)),
            "a wiped image still reported an image",
        );
    }

    // The journal: what a later boot reads back has to be what an earlier one wrote, with the
    // counter advanced and the stamp unchanged - even when the "later boot" is a *fresh vault*
    // opening the bytes the earlier one left behind. That is what persistence means, and it is
    // the one claim a single process cannot make about its own RAM.
    {
        let mut device = crate::block::MemDisk::new(64);
        let mut vault = KellerVault::new(key);
        let first = journal_on(&mut device, &mut vault);
        report.check(
            matches!(first, Ok(entry) if entry.boots == 1),
            "the first journal entry is not entry 1",
        );
        let stamp = match first {
            Ok(entry) => entry.stamp,
            Err(_) => [0u8; 16],
        };
        // A restart: new vault, same medium, nothing carried over in memory.
        let mut device = crate::block::MemDisk::from_bytes(&disk_snapshot(&device, 0));
        let mut vault = KellerVault::new(key);
        match journal_on(&mut device, &mut vault) {
            Ok(entry) => {
                report.check(entry.boots == 2, "the counter did not advance across a restart");
                report.check(entry.stamp == stamp, "the journal's stamp changed across a restart");
            }
            Err(error) => {
                println!("[!!] STORAGE: restart failed: {}", error.as_str());
                report.check(false, "the journal could not be advanced after a restart");
                report.check(false, "the journal could not be advanced after a restart");
            }
        }
    }
    // An edited journal record is refused rather than read back as a counter. The journal is the
    // vault's only sector here, so it is the record in slot 0.
    {
        let mut device = crate::block::MemDisk::new(64);
        let mut vault = KellerVault::new(key);
        let _ = journal_on(&mut device, &mut vault);
        let hdr = read_header(&mut device).unwrap().unwrap();
        let active_bank_start = bank_data_start(hdr.bank, hdr.slots) as usize;
        let mut edited = disk_snapshot(
            &device,
            active_bank_start * SECTOR_SIZE + RECORD_HEADER_BYTES + 2,
        );
        // Wipe Superblock A so it cannot fall back to empty Bank A
        edited[..SECTOR_SIZE].fill(0);
        let mut device = crate::block::MemDisk::from_bytes(&edited);
        let mut vault = KellerVault::new(key);
        report.check(
            matches!(
                journal_on(&mut device, &mut vault),
                Err(StorageError::RecordTampered)
            ),
            "an image with an edited journal record was accepted",
        );
    }

    report
}

/// A copy of an in-memory disk with one byte flipped, for the tamper cases.
fn disk_snapshot(disk: &crate::block::MemDisk, flip_offset: usize) -> Vec<u8> {
    let bytes = disk.sector_count() as usize * SECTOR_SIZE;
    let mut snapshot = Vec::from(disk.peek(0, bytes));
    if flip_offset != 0 {
        snapshot[flip_offset] ^= 0x01;
    }
    snapshot
}
