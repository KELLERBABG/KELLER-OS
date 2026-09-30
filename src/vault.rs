//! The Keller vault: root secret storage with two independent protections.
//!
//! 1. **Sharding** - the root secret is split with Reed-Solomon RS(2,1); no single shard
//!    carries the secret, and `purge()` wipes all of them with volatile writes.
//! 2. **Sector sealing** - the root secret is run through HKDF to produce a sector key,
//!    and every stored sector is AEAD-sealed under it with its own index bound in as
//!    additional data. A sector moved to a different index, or edited by hand, fails to
//!    verify instead of decrypting to garbage.
//!
//! The sector key never leaves this struct: callers hand it plaintext and get plaintext
//! back, so a caller mistake cannot leak the key material.

use crate::crypto::{self, CryptoError, KEY_LEN};
use crate::zk::{Proof, Witness};
use alloc::string::String;
use alloc::vec::Vec;

/// Domain separation for the vault's sector key.
const SECTOR_KEY_INFO: &[u8] = b"KOS-VAULT-SECTOR-KEY";
const SECTOR_KEY_SALT: &[u8] = b"KELLER-OS vault key separation";
/// Probe sector used by `self_test`; kept away from the low indices the shell uses.
const PROBE_SECTOR: u64 = 0xFEED;

struct VaultSector {
    index: u64,
    sealed: Vec<u8>,
}

pub struct KellerVault {
    /// Shards of the root secret: two data shards plus one parity shard.
    pub shards: Vec<Vec<u8>>,
    /// Number of shards needed to reconstruct the secret (RS(2,1) needs two).
    pub threshold: usize,
    /// HKDF-derived sector key; never exposed through the accessor API.
    sector_key: [u8; KEY_LEN],
    /// The zero-knowledge witness derived from the same root secret. This is what lets the vault
    /// *prove* it holds the secret without the disk ever storing one (see [`crate::zk`]).
    witness: Witness,
    sectors: Vec<VaultSector>,
    writes: u64,
    rejected_openings: u64,
}

impl KellerVault {
    pub fn new(data: &[u8]) -> Self {
        let mut data_vec = Vec::from(data);
        let shards = match crypto::rs_encode(&mut data_vec) {
            Ok(shards) => shards,
            Err(error) => {
                crate::println!("[!!] VAULT: shard encoding failed: {}", error.as_str());
                Vec::new()
            }
        };

        let mut sector_key = [0u8; KEY_LEN];
        crypto::hkdf_sha256(SECTOR_KEY_SALT, data, SECTOR_KEY_INFO, &mut sector_key);

        Self {
            shards,
            threshold: crypto::RS_DATA_SHARDS,
            sector_key,
            witness: Witness::from_secret(data),
            sectors: Vec::new(),
            writes: 0,
            rejected_openings: 0,
        }
    }

    /// The public commitment to this vault's root secret. Safe to store, log and compare: it is
    /// what the disk holds instead of a key.
    pub fn proof_commitment(&self) -> [u8; 32] {
        self.witness.commitment()
    }

    /// Proves knowledge of the root secret for `context` (the image's own nonce and header).
    pub fn prove_ownership(&self, context: &[u8]) -> Proof {
        self.witness.prove(context)
    }

    /// Checks that `proof` was made by *this* vault's secret for `public` and `context`.
    pub fn owns(&self, public: &[u8; 32], proof: &Proof, context: &[u8]) -> bool {
        self.witness.proves_ownership(public, proof, context)
    }

    /// The indices of the sectors this vault currently holds, in insertion order.
    pub fn sector_indices(&self) -> Vec<u64> {
        self.sectors.iter().map(|sector| sector.index).collect()
    }

    /// The sealed bytes of sector `index`, exactly as they would be written to a disk.
    pub fn sealed_bytes(&self, index: u64) -> Option<&[u8]> {
        self.sectors
            .iter()
            .find(|sector| sector.index == index)
            .map(|sector| sector.sealed.as_slice())
    }

    /// Installs a sealed sector that came from somewhere else (a disk image), after checking that
    /// it actually opens under this vault's key. A record sealed for a different secret, or for a
    /// different sector index, counts as a rejected opening and is not installed.
    pub fn adopt_sealed(&mut self, index: u64, sealed: &[u8]) -> Result<(), CryptoError> {
        self.open_sealed(index, sealed)?;
        if let Some(sector) = self.sectors.iter_mut().find(|sector| sector.index == index) {
            sector.sealed = Vec::from(sealed);
        } else {
            self.sectors.push(VaultSector {
                index,
                sealed: Vec::from(sealed),
            });
        }
        Ok(())
    }

    /// True when every shard was produced by the encoder.
    pub fn is_healthy(&self) -> bool {
        self.shards.len() == crypto::RS_DATA_SHARDS + crypto::RS_PARITY_SHARDS
    }

    pub fn sector_count(&self) -> usize {
        self.sectors.len()
    }

    pub fn write_count(&self) -> u64 {
        self.writes
    }

    pub fn rejected_openings(&self) -> u64 {
        self.rejected_openings
    }

    /// A public fingerprint of the sector key (hash, not the key), for logs and display.
    pub fn key_fingerprint(&self) -> String {
        hex::encode(&crypto::sha256(&self.sector_key)[..8])
    }

    /// Seals `plaintext` into sector `index`, replacing any previous contents.
    pub fn store(&mut self, index: u64, plaintext: &[u8]) -> Result<(), CryptoError> {
        let sealed = crypto::sector_seal(&self.sector_key, index, plaintext);
        self.writes += 1;
        if let Some(sector) = self.sectors.iter_mut().find(|sector| sector.index == index) {
            sector.sealed = sealed;
        } else {
            self.sectors.push(VaultSector { index, sealed });
        }
        Ok(())
    }

    /// Verifies and decrypts a sealed copy without touching stored state.
    fn open_sealed(&mut self, index: u64, sealed: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match crypto::sector_open(&self.sector_key, index, sealed) {
            Ok(plaintext) => Ok(plaintext),
            Err(error) => {
                self.rejected_openings += 1;
                Err(error)
            }
        }
    }

    /// Verifies and decrypts sector `index`.
    pub fn load(&mut self, index: u64) -> Result<Vec<u8>, CryptoError> {
        let sealed = match self.sectors.iter().find(|sector| sector.index == index) {
            Some(sector) => sector.sealed.clone(),
            None => return Err(CryptoError::BadLength),
        };
        self.open_sealed(index, &sealed)
    }

    /// Overwrites and removes a sector (used after a one-shot probe).
    pub fn wipe_sector(&mut self, index: u64) {
        if let Some(position) = self.sectors.iter().position(|sector| sector.index == index) {
            let mut sector = self.sectors.remove(position);
            crypto::wipe(&mut sector.sealed);
        }
    }

    /// Exercises the sector codec end to end inside the vault: seal, open, reject a
    /// tampered copy, then wipe the probe sector. Returns true only if all four hold.
    pub fn self_test(&mut self) -> bool {
        let payload = b"KELLER-OS VAULT SECTOR ROUND-TRIP PROBE";

        if self.store(PROBE_SECTOR, payload).is_err() {
            return false;
        }
        let round_trip = match self.load(PROBE_SECTOR) {
            Ok(opened) => opened == payload,
            Err(_) => false,
        };

        let stored = match self
            .sectors
            .iter()
            .find(|sector| sector.index == PROBE_SECTOR)
        {
            Some(sector) => sector.sealed.clone(),
            None => return false,
        };
        let mut tampered = stored.clone();
        if !tampered.is_empty() {
            let last = tampered.len() - 1;
            tampered[last] ^= 0x01;
        }
        let rejected = matches!(
            self.open_sealed(PROBE_SECTOR, &tampered),
            Err(CryptoError::TagMismatch)
        );
        // A sector replayed at a different index must not verify either.
        let swapped = matches!(
            self.open_sealed(PROBE_SECTOR + 1, &stored),
            Err(CryptoError::TagMismatch)
        );

        self.wipe_sector(PROBE_SECTOR);
        round_trip && rejected && swapped
    }

    /// Irreversibly clears every secret in RAM: shards, sector key, sealed sectors, and
    /// the derived intermediate material. Volatile writes keep the compiler honest.
    pub fn purge(&mut self) {
        for shard in self.shards.iter_mut() {
            crypto::wipe(shard);
        }
        crypto::wipe(&mut self.sector_key);
        self.witness.clear();
        for sector in self.sectors.iter_mut() {
            crypto::wipe(&mut sector.sealed);
        }
        self.sectors.clear();
    }
}
