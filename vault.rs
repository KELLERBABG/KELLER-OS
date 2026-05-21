// vault.rs
use alloc::vec::Vec;
use crate::crypto; // Importiert deine Krypto-Logik aus crypto.rs

pub struct KellerVault {
    /// Die Bruchstücke (Shards) des Geheimnisses.
    /// Dank Reed-Solomon enthält kein einzelner Shard das vollständige Geheimnis.
    pub shards: Vec<Vec<u8>>,
    /// Anzahl der Shards, die zur Wiederherstellung benötigt werden (Threshold).
    pub threshold: usize,
}

impl KellerVault {
    /// Erzeugt einen neuen Vault. 
    /// Verwendet Reed-Solomon (2,1) Erasure Coding, um die Daten in 
    /// zwei Daten-Shards und einen Paritäts-Shard zu zerlegen.
    pub fn new(data: &[u8]) -> Self {
        let mut data_vec = Vec::from(data);
        
        // Echter Aufruf deiner rs_encode Funktion aus crypto.rs.
        // Diese teilt die Daten auf und berechnet den Paritäts-Block.
        let shards = crypto::rs_encode(&mut data_vec); 
        
        Self { 
            shards, 
            threshold: 2 // Bei RS(2,1) reichen 2 beliebige Shards zur Rekonstruktion.
        }
    }

    /// Löscht alle kryptografischen Fragmente im RAM unwiderruflich.
    /// Nutzt volatile Schreibvorgänge, um zu verhindern, dass der Compiler 
    /// den Löschvorgang wegoptimiert.
    pub fn purge(&mut self) {
        for shard in self.shards.iter_mut() {
            for byte in shard.iter_mut() {
                // Sicherer Zugriff auf den rohen Speicherplatz
                unsafe {
                    core::ptr::write_volatile(byte as *mut u8, 0u8);
                }
            }
        }
    }
}