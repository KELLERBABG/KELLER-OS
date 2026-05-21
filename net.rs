// network.rs
use alloc::vec::Vec;
use alloc::vec;
use crate::crypto::HardwareRng;
use rand_core::RngCore;

pub const BASE_SIZE: usize = 512;
pub const JITTER_MAX: usize = 64;
pub const HANDSHAKE_ID: u8 = 255;

// ---------- Packet field offsets ----------
pub const OFFSET_MSG_ID: usize = 0;
pub const OFFSET_ORIG_LEN: usize = 1;
pub const OFFSET_SHARE_START: usize = 2;
pub const OFFSET_SHARE_END: usize = 35;
pub const OFFSET_COUNTER_START: usize = 35;
pub const OFFSET_COUNTER_END: usize = 43;
pub const OFFSET_SHARD_START: usize = 43;

/// Ein Trait, der von der Sandbox implementiert wird, um Pakete 
/// über den sicheren IPC-Kanal (Bezirk IV) an den Kernel-NIC-Treiber zu leiten.
pub trait IpcPacketSender {
    fn send_via_ipc(&self, packet: &[u8], target_node: u32) -> bool;
}

/// Baut und sendet die drei Handshake-Pakete.
/// Jedes Paket enthält einen Shamir Share und einen RS Shard.
pub fn send_handshake_packets(
    shares: &[Vec<u8>],
    shards: &[Vec<u8>],
    sender: &dyn IpcPacketSender,
    target_node: u32,
) {
    for i in 0..3 {
        let mut p = vec![0u8; BASE_SIZE + 64];
        p[OFFSET_MSG_ID] = HANDSHAKE_ID;
        // original_len bleibt 0 beim Handshake
        
        p[OFFSET_SHARE_START..OFFSET_SHARE_END].copy_from_slice(&shares[i]);
        p[OFFSET_COUNTER_START..OFFSET_COUNTER_END].copy_from_slice(&0u64.to_be_bytes());
        p[OFFSET_SHARD_START..OFFSET_SHARD_START + 480].copy_from_slice(&shards[i]);
        
        // Statt UdpSocket nutzen wir den sicheren IPC-Kanal zum Kernel
        sender.send_via_ipc(&p, target_node);
    }
}

/// Baut und sendet die drei Daten-Pakete für eine Chat-Nachricht.
pub fn send_data_packets(
    msg_id: u8,
    original_len: usize,
    shares: &[Vec<u8>],
    shards: &[Vec<u8>],
    shard_len: usize,
    counter: u64,
    sender: &dyn IpcPacketSender,
    target_node: u32,
) {
    let mut rng = HardwareRng;

    for i in 0..3 {
        // Wir nutzen den Hardware-RNG der CPU für das Jitter-Padding
        let jitter = (rng.next_u32() as usize) % JITTER_MAX;
        let mut p = vec![0u8; BASE_SIZE + jitter];
        
        p[OFFSET_MSG_ID] = msg_id;
        p[OFFSET_ORIG_LEN] = original_len as u8;
        
        p[OFFSET_SHARE_START..OFFSET_SHARE_END].copy_from_slice(&shares[i]);
        p[OFFSET_COUNTER_START..OFFSET_COUNTER_END].copy_from_slice(&counter.to_be_bytes());
        p[OFFSET_SHARD_START..OFFSET_SHARD_START + shard_len].copy_from_slice(&shards[i]);
        
        sender.send_via_ipc(&p, target_node);
    }
}

/// Liest den Sequenz-Zähler aus dem rohen Paket aus.
pub fn parse_counter(buf: &[u8]) -> u64 {
    let mut c = [0u8; 8];
    c.copy_from_slice(&buf[OFFSET_COUNTER_START..OFFSET_COUNTER_END]);
    u64::from_be_bytes(c)
}

/// Berechnet die erwartete Shard-Länge für den Empfänger.
pub fn shard_len_for(msg_id: u8, original_len: usize) -> usize {
    if msg_id == HANDSHAKE_ID {
        480
    } else {
        let effective = ((original_len + 16 + 1) / 2) * 2;
        effective / 2
    }
}
pub struct KellerNet {
    pub node_id: u8,
}

impl KellerNet { // <--- Dieser Block muss die Funktion umschließen
    pub const fn new(node_id: u8) -> Self {
        Self { node_id }
    }

    pub fn wipe(&mut self) { // Nutze &mut self für den Schreibzugriff
        unsafe {
            core::ptr::write_volatile(&mut self.node_id, 0);
        }
    }
} // <--- Block hier schließen