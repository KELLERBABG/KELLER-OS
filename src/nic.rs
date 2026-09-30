//! Intel 8254x (e1000) Ethernet driver: real frames on a real wire.
//!
//! Until this module existed, the Vantablack mesh's transport was an in-RAM stand-in
//! (`net::CaptureSender`): the sealed shard frames were produced and consumed by the same
//! machine, so nothing about the wire path — addresses, headers, DMA, the device itself — was
//! exercised. This is the other end of that path.
//!
//! **Descriptor rings.** Two rings of eight 16-byte descriptors in normal RAM, with eight 4 KiB
//! buffers each. The device reads and writes that memory directly, which is why the buffers come
//! from [`dma_frame`]: the kernel heap sits inside the boot identity map, so a heap block's
//! virtual address *is* its physical address, and the value handed to the device in a descriptor
//! is the same value the driver writes through. Nothing has to be translated and no separate
//! physical allocator has to be kept in sync. The counter for these frames is private to this
//! module on purpose: `paging::frames_in_use()` keeps meaning "page-table and user-space frames",
//! so a permanent DMA arena cannot be mistaken for a leak by the ring-3 reports.
//!
//! **Polling, not interrupts.** PCI INTx for this device is not routed to the PIC (only IRQ0,
//! IRQ1 and IRQ4 are unmasked), and the driver already runs on a 100 Hz kernel loop, so the rings
//! are polled and every interrupt source is masked (`IMS = 0`, `IMC = all ones`). That keeps a
//! device with no interrupt line from becoming a device that hangs a boot, and the counters below
//! are what say the loop is actually reaching it. Interrupt-driven RX is a later optimisation,
//! not a correctness question: the wire tool measures the same packets either way.
//!
//! **What this is not (yet).** The driver runs in ring 0. A DMA-capable device in ring 3 needs
//! either an IOMMU or the bounce-buffer split the specification describes (the sandbox task
//! decides, the kernel moves bytes), and neither exists yet; putting a raw BAR behind a ring-3
//! task today would hand it the whole physical address space, which is the opposite of the
//! isolation work it would be sitting on top of. The plumbing here (rings in identity-mapped
//! frames, MMIO through one window, counters for every path) is exactly what a mediated split
//! needs, and the ports and DMA addresses are already the only things a sandbox would have to be
//! given.
//!
//! **Where the state lives.** The descriptor rings are part of the `Nic` state rather than
//! separately allocated frames, and that only works because two things hold: the state is
//! resident in `.data` (its initialiser carries a non-zero signature, which keeps it out of
//! `.bss` - and the boot handoff explicitly does not zero `.bss`, so a driver whose state began
//! life there would start with someone else's bytes in `present` and in its BAR pointer), and the
//! rings are `align(128)` so the base addresses satisfy the descriptor-ring alignment the device
//! requires. The self-test asserts the alignment and the signature, so a state-placement
//! regression shows up as a failed boot line rather than as a device that receives nothing.
//!
//! Registers follow the 82540EM datasheet; the register map is shared across the 8254x family, so
//! the id table below is a list of "same map", not a list of models this was tested on. QEMU's
//! `e1000` model (what the harness boots with, and what `-device e1000` gives) is `8086:100e`.

use crate::eth;
use crate::pci;
use crate::println;
use alloc::alloc::{alloc, Layout};
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};

// ------------------------------------------------------------------ PCI identity

/// Vendor every device id here belongs to.
const VENDOR_INTEL: u16 = 0x8086;
/// 8254x-family device ids: the register map below is what they share.
const SUPPORTED_IDS: [u16; 24] = [
    0x1004, 0x1008, 0x1009, 0x100C, 0x100D, 0x100E, 0x100F, 0x1010, 0x1012, 0x1013, 0x1015, 0x1016,
    0x1017, 0x1019, 0x1026, 0x1027, 0x1028, 0x1075, 0x1076, 0x1077, 0x1078, 0x1079, 0x107A, 0x107B,
];
/// Names for the ids worth naming in a log line.
fn model_name(device: u16) -> &'static str {
    match device {
        0x1004 => "82543GC",
        0x100E => "82540EM",
        0x100F => "82545EM",
        0x1028 => "82548EM",
        0x1075 => "82547EI",
        0x1076 => "82541GI",
        0x1077 => "82547GI",
        0x1078 => "82541GI",
        _ => "8254x",
    }
}

/// virtio-net, detected only so a machine with one gets an honest line instead of silence.
const VIRTIO_VENDOR: u16 = 0x1AF4;
const VIRTIO_NET_MODERN: u16 = 0x1041;
const VIRTIO_NET_LEGACY: u16 = 0x1000;

/// Preferred BAR0 base when no loader assigned one (the region QEMU's devices normally sit in).
const PREFERRED_BAR: u64 = 0xFEB0_0000;
/// Registers up to `MTA` occupy the first 0x5408 bytes; 32 KiB of window covers them with room.
const REQUIRED_WINDOW: u64 = 32 * 1024;

// ------------------------------------------------------------------ registers

const CTRL: u32 = 0x0000;
const STATUS: u32 = 0x0008;
const EECD: u32 = 0x0010;
/// Interrupt cause: *reading* it clears every bit, which is what deasserts the interrupt.
const ICR: u32 = 0x000C;
const IMS: u32 = 0x00D0;
const IMC: u32 = 0x00D8;
/// Interrupt cause: transmit descriptor written back. Set once per descriptor that asked for a
/// report, which is what makes it the one cause a driver can raise on demand.
const ICR_TXDW: u32 = 1 << 0;
const RCTL: u32 = 0x0100;
const TCTL: u32 = 0x0400;
const RDBAL: u32 = 0x2800;
const RDBAH: u32 = 0x2804;
const RDLEN: u32 = 0x2808;
const RDH: u32 = 0x2810;
const RDT: u32 = 0x2818;
const TDBAL: u32 = 0x3800;
const TDBAH: u32 = 0x3804;
const TDLEN: u32 = 0x3808;
const TDH: u32 = 0x3810;
const TDT: u32 = 0x3818;
const MTA: u32 = 0x5200;
const RAL0: u32 = 0x5400;
const RAH0: u32 = 0x5404;

/// CTRL bits.
const CTRL_FD: u32 = 1 << 0;
const CTRL_SLU: u32 = 1 << 6;
const CTRL_FRCSPD: u32 = 1 << 11;
const CTRL_FRCDPX: u32 = 1 << 12;
const CTRL_RST: u32 = 1 << 26;
/// STATUS bits.
const STATUS_FD: u32 = 1 << 0;
const STATUS_LU: u32 = 1 << 1;
/// RAH0: address valid.
const RAH_AV: u32 = 1 << 31;
/// RCTL: enable, unicast/multicast/broadcast promiscuous, long packets, strip CRC, 2048-byte
/// buffers. Promiscuous receive is deliberate: this is a lab driver whose peer is whoever is on
/// the wire, and every frame that is not for this endpoint is counted as foreign rather than
/// silently dropped — which is how the wire tool proves the filter is doing something.
const RCTL_VALUE: u32 =
    (1 << 1) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 15) | (1 << 26);
/// TCTL: enable, pad short packets, collision threshold 15, distance 64 (full duplex).
const TCTL_VALUE: u32 = (1 << 1) | (1 << 3) | (15 << 4) | (64 << 12);

const TX_DESCRIPTORS: usize = 8;
const RX_DESCRIPTORS: usize = 8;
const DESCRIPTOR_BYTES: usize = 16;
/// Buffer per descriptor: one 4 KiB frame, which holds any Ethernet frame with room to spare.
const BUFFER_BYTES: usize = 4096;

/// Transmit descriptor command bits: end of packet, insert FCS, report status.
const TX_CMD_EOP: u8 = 1 << 0;
const TX_CMD_IFCS: u8 = 1 << 1;
const TX_CMD_RS: u8 = 1 << 3;
/// Descriptor status: descriptor done (both directions).
const DESC_STATUS_DD: u8 = 1 << 0;

/// Register polls before a TX descriptor is declared stuck, and before a reset is declared
/// failed. Both are loops over MMIO reads, so the bound is in the same units as the hardware.
const TX_SPIN_LIMIT: u32 = 200_000;
const RESET_SPIN_LIMIT: u32 = 1_000_000;

/// Marks a `Nic` as initialised. Non-zero on purpose: it is what keeps this state in `.data`,
/// where the loader's bytes are the ones the compiler emitted (see the module comment).
const NIC_SIGNATURE: u64 = 0x4B45_4C4C_4E49_4301; // "KELLNIC\x01"

/// The 8254x legacy transmit descriptor: address, length, offload fields, command, status.
#[repr(C)]
#[derive(Clone, Copy)]
struct TxDescriptor {
    address: u64,
    length: u16,
    cso: u8,
    cmd: u8,
    status: u8,
    css: u8,
    special: u16,
}

/// The 8254x legacy receive descriptor: address, then what the device wrote back.
#[repr(C)]
#[derive(Clone, Copy)]
struct RxDescriptor {
    address: u64,
    length: u16,
    checksum: u16,
    status: u8,
    errors: u8,
    special: u16,
}

/// The two rings, each 128-byte aligned as the descriptor-base registers require (bits 3:0 of
/// `TDBAL`/`RDBAL` are reserved and must be zero).
#[repr(C, align(128))]
struct TxRing {
    descriptors: [TxDescriptor; TX_DESCRIPTORS],
}

#[repr(C, align(128))]
struct RxRing {
    descriptors: [RxDescriptor; RX_DESCRIPTORS],
}

/// Software-side accounting for the DMA arena, kept separate from the paging frame counter.
static DMA_FRAMES: AtomicU64 = AtomicU64::new(0);

/// Allocation of a page-aligned block whose address is also its physical address. See the module
/// comment: the heap lives in the identity map, so no translation is involved anywhere.
fn dma_frame() -> u64 {
    let layout = Layout::from_size_align(BUFFER_BYTES, BUFFER_BYTES).unwrap();
    let pointer = unsafe { alloc(layout) };
    if pointer.is_null() {
        return 0;
    }
    unsafe { ptr::write_bytes(pointer, 0, BUFFER_BYTES) };
    DMA_FRAMES.fetch_add(1, Ordering::Relaxed);
    pointer as u64
}

/// One received datagram, already parsed.
pub struct Received {
    pub port: u16,
    pub source: eth::Endpoint,
    pub identification: u16,
    pub length: usize,
}

/// The shape of the last frame the driver would not hand on.
///
/// A counter says refusal happened; it does not say *what* was refused, and on a shared segment
/// most of what arrives is not for us and never will be. Keeping the header fields of the last
/// refusal turns "malformed=23" into "23 frames, the last one being a 70-byte non-UDP IPv4 frame"
/// - which is the difference between a working filter and a parser that is silently dropping real
/// traffic. Only the fields of the header are kept, never the payload.
#[derive(Clone, Copy)]
pub struct RefusedShape {
    pub count: u64,
    pub length: usize,
    pub reason: Option<eth::Reject>,
    pub ethertype: u16,
    pub ip_protocol: u8,
}

impl RefusedShape {
    const fn empty() -> Self {
        Self {
            count: 0,
            length: 0,
            reason: None,
            ethertype: 0,
            ip_protocol: 0,
        }
    }
}

pub struct Nic {
    /// Written by `Nic::empty()`; see [`NIC_SIGNATURE`].
    signature: u64,
    present: bool,
    bus: u8,
    slot: u8,
    function: u8,
    device: u16,
    bar: u64,
    bar_size: u64,
    /// BAR0 as a register window: 32-bit registers at 4-byte strides.
    mmio: *mut u32,
    mac: [u8; 6],
    link_up: bool,
    speed_mbps: u32,
    full_duplex: bool,
    tx_ring: TxRing,
    rx_ring: RxRing,
    tx_buffers: [u64; TX_DESCRIPTORS],
    rx_buffers: [u64; RX_DESCRIPTORS],
    tx_tail: usize,
    rx_index: usize,
    identification: u16,
    /// Device interrupts taken on the message-signalled vector, and the cause word the last one
    /// carried. Zero for both while the driver runs on polling, which is the default.
    interrupts: u64,
    last_cause: u32,
    /// Frames whose payload was copied out for parsing (a received frame can be larger than the
    /// payload buffer the caller offered).
    scratch: [u8; 2048],
    /// Whether the mesh is allowed onto the wire (see [`set_wire`]).
    wire_enabled: bool,
    last_refused: RefusedShape,
    tx_frames: u64,
    tx_bytes: u64,
    tx_errors: u64,
    rx_frames: u64,
    rx_bytes: u64,
    rx_mesh: u64,
    rx_probe: u64,
    rx_foreign: u64,
    rx_errors: u64,
    rx_malformed: u64,
    rx_fragmented: u64,
    rx_not_udp: u64,
    rx_not_ipv4: u64,
    rx_bad_checksum: u64,
    arp_requests: u64,
    arp_replies: u64,
    arp_ignored: u64,
}

impl Nic {
    const fn empty() -> Self {
        Self {
            signature: NIC_SIGNATURE,
            present: false,
            bus: 0,
            slot: 0,
            function: 0,
            device: 0,
            bar: 0,
            bar_size: 0,
            mmio: ptr::null_mut(),
            mac: [0; 6],
            link_up: false,
            speed_mbps: 0,
            full_duplex: false,
            tx_ring: TxRing {
                descriptors: [TxDescriptor {
                    address: 0,
                    length: 0,
                    cso: 0,
                    cmd: 0,
                    status: 0,
                    css: 0,
                    special: 0,
                }; TX_DESCRIPTORS],
            },
            rx_ring: RxRing {
                descriptors: [RxDescriptor {
                    address: 0,
                    length: 0,
                    checksum: 0,
                    status: 0,
                    errors: 0,
                    special: 0,
                }; RX_DESCRIPTORS],
            },
            tx_buffers: [0; TX_DESCRIPTORS],
            rx_buffers: [0; RX_DESCRIPTORS],
            tx_tail: 0,
            rx_index: 0,
            identification: 0,
            interrupts: 0,
            last_cause: 0,
            scratch: [0; 2048],
            wire_enabled: true,
            last_refused: RefusedShape::empty(),
            tx_frames: 0,
            tx_bytes: 0,
            tx_errors: 0,
            rx_frames: 0,
            rx_bytes: 0,
            rx_mesh: 0,
            rx_probe: 0,
            rx_foreign: 0,
            rx_errors: 0,
            rx_malformed: 0,
            rx_fragmented: 0,
            rx_not_udp: 0,
            rx_not_ipv4: 0,
            rx_bad_checksum: 0,
            arp_requests: 0,
            arp_replies: 0,
            arp_ignored: 0,
        }
    }
}

static mut NIC: Nic = Nic::empty();

unsafe fn nic() -> &'static mut Nic {
    &mut *core::ptr::addr_of_mut!(NIC)
}

// ------------------------------------------------------------------ register access

impl Nic {
    fn read(&self, offset: u32) -> u32 {
        unsafe { ptr::read_volatile(self.mmio.add((offset / 4) as usize)) }
    }

    fn write(&self, offset: u32, value: u32) {
        unsafe { ptr::write_volatile(self.mmio.add((offset / 4) as usize), value) }
    }

    /// Polls a register until `predicate` holds or the budget runs out.
    fn poll(&self, offset: u32, limit: u32, predicate: impl Fn(u32) -> bool) -> u32 {
        let mut spins = 0;
        loop {
            let value = self.read(offset);
            if predicate(value) || spins >= limit {
                return value;
            }
            spins += 1;
            core::hint::spin_loop();
        }
    }

    fn reset(&self) {
        let control = self.read(CTRL);
        self.write(CTRL, control | CTRL_RST);
        self.poll(CTRL, RESET_SPIN_LIMIT, |value| value & CTRL_RST == 0);
    }

    fn read_mac(&self) -> [u8; 6] {
        let low = self.read(RAL0);
        let high = self.read(RAH0);
        [
            low as u8,
            (low >> 8) as u8,
            (low >> 16) as u8,
            (low >> 24) as u8,
            high as u8,
            (high >> 8) as u8,
        ]
    }

    /// Writes the receive address register back with `AV` set, which is what makes the device
    /// accept unicast frames for this MAC at all.
    fn program_mac(&self) {
        let mac = self.mac;
        self.write(RAL0, u32::from_le_bytes([mac[0], mac[1], mac[2], mac[3]]));
        self.write(RAH0, u16::from_le_bytes([mac[4], mac[5]]) as u32 | RAH_AV);
    }

    fn clear_multicast_table(&self) {
        for index in 0..128 {
            self.write(MTA + index * 4, 0);
        }
    }

    fn mask_interrupts(&self) {
        self.write(IMC, 0xFFFF_FFFF);
        let _ = self.read(IMS);
    }

    fn set_link_up(&mut self) {
        let control = self.read(CTRL);
        self.write(
            CTRL,
            (control | CTRL_SLU | CTRL_FRCSPD | CTRL_FRCDPX) & !CTRL_FD,
        );
        // A link takes a moment to come up; read it back rather than assuming.
        let status = self.poll(STATUS, 2_000_000, |value| value & STATUS_LU != 0);
        self.link_up = status & STATUS_LU != 0;
        self.full_duplex = status & STATUS_FD != 0;
        self.speed_mbps = match (status >> 6) & 3 {
            0 => 10,
            1 => 100,
            _ => 1000,
        };
    }

    fn init_tx(&mut self) {
        let ring = self.tx_ring.descriptors.as_mut_ptr() as u64;
        for index in 0..TX_DESCRIPTORS {
            self.tx_ring.descriptors[index] = TxDescriptor {
                address: self.tx_buffers[index],
                length: 0,
                cso: 0,
                cmd: 0,
                status: DESC_STATUS_DD, // free: the first fill waits for nothing
                css: 0,
                special: 0,
            };
        }
        self.write(TDBAL, ring as u32);
        self.write(TDBAH, (ring >> 32) as u32);
        self.write(TDLEN, (TX_DESCRIPTORS * DESCRIPTOR_BYTES) as u32);
        self.write(TDH, 0);
        self.write(TDT, 0);
        self.write(TCTL, TCTL_VALUE);
        self.tx_tail = 0;
    }

    fn init_rx(&mut self) {
        let ring = self.rx_ring.descriptors.as_mut_ptr() as u64;
        for index in 0..RX_DESCRIPTORS {
            self.rx_ring.descriptors[index] = RxDescriptor {
                address: self.rx_buffers[index],
                length: 0,
                checksum: 0,
                status: 0,
                errors: 0,
                special: 0,
            };
        }
        self.write(RDBAL, ring as u32);
        self.write(RDBAH, (ring >> 32) as u32);
        self.write(RDLEN, (RX_DESCRIPTORS * DESCRIPTOR_BYTES) as u32);
        self.write(RDH, 0);
        // The tail is inclusive: hardware may use descriptors up to and including it. Starting at
        // the last one hands it the whole ring, and every cleaned descriptor is given straight
        // back by moving the tail behind the software index.
        self.write(RDT, (RX_DESCRIPTORS - 1) as u32);
        self.write(RCTL, RCTL_VALUE);
        self.rx_index = 0;
    }

    fn wait_tx_done(&self, slot: usize) -> bool {
        let mut spins = 0;
        while self.tx_ring.descriptors[slot].status & DESC_STATUS_DD == 0 {
            if spins >= TX_SPIN_LIMIT {
                return false;
            }
            spins += 1;
            core::hint::spin_loop();
        }
        true
    }

    /// Copies `frame` into the next transmit buffer and hands the descriptor to the device.
    fn transmit_frame(&mut self, frame: &[u8]) -> bool {
        if frame.len() > BUFFER_BYTES || frame.is_empty() {
            return false;
        }
        let slot = self.tx_tail;
        if !self.wait_tx_done(slot) {
            self.tx_errors += 1;
            return false;
        }
        unsafe {
            ptr::copy_nonoverlapping(
                frame.as_ptr(),
                self.tx_buffers[slot] as *mut u8,
                frame.len(),
            );
        }
        self.tx_ring.descriptors[slot].length = frame.len() as u16;
        self.tx_ring.descriptors[slot].status = 0;
        self.tx_ring.descriptors[slot].cmd = TX_CMD_EOP | TX_CMD_IFCS | TX_CMD_RS;
        // The descriptor has to be complete in memory before the device is told about it. A
        // release fence is the ordering the device sees; x86 has no separate DMA flush.
        core::sync::atomic::fence(Ordering::Release);
        self.tx_tail = (slot + 1) % TX_DESCRIPTORS;
        self.write(TDT, self.tx_tail as u32);
        if !self.wait_tx_done(slot) {
            self.tx_errors += 1;
            return false;
        }
        self.tx_frames += 1;
        self.tx_bytes += frame.len() as u64;
        true
    }
}

// ------------------------------------------------------------------ bring-up

/// Finds, resets and programs the adapter. Returns true when frames can be sent.
///
/// # Safety
/// Must run once, after the heap exists, with interrupts either off or harmless: it spins on
/// MMIO while polling for the reset and the link.
pub unsafe fn init() -> bool {
    {
        let nic = nic();
        if nic.present {
            return true;
        }
    }

    let devices = pci::enumerate();
    let mut found = None;
    for device in devices.iter() {
        if device.vendor == VENDOR_INTEL && SUPPORTED_IDS.contains(&device.device) {
            found = Some(*device);
            break;
        }
    }
    let device = match found {
        Some(device) => device,
        None => {
            if let Some(virtio) = devices.iter().find(|candidate| {
                candidate.vendor == VIRTIO_VENDOR
                    && (candidate.device == VIRTIO_NET_MODERN
                        || candidate.device == VIRTIO_NET_LEGACY)
            }) {
                println!(
                    "[--] NETWORK ADAPTER: virtio-net at {:02x}:{:02x}.{} ({:04x}:{:04x}) - this driver speaks the 8254x register map only, so the mesh keeps its in-RAM wire",
                    virtio.bus, virtio.slot, virtio.function, virtio.vendor, virtio.device
                );
            } else {
                println!("[--] NETWORK ADAPTER: none on bus 0 - the mesh keeps its in-RAM wire");
            }
            return false;
        }
    };

    let (bar, bar_size) = match pci::ensure_memory_bar(&device, 0, PREFERRED_BAR) {
        Some(range) => range,
        None => {
            println!(
                "[!!] NETWORK ADAPTER {:02x}:{:02x}.{} has no usable memory BAR",
                device.bus, device.slot, device.function
            );
            return false;
        }
    };
    // Memory decode plus bus mastering: without the second bit the device cannot fetch
    // descriptors, and the symptom is a transmit ring that never completes.
    pci::enable(&device, true);

    {
        let nic = nic();
        nic.present = true;
        nic.bus = device.bus;
        nic.slot = device.slot;
        nic.function = device.function;
        nic.device = device.device;
        nic.bar = bar;
        nic.bar_size = bar_size;
        nic.mmio = bar as *mut u32;
        // Interrupts off before anything else: a spurious line from a device whose handlers do
        // not exist is a nuisance at best.
        nic.mask_interrupts();
        nic.reset();
        nic.mac = nic.read_mac();
        nic.program_mac();
        nic.clear_multicast_table();
        nic.set_link_up();
    }

    // DMA rings: one buffer page per descriptor. The descriptor arrays themselves are in the
    // `Nic` state (`.data`, identity-mapped, so their address is their physical address), which
    // is why nothing has to be allocated for them here.
    {
        let nic = nic();
        if nic.signature != NIC_SIGNATURE {
            println!(
                "[!!] NETWORK ADAPTER: driver state is at {:#x} without its signature - the loader did not place it where the crate expects",
                core::ptr::addr_of!(NIC) as u64
            );
            return false;
        }
        for index in 0..TX_DESCRIPTORS {
            nic.tx_buffers[index] = dma_frame();
        }
        for index in 0..RX_DESCRIPTORS {
            nic.rx_buffers[index] = dma_frame();
        }
        if nic.tx_buffers.iter().any(|frame| *frame == 0)
            || nic.rx_buffers.iter().any(|frame| *frame == 0)
        {
            println!("[!!] NETWORK ADAPTER: no heap left for the packet buffers");
            return false;
        }
        nic.init_tx();
        nic.init_rx();
    }

    let nic = nic();
    println!(
        "[OK] NETWORK ADAPTER: {:02x}:{:02x}.{} {:04x}:{:04x} ({}) bar0={:#x} ({} KiB) bus-master on, mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        nic.bus,
        nic.slot,
        nic.function,
        VENDOR_INTEL,
        nic.device,
        model_name(nic.device),
        nic.bar,
        nic.bar_size / 1024,
        nic.mac[0],
        nic.mac[1],
        nic.mac[2],
        nic.mac[3],
        nic.mac[4],
        nic.mac[5]
    );
    println!(
        "[OK] NIC DMA RINGS: tx {}/{} rx {} descriptors of {} bytes ({} x {} KiB buffers, identity-mapped frames), link={} {} Mb/s {}",
        nic.read(TDLEN) / DESCRIPTOR_BYTES as u32,
        TX_DESCRIPTORS,
        nic.read(RDLEN) / DESCRIPTOR_BYTES as u32,
        DESCRIPTOR_BYTES,
        TX_DESCRIPTORS + RX_DESCRIPTORS,
        BUFFER_BYTES / 1024,
        if nic.link_up { "up" } else { "down" },
        nic.speed_mbps,
        if nic.full_duplex { "full-duplex" } else { "half-duplex" }
    );
    true
}

pub fn ready() -> bool {
    unsafe { nic().present }
}

/// The adapter's PCI function as configuration space has it now. The MSI capability walk needs
/// the device rather than just its BAR, and re-enumerating one bus is cheap.
pub fn pci_device() -> Option<pci::PciDevice> {
    let nic = unsafe { nic() };
    if !nic.present {
        return None;
    }
    pci::enumerate()
        .into_iter()
        .find(|device| {
            device.bus == nic.bus && device.slot == nic.slot && device.function == nic.function
        })
}

/// Unmasks the transmit-descriptor-written-back interrupt on the device. Everything else stays
/// masked: this is the one cause the kernel can raise on purpose, so it is the one an interrupt
/// path can be verified with. Returns the mask register read back out of the device.
pub fn enable_tx_interrupt() -> u32 {
    let nic = unsafe { nic() };
    if !nic.present {
        return 0;
    }
    // Cause first (a stale bit from bring-up would be delivered as soon as the mask opens), then
    // the mask.
    let _ = nic.read(ICR);
    nic.write(IMS, ICR_TXDW);
    nic.read(IMS)
}

/// Reads and clears the device's interrupt cause register. This is the device-side half of one
/// delivery: without it the cause bit stays set and the device would raise the message again
/// immediately. Returns the cause word.
pub fn service_interrupt() -> u32 {
    let nic = unsafe { nic() };
    if !nic.present {
        return 0;
    }
    let cause = nic.read(ICR);
    nic.interrupts += 1;
    nic.last_cause = cause;
    cause
}

/// Device interrupts taken, and the cause word of the last one.
pub fn interrupt_counters() -> (u64, u32) {
    let nic = unsafe { nic() };
    (nic.interrupts, nic.last_cause)
}

pub fn mac() -> [u8; 6] {
    unsafe { nic().mac }
}

pub fn link_up() -> bool {
    unsafe { nic().link_up }
}

/// True while the mesh is allowed onto the wire. Transmit *and* receive are gated by it, so a
/// run can prove the counters stop by turning the wire off and watching them stay put.
pub fn wire_enabled() -> bool {
    unsafe { nic().present && nic().wire_enabled }
}

pub fn set_wire(enabled: bool) {
    unsafe { nic().wire_enabled = enabled };
}

/// The mesh's transport when a supported adapter is up: the same sealed frames the in-RAM wire
/// carries, put on the wire instead of (well, as well as) into a capture.
pub struct WireSender;

impl crate::net::IpcPacketSender for WireSender {
    fn send_via_ipc(&self, packet: &[u8], target_node: u32) -> bool {
        let _ = target_node;
        transmit_mesh(packet)
    }
}

/// The local endpoint the framing layer addresses frames from.
pub fn local_endpoint(port: u16) -> eth::Endpoint {
    eth::endpoint(mac(), eth::GUEST_IP, port)
}

/// Sends one datagram. Both the mesh and the probe use this.
pub fn transmit(payload: &[u8], port: u16) -> bool {
    let nic = unsafe { nic() };
    if !nic.present || !nic.wire_enabled {
        return false;
    }
    nic.identification = nic.identification.wrapping_add(1);
    let identification = nic.identification;
    let mut frame = [0u8; eth::MAX_FRAME];
    let length = match eth::build(
        local_endpoint(port),
        eth::endpoint(eth::GATEWAY_MAC, eth::GATEWAY_IP, port),
        identification,
        payload,
        &mut frame,
    ) {
        Some(length) => length,
        None => return false,
    };
    nic.transmit_frame(&frame[..length])
}

/// Sends one sealed mesh frame over the wire.
pub fn transmit_mesh(frame: &[u8]) -> bool {
    transmit(frame, eth::MESH_PORT)
}

/// Sends the fixed probe datagram, so a wire observer can recognise a test packet by its bytes.
pub fn send_probe() -> bool {
    transmit(eth::PROBE_PAYLOAD, eth::PROBE_PORT)
}

/// Polls the receive ring for the next addressed datagram.
///
/// Frames that are not for this endpoint, or that cannot be parsed, are dequeued, counted and
/// skipped: the ring has to keep moving, and the counters are how "we dropped it" differs from
/// "we never saw it".
pub fn poll(payload: &mut [u8]) -> Option<Received> {
    let nic = unsafe { nic() };
    if !nic.present || !nic.wire_enabled {
        return None;
    }
    for _ in 0..RX_DESCRIPTORS {
        let slot = nic.rx_index;
        if nic.rx_ring.descriptors[slot].status & DESC_STATUS_DD == 0 {
            return None;
        }
        let errors = nic.rx_ring.descriptors[slot].errors;
        let length = nic.rx_ring.descriptors[slot].length as usize;
        let copy_length = core::cmp::min(length, nic.scratch.len());
        unsafe {
            ptr::copy_nonoverlapping(
                nic.rx_buffers[slot] as *const u8,
                nic.scratch.as_mut_ptr(),
                copy_length,
            );
        }
        // Handing the descriptor back is what keeps the device supplied: clear DD, advance the
        // software index, and set the tail to the descriptor just released. The tail is
        // inclusive (the device may use descriptors up to and including it), so pointing it at
        // the released slot re-arms exactly that one - pointing it at the *next* slot instead
        // would leave the ring full and cut the device down to a depth of one.
        nic.rx_ring.descriptors[slot].status = 0;
        nic.rx_index = (slot + 1) % RX_DESCRIPTORS;
        nic.write(RDT, slot as u32);
        nic.rx_frames += 1;
        nic.rx_bytes += length as u64;

        if errors != 0 {
            nic.rx_errors += 1;
            continue;
        }

        // Address resolution first, and before the IPv4 parser, because an ARP frame is exactly
        // the frame `eth::parse` refuses: answering the request is what lets a peer deliver
        // anything to this endpoint at all (see the `eth` module comment).
        if copy_length >= eth::ETHERNET_HEADER_LEN
            && (nic.scratch[12] as u16) << 8 | nic.scratch[13] as u16 == eth::ETHERTYPE_ARP
        {
            nic.arp_requests += 1;
            let message = eth::parse_arp(&nic.scratch[..copy_length]);
            let mut answered = false;
            match message {
                Some(message) if eth::is_request_for(&message, eth::GUEST_IP) => {
                    let mut reply = [0u8; eth::ARP_FRAME_LEN];
                    let length = eth::build_arp_reply(nic.mac, eth::GUEST_IP, &message, &mut reply);
                    match length {
                        Some(length) if nic.transmit_frame(&reply[..length]) => {
                            nic.arp_replies += 1;
                            answered = true;
                        }
                        _ => nic.arp_ignored += 1,
                    }
                }
                // A reply (someone else answering), a request for another address, or a frame
                // that only looked like ARP: counted, never answered.
                _ => nic.arp_ignored += 1,
            }
            // An answered request is not a refusal, so it does not become the last refusal's
            // shape: the record below means "the last frame this driver did not act on".
            if !answered {
                nic.last_refused = RefusedShape {
                    count: nic.arp_ignored,
                    length,
                    reason: None,
                    ethertype: eth::ETHERTYPE_ARP,
                    ip_protocol: 0,
                };
            }
            continue;
        }

        match eth::parse(&nic.scratch[..copy_length]) {
            Ok(datagram) => {
                let port = datagram.destination.port;
                let source = datagram.source;
                let identification = datagram.identification;
                let wanted = (port == eth::MESH_PORT || port == eth::PROBE_PORT)
                    && eth::addressed_to(&datagram, local_endpoint(port), port);
                if !wanted {
                    nic.rx_foreign += 1;
                    nic.last_refused = RefusedShape {
                        count: nic.rx_foreign,
                        length,
                        reason: None, // parsed fine: it is simply addressed elsewhere
                        ethertype: eth::ETHERTYPE_IPV4,
                        ip_protocol: eth::IP_PROTOCOL_UDP,
                    };
                    continue;
                }
                let room = core::cmp::min(payload.len(), datagram.payload.len());
                payload[..room].copy_from_slice(&datagram.payload[..room]);
                match port {
                    eth::MESH_PORT => nic.rx_mesh += 1,
                    eth::PROBE_PORT => nic.rx_probe += 1,
                    _ => {}
                }
                return Some(Received {
                    port,
                    source,
                    identification,
                    length: room,
                });
            }
            Err(reason) => {
                match reason {
                    eth::Reject::Fragmented => nic.rx_fragmented += 1,
                    eth::Reject::NotUdp => nic.rx_not_udp += 1,
                    // A well-formed frame this layer does not speak (IPv6, LLDP, a second ARP
                    // dialect) is not malformed, and saying so would hide a peer behind a
                    // parser complaint. Malformed is reserved for frames that do not make sense.
                    eth::Reject::NotIpv4 => nic.rx_not_ipv4 += 1,
                    eth::Reject::BadChecksum => nic.rx_bad_checksum += 1,
                    _ => nic.rx_malformed += 1,
                }
                nic.last_refused = RefusedShape {
                    count: nic.rx_fragmented
                        + nic.rx_not_udp
                        + nic.rx_not_ipv4
                        + nic.rx_bad_checksum
                        + nic.rx_malformed,
                    length,
                    reason: Some(reason),
                    // Header fields only, and only when the frame is long enough to have them.
                    ethertype: if copy_length >= eth::ETHERNET_HEADER_LEN {
                        (nic.scratch[12] as u16) << 8 | nic.scratch[13] as u16
                    } else {
                        0
                    },
                    ip_protocol: if copy_length >= eth::ETHERNET_HEADER_LEN + 10 {
                        nic.scratch[eth::ETHERNET_HEADER_LEN + 9]
                    } else {
                        0
                    },
                };
                continue;
            }
        }
    }
    None
}

// ------------------------------------------------------------------ reporting

pub fn describe() {
    let nic = unsafe { nic() };
    if !nic.present {
        println!("[SH] NIC: no supported adapter (the mesh uses its in-RAM wire)");
        return;
    }
    println!(
        "[SH] NIC {:02x}:{:02x}.{} {:04x}:{:04x} ({}) bar0={:#x} ({} KiB) mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} link={} {} Mb/s {}",
        nic.bus,
        nic.slot,
        nic.function,
        VENDOR_INTEL,
        nic.device,
        model_name(nic.device),
        nic.bar,
        nic.bar_size / 1024,
        nic.mac[0],
        nic.mac[1],
        nic.mac[2],
        nic.mac[3],
        nic.mac[4],
        nic.mac[5],
        if nic.link_up { "up" } else { "down" },
        nic.speed_mbps,
        if nic.full_duplex { "full" } else { "half" }
    );
    println!(
        "[SH]      registers: ctrl={:#010x} status={:#010x} rctl={:#010x} tctl={:#010x} rdlen={} tdlen={} rdh={} rdt={} tdh={} tdt={} eecd={:#x}",
        nic.read(CTRL),
        nic.read(STATUS),
        nic.read(RCTL),
        nic.read(TCTL),
        nic.read(RDLEN),
        nic.read(TDLEN),
        nic.read(RDH),
        nic.read(RDT),
        nic.read(TDH),
        nic.read(TDT),
        nic.read(EECD)
    );
    println!(
        "[SH]      traffic: tx={} ({} bytes, {} errors) rx={} ({} bytes) mesh-in={} probe-in={} foreign={} errors={}",
        nic.tx_frames,
        nic.tx_bytes,
        nic.tx_errors,
        nic.rx_frames,
        nic.rx_bytes,
        nic.rx_mesh,
        nic.rx_probe,
        nic.rx_foreign,
        nic.rx_errors
    );
    println!(
        "[SH]      refused: malformed={} fragmented={} not-ipv4={} not-udp={} bad-checksum={} (DMA frames={})",
        nic.rx_malformed,
        nic.rx_fragmented,
        nic.rx_not_ipv4,
        nic.rx_not_udp,
        nic.rx_bad_checksum,
        DMA_FRAMES.load(Ordering::Relaxed)
    );
    println!(
        "[SH]      arp: requests={} replies={} ignored={} (answering requests for {} is what makes this endpoint reachable)",
        nic.arp_requests,
        nic.arp_replies,
        nic.arp_ignored,
        eth::GUEST_IP[0]
    );
    println!(
        "[SH]      last-refused: {} frame(s), last {} bytes reason={} ethertype={:#06x} ip-proto={}",
        nic.last_refused.count,
        nic.last_refused.length,
        match nic.last_refused.reason {
            Some(reason) => reason.as_str(),
            None => "addressed-elsewhere",
        },
        nic.last_refused.ethertype,
        nic.last_refused.ip_protocol
    );
    println!(
        "[SH]      wire: {} -> {} port {:#06x}/{} , {}-byte datagrams, egress {} , interrupts masked (polling)",
        eth::GUEST_IP[0],
        eth::GATEWAY_IP[0],
        eth::MESH_PORT,
        eth::PROBE_PORT,
        eth::MAX_FRAME,
        if nic.wire_enabled { "on" } else { "off" }
    );
    // One machine-readable counter line, in the shape the PS/2 driver established, so the wire
    // tool can take a reading, inject, and take another without parsing prose.
    println!(
        "[NIC] counters: tx={} rx={} mesh={} probe={} foreign={} malformed={} fragmented={} not-ipv4={} not-udp={} bad-checksum={} arp-requests={} arp-replies={} arp-ignored={} rx-errors={} tx-errors={} dma-frames={}",
        nic.tx_frames,
        nic.rx_frames,
        nic.rx_mesh,
        nic.rx_probe,
        nic.rx_foreign,
        nic.rx_malformed,
        nic.rx_fragmented,
        nic.rx_not_ipv4,
        nic.rx_not_udp,
        nic.rx_bad_checksum,
        nic.arp_requests,
        nic.arp_replies,
        nic.arp_ignored,
        nic.rx_errors,
        nic.tx_errors,
        DMA_FRAMES.load(Ordering::Relaxed)
    );
}

/// Counters the heartbeat and the harness read: `(tx frames, rx frames, rx mesh, refused)`.
pub fn counters() -> (u64, u64, u64, u64) {
    let nic = unsafe { nic() };
    (
        nic.tx_frames,
        nic.rx_frames,
        nic.rx_mesh,
        nic.rx_malformed
            + nic.rx_fragmented
            + nic.rx_not_ipv4
            + nic.rx_not_udp
            + nic.rx_bad_checksum,
    )
}

// ------------------------------------------------------------------ self-test

pub struct NicReport {
    pub passed: u32,
    pub failed: u32,
    /// Adapter assertions left undone because the machine has no supported device. The framing
    /// checks are pure computation and always run, so a machine without a NIC still proves the
    /// byte layout; it just cannot say anything about a register.
    pub skipped: u32,
    pub failures: alloc::vec::Vec<&'static str>,
}

impl NicReport {
    fn new() -> Self {
        Self {
            passed: 0,
            failed: 0,
            skipped: 0,
            failures: alloc::vec::Vec::new(),
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

    /// Counts an assertion as deliberately not run.
    fn skip(&mut self, count: u32) {
        self.skipped += count;
    }
}

/// How many register assertions the adapter performs. Kept next to the code that makes them so
/// a machine without an adapter reports the same number as "skipped".
const ADAPTER_ASSERTIONS: u32 = 21;

/// Reads the configuration back *out of the device*, so the assertions are about what the
/// hardware accepted rather than about what the driver intended to write.
///
/// The framing layer is half of this driver's correctness and needs no hardware, so its report is
/// merged in here: `eth::self_test` always runs, the register checks run only when a device
/// answered.
pub fn self_test() -> NicReport {
    let mut report = NicReport::new();
    let eth_report = eth::self_test();

    let nic = unsafe { nic() };
    if !nic.present {
        report.passed += eth_report.passed;
        report.failed += eth_report.failed;
        for failure in eth_report.failures.iter() {
            report.failures.push(*failure);
        }
        report.skip(ADAPTER_ASSERTIONS);
        return report;
    }

    let command = pci::config_read_u32(nic.bus, nic.slot, nic.function, 0x04);
    report.check(command & (1 << 1) != 0, "memory space decoding is off");
    report.check(command & (1 << 2) != 0, "bus mastering is off: the device cannot fetch descriptors");
    report.check(nic.bar != 0 && nic.bar % 4 == 0, "BAR0 is not a usable register window");
    report.check(nic.bar_size >= REQUIRED_WINDOW, "BAR0 is smaller than the register window");
    report.check(nic.read(CTRL) & CTRL_RST == 0, "the device did not come out of reset");
    report.check(
        nic.mac != [0; 6] && nic.mac != [0xFF; 6],
        "the MAC address was not loaded from the EEPROM",
    );
    report.check(nic.read(RAH0) & RAH_AV != 0, "the receive address register is not valid");
    report.check(
        nic.read(RAH0) as u16 == u16::from_le_bytes([nic.mac[4], nic.mac[5]]),
        "the programmed MAC does not read back",
    );
    report.check(nic.read(TDLEN) == (TX_DESCRIPTORS * DESCRIPTOR_BYTES) as u32, "TDLEN is wrong");
    report.check(nic.read(RDLEN) == (RX_DESCRIPTORS * DESCRIPTOR_BYTES) as u32, "RDLEN is wrong");
    report.check(nic.read(TCTL) & 0x2 != 0, "the transmit path is not enabled");
    report.check(nic.read(RCTL) & 0x2 != 0, "the receive path is not enabled");
    report.check(nic.read(IMS) == 0, "an interrupt source is still unmasked");
    report.check(nic.signature == NIC_SIGNATURE, "the driver state is not in `.data` (unsigned)");
    report.check(
        (nic.tx_ring.descriptors.as_ptr() as u64) % 128 == 0
            && (nic.rx_ring.descriptors.as_ptr() as u64) % 128 == 0,
        "a descriptor ring is not 128-byte aligned",
    );
    report.check(
        (nic.read(TDBAH) as u64) << 32 | (nic.read(TDBAL) as u64 & !0xF)
            == nic.tx_ring.descriptors.as_ptr() as u64,
        "the device did not keep the transmit ring base it was given",
    );
    report.check(
        (nic.read(RDBAH) as u64) << 32 | (nic.read(RDBAL) as u64 & !0xF)
            == nic.rx_ring.descriptors.as_ptr() as u64,
        "the device did not keep the receive ring base it was given",
    );
    report.check(
        core::mem::size_of::<TxDescriptor>() == DESCRIPTOR_BYTES
            && core::mem::size_of::<RxDescriptor>() == DESCRIPTOR_BYTES,
        "a descriptor is not 16 bytes on the wire",
    );
    report.check(
        nic.tx_buffers.iter().all(|frame| frame % 4096 == 0 && *frame != 0)
            && nic.rx_buffers.iter().all(|frame| frame % 4096 == 0 && *frame != 0),
        "a packet buffer is not page aligned",
    );
    report.check(
        nic.rx_ring.descriptors.iter().all(|descriptor| descriptor.address != 0),
        "a receive descriptor has no buffer",
    );
    report.check(
        nic.mac != [0; 6] && eth::GUEST_IP != [0; 4],
        "the endpoint this driver answers for has no address",
    );

    report.passed += eth_report.passed;
    report.failed += eth_report.failed;
    for failure in eth_report.failures.iter() {
        report.failures.push(*failure);
    }
    report
}
