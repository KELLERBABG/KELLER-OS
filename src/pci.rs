//! Minimal PCI configuration-space access.
//!
//! The kernel boots through PVH (`-kernel`), so no firmware has walked the PCI bus: BARs are
//! unassigned and device memory decoding is off until we turn it on. This module is what
//! makes the graphics adapter usable (GUI_SPECIFICATION.md §3.3 asks for the VGA BAR) and it
//! is the groundwork the Ring-3 NIC driver will need for its packet rings.
//!
//! Only configuration space is touched here; drivers own their own MMIO.

use crate::port::{inl, outl};
use alloc::vec::Vec;

/// PCI configuration address/data port pair (mechanism #1).
pub const CONFIG_ADDRESS: u16 = 0x0CF8;
pub const CONFIG_DATA: u16 = 0x0CFC;

/// Base of the legacy VGA LFB aperture; used when a BAR arrives unassigned.
pub const LEGACY_VGA_BASE: u64 = 0xE000_0000;
/// Second candidate aperture (Bochs uses this one for `VBE_DISPI_LFB_PHYSICAL_ADDRESS`).
pub const BOCHS_VGA_BASE: u64 = 0xFD00_0000;
/// Size reserved for a graphics aperture when we assign one ourselves (16 MiB).
pub const VGA_APERTURE_SIZE: u64 = 16 * 1024 * 1024;

/// VGA-compatible display controller: class 0x03, subclass 0x00.
pub const CLASS_DISPLAY: u8 = 0x03;
pub const SUBCLASS_VGA: u8 = 0x00;

/// Configuration space register offsets.
const VENDOR_ID: u8 = 0x00;
const COMMAND: u8 = 0x04;
const STATUS: u8 = 0x06;
const REVISION: u8 = 0x08;
const HEADER_TYPE: u8 = 0x0E;
const BAR0: u8 = 0x10;
/// First entry of the capability list, when the status register says there is one.
const CAPABILITY_LIST: u8 = 0x34;

/// Status register bit 4: the device has a capability list. Without this bit the pointer at
/// 0x34 is not a pointer and must not be followed.
const STATUS_CAPABILITY_LIST: u16 = 1 << 4;

/// Command register: memory space decode.
const COMMAND_MEMORY_SPACE: u32 = 1 << 1;
/// Command register: I/O space decode.
const COMMAND_IO_SPACE: u32 = 1 << 0;

/// One enumerated function. `bars` keeps the raw values (bit 0 tells I/O from memory).
#[derive(Clone, Copy)]
pub struct PciDevice {
    pub bus: u8,
    pub slot: u8,
    pub function: u8,
    pub vendor: u16,
    pub device: u16,
    pub class: u8,
    pub subclass: u8,
    /// Programming interface (configuration space byte 0x09). This is what separates an AHCI
    /// controller from a SATA controller in legacy or RAID mode, and it is read rather than
    /// guessed from a vendor id.
    pub interface: u8,
    pub header_type: u8,
    pub bars: [u32; 6],
}

impl PciDevice {
    pub fn id(&self) -> u32 {
        ((self.vendor as u32) << 16) | self.device as u32
    }

    /// Address `bus:slot.function`.
    pub fn address(&self) -> u32 {
        ((self.bus as u32) << 16) | ((self.slot as u32) << 11) | ((self.function as u32) << 8)
    }

    pub fn is_vga(&self) -> bool {
        self.class == CLASS_DISPLAY && self.subclass == SUBCLASS_VGA
    }

    /// True when the BAR describes memory (bit 0 clear) and has been assigned.
    pub fn bar_is_memory(&self, index: usize) -> bool {
        self.bars[index] & 1 == 0
    }

    /// Memory BAR base with the low flag bits removed, or `None` when unassigned.
    pub fn bar_address(&self, index: usize) -> Option<u64> {
        if !self.bar_is_memory(index) {
            return None;
        }
        let base = (self.bars[index] & !0xF) as u64;
        if base == 0 {
            None
        } else {
            Some(base)
        }
    }

    /// Raw class code as `class << 8 | subclass`.
    pub fn class_code(&self) -> u16 {
        ((self.class as u16) << 8) | self.subclass as u16
    }

    pub fn describe(&self) {
        crate::println!(
            "[PCI] {:02x}:{:02x}.{} id={:04x}:{:04x} class={:02x}{:02x} if={:02x} bar0={:#010x}",
            self.bus,
            self.slot,
            self.function,
            self.vendor,
            self.device,
            self.class,
            self.subclass,
            self.interface,
            self.bars[0]
        );
    }
}

/// Reads a 32-bit configuration register (mechanism #1: enable bit + bus/slot/func/offset).
pub fn config_read_u32(bus: u8, slot: u8, function: u8, offset: u8) -> u32 {
    unsafe {
        let address = 0x8000_0000u32
            | ((bus as u32) << 16)
            | (((slot as u32) & 0x1F) << 11)
            | (((function as u32) & 0x07) << 8)
            | ((offset as u32) & 0xFC);
        outl(CONFIG_ADDRESS, address);
        inl(CONFIG_DATA)
    }
}

/// Writes a 32-bit configuration register.
pub fn config_write_u32(bus: u8, slot: u8, function: u8, offset: u8, value: u32) {
    unsafe {
        let address = 0x8000_0000u32
            | ((bus as u32) << 16)
            | (((slot as u32) & 0x1F) << 11)
            | (((function as u32) & 0x07) << 8)
            | ((offset as u32) & 0xFC);
        outl(CONFIG_ADDRESS, address);
        outl(CONFIG_DATA, value);
    }
}

pub fn config_read_u16(bus: u8, slot: u8, function: u8, offset: u8) -> u16 {
    let word = config_read_u32(bus, slot, function, offset & !3);
    ((word >> ((offset & 2) * 8)) & 0xFFFF) as u16
}

fn read_device(bus: u8, slot: u8, function: u8) -> Option<PciDevice> {
    let identification = config_read_u32(bus, slot, function, VENDOR_ID);
    let vendor = (identification & 0xFFFF) as u16;
    if vendor == 0xFFFF {
        return None;
    }
    let class_word = config_read_u32(bus, slot, function, REVISION);
    let mut bars = [0u32; 6];
    for (index, bar) in bars.iter_mut().enumerate() {
        *bar = config_read_u32(bus, slot, function, BAR0 + (index as u8) * 4);
    }
    Some(PciDevice {
        bus,
        slot,
        function,
        vendor,
        device: (identification >> 16) as u16,
        class: (class_word >> 24) as u8,
        subclass: (class_word >> 16) as u8,
        interface: (class_word >> 8) as u8,
        header_type: (config_read_u32(bus, slot, function, HEADER_TYPE) & 0xFF) as u8,
        bars,
    })
}

/// Enumerates bus 0 (where every QEMU/Bochs device lives). Multi-function slots are walked
/// in full; single-function slots stop after function 0.
pub fn enumerate() -> Vec<PciDevice> {
    let mut devices = Vec::new();
    for slot in 0..32u8 {
        let header = config_read_u32(0, slot, 0, HEADER_TYPE);
        if (header & 0xFFFF) == 0xFFFF {
            continue;
        }
        let functions = if header & 0x80 != 0 { 8 } else { 1 };
        for function in 0..functions {
            if let Some(device) = read_device(0, slot, function) {
                devices.push(device);
            }
        }
    }
    devices
}

/// Prints every enumerated function (boot-time inventory).
pub fn describe() {
    let devices = enumerate();
    crate::println!("[OK] PCI BUS 0: {} function(s) enumerated", devices.len());
    for device in devices.iter() {
        device.describe();
    }
}

/// Finds the display controller, if one is present.
pub fn find_vga() -> Option<PciDevice> {
    enumerate().into_iter().find(|device| device.is_vga())
}

/// Turns on memory-space decoding and, when asked, bus-master capability for a device.
pub fn enable(device: &PciDevice, bus_master: bool) {
    let mut command = config_read_u32(device.bus, device.slot, device.function, COMMAND)
        | COMMAND_MEMORY_SPACE
        | COMMAND_IO_SPACE;
    if bus_master {
        command |= 1 << 2;
    }
    config_write_u32(device.bus, device.slot, device.function, COMMAND, command);
}

/// Size of a memory BAR, measured the way the PCI spec prescribes: write all ones, read the
/// mask back, restore the original value.
pub fn bar_size(device: &PciDevice, index: usize) -> u64 {
    if !device.bar_is_memory(index) {
        return 0;
    }
    let offset = BAR0 + (index as u8) * 4;
    let saved = config_read_u32(device.bus, device.slot, device.function, offset);
    config_write_u32(device.bus, device.slot, device.function, offset, 0xFFFF_FFFF);
    let mask = config_read_u32(device.bus, device.slot, device.function, offset);
    config_write_u32(device.bus, device.slot, device.function, offset, saved);
    // The mask's low four bits are the type flags, not part of the size. Clear them, invert
    // the *32-bit* mask (a 64-bit inversion would smear the upper half) and add one.
    let aligned = mask & !0xF;
    ((!aligned) as u64).wrapping_add(1)
}

/// Assigns a base address to a memory BAR (used when no firmware did it for us) and returns
/// the address the device now decodes.
pub fn assign_bar(device: &PciDevice, index: usize, base: u64) -> u64 {
    let offset = BAR0 + (index as u8) * 4;
    config_write_u32(
        device.bus,
        device.slot,
        device.function,
        offset,
        (base & !0xF) as u32,
    );
    let assigned = (config_read_u32(device.bus, device.slot, device.function, offset) & !0xF) as u64;
    enable(device, false);
    assigned
}

/// Ensures BAR0 of `device` is a usable memory base, assigning the legacy VGA aperture when
/// the loader left it blank. Returns `(base, size)`.
pub fn ensure_memory_bar(device: &PciDevice, index: usize, preferred: u64) -> Option<(u64, u64)> {
    let size = bar_size(device, index);
    if size == 0 {
        return None;
    }
    if let Some(base) = device.bar_address(index) {
        enable(device, false);
        return Some((base, size));
    }
    let base = assign_bar(device, index, preferred);
    if base == 0 {
        return None;
    }
    Some((base, size))
}

/// Looks a device up by its `vendor:device` pair on bus 0.
pub fn find_by_id(vendor: u16, device: u16) -> Option<PciDevice> {
    enumerate()
        .into_iter()
        .find(|candidate| candidate.vendor == vendor && candidate.device == device)
}

// ---------------------------------------------------------------- capabilities

/// The device's status register. It is the *upper* half of the dword at 0x04 - configuration
/// space is only addressable in dwords, and reading the low half is how a driver ends up
/// testing a command-register bit while believing it is testing a status one (which is exactly
/// how the first version of this walk concluded that the adapter had no capability list).
pub fn status(device: &PciDevice) -> u16 {
    (config_read_u32(device.bus, device.slot, device.function, COMMAND) >> 16) as u16
}

/// MSI capability id (PCI 3.0 §6.8.1) and MSI-X (§6.8.2).
pub const CAP_ID_MSI: u8 = 0x05;
pub const CAP_ID_MSIX: u8 = 0x11;

/// One entry of the capability list.
#[derive(Clone, Copy)]
pub struct Capability {
    pub id: u8,
    /// Configuration space offset of the capability's own header.
    pub offset: u8,
}

/// Walks the device's capability list. Returns an empty list when the status register says the
/// device has no list, and stops on a cycle (a malformed list is a device bug, not a reason to
/// spin forever in configuration space).
pub fn capabilities(device: &PciDevice) -> Vec<Capability> {
    let mut found = Vec::new();
    if status(device) & STATUS_CAPABILITY_LIST == 0 {
        return found;
    }
    let mut pointer =
        config_read_u8(device.bus, device.slot, device.function, CAPABILITY_LIST) & 0xFC;
    let mut guard = 0;
    while pointer >= 0x40 && pointer < 0xFF && guard < 48 {
        guard += 1;
        let header = config_read_u32(device.bus, device.slot, device.function, pointer);
        found.push(Capability {
            id: (header & 0xFF) as u8,
            offset: pointer,
        });
        let next = ((header >> 8) & 0xFF) as u8 & 0xFC;
        if next == 0 || next == pointer {
            break;
        }
        pointer = next;
    }
    found
}

/// The MSI capability, parsed from configuration space.
#[derive(Clone, Copy)]
pub struct MsiCapability {
    pub offset: u8,
    /// Message control word as it currently reads.
    pub control: u16,
    /// Message address as it currently reads (the upper half is zero on a 32-bit capability).
    pub address: u64,
    /// Message data as it currently reads.
    pub data: u16,
    /// Vectors the device is *capable* of, from the multiple-message-capable field (1-32).
    pub capable_vectors: u8,
    /// Vectors currently enabled, from the multiple-message-enable field.
    pub enabled_vectors: u8,
    pub is_64bit: bool,
    pub per_vector_mask: bool,
}

impl MsiCapability {
    pub fn enabled(&self) -> bool {
        self.control & 1 != 0
    }

    /// Where the message data lives: its offset moves by four when the capability carries a
    /// 64-bit address, which is exactly the kind of thing a hardcoded offset gets wrong.
    fn data_offset(&self) -> u8 {
        if self.is_64bit {
            self.offset + 12
        } else {
            self.offset + 8
        }
    }

    fn mask_offset(&self) -> u8 {
        if self.is_64bit {
            self.offset + 16
        } else {
            self.offset + 12
        }
    }
}

/// The capability's message control field is the *upper* half of the dword at the capability's
/// own offset, and configuration space is only addressable in dwords - which is why it is read
/// as a shifted dword rather than through a 16-bit access that the hardware would align down.
fn read_msi_control(bus: u8, slot: u8, function: u8, offset: u8) -> u16 {
    (config_read_u32(bus, slot, function, offset) >> 16) as u16
}

fn write_msi_control(bus: u8, slot: u8, function: u8, offset: u8, control: u16) {
    let header = config_read_u32(bus, slot, function, offset);
    config_write_u32(
        bus,
        slot,
        function,
        offset,
        (header & 0xFFFF) | ((control as u32) << 16),
    );
}

fn read_msi(bus: u8, slot: u8, function: u8, offset: u8) -> MsiCapability {
    let control = read_msi_control(bus, slot, function, offset);
    let is_64bit = control & (1 << 7) != 0;
    let per_vector_mask = control & (1 << 8) != 0;
    let capable_vectors = 1u8 << ((control >> 1) & 7) as u32;
    let enabled_vectors = 1u8 << ((control >> 4) & 7) as u32;
    let address_low = config_read_u32(bus, slot, function, offset + 4);
    let (address, data) = if is_64bit {
        let high = config_read_u32(bus, slot, function, offset + 8);
        (
            ((high as u64) << 32) | address_low as u64,
            (config_read_u32(bus, slot, function, offset + 12) & 0xFFFF) as u16,
        )
    } else {
        (
            address_low as u64,
            (config_read_u32(bus, slot, function, offset + 8) & 0xFFFF) as u16,
        )
    };
    MsiCapability {
        offset,
        control,
        address,
        data,
        capable_vectors,
        enabled_vectors,
        is_64bit,
        per_vector_mask,
    }
}

/// The device's MSI capability, or `None` when it has none.
pub fn msi_capability(device: &PciDevice) -> Option<MsiCapability> {
    capabilities(device)
        .into_iter()
        .find(|capability| capability.id == CAP_ID_MSI)
        .map(|capability| read_msi(device.bus, device.slot, device.function, capability.offset))
}

/// The MSI-X capability: a table in a BAR rather than registers in configuration space.
#[derive(Clone, Copy)]
pub struct MsixCapability {
    pub offset: u8,
    pub control: u16,
    /// BAR the MSI-X table lives in, and its offset inside that BAR.
    pub table_bar: u8,
    pub table_offset: u32,
    /// Number of table entries (one per vector).
    pub table_size: u16,
    pub pba_bar: u8,
    pub pba_offset: u32,
}

impl MsixCapability {
    pub fn enabled(&self) -> bool {
        self.control & (1 << 15) != 0
    }

    pub fn masked(&self) -> bool {
        self.control & (1 << 14) != 0
    }

    /// Physical address of table entry `index`, from the BAR the capability names.
    pub fn entry_address(&self, device: &PciDevice, index: usize) -> Option<u64> {
        let base = device.bar_address(self.table_bar as usize)?;
        Some(base + self.table_offset as u64 + index as u64 * 16)
    }
}

pub fn msix_capability(device: &PciDevice) -> Option<MsixCapability> {
    let capability = capabilities(device)
        .into_iter()
        .find(|capability| capability.id == CAP_ID_MSIX)?;
    let offset = capability.offset;
    let control = read_msi_control(device.bus, device.slot, device.function, offset);
    let table = config_read_u32(device.bus, device.slot, device.function, offset + 4);
    let pba = config_read_u32(device.bus, device.slot, device.function, offset + 8);
    Some(MsixCapability {
        offset,
        control,
        table_bar: (table & 7) as u8,
        table_offset: table & !7,
        table_size: (control & 0x7FF) + 1,
        pba_bar: (pba & 7) as u8,
        pba_offset: pba & !7,
    })
}

/// Programs the device's MSI capability to send `vector` to `dest` and enables it.
///
/// The message address is the x86 MSI format: 0xFEE00000 with the destination APIC id in bits
/// 19-12, physical destination mode, no redirection hint. One vector is enabled even when the
/// device can send more, because a multi-vector device that has only been told the first
/// address would deliver every one of them to it.
///
/// Returns the `(address, data)` pair actually written, read back from the device, or `None`
/// when the device has no MSI capability.
pub fn program_msi(device: &PciDevice, vector: u8, dest_apic_id: u8) -> Option<(u64, u16)> {
    let capability = msi_capability(device)?;
    let address = MSI_ADDRESS_BASE | ((dest_apic_id as u64) << 12);
    let data = vector as u16;

    // Per-vector masks first, and only when the capability has them: a masked vector would
    // swallow the interrupt being programmed for.
    if capability.per_vector_mask {
        config_write_u32(
            device.bus,
            device.slot,
            device.function,
            capability.mask_offset(),
            0,
        );
    }
    config_write_u32(
        device.bus,
        device.slot,
        device.function,
        capability.offset + 4,
        (address & 0xFFFF_FFFF) as u32,
    );
    if capability.is_64bit {
        config_write_u32(
            device.bus,
            device.slot,
            device.function,
            capability.offset + 8,
            (address >> 32) as u32,
        );
    }
    config_write_u32(
        device.bus,
        device.slot,
        device.function,
        capability.data_offset(),
        data as u32,
    );
    // One message, then the enable bit. The multiple-message-enable field is set to zero
    // rather than preserved: a device left able to send four messages would send three of them
    // to a vector this kernel did not program.
    let enabled = (capability.control & !(0b111 << 4)) | 1;
    write_msi_control(
        device.bus,
        device.slot,
        device.function,
        capability.offset,
        enabled,
    );

    let after = read_msi(device.bus, device.slot, device.function, capability.offset);
    let read_back = (after.address, after.data);
    if read_back != (address, data) || !after.enabled() {
        // A device that does not hold what it was given is reported as such rather than
        // being assumed to work; the caller decides whether that is fatal.
        return Some(read_back);
    }
    Some(read_back)
}

/// Clears the MSI enable bit, which puts the device's interrupt back on its legacy line.
pub fn disable_msi(device: &PciDevice) -> bool {
    match msi_capability(device) {
        Some(capability) => {
            let control = capability.control & !1;
            write_msi_control(
                device.bus,
                device.slot,
                device.function,
                capability.offset,
                control,
            );
            !read_msi(device.bus, device.slot, device.function, capability.offset).enabled()
        }
        None => false,
    }
}

/// Base address of an x86 MSI message: the local APIC's page.
pub const MSI_ADDRESS_BASE: u64 = 0xFEE0_0000;

/// Writes the MSI-X capability's message control word (function mask and enable live in its top
/// two bits). The capability's own dword carries the capability id and next pointer in its low
/// half, so the write is a read-modify-write like the MSI one.
pub fn write_msix_control(device: &PciDevice, offset: u8, control: u16) {
    write_msi_control(device.bus, device.slot, device.function, offset, control);
}

/// Clears the MSI-X enable bit, which returns the device to its legacy interrupt line.
pub fn disable_msix(device: &PciDevice) -> bool {
    match msix_capability(device) {
        Some(capability) => {
            write_msix_control(device, capability.offset, capability.control & !(1 << 15));
            !msix_capability(device)
                .map(|after| after.enabled())
                .unwrap_or(false)
        }
        None => false,
    }
}

/// Reads the MSI capability back out of the device: `(message control, address, data)`. This is
/// the device answering, so it is what a verification step compares against what was written.
pub fn msi_state(device: &PciDevice) -> Option<(u16, u64, u16)> {
    let capability = msi_capability(device)?;
    let after = read_msi(device.bus, device.slot, device.function, capability.offset);
    Some((after.control, after.address, after.data))
}

/// Reads a byte from configuration space (used by the descriptor walkers later on).
pub fn config_read_u8(bus: u8, slot: u8, function: u8, offset: u8) -> u8 {
    let word = config_read_u32(bus, slot, function, offset & !3);
    ((word >> ((offset & 3) * 8)) & 0xFF) as u8
}

/// Self-test: configuration space must round-trip at least the vendor id of any device we
/// can see, and a write/read of the command register must be stable.
pub fn self_test() -> bool {
    let devices = enumerate();
    if devices.is_empty() {
        return false;
    }
    let device = devices[0];
    let vendor = config_read_u16(device.bus, device.slot, device.function, VENDOR_ID);
    if vendor == 0xFFFF || vendor != device.vendor {
        return false;
    }
    let command = config_read_u32(device.bus, device.slot, device.function, COMMAND);
    let masked = command & !COMMAND_MEMORY_SPACE;
    config_write_u32(device.bus, device.slot, device.function, COMMAND, masked);
    let read_back = config_read_u32(device.bus, device.slot, device.function, COMMAND);
    config_write_u32(device.bus, device.slot, device.function, COMMAND, command);
    (read_back & COMMAND_MEMORY_SPACE) == (masked & COMMAND_MEMORY_SPACE)
}
