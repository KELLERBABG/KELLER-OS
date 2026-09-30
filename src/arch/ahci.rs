//! AHCI (Serial ATA) host controller: real sectors on a real disk.
//!
//! The vault's design has always been that plaintext never reaches the medium — sectors are
//! AEAD-sealed before they are stored. Until there was a disk, "stored" meant a `Vec` in the
//! kernel heap, which is a fine place to *prove* a format and a useless place to keep data. This
//! is the part that makes it survive a power cycle.
//!
//! **What is implemented.** The HBA is brought out of reset with AHCI enabled, every implemented
//! port is inspected, and the ports with a device on them are brought up with a command list and a
//! FIS receive area. The command that has to work is `IDENTIFY DEVICE`, because that is where the
//! sector count, the model and the logical sector size come from: a device whose logical sector
//! size is not 512 bytes is reported and *not* driven, because every address this layer computes
//! assumes 512. Data transfer is `READ DMA EXT` / `WRITE DMA EXT` (LBA48): one command-table entry
//! plus PRDT entries, and the device reads or writes physical memory directly — so the buffers are
//! identity-mapped frames, exactly as the network driver's are.
//!
//! **What is deliberately not implemented.** No interrupts (every command is polled to completion
//! with a bounded budget), no NCQ (one command in flight), no port multipliers, no ATAPI, no
//! hot-plug, no FIS-based switching, no LBA28 command form (a disk that only speaks 28-bit
//! addressing is reported and refused rather than addressed wrongly). Completion is `PxCI`
//! clearing plus a check of `PxTFD` for an error bit, and a timeout is returned as an error: a
//! disk that has stopped answering must not become a kernel that has stopped booting.
//!
//! **Where the state lives.** The command lists, the received-FIS areas, the command tables, the
//! PRDTs and the transfer frames are this module's own state, in a `repr(align(1024))` structure
//! (the specification requires the command list to be 1 KiB aligned and the FIS area 256-byte
//! aligned) carrying a non-zero signature so the loader places it in `.data` — the boot handoff
//! does not zero `.bss`, so a structure that lived there would start with someone else's bytes in
//! its port pointers. Both facts, and the addresses the device kept, are asserted by the
//! self-test.

use crate::block::{BlockDevice, BlockError, BlockReport, SECTOR_SIZE};
use crate::pci;
use crate::println;
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};

// ------------------------------------------------------------------ PCI identity

const VENDOR_INTEL: u16 = 0x8086;
/// AHCI controllers this driver is willing to drive: 82801IR/IO (ich9), ICH10, and QEMU's
/// `ich9-ahci`, which reports itself as the first of them.
const SUPPORTED_IDS: [u16; 6] = [0x2922, 0x2923, 0x2929, 0x3A22, 0x3A25, 0x2829];
/// Mass storage, subclass SATA.
const CLASS_STORAGE: u8 = 0x01;
const SUBCLASS_SATA: u8 = 0x06;
/// Programming interface: AHCI 1.0. This is what distinguishes an AHCI controller from a SATA
/// controller in legacy or RAID mode, and it is read from configuration space, not guessed.
const INTERFACE_AHCI: u8 = 0x01;
/// Preferred ABAR base when no loader assigned one.
const PREFERRED_BAR: u64 = 0xFEB8_0000;
/// The window this driver actually touches: the generic registers plus one port register block
/// for every implemented port. The specification fixes ABAR at a nominal 8 KiB, but a controller
/// that advertises less is not lying about what it has - QEMU's reports 4 KiB and its port
/// registers fit inside it - so the requirement is what the code reads, not the nominal size.
const fn required_window(implemented_ports: u32) -> u64 {
    (PORT_BASE as u64 + PORT_STRIDE as u64 * implemented_ports.count_ones() as u64).next_multiple_of(1024)
}

// ------------------------------------------------------------------ HBA registers

const CAP: u32 = 0x00;
const GHC: u32 = 0x04;
const IS: u32 = 0x08;
const PI: u32 = 0x0C;
const VS: u32 = 0x10;
const PORT_BASE: u32 = 0x100;
const PORT_STRIDE: u32 = 0x80;

const PX_CLB: u32 = 0x00;
const PX_CLBU: u32 = 0x04;
const PX_FB: u32 = 0x08;
const PX_FBU: u32 = 0x0C;
const PX_IS: u32 = 0x10;
const PX_IE: u32 = 0x14;
const PX_CMD: u32 = 0x18;
const PX_TFD: u32 = 0x20;
const PX_SIG: u32 = 0x24;
const PX_SSTS: u32 = 0x28;
const PX_SCTL: u32 = 0x2C;
const PX_SERR: u32 = 0x30;
const PX_CI: u32 = 0x38;

const GHC_AE: u32 = 1 << 31;
const GHC_HR: u32 = 1 << 0;
const PXCMD_ST: u32 = 1 << 0;
const PXCMD_FRE: u32 = 1 << 4;
const PXCMD_FR: u32 = 1 << 14;
const PXCMD_CR: u32 = 1 << 15;
const TFD_ERR: u32 = 1 << 0;
const TFD_DRQ: u32 = 1 << 3;
const TFD_DF: u32 = 1 << 5;
const TFD_BSY: u32 = 1 << 7;
const SSTS_DET_MASK: u32 = 0x0F;
const SSTS_DET_PRESENT: u32 = 0x03;
const SSTS_IPM_MASK: u32 = 0xF00;
/// ATAPI signature: packet devices are not addressed by this driver.
const SIG_ATAPI: u32 = 0xEB14_0000;
const SIG_ATAPI_MASK: u32 = 0xFFFF_0000;

const MAX_PORTS: usize = 32;
const SLOTS: usize = 32;
const PRDT_ENTRIES: usize = 16;
/// Largest transfer one command issues: one 4 KiB frame, eight 512-byte sectors.
const MAX_SECTORS_PER_COMMAND: u64 = 8;
const DMA_BYTES: usize = SECTOR_SIZE * MAX_SECTORS_PER_COMMAND as usize;

const PORT_SPIN_LIMIT: u32 = 500_000;
const HBA_SPIN_LIMIT: u32 = 1_000_000;

/// ATA commands this driver issues.
const ATA_IDENTIFY: u8 = 0xEC;
const ATA_READ_DMA_EXT: u8 = 0x25;
const ATA_WRITE_DMA_EXT: u8 = 0x35;

/// Signature that keeps this module's state in `.data` (see the module comment).
const AHCI_SIGNATURE: u64 = 0x4B45_4C4C_4148_4301; // "KELLAHCI\x01"

// ------------------------------------------------------------------ structures

#[repr(C)]
#[derive(Clone, Copy)]
struct CommandHeader {
    /// Command FIS length in dwords (bits 0..4), the ATAPI bit (5), the write direction (6) and
    /// the prefetch bit (7).
    flags: u16,
    /// PRDT length in entries.
    prdt_length: u16,
    /// Bytes transferred so far, written back by the device.
    transferred: u32,
    /// Physical address of this slot's command table: CTBA in the low half, CTBAU in the high
    /// half, which is the 64-bit form the device reads from one aligned field.
    table_base: u64,
    _reserved: [u32; 4],
}

/// One PRDT entry. The layout is fixed by the specification and is **16** bytes:
/// address, address-high, then the byte count minus one. Getting this wrong is not a little
/// wrong: the device reads the size field from wherever this structure says it is, so a padded
/// entry makes every transfer one byte long.
#[repr(C)]
#[derive(Clone, Copy)]
struct PrdtEntry {
    data_base: u64,
    data_base_upper: u32,
    /// Byte count minus one; the device sets bit 31 when the entry is done.
    byte_count: u32,
}

#[repr(C, align(128))]
struct CommandTable {
    fis: [u8; 64],
    acmd: [u8; 16],
    _reserved: [u8; 48],
    prdt: [PrdtEntry; PRDT_ENTRIES],
}

#[repr(C, align(1024))]
struct PortBuffers {
    command_list: [CommandHeader; SLOTS],
    tables: [CommandTable; SLOTS],
    fis: [u8; 256],
    data: [u8; DMA_BYTES],
}

#[derive(Clone, Copy)]
struct Port {
    index: u8,
    present: bool,
    signature: u32,
    /// PxTFD as the port read before the driver issued anything: a reset status of `0x130`
    /// (DSC|DF with ABRT in the error register) is what a 512-byte ATA disk reports, and is not
    /// this driver's failure.
    at_attach: u32,
    sectors: u64,
    model: [u8; 40],
    firmware: [u8; 8],
    serial: [u8; 20],
    sector_size_ok: bool,
    support_48bit: bool,
}

impl Port {
    const fn empty() -> Self {
        Self {
            index: 0,
            present: false,
            signature: 0,
            at_attach: 0,
            sectors: 0,
            model: [0; 40],
            firmware: [0; 8],
            serial: [0; 20],
            sector_size_ok: false,
            support_48bit: false,
        }
    }
}

pub struct Ahci {
    signature: u64,
    present: bool,
    bus: u8,
    slot: u8,
    function: u8,
    device: u16,
    bar: u64,
    bar_size: u64,
    mmio: *mut u32,
    version: u32,
    ports_implemented: u32,
    command_list_base: u64,
    fis_base: u64,
    ports: [Port; MAX_PORTS],
    selected: Option<u8>,
    /// Counters count *commands*, not sectors: one command covers up to eight sectors.
    reads: u64,
    writes: u64,
    errors: u64,
    timeouts: u64,
}

impl Ahci {
    const fn empty() -> Self {
        Self {
            signature: AHCI_SIGNATURE,
            present: false,
            bus: 0,
            slot: 0,
            function: 0,
            device: 0,
            bar: 0,
            bar_size: 0,
            mmio: ptr::null_mut(),
            version: 0,
            ports_implemented: 0,
            command_list_base: 0,
            fis_base: 0,
            ports: [Port::empty(); MAX_PORTS],
            selected: None,
            reads: 0,
            writes: 0,
            errors: 0,
            timeouts: 0,
        }
    }
}

/// Kept separate from [`Ahci`] so the 1 KiB alignment requirement lands on a plain structure
/// rather than being inherited by every field beside it.
#[repr(C, align(1024))]
struct Buffers {
    ports: [PortBuffers; MAX_PORTS],
}

static mut HBA: Ahci = Ahci::empty();
static mut BUFFERS: Buffers = Buffers {
    ports: [const {
        PortBuffers {
            command_list: [CommandHeader {
                flags: 0,
                prdt_length: 0,
                transferred: 0,
                table_base: 0,
                _reserved: [0; 4],
            }; SLOTS],
            tables: [const {
                CommandTable {
                    fis: [0; 64],
                    acmd: [0; 16],
                    _reserved: [0; 48],
                    prdt: [PrdtEntry {
                        data_base: 0,
                        data_base_upper: 0,
                        byte_count: 0,
                    }; PRDT_ENTRIES],
                }
            }; SLOTS],
            fis: [0; 256],
            data: [0; DMA_BYTES],
        }
    }; MAX_PORTS],
};

/// The DMA arena, counted apart from the paging frame counter for the same reason the network
/// driver's is: the ring-3 reports treat that counter as "user and page-table frames returned".
static DMA_FRAMES: AtomicU64 = AtomicU64::new(0);

unsafe fn hba() -> &'static mut Ahci {
    &mut *core::ptr::addr_of_mut!(HBA)
}

unsafe fn buffers() -> &'static mut Buffers {
    &mut *core::ptr::addr_of_mut!(BUFFERS)
}

// ------------------------------------------------------------------ register access

impl Ahci {
    fn read(&self, offset: u32) -> u32 {
        unsafe { ptr::read_volatile(self.mmio.add((offset / 4) as usize)) }
    }

    fn write(&self, offset: u32, value: u32) {
        unsafe { ptr::write_volatile(self.mmio.add((offset / 4) as usize), value) }
    }

    fn port_read(&self, port: u8, offset: u32) -> u32 {
        self.read(PORT_BASE + PORT_STRIDE * port as u32 + offset)
    }

    fn port_write(&self, port: u8, offset: u32, value: u32) {
        self.write(PORT_BASE + PORT_STRIDE * port as u32 + offset, value)
    }

    /// Polls a port register until `predicate` holds, the device reports a task-file error, or the
    /// budget runs out.
    fn port_poll(
        &self,
        port: u8,
        offset: u32,
        limit: u32,
        predicate: impl Fn(u32) -> bool,
    ) -> Result<u32, BlockError> {
        let mut spins = 0;
        loop {
            let value = self.port_read(port, offset);
            if predicate(value) {
                return Ok(value);
            }
            if self.port_read(port, PX_TFD) & (TFD_ERR | TFD_DF) != 0 {
                return Err(BlockError::DeviceError);
            }
            if spins >= limit {
                return Err(BlockError::Timeout);
            }
            spins += 1;
            core::hint::spin_loop();
        }
    }

    /// Stops the port's engines, as the specification requires before their addresses move.
    fn stop_port(&self, port: u8) -> Result<(), BlockError> {
        let mut command = self.port_read(port, PX_CMD);
        command &= !PXCMD_ST;
        command &= !PXCMD_FRE;
        self.port_write(port, PX_CMD, command);
        self.port_poll(port, PX_CMD, PORT_SPIN_LIMIT, |value| {
            value & (PXCMD_CR | PXCMD_FR) == 0
        })
        .map(|_| ())
    }

    fn start_port(&self, port: u8) {
        let command = self.port_read(port, PX_CMD);
        self.port_write(port, PX_CMD, command | PXCMD_FRE);
        self.port_write(port, PX_CMD, command | PXCMD_FRE | PXCMD_ST);
    }

    /// Points a port at its command list and FIS area, then starts it.
    fn init_port(&self, port: u8, index: usize) -> Result<(), BlockError> {
        let _ = self.stop_port(port);
        let state = unsafe { buffers() };
        let command_list = core::ptr::addr_of!(state.ports[index].command_list) as u64;
        let fis = core::ptr::addr_of!(state.ports[index].fis) as u64;
        let tables = core::ptr::addr_of!(state.ports[index].tables) as u64;

        self.port_write(port, PX_CLB, command_list as u32);
        self.port_write(port, PX_CLBU, (command_list >> 32) as u32);
        self.port_write(port, PX_FB, fis as u32);
        self.port_write(port, PX_FBU, (fis >> 32) as u32);
        self.port_write(port, PX_IS, 0xFFFF_FFFF);
        self.port_write(port, PX_SERR, 0xFFFF_FFFF);
        self.port_write(port, PX_IE, 0);
        self.port_write(port, PX_CI, 0);
        self.port_write(port, PX_SCTL, 0);

        // Every command header points at its own table. These addresses go to the device, so they
        // must be physical: the buffers are in `.data` inside the boot identity map, which is what
        // makes the pointer equal to the address.
        let table_stride = core::mem::size_of::<CommandTable>() as u64;
        for slot in 0..SLOTS {
            state.ports[index].command_list[slot].table_base = tables + slot as u64 * table_stride;
            state.ports[index].command_list[slot].prdt_length = 0;
            state.ports[index].command_list[slot].flags = 0;
            state.ports[index].command_list[slot].transferred = 0;
        }
        self.start_port(port);
        Ok(())
    }

    /// Issues one ATA command through slot 0.
    ///
    /// `sectors == 0` means a 512-byte transfer that is not addressed by LBA (IDENTIFY).
    fn issue(
        &self,
        port: u8,
        index: usize,
        command: u8,
        lba: u64,
        sectors: u16,
        buffer: &mut [u8],
        write: bool,
    ) -> Result<(), BlockError> {
        let state = unsafe { buffers() };
        let slot = 0usize;

        // Wait for the device to be ready to take a command, and for that check to look at busy
        // and data-request only. The error and fault bits are deliberately *not* a reason to
        // refuse here: a device that has just come out of reset reports them (a 512-byte ATA disk
        // comes up with status DSC|DF and the error register reading ABRT), and they are cleared
        // by the first successful command. Refusing on them before issuing anything would refuse
        // every port on every machine. What matters is checked after the command, below.
        self.port_poll(port, PX_TFD, PORT_SPIN_LIMIT, |value| {
            value & (TFD_BSY | TFD_DRQ) == 0
        })?;

        let data = core::ptr::addr_of!(state.ports[index].data) as u64;
        let table = &mut state.ports[index].tables[slot];
        let header = &mut state.ports[index].command_list[slot];

        for byte in table.fis.iter_mut() {
            *byte = 0;
        }
        table.fis[0] = 0x27; // register host-to-device FIS
        table.fis[1] = 0x80; // update the command register
        table.fis[2] = command;
        table.fis[4] = lba as u8;
        table.fis[5] = (lba >> 8) as u8;
        table.fis[6] = (lba >> 16) as u8;
        table.fis[7] = 0x40; // LBA mode
        table.fis[8] = (lba >> 24) as u8;
        table.fis[9] = (lba >> 32) as u8;
        table.fis[10] = (lba >> 40) as u8;
        table.fis[12] = sectors as u8;
        table.fis[13] = (sectors >> 8) as u8;

        // One PRDT entry per 4 KiB frame describes every transfer this driver issues.
        let bytes = if sectors == 0 {
            SECTOR_SIZE
        } else {
            sectors as usize * SECTOR_SIZE
        };
        let mut remaining = bytes;
        let mut entries = 0usize;
        let mut offset = 0usize;
        while remaining > 0 && entries < PRDT_ENTRIES {
            let chunk = core::cmp::min(remaining, 4096);
            table.prdt[entries] = PrdtEntry {
                data_base: data + offset as u64,
                data_base_upper: 0,
                byte_count: (chunk - 1) as u32,
            };
            offset += chunk;
            remaining -= chunk;
            entries += 1;
        }
        if remaining != 0 {
            // More than the table can describe: refused rather than truncated, because a truncated
            // DMA is data loss that looks like success.
            return Err(BlockError::Unsupported);
        }

        if write {
            if buffer.len() < bytes {
                return Err(BlockError::BadLength);
            }
            unsafe {
                ptr::copy_nonoverlapping(
                    buffer.as_ptr(),
                    state.ports[index].data.as_mut_ptr(),
                    bytes,
                );
            }
            core::sync::atomic::fence(Ordering::Release);
        }

        // PRDTL is the *number* of entries, not one less: the device walks that many 16-byte
        // entries at table offset 0x80. Encoding it as a count-minus-one makes every transfer
        // silently transfer nothing.
        header.prdt_length = entries as u16;
        header.flags = 5 | if write { 1 << 6 } else { 0 };
        header.transferred = 0;
        core::sync::atomic::fence(Ordering::Release);

        self.port_write(port, PX_IS, 0xFFFF_FFFF);
        self.port_write(port, PX_CI, 1 << slot);
        self.port_poll(port, PX_CI, PORT_SPIN_LIMIT, |value| value & (1 << slot) == 0)?;

        if self.port_read(port, PX_TFD) & (TFD_ERR | TFD_DF) != 0 {
            self.port_write(port, PX_SERR, 0xFFFF_FFFF);
            return Err(BlockError::DeviceError);
        }
        if header.transferred as usize != bytes {
            // The device's own byte count is the check that the whole transfer happened; a short
            // transfer is a failure, not a success with fewer bytes.
            return Err(BlockError::DeviceError);
        }

        if !write {
            core::sync::atomic::fence(Ordering::Acquire);
            unsafe {
                ptr::copy_nonoverlapping(
                    state.ports[index].data.as_ptr(),
                    buffer.as_mut_ptr(),
                    bytes,
                );
            }
        }
        Ok(())
    }

    /// Reads the device's identify data into the port's geometry.
    fn identify(&self, port: u8, index: usize) -> Result<(), BlockError> {
        if self.port_read(port, PX_SIG) & SIG_ATAPI_MASK == SIG_ATAPI {
            return Err(BlockError::Unsupported);
        }
        let mut buffer = [0u8; SECTOR_SIZE];
        self.issue(port, index, ATA_IDENTIFY, 0, 0, &mut buffer, false)?;
        let word =
            |index: usize| -> u16 { u16::from_le_bytes([buffer[index * 2], buffer[index * 2 + 1]]) };
        let string = |start: usize, length: usize| -> [u8; 40] {
            // ATA strings are byte-swapped words, space padded.
            let mut out = [b' '; 40];
            for byte in 0..length.min(40) {
                let value = word(start + byte / 2);
                out[byte] = if byte % 2 == 0 {
                    (value >> 8) as u8
                } else {
                    value as u8
                };
            }
            out
        };

        let supports_48 = word(83) & (1 << 10) != 0;
        let sectors_48 = u64::from(word(100))
            | u64::from(word(101)) << 16
            | u64::from(word(102)) << 32
            | u64::from(word(103)) << 48;
        let sectors_28 = u32::from(word(60)) | u32::from(word(61)) << 16;
        // Words 117..118 hold the logical sector size in 16-bit words, and are only valid when
        // word 106 says so. Anything unstated is 512 bytes, which is also what a device that does
        // not implement the field reports - and the check below refuses a device that disagrees,
        // rather than addressing 4 KiB sectors as if they were 512 bytes.
        let logical_bytes = if word(106) & (1 << 12) != 0 {
            let size_words = u32::from(word(117)) | u32::from(word(118)) << 16;
            let bytes = size_words.saturating_mul(2);
            if bytes == 0 {
                SECTOR_SIZE as u32
            } else {
                bytes
            }
        } else {
            SECTOR_SIZE as u32
        };

        let state = unsafe { hba() };
        state.ports[index].signature = self.port_read(port, PX_SIG);
        state.ports[index].model = string(27, 40);
        state.ports[index].firmware = {
            let full = string(23, 8);
            let mut out = [0u8; 8];
            out.copy_from_slice(&full[..8]);
            out
        };
        state.ports[index].serial = {
            let full = string(10, 20);
            let mut out = [0u8; 20];
            out.copy_from_slice(&full[..20]);
            out
        };
        state.ports[index].sector_size_ok = logical_bytes == SECTOR_SIZE as u32;
        state.ports[index].support_48bit = supports_48;
        state.ports[index].sectors = if supports_48 && sectors_48 != 0 {
            sectors_48
        } else {
            u64::from(sectors_28)
        };
        if state.ports[index].sectors == 0 {
            // A device that answers IDENTIFY with zero geometry is answering, so the numbers it
            // did report are the useful part of the failure.
            println!(
                "[AHCI] identify: model=\"{}\" sectors28={:#x} sectors48={:#x} 48bit={} words 60={:#06x} 61={:#06x} 83={:#06x} 100={:#06x} 10{:#x}={:#06x}",
                trim(&state.ports[index].model),
                sectors_28,
                sectors_48,
                supports_48,
                word(60),
                word(61),
                word(83),
                word(100),
                6u16,
                word(106)
            );
            return Err(BlockError::Unsupported);
        }
        Ok(())
    }
}

// ------------------------------------------------------------------ bring-up

/// Finds an AHCI controller, brings its ports up and identifies the device on each.
///
/// # Safety
/// Must run once, after the heap exists, with interrupts off or harmless: it spins on MMIO while
/// resetting the HBA and polling commands.
pub unsafe fn init() -> bool {
    if hba().present {
        return true;
    }
    if hba().signature != AHCI_SIGNATURE {
        println!(
            "[!!] AHCI: controller state is at {:#x} without its signature - the loader did not place it where the crate expects",
            core::ptr::addr_of!(HBA) as u64
        );
        return false;
    }
    if core::ptr::addr_of!(BUFFERS) as u64 % 1024 != 0 {
        println!("[!!] AHCI: the DMA structures are not 1 KiB aligned");
        return false;
    }

    let devices = pci::enumerate();
    let mut found = None;
    for device in devices.iter() {
        let id_matches = device.vendor == VENDOR_INTEL && SUPPORTED_IDS.contains(&device.device);
        let class_matches = device.class == CLASS_STORAGE
            && device.subclass == SUBCLASS_SATA
            && device.interface == INTERFACE_AHCI;
        if class_matches || (id_matches && class_matches) {
            found = Some(*device);
            break;
        }
    }
    let device = match found {
        Some(device) => device,
        None => {
            if let Some(other) = devices.iter().find(|device| device.class == CLASS_STORAGE) {
                println!(
                    "[--] STORAGE CONTROLLER: {:02x}:{:02x}.{} {:04x}:{:04x} is mass storage but not AHCI (subclass {:02x}, interface {:02x}) - this driver speaks AHCI only",
                    other.bus,
                    other.slot,
                    other.function,
                    other.vendor,
                    other.device,
                    other.subclass,
                    other.interface
                );
            } else {
                println!(
                    "[--] STORAGE CONTROLLER: no AHCI controller on bus 0 - the vault stays in RAM"
                );
            }
            return false;
        }
    };

    let (bar, bar_size) = match pci::ensure_memory_bar(&device, 5, PREFERRED_BAR) {
        Some(range) => range,
        None => {
            println!(
                "[!!] AHCI {:02x}:{:02x}.{} has no usable ABAR",
                device.bus, device.slot, device.function
            );
            return false;
        }
    };
    pci::enable(&device, true);

    {
        let hba = hba();
        hba.present = true;
        hba.bus = device.bus;
        hba.slot = device.slot;
        hba.function = device.function;
        hba.device = device.device;
        hba.bar = bar;
        hba.bar_size = bar_size;
        hba.mmio = bar as *mut u32;
    }

    {
        let hba = hba();
        hba.write(IS, 0xFFFF_FFFF);
        hba.write(GHC, hba.read(GHC) | GHC_HR);
        let mut spins = 0;
        while hba.read(GHC) & GHC_HR != 0 {
            if spins >= HBA_SPIN_LIMIT {
                println!("[!!] AHCI: the HBA did not come out of reset");
                return false;
            }
            spins += 1;
            core::hint::spin_loop();
        }
        hba.write(GHC, hba.read(GHC) | GHC_AE);
        hba.version = hba.read(VS);
        hba.ports_implemented = hba.read(PI);
        // The capability register is read so that a controller with no implemented ports is
        // distinguishable in the log from one whose ports are all empty.
        let _ = hba.read(CAP);
    }

    let mut identified = 0usize;
    for index in 0..MAX_PORTS {
        if hba().ports_implemented & (1u32 << index) == 0 {
            continue;
        }
        let port = index as u8;
        let status = hba().port_read(port, PX_SSTS);
        if status & SSTS_DET_MASK != SSTS_DET_PRESENT || status & SSTS_IPM_MASK == 0 {
            continue;
        }
        // The task file as the port came out of reset: kept so a fault the device was already
        // signalling is visible instead of being written off as this command's failure.
        let at_attach = hba().port_read(port, PX_TFD);
        if hba().init_port(port, index).is_err() {
            continue;
        }
        match hba().identify(port, index) {
            Ok(()) => {
                let hba = hba();
                hba.ports[index].index = port;
                hba.ports[index].present = true;
                hba.ports[index].at_attach = at_attach;
                if hba.selected.is_none() {
                    hba.selected = Some(port);
                }
                identified += 1;
            }
            Err(error) => {
                // Say *why*, not just that it failed: the fields below separate "the device
                // refused" (an error bit it set itself) from "the driver's own structures are
                // wrong" (a command header the device never consumed) from "the device never
                // answered" (the command issue bit still set).
                let hba = hba();
                let header = &buffers().ports[index].command_list[0];
                println!(
                    "[--] AHCI PORT {}: a device is present but IDENTIFY failed ({}) - not driven",
                    index,
                    error.as_str()
                );
                println!(
                    "[AHCI] port {}: at-attach tfd={:#010x}, now tfd={:#010x} is={:#010x} serr={:#010x} ci={:#010x} cmd={:#010x}",
                    index,
                    at_attach,
                    hba.port_read(port, PX_TFD),
                    hba.port_read(port, PX_IS),
                    hba.port_read(port, PX_SERR),
                    hba.port_read(port, PX_CI),
                    hba.port_read(port, PX_CMD)
                );
                println!(
                    "[AHCI] header: flags={:#06x} prdtl={} transferred={} table={:#x}",
                    header.flags, header.prdt_length, header.transferred, header.table_base
                );
            }
        }
    }

    DMA_FRAMES.fetch_add(MAX_PORTS as u64 * 2, Ordering::Relaxed);
    let hba = hba();
    let port = match hba.selected {
        Some(port) => port,
        None => {
            println!(
                "[--] STORAGE DEVICE: the AHCI controller is present but no port has a device on it - the vault stays in RAM"
            );
            return false;
        }
    };
    let state = &hba.ports[port as usize];
    println!(
        "[OK] STORAGE CONTROLLER: {:02x}:{:02x}.{} {:04x}:{:04x} AHCI {} ({} ports implemented, {} device(s) identified)",
        hba.bus,
        hba.slot,
        hba.function,
        VENDOR_INTEL,
        hba.device,
        hba.version >> 8,
        hba.ports_implemented.count_ones(),
        identified
    );
    println!(
        "[OK] STORAGE DEVICE: port {} model=\"{}\" fw=\"{}\" serial=\"{}\" {} sectors ({} MiB, {}-byte logical sectors) {}",
        port,
        trim(&state.model),
        trim(&state.firmware),
        trim(&state.serial),
        state.sectors,
        state.sectors * SECTOR_SIZE as u64 / (1024 * 1024),
        SECTOR_SIZE,
        if state.support_48bit { "LBA48" } else { "LBA28" }
    );
    hba.command_list_base =
        (hba.port_read(port, PX_CLBU) as u64) << 32 | hba.port_read(port, PX_CLB) as u64;
    hba.fis_base = (hba.port_read(port, PX_FBU) as u64) << 32 | hba.port_read(port, PX_FB) as u64;
    true
}

/// ATA strings are space padded; trim for a log line.
fn trim(field: &[u8]) -> alloc::string::String {
    let end = field
        .iter()
        .rposition(|byte| *byte != b' ' && *byte != 0)
        .map(|position| position + 1)
        .unwrap_or(0);
    alloc::string::String::from_utf8_lossy(&field[..end]).into_owned()
}

pub fn ready() -> bool {
    unsafe { hba().present && hba().selected.is_some() }
}

pub fn sector_count() -> u64 {
    let hba = unsafe { hba() };
    match hba.selected {
        Some(port) => hba.ports[port as usize].sectors,
        None => 0,
    }
}

pub fn model() -> alloc::string::String {
    let hba = unsafe { hba() };
    match hba.selected {
        Some(port) => trim(&hba.ports[port as usize].model),
        None => alloc::string::String::new(),
    }
}

/// `(read commands, write commands, errors, timeouts)`.
pub fn counters() -> (u64, u64, u64, u64) {
    let hba = unsafe { hba() };
    (hba.reads, hba.writes, hba.errors, hba.timeouts)
}

fn finish(outcome: Result<(), BlockError>, write: bool) -> Result<(), BlockError> {
    let hba = unsafe { hba() };
    match outcome {
        Ok(()) => {
            if write {
                hba.writes += 1;
            } else {
                hba.reads += 1;
            }
            Ok(())
        }
        Err(error) => {
            hba.errors += 1;
            if error == BlockError::Timeout {
                hba.timeouts += 1;
            }
            Err(error)
        }
    }
}

/// One LBA48 command over a buffer the PRDT budget can describe.
fn command(lba: u64, buffer: &mut [u8], sectors: u16, write: bool) -> Result<(), BlockError> {
    let hba = unsafe { hba() };
    if !hba.present {
        return Err(BlockError::NotPresent);
    }
    let port = match hba.selected {
        Some(port) => port,
        None => return Err(BlockError::NotPresent),
    };
    let index = port as usize;
    let state = &hba.ports[index];
    if !state.present {
        return Err(BlockError::NotPresent);
    }
    if !state.sector_size_ok || !state.support_48bit {
        return Err(BlockError::Unsupported);
    }
    let opcode = if write { ATA_WRITE_DMA_EXT } else { ATA_READ_DMA_EXT };
    let outcome = hba.issue(port, index, opcode, lba, sectors, buffer, write);
    finish(outcome, write)
}

/// The controller as a [`BlockDevice`], so nothing above this module ever names a controller.
pub struct AhciDisk;

impl BlockDevice for AhciDisk {
    fn sector_count(&self) -> u64 {
        sector_count()
    }

    fn read_sectors(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        crate::block::validate(self.sector_count(), lba, buffer.len())?;
        let mut offset = 0usize;
        while offset < buffer.len() {
            let chunk = core::cmp::min(DMA_BYTES, buffer.len() - offset);
            let sectors = (chunk / SECTOR_SIZE) as u16;
            let chunk_lba = lba + (offset / SECTOR_SIZE) as u64;
            command(
                chunk_lba,
                &mut buffer[offset..offset + chunk],
                sectors,
                false,
            )?;
            offset += chunk;
        }
        Ok(())
    }

    fn write_sectors(&mut self, lba: u64, buffer: &[u8]) -> Result<(), BlockError> {
        crate::block::validate(self.sector_count(), lba, buffer.len())?;
        // Writes stage through one frame so the address the device is given is always the module's
        // own DMA buffer, whatever the caller's slice looks like.
        let mut staging = [0u8; DMA_BYTES];
        let mut offset = 0usize;
        while offset < buffer.len() {
            let chunk = core::cmp::min(DMA_BYTES, buffer.len() - offset);
            staging[..chunk].copy_from_slice(&buffer[offset..offset + chunk]);
            let sectors = (chunk / SECTOR_SIZE) as u16;
            let chunk_lba = lba + (offset / SECTOR_SIZE) as u64;
            command(chunk_lba, &mut staging[..chunk], sectors, true)?;
            offset += chunk;
        }
        Ok(())
    }
}

// ------------------------------------------------------------------ self-test

const REGISTER_ASSERTIONS: u32 = 9;
const PORT_ASSERTIONS: u32 = 8;
const ROUND_TRIP_ASSERTIONS: u32 = 3;
/// Assertions the adapter makes, so a machine with no controller reports the same number skipped.
const ADAPTER_ASSERTIONS: u32 = REGISTER_ASSERTIONS + PORT_ASSERTIONS + ROUND_TRIP_ASSERTIONS;

fn scratch_pattern() -> [u8; SECTOR_SIZE] {
    let mut pattern = [0u8; SECTOR_SIZE];
    for (offset, byte) in pattern.iter_mut().enumerate() {
        *byte = (offset as u8) ^ 0xA5;
    }
    pattern
}

/// Exercises the controller: the placement and geometry of its DMA structures, the register values
/// the device kept, and - on a working disk - a round trip through a scratch sector.
///
/// The round trip *destroys* the sector it is given, which is why the caller nominates it: `disk
/// test` passes the last sector of the device, and the vault image reserves its own probe sector,
/// so live data is never touched.
pub fn self_test(scratch_lba: Option<u64>) -> BlockReport {
    let mut report = BlockReport::new();
    let hba = unsafe { hba() };
    if !hba.present {
        report.skip(ADAPTER_ASSERTIONS);
        report.failures.push("no AHCI controller was found");
        return report;
    }

    report.check(
        hba.signature == AHCI_SIGNATURE,
        "the controller state is not in `.data`",
    );
    report.check(
        hba.bar != 0 && hba.bar_size >= required_window(hba.ports_implemented),
        "ABAR is smaller than the register window this driver reads",
    );
    report.check(hba.read(GHC) & GHC_AE != 0, "AHCI mode is not enabled");
    report.check(hba.read(GHC) & GHC_HR == 0, "the HBA is still in reset");
    report.check(
        hba.version != 0 && hba.version != 0xFFFF_FFFF,
        "the version register is not readable",
    );
    report.check(hba.ports_implemented != 0, "no ports are implemented");
    let buffers_address = core::ptr::addr_of!(BUFFERS) as u64;
    report.check(
        buffers_address % 1024 == 0,
        "the command list is not 1 KiB aligned (the device masks those bits)",
    );
    report.check(
        (buffers_address
            + core::mem::offset_of!(Buffers, ports) as u64
            + core::mem::offset_of!(PortBuffers, fis) as u64)
            % 256
            == 0,
        "the received-FIS area is not 256-byte aligned",
    );
    report.check(
        core::mem::size_of::<CommandHeader>() == 32
            && core::mem::size_of::<PrdtEntry>() == 16
            && core::mem::size_of::<CommandTable>() % 128 == 0,
        "a controller structure is not the size or alignment the specification defines",
    );

    let port = match hba.selected {
        Some(port) => port,
        None => {
            report.skip(ADAPTER_ASSERTIONS - REGISTER_ASSERTIONS);
            return report;
        }
    };
    let index = port as usize;
    let state = &hba.ports[index];
    report.check(state.present, "the selected port has no device");
    report.check(state.sector_size_ok, "the logical sector size is not 512 bytes");
    report.check(state.sectors > 0, "the device reports no sectors");
    report.check(state.support_48bit, "the device does not support 48-bit addressing");
    report.check(
        hba.port_read(port, PX_CLB) as u64 | ((hba.port_read(port, PX_CLBU) as u64) << 32)
            == hba.command_list_base
            && hba.command_list_base != 0,
        "the device did not keep the command list base it was given",
    );
    report.check(
        hba.port_read(port, PX_FB) != 0,
        "the port's FIS receive area is not programmed",
    );
    report.check(
        hba.port_read(port, PX_CMD) & PXCMD_ST != 0,
        "the port's command engine is not started",
    );
    report.check(
        hba.port_read(port, PX_TFD) & (TFD_ERR | TFD_DF) == 0,
        "the device's task file has an error set",
    );

    if let Some(lba) = scratch_lba {
        if lba < state.sectors {
            let pattern = scratch_pattern();
            let mut disk = AhciDisk;
            match disk.write_sectors(lba, &pattern) {
                Ok(()) => {
                    let mut readback = [0u8; SECTOR_SIZE];
                    match disk.read_sectors(lba, &mut readback) {
                        Ok(()) => {
                            report.check(true, "the scratch read-back command completed");
                            report.check(
                                readback == pattern,
                                "a sector written to the disk did not read back from the disk",
                            );
                            // A second, different pattern proves the medium is not echoing a
                            // stale frame from either side.
                            let mut inverted = pattern;
                            for byte in inverted.iter_mut() {
                                *byte = !*byte;
                            }
                            let mut check = inverted;
                            report.check(
                                disk.write_sectors(lba, &inverted).is_ok()
                                    && disk.read_sectors(lba, &mut check).is_ok()
                                    && check == inverted,
                                "a second write to the scratch sector did not read back as written",
                            );
                        }
                        Err(error) => {
                            println!("[!!] AHCI: scratch read failed: {}", error.as_str());
                            report.check(false, "the scratch read-back command failed");
                            report.skip(1);
                        }
                    }
                }
                Err(error) => {
                    println!("[!!] AHCI: scratch write failed: {}", error.as_str());
                    report.check(false, "a write to the scratch sector failed");
                    report.skip(ROUND_TRIP_ASSERTIONS - 1);
                }
            }
        } else {
            report.skip(ROUND_TRIP_ASSERTIONS);
        }
    } else {
        report.skip(ROUND_TRIP_ASSERTIONS);
    }
    report
}

pub fn describe() {
    let hba = unsafe { hba() };
    if !hba.present {
        println!("[SH] DISK: no AHCI controller (the vault is RAM-only)");
        return;
    }
    println!(
        "[SH] DISK {:02x}:{:02x}.{} {:04x}:{:04x} AHCI {} abar={:#x} ({} KiB) ports={:#x} dma-frames={}",
        hba.bus,
        hba.slot,
        hba.function,
        VENDOR_INTEL,
        hba.device,
        hba.version >> 8,
        hba.bar,
        hba.bar_size / 1024,
        hba.ports_implemented,
        DMA_FRAMES.load(Ordering::Relaxed)
    );
    println!(
        "[SH]      command-list={:#x} fis={:#x} ({} byte headers, {} slots, {} PRDT entries) reads={} writes={} errors={} timeouts={}",
        hba.command_list_base,
        hba.fis_base,
        core::mem::size_of::<CommandHeader>(),
        SLOTS,
        PRDT_ENTRIES,
        hba.reads,
        hba.writes,
        hba.errors,
        hba.timeouts
    );
    for index in 0..MAX_PORTS {
        let state = &hba.ports[index];
        if !state.present {
            continue;
        }
        println!(
            "[SH]      port {} \"{}\" serial=\"{}\" fw=\"{}\" sig={:#010x} {} sectors ({} MiB) {}",
            state.index,
            trim(&state.model),
            trim(&state.serial),
            trim(&state.firmware),
            state.signature,
            state.sectors,
            state.sectors * SECTOR_SIZE as u64 / (1024 * 1024),
            if state.support_48bit { "LBA48" } else { "LBA28" }
        );
    }
    if hba.selected.is_none() {
        println!("[SH]      no port has a device on it");
    }
    println!(
        "[DISK] counters: reads={} writes={} errors={} timeouts={} dma-frames={}",
        hba.reads,
        hba.writes,
        hba.errors,
        hba.timeouts,
        DMA_FRAMES.load(Ordering::Relaxed)
    );
}
