//! Boot protocol detection and handoff parsing.
//!
//! Three handoffs are understood:
//!
//! * **PVH** (`XEN_ELFNOTE_PHYS32_ENTRY`) — QEMU's `-kernel` direct boot. `%ebx` holds
//!   the physical address of Xen's `hvm_start_info`, which carries a memory map.
//! * **Multiboot 1** (`0x2BADB002`) — classic 32-bit loaders.
//! * **Multiboot 2** (`0x36D76289`) — GRUB, used by the bootable ISO image.
//!
//! The point of parsing this at all is honest machine sizing: the heap window and the
//! panic-scrub range are derived from the memory the machine actually reports instead
//! of a hardcoded constant.

use core::ptr;
use core::slice;

pub const MB1_MAGIC: u32 = 0x2BAD_B002;
pub const MB2_MAGIC: u32 = 0x36D7_6289;
pub const PVH_MAGIC: u32 = 0x336E_C578;

/// The kernel image is loaded at 1 MiB; everything below is firmware/interpreter area.
pub const KERNEL_LOAD_BASE: u64 = 0x0010_0000;
/// The bootstrap identity maps the low 4 GiB, so nothing outside it is reachable.
pub const IDENTITY_MAP_LIMIT: u64 = 0x1_0000_0000;

pub const HEAP_MAX_BYTES: u64 = 48 * 1024 * 1024;
pub const HEAP_RESERVE_BYTES: u64 = 8 * 1024 * 1024;

const MAX_MMAP: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Pvh,
    Multiboot1,
    Multiboot2,
    Unknown,
}

impl Protocol {
    pub fn name(self) -> &'static str {
        match self {
            Protocol::Pvh => "PVH-DIRECT",
            Protocol::Multiboot1 => "MULTIBOOT1",
            Protocol::Multiboot2 => "MULTIBOOT2",
            Protocol::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Clone, Copy)]
pub struct Framebuffer {
    pub addr: u64,
    pub pitch: u32,
    pub width: u32,
    pub height: u32,
    pub bpp: u8,
}

/// One entry of the bootloader-provided physical memory map.
#[derive(Clone, Copy)]
pub struct MmapEntry {
    pub base: u64,
    pub length: u64,
    pub kind: u32,
}

impl MmapEntry {
    const EMPTY: Self = Self { base: 0, length: 0, kind: 0 };

    pub fn end(&self) -> u64 {
        self.base.saturating_add(self.length)
    }

    /// Type 1 means usable RAM in both the Multiboot and Xen memory-map encodings.
    pub fn is_available(&self) -> bool {
        self.kind == 1
    }
}

/// The boot handoff is consumed once, single-threaded, before the scheduler exists, so
/// a plain static buffer is sufficient and avoids handing out dangling references.
static mut MMAP_BUFFER: [MmapEntry; MAX_MMAP] = [MmapEntry::EMPTY; MAX_MMAP];

pub struct BootInfo {
    pub protocol: Protocol,
    pub protocol_revision: u32,
    pub mem_lower_kib: u64,
    pub mem_upper_kib: u64,
    pub cmdline: Option<&'static [u8]>,
    pub loader_name: Option<&'static [u8]>,
    pub framebuffer: Option<Framebuffer>,
    pub mmap: &'static [MmapEntry],
    /// Physical address of the ACPI RSDP, when the handoff carries one. PVH does (Xen added the
    /// field for exactly this) and Multiboot does not, which is why `arch::acpi` also knows how
    /// to find the tables the way the BIOS left them.
    pub rsdp: Option<u64>,
}

impl BootInfo {
    fn empty(protocol: Protocol) -> Self {
        Self {
            protocol,
            protocol_revision: 0,
            mem_lower_kib: 0,
            mem_upper_kib: 0,
            cmdline: None,
            loader_name: None,
            framebuffer: None,
            mmap: &[],
            rsdp: None,
        }
    }

    /// Total addressable RAM reported by the bootloader (0 when unknown).
    pub fn total_ram_bytes(&self) -> u64 {
        if !self.mmap.is_empty() {
            self.mmap
                .iter()
                .filter(|e| e.is_available())
                .map(|e| e.end())
                .max()
                .unwrap_or(0)
        } else if self.mem_upper_kib > 0 {
            KERNEL_LOAD_BASE + self.mem_upper_kib * 1024
        } else {
            0
        }
    }

    /// Heap window: the first usable RAM region above the kernel image, capped at
    /// `HEAP_MAX_BYTES` and always inside the identity map.
    pub fn heap_range(&self, kernel_end: u64) -> Option<(u64, u64)> {
        let start = align_up(kernel_end.max(KERNEL_LOAD_BASE), 4096);
        let limit = self
            .total_ram_bytes()
            .min(IDENTITY_MAP_LIMIT)
            .saturating_sub(HEAP_RESERVE_BYTES);
        if limit <= start {
            return None;
        }
        let size = (limit - start).min(HEAP_MAX_BYTES);
        if size < 1024 * 1024 {
            return None;
        }
        Some((start, size))
    }

    pub fn describe(&self) {
        crate::println!(
            "[OK] BOOT PROTOCOL: {} (rev {}, {} MiB usable RAM, {} memory-map entries)",
            self.protocol.name(),
            self.protocol_revision,
            self.total_ram_bytes() / (1024 * 1024),
            self.mmap.len()
        );
        if let Some(name) = self.loader_name {
            crate::println!("[OK] BOOT LOADER: {}", lossy(name));
        }
        if let Some(cmdline) = self.cmdline {
            crate::println!("[OK] KERNEL CMDLINE: '{}'", lossy(cmdline));
        }
        if let Some(fb) = self.framebuffer {
            crate::println!(
                "[OK] FRAMEBUFFER HANDOFF: {}x{}x{} @ {:#x} (pitch {})",
                fb.width,
                fb.height,
                fb.bpp,
                fb.addr,
                fb.pitch
            );
        } else {
            crate::println!("[--] NO FRAMEBUFFER HANDOFF (graphics driver must probe VBE)");
        }
    }
}

pub fn align_up(value: u64, align: u64) -> u64 {
    (value + (align - 1)) & !(align - 1)
}

fn lossy(bytes: &[u8]) -> &str {
    core::str::from_utf8(bytes).unwrap_or("<non-utf8>")
}

unsafe fn cstr(addr: u64, max: usize) -> Option<&'static [u8]> {
    if addr == 0 {
        return None;
    }
    let base = addr as *const u8;
    let mut len = 0usize;
    while len < max && ptr::read_volatile(base.add(len)) != 0 {
        len += 1;
    }
    if len == 0 {
        return None;
    }
    Some(slice::from_raw_parts(base, len))
}

unsafe fn read_u32(addr: u64) -> u32 {
    ptr::read_unaligned(addr as *const u32)
}

unsafe fn read_u64(addr: u64) -> u64 {
    ptr::read_unaligned(addr as *const u64)
}

unsafe fn push(cursor: &mut usize, base: u64, length: u64, kind: u32) {
    if *cursor >= MAX_MMAP || length == 0 {
        return;
    }
    let slot = ptr::addr_of_mut!(MMAP_BUFFER[*cursor]);
    ptr::write(slot, MmapEntry { base, length, kind });
    *cursor += 1;
}

unsafe fn publish(cursor: usize) -> &'static [MmapEntry] {
    slice::from_raw_parts(ptr::addr_of!(MMAP_BUFFER) as *const MmapEntry, cursor)
}

// ---------------------------------------------------------------- Multiboot 1

mod mb1 {
    pub const FLAGS: u64 = 0;
    pub const MEM_LOWER: u64 = 4;
    pub const MEM_UPPER: u64 = 8;
    pub const CMDLINE: u64 = 16;
    pub const MMAP_LENGTH: u64 = 44;
    pub const MMAP_ADDR: u64 = 48;
    pub const BOOT_LOADER_NAME: u64 = 64;

    pub const FLAG_MEMORY: u32 = 1 << 0;
    pub const FLAG_CMDLINE: u32 = 1 << 2;
    pub const FLAG_MMAP: u32 = 1 << 6;
    pub const FLAG_LOADER_NAME: u32 = 1 << 9;
}

unsafe fn parse_mb1(info: u64) -> BootInfo {
    let mut boot = BootInfo::empty(Protocol::Multiboot1);
    let flags = read_u32(info + mb1::FLAGS);
    boot.protocol_revision = flags;

    if flags & mb1::FLAG_MEMORY != 0 {
        boot.mem_lower_kib = read_u32(info + mb1::MEM_LOWER) as u64;
        boot.mem_upper_kib = read_u32(info + mb1::MEM_UPPER) as u64;
    }
    if flags & mb1::FLAG_CMDLINE != 0 {
        boot.cmdline = cstr(read_u32(info + mb1::CMDLINE) as u64, 256);
    }
    if flags & mb1::FLAG_LOADER_NAME != 0 {
        boot.loader_name = cstr(read_u32(info + mb1::BOOT_LOADER_NAME) as u64, 128);
    }
    if flags & mb1::FLAG_MMAP != 0 {
        let length = read_u32(info + mb1::MMAP_LENGTH) as u64;
        let mut entry = read_u32(info + mb1::MMAP_ADDR) as u64;
        let end = entry + length;
        let mut cursor = 0usize;
        // Entry layout: size(u32, excludes itself), base(u64), length(u64), type(u32).
        while entry + 24 <= end && cursor < MAX_MMAP {
            let size = read_u32(entry) as u64;
            push(
                &mut cursor,
                read_u64(entry + 4),
                read_u64(entry + 12),
                read_u32(entry + 20),
            );
            entry += size + 4;
        }
        boot.mmap = publish(cursor);
    }
    boot
}

// ---------------------------------------------------------------- Multiboot 2

mod mb2 {
    pub const END: u32 = 0;
    pub const CMDLINE: u32 = 1;
    pub const BOOT_LOADER_NAME: u32 = 2;
    pub const BASIC_MEMINFO: u32 = 4;
    pub const MMAP: u32 = 6;
    pub const FRAMEBUFFER: u32 = 8;
}

unsafe fn parse_mb2(info: u64) -> BootInfo {
    let mut boot = BootInfo::empty(Protocol::Multiboot2);
    let total_size = read_u32(info) as u64;
    boot.protocol_revision = read_u32(info + 4);

    let mut cursor = info + 8;
    let end = info + total_size.max(8);
    let mut mmap_cursor = 0usize;

    while cursor + 8 <= end {
        let tag_type = read_u32(cursor);
        let tag_size = read_u32(cursor + 4) as u64;
        if tag_type == mb2::END || tag_size < 8 {
            break;
        }
        let payload = cursor + 8;

        match tag_type {
            mb2::CMDLINE => boot.cmdline = cstr(payload, 256),
            mb2::BOOT_LOADER_NAME => boot.loader_name = cstr(payload, 128),
            mb2::BASIC_MEMINFO => {
                boot.mem_lower_kib = read_u32(payload) as u64;
                boot.mem_upper_kib = read_u32(payload + 4) as u64;
            }
            mb2::MMAP => {
                let entry_size = read_u32(payload) as u64;
                let mut entry = payload + 8;
                let tag_end = cursor + tag_size;
                while entry + 24 <= tag_end && mmap_cursor < MAX_MMAP && entry_size >= 24 {
                    push(
                        &mut mmap_cursor,
                        read_u64(entry),
                        read_u64(entry + 8),
                        read_u32(entry + 16),
                    );
                    entry += entry_size;
                }
            }
            mb2::FRAMEBUFFER => {
                let bpp = ptr::read_volatile((payload + 24) as *const u8);
                let fb_type = ptr::read_volatile((payload + 25) as *const u8);
                // 1 = direct RGB; EGA text mode cannot be rendered into.
                if fb_type == 1 {
                    boot.framebuffer = Some(Framebuffer {
                        addr: read_u64(payload),
                        pitch: read_u32(payload + 8),
                        width: read_u32(payload + 12),
                        height: read_u32(payload + 16),
                        bpp,
                    });
                }
            }
            _ => {}
        }
        cursor = align_up(cursor + tag_size, 8);
    }

    boot.mmap = publish(mmap_cursor);
    boot
}

// ---------------------------------------------------------------- PVH / Xen

mod pvh {
    pub const VERSION: u64 = 4;
    pub const NR_MODULES: u64 = 12;
    pub const CMDLINE: u64 = 24;
    /// Added in `hvm_start_info` version 1: the RSDP, so a PVH guest does not have to search for
    /// the ACPI tables in the BIOS area it never had.
    pub const RSDP: u64 = 32;
    pub const MEMMAP: u64 = 40;
    pub const MEMMAP_ENTRIES: u64 = 48;

    pub const ENTRY_STRIDE: u64 = 24;
}

unsafe fn parse_pvh(info: u64) -> BootInfo {
    let mut boot = BootInfo::empty(Protocol::Pvh);
    let version = read_u32(info + pvh::VERSION);
    boot.protocol_revision = version;
    boot.loader_name = Some(b"QEMU PVH direct boot");
    boot.cmdline = cstr(read_u64(info + pvh::CMDLINE), 256);

    if version >= 1 {
        let rsdp = read_u64(info + pvh::RSDP);
        if rsdp != 0 {
            boot.rsdp = Some(rsdp);
        }
    }
    if version >= 1 && read_u32(info + pvh::NR_MODULES) == 0 {
        let memmap = read_u64(info + pvh::MEMMAP);
        let entries = read_u32(info + pvh::MEMMAP_ENTRIES) as usize;
        if memmap != 0 && entries > 0 {
            let mut cursor = 0usize;
            for index in 0..entries.min(MAX_MMAP) {
                let entry = memmap + index as u64 * pvh::ENTRY_STRIDE;
                push(
                    &mut cursor,
                    read_u64(entry),
                    read_u64(entry + 8),
                    read_u32(entry + 16),
                );
            }
            boot.mmap = publish(cursor);
        }
    }

    // PVH has no Multiboot-style KiB counters; derive the usual pair from the map.
    let total = boot.total_ram_bytes();
    boot.mem_upper_kib = total.saturating_sub(KERNEL_LOAD_BASE) / 1024;
    boot.mem_lower_kib = boot
        .mmap
        .iter()
        .filter(|e| e.is_available() && e.base == 0)
        .map(|e| e.length.min(640 * 1024) / 1024)
        .max()
        .unwrap_or(0);
    boot
}

/// Identifies the live boot protocol from the register handoff.
///
/// # Safety
/// `info` must be the physical pointer the bootloader left in EBX. Everything it points
/// at must lie inside the bootstrap identity map (low 4 GiB), which is true for PVH,
/// Multiboot 1 and Multiboot 2.
pub unsafe fn parse(magic: u32, info: u32) -> BootInfo {
    match magic {
        MB1_MAGIC if info != 0 => parse_mb1(info as u64),
        MB2_MAGIC if info != 0 => parse_mb2(info as u64),
        _ if info != 0 && read_u32(info as u64) == PVH_MAGIC => parse_pvh(info as u64),
        _ => {
            crate::println!(
                "[!!] UNRECOGNISED BOOT HANDOFF: magic={:#010x} info={:#010x} first_dword={:#010x}",
                magic,
                info,
                if info != 0 { read_u32(info as u64) } else { 0 }
            );
            BootInfo::empty(Protocol::Unknown)
        }
    }
}
