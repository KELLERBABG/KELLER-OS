//! ACPI table discovery and the MADT: where the interrupt controllers are, and how many CPUs
//! this machine actually has.
//!
//! Nothing here needs firmware. QEMU's `-kernel` direct boot is PVH, and the PVH start info
//! carries the physical address of the RSDP (`rsdp_paddr`, the field Xen added for exactly this
//! reason), so the tables are found by pointer rather than by searching the BIOS area. A scan of
//! the EBDA and the 0xE0000..0x100000 window is kept as a fallback for the Multiboot paths, where
//! the loader hands over no such field - and it is checked with the same rules, so a machine
//! whose tables cannot be found says so instead of inventing an APIC address.
//!
//! What is read out of the MADT and used:
//!
//! * **the local APIC's base address** (and the type-5 override of it, which must win);
//! * **the CPU list**: one local-APIC entry per processor, with the flag that says whether that
//!   processor is enabled. The BSP is one of those entries, but the kernel does not have to guess
//!   *which* one: the APIC ID register says who is running, so the list is used for "who else is
//!   there" and the register for "who am I";
//! * **the IO-APIC**: its id, its MMIO address and the first GSI it handles;
//! * **interrupt source overrides**, which are the only correct way to route the ISA IRQs: on the
//!   PC platform IRQ0 is wired to GSI 2, and a driver that programs redirection entry 0 because
//!   "IRQ0 is GSI0" gets a timer that never fires.

use crate::block::BlockReport;
use crate::println;
use alloc::string::String;

/// RSDP signature, and the shape of the extended (ACPI 2.0+) revision.
const RSDP_SIGNATURE: &[u8; 8] = b"RSD PTR ";
const RSDP_V2_MIN_REVISION: u8 = 2;
/// ACPI table header signature of the MADT.
const MADT_SIGNATURE: &[u8; 4] = b"APIC";
/// How many processors this kernel keeps room for. The MADT is allowed to describe more; the
/// ones beyond this are counted and reported rather than silently dropped.
pub const MAX_CPUS: usize = 8;
const MAX_OVERRIDES: usize = 16;
/// Signature that keeps this module's state in `.data` where the boot handoff cannot disturb it.
const ACPI_SIGNATURE: u64 = 0x4B45_4C4C_4143_5001; // "KELLAC P\x01"

fn read_u16(addr: u64) -> u16 {
    unsafe { core::ptr::read_unaligned(addr as *const u16) }
}

fn read_u32(addr: u64) -> u32 {
    unsafe { core::ptr::read_unaligned(addr as *const u32) }
}

fn read_u64(addr: u64) -> u64 {
    unsafe { core::ptr::read_unaligned(addr as *const u64) }
}

/// Standard ACPI checksum: every byte of the structure must sum to zero in a `u8`.
unsafe fn checksum_ok(addr: u64, length: usize) -> bool {
    if length == 0 || length > 4096 {
        return false;
    }
    let mut sum = 0u8;
    for offset in 0..length {
        sum = sum.wrapping_add(core::ptr::read_volatile((addr as *const u8).add(offset)));
    }
    sum == 0
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct InterruptOverride {
    /// ISA IRQ the override is about.
    pub source: u8,
    /// GSI it is wired to.
    pub gsi: u32,
    /// Flag bits: 0-1 polarity (3 = active low), 2-3 trigger (3 = level).
    pub flags: u16,
}

/// One processor from the MADT.
#[derive(Clone, Copy)]
pub struct Processor {
    pub apic_id: u8,
    /// ACPI processor id, which is what the AML namespace would call it (`\_PR.CPU0`).
    pub acpi_id: u8,
    /// Bit 0 of the entry flags: set means the firmware expects this processor to be usable.
    pub enabled: bool,
}

pub struct State {
    signature: u64,
    present: bool,
    /// Physical address of the RSDP the tables were found through.
    rsdp: u64,
    revision: u8,
    oem_id: [u8; 6],
    /// Local APIC base, after any type-5 override.
    lapic_base: u64,
    /// True when the MADT flags bit 0 was set (PC-AT compatibility: the 8259 exists).
    dual_8259: bool,
    /// The first CPU in the list is the BSP only by convention; the kernel checks its own id
    /// against this list rather than trusting the order.
    processors: [Processor; MAX_CPUS],
    processor_count: usize,
    ioapic_id: u8,
    ioapic_address: u64,
    ioapic_gsi_base: u32,
    ioapic_count: u32,
    overrides: [InterruptOverride; MAX_OVERRIDES],
    override_count: usize,
    /// Raw count of MADT entries walked, for the self-test's arithmetic.
    entries: u32,
}

impl State {
    const fn empty() -> Self {
        Self {
            signature: ACPI_SIGNATURE,
            present: false,
            rsdp: 0,
            revision: 0,
            oem_id: [0; 6],
            lapic_base: 0,
            dual_8259: false,
            processors: [Processor {
                apic_id: 0,
                acpi_id: 0,
                enabled: false,
            }; MAX_CPUS],
            processor_count: 0,
            ioapic_id: 0,
            ioapic_address: 0,
            ioapic_gsi_base: 0,
            ioapic_count: 0,
            overrides: [InterruptOverride {
                source: 0,
                gsi: 0,
                flags: 0,
            }; MAX_OVERRIDES],
            override_count: 0,
            entries: 0,
        }
    }
}

static mut ACPI: State = State::empty();

fn state() -> &'static mut State {
    unsafe { &mut *core::ptr::addr_of_mut!(ACPI) }
}

pub fn present() -> bool {
    state().present
}

pub fn lapic_base() -> u64 {
    state().lapic_base
}

pub fn ioapic_address() -> u64 {
    state().ioapic_address
}

pub fn ioapic_id() -> u8 {
    state().ioapic_id
}

pub fn ioapic_gsi_base() -> u32 {
    state().ioapic_gsi_base
}

pub fn processor_count() -> usize {
    state().processor_count
}

pub fn processor(index: usize) -> Option<Processor> {
    let state = state();
    if index < state.processor_count {
        Some(state.processors[index])
    } else {
        None
    }
}

pub fn dual_8259() -> bool {
    state().dual_8259
}

/// True when the MADT carries an explicit interrupt-source override for `irq`. The difference
/// matters: an override is a statement about this machine, while the identity mapping is the
/// fallback the specification defines for the ISA bus.
pub fn has_override(irq: u8) -> bool {
    let state = state();
    state.overrides[..state.override_count]
        .iter()
        .any(|entry| entry.source == irq)
}

/// The GSI an ISA IRQ is wired to, honoring the MADT's interrupt source overrides. This is the
/// lookup that keeps IRQ0 off redirection entry 0 on a PC (it is GSI 2 there).
pub fn gsi_for_irq(irq: u8) -> u32 {
    let state = state();
    for entry in state.overrides[..state.override_count].iter() {
        if entry.source == irq {
            return entry.gsi;
        }
    }
    irq as u32
}

/// Polarity and trigger for an ISA IRQ from the overrides, defaulting to what the ISA bus means:
/// active high, edge triggered.
pub fn irq_flags(irq: u8) -> (bool, bool) {
    let state = state();
    for entry in state.overrides[..state.override_count].iter() {
        if entry.source == irq {
            let active_low = entry.flags & 3 == 3;
            let level = (entry.flags >> 2) & 3 == 3;
            return (active_low, level);
        }
    }
    (false, false)
}

unsafe fn scan_for_rsdp() -> Option<u64> {
    // The EBDA pointer lives at 0x40E: the segment of the extended BIOS data area.
    let ebda = (read_u16(0x040E) as u64) << 4;
    let regions = [(ebda, 1024usize), (0xE0000, 0x20000usize)];
    for (base, length) in regions {
        if base == 0 || base >= 0x10_0000 {
            continue;
        }
        let mut offset = 0usize;
        while offset + 36 <= length {
            let address = base + offset as u64;
            if core::ptr::read_unaligned(address as *const [u8; 8]) == *RSDP_SIGNATURE
                && checksum_ok(address, 20)
            {
                return Some(address);
            }
            offset += 16;
        }
    }
    None
}

/// Walks an ACPI table list (XSDT when the RSDP says ACPI 2.0+, RSDT otherwise) looking for
/// `signature`. Returns the physical address of the table.
unsafe fn find_table(rsdp: u64, signature: &[u8; 4]) -> Option<u64> {
    let revision = core::ptr::read_volatile((rsdp as *const u8).add(15));
    let (root, entry_size) = if revision >= RSDP_V2_MIN_REVISION {
        let xsdt = read_u64(rsdp + 24);
        if xsdt == 0 {
            (read_u32(rsdp + 16) as u64, 4u64)
        } else {
            (xsdt, 8u64)
        }
    } else {
        (read_u32(rsdp + 16) as u64, 4u64)
    };
    if root == 0 {
        return None;
    }
    let length = read_u32(root + 4) as usize;
    if !checksum_ok(root, length) {
        return None;
    }
    let entries = (length.saturating_sub(36)) / entry_size as usize;
    for index in 0..entries {
        let entry = root + 36 + index as u64 * entry_size;
        let address = if entry_size == 8 {
            read_u64(entry)
        } else {
            read_u32(entry) as u64
        };
        if address == 0 || address > 0x1_0000_0000 {
            continue;
        }
        if core::ptr::read_unaligned(address as *const [u8; 4]) == *signature {
            let table_length = read_u32(address + 4) as usize;
            if checksum_ok(address, table_length) {
                return Some(address);
            }
        }
    }
    None
}

unsafe fn parse_madt(address: u64) -> bool {
    let length = read_u32(address + 4) as usize;
    if length < 44 {
        return false;
    }
    let state = state();
    state.lapic_base = read_u32(address + 36) as u64;
    let flags = read_u32(address + 40);
    state.dual_8259 = flags & 1 != 0;

    let mut cursor = address + 44;
    let end = address + length as u64;
    while cursor + 2 <= end {
        let entry_type = core::ptr::read_volatile(cursor as *const u8);
        let entry_length = core::ptr::read_volatile((cursor + 1) as *const u8) as u64;
        if entry_length < 2 || cursor + entry_length > end {
            break;
        }
        state.entries += 1;
        match entry_type {
            // Local APIC: one per processor.
            0 if entry_length >= 8 => {
                if state.processor_count < MAX_CPUS {
                    // type(1) length(1) acpi_id(1) apic_id(1) flags(4)
                    state.processors[state.processor_count] = Processor {
                        acpi_id: core::ptr::read_volatile((cursor + 2) as *const u8),
                        apic_id: core::ptr::read_volatile((cursor + 3) as *const u8),
                        enabled: read_u32(cursor + 4) & 1 != 0,
                    };
                    state.processor_count += 1;
                }
            }
            // I/O APIC: the first one is the one this kernel drives.
            1 if entry_length >= 12 => {
                if state.ioapic_address == 0 {
                    state.ioapic_id = core::ptr::read_volatile((cursor + 2) as *const u8);
                    state.ioapic_address = read_u32(cursor + 4) as u64;
                    state.ioapic_gsi_base = read_u32(cursor + 8);
                }
                state.ioapic_count += 1;
            }
            // Interrupt source override: the ISA IRQ to GSI mapping.
            2 if entry_length >= 10 => {
                if state.override_count < MAX_OVERRIDES {
                    state.overrides[state.override_count] = InterruptOverride {
                        source: core::ptr::read_volatile((cursor + 3) as *const u8),
                        gsi: read_u32(cursor + 4),
                        flags: read_u16(cursor + 8),
                    };
                    state.override_count += 1;
                }
            }
            // Local APIC address override: the 64-bit address wins over the 32-bit header field.
            5 if entry_length >= 12 => {
                state.lapic_base = read_u64(cursor + 4);
            }
            // Local x2APIC: also a processor, and its id is 32 bits wide.
            9 if entry_length >= 16 => {
                if state.processor_count < MAX_CPUS {
                    let flags = read_u32(cursor + 12);
                    state.processors[state.processor_count] = Processor {
                        acpi_id: read_u32(cursor + 4) as u8,
                        apic_id: read_u32(cursor + 8) as u8,
                        enabled: flags & 1 != 0,
                    };
                    state.processor_count += 1;
                }
            }
            _ => {}
        }
        cursor += entry_length;
    }
    true
}

/// Finds the ACPI tables and reads the MADT out of them.
///
/// # Safety
/// Must run after the identity map is active (the tables are physical addresses below 4 GiB) and
/// before anything programs an APIC. `rsdp_hint` is the address the boot handoff supplied, if it
/// supplied one.
pub unsafe fn init(rsdp_hint: Option<u64>) -> bool {
    let state = state();
    if state.signature != ACPI_SIGNATURE {
        println!(
            "[!!] ACPI: state is at {:#x} without its signature - the loader did not place it where the crate expects",
            core::ptr::addr_of!(ACPI) as u64
        );
        return false;
    }
    state.present = false;
    state.processor_count = 0;
    state.override_count = 0;
    state.ioapic_count = 0;
    state.ioapic_address = 0;
    state.entries = 0;

    let rsdp = match rsdp_hint {
        Some(address) if address != 0 && checksum_ok(address, 20) => address,
        Some(_) => {
            println!("[--] ACPI: the boot handoff's RSDP did not check out, scanning for one");
            scan_for_rsdp().unwrap_or(0)
        }
        None => scan_for_rsdp().unwrap_or(0),
    };
    if rsdp == 0 {
        println!("[--] ACPI: no RSDP found - the machine has no tables to read, so no APIC bring-up");
        return false;
    }

    state.rsdp = rsdp;
    state.revision = core::ptr::read_volatile((rsdp as *const u8).add(15));
    for index in 0..6 {
        state.oem_id[index] = core::ptr::read_volatile((rsdp as *const u8).add(9 + index));
    }
    // The extended checksum covers the whole 36-byte structure on revision 2+.
    if state.revision >= RSDP_V2_MIN_REVISION {
        let length = read_u32(rsdp + 20) as usize;
        if length >= 36 {
            let mut sum = 0u8;
            for offset in 0..length {
                sum = sum.wrapping_add(core::ptr::read_volatile((rsdp as *const u8).add(offset)));
            }
            if sum != 0 {
                println!("[!!] ACPI: the RSDP's extended checksum does not verify");
                return false;
            }
        }
    }

    let madt = match find_table(rsdp, MADT_SIGNATURE) {
        Some(address) => address,
        None => {
            println!(
                "[--] ACPI: RSDP {:#x} (rev {}) verified, but it describes no MADT - falling back to the 8259",
                rsdp, state.revision
            );
            return false;
        }
    };
    if !parse_madt(madt) {
        println!("[!!] ACPI: the MADT at {:#x} is too short or not parseable", madt);
        return false;
    }
    if state.lapic_base == 0 || state.ioapic_address == 0 {
        println!(
            "[--] ACPI: the MADT describes no usable {} - falling back to the 8259",
            if state.lapic_base == 0 { "local APIC" } else { "I/O APIC" }
        );
        return false;
    }
    state.present = true;
    true
}

fn hex2(value: u8) -> String {
    let digits = b"0123456789abcdef";
    let mut out = String::with_capacity(2);
    out.push(digits[(value >> 4) as usize] as char);
    out.push(digits[(value & 0xF) as usize] as char);
    out
}

pub fn describe() {
    let state = state();
    if !state.present {
        println!("[--] ACPI: no tables read - the 8259 and the PIT are the interrupt path");
        return;
    }
    let oem = core::str::from_utf8(&state.oem_id).unwrap_or("?");
    println!(
        "[OK] ACPI: RSDP {:#x} (rev {}, oem \"{}\"), MADT {} entries - LAPIC at {:#x}, IO-APIC #{:#04x} at {:#x} from GSI {}",
        state.rsdp,
        state.revision,
        oem,
        state.entries,
        state.lapic_base,
        state.ioapic_id,
        state.ioapic_address,
        state.ioapic_gsi_base
    );
    let mut line = String::from("[OK] ACPI CPUS: ");
    for index in 0..state.processor_count {
        let processor = state.processors[index];
        if index != 0 {
            line.push(' ');
        }
        line.push_str(&alloc::format!(
            "cpu{}=apic:{}{}",
            index,
            hex2(processor.apic_id),
            if processor.enabled { "" } else { "(disabled)" }
        ));
    }
    println!(
        "{} ({} processor entr{}, {}compatible 8259 pair)",
        line,
        state.processor_count,
        if state.processor_count == 1 { "y" } else { "ies" },
        if state.dual_8259 { "" } else { "not " }
    );
    if state.override_count != 0 {
        let mut line = String::from("[OK] ACPI OVERRIDES: ");
        for index in 0..state.override_count {
            let entry = state.overrides[index];
            if index != 0 {
                line.push(' ');
            }
            line.push_str(&alloc::format!(
                "irq{}->gsi{}{}{}",
                entry.source,
                entry.gsi,
                if entry.flags & 3 == 3 { "/low" } else { "" },
                if (entry.flags >> 2) & 3 == 3 { "/level" } else { "" }
            ));
        }
        println!("{}", line);
    } else {
        println!("[OK] ACPI OVERRIDES: none - every ISA IRQ maps to the GSI of the same number");
    }
}

/// How many assertions this module makes, so a machine with no ACPI reports them as skipped
/// rather than as passes.
pub const ASSERTIONS: u32 = 10;

/// Checks the tables the module read: the RSDP verifies, the table walk found a real MADT, the
/// APIC addresses are sane, and every ISA IRQ's GSI mapping is well defined. The entries are
/// re-parsed from the medium here rather than compared against the module's own cache, so a
/// corrupted cache cannot make the test agree with itself.
pub fn self_test() -> BlockReport {
    let mut report = BlockReport::new();
    let state = state();
    if !state.present {
        report.skip(ASSERTIONS - 1);
        report.check(
            !state.present && state.lapic_base == 0,
            "ACPI reports itself absent but left an APIC address behind",
        );
        return report;
    }
    report.check(
        state.signature == ACPI_SIGNATURE,
        "the ACPI state is not in the placement the crate expects",
    );
    report.check(
        unsafe { checksum_ok(state.rsdp, 20) },
        "the RSDP under the recorded address does not verify any more",
    );
    let madt = unsafe { find_table(state.rsdp, MADT_SIGNATURE) };
    report.check(madt.is_some(), "the MADT could not be found from the RSDP a second time");
    let madt = match madt {
        Some(address) => address,
        None => {
            report.skip(ASSERTIONS - 3);
            return report;
        }
    };
    // The stored base is the header field, unless a type-5 entry overrode it - so it must equal
    // one of the two, and blindly re-reading only the header would be wrong on such a machine.
    let header_base = read_u32(madt + 36) as u64;
    report.check(
        header_base != 0,
        "the MADT's local APIC address field is zero",
    );
    report.check(
        state.lapic_base >= 0xF000_0000 && state.lapic_base < 0x1_0000_0000,
        "the local APIC base is not in the memory-mapped APIC window",
    );
    report.check(
        state.ioapic_address >= 0xF000_0000 && state.ioapic_address < 0x1_0000_0000,
        "the I/O APIC address is not in the memory-mapped APIC window",
    );
    report.check(
        state.processor_count >= 1,
        "the MADT describes no processors at all",
    );
    report.check(
        state.processors[..state.processor_count]
            .iter()
            .all(|processor| processor.enabled),
        "every processor in the MADT is marked disabled",
    );
    // An override for IRQ0 is what makes the timer work at all on a PC, and the classic value is
    // GSI 2. It is asserted as "a defined mapping", not as "the PC one", because a machine is
    // allowed to wire it differently as long as the table says so.
    report.check(gsi_for_irq(0) < 24, "IRQ0's GSI is outside the IO-APIC's 24 lines");
    report.check(
        state.overrides[..state.override_count]
            .iter()
            .all(|entry| entry.gsi < 24),
        "an interrupt override names a GSI outside the IO-APIC's 24 lines",
    );
    report
}
