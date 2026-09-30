//! The I/O APIC: ISA and PCI interrupt lines to vectors, and the end of the 8259's involvement.
//!
//! The 8259 pair is a pair of 8-line controllers that can only be told "vector 32-47" and can
//! only deliver to one processor. The I/O APIC holds one redirection entry per line, each of
//! which names a vector, a destination processor, a polarity and a trigger mode - and each of
//! which can be masked on its own. Once the kernel owns it, two things become visible:
//!
//! * **the MADT's interrupt-source overrides are load-bearing.** On a PC, IRQ0 is wired to
//!   GSI 2, not GSI 0, and a kernel that programs entry 0 because "IRQ0 is GSI 0" gets a timer
//!   that never fires. `acpi::gsi_for_irq` is what is consulted here; the entry number written
//!   is the GSI, never the IRQ.
//! * **the switch-over is verifiable from both ends.** The 8259 is masked in its own IMR *and*
//!   the local APIC's LINT0 is masked (which is the ExtINT path a PIC-delivered interrupt would
//!   have to use), so a tick that still arrives can only have come through this controller.
//!   The self-test also checks that the entry reads back, and counts what was delivered.
//!
//! Vectors 32-47 are kept for the lines, exactly as the 8259 delivered them: `idt`'s stubs, the
//! timer path and the PS/2 and serial handlers do not know which controller is underneath, and
//! the switch-over changes the delivery path without changing a single handler.
//!
//! What is *not* here: MSI. A device with an MSI capability writes its own message and needs no
//! IO-APIC entry at all - `arch::msi` is that path, and it is the one the NIC uses.

use crate::arch::{acpi, lapic};
use crate::block::BlockReport;
use crate::println;
use core::sync::atomic::{AtomicU64, Ordering};

/// Lines on the IO-APIC this kernel programs. The version register says how many there are.
pub const LINES: usize = 24;
/// First vector an ISA IRQ is routed to, which must match `idt`'s IRQ stubs.
const VECTOR_BASE: u8 = 32;

const IOREGSEL: u32 = 0x00;
const IOWIN: u32 = 0x10;
const REG_ID: u32 = 0x00;
const REG_VERSION: u32 = 0x01;
const REG_REDIRECT_BASE: u32 = 0x10;

/// Redirection entry bits, all in the low 32-bit half except the destination.
const VECTOR_MASK: u64 = 0xFF;
const DELIVERY_MODE_FIXED: u64 = 0 << 8;
const DEST_MODE_PHYSICAL: u64 = 0 << 11;
const POLARITY_LOW: u64 = 1 << 13;
const TRIGGER_LEVEL: u64 = 1 << 15;
const MASKED: u64 = 1 << 16;
const DEST_ID_SHIFT: u64 = 56;
/// Read-only bits: delivery status (bit 12) and remote IRR (bit 14) change on their own, so a
/// read-back comparison has to ignore them.
const RO_BITS: u64 = (1 << 12) | (1 << 14);

/// Signature that keeps this module's state in `.data` (the loader does not zero `.bss`).
const IOAPIC_SIGNATURE: u64 = 0x4B45_4C4C_494F_4101; // "KELLIOA\x01"

struct State {
    signature: u64,
    present: bool,
    address: u64,
    id: u8,
    version: u8,
    /// Lines the version register claims, i.e. how many entries the controller has.
    lines: u32,
    /// Vector programmed for each GSI, or 0 when the entry was never touched.
    routed: [u8; LINES],
    /// Per-line flags as programmed: bit 0 level, bit 1 active low, bit 2 masked.
    flags: [u8; LINES],
    /// GSI each ISA IRQ was routed to (0xFFFF when unrouted), for the reports.
    irq_gsi: [u16; 16],
    /// The 8259's interrupt mask registers as this module left them.
    masked_8259: (u8, u8),
}

impl State {
    const fn empty() -> Self {
        Self {
            signature: IOAPIC_SIGNATURE,
            present: false,
            address: 0,
            id: 0,
            version: 0,
            lines: 0,
            routed: [0; LINES],
            flags: [0; LINES],
            irq_gsi: [0xFFFF; 16],
            masked_8259: (0, 0),
        }
    }
}

static mut STATE: State = State::empty();
/// Interrupts acknowledged per ISA IRQ since the switch-over. The timer's counter is the one
/// that matters: it is the evidence that the entry is not merely programmed, but delivering.
static DELIVERED: [AtomicU64; 16] = [const { AtomicU64::new(0) }; 16];
static EOIS: AtomicU64 = AtomicU64::new(0);

fn state() -> &'static mut State {
    unsafe { &mut *core::ptr::addr_of_mut!(STATE) }
}

fn reg_write(index: u32, value: u32) {
    let address = state().address;
    unsafe {
        core::ptr::write_volatile((address + IOREGSEL as u64) as *mut u32, index);
        core::ptr::write_volatile((address + IOWIN as u64) as *mut u32, value);
    }
}

fn reg_read(index: u32) -> u32 {
    let address = state().address;
    unsafe {
        core::ptr::write_volatile((address + IOREGSEL as u64) as *mut u32, index);
        core::ptr::read_volatile((address + IOWIN as u64) as *const u32)
    }
}

fn write_entry(gsi: usize, low: u32, high: u32) {
    let base = REG_REDIRECT_BASE + (gsi as u32) * 2;
    reg_write(base, low);
    reg_write(base + 1, high);
}

/// Reads one redirection entry back out of the controller, as a 64-bit value.
pub fn read_entry(gsi: usize) -> u64 {
    if !state().present || gsi >= LINES {
        return 0;
    }
    let base = REG_REDIRECT_BASE + (gsi as u32) * 2;
    let low = reg_read(base) as u64;
    let high = reg_read(base + 1) as u64;
    (high << 32) | low
}

pub fn vector_for_gsi(gsi: usize) -> u8 {
    if gsi < LINES {
        state().routed[gsi]
    } else {
        0
    }
}

pub fn live() -> bool {
    state().present && state().signature == IOAPIC_SIGNATURE
}

pub fn address() -> u64 {
    state().address
}

pub fn version() -> u8 {
    state().version
}

pub fn lines() -> u32 {
    state().lines
}

pub fn gsi_for_irq(irq: u8) -> Option<u32> {
    if irq as usize >= 16 {
        return None;
    }
    let gsi = state().irq_gsi[irq as usize];
    if gsi == 0xFFFF {
        None
    } else {
        Some(gsi as u32)
    }
}

pub fn delivered(irq: u8) -> u64 {
    if (irq as usize) < 16 {
        DELIVERED[irq as usize].load(Ordering::Relaxed)
    } else {
        0
    }
}

pub fn eois() -> u64 {
    EOIS.load(Ordering::Relaxed)
}

/// Programs one redirection entry. `masked` and the flag bits are what the entry ends up with;
/// nothing about the previous contents is preserved, because there is nothing to preserve.
fn program(gsi: usize, vector: u8, dest: u8, level: bool, active_low: bool, masked: bool) {
    let mut low = vector as u64 & VECTOR_MASK;
    low |= DELIVERY_MODE_FIXED | DEST_MODE_PHYSICAL;
    if active_low {
        low |= POLARITY_LOW;
    }
    if level {
        low |= TRIGGER_LEVEL;
    }
    if masked {
        low |= MASKED;
    }
    write_entry(gsi, low as u32, ((dest as u64) << DEST_ID_SHIFT >> 32) as u32);

    let state = state();
    if gsi < LINES {
        state.routed[gsi] = vector;
        let mut flags = 0u8;
        if level {
            flags |= 1;
        }
        if active_low {
            flags |= 2;
        }
        if masked {
            flags |= 4;
        }
        state.flags[gsi] = flags;
    }
}

/// Which ISA IRQ a GSI's entry belongs to, if any.
fn gsi_owner(gsi: u32) -> Option<u8> {
    let state = state();
    (0..16u8).find(|irq| state.irq_gsi[*irq as usize] as u32 == gsi)
}

/// Routes ISA IRQ `irq` to its vector through the GSI the MADT names, honoring the polarity and
/// trigger mode from the overrides. Returns the GSI it used.
///
/// Two lines are refused rather than programmed:
///
/// * **IRQ2**, the 8259's cascade input. It is not a device line - it is how the slave 8259's
///   interrupts reach the master - so it has nothing to route once the ISA lines go through the
///   IO-APIC one at a time.
/// * any line whose GSI is already another line's. On this machine that is the same conflict
///   seen from the other side: IRQ2's identity mapping would be GSI 2, which is where the table
///   puts the timer, and programming it would replace the timer's entry with a masked one. The
///   first version of this code did exactly that and the timer stopped.
unsafe fn route_irq(irq: u8, dest: u8, masked: bool) -> Option<u32> {
    if irq as usize >= 16 || irq == 2 {
        return None;
    }
    let mut gsi = acpi::gsi_for_irq(irq);
    // A PC wires IRQ0 to GSI 2 and the MADT is required to say so, but a machine whose table
    // omits the override still has the timer on GSI 2 (QEMU's I/O APIC remaps pin 0 to pin 2
    // for exactly this reason). Programming it anyway turns a missing table entry into a timer
    // that still works.
    if irq == 0 && !acpi::has_override(0) {
        gsi = 2;
    }
    if gsi as usize >= LINES {
        return None;
    }
    match gsi_owner(gsi) {
        Some(owner) if owner != irq => return None,
        _ => {}
    }
    let (active_low, level) = acpi::irq_flags(irq);
    program(gsi as usize, VECTOR_BASE + irq, dest, level, active_low, masked);
    state().irq_gsi[irq as usize] = gsi as u16;
    Some(gsi)
}

/// Unmasks ISA IRQ `irq` on whichever controller owns it now. Called by `pic::unmask`, so the
/// PS/2 driver's "unmask the mouse line" keeps meaning the same thing after the switch.
pub unsafe fn unmask(irq: u8) {
    let dest = lapic::id();
    if let Some(gsi) = route_irq(irq, dest, false) {
        let _ = gsi;
    }
}

/// Masks ISA IRQ `irq` again, for a driver that found nothing behind the line.
pub unsafe fn mask(irq: u8) {
    let dest = lapic::id();
    if let Some(gsi) = route_irq(irq, dest, true) {
        let _ = gsi;
    }
}

/// Acknowledges an IO-APIC-delivered interrupt for `vector`.
///
/// For an edge-triggered entry this does nothing at all, and for a level-triggered one the
/// maskable EOI register is the explicit path - the local APIC's own EOI already broadcasts to
/// the IO-APIC (that broadcast is what the TMR bit in the APIC enables), so this is a second,
/// redundant release that QEMU and the specification both define as a no-op in that case.
pub fn end_of_interrupt(vector: u8) {
    if !state().present {
        return;
    }
    EOIS.fetch_add(1, Ordering::Relaxed);
    if vector < VECTOR_BASE {
        return;
    }
    let irq = vector - VECTOR_BASE;
    if (irq as usize) < 16 {
        DELIVERED[irq as usize].fetch_add(1, Ordering::Relaxed);
    }
    if state().version != 0x20 {
        // Version 0x11 has no EOI register; the APIC's broadcast is the only release.
        return;
    }
    // Only level-triggered entries need it, and only for a line this controller actually owns.
    let gsi = match gsi_for_irq(irq) {
        Some(gsi) => gsi as usize,
        None => return,
    };
    if gsi < LINES && state().flags[gsi] & 1 != 0 {
        reg_write(0x40, vector as u32);
    }
}

/// Reads the 8259's interrupt mask registers (used to carry the live lines over to the IO-APIC
/// instead of dropping them).
unsafe fn pic_masks() -> (u8, u8) {
    crate::arch::pic::masks()
}

/// Brings the I/O APIC up: reads its identity, carries every ISA line that the 8259 had live
/// over to a redirection entry, and masks the 8259 completely.
///
/// # Safety
/// Requires `arch::acpi::init` and `lapic::init` to have run, and interrupts to be disabled -
/// an interrupt delivered while the table is half-programmed would be routed by a half-written
/// entry. Must run before interrupts are enabled.
pub unsafe fn init() -> bool {
    let state = state();
    if state.signature != IOAPIC_SIGNATURE {
        println!(
            "[!!] IOAPIC: state is at {:#x} without its signature - the loader did not place it where the crate expects",
            core::ptr::addr_of!(STATE) as u64
        );
        return false;
    }
    state.present = false;
    state.routed = [0; LINES];
    state.flags = [0; LINES];
    state.irq_gsi = [0xFFFF; 16];
    for counter in DELIVERED.iter() {
        counter.store(0, Ordering::Relaxed);
    }
    EOIS.store(0, Ordering::Relaxed);

    let address = acpi::ioapic_address();
    if address == 0 {
        println!("[--] IOAPIC: the MADT named no I/O APIC - the 8259 stays the interrupt path");
        return false;
    }
    state.address = address;

    let identification = reg_read(REG_ID) >> 24;
    let version_word = reg_read(REG_VERSION);
    state.id = identification as u8;
    state.version = (version_word & 0xFF) as u8;
    state.lines = ((version_word >> 16) & 0xFF) + 1;
    if state.version != 0x11 && state.version != 0x20 {
        println!(
            "[!!] IOAPIC: version {:#04x} is neither 0x11 nor 0x20 - refusing to program an unknown controller",
            state.version
        );
        return false;
    }
    state.present = true;

    if state.lines < LINES as u32 {
        println!(
            "[!!] IOAPIC: the controller reports only {} lines - fewer than the {} this kernel programs",
            state.lines, LINES
        );
    }

    // Whatever the 8259 had live is what has to move; everything else is programmed masked so a
    // later `unmask` finds a sane entry rather than a zeroed one. Overridden IRQs go first,
    // because an override is an explicit statement about this machine and the identity mapping
    // for an unlisted IRQ is only a default.
    let (master, slave) = pic_masks();
    let dest = lapic::id();
    let mut live = 0u32;
    let mut moved = 0u32;
    let mut skipped = 0u32;
    for pass in 0..2u32 {
        for irq in 0..16u8 {
            if (pass == 0) != acpi::has_override(irq) {
                continue;
            }
            let was_open = if irq < 8 {
                master & (1 << irq) == 0
            } else {
                slave & (1 << (irq - 8)) == 0
            };
            if was_open {
                live += 1;
            }
            match route_irq(irq, dest, !was_open) {
                Some(_) => {
                    if was_open {
                        moved += 1;
                    }
                }
                None => {
                    if irq == 2 {
                        // The cascade line: not a device, and never routed.
                        continue;
                    }
                    skipped += 1;
                }
            }
        }
    }

    // The 8259 is masked in its own registers, and the local APIC's LINT0 was masked by
    // `lapic::init`, which is the ExtINT path a PIC-delivered interrupt would need. Both ends
    // closed is what makes "delivered after this point" mean "delivered by the IO-APIC".
    crate::arch::pic::mask_everything();
    let (master_after, slave_after) = pic_masks();
    state.masked_8259 = (master_after, slave_after);

    println!(
        "[OK] IOAPIC: #{:#04x} at {:#x} enabled (version {:#04x}, {} lines) - {} of {} live ISA lines routed to vectors {}-{}, 8259 masked (IMR {:#04x}/{:#04x})",
        state.id,
        address,
        state.version,
        state.lines,
        moved,
        live,
        VECTOR_BASE,
        VECTOR_BASE + 15,
        master_after,
        slave_after
    );
    if skipped != 0 {
        println!(
            "[--] IOAPIC: {} ISA line(s) were not routed because another line already owns their GSI (the IDT's vector for that line stays the one it was given)",
            skipped
        );
    }
    let mut line = alloc::string::String::from("[OK] IOAPIC ROUTES: ");
    let mut printed = 0;
    for irq in 0..16u8 {
        if let Some(gsi) = gsi_for_irq(irq) {
            if state.flags[gsi as usize] & 4 != 0 {
                continue;
            }
            if printed != 0 {
                line.push(' ');
            }
            line.push_str(&alloc::format!(
                "irq{}->gsi{}->v{}{}{}",
                irq,
                gsi,
                VECTOR_BASE + irq,
                if state.flags[gsi as usize] & 2 != 0 {
                    "/low"
                } else {
                    "/high"
                },
                if state.flags[gsi as usize] & 1 != 0 {
                    "/level"
                } else {
                    "/edge"
                }
            ));
            printed += 1;
        }
    }
    if printed == 0 {
        println!("[OK] IOAPIC ROUTES: none - no ISA line was open on the 8259");
    } else {
        println!("{}", line);
    }
    true
}

pub fn describe() {
    let state = state();
    if !state.present {
        println!("[--] IOAPIC: no I/O APIC - the 8259 is the interrupt path");
        return;
    }
    println!(
        "[IOAPIC] id={:#04x} version={:#04x} lines={} address={:#x} eois={}",
        state.id,
        state.version,
        state.lines,
        state.address,
        EOIS.load(Ordering::Relaxed)
    );
    for irq in 0..16u8 {
        if let Some(gsi) = gsi_for_irq(irq) {
            let gsi = gsi as usize;
            if gsi >= LINES {
                continue;
            }
            let entry = read_entry(gsi);
            println!(
                "[IOAPIC] irq{} gsi{} vector={:#04x} dest={:#04x} {}{} {} delivered={}",
                irq,
                gsi,
                (entry & VECTOR_MASK) as u8,
                (entry >> 40) as u8 & 0xFF,
                if entry & POLARITY_LOW != 0 { "low" } else { "high" },
                if entry & TRIGGER_LEVEL != 0 { "/level" } else { "/edge" },
                if entry & MASKED != 0 { "MASKED" } else { "open" },
                delivered(irq)
            );
        }
    }
    println!(
        "[IOAPIC] 8259 IMR left at {:#04x}/{:#04x} - a PIC-delivered interrupt has no path left",
        state.masked_8259.0, state.masked_8259.1
    );
}

// ---------------------------------------------------------------- self-test

/// How many assertions this module makes.
pub const ASSERTIONS: u32 = 13;

/// Checks the controller against what it was told to do, and against what has actually been
/// delivered since the switch-over.
pub fn self_test() -> BlockReport {
    let mut report = BlockReport::new();
    let state = state();
    if !state.present {
        report.skip(ASSERTIONS);
        return report;
    }
    report.check(
        state.signature == IOAPIC_SIGNATURE,
        "the IOAPIC state is not in the placement the crate expects",
    );
    report.check(
        state.address == acpi::ioapic_address() && state.address != 0,
        "the IOAPIC address is not the one the MADT names",
    );
    report.check(
        state.version == 0x11 || state.version == 0x20,
        "the IOAPIC reports a version this kernel does not know how to program",
    );
    report.check(
        state.lines == LINES as u32,
        "the controller reports a line count this kernel does not agree with",
    );
    report.check(
        state.id == acpi::ioapic_id(),
        "the IOAPIC's id is not the one the MADT names",
    );

    // Every entry this kernel routed has to read back as programmed. The read is a second trip
    // through IOREGSEL/IOWIN, so it is the device answering rather than the driver's cache.
    let dest = lapic::id();
    let mut routed = 0u32;
    let mut wrong: Option<u8> = None;
    for irq in 0..16u8 {
        if let Some(gsi) = gsi_for_irq(irq) {
            let gsi = gsi as usize;
            if gsi >= LINES {
                continue;
            }
            routed += 1;
            let entry = read_entry(gsi);
            let vector_ok = entry & VECTOR_MASK == (VECTOR_BASE + irq) as u64;
            let dest_ok = ((entry >> 40) & 0xFF) as u8 == dest;
            let mask_ok = (entry & MASKED != 0) == (state.flags[gsi] & 4 != 0);
            let (active_low, level) = acpi::irq_flags(irq);
            let flags_ok = (entry & POLARITY_LOW != 0) == active_low
                && (entry & TRIGGER_LEVEL != 0) == level;
            if !(vector_ok && dest_ok && mask_ok && flags_ok) {
                wrong = Some(irq);
            }
        }
    }
    report.check(routed != 0, "no ISA line was routed at all");
    report.check(
        wrong.is_none(),
        "a redirection entry does not read back as programmed",
    );

    // Writes have to land, not just be accepted: an independent line is masked and unmasked and
    // both states are read back out of the controller.
    let probe_gsi = 23usize;
    let saved = read_entry(probe_gsi);
    program(probe_gsi, 0x2F, dest, false, false, true);
    let masked_read = read_entry(probe_gsi);
    program(probe_gsi, 0x2F, dest, false, false, false);
    let open_read = read_entry(probe_gsi);
    write_entry(probe_gsi, saved as u32, (saved >> 32) as u32);
    report.check(
        masked_read & MASKED != 0 && open_read & MASKED == 0,
        "a redirection entry's mask bit did not follow a write",
    );
    report.check(
        masked_read & VECTOR_MASK == 0x2F && open_read & VECTOR_MASK == 0x2F,
        "a redirection entry's vector did not follow a write",
    );

    // The 8259 must be out of the picture at both ends, and the lines that were live on it must
    // have arrived here rather than being dropped in the move.
    let (master, slave) = unsafe { pic_masks() };
    report.check(
        master == 0xFF && slave == 0xFF,
        "the 8259's mask registers are not fully set - a PIC-delivered interrupt is still possible",
    );
    report.check(
        read_lint0_masked(),
        "the local APIC's LINT0 is not masked - the ExtINT path to the 8259 is still open",
    );

    // The timer is the line that proves the route end to end: on a machine whose MADT says
    // IRQ0 is GSI 2, this is also the check that GSI 2 is what was used.
    let timer_gsi = gsi_for_irq(0);
    report.check(
        timer_gsi == Some(acpi::gsi_for_irq(0)),
        "the timer's GSI is not the one the MADT names",
    );
    report.check(
        timer_gsi.map(|gsi| (gsi as usize) < LINES && read_entry(gsi as usize) & MASKED == 0)
            .unwrap_or(false),
        "the timer's redirection entry is masked",
    );
    report.check(
        delivered(0) != 0,
        "no timer interrupt was delivered through the IO-APIC - the entry is programmed but not working",
    );
    report
}

fn read_lint0_masked() -> bool {
    lapic::lint0_masked()
}
