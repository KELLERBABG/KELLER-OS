//! Legacy 8259 PIC and 8254 PIT.
//!
//! The kernel previously had no programmable interrupt controller, no timer and never
//! executed `sti`: `SYSTEM_TICKS` counted loop iterations and the first scheduler slot
//! halted the CPU permanently. The timer now runs at 100 Hz and drives `clock`, session
//! expiry, the scheduler and the shell.

use crate::port::{inb, io_wait, outb};
use crate::println;

const PIC1_COMMAND: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_COMMAND: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;

const ICW1_INIT: u8 = 0x11;
const ICW4_8086: u8 = 0x01;

const PIT_CHANNEL0: u16 = 0x40;
const PIT_COMMAND: u16 = 0x43;
const PIT_FREQUENCY_HZ: u32 = 1_193_182;

/// Vectors 32-47 (IRQ0-15) is the conventional remap target.
pub const IRQ_OFFSET_MASTER: u8 = 32;
pub const IRQ_OFFSET_SLAVE: u8 = 40;

pub unsafe fn init() {
    remap(IRQ_OFFSET_MASTER, IRQ_OFFSET_SLAVE);
    configure_pit(crate::clock::TICKS_PER_SECOND as u32);
    // Unmask only what the kernel actually services: IRQ0 timer, IRQ1 keyboard,
    // IRQ4 serial RX. Everything else stays masked until a driver owns it - the mouse line
    // (IRQ12) is unmasked by the PS/2 driver itself, through `unmask`.
    let master = !((1 << 0) | (1 << 1) | (1 << 4));
    set_masks(master, 0xFF);
    println!(
        "[OK] PIC REMAPPED TO {}-{} - TIMER {} Hz, KEYBOARD + SERIAL RX UNMASKED",
        IRQ_OFFSET_MASTER,
        IRQ_OFFSET_SLAVE + 7,
        crate::clock::TICKS_PER_SECOND
    );
}

pub unsafe fn remap(offset_master: u8, offset_slave: u8) {
    outb(PIC1_COMMAND, ICW1_INIT);
    io_wait();
    outb(PIC2_COMMAND, ICW1_INIT);
    io_wait();
    outb(PIC1_DATA, offset_master);
    io_wait();
    outb(PIC2_DATA, offset_slave);
    io_wait();
    outb(PIC1_DATA, 0x04); // slave is cascaded through IRQ2
    io_wait();
    outb(PIC2_DATA, 0x02); // cascade identity
    io_wait();
    outb(PIC1_DATA, ICW4_8086);
    io_wait();
    outb(PIC2_DATA, ICW4_8086);
    io_wait();
}

/// True while an I/O APIC and a local APIC are both live, in which case every IRQ-shaped call
/// below goes to the IO-APIC instead. This is what lets the PS/2 driver keep calling
/// `unmask(12)` across the switch-over without knowing that the controller underneath changed.
fn apic_owns_irqs() -> bool {
    crate::arch::lapic::live() && crate::arch::ioapic::live()
}

pub unsafe fn set_masks(master: u8, slave: u8) {
    outb(PIC1_DATA, master);
    outb(PIC2_DATA, slave);
}

/// The 8259's interrupt mask registers, read back from the hardware.
pub fn masks() -> (u8, u8) {
    unsafe { (inb(PIC1_DATA), inb(PIC2_DATA)) }
}

/// Masks every line on both controllers. The IO-APIC does this to the 8259 once it has taken
/// the live lines over: with the IMRs fully set there is no path from an ISA device to the CPU
/// through the old controller, which is what makes a later interrupt provably an APIC one.
pub unsafe fn mask_everything() {
    set_masks(0xFF, 0xFF);
    // A write to the IMR is not a queued operation; reading it back is what proves it landed.
    let (master, slave) = masks();
    if master != 0xFF || slave != 0xFF {
        println!(
            "[!!] PIC: the mask registers would not hold their value (IMR {:#04x}/{:#04x}) - an interrupt could still arrive through the 8259",
            master, slave
        );
    }
}

/// Masks one IRQ line again, for a driver that finds nothing behind it (a port with no device
/// cannot raise a real interrupt, and leaving the line open only invites a spurious one).
pub unsafe fn mask(irq: u8) {
    if apic_owns_irqs() {
        crate::arch::ioapic::mask(irq);
        return;
    }
    if irq < 8 {
        let current = inb(PIC1_DATA);
        outb(PIC1_DATA, current | (1 << irq));
    } else {
        let current = inb(PIC2_DATA);
        outb(PIC2_DATA, current | (1 << (irq - 8)));
    }
}

pub unsafe fn unmask(irq: u8) {
    if apic_owns_irqs() {
        crate::arch::ioapic::unmask(irq);
        return;
    }
    if irq < 8 {
        let current = inb(PIC1_DATA);
        outb(PIC1_DATA, current & !(1 << irq));
    } else {
        let current_master = inb(PIC1_DATA);
        outb(PIC1_DATA, current_master & !(1 << 2));
        let current = inb(PIC2_DATA);
        outb(PIC2_DATA, current & !(1 << (irq - 8)));
    }
}

/// Programs PIT channel 0 in mode 3 (square wave) at `hz`.
pub unsafe fn configure_pit(hz: u32) {
    let divisor = if hz == 0 {
        1
    } else {
        PIT_FREQUENCY_HZ / hz
    };
    let divisor = divisor.clamp(1, 0xFFFF);
    outb(PIT_COMMAND, 0x36); // channel 0, lo/hi byte, mode 3, binary
    outb(PIT_CHANNEL0, (divisor & 0xFF) as u8);
    outb(PIT_CHANNEL0, ((divisor >> 8) & 0xFF) as u8);
}

pub fn end_of_interrupt(irq: u8) {
    // A spurious IRQ7 is reported by the master without any interrupt in service, so
    // acknowledging it blindly would eat a real one.
    if irq == 15 {
        return;
    }
    if apic_owns_irqs() {
        // The IO-APIC entry is released first (a no-op for an edge-triggered line), then the
        // local APIC's EOI, which is what drops the in-service bit the CPU is holding.
        crate::arch::ioapic::end_of_interrupt(IRQ_OFFSET_MASTER + irq);
        crate::arch::lapic::eoi();
        return;
    }
    unsafe {
        if irq >= 8 {
            outb(PIC2_COMMAND, 0x20);
        }
        outb(PIC1_COMMAND, 0x20);
    }
}

/// Raw in-service register pair, exposed for the interrupt self-test.
pub fn in_service() -> (u8, u8) {
    unsafe { (inb(PIC1_COMMAND), inb(PIC2_COMMAND)) }
}
