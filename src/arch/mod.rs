//! x86_64 architecture layer: descriptor tables, interrupts, ACPI/APIC and the legacy PIC/PIT.
//!
//! Everything privileged and machine-specific lives here so the rest of the kernel can
//! stay portable-in-principle and testable through the self-test harness.
pub mod acpi;
pub mod ahci;
pub mod cpu;
pub mod gdt;
pub mod idt;
pub mod ioapic;
pub mod lapic;
pub mod msi;
pub mod paging;
pub mod pic;
pub mod ps2;
pub mod smp;

/// Brings up descriptor tables, the interrupt controller, the timer and input devices.
///
/// AHCI is not initialised here either: a disk is not part of the machine's baseline, and its
/// bring-up belongs next to the network adapter's, after PCI has been enumerated.
///
/// Paging is not initialised here: `paging::init` only reads the boot tables back, and doing it
/// as its own boot step keeps its report line adjacent to the GDT one it depends on.
///
/// # Safety
/// Must run once, on the boot CPU, after the heap and serial console exist (handlers
/// report through them) and before interrupts are enabled.
pub unsafe fn init() {
    gdt::init();
    idt::init();
    pic::init();
    // PS/2 last: it needs the remapped PIC to unmask the mouse line on the slave, and it
    // leaves both devices enabled before the timer ever fires.
    ps2::init();
}
