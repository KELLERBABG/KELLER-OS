//! GDT, TSS and the interrupt stack.
//!
//! Two things are added over the previous plain five-entry GDT:
//!
//! * a **TSS with IST1** and every IDT gate using it. Without a dedicated interrupt
//!   stack, a fault taken on a bad kernel stack re-faults and the CPU triple-faults
//!   (which reaches the firmware and reboots) instead of reaching the lockdown path that
//!   is supposed to zero memory. `#PF`/`#GP`/`#DF` now always arrive on a known-good
//!   stack.
//! * an **I/O permission bitmap base beyond the TSS limit**, which makes the CPU deny
//!   every `in`/`out` from ring 3. That is the port-protection half of the driver-
//!   sandbox design in the canvas (card 07); granular per-capability grants need the
//!   real bitmap and land together with the ring-3 driver tasks.

use crate::arch::acpi;
use crate::panic;
use core::mem::size_of;

const KERNEL_CODE: u64 = 0x00AF_9A00_0000_FFFF;
const KERNEL_DATA: u64 = 0x00AF_9200_0000_FFFF;
const USER_CODE: u64 = 0x00AF_FA00_0000_FFFF;
const USER_DATA: u64 = 0x00AF_F200_0000_FFFF;

/// null, kcode, kdata, ucode, udata, then two entries per processor: one 16-byte task state
/// segment each. One descriptor per processor rather than one shared descriptor is not a
/// decoration: `ltr` marks the descriptor it loads *busy* in the table, so a second processor
/// loading the same selector takes #GP(0x28) - which, with no IDT loaded yet, is a triple fault
/// and a reboot. That is exactly what happened the first time this kernel started a second core.
const TSS_FIRST_INDEX: usize = 5;
const GDT_ENTRIES: usize = TSS_FIRST_INDEX + 2 * acpi::MAX_CPUS;
const IST_STACK_SIZE: usize = 16 * 1024;

#[repr(C, packed)]
struct DescriptorTablePointer {
    limit: u16,
    base: u64,
}

#[repr(C, packed)]
struct TaskStateSegment {
    reserved0: u32,
    rsp0: u64,
    rsp1: u64,
    rsp2: u64,
    reserved1: u64,
    ist: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    iomap_base: u16,
}

static mut GDT: [u64; GDT_ENTRIES] = [0; GDT_ENTRIES];

const fn empty_tss() -> TaskStateSegment {
    TaskStateSegment {
        reserved0: 0,
        rsp0: 0,
        rsp1: 0,
        rsp2: 0,
        reserved1: 0,
        ist: [0; 7],
        reserved2: 0,
        reserved3: 0,
        // Beyond the TSS limit => the CPU denies all ring-3 port I/O.
        iomap_base: 0xFFFF,
    }
}

static mut TSSES: [TaskStateSegment; acpi::MAX_CPUS] = [const { empty_tss() }; acpi::MAX_CPUS];

#[repr(C, align(16))]
struct InterruptStack([u8; IST_STACK_SIZE]);

/// One interrupt stack per processor. Every gate in this kernel switches to IST1, and the CPU
/// reads IST1 out of the TSS that the *current* task register names - so sharing one TSS means
/// sharing one stack, and two processors inside an IST gate at the same time would share it.
static mut IST_STACKS: [InterruptStack; acpi::MAX_CPUS] =
    [const { InterruptStack([0; IST_STACK_SIZE]) }; acpi::MAX_CPUS];

/// The selector a given processor has to load its own task state segment with.
pub fn tss_selector(cpu: usize) -> u16 {
    ((TSS_FIRST_INDEX + 2 * cpu) << 3) as u16
}

/// Points `cpu`'s task state segment at `cpu`'s own interrupt stack. Done from the processor
/// that owns it, before its task register is loaded.
unsafe fn prepare_stack(cpu: usize) {
    let top = core::ptr::addr_of!(IST_STACKS[cpu]) as u64 + IST_STACK_SIZE as u64;
    let tss = &mut *core::ptr::addr_of_mut!(TSSES[cpu]);
    tss.ist[0] = top;
    // Ring 3 entries will switch to this stack once user tasks exist.
    tss.rsp0 = top;
}

/// Writes one processor's 16-byte task state segment descriptor across its two 8-byte slots.
fn write_tss_descriptor(gdt: &mut [u64; GDT_ENTRIES], cpu: usize, base: u64, limit: u64) {
    let low = (limit & 0xFFFF)
        | ((base & 0x00FF_FFFF) << 16)
        | (0x89u64 << 40) // type: *available* 64-bit TSS; the CPU sets the busy bit on `ltr`
        | ((limit >> 16) << 48)
        | (((base >> 24) & 0xFF) << 56);
    gdt[TSS_FIRST_INDEX + 2 * cpu] = low;
    gdt[TSS_FIRST_INDEX + 2 * cpu + 1] = (base >> 32) & 0xFFFF_FFFF;
}

unsafe fn load_table() {
    let pointer = DescriptorTablePointer {
        limit: (size_of::<[u64; GDT_ENTRIES]>() - 1) as u16,
        base: core::ptr::addr_of!(GDT) as u64,
    };
    core::arch::asm!("lgdt [{}]", in(reg) &pointer, options(nostack));
}

/// Reloads the data segments so the descriptor caches pick up the table. CS needs no far jump:
/// the bootstrap GDT (src/boot.rs) already places kernel code at 0x08 with the same attributes
/// this table installs, so the cached descriptor stays valid across the reload.
unsafe fn reload_data_segments() {
    core::arch::asm!(
        "mov ds, {sel}",
        "mov es, {sel}",
        "mov fs, {sel}",
        "mov gs, {sel}",
        "mov ss, {sel}",
        sel = in(reg) 0x10u16,
        options(nomem, nostack)
    );
}

unsafe fn load_task_register(cpu: usize) {
    core::arch::asm!("ltr ax", in("ax") tss_selector(cpu), options(nomem, nostack));
}

pub unsafe fn init() {
    let tss_limit = (size_of::<TaskStateSegment>() - 1) as u64;
    let gdt = &mut *core::ptr::addr_of_mut!(GDT);
    gdt[0] = 0;
    gdt[1] = KERNEL_CODE;
    gdt[2] = KERNEL_DATA;
    gdt[3] = USER_CODE;
    gdt[4] = USER_DATA;
    // Every processor's descriptor is built here, even though only this one loads its task
    // register now: an application processor must not have to write into a table that other
    // processors are already running on.
    for cpu in 0..acpi::MAX_CPUS {
        let base = core::ptr::addr_of!(TSSES[cpu]) as u64;
        write_tss_descriptor(gdt, cpu, base, tss_limit);
        prepare_stack(cpu);
    }

    load_table();
    reload_data_segments();
    load_task_register(0);

    // The interrupt stacks must be scrubbed on panic like any other secret holder. One region
    // covers all of them: they are one array, which is also why the region count does not grow
    // with the number of processors.
    panic::register_scrub_region(
        core::ptr::addr_of!(IST_STACKS) as u64,
        size_of::<[InterruptStack; acpi::MAX_CPUS]>() as u64,
    );
}

/// Adopts this table, and `cpu`'s own task state segment, on a processor that is not running on
/// them - an application processor that has just come through the trampoline, which carries a
/// three-entry table built for nothing but the long-mode transition.
///
/// CS needs no far jump for the same reason `init` does not need one: the trampoline puts kernel
/// code at the same selector with the same attributes, so the cached descriptor stays valid.
///
/// `cpu` is the processor's own index, and it has to be its own: it loads a task state segment
/// that no other processor has loaded, because loading one marks its descriptor busy. Its
/// interrupt stack is the one indexed by the same number, so the IST the IDT's gates switch to
/// is this processor's and nobody else's.
///
/// # Safety
/// Ring 0 only, with the table reachable - which it is as soon as the trampoline has loaded the
/// kernel's `cr3`.
pub unsafe fn adopt(cpu: usize) {
    prepare_stack(cpu);
    load_table();
    reload_data_segments();
    load_task_register(cpu);
}

/// Selector values used when building IDT gates.
pub const KERNEL_CODE_SELECTOR: u16 = 0x08;
/// Ring-3 code selector: GDT index 3 with RPL 3 (0x18 | 3). An `iretq` to this CS is what
/// moves a task to CPL 3.
pub const USER_CODE_SELECTOR: u16 = 0x1B;
/// Ring-3 data selector: GDT index 4 with RPL 3 (0x20 | 3); also what `ss` must be on a
/// ring-3 frame.
pub const USER_DATA_SELECTOR: u16 = 0x23;
/// IST index (1-based in the IDT `ist` field) used by every gate.
pub const IST_INDEX: u8 = 1;

/// Descriptor privilege level of one GDT entry, or 0xFF when the selector is outside the
/// table. Used by the ring-3 self-test to read the privilege of the selectors back out of the
/// live table instead of trusting the constants.
pub fn selector_dpl(selector: u16) -> u8 {
    let index = (selector >> 3) as usize;
    if index >= GDT_ENTRIES {
        return 0xFF;
    }
    unsafe { (((*core::ptr::addr_of!(GDT))[index] >> 45) as u8) & 3 }
}

/// True when the I/O permission bitmap is placed beyond the TSS limit, which makes the CPU
/// deny every `in`/`out` from ring 3 (SDM vol. 1, 19.5.2: with a bit-map base beyond the
/// limit, all ports are treated as denied). This is the port half of the driver sandbox: a
/// ring-3 driver's only way to a port is a kernel-mediated capability.
pub fn port_io_denied() -> bool {
    let tss_limit = (size_of::<TaskStateSegment>() - 1) as u64;
    unsafe { (*core::ptr::addr_of!(TSSES[0])).iomap_base as u64 > tss_limit }
}

/// TSS ring-0 stack pointer, which a gate without an IST would switch to on a ring-3 entry.
/// Every gate here specifies IST1 instead, so this is reported for completeness (and would be
/// the value to program if the gate design ever drops the IST).
pub fn ring0_stack_top() -> u64 {
    unsafe { (*core::ptr::addr_of!(TSSES[0])).rsp0 }
}

pub fn ist_stack_size() -> usize {
    IST_STACK_SIZE
}

/// Current IST1 top of one processor, so interrupt frames can be checked against the stack the
/// CPU actually used - which on a multiprocessor machine is a per-processor question.
pub fn ist_top_of(cpu: usize) -> u64 {
    unsafe { (*core::ptr::addr_of!(TSSES[cpu])).ist[0] }
}

/// IST1 top of the boot processor, which is the only one the boot path can be inside.
pub fn ist_top() -> u64 {
    ist_top_of(0)
}
