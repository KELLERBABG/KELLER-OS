//! Interrupt descriptor table, entry stubs and dispatch.
//!
//! Design notes:
//!
//! * every gate uses **IST1**, so the CPU always pushes SS:RSP and the frame layout is
//!   identical whether the interrupt came from ring 0 or ring 3 — and so a context switch
//!   can move a whole frame to a parked stack and resume it later without a second code path;
//! * the **syscall gate (0x80) is the one DPL-3 gate**. That is the whole point of a door: a
//!   ring-3 task can enter it and nothing else, and the frame it arrives with says `cs=0x1B`,
//!   which is the kernel's evidence that the caller really was a user task;
//! * the exception path branches on the same `cs` value. A fault taken in ring 3 is
//!   **contained** (the task is terminated, the kernel keeps running); a fault taken in ring 0
//!   still locks down, because a faulting kernel is a different kind of event entirely;
//! * the stubs save all fifteen general-purpose registers **and** XMM0-15 before calling
//!   into Rust. SSE2 is mandatory in the x86_64 ABI, so the compiler is free to use vector
//!   registers for block moves in ordinary kernel code; a handler that clobbered them
//!   would corrupt the interrupted computation;
//! * 5 CPU-pushed + 2 stub-pushed + 15 saved register slots = 22 qwords = 176 bytes, so
//!   with a 16-byte-aligned interrupt stack the `call` into Rust is ABI-aligned with no
//!   extra padding.

use crate::arch::gdt::{IST_INDEX, KERNEL_CODE_SELECTOR};
use crate::arch::pic;
use crate::panic::lockdown;
use crate::println;
use core::arch::global_asm;

pub const IRQ_BASE: u64 = 32;
pub const SYSCALL_VECTOR: u64 = 0x80;
/// Vectors the local APIC delivers rather than the 8259: the APIC timer, IPIs, the MSI window
/// and the spurious vector. They are gated exactly like everything else - an APIC vector that
/// had no gate would arrive as a double fault instead of an interrupt.
const APIC_TIMER_VECTOR: u64 = crate::arch::lapic::VECTOR_TIMER as u64;
const APIC_IPI_VECTOR: u64 = crate::arch::lapic::VECTOR_IPI as u64;
const MSI_VECTOR_BASE: u64 = crate::arch::lapic::VECTOR_MSI_BASE as u64;
const MSI_VECTOR_COUNT: u64 = crate::arch::lapic::VECTOR_MSI_COUNT as u64;
const SPURIOUS_VECTOR: u64 = crate::arch::lapic::VECTOR_SPURIOUS as u64;
const IDT_ENTRIES: usize = 256;

#[repr(C)]
pub struct InterruptFrame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    pub vector: u64,
    pub error_code: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

impl InterruptFrame {
    pub fn from_user(&self) -> bool {
        self.cs & 3 == 3
    }
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    attributes: u8,
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}

impl IdtEntry {
    const fn empty() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            attributes: 0,
            offset_mid: 0,
            offset_high: 0,
            reserved: 0,
        }
    }
}

#[repr(C, packed)]
struct IdtPointer {
    limit: u16,
    base: u64,
}

static mut IDT: [IdtEntry; IDT_ENTRIES] = [IdtEntry::empty(); IDT_ENTRIES];

/// Gate attributes: present, DPL 0, 64-bit interrupt gate. Interrupt (not trap) gates clear
/// IF on entry, so a handler — including the preemption switch — runs to completion without a
/// nested timer tick rewriting the frame it is working on.
const GATE_KERNEL: u8 = 0x8E;
/// Gate attributes for the syscall door: present, **DPL 3**, 64-bit interrupt gate. A ring-3
/// `int 0x80` passes the DPL check with this and only this vector; every other gate rejects it
/// with `#GP` before any handler runs.
const GATE_USER: u8 = 0xEE;

/// Parked frame the interrupt epilogue must resume instead of the interrupted one.
///
/// Written by the scheduler (`crate::proc`) from inside `interrupt_dispatch`, read and cleared
/// by the assembly below. It lives here because the code that consumes it is the shared
/// epilogue; keeping the hand-off in one symbol is what makes every switch — timer preemption,
/// task exit, fault containment — the same mechanism.
#[no_mangle]
pub static mut KOS_PENDING_SWITCH_RSP: u64 = 0;

/// Asks the epilogue to resume `parked_rsp` (the base of a parked interrupt frame) instead of
/// returning to the interrupted context. Ignored by everything except the shared epilogue.
pub fn request_switch(parked_rsp: u64) {
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(KOS_PENDING_SWITCH_RSP), parked_rsp);
    }
}

/// Reads the pending switch target (0 when none is armed); the self-test uses it to prove the
/// hand-off is cleared after every switch.
pub fn pending_switch() -> u64 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(KOS_PENDING_SWITCH_RSP)) }
}

pub type IrqHandler = fn(irq: u8);

const IRQ_COUNT: usize = 16;
static mut IRQ_HANDLERS: [Option<IrqHandler>; IRQ_COUNT] = [None; IRQ_COUNT];

/// Registers a handler for hardware IRQ `irq` (0-15, i.e. vectors 32-47).
pub fn register_irq(irq: u8, handler: IrqHandler) {
    if (irq as usize) < IRQ_COUNT {
        unsafe {
            let slot = core::ptr::addr_of_mut!(IRQ_HANDLERS[irq as usize]);
            *slot = Some(handler);
        }
    }
}

extern "C" {
    fn isr_default_noerr();
    fn isr_de();
    fn isr_ud();
    fn isr_nm();
    fn isr_mf();
    fn isr_mc();
    fn isr_xm();
    fn isr_df();
    fn isr_ts();
    fn isr_np();
    fn isr_ss();
    fn isr_gp();
    fn isr_pf();
    fn isr_ac();
    fn isr_cp();
    fn isr_vc();
    fn isr_sx();
    fn isr_syscall();
    fn isr_apic_timer();
    fn isr_apic_ipi();
    fn isr_msi0();
    fn isr_msi1();
    fn isr_msi2();
    fn isr_msi3();
    fn isr_spurious();
    fn isr_irq0();
    fn isr_irq1();
    fn isr_irq2();
    fn isr_irq3();
    fn isr_irq4();
    fn isr_irq5();
    fn isr_irq6();
    fn isr_irq7();
    fn isr_irq8();
    fn isr_irq9();
    fn isr_irq10();
    fn isr_irq11();
    fn isr_irq12();
    fn isr_irq13();
    fn isr_irq14();
    fn isr_irq15();
}

fn stub_for(vector: usize) -> unsafe extern "C" fn() {
    match vector {
        0 => isr_de,
        48 => isr_apic_timer,
        49 => isr_apic_ipi,
        80 => isr_msi0,
        81 => isr_msi1,
        82 => isr_msi2,
        83 => isr_msi3,
        255 => isr_spurious,
        6 => isr_ud,
        7 => isr_nm,
        8 => isr_df,
        10 => isr_ts,
        11 => isr_np,
        12 => isr_ss,
        13 => isr_gp,
        14 => isr_pf,
        16 => isr_mf,
        17 => isr_ac,
        18 => isr_mc,
        19 => isr_xm,
        21 => isr_cp,
        29 => isr_vc,
        30 => isr_sx,
        32 => isr_irq0,
        33 => isr_irq1,
        34 => isr_irq2,
        35 => isr_irq3,
        36 => isr_irq4,
        37 => isr_irq5,
        38 => isr_irq6,
        39 => isr_irq7,
        40 => isr_irq8,
        41 => isr_irq9,
        42 => isr_irq10,
        43 => isr_irq11,
        44 => isr_irq12,
        45 => isr_irq13,
        46 => isr_irq14,
        47 => isr_irq15,
        128 => isr_syscall,
        _ => isr_default_noerr,
    }
}

unsafe fn set_gate(vector: usize, handler: unsafe extern "C" fn(), attributes: u8) {
    let address = handler as usize as u64;
    let entry = &mut *core::ptr::addr_of_mut!(IDT[vector]);
    entry.offset_low = (address & 0xFFFF) as u16;
    entry.selector = KERNEL_CODE_SELECTOR;
    entry.ist = IST_INDEX;
    entry.attributes = attributes;
    entry.offset_mid = ((address >> 16) & 0xFFFF) as u16;
    entry.offset_high = ((address >> 32) & 0xFFFF_FFFF) as u32;
    entry.reserved = 0;
}

/// Debug view of one gate: (handler offset, selector, ist, attributes).
pub fn gate_info(vector: usize) -> (u64, u16, u8, u8) {
    unsafe {
        let entry = &*core::ptr::addr_of!(IDT[vector]);
        let offset = entry.offset_low as u64
            | ((entry.offset_mid as u64) << 16)
            | ((entry.offset_high as u64) << 32);
        (offset, entry.selector, entry.ist, entry.attributes)
    }
}

/// Address the dispatcher expects for a given vector's stub.
pub fn stub_address(vector: usize) -> u64 {
    stub_for(vector) as usize as u64
}

pub unsafe fn init() {
    // `.bss` is not guaranteed zeroed by the loader, so clear the handler table before
    // any gate can dispatch: a stale entry would be called as a function pointer.
    for slot in 0..IRQ_COUNT {
        *core::ptr::addr_of_mut!(IRQ_HANDLERS[slot]) = None;
    }
    core::ptr::write_volatile(core::ptr::addr_of_mut!(KOS_PENDING_SWITCH_RSP), 0);
    for vector in 0..IDT_ENTRIES {
        // The syscall vector is the only DPL-3 door in the table; everything else is a
        // kernel-only gate, which is what keeps a user task from reaching, say, `#DF` or the
        // timer stub to fake an interrupt frame.
        let attributes = if vector as u64 == SYSCALL_VECTOR {
            GATE_USER
        } else {
            GATE_KERNEL
        };
        set_gate(vector, stub_for(vector), attributes);
    }
    let pointer = IdtPointer {
        limit: (core::mem::size_of::<[IdtEntry; IDT_ENTRIES]>() - 1) as u16,
        base: core::ptr::addr_of!(IDT) as u64,
    };
    core::arch::asm!("lidt [{}]", in(reg) &pointer, options(nostack));
}

/// Loads the table this module built into *this* processor's IDTR.
///
/// An application processor needs this explicitly: IDTR does not follow `cr3`, so a processor
/// that came through the trampoline would take its first APIC interrupt with no table at all - a
/// triple fault rather than an interrupt. The table is shared and already built, so this is a
/// load and nothing else.
///
/// # Safety
/// Requires `init` to have run on the boot processor.
pub unsafe fn load() {
    let pointer = IdtPointer {
        limit: (core::mem::size_of::<[IdtEntry; IDT_ENTRIES]>() - 1) as u16,
        base: core::ptr::addr_of!(IDT) as u64,
    };
    core::arch::asm!("lidt [{}]", in(reg) &pointer, options(nostack));
}

/// Human-readable name for an exception vector; used by both the lockdown path and the ring-3
/// containment report.
pub fn exception_name(vector: u64) -> &'static str {
    match vector {
        0 => "#DE divide error",
        1 => "#DB debug",
        2 => "NMI",
        3 => "#BP breakpoint",
        4 => "#OF overflow",
        5 => "#BR bound range",
        6 => "#UD invalid opcode",
        7 => "#NM device not available",
        8 => "#DF double fault",
        10 => "#TS invalid TSS",
        11 => "#NP segment not present",
        12 => "#SS stack-segment fault",
        13 => "#GP general protection",
        14 => "#PF page fault",
        16 => "#MF x87 floating point",
        17 => "#AC alignment check",
        18 => "#MC machine check",
        19 => "#XM SIMD floating point",
        21 => "#CP control protection",
        29 => "#VC VMM communication",
        30 => "#SX security exception",
        _ => "reserved exception",
    }
}

unsafe fn handle_exception(frame: &InterruptFrame) {
    println!(
        "\n[!!] CPU EXCEPTION {} ({}) error={:#x} rip={:#018x} rsp={:#018x}",
        frame.vector,
        exception_name(frame.vector),
        frame.error_code,
        frame.rip,
        frame.rsp
    );
    if frame.vector == 14 {
        let address = crate::arch::cpu::read_cr2();
        println!(
            "     PAGE FAULT at {:#018x} ({}), cr3={:#018x}",
            address,
            match frame.error_code {
                code if code & 1 == 0 => "not present",
                code if code & 2 != 0 => "write",
                _ => "read",
            },
            crate::arch::cpu::read_cr3()
        );
        if frame.error_code & 1 == 0 {
            println!("     -> kernel dereferenced an unmapped address");
        }
    }
    if frame.vector == 8 {
        println!("     -> double fault: an exception handler itself faulted");
    }
    lockdown(exception_name(frame.vector));
}

unsafe fn handle_irq(irq: u8, frame: *mut InterruptFrame) {
    match irq {
        // The timer does double duty: it advances the clock and then gets the chance to
        // preempt the interrupted context. Preemption happens *here*, inside the interrupt,
        // because that is the only place a full CPU register set is already on the stack.
        0 => {
            crate::clock::on_tick();
            crate::proc::on_timer(frame);
        }
        4 => crate::serial::service_rx(),
        _ => {
            let handler = *core::ptr::addr_of!(IRQ_HANDLERS[irq as usize]);
            if let Some(handler) = handler {
                handler(irq);
            }
        }
    }
    pic::end_of_interrupt(irq);
}

/// Entry point shared by every stub.
///
/// The frame is handed over as a raw pointer: a context switch may move it to a parked stack
/// and resume a different task, so the dispatcher must not hold a Rust reference to it across
/// the switch (and `crate::proc` is the only code that knows which task the frame belongs to).
#[no_mangle]
pub unsafe extern "C" fn interrupt_dispatch(frame: *mut InterruptFrame) {
    let vector = (*frame).vector;
    match vector {
        0..=31 => {
            if (*frame).from_user() {
                // A user task faulting is an ordinary, expected event: the driver sandbox
                // exists precisely so that it happens.
                crate::proc::user_fault(frame);
            } else {
                handle_exception(&*frame)
            }
        }
        32..=47 => handle_irq((vector - IRQ_BASE) as u8, frame),
        vector if vector == SYSCALL_VECTOR => {
            if (*frame).from_user() {
                crate::proc::syscall(frame);
            } else {
                crate::syscall(&*frame);
            }
        }
        // APIC-delivered vectors. The APIC timer and IPIs are acknowledged here; the MSI window
        // belongs to the device layer, which counts and clears its own device's status.
        vector if vector == APIC_TIMER_VECTOR => {
            crate::arch::lapic::on_timer();
        }
        vector if vector == APIC_IPI_VECTOR => {
            crate::arch::lapic::on_ipi();
        }
        vector if vector >= MSI_VECTOR_BASE && vector < MSI_VECTOR_BASE + MSI_VECTOR_COUNT => {
            crate::arch::msi::on_vector(vector as u8);
        }
        // The spurious vector needs no EOI: there is no in-service bit behind it, and
        // acknowledging one is a documented way to destroy a real interrupt's state.
        vector if vector == SPURIOUS_VECTOR => crate::arch::lapic::on_spurious(),
        other => {
            let frame = &*frame;
            println!(
                "[!!] UNEXPECTED INTERRUPT VECTOR {} at rip={:#018x} (frame={:p}, cs={:#x}, rflags={:#x})",
                other, frame.rip, frame, frame.cs, frame.rflags
            );
            let words = frame as *const InterruptFrame as *const u64;
            println!(
                "     ist_top={:#x} dispatcher_rsp={:#x}",
                crate::arch::gdt::ist_top(),
                crate::arch::cpu::read_rsp()
            );
            for row in 0..3 {
                let base = row * 8;
                println!(
                    "     frame[{:02}..]: {:016x} {:016x} {:016x} {:016x} {:016x} {:016x} {:016x} {:016x}",
                    base,
                    *words.add(base),
                    *words.add(base + 1),
                    *words.add(base + 2),
                    *words.add(base + 3),
                    *words.add(base + 4),
                    *words.add(base + 5),
                    *words.add(base + 6),
                    *words.add(base + 7)
                );
            }
            lockdown("unexpected interrupt vector");
        }
    }
}

/// Used by the interrupt self-test to prove the gate chain works end to end.
pub unsafe fn raise_breakpoint() {
    core::arch::asm!("int3", options(nomem, nostack));
}

global_asm!(
    r#"
.section .text
.code64

/* ---- stubs without a CPU-pushed error code ---- */
.global isr_default_noerr
isr_default_noerr:
    pushq $0
    pushq $255
    jmp isr_common

.global isr_de
isr_de:
    pushq $0
    pushq $0
    jmp isr_common

.global isr_ud
isr_ud:
    pushq $0
    pushq $6
    jmp isr_common

.global isr_nm
isr_nm:
    pushq $0
    pushq $7
    jmp isr_common

.global isr_mf
isr_mf:
    pushq $0
    pushq $16
    jmp isr_common

.global isr_mc
isr_mc:
    pushq $0
    pushq $18
    jmp isr_common

.global isr_xm
isr_xm:
    pushq $0
    pushq $19
    jmp isr_common

/* ---- stubs where the CPU already pushed an error code ---- */
.global isr_df
isr_df:
    pushq $8
    jmp isr_common

.global isr_ts
isr_ts:
    pushq $10
    jmp isr_common

.global isr_np
isr_np:
    pushq $11
    jmp isr_common

.global isr_ss
isr_ss:
    pushq $12
    jmp isr_common

.global isr_gp
isr_gp:
    pushq $13
    jmp isr_common

.global isr_pf
isr_pf:
    pushq $14
    jmp isr_common

.global isr_ac
isr_ac:
    pushq $17
    jmp isr_common

.global isr_cp
isr_cp:
    pushq $21
    jmp isr_common

.global isr_vc
isr_vc:
    pushq $29
    jmp isr_common

.global isr_sx
isr_sx:
    pushq $30
    jmp isr_common

/* ---- hardware IRQs 0-15 ---- */
.global isr_irq0
isr_irq0:
    pushq $0
    pushq $32
    jmp isr_common
.global isr_irq1
isr_irq1:
    pushq $0
    pushq $33
    jmp isr_common
.global isr_irq2
isr_irq2:
    pushq $0
    pushq $34
    jmp isr_common
.global isr_irq3
isr_irq3:
    pushq $0
    pushq $35
    jmp isr_common
.global isr_irq4
isr_irq4:
    pushq $0
    pushq $36
    jmp isr_common
.global isr_irq5
isr_irq5:
    pushq $0
    pushq $37
    jmp isr_common
.global isr_irq6
isr_irq6:
    pushq $0
    pushq $38
    jmp isr_common
.global isr_irq7
isr_irq7:
    pushq $0
    pushq $39
    jmp isr_common
.global isr_irq8
isr_irq8:
    pushq $0
    pushq $40
    jmp isr_common
.global isr_irq9
isr_irq9:
    pushq $0
    pushq $41
    jmp isr_common
.global isr_irq10
isr_irq10:
    pushq $0
    pushq $42
    jmp isr_common
.global isr_irq11
isr_irq11:
    pushq $0
    pushq $43
    jmp isr_common
.global isr_irq12
isr_irq12:
    pushq $0
    pushq $44
    jmp isr_common
.global isr_irq13
isr_irq13:
    pushq $0
    pushq $45
    jmp isr_common
.global isr_irq14
isr_irq14:
    pushq $0
    pushq $46
    jmp isr_common
.global isr_irq15
isr_irq15:
    pushq $0
    pushq $47
    jmp isr_common

/* ---- system call gate ---- */
.global isr_syscall
isr_syscall:
    pushq $0
    pushq $128
    jmp isr_common

/* ---- local-APIC delivered vectors (timer, IPI, MSI, spurious) ---- */
.global isr_apic_timer
isr_apic_timer:
    pushq $0
    pushq $48
    jmp isr_common
.global isr_apic_ipi
isr_apic_ipi:
    pushq $0
    pushq $49
    jmp isr_common
.global isr_msi0
isr_msi0:
    pushq $0
    pushq $80
    jmp isr_common
.global isr_msi1
isr_msi1:
    pushq $0
    pushq $81
    jmp isr_common
.global isr_msi2
isr_msi2:
    pushq $0
    pushq $82
    jmp isr_common
.global isr_msi3
isr_msi3:
    pushq $0
    pushq $83
    jmp isr_common
.global isr_spurious
isr_spurious:
    pushq $0
    pushq $255
    jmp isr_common

/* ---- shared prologue/epilogue ---- */
.global isr_common
isr_common:
    /* Push order is chosen so that R15 lands at the lowest address, matching
     * `InterruptFrame` field order, and so that 5 (CPU) + 2 (stub) + 15 (here) pushes
     * leave RSP 16-byte aligned for the call. */
    pushq %rax
    pushq %rbx
    pushq %rcx
    pushq %rdx
    pushq %rsi
    pushq %rdi
    pushq %rbp
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15

    mov %rsp, %rdi              /* arg: pointer to InterruptFrame */

    /* Save XMM0-15 *below* the frame, so they stay outside `InterruptFrame` (inserting
     * them between the GPRs and the vector slot would shift every later field). SSE2
     * codegen is ABI-mandatory on x86_64, so ordinary kernel code may hold live values
     * here - a handler that clobbered them would corrupt the interrupted computation.
     * RSP is 16-byte aligned at this point; `movups` is used regardless so the save can
     * never fault on alignment.
     *
     * The 256 bytes below RSP are also the *start* of a parked frame: `crate::proc` parks
     * `frame - 256` .. `frame + 176` as one block and resumes it here, so the switch costs
     * a single `mov` of RSP and needs no separate restore path. */
    sub $256, %rsp
    movups %xmm0, 0(%rsp)
    movups %xmm1, 16(%rsp)
    movups %xmm2, 32(%rsp)
    movups %xmm3, 48(%rsp)
    movups %xmm4, 64(%rsp)
    movups %xmm5, 80(%rsp)
    movups %xmm6, 96(%rsp)
    movups %xmm7, 112(%rsp)
    movups %xmm8, 128(%rsp)
    movups %xmm9, 144(%rsp)
    movups %xmm10, 160(%rsp)
    movups %xmm11, 176(%rsp)
    movups %xmm12, 192(%rsp)
    movups %xmm13, 208(%rsp)
    movups %xmm14, 224(%rsp)
    movups %xmm15, 240(%rsp)

    call interrupt_dispatch

    /* Context switch. A handler may have parked the interrupted frame and armed a different
     * parked frame (timer preemption, a user task exiting, a faulted task being dropped).
     * The pointer is cleared *before* it is used, so a later entry into this epilogue can
     * never resurrect a stale frame. Interrupt gates run with IF=0 and the switch is taken
     * before any of the restored registers is read, so nothing can interleave. */
    movq KOS_PENDING_SWITCH_RSP(%rip), %rax
    testq %rax, %rax
    jz 1f
    movq $0, KOS_PENDING_SWITCH_RSP(%rip)
    movq %rax, %rsp
1:

    movups 0(%rsp), %xmm0
    movups 16(%rsp), %xmm1
    movups 32(%rsp), %xmm2
    movups 48(%rsp), %xmm3
    movups 64(%rsp), %xmm4
    movups 80(%rsp), %xmm5
    movups 96(%rsp), %xmm6
    movups 112(%rsp), %xmm7
    movups 128(%rsp), %xmm8
    movups 144(%rsp), %xmm9
    movups 160(%rsp), %xmm10
    movups 176(%rsp), %xmm11
    movups 192(%rsp), %xmm12
    movups 208(%rsp), %xmm13
    movups 224(%rsp), %xmm14
    movups 240(%rsp), %xmm15
    add $256, %rsp

    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rbp
    popq %rdi
    popq %rsi
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax

    add $16, %rsp               /* drop vector + error code */
    iretq
"#,
    options(att_syntax)
);
