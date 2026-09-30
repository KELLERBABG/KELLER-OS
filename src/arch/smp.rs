//! Symmetric multiprocessing: starting the other processors, and giving them work.
//!
//! An application processor starts life the way the boot processor did, minus the firmware: the
//! `STARTUP` IPI names a *page*, and the processor begins executing at the first byte of it in
//! real mode with paging off. So bring-up has three parts:
//!
//! * **a trampoline page.** It is assembled here (`global_asm!`, 16-bit then 64-bit) and copied
//!   to [`TRAMPOLINE_BASE`], where the STARTUP IPI's page number points. It carries a throwaway
//!   GDT of its own - built from compile-time constants, so no part of it has to be patched
//!   except the three values that cannot be known until runtime: this kernel's `cr3`, the
//!   processor's stack top, and its index. Those three live at fixed offsets, and the self-test
//!   checks the offsets the code uses against the offsets the linker gave the symbols, so a
//!   layout change is a failed boot line rather than a processor that never appears.
//! * **the bring-up sequence.** INIT, wait, STARTUP twice - the multiprocessor specification's
//!   sequence, with the delays taken from the PIT (which is why this runs after the timer is
//!   proven live). One processor is started at a time and waited for, so the single trampoline
//!   page is patched with that processor's values before each one is launched.
//! * **a mailbox, because a started processor is useless without work.** Each AP owns one job
//!   slot: the boot processor writes the payload, sets the state to *posted*, and waits for
//!   *done*; the AP polls its own slot, runs the workload, publishes the digest and its own
//!   identity, and goes back to polling. There is no lock, no allocator and no scheduler on the
//!   AP path, and every field the two sides share is ordered by an acquire/release pair on the
//!   job's own state word.
//!
//! **The workload is real cryptography** - ChaCha20 keystream over 4 KiB chunks chained through
//! SHA-256, [`KAT_ROUNDS`] rounds of it - and it is *pinned*: the same parameters were computed
//! a second time by an independent implementation (`dev-tools/smp_check.py`), so agreement is
//! evidence rather than a tautology. The live job repeats it with a fresh random key and requires
//! every core to agree, which is a claim no single core can satisfy on its own.
//!
//! **What this is not.** The APs run with interrupts masked and poll, because every gate in this
//! kernel switches to IST1 and there is exactly one IST stack: two processors inside an IST gate
//! at the same time would share it. Per-CPU TSS/IST descriptors are the prerequisite for
//! interrupt-driven APs (and for IPI-wake, which is the natural next step), and they are not
//! built yet. The honest consequence is that an idle AP costs a spinning emulated CPU.

use crate::arch::acpi;
use crate::arch::{cpu, gdt, idt, lapic};
use crate::block::BlockReport;
use crate::crypto;
use crate::println;
use core::arch::global_asm;
use core::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------- trampoline page

/// Where the trampoline is copied. A STARTUP IPI can only name a page, so the address has to be
/// page-aligned below 1 MiB - and 0x8000 is inside the identity map, well clear of the kernel
/// image at 1 MiB and of the EBDA at the top of conventional memory.
pub const TRAMPOLINE_BASE: u64 = 0x8000;
/// Bytes of the trampoline page that are actually copied (the rest of the page is untouched).
pub const TRAMPOLINE_LEN: u64 = 0x420;

/// Offsets inside the trampoline page the 16- and 64-bit code addresses directly. These are
/// written out again in the assembly below; `layout_is_intact` checks the two against each other.
const SLOT_GDT_POINTER: u64 = 0x300;
const SLOT_CR3: u64 = 0x310;
const SLOT_STACK: u64 = 0x318;
const SLOT_INDEX: u64 = 0x320;
const SLOT_LONG_MODE: u64 = 0x340;
const SLOT_GDT: u64 = 0x400;

extern "C" {
    static ap_trampoline_start: u8;
    static ap_trampoline_gdt_pointer: u8;
    static ap_trampoline_cr3: u8;
    static ap_trampoline_stack: u8;
    static ap_trampoline_index: u8;
    static ap_trampoline_long_mode: u8;
    static ap_trampoline_end: u8;
}

/// The entry point the trampoline jumps to once long mode is on. `cpu` is the processor's own
/// number, patched into the trampoline page before the IPI is sent - the same number the boot
/// processor polls this processor's slot under, and the same number its APIC record and its
/// interrupt stack are filed under.
#[no_mangle]
pub extern "C" fn kos_ap_entry(cpu: u64) -> ! {
    unsafe {
        // SSE2 is ABI-mandatory and the compiler may use it for block moves, so it has to be
        // enabled before any Rust code runs on this core.
        cpu::enable_fpu_sse();
        let position = cpu as usize;
        // The trampoline came with a throwaway GDT (three entries, long mode only). This is
        // where the processor adopts the kernel's: the same table the boot processor is using,
        // reached through the same physical address, and with *its own* task state segment -
        // the one whose descriptor no other processor has marked busy, and whose interrupt
        // stack is this processor's alone.
        gdt::adopt(position);
        idt::load();

        let apic_id = lapic::init_ap(position);
        // Interrupts stay masked on an AP: see the module comment. `cli` here rather than at the
        // trampoline, so the ordering is visible where the reason is written down.
        cpu::disable_interrupts();

        let slot = slot(position);
        slot.apic_id.store(apic_id as u64, Ordering::Relaxed);
        slot.cycles.fetch_add(cpu::read_tsc(), Ordering::Relaxed);
        // Last: the boot processor starts polling the moment this word moves, and everything
        // above has to be in place before it does.
        slot.state.store(ONLINE, Ordering::Release);

        loop {
            let job = &slot.job;
            if job.state.load(Ordering::Acquire) == JOB_POSTED {
                let note = unsafe { execute(job, position) };
                job.note.store(note, Ordering::Relaxed);
                slot.jobs.fetch_add(1, Ordering::Relaxed);
                job.state.store(JOB_DONE, Ordering::Release);
            } else {
                core::hint::spin_loop();
            }
        }
    }
}

global_asm!(
    r#"
/* ============================================================ AP trampoline
 * Copied to TRAMPOLINE_BASE (0x8000) and entered by a STARTUP IPI: CS = 0x8000, IP = 0, real
 * mode, paging off, IF clear. Everything below addresses the copy by absolute address, which is
 * why the layout offsets appear both here and as constants in the Rust half.
 *
 * The distance from here to the slot area is 0x300 bytes and the 16-bit stage is far shorter
 * than that, so the code and the data it reads never collide.
 */
.section .rodata.ap_trampoline,"a"
.balign 16
.global ap_trampoline_start
ap_trampoline_start:
.code16
    cli
    /* Flat segments: DS = 0 makes a 16-bit absolute displacement reach anywhere in the page. */
    xor %ax, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    mov $0x7c00, %sp            /* below the trampoline page, inside conventional memory */

    /* The trampoline's own GDT: never mind what the firmware left in GDTR, this table is at a
       known address with a known base. It only has to cover the long-mode transition. */
    lgdt 0x8300

    mov %cr4, %eax
    or $0x620, %eax             /* CR4.PAE | OSFXSR | OSXMMEXCPT: the ABI's SSE, from the first
                                   long-mode instruction, not from the first Rust one */
    mov %eax, %cr4
    mov 0x8310, %eax            /* this kernel's page tables */
    mov %eax, %cr3
    mov $0xc0000080, %ecx       /* EFER */
    rdmsr
    or $0x100, %eax             /* EFER.LME */
    wrmsr
    mov %cr0, %eax
    or $0x80000001, %eax        /* CR0.PG | CR0.PE */
    mov %eax, %cr0
    /* Far jump into the 64-bit code segment. The 0x66 prefix makes the offset 32 bits; the
       target is a linear address, which under the identity map is the physical one. */
    .byte 0x66, 0xea
    .long 0x8340
    .word 0x0008

.org 0x300
.global ap_trampoline_gdt_pointer
ap_trampoline_gdt_pointer:
    .short 23                   /* three descriptors, minus one */
    .long 0x8400                /* the trampoline's GDT, in the same page */
.org 0x310
.global ap_trampoline_cr3
ap_trampoline_cr3:
    .long 0
.org 0x318
.global ap_trampoline_stack
ap_trampoline_stack:
    .quad 0
.org 0x320
.global ap_trampoline_index
ap_trampoline_index:
    .quad 0

.org 0x340
.code64
.global ap_trampoline_long_mode
ap_trampoline_long_mode:
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov %ax, %ss
    mov 0x8318, %rsp            /* this processor's stack */
    mov 0x8320, %rdi            /* its index, the argument of the Rust entry point */
    mov $kos_ap_entry, %rax
    jmp *%rax

.org 0x400
ap_trampoline_gdt:
    .quad 0x0000000000000000
    .quad 0x00af9a000000ffff    /* ring 0, long mode: L = 1 */
    .quad 0x00af92000000ffff    /* ring 0 data */
.org 0x420
.global ap_trampoline_end
ap_trampoline_end:
"#,
    options(att_syntax)
);

// ---------------------------------------------------------------- processor state

/// Job state words. The two sides synchronise through the job's own atomic, so these are the
/// only values it ever holds.
const JOB_IDLE: u64 = 0;
const JOB_POSTED: u64 = 1;
const JOB_DONE: u64 = 2;
/// An AP that has finished its bring-up and is polling its mailbox.
pub const ONLINE: u64 = 0x4B4F_535F_4F4E_4C49; // "KOS_ONLI"
/// Signature that keeps this module's state in `.data` (the loader does not zero `.bss`).
const SMP_SIGNATURE: u64 = 0x4B45_4C4C_534D_5001; // "KELLSMP\x01"

/// Job kinds.
const KIND_KAT: u64 = 1;
const KIND_LIVE: u64 = 2;

/// Processors besides the boot one this kernel keeps state for.
pub const MAX_AP: usize = acpi::MAX_CPUS - 1;
///
/// Everything below is indexed by *processor number*, the same number the MADT's order gives:
/// 0 is the boot processor, 1.. are the application processors. That single index is what the
/// trampoline is patched with, what the AP's own state is filed under, and what the boot
/// processor polls - and it is one number rather than two by construction, because two numbers
/// that mean the same thing drift apart the first time nobody is looking (which is exactly how
/// the first version of this file waited forever for a processor that had already come online
/// three slots away).
/// Stack for one application processor. The AP path is shallow on purpose (no printing, no
/// allocation, no scheduler), so this is generous for what runs on it.
pub const AP_STACK_BYTES: usize = 16 * 1024;

/// The pinned offload workload. Every parameter here is part of the vector: the Python tool
/// computes the same digest from the same numbers, so a mismatch is a bug on one side and the
/// self-test says which side by failing.
pub const KAT_MESSAGE: &[u8; 32] = b"KELLER-OS SMP OFFLOAD KEY 000001";
pub const KAT_NONCE: &[u8; 12] = b"KOS-SMP-0001";
/// Sized by what a boot can afford, not by what cryptography deserves: on an emulated core this
/// same construction at 256 rounds x 4 KiB measured **24 seconds** here, and a boot self-test
/// that takes half a minute is a self-test nobody runs. Eight rounds of a kilobyte is 8 KiB of
/// keystream chained through eight SHA-256 compressions, and the digest is still 256 bits - the
/// probability that a wrong implementation agrees is unchanged by the size of the input.
pub const KAT_ROUNDS: u32 = 8;
/// The keystream length one round consumes: 16 ChaCha20 blocks.
pub const ROUND_BYTES: usize = 1024;
/// The pinned digest, produced by an independent implementation of the same construction
/// (`dev-tools/smp_check.py`, which validates its own ChaCha20 and SHA-256 against the RFC 8439 and
/// FIPS 180-4 vectors before it is allowed to produce this number).
pub const KAT_DIGEST: [u8; 32] = [
    0x5f, 0xa1, 0x84, 0xc8, 0xb6, 0x40, 0x3e, 0x0d, 0x6a, 0xc3, 0x88, 0xf3, 0xb1, 0xab, 0x95, 0x6d,
    0x51, 0x3e, 0x52, 0xd0, 0x5c, 0x8c, 0xa8, 0xec, 0x68, 0xa7, 0x41, 0x19, 0x68, 0x83, 0x78, 0xec,
];

/// One unit of work. The payload is written before `state` moves to `JOB_POSTED` and read after
/// it is seen (release/acquire on that word), so no other ordering is needed.
struct Job {
    state: AtomicU64,
    kind: u64,
    key: [u8; crypto::KEY_LEN],
    nonce: [u8; crypto::NONCE_LEN],
    /// First ChaCha20 counter the job uses.
    counter: u32,
    rounds: u32,
    /// Result.
    digest: [u8; 32],
    /// 0 when the job ran, non-zero for the reason it did not.
    note: AtomicU64,
}

impl Job {
    const fn empty() -> Self {
        Self {
            state: AtomicU64::new(JOB_IDLE),
            kind: 0,
            key: [0; crypto::KEY_LEN],
            nonce: [0; crypto::NONCE_LEN],
            counter: 0,
            rounds: 0,
            digest: [0; 32],
            note: AtomicU64::new(0),
        }
    }
}

struct Slot {
    signature: u64,
    state: AtomicU64,
    /// The APIC id the processor read out of its own register.
    apic_id: AtomicU64,
    /// The APIC id the MADT gives the processor at this index, i.e. who was started.
    madt_id: u64,
    /// Stack top the trampoline was patched with.
    stack_top: u64,
    /// Jobs this processor completed, and the TSC reading it took when it came online.
    jobs: AtomicU64,
    cycles: AtomicU64,
    /// The digest this processor produced for the *pinned* workload, kept separately from the
    /// job slot because the job slot ends up holding the last job's result (the live one).
    /// This is the number an outside reader can recompute, so it is the one worth keeping.
    kat: [u8; 32],
    job: Job,
}

impl Slot {
    const fn empty() -> Self {
        Self {
            signature: SMP_SIGNATURE,
            state: AtomicU64::new(0),
            apic_id: AtomicU64::new(0xFF),
            madt_id: 0,
            stack_top: 0,
            jobs: AtomicU64::new(0),
            cycles: AtomicU64::new(0),
            kat: [0; 32],
            job: Job::empty(),
        }
    }
}

#[repr(align(16))]
#[derive(Clone, Copy)]
struct ApStack([u8; AP_STACK_BYTES]);

/// Stacks for the application processors, indexed by processor number (entry 0, the boot
/// processor's slot, is unused: it runs on the boot stack). All-zero, so the linker keeps them
/// in `.bss`, which is exactly right: a stack is written before it is read and needs no copy.
static mut AP_STACKS: [ApStack; acpi::MAX_CPUS] = [const { ApStack([0; AP_STACK_BYTES]) }; acpi::MAX_CPUS];
/// Scratch for the offload workload: 32 bytes of chaining state followed by one round's
/// keystream, so the SHA-256 input is one contiguous buffer.
const SCRATCH_BYTES: usize = ROUND_BYTES + 32;
static mut SCRATCH: [[u8; SCRATCH_BYTES]; acpi::MAX_CPUS] = [[0; SCRATCH_BYTES]; acpi::MAX_CPUS];

static mut SLOTS: [Slot; acpi::MAX_CPUS] = [const { Slot::empty() }; acpi::MAX_CPUS];
static mut STATE: AtomicU64 = AtomicU64::new(0);

fn slot(cpu: usize) -> &'static mut Slot {
    unsafe { &mut *core::ptr::addr_of_mut!(SLOTS[cpu]) }
}

fn scratch(cpu: usize) -> &'static mut [u8; SCRATCH_BYTES] {
    unsafe { &mut *core::ptr::addr_of_mut!(SCRATCH[cpu]) }
}

// ---------------------------------------------------------------- accessors

/// Processors besides this one that reported themselves online.
pub fn online_count() -> usize {
    (1..acpi::MAX_CPUS)
        .filter(|cpu| slot(*cpu).state.load(Ordering::Relaxed) == ONLINE)
        .count()
}

pub fn started() -> usize {
    unsafe { STATE.load(Ordering::Relaxed) as usize }
}

pub fn slot_info(cpu: usize) -> Option<(bool, u8, u8, u64, u64, u64)> {
    if cpu >= acpi::MAX_CPUS {
        return None;
    }
    let slot = slot(cpu);
    if slot.signature != SMP_SIGNATURE {
        return None;
    }
    Some((
        slot.state.load(Ordering::Relaxed) == ONLINE,
        slot.apic_id.load(Ordering::Relaxed) as u8,
        slot.madt_id as u8,
        slot.stack_top,
        slot.jobs.load(Ordering::Relaxed),
        slot.cycles.load(Ordering::Relaxed),
    ))
}

/// Digest the processor at `cpu` produced for its last job, if it has run one.
pub fn last_digest(cpu: usize) -> Option<[u8; 32]> {
    if cpu >= acpi::MAX_CPUS || slot(cpu).jobs.load(Ordering::Relaxed) == 0 {
        return None;
    }
    Some(slot(cpu).job.digest)
}

// ---------------------------------------------------------------- the workload

/// The offload workload. Identical for every core and for the boot processor's own cross-check,
/// and identical to the independent implementation in `dev-tools/smp_check.py`.
fn compute(
    key: &[u8; crypto::KEY_LEN],
    nonce: &[u8; crypto::NONCE_LEN],
    counter: u32,
    rounds: u32,
    buffer: &mut [u8; SCRATCH_BYTES],
) -> [u8; 32] {
    let mut chaining = [0u8; 64];
    chaining[..32].copy_from_slice(key);
    chaining[32..44].copy_from_slice(nonce);
    let mut chain = crypto::sha256(&chaining[..44]);
    let mut block_counter = counter;
    for _ in 0..rounds {
        // XOR against a zeroed buffer is the keystream itself, which is why the chaining state
        // and the keystream can live in one buffer without a second copy.
        for byte in buffer[32..].iter_mut() {
            *byte = 0;
        }
        crypto::chacha20_xor(key, block_counter, nonce, &mut buffer[32..]);
        buffer[..32].copy_from_slice(&chain);
        chain = crypto::sha256(&buffer[..]);
        block_counter = block_counter.wrapping_add((ROUND_BYTES / 64) as u32);
    }
    chain
}

/// Runs the job an AP was handed. Returns 0 on success or the reason it was refused.
unsafe fn execute(job: &Job, cpu: usize) -> u64 {
    match job.kind {
        KIND_KAT | KIND_LIVE => {
            let digest = compute(&job.key, &job.nonce, job.counter, job.rounds, scratch(cpu));
            // The digest is written into the job before the state word moves to done, and that
            // store is a release: the boot processor's acquire load cannot see a partial write.
            let target = core::ptr::addr_of_mut!(SLOTS[cpu].job.digest);
            core::ptr::write_volatile(target, digest);
            if job.kind == KIND_KAT {
                core::ptr::write_volatile(core::ptr::addr_of_mut!(SLOTS[cpu].kat), digest);
            }
            0
        }
        _ => 1,
    }
}

/// The digest `cpu` produced for the pinned workload, once it has run it.
pub fn pinned_digest(cpu: usize) -> Option<[u8; 32]> {
    if cpu >= acpi::MAX_CPUS || slot(cpu).jobs.load(Ordering::Relaxed) == 0 {
        return None;
    }
    Some(slot(cpu).kat)
}

// ---------------------------------------------------------------- dispatch

/// Posts `kind` to the processor at `index` and waits for it to finish.
///
/// Returns the digest the processor produced, or `None` when it is not online or did not finish
/// inside the budget. The wait is a spin rather than a sleep because the boot processor has
/// nothing else to do with the time, and it is bounded so a processor that died mid-job turns
/// into a failed assertion instead of a hung boot.
pub fn submit(
    cpu: usize,
    kind: u64,
    key: &[u8; crypto::KEY_LEN],
    nonce: &[u8; crypto::NONCE_LEN],
    counter: u32,
    rounds: u32,
) -> Option<[u8; 32]> {
    if cpu >= acpi::MAX_CPUS {
        return None;
    }
    let slot = slot(cpu);
    if slot.state.load(Ordering::Acquire) != ONLINE {
        return None;
    }
    let job = &mut slot.job;
    if job.state.load(Ordering::Acquire) == JOB_POSTED {
        return None; // a job is still out; the caller has to wait for it first
    }
    job.kind = kind;
    job.key.copy_from_slice(key);
    job.nonce.copy_from_slice(nonce);
    job.counter = counter;
    job.rounds = rounds;
    job.note.store(0, Ordering::Relaxed);
    job.state.store(JOB_POSTED, Ordering::Release);

    let deadline = lapic::micros() + SUBMIT_BUDGET_US;
    while job.state.load(Ordering::Acquire) != JOB_DONE {
        if lapic::micros() >= deadline {
            return None;
        }
        core::hint::spin_loop();
    }
    let note = job.note.load(Ordering::Relaxed);
    job.state.store(JOB_IDLE, Ordering::Release);
    if note != 0 {
        return None;
    }
    Some(job.digest)
}

/// How long the boot processor waits for one job. This is sized for an emulated core running an
/// unoptimised build, where a quarter of a megabyte of ChaCha20 and a few hundred SHA-256
/// compressions is not the tens of milliseconds it would be on real silicon - and a job that
/// takes ten seconds is still a job that has failed.
const SUBMIT_BUDGET_US: u64 = 10_000_000;

/// Runs the pinned workload on the boot processor. This is the cross-check that makes an AP's
/// digest meaningful: the same code, the same inputs, a different core.
pub fn compute_on_boot(key: &[u8; crypto::KEY_LEN], nonce: &[u8; crypto::NONCE_LEN], rounds: u32) -> [u8; 32] {
    let mut buffer = [0u8; SCRATCH_BYTES];
    compute(key, nonce, 0, rounds, &mut buffer)
}

// ---------------------------------------------------------------- bring-up

/// Checks that the offsets the trampoline's code uses are the offsets the linker gave those
/// symbols. The numbers are written out in the assembly; this is what keeps them honest.
fn layout_is_intact() -> bool {
    let base = unsafe { core::ptr::addr_of!(ap_trampoline_start) as u64 };
    let at = |symbol: *const u8| unsafe { symbol as u64 - base };
    let start = core::ptr::addr_of!(ap_trampoline_start) as *const u8;
    let end = core::ptr::addr_of!(ap_trampoline_end) as *const u8;
    let length = end as u64 - start as u64;
    length <= TRAMPOLINE_LEN
        && at(core::ptr::addr_of!(ap_trampoline_gdt_pointer) as *const u8) == SLOT_GDT_POINTER
        && at(core::ptr::addr_of!(ap_trampoline_cr3) as *const u8) == SLOT_CR3
        && at(core::ptr::addr_of!(ap_trampoline_stack) as *const u8) == SLOT_STACK
        && at(core::ptr::addr_of!(ap_trampoline_index) as *const u8) == SLOT_INDEX
        && at(core::ptr::addr_of!(ap_trampoline_long_mode) as *const u8) == SLOT_LONG_MODE
}

/// Copies the trampoline into the page a STARTUP IPI can name, and patches the three values it
/// cannot know on its own.
unsafe fn install_trampoline() -> bool {
    if !layout_is_intact() {
        println!("[!!] SMP: the trampoline's code and its slots disagree about the layout - refusing to start a processor with it");
        return false;
    }
    let source = core::ptr::addr_of!(ap_trampoline_start) as *const u8;
    let target = TRAMPOLINE_BASE as *mut u8;
    core::ptr::copy_nonoverlapping(source, target, TRAMPOLINE_LEN as usize);

    let cr3 = cpu::read_cr3();
    if cr3 >= 0x1_0000_0000 {
        println!(
            "[!!] SMP: this kernel's page tables are at {:#x}, above the 32 bits the trampoline can load",
            cr3
        );
        return false;
    }
    core::ptr::write_unaligned((TRAMPOLINE_BASE + SLOT_CR3) as *mut u32, cr3 as u32);
    true
}

/// Patches the two values the trampoline cannot know on its own. The index it is handed is the
/// processor *number* - the same number the boot processor will poll that processor's slot
/// under - and not its position in the MADT's list, which happens to coincide here but is not
/// the same claim.
fn patch_slot(cpu: usize, stack_top: u64) {
    unsafe {
        core::ptr::write_unaligned((TRAMPOLINE_BASE + SLOT_STACK) as *mut u64, stack_top);
        core::ptr::write_unaligned((TRAMPOLINE_BASE + SLOT_INDEX) as *mut u64, cpu as u64);
    }
}

/// Starts every processor the MADT describes besides the boot one, and waits for each to report
/// itself online before starting the next.
///
/// # Safety
/// Requires the ACPI tables, the local APIC, the IO-APIC and the IDT to be up, interrupts to be
/// enabled (the INIT-SIPI delays come from the PIT), and the kernel's GDT to be the live one.
pub unsafe fn bring_up() -> usize {
    let expected = acpi::processor_count();
    let state = &mut *core::ptr::addr_of_mut!(STATE);
    state.store(0, Ordering::Relaxed);

    for cpu in 0..acpi::MAX_CPUS {
        let slot = slot(cpu);
        slot.state.store(0, Ordering::Relaxed);
        slot.apic_id.store(0xFF, Ordering::Relaxed);
        slot.jobs.store(0, Ordering::Relaxed);
        slot.cycles.store(0, Ordering::Relaxed);
        slot.job.state.store(JOB_IDLE, Ordering::Relaxed);
        slot.job.note.store(0, Ordering::Relaxed);
    }

    if expected <= 1 {
        println!(
            "[--] SMP: the MADT describes {} processor - no application processor to start",
            expected
        );
        return 0;
    }
    if !install_trampoline() {
        return 0;
    }

    let page = (TRAMPOLINE_BASE >> 12) as u8;
    let mut started = 0usize;
    let mut skipped = 0usize;
    for cpu in 1..expected.min(acpi::MAX_CPUS) {
        let processor = match acpi::processor(cpu) {
            Some(processor) => processor,
            None => break,
        };
        if !processor.enabled {
            skipped += 1;
            continue;
        }
        let stack_top = {
            let base = core::ptr::addr_of_mut!(AP_STACKS) as *mut u8;
            let top = base.add(cpu * AP_STACK_BYTES + AP_STACK_BYTES) as u64;
            // 16-byte aligned, and eight bytes lower so the ABI sees what a `call` would have
            // left: the trampoline `jmp`s into a function that never returns.
            (top & !0xF) - 8
        };
        let slot = slot(cpu);
        slot.madt_id = processor.apic_id as u64;
        slot.stack_top = stack_top;
        slot.state.store(0, Ordering::Relaxed);
        patch_slot(cpu, stack_top);

        if !lapic::start_processor(processor.apic_id, page) {
            println!(
                "[!!] SMP CPU {}: the local APIC refused to send the STARTUP IPI to apic {:#04x}",
                cpu, processor.apic_id
            );
            continue;
        }
        let deadline = lapic::micros() + START_TIMEOUT_US;
        while slot.state.load(Ordering::Acquire) != ONLINE {
            if lapic::micros() >= deadline {
                break;
            }
            core::hint::spin_loop();
        }
        if slot.state.load(Ordering::Acquire) == ONLINE {
            let apic_id = slot.apic_id.load(Ordering::Relaxed);
            started += 1;
            println!(
                "[OK] SMP CPU {}: online, apic {:#04x} (started as {:#04x} by the MADT), stack {:#x}, {} KiB",
                cpu,
                apic_id,
                processor.apic_id,
                stack_top,
                AP_STACK_BYTES / 1024
            );
            if apic_id != processor.apic_id as u64 {
                println!(
                    "[!!] SMP CPU {}: the processor reports apic {:#04x} but the MADT lists {:#04x} at this position",
                    cpu, apic_id, processor.apic_id
                );
            }
        } else {
            println!(
                "[!!] SMP CPU {}: no processor answered the STARTUP IPI to apic {:#04x} within {} ms",
                cpu,
                processor.apic_id,
                START_TIMEOUT_US / 1000
            );
        }
    }

    state.store(started as u64, Ordering::Relaxed);
    if skipped != 0 {
        println!(
            "[--] SMP: {} processor entr{} the MADT marks disabled were not started",
            skipped,
            if skipped == 1 { "y" } else { "ies" }
        );
    }
    println!(
        "[OK] SMP: {} of {} application processor(s) online - offload mailbox ready on {}-byte job slots",
        started,
        expected - 1,
        core::mem::size_of::<Job>()
    );
    started
}

/// How long to wait for one processor to report itself online. INIT-SIPI-SIPI plus a real-mode
/// trampoline is a few milliseconds; a second and a half means it is not coming.
const START_TIMEOUT_US: u64 = 1_500_000;

// ---------------------------------------------------------------- reports

pub fn describe() {
    println!(
        "[SMP] processors: {} described by the MADT, {} started, {} online, trampoline at {:#x} ({} bytes)",
        acpi::processor_count(),
        started(),
        online_count(),
        TRAMPOLINE_BASE,
        TRAMPOLINE_LEN
    );
    for cpu in 1..acpi::MAX_CPUS {
        if let Some((online, apic_id, madt_id, stack, jobs, cycles)) = slot_info(cpu) {
            if !online && jobs == 0 && cycles == 0 {
                continue;
            }
            println!(
                "[SMP] ap{}: {} apic={:#04x} madt={:#04x} stack={:#x} jobs={} tsc-at-entry={}",
                cpu,
                if online { "online " } else { "OFFLINE" },
                apic_id,
                madt_id,
                stack,
                jobs,
                cycles
            );
            // The pinned digest itself, in full, so a reader outside this kernel can recompute
            // the number rather than take the kernel's word for whether it was right.
            if let Some(digest) = pinned_digest(cpu) {
                crate::print!("[SMP] ap{} pinned-kat ", cpu);
                for byte in digest.iter() {
                    crate::print!("{:02x}", byte);
                }
                crate::println!();
            }
        }
    }
}

// ---------------------------------------------------------------- self-test

/// How many assertions this module makes. A single-processor machine skips the ones that need a
/// second processor, and says so.
pub const ASSERTIONS: u32 = 15;

/// Runs the pinned workload on every online processor and on the boot processor, then the live
/// agreement job that no single core can satisfy alone.
pub fn self_test() -> BlockReport {
    let mut report = BlockReport::new();
    let expected = acpi::processor_count();
    if expected <= 1 {
        report.skip(ASSERTIONS - 2);
        report.check(
            online_count() == 0,
            "a processor reports itself online on a machine the MADT says has one",
        );
        report.check(
            started() == 0,
            "the bring-up counter moved on a machine with no application processor",
        );
        return report;
    }

    report.check(
        layout_is_intact(),
        "the trampoline's slot offsets do not match the symbols the linker placed",
    );
    let target = (expected - 1).min(acpi::MAX_CPUS - 1);
    report.check(
        started() == target,
        "not every processor the MADT describes was started",
    );
    report.check(
        online_count() == target,
        "not every started processor reported itself online",
    );

    // The trampoline page has to hold the copy the processors actually executed, read back byte
    // for byte - apart from the two slots that are *patched on purpose* before every STARTUP
    // IPI. Which processor wrote its state into which slot is the evidence that the patching
    // worked, so those two are checked by the processors arriving rather than by a comparison
    // against the image they were told to differ from.
    let source = unsafe { core::ptr::addr_of!(ap_trampoline_start) as *const u8 };
    let copied = TRAMPOLINE_LEN as usize;
    // Two regions of the copy are deliberately not the image: the slots the boot processor
    // patches before every STARTUP IPI, and the throwaway GDT - which the *processor* changes,
    // because loading a segment sets the accessed bit in the descriptor it loaded. So the
    // comparison covers the code and the slots, and the GDT is left to the hardware that reads
    // it. Everything a reader would call "the trampoline" is still compared byte for byte.
    let mut first_difference = None;
    for offset in 0..copied {
        let offset64 = offset as u64;
        let patched = (SLOT_STACK..SLOT_STACK + 16).contains(&offset64)
            || (SLOT_CR3..SLOT_CR3 + 4).contains(&offset64)
            || offset64 >= SLOT_GDT;
        if patched {
            continue;
        }
        let live = unsafe { core::ptr::read_volatile((TRAMPOLINE_BASE as *const u8).add(offset)) };
        let image = unsafe { *source.add(offset) };
        if live != image {
            first_difference = Some((offset, live, image));
            break;
        }
    }
    if let Some((offset, live, image)) = first_difference {
        println!(
            "[!!] SMP: the trampoline page differs from the image at +{:#x} ({:#04x} in memory, {:#04x} in the image)",
            offset, live, image
        );
    }
    report.check(
        first_difference.is_none(),
        "the trampoline page does not hold the trampoline image",
    );

    // Every processor: the id it reports against the id it was started with, and the pinned
    // workload's digest against the value an independent implementation produced.
    let boot_id = lapic::id();
    let mut mismatched_ids = false;
    let mut wrong_digest = false;
    let mut refused = 0usize;
    let mut no_cycles = false;
    let mut same_as_boot = false;
    for cpu in 1..acpi::MAX_CPUS {
        let Some((online, apic_id, madt_id, _, _, cycles)) = slot_info(cpu) else {
            continue;
        };
        if !online {
            continue;
        }
        if apic_id != madt_id {
            mismatched_ids = true;
        }
        if apic_id == boot_id {
            same_as_boot = true;
        }
        if cycles == 0 {
            no_cycles = true;
        }
        match submit(
            cpu,
            KIND_KAT,
            KAT_MESSAGE,
            KAT_NONCE,
            0,
            KAT_ROUNDS,
        ) {
            Some(digest) => {
                if digest != KAT_DIGEST {
                    wrong_digest = true;
                }
            }
            None => refused += 1,
        }
    }
    report.check(!mismatched_ids, "a processor's own APIC id is not the one it was started with");
    report.check(
        !same_as_boot,
        "a job was reported by the boot processor's own APIC id",
    );
    report.check(!no_cycles, "a processor never read its own time-stamp counter");
    report.check(
        refused == 0,
        "a processor refused the pinned workload or did not finish it in time",
    );
    report.check(
        !wrong_digest,
        "a processor's pinned-workload digest does not match the independent vector",
    );

    // The boot processor computes the same thing, which is what makes the digests comparable -
    // and it is also the measurement that says how long one job *should* take, which is what the
    // per-job budget has to be built on.
    let started = lapic::micros();
    let local = compute_on_boot(KAT_MESSAGE, KAT_NONCE, KAT_ROUNDS);
    let elapsed_us = lapic::micros().saturating_sub(started);
    println!(
        "[SMP] the pinned workload takes {} us on the boot processor, so the {} us per-job budget is {}x it",
        elapsed_us,
        SUBMIT_BUDGET_US,
        SUBMIT_BUDGET_US / elapsed_us.max(1)
    );
    report.check(
        local == KAT_DIGEST,
        "the boot processor's own digest does not match the pinned vector either (the workload, not the AP, is wrong)",
    );

    // The live job: a key this machine has never used before, the same answer required from
    // every core. Nothing about it can be precomputed, and a core that did not really run the
    // workload cannot produce it.
    let live_key = crypto::random_key();
    let live_nonce: [u8; crypto::NONCE_LEN] = {
        let mut nonce = [0u8; crypto::NONCE_LEN];
        nonce[..8].copy_from_slice(&crypto::random_u64().to_le_bytes());
        nonce[8..].copy_from_slice(&crypto::random_u64().to_le_bytes()[..4]);
        nonce
    };
    let live_rounds = KAT_ROUNDS;
    let expected_live = compute_on_boot(&live_key, &live_nonce, live_rounds);
    let mut disagreed = false;
    let mut answered = 0usize;
    for cpu in 1..acpi::MAX_CPUS {
        if slot_info(cpu).map(|info| info.0).unwrap_or(false) {
            match submit(cpu, KIND_LIVE, &live_key, &live_nonce, 0, live_rounds) {
                Some(digest) => {
                    answered += 1;
                    if digest != expected_live {
                        disagreed = true;
                    }
                }
                None => {}
            }
        }
    }
    report.check(
        !disagreed,
        "a processor's live-job digest disagrees with the boot processor's",
    );
    report.check(
        answered == online_count(),
        "not every online processor answered the live job",
    );

    // Every online processor should have run both jobs: the pinned one and the live one.
    let underused = (1..acpi::MAX_CPUS).any(|cpu| {
        slot_info(cpu)
            .filter(|info| info.0)
            .map(|info| info.4 < 2)
            .unwrap_or(false)
    });
    report.check(
        !underused,
        "an online processor did not run both jobs",
    );

    // The mailbox's refusals: a number that has no processor behind it, and one whose processor
    // is not online. The first is out of range by construction; the second is found by looking.
    report.check(
        submit(acpi::MAX_CPUS, KIND_KAT, KAT_MESSAGE, KAT_NONCE, 0, 1).is_none(),
        "the mailbox accepted a job for a processor number that does not exist",
    );
    match (1..acpi::MAX_CPUS).find(|cpu| !slot_info(*cpu).map(|info| info.0).unwrap_or(false)) {
        Some(cpu) => report.check(
            submit(cpu, KIND_KAT, KAT_MESSAGE, KAT_NONCE, 0, 1).is_none(),
            "the mailbox accepted a job for a processor that is not online",
        ),
        None => report.skip(1),
    }
    report
}
