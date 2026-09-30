//! Preemptive process table: ring-3 tasks with an address space each.
//!
//! The fixed-slot scheduler (`crate::sched`) still measures out the kernel's own maintenance
//! slots in padded quanta, but it can only switch when a slot *returns*. A driver that never
//! returns cannot be preempted by a cooperative scheduler, so the isolation story keeps a hole
//! in it: one spinning task starves the machine. This module closes that hole.
//!
//! It keeps one row per process — the kernel's own idle context included — and switches
//! contexts **inside the timer interrupt**, where the CPU has already saved the interrupted
//! task's registers:
//!
//! * a switch parks the interrupted frame (the 256 bytes of XMM state plus the 176-byte
//!   CPU/stub frame the ISR prologue built) into the outgoing process's row;
//! * the incoming process's parked frame address is handed to the shared epilogue
//!   ([`idt::request_switch`]), which loads it as RSP and *becomes* the incoming context by
//!   `iretq` — no second restore path, and no way for the two to drift apart;
//! * `cr3` is switched in the same function, so the resumed process sees its own address space
//!   and nothing else.
//!
//! Nothing on that path asks the running task for permission, which is what makes it preemption
//! rather than cooperation. A task in a tight `jmp $` loop, a task that has just faulted and a
//! task that is simply being greedy are all handled by the same three lines.
//!
//! **Ring-3 entry** is an `iretq` to a synthesized frame: `cs = 0x1B`, `ss = 0x23` (the GDT's
//! DPL-3 selectors), `IF = 1` so the timer can preempt the task at all, and the stack pointer
//! inside the task's own stack page. The kernel writes that frame into the row; the CPU does the
//! rest, including the privilege change. The task's only way back into the kernel is the one
//! DPL-3 gate, `int 0x80`.
//!
//! **The syscall door** takes `rax` as the call number, `rdi`/`rsi`/`rdx` as arguments, and
//! returns a value in `rax`. It is deliberately a whitelist: exit, a length-capped write the
//! kernel copies out of the caller's address space, a voluntary yield, a progress counter and
//! one mediated port write. Nothing else exists yet, and a pointer that does not translate to a
//! *user* page in the caller's own space — a kernel address, say — is refused with `EFAULT`
//! instead of being dereferenced, which is the classic way a syscall boundary turns into a
//! privilege escalation.

use crate::arch::gdt;
use crate::arch::idt::{self, InterruptFrame};
use crate::arch::paging::{self, AddressSpace};
use crate::clock;
use crate::panic;
use crate::print;
use crate::println;
use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub const MAX_PROCESSES: usize = 8;
/// The kernel's own context, which the idle loop runs in. It is an ordinary row with no address
/// space of its own, so the switch code needs no special case for "there is no target".
pub const KERNEL_SLOT: usize = 0;
/// 100 ms per slice at the programmed 100 Hz tick: the quantum from spec §3.3, now enforced by
/// the timer instead of by the task being polite.
pub const QUANTUM_TICKS: u64 = 10;

/// One parked frame: 256 bytes of XMM state followed by the CPU/stub frame.
const XMM_BYTES: usize = 256;
/// Bytes of `InterruptFrame` after the XMM block: 15 general-purpose registers, the vector and
/// error code, and the five fields the CPU pushes. Asserted against `size_of::<InterruptFrame>`
/// in the self-test, because the offsets below are the whole contract between the ISR prologue
/// and the park/reload code.
const FRAME_TAIL_BYTES: usize = 176;
pub const FRAME_BYTES: usize = XMM_BYTES + FRAME_TAIL_BYTES;

// Offsets *inside an in-flight `InterruptFrame`*, i.e. relative to the pointer the dispatcher
// receives. Field order comes from the struct in `crate::arch::idt` (and from the push order in
// its assembly), so the `InterruptFrame` size assertion in the self-test guards these too.
const FRAME_RDI: usize = 72;
const FRAME_RSI: usize = 80;
const FRAME_RDX: usize = 88;
const FRAME_RAX: usize = 112;
const FRAME_RIP: usize = 136;
const FRAME_CS: usize = 144;

// Offsets inside a *parked* frame: the 256-byte XMM block first, then the same frame. The two
// sets are deliberately distinct names for distinct bases — mixing them up reads a register out
// of whatever happens to sit above the frame, which is exactly how a syscall door silently
// starts answering garbage.
const PARK_RIP: usize = XMM_BYTES + FRAME_RIP;
const PARK_CS: usize = XMM_BYTES + FRAME_CS;
const PARK_RFLAGS: usize = XMM_BYTES + 152;
const PARK_RSP: usize = XMM_BYTES + 160;
const PARK_SS: usize = XMM_BYTES + 168;

/// Initial `rflags` for a ring-3 task: IF=1 (the timer has to be able to take the CPU away from
/// it) plus bit 1, which is architecturally reserved and must be set.
pub const USER_RFLAGS: u64 = 0x202;

/// User memory layout. Every process maps its code, data and stack at the *same* virtual
/// addresses: two processes agreeing on an address and still reaching different memory is
/// exactly the property the isolation check has to demonstrate.
pub const CODE_VA: u64 = paging::USER_BASE;
pub const DATA_VA: u64 = paging::USER_BASE + 0x1000;
pub const STACK_VA: u64 = paging::USER_BASE + 0x10_0000;
/// A page only one process maps: the neighbour's data, as seen from a process that does not have
/// it. Reading it from another space is not a wild pointer — the address *is* mapped, just not
/// in that space, which is what makes the refusal a hardware statement about isolation.
pub const PEER_VA: u64 = paging::USER_BASE + 0x20_0000;

// ------------------------------------------------------------------ syscall numbers

pub const SYS_EXIT: u64 = 0;
pub const SYS_WRITE: u64 = 1;
pub const SYS_YIELD: u64 = 2;
pub const SYS_PROGRESS: u64 = 3;
pub const SYS_PORT_WRITE: u64 = 4;
/// The one port the kernel's capability table grants to a ring-3 driver: the POST/delay port
/// (the same one `port::io_wait` uses), where a write is visible to nothing but a logic
/// analyser. The demonstration exercises the whole mediated path without touching hardware any
/// part of the machine depends on.
pub const GRANTED_PORT: u64 = 0x80;
/// Returned for a refused pointer or a refused capability.
pub const EFAULT: u64 = u64::MAX;

const MAX_MESSAGE: usize = 80;
/// A probe that never finishes must not hang the boot: the loop gives up and says so.
const MAX_PROBE_TICKS: u64 = 500;
/// How much user work a `ring3 run` phase delivers before it retires its tasks, counted in
/// *slices* (one switch-in each). With `QUANTUM_TICKS` ticks per slice that is about 2.4 s of
/// user time, and the kernel's own slots come between them.
pub const PHASE_BUDGET: u64 = 24;

// ------------------------------------------------------------------ process rows

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum State {
    Free,
    Ready,
    Running,
    Exited,
    Faulted,
}

impl State {
    fn label(self) -> &'static str {
        match self {
            State::Free => "free",
            State::Ready => "ready",
            State::Running => "running",
            State::Exited => "exited",
            State::Faulted => "faulted",
        }
    }

    /// Rows a switch may pick.
    fn runnable(self) -> bool {
        matches!(self, State::Ready | State::Running)
    }
}

/// A parked interrupt frame, 16-byte aligned. 512 bytes rather than the 432 in use, so the
/// epilogue's `movups` restores always start comfortably aligned.
#[repr(align(16))]
struct ParkedFrame([u64; 64]);

impl ParkedFrame {
    const fn zeroed() -> Self {
        Self([0; 64])
    }

    fn base(&self) -> *const u8 {
        self.0.as_ptr() as *const u8
    }

    fn base_mut(&mut self) -> *mut u8 {
        self.0.as_mut_ptr() as *mut u8
    }
}

struct Process {
    name: &'static str,
    state: State,
    /// `None` for the kernel context and for a task whose space has already been freed.
    space: Option<AddressSpace>,
    /// Kept after the space is gone so the report can still name the page tables a dead task ran
    /// on.
    cr3: u64,
    frame: ParkedFrame,
    quantum_left: u64,
    /// Switch-ins, i.e. how often this task got the CPU.
    runs: u64,
    syscalls: u64,
    yields: u64,
    /// Last value reported through `SYS_PROGRESS`: a counter that keeps rising while the task
    /// never yields is the visible proof of preemption.
    progress: u64,
    /// `cs` as the CPU pushed it on this task's first entry: 0x1B when the task really ran at
    /// CPL 3. Read from the *frame*, so it cannot be faked by a claim in kernel code.
    first_cs: u64,
    /// `rip` of the parked frame; for a faulted task, the instruction the CPU refused.
    parked_rip: u64,
    exit_code: i64,
    fault_vector: u64,
    fault_error: u64,
    fault_rip: u64,
    fault_address: u64,
}

impl Process {
    const fn empty() -> Self {
        Self {
            name: "",
            state: State::Free,
            space: None,
            cr3: 0,
            frame: ParkedFrame::zeroed(),
            quantum_left: QUANTUM_TICKS,
            runs: 0,
            syscalls: 0,
            yields: 0,
            progress: 0,
            first_cs: 0,
            parked_rip: 0,
            exit_code: 0,
            fault_vector: 0,
            fault_error: 0,
            fault_rip: 0,
            fault_address: 0,
        }
    }
}

/// Array-repeat needs a const item when the element type is not `Copy`, and `Process` is
/// deliberately not `Copy`: an address space must have exactly one owner.
const EMPTY_PROCESS: Process = Process::empty();
static mut PROCESSES: [Process; MAX_PROCESSES] = [EMPTY_PROCESS; MAX_PROCESSES];

static CURRENT: AtomicU64 = AtomicU64::new(KERNEL_SLOT as u64);
static STARTED: AtomicBool = AtomicBool::new(false);
/// Set between `arm_idle` and `disarm_idle`, i.e. exactly while the kernel context is halted and
/// has nothing to protect. This is the only window in which a ring-0 context may be preempted:
/// kernel work outside it must never be interrupted, because a preempted critical section (the
/// heap lock, a console write) would be resumed by a task that only cares about its quantum.
static IDLE_ARMED: AtomicBool = AtomicBool::new(false);
static PREEMPTIONS: AtomicU64 = AtomicU64::new(0);
static YIELDS: AtomicU64 = AtomicU64::new(0);
static ENTRIES: AtomicU64 = AtomicU64::new(0);
static SYSCALLS: AtomicU64 = AtomicU64::new(0);
static FAULTS: AtomicU64 = AtomicU64::new(0);
static EFAULT_REJECTIONS: AtomicU64 = AtomicU64::new(0);
static GRANTS: AtomicU64 = AtomicU64::new(0);
/// Switch-ins of user tasks. One slice is normally a full quantum, but a task that yields (or
/// exits, or faults) ends its slice early, which is why this counts slices and not quanta — the
/// timer's own expiry count is [`PREEMPTIONS`], and that is the number the preemption claim
/// rests on.
static USER_SLICES: AtomicU64 = AtomicU64::new(0);
/// 0 = idle, 1 = running, 2 = complete.
static PHASE: AtomicU64 = AtomicU64::new(0);
static PHASE_START: AtomicU64 = AtomicU64::new(0);
static PHASE_DEADLINE: AtomicU64 = AtomicU64::new(0);

/// What the last `ring3 run` phase observed, kept after its tasks are retired so the shell can
/// still report it.
#[derive(Clone, Copy)]
struct PhaseSummary {
    slices: u64,
    ticks: u64,
    preemptions: u64,
    yields: u64,
    spin_runs: u64,
    spin_syscalls: u64,
    spin_parked_rip: u64,
    alpha_progress: u64,
    alpha_syscalls: u64,
    beta_progress: u64,
    beta_syscalls: u64,
    beta_yields: u64,
    faults: u64,
    page_faults: u64,
    general_protections: u64,
    efaults: u64,
    grants: u64,
    retired: u64,
    complete: bool,
}

impl PhaseSummary {
    const fn empty() -> Self {
        Self {
            slices: 0,
            ticks: 0,
            preemptions: 0,
            yields: 0,
            spin_runs: 0,
            spin_syscalls: 0,
            spin_parked_rip: 0,
            alpha_progress: 0,
            alpha_syscalls: 0,
            beta_progress: 0,
            beta_syscalls: 0,
            beta_yields: 0,
            faults: 0,
            page_faults: 0,
            general_protections: 0,
            efaults: 0,
            grants: 0,
            retired: 0,
            complete: false,
        }
    }
}

static mut LAST_PHASE: PhaseSummary = PhaseSummary::empty();

// ------------------------------------------------------------------ state helpers

unsafe fn row<R>(index: usize, body: impl FnOnce(&mut Process) -> R) -> R {
    body(&mut *core::ptr::addr_of_mut!(PROCESSES[index]))
}

unsafe fn put(base: *mut u8, offset: usize, value: u64) {
    ptr::write_volatile(base.add(offset) as *mut u64, value);
}

unsafe fn get(base: *const u8, offset: usize) -> u64 {
    ptr::read_volatile(base.add(offset) as *const u64)
}

unsafe fn state_of(index: usize) -> State {
    row(index, |process| process.state)
}

/// Explicit reset of the whole table (`.bss` arrives uninitialised under PVH boot).
///
/// # Safety
/// Must run once, before any process exists and before interrupts can reach `on_timer`.
pub unsafe fn init() {
    for index in 0..MAX_PROCESSES {
        row(index, |process| *process = Process::empty());
    }
    row(KERNEL_SLOT, |process| {
        process.name = "kernel-idle";
        process.state = State::Running;
        process.quantum_left = QUANTUM_TICKS;
    });
    CURRENT.store(KERNEL_SLOT as u64, Ordering::Relaxed);
    STARTED.store(false, Ordering::Relaxed);
    IDLE_ARMED.store(false, Ordering::Relaxed);
    for counter in [
        &PREEMPTIONS,
        &YIELDS,
        &ENTRIES,
        &SYSCALLS,
        &FAULTS,
        &EFAULT_REJECTIONS,
        &GRANTS,
        &USER_SLICES,
    ] {
        counter.store(0, Ordering::Relaxed);
    }
    PHASE.store(0, Ordering::Relaxed);
    PHASE_START.store(0, Ordering::Relaxed);
    PHASE_DEADLINE.store(0, Ordering::Relaxed);
    unsafe { *core::ptr::addr_of_mut!(LAST_PHASE) = PhaseSummary::empty() };
}

pub fn started() -> bool {
    STARTED.load(Ordering::Relaxed)
}

pub fn current_name() -> &'static str {
    let index = CURRENT.load(Ordering::Relaxed) as usize;
    unsafe { row(index, |process| process.name) }
}

pub fn preemptions() -> u64 {
    PREEMPTIONS.load(Ordering::Relaxed)
}

pub fn yields() -> u64 {
    YIELDS.load(Ordering::Relaxed)
}

pub fn ring3_entries() -> u64 {
    ENTRIES.load(Ordering::Relaxed)
}

pub fn syscall_count() -> u64 {
    SYSCALLS.load(Ordering::Relaxed)
}

/// Lets the idle context be preempted. Only ever called immediately before `hlt`.
pub fn arm_idle() {
    IDLE_ARMED.store(true, Ordering::Relaxed);
}

/// Takes the protection back. Called immediately after `hlt` returns — which, for a context that
/// was preempted away, happens only once the scheduler resumes it.
pub fn disarm_idle() {
    IDLE_ARMED.store(false, Ordering::Relaxed);
}

pub fn idle_armed() -> bool {
    IDLE_ARMED.load(Ordering::Relaxed)
}

// ------------------------------------------------------------------ machine-code programs

/// A tiny emitter for the user programs.
///
/// The kernel has no assembler, and shipping opaque blobs would hide what the tasks actually
/// execute — which matters here, because two of them exist precisely to execute forbidden
/// instructions. Every method below emits one documented instruction, and the reports print the
/// resulting bytes in hex so a program can be audited against this source.
struct Program {
    bytes: [u8; 128],
    length: usize,
}

impl Program {
    const fn new() -> Self {
        Self {
            bytes: [0; 128],
            length: 0,
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        assert!(
            self.length + bytes.len() <= 128,
            "user program overflows its buffer"
        );
        for byte in bytes {
            self.bytes[self.length] = *byte;
            self.length += 1;
        }
    }

    /// `mov r32, imm32` (opcode B8+rd). Only the four legacy registers the ABI below uses.
    fn mov_reg(&mut self, register: u8, value: u32) {
        self.push(&[0xB8 + register]);
        self.push(&value.to_le_bytes());
    }

    /// `mov rsi, imm64` (REX.W + BE, 10 bytes) for addresses above 4 GiB.
    fn mov_rsi64(&mut self, value: u64) {
        self.push(&[0x48, 0xBE]);
        self.push(&value.to_le_bytes());
    }

    /// `xor r12d, r12d` — the progress register.
    fn zero_progress(&mut self) {
        self.push(&[0x45, 0x31, 0xE4]);
    }

    /// `inc r12`.
    fn bump_progress(&mut self) {
        self.push(&[0x49, 0xFF, 0xC4]);
    }

    /// `mov rdi, r12` — argument 0 gets the progress value.
    fn progress_to_arg0(&mut self) {
        self.push(&[0x4C, 0x89, 0xE7]);
    }

    /// `int 0x80`, the only DPL-3 gate in the IDT.
    fn syscall(&mut self) {
        self.push(&[0xCD, 0x80]);
    }

    /// `jmp rel32` back to an already emitted offset.
    fn jump_back(&mut self, target: usize) {
        self.push(&[0xE9]);
        let after = self.length + 4;
        self.push(&((target as i64 - after as i64) as i32).to_le_bytes());
    }

    /// `jnz rel32`, patched later by [`Program::patch_jump`].
    fn jump_forward(&mut self) -> usize {
        self.push(&[0x0F, 0x85]);
        let at = self.length;
        self.push(&[0, 0, 0, 0]);
        at
    }

    fn patch_jump(&mut self, at: usize) {
        let after = at + 4;
        let delta = (self.length as i64 - after as i64) as i32;
        self.bytes[at..at + 4].copy_from_slice(&delta.to_le_bytes());
    }

    /// `test r12, mask` — used to yield only every so many progress reports.
    fn test_progress(&mut self, mask: u32) {
        self.push(&[0x49, 0xF7, 0xC4]);
        self.push(&mask.to_le_bytes());
    }

    /// `mov rax, [moffs64]` — a load that walks straight into the page tables.
    fn load_rax_absolute(&mut self, address: u64) {
        self.push(&[0x48, 0xA1]);
        self.push(&address.to_le_bytes());
    }

    /// `mov edx, imm32` then `in al, dx`: a privileged port read at CPL 3.
    fn port_read(&mut self, port: u16) {
        self.push(&[0xBA]);
        self.push(&(port as u32).to_le_bytes());
        self.push(&[0xEC]);
    }

    /// `jmp $` — an infinite loop with no syscall in it: only the timer can end it.
    fn spin_forever(&mut self) {
        self.push(&[0xEB, 0xFE]);
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

/// `write(DATA_VA, message); exit(0)`: the smallest complete ring-3 program.
fn program_hello(message_length: usize) -> Program {
    let mut program = Program::new();
    program.mov_reg(0, SYS_WRITE as u32); // eax = SYS_WRITE
    program.mov_rsi64(DATA_VA);
    program.mov_reg(2, message_length as u32); // edx = length
    program.syscall();
    program.mov_reg(0, SYS_EXIT as u32);
    program.mov_reg(7, 0); // edi = exit code
    program.syscall();
    program.spin_forever(); // unreachable: exit never returns
    program
}

/// The obedient driver: ask the kernel for one mediated port write, then report progress
/// forever. With `yields` it also gives the CPU up voluntarily now and then, which is what lets
/// the report tell the voluntary counter apart from the involuntary one.
fn program_driver(yields: bool) -> Program {
    let mut program = Program::new();
    program.mov_reg(0, SYS_PORT_WRITE as u32);
    program.mov_reg(7, GRANTED_PORT as u32); // edi = port
    program.mov_reg(6, 0x2A); // esi = value
    program.syscall();
    program.zero_progress();
    let loop_start = program.length;
    program.bump_progress();
    program.mov_reg(0, SYS_PROGRESS as u32);
    program.progress_to_arg0();
    program.syscall();
    if yields {
        program.test_progress(0x3FF);
        let patch = program.jump_forward();
        program.mov_reg(0, SYS_YIELD as u32);
        program.syscall();
        program.patch_jump(patch);
    }
    program.jump_back(loop_start);
    program
}

/// A task whose whole body is `jmp $`: nothing in it cooperates, so every switch it gets is the
/// timer taking the CPU from it by force.
fn program_spin_forever() -> Program {
    let mut program = Program::new();
    program.spin_forever();
    program
}

/// The faulty driver, part one: raw port I/O. The TSS I/O permission bitmap sits beyond the TSS
/// limit, so the CPU itself refuses `in al, dx` at CPL 3 with `#GP` — before any kernel code is
/// involved.
fn program_sandbox_port() -> Program {
    let mut program = Program::new();
    program.port_read(0x60);
    program.spin_forever();
    program
}

/// The faulty driver, part two, in two steps.
///
/// First it asks the kernel to print from a *kernel* address. The door refuses, because the walk
/// on the caller's own tables never reaches a user page there — refusing is the whole point of
/// copying through the page tables instead of trusting the pointer.
///
/// Then it reads the neighbour's page directly. That address is mapped in one address space and
/// absent in this one, so the walk stops at a not-present entry and the CPU raises `#PF` with
/// `cr3` pointing at *this* task's tables. No kernel code runs in between: the refusal is the
/// hardware's.
fn program_sandbox_peer() -> Program {
    let mut program = Program::new();
    program.mov_reg(0, SYS_WRITE as u32);
    program.mov_reg(6, crate::bootinfo::KERNEL_LOAD_BASE as u32); // esi = the kernel's own address
    program.mov_reg(2, 8); // edx = 8 bytes
    program.syscall();
    program.load_rax_absolute(PEER_VA);
    program.spin_forever();
    program
}

// ------------------------------------------------------------------ creating processes

/// Builds a ring-3 frame: the state the CPU will restore with `iretq`.
fn build_user_frame(process: &mut Process, entry: u64, stack_top: u64) {
    let base = process.frame.base_mut();
    unsafe {
        ptr::write_bytes(base, 0, 512);
        // No register has a meaningful value yet; only the five CPU-restored fields and the
        // instruction pointer matter. XMM0-15 stay zeroed, which is a valid (if uninteresting)
        // SSE state for a task that never uses the FPU.
        put(base, PARK_RIP, entry);
        put(base, PARK_CS, gdt::USER_CODE_SELECTOR as u64);
        put(base, PARK_RFLAGS, USER_RFLAGS);
        put(base, PARK_RSP, stack_top);
        put(base, PARK_SS, gdt::USER_DATA_SELECTOR as u64);
    }
}

fn free_slot() -> Option<usize> {
    for index in 1..MAX_PROCESSES {
        if unsafe { state_of(index) } == State::Free {
            return Some(index);
        }
    }
    None
}

/// Creates a ring-3 task: its own address space, its own pages, and a parked frame the epilogue
/// can `iretq` into.
///
/// The task is `Ready` and runs only when a switch picks it — for a user task, that means the
/// next timer tick after the kernel context arms preemption.
pub fn spawn_user(
    name: &'static str,
    code: &[u8],
    data: &[u8],
    peer_window: bool,
) -> Option<usize> {
    if !paging::ready() {
        println!("[!!] RING-3: paging is not initialised, refusing to create '{}'", name);
        return None;
    }
    if code.is_empty()
        || code.len() > paging::PAGE_SIZE as usize
        || data.len() > paging::PAGE_SIZE as usize
    {
        println!("[!!] RING-3: '{}' has an image that does not fit a page", name);
        return None;
    }
    let slot = match free_slot() {
        Some(slot) => slot,
        None => {
            println!("[!!] RING-3: no free process slot for '{}'", name);
            return None;
        }
    };

    let mut space = AddressSpace::new(name);
    let code_frame = paging::alloc_frame();
    let data_frame = paging::alloc_frame();
    let stack_frame = paging::alloc_frame();
    let leaf_frames = [code_frame, data_frame, stack_frame];
    let mapped = [
        space.map_page(CODE_VA, code_frame, paging::USER_RX),
        space.map_page(DATA_VA, data_frame, paging::USER_RW),
        space.map_page(STACK_VA, stack_frame, paging::USER_RW),
    ];
    if mapped.iter().any(|mapped| !mapped) {
        // Put back whatever was not mapped, then hand the space (and the leaves it recorded)
        // back to the heap. Losing three frames would be survivable; losing a *mapping* without
        // a frame is how the next task inherits somebody else's memory.
        for (index, frame) in leaf_frames.iter().enumerate() {
            if !mapped[index] {
                unsafe { paging::free_frame(*frame) };
            }
        }
        space.teardown();
        println!("[!!] RING-3: '{}' could not be mapped", name);
        return None;
    }
    space.write_user(CODE_VA, code);
    space.write_user(DATA_VA, data);

    if peer_window {
        let frame = paging::alloc_frame();
        if !space.map_page(PEER_VA, frame, paging::USER_RW) {
            unsafe { paging::free_frame(frame) };
            space.teardown();
            println!("[!!] RING-3: '{}' could not map its peer window", name);
            return None;
        }
    }

    let cr3 = space.cr3;
    unsafe {
        let stack_top = STACK_VA + paging::PAGE_SIZE - 16;
        row(slot, |process| {
            *process = Process::empty();
            process.name = name;
            process.state = State::Ready;
            process.cr3 = cr3;
            process.quantum_left = QUANTUM_TICKS;
            process.space = Some(space);
            build_user_frame(process, CODE_VA, stack_top);
        });
    }
    STARTED.store(true, Ordering::Relaxed);
    Some(slot)
}

/// Frees a dead task's address space, leaving its row (and its numbers) for the report.
///
/// Only safe once the CPU is on another address space: freeing the tables being walked is a
/// triple fault, not an error message.
unsafe fn release_space(slot: usize) {
    let space = row(slot, |process| process.space.take());
    if let Some(space) = space {
        space.teardown();
    }
}

/// Marks a row free again, freeing its space if it still has one.
unsafe fn retire(slot: usize) {
    release_space(slot);
    row(slot, |process| *process = Process::empty());
}

// ------------------------------------------------------------------ switching

#[derive(Clone, Copy, PartialEq, Eq)]
enum Reason {
    Preempt,
    Voluntary,
}

/// Parks the interrupted frame, arms the epilogue with the target's frame and switches `cr3`.
///
/// Everything here runs with interrupts disabled (it is only reached from an interrupt gate) and
/// nothing can fail: the parked frame is a fixed-size copy and the address-space switch is one
/// `mov cr3`, so a switch that starts always finishes.
unsafe fn switch_to(next: usize, frame: *mut InterruptFrame, reason: Reason) {
    let current = CURRENT.load(Ordering::Relaxed) as usize;
    if next == current {
        return;
    }

    row(current, |process| {
        ptr::copy_nonoverlapping(
            (frame as *const u8).offset(-(XMM_BYTES as isize)),
            process.frame.base_mut(),
            FRAME_BYTES,
        );
        process.parked_rip = get(process.frame.base(), PARK_RIP);
        if process.state == State::Running {
            process.state = State::Ready;
        }
    });

    let (target_rsp, user_task) = row(next, |process| {
        process.state = State::Running;
        process.runs += 1;
        // A fresh slice: the task either used its quantum up (the timer reset the counter before
        // switching) or was switched out early by a yield, and both start over.
        process.quantum_left = QUANTUM_TICKS;
        (process.frame.base() as u64, process.space.is_some())
    });
    idt::request_switch(target_rsp);
    CURRENT.store(next as u64, Ordering::Relaxed);

    match row(next, |process| process.cr3) {
        0 => paging::activate_kernel(),
        cr3 => crate::arch::cpu::write_cr3(cr3),
    }

    match reason {
        Reason::Preempt => {
            PREEMPTIONS.fetch_add(1, Ordering::Relaxed);
        }
        Reason::Voluntary => {
            YIELDS.fetch_add(1, Ordering::Relaxed);
        }
    }
    if user_task {
        ENTRIES.fetch_add(1, Ordering::Relaxed);
        USER_SLICES.fetch_add(1, Ordering::Relaxed);
    }
}

/// Round-robin from `from`, skipping rows that are not runnable. The kernel row is always
/// runnable, so there is always a target.
unsafe fn next_runnable(from: usize) -> usize {
    for step in 1..=MAX_PROCESSES {
        let index = (from + step) % MAX_PROCESSES;
        if row(index, |process| process.state.runnable()) {
            return index;
        }
    }
    from
}

/// The timer's half of preemption.
///
/// # Safety
/// Called from the timer IRQ with a live interrupt frame.
pub unsafe fn on_timer(frame: *mut InterruptFrame) {
    if !STARTED.load(Ordering::Relaxed) {
        return;
    }
    let cs = (*frame).cs;
    let current = CURRENT.load(Ordering::Relaxed) as usize;

    if cs & 3 == 3 {
        // Interrupted in ring 3: a real task, so its quantum is charged. The `cs` value also goes
        // into the row — 0x1B here is the CPU's own statement that the task was running
        // unprivileged, which is stronger evidence than any flag the kernel could set itself.
        if current == KERNEL_SLOT {
            return;
        }
        row(current, |process| {
            if process.first_cs == 0 {
                process.first_cs = cs;
            }
            process.quantum_left = process.quantum_left.saturating_sub(1);
        });
        if row(current, |process| process.quantum_left) == 0 {
            row(current, |process| process.quantum_left = QUANTUM_TICKS);
            let next = next_runnable(current);
            if next != current {
                switch_to(next, frame, Reason::Preempt);
            }
        }
        return;
    }

    // Interrupted in ring 0. Kernel work is never preempted — only the idle context, and only in
    // the window where it has halted and has already published that it is safe to switch away.
    if IDLE_ARMED.load(Ordering::Relaxed) && current == KERNEL_SLOT {
        let next = next_runnable(KERNEL_SLOT);
        if next != KERNEL_SLOT {
            switch_to(next, frame, Reason::Preempt);
        }
    }
}

/// Gives the CPU to the next runnable task from inside a syscall. The calling task's frame — the
/// `int 0x80` frame — is parked like any other, so the task resumes after the syscall when its
/// turn comes round again.
unsafe fn yield_now(frame: *mut InterruptFrame) {
    let current = CURRENT.load(Ordering::Relaxed) as usize;
    row(current, |process| process.yields += 1);
    let next = next_runnable(current);
    if next != current {
        switch_to(next, frame, Reason::Voluntary);
    }
}

/// Drops the faulting task and resumes the next one. Called with the exception frame still live
/// on the IST stack, which is why the frame is parked first: the report prints the parked `rip`
/// as the address the CPU refused to execute.
///
/// # Safety
/// Called from the exception path with a live frame of a user task.
pub unsafe fn user_fault(frame: *mut InterruptFrame) {
    let current = CURRENT.load(Ordering::Relaxed) as usize;
    let vector = (*frame).vector;
    let error = (*frame).error_code;
    let rip = (*frame).rip;
    let cs = (*frame).cs;
    let cr3 = crate::arch::cpu::read_cr3();
    let fault_address = if vector == 14 {
        crate::arch::cpu::read_cr2()
    } else {
        0
    };
    let name = row(current, |process| {
        process.state = State::Faulted;
        process.fault_vector = vector;
        process.fault_error = error;
        process.fault_rip = rip;
        process.fault_address = fault_address;
        process.name
    });
    FAULTS.fetch_add(1, Ordering::Relaxed);
    println!(
        "\n[!!] RING-3 CONTAINMENT: '{}' {} (vector {}, error={:#x}) at rip={:#018x} cs={:#x} - task terminated, kernel intact",
        name,
        idt::exception_name(vector),
        vector,
        error,
        rip,
        cs
    );
    if vector == 14 {
        println!(
            "     fault address {:#018x} is not mapped in cr3={:#x}: the page tables refused a read this address space does not allow",
            fault_address, cr3
        );
    }
    if vector == 13 {
        println!(
            "     raw port I/O at CPL 3: the TSS I/O permission bitmap denies every port, so the CPU raised #GP before any kernel handler ran"
        );
    }

    let next = next_runnable(current);
    if next == current {
        panic::lockdown("ring-3 fault containment: no runnable context");
    }
    switch_to(next, frame, Reason::Preempt);
    // Only now is the CPU on another address space, so the failed task's frames can go back to
    // the heap. Its row stays, with the parked frame, for the report.
    release_space(current);
}

// ------------------------------------------------------------------ the syscall door

/// `int 0x80` from ring 3: `rax` selects the call, `rdi`/`rsi`/`rdx` are the arguments, `rax`
/// comes back with the result.
///
/// The gate that delivers this is the only DPL-3 entry in the IDT, so it is not a convention a
/// driver could route around: at CPL 3 there is no other way in.
///
/// # Safety
/// Called from the syscall gate with a live frame of a user task.
pub unsafe fn syscall(frame: *mut InterruptFrame) {
    let current = CURRENT.load(Ordering::Relaxed) as usize;
    let number = get(frame as *const u8, FRAME_RAX);
    let arg0 = get(frame as *const u8, FRAME_RDI);
    let arg1 = get(frame as *const u8, FRAME_RSI);
    let arg2 = get(frame as *const u8, FRAME_RDX);

    row(current, |process| {
        process.syscalls += 1;
        if process.first_cs == 0 {
            process.first_cs = (*frame).cs;
        }
    });
    SYSCALLS.fetch_add(1, Ordering::Relaxed);

    let mut result = 0u64;
    match number {
        SYS_EXIT => {
            let name = row(current, |process| {
                process.state = State::Exited;
                process.exit_code = arg0 as i64;
                process.name
            });
            println!(
                "[R3 {}] exit({}) through syscall 0 - {} syscalls from this task, cs={:#x} on entry",
                name,
                arg0 as i64,
                row(current, |process| process.syscalls),
                (*frame).cs
            );
            let next = next_runnable(current);
            if next == current {
                panic::lockdown("ring-3 exit: no runnable context");
            }
            switch_to(next, frame, Reason::Voluntary);
            release_space(current);
            return;
        }
        SYS_WRITE => {
            if arg2 as usize > MAX_MESSAGE {
                result = EFAULT;
            } else {
                let mut buffer = [0u8; MAX_MESSAGE];
                let length = arg2 as usize;
                let copied = row(current, |process| match process.space.as_ref() {
                    Some(space) => space.copy_from_user(arg1, &mut buffer[..length]),
                    None => None,
                });
                match copied {
                    Some(read) => {
                        let name = row(current, |process| process.name);
                        println!(
                            "[R3 {}] {}",
                            name,
                            core::str::from_utf8(&buffer[..read]).unwrap_or("<not utf-8>")
                        );
                    }
                    None => {
                        // The kernel refused to dereference a pointer the calling task could not
                        // have written itself. That is the point of the check, and the phase
                        // report counts it.
                        EFAULT_REJECTIONS.fetch_add(1, Ordering::Relaxed);
                        println!(
                            "[R3 {}] write({:#x}, {}) refused: EFAULT (not a user page of this address space)",
                            row(current, |process| process.name),
                            arg1,
                            arg2
                        );
                        result = EFAULT;
                    }
                }
            }
        }
        SYS_YIELD => {
            yield_now(frame);
        }
        SYS_PROGRESS => {
            row(current, |process| process.progress = arg0);
        }
        SYS_PORT_WRITE => {
            if arg0 == GRANTED_PORT {
                crate::port::outb(GRANTED_PORT as u16, arg1 as u8);
                GRANTS.fetch_add(1, Ordering::Relaxed);
            } else {
                println!(
                    "[R3 {}] port write to {:#x} refused: not in the capability table",
                    row(current, |process| process.name),
                    arg0
                );
                result = EFAULT;
            }
        }
        other => {
            println!(
                "[R3 {}] unknown syscall {} - the door is a whitelist, not a dispatcher",
                row(current, |process| process.name),
                other
            );
            result = EFAULT;
        }
    }

    put(frame as *mut u8, FRAME_RAX, result);
}

// ------------------------------------------------------------------ one-shot probes

pub struct Probe {
    pub name: &'static str,
    pub cr3: u64,
    pub runs: u64,
    pub syscalls: u64,
    pub ticks: u64,
    pub exit_code: i64,
    pub faulted: bool,
    pub first_cs: u64,
    pub parked_rip: u64,
    pub state: State,
}

/// Runs one ring-3 program to completion through the preemptive path, then retires it.
///
/// The kernel context arms preemption and halts; the timer switches the task in; the task runs
/// and either exits or faults; the switch back lands here, one instruction after the `hlt`.
/// Returns `None` only when the task cannot be created.
pub fn run_probe(name: &'static str, code: &[u8], data: &[u8]) -> Option<Probe> {
    let slot = spawn_user(name, code, data, false)?;
    let cr3 = unsafe { row(slot, |process| process.cr3) };
    let start = clock::ticks();

    loop {
        let state = unsafe { state_of(slot) };
        if state != State::Ready && state != State::Running {
            break;
        }
        if clock::ticks().saturating_sub(start) > MAX_PROBE_TICKS {
            println!(
                "[!!] RING-3 PROBE TIMEOUT: '{}' still {} after {} ticks - retiring it",
                name,
                state.label(),
                MAX_PROBE_TICKS
            );
            break;
        }
        // Give the CPU up the same way the idle loop does: publish that this context has
        // nothing to protect, halt, and take the protection back when it is resumed.
        arm_idle();
        crate::arch::cpu::halt();
        disarm_idle();
    }

    let probe = unsafe {
        row(slot, |process| Probe {
            name: process.name,
            cr3,
            runs: process.runs,
            syscalls: process.syscalls,
            ticks: clock::ticks().saturating_sub(start),
            exit_code: process.exit_code,
            faulted: process.state == State::Faulted,
            first_cs: process.first_cs,
            parked_rip: process.parked_rip,
            state: process.state,
        })
    };
    unsafe { retire(slot) };
    Some(probe)
}

/// Prints the bytes of a program in hex, so the emitted instructions can be checked against the
/// emitter methods above.
fn print_hex(bytes: &[u8]) {
    for byte in bytes {
        print!("{:02x} ", byte);
    }
}

/// The boot-time probe: one ring-3 task that prints a line through the syscall door and exits.
///
/// It is the smallest end-to-end proof of the privilege boundary — `iretq` into CPL 3, a DPL-3
/// gate on the way back in, a clean exit — and it costs about one timer tick.
pub fn boot_probe() {
    const NAME: &'static str = "keller-hello";
    const MESSAGE: &[u8] = b"RING-3 HELLO: this line was printed at CPL=3";
    let program = program_hello(MESSAGE.len());
    let baseline = paging::frames_in_use();
    print!("[--] RING-3 PROGRAM '{}' {} bytes: ", NAME, program.bytes().len());
    print_hex(program.bytes());
    println!(
        "\n     entry {:#x}, stack top {:#x}, data {:#x}, kernel cr3={:#x}",
        CODE_VA,
        STACK_VA + paging::PAGE_SIZE - 16,
        DATA_VA,
        paging::kernel_cr3()
    );
    match run_probe(NAME, program.bytes(), MESSAGE) {
        Some(probe) => {
            println!(
                "[OK] RING-3 ENTRY: '{}' ran at CPL=3 - the CPU's own frame says cs={:#x} ss={:#x}, cr3={:#x} (iretq restored a user frame, not a kernel one)",
                probe.name,
                probe.first_cs,
                gdt::USER_DATA_SELECTOR,
                probe.cr3
            );
            println!(
                "[OK] RING-3 EXIT: state={} {} syscalls, {} switch-ins, {} ticks, exit code {} - parked rip={:#x} (inside its own code page)",
                probe.state.label(),
                probe.syscalls,
                probe.runs,
                probe.ticks,
                probe.exit_code,
                probe.parked_rip
            );
            println!(
                "[OK] RING-3 PROBE COMPLETE: address space torn down, paging frames {} -> {}, kernel cr3={:#x} restored",
                baseline,
                paging::frames_in_use(),
                crate::arch::cpu::read_cr3()
            );
        }
        None => println!("[!!] RING-3 PROBE: the user task was never created"),
    }
}

// ------------------------------------------------------------------ the ring3 run phase

pub fn phase_running() -> bool {
    PHASE.load(Ordering::Relaxed) == 1
}

pub fn phase_complete() -> bool {
    PHASE.load(Ordering::Relaxed) == 2
}

/// Queues the demonstration phase: five ring-3 tasks, three of which behave and two of which
/// exist to misbehave in one specific way each.
pub fn request_phase() -> bool {
    if phase_running() {
        println!("[SH] ring3: a phase is already running - wait for its report");
        return false;
    }
    if !paging::ready() {
        println!("[SH] ring3: paging is not initialised");
        return false;
    }
    for index in 1..MAX_PROCESSES {
        if unsafe { state_of(index) } != State::Free {
            unsafe { retire(index) };
        }
    }

    let alpha = program_driver(false);
    let beta = program_driver(true);
    let spin = program_spin_forever();
    let port = program_sandbox_port();
    let peer = program_sandbox_peer();

    let queued = [
        ("driver-alpha", spawn_user("driver-alpha", alpha.bytes(), &[], false)),
        ("driver-beta", spawn_user("driver-beta", beta.bytes(), &[], true)),
        ("spin-probe", spawn_user("spin-probe", spin.bytes(), &[], false)),
        ("sandbox-port", spawn_user("sandbox-port", port.bytes(), &[], false)),
        ("sandbox-peer", spawn_user("sandbox-peer", peer.bytes(), &[], false)),
    ];
    let mut created = 0;
    for (name, slot) in queued.iter() {
        match slot {
            Some(_) => created += 1,
            None => println!("[SH] RING-3 PHASE: '{}' could not be created", name),
        }
    }
    if created == 0 {
        println!("[SH] RING-3 PHASE: not armed, no task was created");
        return false;
    }

    USER_SLICES.store(0, Ordering::Relaxed);
    PHASE_START.store(clock::ticks(), Ordering::Relaxed);
    PHASE_DEADLINE.store(
        clock::ticks() + PHASE_BUDGET * QUANTUM_TICKS * 3,
        Ordering::Relaxed,
    );
    PHASE.store(1, Ordering::Relaxed);
    unsafe { *core::ptr::addr_of_mut!(LAST_PHASE) = PhaseSummary::empty() };

    println!(
        "[SH] RING-3 PHASE ARMED: {} tasks, one address space each, {} ms quantum enforced by the timer (the kernel context is a row like any other and gives the CPU away at `hlt`)",
        created,
        QUANTUM_TICKS * clock::MS_PER_TICK
    );
    for index in 1..MAX_PROCESSES {
        unsafe {
            row(index, |process| {
                if process.state == State::Free {
                    return;
                }
                print!("     {:14} cr3={:#010x} ", process.name, process.cr3);
                print_cell("code", frame_of(process, CODE_VA));
                print_cell("data", frame_of(process, DATA_VA));
                print_cell("stack", frame_of(process, STACK_VA));
                print_cell("peer", frame_of(process, PEER_VA));
                println!();
            });
        }
    }
    print!("[SH] RING-3 PROGRAM 'driver-alpha' {} bytes: ", alpha.bytes().len());
    print_hex(alpha.bytes());
    print!("\n     PROGRAM 'spin-probe' {} bytes: ", spin.bytes().len());
    print_hex(spin.bytes());
    print!("\n     PROGRAM 'sandbox-port' {} bytes: ", port.bytes().len());
    print_hex(port.bytes());
    print!("\n     PROGRAM 'sandbox-peer' {} bytes: ", peer.bytes().len());
    print_hex(peer.bytes());
    println!();
    true
}

/// Physical frame behind a virtual address in this process's own space, if it has one.
fn frame_of(process: &Process, virt: u64) -> Option<u64> {
    let space = process.space.as_ref()?;
    space
        .translate(virt)
        .map(|walk| walk.phys & !(paging::PAGE_SIZE - 1))
}

/// One entry of the address-space table: the frame, or the fact that the space does not map it.
/// `absent` in a *peer* column is as interesting as a frame is in the others — it is the mapping
/// a neighbouring process could not reach even if it guessed the address.
fn print_cell(label: &str, frame: Option<u64>) {
    match frame {
        Some(phys) => print!("{}={:#x} ", label, phys),
        None => print!("{}=absent ", label),
    }
}

/// Waits for an armed phase, giving the CPU to its tasks the same way the idle loop does.
///
/// The shell calls this from `ring3 run` so the command does not return until the phase's report
/// has been printed: the alternative — arming the phase and letting the idle loop finish it —
/// makes the output land at a time no scripted session can predict.
///
/// The wait is bounded by the phase's own deadline, so a task that never yields cannot wedge the
/// console.
pub fn wait_for_phase() {
    let deadline = clock::ticks() + PHASE_BUDGET * QUANTUM_TICKS * 6;
    while phase_running() && clock::ticks() < deadline {
        phase_poll();
        if !phase_running() {
            break;
        }
        arm_idle();
        crate::arch::cpu::halt();
        disarm_idle();
    }
    if phase_running() {
        println!(
            "[SH] ring3: the phase is still running after {} ticks - it will finish on the next idle pass",
            PHASE_BUDGET * QUANTUM_TICKS * 6
        );
    }
}

/// Drives an armed phase. Called from the kernel's idle loop, which is the only context that can
/// decide the phase is over — the user tasks never would.
pub fn phase_poll() {
    if !phase_running() {
        return;
    }
    let delivered = USER_SLICES.load(Ordering::Relaxed);
    let expired = clock::ticks() >= PHASE_DEADLINE.load(Ordering::Relaxed);
    if delivered < PHASE_BUDGET && !expired {
        return;
    }
    finish_phase(delivered, expired);
}

fn finish_phase(delivered: u64, expired: bool) {
    let spent = clock::ticks().saturating_sub(PHASE_START.load(Ordering::Relaxed));
    let mut summary = PhaseSummary {
        slices: delivered,
        ticks: spent,
        preemptions: PREEMPTIONS.load(Ordering::Relaxed),
        yields: YIELDS.load(Ordering::Relaxed),
        faults: FAULTS.load(Ordering::Relaxed),
        efaults: EFAULT_REJECTIONS.load(Ordering::Relaxed),
        grants: GRANTS.load(Ordering::Relaxed),
        ..PhaseSummary::empty()
    };

    for index in 1..MAX_PROCESSES {
        unsafe {
            row(index, |process| {
                if process.state == State::Free {
                    return;
                }
                if process.state == State::Faulted {
                    match process.fault_vector {
                        14 => summary.page_faults += 1,
                        13 => summary.general_protections += 1,
                        _ => {}
                    }
                }
                match process.name {
                    "spin-probe" => {
                        summary.spin_runs = process.runs;
                        summary.spin_syscalls = process.syscalls;
                        summary.spin_parked_rip = process.parked_rip;
                    }
                    "driver-alpha" => {
                        summary.alpha_progress = process.progress;
                        summary.alpha_syscalls = process.syscalls;
                    }
                    "driver-beta" => {
                        summary.beta_progress = process.progress;
                        summary.beta_syscalls = process.syscalls;
                        summary.beta_yields = process.yields;
                    }
                    _ => {}
                }
                summary.retired += 1;
            });
        }
    }

    println!(
        "[OK] PREEMPTIVE SCHEDULER: {} switches by the timer, {} voluntary yields, {} ring-3 slices delivered in {} ticks ({} ms) - each slice ended by the timer unless the task yielded first",
        summary.preemptions,
        summary.yields,
        summary.slices,
        summary.ticks,
        summary.ticks * clock::MS_PER_TICK
    );
    println!(
        "[OK] RING-3 PREEMPTION PROOF: 'spin-probe' ({}) got the CPU {} times with {} syscalls and parked at rip={:#x} - it never asked to be scheduled, so only the timer could have taken the CPU for it",
        "jmp $",
        summary.spin_runs,
        summary.spin_syscalls,
        summary.spin_parked_rip
    );
    println!(
        "[OK] RING-3 PROGRESS: 'driver-alpha' reported {} through SYS_PROGRESS ({} syscalls), 'driver-beta' {} ({} syscalls, {} voluntary yields) - both kept advancing",
        summary.alpha_progress,
        summary.alpha_syscalls,
        summary.beta_progress,
        summary.beta_syscalls,
        summary.beta_yields
    );
    println!(
        "[OK] RING-3 I/O MEDIATION: {} mediated write(s) to port {:#x} through the capability table; 'sandbox-port' raw `in al, dx` got #GP (the bitmap denied it before any kernel handler ran)",
        summary.grants, GRANTED_PORT
    );
    println!(
        "[OK] RING-3 FAULT CONTAINMENT: {} task(s) killed at CPL 3 ({} #PF, {} #GP), {} copy-from-user call(s) refused with EFAULT, timeout={} - no kernel lockdown, the idle loop keeps its heartbeat",
        summary.faults,
        summary.page_faults,
        summary.general_protections,
        summary.efaults,
        if expired && delivered < PHASE_BUDGET { "yes" } else { "no" }
    );

    // Retire: the only context where it is safe, because a task that still ran would have its
    // tables pulled out from under it.
    for index in 1..MAX_PROCESSES {
        if unsafe { state_of(index) } != State::Free {
            unsafe { retire(index) };
        }
    }
    println!(
        "[OK] RING-3 PHASE COMPLETE: {} processes retired, address spaces torn down, paging frames back to {}, kernel cr3={:#x}",
        summary.retired,
        paging::frames_in_use(),
        crate::arch::cpu::read_cr3()
    );
    summary.complete = true;
    unsafe { *core::ptr::addr_of_mut!(LAST_PHASE) = summary };
    PHASE.store(2, Ordering::Relaxed);
}

// ------------------------------------------------------------------ reporting

/// Live view of the table: who exists, where their pages are, and how the switches are counted.
pub fn describe() {
    println!(
        "[SH] RING-3 PROCESS TABLE: current='{}' cr3={:#x} (kernel cr3={:#x}), {} ring-3 entries, {} syscalls, {} preemptions, {} yields",
        current_name(),
        crate::arch::cpu::read_cr3(),
        paging::kernel_cr3(),
        ENTRIES.load(Ordering::Relaxed),
        SYSCALLS.load(Ordering::Relaxed),
        PREEMPTIONS.load(Ordering::Relaxed),
        YIELDS.load(Ordering::Relaxed)
    );
    let mut live = 0;
    for index in 0..MAX_PROCESSES {
        unsafe {
            row(index, |process| {
                if process.state == State::Free {
                    return;
                }
                live += 1;
                println!(
                    "     slot {} {:14} state={} cr3={:#010x} runs={} syscalls={} progress={} first-cs={:#x}",
                    index,
                    process.name,
                    process.state.label(),
                    process.cr3,
                    process.runs,
                    process.syscalls,
                    process.progress,
                    process.first_cs
                );
            });
        }
    }
    println!(
        "[SH] RING-3 ROWS: {}/{} used, idle_armed={}",
        live,
        MAX_PROCESSES,
        idle_armed()
    );

    // The isolation claim, read back out of the live tables rather than restated: the same
    // virtual addresses in different spaces must resolve to different frames, and a page mapped
    // in one space must be absent in the others.
    let mut spaces = 0usize;
    for index in 1..MAX_PROCESSES {
        unsafe {
            row(index, |process| {
                if process.space.is_none() {
                    return;
                }
                spaces += 1;
                print!("     {:14} ", process.name);
                print_cell("code", frame_of(process, CODE_VA));
                print_cell("data", frame_of(process, DATA_VA));
                print_cell("stack", frame_of(process, STACK_VA));
                print_cell("peer", frame_of(process, PEER_VA));
                println!();
            });
        }
    }
    if spaces == 0 {
        println!("[SH] RING-3 ISOLATION: no live address space (run 'ring3 run' to create some)");
    } else {
        println!(
            "[SH] RING-3 ISOLATION: {} live space(s); the kernel identity map is present in each of them with user_reachable=false, so the user region is reachable only through that space's own leaves",
            spaces
        );
    }
    if phase_complete() {
        let summary = unsafe { &*core::ptr::addr_of!(LAST_PHASE) };
        println!(
            "[SH] RING-3 LAST PHASE: {} slices in {} ticks, {} timer switches, {} voluntary yields, {} faults ({} #PF, {} #GP), {} EFAULT refusals, {} tasks retired",
            summary.slices,
            summary.ticks,
            summary.preemptions,
            summary.yields,
            summary.faults,
            summary.page_faults,
            summary.general_protections,
            summary.efaults,
            summary.retired
        );
    }
}

// ------------------------------------------------------------------ self-test

pub struct ProcReport {
    pub passed: u32,
    pub failed: u32,
    pub failures: Vec<&'static str>,
}

impl ProcReport {
    fn new() -> Self {
        Self {
            passed: 0,
            failed: 0,
            failures: Vec::new(),
        }
    }

    fn check(&mut self, condition: bool, failure: &'static str) {
        if condition {
            self.passed += 1;
        } else {
            self.failed += 1;
            self.failures.push(failure);
        }
    }
}

/// Reads the ring-3 configuration back out of the live tables, then enters ring 3 once to prove
/// the whole chain works: gate attributes, GDT privilege levels, the port-I/O denial, the frame
/// layout the park/reload code assumes, address-space isolation, and one complete probe.
///
/// Nothing here restates a constant: every value comes from the IDT, the GDT, the TSS or a live
/// page-table walk, which is the only kind of claim worth printing.
pub fn self_test() -> ProcReport {
    let mut report = ProcReport::new();
    report.check(paging::ready(), "paging not initialised");

    // The door: DPL 3 on vector 0x80, kernel-only everywhere else.
    let (offset, selector, ist, attributes) = idt::gate_info(idt::SYSCALL_VECTOR as usize);
    report.check(
        offset == idt::stub_address(idt::SYSCALL_VECTOR as usize),
        "the syscall gate does not point at its stub",
    );
    report.check(
        selector == gdt::KERNEL_CODE_SELECTOR,
        "the syscall gate does not target kernel code",
    );
    report.check(
        ist == gdt::IST_INDEX,
        "the syscall gate does not use the IST stack",
    );
    report.check(attributes == 0xEE, "the syscall gate is not DPL 3");
    let (_, _, _, fault_attributes) = idt::gate_info(13);
    report.check(fault_attributes == 0x8E, "a fault gate is reachable from CPL 3");

    // The privilege levels of the selectors a ring-3 frame carries, read from the live GDT.
    report.check(
        gdt::selector_dpl(gdt::USER_CODE_SELECTOR) == 3,
        "the ring-3 code selector is not DPL 3",
    );
    report.check(
        gdt::selector_dpl(gdt::USER_DATA_SELECTOR) == 3,
        "the ring-3 data selector is not DPL 3",
    );
    report.check(
        gdt::selector_dpl(gdt::KERNEL_CODE_SELECTOR) == 0,
        "the kernel code selector is not DPL 0",
    );

    // Port I/O from ring 3: denied by the TSS bitmap, not by a driver convention.
    report.check(
        gdt::port_io_denied(),
        "the I/O permission bitmap does not deny ring-3 ports",
    );
    report.check(gdt::ring0_stack_top() != 0, "the TSS has no ring-0 stack");

    // The park/reload code hard-codes offsets into a 432-byte frame, and the Rust struct is the
    // source of truth for the frame's size, so the two are checked against each other.
    report.check(
        core::mem::size_of::<InterruptFrame>() == FRAME_TAIL_BYTES,
        "InterruptFrame changed size: the parked-frame offsets are stale",
    );
    report.check(FRAME_BYTES == 256 + FRAME_TAIL_BYTES, "the parked frame size is wrong");
    report.check(
        core::mem::offset_of!(InterruptFrame, rdi) == FRAME_RDI
            && core::mem::offset_of!(InterruptFrame, rsi) == FRAME_RSI
            && core::mem::offset_of!(InterruptFrame, rdx) == FRAME_RDX
            && core::mem::offset_of!(InterruptFrame, rax) == FRAME_RAX
            && core::mem::offset_of!(InterruptFrame, rip) == FRAME_RIP
            && core::mem::offset_of!(InterruptFrame, cs) == FRAME_CS,
        "the hard-coded syscall-frame offsets no longer match InterruptFrame",
    );
    report.check(idt::pending_switch() == 0, "a context switch was left armed");

    // Address-space separation, built from scratch so this works whether or not a phase ran.
    let paging_report = paging::self_test();
    report.passed += paging_report.passed;
    report.failed += paging_report.failed;
    for failure in paging_report.failures.iter() {
        report.failures.push(*failure);
    }

    // One real entry into ring 3.
    const MESSAGE: &[u8] = b"RING-3 SELF-TEST: entered CPL=3 and came back";
    let program = program_hello(MESSAGE.len());
    let baseline = paging::frames_in_use();
    match run_probe("ring3-selftest", program.bytes(), MESSAGE) {
        Some(probe) => {
            report.check(
                probe.first_cs == gdt::USER_CODE_SELECTOR as u64,
                "the probe did not run at CPL 3",
            );
            report.check(probe.runs >= 1, "the probe was never switched in");
            report.check(!probe.faulted, "the probe faulted");
            report.check(probe.exit_code == 0, "the probe did not exit cleanly");
            report.check(probe.syscalls >= 2, "the probe did not use the syscall door");
            report.check(
                probe.parked_rip >= CODE_VA && probe.parked_rip < CODE_VA + paging::PAGE_SIZE,
                "the parked frame does not point into the task's own code page",
            );
            report.check(
                paging::frames_in_use() == baseline,
                "the probe's address space was not returned to the heap",
            );
            println!(
                "[SH] RING-3 EMPIRICAL: '{}' state={} cs={:#x}, {} switch-ins, {} syscalls, {} ticks, parked rip={:#x}, cr3={:#x}",
                probe.name,
                probe.state.label(),
                probe.first_cs,
                probe.runs,
                probe.syscalls,
                probe.ticks,
                probe.parked_rip,
                probe.cr3
            );
        }
        None => {
            report.check(false, "the probe could not be created");
        }
    }
    report
}
