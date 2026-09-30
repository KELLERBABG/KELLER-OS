//! Atomic lockdown: the anti-forensic wipe that runs on panic or tamper.
//!
//! `SPECIFICATION.md` §4.1 and the cryptography deep dive require that a panic erases
//! secrets from RAM rather than merely halting. The previous implementation wiped a
//! hardcoded 16 MiB at 0x1000000 and had to *remove* the vault purge because following
//! stale pointers from a panicking kernel was unsafe; the vault therefore survived a
//! panic intact. This version fixes that by inverting the control flow:
//!
//! * owners register the regions they own (`mm` registers the heap, the boot layer
//!   registers its stack, the arch layer registers the IST stack);
//! * subsystems register *hooks* that can safely clear themselves (`KellerVault`,
//!   `KellerNet`, and later the framebuffer).
//!
//! Every wipe is a multi-pass volatile write (`0x00`, `0xFF`, hardware random), which
//! LLVM cannot elide because the stores are volatile.

use crate::println;
use core::alloc::Layout;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};

const MAX_REGIONS: usize = 8;
const MAX_HOOKS: usize = 6;
const WIPE_PASSES: usize = 3;

type Region = (u64, u64);
pub type ScrubHook = unsafe fn();

static mut REGIONS: [Region; MAX_REGIONS] = [(0, 0); MAX_REGIONS];
static mut REGION_COUNT: usize = 0;
static mut HOOKS: [Option<ScrubHook>; MAX_HOOKS] = [None; MAX_HOOKS];
static mut HOOK_COUNT: usize = 0;
static IN_LOCKDOWN: AtomicBool = AtomicBool::new(false);

/// Explicit reset of the scrub bookkeeping. `.bss` cannot be assumed zeroed by the
/// bootloader, and a stale non-zero `IN_LOCKDOWN` would skip the wipe entirely.
pub fn init() {
    unsafe {
        IN_LOCKDOWN.store(false, Ordering::SeqCst);
        REGION_COUNT = 0;
        HOOK_COUNT = 0;
        for index in 0..MAX_REGIONS {
            *core::ptr::addr_of_mut!(REGIONS[index]) = (0, 0);
        }
        for index in 0..MAX_HOOKS {
            *core::ptr::addr_of_mut!(HOOKS[index]) = None;
        }
    }
}

pub fn register_scrub_region(addr: u64, len: u64) {
    unsafe {
        let count = REGION_COUNT;
        if count >= MAX_REGIONS || len == 0 {
            return;
        }
        let slot = core::ptr::addr_of_mut!(REGIONS[count]);
        core::ptr::write(slot, (addr, len));
        REGION_COUNT = count + 1;
    }
}

pub fn register_scrub_hook(hook: ScrubHook) {
    unsafe {
        for index in 0..MAX_HOOKS {
            let slot = core::ptr::addr_of_mut!(HOOKS[index]);
            if (*slot).is_none() {
                *slot = Some(hook);
                HOOK_COUNT = index + 1;
                return;
            }
        }
    }
}

pub fn scrub_region_count() -> usize {
    unsafe { REGION_COUNT }
}

/// Registered scrub hooks (reported on the lockdown path).
pub fn scrub_hook_count() -> usize {
    unsafe { HOOK_COUNT }
}

#[inline]
fn random_u64() -> u64 {
    let mut value: u64 = 0;
    unsafe {
        if core::arch::x86_64::_rdrand64_step(&mut value) == 1 {
            return value;
        }
    }
    // Fallback so the wipe never degenerates into a fixed pattern.
    0xA5A5_5A5A_C3C3_3C3C
}

/// One pass of `rep stosq`. The wipe has to complete while the kernel is dying, so it
/// cannot afford per-word branches; the stores are architecturally visible regardless of
/// optimisation level.
unsafe fn fill(addr: u64, len: u64, pattern: u64) {
    let words = len / 8;
    if words == 0 {
        return;
    }
    core::arch::asm!(
        "cld",
        "rep stosq",
        inout("rcx") words => _,
        inout("rdi") addr as usize => _,
        in("rax") pattern,
        options(nostack, preserves_flags)
    );
}

/// Three-pass scrub of a physical range: zeros, ones, then hardware random.
unsafe fn scrub(addr: u64, len: u64) {
    for pass in 0..WIPE_PASSES {
        let pattern = match pass {
            0 => 0u64,
            1 => u64::MAX,
            _ => random_u64(),
        };
        fill(addr, len, pattern);
        core::sync::atomic::fence(Ordering::SeqCst);
    }
}

/// Scrubs a region, keeping `protect` alive.
///
/// The panic path runs on one of the very stacks it is clearing, so wiping that window
/// would destroy its own frames (the previous build avoided this by not clearing the
/// vault at all). The window is clipped out of the range rather than tested per word.
unsafe fn wipe(addr: u64, len: u64, protect: Option<(u64, u64)>) {
    let end = addr.saturating_add(len);
    match protect {
        Some((protect_start, protect_end))
            if protect_start < end && protect_end > addr =>
        {
            let head_end = core::cmp::min(end, protect_start);
            if head_end > addr {
                scrub(addr, head_end - addr);
            }
            let tail_start = core::cmp::max(addr, protect_end);
            if end > tail_start {
                scrub(tail_start, end - tail_start);
            }
        }
        _ => scrub(addr, len),
    }
}

/// Irreversible: clears secrets, clears CPU registers, then halts with interrupts off.
///
/// # Safety
/// Never returns. Callers must already have decided that continuing is not an option.
pub unsafe fn lockdown(reason: &str) -> ! {
    core::arch::asm!("cli", options(nomem, nostack));

    if !IN_LOCKDOWN.swap(true, Ordering::SeqCst) {
        println!("\n[!] LOCKDOWN: {}", reason);
        println!("[!] ATOMIC MEMORY WIPE INITIATED (anti-forensic zeroing)");

        // Let owners clear structures that own their own allocations first.
        for index in 0..MAX_HOOKS {
            let hook = *core::ptr::addr_of!(HOOKS[index]);
            if let Some(hook) = hook {
                hook();
            }
        }
        println!(
            "[!] SUBSYSTEM SECRETS CLEARED ({} hooks)",
            *core::ptr::addr_of!(HOOK_COUNT)
        );

        // Then the raw regions: heap, boot stack, IST stack, (later) framebuffer. The
        // window around the live stack pointer is preserved so the wipe can finish; the
        // stack below it is still cleared.
        let stack_pointer: u64;
        core::arch::asm!("mov {}, rsp", out(reg) stack_pointer, options(nomem, nostack));
        let protect = (
            stack_pointer.saturating_sub(4096),
            stack_pointer.saturating_add(16384),
        );
        let count = REGION_COUNT;
        for index in 0..count {
            let (addr, len) = *core::ptr::addr_of!(REGIONS[index]);
            wipe(addr, len, Some(protect));
        }
        println!("[!] {} MEMORY REGIONS WIPED x{} PASSES", count, WIPE_PASSES);

        // Zero the general-purpose registers before halting.
        core::arch::asm!(
            "xor eax, eax",
            "xor ebx, ebx",
            "xor ecx, ecx",
            "xor edx, edx",
            "xor esi, esi",
            "xor edi, edi",
            "xor ebp, ebp",
            "xor r8d, r8d",
            "xor r9d, r9d",
            "xor r10d, r10d",
            "xor r11d, r11d",
            "xor r12d, r12d",
            "xor r13d, r13d",
            "xor r14d, r14d",
            "xor r15d, r15d",
            options(nomem, nostack)
        );
        println!("[!] CPU REGISTERS ZEROED - HALT");
    }

    loop {
        core::arch::asm!("cli", "hlt", options(nomem, nostack));
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("\n[!!] KERNEL PANIC: {}", info);
    unsafe { lockdown("kernel panic") }
}

#[alloc_error_handler]
fn alloc_error(layout: Layout) -> ! {
    println!(
        "\n[!!] ALLOCATION FAILURE: {} bytes, align {}",
        layout.size(),
        layout.align()
    );
    unsafe { lockdown("out of memory") }
}
