//! Privileged CPU helpers.

#[inline]
pub unsafe fn disable_interrupts() {
    core::arch::asm!("cli", options(nomem, nostack));
}

#[inline]
pub unsafe fn enable_interrupts() {
    core::arch::asm!("sti", options(nomem, nostack));
}

#[inline]
pub fn interrupts_enabled() -> bool {
    let flags: u64;
    unsafe { core::arch::asm!("pushfq", "pop {}", out(reg) flags, options(nomem)) };
    flags & (1 << 9) != 0
}

/// Halt until the next interrupt. Interrupts must be enabled, otherwise this never
/// returns — the bug that froze the previous kernel on its first scheduler slot.
#[inline]
pub fn halt() {
    unsafe { core::arch::asm!("hlt", options(nomem, nostack)) };
}

#[inline]
pub fn read_cr2() -> u64 {
    let value: u64;
    unsafe { core::arch::asm!("mov {}, cr2", out(reg) value, options(nomem, nostack)) };
    value
}

#[inline]
pub fn read_cr3() -> u64 {
    let value: u64;
    unsafe { core::arch::asm!("mov {}, cr3", out(reg) value, options(nomem, nostack)) };
    value
}

#[inline]
pub fn read_rsp() -> u64 {
    let value: u64;
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) value, options(nomem, nostack)) };
    value
}

/// Loads a new page-table root.
///
/// Writing `cr3` is also the TLB flush on this machine: the kernel keeps PGE set but never
/// marks a page global, so no translation of the outgoing address space survives the switch.
#[inline]
pub unsafe fn write_cr3(value: u64) {
    core::arch::asm!("mov cr3, {}", in(reg) value, options(nomem, nostack));
}

/// Drops one virtual address from the TLB (`invlpg`).
#[inline]
pub fn invalidate_page(virtual_address: u64) {
    unsafe { core::arch::asm!("invlpg [{}]", in(reg) virtual_address, options(nomem, nostack)) };
}

/// Enables the FPU/SSE units. SSE2 is part of the x86_64 ABI, so the compiler may emit
/// vector moves (for example inside `memcpy`) even though the kernel never does floating
/// point arithmetic; without OSFXSR/OSXMMEXCPT set those instructions fault.
pub unsafe fn enable_fpu_sse() {
    let mut cr0: u64;
    core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack));
    cr0 &= !(1 << 2); // clear EM: no FPU emulation
    cr0 |= 1 << 1; // set MP
    core::arch::asm!("mov cr0, {}", in(reg) cr0, options(nomem, nostack));

    let mut cr4: u64;
    core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack));
    cr4 |= (1 << 9) | (1 << 10); // OSFXSR | OSXMMEXCPT
    cr4 |= 1 << 7; // PGE: global pages
    core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack));
}

/// Time-stamp counter. Not a clock this kernel times anything with (the TSC's frequency is a
/// firmware property, and this machine has no calibrated value for it) but a monotonic counter
/// that lets each core prove it ran code of its own, in the order the reports claim.
#[inline]
pub fn read_tsc() -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        core::arch::asm!("rdtsc", out("eax") low, out("edx") high, options(nomem, nostack));
    }
    ((high as u64) << 32) | low as u64
}

/// Reads a model-specific register. Privileged, ring 0 only.
#[inline]
pub fn read_msr(register: u32) -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") register,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack)
        );
    }
    ((high as u64) << 32) | low as u64
}

/// Writes a model-specific register. Privileged, ring 0 only.
#[inline]
pub fn write_msr(register: u32, value: u64) {
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") register,
            in("eax") value as u32,
            in("edx") (value >> 32) as u32,
            options(nomem, nostack)
        );
    }
}

/// CPU vendor string from CPUID leaf 0 ("GenuineIntel", "AuthenticAMD", ...).
pub fn vendor() -> [u8; 12] {
    let leaf = core::arch::x86_64::__cpuid(0);
    let mut vendor = [0u8; 12];
    vendor[0..4].copy_from_slice(&leaf.ebx.to_le_bytes());
    vendor[4..8].copy_from_slice(&leaf.edx.to_le_bytes());
    vendor[8..12].copy_from_slice(&leaf.ecx.to_le_bytes());
    vendor
}

/// True when the CPU advertises RDRAND (CPUID leaf 1, ECX bit 30). The RNG path relies
/// on it for entropy and for the Poisson cover-traffic jitter.
pub fn has_rdrand() -> bool {
    core::arch::x86_64::__cpuid(1).ecx & (1 << 30) != 0
}
