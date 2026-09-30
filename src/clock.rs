//! Monotonic kernel clock driven by the PIT.
//!
//! The previous kernel counted scheduler *loop iterations* and called them ticks, which
//! made every timeout in the design documents meaningless. The timer IRQ now advances a
//! real 100 Hz counter, and all session/quota arithmetic is expressed in milliseconds.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// PIT frequency programmed in `arch::pic::init`. 10 ms per tick.
pub const TICKS_PER_SECOND: u64 = 100;
pub const MS_PER_TICK: u64 = 1000 / TICKS_PER_SECOND;

static TICKS: AtomicU64 = AtomicU64::new(0);
static TICK_OVERFLOW: AtomicU32 = AtomicU32::new(0);

/// Explicit reset of the clock state. `.bss` cannot be assumed zeroed by the
/// bootloader, so counters are initialised here rather than relying on a static
/// initialiser (which LLVM is free to place in `.bss`).
pub fn init() {
    TICKS.store(0, Ordering::Relaxed);
    TICK_OVERFLOW.store(0, Ordering::Relaxed);
}

/// Called from the timer IRQ handler.
pub fn on_tick() {
    TICKS.fetch_add(1, Ordering::Relaxed);
}

/// Records a lost timer interrupt so drift is visible instead of silent.
pub fn note_overflow() {
    TICK_OVERFLOW.fetch_add(1, Ordering::Relaxed);
}

pub fn ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

pub fn overflow_count() -> u32 {
    TICK_OVERFLOW.load(Ordering::Relaxed)
}

pub fn uptime_ms() -> u64 {
    ticks() * MS_PER_TICK
}

/// Converts a millisecond duration into whole ticks, rounding up.
pub fn ms_to_ticks(ms: u64) -> u64 {
    (ms + MS_PER_TICK - 1) / MS_PER_TICK
}

/// Spins until the tick counter advances by `ticks`. Requires interrupts to be enabled;
/// the boot self-test uses it to prove the timer is live.
pub fn wait_ticks(ticks_to_wait: u64) {
    let target = ticks() + ticks_to_wait;
    while ticks() < target {
        core::hint::spin_loop();
    }
}
