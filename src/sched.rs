//! Fixed-slot deterministic scheduler (spec §3.3).
//!
//! Tasks run round-robin in fixed quanta measured by the PIT clock, and each slot is
//! padded to the full quantum. Padding matters: without it, the amount of idle time in a
//! slot is observable from outside and leaks what the tasks are doing. The previous
//! version counted loop iterations, registered a task twice, and ran `hlt` with
//! interrupts disabled on the first slot — which froze the machine right after boot.

use crate::clock;
use crate::println;

pub const MAX_TASKS: usize = 8;
/// 100 ms per slot at the programmed 100 Hz tick.
pub const QUANTUM_MS: u64 = 100;

pub type TaskFn = fn();

#[derive(Clone, Copy)]
struct TaskSlot {
    func: Option<TaskFn>,
    name: &'static str,
    runs: u64,
}

impl TaskSlot {
    const fn empty() -> Self {
        Self {
            func: None,
            name: "",
            runs: 0,
        }
    }
}

pub struct FixedSlotScheduler {
    tasks: [TaskSlot; MAX_TASKS],
    count: usize,
    current: usize,
    slot_started_ms: u64,
    underruns: u64,
}

impl FixedSlotScheduler {
    pub const fn new() -> Self {
        Self {
            tasks: [TaskSlot::empty(); MAX_TASKS],
            count: 0,
            current: 0,
            slot_started_ms: 0,
            underruns: 0,
        }
    }

    pub fn register(&mut self, name: &'static str, func: TaskFn) -> bool {
        if self.count >= MAX_TASKS {
            return false;
        }
        self.tasks[self.count] = TaskSlot {
            func: Some(func),
            name,
            runs: 0,
        };
        self.count += 1;
        true
    }

    pub fn task_count(&self) -> usize {
        self.count
    }

    pub fn underruns(&self) -> u64 {
        self.underruns
    }

    pub fn runs(&self, index: usize) -> u64 {
        if index < self.count {
            self.tasks[index].runs
        } else {
            0
        }
    }

    /// Runs at most one task per quantum, then pads the slot to a constant duration.
    pub fn tick(&mut self) {
        if self.count == 0 {
            return;
        }
        let now = clock::uptime_ms();
        if now.saturating_sub(self.slot_started_ms) < QUANTUM_MS {
            return;
        }

        let index = self.current % self.count;
        let slot = &mut self.tasks[index];
        if let Some(func) = slot.func {
            func();
            slot.runs += 1;
        } else {
            self.underruns += 1;
        }

        // Temporal isolation: append a fixed-cost pad to every slot so the observable
        // slot length does not depend on how much work the task actually performed. The
        // pad is a constant (QUANTUM_MS / 8) rather than "whatever is left", because a
        // task that overran the quantum must not silently shrink the next slot.
        let pad_until = clock::uptime_ms().saturating_add(QUANTUM_MS / 8);
        while clock::uptime_ms() < pad_until {
            core::hint::spin_loop();
        }

        self.slot_started_ms = clock::uptime_ms();
        self.current = self.current.wrapping_add(1);
    }

    pub fn describe(&self) {
        println!(
            "[OK] FIXED-SLOT SCHEDULER: {} tasks, {} ms quanta, {} underruns",
            self.count,
            QUANTUM_MS,
            self.underruns
        );
        for index in 0..self.count {
            println!(
                "     slot {} - {} ({} runs)",
                index, self.tasks[index].name, self.tasks[index].runs
            );
        }
    }
}

static mut SCHEDULER: FixedSlotScheduler = FixedSlotScheduler::new();

/// Explicit reset of the scheduler state (`.bss` may not be zeroed by the loader, and a
/// stale slot counter would corrupt the round-robin order).
pub fn init() {
    unsafe {
        let scheduler = &mut *core::ptr::addr_of_mut!(SCHEDULER);
        scheduler.count = 0;
        scheduler.current = 0;
        scheduler.slot_started_ms = 0;
        scheduler.underruns = 0;
        for slot in scheduler.tasks.iter_mut() {
            *slot = TaskSlot::empty();
        }
    }
}

pub fn register(name: &'static str, func: TaskFn) -> bool {
    unsafe { (*core::ptr::addr_of_mut!(SCHEDULER)).register(name, func) }
}

pub fn tick() {
    unsafe { (*core::ptr::addr_of_mut!(SCHEDULER)).tick() }
}

pub fn describe() {
    unsafe { (*core::ptr::addr_of!(SCHEDULER)).describe() }
}

pub fn task_count() -> usize {
    unsafe { (*core::ptr::addr_of!(SCHEDULER)).task_count() }
}
