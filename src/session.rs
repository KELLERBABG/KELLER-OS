//! Kernel session guard: a 128-bit sliding replay window plus wall-clock timeouts.
//!
//! Every packet that arrives on a session carries a monotonically increasing counter. The
//! guard stores the highest counter seen (`v_max`) and a bitmap of the 128 counters below
//! it, so:
//!
//! * a counter ahead of `v_max` advances the window and is accepted;
//! * a counter inside the window that arrives out of order is accepted once;
//! * a counter already marked in the bitmap is a replay and is refused;
//! * a counter more than 128 behind `v_max` is outside the window and is refused.
//!
//! Timeouts are wall-clock milliseconds (`clock::uptime_ms`), not raw ticks, so the
//! constants read the same way the specification writes them.

use crate::clock;

/// Absolute session lifetime.
pub const HARD_TIMEOUT_MS: u64 = 24 * 60 * 60 * 1_000;
/// Inactivity after which the session is refused.
pub const IDLE_TIMEOUT_MS: u64 = 30 * 60 * 1_000;
/// Counters tracked behind `v_max`; one bit per counter in a `u128`.
pub const WINDOW_BITS: u64 = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionVerdict {
    /// Fresh counter: accepted and recorded.
    Accepted,
    /// Counter was already inside the window.
    Replay,
    /// Hard or idle timeout elapsed.
    Expired,
    /// Counter is so far behind `v_max` that it fell out of the window.
    OutOfWindow,
}

impl SessionVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            SessionVerdict::Accepted => "accepted",
            SessionVerdict::Replay => "replay",
            SessionVerdict::Expired => "expired",
            SessionVerdict::OutOfWindow => "out-of-window",
        }
    }
}

pub struct KernelSessionGuard {
    started_ms: u64,
    last_activity_ms: u64,
    v_max: u64,
    bitmap: u128,
    accepted: u64,
    rejected: u64,
}

impl KernelSessionGuard {
    pub fn open() -> Self {
        Self::open_at(clock::uptime_ms())
    }

    /// Opens a session with an explicit start instant (session resume, and the tests).
    pub fn open_at(now_ms: u64) -> Self {
        Self {
            started_ms: now_ms,
            last_activity_ms: now_ms,
            v_max: 0,
            bitmap: 0,
            accepted: 0,
            rejected: 0,
        }
    }

    pub fn age_ms(&self) -> u64 {
        clock::uptime_ms().saturating_sub(self.started_ms)
    }

    pub fn idle_ms(&self) -> u64 {
        clock::uptime_ms().saturating_sub(self.last_activity_ms)
    }

    pub fn is_expired(&self) -> bool {
        self.age_ms() >= HARD_TIMEOUT_MS || self.idle_ms() >= IDLE_TIMEOUT_MS
    }

    pub fn accepted_count(&self) -> u64 {
        self.accepted
    }

    pub fn rejected_count(&self) -> u64 {
        self.rejected
    }

    pub fn highest_counter(&self) -> u64 {
        self.v_max
    }

    /// Classifies and records `counter` according to the window rules above.
    pub fn accept(&mut self, counter: u64) -> SessionVerdict {
        self.accept_at(counter, clock::uptime_ms())
    }

    /// Time-injectable form of `accept`: `now_ms` is the instant the packet arrived, so
    /// the timeout paths can be exercised without waiting out a real timeout.
    pub fn accept_at(&mut self, counter: u64, now_ms: u64) -> SessionVerdict {
        let expired = now_ms.saturating_sub(self.started_ms) >= HARD_TIMEOUT_MS
            || now_ms.saturating_sub(self.last_activity_ms) >= IDLE_TIMEOUT_MS;
        if expired {
            self.rejected += 1;
            return SessionVerdict::Expired;
        }

        let now = now_ms;

        if counter > self.v_max {
            let advance = counter - self.v_max;
            if advance >= WINDOW_BITS {
                // Everything previously tracked is now outside the window.
                self.bitmap = 1;
            } else {
                self.bitmap = (self.bitmap << advance) | 1;
            }
            self.v_max = counter;
            self.accepted += 1;
            self.last_activity_ms = now;
            return SessionVerdict::Accepted;
        }

        let behind = self.v_max - counter;
        if behind >= WINDOW_BITS {
            self.rejected += 1;
            return SessionVerdict::OutOfWindow;
        }

        let flag = 1u128 << behind;
        if self.bitmap & flag != 0 {
            self.rejected += 1;
            return SessionVerdict::Replay;
        }
        self.bitmap |= flag;
        self.accepted += 1;
        self.last_activity_ms = now;
        SessionVerdict::Accepted
    }

    pub fn describe(&self) {
        crate::println!(
            "[SESS] v_max={} accepted={} rejected={} window={} age={} ms idle={} ms",
            self.v_max,
            self.accepted,
            self.rejected,
            WINDOW_BITS,
            self.age_ms(),
            self.idle_ms()
        );
    }
}

/// Exercises the window: in-order, reordering, replay, window jump and expiry.
pub fn self_test() -> bool {
    let mut guard = KernelSessionGuard::open();

    for counter in 0..4 {
        if guard.accept(counter) != SessionVerdict::Accepted {
            return false;
        }
    }
    // A counter already seen is a replay.
    if guard.accept(3) != SessionVerdict::Replay {
        return false;
    }
    // Out-of-order arrival inside the window is fine, exactly once.
    if guard.accept(7) != SessionVerdict::Accepted {
        return false;
    }
    if guard.accept(5) != SessionVerdict::Accepted {
        return false;
    }
    if guard.accept(5) != SessionVerdict::Replay {
        return false;
    }

    // A big jump clears the window; the boundary is exactly WINDOW_BITS behind.
    let jump_target = guard.highest_counter() + 500;
    if guard.accept(jump_target) != SessionVerdict::Accepted {
        return false;
    }
    if guard.accept(jump_target - WINDOW_BITS) != SessionVerdict::OutOfWindow {
        return false;
    }
    if guard.accept(jump_target - WINDOW_BITS + 1) != SessionVerdict::Accepted {
        return false;
    }

    // A session that has been idle past the idle timeout refuses even a fresh counter.
    let mut idle_expired = KernelSessionGuard::open_at(0);
    if idle_expired.accept_at(1, IDLE_TIMEOUT_MS) != SessionVerdict::Expired {
        return false;
    }
    // At the hard timeout it is refused too, whatever the activity.
    let mut hard_expired = KernelSessionGuard::open_at(0);
    if hard_expired.accept_at(1, HARD_TIMEOUT_MS) != SessionVerdict::Expired {
        return false;
    }
    // One millisecond earlier the same session still accepts.
    let mut still_live = KernelSessionGuard::open_at(0);
    if still_live.accept_at(1, IDLE_TIMEOUT_MS - 1) != SessionVerdict::Accepted {
        return false;
    }

    // Counters: 4 initial + 2 reorder + 2 around the jump = 8 accepted, 3 refused.
    guard.accepted_count() == 8 && guard.rejected_count() == 3
}
