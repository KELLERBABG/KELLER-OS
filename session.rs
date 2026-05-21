const WINDOW_SIZE: u64 = 128;
const SESSION_HARD_TIMEOUT_TICKS: u64 = 86_400_000; // Angenommen 1000 Ticks = 1 Sekunde
const SESSION_IDLE_TIMEOUT_TICKS: u64 = 1_800_000;

pub struct KernelSessionGuard {
    pub start_tick: u64,
    pub last_activity: u64,
    pub v_max: u64,
    pub bitmask: u128,
}

impl KernelSessionGuard {
    pub fn new(current_tick: u64) -> Self {
        Self {
            start_tick: current_tick,
            last_activity: current_tick,
            v_max: 0,
            bitmask: 0,
        }
    }

    pub fn is_valid(&self, current_tick: u64) -> bool {
        current_tick.saturating_sub(self.start_tick) < SESSION_HARD_TIMEOUT_TICKS
            && current_tick.saturating_sub(self.last_activity) < SESSION_IDLE_TIMEOUT_TICKS
    }

    pub fn check_and_update(&mut self, counter: u64, current_tick: u64) -> bool {
        if !self.is_valid(current_tick) {
            return false;
        }
        if counter > self.v_max {
            let shift = counter - self.v_max;
            if shift >= WINDOW_SIZE {
                self.bitmask = 1;
            } else {
                self.bitmask = (self.bitmask << shift) | 1;
            }
            self.v_max = counter;
            self.last_activity = current_tick;
            true
        } else {
            if counter <= self.v_max.saturating_sub(WINDOW_SIZE) {
                return false;
            }
            let offset = (self.v_max - counter) as u32;
            if (self.bitmask & (1 << offset)) != 0 {
                return false; // Replay detektiert
            }
            self.bitmask |= 1 << offset;
            self.last_activity = current_tick;
            true
        }
    }
}