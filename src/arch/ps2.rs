//! PS/2 controller (Intel 8042): keyboard on IRQ1, mouse on IRQ12.
//!
//! Layout: status/command on `0x64`, data on `0x60`. The keyboard is the "first port", the
//! mouse the "second" (aux) port; device commands for the aux port are prefixed with `0xD4`.
//! Traffic comes back through one output buffer, and the status register's **bit 5** says
//! which device that byte belongs to - so both interrupt handlers call the same
//! [`service`], which consumes every pending byte and routes by that bit. A byte never waits
//! for "its" interrupt.
//!
//! **Scancode set.** The controller's translation bit is *cleared* and the keyboard is then
//! commanded to set 1 (`0xF0 0x01`), so what arrives is set 1 make/break on every path: on
//! real hardware because translation is off and the device was told set 1, and under QEMU
//! because `0xF0 0x01` is how QEMU's PS/2 model implements "set scancode set" (it flips its
//! own translate flag). Turning the 8042 translation bit on *and* asking for set 1 would
//! translate twice, which is the bug this ordering avoids. When the device refuses, the
//! decoder still runs and [`status`] reports `scancode set: UNCONFIRMED`.
//!
//! **Where decoding runs.** The interrupt handlers move bytes into small rings and nothing
//! else; [`drain`] (idle loop) decodes them into [`KeyEvent`]s / [`MousePacket`]s and hands
//! them to the display server. That keeps the ISR to a few port reads and means input
//! routing happens in ordinary kernel context, next to the window state it depends on.
//!
//! **Where events go.** The GUI owns the policy (`GUI_SPECIFICATION.md` §2: keystrokes and
//! pointer events are routed exclusively to the holder of the `InputFocusCapability`), so
//! this module never looks at a window: it decodes and calls `gui::route_key` /
//! `gui::route_mouse`.
//!
//! **No controller at all.** A machine built without an 8042 (`-machine pc,i8042=off`) does
//! not leave reads of `0x64` empty - they answer `0xFF`, which the status bits decode as
//! "output full, aux data". Polling that would invent a phantom mouse byte forever, so the
//! presence probes read through [`probe_byte`] (which counts nothing) and, when the self-test
//! fails *and* the aux-port test finds nothing, the controller is declared **absent**: one
//! line at boot, no IRQ registered, and [`service`] / [`drain`] return before touching a port.
//!
//! **Per-device presence.** Answering the controller tests says nothing about the two ports,
//! so each device is reported on its own evidence: the keyboard by the `0xFA` it owes its
//! bring-up commands (`0xF0 0x01` / `0xF4`), the mouse by the id byte that follows its `0xF2`
//! ACK. A present controller with a dead keyboard or no mouse therefore says which device is
//! missing instead of looking healthy, and only the devices that answered get an IRQ: IRQ1 is
//! masked when the keyboard is silent, IRQ12 is never unmasked without a mouse. See
//! [`keyboard_present`], [`mouse_present`] and [`present`] (the controller's own state).

use crate::arch::idt;
use crate::port::{inb, io_wait, outb};
use crate::println;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

const DATA: u16 = 0x60;
const STATUS: u16 = 0x64;
const COMMAND: u16 = 0x64;

/// Status register bits.
const STATUS_OUTPUT_FULL: u8 = 0x01;
const STATUS_INPUT_FULL: u8 = 0x02;
const STATUS_AUX_DATA: u8 = 0x20;

/// Controller commands (`0x64`).
const CMD_READ_CONFIG: u8 = 0x20;
const CMD_WRITE_CONFIG: u8 = 0x60;
const CMD_DISABLE_FIRST: u8 = 0xAD;
const CMD_DISABLE_SECOND: u8 = 0xA7;
const CMD_ENABLE_SECOND: u8 = 0xA8;
const CMD_TEST_SECOND: u8 = 0xA9;
const CMD_SELF_TEST: u8 = 0xAA;
const CMD_WRITE_SECOND: u8 = 0xD4;

/// Config-byte bits (`0x20` / `0x60`).
const CONFIG_KEYBOARD_IRQ: u8 = 0x01;
const CONFIG_MOUSE_IRQ: u8 = 0x02;
const CONFIG_SYSTEM_FLAG: u8 = 0x04;
const CONFIG_KEYBOARD_CLOCK_DISABLE: u8 = 0x10;
const CONFIG_MOUSE_CLOCK_DISABLE: u8 = 0x20;
const CONFIG_TRANSLATE: u8 = 0x40;

/// Device commands (first port).
const DEV_SET_SCANCODE_SET: u8 = 0xF0;
const DEV_ENABLE_REPORTING: u8 = 0xF4;
/// Device commands (aux port).
const DEV_SET_DEFAULTS: u8 = 0xF6;
const DEV_SET_RESOLUTION: u8 = 0xE8;
const DEV_SET_SAMPLE_RATE: u8 = 0xF3;
const DEV_GET_ID: u8 = 0xF2;

/// Device answers.
const DEV_ACK: u8 = 0xFA;
const CONTROLLER_SELF_TEST_OK: u8 = 0x55;
const AUX_TEST_OK: u8 = 0x00;

/// Bounded spins used while the controller is being configured. The 8042 answers within a few
/// microseconds; the bound only exists so a missing device cannot hang the boot.
const WAIT_TICKS: usize = 200_000;
/// Highest number of bytes one interrupt will consume from the output buffer.
const SERVICE_BURST: usize = 32;
/// Depth of the byte rings (enough for a fast typist between idle-loop passes).
const QUEUE_CAPACITY: usize = 64;

/// Modifier bits of [`KeyEvent::modifiers`].
pub const MOD_SHIFT: u8 = 1 << 0;
pub const MOD_CTRL: u8 = 1 << 1;
pub const MOD_ALT: u8 = 1 << 2;
pub const MOD_CAPS: u8 = 1 << 3;
pub const MOD_NUM: u8 = 1 << 4;
pub const MOD_SCROLL: u8 = 1 << 5;
/// Set whenever *either* shift key is down (the reference implementation the probe checks).
pub const MOD_ANY_SHIFT: u8 = 1 << 6;

/// Mouse button bits of [`MousePacket::buttons`].
pub const BUTTON_LEFT: u8 = 1 << 0;
pub const BUTTON_RIGHT: u8 = 1 << 1;
pub const BUTTON_MIDDLE: u8 = 1 << 2;

/// Logical key, normalized away from the wire encoding.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Code {
    /// Printable key: see [`KeyEvent::character`].
    Character,
    Enter,
    Escape,
    Backspace,
    Tab,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
    Insert,
    Delete,
    /// F1-F12 ([`KeyEvent::raw`] carries which one).
    Function,
    /// Shift/Ctrl/Alt/Caps/Num/Scroll state change - delivered so clients can see chords.
    Modifier,
    Unknown,
}

/// One decoded key transition.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KeyEvent {
    pub code: Code,
    /// Printable key after shift/caps are applied, if the key produces text.
    pub character: Option<u8>,
    /// `true` on make (press), `false` on break (release).
    pub pressed: bool,
    /// Modifier state *after* this event.
    pub modifiers: u8,
    /// Raw make code from the wire (diagnostics and the probe).
    pub raw: u8,
    /// True for the `0xE0`-prefixed half of the key map (arrows, keypad, right-hand modifiers).
    pub extended: bool,
}

/// One validated mouse packet: three bytes, or four when the device answered the wheel
/// bring-up with a 3/4 id.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MousePacket {
    /// Horizontal motion in device counts (positive is right).
    pub dx: i16,
    /// Vertical motion in device counts (**positive is up**, the PS/2 convention).
    pub dy: i16,
    pub buttons: u8,
    /// Wheel notches: **positive is away from the user** - the direction a terminal scrolls back
    /// into its history - and zero on a three-byte packet, which is what a device with no wheel
    /// sends. The wire format's own nibble runs the *other* way (positive there is a notch
    /// towards the user), and the decoder flips it once, where the byte is read, so that no
    /// caller has to know which way round a mouse wheel's sign is today.
    pub wheel: i8,
    /// The fourth byte's high bits: the fourth and fifth buttons on a 5-button mouse, zero
    /// otherwise. Carried through so a client can see them even though nothing binds them yet.
    pub extra_buttons: u8,
    /// Overflow bit or a bad sync byte - the packet is discarded, not guessed at.
    pub rejected: bool,
}

// ---------------------------------------------------------------------------------------
// Byte rings
// ---------------------------------------------------------------------------------------

/// Single-producer/single-consumer ring, guarded by an interrupt-disable window (one CPU,
/// so a critical section is just `cli`/`sti`).
struct ByteQueue {
    buf: [u8; QUEUE_CAPACITY],
    head: usize,
    tail: usize,
    loss: u64,
}

impl ByteQueue {
    const fn new() -> Self {
        Self {
            buf: [0; QUEUE_CAPACITY],
            head: 0,
            tail: 0,
            loss: 0,
        }
    }

    fn reset(&mut self) {
        self.head = 0;
        self.tail = 0;
        self.loss = 0;
    }

    fn push(&mut self, byte: u8) {
        let next = (self.head + 1) % QUEUE_CAPACITY;
        if next == self.tail {
            // Full: drop, but say so - a lost keystroke must be visible in the counters.
            self.loss += 1;
            return;
        }
        self.buf[self.head] = byte;
        self.head = next;
    }

    fn pop(&mut self) -> Option<u8> {
        if self.tail == self.head {
            return None;
        }
        let byte = self.buf[self.tail];
        self.tail = (self.tail + 1) % QUEUE_CAPACITY;
        Some(byte)
    }

    fn depth(&self) -> usize {
        (self.head + QUEUE_CAPACITY - self.tail) % QUEUE_CAPACITY
    }
}

static mut KEY_QUEUE: ByteQueue = ByteQueue::new();
static mut MOUSE_QUEUE: ByteQueue = ByteQueue::new();

/// Runs `body` with interrupts disabled, restoring the previous state.
fn critical(body: impl FnOnce()) {
    let enabled = crate::arch::cpu::interrupts_enabled();
    unsafe { crate::arch::cpu::disable_interrupts() };
    body();
    if enabled {
        unsafe { crate::arch::cpu::enable_interrupts() };
    }
}

fn key_queue() -> &'static mut ByteQueue {
    unsafe { &mut *core::ptr::addr_of_mut!(KEY_QUEUE) }
}

fn mouse_queue() -> &'static mut ByteQueue {
    unsafe { &mut *core::ptr::addr_of_mut!(MOUSE_QUEUE) }
}

/// Pushes one keyboard-port byte (called from the interrupt handler or the probe).
pub fn push_keyboard(byte: u8) {
    critical(|| key_queue().push(byte));
    KEY_BYTES.fetch_add(1, Ordering::Relaxed);
}

/// Pushes one aux-port byte.
pub fn push_mouse(byte: u8) {
    critical(|| mouse_queue().push(byte));
    MOUSE_BYTES.fetch_add(1, Ordering::Relaxed);
}

fn pop_keyboard() -> Option<u8> {
    let mut byte = None;
    critical(|| byte = key_queue().pop());
    byte
}

fn pop_mouse() -> Option<u8> {
    let mut byte = None;
    critical(|| byte = mouse_queue().pop());
    byte
}

/// Reads one byte from the output buffer **without counting or queueing it**.
///
/// Used by the presence probes only: before the controller has identified itself a byte cannot
/// honestly be attributed to a device (no device is reporting yet - both ports were just
/// disabled), and a machine with no 8042 answers every read with `0xFF`, whose bits read as
/// "output full, aux data". Counting those would invent input; the probes just look for the
/// answer they are waiting for and drop whatever else is there.
fn probe_byte(expect_aux: bool) -> Option<u8> {
    for _ in 0..WAIT_TICKS {
        let status = unsafe { inb(STATUS) };
        if status & STATUS_OUTPUT_FULL != 0 {
            let byte = unsafe { inb(DATA) };
            if (status & STATUS_AUX_DATA != 0) == expect_aux {
                return Some(byte);
            }
        } else {
            unsafe { io_wait() };
        }
    }
    None
}

// ---------------------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------------------

static KEY_BYTES: AtomicU64 = AtomicU64::new(0);
static MOUSE_BYTES: AtomicU64 = AtomicU64::new(0);
static KEYS_DECODED: AtomicU64 = AtomicU64::new(0);
static KEY_RELEASES: AtomicU64 = AtomicU64::new(0);
static KEYS_IGNORED: AtomicU64 = AtomicU64::new(0);
static MOUSE_PACKETS: AtomicU64 = AtomicU64::new(0);
static MOUSE_REJECTED: AtomicU64 = AtomicU64::new(0);
static MOUSE_WHEEL_BYTES: AtomicU64 = AtomicU64::new(0);
static CONTROLLER_OK: AtomicBool = AtomicBool::new(false);
static AUX_OK: AtomicBool = AtomicBool::new(false);
/// Whether an 8042 answered at all: `false` when both presence probes found nothing.
static CONTROLLER_PRESENT: AtomicBool = AtomicBool::new(false);
/// Whether the keyboard answered its bring-up commands. A controller that passes its own
/// tests says nothing about its ports: an empty first port still passes both.
static KEYBOARD_OK: AtomicBool = AtomicBool::new(false);
/// Whether the mouse answered its identify sequence (`0xF2` -> ACK + id byte). The aux-port
/// test (`0xA9`) proves the *port* works, not that a device is behind it.
static MOUSE_OK: AtomicBool = AtomicBool::new(false);
static SCANCODE_SET: AtomicU8 = AtomicU8::new(0);
static MOUSE_ID: AtomicU8 = AtomicU8::new(0xFF);
/// Mouse packet length implied by the device id (3 = standard, 4 = wheel/5-button).
static MOUSE_PACKET_LEN: AtomicU8 = AtomicU8::new(3);
/// Whether the device acknowledged the IntelliMouse sample-rate sequence. Recorded separately
/// from the packet length on purpose: "the mouse would not negotiate a wheel" and "it agreed
/// and then reported an id without one" are different faults, and only the id byte is allowed
/// to decide the packet length.
static MOUSE_WHEEL_OFFERED: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------------------
// Controller access
// ---------------------------------------------------------------------------------------

/// Waits for the controller's input buffer to drain, so a write is not lost.
fn wait_input_clear() -> bool {
    for _ in 0..WAIT_TICKS {
        if unsafe { inb(STATUS) } & STATUS_INPUT_FULL == 0 {
            return true;
        }
        unsafe { io_wait() };
    }
    false
}

/// Reads one byte from the output buffer.
///
/// `expect_aux` selects which device the caller is waiting on. A byte that belongs to the
/// other device is *kept* (pushed into its ring) rather than dropped: during bring-up the
/// mouse can answer while the keyboard is being configured.
fn poll_byte(expect_aux: bool) -> Option<u8> {
    for _ in 0..WAIT_TICKS {
        let status = unsafe { inb(STATUS) };
        if status & STATUS_OUTPUT_FULL != 0 {
            let byte = unsafe { inb(DATA) };
            let aux = status & STATUS_AUX_DATA != 0;
            if aux == expect_aux {
                return Some(byte);
            }
            if aux {
                push_mouse(byte);
            } else {
                push_keyboard(byte);
            }
        } else {
            unsafe { io_wait() };
        }
    }
    None
}

/// Sends a controller command byte.
unsafe fn command(byte: u8) {
    wait_input_clear();
    outb(COMMAND, byte);
}

/// Sends one data byte to whichever port is currently selected.
unsafe fn write_data(byte: u8) {
    wait_input_clear();
    outb(DATA, byte);
}

/// Empties the output buffer **without counting what it drops**, for the stage before the
/// controller has been identified (see [`probe_byte`]).
unsafe fn discard_output() {
    for _ in 0..SERVICE_BURST {
        let status = inb(STATUS);
        if status & STATUS_OUTPUT_FULL == 0 {
            break;
        }
        let _ = inb(DATA);
    }
}

/// Drains residual bytes out of the controller (used before reconfiguring it).
unsafe fn flush_output() {
    for _ in 0..SERVICE_BURST {
        let status = inb(STATUS);
        if status & STATUS_OUTPUT_FULL == 0 {
            break;
        }
        let byte = inb(DATA);
        if status & STATUS_AUX_DATA != 0 {
            push_mouse(byte);
        } else {
            push_keyboard(byte);
        }
    }
}

unsafe fn read_config() -> u8 {
    command(CMD_READ_CONFIG);
    poll_byte(false).unwrap_or(0)
}

unsafe fn write_config(value: u8) {
    command(CMD_WRITE_CONFIG);
    write_data(value);
}

/// Sends one byte to the keyboard and returns the device's answer.
unsafe fn keyboard_command(byte: u8) -> Option<u8> {
    write_data(byte);
    poll_byte(false)
}

/// Sends one byte to the mouse (prefixed with `0xD4`) and returns the device's answer.
unsafe fn mouse_command(byte: u8) -> Option<u8> {
    command(CMD_WRITE_SECOND);
    write_data(byte);
    poll_byte(true)
}

// ---------------------------------------------------------------------------------------
// Decoders
// ---------------------------------------------------------------------------------------

/// Set-1 keyboard state machine (make/break codes, `0xE0` and `0xE1` prefixes).
struct Keyboard {
    shift_left: bool,
    shift_right: bool,
    ctrl_left: bool,
    ctrl_right: bool,
    alt_left: bool,
    alt_right: bool,
    caps: bool,
    num: bool,
    scroll: bool,
    extended: bool,
    /// Step counter for the `0xE1 0x1D 0x45 0xE1 0x9D 0xC5` pause sequence.
    pause: u8,
    /// Bytes this decoder refused to turn into a key. Per-instance, so the probe can run a
    /// scratch decoder without disturbing the live counters (`drain` folds the deltas in).
    ignored: u64,
}

impl Keyboard {
    const fn new() -> Self {
        Self {
            shift_left: false,
            shift_right: false,
            ctrl_left: false,
            ctrl_right: false,
            alt_left: false,
            alt_right: false,
            caps: false,
            num: false,
            scroll: false,
            extended: false,
            pause: 0,
            ignored: 0,
        }
    }

    fn reset(&mut self) {
        *self = Self::new();
    }

    fn modifiers(&self) -> u8 {
        let mut state = 0u8;
        if self.shift_left || self.shift_right {
            state |= MOD_SHIFT | MOD_ANY_SHIFT;
        }
        if self.ctrl_left || self.ctrl_right {
            state |= MOD_CTRL;
        }
        if self.alt_left || self.alt_right {
            state |= MOD_ALT;
        }
        if self.caps {
            state |= MOD_CAPS;
        }
        if self.num {
            state |= MOD_NUM;
        }
        if self.scroll {
            state |= MOD_SCROLL;
        }
        state
    }

    /// Feeds one set-1 byte. Returns the event it completes, if any.
    fn byte(&mut self, byte: u8) -> Option<KeyEvent> {
        // Pause/Break is a six-byte sequence with no key code the desktop needs.
        if self.pause > 0 {
            self.pause += 1;
            if self.pause >= 6 {
                self.pause = 0;
            }
            return None;
        }
        match byte {
            0xE0 => {
                self.extended = true;
                return None;
            }
            0xE1 => {
                self.pause = 1;
                return None;
            }
            // Controller/device chatter: ACK, resend, overrun, power-on reset.
            //
            // `0xAA` is deliberately *not* in this list even though it is the keyboard's
            // BAT-complete code: it is also the break code for left shift (`0x2A | 0x80`),
            // and swallowing it leaves shift stuck down. Decoding it as a shift release is
            // harmless in the rare case it really was BAT completion (we never reset the
            // keyboard, so it cannot be), and correct in the case that matters.
            0xFA | 0xFE | 0x00 | 0xFF => {
                self.ignored += 1;
                self.extended = false;
                return None;
            }
            _ => {}
        }

        let extended = self.extended;
        self.extended = false;
        let pressed = byte & 0x80 == 0;
        let code = byte & 0x7F;

        let modifiers = match (code, extended) {
            (0x2A, false) => {
                self.shift_left = pressed;
                Some(Code::Modifier)
            }
            (0x36, false) => {
                self.shift_right = pressed;
                Some(Code::Modifier)
            }
            (0x1D, false) => {
                self.ctrl_left = pressed;
                Some(Code::Modifier)
            }
            (0x1D, true) => {
                self.ctrl_right = pressed;
                Some(Code::Modifier)
            }
            (0x38, false) => {
                self.alt_left = pressed;
                Some(Code::Modifier)
            }
            (0x38, true) => {
                self.alt_right = pressed;
                Some(Code::Modifier)
            }
            (0x3A, false) => {
                if pressed {
                    self.caps = !self.caps;
                }
                Some(Code::Modifier)
            }
            (0x45, false) => {
                if pressed {
                    self.num = !self.num;
                }
                Some(Code::Modifier)
            }
            (0x46, false) => {
                if pressed {
                    self.scroll = !self.scroll;
                }
                Some(Code::Modifier)
            }
            _ => None,
        };
        let modifiers = match modifiers {
            Some(code) => Some((code, None)),
            None => mapping(code, extended),
        };

        let (logical, character) = match modifiers {
            Some((logical, key)) => {
                let character = key.map(|(normal, shifted)| {
                    // Caps Lock affects letters only; both shift keys overrule it.
                    let letter = normal.is_ascii_lowercase() && shifted == normal.to_ascii_uppercase();
                    let upper = self.shift_left || self.shift_right;
                    if (letter && self.caps) ^ upper {
                        shifted
                    } else {
                        normal
                    }
                });
                (logical, character)
            }
            None => {
                self.ignored += 1;
                (Code::Unknown, None)
            }
        };

        Some(KeyEvent {
            code: logical,
            character,
            pressed,
            modifiers: self.modifiers(),
            raw: code,
            extended,
        })
    }
}

/// Set-1 make code -> (logical key, unshifted character, shifted character).
///
/// `extended` selects the `0xE0` half of the map (keypad enter, right-hand modifiers,
/// navigation cluster).
fn mapping(code: u8, extended: bool) -> Option<(Code, Option<(u8, u8)>)> {
    if extended {
        return Some(match code {
            0x1C => (Code::Enter, None),
            0x35 => (Code::Character, Some((b'/', b'/'))),
            0x47 => (Code::Home, None),
            0x48 => (Code::Up, None),
            0x49 => (Code::PageUp, None),
            0x4B => (Code::Left, None),
            0x4D => (Code::Right, None),
            0x4F => (Code::End, None),
            0x50 => (Code::Down, None),
            0x51 => (Code::PageDown, None),
            0x52 => (Code::Insert, None),
            0x53 => (Code::Delete, None),
            _ => (Code::Unknown, None),
        });
    }
    Some(match code {
        0x01 => (Code::Escape, None),
        0x0E => (Code::Backspace, None),
        0x0F => (Code::Tab, None),
        0x1C => (Code::Enter, None),
        0x39 => (Code::Character, Some((b' ', b' '))),
        0x02 => (Code::Character, Some((b'1', b'!'))),
        0x03 => (Code::Character, Some((b'2', b'@'))),
        0x04 => (Code::Character, Some((b'3', b'#'))),
        0x05 => (Code::Character, Some((b'4', b'$'))),
        0x06 => (Code::Character, Some((b'5', b'%'))),
        0x07 => (Code::Character, Some((b'6', b'^'))),
        0x08 => (Code::Character, Some((b'7', b'&'))),
        0x09 => (Code::Character, Some((b'8', b'*'))),
        0x0A => (Code::Character, Some((b'9', b'('))),
        0x0B => (Code::Character, Some((b'0', b')'))),
        0x0C => (Code::Character, Some((b'-', b'_'))),
        0x0D => (Code::Character, Some((b'=', b'+'))),
        0x10 => (Code::Character, Some((b'q', b'Q'))),
        0x11 => (Code::Character, Some((b'w', b'W'))),
        0x12 => (Code::Character, Some((b'e', b'E'))),
        0x13 => (Code::Character, Some((b'r', b'R'))),
        0x14 => (Code::Character, Some((b't', b'T'))),
        0x15 => (Code::Character, Some((b'y', b'Y'))),
        0x16 => (Code::Character, Some((b'u', b'U'))),
        0x17 => (Code::Character, Some((b'i', b'I'))),
        0x18 => (Code::Character, Some((b'o', b'O'))),
        0x19 => (Code::Character, Some((b'p', b'P'))),
        0x1A => (Code::Character, Some((b'[', b'{'))),
        0x1B => (Code::Character, Some((b']', b'}'))),
        0x1E => (Code::Character, Some((b'a', b'A'))),
        0x1F => (Code::Character, Some((b's', b'S'))),
        0x20 => (Code::Character, Some((b'd', b'D'))),
        0x21 => (Code::Character, Some((b'f', b'F'))),
        0x22 => (Code::Character, Some((b'g', b'G'))),
        0x23 => (Code::Character, Some((b'h', b'H'))),
        0x24 => (Code::Character, Some((b'j', b'J'))),
        0x25 => (Code::Character, Some((b'k', b'K'))),
        0x26 => (Code::Character, Some((b'l', b'L'))),
        0x27 => (Code::Character, Some((b';', b':'))),
        0x28 => (Code::Character, Some((b'\'', b'"'))),
        0x29 => (Code::Character, Some((b'`', b'~'))),
        0x2B => (Code::Character, Some((b'\\', b'|'))),
        0x2C => (Code::Character, Some((b'z', b'Z'))),
        0x2D => (Code::Character, Some((b'x', b'X'))),
        0x2E => (Code::Character, Some((b'c', b'C'))),
        0x2F => (Code::Character, Some((b'v', b'V'))),
        0x30 => (Code::Character, Some((b'b', b'B'))),
        0x31 => (Code::Character, Some((b'n', b'N'))),
        0x32 => (Code::Character, Some((b'm', b'M'))),
        0x33 => (Code::Character, Some((b',', b'<'))),
        0x34 => (Code::Character, Some((b'.', b'>'))),
        0x35 => (Code::Character, Some((b'/', b'?'))),
        // Keypad: always numeric here (the numpad-as-arrows mode needs NumLock-aware
        // navigation, which the shell does not use yet - `input status` reports the lock).
        0x37 => (Code::Character, Some((b'*', b'*'))),
        0x47 => (Code::Character, Some((b'7', b'7'))),
        0x48 => (Code::Character, Some((b'8', b'8'))),
        0x49 => (Code::Character, Some((b'9', b'9'))),
        0x4A => (Code::Character, Some((b'-', b'-'))),
        0x4B => (Code::Character, Some((b'4', b'4'))),
        0x4C => (Code::Character, Some((b'5', b'5'))),
        0x4D => (Code::Character, Some((b'6', b'6'))),
        0x4E => (Code::Character, Some((b'+', b'+'))),
        0x4F => (Code::Character, Some((b'1', b'1'))),
        0x50 => (Code::Character, Some((b'2', b'2'))),
        0x51 => (Code::Character, Some((b'3', b'3'))),
        0x52 => (Code::Character, Some((b'0', b'0'))),
        0x53 => (Code::Character, Some((b'.', b'.'))),
        0x3B..=0x44 => (Code::Function, None),
        0x57 | 0x58 => (Code::Function, None),
        _ => (Code::Unknown, None),
    })
}

/// 3- or 4-byte mouse packet assembly, with resynchronisation on a bad sync byte.
struct Mouse {
    buffer: [u8; 4],
    index: usize,
    /// Packets dropped for a bad sync byte or an overflow flag (per-instance, as above).
    rejected: u64,
    /// Wheel bytes consumed from 4-byte packets.
    wheel: u64,
}

impl Mouse {
    const fn new() -> Self {
        Self {
            buffer: [0; 4],
            index: 0,
            rejected: 0,
            wheel: 0,
        }
    }

    fn reset(&mut self) {
        *self = Self::new();
    }

    /// Feeds one byte; returns a packet once `length` bytes have assembled.
    ///
    /// Byte 0 bit 3 is always set on a real packet, so its absence means the stream is out of
    /// step: the byte is dropped and the rest of the buffer shifts down, which resynchronises
    /// within one packet instead of desyncing forever.
    fn byte(&mut self, byte: u8, length: usize) -> Option<MousePacket> {
        if self.index == 0 && byte & 0x08 == 0 {
            self.rejected += 1;
            return None;
        }
        self.buffer[self.index] = byte;
        self.index += 1;
        if self.index < length.max(3) {
            return None;
        }
        self.index = 0;

        let flags = self.buffer[0];
        let mut dx = self.buffer[1] as i16 | (((flags >> 4) & 1) as i16) << 8;
        let mut dy = self.buffer[2] as i16 | (((flags >> 5) & 1) as i16) << 8;
        if dx & 0x100 != 0 {
            dx -= 0x200;
        }
        if dy & 0x100 != 0 {
            dy -= 0x200;
        }
        // The fourth byte: the low nibble is the wheel as a signed 4-bit count, the high nibble
        // carries buttons four and five. `length >= 4` is the device id's decision, not a guess
        // - a three-byte mouse never gets here, and its packets decode to a still wheel rather
        // than to whatever byte happens to follow them.
        //
        // The device's own sign for that nibble is *inverted* against the one this kernel
        // publishes: a positive nibble is a notch towards the user. Linux reports the same byte
        // negated (`input_report_rel(dev, REL_WHEEL, -(s8) packet[3])`) for exactly this reason,
        // and something has to choose a direction - a backscroll that travels the wrong way is
        // worse than one that does not move at all. The flip happens here, once, at the byte.
        let mut wheel = 0i8;
        let mut extra_buttons = 0u8;
        if length >= 4 {
            self.wheel += 1;
            let raw = self.buffer[3];
            let notches = raw & 0x0F;
            let towards_user = if notches >= 8 {
                notches as i16 - 16
            } else {
                notches as i16
            };
            wheel = -(towards_user as i8);
            extra_buttons = (raw >> 4) & 0x03;
        }

        let overflow = flags & 0xC0 != 0;
        let mut buttons = 0u8;
        if flags & 0x01 != 0 {
            buttons |= BUTTON_LEFT;
        }
        if flags & 0x02 != 0 {
            buttons |= BUTTON_RIGHT;
        }
        if flags & 0x04 != 0 {
            buttons |= BUTTON_MIDDLE;
        }
        if overflow {
            self.rejected += 1;
        }
        Some(MousePacket {
            dx,
            dy,
            buttons,
            wheel,
            extra_buttons,
            rejected: overflow,
        })
    }
}

static mut KEYBOARD: Keyboard = Keyboard::new();
static mut MOUSE: Mouse = Mouse::new();

fn keyboard() -> &'static mut Keyboard {
    unsafe { &mut *core::ptr::addr_of_mut!(KEYBOARD) }
}

fn mouse() -> &'static mut Mouse {
    unsafe { &mut *core::ptr::addr_of_mut!(MOUSE) }
}

// ---------------------------------------------------------------------------------------
// Bring-up
// ---------------------------------------------------------------------------------------

/// Explicit self-initialisation of the module's statics (`.bss` arrives uninitialised).
fn reset() {
    key_queue().reset();
    mouse_queue().reset();
    keyboard().reset();
    mouse().reset();
    KEY_BYTES.store(0, Ordering::Relaxed);
    MOUSE_BYTES.store(0, Ordering::Relaxed);
    KEYS_DECODED.store(0, Ordering::Relaxed);
    KEY_RELEASES.store(0, Ordering::Relaxed);
    KEYS_IGNORED.store(0, Ordering::Relaxed);
    MOUSE_PACKETS.store(0, Ordering::Relaxed);
    MOUSE_REJECTED.store(0, Ordering::Relaxed);
    MOUSE_WHEEL_BYTES.store(0, Ordering::Relaxed);
    CONTROLLER_OK.store(false, Ordering::Relaxed);
    AUX_OK.store(false, Ordering::Relaxed);
    CONTROLLER_PRESENT.store(false, Ordering::Relaxed);
    KEYBOARD_OK.store(false, Ordering::Relaxed);
    MOUSE_OK.store(false, Ordering::Relaxed);
    SCANCODE_SET.store(0, Ordering::Relaxed);
    MOUSE_ID.store(0xFF, Ordering::Relaxed);
    MOUSE_PACKET_LEN.store(3, Ordering::Relaxed);
}

/// Brings up the 8042, both devices and both IRQ lines.
///
/// # Safety
/// Must run once, before interrupts are enabled (the PIC must already be remapped).
pub unsafe fn init() {
    reset();

    command(CMD_DISABLE_FIRST);
    command(CMD_DISABLE_SECOND);
    discard_output();

    // Controller self-test (0xAA): 0x55 means the controller is wired correctly. It also
    // resets the config byte, so the config must be read *after* this point. The two presence
    // probes read through `probe_byte`, so a machine with no 8042 cannot turn the `0xFF` it
    // returns on every port read into input counters.
    command(CMD_SELF_TEST);
    let self_test = probe_byte(false);
    let self_test_ok = self_test == Some(CONTROLLER_SELF_TEST_OK);
    CONTROLLER_OK.store(self_test_ok, Ordering::Relaxed);

    // Second-port (aux) presence test (0xA9): 0x00 means the mouse port behaves.
    command(CMD_TEST_SECOND);
    let aux = probe_byte(false);
    let aux_ok = aux == Some(AUX_TEST_OK);
    AUX_OK.store(aux_ok, Ordering::Relaxed);

    // A failed self-test *and* no aux port means there is no 8042 to talk to at all. Stop
    // here instead of configuring devices that are not there: every later read of the status
    // port would keep claiming "output full, aux data", which is the phantom byte source.
    let present = self_test_ok || aux_ok;
    CONTROLLER_PRESENT.store(present, Ordering::Relaxed);
    if !present {
        println!(
            "[--] PS/2 CONTROLLER ABSENT: self-test FAIL ({:#04x}), aux port absent - no 8042 on this machine, input disabled (0x64/0x60 never read, IRQ1/IRQ12 stay masked)",
            self_test.unwrap_or(0)
        );
        return;
    }

    let config = read_config();
    // Both interrupts on, both clocks enabled, system flag set, and - importantly - the
    // controller's translation bit *off* so set 1 arrives exactly as the device sends it.
    let desired = (config | CONFIG_KEYBOARD_IRQ | CONFIG_MOUSE_IRQ | CONFIG_SYSTEM_FLAG)
        & !(CONFIG_KEYBOARD_CLOCK_DISABLE
            | CONFIG_MOUSE_CLOCK_DISABLE
            | CONFIG_TRANSLATE
            | 0x80);
    command(CMD_ENABLE_SECOND);
    write_config(desired);

    // Keyboard: scancode set 1 (see the module docs). The `0xF0` command itself is not
    // answered - only its parameter is, which is why the ACK is read after `0x01`. Either
    // command's `0xFA` proves a device on the first port; neither answering means the port is
    // empty (or the keyboard died), which is what `KEYBOARD_OK` records.
    write_data(DEV_SET_SCANCODE_SET);
    let set = keyboard_command(0x01);
    let set_ack = set == Some(DEV_ACK);
    SCANCODE_SET.store(if set_ack { 1 } else { 0 }, Ordering::Relaxed);
    let reports_ack = keyboard_command(DEV_ENABLE_REPORTING) == Some(DEV_ACK);
    let keyboard_ok = set_ack || reports_ack;
    KEYBOARD_OK.store(keyboard_ok, Ordering::Relaxed);

    // Mouse: defaults, 8 counts/mm, then the IntelliMouse bring-up. The sample-rate sequence
    // 200, 100, 80 is how a wheel mouse is told to add the fourth packet byte; without it a
    // wheel mouse answers `0xF2` with id 0x00, this driver commits to three-byte packets, and
    // the wheel is a device nobody ever hears from. A mouse that does not know the sequence
    // just sets its rate three times and keeps its old id, which is why the id after the
    // sequence - not the attempt - is what decides.
    mouse_command(DEV_SET_DEFAULTS);
    mouse_command(DEV_SET_RESOLUTION);
    mouse_command(0x03);
    let wheel_offered = mouse_command(DEV_SET_SAMPLE_RATE) == Some(DEV_ACK)
        && mouse_command(0xC8) == Some(DEV_ACK)
        && mouse_command(DEV_SET_SAMPLE_RATE) == Some(DEV_ACK)
        && mouse_command(0x64) == Some(DEV_ACK)
        && mouse_command(DEV_SET_SAMPLE_RATE) == Some(DEV_ACK)
        && mouse_command(0x50) == Some(DEV_ACK);
    MOUSE_WHEEL_OFFERED.store(wheel_offered, Ordering::Relaxed);
    // Back to 100 reports/s whether or not the negotiation landed: the sequence leaves the
    // device at 80, and a report rate the pointer has to share is felt as a sticky pointer.
    mouse_command(DEV_SET_SAMPLE_RATE);
    mouse_command(0x64);
    // The mouse counts as present only when the whole identify sequence answered: the ACK to
    // `0xF2` *and* the id byte that follows it. No id byte leaves `MOUSE_ID` at its 0xFF
    // "nothing answered" sentinel, and then no packet can ever be decoded either.
    let identify = mouse_command(DEV_GET_ID);
    let id = identify.and_then(|_| poll_byte(true)).unwrap_or(0xFF);
    MOUSE_ID.store(id, Ordering::Relaxed);
    let mouse_ok = identify == Some(DEV_ACK) && id != 0xFF;
    MOUSE_OK.store(mouse_ok, Ordering::Relaxed);
    let packet_len = if id == 0x03 || id == 0x04 { 4 } else { 3 };
    MOUSE_PACKET_LEN.store(packet_len, Ordering::Relaxed);
    mouse_command(DEV_ENABLE_REPORTING);

    // IRQ1 keyboard, IRQ12 mouse: the second port arrives through the master's cascade line.
    // A line is only wired up for a device that answered: registering an interrupt for an
    // empty port would let a floating line spin `service` for input that cannot exist.
    if keyboard_ok {
        idt::register_irq(1, |_| service());
    } else {
        // The PIC leaves IRQ1 unmasked for the keyboard; a port with nothing behind it has to
        // be masked instead.
        crate::arch::pic::mask(1);
    }
    if mouse_ok {
        idt::register_irq(12, |_| service());
        crate::arch::pic::unmask(12);
    }

    flush_output();

    // The controller's own verdict, deliberately without any device claim: the line below it
    // is the one that says what is actually plugged in.
    println!(
        "[OK] PS/2 CONTROLLER: self-test {} ({:#04x}), aux port {}",
        if CONTROLLER_OK.load(Ordering::Relaxed) { "PASS" } else { "FAIL" },
        self_test.unwrap_or(0),
        if AUX_OK.load(Ordering::Relaxed) { "present" } else { "absent" }
    );
    // Per-device presence, from the devices' own answers above. Without this, a controller
    // that answers while a port is empty (dead keyboard, no mouse) looks fully healthy.
    match (keyboard_ok, mouse_ok) {
        (true, true) => println!(
            "[OK] PS/2 DEVICES: keyboard present (scancode set {}), mouse present (id {:#04x}, {} byte packets)",
            if set_ack { "1 confirmed" } else { "unconfirmed - decoder assumes set 1" },
            id,
            packet_len
        ),
        (true, false) => println!(
            "[--] PS/2 DEVICES: keyboard present (scancode set {}), mouse ABSENT - nothing answered the identify sequence (0xF2) on the aux port",
            if set_ack { "1 confirmed" } else { "unconfirmed - decoder assumes set 1" }
        ),
        (false, true) => println!(
            "[--] PS/2 DEVICES: keyboard ABSENT - nothing answered its bring-up commands (0xF0 0x01 / 0xF4), mouse present (id {:#04x}, {} byte packets)",
            id,
            packet_len
        ),
        (false, false) => println!(
            "[--] PS/2 DEVICES: keyboard ABSENT (no answer to 0xF0 0x01 / 0xF4), mouse ABSENT (no answer to identify 0xF2) - the controller works, but neither port has a device"
        ),
    }
    // The wheel gets a line of its own because its absence is otherwise silent: a three-byte
    // mouse tracks and clicks perfectly well, so a wheel that was never negotiated looks exactly
    // like a wheel that is broken. `MOUSE_WHEEL_OFFERED` is what tells the two apart - whether
    // the device refused the sequence, or agreed to it and reported an id without a wheel
    // anyway - and only the id byte is allowed to decide the packet length.
    if mouse_ok {
        if packet_len == 4 {
            println!(
                "[OK] PS/2 MOUSE WHEEL: IntelliMouse negotiated (id {:#04x}) - the fourth packet byte carries the wheel as a signed 4-bit count, so the wheel scrolls",
                id
            );
        } else if wheel_offered {
            println!(
                "[--] PS/2 MOUSE WHEEL: the device acknowledged the IntelliMouse sequence but still reports id {:#04x} - three-byte packets, so no wheel byte ever arrives",
                id
            );
        } else {
            println!(
                "[--] PS/2 MOUSE WHEEL: the device refused the IntelliMouse sample-rate sequence - three-byte packets, so no wheel byte ever arrives"
            );
        }
    }
    match (keyboard_ok, mouse_ok) {
        (true, true) => println!(
            "[OK] PS/2 INPUT: keyboard IRQ1 + mouse IRQ12 unmasked (translation off)"
        ),
        (true, false) => println!(
            "[--] PS/2 INPUT: keyboard IRQ1 unmasked, mouse IRQ12 left masked - no mouse packets are expected (translation off)"
        ),
        (false, true) => println!(
            "[--] PS/2 INPUT: mouse IRQ12 unmasked, keyboard IRQ1 masked - no keystrokes are expected (translation off)"
        ),
        (false, false) => println!(
            "[--] PS/2 INPUT: keyboard IRQ1 masked, mouse IRQ12 left masked - no device answered, so no input is expected (translation off)"
        ),
    }
}

// ---------------------------------------------------------------------------------------
// Interrupt path and decode pump
// ---------------------------------------------------------------------------------------

/// Consumes every byte the controller has for us.
///
/// Registered for *both* IRQ1 and IRQ12: whichever device raises the interrupt, the status
/// register's aux bit decides where each byte belongs, so no byte waits for "its" IRQ.
pub fn service() {
    // Never registered when the controller is absent, but a status port that answers `0xFF`
    // must not be able to start a read loop even if it were.
    if !present() {
        return;
    }
    unsafe {
        for _ in 0..SERVICE_BURST {
            let status = inb(STATUS);
            if status & STATUS_OUTPUT_FULL == 0 {
                break;
            }
            let byte = inb(DATA);
            if status & STATUS_AUX_DATA != 0 {
                push_mouse(byte);
            } else {
                push_keyboard(byte);
            }
        }
    }
}

/// Decodes queued bytes into events and routes them to the display server.
///
/// Called from the kernel's idle loop: interrupt context only moves bytes, so decoding,
/// modifier tracking and delivery all happen in ordinary kernel context.
pub fn drain() {
    // With no controller there is nothing to decode and no port worth reading: a read of the
    // status register would consume the `0xFF` such a machine returns on every access.
    if !present() {
        return;
    }
    // The decoders are pure state machines with their own counters (the probe runs scratch
    // copies of them), so the live counters are folded in here as deltas.
    let ignored_before = keyboard().ignored;
    while let Some(byte) = pop_keyboard() {
        if let Some(event) = keyboard().byte(byte) {
            KEYS_DECODED.fetch_add(1, Ordering::Relaxed);
            if !event.pressed {
                KEY_RELEASES.fetch_add(1, Ordering::Relaxed);
            }
            crate::gui::route_key(event);
        }
    }
    KEYS_IGNORED.fetch_add(
        keyboard().ignored - ignored_before,
        Ordering::Relaxed,
    );

    let length = MOUSE_PACKET_LEN.load(Ordering::Relaxed) as usize;
    let rejected_before = mouse().rejected;
    let wheel_before = mouse().wheel;
    while let Some(byte) = pop_mouse() {
        if let Some(packet) = mouse().byte(byte, length) {
            if packet.rejected {
                continue;
            }
            MOUSE_PACKETS.fetch_add(1, Ordering::Relaxed);
            crate::gui::route_mouse(&packet);
        }
    }
    MOUSE_REJECTED.fetch_add(mouse().rejected - rejected_before, Ordering::Relaxed);
    MOUSE_WHEEL_BYTES.fetch_add(mouse().wheel - wheel_before, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------------------
// Introspection
// ---------------------------------------------------------------------------------------

pub fn controller_ready() -> bool {
    CONTROLLER_OK.load(Ordering::Relaxed)
}

/// Whether an 8042 answered its presence probes at all. `false` means both the self-test and
/// the aux-port test found nothing (`-machine pc,i8042=off`): no IRQ, no port reads, no input.
/// This is the *controller's* state only - a `true` here still says nothing about the two
/// devices, which [`keyboard_present`] and [`mouse_present`] report separately.
pub fn present() -> bool {
    CONTROLLER_PRESENT.load(Ordering::Relaxed)
}

pub fn aux_present() -> bool {
    AUX_OK.load(Ordering::Relaxed)
}

/// Whether the keyboard answered its bring-up commands (`0xF0 0x01` / `0xF4` -> `0xFA`).
/// Independent of the controller: an 8042 with an empty first port still passes both of its
/// own tests, so this is the only thing that proves a keyboard is there.
pub fn keyboard_present() -> bool {
    KEYBOARD_OK.load(Ordering::Relaxed)
}

/// Whether the mouse answered its identify sequence (`0xF2` -> ACK + id byte). The aux-port
/// test (`0xA9`) only proves the *port* answers; this proves a device is behind it.
pub fn mouse_present() -> bool {
    MOUSE_OK.load(Ordering::Relaxed)
}

/// 1 when the device confirmed set 1, 0 when it did not answer.
pub fn scancode_set() -> u8 {
    SCANCODE_SET.load(Ordering::Relaxed)
}

pub fn mouse_device_id() -> u8 {
    MOUSE_ID.load(Ordering::Relaxed)
}

pub fn mouse_packet_length() -> u8 {
    MOUSE_PACKET_LEN.load(Ordering::Relaxed)
}

/// (keyboard bytes, mouse bytes, decoded keys, key releases, ignored codes).
pub fn byte_counters() -> (u64, u64, u64, u64, u64) {
    (
        KEY_BYTES.load(Ordering::Relaxed),
        MOUSE_BYTES.load(Ordering::Relaxed),
        KEYS_DECODED.load(Ordering::Relaxed),
        KEY_RELEASES.load(Ordering::Relaxed),
        KEYS_IGNORED.load(Ordering::Relaxed),
    )
}

/// (mouse packets delivered, rejected, wheel bytes seen).
pub fn mouse_counters() -> (u64, u64, u64) {
    (
        MOUSE_PACKETS.load(Ordering::Relaxed),
        MOUSE_REJECTED.load(Ordering::Relaxed),
        MOUSE_WHEEL_BYTES.load(Ordering::Relaxed),
    )
}

/// (keyboard queue depth, keyboard queue loss, mouse queue depth, mouse queue loss).
pub fn queue_depth() -> (usize, u64, usize, u64) {
    let keys = key_queue();
    let mouse = mouse_queue();
    (keys.depth(), keys.loss, mouse.depth(), mouse.loss)
}

/// Current modifier state, for `input status`.
pub fn modifier_state() -> u8 {
    keyboard().modifiers()
}

/// Prints the driver's state (used by the shell's `input` command).
pub fn status() {
    let (key_bytes, mouse_bytes, decoded, releases, ignored) = byte_counters();
    let (packets, rejected, wheel) = mouse_counters();
    let (key_depth, key_loss, mouse_depth, mouse_loss) = queue_depth();
    let modifiers = modifier_state();

    if !present() {
        // The counter lines below still print (and stay at zero): the harness reads them by
        // name, and "no bytes at all" is the evidence that nothing was fabricated.
        println!(
            "[PS2] controller: present=false self-test={} aux-port={} - no 8042, input disabled, no port reads",
            if controller_ready() { "PASS" } else { "FAIL" },
            if aux_present() { "present" } else { "absent" }
        );
    } else {
        println!(
            "[PS2] controller: present=true self-test={} aux-port={} scancode-set={} mouse-id={:#04x} packet={}B",
            if controller_ready() { "PASS" } else { "FAIL" },
            if aux_present() { "present" } else { "absent" },
            match scancode_set() {
                1 => "1",
                0 => "unconfirmed",
                _ => "?",
            },
            mouse_device_id(),
            mouse_packet_length()
        );
        // The line above is about the 8042 itself. This one names each device, so a machine
        // whose controller answers while a port is empty cannot read as healthy here either.
        println!(
            "[PS2] devices: keyboard={} mouse={} keyboard-irq={} mouse-irq={}",
            if keyboard_present() { "present" } else { "absent" },
            if mouse_present() { "present" } else { "absent" },
            if keyboard_present() { "unmasked" } else { "masked" },
            if mouse_present() { "unmasked" } else { "masked" }
        );
    }
    println!(
        "[PS2] keyboard: bytes={} decoded={} releases={} ignored={} queue={}/{} lost={}",
        key_bytes,
        decoded,
        releases,
        ignored,
        key_depth,
        QUEUE_CAPACITY,
        key_loss
    );
    println!(
        "[PS2] mouse: bytes={} packets={} rejected={} wheel={} queue={}/{} lost={}",
        mouse_bytes,
        packets,
        rejected,
        wheel,
        mouse_depth,
        QUEUE_CAPACITY,
        mouse_loss
    );
    println!(
        "[PS2] modifiers: shift={} ctrl={} alt={} caps={} num={} scroll={}",
        modifiers & (MOD_SHIFT | MOD_ANY_SHIFT) != 0,
        modifiers & MOD_CTRL != 0,
        modifiers & MOD_ALT != 0,
        modifiers & MOD_CAPS != 0,
        modifiers & MOD_NUM != 0,
        modifiers & MOD_SCROLL != 0
    );
}

// ---------------------------------------------------------------------------------------
// Probe
// ---------------------------------------------------------------------------------------

pub struct InputReport {
    pub passed: u32,
    pub failed: u32,
    /// Assertions that cannot run on this machine (routing needs a display server to have a
    /// focus holder at all). Reported rather than quietly dropped.
    pub skipped: u32,
    pub failures: alloc::vec::Vec<&'static str>,
}

impl InputReport {
    fn new() -> Self {
        Self {
            passed: 0,
            failed: 0,
            skipped: 0,
            failures: alloc::vec::Vec::new(),
        }
    }

    fn record(&mut self, name: &'static str, ok: bool) {
        if ok {
            self.passed += 1;
        } else {
            self.failed += 1;
            if self.failures.len() < 8 {
                self.failures.push(name);
            }
        }
    }
}

/// Runs the decoders and the focus-routing policy on synthetic traffic.
///
/// The device itself cannot be driven from software, so the probe feeds set-1 bytes and mouse
/// packets straight into scratch decoder instances (the exact code paths IRQ1/IRQ12 feed) and
/// then checks the *policy* against the live display server: a key reaches the focused
/// window's owner and is refused everywhere else. The real device path is covered by the QEMU
/// harness, which injects actual key events through the emulated 8042.
pub fn self_test() -> InputReport {
    let mut report = InputReport::new();
    // Snapshot of the live counters: synthetic traffic must not move any of them.
    let live_before = (byte_counters(), mouse_counters());

    // 1. Make/break of a printable key.
    let mut kbd = Keyboard::new();
    let press = kbd.byte(0x1E); // 'a' down
    let release = kbd.byte(0x9E); // 'a' up
    report.record(
        "scancode-make-break",
        press == Some(KeyEvent {
            code: Code::Character,
            character: Some(b'a'),
            pressed: true,
            modifiers: 0,
            raw: 0x1E,
            extended: false,
        }) && release.map(|event| (event.character, event.pressed)) == Some((Some(b'a'), false)),
    );

    // 2. Shift (left) overrules the character but does not overrule itself.
    kbd.byte(0x2A);
    let shifted = kbd.byte(0x1E);
    report.record(
        "shift-modifier",
        shifted.map(|event| event.character) == Some(Some(b'A'))
            && shifted.map(|event| event.modifiers) == Some(MOD_SHIFT | MOD_ANY_SHIFT),
    );
    kbd.byte(0xAA);
    let unshifted = kbd.byte(0x1E);
    report.record(
        "shift-release",
        unshifted.map(|event| (event.character, event.modifiers)) == Some((Some(b'a'), 0)),
    );

    // 3. Right shift sets the same logical modifier bit as the left one.
    kbd.byte(0x36);
    let right_shift = kbd.byte(0x2B); // '\'
    report.record(
        "right-shift",
        right_shift.map(|event| (event.character, event.modifiers))
            == Some((Some(b'|'), MOD_SHIFT | MOD_ANY_SHIFT)),
    );
    kbd.byte(0xB6);

    // 4. Caps Lock affects letters only and is released by shift.
    kbd.byte(0x3A); // caps on
    let capped = kbd.byte(0x1E);
    let capped_digit = kbd.byte(0x02);
    report.record(
        "caps-lock-letters-only",
        capped.map(|event| event.character) == Some(Some(b'A'))
            && capped_digit.map(|event| event.character) == Some(Some(b'1'))
            && capped.map(|event| event.modifiers) == Some(MOD_CAPS),
    );
    kbd.byte(0x2A);
    let caps_with_shift = kbd.byte(0x1E);
    report.record(
        "caps-lock-shift-inverts",
        caps_with_shift.map(|event| event.character) == Some(Some(b'a')),
    );
    kbd.byte(0xAA);
    kbd.byte(0x3A); // caps off

    // 5. Extended keys: `0xE0 0x48` is Up, `0xE0 0x1C` is keypad Enter. The prefix byte
    //    produces no event of its own, so it is fed for its side effect rather than chained.
    kbd.byte(0xE0);
    let up = kbd.byte(0x48);
    kbd.byte(0xE0);
    let keypad_enter = kbd.byte(0x1C);
    report.record(
        "extended-keys",
        up.map(|event| (event.code, event.extended)) == Some((Code::Up, true))
            && keypad_enter.map(|event| event.code) == Some(Code::Enter),
    );

    // 6. Ctrl/Alt recorded, and the Ctrl+Alt+Del triplet is only three ordinary events.
    kbd.byte(0x1D);
    let ctrl = kbd.byte(0x38);
    report.record(
        "ctrl-alt-chord",
        ctrl.map(|event| event.modifiers & (MOD_CTRL | MOD_ALT)) == Some(MOD_CTRL | MOD_ALT),
    );
    kbd.byte(0x9D);
    kbd.byte(0xB8);

    // 7. Controller chatter is ignored, not decoded as a key (counted by the decoder itself).
    let ignored_before = kbd.ignored;
    let ack = kbd.byte(0xFA);
    let resend = kbd.byte(0xFE);
    report.record(
        "chatter-ignored",
        ack.is_none() && resend.is_none() && kbd.ignored == ignored_before + 2,
    );

    // 7b. `0xAA` is the keyboard's BAT-complete code *and* the break code for left shift, so
    //     it has to reach the modifier state instead of being swallowed as chatter.
    kbd.byte(0x2A);
    let bat_or_release = kbd.byte(0xAA);
    let after_shift = kbd.byte(0x1E);
    report.record(
        "bat-code-vs-shift-release",
        bat_or_release.map(|event| (event.code, event.pressed)) == Some((Code::Modifier, false))
            && after_shift.map(|event| (event.character, event.modifiers))
                == Some((Some(b'a'), 0)),
    );

    // 8. Mouse packet decode: dx = 10, dy = -2 (device counts, +y up). The ninth bit of
    //    each axis lives in the flag byte (bit 4 for X, bit 5 for Y), so a negative Y is
    //    sign + two's-complement byte, not a bare `0xFE`.
    let mut mouse = Mouse::new();
    let packet = mouse
        .byte(0x08 | 0x20, 3)
        .or_else(|| mouse.byte(10, 3))
        .or_else(|| mouse.byte(0xFE, 3));
    report.record(
        "mouse-packet",
        packet
            .map(|packet| (packet.dx, packet.dy, packet.buttons, packet.rejected))
            == Some((10, -2, 0, false)),
    );

    // 9. Buttons and negative-dx sign extension (flag bit 4 = X negative, bit 0 = left).
    mouse.byte(0x08 | 0x10 | 0x01, 3);
    mouse.byte(0xF6, 3); // -10
    let click = mouse.byte(0x02, 3); // +2
    report.record(
        "mouse-buttons-sign",
        click.map(|packet| (packet.dx, packet.dy, packet.buttons))
            == Some((-10, 2, BUTTON_LEFT)),
    );

    // 10. A byte without the sync bit resynchronises the stream instead of desyncing it.
    let mut resync = Mouse::new();
    let rejected = resync.byte(0x00, 3);
    let good = resync
        .byte(0x08, 3)
        .or_else(|| resync.byte(5, 3))
        .or_else(|| resync.byte(5, 3));
    report.record(
        "mouse-resync",
        rejected.is_none() && resync.rejected >= 1 && good.map(|packet| packet.dx) == Some(5),
    );

    // 11. Overflow packets are rejected rather than guessed at.
    let mut overflow = Mouse::new();
    let flagged = overflow
        .byte(0x48, 3) // bit 3 set, bit 6 = X overflow
        .or_else(|| overflow.byte(1, 3))
        .or_else(|| overflow.byte(1, 3));
    report.record(
        "mouse-overflow-reject",
        flagged.map(|packet| packet.rejected) == Some(true) && overflow.rejected == 1,
    );

    // 12. Four-byte (wheel) packets consume the fourth byte, so the next packet still starts
    //     on a sync byte.
    let mut wheel = Mouse::new();
    let wheel_packet = wheel
        .byte(0x08, 4)
        .or_else(|| wheel.byte(1, 4))
        .or_else(|| wheel.byte(1, 4))
        .or_else(|| wheel.byte(0x01, 4)); // wheel byte: the device's own +1, one notch towards the user
    let after_wheel = wheel.byte(0x00, 4); // bad sync byte again
    report.record(
        "mouse-wheel-length",
        wheel_packet.map(|packet| (packet.dx, packet.dy, packet.buttons, packet.wheel))
            == Some((1, 1, 0, -1))
            && after_wheel.is_none(),
    );

    // 13. The wheel's sign, which is the one thing about a wheel packet that cannot be got wrong
    //     silently: a backscroll travelling the wrong direction looks like a working scroll.
    //     The low nibble is a signed four-bit count whose wire sense is inverted against the one
    //     this kernel publishes (see [`MousePacket::wheel`]), so 0x0F is one notch *away* from
    //     the user - up, and back into the history - and not fifteen notches forwards.
    let mut wheel_away = Mouse::new();
    let away_packet = wheel_away
        .byte(0x08, 4)
        .or_else(|| wheel_away.byte(0, 4))
        .or_else(|| wheel_away.byte(0, 4))
        .or_else(|| wheel_away.byte(0x0F, 4));
    // The extremes of the nibble, so the negation cannot be an off-by-one that only happens to
    // look right at unit values: -8 and +7 are the ends of a signed four-bit count.
    let mut wheel_far = Mouse::new();
    let far_packet = wheel_far
        .byte(0x08, 4)
        .or_else(|| wheel_far.byte(0, 4))
        .or_else(|| wheel_far.byte(0, 4))
        .or_else(|| wheel_far.byte(0x08, 4));
    report.record(
        "mouse-wheel-sign",
        away_packet.map(|packet| (packet.wheel, packet.buttons, packet.rejected))
            == Some((1, 0, false))
            && far_packet.map(|packet| packet.wheel) == Some(8),
    );

    // 14. Byte ring: FIFO order, wrap-around, and loss is counted rather than silent.
    let mut queue = ByteQueue::new();
    for index in 0..QUEUE_CAPACITY + 8 {
        queue.push(index as u8);
    }
    let mut order_ok = true;
    for index in 0..QUEUE_CAPACITY - 1 {
        if queue.pop() != Some(index as u8) {
            order_ok = false;
            break;
        }
    }
    report.record(
        "byte-queue-order-loss",
        order_ok && queue.loss == 9 && queue.pop().is_none(),
    );

    // The last three assertions are about the *policy* the display server applies, so they
    // need a display server: on a machine with no adapter there is no focus holder and no
    // window to route to, and pretending otherwise would be a false pass or a false failure.
    let routing_available = crate::gui::installed();
    if !routing_available {
        report.skipped += 4;
    }

    // 15. Input routing: only the focused window receives keys.
    let focused_before = crate::gui::focused_title();
    let shell_focused = !routing_available || crate::gui::focus_window_named("KELLER SHELL");
    let line_before = crate::shell::line_length();
    let delivered = crate::gui::route_key(KeyEvent {
        code: Code::Character,
        character: Some(b'#'),
        pressed: true,
        modifiers: 0,
        raw: 0x04,
        extended: false,
    });
    let line_after = crate::shell::line_length();
    // The shell echoes what it receives, so the character is also the visible proof; the probe
    // erases it again so no residue is left in the line buffer.
    let erased = crate::gui::route_key(KeyEvent {
        code: Code::Backspace,
        character: None,
        pressed: true,
        modifiers: 0,
        raw: 0x0E,
        extended: false,
    });
    if routing_available {
        report.record(
            "focus-route-to-shell",
            shell_focused
                && delivered
                && line_after == line_before + 1
                && erased
                && crate::shell::line_length() == line_before,
        );
    }

    // 16. A key delivered to a window that is not the shell is not seen by the shell. This is
    //     the anti-keylogger property of the focus capability, and it is what "click the vault
    //     tile and type" has to mean: the key is delivered *there* and to nowhere else. (Before
    //     the tiles could accept input this assertion was "refused"; the property is the same
    //     one, with the tile as the recipient instead of the void.)
    let vault_focused = crate::gui::focus_window_named("KELLER VAULT");
    let line_before = crate::shell::line_length();
    let (routed_before, _, _) = crate::gui::input_counters();
    let (_, _, tiles_before, _) = crate::gui::scroll_counters();
    let delivered_to_tile = crate::gui::route_key(KeyEvent {
        code: Code::Character,
        character: Some(b'#'),
        pressed: true,
        modifiers: 0,
        raw: 0x04,
        extended: false,
    });
    let refused_line = crate::shell::line_length();
    let (routed_after, _, _) = crate::gui::input_counters();
    let (_, _, tiles_after, _) = crate::gui::scroll_counters();
    if routing_available {
        report.record(
            "focus-routes-away-from-shell",
            vault_focused
                && delivered_to_tile
                && refused_line == line_before
                && routed_after == routed_before + 1
                && tiles_after == tiles_before + 1,
        );
    }

    // 16b. Backscroll: PageUp moves the focused window into its history and End brings it back
    //      to the live tail. The view is the shell's own scrollback, so this is also what says
    //      a long `help` or `selftest` output can be read instead of running off the tile.
    //      At boot this is often skipped rather than green: there is no history until the log
    //      is deeper than the tile, and `input test` run later from the shell is where the
    //      property is actually exercised.
    let shell_focused = crate::gui::focus_window_named("KELLER SHELL");
    // The history on offer is the *shell's* - the focus holder from the previous assertion is
    // the vault tile, which has no history at all, so asking before moving the focus would ask
    // the wrong window.
    let history = crate::gui::scroll_state().map(|(_, _, max)| max).unwrap_or(0);
    if routing_available && history == 0 {
        report.skipped += 1;
    } else if routing_available {
        let (steps_before, _, _, _) = crate::gui::scroll_counters();
        let paged = crate::gui::route_key(KeyEvent {
            code: Code::PageUp,
            character: None,
            pressed: true,
            modifiers: 0,
            raw: 0x49,
            extended: true,
        });
        let scrolled = crate::gui::scroll_state();
        let backed_up = scrolled.map(|(_, back, _)| back > 0).unwrap_or(false);
        let returned = crate::gui::route_key(KeyEvent {
            code: Code::End,
            character: None,
            pressed: true,
            modifiers: 0,
            raw: 0x4F,
            extended: true,
        });
        let (steps_after, _, _, _) = crate::gui::scroll_counters();
        let live_again = crate::gui::scroll_state()
            .map(|(_, back, _)| back == 0)
            .unwrap_or(false);
        let ok = shell_focused
            && paged
            && backed_up
            && returned
            && steps_after >= steps_before + 2
            && live_again;
        if !ok {
            // The components, not just the verdict: a scroll that did not move is a different
            // bug from a key that was not delivered, and the numbers say which one this is.
            crate::println!(
                "[PS2] scrollback probe: shell-focused={} paged={} backed-up={} returned={} steps {}->{} history={} max={}",
                shell_focused,
                paged,
                backed_up,
                returned,
                steps_before,
                steps_after,
                history,
                crate::gui::scroll_state().map(|(_, _, max)| max).unwrap_or(0)
            );
        }
        report.record("scrollback-page-and-end", ok);
    }

    // 17. Alt+Tab cycles focus through every window slot and back to the start.
    let cycling = !routing_available
        || (crate::gui::focus_window_named("KELLER SHELL")
            && crate::gui::focus_cycle() == Some("KELLER VAULT")
            && crate::gui::focus_cycle() == Some("SUBSYSTEMS")
            && crate::gui::focus_cycle() == Some("KELLER SHELL"));
    if routing_available {
        report.record("alt-tab-focus-cycle", cycling);

        // Leave the shell focused, where it started.
        let restored = crate::gui::focus_window_named(focused_before.unwrap_or("KELLER SHELL"));
        report.record(
            "focus-restored",
            restored && crate::gui::focused_title() == focused_before,
        );
    }

    // 18. The probe decoded synthetic traffic, so the live counters must be exactly where
    //     they were: a scratch decoder that wrote to the global counters would make
    //     `input status` report keys nobody ever typed.
    let live_after = (byte_counters(), mouse_counters());
    report.record("probe-leaves-counters-clean", live_before == live_after);

    report
}
