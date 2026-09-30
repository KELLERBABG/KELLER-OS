//! COM1 (16550 UART) driver: kernel logging plus the interactive console channel
//! used by `Keller Shell`.
//!
//! TX is polled on the Line Status Register. RX is interrupt driven (IRQ4) into a
//! fixed-size ring buffer so the shell can drain input without blocking the kernel.

use crate::port::{inb, outb};
use core::fmt;
use core::sync::atomic::{AtomicUsize, Ordering};

pub const COM1: u16 = 0x3F8;

const RBR: u16 = 0; // receive buffer (read)
const THR: u16 = 0; // transmit holding (write)
const IER: u16 = 1; // interrupt enable
const FCR: u16 = 2; // FIFO control
const LCR: u16 = 3; // line control
const MCR: u16 = 4; // modem control
const LSR: u16 = 5; // line status: bit 5 = THR empty, bit 0 = data ready
const DLL: u16 = 0;
const DLM: u16 = 1;

const RX_CAPACITY: usize = 256;

struct RxRing {
    buf: [u8; RX_CAPACITY],
    head: usize,
    tail: usize,
}

impl RxRing {
    const fn new() -> Self {
        Self { buf: [0; RX_CAPACITY], head: 0, tail: 0 }
    }
}

// Written from the IRQ4 handler and read from the shell: accesses are serialised by
// the interrupt disable/re-enable window in `push_byte`/`pop_byte`, never by threads.
static mut RX: RxRing = RxRing::new();
static RX_LOSS: AtomicUsize = AtomicUsize::new(0);
static TX_SEQ: AtomicUsize = AtomicUsize::new(0);

struct TxLock(AtomicUsize);

impl TxLock {
    const fn new() -> Self {
        Self(AtomicUsize::new(0))
    }

    fn acquire(&self) {
        while self
            .0
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
    }

    fn release(&self) {
        self.0.store(0, Ordering::Release);
    }
}

static TX_LOCK: TxLock = TxLock::new();

pub unsafe fn init() {
    // `.bss` is not guaranteed zeroed by the loader: reset the driver's own state.
    RX_LOSS.store(0, Ordering::Relaxed);
    TX_SEQ.store(0, Ordering::Relaxed);
    let ring = &mut *core::ptr::addr_of_mut!(RX);
    ring.head = 0;
    ring.tail = 0;

    outb(COM1 + IER, 0x00); // interrupts off while configuring
    outb(COM1 + LCR, 0x80); // DLAB on
    outb(COM1 + DLL, 0x01); // 115200 baud
    outb(COM1 + DLM, 0x00);
    outb(COM1 + LCR, 0x03); // 8 bits, no parity, one stop bit
    outb(COM1 + FCR, 0xC7); // enable + clear FIFOs, 14-byte trigger
    outb(COM1 + MCR, 0x0B); // DTR, RTS, OUT2 (required for IRQ delivery)
}

/// Enables the "received data available" interrupt (IRQ4).
pub unsafe fn enable_rx_interrupt() {
    outb(COM1 + IER, 0x01);
}

pub fn write_byte(byte: u8) {
    // Every `print!` in the kernel passes through here, so this is the one place that has to
    // mirror the log into the GUI console tile (GUI_SPECIFICATION.md §4.2: the shell window
    // shows the kernel log). The mirror only buffers; it never draws.
    crate::gui::console_write(byte);

    TX_LOCK.acquire();
    unsafe {
        while (inb(COM1 + LSR) & 0x20) == 0 {
            core::hint::spin_loop();
        }
        outb(COM1 + THR, byte);
    }
    TX_LOCK.release();
    TX_SEQ.fetch_add(1, Ordering::Relaxed);
}

pub fn write_str(s: &str) {
    for b in s.as_bytes() {
        if *b == b'\n' {
            write_byte(b'\r');
        }
        write_byte(*b);
    }
}

pub fn write_fmt(args: fmt::Arguments) {
    use fmt::Write;
    struct W;
    impl fmt::Write for W {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            write_str(s);
            Ok(())
        }
    }
    let _ = W.write_fmt(args);
}

/// Number of bytes pushed out of COM1 — used by the boot self-test summary.
pub fn tx_bytes() -> usize {
    TX_SEQ.load(Ordering::Relaxed)
}

/// Pushes one received byte into the ring. Called from the IRQ4 handler.
pub fn push_rx(byte: u8) {
    unsafe {
        let ring = &mut *core::ptr::addr_of_mut!(RX);
        let next = (ring.head + 1) % RX_CAPACITY;
        if next == ring.tail {
            RX_LOSS.fetch_add(1, Ordering::Relaxed);
            return;
        }
        ring.buf[ring.head] = byte;
        ring.head = next;
    }
}

pub fn pop_rx() -> Option<u8> {
    unsafe {
        let ring = &mut *core::ptr::addr_of_mut!(RX);
        if ring.head == ring.tail {
            return None;
        }
        let byte = ring.buf[ring.tail];
        ring.tail = (ring.tail + 1) % RX_CAPACITY;
        Some(byte)
    }
}

/// Drains the receive FIFO into the ring; called from IRQ4 (and safe to call in a
/// poll loop when interrupts are off).
pub fn service_rx() {
    unsafe {
        while (inb(COM1 + LSR) & 0x01) != 0 {
            push_rx(inb(COM1 + RBR));
        }
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        $crate::serial::write_fmt(format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! println {
    () => {{ $crate::print!("\n"); }};
    ($($arg:tt)*) => {{
        $crate::serial::write_fmt(format_args!($($arg)*));
        $crate::serial::write_byte(b'\n');
    }};
}
