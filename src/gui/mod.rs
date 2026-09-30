//! KELLER-OS display server (GUI_SPECIFICATION.md §4, phases 1-4 in Ring 0).
//!
//! The specification puts the compositor in Ring 3 and keeps Ring 0 free of graphics code.
//! This module is the bring-up stage of that plan and is written so it can be moved: it owns
//! a backbuffer (never drawing straight into the framebuffer), it exposes a fixed pool of
//! window descriptors with bounding boxes, capability tokens and focus state, and it blits
//! only the rectangles whose content actually changed. What is missing on purpose is the
//! Ring-3 boundary itself (a sandboxed `keller-wm` process) — the interfaces here are the
//! ones it will consume.
//!
//! Layout: a top status bar, a shell console tile mirroring the kernel log, a vault tile and
//! a subsystem tile (mesh, IPC, session). Refresh is a fixed 100 ms slot — no animations, no
//! partial frames, no allocation after start-up.

pub mod canvas;
pub mod font;

use crate::arch::ps2;
use crate::clock;
use crate::fb;
use canvas::{Canvas, Rect, BG, BORDER, CHROME, DANGER, PANEL, SECURE, TEXT, TEXT_DIM};
use core::fmt::{self, Write};
use core::mem::MaybeUninit;

/// Fixed refresh cadence: one slot per scheduler quantum.
pub const REFRESH_MS: u64 = 100;
/// Fixed pool of window slots, as the specification requires (`MAX_WINDOWS = 8`).
pub const MAX_WINDOWS: usize = 8;
/// Bytes per text line (also the column budget of the widest tile).
/// One text line. Sized so the top status bar (version, subsystem states, entropy source,
/// uptime, focus holder and cursor position) fits the full 128-column width without being
/// silently truncated.
pub const LINE_CAPACITY: usize = 128;
/// Lines kept per tile.
pub const TILE_LINES: usize = 34;
/// Console scrollback lines mirrored from the kernel log. Deliberately much larger than the
/// tile: the tile is a *view* onto this ring, not the ring itself, which is what makes `help`,
/// `selftest` and a long boot log scrollable instead of merely truncated.
pub const CONSOLE_LINES: usize = 256;
/// Interior padding of a tile, in pixels.
const PADDING: u32 = 6;
/// Title-bar height of a tile, per the specification's 20px chrome.
const CHROME_HEIGHT: u32 = 20;
/// Height of the top status bar and the footer.
const TOP_BAR_HEIGHT: u32 = 30;
const FOOTER_HEIGHT: u32 = 22;

// ---------------------------------------------------------------------------------------
// Fixed-capacity text
// ---------------------------------------------------------------------------------------

/// One fixed-capacity text line; also a `fmt::Write` sink, so tiles format with `write!`.
#[derive(Clone, Copy)]
pub struct Line {
    bytes: [u8; LINE_CAPACITY],
    len: usize,
}

impl Line {
    pub const fn new() -> Self {
        Self {
            bytes: [0; LINE_CAPACITY],
            len: 0,
        }
    }

    pub fn clear(&mut self) {
        self.len = 0;
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.len]).unwrap_or("")
    }

    pub fn from_str(text: &str) -> Self {
        let mut line = Self::new();
        let _ = line.write_str(text);
        line
    }

    fn same_as(&self, other: &Line) -> bool {
        self.len == other.len && self.bytes[..self.len] == other.bytes[..other.len]
    }
}

impl fmt::Write for Line {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        for byte in text.bytes() {
            if self.len >= LINE_CAPACITY {
                break;
            }
            self.bytes[self.len] = byte;
            self.len += 1;
        }
        Ok(())
    }
}

/// A fixed-capacity block of lines: one tile's text.
#[derive(Clone, Copy)]
pub struct TextBlock {
    lines: [Line; TILE_LINES],
    count: usize,
}

impl TextBlock {
    pub const fn new() -> Self {
        Self {
            lines: [Line::new(); TILE_LINES],
            count: 0,
        }
    }

    pub fn clear(&mut self) {
        self.count = 0;
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Appends a fresh line and returns it for formatting.
    pub fn push(&mut self) -> &mut Line {
        if self.count < TILE_LINES {
            self.lines[self.count].clear();
            self.count += 1;
        } else {
            // Full: recycle the last line rather than dropping the newest information.
            let last = TILE_LINES - 1;
            self.lines[last].clear();
        }
        let index = if self.count == 0 { 0 } else { self.count - 1 };
        &mut self.lines[index]
    }

    pub fn push_str(&mut self, text: &str) {
        let line = self.push();
        let _ = line.write_str(text);
    }

    pub fn line(&self, index: usize) -> &Line {
        &self.lines[index]
    }

    fn changed_from(&self, other: &TextBlock) -> bool {
        if self.count != other.count {
            return true;
        }
        for index in 0..self.count {
            if !self.lines[index].same_as(&other.lines[index]) {
                return true;
            }
        }
        false
    }

    fn copy_into(&self, other: &mut TextBlock) {
        other.count = self.count;
        for index in 0..self.count {
            other.lines[index] = self.lines[index];
        }
    }
}

// ---------------------------------------------------------------------------------------
// Window descriptors (the Ring-3 compositor's contract)
// ---------------------------------------------------------------------------------------

/// One window slot. In Ring 3 the backbuffer pointer names a shared memory segment; in this
/// bring-up the tile rasterises straight into the compositor's backbuffer at the same
/// coordinates, and the descriptor still carries the capability token and focus state the
/// sandboxed compositor will check.
#[derive(Clone, Copy)]
pub struct WindowDesc {
    pub id: u32,
    pub owner_pid: u32,
    pub title: &'static str,
    pub rect: Rect,
    pub capability: u64,
    pub focus: bool,
}

pub struct WindowManager {
    slots: [Option<WindowDesc>; MAX_WINDOWS],
    count: usize,
    focus: usize,
}

impl WindowManager {
    pub const fn new() -> Self {
        Self {
            slots: [None; MAX_WINDOWS],
            count: 0,
            focus: 0,
        }
    }

    pub fn spawn(
        &mut self,
        id: u32,
        owner_pid: u32,
        title: &'static str,
        rect: Rect,
        capability: u64,
        focus: bool,
    ) -> bool {
        if self.count >= MAX_WINDOWS {
            return false;
        }
        for slot in self.slots.iter_mut() {
            if slot.is_none() {
                *slot = Some(WindowDesc {
                    id,
                    owner_pid,
                    title,
                    rect,
                    capability,
                    focus,
                });
                self.count += 1;
                return true;
            }
        }
        false
    }

    pub fn count(&self) -> usize {
        self.count
    }

    pub fn get(&self, index: usize) -> Option<&WindowDesc> {
        self.slots.get(index).and_then(|slot| slot.as_ref())
    }

    pub fn focused(&self) -> Option<&WindowDesc> {
        self.slots
            .iter()
            .flatten()
            .find(|window| window.focus)
            .or_else(|| self.slots.iter().flatten().next())
    }

    /// Slot index of the focus holder. The slots are filled in order, so this is also the index
    /// of the tile the window draws and of the scroll offset that belongs to it.
    pub fn focused_index(&self) -> usize {
        self.focus
    }

    /// Grants focus to the window with this title, the way a click or the `Alt + Tab` order
    /// would. Returns false when no slot carries that title.
    pub fn focus_by_title(&mut self, title: &str) -> bool {
        let mut located = None;
        let mut seen = 0usize;
        for window in self.slots.iter().flatten() {
            if window.title == title {
                located = Some(seen);
                break;
            }
            seen += 1;
        }
        match located {
            Some(index) => self.set_focus(index).is_some(),
            None => false,
        }
    }

    /// Click-to-focus: the topmost window containing the point gets the focus capability.
    pub fn focus_at(&mut self, x: u32, y: u32) -> Option<&'static str> {
        let mut located = None;
        let mut seen = 0usize;
        for window in self.slots.iter().flatten() {
            if window.rect.contains(x, y) {
                located = Some(seen);
            }
            seen += 1;
        }
        located.and_then(|index| self.set_focus(index))
    }

    /// Focuses one slot by index and returns its title.
    fn set_focus(&mut self, index: usize) -> Option<&'static str> {
        let mut title = None;
        let mut seen = 0usize;
        for window in self.slots.iter_mut().flatten() {
            window.focus = seen == index;
            if seen == index {
                title = Some(window.title);
            }
            seen += 1;
        }
        if title.is_some() {
            self.focus = index;
        }
        title
    }

    /// Advances focus to the next slot: the `Alt + Tab` order, bound to the keyboard in
    /// `route_key` (the compositor consumes that chord itself).
    pub fn focus_next(&mut self) -> usize {
        let total = self.count;
        if total == 0 {
            return 0;
        }
        let mut focused = 0usize;
        let mut seen = 0usize;
        for window in self.slots.iter_mut().flatten() {
            if window.focus {
                window.focus = false;
            }
            if seen == (self.focus + 1) % total {
                window.focus = true;
                focused = seen;
            }
            seen += 1;
        }
        self.focus = focused;
        focused
    }

    pub fn describe(&self) {
        crate::println!("[GUI] window slots: {}/{}", self.count, MAX_WINDOWS);
        for window in self.slots.iter().flatten() {
            crate::println!(
                "[GUI]   win{} {} pid={} rect={}x{}+{}+{} capability={:#018x} focus={}",
                window.id,
                window.title,
                window.owner_pid,
                window.rect.width,
                window.rect.height,
                window.rect.x,
                window.rect.y,
                window.capability,
                window.focus
            );
        }
    }
}

// ---------------------------------------------------------------------------------------
// Console mirror
// ---------------------------------------------------------------------------------------

/// Ring buffer of kernel-log lines. `serial::write_byte` feeds this one byte at a time, which
/// is the lowest point every `print!` in the kernel passes through.
struct ConsoleMirror {
    lines: [[u8; LINE_CAPACITY]; CONSOLE_LINES],
    lengths: [usize; CONSOLE_LINES],
    write_line: usize,
    count: usize,
    escape: bool,
}

impl ConsoleMirror {
    const fn new() -> Self {
        Self {
            lines: [[0; LINE_CAPACITY]; CONSOLE_LINES],
            lengths: [0; CONSOLE_LINES],
            write_line: 0,
            count: 0,
            escape: false,
        }
    }

    fn reset(&mut self) {
        self.write_line = 0;
        self.count = 0;
        self.escape = false;
        for length in self.lengths.iter_mut() {
            *length = 0;
        }
    }

    fn advance(&mut self) {
        self.write_line = (self.write_line + 1) % CONSOLE_LINES;
        self.lengths[self.write_line] = 0;
        if self.count < CONSOLE_LINES {
            self.count += 1;
        }
    }

    fn push_byte(&mut self, byte: u8) {
        match byte {
            b'\n' => self.advance(),
            b'\r' => self.lengths[self.write_line] = 0,
            0x1B => self.escape = true,
            0x00..=0x1F | 0x7F => {}
            _ => {
                let length = self.lengths[self.write_line];
                if length >= LINE_CAPACITY {
                    self.advance();
                }
                let index = self.lengths[self.write_line];
                if index == 0 && self.count == 0 {
                    self.count = 1;
                }
                self.lines[self.write_line][index] = byte;
                self.lengths[self.write_line] = index + 1;
            }
        }
    }

    /// Copies the newest `TILE_LINES` lines, oldest first, into a tile (the live view).
    fn fill(&self, tile: &mut TextBlock) {
        self.fill_window(tile, 0);
    }

    /// Copies a `TILE_LINES`-line window into a tile, ending `back` lines above the newest one.
    /// `back == 0` is the live tail; the ring is the whole scrollback and the tile is the window
    /// onto it.
    fn fill_window(&self, tile: &mut TextBlock, back: usize) {
        tile.clear();
        let total = self.count.min(CONSOLE_LINES);
        if total == 0 {
            return;
        }
        // The window ends `back` lines above the newest line and is as tall as the tile, so the
        // oldest line it can show is `start`.
        let end = total - back.min(total.saturating_sub(1));
        let start = end.saturating_sub(tile_capacity());
        for position in start..end {
            let index = (self.write_line + CONSOLE_LINES - (total - 1 - position)) % CONSOLE_LINES;
            let length = self.lengths[index];
            let line = tile.push();
            let _ = line.write_str(
                core::str::from_utf8(&self.lines[index][..length]).unwrap_or(""),
            );
        }
    }

    /// Lines the ring is actually holding.
    fn held(&self) -> usize {
        self.count.min(CONSOLE_LINES)
    }
}

/// How many lines of backscroll a window can offer: the history minus the window's own height.
fn scroll_max(index: usize) -> usize {
    match index {
        0 => console_lines().saturating_sub(TILE_LINES),
        _ => 0,
    }
}

/// Tile a window index shows. The three tiles are the console, the vault and the subsystems.


fn tile_capacity() -> usize {
    TILE_LINES
}

static mut CONSOLE: ConsoleMirror = ConsoleMirror::new();

/// Feeds one byte of kernel log output into the console tile. Called from the serial driver.
pub fn console_write(byte: u8) {
    unsafe {
        let console = core::ptr::addr_of_mut!(CONSOLE);
        if (*console).escape {
            // Swallow one escape sequence (the shell's `clear` sends two).
            if byte.is_ascii_alphabetic() || byte == b'm' {
                (*console).escape = false;
            }
            return;
        }
        (*console).push_byte(byte);
    }
}

/// Clears the console tile's scrollback.
pub fn console_clear() {
    unsafe {
        core::ptr::addr_of_mut!(CONSOLE).as_mut().map(|console| console.reset());
    }
}

/// Number of log lines the console tile is holding (used by the probe and `gui status`).
pub fn console_lines() -> usize {
    unsafe { (*core::ptr::addr_of!(CONSOLE)).count }
}

// ---------------------------------------------------------------------------------------
// Display server
// ---------------------------------------------------------------------------------------

struct DisplayServer {
    canvas: Canvas,
    windows: WindowManager,
    console: TextBlock,
    console_rendered: TextBlock,
    vault: TextBlock,
    vault_rendered: TextBlock,
    subsystems: TextBlock,
    subsystems_rendered: TextBlock,
    top: Line,
    top_rendered: Line,
    footer: Line,
    footer_rendered: Line,
    enabled: bool,
    full_repaint: bool,
    frames: u64,
    blits: u64,
    dirty_rects: u64,
    full_screens: u64,
    last_refresh_ms: u64,
    bytes: u64,
    /// Software cursor: the arrow is drawn into the backbuffer like any other window content,
    /// so a repaint rectangle carries it and no hardware cursor is needed.
    cursor: (u32, u32),
    /// Where the backbuffer currently has the arrow. Moving it means repairing the pixels it
    /// left behind, which is one more rectangle for the next pass.
    cursor_drawn: Option<(u32, u32)>,
    cursor_moved: bool,
    /// Focus moved: the title colours changed even though no tile text did, so the chrome of
    /// every window is repainted on the next pass.
    focus_repaint: bool,
    /// Per-window backscroll, in lines above the newest (`0` = live). Indexed the way the
    /// windows are, so the window a key or a wheel notch was routed to is the one that moves.
    scroll: [usize; 3],
    /// Scroll gestures that moved a view, and wheel notches received (including ones that hit
    /// the end of the history, which is a scroll that did nothing rather than a lost event).
    scroll_steps: u64,
    wheel_notches: i64,
    /// Keys delivered to a window that is not the shell: the proof that focus really routes
    /// input somewhere other than the console.
    keys_to_tiles: u64,
    /// Pointer buttons currently held (needed so a held button is one click, not sixty).
    buttons: u8,
    /// Input routed to the focus holder, and input refused because no window held focus.
    keys_routed: u64,
    keys_refused: u64,
    characters_delivered: u64,
    mouse_packets: u64,
    clicks: u64,
    focus_changes: u64,
    motion: (i64, i64),
}

/// The display state lives in `.bss` and is filled *in place*. A `DisplayServer` is ~20 KiB,
/// and building one as a local costs over 100 KiB of frames in a debug build - more than the
/// boot stack has, which used to tumble into the page tables below it (a triple fault, not a
/// panic). Every field is therefore written through a raw pointer; see `init`.
static mut SERVER: MaybeUninit<DisplayServer> = MaybeUninit::uninit();

/// Explicit readiness flag. `.bss` is not zeroed by the bootloader, so this is only
/// meaningful after [`reset`].
static mut SERVER_READY: bool = false;

/// High-water mark of boot-stack use seen by the display server (see [`stack_peak`]).
static mut STACK_PEAK: u64 = 0;

fn server_ptr() -> *mut DisplayServer {
    unsafe { (*core::ptr::addr_of_mut!(SERVER)).as_mut_ptr() }
}

fn server() -> Option<&'static mut DisplayServer> {
    unsafe {
        if *core::ptr::addr_of!(SERVER_READY) {
            Some(&mut *server_ptr())
        } else {
            None
        }
    }
}

/// Explicit self-initialisation of the module's mutable statics.
///
/// `kernel_main` calls this before the serial console starts mirroring bytes, because
/// `serial::write_byte` feeds [`console_write`] from the very first `print!` - long before
/// `init` runs. `init` calls it again so the display server is never read through stale
/// memory either way.
pub fn reset() {
    unsafe {
        *core::ptr::addr_of_mut!(SERVER_READY) = false;
        *core::ptr::addr_of_mut!(STACK_PEAK) = 0;
        core::ptr::addr_of_mut!(CONSOLE)
            .as_mut()
            .map(|console| console.reset());
    }
}

pub fn installed() -> bool {
    unsafe { *core::ptr::addr_of!(SERVER_READY) }
}

/// Bytes of the boot stack in use right now (`__boot_stack_top` - `rsp`).
///
/// Ring 0 runs on one static stack, so the compositor measures itself: an oversized frame
/// does not fault cleanly here, it walks into whatever `.bss` holds below the stack.
fn stack_used() -> u64 {
    extern "C" {
        static __boot_stack_top: u8;
    }
    let sp: u64;
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) sp, options(nomem, nostack));
        (&__boot_stack_top as *const u8 as u64).saturating_sub(sp)
    }
}

/// Records the deepest stack use seen so far and returns it.
fn note_stack() -> u64 {
    let used = stack_used();
    unsafe {
        let peak = core::ptr::addr_of_mut!(STACK_PEAK);
        if used > *peak {
            *peak = used;
        }
        *peak
    }
}

/// Deepest boot-stack use the display server has needed (bytes below the stack top).
pub fn stack_peak() -> u64 {
    unsafe { *core::ptr::addr_of!(STACK_PEAK) }
}

/// Zeroes a field in place. `Line::new()` and `TextBlock::new()` are all-zero by
/// construction, so this initialises them without a multi-KiB stack temporary.
unsafe fn zero_in_place<T>(pointer: *mut T) {
    core::ptr::write_bytes(pointer as *mut u8, 0, core::mem::size_of::<T>());
}

pub fn enabled() -> bool {
    server().map(|server| server.enabled).unwrap_or(false)
}

pub fn set_enabled(enabled: bool) {
    if let Some(server) = server() {
        server.enabled = enabled;
        server.full_repaint = true;
    }
}

pub fn frames() -> u64 {
    server().map(|server| server.frames).unwrap_or(0)
}

pub fn blits() -> u64 {
    server().map(|server| server.blits).unwrap_or(0)
}

pub fn backbuffer_bytes() -> u64 {
    server().map(|server| server.bytes).unwrap_or(0)
}

/// Allocates the backbuffer, lays out the windows and paints the first frame.
///
/// The boot loader does not zero `.bss`, so the display state and the console mirror are
/// reset explicitly before anything reads them (see `main.rs` on module self-initialisation).
pub fn init(width: u32, height: u32) -> bool {
    reset();
    note_stack();
    if width < 640 || height < 400 || installed() {
        return false;
    }

    let top = Rect::new(0, 0, width, TOP_BAR_HEIGHT);
    let footer = Rect::new(0, height - FOOTER_HEIGHT, width, FOOTER_HEIGHT);
    let body_top = top.height + 6;
    let body_height = footer.y - body_top - 6;
    let left_width = (width * 62) / 100;
    let right_x = left_width + 10;
    let right_width = width - right_x - 8;
    let upper_height = (body_height * 52) / 100;
    let console_rect = Rect::new(8, body_top, left_width - 8, body_height);
    let vault_rect = Rect::new(right_x, body_top, right_width, upper_height);
    let subsystems_rect = Rect::new(
        right_x,
        body_top + upper_height + 8,
        right_width,
        body_height - upper_height - 8,
    );

    // Fields are written where they live, so nothing larger than a `Rect` ever becomes a
    // stack temporary. The three tiles are registered through the window manager exactly like
    // a Ring-3 client will register its own window.
    unsafe {
        let display = server_ptr();
        core::ptr::write(
            core::ptr::addr_of_mut!((*display).canvas),
            Canvas::new(width, height),
        );
        core::ptr::write(
            core::ptr::addr_of_mut!((*display).windows),
            WindowManager::new(),
        );
        zero_in_place(core::ptr::addr_of_mut!((*display).console));
        zero_in_place(core::ptr::addr_of_mut!((*display).console_rendered));
        zero_in_place(core::ptr::addr_of_mut!((*display).vault));
        zero_in_place(core::ptr::addr_of_mut!((*display).vault_rendered));
        zero_in_place(core::ptr::addr_of_mut!((*display).subsystems));
        zero_in_place(core::ptr::addr_of_mut!((*display).subsystems_rendered));
        zero_in_place(core::ptr::addr_of_mut!((*display).top));
        zero_in_place(core::ptr::addr_of_mut!((*display).top_rendered));
        zero_in_place(core::ptr::addr_of_mut!((*display).footer));
        zero_in_place(core::ptr::addr_of_mut!((*display).footer_rendered));
        (*display).enabled = true;
        (*display).full_repaint = true;
        (*display).frames = 0;
        (*display).blits = 0;
        (*display).dirty_rects = 0;
        (*display).full_screens = 0;
        (*display).last_refresh_ms = 0;
        (*display).bytes = (*display).canvas.bytes();
        // The pointer starts centred so the first frame already proves the cursor composites
        // with the tiles underneath it.
        (*display).cursor = (width / 2, height / 2);
        (*display).cursor_drawn = None;
        (*display).cursor_moved = false;
        (*display).focus_repaint = false;
        (*display).scroll = [0; 3];
        (*display).scroll_steps = 0;
        (*display).wheel_notches = 0;
        (*display).keys_to_tiles = 0;
        (*display).buttons = 0;
        (*display).keys_routed = 0;
        (*display).keys_refused = 0;
        (*display).characters_delivered = 0;
        (*display).mouse_packets = 0;
        (*display).clicks = 0;
        (*display).focus_changes = 0;
        (*display).motion = (0, 0);

        (*display).windows.spawn(1, 1, "KELLER SHELL", console_rect, 0x5348_454C_4C01, true);
        (*display).windows.spawn(2, 2, "KELLER VAULT", vault_rect, 0x5641_554C_5402, false);
        (*display).windows.spawn(3, 3, "SUBSYSTEMS", subsystems_rect, 0x5355_4253_5953, false);

        let console = core::ptr::addr_of!(CONSOLE);
        (*console).fill(&mut (*display).console);
        let focus = (*display).windows.focused().map(|window| window.title);
        let cursor = (*display).cursor;
        format_top(&mut (*display).top, focus, cursor);
        format_footer(&mut (*display).footer, focus, 0);
        format_vault(&mut (*display).vault);
        format_subsystems(&mut (*display).subsystems);

        *core::ptr::addr_of_mut!(SERVER_READY) = true;
    }
    note_stack();
    paint(clock::uptime_ms());
    note_stack();
    true
}

fn format_top(line: &mut Line, focus: Option<&str>, cursor: (u32, u32)) {
    line.clear();
    let vault_state = match crate::vault_handle() {
        Some(vault) if vault.is_healthy() => "VAULT: READY",
        Some(_) => "VAULT: DEGRADED",
        None => "VAULT: OFFLINE",
    };
    let net_state = match crate::net_handle() {
        Some(mesh) if !mesh.is_provisioned() => "NET: UNPROVISIONED",
        Some(mesh) if mesh.isolated_peers() != 0 => "NET: ISOLATED",
        Some(mesh) if mesh.messages_delivered() != 0 => "NET: ACTIVE",
        Some(_) => "NET: IDLE",
        None => "NET: OFFLINE",
    };
    // The focus holder and the cursor position are part of the status bar: they are how a
    // screenshot proves that a keystroke or a click went where it should have.
    let _ = write!(
        line,
        "KOS v2.5 | {} | {} | {} | T+{}ms | FOCUS {} | CUR {},{} | F{} @{}Hz",
        vault_state,
        net_state,
        crate::crypto::entropy_source(),
        clock::uptime_ms(),
        focus.unwrap_or("NONE"),
        cursor.0,
        cursor.1,
        frames(),
        clock::TICKS_PER_SECOND * clock::MS_PER_TICK / REFRESH_MS
    );
}

/// The footer is the honest status line for what the compositor can and cannot do - and it
/// carries the focused window's backscroll, because "which window is scrolled and by how much"
/// is exactly the thing a screenshot of this display has to be able to answer.
fn format_footer(line: &mut Line, focus: Option<&str>, back: usize) {
    line.clear();
    let holder = focus.unwrap_or("NONE");
    if back == 0 {
        let _ = write!(
            line,
            "click or alt+tab to focus | PgUp/PgDn and the wheel scroll | FOCUS {} at the live tail",
            holder
        );
    } else {
        let _ = write!(
            line,
            "click or alt+tab to focus | PgUp/PgDn and the wheel scroll | FOCUS {} {} lines back of {}",
            holder,
            back,
            scroll_max(0)
        );
    }
}

fn format_vault(tile: &mut TextBlock) {
    tile.clear();
    match crate::vault_handle() {
        Some(vault) => {
            let mut line = Line::new();
            let _ = write!(line, "FINGERPRINT  {}", vault.key_fingerprint());
            tile.push_str(line.as_str());
            let mut line = Line::new();
            let _ = write!(
                line,
                "SHARDS       {} of {} (threshold {})",
                vault.shards.len(),
                crate::crypto::RS_DATA_SHARDS + crate::crypto::RS_PARITY_SHARDS,
                vault.threshold
            );
            tile.push_str(line.as_str());
            let mut line = Line::new();
            let _ = write!(
                line,
                "HEALTH       {}",
                if vault.is_healthy() { "SEALED" } else { "DEGRADED" }
            );
            tile.push_str(line.as_str());
            let mut line = Line::new();
            let _ = write!(line, "SECTORS      {}", vault.sector_count());
            tile.push_str(line.as_str());
            let mut line = Line::new();
            let _ = write!(line, "WRITES       {}", vault.write_count());
            tile.push_str(line.as_str());
            let mut line = Line::new();
            let _ = write!(
                line,
                "REJECTED     {} forged openings",
                vault.rejected_openings()
            );
            tile.push_str(line.as_str());
            let mut line = Line::new();
            let _ = write!(
                line,
                "KDF          HKDF-SHA256 / RS(2,1) / AEAD per sector"
            );
            tile.push_str(line.as_str());
            tile.push_str("");
            tile.push_str("[PANIC: ZERO VAULT & HALT]");
            tile.push_str("(shell: `panic` or `purge`)");
        }
        None => tile.push_str("vault subsystem offline"),
    }
}

fn format_subsystems(tile: &mut TextBlock) {
    tile.clear();
    let mut line = Line::new();
    let _ = write!(
        line,
        "CRYPTO   {} | entropy={}",
        if crate::crypto::entropy_is_hardware() {
            "KAT 7/7 HARDWARE"
        } else {
            "KAT 7/7 SEEDED"
        },
        crate::crypto::entropy_source()
    );
    tile.push_str(line.as_str());

    let mut line = Line::new();
    let _ = write!(
        line,
        "IPC      delivered={} dropped={} key={}",
        crate::ipc::delivered_count(),
        crate::ipc::dropped_count(),
        if crate::ipc::key_ready() {
            "HMAC-SHA256"
        } else {
            "UNSEEDED"
        }
    );
    tile.push_str(line.as_str());

    let mut line = Line::new();
    let _ = write!(
        line,
        "SESSION  window={} idle={}min hard={}h",
        crate::session::WINDOW_BITS,
        crate::session::IDLE_TIMEOUT_MS / 60_000,
        crate::session::HARD_TIMEOUT_MS / 3_600_000
    );
    tile.push_str(line.as_str());

    match crate::net_handle() {
        Some(mesh) => {
            let mut line = Line::new();
            let _ = write!(
                line,
                "MESH     node={} peers={} prefix-fp={:#010x}",
                mesh.node_id,
                mesh.peer_count(),
                mesh.key_fingerprint()
            );
            tile.push_str(line.as_str());
            let mut line = Line::new();
            let _ = write!(
                line,
                "         out={} in={} msgs={} handshakes={}",
                mesh.frames_sent(),
                mesh.frames_received(),
                mesh.messages_delivered(),
                mesh.handshakes_delivered()
            );
            tile.push_str(line.as_str());
            let mut line = Line::new();
            let _ = write!(
                line,
                "         refused={} replayed={} oow={} byzantine={}",
                mesh.shards_refused(),
                mesh.replays(),
                mesh.out_of_window(),
                mesh.byzantine_shards()
            );
            tile.push_str(line.as_str());
            let mut line = Line::new();
            let _ = write!(
                line,
                "         isolated={} cover out={} in={} wire={}B",
                mesh.isolated_peers(),
                mesh.cover().emitted(),
                mesh.cover_delivered(),
                crate::net::WIRE_FRAME_LEN
            );
            tile.push_str(line.as_str());
        }
        None => tile.push_str("MESH     offline"),
    }

    let mut line = Line::new();
    let _ = write!(
        line,
        "SCHED    {} slots x{}ms | scrub regions={}",
        crate::sched::task_count(),
        crate::sched::QUANTUM_MS,
        crate::panic::scrub_region_count()
    );
    tile.push_str(line.as_str());
}

// ---------------------------------------------------------------------------------------
// Painting
// ---------------------------------------------------------------------------------------

/// Draws one window tile. `clip` is the repaint rectangle the caller needs pixels for; the
/// draw calls fill *whole* rectangles and let the canvas clip them, which is what keeps a
/// partial repaint (a moved cursor, one changed tile) correct without a shadow buffer.
fn draw_tile(canvas: &mut Canvas, window: &WindowDesc, tile: &TextBlock, clip: Rect) {
    let rect = window.rect;
    let visible = rect.intersect(&clip);
    if visible.is_empty() {
        return;
    }
    canvas.set_clip(visible);
    canvas.fill_rect(rect, PANEL);
    let chrome = Rect::new(rect.x, rect.y, rect.width, CHROME_HEIGHT);
    canvas.fill_rect(chrome, CHROME);
    canvas.draw_rect_border(rect, BORDER);

    let title_color = if window.focus { SECURE } else { TEXT };
    canvas.draw_string(
        rect.x + PADDING,
        rect.y + 2,
        window.title,
        title_color,
        Some(CHROME),
    );
    let mut right = Line::new();
    let _ = write!(right, "pid {} cap {:#06x}", window.owner_pid, window.capability as u16);
    let columns = (rect.width / canvas::CHAR_WIDTH).saturating_sub(24);
    canvas.draw_string_clipped(
        rect.right() - PADDING - columns * canvas::CHAR_WIDTH,
        rect.y + 2,
        right.as_str(),
        TEXT_DIM,
        Some(CHROME),
        columns,
    );

    let interior = Rect::new(
        rect.x + PADDING,
        rect.y + CHROME_HEIGHT + 2,
        rect.width.saturating_sub(PADDING * 2),
        rect.height.saturating_sub(CHROME_HEIGHT + PADDING + 2),
    );
    canvas.set_clip(interior.intersect(&visible));
    let rows = interior.height / canvas::CHAR_HEIGHT;
    let columns = interior.width / canvas::CHAR_WIDTH;
    for index in 0..tile.len() {
        if index as u32 >= rows {
            break;
        }
        let y = interior.y + (index as u32) * canvas::CHAR_HEIGHT;
        let text = tile.line(index).as_str();
        let color = if text.starts_with("[PANIC") {
            DANGER
        } else if text.starts_with("(shell") {
            TEXT_DIM
        } else {
            TEXT
        };
        canvas.draw_string_clipped(
            interior.x,
            y,
            text,
            color,
            Some(PANEL),
            columns,
        );
    }
    canvas.set_clip(clip);
}

fn draw_top(canvas: &mut Canvas, top: &Line, clip: Rect) {
    let rect = Rect::new(0, 0, canvas.width(), TOP_BAR_HEIGHT);
    let visible = rect.intersect(&clip);
    if visible.is_empty() {
        return;
    }
    canvas.set_clip(visible);
    canvas.fill_rect(rect, PANEL);
    canvas.draw_string(8, 7, top.as_str(), TEXT, Some(PANEL));
    canvas.fill_rect(Rect::new(0, TOP_BAR_HEIGHT - 2, canvas.width(), 2), BORDER);
    canvas.set_clip(clip);
}

fn draw_footer(canvas: &mut Canvas, footer: &Line, clip: Rect) {
    let rect = Rect::new(
        0,
        canvas.height().saturating_sub(FOOTER_HEIGHT),
        canvas.width(),
        FOOTER_HEIGHT,
    );
    let visible = rect.intersect(&clip);
    if visible.is_empty() {
        return;
    }
    canvas.set_clip(visible);
    canvas.fill_rect(rect, PANEL);
    canvas.fill_rect(Rect::new(0, rect.y, canvas.width(), 2), BORDER);
    canvas.draw_string(8, rect.y + 3, footer.as_str(), TEXT_DIM, Some(PANEL));
    canvas.set_clip(clip);
}

/// Software pointer: a classic 9x14 arrow, white with a one-pixel `BG` outline so it stays
/// legible over both the panel and the border colours. Bit 8 of each row is the leftmost
/// pixel.
const CURSOR_WIDTH: u32 = 9;
const CURSOR_HEIGHT: u32 = 14;
const CURSOR_SHAPE: [u16; CURSOR_HEIGHT as usize] = [
    0x100, 0x180, 0x140, 0x120, 0x110, 0x108, 0x104, 0x102, 0x1FF, 0x120, 0x150, 0x188, 0x10C,
    0x006,
];

fn cursor_lit(row: u32, column: u32) -> bool {
    row < CURSOR_HEIGHT
        && column < CURSOR_WIDTH
        && CURSOR_SHAPE[row as usize] & (0x100 >> column) != 0
}

/// True for the outline pixels: empty pixels that touch a lit one.
fn cursor_outline(row: u32, column: u32) -> bool {
    if cursor_lit(row, column) {
        return false;
    }
    let mut any = false;
    for (dr, dc) in [(-1i32, 0i32), (1, 0), (0, -1), (0, 1)] {
        let r = row as i32 + dr;
        let c = column as i32 + dc;
        if r >= 0 && c >= 0 && cursor_lit(r as u32, c as u32) {
            any = true;
        }
    }
    any
}

fn cursor_rect(position: (u32, u32)) -> Rect {
    Rect::new(position.0, position.1, CURSOR_WIDTH, CURSOR_HEIGHT)
}

fn draw_cursor(canvas: &mut Canvas, position: (u32, u32), clip: Rect) {
    let rect = cursor_rect(position);
    let visible = rect.intersect(&clip);
    if visible.is_empty() {
        return;
    }
    canvas.set_clip(visible);
    // Every pixel of the arrow's rectangle is written: lit pixels in `TEXT`, the outline in
    // `BG`, and nothing at all where the underlying window shows through (those pixels are
    // already correct in the backbuffer from `draw_scene`).
    for row in 0..CURSOR_HEIGHT {
        for column in 0..CURSOR_WIDTH {
            if cursor_lit(row, column) {
                canvas.put_pixel(position.0 + column, position.1 + row, TEXT);
            } else if cursor_outline(row, column) {
                canvas.put_pixel(position.0 + column, position.1 + row, BG);
            }
        }
    }
    canvas.set_clip(clip);
}

/// Up to eight repaint rectangles: the content changes plus the cursor's old and new
/// footprints, merged whenever they touch so one pass never pays for the same pixels twice.
const MAX_REPAINT_RECTS: usize = 8;

struct RepaintPlan {
    rects: [Rect; MAX_REPAINT_RECTS],
    count: usize,
    /// A ninth rectangle means the regions were too scattered to track: repaint the screen.
    everything: bool,
}

impl RepaintPlan {
    fn new() -> Self {
        Self {
            rects: [Rect::new(0, 0, 0, 0); MAX_REPAINT_RECTS],
            count: 0,
            everything: false,
        }
    }

    fn is_empty(&self) -> bool {
        self.count == 0 && !self.everything
    }

    /// Adds a rectangle, merging it into any rectangle it overlaps.
    fn add(&mut self, rect: Rect, screen: Rect) {
        if self.everything || rect.is_empty() {
            return;
        }
        let mut merged = rect.intersect(&screen);
        if merged.is_empty() {
            merged = rect;
        }
        let mut index = 0;
        while index < self.count {
            if self.rects[index].intersects(&merged) {
                merged = self.rects[index].union(&merged);
                self.count -= 1;
                self.rects[index] = self.rects[self.count];
                index = 0;
            } else {
                index += 1;
            }
        }
        if self.count == MAX_REPAINT_RECTS {
            self.everything = true;
            self.count = 1;
            self.rects[0] = screen;
            return;
        }
        self.rects[self.count] = merged;
        self.count += 1;
    }

    fn rects(&self) -> &[Rect] {
        &self.rects[..self.count]
    }
}

/// Copies one region of the backbuffer into the framebuffer with a single span per row.
fn blit_region(framebuffer: &mut fb::Framebuffer, canvas: &Canvas, rect: Rect) {
    let width = core::cmp::min(rect.width, canvas.width().saturating_sub(rect.x));
    let rows = core::cmp::min(rect.height, canvas.height().saturating_sub(rect.y));
    let stride = canvas.width();
    for row in 0..rows {
        let start = (rect.y + row) as usize * stride as usize + rect.x as usize;
        let end = start + width as usize;
        framebuffer.write_span(rect.x, rect.y + row, &canvas.pixels()[start..end], width as usize);
    }
}

/// Paints the whole scene through `clip`: background, then every panel, then the cursor.
///
/// One function serves both a full repaint and a two-hundred-pixel cursor repair, because
/// every painter intersects its own rectangle with `clip` first. That is what makes a
/// partial repaint correct: the pixels inside `clip` are always produced from the model
/// (window rectangles, tile text, cursor position), never from a stale buffer.
fn draw_scene(server: &mut DisplayServer, clip: Rect) {
    // Borrowed field by field (not copied): a `[TextBlock; 3]` by value would cost ~9 KiB of
    // stack in a debug build.
    let tiles = [&server.console, &server.vault, &server.subsystems];
    let top = &server.top;
    let footer = &server.footer;
    let cursor = server.cursor;
    let canvas = &mut server.canvas;

    canvas.set_clip(clip);
    canvas.fill_rect(clip, BG);
    draw_top(canvas, top, clip);
    draw_footer(canvas, footer, clip);
    for index in 0..tiles.len() {
        if let Some(window) = server.windows.get(index).copied() {
            draw_tile(canvas, &window, tiles[index], clip);
        }
    }
    draw_cursor(canvas, cursor, clip);
    canvas.reset_clip();
}

/// Repaints the backbuffer for whichever rectangles need pixels, then blits exactly those.
fn paint(now_ms: u64) -> bool {
    note_stack();
    let framebuffer = match fb::handle() {
        Some(framebuffer) => framebuffer,
        None => return false,
    };
    let server = match server() {
        Some(server) => server,
        None => return false,
    };
    if !server.enabled {
        return false;
    }

    let focus = server.windows.focused().map(|window| window.title);
    let cursor = server.cursor;
    format_top(&mut server.top, focus, cursor);
    // The console tile is a window onto the log ring, so what it shows is decided here rather
    // than by the ring itself: the scroll offset is clamped to what the history can actually
    // offer, and the *rendered text* then differs, which is what makes the tile repaint itself.
    let back = server.scroll[0].min(scroll_max(0));
    server.scroll[0] = back;
    let focused = server.windows.focused_index();
    let focused_back = server.scroll[focused].min(scroll_max(focused));
    format_footer(&mut server.footer, focus, focused_back);
    unsafe {
        let console = core::ptr::addr_of!(CONSOLE);
        (*console).fill_window(&mut server.console, back);
    }
    format_vault(&mut server.vault);
    format_subsystems(&mut server.subsystems);

    let width = server.canvas.width();
    let height = server.canvas.height();
    let screen = Rect::new(0, 0, width, height);
    let regions = [
        Rect::new(0, 0, width, TOP_BAR_HEIGHT),
        Rect::new(0, height - FOOTER_HEIGHT, width, FOOTER_HEIGHT),
        window_rect(server, 0),
        window_rect(server, 1),
        window_rect(server, 2),
    ];

    // Rectangle 0 is the top bar, 1 the footer, 2..5 the three tiles. A rectangle is added
    // only when the text it shows actually changed - that is what keeps a 10 Hz refresh
    // cheap - and a full repaint adds all of them.
    let mut plan = RepaintPlan::new();
    if server.full_repaint {
        plan.add(screen, screen);
    } else {
        if !server.top.same_as(&server.top_rendered) {
            plan.add(regions[0], screen);
        }
        if !server.footer.same_as(&server.footer_rendered) {
            plan.add(regions[1], screen);
        }
        if server.console.changed_from(&server.console_rendered) {
            plan.add(regions[2], screen);
        }
        if server.vault.changed_from(&server.vault_rendered) {
            plan.add(regions[3], screen);
        }
        if server.subsystems.changed_from(&server.subsystems_rendered) {
            plan.add(regions[4], screen);
        }
    }

    // The cursor is composited into the backbuffer, so moving it means repairing the pixels
    // it left behind as well as painting the new ones. Both are ordinary rectangles.
    if server.cursor_moved {
        if let Some(previous) = server.cursor_drawn {
            plan.add(cursor_rect(previous), screen);
        }
        plan.add(cursor_rect(server.cursor), screen);
    }

    // Focus moving changes the title colour of two windows without changing any text, so
    // those rectangles have to be added explicitly.
    if server.focus_repaint {
        for index in 0..3 {
            plan.add(window_rect(server, index), screen);
        }
    }

    if plan.is_empty() {
        server.last_refresh_ms = now_ms;
        return false;
    }

    let full_repaint = server.full_repaint;
    let mut blits = 0u64;
    for rect in plan.rects() {
        let rect = *rect;
        draw_scene(server, rect);
        blit_region(framebuffer, &server.canvas, rect);
        blits += 1;
    }

    let dirty_count = plan.rects().len() as u64;
    server.top_rendered = server.top;
    server.footer_rendered = server.footer;
    server.console.copy_into(&mut server.console_rendered);
    server.vault.copy_into(&mut server.vault_rendered);
    server.subsystems.copy_into(&mut server.subsystems_rendered);
    server.full_repaint = false;
    server.cursor_drawn = Some(server.cursor);
    server.cursor_moved = false;
    server.focus_repaint = false;
    server.frames += 1;
    server.blits += blits;
    server.dirty_rects += dirty_count;
    if full_repaint {
        server.full_screens += 1;
    }
    server.last_refresh_ms = now_ms;
    true
}

fn window_rect(server: &DisplayServer, index: usize) -> Rect {
    server
        .windows
        .get(index)
        .map(|window| window.rect)
        .unwrap_or(Rect::new(0, 0, 0, 0))
}

/// Requests a full repaint on the next tick.
pub fn request_full_repaint() {
    if let Some(server) = server() {
        server.full_repaint = true;
    }
}

// ---------------------------------------------------------------------------------------
// Input routing
// ---------------------------------------------------------------------------------------
//
// `GUI_SPECIFICATION.md` §2: keystrokes and pointer events go to the window that holds the
// focus capability and to no other window, so a client without it learns nothing about what
// was typed. These functions are the whole of that policy; `arch::ps2` decodes bytes and
// never looks at a window.

/// Body used while the caller already holds the display server (avoids aliasing the static).
fn focus_cycle_on(server: &mut DisplayServer) -> Option<&'static str> {
    let before = server.windows.focused().map(|window| window.title);
    server.windows.focus_next();
    note_focus_change(server, before);
    server.windows.focused().map(|window| window.title)
}

fn focus_named_on(server: &mut DisplayServer, title: &str) -> bool {
    let before = server.windows.focused().map(|window| window.title);
    if !server.windows.focus_by_title(title) {
        return false;
    }
    note_focus_change(server, before);
    true
}

/// Records a focus move: the count rises only when the holder really changed, and the chrome
/// is queued for repainting because the title colour changes while its text does not.
fn note_focus_change(server: &mut DisplayServer, before: Option<&'static str>) {
    let after = server.windows.focused().map(|window| window.title);
    if before != after {
        server.focus_changes += 1;
        server.focus_repaint = true;
    }
}

/// Moves focus to the next window slot (`Alt + Tab`) and returns its title.
pub fn focus_cycle() -> Option<&'static str> {
    let server = server()?;
    focus_cycle_on(server)
}

/// Grants focus to a window by title (the probe uses this to aim a key at a specific window).
pub fn focus_window_named(title: &str) -> bool {
    match server() {
        Some(server) => focus_named_on(server, title),
        None => false,
    }
}

/// Title of the window that currently holds focus.
pub fn focused_title() -> Option<&'static str> {
    server().and_then(|server| server.windows.focused().map(|window| window.title))
}

/// Capability token of the window that currently holds focus.
pub fn focused_capability() -> Option<u64> {
    server().and_then(|server| server.windows.focused().map(|window| window.capability))
}

/// Scrolls one window's view by `delta` lines (positive is back into the history) and reports
/// whether the view moved. The clamp is against what the window's source can actually offer,
/// so a wheel notch at the end of the history moves nothing rather than inventing lines.
fn scroll_window_on(server: &mut DisplayServer, index: usize, delta: i64) -> bool {
    if index >= server.scroll.len() {
        return false;
    }
    let max = scroll_max(index);
    let before = server.scroll[index].min(max);
    let after = if delta >= 0 {
        before.saturating_add(delta as usize).min(max)
    } else {
        before.saturating_sub((-delta) as usize)
    };
    server.scroll[index] = after;
    if after != before {
        server.scroll_steps += 1;
    }
    after != before
}

/// Scrolls the focused window: what a PageUp or a wheel notch over it does.
pub fn scroll_focused(delta: i64) -> bool {
    let server = match server() {
        Some(server) => server,
        None => return false,
    };
    let index = server.windows.focused_index();
    scroll_window_on(server, index, delta)
}

/// Jumps the focused window's view to one end of its history.
pub fn scroll_focused_to(back: Option<usize>) -> bool {
    let server = match server() {
        Some(server) => server,
        None => return false,
    };
    let index = server.windows.focused_index();
    let target = match back {
        Some(lines) => lines.min(scroll_max(index)),
        None => scroll_max(index),
    };
    scroll_window_on(server, index, target as i64 - server.scroll[index] as i64)
}

/// (title, lines back, lines available) of the window that holds focus.
pub fn scroll_state() -> Option<(&'static str, usize, usize)> {
    let server = server()?;
    let index = server.windows.focused_index();
    let title = server.windows.focused().map(|window| window.title)?;
    let max = scroll_max(index);
    Some((title, server.scroll[index].min(max), max))
}

/// Lines the console ring is holding (the depth of the shell's backscroll).
pub fn console_history() -> usize {
    unsafe { (*core::ptr::addr_of!(CONSOLE)).held() }
}

/// (scroll gestures that moved a view, wheel notches, keys delivered to a non-shell window,
/// console lines held).
pub fn scroll_counters() -> (u64, i64, u64, usize) {
    match server() {
        Some(server) => (
            server.scroll_steps,
            server.wheel_notches,
            server.keys_to_tiles,
            console_history(),
        ),
        None => (0, 0, 0, console_history()),
    }
}

/// Routes one decoded key event. Returns true when it was delivered to a window.
pub fn route_key(event: ps2::KeyEvent) -> bool {
    let server = match server() {
        Some(server) => server,
        None => return false,
    };
    if !event.pressed {
        // Releases carry modifier state only; nothing is delivered for them.
        return true;
    }
    // The window-manager chord is consumed by the compositor itself, never forwarded.
    if event.modifiers & ps2::MOD_ALT != 0 && event.code == ps2::Code::Tab {
        focus_cycle_on(server);
        return true;
    }

    let owner = match server.windows.focused() {
        Some(window) => window.owner_pid,
        None => {
            server.keys_refused += 1;
            return false;
        }
    };
    let index = server.windows.focused_index();

    // Navigation is delivered to whichever window holds focus, because the window that is
    // scrolled should be the window the user looked at and clicked - not always the console.
    match event.code {
        ps2::Code::PageUp => {
            scroll_window_on(server, index, TILE_LINES as i64);
            server.keys_routed += 1;
            if index != 0 {
                server.keys_to_tiles += 1;
            }
            return true;
        }
        ps2::Code::PageDown => {
            scroll_window_on(server, index, -(TILE_LINES as i64));
            server.keys_routed += 1;
            if index != 0 {
                server.keys_to_tiles += 1;
            }
            return true;
        }
        // Home is the oldest line this window can show, End is the live tail - the terminal
        // bindings, and the reason `End` means "stop scrolling" rather than "delete".
        ps2::Code::Home => {
            let max = scroll_max(index);
            scroll_window_on(server, index, max as i64);
            server.keys_routed += 1;
            if index != 0 {
                server.keys_to_tiles += 1;
            }
            return true;
        }
        ps2::Code::End => {
            let back = server.scroll[index];
            scroll_window_on(server, index, -(back as i64));
            server.keys_routed += 1;
            if index != 0 {
                server.keys_to_tiles += 1;
            }
            return true;
        }
        _ => {}
    }

    match owner {
        // pid 1 owns the console tile, and the shell owns the line buffer the tile shows.
        // Both COM1 and the keyboard feed that one buffer, so a keystroke here is
        // indistinguishable from one typed at the serial console - including the echo.
        1 => {
            match event.code {
                ps2::Code::Character => {
                    if let Some(character) = event.character {
                        server.characters_delivered += 1;
                        crate::shell::feed(character);
                    }
                }
                ps2::Code::Enter => crate::shell::feed(b'\r'),
                ps2::Code::Backspace => crate::shell::feed(0x08),
                ps2::Code::Tab => crate::shell::feed(0x09),
                // No further binding: the key was delivered to the focus holder, which is the
                // promise; that the holder has nothing to do with it is its business.
                _ => {}
            }
            // Typing in a scrolled console means you want to see the prompt again: every key
            // that reaches the shell returns its view to the live tail, which is what a
            // terminal does and what stops an abandoned scroll from hiding the answer to the
            // command that was just typed.
            scroll_window_on(server, 0, -(server.scroll[0] as i64));
            server.keys_routed += 1;
            true
        }
        // Every other window: the key is delivered to the focus holder rather than to the
        // shell, and `Enter` additionally asks for a repaint - which is a real, observable
        // effect, because every tile is re-read from its model on each pass.
        _ => {
            server.keys_to_tiles += 1;
            server.keys_routed += 1;
            if event.code == ps2::Code::Enter {
                request_full_repaint();
            }
            true
        }
    }
}

/// Routes one validated mouse packet: motion moves the cursor, a fresh left click grants
/// focus to the window under it. Returns true when the cursor or the focus changed.
pub fn route_mouse(packet: &ps2::MousePacket) -> bool {
    let server = match server() {
        Some(server) => server,
        None => return false,
    };
    server.mouse_packets += 1;
    if packet.rejected {
        return false;
    }

    let max_x = server.canvas.width().saturating_sub(CURSOR_WIDTH);
    let max_y = server.canvas.height().saturating_sub(CURSOR_HEIGHT);
    // The wire convention is +y = up, the screen's is +y = down.
    let x = (server.cursor.0 as i32 + packet.dx as i32).clamp(0, max_x as i32) as u32;
    let y = (server.cursor.1 as i32 - packet.dy as i32).clamp(0, max_y as i32) as u32;
    let moved = (x, y) != server.cursor;
    if moved {
        server.cursor = (x, y);
        server.cursor_moved = true;
    }
    server.motion.0 += packet.dx as i64;
    server.motion.1 += packet.dy as i64;

    // The wheel scrolls the window *under the pointer*, which is the window the user is
    // looking at - not the focus holder, which a click is what changes. Three lines per notch
    // is the terminal convention, and the wheel's own convention is that positive is up, so a
    // notch up means back into the history.
    if packet.wheel != 0 {
        server.wheel_notches += packet.wheel as i64;
        let target = (0..server.scroll.len())
            .find(|index| window_rect(server, *index).contains(x, y));
        if let Some(index) = target {
            scroll_window_on(server, index, packet.wheel as i64 * 3);
        }
    }

    let left_now = packet.buttons & ps2::BUTTON_LEFT != 0;
    let left_before = server.buttons & ps2::BUTTON_LEFT != 0;
    server.buttons = packet.buttons;
    let mut focus_moved = false;
    if left_now && !left_before {
        // A button press is a transition, not a repeat: one click grants focus once.
        server.clicks += 1;
        let before = server.windows.focused().map(|window| window.title);
        server.windows.focus_at(x, y);
        note_focus_change(server, before);
        focus_moved = server.windows.focused().map(|window| window.title) != before;
    }
    moved || focus_moved
}

/// (keys routed, keys refused, focus changes).
pub fn input_counters() -> (u64, u64, u64) {
    match server() {
        Some(server) => (server.keys_routed, server.keys_refused, server.focus_changes),
        None => (0, 0, 0),
    }
}

/// True when the point lands inside the window with this index (the wheel's target).
pub fn window_contains(index: usize, x: u32, y: u32) -> bool {
    match server() {
        Some(server) => window_rect(server, index).contains(x, y),
        None => false,
    }
}

/// (characters delivered, mouse packets, clicks, motion x, motion y).
pub fn mouse_counters() -> (u64, u64, u64, i64, i64) {
    match server() {
        Some(server) => (
            server.characters_delivered,
            server.mouse_packets,
            server.clicks,
            server.motion.0,
            server.motion.1,
        ),
        None => (0, 0, 0, 0, 0),
    }
}

/// Software cursor position, clamped to the backbuffer.
pub fn cursor_position() -> Option<(u32, u32)> {
    server().map(|server| server.cursor)
}

/// Prints the input state (shell `input status`).
pub fn input_inventory() {
    let server = match server() {
        Some(server) => server,
        None => {
            crate::println!("[GUI] input: display server offline");
            return;
        }
    };
    let (cursor_x, cursor_y) = server.cursor;
    crate::println!(
        "[GUI] input: keys routed={} refused={} characters={} focus-changes={}",
        server.keys_routed,
        server.keys_refused,
        server.characters_delivered,
        server.focus_changes
    );
    crate::println!(
        "[GUI] pointer: cursor={},{} packets={} clicks={} motion={},{} buttons={:#04x}",
        cursor_x,
        cursor_y,
        server.mouse_packets,
        server.clicks,
        server.motion.0,
        server.motion.1,
        server.buttons
    );
    let index = server.windows.focused_index();
    crate::println!(
        "[GUI] scroll: wheel-notches={} gestures={} keys-to-tiles={} | {} {} of {} lines back ({} held)",
        server.wheel_notches,
        server.scroll_steps,
        server.keys_to_tiles,
        server.windows.focused().map(|window| window.title).unwrap_or("NONE"),
        server.scroll[index].min(scroll_max(index)),
        scroll_max(index),
        console_history()
    );
    match server.windows.focused() {
        Some(window) => crate::println!(
            "[GUI] focus holder: {} (pid {}, capability {:#018x})",
            window.title, window.owner_pid, window.capability
        ),
        None => crate::println!("[GUI] focus holder: none (input is refused)"),
    }
}

/// Fixed-slot refresh: renders at most once per [`REFRESH_MS`]. Returns true when a frame
/// was produced (and therefore pixels reached the framebuffer).
pub fn render_tick(now_ms: u64) -> bool {
    note_stack();
    let server = match server() {
        Some(server) => server,
        None => return false,
    };
    if !server.enabled {
        return false;
    }
    if now_ms.saturating_sub(server.last_refresh_ms) < REFRESH_MS {
        return false;
    }
    paint(now_ms)
}

/// Paints immediately, regardless of the refresh slot (used by `gui` and by the probe).
pub fn render_now() -> bool {
    paint(clock::uptime_ms())
}

/// Zeroes the framebuffer through the same path the panic hook uses.
pub fn scrub_screen() -> u64 {
    match fb::handle() {
        Some(framebuffer) => unsafe { framebuffer.scrub() },
        None => 0,
    }
}

pub fn describe() {
    match server() {
        Some(server) => {
            crate::println!(
                "[GUI] display server: {}x{} backbuffer ({} KiB), {} windows, {} ms fixed refresh",
                server.canvas.width(),
                server.canvas.height(),
                server.bytes / 1024,
                server.windows.count(),
                REFRESH_MS
            );
            crate::println!(
                "[GUI] frames={} full={} dirty-rects={} blits={} fills={} glyphs={} enabled={}",
                server.frames,
                server.full_screens,
                server.dirty_rects,
                server.blits,
                server.canvas.fill_count(),
                server.canvas.glyph_count(),
                server.enabled
            );
            crate::println!(
                "[GUI] strategy: in-RAM backbuffer -> dirty rectangles -> fb.write_span (no partial frames)"
            );
            crate::println!(
                "[GUI] input: keys routed={} refused={} chars={} focus-changes={} cursor={},{} clicks={}",
                server.keys_routed,
                server.keys_refused,
                server.characters_delivered,
                server.focus_changes,
                server.cursor.0,
                server.cursor.1,
                server.clicks
            );
            let index = server.windows.focused_index();
            crate::println!(
                "[GUI] scrollback: {} lines held, {} shown per tile, focused view {} of {} lines back ({} gestures, {} wheel notches, {} keys to non-shell windows)",
                console_history(),
                TILE_LINES,
                server.scroll[index].min(scroll_max(index)),
                scroll_max(index),
                server.scroll_steps,
                server.wheel_notches,
                server.keys_to_tiles
            );
            if let Some(focused) = server.windows.focused() {
                crate::println!(
                    "[GUI] focused: {} (pid {}), rect {}x{}+{}+{}",
                    focused.title,
                    focused.owner_pid,
                    focused.rect.width,
                    focused.rect.height,
                    focused.rect.x,
                    focused.rect.y
                );
            }
            server.windows.describe();
        }
        None => crate::println!("[GUI] display server offline"),
    }
}

/// Probe: backbuffer pattern round-trip, a forced full repaint, a read-back of the same pixels
/// from the framebuffer itself, and the scrollback. Proves the compositor and the aperture
/// agree, and that what the compositor shows is a *view* onto the history rather than the
/// history itself.
pub fn self_test() -> bool {
    let server = match server() {
        Some(server) => server,
        None => return false,
    };
    let width = server.canvas.width();
    let height = server.canvas.height();
    if width < 32 || height < 32 {
        return false;
    }

    // 1. Rasteriser round-trip inside the backbuffer.
    let probes = [(1u32, 1u32, 0x00FF_00FF), (width - 2, 3, 0x0000_FFFF)];
    let mut saved = [(0u32, 0u32, 0u32); 2];
    let mut ok = true;
    for (index, (x, y, color)) in probes.iter().enumerate() {
        saved[index] = (*x, *y, server.canvas.get_pixel(*x, *y).unwrap_or(0));
        server.canvas.put_pixel(*x, *y, *color);
        if server.canvas.get_pixel(*x, *y) != Some(*color) {
            ok = false;
        }
        server.canvas.put_pixel(*x, *y, saved[index].2);
    }
    if !ok {
        return false;
    }

    // 2. Text rendering must produce ink: draw a glyph and count lit pixels.
    let before = server.canvas.glyph_count();
    server.canvas.draw_char(16, height - 24, b'K', DANGER, Some(PANEL));
    let lit = (0..16)
        .flat_map(|row| (0..8).map(move |column| (row, column)))
        .filter(|(row, column)| {
            server
                .canvas
                .get_pixel(16 + *column, height - 24 + *row)
                .map(|pixel| pixel == DANGER)
                .unwrap_or(false)
        })
        .count();
    let glyph_ok = server.canvas.glyph_count() == before + 1 && lit > 8;

    // 3. Full repaint, then read the same pixels back out of the framebuffer.
    request_full_repaint();
    let painted = render_now();
    let framebuffer_ok = match fb::handle() {
        Some(framebuffer) => {
            framebuffer.read_pixel(2, 2) == server.canvas.get_pixel(2, 2)
                && framebuffer.read_pixel(width - 2, height - 2) == server.canvas.get_pixel(width - 2, height - 2)
        }
        None => false,
    };
    if !(glyph_ok && painted && framebuffer_ok) {
        return false;
    }

    // 4. Scrollback: the history is deeper than the tile, the tile follows the offset, and the
    //    window returns to the live tail. Run against the console window, which is the one with
    //    a log behind it - and restore whatever the user was looking at afterwards.
    let max = scroll_max(0);
    if max == 0 {
        // Not enough log yet to have a history: the deeper ring is only as deep as what the
        // boot has printed. Nothing to prove, and nothing to fail.
        return true;
    }
    let (steps_before, _, _, _) = scroll_counters();
    let live_first = Line::from_str(server.console.line(0).as_str());
    let moved_back = scroll_window_on(server, 0, max as i64);
    {
        let console = core::ptr::addr_of!(CONSOLE);
        unsafe { (*console).fill_window(&mut server.console, max) };
    }
    let oldest_first = Line::from_str(server.console.line(0).as_str());
    let different = !oldest_first.same_as(&live_first);
    let back_to_live = scroll_window_on(server, 0, -(max as i64));
    {
        let console = core::ptr::addr_of!(CONSOLE);
        unsafe { (*console).fill_window(&mut server.console, 0) };
    }
    let live_again = Line::from_str(server.console.line(0).as_str()).same_as(&live_first);
    let (steps_after, _, _, _) = scroll_counters();
    request_full_repaint();
    render_now();
    moved_back && different && back_to_live && live_again && steps_after >= steps_before + 2
}
