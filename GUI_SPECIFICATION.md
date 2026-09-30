# KELLER-OS: Graphical User Interface (GUI) Specification
*A High-Assurance, Minimalist, Capability-Secured Display Server & Windowing Environment*

---

## 1. Executive Summary & Philosophy

The objective of this specification is to define the architecture, hardware interface, visual design, and implementation path for introducing a native Graphical User Interface (GUI) to **KELLER-OS**.

Unlike conventional desktop operating systems (e.g., Windows DWM, macOS Quartz, Linux X11/Wayland), where graphics stacks consist of millions of lines of complex C/C++ running with excessive privileges, the **KELLER-OS GUI** is designed from the ground up according to the **`KELLER OS.canvas`** security blueprint:

1. **Zero Animations / Zero GPU Bloat:** Deterministic, instantaneous redraws. No compositing shaders, no blur effects, no transitions. Eliminates GPU side-channel timing attacks (Spectre/Meltdown variants) and keeps CPU resource usage predictable.
2. **Microkernel Driver Sandbox:** The graphics adapter driver and display compositor execute strictly in **Userspace (Ring 3)**. A crash in the display subsystem never halts or compromises the microkernel.
3. **Capability-Gated Windowing:** Processes have zero ambient visibility into the screen. Window buffers are strictly private. Keystrokes and mouse events are routed exclusively to the holder of an unforgeable `InputFocusCapability`, mathematically preventing screen-scraping malware and keyloggers.
4. **Panic-Zeroing Display Scrubbing:** When a tamper event or kernel panic occurs, the framebuffers (both front VRAM and backbuffers) are wiped within milliseconds alongside `Keller Vault` secrets to prevent cold-boot display/VRAM forensics.
5. **Brutalist, Slim, High-Information Visuals:** Utilitarian, monocromatic-accented, keyboard-navigable desktop with an embedded system monitor, an integrated `Keller Shell` terminal, and direct interaction with the `Vault`, `Net`, and `Auth` subsystems.

---

## 2. Canvas Architecture Traceability Matrix

Every component of the GUI maps directly to the core tenets in `KELLER OS.canvas`:

| Canvas Tenet / Subsystem | GUI Design Requirement | Security Rationale |
| :--- | :--- | :--- |
| **`Hardened Drivers in Userspace`** | Linear Framebuffer mapped to a Ring 3 Display Server via IPC. | Graphics bugs cannot cause privilege escalation or kernel panics. |
| **`Capability-based Security`** | Applications cannot allocate windows or capture events without `WindowCap` and `InputCap`. | Prevents unauthorized window spoofing, clickjacking, and keylogging. |
| **`Temporal Isolation`** | Fixed-slot, deterministic blit scheduling (e.g. 30 Hz sync tick). | Prevents timing side channels where rendering lags disclose secret computations. |
| **`Self-Destruct (Panic-Zeroing)`** | Framebuffer scrub hook in `PanicInfo` handler. | Neutralizes cold-boot and persistent phosphor/VRAM residue attacks. |
| **`Keller Auth`** | Sovereign Lockscreen with Schnorr ZK authentication & Decoy Mode. | Login occurs without disk passwords; decoy password launches sterile sandbox. |
| **`Keller Vault`** | Graphical Vault Status Widget & Panic Kill Switch. | Real-time visual confirmation of memory page encryption and instant purge button. |
| **`Keller Net`** | Telemetry HUD showing deterministic packet queues & MAC verifications. | Immediate visual insight into air-gapped/routed interfaces. |
| **`Keller Shell`** | Native tileable Terminal Window inside the GUI. | Seamless transition between graphical workflows and sovereign microkernel CLI. |

---

## 3. Hardware Video Subsystem & Boot Interface

### 3.1 Linear Framebuffer Acquisition (Multiboot2)
In x86_64 Long Mode, legacy BIOS INT 10h interrupts are inaccessible. The standard and robust method to establish high-resolution graphics is having the bootloader (GRUB Multiboot2) query VBE/GOP before switching to 64-bit mode.

#### Multiboot2 Header Modification (`src/boot.rs`)
Add a Multiboot2 Framebuffer Request Tag (`type = 5`). The shipped build emits the tag from the `global_asm!` header in [`src/boot.rs`](src/boot.rs) (there is no `boot.s` any more: one rustc invocation assembles the whole image) and marks it **optional**, so a loader without VBE support still boots the kernel into serial-only mode:

```nasm
section .multiboot_header
header_start:
    dd 0xE85250D6                ; Multiboot2 magic
    dd 0                         ; Architecture 0 (x86/protected mode)
    dd header_end - header_start ; Header length
    dd -(0xE85250D6 + 0 + (header_end - header_start)) ; Checksum

    ; --- TAG: Request Linear Framebuffer ---
    align 8
framebuffer_tag_start:
    dw 5                         ; Type = FRAMEBUFFER
    dw 0                         ; Flags = not optional
    dd framebuffer_tag_end - framebuffer_tag_start ; Size = 20 bytes
    dd 1024                      ; Preferred Width (e.g., 1024px)
    dd 768                       ; Preferred Height (e.g., 768px)
    dd 32                        ; Preferred Depth (32-bit BGR/RGBA)
framebuffer_tag_end:

    ; --- TAG: End of Tags ---
    align 8
    dw 0
    dw 0
    dd 8
header_end:
```

### 3.2 Bootloader Hand-off Parsing (`src/bootinfo.rs`)
The Multiboot 2 information pointer arrives in `EBX` / `RBX` and the kernel scans tags for Tag 8 (`MULTIBOOT_TAG_TYPE_FRAMEBUFFER`) while it parses the handoff. The handoff is consumed once and published as `BootInfo::framebuffer`, so `fb::adopt_handoff` can take ownership of a loader-provided aperture before any hardware probe runs:

```rust
#[repr(C, packed)]
pub struct MultibootFramebufferTag {
    pub tag_type: u32,       // 8
    pub size: u32,
    pub framebuffer_addr: u64,
    pub framebuffer_pitch: u32,
    pub framebuffer_width: u32,
    pub framebuffer_height: u32,
    pub framebuffer_bpp: u8,
    pub framebuffer_type: u8,
    pub reserved: u16,
}
```

### 3.3 Hardware Fallback: Bochs / QEMU BGA (Bochs Graphics Adapter)
For environments where the bootloader did not set the framebuffer (or for dynamic resolution switching in QEMU/Bochs), KELLER-OS drives the adapter itself in [`src/fb.rs`](src/fb.rs). QEMU's `-kernel` PVH path never hands over a framebuffer, so this is the path every emulator run takes:

* **Registers:**
  * `VBE_DISPI_INDEX_ID` (0x00) -> read back as `0xB0C0`..`0xB0C5`
  * `VBE_DISPI_INDEX_XRES` (0x01) -> `1024`
  * `VBE_DISPI_INDEX_YRES` (0x02) -> `768`
  * `VBE_DISPI_INDEX_BPP`  (0x03) -> `32`
  * `VBE_DISPI_INDEX_ENABLE` (0x04) -> `VBE_DISPI_ENABLED | VBE_DISPI_LFB_ENABLED` (`0x41`)
* **Physical LFB Base:** PCI BAR0 of device `0x1234:0x1111`, i.e. `0xFD000000` here (16 MiB aperture, `pitch = 4096` at 1024x768x32).

#### Where the BGA registers actually live (measured, not assumed)
The classic **index port `0x01CE` / data port `0x01CF`** pair read back `0xFFFF` on the QEMU build this kernel is validated against, so a port-only probe reports no adapter on a machine that plainly has one. The interface that answers is the adapter's **PCI region 2**, a 4 KiB MMIO bar that maps the VGA ports flat:

| Offset | Register block |
| :--- | :--- |
| `0x000-0x3FF` | EDID |
| `0x400-0x41F` | remapped VGA I/O ports |
| `0x500-0x515` | **Bochs dispi registers**, one `u16` every two bytes (`index << 1`) |
| `0x600-0x607` | QEMU extended registers (`0x604` = endianness) |

`fb::find_dispi` therefore probes the MMIO path first (`Dispi::Mmio(base)`), falls back to the legacy ports (`Dispi::Ports`) for real Bochs hardware, and reports `Dispi::Missing` otherwise - a machine with no adapter at all still boots, prints `[--] NO DISPLAY ADAPTER (serial console only)` and keeps the serial shell. The 4 KiB bar is assigned from the PCI hole (`0xFEBE0000` preferred) when the loader left BAR2 blank, and the aperture is reachable because `src/boot.rs` identity-maps the low 4 GiB before entering long mode.

---

## 4. GUI Layer Architecture: The Microkernel Separation

```
+---------------------------------------------------------------+
|                       KELLER-OS DISPLAY                      |
+---------------------------------------------------------------+
| Top Bar: [KELLER-OS v2.5] [VAULT: LOCKED] [NET: ISOLATED] [!] |
+-------------------------------+-------------------------------+
|                               |                               |
|        KELLER SHELL           |        KELLER VAULT HUD       |
|                               |                               |
| > status                      | Sector 0: [ENCRYPTED]         |
| [OK] SCHNORR SESSION VALID    | Sector 1: [ENCRYPTED]         |
| > vault dump                  | Key Identity: ED25519-PQC     |
| ACCESS DENIED: CAPABILITY REQ | Zeroization Test: [ARMED]     |
|                               |                               |
|                               | [PURGE & ZERO RAM NOW]        |
+-------------------------------+-------------------------------+
```

> **Implementation status.** Phases 1-3 and the mechanical half of 4 are implemented and
> verified in Ring 0 (`src/fb.rs`, `src/pci.rs`, `src/gui/`, `src/arch/ps2.rs`); the Ring-3
> boundary itself and the `Keller Auth` lockscreen are still open - see §6. The interfaces
> below are written so the compositor can move out of the kernel without the callers changing:
> window slots already carry an owner PID, a capability token and focus state, input is
> already delivered by capability rather than by address, and the display server only ever
> exposes rectangles.

### 4.1 Ring 0 (Microkernel Core)
* **Zero Graphics Code:** Ring 0 does not know what a "window" or "font" is.
* **Memory Management:** Maps the physical LFB pages into the page table of the sandboxed Compositor process.
* **IPC Transport:** Transfers input event packets (keyboard scancodes, mouse movements) from device IRQs to the Compositor mailbox.
* **Panic Hook:** In the event of a kernel panic, Ring 0 writes zeros to the raw physical LFB address space:
  ```rust
  pub unsafe fn panic_scrub_framebuffer(addr: *mut u8, len: usize) {
      core::ptr::write_bytes(addr, 0x00, len);
  }
  ```

### 4.2 Ring 3 (Compositor & Display Server)
The Compositor (`keller-wm`) manages:
1. **Double Buffering:** Maintains an in-RAM backbuffer (`1024 x 768 x 4` bytes = 3 MB) to prevent screen tearing without requiring V-Sync GPU interrupts.
2. **Window Descriptors (`WindowDesc`):**
   * Window ID & Owner Process ID
   * Bounding box `(x, y, width, height)`
   * Backbuffer pointer (shared memory segment)
   * Capability Token (cryptographically signed ID)
   * Focus state
3. **Dirty-Rectangle Blitting:** Only modified rectangular areas are copied from backbuffer to LFB to preserve CPU cycles.

#### Bring-up instantiation (`src/gui/mod.rs`)
The windowing contract is live today as a Ring-0 display server with the same data structures and the same pixel path. Each of the three windows below is registered through `WindowManager::spawn` with a capability token, exactly as a Ring-3 client will:

| Slot | Window | Owner | Capability |
| :--- | :--- | :--- | :--- |
| 1 | `KELLER SHELL` | pid 1 | `0x5348454C4C01` |
| 2 | `KELLER VAULT` | pid 2 | `0x5641554C5402` |
| 3 | `SUBSYSTEMS` | pid 3 | `0x535542535953` |

* **Console mirror:** `serial::write_byte` feeds `gui::console_write` one byte at a time, so every `print!` in the kernel - including the shell's own output - lands in the shell tile without the shell knowing a GUI exists.
* **Dirty mask:** one bit per region (top bar, footer, three tiles). A region is repainted only when its text actually changed (`Line::same_as`, `TextBlock::changed_from`), and `blits` counts rectangles, not frames.
* **Fixed slot:** `REFRESH_MS = 100`, driven from the idle loop's `gui::render_tick(clock::uptime_ms())` - a repaint happens inside a scheduler quantum, never on an interrupt.
* **Determinism:** no allocation after start-up (the canvas is one 3 MiB `Vec<u32>` taken during bring-up); `MAX_WINDOWS = 8` fixed slots; no partial frames - a repaint always completes against the backbuffer before one `write_span` per row touches the aperture.
* **Stack discipline:** the display state lives in `.bss` and is filled *in place*. A `DisplayServer` is ~20 KiB, and constructing one as a local cost >100 KiB of debug-build frames - more than the old 64 KiB boot stack, which walked into the page tables below it and surfaced as a silent triple fault. The boot stack is 256 KiB, a 4 KiB poison band sits under it, and `[OK] STACK GUARD: ...` reports the guard state and the compositor's high-water mark (`5920` bytes at bring-up) on every boot.

---

## 5. Visual Language & UX Guidelines

To maintain alignment with sovereign, high-security computing:

1. **Geometry:** Flat, sharp rectangles. Zero border radius (no rounded corners).
2. **Typography:** Monospaced 8x16 bitmap font (baked directly into the binary as a constant byte array, zero dynamic font-engine overhead). Shipped as `FONT_8X16: [u8; 256 * 16]` = 4096 bytes in [`src/gui/font.rs`](src/gui/font.rs), generated by [`dev-tools/make_font.py`](dev-tools/make_font.py) from CascadiaMono.ttf (SIL OFL 1.1) rasterised at 12 px on baseline row 12, MSB-first rows, one row per byte.
3. **Palette:** High-contrast, dark-mode terminal aesthetic:
   * **Background (`--bg`):** `#030712` (Pitch black)
   * **Window Chrome / Cards (`--panel`):** `#0F172A` (Deep slate)
   * **Borders / Separators (`--border`):** `#6366F1` (Indigo accent)
   * **Text Primary:** `#F8FAFC` (Pure white)
   * **Text Secondary:** `#94A3B8` (Muted cyan/slate)
   * **Status Danger / Kill-Switch:** `#EF4444` (Vibrant crimson)
   * **Status Secure / Active:** `#10B981` (Emerald green)

   Shipped as the `BG` / `PANEL` / `BORDER` / `TEXT` / `TEXT_DIM` / `DANGER` / `SECURE` constants in [`src/gui/canvas.rs`](src/gui/canvas.rs) (`0x00RRGGBB`), plus one implementation shade `CHROME = #1B2438` for title strips. `dev-tools/verify_gui.py` asserts every one of them is present in a `--screendump` capture, so the palette is checked against the emulator and not just against the source.
4. **Window Interaction:**
   * Clean 20px title bar with window name and capability badge.
   * Keyboard-first navigation: `Alt + Tab` cycle focus (**bound**), `Alt + Q` close,
     `Alt + Arrow` tile (**not bound yet**).
   * Mouse tracking via PS/2 packet decoding (**bound**: the arrow is composited into the
     backbuffer and a left click grants focus to the window under it). The device is brought up
     as an **IntelliMouse** - the sample-rate sequence `200, 100, 80` asks a wheel mouse to add
     the fourth packet byte, so `id 0x03` and four-byte packets rather than the three-byte ones
     every mouse sends by default. Without that negotiation the decoder commits to three bytes
     and the wheel is a device nobody ever hears from, which looks exactly like a broken wheel:
     boot therefore says which of the two happened, in a line of its own
     (`[OK] PS/2 MOUSE WHEEL: IntelliMouse negotiated (id 0x03) ...`, or `[--]` naming whether the
     device refused the sequence or accepted it and reported an id without a wheel anyway).
   * **Backscroll.** The console tile is a 626x704 px **view** onto a ring of
     `CONSOLE_LINES = 256` log lines, not the last 34 of them: `PageUp` / `PageDown` scroll the
     focused window (three lines a notch, `Home` / `End` jump to the ends), and the wheel
     scrolls the window **under the pointer** - the one the user is looking at, which a click is
     what changes. Typing in the shell snaps the view back to the live tail, because a keystroke
     that scrolls away from its own echo is a surprising thing for a console to do. The footer
     says which it is: `FOCUS KELLER SHELL at the live tail`, or `FOCUS KELLER SHELL 12 lines
     back of 81`. `gui scroll` prints the same state from the shell, and `gui top | bottom | up |
     down` move it without a keyboard.

   `input status` reports the live state (decoded bytes, routed/refused keys, cursor,
   clicks, focus holder and its capability); `input test` runs the probe described in §6. On a
   machine with no 8042 at all (`-machine pc,i8042=off`) the driver declares the controller
   **absent**: one `[--] PS/2 CONTROLLER ABSENT` line at boot, no IRQ registered, and neither
   `0x64` nor `0x60` is read again - the port answers `0xFF`, whose status bits read as "output
   full, aux data", so draining it would invent a phantom mouse byte on every pass. `input`
   then shows `present=false` with every counter at zero, and `input test` notes that its
   assertions cover the decoders and the focus policy, not a live device path.

   Presence is reported **per device**, never inherited from the controller: passing both 8042
   self-tests proves nothing about the two ports, so the keyboard counts as present only when
   it ACKs its bring-up commands (`0xF0 0x01` / `0xF4`) and the mouse only when the id byte
   follows its `0xF2` ACK. Boot says which of them answered (`[OK] PS/2 DEVICES: keyboard
   present (scancode set 1 confirmed), mouse present (id 0x03, 4 byte packets)`), `input` adds
   `[PS2] devices: keyboard=present mouse=present keyboard-irq=unmasked mouse-irq=unmasked`, and
   a silent port flips both to `[--]` / `absent`, keeps its IRQ unwired (IRQ1 masked when the
   keyboard is silent, IRQ12 never unmasked without a mouse) and is named by `input test` as
   the missing device. QEMU's `i8042=off` removes the whole controller, so a live controller
   with a dead keyboard or mouse is the one input case that has to be reproduced on real
   hardware - the same three boot lines appear there, with `ABSENT` in place of `present`.

---

## 6. Implementation Step-by-Step Roadmap

### Phase 1: Boot & Physical Video Output - *done*
- [x] Emit the Multiboot2 Linear Framebuffer Tag (5) - in [`src/boot.rs`](src/boot.rs) (the `boot.s`/`boot.o` pair is gone; the header is one `global_asm!` block). Marked optional.
- [x] Parse the Multiboot2 information structure for `framebuffer_addr`, `pitch`, `width`, `height` - [`src/bootinfo.rs`](src/bootinfo.rs) publishes `BootInfo::framebuffer`, adopted by `fb::adopt_handoff` before any probe.
- [x] Bochs VBE fallback when the loader passes no framebuffer - [`src/fb.rs`](src/fb.rs) `init`, via PCI MMIO region 2 (see §3.3: the legacy `0x01CE`/`0x01CF` pair is tried second because it does not answer on this QEMU).
- [x] Raw pixel primitive - `Framebuffer::write_pixel` / `read_pixel` / `write_span` / `blit` / `fill` / `scrub`, all through the aperture, plus `fb::self_test` (four corners written, read back and restored).

### Phase 2: Minimalist `no_std` Graphics Primitives - *done*
- [x] [`src/gui/mod.rs`](src/gui/mod.rs) and [`src/gui/canvas.rs`](src/gui/canvas.rs).
- [x] 2D drawing routines: `fill_rect`, `draw_rect_border`, `hline`, `vline`, `line`, all clipped to a `Rect` (zero-radius rectangles only, no curves).
- [x] Baked font table - 4096 bytes of glyph data (256 glyphs x 16 rows), no font engine, plus `draw_char` / `draw_string` / `draw_string_clipped`.

### Phase 3: Display Server & Window Management - *done in Ring 0, Ring-3 split open*
- [x] `Canvas` (the `Surface` of the plan): a packed `u32` backbuffer owned by the display server, never drawn into directly by clients.
- [x] `WindowManager` with a fixed pool of `MAX_WINDOWS = 8` slots, capability tokens, owner PIDs and focus state; `focus_next()` defines the `Alt + Tab` order and `gui::route_key` binds the real chord to it, so the chord advances focus and the title strips follow.
- [x] Top status bar: vault health, mesh state, entropy source, uptime, **focus holder, cursor position**, frame counter and refresh rate.
- [x] Shell tile mirrors the kernel log (`serial::write_byte` -> `gui::console_write`) - the 80x25 cell grid idea, at 626x704 px.
- [x] Hardware cursor / PS/2 mouse: no hardware cursor is used - the arrow (9x14, `TEXT` on a `BG` outline) is composited into the backbuffer like any other content, so moving it repairs what it left behind as one more repaint rectangle.
- [x] **Input routing:** `arch::ps2` decodes set-1 scancodes and 3- or 4-byte (wheel) mouse packets on IRQ1/IRQ12 into rings, `main`'s idle loop drains them through `ps2::drain`, and `gui::route_key` / `gui::route_mouse` deliver to the window that holds focus - a keystroke aimed at a window that does not hold it is *dropped* and counted, never queued for later.
- [x] **Backscroll:** a ring of 256 log lines behind a 34-line tile, per-window scroll offsets moved by `PageUp`/`PageDown`/`Home`/`End`, by the mouse wheel (the window under the pointer, 3 lines a notch) and by the shell's `gui top|bottom|up|down`; the tile is re-read from its model on every repaint, so the view is a view and not a copy.

### Phase 4: Integration with Subsystems - *partly done*
- [ ] **Lockscreen / Auth (`Keller Auth`):** **open** - no credential prompt, no Schnorr indicator, no decoy mode in the GUI yet.
- [x] **Shell Window (`Keller Shell`):** the console tile mirrors the kernel log verbatim, and *both* COM1 and the PS/2 keyboard feed the same line buffer - a keystroke typed at the QEMU window and one typed over the serial console are indistinguishable, echo included.
- [x] **Vault Controller (`Keller Vault`):** fingerprint, shard count, threshold, sealed/degraded state, sector and write counters, forged-opening count, and the red `[PANIC: ZERO VAULT & HALT]` affordance wired to the same code path as the shell's `panic` command.
- [x] **Panic Hook:** `fb::scrub_hook` is registered before the display server starts; verified by capturing the screen after the shell's `panic` command - all 786432 pixels read back black.

### Phase 5: Verification in QEMU - *done*
- [x] [`run.ps1`](run.ps1) boots with `-vga std` and a QEMU window by default, `-Headless` for capture-only runs, `-NoGraphics` for a machine with no adapter at all.
- [x] [`dev-tools/qemu_check.py`](dev-tools/qemu_check.py) drives the shell over COM1, **  synthesises real keyboard and pointer input through the emulated 8042** (`--type`, `--key`, `--mouse`, `--click`, `--wheel`), captures the screen (`--vga std --screendump`) and then has the guest account for every event it injected (see §6, *Input evidence*). `--wheel N` injects N wheel notches one at a time, because the emulated device batches whatever arrives before its next report and a batch of three would be one packet where the guest counts three.
- [x] [`dev-tools/verify_gui.py`](dev-tools/verify_gui.py) checks the capture against this specification (palette, rules, window rectangles, tile ink, danger affordance, cursor arrow) and writes a PNG plus a self-contained HTML report.

#### Input evidence

The QMP phase enters the guest through the emulated controller, so what the serial log then shows was produced by the kernel's own driver, decoder and routing:

| Injected | Observed |
| :--- | :--- |
| `--mouse 128,-184`, `--click left`, `--mouse=-340,100`, `--click left` | `[PS2] mouse: bytes=27 packets=9 rejected=0 wheel=0 queue=0/64 lost=0`, `[GUI] pointer: cursor=300,300 packets=9 clicks=2 motion=-212,84 buttons=0x00` |
| `--type "input\n"` with the shell focused | twelve scancode bytes for six keys - `[PS2] keyboard: bytes=12 decoded=11 releases=5 ignored=0 queue=1/64 lost=0` - and the shell runs the command that was typed |
| `--key alt-tab` then `--type "mem\n"` | the focus holder line moves to `KELLER VAULT`; the heartbeat reads `ps2 kbd=12/12 mouse=0/0 rejected=0 routed=1 refused=4` - one chord accepted, four typed keys refused - and `[SH] heap` never prints, so the command never ran |
| `--mouse=250,0`, `--click left` | the cursor moves `512,384 -> 762,384`, which is inside the vault tile, and the next `input` reads `[GUI] input: ... focus-changes=1` with `[GUI] focus holder: KELLER VAULT (pid 2, capability 0x00005641554c5402)` - the click granted focus, and the top bar and the title strips follow it |
| `--wheel 4` with the pointer over the shell | `[PS2] mouse: bytes=16 packets=4 rejected=0 wheel=4 queue=0/64 lost=0`, then `[GUI] scroll: wheel-notches=4 gestures=4 keys-to-tiles=0 \| KELLER SHELL 12 of 81 lines back (115 held)` - four device notches, four scroll gestures, and a view twelve lines into the history |

The `motion` counter is the raw PS/2 delta (positive `dy` is up), which is why the pointer ends 84 px above the 384 px it started at. The last row is the property the specification is really about: with focus on another window the same keystrokes are not delivered, not echoed and not queued.

Wheel notches are counted in *four-byte packets*, not in notches and not signed: a notch down is a wheel byte exactly as much as a notch up is, so a mouse that never negotiated IntelliMouse mode shows up as zero rather than as a wrong direction. An up-notch is held to a second, stronger standard, because a device byte is not a scrolled view: the harness reads the display server's own `[GUI] scroll:` line and requires the notch count to match, at least one gesture to have moved something, and the focused window's view to be *off* the live tail. That is what catches the sign being inverted, which it was: the wire format's nibble is positive for a notch *towards* the user (Linux negates the same byte, `input_report_rel(dev, REL_WHEEL, -(s8) packet[3])`), so a decoder that publishes it unnegated scrolls the history the wrong way and looks like a working wheel while doing it. QEMU follows Linux, so `--wheel 1` is one notch away from the user.

Every input run also checks itself. Before and after the injection the harness types `input` at the guest on COM1 - which the PS/2 counters cannot see - and requires the guest's own numbers to account for what it sent: keyboard bytes, mouse packets, wheel bytes, clicks, the cumulative motion and the cursor's landing point, with nothing lost in either ring. `--key alt-tab --type "mem\n"` therefore has to show up as `+12 bytes of 12` and `+1 routed / +4 refused` in the run's own evidence lines, and the run fails outright if the guest never answers - so a `--forbid` guard can no longer pass because the injection silently did nothing. Scripted console lines are held to the same standard: each one must be echoed back before the next is sent, so a command the console dropped fails the run instead of quietly never running. `--no-input-check` turns the counter check off.

### Verified evidence (this build)

```powershell
# Full suite with the adapter attached: 161 assertions plus 20 skipped. The input probe is 23
# of them, and the 24-assertion gap to the no-adapter run below is the whole display-server and
# input delta - a check that did not run is never added to one that passed.
python dev-tools\qemu_check.py --vga std --secs 110 --stdin-script target\full-input.txt `
    --stdin-delay 18 `
    --expect "[OK] GUI DISPLAY SERVER" `
    --expect "[SH] INPUT PROBE assertions: 23 passed, 0 failed" `
    --expect "SELF-TEST SUMMARY: 161 passed, 0 failed, 20 skipped" `
    --expect "[OK] PS/2 MOUSE WHEEL: IntelliMouse negotiated" `
    --expect "STACK GUARD: 4 KiB poison band intact" --forbid "LOCKDOWN"

# Real input through the emulated 8042, after the scripted commands: aim, click, aim, click,
# then a typed command. The screendump is taken once the input phase has settled.
python dev-tools\qemu_check.py --vga std --secs 42 --stdin-script target\gui-input.txt `
    --type "input\n" --mouse 128,-184 --click left --mouse=-340,100 --click left `
    --screendump target\gui.ppm `
    --expect "[SH] GUI PROBE: aperture round-trip=PASS + backbuffer/glyph/blit=PASS => PASS" `
    --expect "[PS2] mouse: bytes=27 packets=9" `
    --expect "[GUI] pointer: cursor=300,300 packets=9 clicks=2 motion=-212,84"

# Pixel-level check of that capture: 30 assertions, one per palette colour plus the cursor arrow.
python dev-tools\verify_gui.py --ppm target\gui.ppm --png target\gui.png --html target\gui-preview.html --cursor 300,300

# The capability gate: Alt+Tab moves the focus to KELLER VAULT, so the typed command is refused
# and never runs - `--forbid` the line only `mem` prints. The input check then prints the ledger:
# +12 bytes of 12 injected, +1 routed (the chord), +4 refused (the text), cursor unmoved.
python dev-tools\qemu_check.py --vga std --secs 40 --stdin-script target\input-input.txt `
    --key alt-tab --type "mem\n" --input-settle 26 `
    --expect "[OK] GUI DISPLAY SERVER" --forbid "[SH] heap"

# Panic path: the screen must be black afterwards (framebuffer wiped by the hook).
python dev-tools\qemu_check.py --vga std --secs 26 --stdin-script target\panic-input.txt `
    --screendump target\panic.ppm --expect "[!] CPU REGISTERS ZEROED - HALT"
python dev-tools\verify_gui.py --ppm target\panic.ppm --png target\panic.png --wiped

# No adapter at all: everything still boots, the suite reports 137 (161 minus the display-server
# and input assertions) and the input probe 18 + 4 skipped - the four focus-routing and
# backscroll assertions have no focus holder to route to, and no history to scroll. The network
# adapter is unaffected and moves to 00:02.0.
python dev-tools\qemu_check.py --vga none --secs 110 --stdin-script target\full-input.txt `
    --stdin-delay 18 `
    --expect "NO DISPLAY ADAPTER (serial console only)" `
    --expect "INPUT PROBE assertions: 18 passed, 0 failed, 4 skipped" `
    --expect "SELF-TEST SUMMARY: 137 passed, 0 failed, 20 skipped" --forbid "FAILED"
```

Measured on the run above: `[FB] 1024x768x32 @ 0xfd000000 pitch=4096 origin=bochs/qemu vga (3.0 MiB aperture)`,
`[OK] GUI DISPLAY SERVER: 3072 KiB backbuffer, 8 window slots, 100 ms fixed refresh`,
`[OK] PS/2 CONTROLLER: self-test PASS (0x55), aux port present`,
`[OK] PS/2 MOUSE WHEEL: IntelliMouse negotiated (id 0x03) - the fourth packet byte carries the wheel as a signed 4-bit count, so the wheel scrolls`,
`[OK] PS/2 DEVICES: keyboard present (scancode set 1 confirmed), mouse present (id 0x03, 4 byte packets)`,
`[OK] PS/2 INPUT: keyboard IRQ1 + mouse IRQ12 unmasked (translation off)`,
`[OK] GUI SCROLLBACK: 13 lines of log held behind a 34 line tile (0 lines of backscroll), PgUp/PgDn + Home/End + wheel scroll the focused window`,
`[OK] STACK GUARD: 4 KiB poison band intact, compositor peak 5920 bytes of 262144`, plus the
injected-pointer evidence `[PS2] mouse: bytes=27 packets=9 rejected=0 wheel=0 queue=0/64 lost=0`
and `[GUI] pointer: cursor=300,300 packets=9 clicks=2 motion=-212,84 buttons=0x00`, and a
screendump with 3 window frames, 29 log-filled text cells, the danger affordance and the
cursor arrow at the coordinates the status bar claims (30 pixel-level checks).

---

## 7. Remaining Work

1. **Move the compositor to Ring 3** (`keller-wm`): map the LFB into a sandboxed process, move `Canvas`/`WindowManager` behind IPC, and keep Ring 0 to page mapping, the panic scrub hook and the syscall gate. The `WindowDesc` capability tokens already identify the clients this will gate, and input already travels as events rather than as memory.
2. **More window-manager chords:** `Alt + Q` (close) and `Alt + Arrow` (tile) are declared in §5.4 but not bound; the routing switch in `gui::route_key` is the single place that has to learn them, and `WindowManager` needs a close/tile operation it does not have yet.
3. **`Keller Auth` lockscreen** as the first full-screen window: credential challenge, Schnorr verification indicator, decoy mode.
4. **Vault sector map in the tile** plus a clickable purge button (the pointer path now exists: `MousePacket::buttons` and click-to-focus are already delivered).
5. **Numpad-as-arrows and the keyboard LEDs:** `input status` tracks Num/Caps/Scroll state, but the numpad always types its digits and the 8042 LED command (`0xED`) is not sent, so the keyboard's own lamps do not follow the state.
6. **Bootable ISO + Bochs check:** the Multiboot2 request tag now ships, so a GRUB ISO would exercise the handoff path (`fb::adopt_handoff`) that QEMU's PVH direct boot cannot - which also means a Bochs run would exercise the legacy `0x01CE`/`0x01CF` BGA ports and a non-QEMU PS/2 controller.
