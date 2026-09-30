# KELLER-OS: Bare-Metal Sovereign Microkernel & Hypervisor

<div align="center">

![KELLER-OS Banner](assets/banner.svg)

**A high-assurance, mathematically disciplined sovereign microkernel engineered for zero-trust, anti-forensics, and post-quantum mesh environments.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust: Nightly](https://img.shields.io/badge/Rust-Nightly%20no__std-orange.svg)](https://www.rust-lang.org/)
[![Target: x86__64](https://img.shields.io/badge/Target-x86__64--sovereign__core-blueviolet.svg)](x86_64-sovereign_core.json)
[![Crypto: Post--Quantum](https://img.shields.io/badge/Crypto-Kyber--512%20%7C%20Ed25519-green.svg)](CRYPTOGRAPHY_DEEP_DIVE.md)
[![Mesh: Vantablack](https://img.shields.io/badge/Network-Vantablack%20WAN%20Mesh-black.svg)](VANTABLACK_INTEGRATION.md)

[**System Specification**](SPECIFICATION.md) &bull; [**Cryptography Deep Dive**](CRYPTOGRAPHY_DEEP_DIVE.md) &bull; [**GUI Specification**](GUI_SPECIFICATION.md) &bull; [**Vantablack Integration**](VANTABLACK_INTEGRATION.md) &bull; [**Visual Canvas**](KELLER%20OS.canvas)

</div>

---

## 1. Overview

**KELLER-OS** is an independent, bare-metal operating system built from scratch in Rust (`#no_std`). Unlike monolithic operating systems with millions of lines of code running in Ring 0, KELLER-OS enforces a strict **seL4-class microkernel design**:
* **Under 10,000 lines of code** execute in privileged Ring 0.
* Drivers, networking, file storage, graphics, and user shells run in **fault-isolated Ring 3 tasks**.
* Every resource access is mediated by unforgeable, cryptographically signed **capability tokens** (zero ambient authority).
* In-RAM data is protected by **ChaCha20 sector encryption** and instant **volatile panic-zeroing** to defeat liquid nitrogen cold-boot memory dumps.
* Native internet access is routed exclusively through **[Vantablack](https://github.com/KELLERBABG/Vantablack)**—a post-quantum, erasure-sharded ($\text{RS}(2,1)$) decentralized WAN mesh network with rotating egress gateways.

**Bring-up status (this build).** Live and probe-verified from the shell: PVH/Multiboot2 boot,
coalescing allocator, GDT/IDT/PIC/PIT, fixed-slot scheduler, `Keller Vault` (RS-sharded root
secret, per-sector AEAD), `Keller Net` (ShardSec frames, Byzantine isolation, replay window,
Poisson cover) and a Ring-0 display server driving a 1024x768x32 Bochs/QEMU VBE framebuffer
with dirty-rectangle blitting, a composited software cursor and a panic screen wipe. The
**Ring-3 boundary is real**: every process gets its own PML4 and `cr3` is switched on the task
switch, so two tasks using the same virtual addresses reach different frames and cannot readeach other's memory; tasks are entered by `iretq` into a DPL-3 frame whose only way back in is one
DPL-3 gate (`int 0x80`), port I/O from CPL 3 is denied by the TSS bitmap, a faulting task is
terminated instead of locking the kernel down, and the context switch happens inside the timer
interrupt — so a task that never yields, or one that is already dead, is handled without its
cooperation ([`RING3_ISOLATION.md`](RING3_ISOLATION.md)). The mesh's transport is a **real wire**:
an Intel 82540EM (`e1000`) driver with DMA descriptor rings puts the sealed 576-byte frames on the
segment as Ethernet/IPv4/UDP datagrams and takes peer frames back through the same ingress
pipeline, answers ARP for its own address so a peer can deliver to it at all, and is checked from
the *outside* by [`tools/wire_check.py`](dev-tools/wire_check.py), which attaches as the adapter's
peer and validates every frame, prints the counter deltas it predicted for each frame it refused,
and re-reads its own pcap ([`NIC_WIRE.md`](NIC_WIRE.md)). The vault is also **on a disk**: an
AHCI driver drives a real SATA device, the sealed sectors become a disk image with a superblock
and per-slot records, and the image is only opened after a Schnorr proof has been checked against
both the owner commitment and the header that is on the medium - so the machine that boots with
the disk attached reads its own data back, and a [host-side reader](dev-tools/disk_check.py) confirms
independently that the plaintext is nowhere on the platter
([`STORAGE_PERSISTENCE.md`](STORAGE_PERSISTENCE.md)). The PS/2
input path decodes set-1 scancodes and three- or four-byte mouse packets on IRQ1/IRQ12 and
delivers them to the focused window's capability: `alt+tab` cycles focus (`WindowManager::focus_next`)
and a left click focuses the window under the pointer, while keystrokes aimed at a window that
does not hold focus are dropped and counted. The mouse is negotiated up to IntelliMouse at
bring-up (the `200, 100, 80` sample-rate sequence), which is what makes its wheel exist as a
fourth packet byte at all - the wheel then scrolls the window under the pointer, and
`PageUp`/`PageDown`/`Home`/`End` scroll the focused one, through a 256-line history behind the
34-line console tile; the keyboard and the mouse are reported **separately** at
boot (`[OK] PS/2 DEVICES: ...`), because a controller that passes its own tests still says
nothing about what is plugged into its two ports - a dead keyboard or an empty aux port is
named rather than hidden behind a healthy-looking controller; a machine with no 8042 is called
`[--] PS/2 CONTROLLER ABSENT` once and then left alone instead of being polled into a phantom
byte stream. Still
open, and said so in the code and logs where it matters: moving the existing PS/2 driver, network
driver, display server and shell command set *onto* the ring-3 substrate (they run in ring 0
today), per-process capability grants beyond the single mediated port, `copy_to_user`, the SOCKS5
egress daemon, the `Keller Auth` lockscreen, and a regenerated Multiboot ISO.

---

## 2. Master Specifications Index

The repository includes complete, professional specifications detailing every subsystem:

| Document | Purpose & Scope |
| :--- | :--- |
| [**`SPECIFICATION.md`**](SPECIFICATION.md) | **Master System Architecture & Engineering Specification:** Threat model, microkernel core, `SovereignAllocator`, IDT/GDT, scheduler, capabilities, and subsystem blueprints. |
| [**`CRYPTOGRAPHY_DEEP_DIVE.md`**](CRYPTOGRAPHY_DEEP_DIVE.md) | **Mathematical Cryptographic Deep Dive:** Kyber-512 (ML-KEM) + X25519 hybrid handshake, Shamir Secret Sharing (2-of-3), Reed-Solomon $\text{RS}(2,1)$, pure-Rust ChaCha20-Poly1305, and Schnorr ZKP. |
| [**`GUI_SPECIFICATION.md`**](GUI_SPECIFICATION.md) | **Capability-Based Display Server:** Multiboot2 linear framebuffer, Bochs VBE fallback, double-buffered compositor, embedded 8x16 bitmap fonts, zero animations, and panic display scrubbing. |
| [**`RING3_ISOLATION.md`**](RING3_ISOLATION.md) | **Ring-3 Isolation, Address Spaces & Preemption:** per-process PML4s with `cr3` switching, the DPL-3 syscall door, fault containment, the timer-ISR context switch, and the phase that demonstrates all of it. |
| [**`NIC_WIRE.md`**](NIC_WIRE.md) | **Physical Network Driver & On-Wire Verification:** The Intel 8254x (`e1000`) driver, its DMA descriptor rings, the Ethernet/IPv4/UDP framing and ARP responder, and the peer tool that validates every frame independently. |
| [**`STORAGE_PERSISTENCE.md`**](STORAGE_PERSISTENCE.md) | **Persistent Vault Storage:** The AHCI (SATA) driver, the block layer, the on-disk image format, the zero-knowledge unlock gate that derives the disk key from a Schnorr transcript, the journal counter, and the two-boot plus host-side verification. |
| [**`VANTABLACK_INTEGRATION.md`**](VANTABLACK_INTEGRATION.md) | **Native Internet Access Layer:** Zero-leak WAN mesh integration with [KELLERBABG/Vantablack](https://github.com/KELLERBABG/Vantablack), ShardSec per-shard AEAD, Byzantine tamper isolation, and SOCKS5 proxying. |
| [**`KELLER OS.canvas`**](KELLER%20OS.canvas) | **Obsidian Master Architecture Canvas:** Visual node graph mapping out core tenets and peripheral subsystems. |

---

## 3. Directory Layout

```text
KELLER-OS/
├── .cargo/
│   └── config.toml             # Target triples, build-std, and rustflags
├── assets/
│   ├── banner.svg              # KELLER-OS vector banner
│   └── icon.svg                # Vector insignia for landing page and GUI
├── boot/
│   └── grub/
│       └── grub.cfg            # Multiboot2 bootloader configuration
├── src/
│   ├── arch/
│   │   ├── acpi.rs             # RSDP/XSDT walk, MADT + MCFG parsing, processor enumeration
│   │   ├── ahci.rs             # SATA HBA bring-up, PRDT DMA, sector read/write, adapter self-test
│   │   ├── cpu.rs              # CR0/CR4 bring-up, RDRAND/CPUID, cli/sti/hlt
│   │   ├── gdt.rs              # GDT + per-CPU TSS with dedicated IST stacks
│   │   ├── idt.rs              # 256 interrupt gates, XMM-safe stubs, dispatch
│   │   ├── ioapic.rs           # Redirection entries, GSI routing, the 8259 masked behind it
│   │   ├── lapic.rs            # Local APIC, calibrated timer, self-IPI, EOI
│   │   ├── mod.rs              # arch bring-up order
│   │   ├── msi.rs              # MSI/MSI-X capability probe and message-page delivery
│   │   ├── paging.rs           # Per-process PML4, 4 GiB identity map, frame accounting
│   │   ├── pic.rs              # 8259 remap to 32-47, PIT at 100 Hz
│   │   ├── ps2.rs              # 8042: set-1 scancodes, 3/4-byte mouse packets, IntelliMouse
│   │   └── smp.rs              # INIT-SIPI-SIPI trampoline, per-CPU state, pinned ChaCha20 KAT
│   ├── block.rs                # Sector layer between the vault image format and the disk
│   ├── boot.rs                 # Multiboot2 + PVH entry, page tables, 256 KiB boot stack + guard
│   ├── bootinfo.rs             # Handoff parser: memory map and framebuffer tag
│   ├── clock.rs                # PIT tick counter, uptime in ms
│   ├── crypto.rs               # ChaCha20-Poly1305, SHA-256/HKDF, RS(2,1), Shamir, Kyber-512
│   ├── eth.rs                  # Ethernet/IPv4/UDP framing, checksums, ARP responder, known-answer test
│   ├── fb.rs                   # Framebuffer: BGA mode set, pixel/span/blit, panic scrub
│   ├── gui/
│   │   ├── canvas.rs           # Rasteriser: rectangles, borders, lines, 8x16 text
│   │   ├── font.rs             # Baked 4096-byte glyph table (generated by dev-tools/make_font.py)
│   │   └── mod.rs              # Display server: console mirror, windows, dirty-rect blits
│   ├── integrity.rs            # FNV1a-64 self-measurement of .text
│   ├── ipc.rs                  # HMAC-SHA256 verified IPC queue
│   ├── linker.ld               # Memory layout (__text_start, bss, rodata)
│   ├── main.rs                 # Kernel entry, allocator, GDT/IDT, scheduler, idle loop
│   ├── mm.rs                   # Coalescing free-list allocator
│   ├── net.rs                  # Vantablack mesh: ShardSec frames, Byzantine isolation, cover traffic
│   ├── nic.rs                  # Intel 8254x (e1000): DMA descriptor rings, MAC, ARP replies, counters
│   ├── panic.rs                # 3-pass memory wipe, scrub hooks, lockdown
│   ├── pci.rs                  # PCI bus 0 enumeration, BAR sizing/assignment, VGA lookup
│   ├── port.rs                 # Port I/O primitives
│   ├── proc.rs                 # Process table, per-task address spaces, fault retirement
│   ├── sched.rs                # Fixed-slot scheduler with temporal isolation
│   ├── serial.rs               # 16550 UART driver, RX ring, console macros, GUI log mirror
│   ├── session.rs              # Capability tokens & 128-bit replay window
│   ├── shell.rs                # COM1 line editor and command dispatch
│   ├── storage.rs              # Vault image format, superblock, records, journal
│   ├── vault.rs                # RAM sector encryption & panic-zeroing
│   └── zk.rs                   # Schnorr proofs, GHOST blobs, the unlock gate
├── dev-tools/                 # Development-only helpers: never needed to build or boot the kernel
│   ├── bochsrc.txt             # Bochs emulator hardware profile
│   ├── disk_check.py           # Independent reader for a vault image: geometry, framing, no plaintext
│   ├── make_font.py            # Bakes src/gui/font.rs from CascadiaMono.ttf
│   ├── qemu_check.py           # QEMU harness: expect/forbid patterns, screendump, input injection
│   ├── smp_check.py            # Independent ChaCha20/SHA-256 checks of the per-AP KAT digests
│   ├── verify_gui.py           # Screendump -> spec checks, PNG and HTML report
│   └── wire_check.py           # Independent peer on the NIC segment: validates every frame
├── .gitignore                  # Build artifact and log exclusions
├── build.rs                    # Cargo build script linking assembly bootstrap
├── Cargo.lock                  # Pinned dependency lockfile
├── Cargo.toml                  # Package manifest & profile optimizations
├── CANVAS_EXPANSION_TOPICS.md  # Expansion catalogue for the architecture canvas
├── CRYPTOGRAPHY_DEEP_DIVE.md   # Mathematical & Global Mesh Cryptographic Deep Dive
├── GUI_SPECIFICATION.md        # Dedicated Graphical Subsystem Specification
├── index.html                  # Landing page for kernel.kellersystems.dev
├── KELLER OS.canvas            # Obsidian master architectural canvas
├── NIC_WIRE.md                 # Wire-level NIC verification: the harness as the adapter's peer
├── README.md                   # Quickstart and build guide (this document)
├── RING3_ISOLATION.md          # Ring-3 address spaces, the syscall door, fault containment
├── run.ps1                     # QEMU launch and debug harness (-Headless / -NoGraphics)
├── rust-toolchain.toml         # Nightly channel & component configuration
├── SPECIFICATION.md            # Master System Specification document
├── STORAGE_PERSISTENCE.md      # Persistent vault storage on a real disk (AHCI + ZK unlock gate)
├── VANTABLACK_INTEGRATION.md   # Sovereign WAN Mesh & Native Internet Access Specification
└── x86_64-sovereign_core.json  # Bare-metal LLVM target specification
```

---

## 4. Prerequisites & Environment Setup

To compile and execute the kernel on Windows (or Linux/WSL2):

1. **Rust Nightly Toolchain:**
   The repository automatically uses the toolchain specified in [`rust-toolchain.toml`](rust-toolchain.toml):
   ```bash
   rustup override set nightly
   rustup component add rust-src llvm-tools-preview
   ```

2. **Hypervisor / Emulators:**
   * **QEMU:** `qemu-system-x86_64` (installed at `C:\Program Files\qemu` on Windows, or via `apt install qemu-system-x86` on Linux).
   * **Bochs (Optional):** For cycle-accurate hardware emulation ([`dev-tools/bochsrc.txt`](dev-tools/bochsrc.txt)).

3. **Multiboot2 ISO Tools (Optional, for ISO packaging, not installed here):**
   * `grub-mkrescue` and `xorriso` (available via WSL2: `sudo apt install grub-pc-bin grub-common xorriso mtools`).
   * On this machine WSL defaults to the `docker-desktop` distro, so no GRUB tools and no assembler are available. The kernel therefore boots as an ELF via QEMU's `-kernel` loader (PVH direct boot), and no ISO can be built here (section 6).

---

## 5. Build & Execution Quickstart

### Step 1: Verification / Check Build
To verify the code and compile dependencies:
```bash
cargo check -Zjson-target-spec
```

### Step 2: Compile the Sovereign Kernel Binary
Compile the release ELF kernel executable:
```bash
cargo build -Zjson-target-spec --release
```
The compiled bare-metal kernel binary will be produced at:
`target/x86_64-sovereign_core/release/sovereign-core`

### Step 3: Run Headless in QEMU (Serial Output)
Run the automated PowerShell runner:
```powershell
.\run.ps1 -NoGraphics
```
Or execute QEMU directly:
```bash
qemu-system-x86_64 -cpu max -m 256M -kernel target/x86_64-sovereign_core/debug/sovereign-core -serial stdio -display none -d guest_errors,int -no-reboot -D target/qemu-debug.log
```

> **Why `-kernel` and not `-device loader` / `-cdrom`?**
> The kernel is entered through the PVH `XEN_ELFNOTE_PHYS32_ENTRY` note emitted by
> [`src/boot.rs`](src/boot.rs), which QEMU's `-kernel` loader understands. QEMU's
> multiboot ROM refuses ELF64 images ("Cannot load x86-64 image, give a 32bit one"), and
> `-device loader,...,cpu-num=0` never hands control to a PVH kernel. Use `-cpu max` to
> give the kernel RDRAND; without it the DRBG falls back to a TSC/PIT seed and says so.

Type into the same COM1 console to drive the shell. `help` lists every command; the probes
that print a verdict are `crypto`, `vault test`, `ipc test`, `session test`,
`gui test` (framebuffer aperture round-trip plus backbuffer/glyph/blit),
`input test` (set-1 scancode and mouse-packet decoding, plus focus routing) and
`net test` (the Vantablack mesh: ShardSec per-shard sealing, shard/index/counter swap
rejection, replay window, Byzantine route isolation, handshake key agreement and Poisson
cover traffic), with `selftest` running all of them plus the boot crypto KATs. `selftest`
reports 44 assertions with a display adapter attached and 22 without one, where the display and
input probes have nothing to prove; on a bare machine `input test` then reports `17 passed,
0 failed, 4 skipped`.

### Step 4: Run with Graphical Display Output in QEMU
```powershell
.\run.ps1              # -vga std + QEMU window (kernel log also arrives on this terminal)
.\run.ps1 -Headless    # adapter emulated, no window: for scripted capture runs
.\run.ps1 -NoGraphics  # no display adapter at all: serial console only
```

With an adapter attached the kernel reports the mode it set and starts the display server:

```text
[FB] probe: bochs dispi via pci region 2 mmio @0x500 id=0xb0c5 (expected 0xb0c0..0xb0c5)
[FB] 1024x768x32 @ 0xfd000000 pitch=4096 origin=bochs/qemu vga (3.0 MiB aperture)
[OK] PS/2 CONTROLLER: self-test PASS (0x55), aux port present
[OK] PS/2 MOUSE WHEEL: IntelliMouse negotiated (id 0x03) - the fourth packet byte carries the wheel as a signed 4-bit count, so the wheel scrolls
[OK] PS/2 DEVICES: keyboard present (scancode set 1 confirmed), mouse present (id 0x03, 4 byte packets)
[OK] PS/2 INPUT: keyboard IRQ1 + mouse IRQ12 unmasked (translation off)
[OK] FRAMEBUFFER SELF-TEST: 4 corner pixels written and read back through the aperture
[OK] GUI DISPLAY SERVER: 3072 KiB backbuffer, 8 window slots, 100 ms fixed refresh
[OK] GUI SCROLLBACK: 13 lines of log held behind a 34 line tile (0 lines of backscroll), PgUp/PgDn + Home/End + wheel scroll the focused window
[OK] STACK GUARD: 4 KiB poison band intact, compositor peak 5920 bytes of 262144
```

The screen shows the top status bar, the `KELLER SHELL` tile mirroring COM1, the vault tile with
its red `[PANIC: ZERO VAULT & HALT]` affordance and the subsystem tile. `gui` prints the
frame/blit counters, `gui test` proves the aperture and backbuffer agree, `gui off` returns to a
serial-only console. `input` reports what the controller, the decoders and the focus routing are
doing, and `input test` proves the decoders against synthetic traffic; the keyboard and mouse
reach the guest through the emulated PS/2 controller, so in a QEMU window a click focuses the
tile under the pointer, the wheel scrolls the tile under it and `Alt + Tab` cycles focus. Capture
and check a frame (30 pixel-level assertions against
[`GUI_SPECIFICATION.md`](GUI_SPECIFICATION.md)):

```powershell
python dev-tools\qemu_check.py --vga std --secs 42 --stdin-script target\gui-input.txt --screendump target\gui.ppm
python dev-tools\verify_gui.py --ppm target\gui.ppm --png target\gui.png --html target\gui-preview.html --cursor 300,300
```

Input can also be injected end to end, which is how the input evidence in
[`GUI_SPECIFICATION.md`](GUI_SPECIFICATION.md) is produced - here the pointer is aimed at the
`KELLER VAULT` tile and clicked, then a command is typed at whichever window ended up focused:

```powershell
python dev-tools\qemu_check.py --vga std --secs 42 --stdin-script target\gui-input.txt `
    --type "input\n" --mouse 128,-184 --click left --mouse=-340,100 --click left

# The wheel, end to end: five notches away from the user with the pointer over the shell tile.
# The guest has to show the five notches in its own counters *and* a view off the live tail.
python dev-tools\qemu_check.py --vga std --secs 60 --wheel 5 `
    --expect "[OK] PS/2 MOUSE WHEEL: IntelliMouse negotiated"
```

Injection runs verify themselves: the harness asks the guest for its PS/2 counters before and
after the phase and requires them to account for exactly what it sent, so a run can no longer
pass because the input silently went nowhere. Wheel notches are held to a second, stronger
standard than the device bytes they arrive as - the display server's own `[GUI] scroll:` line has
to show the same notch count, at least one gesture that moved something, and a focused view that
is no longer at the live tail - because a decoder with the wheel's sign inverted scrolls the
history backwards and looks perfectly healthy while doing it. Scripted console lines are acknowledged the same
way - each one is typed a byte at a time and has to be echoed back before the next goes out, since
the guest's UART drops whatever arrives while it is busy, and a line that did not come back is
retried only after the partial prefix has been erased (a retry appended to half a command would be
a different command entirely). Run `--no-input-check` to skip the counter check, and use
`--qemu-arg` to vary the emulated hardware, e.g. `--qemu-arg=-machine --qemu-arg=pc,i8042=off`
to prove the check really fails when there is no PS/2 controller to deliver the events. That
machine gets an honest guest rather than a noisy one: the presence probes count nothing, and
with the self-test failed and no aux port the driver prints a single
`[--] PS/2 CONTROLLER ABSENT` line, registers no IRQ and never reads `0x64`/`0x60` again, so
`input` shows `present=false` and zero bytes instead of a stream of phantom `0xFF` reads.

The other half of the same question - the controller answers, but is anything behind its two
ports? - is answered by the devices themselves rather than by the controller's tests: boot
prints `[OK] PS/2 DEVICES: keyboard present (scancode set 1 confirmed), mouse present (id 0x03,
4 byte packets)` only when the keyboard ACKed its bring-up commands (`0xF0 0x01` / `0xF4`) and
the mouse followed its `0xF2` ACK with an id byte, and `input` adds
`[PS2] devices: keyboard=present mouse=present keyboard-irq=unmasked mouse-irq=unmasked`. A
silent port flips that line to `[--]` and `input test` names the missing device, because its
assertions cover the decoders and the focus policy, not a dead port. Nothing is wired up for a
device that never answered: IRQ1 is masked when the keyboard is silent, IRQ12 is never unmasked
without a mouse. QEMU can only remove the whole 8042 (`i8042=off`), never one device behind it,
so a controller with a dead keyboard or mouse has to be reproduced on real hardware - it will
print the same three boot lines there, with `ABSENT` in place of `present`.

### Step 5: Put the Vantablack Mesh on a Real Wire

QEMU's default machine already has an Intel 82540EM on `00:03.0`, so the driver is exercised by
every run above. With an adapter on the bus, boot says:

```text
[ETH] framing: ethernet+ipv4+udp, headers=42 bytes, payload<=576 (a datagram is 42-618 bytes, so nothing here needs fragmentation)
[ETH] profile: guest 10.0.2.15, gateway 10.0.2.2 mac=52:55:0a:00:02:02, mesh-port=0x4b4c probe-port=0x4b4d
[OK] NETWORK ADAPTER: 00:03.0 8086:100e (82540EM) bar0=0xfebc0000 (128 KiB) bus-master on, mac=52:54:00:12:34:56
[OK] NIC DMA RINGS: tx 8/8 rx 8 descriptors of 16 bytes (16 x 4 KiB buffers, identity-mapped frames), link=up 1000 Mb/s full-duplex
[OK] NIC SELF-TEST: 47 assertions passed, 0 failed (framing + register readback)
[OK] NIC LINK: up, egress on - the mesh's sealed frames now leave the machine
```

From the shell, `nic` reports the registers, the counters and the shape of the last frame it
refused, `nic test` re-runs the 47 assertions, `nic probe` sends one fixed datagram a wire observer
can recognise, and `nic on` / `nic off` gate the wire in both directions:

```text
[SH] NIC 00:03.0 8086:100e (82540EM) bar0=0xfebc0000 (128 KiB) mac=52:54:00:12:34:56 link=up 1000 Mb/s full
[SH]      registers: ctrl=0x00141a40 status=0x80080783 rctl=0x0400803a tctl=0x000400fa rdlen=128 tdlen=128 rdh=3 rdt=2 tdh=3 tdt=3 eecd=0x188
[SH]      traffic: tx=3 (178 bytes, 0 errors) rx=3 (252 bytes) mesh-in=0 probe-in=0 foreign=0 errors=0
[SH]      arp: requests=1 replies=1 ignored=0 (answering requests for 10 is what makes this endpoint reachable)
[SH]      last-refused: 2 frame(s), last 96 bytes reason=not-udp ethertype=0x0800 ip-proto=1
[SH]      wire: 10 -> 10 port 0x4b4c/19277 , 618-byte datagrams, egress on , interrupts masked (polling)
[NIC] counters: tx=3 rx=3 mesh=0 probe=0 foreign=0 malformed=0 fragmented=0 not-ipv4=0 not-udp=2 bad-checksum=0 arp-requests=1 arp-replies=1 arp-ignored=0 rx-errors=0 tx-errors=0 dma-frames=16
```

The counters are the point: `tx` moves every time the mesh decides to send something, `mesh` and
`probe` say which port a received datagram arrived on, and every frame the driver would not hand on
is counted under the reason it was refused (`foreign`, `not-ipv4`, `not-udp`, `bad-checksum`,
`fragmented`, `malformed`) rather than disappearing. The heartbeat carries them too
(`wire-tx=`, `wire-rx=`, `wire-mesh=`, `wire-refused=`).

Read that last block as a sequence: the guest transmitted three datagrams, slirp answered its ARP
request (so the endpoint is reachable at all), and the two frames that came back were ICMP
port-unreachable messages — counted as `not-udp`, with the last one's shape recorded (`96 bytes,
ethertype=0x0800, ip-proto=1`) instead of silently dropped. That record is why it exists: a counter
alone would have said "2 frames refused" and left the reason to guesswork, and an earlier build
proved the cost of that — with ARP unanswered, the frames that did arrive were all folded into
`malformed`, which reads like a parser bug and was in fact a peer being ignored.

That is still the guest talking about itself. To check it from the other end of the cable, this
boots the kernel with the default NIC replaced by a QEMU socket peer, so the only station on the
segment is the tool:

```powershell
python dev-tools\wire_check.py --secs 130
```

It validates every frame the guest transmits against the RFCs and against the Vantablack geometry,
requires a frame it *typed* (`nic probe`) to match one it builds itself byte for byte, injects a
ledger of frames that should each be refused for a different reason and requires the guest's own
counters to move by exactly the predicted amount, checks that the mesh - not just the driver -
refuses the replayed and tampered ones, and re-reads its own pcap:

```text
PASS the guest's probe frame is byte-identical to this tool's independent build
PASS the mesh's own sealed frames cross the wire (12 seen)
PASS one message is carried by one frame per shard index ([0, 1, 2])
     guest deltas: {'rx': 9, 'mesh': 2, 'foreign': 2, 'malformed': 1, 'fragmented': 1, 'not_udp': 1, 'bad_checksum': 1, 'arp_requests': 1, 'arp_replies': 1, ...}
PASS the mesh counted the replayed frame as a replay (1)
PASS the mesh counted the fresh-counter edit as a tampered shard (1)
     wire summary: 14 frame(s) seen (mesh=12 probe=1 arp=1)
wire: PASS
```

The design, the descriptor-ring rules that were bugs first, and what is deliberately still missing
(the driver is ring 0, receive is polled, there is no IOMMU or bounce-buffer split for a ring-3
driver yet) are in [`NIC_WIRE.md`](NIC_WIRE.md).

### Step 6: Prove Ring-3 Isolation, Address Spaces and Preemption

Every boot runs one ring-3 task before the shell comes up, because the privilege boundary is the
claim the rest of the microkernel argument rests on and this machine is the only thing that can
check it. It costs about one timer tick:

```text
[--] RING-3 PROGRAM 'keller-hello' 36 bytes: b8 01 00 00 00 48 be 00 10 00 00 40 00 00 00 ba 2c 00 00 00 cd 80 b8 00 00 00 00 bf 00 00 00 00 cd 80 eb fe
     entry 0x4000000000, stack top 0x4000100ff0, data 0x4000001000, kernel cr3=0x263000
[R3 keller-hello] RING-3 HELLO: this line was printed at CPL=3
[OK] RING-3 ENTRY: 'keller-hello' ran at CPL=3 - the CPU's own frame says cs=0x1b ss=0x23, cr3=0x5b9000 (iretq restored a user frame, not a kernel one)
[OK] RING-3 EXIT: state=exited 2 syscalls, 1 switch-ins, 1 ticks, exit code 0 - parked rip=0x4000000022 (inside its own code page)
[OK] RING-3 PROBE COMPLETE: address space torn down, paging frames 0 -> 0, kernel cr3=0x263000 restored
```

The middle line was produced by the task itself, at CPL 3, through the one DPL-3 gate; `cs=0x1b`
in the entry line is read out of the frame the *CPU* pushed, not out of a flag the kernel set; and
`paging frames 0 -> 0` is the teardown accounting — the probe leaves the heap exactly as it found
it. `ring3` prints the live process table with each row's `cr3` and its per-virtual-address frames,
`ring3 test` reports 40 assertions (gate privilege, GDT DPLs, I/O-bitmap denial, frame-layout
agreement with `InterruptFrame`, address-space separation, and one live entry into ring 3), and
`ring3 run` delivers 24 ring-3 slices across five sandboxed tasks:

```text
[!!] RING-3 CONTAINMENT: 'sandbox-port' #GP general protection (vector 13, error=0x0) at rip=0x0000004000000005 cs=0x1b - task terminated, kernel intact
     raw port I/O at CPL 3: the TSS I/O permission bitmap denies every port, so the CPU raised #GP before any kernel handler ran
[R3 sandbox-peer] write(0x100000, 8) refused: EFAULT (not a user page of this address space)
[!!] RING-3 CONTAINMENT: 'sandbox-peer' #PF page fault (vector 14, error=0x4) at rip=0x0000004000000011 cs=0x1b - task terminated, kernel intact
     fault address 0x0000004000200000 is not mapped in cr3=0x5f5000: the page tables refused a read this address space does not allow
[OK] PREEMPTIVE SCHEDULER: 28 switches by the timer, 10 voluntary yields, 26 ring-3 slices delivered in 185 ticks (1850 ms) - each slice ended by the timer unless the task yielded first
[OK] RING-3 PREEMPTION PROOF: 'spin-probe' (jmp $) got the CPU 8 times with 0 syscalls and parked at rip=0x4000000000 - it never asked to be scheduled, so only the timer could have taken the CPU for it
[OK] RING-3 FAULT CONTAINMENT: 2 task(s) killed at CPL 3 (1 #PF, 1 #GP), 1 copy-from-user call(s) refused with EFAULT, timeout=no - no kernel lockdown, the idle loop keeps its heartbeat
[OK] RING-3 PHASE COMPLETE: 5 processes retired, address spaces torn down, paging frames back to 0, kernel cr3=0x263000
```

Read as a set: a task whose program is two bytes of `jmp $` lost the CPU eight times without ever
making a syscall (the timer did that, not cooperation); a driver that only ever asked for port I/O
*through the kernel* was granted it, while the same instruction executed directly got `#GP` from
the CPU before any handler ran; a process that read its neighbour's page was stopped by its own
page tables (`error=0x4`: user mode, not present, read); and the shell answered `status` afterwards,
which is what "the kernel is still alive" has to mean. The full design — layout, the 432-byte
parked-frame contract, why every gate's IST makes the switch cheap, and what is deliberately still
missing — is in [`RING3_ISOLATION.md`](RING3_ISOLATION.md).

```powershell
python dev-tools\qemu_check.py --vga std --secs 30 --stdin-script target\ring3-input.txt `
    --expect "[SH] RING-3 PROBE assertions: 40 passed, 0 failed" `
    --expect "[OK] RING-3 PREEMPTION PROOF: 'spin-probe' (jmp $) got the CPU" `
    --expect "[OK] RING-3 FAULT CONTAINMENT: 2 task(s) killed at CPL 3 (1 #PF, 1 #GP)" `
    --expect "[OK] RING-3 PHASE COMPLETE: 5 processes retired, address spaces torn down, paging frames back to 0" `
    --expect "[SH] RING-3 ROWS: 1/8 used" `
    --forbid "LOCKDOWN" --forbid "unknown syscall" --forbid "state=ready" --forbid "idle_armed=true"
```

The forbids are the interesting half: `unknown syscall` catches an ABI mismatch between the user
programs and the door, `state=ready` catches a phase that armed tasks and never finished them,
`idle_armed=true` catches preemption left enabled after the phase, and the frame count returning to
zero catches a leaked page table. `LOCKDOWN` there would mean a ring-3 fault took the kernel down
instead of being contained, which is the whole thing this path exists to prevent.

### Step 7: Prove the Vault Survives a Power Cycle

Attach a disk and the vault stops being a heap allocation. The controller, the disk it found and
the verdict on the image are printed at boot, and the format is checked against the block layer's
in-memory reference device on every machine — including one with no disk at all, where the same
lines end in `[--]` and the vault stays in RAM:

```text
[OK] STORAGE CONTROLLER: 00:04.0 8086:2922 AHCI 256 (6 ports implemented, 1 device(s) identified)
[OK] STORAGE DEVICE: port 0 model="QEMU HARDDISK" fw="2.5+" serial="QM00005" 32768 sectors (16 MiB, 512-byte logical sectors) LBA48
[--] VAULT IMAGE: "QEMU HARDDISK" has 32768 sectors and no vault image on it (`disk format` writes one)
[OK] VAULT FORMAT SELF-TEST: 25 assertions passed, 0 failed (block layer, proof gate, image format, journal - on the reference device)
[OK] DISK SELF-TEST: 20 assertions passed, 0 failed (registers, port geometry, scratch round-trip)
```

With an image on the disk, the next boot authenticates it before adopting a single record, and
says where the counter it reads back came from:

```text
[OK] VAULT IMAGE: generation 3 owner=4f64bd803599f372 slots=8 nonce=13a52e78ba12e7d1 on "QEMU HARDDISK" (32768 sectors)
[OK] VAULT RESTORE: 2 sector(s) adopted from the image, generation 3
[OK] DISK JOURNAL: boots=1 stamp=5c6d2ba85ee9460ef5473883e739cdb7 (a counter only the medium could have kept)
```

`disk write <text>` puts a sector in the vault and saves the image, `disk read` opens it again,
`disk journal` advances a counter that lives on the platter, and `disk superblock` prints the
superblock as it is on the device right now, for an independent reader to compare against:

```text
[SH] DISK: formatted generation 1 slots=8 owner=feb5a8febf6879c8 nonce=13a52e78ba12e7d1
[SH] DISK: wrote 18 bytes to sector 0x55534552, generation 2
[SH] DISK USER SECTOR: 18 byte(s): "KELLER-OS PERSISTS"
[SH] DISK JOURNAL: boots=1 image-generation=3 stamp=5c6d2ba85ee9460ef5473883e739cdb7
[SH] DISK PROBE assertions: 88 passed, 0 failed
```

Persistence cannot be proved inside one process, so the harness runs two emulators against one
image file: the first formats, writes a marker and advances the journal; the second is a power
cycle as far as the guest can tell, and has to read the marker back byte for byte and arrive at
`boots=2` with the *same* stamp.

The two console scripts are line lists: `target\disk-a.txt` holds `disk test`, `disk format`,
`disk write KELLER-OS PERSISTS`, `disk read` and `disk journal`; `target\disk-b.txt` holds
`disk read`, `disk journal` and `disk superblock`.

```powershell
& "C:\Program Files\qemu\qemu-img.exe" create -f raw target\vault.img 16M
python dev-tools\qemu_check.py --vga std --secs 60 --stdin-script target\disk-a.txt --stdin-delay 6 `
    --qemu-arg=-device --qemu-arg=ich9-ahci,id=ahci `
    --qemu-arg=-drive --qemu-arg=id=vdisk,file=target\vault.img,if=none,format=raw `
    --qemu-arg=-device --qemu-arg=ide-hd,drive=vdisk,bus=ahci.0 `
    --expect "[OK] STORAGE DEVICE: port 0 model=\"QEMU HARDDISK\"" `
    --expect "[SH] DISK PROBE assertions: 88 passed, 0 failed" `
    --expect "[SH] DISK USER SECTOR: 18 byte(s): \"KELLER-OS PERSISTS\"" `
    --expect "[SH] DISK JOURNAL: boots=1" --forbid LOCKDOWN

python dev-tools\qemu_check.py --vga std --secs 60 --stdin-script target\disk-b.txt --stdin-delay 6 `
    --qemu-arg=-device --qemu-arg=ich9-ahci,id=ahci `
    --qemu-arg=-drive --qemu-arg=id=vdisk,file=target\vault.img,if=none,format=raw `
    --qemu-arg=-device --qemu-arg=ide-hd,drive=vdisk,bus=ahci.0 `
    --expect "[OK] VAULT RESTORE: 2 sector(s) adopted from the image, generation 3" `
    --expect "[SH] DISK USER SECTOR: 18 byte(s): \"KELLER-OS PERSISTS\"" `
    --expect "[SH] DISK JOURNAL: boots=2" --forbid LOCKDOWN
```

Then read the medium from the *outside*, which is the half the guest cannot do for itself: the
image is parsed with a second implementation of the layout, and the marker has to be nowhere in it.

The same tool catches the cases that should fail - a planted plaintext, a reused record nonce - and
it is what turns "the vault is encrypted at rest" from a claim in a document into a byte-level fact:

```powershell
python dev-tools\disk_check.py --img target\vault-a.img --later target\vault.img `
    --marker "KELLER-OS PERSISTS" --from-log target\disk-run-b.log
```

```text
disk: two boots: generation 3 -> 4, 2 -> 2 record(s), same device nonce, every shared slot rewritten
disk: cross-check: the guest's own read of the superblock agrees with this parse (generation 4, 8 slots, nonce 13a52e78ba12e7d1...)
disk: image: PASS - 75 assertion(s) passed, 0 failed
        (image geometry, record framing, no repeated nonces, no plaintext on the medium)
```

A single flipped byte in a record is refused at boot rather than adopted, and it does not take the
kernel down with it — a disk that has been edited is a storage failure, not a reason to halt:

```text
[!!] VAULT RESTORE: refused (record-tampered)
```

The format, the proof gate that derives the key, the seven bugs verification caught (a 24-byte PRDT
entry that should be 16, a `PRDTL` written as "count minus one", a record header declared shorter
than the nonce it holds, and a proof taken over a header that then changed) and the honest limits —
a rollback is not detectable without a trusted counter, a power cut mid-save is a refusal rather
than a recovery, and the driver is still ring 0 — are in
[`STORAGE_PERSISTENCE.md`](STORAGE_PERSISTENCE.md).

### Step 8: Run a Bootable ISO Image (built elsewhere)
The repository ships no ISO: it is a build product and is gitignored (`*.iso`). Build one
where the GRUB tools exist (section 6), then boot it:
```bash
qemu-system-x86_64 -cdrom sovereign.iso -serial stdio -display none
```
> **Note:** the `-kernel` runs above are the path the harness exercises; an ISO only adds a
> GRUB stage in front of the same PVH entry point.

### Step 9: Emulate with Bochs (Cycle-Accurate Hardware Emulation)
```bash
bochs -f dev-tools\bochsrc.txt
```

---

## 6. How to Package a New Bootable ISO Image

When you modify the kernel and want to generate a fresh `sovereign.iso` (on a machine with
GRUB tooling - the artifact is gitignored, so it stays on your machine):

1. Build the release kernel binary:
   ```bash
   cargo build -Zjson-target-spec --release
   ```
2. In a Linux/WSL2 environment with GRUB utilities:
   ```bash
   mkdir -p isofiles/boot/grub
   cp target/x86_64-sovereign_core/release/sovereign-core isofiles/boot/
   cp boot/grub/grub.cfg isofiles/boot/grub/
   grub-mkrescue -o sovereign.iso isofiles/
   ```

---

## 7. License

Licensed under the [MIT License](LICENSE).  
Copyright &copy; 2026 KELLER SYSTEMS. All rights reserved.
