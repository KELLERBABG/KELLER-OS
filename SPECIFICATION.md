# KELLER-OS: System Architecture & Engineering Specification
**Document ID:** KOS-SPEC-2026-V2.5  
**Version:** 2.5.0  
**Classification:** High-Assurance Sovereign Microkernel & Hypervisor  
**Standard Compliance:** seL4-Class Microkernel, Capability-Based Security, Anti-Forensic Zero-Trust  
**Target Architecture:** `x86_64-sovereign_core` (`no_std`, bare-metal)

---

## 1. Executive Summary & Vision

**KELLER-OS** is an open-source, mathematically disciplined, sovereign bare-metal microkernel engineered for zero-trust, hostile-environment computing. Rooted in the principles of formal verification, capability-based security, and anti-forensics, KELLER-OS is designed to operate under the assumption that the physical machine, peripheral hardware, and external network are inherently compromised.

### Core Tenets
1. **Minimal Privileged Footprint:** Less than 10,000 lines of code execute in Ring 0. Drivers, networking, file storage, graphics, and shells run exclusively in isolated Ring 3 userspace tasks.
2. **Zero Ambient Authority:** There is no "root" or superuser. Every process must possess an unforgeable, cryptographically signed capability token to interact with any hardware port, memory page, or IPC endpoint.
3. **Anti-Forensic Resilience:** Physical cold-boot attacks, liquid nitrogen memory dumping, and bus snooping are countered through sector-level RAM encryption, DMA air-gapping, and millisecond panic-zeroing.
4. **Side-Channel Immunity:** System calls, process scheduling, and network packet dispatch operate on deterministic fixed-slot time quanta to defeat timing side-channel attacks (Spectre/Meltdown variants).
5. **Post-Quantum & Zero-Knowledge Cryptography:** Integration of post-quantum lattice cryptography (Kyber-512) alongside classical Edwards-curve primitives (Ed25519, X25519) and zero-knowledge Schnorr identification.

---

## 2. Threat Model & Security Guarantees

KELLER-OS is engineered to defend against high-tier adversaries possessing physical access, hardware bus taps, or supply-chain exploitation capabilities:

```
+--------------------------------------------------------------------------+
|                            ADVERSARY MATRIX                              |
+--------------------------------+-----------------------------------------+
| Threat Vector                  | KELLER-OS Defense Mechanism             |
+--------------------------------+-----------------------------------------+
| Cold-Boot Memory Extraction    | Symmetrical RAM Sector Encryption       |
| (Liquid Nitrogen / RAM Dump)   | (ChaCha20/Poly1305) + Panic-Zeroing     |
+--------------------------------+-----------------------------------------+
| Rogue Peripheral DMA           | Dedicated Air-Gap isolation; SDR drivers|
| (Malicious PCIe / USB / SDR)   | run in Ring 3 without direct DMA access |
+--------------------------------+-----------------------------------------+
| Timing Side-Channel Analysis   | Temporal Isolation via Fixed-Slot       |
| (Spectre, Meltdown, Cache leaks| deterministic round-robin scheduling    |
+--------------------------------+-----------------------------------------+
| Privilege Escalation Exploits  | Capability-Based Tokens; absence of     |
| (Memory corruption / Buffer OF)| ambient authority; hardened userspace   |
+--------------------------------+-----------------------------------------+
| Stored Credential Compromise   | Zero-Knowledge Schnorr Identification   |
| (Disk hashes / Passwords)      | (No passwords or hashes stored on disk) |
+--------------------------------+-----------------------------------------+
| Duress / Physical Coercion     | Honey-Pot Decoy Authentication Mode     |
|                                | (Launches sterile, unlinked sandbox)    |
+--------------------------------+-----------------------------------------+
```

---

## 3. Microkernel Core Architecture (Ring 0)

The microkernel core resides in [`src/main.rs`](src/main.rs), [`src/boot.rs`](src/boot.rs) (the 32-bit bootstrap, page tables and boot headers are one `global_asm!` block - there is no separate `boot.s`), and [`src/linker.ld`](src/linker.ld).

```
                      +-----------------------+
                      |   RING 0: MICROKERNEL |
                      |                       |
                      |  * SovereignAllocator |
                      |  * GDT / IDT Setup    |
                      |  * Capability Gate    |
                      |  * Fixed-Slot Sched   |
                      |  * Panic Zero-Wipe    |
                      +-----------+-----------+
                                  | Verified Synchronous IPC
          +-----------------------+-----------------------+
          |                       |                       |
+---------v---------+   +---------v---------+   +---------v---------+
|      RING 3       |   |      RING 3       |   |      RING 3       |
|   Keller Vault    |   |    Keller Net     |   |    Keller GUI     |
| (Sector Crypto)   |   |  (Salted MAC IPC) |   |  (Display Server) |
+-------------------+   +-------------------+   +-------------------+
```

### 3.1 Memory Management: The `SovereignAllocator`
* **Static Over Dynamic:** Dynamic heap usage is strictly contained. Unbounded allocation in the critical path is prohibited to avoid heap fragmentation and Out-of-Memory (OOM) denial-of-service vulnerabilities.
* **Lock-Free Linked-List Allocator:** Implemented via atomic pointer swaps (`AtomicPtr<FreeBlock>`, `AtomicBool`) avoiding blocking mutexes in interrupt contexts.
* **Deterministic Layout:** Memory addresses are bound to defined linker sections:
  * `.text`: Executable instructions (`__text_start` to `__text_end`).
  * `.rodata`: Immutable constants and pre-baked bitmap fonts.
  * `.data`: Initialized kernel data structures (page-aligned).
  * `.bss`: Zero-initialized heap and stack (`__bss_start` to `__bss_end`).

### 3.2 Interrupt Descriptor Table (IDT) & GDT
* Configures 256 interrupt gates with dedicated kernel stack segments (IST - Interrupt Stack Table).
* Interrupts are separated into architecture-level exceptions (Divide Error, Page Fault, General Protection Fault) and software IPC dispatch gates (`int 0x80`).
* **`int 0x80` is the only DPL-3 gate in the table** (`attributes = 0xEE`; every other vector is `0x8E`). It is the ring-3 syscall door, and the frame it delivers carries `cs = 0x1B` — the CPU's own evidence that the caller ran unprivileged. Being the only way in is what makes the boundary a boundary rather than a convention.
* **GDT privilege levels are read back, not assumed:** the table carries DPL-3 code (`0x1B`) and data (`0x23`) selectors, and the TSS I/O permission bitmap base sits beyond the TSS limit so the CPU denies every `in`/`out` from ring 3 (`gdt::port_io_denied()`).
* **Exception dispatch branches on the faulting frame's `cs`.** From ring 3 a fault is contained: the task is marked faulted, the fault is reported with vector/error/`rip`/`cr3` (and `cr2` for `#PF`), the next runnable task is resumed and the dead task's address space is returned to the heap — no lockdown. From ring 0 the panic handler still intercepts unrecoverable exceptions and executes panic-zeroing before the CPU halts.

### 3.3 Scheduler: Fixed Slots for the Kernel, Preemption for Processes
* Avoids standard priority-decay or heuristic schedulers that leak execution profiles.
* **Kernel maintenance slots** are scheduled in **deterministic, fixed time-slots**; if a slot finishes early, the remainder is padded with constant-time dummy instructions, eliminating cycle-count leakage.
* **Ring-3 processes are preempted, not cooperated with** ([`src/proc.rs`](src/proc.rs)). The switch happens inside the timer interrupt, where the CPU has already saved the interrupted task's registers: the 256-byte XMM block plus the 176-byte CPU/stub frame is parked into the outgoing row, the incoming row's parked frame is handed to the shared ISR epilogue, and the epilogue loads it as `rsp` and resumes it by `iretq` — one restore path for every switch, whether it was a quantum expiring, a task exiting, or a task being killed for faulting.
* A task that never calls a system call cannot hold the machine: `spin-probe` (a two-byte `jmp $`) loses the CPU every quantum with zero cooperation. Kernel work is never preempted — only the idle context, and only between `arm_idle`/`disarm_idle`, which bracket the idle loop's `hlt`.
* Voluntary yields are counted separately from timer switches, because the difference between them is the difference between an obedient driver and a preemptive scheduler.

### 3.4 Paging & Address Spaces (Hardware Isolation)
* **One PML4 per process**, built by [`src/arch/paging.rs`](src/arch/paging.rs) on top of the boot tables that `paging::init` reads back out of `cr3`. `cr3` is switched in the same function as the context switch, so a resumed task always runs on its own tables.
* **`SpaceA ∩ SpaceB = ∅` is a hardware property.** Every space copies the kernel's identity map into its `PDPT[0..4]` with U/S = 0 (so kernel code, heap and framebuffer stay reachable *in* that space and unreachable *from* it), and gives the process its own pages at 256 GiB — a region the boot identity map leaves empty. Two processes therefore use identical virtual addresses and reach different frames; a cross-space read is a not-present `#PF`, not a permission the kernel had to check.
* **Frames come from the kernel heap**, which is inside the identity map: a frame's address is at once the kernel's pointer and the CPU's physical address, so there is no shadow allocator to keep in sync. Teardown returns every leaf and every table — the PML4 included — and reports the frame count so a leak is visible.
* **User pointers are never trusted.** `AddressSpace::copy_from_user` walks the *caller's* tables, requires U/S = 1 at every level and copies through the identity map, so a kernel address passed to the syscall door comes back as `EFAULT`.
* **The syscall door is a whitelist**, not a dispatcher: `exit`, a length-capped `write`, `yield`, `progress` and one mediated `port_write` to the single port in the capability table (`0x80`). Everything else returns `EFAULT` and says so.
* **Layout:** code `0x4000000000` (present, user, not writable), data `0x4000001000`, stack `0x4000100000`, plus an optional peer window `0x4000200000` mapped in exactly one space. Full detail, including the 432-byte parked-frame contract and the verification matrix, is in [`RING3_ISOLATION.md`](RING3_ISOLATION.md).

---

## 4. Subsystem Specifications

### Subsystem I: `Keller Vault` (Memory Encryption & Panic-Zeroing)
* **Location:** [`src/vault.rs`](src/vault.rs), [`src/crypto.rs`](src/crypto.rs)
* **Persistence:** [`src/storage.rs`](src/storage.rs) (the image), [`src/arch/ahci.rs`](src/arch/ahci.rs) (the AHCI/SATA controller), [`src/block.rs`](src/block.rs) (the sector layer and its in-memory reference device), [`src/zk.rs`](src/zk.rs) (the proof that gates the image's key) — design, format and verification in [`STORAGE_PERSISTENCE.md`](STORAGE_PERSISTENCE.md).
* **Specification:**
  1. **Sector Encryption:** Implements in-memory sector encryption utilizing ChaCha20-Poly1305 / AES-XTS. RAM pages are encrypted with ephemeral session keys derived at boot.
  2. **Atomic Panic-Zeroing:** When a tamper sensor or panic interrupt fires, the `panic_handler` performs a multi-pass write of `0x00`, `0xFF`, and cryptographically pseudo-random bytes across:
     * All registered `KellerVault` sector buffers.
     * The kernel heap and stack space.
     * Active video framebuffers.
     * CPU registers (cleared via assembly `xor` before `cli; hlt`).
  3. **Persistent Vault Image (implemented):** sealed sectors are written to a real disk as an image with a superblock and one record per slot, and read back at boot. The disk key is *not* stored: it is derived from a Schnorr proof over the header that is on the medium (`HKDF-SHA256` salted with the image's device nonce), so the medium holds no secret, no shard of one, and no hash to test guesses against — only the group commitment `X`. A wrong secret, an edited header and an edited record are three distinct refusals, and none of them yields a key. Every save increments a generation bound into each record's AAD (so a mixture of two saves cannot load) and a journal sector carries a counter and a random stamp that only the medium could have kept.

### Subsystem II: `Keller Net` & Vantablack (Sovereign WAN Mesh & Native Internet Access)
* **Master Specification:** [`VANTABLACK_INTEGRATION.md`](VANTABLACK_INTEGRATION.md)
* **Reference Implementation:** [KELLERBABG/Vantablack](https://github.com/KELLERBABG/Vantablack)
* **Location:** [`src/net.rs`](src/net.rs), [`src/session.rs`](src/session.rs)
* **Specification:**
  1. **Zero-Leak Native Internet Layer:** Direct, unencrypted TCP/IP to commercial ISP gateways is prohibited. [Vantablack](https://github.com/KELLERBABG/Vantablack) serves as the native sovereign internet access engine, encapsulating all external traffic into multi-path, erasure-sharded privacy frames.
  2. **Asymmetric Shard Routing:** Payloads are split via Reed-Solomon $\text{RS}(2,1)$ and Shamir Secret Sharing (2-of-3) across divergent WAN carrier routes. Any 2 shards reconstruct pristine plaintext without retransmissions.
  3. **ShardSec & Byzantine Tamper Isolation:** Individual shards are authenticated via HKDF-Poly1305 tags (`ShardSec`, one subkey per shard index, frame header and entropy tail bound as associated data), the message itself carries an HMAC tag so a reconstruction is authenticated end to end, and combinatorial pairwise verification isolates malicious or corrupted intermediary nodes. Replay windows are per peer, and a route that trips the tamper budget is severed until recalculation rehabilitates it.
  4. **Anti-Traffic Analysis:** Every frame is exactly a 576-byte wire envelope — 33-byte share, 8-byte counter, ShardSec record and a 16..64-byte hardware-entropy tail that is itself authenticated as associated data — and idle links are filled with Poisson-distributed decoy frames (`CoverTraffic`, one Bernoulli trial per tick, λ = 0.2 frames/s by default) so packet size and silence both stop being signals. `net [test]` in the shell prints the live mesh state and re-runs the probe.
  5. **Air-Gap DMA Protection:** SDR (Software Defined Radio) and physical NICs operate in Ring 3 without direct kernel DMA access. Peripherals write strictly into isolated bounce buffers.

### Subsystem III: `Keller Auth` (Zero-Knowledge Identity & Capabilities)
* **Location:** [`src/session.rs`](src/session.rs), [`src/crypto.rs`](src/crypto.rs)
* **Specification:**
  1. **Schnorr Zero-Knowledge Identification:** Proof of identity is established without transmitting private keys, passwords, or hashed credentials. The prover demonstrates knowledge of a discrete logarithm over Curve25519:
     $$\text{Prover chooses } r \leftarrow \mathbb{Z}_q,\; R = r \cdot G$$
     $$\text{Challenge } e = H(R \parallel M \parallel P)$$
     $$\text{Response } s = r + e \cdot x \pmod q$$
  2. **Capability Token Lifecycle:**
     * Tokens are cryptographically signed 128-bit descriptors containing permissions, object references, and expiration ticks.
     * Immediate revocation: When an anomaly or expiration occurs, the kernel scrubs the capability table entry and invalidates the session atomics.
  3. **Decoy (Honey-Pot) Authentication:** A designated secondary passphrase triggers a sterile sandbox environment. The system appears operational but isolates all vault storage and simulates dummy telemetry.

### Subsystem IV: `Keller Driver Sandbox`
* **Specification:**
  1. Hardware drivers (Storage, NIC, Framebuffer, Input) execute in Ring 3 tasks.
  2. All port I/O (`in`/`out` instructions) is mediated through kernel capability verification or hardware I/O permission bitmaps (TSS IOPB).
  3. Fault isolation: If a driver faults (e.g. invalid memory access), the microkernel isolates the offending PID, wipes its transient state, and relaunches the driver without impacting system uptime.
* **Implemented (this build):** 2 (both halves — the TSS bitmap denies every port from CPL 3, and `port_write` is the one mediated path, granted per call against a capability table) and 3 (a faulting ring-3 task is terminated, its address space is torn down, and the kernel keeps running; the fault is reported with the vector, error code, `rip` and `cr3`). Item 1's *substrate* is in place — real CPL-3 tasks, per-process PML4s, a syscall door and timer preemption — and the phase's `driver-alpha` is the shape a ported driver takes; the existing PS/2 driver, display server and shell still run in ring 0, because porting them without a per-capability API (and a `copy_to_user`) would be a slower kernel rather than a safer one. Relaunch after a fault is not there yet: a faulted task is retired, not respawned.

### Subsystem V: `Keller Shell` (Sovereign Interface)
* **Specification:**
  1. Text and graphical command interface requiring verified active Schnorr authentication tokens.
  2. Command dispatch executes under temporal isolation. Execution timing is padded to constant-time intervals to prevent keystroke or command length inference.

---

## 5. Graphical User Interface (GUI) Specification

* **Comprehensive Reference:** [`GUI_SPECIFICATION.md`](GUI_SPECIFICATION.md)
* **Design Philosophy:** Minimalist, brutalist, zero animations, fixed-slot deterministic refresh.

### 5.1 Video Mode Acquisition
* **Primary:** Multiboot2 Linear Framebuffer Tag (`type = 5`, optional) emitted from the `global_asm!` boot header in [`src/boot.rs`](src/boot.rs) (1024x768x32bpp) and parsed by [`src/bootinfo.rs`](src/bootinfo.rs) into `BootInfo::framebuffer`.
* **Fallback:** Bochs / QEMU VBE driver in [`src/fb.rs`](src/fb.rs), driven through the adapter's PCI region-2 MMIO bar at `+0x500` (the legacy `0x01CE`/`0x01CF` index/data pair is tried second - it does not answer on this QEMU build).
* **No-adapter path:** everything still boots; `main` prints `[--] NO DISPLAY ADAPTER (serial console only)` and the shell reports `display server offline`.
* **PCI enumeration:** [`src/pci.rs`](src/pci.rs) walks bus 0 (config space via `0xCF8`/`0xCFC`), sizes and assigns BARs, and prints `[OK] PCI SELF-TEST: configuration space round-trip verified` before the framebuffer probe runs.

### 5.2 Desktop Geometry & Subsystem HUD

The sketch below is the design target ([`KELLER OS.canvas`](KELLER%20OS.canvas)); the shipped
bring-up fills the same three panes from live subsystem state:

| Region | Shipped rectangle | Content |
| :--- | :--- | :--- |
| Top status bar | `1024x30+0+0` | version, `VAULT: READY/OFFLINE`, `NET: ACTIVE/IDLE/OFFLINE`, entropy source, `T+ms`, focus holder, `CUR x,y`, frame count and refresh rate |
| `KELLER SHELL` | `626x704+8+36` | kernel log mirror (the same bytes COM1 receives), as a 34-line view onto a 256-line ring - `PageUp`/`PageDown`, the wheel and `gui top|bottom|up|down` move it |
| `KELLER VAULT` | `372x366+644+36` | fingerprint, shard count/threshold, sealed state, sectors, writes, forged openings, `[PANIC: ZERO VAULT & HALT]` |
| `SUBSYSTEMS` | `372x330+644+410` | crypto KAT status, IPC delivered/dropped, session window, mesh peers/frames/refusals/cover, scheduler slots |
| Footer | `1024x22+0+746` | available commands, the live PS/2 counters and the bound chords (`alt+tab` focus, click to focus) |

The `Keller Auth` lockscreen remains unattached - there is no credential prompt in the
bring-up window set yet (see [`GUI_SPECIFICATION.md`](GUI_SPECIFICATION.md) §6).
```text
+--------------------------------------------------------------------------+
| [KOS v2.5] | VAULT: [LOCKED/AES] | NET: [ISOLATED] | IRQ: 0x20 | [PANIC] |
+------------------------------------+-------------------------------------+
|                                    |                                     |
|           KELLER SHELL             |          KELLER VAULT HUD           |
|                                    |                                     |
|  > kos-auth --status               |  Active Key: ED25519-PQC (KYBER512) |
|  [OK] ZK PROOF VERIFIED            |  Sector 00: ENCRYPTED (CHACHA20)    |
|  > vault list                      |  Sector 01: ENCRYPTED (CHACHA20)    |
|  [0x00] GGN/PEM MASTER CERT        |  RAM Scrub Trigger: ARMED           |
|  [0x01] PEER ROUTING TOKEN         |                                     |
|  > _                               |  [ PURGE & ZERO ALL MEMORY NOW ]    |
|                                    |                                     |
+------------------------------------+-------------------------------------+
```

### 5.3 Rasterizer & Font Subsystem
* Embedded 8x16 monospaced ASCII bitmap font in `.rodata` for zero-allocation text rendering: `FONT_8X16: [u8; 256 * 16]` in [`src/gui/font.rs`](src/gui/font.rs), baked by [`dev-tools/make_font.py`](dev-tools/make_font.py) from CascadiaMono.ttf (SIL OFL 1.1).
* Double-buffered backbuffer (3 MiB `Vec<u32>` in the heap) to eliminate tearing without GPU interrupts; only dirty rectangles are copied to the aperture.
* Fixed 100 ms refresh slot driven from the idle loop, so a repaint never runs in an interrupt and never allocates.
* Mask on panic ensures zero visual persistence on LCD/CRT panels (`fb::scrub_hook`); verified by capturing the screen after `panic` and finding all 786432 pixels black.
* Window slots carry owner PID, capability token and focus state ([`src/gui/mod.rs`](src/gui/mod.rs)), which is the contract the Ring-3 compositor will consume in place of the current Ring-0 bring-up.
* Network path: [`src/eth.rs`](src/eth.rs) builds and parses Ethernet/IPv4/UDP datagrams (the mesh runs on UDP `0x4B4C`, the driver's probe on `0x4B4D`), validates the IPv4 and UDP checksums against an independently generated known-answer vector, refuses fragments, IPv4 options, non-UDP protocols and length lies with a distinct reason each, and answers an ARP request for its own address - without which a peer that has to learn the MAC can never deliver anything, which is exactly what QEMU's user-mode network does. [`src/nic.rs`](src/nic.rs) drives the Intel 8254x (`e1000`): BAR0 via [`src/pci.rs`](src/pci.rs), EEPROM MAC, a reset-and-program sequence, 8+8 descriptors of 16 bytes with 4 KiB buffers each, and polling from the idle loop with every interrupt source masked. The rings and buffers are ordinary identity-mapped frames, so a descriptor's value is a pointer the driver can dereference; the state lives in `.data` (the loader does not zero `.bss`) and the rings are 128-byte aligned, both of which the self-test reads back out of the device. Counters classify every frame (`mesh`, `probe`, `foreign`, `not-ipv4`, `not-udp`, `bad-checksum`, `fragmented`, `malformed`, `arp-requests`, `arp-replies`) and the shape of the last frame that was not delivered is kept, so a refusal reason is evidence rather than a number. The driver is ring 0 today: a DMA-capable device behind a ring-3 task needs an IOMMU or the bounce-buffer split §3.1 describes, and neither exists yet ([`NIC_WIRE.md`](NIC_WIRE.md)).
* Storage path: [`src/arch/ahci.rs`](src/arch/ahci.rs) brings an AHCI controller out of reset, inspects every implemented port, and drives the device on the first port that answers `IDENTIFY DEVICE` — 48-bit LBA, `READ/WRITE DMA EXT`, one 4 KiB transfer frame per command, polled to completion with a bounded budget and every interrupt source masked. It refuses a device whose logical sector size is not 512 bytes rather than addressing 4 KiB sectors as if they were 512, and it reports the task file as the port came out of reset alongside any failure, because a fresh 512-byte ATA disk legitimately comes up reporting `DSC|DF` with `ABRT` set and that is not the driver's fault to blame on itself. [`src/block.rs`](src/block.rs) defines the sector interface and a `MemDisk` reference device, so the image format is exercised on machines with no disk at all; [`src/storage.rs`](src/storage.rs) owns the format, the superblock, the journal and the refusal reasons (`no-device`, `no-image`, `not-authenticated`, `header-tampered`, `record-tampered`, `device-error`, `bad-image`, `too-many-sectors`). `disk status|test|format|save|load|write <text>|read|journal|wipe|superblock` drive it from the shell, and a boot with an image on the disk prints `[OK] VAULT RESTORE: n sector(s) adopted from the image, generation g` after the proof and the MAC have both been checked; a refused image is a documented state that leaves the vault in RAM rather than a lockdown. The driver is ring 0 today, for the same reason the NIC is: a DMA-capable device behind a ring-3 task needs an IOMMU or the bounce-buffer split §3.1 describes ([`STORAGE_PERSISTENCE.md`](STORAGE_PERSISTENCE.md)).
* Input path: [`src/arch/ps2.rs`](src/arch/ps2.rs) owns the 8042 controller (self-test, config byte with translation off), decodes set-1 scancodes and three- or four-byte mouse packets on IRQ1/IRQ12 into 64-byte rings, and the idle loop drains them into `gui::route_key` / `gui::route_mouse`, which deliver to the focused window's capability; a keystroke aimed at a window that does not hold focus is dropped and counted, never queued. The mouse is negotiated up to **IntelliMouse** at bring-up (the `200, 100, 80` sample-rate sequence, so `0xF2` reports `id 0x03` and the fourth packet byte exists at all), which is what makes the wheel a real input rather than a byte the driver never sees; the wire format's nibble is signed the *other* way round from the direction the kernel publishes, so the decoder negates it once, at the byte (`-(s8)` is the same flip Linux's `psmouse` applies). A left click grants focus to the window under the pointer, `PageUp`/`PageDown`/`Home`/`End` and the wheel move the focused or pointed-at window's backscroll, and typing in the shell snaps its view to the live tail. `Alt + Tab` is consumed by the compositor, and `input status` / `input test` report and probe the whole path. A machine with no 8042 (`-machine pc,i8042=off`) is handled honestly rather than as a flood of phantom bytes: the presence probes count nothing, and when the self-test fails *and* the aux-port test finds nothing the driver declares the controller absent - one `[--] PS/2 CONTROLLER ABSENT` line at boot, no IRQ registered, and `service` / `drain` return before reading `0x64`/`0x60` again, so `input status` shows `present=false` with every counter at zero. Device presence is tracked separately from the controller's, because an 8042 that passes both of its own tests has still proved nothing about what is plugged into it: the keyboard counts as present only when it ACKs its bring-up commands (`0xF0 0x01` / `0xF4`) and the mouse only when the id byte follows its `0xF2` ACK. Boot prints the verdict per device (`[OK] PS/2 DEVICES: keyboard present (...), mouse present (...)`), `input` adds `[PS2] devices: keyboard=present mouse=present keyboard-irq=unmasked mouse-irq=unmasked`, and a silent device turns those into `[--]` / `absent` and is named by `input test` - no interrupt is wired for it either (IRQ1 is masked when the keyboard is silent, IRQ12 is never unmasked without a mouse). QEMU's only PS/2 switch is the whole controller (`i8042=off`), so that half-dead case is reproduced on real hardware; the boot lines are the same there, with `ABSENT` in place of `present`.

---

## 6. Cryptographic Architecture & Primitives

* **Comprehensive Master Reference:** [`CRYPTOGRAPHY_DEEP_DIVE.md`](CRYPTOGRAPHY_DEEP_DIVE.md)

KELLER-OS implements a multi-path global mesh cryptographic engine combining post-quantum lattice cryptography (Kyber-512), classical curve cryptography (Ed25519/X25519), pure-Rust constant-time ChaCha20-Poly1305 AEAD, Shamir secret sharing (2-of-3 threshold), and Reed-Solomon RS(2,1) erasure coding directly within [`src/crypto.rs`](src/crypto.rs):

```
+--------------------------------------------------------------------------+
|                      CRYPTOGRAPHIC SUITE OVERVIEW                        |
+---------------------+-------------------+--------------------------------+
| Primitive           | Algorithm         | Application                    |
+---------------------+-------------------+--------------------------------+
| Symmetric Cipher    | ChaCha20          | Sector-level RAM encryption    |
+---------------------+-------------------+--------------------------------+
| Asymmetric Identity | Ed25519 / X25519  | Key exchange & signatures      |
+---------------------+-------------------+--------------------------------+
| Post-Quantum KEM    | Kyber-512 (PQC)   | Quantum-resistant key exchange |
+---------------------+-------------------+--------------------------------+
| Zero-Knowledge      | Schnorr Protocol  | Challenge-response login       |
+---------------------+-------------------+--------------------------------+
| Hashing             | SHA-256           | Integrity digests & HMACs      |
+---------------------+-------------------+--------------------------------+
| Secret Sharing      | Sharks / Shamir   | Multi-custody key sharding     |
+---------------------+-------------------+--------------------------------+
| Erasure Coding      | Reed-Solomon      | Fault-tolerant storage packets |
+---------------------+-------------------+--------------------------------+
```

---

## 7. Deterministic Build & Verification Standards

To guarantee sovereign supply-chain integrity:
1. **Deterministic Binaries:** The build system produces bit-for-bit identical ELF binaries from source code. All timestamps, random build paths, and host metadata are excluded.
2. **Toolchain Pinning:** Rust nightly toolchain is strictly pinned via [`rust-toolchain.toml`](rust-toolchain.toml) (`nightly-x86_64-pc-windows-msvc` / `rust-src`).
3. **Formal Verification Roadmap:**
   * **TLA+:** Modeling the capability grant/revocation state machine to prove absence of deadlock and privilege leakage.
   * **Coq / Lean:** Inductive proofs verifying the mathematical correctness of the linked-list allocator and panic-zeroing routines.

---

## 8. Directory & Repository Layout

```text
KELLER-OS/
├── .cargo/
│   └── config.toml             # Target triples, build-std, and rustflags
├── assets/
│   ├── banner.svg              # KELLER-OS vector banner
│   └── icon.svg                # System vector insignia
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
│   ├── block.rs               # Sector layer between the vault image format and the disk
│   ├── boot.rs                 # global_asm! bootstrap: Multiboot2 + PVH notes, 4 GiB map, 256 KiB stack + guard band
│   ├── bootinfo.rs             # PVH/Multiboot1/Multiboot2 handoff parser, memory map, framebuffer tag
│   ├── clock.rs                # PIT tick counter, uptime in ms
│   ├── crypto.rs               # RFC 8439 AEAD, HMAC/HKDF, RS + Shamir, GHOST blob, KATs
│   ├── eth.rs                  # Ethernet/IPv4/UDP framing, checksums, ARP responder, known-answer test
│   ├── fb.rs                   # Framebuffer: handoff adoption, BGA mode set, pixel/span/blit/scrub
│   ├── gui/
│   │   ├── canvas.rs           # Rasteriser and palette: rectangles, borders, lines, 8x16 text
│   │   ├── font.rs             # Baked 4096-byte glyph table (generated, do not edit)
│   │   └── mod.rs              # Display server: console mirror, window slots, dirty-rect blits
│   ├── integrity.rs            # FNV1a-64 self-measurement of .text
│   ├── ipc.rs                  # HMAC-SHA256 verified IPC queue
│   ├── linker.ld               # Memory layout (text, rodata, data, note, bss)
│   ├── main.rs                 # Kernel entry, allocator, boot order, idle loop
│   ├── mm.rs                   # Coalescing free-list allocator
│   ├── net.rs                  # Vantablack mesh: ShardSec frames, Byzantine isolation, cover traffic
│   ├── nic.rs                  # Intel 8254x (e1000): DMA descriptor rings, MAC, ARP replies, counters
│   ├── panic.rs                # 3-pass memory wipe, scrub hooks, lockdown
│   ├── pci.rs                  # Config space, bus enumeration, BAR sizing/assignment, VGA lookup
│   ├── port.rs                 # Port I/O primitives
│   ├── proc.rs                 # Process table, per-task address spaces, fault retirement
│   ├── sched.rs                # Fixed-slot scheduler with temporal isolation
│   ├── serial.rs               # 16550 UART driver, RX ring, console macros, GUI log mirror
│   ├── session.rs              # 128-bit sliding replay window + ms timeouts
│   ├── shell.rs                # COM1 line editor and command dispatch
│   ├── storage.rs              # Vault image format, superblock, records, journal
│   ├── vault.rs                # RS-sharded root secret + per-sector AEAD
│   └── zk.rs                   # Schnorr proofs, GHOST blobs, the unlock gate
├── dev-tools/                  # Development-only helpers: not needed to build or boot the kernel
│   ├── bochsrc.txt             # Bochs emulator hardware profile
│   ├── disk_check.py           # Independent reader for a vault image: geometry, framing, no plaintext
│   ├── make_font.py            # Bakes src/gui/font.rs from CascadiaMono.ttf (OFL)
│   ├── qemu_check.py           # Headless verification harness (expect/forbid, screendump, input)
│   ├── smp_check.py            # Independent ChaCha20/SHA-256 checks of the per-AP KAT digests
│   ├── verify_gui.py           # Checks a screendump against the GUI spec, writes PNG/HTML
│   └── wire_check.py           # Independent peer on the NIC's segment: validates every frame
├── .gitignore                  # Build artifact and log exclusions
├── build.rs                    # Cargo build script linking assembly bootstrap
├── Cargo.lock                  # Pinned dependency lockfile
├── Cargo.toml                  # Package manifest & profile optimizations
├── CRYPTOGRAPHY_DEEP_DIVE.md   # Mathematical & Global Mesh Cryptographic Deep Dive
├── GUI_SPECIFICATION.md        # Dedicated Graphical Subsystem Specification
├── index.html                  # Landing page for kernel.kellersystems.dev
├── KELLER OS.canvas            # Obsidian master architectural canvas
├── run.ps1                     # QEMU launch and debug harness
├── rust-toolchain.toml         # Nightly channel & component configuration
├── SPECIFICATION.md            # This Master System Specification document
├── STORAGE_PERSISTENCE.md      # Persistent vault storage: AHCI driver, image format, unlock gate
├── VANTABLACK_INTEGRATION.md   # Sovereign WAN Mesh & Native Internet Access Specification
└── x86_64-sovereign_core.json  # Bare-metal LLVM target specification
```

---

## 9. Verification & Execution Harness

### Headless QEMU Test Harness
```powershell
.\run.ps1
```
Runs QEMU with serial output directed to stdio and guest error reporting enabled.

### Scripted Verification Harness
```powershell
python dev-tools\qemu_check.py --secs 32 --stdin-script target\full-input.txt `
    --expect "SELF-TEST SUMMARY: 159 passed, 0 failed" --forbid "LOCKDOWN" --forbid "NIC KAT FAILED"
# (159 with a network adapter and no disk: the AHCI adapter checks report themselves skipped,
#  which appends a "20 skipped" clause to the same line. Attach the disk in the Step 7 commands
#  and the same script reports 179 passed, 0 failed.)

# Persistent storage, checked from both ends: two emulator processes against one image file, then
# an independent host-side reader of the raw image
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
python dev-tools\disk_check.py --img target\vault-a.img --later target\vault.img `
    --marker "KELLER-OS PERSISTS" --from-log target\disk-run-b.log

# The mesh's transport on a real wire, checked from the other end of the cable: the adapter's
# registers and rings read back out of the device, the framing layer's known-answer vector, then
# an independent peer that validates every transmitted frame, matches one it typed byte for byte,
# and injects frames whose refusal the guest's own counters have to account for exactly
python dev-tools\wire_check.py --secs 130

# Ring-3 isolation, address spaces and preemption: 40 probe assertions, two faults contained at
# CPL 3, a `jmp $` task preempted by the timer with zero syscalls, every frame returned, and the
# shell still answering afterwards
python dev-tools\qemu_check.py --vga std --secs 30 --stdin-script target\ring3-input.txt `
    --expect "[SH] RING-3 PROBE assertions: 40 passed, 0 failed" `
    --expect "[OK] RING-3 PREEMPTION PROOF: 'spin-probe' (jmp $) got the CPU" `
    --expect "[OK] RING-3 FAULT CONTAINMENT: 2 task(s) killed at CPL 3 (1 #PF, 1 #GP)" `
    --expect "[OK] RING-3 PHASE COMPLETE: 5 processes retired, address spaces torn down, paging frames back to 0" `
    --expect "[SH] RING-3 ROWS: 1/8 used" `
    --forbid "LOCKDOWN" --forbid "unknown syscall" --forbid "state=ready" --forbid "idle_armed=true"

# The mesh probe on its own: 12 assertions including shard-swap and Byzantine isolation
python dev-tools\qemu_check.py --secs 30 --stdin-script target\net-input.txt `
    --expect "NET PROBE assertions: 12 passed, 0 failed" --expect "poisson-cover => PASS"

# The GUI path end to end: display server up, both probes green, stack guard intact
python dev-tools\qemu_check.py --vga std --secs 45 --stdin-script target\gui-input.txt `
    --screendump target\gui.ppm --expect "[OK] GUI DISPLAY SERVER" `
    --expect "[SH] GUI PROBE: aperture round-trip=PASS + backbuffer/glyph/blit=PASS => PASS" `
    --expect "[SH] INPUT PROBE assertions: 21 passed, 0 failed" `
    --expect "[OK] NETWORK ADAPTER: 00:03.0 8086:100e (82540EM)" `
    --expect "[OK] NIC DMA RINGS: tx 8/8 rx 8 descriptors of 16 bytes" `
    --expect "SELF-TEST SUMMARY: 159 passed, 0 failed"

# Real PS/2 input through the emulated 8042: aim, click, aim, click, then type a command
python dev-tools\qemu_check.py --vga std --secs 42 --stdin-script target\gui-input.txt `
    --type "input\n" --mouse 128,-184 --click left --mouse=-340,100 --click left `
    --expect "[PS2] mouse: bytes=27 packets=9" `
    --expect "[GUI] pointer: cursor=300,300 packets=9 clicks=2 motion=-212,84"

# The capability gate: after Alt+Tab the focus is on KELLER VAULT, so the same keystrokes are
# refused and the typed command never prints - routed=1 (the chord) against refused=4 (the text)
python dev-tools\qemu_check.py --vga std --secs 40 --stdin-script target\input-input.txt `
    --key alt-tab --type "mem\n" --input-settle 26 --forbid "[SH] heap"

# Proof that injection reached the kernel, not just "no symptom appeared": the harness asks the
# guest for its PS/2 counters over COM1 and compares them with what it sent. A run that cannot
# produce that evidence fails, however the --expect/--forbid patterns fall out. Here there is no
# 8042 to deliver anything, so the guest says `[--] PS/2 CONTROLLER ABSENT` once, its counters
# stay at zero (no phantom 0xFF reads), and the four injection checks fail - which is the point.
python dev-tools\qemu_check.py --vga std --secs 25 --qemu-arg=-machine --qemu-arg=pc,i8042=off `
    --mouse 40,-30 --click left --expect "[--] PS/2 CONTROLLER ABSENT" --expect "[OK] BOOT PROTOCOL"

# 30 pixel-level assertions against the capture above (palette, rules, rectangles, cursor arrow)
python dev-tools\verify_gui.py --ppm target\gui.ppm --png target\gui.png `
    --html target\gui-preview.html --cursor 300,300
```
The aggregate count grows only on a machine with a display adapter (QEMU provides a standard VGA
by default): with one, the same script reports `161 passed, 0 failed, 20 skipped` and its input
probe `23 passed, 0 failed`, whereas under `--vga none` - where the kernel prints `[--] NO DISPLAY
ADAPTER (serial console only)` and keeps working - it reports `137 passed, 0 failed, 20 skipped`
with the probe at `18 passed, 0 failed, 4 skipped`, because the four focus-routing and backscroll
checks have no focus holder to route to and no history to scroll. The difference is 24 in both
counts, which is the whole display-server and input delta. The 20 skipped are the AHCI adapter
checks, and a run with a disk passes them and reports `181`: the arithmetic is the point, because a
check that did not run must never be added to a check that passed.
Injecting input makes a run self-verifying: the harness asks the guest for its PS/2 counters
before and after the phase and requires `keyboard bytes`, `mouse packets`, `clicks`, cumulative
`motion` and the cursor's landing point to match the injection exactly, with nothing lost in
either ring (`--no-input-check` opts out). Scripted console lines get the same treatment - each
one is echoed back before the next is sent, because QEMU forwards serial input only as fast as the
guest's UART accepts it and a burst is silently truncated. Two details make that protocol hold up
when a command keeps the shell busy for seconds (a probe over the whole storage stack does): the
harness types one byte at a time, so nothing is ever sitting in the emulated FIFO when the guest is
not looking, and a line that did not come back is retried only after the partial prefix has been
erased - a retry appended to half a command would be a *different* command, and `disk write
KELLER` is a perfectly valid line. The upside is that the last
example above fails loudly even though every `--expect` pattern still appears: with no PS/2
controller the QMP events are rejected, the counters never move, and the exit code is 1.
Boots the ELF with `-kernel`, drip-feeds shell input line by line (each one has to be echoed
back before the next is sent), and exits 0 only when every `--expect` pattern appeared, no
`--forbid` pattern did, and the input evidence - when anything was injected - adds up. The harness drains QEMU's
serial pipe in a background thread: serial output and QMP share one main loop, so a full
pipe would otherwise stop the emulator from answering `quit`.

### Graphical QEMU Harness
```powershell
.\run.ps1              # -vga std + QEMU window, kernel log on this terminal
.\run.ps1 -Headless    # adapter emulated, no window (what the harness uses)
.\run.ps1 -NoGraphics  # no adapter at all
```
The kernel brings up a 1024x768x32 framebuffer, prints `[OK] GUI DISPLAY SERVER: 3072 KiB
backbuffer, 8 window slots, 100 ms fixed refresh`, and the shell's `gui` command reports the
frames/blits/fills/glyph counters. `gui on|off|redraw|scrub` drives the server and `gui test`
runs the aperture round-trip plus the backbuffer/glyph/blit probe. `input` reports the
controller, decoder and focus-routing counters, `input test` runs the PS/2 probe, and in a QEMU
window a click focuses the tile under the pointer while `Alt + Tab` cycles focus.

### Bochs Strict Hardware Emulation
```bash
bochs -f dev-tools\bochsrc.txt
```
Simulates hardware register states, memory boundaries, and cycle-accurate execution.
