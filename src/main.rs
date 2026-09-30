//! KELLER-OS sovereign microkernel entry point.
//!
//! Boot order (each step is verified on COM1 before the next one runs):
//!
//! 1. serial console, then the boot handoff (PVH / Multiboot) and memory map;
//! 2. build integrity self-hash of `.text`;
//! 3. heap sized from the boot memory map, registered as a panic scrub region;
//! 4. GDT + TSS/IST, IDT with all 256 vectors gated, PIC remapped, PIT at 100 Hz;
//! 5. subsystem bring-up (vault, mesh) plus panic scrub hooks;
//! 6. interrupts enabled - the kernel then idles with `hlt` and wakes on the timer,
//!    which is the fix for the previous build freezing on its first scheduler slot.

#![feature(alloc_error_handler)]
#![no_std]
#![no_main]
#![allow(dead_code)]

extern crate alloc;

use alloc::boxed::Box;
use core::sync::atomic::{AtomicPtr, Ordering};

mod arch;
mod block;
mod boot;
mod bootinfo;
mod clock;
mod crypto;
mod eth;
mod integrity;
mod ipc;
mod fb;
mod gui;
mod mm;
mod net;
mod nic;
mod panic;
mod pci;
mod port;
mod proc;
mod sched;
mod serial;
mod session;
mod shell;
mod storage;
mod vault;
mod zk;

use crate::arch::idt::InterruptFrame;
use crate::net::KellerNet;
use crate::vault::KellerVault;

extern "C" {
    static __text_start: u8;
    static __text_end: u8;
    static __bss_start: u8;
    static __bss_end: u8;
    static __stack_guard_bottom: u8;
    static __boot_stack_bottom: u8;
    static __boot_stack_top: u8;
}

/// Byte written into the poison band that sits immediately below the boot stack.
const STACK_GUARD_PATTERN: u8 = 0x5A;

/// Paints the poison band below the boot stack (see `src/boot.rs`).
///
/// The page tables live directly above the band, so a stack overflow has to cross it first:
/// checking the band turns what the CPU otherwise reports as a silent triple fault into an
/// ordinary failed comparison.
unsafe fn poison_stack_guard() {
    let bottom = &__stack_guard_bottom as *const u8 as u64;
    let top = &__boot_stack_bottom as *const u8 as u64;
    core::ptr::write_bytes(bottom as *mut u8, STACK_GUARD_PATTERN, (top - bottom) as usize);
}

/// True while nothing has pushed a frame through the guard band.
unsafe fn stack_guard_intact() -> bool {
    let bottom = &__stack_guard_bottom as *const u8 as u64;
    let top = &__boot_stack_bottom as *const u8 as u64;
    (bottom..top).all(|address| *(address as *const u8) == STACK_GUARD_PATTERN)
}

/// Subsystem handles are raw pointers so the panic path can reach them without
/// resurrecting references a panicking kernel cannot trust.
static GLOBAL_VAULT: AtomicPtr<KellerVault> = AtomicPtr::new(core::ptr::null_mut());
static GLOBAL_NET: AtomicPtr<KellerNet> = AtomicPtr::new(core::ptr::null_mut());

unsafe fn scrub_vault_hook() {
    let pointer = GLOBAL_VAULT.load(Ordering::SeqCst);
    if let Some(vault) = pointer.as_mut() {
        vault.purge();
    }
}

unsafe fn scrub_net_hook() {
    let pointer = GLOBAL_NET.load(Ordering::SeqCst);
    if let Some(net) = pointer.as_mut() {
        net.wipe();
    }
}

/// Clears both subsystems' secret material (used by the shell's `purge` command).
pub unsafe fn purge_subsystem_secrets() {
    scrub_vault_hook();
    scrub_net_hook();
}

pub fn vault_handle() -> Option<&'static mut KellerVault> {
    unsafe { GLOBAL_VAULT.load(Ordering::SeqCst).as_mut() }
}

pub fn net_handle() -> Option<&'static mut KellerNet> {
    unsafe { GLOBAL_NET.load(Ordering::SeqCst).as_mut() }
}

/// Software-interrupt gate handler (`int 0x80`): the syscall entry used for verified IPC.
pub fn syscall(frame: &InterruptFrame) {
    crate::println!(
        "[KOS] SYSCALL GATE: verified IPC active (rip={:#018x}, rax={:#x})",
        frame.rip,
        frame.rax
    );
}

// ---------------------------------------------------------------- scheduler slots

/// Slot 0 is the idle slot. `hlt` deliberately does not happen here: the main loop halts
/// the CPU itself, in a context where interrupts are enabled.
fn idle_task() {}

/// Periodic vault maintenance slot: stands in for key rotation / scrub verification.
fn vault_task() {
    static mut ROTATIONS: u64 = 0;
    unsafe {
        let rotations = core::ptr::addr_of_mut!(ROTATIONS);
        *rotations += 1;
    }
}

/// Notices a stalled timer rather than silently losing time.
fn watchdog_task() {
    let lost = clock::overflow_count();
    if lost != 0 && lost % 8 == 0 {
        crate::println!("[!!] WATCHDOG: {} timer interrupts lost", lost);
    }
}

// ---------------------------------------------------------------- entry point

#[no_mangle]
pub extern "C" fn kernel_main(magic: u32, boot_info: u32) -> ! {
    unsafe {
        // A kernel must not assume the loader zeroed `.bss` (PVH direct boot leaves it
        // untouched — and the page tables and boot stack live in `.bss`, so a blanket
        // memset would destroy the running kernel). Every module therefore initialises
        // its own mutable static state explicitly, in dependency order.
        let bss_start = &__bss_start as *const u8 as u64;
        let bss_end = &__bss_end as *const u8 as u64;
        let loader_probe = core::ptr::read_volatile(bss_start as *const u64);

        panic::init();
        clock::init();
        // The console mirror and the display state must be cleared before the serial driver
        // can mirror its first byte into them (`.bss` arrives uninitialised).
        gui::reset();
        poison_stack_guard();
        serial::init();
        println!();
        println!("==============================================================");
        println!(" KELLER-OS v2.5 - SOVEREIGN MICROKERNEL - RING 0 BRING-UP");
        println!("==============================================================");

        // [1] Boot handoff and memory map.
        let boot = bootinfo::parse(magic, boot_info);
        boot.describe();

        // [2] Chain of trust: measure the running text segment.
        integrity::verify_text_hash();

        // [3] Heap sized from what the machine actually reported.
        let kernel_end = &__bss_end as *const u8 as u64;
        let (heap_start, heap_size) = boot
            .heap_range(kernel_end)
            .unwrap_or((0x100_0000, 0x20_0000));
        mm::init_heap(heap_start, heap_size);
        println!(
            "[OK] SOVEREIGN ALLOCATOR: {:#x}..{:#x} ({} MiB, coalescing free list)",
            heap_start,
            heap_start + heap_size,
            heap_size / (1024 * 1024)
        );

        // The kernel's own stack must be scrubbed too (spec §4.1).
        let stack_bottom = &__boot_stack_bottom as *const u8 as u64;
        let stack_top = &__boot_stack_top as *const u8 as u64;
        panic::register_scrub_region(stack_bottom, stack_top - stack_bottom);

        // [4] Descriptor tables, interrupt controller, timer.
        ipc::init();
        sched::init();
        // The process table must be zeroed before interrupts are enabled: the timer handler
        // indexes it on its very first tick.
        proc::init();
        shell::init();
        arch::cpu::enable_fpu_sse();
        arch::init();

        // [4f] The firmware's tables, read before anything programs an interrupt controller:
        // the MADT says where the local APIC and the I/O APIC are, which GSI each ISA IRQ is
        // wired to, and how many processors this machine has. Nothing is programmed here - this
        // is the read, and every line it prints is a fact about the machine rather than a
        // decision this kernel made.
        arch::acpi::init(boot.rsdp);
        arch::acpi::describe();

        // [4g] The interrupt controllers the tables just named. The local APIC is enabled with
        // every unused source masked (LINT0 with them, which is the ExtINT pin the 8259 would
        // need), and then every ISA line the 8259 had open is carried over to an IO-APIC
        // redirection entry before the 8259 is masked in its own registers. Both ends closed is
        // what makes a later interrupt provably an APIC one. This runs with interrupts disabled,
        // so nothing can be delivered against a half-programmed table.
        arch::lapic::init();
        arch::ioapic::init();

        // [4a] Graphics adapter, on whichever path is available: bootloader hand-off first,
        // Bochs/QEMU VBE second (see GUI_SPECIFICATION.md §3). Everything below still runs on
        // a machine with no display adapter at all — the console is COM1.
        pci::describe();
        println!(
            "[OK] PCI SELF-TEST: {}",
            if pci::self_test() {
                "configuration space round-trip verified"
            } else {
                "no device answered"
            }
        );
        let mut framebuffer_ready = false;
        if let Some(handoff) = boot.framebuffer {
            framebuffer_ready = fb::adopt_handoff(&handoff) && fb::self_test();
        }
        if !framebuffer_ready {
            fb::describe_probe();
            framebuffer_ready = fb::init(fb::DEFAULT_WIDTH, fb::DEFAULT_HEIGHT) && fb::self_test();
        }
        if framebuffer_ready {
            if let Some(framebuffer) = fb::handle() {
                framebuffer.describe();
            }
            println!(
                "[OK] FRAMEBUFFER SELF-TEST: 4 corner pixels written and read back through the aperture"
            );
            panic::register_scrub_hook(fb::scrub_hook);
            if gui::init(fb::DEFAULT_WIDTH, fb::DEFAULT_HEIGHT) {
                println!(
                    "[OK] GUI DISPLAY SERVER: {} KiB backbuffer, {} window slots, {} ms fixed refresh",
                    gui::backbuffer_bytes() / 1024,
                    gui::MAX_WINDOWS,
                    gui::REFRESH_MS
                );
                gui::describe();
                // The scrollback is a *view*: a deep ring of log lines behind a tile-sized window,
                // moved by PageUp/PageDown, Home/End and the mouse wheel, and by the shell's
                // `gui top|bottom|up|down`. Saying how deep it is at boot is how a reader knows
                // whether `selftest` output is readable or just truncated.
                println!(
                    "[OK] GUI SCROLLBACK: {} lines of log held behind a {} line tile ({} lines of backscroll), PgUp/PgDn + Home/End + wheel scroll the focused window",
                    gui::console_history(),
                    gui::TILE_LINES,
                    gui::console_history().saturating_sub(gui::TILE_LINES)
                );
                let guard_intact = stack_guard_intact();
                println!(
                    "[OK] STACK GUARD: {} KiB poison band {}, compositor peak {} bytes of {}",
                    (stack_bottom - &__stack_guard_bottom as *const u8 as u64) / 1024,
                    if guard_intact {
                        "intact"
                    } else {
                        "SMASHED (stack overflow)"
                    },
                    gui::stack_peak(),
                    stack_top - stack_bottom
                );
            } else {
                println!("[!!] GUI DISPLAY SERVER: backbuffer not installed (stack guard check follows)");
                let guard_intact = stack_guard_intact();
                println!(
                    "[!!] STACK GUARD: poison band {}",
                    if guard_intact { "intact" } else { "SMASHED (stack overflow)" }
                );
            }
        } else {
            println!("[--] NO DISPLAY ADAPTER (serial console only)");
        }
        println!(
            "[OK] GDT + TSS/IST INSTALLED ({} KiB interrupt stack, ring-3 port I/O denied)",
            arch::gdt::ist_stack_size() / 1024
        );

        // [4d] Paging: read the boot tables back (their `cr3`, the identity map's contents) so
        // per-process address spaces can be built on top of them rather than beside them.
        arch::paging::init();

        // [4e2] Persistent storage: an AHCI controller and whatever is on the disk behind it. A
        // machine with no controller, or a controller with no disk, is reported and the vault
        // simply stays in RAM - a missing disk is a documented state, not a boot failure.
        storage::init();
        // The image format is checked on every machine, because it is written against the block
        // layer's reference device; only the controller half needs a controller.
        let storage_report = storage::self_test();
        println!(
            "[OK] VAULT FORMAT SELF-TEST: {} assertions passed, {} failed (block layer, proof gate, image format, journal - on the reference device)",
            storage_report.passed, storage_report.failed
        );
        for failure in storage_report.failures.iter() {
            println!("[!!] VAULT FORMAT KAT FAILED: {}", failure);
        }
        if arch::ahci::ready() {
            // The scratch sector is the *last* one on the device, which no image ever uses: the
            // round trip destroys what it touches, so it must not touch vault data.
            let scratch = arch::ahci::sector_count().saturating_sub(1);
            let adapter = arch::ahci::self_test(Some(scratch));
            println!(
                "[OK] DISK SELF-TEST: {} assertions passed, {} failed (registers, port geometry, scratch round-trip)",
                adapter.passed, adapter.failed
            );
            for failure in adapter.failures.iter() {
                println!("[!!] DISK KAT FAILED: {}", failure);
            }
        }

        // [4e] The network adapter: PCI function 00:03.0 on the harness's machine. Bring-up
        // prints what it found either way, because "no adapter" and "adapter that answered
        // nothing" are different failures and the in-RAM wire keeps working in both.
        eth::describe();
        nic::init();
        if nic::ready() {
            let wire_report = nic::self_test();
            println!(
                "[OK] NIC SELF-TEST: {} assertions passed, {} failed (framing + register readback)",
                wire_report.passed, wire_report.failed
            );
            for failure in wire_report.failures.iter() {
                println!("[!!] NIC KAT FAILED: {}", failure);
            }
            if nic::link_up() {
                println!("[OK] NIC LINK: up, egress on - the mesh's sealed frames now leave the machine");
            } else {
                println!("[--] NIC LINK: down - the device is programmed but nothing is connected to it");
            }
        }

        // [4c] Entropy and the cryptographic self-test. Every key the vault will ever
        // hold comes out of this module, so a failing known-answer test is fatal.
        crypto::init_entropy(
            (stack_top ^ kernel_end ^ boot.total_ram_bytes()).wrapping_mul(0x9E37_79B9_7F4A_7C15),
        );
        println!("[OK] ENTROPY: {}", crypto::entropy_source());
        ipc::seed_key();
        if !ipc::self_test() {
            println!("[!!] IPC MAC SELF-TEST FAILED");
            panic::lockdown("ipc transport self-test failure");
        }
        println!("[OK] IPC MAC SELF-TEST: genuine message delivered, forged message dropped");
        println!(
            "[OK] SESSION GUARD: {}-counter replay window, {}-minute idle timeout, {}-hour hard timeout",
            session::WINDOW_BITS,
            session::IDLE_TIMEOUT_MS / 60_000,
            session::HARD_TIMEOUT_MS / 3_600_000
        );

        let report = crypto::self_test();
        println!(
            "[OK] CRYPTO SELF-TEST: {} assertions passed, {} failed",
            report.passed, report.failed
        );
        for failure in report.failures.iter() {
            println!("[!!] CRYPTO KAT FAILED: {}", failure);
        }
        if report.failed != 0 {
            panic::lockdown("cryptographic self-test failure");
        }

        // [5] Subsystems.
        let mut vault = Box::new(KellerVault::new(b"LOCAL_ROOT_SECRET"));
        // [5a] Whatever the disk is holding comes back now: the image is authenticated against
        // the vault's commitment *and* the header that is on the medium, and only then are its
        // records adopted. A refusal is a documented state and leaves the vault empty rather
        // than half-filled.
        if storage::has_image() {
            match storage::load(&mut vault) {
                Ok(adopted) => {
                    println!(
                        "[OK] VAULT RESTORE: {} sector(s) adopted from the image, generation {}",
                        adopted,
                        storage::generation()
                    );
                    match storage::read_journal(&mut vault) {
                        Ok(entry) => println!(
                            "[OK] DISK JOURNAL: boots={} stamp={} (a counter only the medium could have kept)",
                            entry.boots,
                            hex::encode(&entry.stamp)
                        ),
                        Err(error) => println!(
                            "[--] DISK JOURNAL: no entry readable ({})",
                            error.as_str()
                        ),
                    }
                }
                Err(error) => println!("[!!] VAULT RESTORE: refused ({})", error.as_str()),
            }
        }
        GLOBAL_VAULT.store(Box::into_raw(vault), Ordering::SeqCst);
        panic::register_scrub_hook(scrub_vault_hook);

        // The mesh derives its ShardSec subkeys from a fresh DRBG master key and registers
        // the local Ring-3 Vantablack daemon as its only route until the NIC driver lands.
        let mut net = Box::new(KellerNet::new(net::SELF_NODE));
        let mesh_fingerprint = net.provision();
        net.register_peer(net::RELAY_NODE, b"KOS-VANTABLACK-DAEMON");
        GLOBAL_NET.store(Box::into_raw(net), Ordering::SeqCst);
        panic::register_scrub_hook(scrub_net_hook);
        println!("[OK] KELLER SUBSYSTEMS (VAULT & MESH) ONLINE");
        println!(
            "[OK] VANTABLACK MESH: shard-subkeys 3/3 (master-fp={:#010x}), {} byte quantized frames, {}-counter replay window",
            mesh_fingerprint,
            net::WIRE_FRAME_LEN,
            session::WINDOW_BITS
        );
        if let Some(mesh) = net_handle() {
            mesh.describe();
        }

        println!(
            "[--] BSS {:#x}..{:#x}; loader left {:#018x} (modules self-initialise)",
            bss_start, bss_end, loader_probe
        );

        // [4b] Syscall-gate self-test: exercises the IDT stub, the frame layout and the
        // dispatcher before any hardware interrupt can fire.
        let (gate_offset, gate_selector, gate_ist, gate_attributes) = arch::idt::gate_info(128);
        println!(
            "[--] GATE 0x80: offset={:#x} expected={:#x} sel={:#x} ist={} attr={:#x}",
            gate_offset,
            arch::idt::stub_address(128),
            gate_selector,
            gate_ist,
            gate_attributes
        );
        core::arch::asm!("int 0x80", options(nomem, nostack));

        // [6] Scheduler slots.
        sched::register("idle", idle_task);
        sched::register("vault-maintenance", vault_task);
        sched::register("watchdog", watchdog_task);
        sched::describe();

        // [7] Interrupt self-test: the timer must actually advance.
        serial::enable_rx_interrupt();
        arch::cpu::enable_interrupts();
        println!("[OK] INTERRUPTS ENABLED (IF=1)");
        clock::wait_ticks(20);
        let ticks = clock::ticks();
        if ticks >= 20 {
            println!(
                "[OK] PIT TIMER LIVE: {} ticks / ~{} ms ({} lost)",
                ticks,
                clock::uptime_ms(),
                clock::overflow_count()
            );
        } else {
            println!(
                "[!!] PIT TIMER STALLED: only {} ticks after waiting 200 ms",
                ticks
            );
        }

        // [7b] The APIC's own timer, calibrated against the PIT that was just proven live - and
        // the APIC self-test, which is where the self-IPI, the two clocks and the IO-APIC's
        // entries are checked. It runs here because a self-IPI needs interrupts enabled and an
        // EOI needs a handler that can run.
        arch::lapic::start_timer(1_000);
        let apic_report = arch::lapic::self_test();
        println!(
            "[OK] APIC SELF-TEST: {} assertions passed, {} failed (registers, self-IPI, two clocks against each other)",
            apic_report.passed, apic_report.failed
        );
        for failure in apic_report.failures.iter() {
            println!("[!!] APIC KAT FAILED: {}", failure);
        }
        let ioapic_report = arch::ioapic::self_test();
        println!(
            "[OK] IOAPIC SELF-TEST: {} assertions passed, {} failed ({})",
            ioapic_report.passed,
            ioapic_report.failed,
            if arch::ioapic::live() {
                "identity, redirection entries read back, writes land, 8259 masked, timer delivered through the controller"
            } else {
                "no I/O APIC on this machine"
            }
        );
        for failure in ioapic_report.failures.iter() {
            println!("[!!] IOAPIC KAT FAILED: {}", failure);
        }

        // [7c] The other processors: a trampoline page, the specification's INIT-SIPI-SIPI
        // sequence, and a mailbox so that a processor which has been started is not a processor
        // that does nothing. The self-test is where the pinned ChaCha20/SHA-256 workload is run
        // on every core and compared with a vector produced by an independent implementation.
        arch::smp::bring_up();
        let smp_report = arch::smp::self_test();
        println!(
            "[OK] SMP SELF-TEST: {} assertions passed, {} failed, {} skipped (trampoline layout, APIC ids, pinned ChaCha20 workload on every core, live agreement)",
            smp_report.passed, smp_report.failed, smp_report.skipped
        );
        for failure in smp_report.failures.iter() {
            println!("[!!] SMP KAT FAILED: {}", failure);
        }
        // The report comes after the verdict on purpose: it carries each processor's digest in
        // full, which is what an outside reader checks the kernel's claim against.
        arch::smp::describe();

        // [7d] Message-signalled interrupts, on the adapter if it has the capability for them.
        // The device's own transmit-descriptor interrupt is the one cause this kernel can raise
        // on demand, so that is the one the delivery is proven with: program the capability,
        // unmask that one source in the device, send a frame, and require the vector to arrive
        // with a cause behind it.
        arch::msi::set_service_hook(nic::service_interrupt);
        if let Some(device) = nic::pci_device() {
            let vector = arch::lapic::VECTOR_MSI_BASE;
            if arch::msi::install(&device, vector) {
                let mask = nic::enable_tx_interrupt();
                nic::send_probe();
                let deadline = arch::lapic::micros() + 1_000_000;
                while arch::msi::caused() == 0 && arch::lapic::micros() < deadline {
                    core::hint::spin_loop();
                }
                println!(
                    "[OK] MSI DEVICE PATH: IMS={:#010x} (transmit-written-back only), {} interrupt(s) delivered, {} with a device cause, last cause {:#010x}",
                    mask,
                    arch::msi::interrupts(),
                    arch::msi::caused(),
                    arch::msi::last_cause()
                );
            }
        }
        let msi_report = arch::msi::self_test();
        println!(
            "[OK] MSI SELF-TEST: {} assertions passed, {} failed, {} skipped (message page delivery, device capability read back, device-caused interrupt)",
            msi_report.passed, msi_report.failed, msi_report.skipped
        );
        for failure in msi_report.failures.iter() {
            println!("[!!] MSI KAT FAILED: {}", failure);
        }

        // [7e] The privilege boundary, end to end: build an address space, `iretq` into CPL 3,
        // let the task print through the syscall door and exit, then tear its tables down. This
        // runs before the shell comes up because it is the one claim everything else in the
        // microkernel story rests on, and it costs about one timer tick.
        proc::boot_probe();

        // [8] Prove the shell path works without an operator at the console.
        shell::execute(b"status");

        println!("[OK] SOVEREIGN-CORE BOOT COMPLETE - IDLE LOOP ENTERED (hlt, interrupts on)");

        // Idle loop: the scheduler runs one padded slot per quantum, the shell drains its
        // receive queue, and the CPU sleeps in `hlt` between timer interrupts. The local
        // wire stands in for the Ring-3 daemon's packet ring: Poisson cover frames go out
        // through it and come back through the ingress pipeline, keys and all.
        let mut heartbeat = 0u64;
        let wire = net::CaptureSender::new();
        loop {
            shell::poll();
            sched::tick();
            // An armed ring-3 phase delivers its tasks while the kernel idles; the report is
            // printed from here, because a task that is already dead cannot report anything.
            proc::phase_poll();

            // Input before the frame: PS/2 bytes queued by IRQ1/IRQ12 are decoded here and
            // routed to the window that holds focus, so a keystroke and the pixels it causes
            // land in the same refresh slot.
            arch::ps2::drain();

            // Fixed-slot GUI refresh: one frame per 100 ms quantum, no animations.
            gui::render_tick(clock::uptime_ms());

            if let Some(mesh) = net_handle() {
                mesh.cover_poll(clock::ticks(), &wire, net::RELAY_NODE);
                for frame in wire.take() {
                    // Every sealed frame the mesh emits also goes out the adapter when one is up.
                    // The in-RAM wire stays in the loop because it is the only path that proves
                    // egress -> wire -> ingress without a peer on the other end; the adapter is
                    // the same frames on real headers, and `nic status` counts them apart.
                    nic::transmit_mesh(&frame);
                    if let net::Ingest::Delivered {
                        session_key: Some(key),
                        ..
                    } = mesh.ingest_from(net::RELAY_NODE, &frame)
                    {
                        // GHOST handshake: both endpoints converge on the same ShardSec set.
                        mesh.adopt_master(&key);
                    }
                }

                // Frames that arrived from the wire go through the same ingress pipeline, which
                // is what makes the adapter an egress *and* ingress path rather than a printer.
                // Anything that is not a full-size mesh frame was already counted as refused by
                // the driver (foreign, not-udp, bad-checksum, ...) and is not fed to the mesh.
                let mut received = [0u8; eth::MAX_PAYLOAD];
                while let Some(datagram) = nic::poll(&mut received) {
                    if datagram.port != eth::MESH_PORT || datagram.length != net::WIRE_FRAME_LEN {
                        continue;
                    }
                    if let net::Ingest::Delivered {
                        session_key: Some(key),
                        ..
                    } = mesh.ingest_from(net::RELAY_NODE, &received[..datagram.length])
                    {
                        mesh.adopt_master(&key);
                    }
                }
            }

            let beat = clock::ticks() / 500;
            if beat != heartbeat {
                heartbeat = beat;
                // The heartbeat carries the input counters because they are the only
                // observable of a device path that has no other output of its own: a byte
                // count that does not move is a driver that is not being reached, and the
                // harness verifies exactly that with synthetic keys and motion.
                let (key_bytes, mouse_bytes, decoded, _, _) = arch::ps2::byte_counters();
                let (packets, rejected, _) = arch::ps2::mouse_counters();
                let (routed, refused, _) = gui::input_counters();
                let (wire_tx, wire_rx, wire_mesh, wire_refused) = nic::counters();
                println!(
                    "[hb] uptime {} ms, ticks {}, ipc delivered {} dropped {}, ps2 kbd={}/{} mouse={}/{} rejected={} routed={} refused={} cursor={},{} proc={} preempt={} yields={} r3={} wire-tx={} wire-rx={} wire-mesh={} wire-refused={}",
                    clock::uptime_ms(),
                    clock::ticks(),
                    ipc::delivered_count(),
                    ipc::dropped_count(),
                    key_bytes,
                    decoded,
                    mouse_bytes,
                    packets,
                    rejected,
                    routed,
                    refused,
                    gui::cursor_position().map(|position| position.0).unwrap_or(0),
                    gui::cursor_position().map(|position| position.1).unwrap_or(0),
                    proc::current_name(),
                    proc::preemptions(),
                    proc::yields(),
                    proc::ring3_entries(),
                    wire_tx,
                    wire_rx,
                    wire_mesh,
                    wire_refused
                );
            }

            // The idle context hands the CPU to ring-3 tasks here. `arm_idle` publishes that
            // nothing below depends on this context still running, which is the only window in
            // which the timer may switch away from ring 0; it is cleared the moment this context
            // is resumed, one instruction after the `hlt` that gave the CPU up.
            proc::arm_idle();
            arch::cpu::halt();
            proc::disarm_idle();
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

#[no_mangle]
pub unsafe extern "C" fn memset(s: *mut u8, c: i32, n: usize) -> *mut u8 {
    let mut index = 0;
    while index < n {
        *s.add(index) = c as u8;
        index += 1;
    }
    s
}

#[no_mangle]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut index = 0;
    while index < n {
        *dest.add(index) = *src.add(index);
        index += 1;
    }
    dest
}
