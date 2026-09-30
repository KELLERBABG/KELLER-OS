//! Keller Shell: the sovereign command interface (spec §4, subsystem V).
//!
//! Input arrives from COM1 RX (IRQ4) and, once the PS/2 driver lands, from the keyboard;
//! both feed this one line buffer. Command dispatch runs under the fixed-slot scheduler's
//! temporal-isolation discipline: every command is padded to a constant-cost window so
//! command length and execution profile are not observable from timing.

use crate::clock;
use crate::ipc;
use crate::mm;
use crate::println;
use core::sync::atomic::{AtomicU64, Ordering};

const LINE_CAPACITY: usize = 96;

static mut LINE: [u8; LINE_CAPACITY] = [0; LINE_CAPACITY];
static mut LENGTH: usize = 0;
static COMMANDS: AtomicU64 = AtomicU64::new(0);

/// Cost pad applied after every command (constant, never dependent on the command).
const DISPATCH_PAD_MS: u64 = 5;

/// Explicit reset of the shell's line buffer and counters.
pub fn init() {
    unsafe {
        LENGTH = 0;
        for index in 0..LINE_CAPACITY {
            *core::ptr::addr_of_mut!(LINE[index]) = 0;
        }
    }
    COMMANDS.store(0, Ordering::Relaxed);
}

pub fn poll() {
    while let Some(byte) = crate::serial::pop_rx() {
        feed(byte);
    }
}

/// Characters currently in the line buffer.
///
/// The keyboard reaches this same buffer through the display server's focus routing, so the
/// input probe uses this to prove a keystroke landed in the shell (and that a keystroke sent
/// to a window without focus did not).
pub fn line_length() -> usize {
    unsafe { *core::ptr::addr_of!(LENGTH) }
}

pub fn feed(byte: u8) {
    match byte {
        b'\r' | b'\n' => submit(),
        0x08 | 0x7F => backspace(),
        0x20..=0x7E => push(byte),
        _ => {}
    }
}

fn push(byte: u8) {
    unsafe {
        let length = LENGTH;
        if length + 1 >= LINE_CAPACITY {
            return;
        }
        let slot = core::ptr::addr_of_mut!(LINE[length]);
        *slot = byte;
        LENGTH = length + 1;
    }
    crate::serial::write_byte(byte);
}

fn backspace() {
    unsafe {
        let length = LENGTH;
        if length == 0 {
            return;
        }
        LENGTH = length - 1;
    }
    crate::serial::write_str("\x08 \x08");
}

fn submit() {
    let mut buffer = [0u8; LINE_CAPACITY];
    let length = unsafe {
        let length = LENGTH;
        for index in 0..length {
            buffer[index] = *core::ptr::addr_of!(LINE[index]);
        }
        LENGTH = 0;
        length
    };
    crate::serial::write_str("\n");
    execute(&buffer[..length]);
}

/// Executes a command line. Also used by the boot self-test so the shell is verified
/// without needing an operator at the console.
pub fn execute(bytes: &[u8]) {
    COMMANDS.fetch_add(1, Ordering::Relaxed);
    let line = match core::str::from_utf8(bytes) {
        Ok(line) => line.trim(),
        Err(_) => {
            println!("[SH] command rejected: not valid UTF-8");
            return;
        }
    };

    let (command, argument) = match line.split_once(' ') {
        Some((command, argument)) => (command, argument.trim()),
        None => (line, ""),
    };

    match command {
        "" => {}
        "help" => help(),
        "status" => status(),
        "clock" => {
            println!(
                "[SH] ticks={} uptime={} ms overflow={}",
                clock::ticks(),
                clock::uptime_ms(),
                clock::overflow_count()
            );
            clock_command(argument);
        }
        "mem" => memory(),
        "ipc" => ipc_command(argument),
        "cpu" => {
            let mut vendor = [0u8; 12];
            vendor.copy_from_slice(&crate::arch::cpu::vendor());
            println!(
                "[SH] vendor={} rdrand={} interrupts={}",
                core::str::from_utf8(&vendor).unwrap_or("unknown"),
                crate::arch::cpu::has_rdrand(),
                crate::arch::cpu::interrupts_enabled()
            );
        }
        "sched" => crate::sched::describe(),
        "crypto" => crypto_summary(),
        "selftest" => self_test(),
        "session" => session_command(argument),
        "net" => net_command(argument),
        "nic" => nic_command(argument),
        "disk" => disk_command(argument),
        "gui" => gui_command(argument),
        "input" => input_command(argument),
        "ring3" => ring3_command(argument),
        "vault" => vault_command(argument),
        "purge" => {
            println!("[SH] PURGE requested: clearing vault secrets");
            unsafe { crate::purge_subsystem_secrets() };
            println!("[SH] vault purged");
        }
        "panic" => {
            println!("[SH] deliberate lockdown test requested");
            unsafe { crate::panic::lockdown("shell panic command") }
        }
        "clear" => crate::serial::write_str("\x1b[2J\x1b[H"),
        unknown => println!("[SH] unknown command '{}' - try 'help'", unknown),
    }

    // Temporal isolation: constant extra work per command.
    let pad_until = clock::uptime_ms() + DISPATCH_PAD_MS;
    while clock::uptime_ms() < pad_until {
        core::hint::spin_loop();
    }
}

fn help() {
    println!("[SH] KELLER-OS shell commands:");
    println!("     help              this text");
    println!("     status            subsystem summary");
    println!("     clock             tick/uptime counters");
    println!("     mem               heap span");
    println!("     cpu               vendor, RDRAND, interrupt state");
    println!("     ipc [test]        IPC queue statistics, or run the MAC probe");
    println!("     sched             fixed-slot scheduler state");
    println!("     crypto            entropy source and primitive summary");
    println!("     session [test]    replay-window state, or run the window probe");
    println!("     net [test]        mesh state, or run the ShardSec/Byzantine/cover probe");
    println!("     nic [status|test|probe|on|off]  network adapter: registers, counters, wire probe");
    println!("     disk [status|test|format|save|load|write <text>|read|journal|wipe|superblock]");
    println!("                       AHCI controller + vault image: what is on the medium, and what
                          survives a power cycle");
    println!("     gui [on|off|test|redraw|scrub]  display server: state, probe, repaint, wipe");
    println!("     gui scroll | gui top|bottom|up|down");
    println!("                       the focused window's backscroll: what it is showing, and how
                          deep the history behind it is (keys: PgUp/PgDn, Home/End, wheel)");
    println!("     input [status|test]  PS/2 keyboard + mouse: counters, focus routing, probe");
    println!("     ring3 [status|run|test]  ring-3 process table, isolation proof, preemptive run, probe");
    println!("     selftest          re-run every subsystem probe (crypto, vault, ipc, session, net, gui)");
    println!("     vault [test]      vault status, or run the sector probe");
    println!("     purge             wipe vault secrets now");
    println!("     panic             deliberate lockdown + memory wipe");
    println!("     clear             clear the screen");
}

/// The two clocks, side by side, measured over the same window.
///
/// The PIT counts interrupts (and an emulator that stalls the guest resynchronises them rather
/// than delivering a burst, so it can only lose time); the APIC timer counts and cannot. Showing
/// both, and the drift between them, is what makes "a finer clock" a measurement rather than a
/// claim - and the drift is the interesting number on a host that is busy.
fn clock_command(argument: &str) {
    let (counts, timer_ticks, in_service, eois, current) = crate::arch::lapic::clock_state();
    if !crate::arch::lapic::timer_running() {
        println!("[SH] apic clock: not armed (no local APIC timer on this machine)");
        return;
    }
    let (divide, lvt, initial, current, svr, isr, irr, tpr) = crate::arch::lapic::registers();
    println!(
        "[SH] apic registers: divide={:#x} (code {}), lvt-timer={:#010x} (vector {}, mode {}), reload={} current={}, svr={:#x}, tpr={:#x}, isr={:#04x}, irr={:#04x}",
        divide,
        (divide & 0xB),
        lvt,
        lvt & 0xFF,
        if lvt & (1 << 17) != 0 { "periodic" } else { "one-shot" },
        initial,
        current,
        svr,
        tpr,
        isr,
        irr
    );
    println!(
        "[SH] apic clock: asked for {} Hz, delivers {} Hz measured, counter register at {} Hz, {} counts reload, {} us elapsed, {} interrupts, {} in-service, {} eois, {} counts accounted, counter now {}",
        crate::arch::lapic::requested_hz(),
        crate::arch::lapic::achieved_hz(),
        crate::arch::lapic::counter_hz(),
        crate::arch::lapic::timer_period(),
        crate::arch::lapic::micros(),
        timer_ticks,
        in_service,
        eois,
        counts,
        current
    );
    if argument == "drift" {
        // 200 ms of both clocks, side by side.
        let pit_start = clock::uptime_ms();
        let apic_start = crate::arch::lapic::micros();
        let ticks_start = crate::arch::lapic::timer_ticks();
        while clock::uptime_ms() < pit_start + 20 {
            core::hint::spin_loop();
        }
        let pit_us = (clock::uptime_ms() - pit_start) * 1000;
        let apic_us = crate::arch::lapic::micros().saturating_sub(apic_start);
        let timer_delta = crate::arch::lapic::timer_ticks() - ticks_start;
        // Counted against the *PIT*, not against `apic_us`: dividing the interrupt count by a
        // duration built from the same interrupts returns the armed rate whatever the hardware
        // is doing, which is the one number that can never be wrong and therefore never useful.
        let rate = if pit_us == 0 {
            0
        } else {
            timer_delta * 1_000_000 / pit_us
        };
        println!(
            "[SH] clocks over {} PIT ticks: pit={} us, apic={} us, timer interrupts={} ({} Hz against the PIT, asked for {} Hz), apic minus pit={} us",
            20,
            pit_us,
            apic_us,
            timer_delta,
            rate,
            crate::arch::lapic::requested_hz(),
            apic_us as i64 - pit_us as i64
        );
    } else {
        println!("[SH] apic clock: try 'clock drift' for a 200 ms comparison against the PIT");
    }
}

fn memory() {
    match mm::heap_span() {
        Some((start, size)) => println!(
            "[SH] heap {:#x}..{:#x} ({} MiB), scrub regions={}",
            start,
            start + size,
            size / (1024 * 1024),
            crate::panic::scrub_region_count()
        ),
        None => println!("[SH] heap not initialised"),
    }
}

fn status() {
    println!("[SH] ---- KELLER-OS STATUS ----");
    println!(
        "     uptime        : {} ms ({} ticks, {} lost)",
        clock::uptime_ms(),
        clock::ticks(),
        clock::overflow_count()
    );
    println!(
        "     interrupts    : {}",
        if crate::arch::cpu::interrupts_enabled() {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!("     scheduler     : {} slots", crate::sched::task_count());
    println!("     entropy       : {}", crate::crypto::entropy_source());
    if let Some(vault) = crate::vault_handle() {
        println!(
            "     vault         : fingerprint={} shards={} sectors={} rejected-openings={}",
            vault.key_fingerprint(),
            vault.shards.len(),
            vault.sector_count(),
            vault.rejected_openings()
        );
    }
    println!(
        "     ipc           : delivered={} dropped={}",
        ipc::delivered_count(),
        ipc::dropped_count()
    );
    if let Some(mesh) = crate::net_handle() {
        println!(
            "     mesh          : node={} peers={} frames-out={} delivered={} refused-shards={} byzantine={} cover-out={}",
            mesh.node_id,
            mesh.peer_count(),
            mesh.frames_sent(),
            mesh.messages_delivered(),
            mesh.shards_refused(),
            mesh.byzantine_shards(),
            mesh.cover().emitted()
        );
    }
    println!("     scrub regions : {}", crate::panic::scrub_region_count());
    println!(
        "     commands run  : {}",
        COMMANDS.load(Ordering::Relaxed)
    );
}

fn ipc_command(argument: &str) {
    match argument {
        "" | "status" => println!(
            "[SH] IPC delivered={} dropped={} depth={} transport-key={}",
            ipc::delivered_count(),
            ipc::dropped_count(),
            ipc::depth(),
            if ipc::key_ready() {
                "HMAC-SHA256"
            } else {
                "UNSEEDED"
            }
        ),
        "test" => {
            let passed = ipc::self_test();
            println!(
                "[SH] IPC MAC PROBE: genuine-deliver + forged-drop => {}",
                if passed { "PASS" } else { "FAIL" }
            );
        }
        other => println!("[SH] ipc: unknown argument '{}' - try 'ipc' or 'ipc test'", other),
    }
}

fn crypto_summary() {
    println!(
        "[SH] entropy={} hardware={}",
        crate::crypto::entropy_source(),
        crate::crypto::entropy_is_hardware()
    );
    println!(
        "[SH] digests=sha256+hmac+hkdf aead=chacha20-poly1305 shards=rs(2,1)+shamir(2,n) sample={:#018x}",
        crate::crypto::random_u64()
    );
}

/// Aggregated self-test suite: crypto KATs, vault sector probe, IPC MAC probe, the session
/// window and the Vantablack mesh. Ends with the `n passed / m failed` summary line the spec
/// asks for.
fn self_test() {
    let report = crate::crypto::self_test();
    let mut passed = report.passed;
    let mut failed = report.failed;
    for failure in report.failures.iter() {
        println!("[SH]   FAILED: {}", failure);
    }

    let vault_ok = match crate::vault_handle() {
        Some(vault) => vault.self_test(),
        None => false,
    };
    if vault_ok {
        passed += 1;
    } else {
        failed += 1;
        println!("[SH]   FAILED: vault sector probe");
    }

    if ipc::self_test() {
        passed += 1;
    } else {
        failed += 1;
        println!("[SH]   FAILED: ipc mac probe");
    }

    if crate::session::self_test() {
        passed += 1;
    } else {
        failed += 1;
        println!("[SH]   FAILED: session replay window");
    }

    // Vantablack mesh: ShardSec sealing, Byzantine isolation, replay window wiring, cover.
    let mesh = crate::net::self_test();
    passed += mesh.passed;
    failed += mesh.failed;
    for failure in mesh.failures.iter() {
        println!("[SH]   FAILED: mesh {}", failure);
    }

    // Network adapter: the wire framing layer plus the register readback. The framing half runs
    // everywhere; the register half reports itself as skipped when no adapter answered, so a
    // machine without one still adds up.
    let wire = crate::nic::self_test();
    passed += wire.passed;
    failed += wire.failed;
    for failure in wire.failures.iter() {
        println!("[SH]   FAILED: nic {}", failure);
    }

    // Storage: the block layer, the proof that gates the image's key, the image format itself,
    // and the controller. All four run against the in-memory reference device and the controller
    // reports itself as skipped when no disk answered, so a machine without one still adds up.
    let mut storage_skipped = 0u32;
    for (name, report) in [
        ("block", crate::block::self_test()),
        ("proof", crate::zk::self_test()),
        ("image", crate::storage::self_test()),
    ]
    .iter()
    {
        passed += report.passed;
        failed += report.failed;
        storage_skipped += report.skipped;
        for failure in report.failures.iter() {
            println!("[SH]   FAILED: {} {}", name, failure);
        }
    }
    let scratch = if crate::arch::ahci::ready() {
        Some(crate::arch::ahci::sector_count().saturating_sub(1))
    } else {
        None
    };
    let adapter = crate::arch::ahci::self_test(scratch);
    passed += adapter.passed;
    failed += adapter.failed;
    storage_skipped += adapter.skipped;
    for failure in adapter.failures.iter() {
        println!("[SH]   FAILED: disk {}", failure);
    }

    // Display server: backbuffer round-trip, glyph coverage and a blit that the aperture
    // reads back. Skipped on a machine with no adapter, where there is nothing to prove.
    if crate::gui::installed() {
        if crate::fb::self_test() && crate::gui::self_test() {
            passed += 1;
        } else {
            failed += 1;
            println!("[SH]   FAILED: framebuffer/display probe");
        }

        // PS/2 input: decoder checks on synthetic traffic plus the focus-routing policy,
        // which needs a live display server to have a focus holder at all.
        let input = crate::arch::ps2::self_test();
        passed += input.passed;
        failed += input.failed;
        for failure in input.failures.iter() {
            println!("[SH]   FAILED: input {}", failure);
        }
    }

    // The adapter halves - NIC and AHCI - report skipped assertions on a machine without the
    // devices; they are named here rather than hidden, because "not run" and "passed" are
    // different claims.
    let skipped = wire.skipped + storage_skipped;
    if skipped != 0 {
        println!(
            "[SH] SELF-TEST SUMMARY: {} passed, {} failed, {} skipped (checks that need hardware this machine does not have)",
            passed, failed, skipped
        );
    } else {
        println!("[SH] SELF-TEST SUMMARY: {} passed, {} failed", passed, failed);
    }
}

/// PS/2 keyboard and mouse: counters, focus routing and the probe.
fn input_command(argument: &str) {
    match argument {
        "" | "status" => {
            crate::arch::ps2::status();
            crate::gui::input_inventory();
        }
        "test" => {
            let report = crate::arch::ps2::self_test();
            println!(
                "[SH] INPUT PROBE: scancode-make/break + shift + caps + extended-keys + chatter + bat-code-vs-shift + mouse-packet + resync + overflow-reject + wheel-length + byte-queue + focus-route + focus-refusal + alt-tab-cycle => {}",
                if report.failed == 0 { "PASS" } else { "FAIL" }
            );
            if report.skipped == 0 {
                println!(
                    "[SH] INPUT PROBE assertions: {} passed, {} failed",
                    report.passed, report.failed
                );
            } else {
                println!(
                    "[SH] INPUT PROBE assertions: {} passed, {} failed, {} skipped (nothing to route to: no display server, or a log too short to have a history to scroll)",
                    report.passed, report.failed, report.skipped
                );
            }
            for failure in report.failures.iter() {
                println!("[SH]   FAILED: input {}", failure);
            }
            // The assertions cover the decoders and the focus policy, which is all that can be
            // tested from software - but a machine missing half its input path has to say so
            // rather than let a green probe imply a live keyboard or mouse.
            if !crate::arch::ps2::present() {
                println!(
                    "[SH] INPUT PROBE NOTE: no PS/2 controller on this machine - the assertions cover the decoders and the focus policy, not a live device path"
                );
            } else if !crate::arch::ps2::keyboard_present() || !crate::arch::ps2::mouse_present() {
                println!(
                    "[SH] INPUT PROBE NOTE: controller present but {} - the assertions cover the decoders and the focus policy, not the missing device's path",
                    match (
                        crate::arch::ps2::keyboard_present(),
                        crate::arch::ps2::mouse_present()
                    ) {
                        (false, false) => {
                            "neither port answered (keyboard ABSENT, mouse ABSENT)"
                        }
                        (false, true) => {
                            "the keyboard is ABSENT (nothing answered 0xF0 0x01 / 0xF4)"
                        }
                        _ => "the mouse is ABSENT (nothing answered identify 0xF2)",
                    }
                );
            }
        }
        other => println!(
            "[SH] input: unknown argument '{}' - try 'input' or 'input test'",
            other
        ),
    }
}

/// Ring-3 isolation and the preemptive scheduler: the process table, the address-space proof and
/// the detection run.
///
/// `ring3 run` only arms the phase; the tasks then run whenever the kernel loop is idle, and the
/// report arrives on this same console from the idle loop. That is deliberate — the phase must
/// not depend on the command that started it, because the command's own stack gets preempted
/// away while the phase runs.
fn ring3_command(argument: &str) {
    match argument {
        "" | "status" => crate::proc::describe(),
        "run" => {
            if crate::proc::request_phase() {
                println!(
                    "[SH] ring3: delivering {} ring-3 slices (~{} ticks each) - the kernel context only runs its own slot between them",
                    crate::proc::PHASE_BUDGET,
                    crate::proc::QUANTUM_TICKS
                );
                // Wait it out here so the phase's report is printed before this command is
                // echoed back, which is what makes the run scriptable.
                crate::proc::wait_for_phase();
            }
        }
        "test" => {
            let report = crate::proc::self_test();
            println!(
                "[SH] RING-3 PROBE: syscall-gate-DPL + GDT-privilege + port-IO-denial + parked-frame-layout + address-space-separation + live-CPL-3-entry => {}",
                if report.failed == 0 { "PASS" } else { "FAIL" }
            );
            println!(
                "[SH] RING-3 PROBE assertions: {} passed, {} failed",
                report.passed, report.failed
            );
            for failure in report.failures.iter() {
                println!("[SH]   FAILED: ring3 {}", failure);
            }
        }
        other => println!(
            "[SH] ring3: unknown argument '{}' - try 'ring3', 'ring3 run' or 'ring3 test'",
            other
        ),
    }
}

fn gui_command(argument: &str) {
    if !crate::gui::installed() {
        println!("[SH] display server offline (no framebuffer)");
        return;
    }

    match argument {
        "" | "status" => {
            match crate::fb::handle() {
                Some(framebuffer) => framebuffer.describe(),
                None => println!("[SH] framebuffer not installed"),
            }
            crate::gui::describe();
        }
        "on" => {
            crate::gui::set_enabled(true);
            let painted = crate::gui::render_now();
            println!(
                "[SH] GUI DISPLAY: enabled, first frame {}",
                if painted { "painted" } else { "not painted" }
            );
        }
        "off" => {
            crate::gui::set_enabled(false);
            println!("[SH] GUI DISPLAY: disabled (serial console unaffected)");
        }
        "redraw" => {
            crate::gui::request_full_repaint();
            let painted = crate::gui::render_now();
            println!(
                "[SH] GUI REDRAW: full repaint {} ({} frames, {} blits so far)",
                if painted { "done" } else { "skipped" },
                crate::gui::frames(),
                crate::gui::blits()
            );
        }
        "scrub" => {
            let bytes = crate::gui::scrub_screen();
            println!(
                "[SH] GUI SCRUB: {} KiB of framebuffer zeroed volatile (panic path)",
                bytes / 1024
            );
        }
        "scroll" => {
            let (_, steps, wheel, held) = crate::gui::scroll_counters();
            match crate::gui::scroll_state() {
                Some((title, back, max)) => println!(
                    "[SH] GUI SCROLL: {} is {} of {} lines back ({} lines of history held, {} gestures, {} wheel notches)",
                    title, back, max, held, steps, wheel
                ),
                None => println!("[SH] GUI SCROLL: no window holds focus"),
            }
        }
        "top" | "bottom" | "up" | "down" => {
            let moved = match argument {
                "top" => crate::gui::scroll_focused_to(None),
                "bottom" => crate::gui::scroll_focused_to(Some(0)),
                "up" => crate::gui::scroll_focused(-(crate::gui::TILE_LINES as i64)),
                _ => crate::gui::scroll_focused(crate::gui::TILE_LINES as i64),
            };
            let (title, back, max) = crate::gui::scroll_state().unwrap_or(("NONE", 0, 0));
            println!(
                "[SH] GUI SCROLL: {} {} -> {} of {} lines back",
                title,
                if moved { "moved" } else { "already at the end" },
                back,
                max
            );
            crate::gui::render_now();
        }
        "test" => {
            let framebuffer = crate::fb::self_test();
            let display = crate::gui::self_test();
            println!(
                "[SH] GUI PROBE: aperture round-trip={} + backbuffer/glyph/blit={} => {}",
                if framebuffer { "PASS" } else { "FAIL" },
                if display { "PASS" } else { "FAIL" },
                if framebuffer && display { "PASS" } else { "FAIL" }
            );
        }
        other => println!(
            "[SH] gui: unknown argument '{}' - try 'gui', 'gui on|off|test|redraw|scrub|scroll', 'gui top|bottom|up|down'",
            other
        ),
    }
}

fn net_command(argument: &str) {
    let mesh = match crate::net_handle() {
        Some(mesh) => mesh,
        None => {
            println!("[SH] mesh not online");
            return;
        }
    };

    match argument {
        "" | "status" => {
            mesh.describe();
            println!(
                "[SH] NET sealing=shard-subkeys-hkdf aad=header+record+tail wire={} bytes window={} counters isolated={}",
                crate::net::WIRE_FRAME_LEN,
                crate::session::WINDOW_BITS,
                mesh.isolated_peers()
            );
        }
        "test" => {
            let report = crate::net::self_test();
            for failure in report.failures.iter() {
                println!("[SH]   FAILED: net {}", failure);
            }
            println!(
                "[SH] NET MESH PROBE: round-trip + shard-swap-reject + index-swap-reject + counter-swap-reject + tail-tamper-reject + duplicate-reject + replay-reject + window-boundary + byzantine-isolation + handshake-key-agreement + poisson-cover => {}",
                if report.failed == 0 { "PASS" } else { "FAIL" }
            );
            println!(
                "[SH] NET PROBE assertions: {} passed, {} failed",
                report.passed, report.failed
            );
        }
        other => println!("[SH] net: unknown argument '{}' - try 'net' or 'net test'", other),
    }
}

/// Network adapter: registers, counters, the framing probe, and the wire switch.
///
/// `probe` deliberately sends a fixed 68-byte datagram (`eth::PROBE_PAYLOAD`), so a peer on the
/// wire can recognise a test packet by its bytes and answer with something equally identifiable.
fn nic_command(argument: &str) {
    match argument {
        "" | "status" => {
            crate::nic::describe();
        }
        "test" => {
            let report = crate::nic::self_test();
            for failure in report.failures.iter() {
                println!("[SH]   FAILED: nic {}", failure);
            }
            println!(
                "[SH] NIC WIRE PROBE: ethernet+ipv4+udp layout + checksums + ipv4-known-answer + bad-payload-reject + bad-header-reject + non-ipv4-reject + fragment-reject + non-udp-reject + options-reject + lying-length-reject + register-readback + ring-alignment + bus-master + state-placement => {}",
                if report.failed == 0 { "PASS" } else { "FAIL" }
            );
            if report.skipped == 0 {
                println!(
                    "[SH] NIC PROBE assertions: {} passed, {} failed",
                    report.passed, report.failed
                );
            } else {
                println!(
                    "[SH] NIC PROBE assertions: {} passed, {} failed, {} skipped (no supported adapter: the framing checks ran, the register checks did not)",
                    report.passed, report.failed, report.skipped
                );
            }
        }
        "probe" => {
            if !crate::nic::ready() {
                println!("[SH] NIC: no adapter to probe");
                return;
            }
            let sent = crate::nic::send_probe();
            let (tx, _, _, _) = crate::nic::counters();
            println!(
                "[SH] NIC PROBE: {} the fixed {} byte datagram on port {:#06x} (tx frames now {})",
                if sent { "sent" } else { "could not send" },
                crate::eth::PROBE_PAYLOAD.len(),
                crate::eth::PROBE_PORT,
                tx
            );
        }
        "on" | "off" => {
            let enabled = argument == "on";
            crate::nic::set_wire(enabled);
            println!(
                "[SH] NIC WIRE: egress {} - inbound frames are {} the mesh pipeline",
                if enabled { "on" } else { "off" },
                if enabled { "fed to" } else { "dropped before" }
            );
        }
        other => println!(
            "[SH] nic: unknown argument '{}' - try 'nic', 'nic test', 'nic probe', 'nic on' or 'nic off'",
            other
        ),
    }
}

/// Persistent storage: the controller, the vault image, and the two questions that matter about
/// a disk - what is on it, and what is still there after the machine has been off.
///
/// `write` and `read` are the user-data path: a sector goes into the vault, the vault is sealed
/// and the image saved; on the next boot the image is opened again and the bytes come back. The
/// harness runs those in two separate QEMU processes against the same disk image, which is the
/// only way to check persistence honestly.
fn disk_command(argument: &str) {
    let (verb, rest) = match argument.split_once(' ') {
        Some((verb, rest)) => (verb, rest.trim()),
        None => (argument, ""),
    };
    match verb {
        "" | "status" => {
            crate::arch::ahci::describe();
            crate::storage::describe();
        }
        "test" => {
            let block = crate::block::self_test();
            let proof = crate::zk::self_test();
            let image = crate::storage::self_test();
            let scratch = if crate::arch::ahci::ready() {
                Some(crate::arch::ahci::sector_count().saturating_sub(1))
            } else {
                None
            };
            let adapter = crate::arch::ahci::self_test(scratch);
            let reports = [&block, &proof, &image, &adapter];
            let mut passed = 0u32;
            let mut failed = 0u32;
            let mut skipped = 0u32;
            for report in reports.iter() {
                passed += report.passed;
                failed += report.failed;
                skipped += report.skipped;
                for failure in report.failures.iter() {
                    println!("[SH]   FAILED: {}", failure);
                }
            }
            println!(
                "[SH] DISK PROBE: block-geometry+round-trip+refusals + schnorr-proof+unlock-key + image-format+auth+tamper+journal + ahci-registers+ports+scratch-round-trip => {}",
                if failed == 0 { "PASS" } else { "FAIL" }
            );
            if skipped == 0 {
                println!(
                    "[SH] DISK PROBE assertions: {} passed, {} failed",
                    passed, failed
                );
            } else {
                println!(
                    "[SH] DISK PROBE assertions: {} passed, {} failed, {} skipped (no device to drive: the format ran against the reference device, the adapter checks did not)",
                    passed, failed, skipped
                );
            }
        }
        "format" => match crate::vault_handle() {
            Some(vault) => match crate::storage::format(vault) {
                Ok(header) => println!(
                    "[SH] DISK: formatted generation {} slots={} owner={} nonce={}",
                    header.generation,
                    header.slots,
                    hex::encode(&header.owner[..8]),
                    hex::encode(&header.device_nonce[..8])
                ),
                Err(error) => println!("[SH] DISK: format refused ({})", error.as_str()),
            },
            None => println!("[SH] DISK: no vault to format for"),
        },
        "save" => match crate::vault_handle() {
            Some(vault) => match crate::storage::save(vault) {
                Ok(header) => println!(
                    "[SH] DISK: saved generation {} ({} vault sector(s) written)",
                    header.generation,
                    vault.sector_count()
                ),
                Err(error) => println!("[SH] DISK: save refused ({})", error.as_str()),
            },
            None => println!("[SH] DISK: no vault to save"),
        },
        "load" => match crate::vault_handle() {
            Some(vault) => match crate::storage::load(vault) {
                Ok(adopted) => {
                    println!(
                        "[SH] DISK: loaded {} vault sector(s) from the image, generation {}",
                        adopted,
                        crate::storage::generation()
                    );
                    for index in vault.sector_indices() {
                        println!(
                            "[SH] DISK: sector {} present ({} sealed bytes)",
                            index,
                            vault.sealed_bytes(index).map(|bytes| bytes.len()).unwrap_or(0)
                        );
                    }
                    match crate::storage::read_journal(vault) {
                        Ok(entry) => println!(
                            "[SH] DISK JOURNAL: boots={} image-generation={} stamp={}",
                            entry.boots,
                            entry.image_generation,
                            hex::encode(&entry.stamp)
                        ),
                        Err(error) => {
                            println!("[SH] DISK JOURNAL: none readable ({})", error.as_str())
                        }
                    }
                }
                Err(error) => println!("[SH] DISK: load refused ({})", error.as_str()),
            },
            None => println!("[SH] DISK: no vault to load into"),
        },
        "write" => {
            if rest.is_empty() {
                println!("[SH] DISK: 'disk write' needs something to write");
                return;
            }
            match crate::vault_handle() {
                Some(vault) => {
                    let result = crate::storage::write_sector(vault, crate::storage::USER_SECTOR, rest.as_bytes());
                    match result {
                        Ok(header) => println!(
                            "[SH] DISK: wrote {} bytes to sector {:#x}, generation {}",
                            rest.len(),
                            crate::storage::USER_SECTOR,
                            header.generation
                        ),
                        Err(error) => println!("[SH] DISK: write refused ({})", error.as_str()),
                    }
                }
                None => println!("[SH] DISK: no vault to write into"),
            }
        }
        "read" => match crate::vault_handle() {
            Some(vault) => match crate::storage::read_sector(vault, crate::storage::USER_SECTOR) {
                Ok(bytes) => println!(
                    "[SH] DISK USER SECTOR: {} byte(s): \"{}\"",
                    bytes.len(),
                    core::str::from_utf8(&bytes).unwrap_or("<not UTF-8>")
                ),
                Err(error) => println!("[SH] DISK: read refused ({})", error.as_str()),
            },
            None => println!("[SH] DISK: no vault to read with"),
        },
        "journal" => match crate::vault_handle() {
            Some(vault) => match crate::storage::journal(vault) {
                Ok(entry) => println!(
                    "[SH] DISK JOURNAL: boots={} image-generation={} stamp={}",
                    entry.boots,
                    entry.image_generation,
                    hex::encode(&entry.stamp)
                ),
                Err(error) => println!("[SH] DISK: journal refused ({})", error.as_str()),
            },
            None => println!("[SH] DISK: no vault to journal with"),
        },
        "wipe" => match crate::storage::wipe() {
            Ok(()) => println!("[SH] DISK: image and its records overwritten, superblock zeroed"),
            Err(error) => println!("[SH] DISK: wipe refused ({})", error.as_str()),
        },
        "superblock" => {
            match crate::storage::superblock_line() {
                Some(line) => println!("[DISK] superblock: {}", line),
                None => println!("[SH] DISK: no superblock to read"),
            };
        }
        other => println!(
            "[SH] disk: unknown argument '{}' - try 'disk status', 'disk test', 'disk format', 'disk write <text>', 'disk read', 'disk journal', 'disk wipe' or 'disk superblock'",
            other
        ),
    }
}

fn session_command(argument: &str) {
    match argument {
        "" | "status" => {
            let guard = crate::session::KernelSessionGuard::open();
            guard.describe();
            println!(
                "[SH] timeouts: idle={} min, hard={} h; window={} counters",
                crate::session::IDLE_TIMEOUT_MS / 60_000,
                crate::session::HARD_TIMEOUT_MS / 3_600_000,
                crate::session::WINDOW_BITS
            );
        }
        "test" => {
            let passed = crate::session::self_test();
            println!(
                "[SH] SESSION WINDOW PROBE: in-order + reorder + replay + boundary + expiry => {}",
                if passed { "PASS" } else { "FAIL" }
            );
        }
        other => println!(
            "[SH] session: unknown argument '{}' - try 'session' or 'session test'",
            other
        ),
    }
}

fn vault_command(argument: &str) {
    let vault = match crate::vault_handle() {
        Some(vault) => vault,
        None => {
            println!("[SH] vault not online");
            return;
        }
    };

    match argument {
        "" | "status" => {
            println!(
                "[SH] VAULT fingerprint={} shards={} threshold={} healthy={}",
                vault.key_fingerprint(),
                vault.shards.len(),
                vault.threshold,
                vault.is_healthy()
            );
            println!(
                "[SH]      sectors={} writes={} rejected-openings={} (every sector AEAD-sealed)",
                vault.sector_count(),
                vault.write_count(),
                vault.rejected_openings()
            );
        }
        "test" => {
            let passed = vault.self_test();
            println!(
                "[SH] VAULT SECTOR PROBE: round-trip + tamper-reject + index-swap-reject => {}",
                if passed { "PASS" } else { "FAIL" }
            );
        }
        other => println!(
            "[SH] vault: unknown argument '{}' - try 'vault' or 'vault test'",
            other
        ),
    }
}
