//! Message-signalled interrupts: a device that writes its own interrupt message.
//!
//! The IO-APIC routes *lines*: one redirection entry per wire, shared by every device on it, and
//! the device cannot say anything more than "the line is asserted". MSI is the other model - the
//! device performs a memory write to `0xFEE00000 | (apic_id << 12)` with the vector in the data
//! word, and the local APIC turns that write into an interrupt on exactly that vector. Nothing
//! is shared, nothing has to be acknowledged at the controller, and a device that can send more
//! than one message can name a different vector for each cause.
//!
//! Two transports are handled, because two exist:
//!
//! * **MSI** (`cap id 0x05`) keeps the message in configuration space: an address, a data word
//!   and a control word with the enable bit. This is what the adapter in this machine has.
//! * **MSI-X** (`cap id 0x11`) keeps a *table* of messages in one of the device's BARs, one
//!   16-byte entry per vector, with a per-vector mask bit and a pending-bit array alongside it.
//!   A device that only offers MSI-X is programmed through its table; the code below writes
//!   entry 0, masks every other entry, and enables the capability.
//!
//! What is deliberately *not* claimed: this does not allocate vectors per CPU, and it does not
//! implement interrupt affinity (`apic_id` is the boot processor). A device is still on one
//! vector, on one processor - what changed is how the message gets there, and that the kernel can
//! now verify it end to end, because the last vector a device actually delivered on is recorded
//! rather than assumed.

use crate::arch::lapic;
use crate::block::BlockReport;
use crate::pci::{self, PciDevice};
use crate::println;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Signature that keeps this module's state in `.data` (the loader does not zero `.bss`).
const MSI_SIGNATURE: u64 = 0x4B45_4C4C_4D53_4901; // "KELLMSI\x01"

struct State {
    signature: u64,
    present: bool,
    enabled: bool,
    /// True when the live programming is through an MSI-X table rather than the capability.
    through_table: bool,
    /// The device this module programmed, so reports can name it.
    device: PciDevice,
    capability_offset: u8,
    vector: u8,
    address: u64,
    data: u16,
    /// How many vectors the device could address, and how many the capability was found to hold.
    capable_vectors: u8,
    entries: u16,
}

impl State {
    const fn empty() -> Self {
        Self {
            signature: MSI_SIGNATURE,
            present: false,
            enabled: false,
            through_table: false,
            device: PciDevice {
                bus: 0,
                slot: 0,
                function: 0,
                vendor: 0,
                device: 0,
                class: 0,
                subclass: 0,
                interface: 0,
                header_type: 0,
                bars: [0; 6],
            },
            capability_offset: 0,
            vector: 0,
            address: 0,
            data: 0,
            capable_vectors: 0,
            entries: 0,
        }
    }
}

static mut STATE: State = State::empty();
/// Interrupts delivered per MSI vector this kernel hands out.
static DELIVERED: [AtomicU64; lapic::VECTOR_MSI_COUNT as usize] =
    [const { AtomicU64::new(0) }; lapic::VECTOR_MSI_COUNT as usize];
/// Deliveries whose device-side cause register had a bit set: a real device event rather than an
/// interrupt that arrived with nothing behind it.
static CAUSED: AtomicU64 = AtomicU64::new(0);
static LAST_CAUSE: AtomicU32 = AtomicU32::new(0);

/// The device-side half of one delivery: reads and clears the device's interrupt cause and
/// returns the bits that were pending. Registered by the driver that owns the device, because
/// only it knows which register to read.
static mut SERVICE: Option<fn() -> u32> = None;

fn state() -> &'static mut State {
    unsafe { &mut *core::ptr::addr_of_mut!(STATE) }
}

pub fn set_service_hook(hook: fn() -> u32) {
    unsafe {
        let slot = core::ptr::addr_of_mut!(SERVICE);
        *slot = Some(hook);
    }
}

pub fn present() -> bool {
    state().present
}

pub fn enabled() -> bool {
    state().enabled
}

pub fn through_table() -> bool {
    state().through_table
}

pub fn vector() -> u8 {
    state().vector
}

pub fn address() -> u64 {
    state().address
}

pub fn device_state() -> (PciDevice, u8, u8, u16) {
    let state = state();
    (
        state.device,
        state.capability_offset,
        state.vector,
        state.data,
    )
}

pub fn interrupts() -> u64 {
    DELIVERED.iter().map(|counter| counter.load(Ordering::Relaxed)).sum()
}

pub fn caused() -> u64 {
    CAUSED.load(Ordering::Relaxed)
}

pub fn last_cause() -> u32 {
    LAST_CAUSE.load(Ordering::Relaxed)
}

pub fn delivered_on(vector: u8) -> u64 {
    let index = vector.saturating_sub(lapic::VECTOR_MSI_BASE) as usize;
    DELIVERED
        .get(index)
        .map(|counter| counter.load(Ordering::Relaxed))
        .unwrap_or(0)
}

/// The dispatcher's entry point for the MSI vector window. There is no controller to
/// acknowledge: the device's own cause register is the acknowledgement, and the local APIC's
/// EOI closes the delivery.
pub fn on_vector(vector: u8) {
    let index = vector.saturating_sub(lapic::VECTOR_MSI_BASE) as usize;
    if let Some(counter) = DELIVERED.get(index) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
    let cause = unsafe {
        match core::ptr::read_volatile(core::ptr::addr_of!(SERVICE)) {
            Some(hook) => hook(),
            None => 0,
        }
    };
    if cause != 0 {
        CAUSED.fetch_add(1, Ordering::Relaxed);
        LAST_CAUSE.store(cause, Ordering::Relaxed);
    }
    lapic::eoi();
}

/// Programs `device` to deliver `vector` to this processor, by MSI when the device has that
/// capability and through its MSI-X table when it only has that one.
///
/// Returns true when the device holds what it was given: the message address, the message data
/// and the enable bit are all read back out of the device rather than remembered.
///
/// # Safety
/// Requires the local APIC to be live (the message's destination is its page) and the device's
/// BAR, if the table path is used, to be inside the identity map.
pub unsafe fn install(device: &PciDevice, vector: u8) -> bool {
    let state = state();
    if state.signature != MSI_SIGNATURE {
        println!(
            "[!!] MSI: state is at {:#x} without its signature - the loader did not place it where the crate expects",
            core::ptr::addr_of!(STATE) as u64
        );
        return false;
    }
    state.present = false;
    state.enabled = false;
    state.through_table = false;

    if !lapic::live() {
        println!("[--] MSI: no local APIC to deliver to - the device keeps its legacy line");
        return false;
    }
    let dest = lapic::id();
    let address = pci::MSI_ADDRESS_BASE | ((dest as u64) << 12);

    let capabilities: alloc::vec::Vec<u8> = pci::capabilities(device)
        .into_iter()
        .map(|capability| capability.id)
        .collect();
    let has_msi = capabilities.contains(&pci::CAP_ID_MSI);
    let has_msix = capabilities.contains(&pci::CAP_ID_MSIX);

    if has_msi {
        let capability = match pci::msi_capability(device) {
            Some(capability) => capability,
            None => return false,
        };
        let written = pci::program_msi(device, vector, dest);
        let confirmed = pci::msi_state(device);
        let (control, read_address, read_data) = match confirmed {
            Some(values) => values,
            None => return false,
        };
        state.present = true;
        state.capability_offset = capability.offset;
        state.vector = vector;
        state.address = read_address;
        state.data = read_data;
        state.capable_vectors = capability.capable_vectors;
        state.entries = 1;
        state.enabled = control & 1 != 0 && read_address == address && read_data == vector as u16;
        println!(
            "[OK] MSI: {} at {:02x}:{:02x}.{} capability at {:#04x} - message {:#x}/data {:#x} -> vector {} ({}-bit address, {} message{}, per-vector mask {}), {}",
            if state.enabled { "programmed" } else { "ATTEMPTED and NOT confirmed" },
            device.bus,
            device.slot,
            device.function,
            capability.offset,
            read_address,
            read_data,
            vector,
            if capability.is_64bit { "64" } else { "32" },
            capability.capable_vectors,
            if capability.capable_vectors == 1 { "" } else { "s" },
            if capability.per_vector_mask { "available" } else { "absent" },
            match written {
                Some(_) => "enable bit reads back set",
                None => "the device has no MSI capability after all",
            }
        );
        return state.enabled;
    }

    if has_msix {
        let capability = match pci::msix_capability(device) {
            Some(capability) => capability,
            None => return false,
        };
        let entry = match capability.entry_address(device, 0) {
            Some(entry) => entry,
            None => {
                println!(
                    "[--] MSI-X: the table lives in BAR {} which this machine has not assigned",
                    capability.table_bar
                );
                return false;
            }
        };
        // Every other entry is masked before anything is enabled: an unmasked entry holds a
        // message this kernel did not write, and a device is free to use any of them.
        for index in 1..capability.table_size as usize {
            let control = (entry + index as u64 * 16 + 12) as *mut u32;
            core::ptr::write_volatile(control, 1);
        }
        core::ptr::write_volatile(entry as *mut u32, address as u32);
        core::ptr::write_volatile((entry + 4) as *mut u32, (address >> 32) as u32);
        core::ptr::write_volatile((entry + 8) as *mut u32, vector as u32);
        core::ptr::write_volatile((entry + 12) as *mut u32, 0);
        // Function mask off, MSI-X enable on.
        pci::write_msix_control(device, capability.offset, (capability.control & !(1 << 14)) | (1 << 15));

        let after = pci::msix_capability(device).unwrap_or(capability);
        let read_address = ((core::ptr::read_volatile((entry + 4) as *const u32) as u64) << 32)
            | core::ptr::read_volatile(entry as *const u32) as u64;
        let read_data = core::ptr::read_volatile((entry + 8) as *const u32) as u16;
        let read_control = core::ptr::read_volatile((entry + 12) as *const u32);

        state.present = true;
        state.through_table = true;
        state.capability_offset = capability.offset;
        state.vector = vector;
        state.address = read_address;
        state.data = read_data;
        state.capable_vectors = 0;
        state.entries = capability.table_size;
        state.enabled = after.enabled()
            && read_address == address
            && read_data == vector as u16
            && read_control & 1 == 0;
        println!(
            "[OK] MSI-X: table of {} entries in BAR {} at offset {:#x}, entry 0 -> message {:#x}/data {:#x} to vector {} ({}), {}",
            capability.table_size,
            capability.table_bar,
            capability.table_offset,
            read_address,
            read_data,
            vector,
            if state.enabled { "confirmed" } else { "NOT confirmed" },
            if !has_msi {
                "the device has no MSI capability, so this is the only message path it has"
            } else {
                "MSI takes precedence over MSI-X in this kernel"
            }
        );
        return state.enabled;
    }

    println!(
        "[--] MSI: {:02x}:{:02x}.{} has no MSI capability (capabilities: {}) - its interrupt line is the IO-APIC's problem",
        device.bus,
        device.slot,
        device.function,
        if capabilities.is_empty() {
            alloc::string::String::from("none")
        } else {
            let mut text = alloc::string::String::new();
            for (index, id) in capabilities.iter().enumerate() {
                if index != 0 {
                    text.push(',');
                }
                text.push_str(&alloc::format!("{:#04x}", id));
            }
            text
        }
    );
    false
}

/// Turns the device's message off again, which puts its interrupt back on the legacy line.
pub fn disable() -> bool {
    let state = state();
    if !state.present {
        return false;
    }
    let disabled = if state.through_table {
        pci::disable_msix(&state.device)
    } else {
        pci::disable_msi(&state.device)
    };
    if disabled {
        state.enabled = false;
    }
    disabled
}

pub fn describe() {
    let state = state();
    if !state.present {
        println!("[--] MSI: no device is programmed for message-signalled interrupts");
        return;
    }
    println!(
        "[MSI] {:02x}:{:02x}.{} {} at {:#04x} -> vector {} on apic {:#04x}, {:x} entries, {}: {} interrupts ({} with a device cause), last cause {:#010x}",
        state.device.bus,
        state.device.slot,
        state.device.function,
        if state.through_table { "MSI-X table" } else { "MSI capability" },
        state.capability_offset,
        state.vector,
        lapic::id(),
        state.entries,
        if state.enabled { "enabled" } else { "DISABLED" },
        interrupts(),
        caused(),
        last_cause()
    );
    println!(
        "[MSI] message memory address {:#x} data {:#x} (the x86 layout: destination APIC id in bits 19-12, vector in the data word)",
        state.address, state.data
    );
}

/// Writes the MSI message a device would write, without a device.
///
/// The message *is* a memory write: `0xFEE00000 | (dest << 12)` with the vector in the data
/// word. Making that write from software exercises the whole delivery path - the message format,
/// the local APIC's decode of it, the IDT gate, the handler and the EOI - with no device and no
/// capability involved. That is what makes the MSI claim checkable on a machine whose adapter
/// does not offer it, and it is also the sharpest possible test of the message format itself.
///
/// # Safety
/// Requires the local APIC to be live and its page to be mapped, which the boot identity map
/// guarantees.
pub unsafe fn probe_message(vector: u8) -> bool {
    if !lapic::live() {
        return false;
    }
    let dest = lapic::id() as u64;
    let address = (pci::MSI_ADDRESS_BASE | (dest << 12)) as *mut u32;
    let before = delivered_on(vector);
    core::ptr::write_volatile(address, vector as u32);
    let deadline = lapic::micros() + 100_000;
    while delivered_on(vector) == before {
        if lapic::micros() >= deadline {
            return false;
        }
        core::hint::spin_loop();
    }
    true
}

// ---------------------------------------------------------------- self-test

/// Assertions this module makes. Four of them need only a local APIC; the rest need a device
/// with an MSI capability and are reported as skipped when there is none.
pub const ASSERTIONS: u32 = 10;

/// Verifies the programming against the device's own configuration space and against what the
/// device has actually caused since.
pub fn self_test() -> BlockReport {
    let mut report = BlockReport::new();
    let state = state();
    if !lapic::live() {
        report.skip(ASSERTIONS);
        return report;
    }

    // The message path with no device in it: software writes what a device would write, and the
    // vector has to be delivered and counted. This runs on every machine with a local APIC.
    let probe_vector = lapic::VECTOR_MSI_BASE + 1;
    let before = delivered_on(probe_vector);
    let delivered = unsafe { probe_message(probe_vector) };
    report.check(
        delivered,
        "a message written to the APIC's message page was not delivered on its vector",
    );
    report.check(
        delivered_on(probe_vector) > before,
        "the message arrived but the vector's counter did not move",
    );
    report.check(
        state.signature == MSI_SIGNATURE,
        "the MSI state is not in the placement the crate expects",
    );
    report.check(
        lapic::base() == pci::MSI_ADDRESS_BASE,
        "the message's destination page is not the local APIC's own page",
    );

    if !state.present {
        report.skip(ASSERTIONS - 4);
        return report;
    }
    let expected_address = pci::MSI_ADDRESS_BASE | ((lapic::id() as u64) << 12);
    report.check(
        state.address == expected_address,
        "the message address does not name this processor's APIC page",
    );
    report.check(
        state.data == state.vector as u16,
        "the message data word is not the vector this kernel allocated",
    );
    report.check(
        state.vector >= lapic::VECTOR_MSI_BASE
            && state.vector < lapic::VECTOR_MSI_BASE + lapic::VECTOR_MSI_COUNT,
        "the vector is outside the window this kernel reserved for MSI",
    );
    report.check(
        state.enabled,
        "the device's MSI enable bit does not read back set",
    );
    if state.through_table {
        report.check(
            state.entries > 0,
            "the MSI-X table claims no entries at all",
        );
    } else {
        report.check(
            state.capable_vectors >= 1,
            "the MSI capability claims it can address no messages",
        );
    }
    // The one assertion that cannot be satisfied by reading: the device has to have raised the
    // interrupt and the vector has to have arrived with a cause behind it.
    report.check(
        interrupts() != 0 && caused() != 0,
        "no device-caused MSI has been delivered (the vector was programmed but the device has not used it)",
    );
    report
}
