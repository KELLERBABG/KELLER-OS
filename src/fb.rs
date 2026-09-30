//! Graphics adapter bring-up and the linear framebuffer (GUI_SPECIFICATION.md §3).
//!
//! Two acquisition paths, in the order the specification lists them:
//!
//! 1. **Bootloader hand-off** — a Multiboot2 framebuffer tag (`bootinfo.rs` parses it).
//! 2. **Bochs / QEMU VGA (BGA)** — the fallback this kernel actually uses, because it boots
//!    through PVH (`-kernel`), where no firmware has programmed the adapter: no framebuffer
//!    tag arrives, the VGA BAR is unassigned and memory decoding is off. The driver therefore
//!    enumerates PCI, assigns/enables the adapter's BAR0, programs the Bochs VBE registers
//!    (`0x01CE`/`0x01CF`) for a linear 32-bpp mode, and verifies the result by writing and
//!    reading back pixels before anything is drawn.
//!
//! The aperture stays mapped by the boot identity map (2 MiB pages marked present+writable),
//! which QEMU backs with ordinary RAM, so cached writes land in the adapter's VRAM. On real
//! hardware the LFB pages must additionally be mapped uncached; that is noted here rather
//! than assumed, and the read-back probe is what would expose it.

use crate::pci;
use crate::port::{inb, outw};

/// Bochs VBE register index/data ports (the legacy path).
pub const DISPI_INDEX_PORT: u16 = 0x01CE;
pub const DISPI_DATA_PORT: u16 = 0x01CF;
/// Offset of the flat dispi register block inside the adapter's MMIO bar, and the preferred
/// address to give that bar when the loader left it unassigned.
const DISPI_MMIO_OFFSET: u64 = 0x500;
const MMIO_BAR_PREFERRED: u64 = 0x0000_0000_FEBE_0000;
/// QEMU/Bochs default framebuffer aperture, and the ISA variant's fixed window.
const DEFAULT_LFB_BASE: u64 = 0xFD00_0000;

/// Bochs VBE register indices.
const DISPI_ID: u16 = 0x00;
const DISPI_XRES: u16 = 0x01;
const DISPI_YRES: u16 = 0x02;
const DISPI_BPP: u16 = 0x03;
const DISPI_ENABLE: u16 = 0x04;
const DISPI_VIRT_WIDTH: u16 = 0x06;
const DISPI_VIRT_HEIGHT: u16 = 0x07;
const DISPI_LFB_ADDRESS: u16 = 0x0A;

/// `DISPI_ENABLE` bits.
const DISPI_ENABLED: u16 = 0x01;
const DISPI_LFB_ENABLED: u16 = 0x40;

/// VBE interface id range the BGA reports (Bochs/QEMU answer 0xB0C0..0xB0C5).
const VBE_DISPI_ID_MIN: u16 = 0xB0C0;
const VBE_DISPI_ID_MAX: u16 = 0xB0C5;

/// Native geometry the GUI is designed around.
pub const DEFAULT_WIDTH: u32 = 1024;
pub const DEFAULT_HEIGHT: u32 = 768;
pub const DEFAULT_BPP: u32 = 32;

/// Where the framebuffer came from (printed at boot, and shown by `gui`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Handed over by the bootloader.
    Handoff,
    /// Programmed through the Bochs/QEMU VGA registers.
    BochsVbe,
}

impl Origin {
    pub fn as_str(self) -> &'static str {
        match self {
            Origin::Handoff => "bootloader hand-off",
            Origin::BochsVbe => "bochs/qemu vga",
        }
    }
}

/// One linear framebuffer. All coordinates are pixels; `pitch` is in bytes.
#[derive(Clone, Copy)]
pub struct Framebuffer {
    pub addr: u64,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub bpp: u8,
    pub origin: Origin,
}

impl Framebuffer {
    pub fn bytes(&self) -> u64 {
        self.pitch as u64 * self.height as u64
    }

    pub fn pixels(&self) -> u64 {
        self.width as u64 * self.height as u64
    }

    /// Bytes per pixel, derived from the mode (the GUI only draws 32-bpp modes).
    pub fn bytes_per_pixel(&self) -> u32 {
        (self.bpp as u32 + 7) / 8
    }

    /// Writes one pixel. `color` is `0x00RRGGBB` and is stored in the adapter's BGRX order.
    pub fn write_pixel(&mut self, x: u32, y: u32, color: u32) -> bool {
        if x >= self.width || y >= self.height || self.bytes_per_pixel() != 4 {
            return false;
        }
        let offset = (y as u64 * self.pitch as u64 + x as u64 * 4) as usize;
        unsafe {
            let pixel = (self.addr as *mut u32).add(offset / 4);
            core::ptr::write_volatile(pixel, color & 0x00FF_FFFF);
        }
        true
    }

    /// Reads one pixel back (the verification path, and the framebuffer self-test).
    pub fn read_pixel(&self, x: u32, y: u32) -> Option<u32> {
        if x >= self.width || y >= self.height || self.bytes_per_pixel() != 4 {
            return None;
        }
        let offset = (y as u64 * self.pitch as u64 + x as u64 * 4) as usize;
        unsafe {
            let pixel = (self.addr as *const u32).add(offset / 4);
            Some(core::ptr::read_volatile(pixel) & 0x00FF_FFFF)
        }
    }

    /// Copies `width` pixels of one row from a u32 slice into the framebuffer.
    pub fn write_span(&mut self, x: u32, y: u32, source: &[u32], count: usize) {
        if y >= self.height || self.bytes_per_pixel() != 4 {
            return;
        }
        for index in 0..count {
            let column = x + index as u32;
            if column >= self.width || index >= source.len() {
                break;
            }
            let offset = (y as u64 * self.pitch as u64 + column as u64 * 4) as usize;
            unsafe {
                let pixel = (self.addr as *mut u32).add(offset / 4);
                core::ptr::write_volatile(pixel, source[index] & 0x00FF_FFFF);
            }
        }
    }

    /// Blits a rectangle out of a packed stride-`stride` source buffer.
    pub fn blit(&mut self, x: u32, y: u32, width: u32, height: u32, source: &[u32], stride: u32) {
        if self.bytes_per_pixel() != 4 {
            return;
        }
        for row in 0..height {
            let target_y = y + row;
            if target_y >= self.height {
                break;
            }
            let start = (row * stride) as usize;
            let end = start + width as usize;
            if end > source.len() {
                break;
            }
            self.write_span(x, target_y, &source[start..end], width as usize);
        }
    }

    /// Fills the whole screen with one color.
    pub fn fill(&mut self, color: u32) {
        let row_length = self.width as usize;
        if row_length == 0 || self.bytes_per_pixel() != 4 {
            return;
        }
        let row: alloc::vec::Vec<u32> = alloc::vec![color & 0x00FF_FFFF; row_length];
        for y in 0..self.height {
            self.write_span(0, y, &row, row_length);
        }
    }

    /// Overwrites every framebuffer byte with zeros (the panic path, and `gui scrub`).
    /// Volatile writes keep the compiler from eliding the wipe.
    pub unsafe fn scrub(&mut self) -> u64 {
        let bytes = self.bytes();
        let base = self.addr as *mut u8;
        let mut index = 0u64;
        while index < bytes {
            core::ptr::write_volatile(base.add(index as usize), 0);
            index += 1;
        }
        bytes
    }

    pub fn describe(&self) {
        crate::println!(
            "[FB] {}x{}x{} @ {:#010x} pitch={} origin={} ({:.1} MiB aperture)",
            self.width,
            self.height,
            self.bpp,
            self.addr,
            self.pitch,
            self.origin.as_str(),
            self.bytes() as f32 / (1024.0 * 1024.0)
        );
    }
}

/// The installed framebuffer. `.bss` is not zeroed by the loader, so this is treated as a
/// self-initialising static like every other module's state.
static mut INSTANCE: Option<Framebuffer> = None;

/// Explicit reset. The boot loader does not zero `.bss` (see `main.rs`), so an `Option` in
/// static storage cannot be assumed to start as `None`: every entry point that reads the
/// instance clears it first.
pub fn reset() {
    unsafe {
        *core::ptr::addr_of_mut!(INSTANCE) = None;
    }
}

pub fn installed() -> bool {
    unsafe { (*core::ptr::addr_of!(INSTANCE)).is_some() }
}

pub fn handle() -> Option<&'static mut Framebuffer> {
    unsafe { (*core::ptr::addr_of_mut!(INSTANCE)).as_mut() }
}

pub fn geometry() -> Option<(u32, u32)> {
    unsafe { (*core::ptr::addr_of!(INSTANCE)).map(|fb| (fb.width, fb.height)) }
}

fn install(framebuffer: Framebuffer) {
    unsafe {
        *core::ptr::addr_of_mut!(INSTANCE) = Some(framebuffer);
    }
}

/// Adopts a framebuffer handed over by the bootloader (Multiboot2 tag 8).
pub fn adopt_handoff(handoff: &crate::bootinfo::Framebuffer) -> bool {
    if handoff.addr == 0 || handoff.width == 0 || handoff.height == 0 {
        return false;
    }
    let pitch = if handoff.pitch == 0 {
        handoff.width * ((handoff.bpp as u32 + 7) / 8)
    } else {
        handoff.pitch
    };
    install(Framebuffer {
        addr: handoff.addr,
        width: handoff.width,
        height: handoff.height,
        pitch,
        bpp: handoff.bpp,
        origin: Origin::Handoff,
    });
    true
}

// ---------------------------------------------------------------------------------------
// Bochs / QEMU VGA (BGA) programming
// ---------------------------------------------------------------------------------------

/// How the bochs dispi register block is reached.
///
/// QEMU's standard VGA maps it **flat in PCI region 2** at offset `0x500` (documented in the
/// QEMU standard-VGA spec: "bochs dispi interface registers, mapped flat without index/data
/// ports; use `(index << 1)` as the offset for 16-bit register access"), and the traditional
/// `0x01CE`/`0x01CF` index/data pair as the legacy alternative. This driver prefers the MMIO
/// block, because the legacy ports are the part that varies between VGA variants.
#[derive(Clone, Copy)]
enum Dispi {
    /// Flat 16-bit registers at `base + 0x500 + (index << 1)`.
    Mmio(u64),
    /// Legacy index (`0x01CE`) and data (`0x01CF`) ports.
    Ports,
    /// No VBE interface answered on either path.
    Missing,
}

impl Dispi {
    fn write(self, index: u16, value: u16) {
        match self {
            Dispi::Mmio(base) => unsafe {
                let register = (base + DISPI_MMIO_OFFSET + (index as u64) * 2) as *mut u16;
                core::ptr::write_volatile(register, value);
            },
            Dispi::Ports => unsafe {
                outw(DISPI_INDEX_PORT, index);
                outw(DISPI_DATA_PORT, value);
            },
            Dispi::Missing => {}
        }
    }

    fn read(self, index: u16) -> u16 {
        match self {
            Dispi::Mmio(base) => unsafe {
                let register = (base + DISPI_MMIO_OFFSET + (index as u64) * 2) as *const u16;
                core::ptr::read_volatile(register)
            }
            Dispi::Ports => unsafe {
                outw(DISPI_INDEX_PORT, index);
                inb(DISPI_DATA_PORT) as u16 | ((inb(DISPI_DATA_PORT + 1) as u16) << 8)
            }
            Dispi::Missing => 0xFFFF,
        }
    }

    fn id(self) -> u16 {
        self.read(DISPI_ID)
    }

    fn is_live(self) -> bool {
        (VBE_DISPI_ID_MIN..=VBE_DISPI_ID_MAX).contains(&self.id())
    }

    fn as_str(self) -> &'static str {
        match self {
            Dispi::Mmio(_) => "pci region 2 mmio @0x500",
            Dispi::Ports => "legacy 0x01ce/0x01cf",
            Dispi::Missing => "absent",
        }
    }
}

/// Probes both register paths and returns the first that answers.
fn find_dispi() -> Dispi {
    if let Some(base) = mmio_bar() {
        let candidate = Dispi::Mmio(base);
        if candidate.is_live() {
            return candidate;
        }
    }
    if Dispi::Ports.is_live() {
        return Dispi::Ports;
    }
    Dispi::Missing
}

/// Address of the adapter's MMIO bar (PCI region 2), assigning one when the loader left it
/// blank. The bar holds the remapped VGA ports, the dispi block and the QEMU extended
/// registers, and is small enough (4 KiB) that the PCI hole has room for it.
pub fn mmio_bar() -> Option<u64> {
    let device = pci::find_by_id(0x1234, 0x1111).or_else(pci::find_vga)?;
    pci::enable(&device, false);
    let (base, size) = pci::ensure_memory_bar(&device, 2, MMIO_BAR_PREFERRED)?;
    if size < 0x1000 {
        return None;
    }
    Some(base)
}

/// Reads the VBE interface id from whichever path answers (diagnostics).
pub fn bga_interface_id() -> u16 {
    find_dispi().id()
}

/// True when a Bochs-compatible VBE interface answers.
pub fn bga_present() -> bool {
    find_dispi().is_live()
}

/// Prints what the adapter answers: the PCI identity, its bars, and the register path that
/// answered. This is the first thing to look at when the GUI refuses to start.
pub fn describe_probe() {
    match pci::find_by_id(0x1234, 0x1111).or_else(pci::find_vga) {
        Some(device) => {
            crate::println!(
                "[FB] probe: pci {:04x}:{:04x} at {:02x}:{:02x}.{} class={:04x} command={:#06x}",
                device.vendor,
                device.device,
                device.bus,
                device.slot,
                device.function,
                device.class_code(),
                pci::config_read_u32(device.bus, device.slot, device.function, 0x04) & 0xFFFF
            );
            for index in 0..3usize {
                crate::println!(
                    "[FB] probe: bar{}={:#010x} size={} KiB{}",
                    index,
                    device.bars[index],
                    pci::bar_size(&device, index) / 1024,
                    if device.bar_is_memory(index) { " mem" } else { " io" }
                );
            }
        }
        None => crate::println!("[FB] probe: no display controller on PCI bus 0"),
    }
    let dispi = find_dispi();
    crate::println!(
        "[FB] probe: bochs dispi via {} id={:#06x} (expected {:#06x}..{:#06x})",
        dispi.as_str(),
        dispi.id(),
        VBE_DISPI_ID_MIN,
        VBE_DISPI_ID_MAX
    );
}

/// Programs a linear 32-bpp mode and resolves the LFB base address.
///
/// PCI first: with no firmware the adapter's command register may be zero, so its memory
/// decode (which owns the aperture) and its MMIO bar are switched on here before anything is
/// touched.
pub fn bga_init(width: u32, height: u32) -> Option<Framebuffer> {
    let device = pci::find_by_id(0x1234, 0x1111).or_else(pci::find_vga);
    if let Some(device) = device.as_ref() {
        pci::enable(device, false);
    }
    let dispi = find_dispi();
    if !dispi.is_live() {
        return None;
    }

    dispi.write(DISPI_ENABLE, 0);
    dispi.write(DISPI_XRES, width as u16);
    dispi.write(DISPI_YRES, height as u16);
    dispi.write(DISPI_BPP, DEFAULT_BPP as u16);
    dispi.write(DISPI_ENABLE, DISPI_ENABLED | DISPI_LFB_ENABLED);

    let active_width = dispi.read(DISPI_XRES) as u32;
    let active_height = dispi.read(DISPI_YRES) as u32;
    let active_bpp = dispi.read(DISPI_BPP) as u32;
    if active_width == 0 || active_height == 0 || active_bpp != DEFAULT_BPP {
        crate::println!(
            "[FB] mode set refused: {}x{}x{} (dispi via {})",
            active_width,
            active_height,
            active_bpp,
            dispi.as_str()
        );
        return None;
    }
    let virtual_width = dispi.read(DISPI_VIRT_WIDTH) as u32;
    let pitch = if virtual_width >= active_width && virtual_width != 0 {
        virtual_width * (active_bpp / 8)
    } else {
        active_width * (active_bpp / 8)
    };

    // The aperture address: the adapter's BAR if it has one, otherwise what the DISPI
    // register reports (in 64 KiB units), otherwise the legacy VGA window.
    let pci_base = device
        .as_ref()
        .and_then(|device| {
            let (base, size) = pci::ensure_memory_bar(device, 0, pci::LEGACY_VGA_BASE)?;
            crate::println!(
                "[OK] VGA PCI {:04x}:{:04x} at {:02x}:{:02x}.{} base={:#010x} aperture={} MiB",
                device.vendor,
                device.device,
                device.bus,
                device.slot,
                device.function,
                base,
                size / (1024 * 1024)
            );
            Some(base)
        });

    let dispi_base = (dispi.read(DISPI_LFB_ADDRESS) as u64) << 16;
    let addr = match (pci_base, dispi_base) {
        (Some(base), _) => base,
        (None, base) if base != 0 => base,
        (None, _) => DEFAULT_LFB_BASE,
    };
    crate::println!(
        "[FB] mode {}x{}x{} set via {}, aperture {} at {:#010x} pitch={}",
        active_width,
        active_height,
        active_bpp,
        dispi.as_str(),
        if virtual_width >= active_width && virtual_width != 0 {
            "virtual"
        } else {
            "linear"
        },
        addr,
        pitch
    );

    Some(Framebuffer {
        addr,
        width: active_width,
        height: active_height,
        pitch,
        bpp: active_bpp as u8,
        origin: Origin::BochsVbe,
    })
}

/// Installs the graphics adapter, preferring a bootloader hand-off. Returns true when a
/// framebuffer is live afterwards.
pub fn init(width: u32, height: u32) -> bool {
    if installed() {
        return true;
    }
    reset();
    if let Some(framebuffer) = bga_init(width, height) {
        install(framebuffer);
        return true;
    }
    false
}

/// Proves the aperture is real: write two known pixels at opposite corners, read them back,
/// then restore what was there. A cached or unmapped aperture fails this and the GUI is
/// refused instead of drawing into nowhere.
pub fn self_test() -> bool {
    let framebuffer = match handle() {
        Some(framebuffer) => framebuffer,
        None => return false,
    };
    if framebuffer.bytes_per_pixel() != 4 || framebuffer.width < 8 || framebuffer.height < 8 {
        return false;
    }
    let (width, height) = (framebuffer.width, framebuffer.height);
    let probes = [
        (0u32, 0u32, 0x00AB_CDEFu32),
        (width - 1, 0, 0x0012_3456),
        (0, height - 1, 0x00FED_CBA9),
        (width - 1, height - 1, 0x0000_FF00),
    ];
    let mut saved = [(0u32, 0u32, 0u32); 4];
    let mut ok = true;
    for (index, (x, y, color)) in probes.iter().enumerate() {
        let before = framebuffer.read_pixel(*x, *y).unwrap_or(0);
        saved[index] = (*x, *y, before);
        if !framebuffer.write_pixel(*x, *y, *color) {
            ok = false;
            break;
        }
        let read_back = framebuffer.read_pixel(*x, *y).unwrap_or(!*color);
        if read_back != (*color & 0x00FF_FFFF) {
            ok = false;
            break;
        }
    }
    for (x, y, color) in saved.iter() {
        framebuffer.write_pixel(*x, *y, *color);
    }
    ok
}

/// Zeroes the framebuffer (registered as a panic scrub hook by `main`).
pub unsafe fn scrub_hook() {
    if let Some(framebuffer) = handle() {
        framebuffer.scrub();
    }
}
