# KELLER-OS: build the kernel and boot it under QEMU.
#
# Boot path: QEMU's `-kernel` loader, which enters the kernel through the PVH
# XEN_ELFNOTE_PHYS32_ENTRY note emitted by src/boot.rs. This is the only path that works
# on this toolchain:
#   * QEMU's multiboot ROM rejects ELF64 images ("Cannot load x86-64 image, give a 32bit
#     one"), and
#   * `-device loader,...,cpu-num=0` never hands control to a PVH kernel.
#
# `-cpu max` is required for hardware entropy: without RDRAND the kernel falls back to its
# TSC/PIT-seeded ChaCha20 DRBG and says so on COM1.
#
# Display: `-vga std` attaches the Bochs/QEMU VBE adapter that the kernel's PCI path drives
# (PCI 1234:1111, BGA registers through bar 2 MMIO at +0x500, 1024x768x32). Machines without
# an adapter are equally supported - the kernel then prints "[--] NO DISPLAY ADAPTER" and
# keeps the serial console.
#
#   .\run.ps1                 # QEMU window + COM1 on this terminal (log also mirrors into
#                             # the shell window inside the GUI)
#   .\run.ps1 -Headless       # adapter emulated, no window (for dev-tools/qemu_check.py runs)
#   .\run.ps1 -NoGraphics     # no display adapter at all: serial console only
#
# Scripted verification with expected output lives in dev-tools/qemu_check.py.

param(
    [switch]$Headless,
    [switch]$NoGraphics
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

# `.json` target specs need the unstable flag; the offline flag keeps the build hermetic.
cargo build --offline -Zjson-target-spec

$qemuArgs = @(
    "-cpu", "max",
    "-m", "256M",
    "-kernel", "target\x86_64-sovereign_core\debug\sovereign-core",
    "-serial", "stdio",
    "-no-reboot",
    "-d", "guest_errors,int",
    "-D", "target\qemu-debug.log"
)

if ($NoGraphics) {
    $qemuArgs += @("-display", "none")
} else {
    # The adapter is always attached unless -NoGraphics: the window is only a view of it.
    $qemuArgs += @("-vga", "std")
    if ($Headless) {
        $qemuArgs += @("-display", "none")
    } else {
        $qemuArgs += @("-display", "gtk")
    }
}

& "C:\Program Files\qemu\qemu-system-x86_64.exe" @qemuArgs
