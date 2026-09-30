# dev-tools

Local development and verification helpers. Nothing in here is needed to build or boot the
kernel: `cargo build --offline -Zjson-target-spec` plus `src/` is the whole product, and the
bootable ISO is a build artifact (`*.iso` is gitignored).

**Run every script from the repository root.** They resolve `target/` and `src/` relative to
the invocation directory, which is how the commands in `README.md`, `SPECIFICATION.md` and
`GUI_SPECIFICATION.md` are written:

```powershell
python dev-tools\qemu_check.py --vga std --secs 42 --stdin-script target\gui-input.txt --screendump target\gui.ppm
```

| Script | Role |
| --- | --- |
| `qemu_check.py` | Boots the kernel under QEMU, drives the shell over COM1, synthesises real keyboard/pointer/wheel input through the emulated 8042, captures the screen, and checks expect/forbid patterns. |
| `verify_gui.py` | Checks a screendump against `GUI_SPECIFICATION.md` (palette, rules, window rectangles, cursor) and writes a PNG plus a self-contained HTML report. |
| `wire_check.py` | The other end of the wire: attaches to the guest NIC's segment, validates every frame independently, and re-reads its own pcap. Imports `qemu_check`. |
| `disk_check.py` | Independent reader for a vault disk image: geometry, record framing, and confirmation that no plaintext is on the platter. |
| `smp_check.py` | Re-verifies each application processor's ChaCha20/SHA-256 KAT digest with its own implementation. |
| `make_font.py` | Re-bakes `src/gui/font.rs` from CascadiaMono.ttf (requires Pillow). |
| `bochsrc.txt` | Bochs hardware profile for the cycle-accurate emulation path. |

Machine-specific by nature: `bochsrc.txt` and the face list in `make_font.py` point at Windows
paths, and `qemu_check.py` expects `qemu-system-x86_64` on `PATH` (or `--qemu`).
