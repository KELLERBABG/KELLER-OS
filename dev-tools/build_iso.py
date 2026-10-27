#!/usr/bin/env python3
"""Reproducible ISO 9660 Builder for KELLER-OS (Multiboot2).

Constructs `sovereign.iso` containing:
- /boot/sovereign-core (the Multiboot2 ELF kernel binary)
- /boot/grub/grub.cfg (the boot configuration)
And computes SHA-256 release checksums.
"""

import os
import sys
import hashlib
import struct

SECTOR_SIZE = 2048

def pad_sector(data: bytes) -> bytes:
    remainder = len(data) % SECTOR_SIZE
    if remainder != 0:
        return data + b"\x00" * (SECTOR_SIZE - remainder)
    return data

def build_iso(kernel_path: str, grub_cfg_path: str, output_iso: str):
    print(f"[*] Reading kernel binary: {kernel_path}")
    with open(kernel_path, "rb") as f:
        kernel_data = f.read()

    print(f"[*] Reading GRUB config: {grub_cfg_path}")
    with open(grub_cfg_path, "rb") as f:
        grub_data = f.read()

    # Pre-pad files to 2048-byte sector alignment
    kernel_sectors = (len(kernel_data) + SECTOR_SIZE - 1) // SECTOR_SIZE
    grub_sectors = (len(grub_data) + SECTOR_SIZE - 1) // SECTOR_SIZE

    # Sector Layout:
    # 0..15: System area (32 KiB)
    # 16: Primary Volume Descriptor
    # 17: Volume Descriptor Set Terminator
    # 18: Root Directory & /boot Directory
    # 19: /boot/grub Directory
    # 20 .. 20 + grub_sectors - 1: grub.cfg data
    # 20 + grub_sectors .. : sovereign-core kernel data

    sec_pvd = 16
    sec_term = 17
    sec_root = 18
    sec_boot = 19
    sec_grub = 20
    sec_grub_cfg = 21
    sec_kernel = sec_grub_cfg + grub_sectors

    total_sectors = sec_kernel + kernel_sectors

    # Directory record helper
    def make_dir_record(name: bytes, lba: int, size: int, is_dir: bool = False) -> bytes:
        flags = 2 if is_dir else 0
        name_field = name
        rec_len = 33 + len(name_field)
        if rec_len % 2 != 0:
            rec_len += 1
            name_field += b"\x00"
        
        # 1 byte len, 1 byte ext len, 8 bytes LBA (both endian), 8 bytes size (both endian)
        # 7 bytes date, 1 byte flags, 1 byte file unit, 1 byte interleave, 4 bytes vol seq, 1 byte name len
        rec = bytearray(rec_len)
        rec[0] = rec_len
        rec[1] = 0
        rec[2:6] = lba.to_bytes(4, 'little')
        rec[6:10] = lba.to_bytes(4, 'big')
        rec[10:14] = size.to_bytes(4, 'little')
        rec[14:18] = size.to_bytes(4, 'big')
        # 19..24 date (year-1900, month, day, hour, min, sec, tz)
        rec[18:25] = bytes([126, 10, 13, 22, 0, 0, 0])
        rec[25] = flags
        rec[26] = 0
        rec[27] = 0
        rec[28:30] = (1).to_bytes(2, 'little')
        rec[30:32] = (1).to_bytes(2, 'big')
        rec[32] = len(name)
        rec[33:33 + len(name_field)] = name_field
        return bytes(rec)

    # 1. PVD (Sector 16)
    pvd = bytearray(SECTOR_SIZE)
    pvd[0] = 1 # Type: PVD
    pvd[1:6] = b"CD001" # Standard ID
    pvd[6] = 1 # Version
    pvd[8:40] = b"KELLER_OS_BOOT".ljust(32) # System ID
    pvd[40:72] = b"SOVEREIGN_CORE".ljust(32) # Volume ID
    pvd[80:84] = total_sectors.to_bytes(4, 'little')
    pvd[84:88] = total_sectors.to_bytes(4, 'big')
    pvd[120:122] = (1).to_bytes(2, 'little')
    pvd[122:124] = (1).to_bytes(2, 'big')
    pvd[124:126] = (1).to_bytes(2, 'little')
    pvd[126:128] = (1).to_bytes(2, 'big')
    pvd[128:130] = SECTOR_SIZE.to_bytes(2, 'little')
    pvd[130:132] = SECTOR_SIZE.to_bytes(2, 'big')

    root_record = make_dir_record(b"\x00", sec_root, SECTOR_SIZE, is_dir=True)
    pvd[156:156 + len(root_record)] = root_record

    # 2. Terminator (Sector 17)
    term = bytearray(SECTOR_SIZE)
    term[0] = 255 # Type: Terminator
    term[1:6] = b"CD001"
    term[6] = 1

    # 3. Root directory (Sector 18): '.' and '..' and 'BOOT'
    root_dir = bytearray(SECTOR_SIZE)
    r_dot = make_dir_record(b"\x00", sec_root, SECTOR_SIZE, is_dir=True)
    r_dotdot = make_dir_record(b"\x01", sec_root, SECTOR_SIZE, is_dir=True)
    r_boot = make_dir_record(b"BOOT", sec_boot, SECTOR_SIZE, is_dir=True)
    pos = 0
    root_dir[pos:pos+len(r_dot)] = r_dot; pos += len(r_dot)
    root_dir[pos:pos+len(r_dotdot)] = r_dotdot; pos += len(r_dotdot)
    root_dir[pos:pos+len(r_boot)] = r_boot; pos += len(r_boot)

    # 4. /boot directory (Sector 19): '.' and '..' and 'GRUB' and 'SOVEREIGN_CORE'
    boot_dir = bytearray(SECTOR_SIZE)
    b_dot = make_dir_record(b"\x00", sec_boot, SECTOR_SIZE, is_dir=True)
    b_dotdot = make_dir_record(b"\x01", sec_root, SECTOR_SIZE, is_dir=True)
    b_grub = make_dir_record(b"GRUB", sec_grub, SECTOR_SIZE, is_dir=True)
    b_kernel = make_dir_record(b"SOVEREIGN_CORE.;1", sec_kernel, len(kernel_data), is_dir=False)
    pos = 0
    boot_dir[pos:pos+len(b_dot)] = b_dot; pos += len(b_dot)
    boot_dir[pos:pos+len(b_dotdot)] = b_dotdot; pos += len(b_dotdot)
    boot_dir[pos:pos+len(b_grub)] = b_grub; pos += len(b_grub)
    boot_dir[pos:pos+len(b_kernel)] = b_kernel; pos += len(b_kernel)

    # 5. /boot/grub directory (Sector 20): '.' and '..' and 'GRUB.CFG'
    grub_dir = bytearray(SECTOR_SIZE)
    g_dot = make_dir_record(b"\x00", sec_grub, SECTOR_SIZE, is_dir=True)
    g_dotdot = make_dir_record(b"\x01", sec_boot, SECTOR_SIZE, is_dir=True)
    g_cfg = make_dir_record(b"GRUB.CFG;1", sec_grub_cfg, len(grub_data), is_dir=False)
    pos = 0
    grub_dir[pos:pos+len(g_dot)] = g_dot; pos += len(g_dot)
    grub_dir[pos:pos+len(g_dotdot)] = g_dotdot; pos += len(g_dotdot)
    grub_dir[pos:pos+len(g_cfg)] = g_cfg; pos += len(g_cfg)

    # Write out entire ISO image
    print(f"[*] Packaging ISO image: {output_iso} ({total_sectors} sectors, {total_sectors * 2 // 1024} MiB)")
    with open(output_iso, "wb") as out:
        # System area: 16 sectors of zero
        out.write(b"\x00" * (16 * SECTOR_SIZE))
        # PVD & Terminator
        out.write(pvd)
        out.write(term)
        # Directory tables
        out.write(root_dir)
        out.write(boot_dir)
        out.write(grub_dir)
        # Files
        out.write(pad_sector(grub_data))
        out.write(pad_sector(kernel_data))

    # Compute SHA-256
    with open(output_iso, "rb") as f:
        sha = hashlib.sha256(f.read()).hexdigest()
    
    sha_file = output_iso + ".sha256"
    with open(sha_file, "w") as f:
        f.write(f"{sha}  {os.path.basename(output_iso)}\n")

    print(f"[OK] ISO generated: {output_iso}")
    print(f"[OK] SHA-256: {sha}")
    print(f"[OK] Checksum saved to: {sha_file}")

if __name__ == "__main__":
    kernel = "target/x86_64-sovereign_core/debug/sovereign-core"
    if not os.path.exists(kernel):
        kernel = "target/x86_64-sovereign_core/release/sovereign-core"
    cfg = "boot/grub/grub.cfg"
    out = "sovereign.iso"
    build_iso(kernel, cfg, out)
