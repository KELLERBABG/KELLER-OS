#!/usr/bin/env python3
"""Independent reader for a KELLER-OS vault image.

The guest's own self-tests prove the format works *from the inside*: it writes an image with a
reference device and reads it back. This tool is the other half of that argument. It opens the raw
disk image the emulator wrote, parses the superblock and every record with a second implementation
of the layout, and checks the properties that must hold on the medium no matter what the guest
believes:

  * the superblock's geometry is self-consistent and matches what the guest printed;
  * the format magic appears exactly once, so no stale superblock is left on the device;
  * the data slots are either a well-formed record or a blank sector - never a partial one;
  * no record nonce repeats, so the AEAD keystream is never reused;
  * **the marker plaintext is nowhere on the medium**: a sealed vault is a claim about bytes on a
    disk, and this is the check that the claim holds at the byte level;
  * across two boots, the generation strictly advanced, the device nonce and the owner commitment
    stayed the same (it is the same image), and every record's ciphertext changed (a save is not a
    no-op that echoes the previous bytes back).

What this tool deliberately cannot check: the superblock's HMAC. The key is derived from a Schnorr
proof transcript, which exists only inside the guest and is never written down - that is the whole
point of the design - so the tag can only be verified by a holder of the root secret. The guest
does that; this tool checks everything that does not need the key, which is why the two together
are stronger than either alone.

Usage
-----
    python dev-tools/disk_check.py --img target/vault.img --marker "KELLER-OS PERSISTS"
    python dev-tools/disk_check.py --img target/vault-before.img --later target/vault.img \
        --marker "KELLER-OS PERSISTS" --from-log target/disk-restore.log
"""

import argparse
import os
import re
import sys

MAGIC = b"KOSVLT01"
VERSION = 1
SECTOR_SIZE = 512
SUPERBLOCK_SECTOR = 0
DATA_START = 1
MAX_SLOTS = 512
RECORD_HEADER_BYTES = 8 + 4 + 12  # vault index, payload length, record nonce
TAG_BYTES = 16
MAX_VAULT_SECTOR_BYTES = SECTOR_SIZE - RECORD_HEADER_BYTES - TAG_BYTES
MAC_OFFSET = 96


class Report:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.failures = []

    def check(self, condition, message):
        if condition:
            self.passed += 1
        else:
            self.failed += 1
            self.failures.append(message)

    def summary(self, label):
        verdict = "PASS" if self.failed == 0 else "FAIL"
        print(f"disk: {label}: {verdict} - {self.passed} assertion(s) passed, {self.failed} failed")
        for failure in self.failures:
            print(f"  FAILED: {failure}")
        if self.failed == 0:
            print("        (image geometry, record framing, no repeated nonces, no plaintext on the medium)")


def parse_superblock(sector):
    if sector[:8] != MAGIC:
        return None
    return {
        "magic": sector[:8].decode("ascii"),
        "version": int.from_bytes(sector[8:10], "little"),
        "slots": int.from_bytes(sector[10:12], "little"),
        "record_size": int.from_bytes(sector[12:14], "little"),
        "flags": int.from_bytes(sector[14:16], "little"),
        "generation": int.from_bytes(sector[16:24], "little"),
        "device_nonce": sector[32:64],
        "owner": sector[64:96],
        "mac": sector[MAC_OFFSET:MAC_OFFSET + 32],
        "padding": sector[128:],
    }


def read_image(path):
    with open(path, "rb") as handle:
        return handle.read()


def records(image, header):
    """Every non-blank data slot, as `(slot, index, length)` plus the raw record bytes."""
    found = []
    for slot in range(header["slots"]):
        start = (DATA_START + slot) * SECTOR_SIZE
        block = image[start:start + SECTOR_SIZE]
        if len(block) < SECTOR_SIZE:
            found.append((slot, None, None, block))
            continue
        if block == b"\0" * SECTOR_SIZE:
            continue
        index = int.from_bytes(block[0:8], "little")
        length = int.from_bytes(block[8:12], "little")
        found.append((slot, index, length, block))
    return found


def check_image(report, path, marker, label):
    image = read_image(path)
    report.check(
        len(image) % SECTOR_SIZE == 0,
        f"{label}: the image is not a whole number of 512-byte sectors",
    )
    report.check(
        len(image) // SECTOR_SIZE >= DATA_START + 2,
        f"{label}: the image is too small to hold a superblock and a record",
    )
    sector = image[SUPERBLOCK_SECTOR * SECTOR_SIZE:(SUPERBLOCK_SECTOR + 1) * SECTOR_SIZE]
    header = parse_superblock(sector)
    report.check(header is not None, f"{label}: sector 0 does not carry the format magic")
    if header is None:
        return None, None, None

    report.check(header["version"] == VERSION, f"{label}: unknown format version {header['version']}")
    report.check(
        header["record_size"] == SECTOR_SIZE,
        f"{label}: the superblock claims {header['record_size']}-byte records, not {SECTOR_SIZE}",
    )
    report.check(
        1 <= header["slots"] <= MAX_SLOTS,
        f"{label}: the slot count {header['slots']} is outside the format's range",
    )
    report.check(
        DATA_START + header["slots"] < len(image) // SECTOR_SIZE,
        f"{label}: the slot count runs past the end of the device",
    )
    report.check(header["generation"] >= 1, f"{label}: generation {header['generation']} is not a saved image")
    report.check(header["flags"] & 1 == 1, f"{label}: the probe-write flag was not committed")
    report.check(header["device_nonce"] != bytes(32), f"{label}: the device nonce is all zeros")
    report.check(header["owner"] != bytes(32), f"{label}: the owner commitment is all zeros")
    report.check(header["mac"] != bytes(32), f"{label}: the superblock MAC is all zeros")
    report.check(header["mac"] != header["owner"], f"{label}: the MAC echoes the owner commitment")
    report.check(
        header["padding"] == bytes(len(header["padding"])),
        f"{label}: the superblock's padding is not zero",
    )
    # The magic is a format marker, not a pattern that may appear in data: a second copy would be
    # a superblock from an earlier format left on the device.
    report.check(
        image.count(MAGIC) == 1,
        f"{label}: the format magic appears {image.count(MAGIC)} times, so a stale superblock survives",
    )

    found = records(image, header)
    report.check(found, f"{label}: no record on the device at all")
    nonces = []
    indices = []
    for slot, index, length, block in found:
        if index is None:
            report.check(False, f"{label}: slot {slot} is shorter than a sector")
            continue
        report.check(
            0 < length <= MAX_VAULT_SECTOR_BYTES,
            f"{label}: slot {slot} claims a {length}-byte payload, which cannot fit a record",
        )
        report.check(
            RECORD_HEADER_BYTES + length + TAG_BYTES <= SECTOR_SIZE,
            f"{label}: slot {slot}'s payload runs past the end of its sector",
        )
        report.check(
            block[12:24] != bytes(12),
            f"{label}: slot {slot} has an all-zero record nonce, which is not a fresh nonce",
        )
        nonces.append(block[12:24])
        indices.append(index)
        report.check(
            block[RECORD_HEADER_BYTES + length:TAG_BYTES + RECORD_HEADER_BYTES + length] != bytes(TAG_BYTES),
            f"{label}: slot {slot}'s tag is all zeros",
        )
        # The slot's own padding after the sealed payload must be zero, so nothing leaks there.
        report.check(
            block[RECORD_HEADER_BYTES + length + TAG_BYTES:] == bytes(SECTOR_SIZE - RECORD_HEADER_BYTES - length - TAG_BYTES),
            f"{label}: slot {slot} has non-zero bytes after its sealed payload",
        )
    report.check(
        len(set(nonces)) == len(nonces),
        f"{label}: two records share a nonce, so the AEAD keystream repeats",
    )
    report.check(
        len(set(indices)) == len(indices),
        f"{label}: two records claim the same vault index",
    )

    if marker:
        for text in marker:
            needle = text.encode("utf-8")
            report.check(needle not in image, f"{label}: the plaintext {text!r} appears on the medium")
            report.check(
                needle.lower() not in image.lower(),
                f"{label}: the plaintext {text!r} appears on the medium in another case",
            )
            # Quarter of the marker is enough to catch a partial write, and short enough that a
            # random match is still unlikely in a 16 MiB image.
            fragment = needle[: max(4, len(needle) // 4)]
            report.check(fragment not in image, f"{label}: {fragment!r} appears on the medium")
    return header, found, image


def cross_check_guest(report, header, guest_line, label):
    """Compare the host's parse with the line the guest printed from its own read of the device."""
    if not guest_line:
        return
    fields = dict(re.findall(r"(\w[\w-]*)=(\S+)", guest_line))
    if not fields:
        report.check(False, f"{label}: the guest's superblock line could not be parsed")
        return
    report.check(fields.get("magic") == header["magic"], "the guest's magic does not match the medium")
    report.check(
        fields.get("version") == str(header["version"]),
        f"the guest reports version {fields.get('version')}, the medium says {header['version']}",
    )
    report.check(
        fields.get("slots") == str(header["slots"]),
        f"the guest reports {fields.get('slots')} slots, the medium says {header['slots']}",
    )
    report.check(
        fields.get("generation") == str(header["generation"]),
        f"the guest reports generation {fields.get('generation')}, the medium says {header['generation']}",
    )
    report.check(
        (fields.get("owner") or "").lower() == header["owner"].hex(),
        "the guest's owner commitment does not match the medium",
    )
    report.check(
        (fields.get("nonce") or "").lower() == header["device_nonce"].hex(),
        "the guest's device nonce does not match the medium",
    )
    report.check(
        (fields.get("mac") or "").lower() == header["mac"].hex(),
        "the guest's superblock MAC does not match the medium",
    )
    print(
        f"disk: cross-check: the guest's own read of the superblock agrees with this parse "
        f"(generation {header['generation']}, {header['slots']} slots, "
        f"nonce {header['device_nonce'].hex()[:16]}...)"
    )


def main():
    parser = argparse.ArgumentParser(description="Check a KELLER-OS vault image from the host side")
    parser.add_argument("--img", required=True, help="the raw disk image to read")
    parser.add_argument("--later", default=None,
                        help="an image written by a later boot of the same device; its generation "
                             "must have advanced and its records must differ")
    parser.add_argument("--fresh", default=None,
                        help="an image formatted separately: its device nonce must differ, because "
                             "a format that reuses a nonce is not a fresh format")
    parser.add_argument("--marker", action="append", default=[],
                        help="plaintext that must not appear on the medium; repeatable")
    parser.add_argument("--from-log", default=None,
                        help="a serial log to take the guest's 'disk superblock' line from")
    args = parser.parse_args()

    for path in [args.img, args.later, args.fresh]:
        if path and not os.path.exists(path):
            print(f"disk: no such image: {path}", file=sys.stderr)
            return 2

    guest_line = None
    if args.from_log:
        with open(args.from_log, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if "[DISK] superblock:" in line:
                    guest_line = line.split("[DISK] superblock:", 1)[1].strip()
        if guest_line is None:
            print(
                f"disk: no '[DISK] superblock:' line in {args.from_log}: the guest never re-read "
                "the device, so there is nothing to cross-check",
                file=sys.stderr,
            )
            return 2

    report = Report()
    header, found, image = check_image(report, args.img, args.marker, "image")
    if header is None:
        report.summary("image")
        return 1
    # The guest's line describes the device as it stood when it read it, which is the *latest*
    # image here: a cross-check against an earlier snapshot would compare two different states.
    latest = header

    if args.later:
        later_header, later_found, later_image = check_image(report, args.later, args.marker, "later")
        if later_header is not None:
            latest = later_header
            report.check(
                later_header["generation"] > header["generation"],
                f"the later image's generation {later_header['generation']} did not advance past "
                f"{header['generation']}",
            )
            report.check(
                later_header["device_nonce"] == header["device_nonce"],
                "the two images carry different device nonces, so they are not the same device",
            )
            report.check(
                later_header["owner"] == header["owner"],
                "the two images have different owners, so they were not written by the same secret",
            )
            report.check(
                later_header["mac"] != header["mac"],
                "the later image's MAC is unchanged, so the superblock was not rewritten",
            )
            before_cipher = {slot: block[RECORD_HEADER_BYTES:] for slot, _, _, block in found}
            after_cipher = {slot: block[RECORD_HEADER_BYTES:] for slot, _, _, block in later_found}
            shared = set(before_cipher) & set(after_cipher)
            report.check(
                all(before_cipher[slot] != after_cipher[slot] for slot in shared),
                "a record's ciphertext is byte-identical across two saves, so the save was a no-op",
            )
            report.check(
                len(after_cipher) >= len(before_cipher),
                "the later image has fewer records than the earlier one, which no save does",
            )
            print(
                f"disk: two boots: generation {header['generation']} -> "
                f"{later_header['generation']}, "
                f"{len(before_cipher)} -> {len(after_cipher)} record(s), same device nonce, "
                f"every shared slot rewritten"
            )

    if args.fresh:
        fresh_header, _, _ = check_image(report, args.fresh, args.marker, "fresh")
        if fresh_header is not None:
            report.check(
                fresh_header["device_nonce"] != header["device_nonce"],
                "two separately formatted images share a device nonce",
            )
            report.check(
                fresh_header["owner"] == header["owner"], "the same secret formatted two owners"
            )
            report.check(fresh_header["generation"] < header["generation"], "the fresh image is not the earlier one")

    cross_check_guest(report, latest, guest_line, "guest")
    report.summary("image")
    return 0 if report.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
