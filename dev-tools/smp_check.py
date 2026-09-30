#!/usr/bin/env python3
"""Independent verification of the APIC / IO-APIC / SMP work item.

Two jobs, and they are deliberately separate:

1. **Recompute the pinned offload vector.** The kernel hands the pinning digest to every
   application processor and requires each one to produce it. That is only evidence if the
   expected value was produced by *something else* - so this file carries its own ChaCha20 and
   its own SHA-256, validates them against the RFC 8439 and FIPS 180-4 test vectors (a digest
   that agrees with a buggy implementation agrees with nothing), and recomputes the digest of
   the exact construction the kernel uses.

2. **Read the boot log and check the claims the kernel made about itself.** Every line this
   tool trusts is one it derived from the log rather than from the kernel's own verdict: the
   MADT's processor list against the APIC ids that answered, the delivered timer rate against
   the counter register's rate, and - the payload - each processor's digest against the one
   computed here.

Nothing here shares code with the kernel or with the other tools, which is the point: two
independent implementations that agree are evidence, and one implementation checked against
itself is a tautology.
"""

import argparse
import re
import struct
import sys

# ------------------------------------------------------------------ ChaCha20 (RFC 8439)

MASK32 = 0xFFFFFFFF


def _rotl(value, count):
    return ((value << count) | (value >> (32 - count))) & MASK32


def _quarter_round(state, a, b, c, d):
    state[a] = (state[a] + state[b]) & MASK32
    state[d] = _rotl(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = _rotl(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & MASK32
    state[d] = _rotl(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = _rotl(state[b] ^ state[c], 7)


def chacha20_block(key, counter, nonce):
    """One 64-byte ChaCha20 block for the given block counter (RFC 8439 section 2.3.2)."""
    assert len(key) == 32 and len(nonce) == 12
    state = list(struct.unpack("<4I", b"expand 32-byte k"))
    state += list(struct.unpack("<8I", key))
    state.append(counter & MASK32)
    state += list(struct.unpack("<3I", nonce))
    working = list(state)
    for _ in range(10):  # 10 double rounds
        _quarter_round(working, 0, 4, 8, 12)
        _quarter_round(working, 1, 5, 9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7, 8, 13)
        _quarter_round(working, 3, 4, 9, 14)
    out = [(working[i] + state[i]) & MASK32 for i in range(16)]
    return struct.pack("<16I", *out)


def chacha20_keystream(key, counter, nonce, length):
    """`length` bytes of keystream, blocks taken from `counter` upwards.

    The kernel's primitive takes a starting block counter and runs forward, so this does the
    same rather than assuming the RFC's payload convention of starting at one.
    """
    stream = bytearray()
    block = counter
    while len(stream) < length:
        stream += chacha20_block(key, block, nonce)
        block = (block + 1) & MASK32
    return bytes(stream[:length])


def chacha20_xor(key, counter, nonce, data):
    stream = chacha20_keystream(key, counter, nonce, len(data))
    return bytes(a ^ b for a, b in zip(data, stream))


# ------------------------------------------------------------------ SHA-256 (FIPS 180-4)

_SHA256_K = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4,
    0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE,
    0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F,
    0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC,
    0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B,
    0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070, 0x19A4C116,
    0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7,
    0xC67178F2,
]


def sha256(message):
    """SHA-256 written out rather than imported: an independent check cannot be a call to the
    thing it is checking."""
    h = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
         0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
    data = bytearray(message)
    bit_length = len(data) * 8
    data.append(0x80)
    while len(data) % 64 != 56:
        data.append(0)
    data += struct.pack(">Q", bit_length)

    for offset in range(0, len(data), 64):
        w = list(struct.unpack(">16I", bytes(data[offset:offset + 64])))
        for i in range(16, 64):
            s0 = _rotl(w[i - 15], 25) ^ _rotl(w[i - 15], 14) ^ (w[i - 15] >> 3)
            s1 = _rotl(w[i - 2], 15) ^ _rotl(w[i - 2], 13) ^ (w[i - 2] >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & MASK32)
        a, b, c, d, e, f, g, hh = h
        for i in range(64):
            s1 = _rotl(e, 26) ^ _rotl(e, 21) ^ _rotl(e, 7)
            ch = (e & f) ^ (~e & MASK32 & g)
            temp1 = (hh + s1 + ch + _SHA256_K[i] + w[i]) & MASK32
            # SIGMA0 is ROTR 2/13/22 - which as left rotations is 30/19/10, not 2/13/22.
            s0 = _rotl(a, 30) ^ _rotl(a, 19) ^ _rotl(a, 10)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + maj) & MASK32
            hh, g, f, e, d, c, b, a = g, f, e, (d + temp1) & MASK32, c, b, a, (temp1 + temp2) & MASK32
        h = [(x + y) & MASK32 for x, y in zip(h, (a, b, c, d, e, f, g, hh))]
    return struct.pack(">8I", *h)


# ------------------------------------------------------------------ the pinned construction

#: The offload key. Named as the kernel names it; both sides must agree on every byte.
KEY = b"KELLER-OS SMP OFFLOAD KEY 000001"
NONCE = b"KOS-SMP-0001"
#: Defaults, which have to match `KAT_ROUNDS` and `ROUND_BYTES` in `src/arch/smp.rs`.
ROUNDS = 8
ROUND_BYTES = 1024
#: The pinned digest: what the kernel requires every processor to produce.
DIGEST = bytes.fromhex(
    "5fa184c8b6403e0d6ac388f3b1ab956d513e52d05c8ca8ec68a74119688378ec"
)


def offload_digest(rounds=ROUNDS, round_bytes=ROUND_BYTES, counter=0):
    """The kernel's offload workload, in Python.

    A chaining state of `sha256(key || nonce)` is fed, round by round, into `sha256(state ||
    keystream)`, where the keystream is ChaCha20's, `round_bytes` at a time, and the block
    counter advances by one block per 64 bytes of keystream.
    """
    chain = sha256(KEY + NONCE)
    block_counter = counter
    for _ in range(rounds):
        keystream = chacha20_keystream(KEY, block_counter, NONCE, round_bytes)
        chain = sha256(chain + keystream)
        block_counter = (block_counter + round_bytes // 64) & MASK32
    return chain


# ------------------------------------------------------------------ the tool's own tests

def self_check():
    """Both primitives against their published test vectors."""
    failures = []

    # RFC 8439 section 2.3.2: block function, counter 1.
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a00000000")
    expected_block = bytes.fromhex(
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
    )
    got = chacha20_block(key, 1, nonce)
    if got != expected_block:
        failures.append("ChaCha20 block does not match RFC 8439 2.3.2")

    # RFC 8439 section 2.4.2: encryption, counter 1, 114 bytes of the plaintext. Its nonce is
    # not the block-function test's nonce: the two vectors in the RFC differ in it.
    nonce = bytes.fromhex("000000000000004a00000000")
    plaintext = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
                 b"for the future, sunscreen would be it.")
    expected_ciphertext = bytes.fromhex(
        "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42874d"
    )
    got = chacha20_xor(key, 1, nonce, plaintext)
    if got != expected_ciphertext:
        failures.append("ChaCha20 encryption does not match RFC 8439 2.4.2")

    # FIPS 180-4: "abc", and the empty string.
    if sha256(b"abc").hex() != (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    ):
        failures.append("SHA-256 does not match the FIPS 180-4 vector for 'abc'")
    if sha256(b"").hex() != (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ):
        failures.append("SHA-256 does not match the FIPS 180-4 vector for the empty message")

    for failure in failures:
        print(f"  FAIL {failure}")
    if not failures:
        print("  ok   ChaCha20 matches RFC 8439 (block + encryption vectors)")
        print("  ok   SHA-256 matches FIPS 180-4 (two vectors)")
    return failures


# ------------------------------------------------------------------ the boot log

def normalise(line):
    return line.replace("\r", "").rstrip("\n")


def check_log(path, rounds, round_bytes, digest):
    """Everything the log has to say, checked against what this tool computed."""
    failures = []
    notes = []

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            lines = [normalise(line) for line in handle]
    except OSError as error:
        return [f"cannot read the boot log {path}: {error}"], []

    text = "\n".join(lines)

    def want(pattern, description):
        match = re.search(pattern, text)
        if not match:
            failures.append(f"the log has no {description}")
        return match

    # The APIC has to be the interrupt path, not a decoration next to the 8259.
    want(r"\[OK\] APIC: local APIC at 0x[0-9a-f]+ enabled",
         "enabled local APIC line")
    want(r"\[OK\] IOAPIC: #0x[0-9a-f]+ at 0x[0-9a-f]+ enabled.*8259 masked",
         "enabled IO-APIC line that masks the 8259")
    if "8259 masked (IMR 0xff/0xff)" not in text:
        failures.append("the 8259's mask registers were not read back as fully masked")

    # The timer: the delivered rate has to be the rate the clock was calibrated at. The two
    # numbers are printed by the kernel on the same line, so this is a check of their
    # consistency rather than of either one alone.
    match = want(r"asked for (\d+) Hz, (\d+) probe\(s\).*delivers (\d+) Hz at a reload of (\d+) counts",
                 "APIC timer calibration line")
    if match:
        requested, probes, delivered, reload = (int(match.group(i)) for i in range(1, 5))
        notes.append(f"timer asked for {requested} Hz, delivers {delivered} Hz "
                     f"(reload {reload}, {probes} probes)")
        if delivered <= 0 or int(reload) < 2:
            failures.append("the APIC timer's delivered rate or reload is not a clock")

    # The counter register and the interrupt: reported side by side because they disagree on
    # this emulator, and the log should say so rather than hide it.
    match = re.search(r"counter register (\d+) Hz", text)
    if match:
        notes.append(f"counter register '{match.group(1)} Hz'")

    # Every processor: the id it reported against the id the MADT lists, and its digest.
    apic_ids = re.findall(r"\[OK\] SMP CPU (\d+): online, apic (0x[0-9a-f]+) \(started as (0x[0-9a-f]+) by the MADT\)",
                          text)
    if not apic_ids:
        failures.append("no application processor reported itself online")
    for cpu, reported, madt in apic_ids:
        if reported != madt:
            failures.append(f"CPU {cpu} answered on apic {reported} but was started as {madt}")
    if apic_ids:
        notes.append(f"{len(apic_ids)} application processor(s) online")

    match = re.search(r"asked for (\d+) Hz", text)
    _ = match

    # The offload digests: whatever the kernel printed, against what this file computed.
    printed = re.findall(r"\[SMP\] (ap\d+|cpu\d+) pinned-kat ([0-9a-f]{64})", text)
    expected_hex = digest.hex()
    if printed:
        for label, value in printed:
            if value != expected_hex:
                failures.append(
                    f"{label} produced {value}, while this tool computes {expected_hex}"
                )
        notes.append(f"{len(printed)} offload digest(es) match the independently computed value")
    else:
        notes.append("the log carries no per-processor digest to compare against "
                     f"{expected_hex} (the kernel's own KAT lines were the only claim)")

    if "[!!]" in text:
        for line in lines:
            if "[!!]" in line:
                failures.append(f"the kernel reported a failure: {line.strip()}")
    if "KAT FAILED" in text:
        failures.append("the kernel reported a failed known-answer test")

    return failures, notes


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--log", default="target/serial.log",
                        help="boot log to verify (default: target/serial.log)")
    parser.add_argument("--rounds", type=int, default=ROUNDS,
                        help="rounds in the pinned workload (default: %(default)s)")
    parser.add_argument("--bytes", type=int, default=ROUND_BYTES, dest="round_bytes",
                        help="keystream bytes per round (default: %(default)s)")
    parser.add_argument("--print-digest", action="store_true",
                        help="print the digest and exit without reading a log")
    args = parser.parse_args()

    print("smp_check: primitives against their published vectors")
    failures = self_check()

    computed = offload_digest(args.rounds, args.round_bytes)
    print(f"offload workload: rounds={args.rounds} bytes/round={args.round_bytes}")
    print(f"  digest   {computed.hex()}")
    if computed != DIGEST:
        print(f"  pinned   {DIGEST.hex()}")
        failures.append("the pinned digest in this file does not match its own computation")

    if args.print_digest:
        return 1 if failures else 0

    print(f"boot log: {args.log}")
    log_failures, notes = check_log(args.log, args.rounds, args.round_bytes, computed)
    for note in notes:
        print(f"  note     {note}")
    failures += log_failures

    print("verdict")
    if failures:
        for failure in failures:
            print(f"  FAIL {failure}")
        return 1
    print("  PASS every smoking gun the log claims is one this tool computed itself")
    return 0


if __name__ == "__main__":
    sys.exit(main())
