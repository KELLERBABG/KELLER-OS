#!/usr/bin/env python3
"""Independent on-the-wire verification of KELLER-OS's e1000 driver.

`verify_gui.py` reads pixels and `qemu_check.py` reads the guest's serial console. Both are the
guest talking about itself. This tool is the other end of the cable: it attaches to the guest's
adapter through a QEMU `socket` netdev, and it *is* the peer, so every claim it makes is about
bytes it received rather than bytes the guest said it sent.

What it does, in order:

1. boots the kernel with `-nic none -netdev socket,id=w1,listen=...` and `-device e1000`,
   so the only thing on the segment is this process;
2. validates every frame the guest transmits, from the outside in: Ethernet addresses and
   ethertype, the IPv4 header and its checksum, UDP and its pseudo-header checksum, and then the
   Vantablack frame geometry inside the payload (576 bytes, a counter that never goes backwards,
   three shard indices per message, and an authenticated tail of a legal length);
3. writes everything it saw to a pcap and then re-reads that file with a separate parser, so the
   recording is checked rather than assumed;
4. types `nic probe` on the console and requires the resulting frame on the wire to match a
   datagram this tool builds itself - typed input, syscall path, descriptor rings, headers;
5. injects a ledger of frames that should each be refused for a *different* reason (a replay of a
   frame the guest itself sent, a payload edited under a recomputed checksum, a bad UDP checksum,
   a fragment, a non-UDP protocol, a foreign port, a truncated frame) plus an ARP request, and
   then requires the guest's own counters to have moved by exactly the amount predicted, with the
   right reasons.

Everything here is deliberately a second implementation. The framing, the checksums and the
quantized-geometry rules are written from the RFCs and from VANTABLACK_INTEGRATION.md §3.1, not
imported from the kernel, so agreement is evidence and not a tautology.

Exit code 0 only when every observation and every predicted counter delta holds.
"""
import argparse
import hashlib
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from qemu_check import (  # noqa: E402  (path set up above)
    DEFAULT_IMG,
    QEMU,
    echoed,
    key_chord,
    qmp,
    qmp_connect,
    send_chord,
)

# ---------------------------------------------------------------- the lab profile
#
# Same values the kernel configures in src/eth.rs, written out again on purpose: if these two
# ever disagree, the frames on the wire are what settles it.

GUEST_MAC = bytes.fromhex("525400123456")
GATEWAY_MAC = bytes.fromhex("52550a000202")
BROADCAST_MAC = b"\xff" * 6
GUEST_IP = bytes([10, 0, 2, 15])
GATEWAY_IP = bytes([10, 0, 2, 2])
FOREIGN_IP = bytes([10, 0, 2, 9])

MESH_PORT = 0x4B4C
PROBE_PORT = 0x4B4D
FOREIGN_PORT = 0x4B4E
PROBE_PAYLOAD = b"KELLER-OS e1000 wire probe"

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
IP_PROTOCOL_UDP = 17
IP_PROTOCOL_ICMP = 1

# Vantablack frame geometry (VANTABLACK_INTEGRATION.md §3.1, mirrored in src/net.rs).
WIRE_FRAME_LEN = 576
SHARD_COUNT = 3
OFFSET_MSG_ID = 0
OFFSET_ORIG_LEN = 1
OFFSET_COUNTER = (35, 43)
OFFSET_SHARD_START = 43
RECORD_INDEX = 0
RECORD_PLAIN_LEN = 1
SHARD_OVERHEAD = 31
MIN_TAIL_LEN = 16
MAX_TAIL_LEN = 64
COVER_ID = 254
HANDSHAKE_ID = 255

PEER_COUNTERS = re.compile(
    r"\[NET\] peer (\d+) fp=0x[0-9a-f]+ accepted=(?P<accepted>\d+) refused=(?P<refused>\d+) "
    r"delivered=(?P<delivered>\d+) byzantine=(?P<byzantine>\d+) isolated=(?P<isolated>\w+) "
    r"v_max=(?P<v_max>\d+)"
)
MESH_COUNTERS = re.compile(
    r"\[NET\] refused shards=(?P<shards>\d+) replays=(?P<replays>\d+) "
    r"out-of-window=(?P<out_of_window>\d+) byzantine=(?P<byzantine>\d+) "
    r"abandoned=(?P<abandoned>\d+)"
)
NIC_COUNTERS = re.compile(
    r"\[NIC\] counters: tx=(?P<tx>\d+) rx=(?P<rx>\d+) mesh=(?P<mesh>\d+) probe=(?P<probe>\d+) "
    r"foreign=(?P<foreign>\d+) malformed=(?P<malformed>\d+) fragmented=(?P<fragmented>\d+) "
    r"not-ipv4=(?P<not_ipv4>\d+) not-udp=(?P<not_udp>\d+) bad-checksum=(?P<bad_checksum>\d+) "
    r"arp-requests=(?P<arp_requests>\d+) arp-replies=(?P<arp_replies>\d+) "
    r"arp-ignored=(?P<arp_ignored>\d+) rx-errors=(?P<rx_errors>\d+) tx-errors=(?P<tx_errors>\d+) "
    r"dma-frames=(?P<dma_frames>\d+)"
)

# Counter names as the guest spells them, mapped to the parser's group names.
COUNTER_ALIASES = {"bad-checksum": "bad_checksum", "not-udp": "not_udp", "not-ipv4": "not_ipv4"}


# ---------------------------------------------------------------- checksums (RFC 1071)

def ones_complement(data, initial=0):
    """Sum with end-around carry. An odd trailing byte is padded with zero, as every
    implementation does for the UDP pseudo-header."""
    if len(data) % 2:
        data = data + b"\x00"
    total = initial
    for index in range(0, len(data), 2):
        total += (data[index] << 8) | data[index + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def ipv4_checksum(header):
    return (~ones_complement(header)) & 0xFFFF


def udp_checksum(source_ip, destination_ip, source_port, destination_port, payload):
    udp_length = 8 + len(payload)
    pseudo = source_ip + destination_ip + bytes([0, IP_PROTOCOL_UDP]) + struct.pack("!H", udp_length)
    header = struct.pack("!HHHH", source_port, destination_port, udp_length, 0)
    total = ones_complement(pseudo) + ones_complement(header) + ones_complement(payload)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    value = (~total) & 0xFFFF
    return value if value else 0xFFFF


# ---------------------------------------------------------------- builders

def build_udp(
    payload,
    destination_port,
    source_port=MESH_PORT,
    destination_ip=GATEWAY_IP,
    destination_mac=GATEWAY_MAC,
    identification=1,
    protocol=IP_PROTOCOL_UDP,
    more_fragments=False,
    fragment_offset=0,
    corrupt_udp_checksum=False,
    corrupt_ip_checksum=False,
    source_ip=GUEST_IP,
    source_mac=None,
):
    """One Ethernet/IPv4/UDP datagram, built from the RFCs.

    Every knob exists so that a single field can be wrong on purpose: that is how one frame per
    refusal reason is manufactured, with everything else about it legal.
    """
    source_mac = GUEST_MAC if source_mac is None else source_mac
    udp_length = 8 + len(payload)
    total_length = 20 + udp_length

    flags = 0x4000 | (0x2000 if more_fragments else 0)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0x00,
        total_length,
        identification,
        flags | (fragment_offset & 0x1FFF),
        64,
        protocol,
        0,
        source_ip,
        destination_ip,
    )
    checksum = ipv4_checksum(header)
    if corrupt_ip_checksum:
        checksum ^= 0xFFFF
    header = header[:10] + struct.pack("!H", checksum) + header[12:]

    checksum = udp_checksum(source_ip, destination_ip, source_port, destination_port, payload)
    if corrupt_udp_checksum:
        checksum ^= 0xFFFF
    udp = struct.pack("!HHHH", source_port, destination_port, udp_length, checksum)

    frame = destination_mac + source_mac + struct.pack("!H", ETHERTYPE_IPV4) + header + udp + payload
    if len(frame) < 60:
        frame += b"\x00" * (60 - len(frame))  # what the adapter's pad-short-packets does
    return frame


def build_arp_request(target_ip, sender_ip=GATEWAY_IP, sender_mac=GATEWAY_MAC):
    arp = struct.pack("!HHBBH", 1, ETHERTYPE_IPV4, 6, 4, 1)
    arp += sender_mac + sender_ip + b"\x00" * 6 + target_ip
    frame = BROADCAST_MAC + sender_mac + struct.pack("!H", ETHERTYPE_ARP) + arp
    return frame + b"\x00" * (60 - len(frame))


# ---------------------------------------------------------------- the validator

class Observation:
    __slots__ = ("index", "length", "kind", "problems", "info")

    def __init__(self, index, length, kind, problems, info):
        self.index = index
        self.length = length
        self.kind = kind
        self.problems = problems
        self.info = info


def inspect_arp(frame):
    problems = []
    info = {}
    if len(frame) < 42:
        return "arp", ["shorter than an ARP message"], info
    arp = frame[14:]
    hardware, protocol, hlen, plen, opcode = struct.unpack("!HHBBH", arp[:8])
    if (hardware, protocol, hlen, plen) != (1, ETHERTYPE_IPV4, 6, 4):
        problems.append(f"ARP header {hardware}/{protocol}/{hlen}/{plen} is not Ethernet/IPv4")
    info["opcode"] = opcode
    info["sender_mac"] = arp[8:14]
    info["sender_ip"] = arp[14:18]
    info["target_ip"] = arp[24:28]
    if opcode not in (1, 2):
        problems.append(f"ARP opcode {opcode} is neither request nor reply")
    if info["sender_mac"] != GUEST_MAC and opcode == 2:
        problems.append("the ARP reply's sender is not the guest's MAC")
    if info["sender_ip"] != GUEST_IP and opcode == 2:
        problems.append("the ARP reply's sender address is not the guest's")
    return "arp", problems, info


def inspect_udp(frame):
    """Validates one IPv4/UDP frame and, when the payload is a Vantablack frame, its geometry."""
    problems = []
    info = {}
    if len(frame) < 34:
        return "ipv4", ["shorter than an IPv4 header"], info

    version_ihl = frame[14]
    if version_ihl >> 4 != 4:
        return "ipv4", [f"IP version {version_ihl >> 4} is not 4"], info
    if version_ihl & 0x0F != 5:
        return "ipv4", [f"IHL {version_ihl & 0x0F} is not 5 (this profile has no options)"], info

    total_length = struct.unpack("!H", frame[16:18])[0]
    if total_length > len(frame) - 14:
        problems.append(f"IPv4 total length {total_length} exceeds the {len(frame) - 14} bytes present")
    if total_length < 28:
        problems.append(f"IPv4 total length {total_length} cannot hold UDP")
    header = bytearray(frame[14:34])
    declared = struct.unpack("!H", bytes(header[10:12]))[0]
    header[10:12] = b"\x00\x00"
    if ipv4_checksum(bytes(header)) != declared:
        problems.append(
            f"IPv4 header checksum {declared:#06x} does not match the computed {ipv4_checksum(bytes(header)):#06x}"
        )
    if frame[22] != 64:
        problems.append(f"TTL {frame[22]} is not 64")

    info["identification"] = struct.unpack("!H", frame[18:20])[0]
    info["protocol"] = frame[23]
    info["source_ip"] = frame[26:30]
    info["destination_ip"] = frame[30:34]
    info["flags_offset"] = struct.unpack("!H", frame[20:22])[0]
    if info["flags_offset"] & 0x3FFF:
        problems.append(f"the frame is a fragment (flags/offset {info['flags_offset']:#06x})")

    if info["protocol"] != IP_PROTOCOL_UDP:
        return "ipv4", problems, info

    udp = frame[34:14 + total_length]
    if len(udp) < 8:
        problems.append("the UDP header was truncated")
        return "udp", problems, info
    source_port, destination_port, udp_length, checksum = struct.unpack("!HHHH", udp[:8])
    info["source_port"] = source_port
    info["destination_port"] = destination_port
    payload = udp[8:]
    if udp_length != 8 + len(payload):
        problems.append(f"UDP length {udp_length} disagrees with the {len(payload)} payload bytes")
    expected = udp_checksum(
        info["source_ip"], info["destination_ip"], source_port, destination_port, payload
    )
    if checksum != expected:
        problems.append(f"UDP checksum {checksum:#06x} does not match the computed {expected:#06x}")
    info["payload"] = payload
    return "udp", problems, info


def inspect_mesh_frame(payload):
    """The quantized geometry of a 576-byte Vantablack frame, checked without the guest's code."""
    problems = []
    info = {}
    if len(payload) != WIRE_FRAME_LEN:
        return [f"the mesh payload is {len(payload)} bytes, not {WIRE_FRAME_LEN}"], info
    info["msg_id"] = payload[OFFSET_MSG_ID]
    info["original_len"] = payload[OFFSET_ORIG_LEN]
    info["counter"] = int.from_bytes(payload[OFFSET_COUNTER[0]:OFFSET_COUNTER[1]], "big")
    info["shard_index"] = payload[OFFSET_SHARD_START + RECORD_INDEX]
    plain_len = int.from_bytes(
        payload[
            OFFSET_SHARD_START + RECORD_PLAIN_LEN:OFFSET_SHARD_START + RECORD_PLAIN_LEN + 2
        ],
        "big",
    )
    info["plain_len"] = plain_len
    if info["shard_index"] >= SHARD_COUNT:
        problems.append(f"shard index {info['shard_index']} is outside 0..{SHARD_COUNT - 1}")
    tail_start = OFFSET_SHARD_START + SHARD_OVERHEAD + plain_len
    tail_len = WIRE_FRAME_LEN - tail_start
    if not (MIN_TAIL_LEN <= tail_len <= MAX_TAIL_LEN):
        problems.append(f"the tail would be {tail_len} bytes, outside {MIN_TAIL_LEN}..{MAX_TAIL_LEN}")
    else:
        tail = payload[tail_start:]
        info["tail"] = tail
        if tail == b"\x00" * len(tail):
            problems.append("the entropy tail is all zero")
    info["nonce"] = payload[OFFSET_SHARD_START + 3:OFFSET_SHARD_START + 15]
    return problems, info


class Peer:
    """The other end of the segment: reads frames, validates them, and records a pcap."""

    def __init__(self, sock, pcap_path):
        self.sock = sock
        self.frames = []
        self.observations = []
        self.lock = threading.Lock()
        self.running = True
        self.prefixed = None
        self.buffer = b""
        self.pcap = open(pcap_path, "wb")
        self.pcap.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        self.thread = threading.Thread(target=self._read_loop, daemon=True)

    def start(self):
        self.thread.start()

    def send(self, frame):
        """Puts one frame on the segment, in whichever framing the peer turned out to use.

        QEMU's stream (TCP) socket netdev prefixes every frame with its length in both
        directions, which is why the same auto-detection that decodes its frames has to encode
        ours: sending a bare Ethernet header and getting silence back looks exactly like a guest
        that ignores incoming traffic, and it is not.
        """
        prefixed = True if self.prefixed is None else self.prefixed
        if prefixed:
            self.sock.sendall(struct.pack("!I", len(frame)) + frame)
        else:
            self.sock.sendall(frame)

    def stop(self):
        self.running = False
        self.thread.join(timeout=2.0)
        self.pcap.close()

    def _record(self, frame):
        stamp = time.time()
        index = len(self.frames)
        self.frames.append(frame)
        with self.lock:
            self.pcap.write(
                struct.pack(
                    "<IIII", int(stamp), int((stamp % 1) * 1_000_000), len(frame), len(frame)
                )
            )
            self.pcap.write(frame)
            self.pcap.flush()

        destination_mac, source_mac = frame[0:6], frame[6:12]
        ethertype = struct.unpack("!H", frame[12:14])[0]
        problems = []
        info = {"index": index, "ethertype": ethertype}
        if source_mac != GUEST_MAC:
            problems.append(f"source MAC {source_mac.hex(':')} is not the guest's {GUEST_MAC.hex(':')}")
        if destination_mac not in (GATEWAY_MAC, BROADCAST_MAC) and not destination_mac.startswith(
            b"\x33\x33"
        ):
            problems.append(
                f"destination MAC {destination_mac.hex(':')} is neither the gateway nor broadcast"
            )
        if ethertype == ETHERTYPE_IPV4:
            kind, problems2, info2 = inspect_udp(frame)
            problems += problems2
            info.update(info2)
            payload = info.get("payload")
            if payload is not None and info.get("destination_port") in (MESH_PORT, PROBE_PORT):
                geometry_problems, geometry = inspect_mesh_frame(payload)
                if info["destination_port"] == PROBE_PORT:
                    if payload != PROBE_PAYLOAD:
                        problems.append("the probe port carried something other than the probe payload")
                else:
                    problems += geometry_problems
                    info.update(geometry)
            elif payload is not None:
                problems.append(
                    f"traffic on an unexpected port {info.get('destination_port')}"
                )
        elif ethertype == ETHERTYPE_ARP:
            kind, problems2, info2 = inspect_arp(frame)
            problems += problems2
            info.update(info2)
        else:
            kind = "other"
            problems.append(f"unexpected ethertype {ethertype:#06x}")
        with self.lock:
            self.observations.append(Observation(index, len(frame), kind, problems, info))

    def _read_loop(self):
        while self.running:
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                break
            if not chunk:
                break
            self.buffer += chunk
            while True:
                if self.prefixed is None:
                    if len(self.buffer) < 4:
                        break
                    candidate = struct.unpack("!I", self.buffer[:4])[0]
                    # QEMU's stream socket mode prefixes each frame with its length. Auto-detect
                    # it from the first frame rather than assuming, because UDP mode has no
                    # prefix at all and a length that looks like an Ethernet header is not.
                    self.prefixed = 14 <= candidate <= 2048
                if not self.prefixed:
                    frame, self.buffer = self.buffer, b""
                    if frame:
                        self._record(frame)
                    break
                if len(self.buffer) < 4:
                    break
                length = struct.unpack("!I", self.buffer[:4])[0]
                if len(self.buffer) < 4 + length:
                    break
                frame = self.buffer[4:4 + length]
                self.buffer = self.buffer[4 + length:]
                self._record(frame)

    def snapshot(self):
        with self.lock:
            return list(self.observations)


# ---------------------------------------------------------------- QEMU

def launch(args, netdev_port, pcap_path):
    cmd = [
        QEMU, "-cpu", "max", "-m", "256M",
        "-kernel", os.path.abspath(args.img),
        "-no-reboot",
        "-display", "none",
        "-vga", args.vga,
        "-serial", "stdio",
        "-qmp", f"tcp:127.0.0.1:{args.qmp_port},server,nowait",
        # Replace the machine's default user-mode NIC with a socket peer: the only station on
        # this segment is this process, so anything the guest receives was sent by the tool and
        # anything the tool receives was sent by the guest.
        "-nic", "none",
        "-netdev", f"socket,id=wire,listen=127.0.0.1:{netdev_port}",
        "-device", "e1000,netdev=wire",
    ]
    return subprocess.Popen(
        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
    )


def connect_netdev(port, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=1.0)
            sock.settimeout(0.5)
            return sock
        except OSError:
            time.sleep(0.2)
    return None


class Console:
    """The guest's serial console: drained in a thread so it can be read while QEMU runs."""

    def __init__(self, proc):
        self.proc = proc
        self.captured = bytearray()
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self._drain, daemon=True)
        self.thread.start()

    def _drain(self):
        while True:
            try:
                chunk = self.proc.stdout.read1(4096)
            except Exception:
                break
            if not chunk:
                break
            with self.lock:
                self.captured.extend(chunk)

    def text(self):
        with self.lock:
            return bytes(self.captured).decode("utf-8", "replace")

    def wait_for(self, needle, timeout):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if needle in self.text():
                return True
            time.sleep(0.25)
        return False

    def type_line(self, sock, line, settle=1.2):
        """Types a command through the emulated keyboard, one chord per character."""
        for character in line:
            send_chord(sock, key_chord(character))
            time.sleep(0.03)
        send_chord(sock, ["ret"])
        time.sleep(settle)


def counters(text):
    """The most recent `[NIC] counters:` line, as a dict of ints."""
    matches = list(NIC_COUNTERS.finditer(text))
    if not matches:
        return None
    return {key: int(value) for key, value in matches[-1].groupdict().items()}


def mesh_counters(text):
    """The most recent `[NET] refused shards=...` line, as a dict of ints."""
    matches = list(MESH_COUNTERS.finditer(text))
    if not matches:
        return None
    return {key: int(value) for key, value in matches[-1].groupdict().items()}


def peer_v_max(text):
    """The highest message counter the guest has accepted from a peer, as the guest reports it.

    Needed because the tamper case has to arrive on a *fresh* counter. The mesh consults its
    replay window before it decrypts anything (by design: a replayed message must not cost AEAD
    work), so a frame that reuses a counter it has already taken is refused as a replay and never
    reaches the tag check - which is the check a wire test is trying to exercise.
    """
    matches = list(PEER_COUNTERS.finditer(text))
    return max((int(match.group("v_max")) for match in matches), default=0)


def address_to_guest(payload, destination_port=MESH_PORT, identification=1):
    """A datagram from the gateway to the guest: the shape a real peer's traffic has."""
    return build_udp(
        payload,
        destination_port,
        source_port=destination_port,
        destination_ip=GUEST_IP,
        destination_mac=GUEST_MAC,
        source_ip=GATEWAY_IP,
        source_mac=GATEWAY_MAC,
        identification=identification,
    )


def counter_deltas(before, after):
    return {key: after[key] - before[key] for key in after}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--img", default=DEFAULT_IMG)
    parser.add_argument("--netdev-port", type=int, default=5601, help="TCP port QEMU listens on")
    parser.add_argument("--qmp-port", type=int, default=4478)
    parser.add_argument("--secs", type=float, default=90.0, help="how long to let the guest run")
    parser.add_argument("--vga", default="std")
    parser.add_argument("--pcap", default="target/wire.pcap")
    parser.add_argument("--serial-out", default="target/wire-serial.log")
    parser.add_argument("--inject", action=argparse.BooleanOptionalAction, default=True,
                        help="send the crafted ledger and require exact counter deltas")
    parser.add_argument("--cover-wait", type=float, default=30.0,
                        help="how long to wait for the mesh's own cover traffic to appear")
    parser.add_argument("--show-log", action="store_true")
    args = parser.parse_args()

    if not os.path.exists(args.img):
        print(f"wire: image not found: {args.img}", file=sys.stderr)
        return 2
    os.makedirs(os.path.dirname(os.path.abspath(args.pcap)), exist_ok=True)

    failures = []

    def require(condition, note):
        print(f"{'PASS' if condition else 'FAIL'} {note}")
        if not condition:
            failures.append(note)
        return condition

    # Before anything else: this tool's own framing has to reproduce the vector both the kernel
    # and the harness pin. If it does not, every later claim would be about the wrong bytes.
    require(builder_matches_known_answer(),
            "this tool's own builder reproduces the pinned Ethernet/IPv4/UDP known-answer frame")

    proc = launch(args, args.netdev_port, args.pcap)
    console = Console(proc)
    peer = None
    sock = None
    try:
        sock = qmp_connect(args.qmp_port, timeout=15.0)
        if sock is None:
            print("wire: could not connect to QMP", file=sys.stderr)
            return 2
        net = connect_netdev(args.netdev_port)
        if net is None:
            print("wire: could not connect to the socket netdev", file=sys.stderr)
            return 2
        peer = Peer(net, args.pcap)
        peer.start()

        if not console.wait_for("NIC LINK", timeout=45.0):
            print("wire: the guest never reported a link", file=sys.stderr)
            print(console.text(), file=sys.stderr)
            return 1

        boot = console.text()
        require("[OK] NETWORK ADAPTER" in boot, "the guest brought the adapter up and named it")
        require("bus-master on" in boot, "the adapter was given bus-mastering")
        require("[OK] NIC SELF-TEST" in boot and "0 failed" in boot,
                "the in-guest framing + register self-test passed")
        console.wait_for("BOOT COMPLETE", timeout=30.0)

        # ---- 1. a command typed on the console has to come out of the adapter
        before_probe = len(peer.snapshot())
        console.type_line(sock, "nic probe", settle=2.5)
        deadline = time.time() + 8.0
        probe_frames = []
        while time.time() < deadline:
            probe_frames = [
                observation for observation in peer.snapshot()[before_probe:]
                if observation.info.get("destination_port") == PROBE_PORT
            ]
            if probe_frames:
                break
            time.sleep(0.25)
        typed = echoed(console.text(), "nic probe")
        require(typed >= 1, "`nic probe` reached the shell through the emulated keyboard")
        if require(bool(probe_frames), "the probe datagram appeared on the wire"):
            observation = probe_frames[0]
            require(not observation.problems,
                    "the probe frame validates: addresses, IPv4 header, UDP checksum, payload")
            require(observation.length == 42 + len(PROBE_PAYLOAD),
                    f"the probe frame is {42 + len(PROBE_PAYLOAD)} bytes, as the builder says")
            require(observation.info.get("source_port") == PROBE_PORT
                    and observation.info.get("destination_port") == PROBE_PORT,
                    "the probe uses the probe port in both directions")
            require(observation.info.get("payload") == PROBE_PAYLOAD,
                    "the probe payload is byte-identical to the one this tool built")
            require(uint16(observation, "identification") > 0,
                    "the probe carries a non-zero IP identification (the egress counter)")
            # The strongest form of the claim, and the reason the tool exists: build the same
            # datagram from the RFCs, with the identification the guest actually used, and require
            # every byte - headers, both checksums, payload - to be identical.
            expected = build_udp(PROBE_PAYLOAD, PROBE_PORT, source_port=PROBE_PORT,
                                 identification=uint16(observation, "identification"))
            require(expected == peer.frames[observation.index],
                    "the guest's probe frame is byte-identical to this tool's independent build")

        # ---- 2. whatever the mesh itself puts on the wire, without being asked
        #
        # This is the egress that exists because the kernel decided to send something, not because
        # an operator typed a command, and it is what the driver is *for*: the sealed frames of the
        # Vantablack mesh, on a real wire, with the headers this tool parses from the RFCs. The
        # decoys come due on a Poisson sampler at 1 per 5 s on average, so the window is generous
        # and a miss is a finding rather than an accident.
        deadline = time.time() + args.cover_wait
        mesh_frames = []
        while time.time() < deadline:
            mesh_frames = [
                observation for observation in peer.snapshot()
                if observation.info.get("destination_port") == MESH_PORT
            ]
            if mesh_frames:
                break
            time.sleep(0.5)
        if require(bool(mesh_frames),
                   f"the mesh's own sealed frames cross the wire ({len(mesh_frames)} seen)"):
            for observation in mesh_frames[:4]:
                require(not observation.problems,
                        f"frame {observation.index} validates from the outside "
                        f"({observation.length} bytes, msg-id={observation.info.get('msg_id')}, "
                        f"counter={observation.info.get('counter')}, "
                        f"shard={observation.info.get('shard_index')})")
            counters_seen = [observation.info.get("counter") for observation in mesh_frames]
            require(counters_seen == sorted(counters_seen),
                    f"the message counters on the wire never go backwards ({counters_seen})")
            if len(mesh_frames) >= 3:
                shards = [observation.info.get("shard_index") for observation in mesh_frames[:3]]
                require(sorted(shards) == list(range(SHARD_COUNT)),
                        f"one message is carried by one frame per shard index ({shards})")

        # ---- 3. the injected ledger and the guest's own account of it
        if args.inject:
            mesh_sample = mesh_frames[0] if mesh_frames else None
            if mesh_sample is None:
                # Nothing of the mesh's own to replay; the refusal ledger still proves that the
                # machinery moves when the tool, rather than a peer, is the sender.
                print("note: no captured mesh frame to replay; skipping the replay case")
            before = counters(console.text())
            if before is None:
                console.type_line(sock, "nic status", settle=1.5)
                before = counters(console.text())
            if not require(before is not None, "the guest reported its NIC counters"):
                return 1

            # Learn the highest counter this peer's window has taken, so the tamper case can be
            # built ahead of it. The margin matters: the guest's own decoys travel back through its
            # in-RAM loopback, and each accepted frame claims the next counter, so a frame built on
            # the *immediately* next value can lose the race and be refused as a replay before its
            # tag is ever checked. Eight counters is a few decoy intervals, which is far longer
            # than the seconds between building the ledger and sending it, and still well inside
            # the 64-counter window the session guard allows.
            console.type_line(sock, "net", settle=1.5)
            fresh = peer_v_max(console.text()) + 8

            ledger = []
            if mesh_sample is not None:
                # Pull the sealed 576-byte frame out of the guard's own datagram and put it back
                # on the wire addressed to the guest. This is the case that matters: the guest
                # cannot tell these apart from a peer's frames by any header, so the refusal has to
                # come from the mesh's own replay window and tag - the layer above the driver.
                sealed = peer.frames[mesh_sample.index][42:]
                ledger.append(("a replay of a frame the guest itself sent, addressed back to it",
                               address_to_guest(sealed, identification=0x9101),
                               {"rx": 1, "mesh": 1}))
                # A fresh counter, and a byte of ciphertext flipped: the window lets it through
                # (it is new) and the ShardSec tag is what refuses it. The counter lives in the
                # frame header *and* inside the AAD the tag covers, so moving it is itself a
                # tamper - which is the point.
                edited = bytearray(sealed)
                edited[OFFSET_COUNTER[0]:OFFSET_COUNTER[1]] = fresh.to_bytes(8, "big")  # not yet claimed
                edited[100] ^= 0x5A
                ledger.append((f"a sealed frame on a fresh counter {fresh} with its record edited",
                               address_to_guest(bytes(edited), identification=0x9102),
                               {"rx": 1, "mesh": 1}))
                # And the same frame exactly as the guest sent it: the guest addressed it to the
                # gateway, so echoing it back unchanged is traffic for someone else, and the
                # driver has to say so rather than guess.
                ledger.append(("a byte-identical echo of a frame the guest sent to someone else",
                               peer.frames[mesh_sample.index], {"rx": 1, "foreign": 1}))

            ledger.append(("a frame with a broken UDP checksum",
                           build_udp(b"\x11" * WIRE_FRAME_LEN, MESH_PORT,
                                     corrupt_udp_checksum=True, identification=0x9001),
                           {"rx": 1, "bad_checksum": 1}))
            ledger.append(("a fragment (more-fragments set)",
                           build_udp(b"\x22" * WIRE_FRAME_LEN, MESH_PORT,
                                     more_fragments=True, identification=0x9002),
                           {"rx": 1, "fragmented": 1}))
            ledger.append(("a non-UDP protocol (ICMP)",
                           build_udp(b"\x33" * 32, MESH_PORT, protocol=IP_PROTOCOL_ICMP,
                                     identification=0x9003),
                           {"rx": 1, "not_udp": 1}))
            ledger.append(("a well-formed frame on a foreign port",
                           build_udp(b"\x44" * 64, FOREIGN_PORT, destination_ip=GUEST_IP,
                                     destination_mac=GUEST_MAC, identification=0x9004),
                           {"rx": 1, "foreign": 1}))
            ledger.append(("a truncated Ethernet frame",
                           GUEST_MAC + GATEWAY_MAC + struct.pack("!H", ETHERTYPE_IPV4) + b"\x45\x00",
                           {"rx": 1, "malformed": 1}))
            ledger.append(("an ARP request for the guest's address",
                           build_arp_request(GUEST_IP), {"rx": 1, "arp_requests": 1,
                                                         "arp_replies": 1}))

            sent = 0
            for description, frame, expected in ledger:
                peer.send(frame)
                sent += 1
                time.sleep(0.35)
                print(f"     injected: {description} ({len(frame)} bytes)")

            time.sleep(3.0)
            console.type_line(sock, "nic status", settle=2.0)
            after = counters(console.text())
            if not require(after is not None, "the guest reported its counters again"):
                return 1

            delta = counter_deltas(before, after)
            print(f"     guest deltas: {delta}")
            require(delta["rx"] == sent, f"the guest received exactly the {sent} injected frames")

            predicted = {}
            for _, _, expected in ledger:
                for key, value in expected.items():
                    predicted[key] = predicted.get(key, 0) + value
            for key, value in sorted(predicted.items()):
                require(delta[key] == value,
                        f"counter {key} moved by {delta[key]}, predicted {value}")

            # The two addressed mesh frames reached the mesh, which refused both - and it says so
            # itself, so the driver's counter and the mesh's counter have to agree. This is the
            # whole point of putting sealed frames on a real wire: the refusal comes from the
            # replay window and the tag, not from the driver's header checks.
            console.type_line(sock, "net", settle=1.5)
            mesh = mesh_counters(console.text())
            if mesh_sample is not None:
                if require(mesh is not None, "the mesh reported its refusal counters"):
                    require(mesh["replays"] >= 1,
                            f"the mesh counted the replayed frame as a replay ({mesh['replays']})")
                    require(mesh["shards"] >= 1,
                            f"the mesh counted the fresh-counter edit as a tampered shard ({mesh['shards']})")
                    peer_lines = list(PEER_COUNTERS.finditer(console.text()))
                    peer_line = peer_lines[-1] if peer_lines else None
                    if require(peer_line is not None, "the mesh reported its peer counters"):
                        require(peer_line.group("isolated") == "false",
                                "one tampered shard did not sever the route (the budget is three)")

            # The ARP exchange is the only one with an answer, and the tool saw it.
            replies = [
                observation for observation in peer.snapshot()[before_probe:]
                if observation.info.get("opcode") == 2
            ]
            if require(bool(replies), "the guest answered the ARP request on the wire"):
                reply = replies[0]
                require(not reply.problems, "the ARP reply validates: opcode, sender MAC and address")
                require(reply.info.get("sender_mac") == GUEST_MAC
                        and reply.info.get("sender_ip") == GUEST_IP,
                        "the ARP reply maps the guest's address to the guest's MAC")

        # ---- 4. the recording is checked, not assumed
        observations = peer.snapshot()
        pcap_frames = read_pcap(args.pcap)
        require(len(pcap_frames) == len(observations),
                f"the pcap holds every frame that was seen ({len(pcap_frames)})")
        if pcap_frames and peer.frames:
            require(pcap_frames[0] == peer.frames[0],
                    "the recording's first frame is byte-identical to the one that was validated")
            require(hashlib.sha256(b"".join(pcap_frames)).digest() ==
                    hashlib.sha256(b"".join(peer.frames)).digest(),
                    "the recording holds exactly the frames that were validated, in order")

        bad = [observation for observation in observations if observation.problems]
        require(not bad, "no frame the guest transmitted had a defect")
        for observation in bad:
            for problem in observation.problems:
                print(f"     frame {observation.index}: {problem}")

        seen = {"mesh": 0, "probe": 0, "arp": 0}
        for observation in observations:
            if observation.info.get("destination_port") == MESH_PORT:
                seen["mesh"] += 1
            elif observation.info.get("destination_port") == PROBE_PORT:
                seen["probe"] += 1
            elif observation.kind == "arp":
                seen["arp"] += 1
        print(f"     wire summary: {len(observations)} frame(s) seen "
              f"(mesh={seen['mesh']} probe={seen['probe']} arp={seen['arp']})")

        text = console.text()
        with open(args.serial_out, "w", encoding="utf-8") as handle:
            handle.write(text)
        if args.show_log:
            print("---- serial ----")
            print(text)
            print("---- end ----")
    finally:
        if peer is not None:
            peer.stop()
        if sock is not None:
            qmp(sock, "quit")
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        if proc.stdout:
            proc.stdout.close()

    print(f"\nwire: {'PASS' if not failures else 'FAIL'}")
    for failure in failures:
        print(f"  FAILED: {failure}")
    print(f"wire: pcap {os.path.abspath(args.pcap)}, serial {os.path.abspath(args.serial_out)}")
    return 0 if not failures else 1


def uint16(observation, key):
    return observation.info.get(key, 0)


# The 68-byte probe datagram, pinned: the same bytes appear as `KAT_FRAME` in src/eth.rs and as
# the builder's output in the harness. Reproducing it here is what makes this tool a second
# implementation rather than a copy of the first.
KAT_FRAME = bytes.fromhex(
    "52550a000202" "525400123456" "0800"
    "4500003600014000" "4011" "22a6" "0a00020f" "0a000202"
    "4b4c" "4b4c" "0022" "4f18"
) + PROBE_PAYLOAD


def builder_matches_known_answer():
    frame = build_udp(PROBE_PAYLOAD, MESH_PORT, source_port=MESH_PORT, identification=1)
    return frame == KAT_FRAME


def rewrite_checksums(frame):
    """Recomputes the IPv4 and UDP checksums of an IPv4/UDP frame, leaving the payload as is."""
    frame = bytearray(frame)
    total_length = struct.unpack("!H", bytes(frame[16:18]))[0]
    header = frame[14:34]
    header[10:12] = b"\x00\x00"
    frame[24:26] = struct.pack("!H", ipv4_checksum(bytes(header)))
    source_ip = bytes(frame[26:30])
    destination_ip = bytes(frame[30:34])
    source_port, destination_port = struct.unpack("!HH", bytes(frame[34:38]))
    payload = bytes(frame[42:14 + total_length])
    frame[40:42] = struct.pack(
        "!H", udp_checksum(source_ip, destination_ip, source_port, destination_port, payload)
    )
    return bytes(frame)


def read_pcap(path):
    """Reads the recording back with a parser that shares nothing with the live one."""
    frames = []
    with open(path, "rb") as handle:
        magic = handle.read(4)
        if len(magic) < 4 or struct.unpack("<I", magic)[0] not in (0xA1B2C3D4, 0xA1B2C3D5):
            return frames
        handle.read(20)
        while True:
            record = handle.read(16)
            if len(record) < 16:
                break
            _, _, included, original = struct.unpack("<IIII", record)
            data = handle.read(included)
            if len(data) < included:
                break
            frames.append(data)
    return frames


if __name__ == "__main__":
    sys.exit(main())
