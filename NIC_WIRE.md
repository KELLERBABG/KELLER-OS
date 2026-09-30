# KELLER-OS — Physical Network Driver & On-Wire Verification

**Scope.** What it takes to put the Vantablack mesh's sealed frames on a real wire from bare
metal: the Intel 8254x (`e1000`) driver in [`src/nic.rs`](src/nic.rs), the Ethernet/IPv4/UDP
framing in [`src/eth.rs`](src/eth.rs), and the independent tool
([`tools/wire_check.py`](tools/wire_check.py)) that attaches to the guest's adapter as its peer
and checks every claim from the outside.

Until this landed, the mesh's transport was `net::CaptureSender`: an in-RAM stand-in that handed
sealed frames to the ingress pipeline unchanged. It proved the mesh's own logic and nothing about
the wire — no headers, no DMA, no device. That is now the *loopback* path; the adapter is the real
one, and both run at the same time.

---

## 1. The adapter

| | |
| :--- | :--- |
| Device | Intel 82540EM (`8086:100e`), QEMU's `e1000` model; the id table accepts the whole 8254x family because they share the register map |
| PCI | Bus 0, function `00:03.0` with a VGA adapter present and `00:02.0` without one; BAR0 assigned by `pci::ensure_memory_bar` to `0xfeb00000` when no firmware did it, 128 KiB aperture, memory space + bus master enabled |
| Rings | 8 transmit and 8 receive descriptors of 16 bytes, 4 KiB buffer per descriptor |
| Interrupts | None. Every source is masked (`IMC = all ones`); the rings are polled from the kernel's 100 Hz idle loop |
| MAC | Read from the EEPROM through `RAL0`/`RAH0` and written back with `AV` set |

Bring-up is `mask interrupts → reset → read and program the MAC → clear the multicast table →
force link up → program both rings → enable`. Boot says what it got:

```text
[OK] NETWORK ADAPTER: 00:03.0 8086:100e (82540EM) bar0=0xfebc0000 (128 KiB) bus-master on, mac=52:54:00:12:34:56
[OK] NIC DMA RINGS: tx 8/8 rx 8 descriptors of 16 bytes (16 x 4 KiB buffers, identity-mapped frames), link=up 1000 Mb/s full-duplex
[OK] NIC SELF-TEST: 47 assertions passed, 0 failed (framing + register readback)
[OK] NIC LINK: up, egress on - the mesh's sealed frames now leave the machine
```

`nic status` reports the registers, the counters, the last refused frame's shape and the wire
switch; `nic test` re-runs the 47 assertions; `nic probe` sends one fixed datagram; `nic on` /
`nic off` gate the wire in both directions.

## 2. Where the descriptors live, and why it matters

The descriptor rings are part of the `Nic` state, not separately allocated, and the buffers come
from the kernel heap. Both of those work for one reason: **the heap sits inside the identity map
the boot tables install**, so a heap block's virtual address *is* its physical address, and the
value written into a descriptor is the same value the driver dereferences. No translation, no
second physical allocator to keep in sync — and a driver whose DMA is a `copy_from_slice`.

Three consequences are worth stating plainly, because each was a bug first:

1. **The state has to be in `.data`.** The boot handoff does not zero `.bss`; modules self-initialise
   (see the `[--] BSS ...; loader left ... (modules self-initialise)` line). A `Nic` whose
   initialiser is all zeroes would be placed in `.bss` and would begin life with someone else's
   bytes in `present` and in its MMIO pointer. Its initialiser therefore carries a non-zero
   signature, which keeps it in `.data`, and the self-test asserts the signature is there.
2. **The rings have to be aligned.** `TDBAL`/`RDBAL` ignore their low four bits, so an unaligned
   ring base is silently truncated and the device fetches descriptors from the wrong place. The
   ring types are `repr(align(128))`, and the self-test reads the bases back out of the device and
   compares them with the addresses the driver meant.
3. **The receive tail is inclusive.** The device may use descriptors up to and including `RDT`, so
   releasing a descriptor means pointing the tail *at the slot just released*. Pointing it at the
   next slot instead leaves the ring full and cuts receive down to a depth of one buffer.

The DMA arena has its own frame counter (`dma-frames`), deliberately separate from
`paging::frames_in_use()`: the ring-3 reports verify that every user-space frame is returned, and a
permanent DMA arena must not be mistaken for a leak there.

## 3. Framing

One datagram per sealed frame, always the same shape:

```text
 0              14        34                  42                    42+n
 +--------------+---------+-------------------+---------------------+
 | Ethernet     | IPv4    | UDP               | Vantablack frame    |
 | dst,src,0800 | 20 B    | src,dst,len,csum  | (sealed shard)      |
 +--------------+---------+-------------------+---------------------+
```

Mesh traffic runs on UDP port `0x4B4C` ("KL") and the driver's probe on `0x4B4D`. A full-size
frame is 618 bytes, well inside the MTU, so nothing here can need fragmentation — and a frame that
arrives fragmented is refused and counted rather than guessed at. The IPv4 and UDP checksums are
computed over the header and the pseudo-header; the known-answer vector in `src/eth.rs` was
produced by a second implementation (Python), so a byte-order slip or a checksum regression cannot
pass by agreeing with itself.

`parse` is structural first and cryptographic never: it checks the version, the IHL, the declared
lengths, the fragment field and the protocol, and only then the checksums. That order is not
cosmetic — a frame that is not UDP is not UDP whatever its checksum says, and a caller probing one
field at a time should see the refusal it is probing for.

### 3.1 Address resolution

One piece of ARP exists, and only the piece needed to be *reachable*: a request for this
endpoint's address is answered with this endpoint's MAC. Without it, a peer that has to learn the
MAC cannot deliver anything at all — on QEMU's user-mode network the guest's outbound datagrams
produce replies that slirp then queues behind an ARP request nobody answers, so the segment looks
healthy while nothing ever arrives. That was the first thing the driver did wrong, and it was
visible only because the refused frames were recorded *with* their header fields
(`last-refused: ... ethertype=0x0806`): "malformed=23" would have hidden a peer behind a parser
complaint. Well-formed frames this layer does not speak are now counted as `not-ipv4`, and only
frames that make no sense are `malformed`.

The rest of ARP (proactive resolution, caching, announcements) is still absent on purpose: this
profile configures its addresses rather than discovering them.

## 4. What is verified, and by whom

The kernel's own answer is a start: 47 assertions read the configuration back *out of the device*
(memory decoding, bus mastering, the BAR, reset, the MAC in `RAH0`, both ring lengths, both enables,
the interrupt mask, the ring alignment and the ring bases as the device kept them) plus the whole
framing layer including its known-answer vector.

That is the device and the guest agreeing with themselves. `tools/wire_check.py` is the other end
of the cable: it boots QEMU with `-nic none -netdev socket,id=wire,listen=... -device e1000`, so
the only station on the segment is the tool, and then it does five things.

```powershell
python tools\wire_check.py --secs 130
```

1. **Validates every frame the guest transmits** from the outside in — Ethernet addresses and
   ethertype, the IPv4 header and its checksum, UDP and its pseudo-header checksum, and then the
   quantized geometry of the sealed frame inside the payload (exactly 576 bytes, a tail of a legal
   length that is not all zeroes, a shard index inside the ring, counters that never go backwards,
   and one frame per shard index per message).
2. **Requires a command typed on the console to come out of the adapter.** It types `nic probe`
   through the emulated keyboard and then compares the resulting frame with one it builds itself
   from the RFCs, byte for byte — headers, both checksums, payload. Typed input, syscall path,
   descriptor rings and wire, in one check.
3. **Injects a ledger of frames that should each be refused for a different reason** and then
   requires the guest's own counters to have moved by exactly the predicted amount: a replay of a
   frame the guest itself sent (addressed back to it), a sealed frame on a fresh counter with its
   record edited, a byte-identical echo of a frame addressed to someone else, a broken UDP
   checksum, a fragment, a non-UDP protocol, a foreign port, a truncated frame, and an ARP request.
4. **Checks the layer above the driver too.** The two addressed mesh frames reach the mesh, and the
   mesh's *own* counters have to show what happened: one replay refused by the 64-counter window
   and one tampered shard refused by the ShardSec tag, with the route not severed (the isolation
   budget is three). This is the part a header check cannot fake.
5. **Records a pcap and re-reads it** with a separate parser, so the recording is checked rather
   than assumed.

Measured on a passing run:

```text
PASS the guest's probe frame is byte-identical to this tool's independent build
PASS the mesh's own sealed frames cross the wire (12 seen)
PASS frame 1 validates from the outside (618 bytes, msg-id=254, counter=1, shard=0)
PASS one message is carried by one frame per shard index ([0, 1, 2])
     guest deltas: {'rx': 9, 'mesh': 2, 'foreign': 2, 'malformed': 1, 'fragmented': 1,
                    'not_udp': 1, 'bad_checksum': 1, 'arp_requests': 1, 'arp_replies': 1, ...}
PASS the guest received exactly the 9 injected frames
PASS the mesh counted the replayed frame as a replay (1)
PASS the mesh counted the fresh-counter edit as a tampered shard (1)
     wire summary: 14 frame(s) seen (mesh=12 probe=1 arp=1)
wire: PASS
```

Two details in that tool are worth keeping if it is ever rewritten. The tampered frame has to be
built on a counter the guest has not taken yet, *and* far enough ahead that the guest's own decoys
— which travel back through its in-RAM loopback and claim the next counter each — cannot win the
race; a frame on the immediately-next counter is refused as a replay before its tag is ever
checked, which is exactly the wrong finding. And QEMU's stream socket netdev prefixes every frame
with its length in *both* directions, so a tool that reads that framing but writes bare Ethernet
gets silence back that looks precisely like a guest ignoring incoming traffic.

## 5. Deliberately still missing

* **The driver runs in ring 0.** A DMA-capable device behind a ring-3 task needs either an IOMMU
  or the bounce-buffer split `SPECIFICATION.md` §3 describes (the sandbox decides, the kernel
  moves the bytes); neither exists yet, and handing a ring-3 task a raw BAR today would give it
  the whole physical address space — the opposite of the isolation it would be sitting on. The
  plumbing a mediated split needs is in place: the rings are ordinary frames, the MMIO goes through
  one window, and the ports and DMA addresses are already the only things a sandbox would have to
  be granted.
* **No interrupts.** RX is polled from the 100 Hz loop. Interrupt-driven receive is a latency
  optimisation, not a correctness question: the wire tool measures the same frames either way.
* **No `copy_to_user` for the packet path**, so a receiving ring-3 task would have to be handed
  bytes through the same door a kernel caller uses.
* **No ARP cache, no DHCP, no IPv4 options, no reassembly, no IGMP, no PCID.** The profile is
  configured, not discovered.
* **The SOCKS5 egress daemon is still not written** — the 1080 proxy `VANTABLACK_INTEGRATION.md`
  describes needs a ring-3 task holding a socket table, and the transport it would stand on is
  what this document delivers.
