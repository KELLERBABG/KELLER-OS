# Persistent Storage: the Vault on a Real Disk

The vault has sealed every sector with AEAD since the day it existed, which made "stored" mean a
`Vec` in the kernel heap — a good place to prove a format and a useless place to keep data. This is
the part that makes a sector survive the machine being switched off: an AHCI driver, a block layer,
an on-disk image, and a boot path that reads the image back — but only after a zero-knowledge proof
has said the image belongs to the secret this machine holds.

It is deliberately four small layers rather than one driver, because each one can be tested without
the others:

| File | What it is |
|---|---|
| [`src/block.rs`](../src/block.rs) | Sectors, geometry, the `BlockDevice` interface, and `MemDisk` — a reference device used by every format test, so the format is checked on a machine with no disk at all |
| [`src/arch/ahci.rs`](../src/arch/ahci.rs) | The Intel AHCI host controller: reset, ports, `IDENTIFY`, `READ/WRITE DMA EXT`, polled, with no interrupts and one command in flight |
| [`src/zk.rs`](../src/zk.rs) | The Schnorr proof that gates the image's key, and the key schedule that turns the proof transcript into a key |
| [`src/storage.rs`](../src/storage.rs) | The image: superblock, per-slot records, the journal sector, the authentication step, the refusal reasons |

## 1. The image

```text
  sector 0        superblock (512 bytes; readable without a key - and holding none)
  sectors 1..1+n  one vault sector per slot, each sealed twice
  sector 1+n      probe slot: written and read back before the superblock is committed
```

Superblock:

```text
  0   8  magic "KOSVLT01"
  8   2  format version
 10   2  slot count
 12   2  record size (512)
 14   2  flags (bit 0: the probe slot verified on the last save)
 16   8  generation, incremented on every save
 24   8  reserved
 32  32  device nonce, fresh on every format
 64  32  the owner's public commitment X = x*G
 96  32  HMAC-SHA256 over bytes 0..96 under the unlock key
128      zero padding
```

Record (one per slot):

```text
  0   8  vault sector index
  8   4  sealed payload length
 12  12  record nonce, fresh for every write
 24      the record's AEAD seal, whose AAD binds the slot, the generation and the vault index
```

The payload inside that seal is the *vault's* own sealed sector. Two keys, for two reasons: the
vault's key authenticates the **contents**, the disk key authenticates **this record, in this slot,
in this generation**. The slot and generation in the AAD are what stop a record from being moved, or
a rollback from being assembled out of a mixture of saves — a record written for generation 5 simply
does not open in generation 6.

## 2. Why a proof is what gates the key

The unlock key is derived from the Schnorr transcript:

```text
  proof   = Schnorr proof of knowledge of x, for the statement "this header"
  key     = HKDF-SHA256(salt = device nonce, ikm = X || R || s, info = "KOS-VAULT-DISK-KEY")
```

so the key does not exist until a proof has been produced **and** checked against `X` **and** against
the header that is on the medium right now. Three failures are distinct and all of them are harmless:

* a wrong secret produces a proof that does not verify (`not-authenticated`);
* an edited header changes the statement, so the MAC under the derived key no longer matches
  (`header-tampered`);
* an edited record fails its AEAD tag (`record-tampered`).

None of them yields a key, and none of them can be turned into "load whatever was readable and hope".

What the medium does **not** hold: no root secret, no shard of it, no key, and no hash of the secret
to test guesses against — the only function of the secret in the image is the group commitment `X`.
That is the whole reason the gate uses a zero-knowledge proof instead of a "compare a hash" check.

The proof nonce is derived (`H(secret || context)`, the RFC 6979 idea) rather than random, and that
is a requirement rather than a shortcut: the key is a function of the transcript, so the *same* image
has to produce the *same* transcript on every boot or the key it was written under could never be
re-derived. A different statement gives a different nonce, hence a different `R`. The randomized
prover is still there as [`Witness::prove_randomized`](../src/zk.rs) for the interactive case.

Corollary worth stating plainly: a proof about a statement is not evidence that the statement was
*true* when the image was written. An attacker who edits a superblock field can hand the field to
the vault and get back a proof about the edited statement — because that is what a proof is. What
the attacker cannot do is make the edited header's MAC come out right, since the key is salted with
the edited bytes. The self-test asserts both halves of that separately.

## 3. The journal sector

One vault sector belongs to the storage module itself (`0x4B45_4C4C_4552`, "KELLER"). Its payload is
a 40-byte entry: a tag, a counter, and a 16-byte stamp drawn from hardware entropy when the entry is
first written. Each `disk journal` reads the entry that is *on the medium*, increments the counter,
and saves.

It exists so that persistence is something the machine can demonstrate about itself rather than only
in a test: a counter that keeps climbing across power cycles cannot have come from RAM, and the stamp
comes back unchanged with it, so a machine can tell its own image from a copy of one. `disk test`
proves the same property against `MemDisk` in miniature, including a fresh vault opening the bytes an
earlier one left behind — which is what a restart *is*.

## 4. What the boot does

```text
[OK] STORAGE CONTROLLER: 00:04.0 8086:2922 AHCI 256 (6 ports implemented, 1 device(s) identified)
[OK] STORAGE DEVICE: port 0 model="QEMU HARDDISK" fw="2.5+" serial="QM00005" 32768 sectors (16 MiB, 512-byte logical sectors) LBA48
[--] VAULT IMAGE: "QEMU HARDDISK" has 32768 sectors and no vault image on it (`disk format` writes one)
[OK] VAULT FORMAT SELF-TEST: 25 assertions passed, 0 failed (block layer, proof gate, image format, journal - on the reference device)
[OK] DISK SELF-TEST: 20 assertions passed, 0 failed (registers, port geometry, scratch round-trip)
```

On the next boot, with an image present:

```text
[OK] VAULT IMAGE: generation 3 owner=4f64bd803599f372 slots=8 nonce=13a52e78ba12e7d1 on "QEMU HARDDISK" (32768 sectors)
[OK] VAULT RESTORE: 2 sector(s) adopted from the image, generation 3
[OK] DISK JOURNAL: boots=1 stamp=5c6d2ba85ee9460ef5473883e739cdb7 (a counter only the medium could have kept)
```

A device that answers nothing, a controller with no disk, a blank disk, and a disk whose image is
refused are all documented states, not boot failures — the vault simply stays in RAM:

```text
[--] STORAGE CONTROLLER: no AHCI controller on bus 0 - the vault stays in RAM
[--] STORAGE DEVICE: the AHCI controller is present but no port has a device on it - the vault stays in RAM
[!!] VAULT RESTORE: refused (record-tampered)
```

That last line is what a single flipped byte in a record produces: the boot refuses the image,
reports which layer noticed, and carries on booting without it. It is worth being precise about why
that is not a lockdown: a disk that has been edited (or has rotted) is a *storage* failure, and the
kernel's job is to keep the machine running on the memory it can still trust, not to halt because a
peripheral lied. The image is never partially adopted — `load_image` authenticates the superblock
before it reads a single record.

## 5. The shell surface

```text
disk [status|test|format|save|load|write <text>|read|journal|wipe|superblock]
```

`disk write` / `disk read` are the user-data path (`KELLER-OS PERSISTS` in the examples below);
`disk journal` is the counter described above; `disk superblock` prints the superblock *as read from
the device right now*, in a form an independent reader can compare with its own parse of the raw
image; `disk wipe` overwrites every record and then the superblock, so "the vault was wiped" does not
leave readable records behind.

```text
[SH] DISK: formatted generation 1 slots=8 owner=feb5a8febf6879c8 nonce=13a52e78ba12e7d1
[SH] DISK: wrote 18 bytes to sector 0x55534552, generation 2
[SH] DISK USER SECTOR: 18 byte(s): "KELLER-OS PERSISTS"
[SH] DISK JOURNAL: boots=1 image-generation=3 stamp=5c6d2ba85ee9460ef5473883e739cdb7
[SH] DISK PROBE assertions: 88 passed, 0 failed
[DISK] superblock: magic=KOSVLT01 version=1 slots=8 sector-size=512 flags=0x0001 generation=4 owner=... nonce=... mac=...
```

## 6. Verification

### 6.1 Two boots, one disk

Persistence cannot be checked inside a single process, so the harness runs two QEMU processes against
one raw image file. The two console scripts are plain line lists:

```text
target\disk-a.txt        target\disk-b.txt
------------------        ------------------
disk test                 disk read
disk format               disk journal
disk write KELLER-OS PERSISTS   disk superblock
disk read
disk journal
```

Run A formats, writes the marker and advances the journal:

```powershell
& "C:\Program Files\qemu\qemu-img.exe" create -f raw target\vault.img 16M
python dev-tools\qemu_check.py --vga std --secs 60 --stdin-script target\disk-a.txt --stdin-delay 6 `
    --qemu-arg=-device --qemu-arg=ich9-ahci,id=ahci `
    --qemu-arg=-drive --qemu-arg=id=vdisk,file=target\vault.img,if=none,format=raw `
    --qemu-arg=-device --qemu-arg=ide-hd,drive=vdisk,bus=ahci.0 `
    --expect "[OK] STORAGE DEVICE: port 0 model=\"QEMU HARDDISK\"" `
    --expect "[SH] DISK PROBE assertions: 88 passed, 0 failed" `
    --expect "[SH] DISK USER SECTOR: 18 byte(s): \"KELLER-OS PERSISTS\"" `
    --expect "[SH] DISK JOURNAL: boots=1" --forbid LOCKDOWN
```

Run B is the same image, in a second emulator process — a power cycle as far as the guest can tell:

```powershell
python dev-tools\qemu_check.py --vga std --secs 60 --stdin-script target\disk-b.txt --stdin-delay 6 `
    --qemu-arg=-device --qemu-arg=ich9-ahci,id=ahci `
    --qemu-arg=-drive --qemu-arg=id=vdisk,file=target\vault.img,if=none,format=raw `
    --qemu-arg=-device --qemu-arg=ide-hd,drive=vdisk,bus=ahci.0 `
    --expect "[OK] VAULT RESTORE: 2 sector(s) adopted from the image, generation 3" `
    --expect "[SH] DISK USER SECTOR: 18 byte(s): \"KELLER-OS PERSISTS\"" `
    --expect "[SH] DISK JOURNAL: boots=2" --forbid LOCKDOWN
```

`disk-a.txt` runs `disk test`, `disk format`, `disk write KELLER-OS PERSISTS`, `disk read` and
`disk journal`; `disk-b.txt` runs `disk read`, `disk journal` and `disk superblock`. The marker
coming back byte for byte in the second process, and the journal counter arriving at 2 with the
*same* stamp, are the two things that cannot be faked out of RAM — and the scripted lines are only
sent one at a time, each after the guest has echoed the previous one, because `disk test` keeps the
shell busy for seconds and the emulator drops serial bytes that arrive while it is: a line the
guest never echoed is re-sent, with the partial prefix erased first so a retry cannot turn into a
different command.

### 6.2 The other side of the cable: ` dev-tools/disk_check.py`

The guest's own self-tests prove the format works from the inside. The host tool opens the raw image
and parses it with a second implementation of the same layout:

```powershell
python dev-tools\disk_check.py --img target\vault-a.img --later target\vault.img `
    --marker "KELLER-OS PERSISTS" --from-log target\disk-run-b.log
```

```text
disk: two boots: generation 3 -> 4, 2 -> 2 record(s), same device nonce, every shared slot rewritten
disk: cross-check: the guest's own read of the superblock agrees with this parse (generation 4, 8 slots, nonce 13a52e78ba12e7d1...)
disk: image: PASS - 75 assertion(s) passed, 0 failed
        (image geometry, record framing, no repeated nonces, no plaintext on the medium)
```

What it checks: the geometry is self-consistent and matches what the guest printed from its own read;
the magic appears exactly once, so no stale superblock survives; every non-blank slot is a
well-formed record with a non-zero nonce and zeroed padding; no two records share a nonce (no AEAD
keystream reuse); **the marker plaintext is nowhere on the medium**, in any case; and, across the two
boots, the generation strictly advanced, the device nonce and owner commitment stayed the same, and
every shared slot's ciphertext changed.

It also verifies itself in the negative direction, which is the only way a checker's pass means
anything: planting the marker in a free sector makes it fail three assertions, copying one record's
nonce onto another makes it report the keystream reuse, and it exits non-zero in both cases.

**What it cannot check:** the superblock's HMAC, and therefore any edited *ciphertext*. The key is a
function of a proof transcript that exists only inside the guest and is never written down — that is
the entire point of the design — so only a holder of the root secret can verify the tag. The guest
does that at boot; the host checks everything that does not need the key. The two together are
stronger than either alone.

### 6.3 The rest of the matrix

| Run | Result |
|---|---|
| `--vga std` + `target/full-input.txt` | `SELF-TEST SUMMARY: 159 passed, 0 failed, 20 skipped` (the 20 are the AHCI adapter checks on a machine with no AHCI) |
| the same script with `-device ich9-ahci` + a 16 MiB disk | `SELF-TEST SUMMARY: 179 passed, 0 failed` |
| `disk test` on a disk machine | `88 passed, 0 failed` (block layer + proof + image format + adapter) |
| `--vga none` | `137 passed, 0 failed, 20 skipped`, input probe `17 passed, 0 failed, 4 skipped` |
| `-machine pc,i8042=off` | unchanged: `159 passed, 0 failed, 20 skipped`, and the injection run still fails honestly |
| ring-3 phase | unchanged: 40/40, preemption proof, fault containment, frames back to 0 |
| ` dev-tools/wire_check.py --secs 130` | unchanged: 11 frames on the wire, all validated independently |
| one flipped byte in a record | boot prints `[!!] VAULT RESTORE: refused (record-tampered)`, no lockdown, machine boots |
| the disk unplugged entirely | `[--] STORAGE CONTROLLER: no AHCI controller on bus 0` — the vault stays in RAM |

## 7. What verification caught

Seven real bugs, none of them found by reading the code:

1. **The PRDT entry was 24 bytes instead of 16.** The specification's descriptor is address,
   address-high, then *byte count minus one*; a padded structure makes the device read the size from
   the wrong place, and every transfer becomes one byte long. This is the kind of thing that looks
   fine until `IDENTIFY` returns 512 bytes of zeros.
2. **`PRDTL` was written as "entries minus one".** It is a count. QEMU sees `prdtl == 0` and returns
   "no PRDT" — and because a failed PRDT still accumulates into the command header's byte counter,
   the transfer *reported* 512 bytes while nothing had moved. That combination is exactly why the
   driver checks the data, not the counter.
3. **The driver refused any port whose task file had an error or fault bit set before issuing
   anything.** A 512-byte ATA disk comes out of reset reporting status `DSC|DF` with `ABRT` in the
   error register (QEMU's `ahci_reset_port` sets exactly that), so this refused every port on every
   machine. The bits now only matter *after* a command, and the task file as the port came out of
   reset is kept and printed with any failure.
4. **The pre-command data-request wait polled the wrong bit order** — it returned `DeviceError`
   rather than continuing when the device was merely busy. The current check waits for `BSY|DRQ` to
   clear, which is what the specification asks for.
5. **The record header was declared 16 bytes while holding 24** (index 8 + length 4 + nonce 12). The
   payload overwrote the last 8 bytes of the nonce, so *no record could ever be opened again* — and
   the old self-test never noticed because it only loaded a vault it had just saved in the same
   call.
6. **The proof was taken over a header that then changed.** `format_image` set the probe flag *after*
   proving, and `save_image` incremented the generation *after* deriving the key, so in both cases
   the key on the medium was derived from a statement the medium does not hold. The first save
   worked and the second one — and every save after a reboot — failed `header-tampered`.
7. **The self-test's own generation case called `unwrap()` on the authentication step**, turning a
   finding into a kernel panic (and a lockdown). It now reports the failure it found.

Two of those (6 and 7) were only reachable from a *third* save or a *reboot*, which is a fair
argument for doing persistence verification across two processes rather than one.

## 8. Honest limits

* **A rollback is not detectable by this design.** The image carries its generation, but the machine
  has no trusted memory of the highest generation it has seen, so an old copy of the disk (or of a
  sector) restores the old bytes and the old key. Detecting that needs a monotonic counter the guest
  cannot reset — a TPM, an SEV-SNP-style measurement or a write-once fuse — and there is none here.
  The generation binding stops a *mixture* of two saves from loading, which is a different property.
* **One image, no journal: a power cut mid-save is a refusal, not a recovery.** Records are written
  before the superblock, so an interrupted save leaves the previous superblock describing records
  that have already been overwritten. The next load refuses with `record-tampered` rather than loading
  a mixture, and getting back to a working state means saving again or formatting. There is no
  two-phase commit, no free list and no rollback log.
* **The driver is ring 0**, exactly like the NIC's, and for the same reason: a DMA-capable device
  behind a ring-3 task needs an IOMMU or the bounce-buffer split the specification describes, and
  neither exists yet. Handing a ring-3 task a raw BAR today would give it the whole physical address
  space.
* **512-byte sectors only.** A device whose logical sector size is not 512 is reported and refused
  rather than addressed wrongly. No NCQ, no port multipliers, no hot-plug, no interrupts: one polled
  command at a time, with every interrupt source masked.
* **The superblock's MAC can only be checked by the guest**, so a host-side tool cannot tell a
  well-formed forgery of a record from a real one. It can tell that the plaintext is absent, which is
  the property that matters if the disk is stolen.
* **The root secret is still `LOCAL_ROOT_SECRET` in [`src/main.rs`](../src/main.rs)**: the persistence
  path is complete, but the secret it authenticates with is a build-time constant rather than
  something an operator supplies, so "this image is yours" currently means "this build generated it".
  That is the next thing the vault needs, and it is not a storage-layer problem.
* **The unlock key lives in kernel memory for the duration of a load or save** and is wiped where the
  code can (the module wipes transcripts, `crypto::wipe` is used on the seal keys, and the panic path
  scrubs the heap), but there is no hardware key store, so a hostile kernel or a physical attacker
  with a debugger is out of scope — as it is for the vault's RAM keys.
