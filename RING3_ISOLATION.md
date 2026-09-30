# KELLER-OS: Ring-3 Isolation, Address Spaces & Preemption

This document describes the three pieces the microkernel story was missing, and how each one is
verified from the boot log rather than asserted:

1. **Real Ring-3 transitions.** A task is entered with `iretq` into a synthesized frame whose
   `cs` is a DPL-3 descriptor, and its only way back into the kernel is a single DPL-3 gate.
2. **Per-process address spaces.** Every process owns a PML4; `cr3` is switched on the task
   switch, so two processes that use the *same* virtual addresses reach different physical frames
   and neither can read the other's memory in hardware.
3. **Preemptive scheduling.** The context switch happens inside the timer interrupt: the
   interrupted frame is parked, the next process's parked frame is loaded, and a task that never
   cooperates — or has already faulted — is handled by the same three lines.

Sources: [`src/arch/paging.rs`](src/arch/paging.rs) (address spaces),
[`src/proc.rs`](src/proc.rs) (process table, syscall door, containment, phase driver),
[`src/arch/idt.rs`](src/arch/idt.rs) (the DPL-3 gate and the switch in the ISR epilogue),
[`src/arch/gdt.rs`](src/arch/gdt.rs) (the DPL-3 selectors and the I/O permission bitmap).

---

## 1. Address spaces

The boot tables ([`src/boot.rs`](src/boot.rs)) identity-map the low 4 GiB with 2 MiB pages and
hand the kernel one PML4 in `cr3`. One address space is enough for a kernel that only runs its
own code — and it is exactly what makes per-process isolation impossible: everyone sees
everything.

`paging::init` reads those tables back out of `cr3` (no symbol from the bootstrap is exported), so
a process space can be built *on top of* them:

```
PML4[0]  -> process PDPT             (present, writable, U/S = 1)
             PDPT[0..4] -> kernel PDs (copied verbatim: present, writable, U/S = 0)
             ...
             PDPT[256]  -> process PD -> PT -> the process's own 4 KiB pages (U/S = 1)
```

**User virtual layout.** Identical in every space — that is the point, because two processes that
agree on an address and still reach different memory are the property under test:

| Address | Maps |
| :--- | :--- |
| `0x4000000000` | code page (present, user, **no** write bit) |
| `0x4000001000` | data page (present, writable, user) |
| `0x4000100000` | stack page, `rsp` starts 16 bytes below its top |
| `0x4000200000` | peer window — mapped in **one** phase task only |

`0x4000000000` is 256 GiB: far above the boot identity map, so no user page can shadow a kernel
page, and inside `PML4[0]`, so every process can share the kernel's tables instead of duplicating
a 4 GiB map.

**Supervisor pages stay supervisor.** The CPU ANDs the U/S bit along the walk. `PML4[0]` is
U/S = 1 so a path *through* it exists, but the copied PDPT entries keep U/S = 0, so kernel code,
heap and framebuffer remain unreachable from CPL 3 — while staying reachable *in* that space,
which is what lets the kernel run with a process's `cr3` loaded.

**Frames come from the kernel heap.** The heap is inside the identity map, so a frame's address is
at once the pointer the kernel writes through and the physical address the CPU wants in a
page-table entry or in `cr3`. There is no second allocator and no translation table to keep in
sync; a "frame" is a `u64`. Teardown hands every leaf and every table — the PML4 included — back
to the heap, and the boot log shows the count return to where it started.

---

## 2. Entering ring 3

`proc::spawn_user` maps the pages and writes a **synthetic interrupt frame** into the process's
row. The ISR epilogue is the same code path for a resumed task and a brand-new one, so entry is
just "resume a frame nobody has run yet":

| Offset | Contents |
| :--- | :--- |
| `0` | XMM0-15 (256 bytes; all zero for a new task) |
| `256` | r15 … rax (15 registers) |
| `376` | vector, `384` error code |
| `392` | `rip` = the entry address |
| `400` | `cs` = `0x1B` (GDT index 3, RPL 3) |
| `408` | `rflags` = `0x202` (IF = 1, so the timer can preempt the task at all) |
| `416` | `rsp` = inside the task's own stack page |
| `424` | `ss` = `0x23` (GDT index 4, RPL 3) |

Total 432 bytes; the row reserves 512 so the epilogue's `movups` restores are always aligned. The
offsets are checked against `core::mem::offset_of!(InterruptFrame, …)` in `ring3 test`, so the
park/reload contract cannot drift from the struct in [`src/arch/idt.rs`](src/arch/idt.rs).

Two further facts make a ring-3 task genuinely unprivileged:

* **Port I/O is denied by hardware.** The TSS I/O permission bitmap base sits beyond the TSS
  limit, so the CPU treats every port as denied for CPL 3 and raises `#GP` on `in`/`out` before
  any kernel code runs. `gdt::port_io_denied()` is what the self-test reads back.
* **One door, DPL 3.** Vector `0x80` is the only gate whose attributes are `0xEE`
  (present, DPL 3, 64-bit interrupt gate); every other gate is `0x8E`. A user task cannot reach
  the timer stub, a fault stub, or anything else to fake a frame.

---

## 3. The context switch

Every gate uses IST1, which means two things that make switching cheap and correct:

* the CPU always switches to the IST stack, so the frame layout is identical whether the interrupt
  came from ring 0 or ring 3, and the kernel's own stack pointer is not involved;
* every interrupt re-enters at the IST top, so a frame abandoned mid-switch is simply overwritten
  next time — there is no per-task kernel stack to maintain.

`proc::on_timer` runs in the timer IRQ, after `clock::on_tick`:

| Interrupted context | Behaviour |
| :--- | :--- |
| ring 3 (`cs & 3 == 3`) | charge one tick of the quantum; at zero, reset it and switch to the next runnable row |
| ring 0, **idle-armed** | switch immediately — the idle context has published that it is halted with nothing to protect |
| ring 0, otherwise | nothing: kernel work is never preempted |

`switch_to` copies the 432-byte frame into the outgoing row, records the parked `rip` (for faulted
tasks it is the faulting instruction), marks the row ready, increments the incoming row's counters,
arms `idt::request_switch` with the incoming frame's address and loads that process's `cr3`. The
interrupt epilogue then loads the armed address into `rsp` and restores from it, so the resumed
process *is* the interrupted one — same instruction stream, same registers, same address space.

Interrupt gates clear IF and nothing re-enables it inside a handler, so a syscall cannot be
preempted and a switch can never race another switch. The kernel's own critical sections (heap,
console) are therefore only ever entered with preemption off; the single window where the kernel
may be switched away from is between `proc::arm_idle()` and `proc::disarm_idle()`, which brackets
the `hlt` in the idle loop.

**The kernel is a row, not a special case.** Slot 0 (`kernel-idle`) is an ordinary process row with
no address space: it is picked like any other, and when it runs it hands the CPU straight back at
the next `hlt`. That is how ring-0 work (shell polling, GUI refresh, mesh cover traffic, the
heartbeat) still runs while five ring-3 tasks spin, and why the heartbeat keeps printing during
the phase.

---

## 4. The syscall door, and what it refuses

`int 0x80` from ring 3 arrives with a frame whose `cs` is `0x1B` — the CPU's own statement that
the caller was a user task, and the strongest evidence in the log that the boundary is real.

| `rax` | Call | Arguments | Returns |
| :--- | :--- | :--- | :--- |
| 0 | `exit` | `rdi` = status | never returns; the row is retired |
| 1 | `write` | `rsi` = user buffer, `rdx` = length (≤ 80) | bytes printed, or `EFAULT` |
| 2 | `yield` | — | switches to the next runnable task, counted separately |
| 3 | `progress` | `rdi` = counter | recorded in the row |
| 4 | `port_write` | `rdi` = port, `rsi` = value | 0, or `EFAULT` for a port outside the capability table |

`write` never dereferences the caller's pointer. `AddressSpace::copy_from_user` walks the
*caller's* tables, requires U/S = 1 at every level, and copies out through the identity map. A
kernel address handed to the door therefore fails the walk and comes back as `EFAULT` — the check
that separates "kernel reads a user pointer" from "kernel trusts a user pointer". The phase
exercises it: `[R3 sandbox-peer] write(0x100000, 8) refused: EFAULT`.

The capability table holds exactly one port (`0x80`, the POST/delay port that `port::io_wait`
already uses), so the obedient driver's sanctioned port write and the faulty driver's raw `in al,
dx` differ in their *outcome*, not just in their intent.

---

## 5. Fault containment

The exception path branches on the same `cs` value the frame carries:

* **from ring 3** — the task is marked faulted, the fault is printed with vector, error code,
  `rip`, `cs`, `cr3` (and `cr2` for `#PF`), the next runnable row is resumed, and the dead task's
  address space is handed back to the heap. The kernel never locks down: a driver faulting is an
  ordinary event for a machine whose drivers are sandboxed.
* **from ring 0** — unchanged: `lockdown()`, which wipes scrub regions and parks the CPU.

Two tasks in the phase exist to make that branch real:

```
[!!] RING-3 CONTAINMENT: 'sandbox-port' #GP general protection (vector 13, error=0x0) at rip=0x0000004000000005 cs=0x1b - task terminated, kernel intact
     raw port I/O at CPL 3: the TSS I/O permission bitmap denies every port, so the CPU raised #GP before any kernel handler ran
[R3 sandbox-peer] write(0x100000, 8) refused: EFAULT (not a user page of this address space)
[!!] RING-3 CONTAINMENT: 'sandbox-peer' #PF page fault (vector 14, error=0x4) at rip=0x0000004000000011 cs=0x1b - task terminated, kernel intact
     fault address 0x0000004000200000 is not mapped in cr3=0x5f5000: the page tables refused a read this address space does not allow
```

`sandbox-port` fails on the fifth byte of its program — the `in al, dx` — and `sandbox-peer` on
the seventeenth, the `mov rax, [0x4000200000]` that is mapped in `driver-beta` and nowhere else.
`error=0x4` is "user mode, not present, read": the CPU declining a cross-space read.

---

## 6. The demonstration tasks

`ring3 run` creates five ring-3 tasks, one address space each, and delivers
`PHASE_BUDGET` (24) slices of 100 ms with the kernel row interleaved:

| Task | Program | Purpose |
| :--- | :--- | :--- |
| `driver-alpha` | mediated port write, then a `SYS_PROGRESS` loop | an obedient driver: advances forever, never yields |
| `driver-beta` | the same, plus a `SYS_YIELD` every 1024 reports | makes the voluntary counter distinguishable from the involuntary one |
| `spin-probe` | `jmp $` (2 bytes) | zero syscalls, zero cooperation: only the timer can take the CPU from it |
| `sandbox-port` | `mov edx, 0x60; in al, dx` | raw port I/O at CPL 3 → `#GP` |
| `sandbox-peer` | `write(kernel address)` then `mov rax, [peer page]` | `EFAULT` from the door, then `#PF` from the page tables |

The programs are emitted by a small assembler-in-Rust (`Program`) whose every method emits one
documented instruction, and the reports print the resulting bytes in hex — so the two programs
that exist to misbehave can be read rather than trusted:

```
[SH] RING-3 PROGRAM 'driver-alpha' 38 bytes: b8 04 00 00 00 bf 80 00 00 00 be 2a 00 00 00 cd 80 45 31 e4 49 ff c4 b8 03 00 00 00 4c 89 e7 cd 80 e9 ee ff ff ff
     PROGRAM 'spin-probe' 2 bytes: eb fe
     PROGRAM 'sandbox-port' 8 bytes: ba 60 00 00 00 ec eb fe
     PROGRAM 'sandbox-peer' 29 bytes: b8 01 00 00 00 be 00 00 10 00 ba 08 00 00 00 cd 80 48 a1 00 00 20 00 40 00 00 00 eb fe
```

The address-space table printed when the phase is armed is the isolation statement itself: the
same three virtual addresses, five different frames, and one peer window that is `absent` in
every space but one.

---

## 7. Boot-time probe

Every boot runs one ring-3 task before the shell comes up, because the privilege boundary is the
claim the rest of the microkernel argument rests on and a claim only this machine can check. It
costs about one timer tick:

```
[--] RING-3 PROGRAM 'keller-hello' 36 bytes: b8 01 00 00 00 48 be 00 10 00 00 40 00 00 00 ba 2c 00 00 00 cd 80 b8 00 00 00 00 bf 00 00 00 00 cd 80 eb fe
     entry 0x4000000000, stack top 0x4000100ff0, data 0x4000001000, kernel cr3=0x263000
[R3 keller-hello] RING-3 HELLO: this line was printed at CPL=3
[R3 keller-hello] exit(0) through syscall 0 - 2 syscalls from this task, cs=0x1b on entry
[OK] RING-3 ENTRY: 'keller-hello' ran at CPL=3 - the CPU's own frame says cs=0x1b ss=0x23, cr3=0x5b9000 (iretq restored a user frame, not a kernel one)
[OK] RING-3 EXIT: state=exited 2 syscalls, 1 switch-ins, 1 ticks, exit code 0 - parked rip=0x4000000022 (inside its own code page)
[OK] RING-3 PROBE COMPLETE: address space torn down, paging frames 0 -> 0, kernel cr3=0x263000 restored
```

The text of the middle line was produced by the task itself, at CPL 3, through the door; the parked
`rip` is the `jmp $` that follows the exit call, six bytes before the end of its own code page.
Frames `0 -> 0` is the teardown accounting: the probe leaves the heap exactly as it found it.

---

## 8. The preemptive scheduler, measured

```
[OK] PREEMPTIVE SCHEDULER: 28 switches by the timer, 10 voluntary yields, 26 ring-3 slices delivered in 185 ticks (1850 ms) - each slice ended by the timer unless the task yielded first
[OK] RING-3 PREEMPTION PROOF: 'spin-probe' (jmp $) got the CPU 8 times with 0 syscalls and parked at rip=0x4000000000 - it never asked to be scheduled, so only the timer could have taken the CPU for it
[OK] RING-3 PROGRESS: 'driver-alpha' reported 37201 through SYS_PROGRESS (37202 syscalls), 'driver-beta' 8192 (8201 syscalls, 8 voluntary yields) - both kept advancing
[OK] RING-3 I/O MEDIATION: 2 mediated write(s) to port 0x80 through the capability table; 'sandbox-port' raw `in al, dx` got #GP (the bitmap denied it before any kernel handler ran)
[OK] RING-3 FAULT CONTAINMENT: 2 task(s) killed at CPL 3 (1 #PF, 1 #GP), 1 copy-from-user call(s) refused with EFAULT, timeout=no - no kernel lockdown, the idle loop keeps its heartbeat
[OK] RING-3 PHASE COMPLETE: 5 processes retired, address spaces torn down, paging frames back to 0, kernel cr3=0x263000
```

Read together: a task that never made a single syscall still lost the CPU eight times (the timer
did that, not cooperation); a task that never yielded reported 37 201 progress values while the
kernel ran its own idle loop between slices; the two faulty drivers died without taking the
machine with them; and the whole phase gave every frame back.

`yields = 10` is not a guess either: eight of them are `driver-beta`'s schedule (one per 1024
reports) and two are the boot probe's and the self-test probe's `exit`.

---

## 9. Verification

```powershell
# Boot probe (part of every run): CPL 3 entry, syscall door, clean exit, frames returned
python dev-tools\qemu_check.py --vga std --secs 45 --stdin-script target\full-input.txt `
    --expect "[OK] RING-3 ENTRY: 'keller-hello' ran at CPL=3" `
    --expect "[R3 keller-hello] RING-3 HELLO: this line was printed at CPL=3" `
    --expect "[OK] RING-3 PROBE COMPLETE: address space torn down, paging frames 0 -> 0" `
    --expect "[SH] SELF-TEST SUMMARY: 159 passed, 0 failed" --forbid "LOCKDOWN"

# The probe assertions: gate DPL, GDT privilege, port-IO denial, frame layout, address-space
# separation, and one live entry into ring 3
python dev-tools\qemu_check.py --vga std --secs 30 --stdin-script target\ring3-input.txt `
    --expect "[SH] RING-3 PROBE assertions: 40 passed, 0 failed" `
    --expect "[SH] RING-3 EMPIRICAL: 'ring3-selftest' state=exited cs=0x1b"

# The phase: two faults contained, preemption proven, everything torn down, kernel still answering
python dev-tools\qemu_check.py --vga std --secs 30 --stdin-script target\ring3-input.txt `
    --expect "[!!] RING-3 CONTAINMENT: 'sandbox-port' #GP general protection (vector 13, error=0x0) at rip=0x0000004000000005 cs=0x1b" `
    --expect "[R3 sandbox-peer] write(0x100000, 8) refused: EFAULT" `
    --expect "[!!] RING-3 CONTAINMENT: 'sandbox-peer' #PF page fault (vector 14, error=0x4) at rip=0x0000004000000011 cs=0x1b" `
    --expect "[OK] RING-3 PREEMPTION PROOF: 'spin-probe' (jmp $) got the CPU" `
    --expect "[OK] RING-3 FAULT CONTAINMENT: 2 task(s) killed at CPL 3 (1 #PF, 1 #GP)" `
    --expect "[OK] RING-3 PHASE COMPLETE: 5 processes retired, address spaces torn down, paging frames back to 0" `
    --expect "[SH] RING-3 ROWS: 1/8 used" --expect "[SH] ---- KELLER-OS STATUS ----" `
    --forbid "LOCKDOWN" --forbid "unknown syscall" --forbid "state=ready" --forbid "idle_armed=true"
```

What those guards are for: `unknown syscall` catches an ABI mismatch between the emitted programs
and the door (it fired once, when the frame offsets were park-relative instead of frame-relative);
`state=ready` catches a phase that armed tasks and never finished them; `idle_armed=true` catches
preemption left enabled after the phase; `paging frames back to 0` catches a leaked page table; and
`[SH] ---- KELLER-OS STATUS ----` after two containment events is the kernel still being alive as
observed by a shell command rather than as claimed by the fault handler.

`ring3` prints the live table and the isolation comparison. `ring3 run` arms the phase and waits
it out. `ring3 test` reports 40 assertions, none of which restates a constant: the syscall gate's
attributes, target and IST index; that a fault gate is *not* reachable from CPL 3; the DPL of the
three code/data selectors read back out of the live GDT; that the TSS bitmap denies every port;
that `InterruptFrame`'s size and the hard-coded frame offsets agree with the struct; that no
context switch was left armed; the address-space self-test (distinct roots, identical virtual
addresses resolving to distinct frames, a peer page absent in the other space, the kernel mapping
present but unreachable from CPL 3, `copy_from_user` refusing a supervisor address, every frame
returned on teardown); and one live entry into ring 3 whose `cs` really was `0x1B`.

---

## 10. What is not done yet

Stated plainly, because the boundary exists but the port is not finished:

* **The existing PS/2 driver, display server and shell command set still run in ring 0.** They are
  kernel modules that touch ports, the heap and global state directly; moving them behind the door
  needs a capability API for each (port grants, a user-mode heap, `copy_to_user`) before it is an
  improvement rather than a slower kernel. The substrate they need is what landed here, and the
  phase's `driver-alpha` is the shape a ported driver would take.
* **Capability grants are a one-port table**, not a per-process rights structure. The TSS bitmap is
  still "deny everything" rather than a real per-capability bitmap, which is deliberate: a partly
  programed bitmap is a hole, and the mediated-syscall path is the safer direction.
* **No `copy_to_user`.** Only the kernel reading user memory exists. Nothing yet writes back, which
  is why the door returns a scalar in `rax`.
* **The APIC is unused.** Preemption rides the PIT (100 Hz, 10 ms quanta). An APIC timer would make
  the quantum a cycle count instead of a wall-clock tick and would allow timer vectors per mode.
* **No PCID**, so every `cr3` write flushes the TLB. At 10 switches per second that is free; at
  tens of thousands it would not be.
* **SMP is out of scope**: one boot CPU, one IST stack, one process table.
