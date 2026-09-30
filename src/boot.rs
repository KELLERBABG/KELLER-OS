//! Bare-metal bootstrap: boot headers, 32-bit page-table setup, long-mode switch.
//!
//! This replaces the pre-compiled `boot.s`/`boot.o` pair so the whole image is built
//! by rustc alone (no external assembler). Two boot protocols are advertised:
//!
//! * **PVH direct boot** (`XEN_ELFNOTE_PHYS32_ENTRY`) — what `qemu-system-x86_64
//!   -kernel <elf>` uses. No firmware or GRUB runs; the CPU enters 32-bit protected
//!   mode at the 32-bit physical entry named by the note, with `%ebx` pointing at the
//!   Xen `hvm_start_info` structure (memory map included). This is what
//!   `tools/qemu_check.py` drives. QEMU's multiboot ROM cannot be used here because it
//!   only accepts 32-bit ELF images.
//! * **Multiboot 2** (`0xE85250D6`) — used by GRUB for the bootable ISO image.
//!
//! The Multiboot 2 header stays first in `.multiboot_header` so GRUB finds it inside
//! the first 32 KiB of the image.
//!
//! Both hand off in 32-bit protected mode with EAX = magic and EBX = info pointer, so
//! one entry path serves them and `bootinfo::parse` decides which protocol is live.

use core::arch::global_asm;

global_asm!(
    r#"
.section .multiboot_header, "a"
.align 8
/* ---- Multiboot 2 header (GRUB / ISO) ---- */
mb2_start:
    .long 0xE85250D6
    .long 0
    .long mb2_end - mb2_start
    .long -(0xE85250D6 + (mb2_end - mb2_start))

    /* Framebuffer request: 1024x768x32, marked optional so non-VBE loaders still boot. */
    .align 8
    .short 5
    .short 1
    .long 20
    .long 1024
    .long 768
    .long 32

    /* Module alignment. */
    .align 8
    .short 6
    .short 0
    .long 8

    /* End tag. */
    .align 8
    .short 0
    .short 0
    .long 8
mb2_end:

/* ---- PVH direct boot note (QEMU -kernel, no firmware) ----
 * The descriptor is the 32-bit physical entry point, which is where QEMU starts the
 * CPU in 32-bit protected mode with paging off. */
.section .note.Xen, "a", @note
.align 4
    .long 4                     /* namesz: "Xen\0" */
    .long 4                     /* descsz: one 32-bit entry address */
    .long 18                    /* XEN_ELFNOTE_PHYS32_ENTRY */
    .asciz "Xen"
    .align 4
    .long _start
    .align 4

.section .text
.code32
.global _start
_start:
    cli
    mov $stack_top, %esp
    /* Stash the handoff before paging setup clobbers the volatile registers. */
    mov %eax, boot_magic
    mov %ebx, boot_info
    call setup_paging
    lgdt (gdt64_ptr)
    mov %cr0, %eax
    or $0x80000001, %eax
    mov %eax, %cr0
    ljmp $0x08, $long_mode_start

setup_paging:
    /* Zero PML4, PDPT and the four page directories (6 pages). */
    mov $pml4, %edi
    xor %eax, %eax
    mov $(6 * 1024), %ecx
    rep stosl

    /* PML4[0] -> PDPT */
    mov $pdpt, %eax
    or $3, %eax
    mov %eax, pml4

    /* PDPT[i] -> pd_i, so the low 4 GiB is identity mapped. The framebuffer lives
     * around 0xFD000000, well outside a 1 GiB map. */
    mov $pdpt, %edi
    mov $pd0, %eax
    or $3, %eax
    mov $4, %ecx
1:  mov %eax, (%edi)
    add $4096, %eax
    add $8, %edi
    loop 1b

    /* 2048 x 2 MiB pages: 0x00000000 .. 0xFFFFFFFF, present + writable. */
    mov $pd0, %edi
    mov $0x83, %eax
    mov $2048, %ecx
2:  mov %eax, (%edi)
    add $0x200000, %eax
    add $8, %edi
    loop 2b

    mov %cr4, %eax
    or $0x20, %eax          /* CR4.PAE */
    mov %eax, %cr4

    mov $0xC0000080, %ecx   /* EFER.LME */
    rdmsr
    or $0x100, %eax
    wrmsr

    mov $pml4, %eax
    mov %eax, %cr3
    ret

.code64
long_mode_start:
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov %ax, %ss
    mov $stack_top, %esp
    /* kernel_main(magic: u32, info: u32) -> (edi, esi) */
    mov boot_magic(%rip), %edi
    mov boot_info(%rip), %esi
    call kernel_main

.global boot_park
boot_park:
    cli
    hlt
    jmp boot_park

.section .data
.align 16
gdt64:
    .quad 0x0000000000000000
    .quad 0x00AF9A000000FFFF   /* ring 0 code */
    .quad 0x00AF92000000FFFF   /* ring 0 data */
gdt64_ptr:
    .short gdt64_ptr - gdt64 - 1
    .long gdt64
boot_magic:
    .long 0
boot_info:
    .long 0

.section .bss
.align 4096
pml4:  .space 4096
pdpt:  .space 4096
pd0:   .space 4096
pd1:   .space 4096
pd2:   .space 4096
pd3:   .space 4096
.align 16
/* Poison band immediately below the boot stack. `.bss` puts the page tables just above it,
   so an overflow would corrupt a page table and surface as a silent triple fault; the band
   is memset by `kernel_main` and re-checked after the graphics path, which is what makes an
   oversized frame a diagnosable failure instead of a hang. */
.global __stack_guard_bottom
__stack_guard_bottom:
.space 0x1000
.global __boot_stack_bottom
__boot_stack_bottom:
/* 256 KiB: the bring-up path (PCI + BGA + display server) runs in a debug build, where
   frames are far larger than in release. `gui::stack_peak()` reports the real high-water
   mark on every boot so the budget stays verifiable. */
.space 0x40000
.global __boot_stack_top
__boot_stack_top:
stack_top:
"#,
    options(att_syntax)
);
