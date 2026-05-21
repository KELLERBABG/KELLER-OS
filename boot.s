# boot.s - 32-bit Bootstrap fuer Multiboot2 -> Long Mode
.set STACK_SIZE, 0x10000

.section .multiboot_header, "a"
.align 8
mb2_start:
    .long 0xE85250D6
    .long 0
    .long mb2_end - mb2_start
    .long -(0xE85250D6 + 0 + (mb2_end - mb2_start))
    .short 0
    .short 0
    .long 8
mb2_end:

.section .text
.code32
.global _start
_start:
    cli
    mov $stack_top, %esp
    call setup_paging
    lgdt (gdt64_ptr)
    mov %cr0, %eax
    or $0x80000001, %eax
    mov %eax, %cr0
    ljmp $0x08, $long_mode_start

setup_paging:
    mov $pml4, %edi
    xor %eax, %eax
    mov $3072, %ecx
    rep stosl

    mov $pdpt, %eax
    or $3, %eax
    mov %eax, pml4

    mov $pd, %eax
    or $3, %eax
    mov %eax, pdpt

    mov $pd, %edi
    mov $0x83, %eax
    mov $512, %ecx
1:
    mov %eax, (%edi)
    add $0x200000, %eax
    add $8, %edi
    loop 1b

    mov %cr4, %eax
    or $0x20, %eax
    mov %eax, %cr4

    mov $0xC0000080, %ecx
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
    call kernel_main
halt:
    cli
    hlt
    jmp halt

.section .data
.align 16
gdt64:
    .quad 0x0000000000000000
    .quad 0x00AF9A000000FFFF
    .quad 0x00AF92000000FFFF
gdt64_ptr:
    .short gdt64_ptr - gdt64 - 1
    .long gdt64

.section .bss
.align 4096
pml4:   .space 4096
pdpt:   .space 4096
pd:     .space 4096
.space STACK_SIZE
stack_top: