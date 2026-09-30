ENTRY(_start)
OUTPUT_FORMAT(elf64-x86-64)

PHDRS
{
    text   PT_LOAD FLAGS(5);   /* R + X */
    rodata PT_LOAD FLAGS(4);   /* R     */
    data   PT_LOAD FLAGS(6);   /* R + W */
    note   PT_NOTE FLAGS(4);
}

SECTIONS {
    . = 0x100000;

    .multiboot_header : { KEEP(*(.multiboot_header)) } :text
    /* QEMU reads the PVH entry note from this PT_NOTE segment. */
    .note.Xen : ALIGN(4) { KEEP(*(.note.Xen)) } :note
    .text : {
        __text_start = .;
        *(.text .text.*)
        __text_end = .;
    } :text

    .rodata : ALIGN(4096) { *(.rodata .rodata.*) } :rodata
    .data   : ALIGN(4096) { *(.data .data.*) } :data
    .bss    : ALIGN(4096) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    } :data
}