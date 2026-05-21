ENTRY(_start)
OUTPUT_FORMAT(elf64-x86-64)

SECTIONS {
    . = 0x100000;

    .multiboot_header : { KEEP(*(.multiboot_header)) }
    .text : {
        __text_start = .;
        *(.text .text.*)
        __text_end = .;
    }
    .rodata : ALIGN(4096) { *(.rodata .rodata.*) }
    .data   : ALIGN(4096) { *(.data .data.*) }
    .bss    : ALIGN(4096) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }
}