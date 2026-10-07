SECTIONS
{
    . = 1M;
    __text_start = .;  /* Hier definieren wir den Start-Marker */

    .text :
    {
        KEEP(*(.multiboot_header))
        *(.text .text.*)
    }
    
    __text_end = .;    /* Hier definieren wir den End-Marker */

    .rodata : { *(.rodata .rodata.*) }
    .data :   { *(.data .data.*) }
    .bss :    { *(COMMON) *(.bss .bss.*) }
}