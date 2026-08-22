ENTRY(_start)

SECTIONS
{
    /* Main kernel at 1M */
    . = 1M;
    _kernel_start = .;

    .multiboot2 : ALIGN(8) {
        KEEP(*(.multiboot2))
    }

    .text.entry : ALIGN(4K) {
        *(.text.entry)
    }

    .text : ALIGN(4K) {
        *(.text .text.*)
    }

    .rodata : ALIGN(4K) {
        *(.rodata .rodata.*)
    }

    .eh_frame_hdr : ALIGN(4K) {
        __eh_frame_hdr_start = .;
        *(.eh_frame_hdr)
        __eh_frame_hdr_end = .;
    }

    .data : ALIGN(4K) {
        *(.data .data.*)
        *(.got .got.*)
        *(.got.plt)
    }

    .bss : ALIGN(4K) {
        *(COMMON)
        *(.bss .bss.*)
        . = ALIGN(4K);
        stack_bottom = .;
        . += 32K;
        stack_top = .;
    }

    _kernel_end = ALIGN(4K);
}

PHDRS
{
    kernel PT_LOAD FLAGS(5) AT(1M);  /* R E - covers .multiboot2 + .text.entry + .text */
    rodata PT_LOAD FLAGS(4); /* R */
    data PT_LOAD FLAGS(6);   /* R W */
    bss PT_LOAD FLAGS(6);    /* R W */
}