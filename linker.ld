ENTRY(_start)

SECTIONS
{
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
