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
        _kernel_text_start = .;
        *(.text .text.*)
        _kernel_text_end = .;
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
    _kernel_data_end = .;

    /* Kernel BSS is placed HIGH (128M), far above any user ELF image
       (M1 images top out at ~0x64B9C8 for fastfetch; runit/init helpers are
       small). User pml4s map the ELF image at 0x400000-0x650000 as USER
       pages, which would ALIAS low kernel statics when that task is current
       (BADPML4E class: RUNQUEUE/PAGING_LOCK/SYS_PF_COUNT etc. live in .bss
       and were being read/written through the image -> boot hang). The
       identity map (0-1GB, non-USER, copied into every pml4) covers 128M so
       kernel-dynamic state stays reachable from any CR3. */
    . = 0x8000000;
    _kernel_bss_start = .;
    .bss : ALIGN(4K) {
        *(COMMON)
        *(.bss .bss.*)
        . = ALIGN(4K);
        stack_bottom = .;
        . += 32K;
        stack_top = .;
    }
    _kernel_bss_end = ALIGN(4K);
    _kernel_end = _kernel_bss_end;
}

PHDRS
{
    kernel PT_LOAD FLAGS(5) AT(1M);  /* R E - covers .multiboot2 + .text.entry + .text */
    rodata PT_LOAD FLAGS(4); /* R */
    data PT_LOAD FLAGS(6);   /* R W */
    bss PT_LOAD FLAGS(6);    /* R W */
}