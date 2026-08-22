ENTRY(ap_trampoline_start)
SECTIONS
{
    . = 0x7000;
    .trampoline : {
        *(.ap_trampoline)
    }
    . = 0x7100;
    .trampoline_gdt : {
        *(.ap_trampoline_gdt)
    }
    . = 0x71F8;
    .trampoline_entry_ptr : {
        *(.ap_trampoline_entry_ptr)
    }
    . = 0x7200;
    .trampoline_pml4 : {
        *(.ap_trampoline_pml4)
    }
    /DISCARD/ : {
        *(.note.gnu.property)
    }
    . = 0x8000;
}