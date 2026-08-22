/* AP Trampoline: 16-bit real mode -> 32-bit protected -> 64-bit long mode
 * Runs at physical 0x7000 (SIPI vector 0x07).
 * Built as flat binary: as --64 -o ap_trampoline.o ap_trampoline.S
 * objcopy -O binary -j .ap_trampoline ap_trampoline.o ap_trampoline_raw.bin
 * build.rs copies raw binary to 4KB page, then overlays GDT/GDTR at fixed offsets
 * Layout (final 4KB page at 0x7000):
 *   0x000-0x0FF: trampoline code (objcopy output)
 *   0x100-0x127: GDT (5 descriptors × 8 = 40 bytes)
 *   0x1F8: ap_entry_ptr (8 bytes, patched at runtime)
 *   0x200: ap_pml4_phys (8 bytes, patched at runtime)
 *   0x300: GDTR pseudo-descriptor (6 bytes)
 */

.section .ap_trampoline,"ax",@progbits
.global ap_trampoline_start
ap_trampoline_start:
/* ===== 16-bit real mode ===== */
.code16
    /* Early debug: write 'R' to serial 0x3F8 */
    movb $0x52, %al
    movw $0x3F8, %dx
    outb %al, %dx
    /* Also QEMU debug port 0xE9 */
    movb $0x52, %al
    outb %al, $0xE9
    
    cli
    xorw %ax, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss
    movl $0x8000, %esp

    /* Debug '0' - after setup */
    movb $0x30, %al
    outb %al, $0xE9
    
    /* Load 32-bit GDT via GDTR pseudo-descriptor at physical 0x7300 (GDTR base now 0x7400) */
    movl $0x7300, %eax
    lgdtl (%eax)

    /* Debug '1' - after lgdt */
    movb $0x31, %al
    outb %al, $0xE9
    
    /* Enable Protected Mode */
    movl $1, %eax
    movl %eax, %cr0

    /* Marker 'A' - PE set, before jump */
    movb $0x41, %al
    outb %al, $0xE9

    /* Far jump to 32-bit code segment - 32-bit far jmp (Linux style) */
    .code16
    ljmpl $0x08, $0x704C

    /* Fallthrough marker 'F' - should never execute if jump works */
    movb $0x46, %al
    outb %al, $0xE9

    /* Infinite loop if fallthrough */
    jmp .

/* prot32_entry at offset 0x49 (physical 0x7049) - naturally falls here */
.code32
prot32_entry:
    /* Debug 'Z' - reached 32-bit entry */
    movb $0x5A, %al
    outb %al, $0xE9
    movw $0x3F8, %dx
    outb %al, %dx
    /* Debug 'P' */
    movb $0x50, %al
    movw $0x3F8, %dx
    outb %al, %dx
    movb $0x50, %al
    outb %al, $0xE9
    
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss
    movl $0x8000, %esp

    /* Debug '3' - in 32-bit mode */
    movb $0x33, %al
    outb %al, $0xE9

    /* Enable PAE */
    movl %cr4, %eax
    orl $(1<<5), %eax
    movl %eax, %cr4

    /* Debug '4' - after PAE */
    movb $0x34, %al
    outb %al, $0xE9

    /* Load PML4 from physical 0x7200 (offset 0x200 from trampoline start) */
    movl $0x7200, %eax
    movl (%eax), %eax
    movl %eax, %cr3

    /* Debug 'M' */
    movb $0x4D, %al
    movw $0x3F8, %dx
    outb %al, %dx

    /* Enable Long Mode */
    movl $0xC0000080, %ecx
    rdmsr
    orl $(1<<8), %eax
    wrmsr

    /* Debug '5' - after long mode enable */
    movb $0x35, %al
    outb %al, $0xE9

    /* Enable Paging */
    movl %cr0, %eax
    orl $(1<<31), %eax
    movl %eax, %cr0

    /* Debug '6' - after paging */
    movb $0x36, %al
    outb %al, $0xE9

    /* Far jump to 64-bit code segment - 32-bit far jmp (like Linux) */
    .code32
    ljmpl $0x18, $0x70CE

.code64
long_mode_entry:
    /* Set up AP bootstrap stack: mapped at 0xFFFF800000008000 (4 pages, top at 0xC000) */
    movabsq $0xFFFF80000000C000, %rsp
    
    /* Debug 'L' */
    movb $0x4C, %al
    movw $0x3F8, %dx
    outb %al, %dx
    movb $0x4C, %al
    outb %al, $0xE9
    
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss

    /* Debug '7' - 64-bit segments loaded */
    movb $0x37, %al
    outb %al, $0xE9

    /* Enable LAPIC (use kernel virtual mapping at 0xFFFF_8000_FEE0_0000) */
    movabsq $0xFFFF8000FEE000F0, %rax
    movl (%rax), %eax
    orl $(1<<11), %eax
    movl %eax, (%rax)

    /* Debug 'A' */
    movb $0x41, %al
    movw $0x3F8, %dx
    outb %al, %dx
    movb $0x41, %al
    outb %al, $0xE9

    /* Get APIC ID */
    movabsq $0xFFFF8000FEE00020, %rax
    movl (%rax), %eax
    shrl $24, %eax
    movl %eax, %edi

    /* Debug '8' - got APIC ID */
    movb $0x38, %al
    outb %al, $0xE9

    /* Debug 'E' */
    movb $0x45, %al
    movw $0x3F8, %dx
    outb %al, %dx
    movb $0x45, %al
    outb %al, $0xE9

    /* Call ap_entry via address at physical 0x71F8 (offset 0x1F8 from trampoline start) */
    movq 0x71F8, %rax

    /* Debug '9' - about to call ap_entry */
    movb $0x39, %al
    outb %al, $0xE9

    call *%rax

    cli
1:  hlt
    jmp 1b

_end: