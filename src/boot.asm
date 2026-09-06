.intel_syntax noprefix

/* Multiboot2 header */
.set MAGIC, 0xE85250D6
.set ARCH, 0
.set HDR_LEN, header_end - multiboot_header

.section .multiboot2, "a"
.balign 8
multiboot_header:
    .long MAGIC
    .long ARCH
    .long HDR_LEN
    .long -(MAGIC + ARCH + HDR_LEN)
    /* Framebuffer tag (type 5): request a 1024x768x32 direct-colour display.
       GRUB reads this and honours the gfxpayload path on BIOS (otherwise it
       forces "text" and hands over only an EGA text tag). width/height/depth
       being non-zero makes GRUB set gfxpayload="1024x768x32,1024x768,auto". */
    .balign 8
    .word 5
    .word 0
    .long 20
    .long 1024
    .long 768
    .long 32
    /* End tag (type 0, size 8) */
    .balign 8
    .word 0
    .word 0
    .long 8
header_end:

/* 32-bit GDT for transition */
.section .text.entry, "ax"
.balign 8
gdt:
    .quad 0x0000000000000000   /* 0x00: null */
    .quad 0x00CF9A000000FFFF   /* 0x08: 32-bit code, ring 0 */
    .quad 0x00CF92000000FFFF   /* 0x10: data, ring 0 */
    .quad 0x00209A0000000000   /* 0x18: 64-bit code, ring 0 */
    .quad 0x0000920000000000   /* 0x20: 64-bit data, ring 0 */
gdt_end:

/* Page tables */
.balign 4096
pml4:
    .space 4096
pdpt:
    .space 4096
pd:
    .space 4096

/* Entry point */
.code32
.globl _start
_start:
    /* Save multiboot info: eax=magic, ebx=info */
    mov esi, eax
    mov edx, ebx
    cli

    /* Load our GDT */
    sub esp, 6
    mov word ptr [esp], 39
    lea eax, gdt
    mov dword ptr [esp + 2], eax
    lgdt [esp]
    add esp, 6

    /* Reload CS (32-bit) */
    push 0x08
    lea eax, .L32
    push eax
    retf

.L32:
    /* Set data segments */
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax

    /* Set up stack */
    lea esp, stack_top

    /* Initialize page tables */
    /* PML4[0] = pdpt | 3 */
    lea eax, pdpt
    or eax, 3
    mov dword ptr [pml4], eax

    /* PDPT[0] = pd | 3 */
    lea eax, pd
    or eax, 3
    mov dword ptr [pdpt], eax

    /* Fill PD: 512 entries, 2MB huge pages, identity map 0-1GB */
    lea edi, pd
    xor ecx, ecx
    xor ebx, ebx
.Lpd_fill:
    mov eax, ebx
    or eax, 0x83
    mov [edi + ecx*8], eax
    add ebx, 0x200000
    inc ecx
    cmp ecx, 512
    jne .Lpd_fill

    /* Load PML4 -> CR3 */
    lea eax, pml4
    mov cr3, eax

    /* Enable PAE */
    mov eax, cr4
    or eax, 0x20
    mov cr4, eax

    /* Enable long mode (IA32_EFER.LME) */
    mov ecx, 0xC0000080
    push edx
    rdmsr
    or eax, 0x100
    wrmsr
    pop edx

    /* Enable paging (PG) + protected mode (PE) */
    mov eax, cr0
    or eax, 0x80000001
    mov cr0, eax

    /* Far jump to 64-bit code */
    push 0x18
    lea eax, .L64
    push eax
    retf

/* 64-bit code */
.code64
.L64:
    /* Set segment registers */
    mov ax, 0x20
    mov ds, ax
    mov es, ax
    mov ss, ax
    xor ax, ax
    mov fs, ax
    mov gs, ax

    /* Call kernel_main(magic, info) */
    /* rsi=magic, rdx=info (zero-extended from esi,edx) */
    /* SysV: rdi=arg1, rsi=arg2 */
    mov rax, rsi
    mov rsi, rdx
    mov rdi, rax
    call kernel_main

    /* Should never reach here */
    cli
    hlt
.Lhalt:
    jmp .Lhalt
