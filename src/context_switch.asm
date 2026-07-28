.global context_switch
.global syscall_entry
.global syscall_return
.global debug_print_hex

.section .bss
.align 16
syscall_stack:
    .space 16384
syscall_stack_top:

.text

syscall_entry:
    swapgs
    push r10              // Save arg4 (R10) on user stack
    push r8               // Save arg5 (R8) on user stack
    push r9               // Save arg6 (R9) on user stack
    mov r10, rsp          // r10 = user RSP (pointing to 3 saved args)
    lea rsp, [rip + syscall_stack_top]
    
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    push rcx              // Save return RIP
    push r11              // Save return RFLAGS
    
    mov r11, [r10 + 16]   // r11 = arg4
    mov r8,  [r10 + 8]    // r8  = arg5
    mov r9,  [r10]        // r9  = arg6
    
    push r9               // arg6 -> stack (7th C arg)
    push r10              // Save user RSP (R10 is scratch in System V ABI)
    
    mov rcx, rdx          // rcx = arg3
    mov rdx, rsi          // rdx = arg2
    mov rsi, rdi          // rsi = arg1
    mov rdi, rax          // rdi = syscall_num
    mov r9, r8            // r9  = arg5
    mov r8, r11           // r8  = arg4
    
    call syscall_handler
    
    pop r10               // Restore user RSP (preserved across C call)
    add rsp, 8            // Remove arg6
    
    pop r11               // Restore RFLAGS
    pop rcx               // Restore RIP

    // Debug: 'P' + CH high nibble + CH low nibble + CL high nibble + CL low nibble
    push rax
    push rcx
    push rdx
    mov dx, 0x3F8
    mov al, 'P'
    out dx, al
    mov al, ch
    mov ah, al
    shr al, 4
    and ah, 0x0F
    cmp al, 10
    jb 1f
    add al, 'A' - '0' - 10
1:  add al, '0'
    out dx, al
    mov al, ah
    cmp al, 10
    jb 2f
    add al, 'A' - '0' - 10
2:  add al, '0'
    out dx, al
    mov al, cl
    mov ah, al
    shr al, 4
    and ah, 0x0F
    cmp al, 10
    jb 3f
    add al, 'A' - '0' - 10
3:  add al, '0'
    out dx, al
    mov al, ah
    cmp al, 10
    jb 4f
    add al, 'A' - '0' - 10
4:  add al, '0'
    out dx, al
    pop rdx
    pop rcx
    pop rax

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    
    mov rsp, r10
    add rsp, 24
    swapgs

    // Debug: 'R' + CH high nibble + CH low nibble + CL high nibble + CL low nibble
    push rax
    push rcx
    push rdx
    mov dx, 0x3F8
    mov al, 'R'
    out dx, al
    mov al, ch
    mov ah, al
    shr al, 4
    and ah, 0x0F
    cmp al, 10
    jb 5f
    add al, 'A' - '0' - 10
5:  add al, '0'
    out dx, al
    mov al, ah
    cmp al, 10
    jb 6f
    add al, 'A' - '0' - 10
6:  add al, '0'
    out dx, al
    mov al, cl
    mov ah, al
    shr al, 4
    and ah, 0x0F
    cmp al, 10
    jb 7f
    add al, 'A' - '0' - 10
7:  add al, '0'
    out dx, al
    mov al, ah
    cmp al, 10
    jb 8f
    add al, 'A' - '0' - 10
8:  add al, '0'
    out dx, al
    pop rdx
    pop rcx
    pop rax

    sysretq

syscall_return:
    iretq