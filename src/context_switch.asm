.global context_switch
.global syscall_entry
.global syscall_return

.section .bss
.align 16
syscall_stack:
    .space 16384
syscall_stack_top:

.text

syscall_entry:
    // On entry:
    //   RAX = syscall number
    //   RDI = arg1, RSI = arg2, RDX = arg3
    //   R10 = arg4, R8  = arg5, R9  = arg6
    //   RCX = user RIP, R11 = user RFLAGS (clobbered by SYSCALL)
    // 
    // We must preserve arg4 (R10) before clobbering it with user RSP.
    // Save volatile args onto user stack, then switch to kernel stack.
    
    swapgs
    push r10              // Save arg4 (R10) on user stack
    push r8               // Save arg5 (R8) on user stack
    push r9               // Save arg6 (R9) on user stack
    mov r10, rsp          // r10 = user RSP (pointing to 3 saved args)
    lea rsp, [rip + syscall_stack_top]
    
    // Save callee-saved registers and RCX/R11
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    push rcx              // Save return RIP
    push r11              // Save return RFLAGS
    
    // Load arg4, arg5, arg6 from user stack (at r10)
    mov r11, [r10 + 16]   // r11 = arg4
    mov r8,  [r10 + 8]    // r8  = arg5
    mov r9,  [r10]        // r9  = arg6
    
    // Set up C ABI call: syscall_handler(num, arg1..arg6)
    // Need: rdi=num, rsi=arg1, rdx=arg2, rcx=arg3, r8=arg4, r9=arg5, [rsp]=arg6
    // Have: rdi=arg1, rsi=arg2, rdx=arg3, r11=arg4, r8=arg5, r9=arg6
    push r9               // arg6 -> stack (7th C arg)
    
    mov rcx, rdx          // rcx = arg3
    mov rdx, rsi          // rdx = arg2
    mov rsi, rdi          // rsi = arg1
    mov rdi, rax          // rdi = syscall_num
    mov r9, r8            // r9  = arg5
    mov r8, r11           // r8  = arg4
    
    call syscall_handler
    
    // Remove arg6 from stack
    add rsp, 8
    
    // Restore registers
    pop r11               // Restore RFLAGS
    pop rcx               // Restore RIP
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    
    // Restore user RSP (skip past the 3 pushed args on user stack)
    mov rsp, r10
    add rsp, 24
    swapgs
    
    sysretq

syscall_return:
    iretq