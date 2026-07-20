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
    // Save registers that we will need to restore
    // We need to preserve RCX and R11 for SYSRET (they hold return RIP and RFLAGS)
    // We also need to preserve callee-saved registers: RBX, RBP, R12-R15
    // We can use RAX, RDX, RSI, RDI, R8-R10 for temporaries
    
    swapgs
    mov r10, rsp          // Save user RSP
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
    
    // Set up arguments for C function
    // SYSCALL convention:
    //   RAX = syscall number
    //   RDI = arg1
    //   RSI = arg2
    //   RDX = arg3
    //   R10 = arg4
    //   R8  = arg5
    //   R9  = arg6
    //
    // System V ABI for function calls:
    //   RDI = arg1
    //   RSI = arg2
    //   RDX = arg3
    //   RCX = arg4
    //   R8  = arg5
    //   R9  = arg6
    //
    // So we need to:
    //   RDI = RAX (syscall number)
    //   RSI = RDI (arg1) - but we just overwrote RDI! Need to save args first
    //   RDX = RSI
    //   RCX = RDX
    //   R8  = R10
    //   R9  = R8
    
    // Save the argument registers
    mov r8, rdi       // arg1
    mov r9, rsi       // arg2
    mov r10, rdx      // arg3
    mov r11, r10      // arg4 (r10 was arg3 from syscall)
    mov r12, r8       // arg5
    mov r13, r9       // arg6
    
    // Now set up arguments for C call
    mov rdi, rax      // arg1 = syscall number
    mov rsi, r8       // arg2 = arg1
    mov rdx, r9       // arg3 = arg2
    mov rcx, r10      // arg4 = arg3
    mov r8,  r11      // arg5 = arg4
    mov r9,  r12      // arg6 = arg5
    
    // Call the C handler
    call syscall_handler
    
    // Return value is in RAX (already correct for syscall convention)
    
    // Restore registers in reverse order
    pop r11             // Restore R11 (return RFLAGS)
    pop rcx             // Restore RCX (return RIP)
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    
    // Restore user RSP and switch back to user GS
    mov rsp, r10
    swapgs
    
    // Return to user mode
    sysretq

syscall_return:
    iretq