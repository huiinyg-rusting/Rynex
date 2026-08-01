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
    cli                       // No timer preemption inside a syscall: the
                              // kernel->kernel preempt resume for user tasks
                              // caught mid-syscall on the shared syscall_stack
                              // is unreliable and can resume with a corrupted
                              // stack pointer, jumping into data pages.
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

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    
    mov rsp, r10
    add rsp, 24
    // Keep IF=0 through sysretq: at this point RSP is a *user* address, so a
    // timer interrupt here would push its save area onto the user stack and
    // never restore that memory, corrupting the user's stack frame. sysretq
    // resumes user mode with IF from R11 (the user's saved RFLAGS), which
    // re-enables interrupts on the per-task kernel_stack (TSS rsp0) instead.
    swapgs

    sysretq

syscall_return:
    iretq