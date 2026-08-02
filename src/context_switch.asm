.global context_switch
.global syscall_entry
.global syscall_return
.global debug_print_hex

.extern SYSCALL_USER_RIP
.extern SYSCALL_USER_RSP
.extern SYSCALL_USER_RFLAGS
.extern SYSCALL_USER_FS_BASE

.section .bss
.align 16
syscall_stack:
    .space 131072        # 128 KB (was 16 KB; syscall_handler zeroes ~96 KB)
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

    // Capture the exact user-mode resume context for fork():
    // return RIP=rcx, return RFLAGS=r11, post-syscall RSP=r10+24, TLS FS base.
    // Runs AFTER rcx/r11 are pushed so we may clobber them freely; rdx is a
    // caller-saved scratch (overwritten later by arg setup), rbp/r12 were
    // pushed above and get popped back, and rax (syscall_num) is preserved.
    lea rdx, [rip + SYSCALL_USER_RIP]
    mov [rdx], rcx
    lea rdx, [rip + SYSCALL_USER_RSP]
    lea rbp, [r10 + 24]
    mov [rdx], rbp
    lea rdx, [rip + SYSCALL_USER_RFLAGS]
    mov [rdx], r11
    mov r12, rax            // save syscall_num
    mov ecx, 0xC0000100
    rdmsr
    shl rdx, 32
    or rax, rdx
    lea rdx, [rip + SYSCALL_USER_FS_BASE]
    mov [rdx], rax
    mov rax, r12            // restore syscall_num

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