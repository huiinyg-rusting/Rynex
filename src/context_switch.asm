.global context_switch
.global syscall_entry
.global syscall_return
.global debug_print_hex

.extern SYSCALL_USER_RIP
.extern SYSCALL_USER_RSP
.extern SYSCALL_USER_RFLAGS
.extern SYSCALL_USER_FS_BASE
.extern CURRENT_SYSCALL_STACK_TOP
.extern SYSCALL_CALLEE_REGS

.text

syscall_entry:
    swapgs
    cli                       // No timer preemption inside a syscall: the
                              // kernel->kernel preempt resume for user tasks
                              // caught mid-syscall is unreliable and can
                              // resume with a corrupted stack pointer.
    push r10              // Save arg4 (R10) on user stack
    push r8               // Save arg5 (R8) on user stack
    push r9               // Save arg6 (R9) on user stack
    mov r10, rsp          // r10 = user RSP (pointing to 3 saved args)
    mov rsp, [rip + CURRENT_SYSCALL_STACK_TOP]   // per-task kernel stack
    
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    push rcx              // Save return RIP
    push r11              // Save return RFLAGS
    push rdx              // Save arg3 (rdx is clobbered by the fork-context
                          // capture below: it is used as scratch and by rdmsr)
    push rdi              // Save arg1 (Linux preserves all user regs across
                          // a syscall except rax/rcx/r11; musl wrappers rely
                          // on rdi/rsi/rdx/r8/r9 surviving, e.g. sched_getaffinity)
    push rsi              // Save arg2
    push r8               // Save arg5
    push r9               // Save arg6

    // Save callee-saved regs for fork() (rbx,rbp,r12-r15). syscall_entry runs
    // in user context so TASKS[].regs is stale; the child must resume with the
    // parent's live callee-saved registers.
    lea rdx, [rip + SYSCALL_CALLEE_REGS]
    mov [rdx + 0x00], rbx
    mov [rdx + 0x08], rbp
    mov [rdx + 0x10], r12
    mov [rdx + 0x18], r13
    mov [rdx + 0x20], r14
    mov [rdx + 0x28], r15

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

    // Kernel stack (top -> bottom) holds the saved user regs:
    //   [rsp+0]=r9 [rsp+8]=r8 [rsp+16]=rsi [rsp+24]=rdi [rsp+32]=rdx
    //   [rsp+40]=r11 [rsp+48]=rcx [rsp+56..96]=r15..rbx
    // Read the original arg values back to build the handler call, then keep
    // them on the stack so the exit path restores them into the user regs
    // (Linux preserves rdi/rsi/rdx/r8/r9 across a syscall; musl relies on it).
    mov rcx, [rsp + 32]   // rcx = arg3 (original rdx)
    mov rsi, [rsp + 24]   // rsi = arg1 (original rdi)
    mov rdx, [rsp + 16]   // rdx = arg2 (original rsi)
    mov r8,  [r10 + 16]   // r8  = arg4 (original r10, saved on user stack)
    mov r9,  [r10 + 8]    // r9  = arg5 (original r8, saved on user stack)

    // 7th C arg (arg6) must be on top of stack ([rsp]) when `call` executes;
    // callee sees it at [rsp+8]. So push userRSP FIRST, arg6 LAST.
    push r10              // Save user RSP (R10 is scratch in System V ABI)
    push qword ptr [r10]  // arg6 (original r9) -> stack (7th C arg)

    mov rdi, rax          // rdi = syscall_num
    
    call syscall_handler
    
    add rsp, 8            // Remove arg6
    pop r10               // Restore user RSP (preserved across C call)
    
    pop r9                // Restore arg6 (original user r9)
    pop r8                // Restore arg5 (original user r8)
    pop rsi               // Restore arg2 (original user rsi)
    pop rdi               // Restore arg1 (original user rdi)
    pop rdx               // Restore arg3 (original user rdx)
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