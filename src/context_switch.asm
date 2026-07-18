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
    swapgs
    mov r10, rsp
    mov rsp, syscall_stack_top
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov rax, 0x2B
    push rax
    mov rax, r10
    push rax
    pushfq
    pushfq
    mov rax, 0x23
    push rax
    mov rax, 0x400000
    push rax
    mov rdi, rsp
    call syscall_handler
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    swapgs
    iretq

syscall_return:
    iretq
