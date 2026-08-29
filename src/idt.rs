#![allow(static_mut_refs)]
use x86_64::structures::idt::InterruptDescriptorTable;
use crate::interrupts;
use crate::task;

static mut IDT: InterruptDescriptorTable = InterruptDescriptorTable::new();

pub fn init() {
    let idt = unsafe { &mut IDT };

    idt.divide_error.set_handler_fn(interrupts::divide_error);
    idt.debug.set_handler_fn(interrupts::debug);
    idt.non_maskable_interrupt.set_handler_fn(interrupts::nmi);
    idt.breakpoint.set_handler_fn(interrupts::breakpoint);
    idt.overflow.set_handler_fn(interrupts::overflow);
    idt.bound_range_exceeded.set_handler_fn(interrupts::bound_range);
    idt.invalid_opcode.set_handler_fn(interrupts::invalid_opcode);
    idt.device_not_available.set_handler_fn(interrupts::device_not_available);

    unsafe {
        idt.double_fault
            .set_handler_fn(interrupts::double_fault)
            .set_stack_index(1); // IST 1 (TSS.ist[0]) for Double Fault

        idt[task::TIMER_IRQ_VECTOR]
            .set_handler_addr(x86_64::VirtAddr::new(task::timer_interrupt_handler as u64));
            // No IST: the timer runs on the current task's kernel stack.
            // Without IST the CPU preserves RSP for same-CPL interrupts,
            // so the zero path correctly restores the original RSP.

        // Test: use real PF handler with DF's IST stack (index 1)
        idt.page_fault
            .set_handler_fn(interrupts::page_fault_real)
            .set_stack_index(1); // DF's IST stack (temporarily)
    }

    idt.invalid_tss.set_handler_fn(interrupts::invalid_tss);
    idt.segment_not_present.set_handler_fn(interrupts::segment_not_present);
    idt.stack_segment_fault.set_handler_fn(interrupts::stack_fault);
    idt.general_protection_fault.set_handler_fn(interrupts::general_protection);
    idt.x87_floating_point.set_handler_fn(interrupts::x87_fp);
    idt.alignment_check.set_handler_fn(interrupts::alignment_check);
    idt.machine_check.set_handler_fn(interrupts::machine_check);
    idt.simd_floating_point.set_handler_fn(interrupts::simd_fp);
    idt.virtualization.set_handler_fn(interrupts::virtualization);

    idt.load();
}

/// Reload the (shared) IDT into the current CPU's IDTR. The BSP loads it once in
/// init(); each AP must load it into its own per-CPU IDTR before enabling
/// interrupts, since IDTR is a per-CPU register.
pub unsafe fn load_current() {
    (unsafe { &IDT }).load();
}

pub fn register_irq(vector: u8, handler_addr: u64) {
    unsafe {
        IDT[vector].set_handler_addr(x86_64::VirtAddr::new(handler_addr));
    }
}
