use core::sync::atomic::Ordering;
use alloc::vec::Vec;
use crate::task::{alloc_stack, KERNEL_STACK_PAGES};
use crate::paging::{KERNEL_BASE, KERNEL_PML4};

// Auto-generated trampoline binary (4KB page at physical 0x7000)
include!(concat!(env!("OUT_DIR"), "/ap_trampoline.rs"));

pub unsafe fn detect_cpus() -> Vec<u32> {
    let mut cpus = Vec::new();
    
    // For testing with QEMU -smp 2, the second CPU typically has APIC ID 1
    // In a real implementation, we'd parse CPUID leaf 0xB or ACPI MADT
    let bsp_id = crate::apic::bsp_apic_id();
    crate::serial::write_str("SMP: BSP APIC ID = 0x");
    crate::serial::write_hex(bsp_id as u64);
    crate::serial::write_str("\n");
    cpus.push(bsp_id);
    
    // Hardcode second CPU for QEMU -smp 2 testing
    let ap_id = if bsp_id == 0 { 1 } else { 0 };
    crate::serial::write_str("SMP: Will start AP with APIC ID = 0x");
    crate::serial::write_hex(ap_id as u64);
    crate::serial::write_str("\n");
    cpus.push(ap_id);
    
    cpus
}

pub unsafe fn init_aps(ap_entry_fn: u64) {
    let cpus = detect_cpus();
    let bsp_id = crate::apic::bsp_apic_id();
    
use crate::task::{alloc_stack, KERNEL_STACK_PAGES};
use crate::paging::KERNEL_BASE;
    
    // Fixed trampoline at physical 0x7000 (SIPI vector 0x07 = 0x7000 / 4096)
    const TRAMPOLINE_PHYS: u64 = 0x7000;
    const TRAMPOLINE_VIRT: u64 = KERNEL_BASE + TRAMPOLINE_PHYS;
    let sipi_vector = 0x07u32;
    
    // Copy trampoline byte array to physical 0x7000 (via identity map at KERNEL_BASE + 0x7000)
    let trampoline_dst = TRAMPOLINE_VIRT as *mut u8;
    for i in 0..AP_TRAMPOLINE_LEN {
        unsafe { core::ptr::write_volatile(trampoline_dst.add(i), AP_TRAMPOLINE[i]); }
    }
    
    // Verify trampoline at physical 0x7000
    let first_byte = unsafe { core::ptr::read_volatile(TRAMPOLINE_VIRT as *const u8) };
    crate::serial::write_str("SMP: verify trampoline at 0x7000, byte0=0x");
    crate::serial::write_hex(first_byte as u64);
    crate::serial::write_str(" (expected 0xB0)\n");
    
// Patch ap_entry address at physical 0x71F8 (via direct map)
    let entry_ptr = (KERNEL_BASE + TRAMPOLINE_PHYS + 0x1F8) as *mut u64;
    core::ptr::write_volatile(entry_ptr, ap_entry_fn);
    
    // Write kernel PML4 to trampoline's ap_pml4_phys (at physical 0x7200)
    let kernel_pml4 = KERNEL_PML4.load(Ordering::SeqCst);
    let pml4_ptr = (KERNEL_BASE + TRAMPOLINE_PHYS + 0x200) as *mut u64;
    core::ptr::write_volatile(pml4_ptr, kernel_pml4);
    
    crate::serial::write_str("SMP: trampoline at 0x7000 SIPI vector=0x07 ap_entry=0x");
    crate::serial::write_hex(ap_entry_fn);
    crate::serial::write_str("\n");
    
    for &apic_id in &cpus {
        if apic_id == bsp_id { continue; }
        
        crate::serial::write_str("SMP: starting AP ");
        crate::serial::write_hex(apic_id as u64);
        crate::serial::write_str("\n");
        
        // INIT-SIPI-SIPI sequence
        // INIT assert (edge/level - keep simple, trigger=0)
        crate::apic::send_ipi(apic_id, 0x500, 0, 1, 0); // INIT assert
        crate::pit::wait_ms(10);
        
        // INIT deassert
        crate::apic::send_ipi(apic_id, 0x500, 0, 0, 0); // INIT deassert
        crate::pit::wait_ms(1);
        
        // SIPI #1 (asserted, edge)
        crate::apic::send_ipi(apic_id, 0x600, sipi_vector, 1, 0); // SIPI assert
        crate::pit::wait_us(200);
        
        // SIPI #2
        crate::apic::send_ipi(apic_id, 0x600, sipi_vector, 1, 0); // SIPI assert
        crate::pit::wait_ms(2);
    }
    
    crate::serial::write_str("SMP: all APs started\n");
}

#[inline(never)]
unsafe fn e9(c: u8) {
    core::arch::asm!(
        "out dx, al",
        in("dx") 0xE9u16,
        in("al") c,
        options(nostack, preserves_flags)
    );
}

#[no_mangle]
pub extern "C" fn ap_entry(apic_id: u32) -> ! {
    unsafe { e9(b'a'); }
    // Early debug - write directly to serial port
    unsafe {
        core::arch::asm!(
            "mov dx, 0x3F8",
            "mov al, 'A'",
            "out dx, al",
            "mov al, 'P'",
            "out dx, al",
            "mov al, ' '",
            "out dx, al",
            in("eax") apic_id,
            options(nostack, preserves_flags)
        );
    }
    
    // 1. Set up per-CPU GDT/TSS/IST stacks
    let pc = crate::percpu::percpu(apic_id);
    pc.apic_id = apic_id;
    unsafe { e9(b'b'); }
    
    // Allocate kernel stack + 4 IST stacks
    let kernel_stack_phys = crate::task::alloc_stack(crate::task::KERNEL_STACK_PAGES)
        .expect("AP kernel stack alloc failed");
    let kernel_stack = KERNEL_BASE + kernel_stack_phys;
    pc.kernel_stack = kernel_stack;
    
    let ist_df_phys = crate::task::alloc_stack(1).expect("AP DF stack");
    let ist_timer_phys = crate::task::alloc_stack(1).expect("AP timer stack");
    let ist_syscall_phys = crate::task::alloc_stack(1).expect("AP syscall stack");
    let ist_pf_phys = crate::task::alloc_stack(1).expect("AP PF stack");
    
    let ist_stacks = [
        KERNEL_BASE + ist_df_phys + 4096,
        KERNEL_BASE + ist_timer_phys + 4096,
        KERNEL_BASE + ist_syscall_phys + 4096,
        KERNEL_BASE + ist_pf_phys + 4096,
    ];
    
    pc.tss.rsp[0] = kernel_stack;
    
    // Setup per-CPU GDT
    crate::gdt::setup_percpu_gdt(&mut pc.gdt, &mut pc.tss, ist_stacks);
    crate::gdt::load_percpu_gdt(&pc.gdt);
    unsafe { e9(b'c'); }
    
    // 2. Initialize LAPIC timer
    unsafe { crate::apic::init_timer(); }
    unsafe { e9(b'd'); }
    
    // 3. Enable interrupts
    unsafe { core::arch::asm!("sti", options(nostack)); }
    unsafe { e9(b'e'); }
    
    // 4. Mark this CPU online
    crate::task::mark_cpu_online(apic_id);
    unsafe { e9(b'f'); }
    
    crate::serial::write_str("AP ");
    crate::serial::write_hex(apic_id as u64);
    crate::serial::write_str(" online\n");
    unsafe { e9(b'o'); }
    
    // 5. Enter idle loop
    loop {
        crate::task::yield_now_force();
    }
}