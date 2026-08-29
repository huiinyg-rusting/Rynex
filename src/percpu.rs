use core::sync::atomic::AtomicU64;
use core::mem::MaybeUninit;

pub const MAX_CPUS: usize = 256;

#[repr(C, align(4096))]
pub struct PerCpu {
    pub gdt: [u64; 7],
    pub tss: crate::gdt::TaskStateSegment,
    pub current_task: AtomicU64,
    pub kernel_stack: u64,
    pub apic_id: u32,
    pub _pad: [u8; 4096 - core::mem::size_of::<[u64;7]>() 
                   - core::mem::size_of::<crate::gdt::TaskStateSegment>()
                   - 8 - 8 - 4],
}

static mut PERCPU: [MaybeUninit<PerCpu>; MAX_CPUS] = 
    [const { MaybeUninit::uninit() }; MAX_CPUS];

impl PerCpu {
    pub const fn new() -> Self {
        PerCpu {
            gdt: [0; 7],
            tss: crate::gdt::TaskStateSegment::new(),
            current_task: AtomicU64::new(0),
            kernel_stack: 0,
            apic_id: 0xFF_FF_FF_FF,
            _pad: [0; 4096 - 56 - 104 - 8 - 8 - 4],
        }
    }

    pub fn init(&mut self) {
        *self = PerCpu::new();
    }
}

pub fn percpu(apic_id: u32) -> &'static mut PerCpu {
    let idx = apic_id as usize % MAX_CPUS;
    unsafe {
        let slot = &mut PERCPU[idx];
        // Initialize on first access
        if (*slot.as_ptr()).apic_id == 0xFF_FF_FF_FF {
            slot.write(PerCpu::new());
        }
        &mut *slot.as_mut_ptr()
    }
}

pub fn current_percpu() -> &'static mut PerCpu {
    let id = unsafe { crate::apic::read_reg(0x20) >> 24 };
    percpu(id)
}