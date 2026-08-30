use std::env;
use std::fs;
use std::fmt::Write;
use std::process::Command;

fn main() {
    let dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-arg=-T{}/linker.ld", dir);
    
    let out_dir = env::var("OUT_DIR").unwrap();
    let trampoline_obj = format!("{}/ap_trampoline.o", out_dir);
    let trampoline_bin = format!("{}/ap_trampoline.bin", out_dir);
    let trampoline_rs = format!("{}/ap_trampoline.rs", out_dir);
    
    // Assemble
    let status = Command::new("as")
        .args(["--64", "asm/ap_trampoline.S", "-o", &trampoline_obj])
        .status()
        .expect("failed to assemble ap_trampoline.S");
    eprintln!("as status={:?}", status);
    
    // Extract .ap_trampoline section as raw binary
    let raw_bin = format!("{}/ap_trampoline_raw.bin", out_dir);
    let status = Command::new("objcopy")
        .args([
            "-O", "binary",
            "-j", ".ap_trampoline",
            &trampoline_obj,
            &raw_bin,
        ])
        .status()
        .expect("failed to objcopy trampoline to binary");
    eprintln!("objcopy status={:?}", status);
    
    let raw_data = fs::read(&raw_bin).expect("failed to read trampoline binary");
    eprintln!("raw trampoline size: {}", raw_data.len());
    
    // Build 4KB page with fixed layout:
    // 0x000-0x0FF: trampoline code (first 256 bytes of .ap_trampoline section)
    // 0x100-0x127: GDT (5 descriptors × 8 = 40 bytes)
    // 0x1F8: ap_entry_ptr (8 bytes, patched at runtime)
    // 0x200: ap_pml4_phys (8 bytes, patched at runtime)
    // 0x300: GDTR pseudo-descriptor (6 bytes)
    // Rest zeroed to 4KB
    
    let mut page = vec![0u8; 4096];
    
    // Copy trampoline code at offset 0 (full section)
    let code_len = raw_data.len();
    page[..code_len].copy_from_slice(&raw_data);
    
    // GDT at offset 0x400 (1KB) - after the code
    let gdt_offset = 0x400;
    let gdt = [
        0x0000000000000000u64,     // NULL
        0x00CF9B000000FFFFu64,     // CODE32 (D=1, L=0, accessed)
        0x00CF92000000FFFFu64,     // DATA32
        0x00AF9B000000FFFFu64,     // CODE64 (L=1, long mode, accessed)
        0x00CF92000000FFFFu64,     // DATA64
    ];
    
    for (i, &entry) in gdt.iter().enumerate() {
        let offset = gdt_offset + i * 8;
        page[offset..offset + 8].copy_from_slice(&entry.to_le_bytes());
    }
    
    // ap_entry_ptr at 0x1F8 (patched at runtime)
    // ap_pml4_phys at 0x200 (patched at runtime)
    
    // GDTR pseudo-descriptor at 0x300: limit=0x27, base=0x7000 + gdt_offset
    let gdtr_offset = 0x300;
    let gdt_phys_base = 0x7000 + gdt_offset;
    page[gdtr_offset] = 0x27;
    page[gdtr_offset + 1] = 0x00;
    page[gdtr_offset + 2] = (gdt_phys_base & 0xFF) as u8;
    page[gdtr_offset + 3] = ((gdt_phys_base >> 8) & 0xFF) as u8;
    page[gdtr_offset + 4] = ((gdt_phys_base >> 16) & 0xFF) as u8;
    page[gdtr_offset + 5] = ((gdt_phys_base >> 24) & 0xFF) as u8;
    
    page.truncate(4096);
    eprintln!("final trampoline page size: {}", page.len());
    
    fs::write(&trampoline_bin, &page).expect("failed to write trampoline binary");
    
    // Generate Rust byte array
    let mut rs_content = String::new();
    rs_content.push_str("// Auto-generated from ap_trampoline.bin (4KB page at 0x7000)\n");
    rs_content.push_str("#[allow(dead_code)]\n");
    rs_content.push_str("pub const AP_TRAMPOLINE: &[u8] = &[\n    ");
    for (i, byte) in page.iter().enumerate() {
        write!(&mut rs_content, "0x{:02X}, ", byte).unwrap();
        if (i + 1) % 16 == 0 {
            rs_content.push_str("\n    ");
        }
    }
    rs_content.push_str("\n];\n");
    rs_content.push_str(&format!("pub const AP_TRAMPOLINE_LEN: usize = {};\n", page.len()));
    
    fs::write(&trampoline_rs, &rs_content).expect("failed to write trampoline.rs");
    eprintln!("generated trampoline.rs with {} bytes", page.len());
    println!("cargo:rerun-if-changed=asm/ap_trampoline.S");
}