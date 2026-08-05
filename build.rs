fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-arg=-T{d}/linker.ld", d = dir);
    // When building with the host target (via `cargo build`), cc is the linker driver
    // and the global config may set -fuse-ld=mold which doesn't support our linker script.
    // Override with bfd and skip CRT startup files.
    // When building with --target x86_64-unknown-none (via `make`), rust-lld is used
    // directly and doesn't understand these cc-specific flags.
    let target = std::env::var("TARGET").unwrap_or_default();
    if target == "x86_64-unknown-linux-gnu" {
        println!("cargo:rustc-link-arg=-fuse-ld=bfd");
        println!("cargo:rustc-link-arg=-nostartfiles");
    }

    // Export __eh_frame_hdr_start symbol for AT_SYSINFO_EHDR
    println!("cargo:rustc-link-arg=--defsym=__eh_frame_hdr_start=__eh_frame_hdr_start");
    println!("cargo:rustc-link-arg=--defsym=__eh_frame_hdr_end=__eh_frame_hdr_end");

    // Tell cargo to rerun if linker.ld changes
    println!("cargo:rerun-if-changed=linker.ld");
}
