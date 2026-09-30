fn main() {
    println!("cargo:rerun-if-changed=src/linker.ld");
    // The link flags live here rather than in `[target.*].rustflags`, because cargo
    // ignores `.cargo/config.toml` rustflags whenever the `RUSTFLAGS` environment
    // variable is set (this machine sets it globally).
    println!("cargo:rustc-link-arg=-Tsrc/linker.ld");
    println!("cargo:rustc-link-arg=-no-pie");
    println!("cargo:rustc-link-arg=-static");
    // No assembler is needed: the bootstrap (Multiboot2 header, PVH note, page tables)
    // is emitted by `global_asm!` in src/boot.rs.
}
