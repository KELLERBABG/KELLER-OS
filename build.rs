fn main() {
    println!("cargo:rerun-if-changed=src/boot.s");
    // boot.o wird manuell in WSL kompiliert und liegt in src/
    println!("cargo:rustc-link-arg=src/boot.o");
}
