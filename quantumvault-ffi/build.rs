extern crate cbindgen;

use std::env;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    
    // We only want to generate bindings if the build target is FFI.
    // Also tells Cargo to rerun if source files change.
    println!("cargo:rerun-if-changed=src/lib.rs");

    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_language(cbindgen::Language::C)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("quantumvault.h");
}
