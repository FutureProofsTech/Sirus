//! Rebuild the protector when generated-VM source fragments change.
//!
//! `vmgen.rs` embeds these files with `include_str!`, which Cargo does not
//! track as a dependency by default. Without this script a release binary can
//! keep an older VM engine or wire format while the compiler core uses the new
//! one, producing a mismatched generated runtime.

fn main() {
    println!("cargo:rerun-if-changed=../sirus-core/src/shared/sip.rs");
    println!("cargo:rerun-if-changed=../sirus-core/src/shared/format.rs");
    println!("cargo:rerun-if-changed=../sirus-core/src/shared/derive.rs");
    println!("cargo:rerun-if-changed=../sirus-core/src/shared/cipher.rs");
    println!("cargo:rerun-if-changed=../sirus-vm/src/engine.rs");
    println!("cargo:rerun-if-changed=../sirus-hardened/src/runtime.rs");
}
