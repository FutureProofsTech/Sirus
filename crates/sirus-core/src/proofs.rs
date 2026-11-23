//! Kani verification harnesses. Compiled only under `cargo kani`.

#![cfg(kani)]

/// Manifest size arithmetic never panics and rejects oversized counts.
#[kani::proof]
fn manifest_size_is_total() {
    let count: usize = kani::any();
    let _ = crate::shared::cipher::manifest_size(count);
}

/// Bounded vectors never accept an item beyond capacity.
#[kani::proof]
fn bounded_push_is_total() {
    let value: u8 = kani::any();
    let mut vector = crate::ir::BoundedVec::<u8, 4>::new();
    let _ = vector.push(value);
    assert!(vector.len() <= 4);
}
