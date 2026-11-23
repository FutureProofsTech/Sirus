//! Creusot proof models for the boundary checks copied from `sirus-vm`.
//!
//! This crate is intentionally not a workspace member: `creusot-std` is
//! tooling-only and must never enter the zero-dependency shipped workspace.
//! `scripts/creusot-check.sh` runs the proofs.

#![no_std]
#![forbid(unsafe_code)]

use creusot_std::prelude::*;

/// The `start.checked_add(width) <= length` predicate used by the VM's
/// `load_memory` and `store_memory` helpers before any slice access.
#[requires(width@ <= 8)]
#[ensures(result == (start@ + width@ <= length@))]
pub fn end_in_bounds(start: usize, width: usize, length: usize) -> bool {
    match start.checked_add(width) {
        Some(end) => end <= length,
        None => false,
    }
}

/// The exact successful range guarantee of a VM memory access.
#[requires(width@ <= 8)]
#[ensures(match result {
    None => true,
    Some(()) => address@ + width@ <= memory@.len(),
})]
pub fn checked_access(memory: &[u8], address: usize, width: usize) -> Option<()> {
    let end = address.checked_add(width)?;
    if end > memory.len() {
        return None;
    }
    Some(())
}

/// The literal manifest-size computation from `sirus-core`.
#[requires(count@ <= 256)]
#[ensures(match result {
    Some(size) => size@ == count@ * 16 + 8,
    None => false,
})]
pub fn manifest_size(count: usize) -> Option<usize> {
    if count > 256 {
        return None;
    }
    count.checked_mul(16)?.checked_add(8)
}
