//! Sirus compiler core.
//!
//! This crate is `no_std`, allocation-free and contains no `unsafe`. It owns the
//! shared cryptographic primitives, the virtual ISA contract, the deterministic
//! per-build table derivation, payload ciphers, the x86-64 lifter, the IR, the
//! MBA engine, control-flow flattening, and payload encoding.
//!
//! The build-time protector is the only component allowed to use `std`; it is a
//! separate crate so the runtime and compiler core can be audited in isolation.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    clippy::alloc_instead_of_core,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unreachable,
    clippy::as_conversions,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::float_arithmetic,
    clippy::missing_inline_in_public_items,
    clippy::exhaustive_structs
)]
#![allow(
    clippy::too_many_lines,
    clippy::large_stack_arrays,
    clippy::large_stack_frames,
    clippy::redundant_pub_crate,
    reason = "bounded no-allocation state machines and intentionally private helper modules"
)]
#![cfg_attr(
    test,
    allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::panic,
        reason = "test assertions and fixed-size test vectors intentionally panic on failure"
    )
)]

#[cfg(test)]
extern crate std;

pub mod decode;
pub(crate) mod encode;
pub mod error;
pub mod ir;
pub mod lifter;
pub(crate) mod mba;
pub mod program;
pub(crate) mod proofs;
pub mod shared;
