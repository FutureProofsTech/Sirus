//! Sirus freestanding virtual machine runtime.
//!
//! The engine source is also embedded verbatim into generated injected
//! runtimes. This crate exposes a testable reference build of the same code.

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
    reason = "the VM dispatcher is a single bounded state machine with fixed on-stack memory"
)]
#![cfg_attr(
    test,
    allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::panic,
        reason = "VM tests use fixed vectors and assertion panics by design"
    )
)]

pub use sirus_core::shared;

pub mod engine;
