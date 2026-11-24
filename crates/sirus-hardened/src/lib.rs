//! Optional hardened runtime checks for Sirus.
//!
//! The safe tier does not depend on this crate. `--hardened` generated VMs
//! include `runtime` and allow unsafe code; `host` is used only by the
//! protector CLI for debug-register inspection.

#![no_std]
#![allow(unsafe_code)]

pub mod runtime;

#[cfg(feature = "host")]
pub mod host;

pub use runtime::{debugger_present, hypervisor_present, lfence, rdtsc, timing_ok};
