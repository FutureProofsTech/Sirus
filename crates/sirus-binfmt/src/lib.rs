//! Binary format support for Sirus.
//!
//! Parsing is performed on borrowed bytes with checked arithmetic. Editing is
//! performed with `alloc` only at build time. No path in this crate uses
//! `unsafe`.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    clippy::std_instead_of_core,
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
    reason = "strict binary parsers are naturally large state machines; bounded allocations are deliberate"
)]
#![cfg_attr(
    test,
    allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::panic,
        reason = "test assertions and fixed binary fixtures intentionally panic on failure"
    )
)]

extern crate alloc;

pub mod elf;
pub mod pe;

/// Result alias for binary format operations.
pub type Result<T> = core::result::Result<T, FormatError>;

/// Errors produced by binary parsing and editing.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormatError {
    /// The input is structurally malformed.
    Malformed,
    /// The format or architecture is unsupported.
    Unsupported,
    /// A range check failed.
    Bounds,
    /// A count exceeds the production safety ceiling.
    TooManyItems,
    /// The requested target was not found.
    NotFound,
    /// The requested target matched more than once.
    Ambiguous,
    /// A new segment overlaps an existing mapping.
    Overlap,
    /// A relative patch is out of range.
    JumpOutOfRange,
    /// The payload range lies outside the VM image.
    PayloadOutsideVm,
    /// A target range lies outside an executable segment.
    RangeOutsideExecutable,
    /// An alignment requirement was violated.
    BadAlignment,
    /// Section metadata is missing or inconsistent.
    SectionTableInvalid,
    /// The target is already protected.
    AlreadyProtected,
    /// The requested action is not supported for this binary.
    UnsupportedAction,
}

impl core::fmt::Display for FormatError {
    #[inline]
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let text = match self {
            Self::Malformed => "malformed binary",
            Self::Unsupported => "unsupported binary format",
            Self::Bounds => "range out of bounds",
            Self::TooManyItems => "too many headers or symbols",
            Self::NotFound => "target not found",
            Self::Ambiguous => "target is ambiguous",
            Self::Overlap => "new mapping overlaps an existing mapping",
            Self::JumpOutOfRange => "relative jump out of range",
            Self::PayloadOutsideVm => "payload lies outside the VM image",
            Self::RangeOutsideExecutable => "range lies outside an executable segment",
            Self::BadAlignment => "misaligned region",
            Self::SectionTableInvalid => "invalid section table",
            Self::AlreadyProtected => "binary is already protected",
            Self::UnsupportedAction => "unsupported action",
        };
        formatter.write_str(text)
    }
}

/// Reads a little-endian `u16` with bounds checking.
#[inline]
pub(crate) fn read_u16(data: &[u8], offset: usize) -> Result<u16> {
    data.get(offset..offset.checked_add(2).ok_or(FormatError::Bounds)?)
        .and_then(|slice| <[u8; 2]>::try_from(slice).ok())
        .map(u16::from_le_bytes)
        .ok_or(FormatError::Bounds)
}

/// Reads a little-endian `u32` with bounds checking.
#[inline]
pub(crate) fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    data.get(offset..offset.checked_add(4).ok_or(FormatError::Bounds)?)
        .and_then(|slice| <[u8; 4]>::try_from(slice).ok())
        .map(u32::from_le_bytes)
        .ok_or(FormatError::Bounds)
}

/// Reads a little-endian `u64` with bounds checking.
#[inline]
pub(crate) fn read_u64(data: &[u8], offset: usize) -> Result<u64> {
    data.get(offset..offset.checked_add(8).ok_or(FormatError::Bounds)?)
        .and_then(|slice| <[u8; 8]>::try_from(slice).ok())
        .map(u64::from_le_bytes)
        .ok_or(FormatError::Bounds)
}

/// Writes a little-endian `u16` with bounds checking.
#[inline]
pub(crate) fn write_u16(data: &mut [u8], offset: usize, value: u16) -> Result<()> {
    let target = data
        .get_mut(offset..offset.checked_add(2).ok_or(FormatError::Bounds)?)
        .ok_or(FormatError::Bounds)?;
    target.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

/// Writes a little-endian `u32` with bounds checking.
#[inline]
pub(crate) fn write_u32(data: &mut [u8], offset: usize, value: u32) -> Result<()> {
    let target = data
        .get_mut(offset..offset.checked_add(4).ok_or(FormatError::Bounds)?)
        .ok_or(FormatError::Bounds)?;
    target.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

/// Writes a little-endian `u64` with bounds checking.
#[inline]
pub(crate) fn write_u64(data: &mut [u8], offset: usize, value: u64) -> Result<()> {
    let target = data
        .get_mut(offset..offset.checked_add(8).ok_or(FormatError::Bounds)?)
        .ok_or(FormatError::Bounds)?;
    target.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

/// Aligns an address upward to a power-of-two boundary.
#[inline]
pub(crate) fn align_up(value: u64, alignment: u64) -> Result<u64> {
    if alignment == 0 || !alignment.is_power_of_two() {
        return Err(FormatError::BadAlignment);
    }
    let mask = alignment.saturating_sub(1);
    value
        .checked_add(mask)
        .map(|sum| sum & !mask)
        .ok_or(FormatError::Bounds)
}

/// Aligns a file offset upward to a power-of-two boundary.
#[inline]
pub(crate) fn align_up_usize(value: usize, alignment: usize) -> Result<usize> {
    if alignment == 0 || !alignment.is_power_of_two() {
        return Err(FormatError::BadAlignment);
    }
    let mask = alignment.saturating_sub(1);
    value
        .checked_add(mask)
        .map(|sum| sum & !mask)
        .ok_or(FormatError::Bounds)
}
