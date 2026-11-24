//! Typed errors shared by the compiler core.

use core::fmt;

/// Detailed reason a byte sequence could not be decoded.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeReason {
    /// The instruction ran past the end of the supplied range.
    Truncated,
    /// A legacy or REX prefix combination is unsupported.
    UnsupportedPrefix,
    /// A VEX/EVEX or otherwise unsupported encoding was encountered.
    UnsupportedEncoding,
    /// The opcode is not in the supported subset.
    UnsupportedOpcode,
    /// ModRM/SIB addressing is unsupported or malformed.
    UnsupportedAddressing,
    /// RIP-relative memory access is prohibited in virtualized code.
    RipRelativeMemory,
    /// Absolute memory access is prohibited.
    AbsoluteMemory,
    /// An 8-bit high register (`AH`/`BH`/`CH`/`DH`) was used without REX.
    HighByteRegister,
    /// The instruction exceeds the architectural 15-byte limit.
    TooLong,
    /// The decoded form requires a feature the lifter does not support.
    UnsupportedForm,
}

/// Error produced by decoding one x86-64 instruction.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeError {
    /// Virtual address at which decoding started.
    pub offset: u64,
    /// Why decoding failed.
    pub reason: DecodeReason,
}

/// Error produced anywhere in the compiler pipeline.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreError {
    /// A bounded collection reached capacity.
    CapacityExceeded,
    /// An x86-64 decode failed.
    Decode(DecodeError),
    /// A branch target was outside the protected function or not a leader.
    InvalidBranchTarget {
        /// Address of the branch instruction.
        offset: u64,
        /// Requested target address.
        target: u64,
    },
    /// Two decoded instructions overlap.
    OverlappingInstruction {
        /// Address at which the overlap was detected.
        offset: u64,
    },
    /// A basic block has no terminator.
    MissingTerminator {
        /// Start address of the block.
        offset: u64,
    },
    /// A condition depends on flags produced by an unsupported instruction.
    UnknownFlags {
        /// Address of the conditional jump.
        offset: u64,
    },
    /// A parity condition was requested; parity flags are not modeled.
    UnsupportedCondition {
        /// Address of the conditional instruction.
        offset: u64,
    },
    /// A register operand is outside the virtual register file.
    InvalidRegister {
        /// The invalid register id.
        register: u8,
    },
    /// A basic-block id is invalid.
    InvalidBlock {
        /// The invalid block id.
        block: u16,
    },
    /// An immediate value or offset overflowed.
    ArithmeticOverflow,
    /// The generated payload exceeds its fixed capacity.
    PayloadTooLarge,
    /// A semantic operation or operand layout is invalid.
    InvalidPlan,
    /// The derived ISA tables rejected the seed or semantic set.
    DerivationFailed,
    /// A state id was zero or duplicated.
    InvalidState,
    /// A function is empty or larger than the configured ceiling.
    InvalidFunctionSize {
        /// Reported byte length.
        size: u64,
    },
    /// A marker or symbol range is outside an executable segment.
    RangeOutsideExecutable,
    /// Input is not a supported ELF or PE image.
    UnsupportedBinaryFormat,
    /// The binary format is structurally malformed.
    MalformedBinary,
    /// The requested target was not found exactly once.
    TargetNotFound,
    /// The requested target matched more than once.
    AmbiguousTarget,
    /// The target function overlaps another protected function.
    TargetsOverlap,
    /// A relative patch cannot reach its destination.
    JumpOutOfRange,
    /// The injected blob failed structural validation.
    InvalidBlob,
    /// An external tool failed.
    ToolFailure,
    /// Filesystem or process I/O failed.
    Io,
    /// A feature is intentionally unsupported under the current ABI.
    UnsupportedAbi,
}

impl fmt::Display for DecodeReason {
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Truncated => "truncated instruction",
            Self::UnsupportedPrefix => "unsupported prefix combination",
            Self::UnsupportedEncoding => "unsupported instruction encoding",
            Self::UnsupportedOpcode => "unsupported opcode",
            Self::UnsupportedAddressing => "unsupported addressing form",
            Self::RipRelativeMemory => "RIP-relative memory access",
            Self::AbsoluteMemory => "absolute memory access",
            Self::HighByteRegister => "high-byte register without REX",
            Self::TooLong => "instruction exceeds 15 bytes",
            Self::UnsupportedForm => "unsupported instruction form",
        };
        formatter.write_str(text)
    }
}

impl fmt::Display for CoreError {
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapacityExceeded => formatter.write_str("fixed capacity exceeded"),
            Self::Decode(error) => {
                write!(
                    formatter,
                    "decode failed at {:#x}: {}",
                    error.offset, error.reason
                )
            }
            Self::InvalidBranchTarget { offset, target } => {
                write!(
                    formatter,
                    "invalid branch target {target:#x} at {offset:#x}"
                )
            }
            Self::OverlappingInstruction { offset } => {
                write!(formatter, "overlapping instruction at {offset:#x}")
            }
            Self::MissingTerminator { offset } => {
                write!(formatter, "block at {offset:#x} has no terminator")
            }
            Self::UnknownFlags { offset } => {
                write!(formatter, "flags unknown at conditional jump {offset:#x}")
            }
            Self::UnsupportedCondition { offset } => {
                write!(formatter, "unsupported condition at {offset:#x}")
            }
            Self::InvalidRegister { register } => {
                write!(formatter, "invalid virtual register {register}")
            }
            Self::InvalidBlock { block } => write!(formatter, "invalid block {block}"),
            Self::ArithmeticOverflow => formatter.write_str("arithmetic overflow"),
            Self::PayloadTooLarge => formatter.write_str("payload exceeds capacity"),
            Self::InvalidPlan => formatter.write_str("invalid ISA plan"),
            Self::DerivationFailed => formatter.write_str("ISA table derivation failed"),
            Self::InvalidState => formatter.write_str("invalid or duplicate state id"),
            Self::InvalidFunctionSize { size } => {
                write!(formatter, "invalid function size {size}")
            }
            Self::RangeOutsideExecutable => {
                formatter.write_str("range is outside an executable segment")
            }
            Self::UnsupportedBinaryFormat => formatter.write_str("unsupported binary format"),
            Self::MalformedBinary => formatter.write_str("malformed binary"),
            Self::TargetNotFound => formatter.write_str("protected target not found"),
            Self::AmbiguousTarget => formatter.write_str("protected target is ambiguous"),
            Self::TargetsOverlap => formatter.write_str("protected targets overlap"),
            Self::JumpOutOfRange => formatter.write_str("relative jump is out of range"),
            Self::InvalidBlob => formatter.write_str("generated VM blob is invalid"),
            Self::ToolFailure => formatter.write_str("external tool failed"),
            Self::Io => formatter.write_str("I/O failure"),
            Self::UnsupportedAbi => formatter.write_str("unsupported ABI"),
        }
    }
}

/// Convenient result alias.
pub type Result<T> = core::result::Result<T, CoreError>;

#[cfg(test)]
mod tests {
    use super::{CoreError, DecodeError, DecodeReason};
    use core::fmt::Write as _;

    struct Buffer {
        bytes: [u8; 512],
        len: usize,
    }

    impl Buffer {
        fn new() -> Self {
            Self {
                bytes: [0; 512],
                len: 0,
            }
        }

        fn text(&self) -> &str {
            core::str::from_utf8(self.bytes.get(..self.len).unwrap_or(&[])).unwrap_or("")
        }
    }

    impl core::fmt::Write for Buffer {
        fn write_str(&mut self, value: &str) -> core::fmt::Result {
            let end = self.len.saturating_add(value.len());
            if end > 512 {
                return Err(core::fmt::Error);
            }
            if let Some(slot) = self.bytes.get_mut(self.len..end) {
                slot.copy_from_slice(value.as_bytes());
                self.len = end;
                Ok(())
            } else {
                Err(core::fmt::Error)
            }
        }
    }

    #[test]
    fn every_error_has_a_message() {
        let reasons = [
            DecodeReason::Truncated,
            DecodeReason::UnsupportedPrefix,
            DecodeReason::UnsupportedEncoding,
            DecodeReason::UnsupportedOpcode,
            DecodeReason::UnsupportedAddressing,
            DecodeReason::RipRelativeMemory,
            DecodeReason::AbsoluteMemory,
            DecodeReason::HighByteRegister,
            DecodeReason::TooLong,
            DecodeReason::UnsupportedForm,
        ];
        for reason in reasons {
            let mut buffer = Buffer::new();
            if let Err(error) = write!(&mut buffer, "{reason}") {
                assert_eq!(error, core::fmt::Error);
            }
            assert_ne!(buffer.text(), "");
        }
        let errors = [
            CoreError::CapacityExceeded,
            CoreError::Decode(DecodeError {
                offset: 1,
                reason: DecodeReason::Truncated,
            }),
            CoreError::InvalidBranchTarget {
                offset: 1,
                target: 2,
            },
            CoreError::OverlappingInstruction { offset: 1 },
            CoreError::MissingTerminator { offset: 1 },
            CoreError::UnknownFlags { offset: 1 },
            CoreError::UnsupportedCondition { offset: 1 },
            CoreError::InvalidRegister { register: 1 },
            CoreError::InvalidBlock { block: 1 },
            CoreError::ArithmeticOverflow,
            CoreError::PayloadTooLarge,
            CoreError::InvalidPlan,
            CoreError::DerivationFailed,
            CoreError::InvalidState,
            CoreError::InvalidFunctionSize { size: 1 },
            CoreError::RangeOutsideExecutable,
            CoreError::UnsupportedBinaryFormat,
            CoreError::MalformedBinary,
            CoreError::TargetNotFound,
            CoreError::AmbiguousTarget,
            CoreError::TargetsOverlap,
            CoreError::JumpOutOfRange,
            CoreError::InvalidBlob,
            CoreError::ToolFailure,
            CoreError::Io,
            CoreError::UnsupportedAbi,
        ];
        for error in errors {
            let mut buffer = Buffer::new();
            if let Err(write_error) = write!(&mut buffer, "{error}") {
                assert_eq!(write_error, core::fmt::Error);
            }
            assert_ne!(buffer.text(), "");
        }
    }
}
