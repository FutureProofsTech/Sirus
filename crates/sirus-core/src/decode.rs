//! Bounded, fail-closed x86-64 decoder for the virtualizer subset.
//!
//! The decoder understands instruction *length* and operand structure only for
//! the forms the lifter supports. Everything else is rejected with a precise
//! offset and reason. No instruction is ever guessed or skipped.

use crate::error::{CoreError, DecodeError, DecodeReason, Result};
use crate::ir::Width;

/// Maximum architectural x86-64 instruction length.
pub const MAX_X86_INSTRUCTION_BYTES: usize = 15;

/// x86 condition code.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Condition {
    /// Overflow.
    Overflow,
    /// No overflow.
    NoOverflow,
    /// Unsigned below / carry.
    Below,
    /// Unsigned above or equal / no carry.
    AboveOrEqual,
    /// Equal / zero.
    Equal,
    /// Not equal / not zero.
    NotEqual,
    /// Unsigned below or equal.
    BelowOrEqual,
    /// Unsigned above.
    Above,
    /// Sign.
    Sign,
    /// No sign.
    NoSign,
    /// Parity even.
    Parity,
    /// Parity odd.
    NoParity,
    /// Signed less.
    Less,
    /// Signed greater or equal.
    GreaterOrEqual,
    /// Signed less or equal.
    LessOrEqual,
    /// Signed greater.
    Greater,
}

impl Condition {
    #[inline]
    const fn from_nibble(nibble: u8) -> Option<Self> {
        match nibble & 0x0f {
            0x0 => Some(Self::Overflow),
            0x1 => Some(Self::NoOverflow),
            0x2 => Some(Self::Below),
            0x3 => Some(Self::AboveOrEqual),
            0x4 => Some(Self::Equal),
            0x5 => Some(Self::NotEqual),
            0x6 => Some(Self::BelowOrEqual),
            0x7 => Some(Self::Above),
            0x8 => Some(Self::Sign),
            0x9 => Some(Self::NoSign),
            0xa => Some(Self::Parity),
            0xb => Some(Self::NoParity),
            0xc => Some(Self::Less),
            0xd => Some(Self::GreaterOrEqual),
            0xe => Some(Self::LessOrEqual),
            0xf => Some(Self::Greater),
            _ => None,
        }
    }
}

/// Supported SSE/SSE2 operations.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SseOp {
    /// Load 16 unaligned bytes into an XMM register.
    MovdquLoad,
    /// Store 16 unaligned bytes from an XMM register.
    MovdquStore,
    /// Load 16 aligned bytes into an XMM register.
    MovdqaLoad,
    /// Store 16 aligned bytes from an XMM register.
    MovdqaStore,
    /// Bitwise XOR of 128-bit values.
    Pxor,
    /// Bitwise AND of 128-bit values.
    Pand,
    /// Bitwise OR of 128-bit values.
    Por,
    /// Add two 64-bit lanes.
    Paddq,
    /// Subtract two 64-bit lanes.
    Psubq,
    /// Shift the 128-bit value right by a byte count.
    Psrldq {
        /// Byte count.
        shift: u8,
    },
    /// Shift the 128-bit value left by a byte count.
    Pslldq {
        /// Byte count.
        shift: u8,
    },
    /// Move the low 32/64 bits of an XMM register to a GPR or memory.
    MovqToGpr,
    /// Move a 32/64-bit GPR or memory value into the low half of an XMM register.
    MovqFromGpr,
    /// Add four 32-bit lanes.
    Paddd,
    /// Subtract four 32-bit lanes.
    Psubd,
    /// Multiply the low 32 bits of each 64-bit lane.
    Pmuludq,
    /// Interleave the low 64-bit lanes.
    Punpcklqdq,
    /// Interleave the high 64-bit lanes.
    Punpckhqdq,
    /// Load 64 bits into the low half of an XMM register.
    MovqLoad,
    /// Store the low 64 bits of an XMM register.
    MovqStore,
}

/// Decoded instruction mnemonic.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mnemonic {
    /// No operation.
    Nop,
    /// CET landing pad.
    Endbr,
    /// Register/memory move.
    Mov,
    /// Zero-extending move.
    Movzx,
    /// Sign-extending move.
    Movsx,
    /// Sign-extending 32-bit move to 64 bits.
    Movsxd,
    /// Load effective address.
    Lea,
    /// Addition.
    Add,
    /// Subtraction.
    Sub,
    /// Bitwise AND.
    And,
    /// Bitwise OR.
    Or,
    /// Bitwise XOR.
    Xor,
    /// Compare.
    Cmp,
    /// Bitwise test.
    Test,
    /// Increment.
    Inc,
    /// Decrement.
    Dec,
    /// Two's-complement negation.
    Neg,
    /// Bitwise complement.
    Not,
    /// Signed multiply.
    Imul,
    /// Left shift.
    Shl,
    /// Logical right shift.
    Shr,
    /// Arithmetic right shift.
    Sar,
    /// Rotate left.
    Rol,
    /// Rotate right.
    Ror,
    /// Push.
    Push,
    /// Pop.
    Pop,
    /// Leave stack frame.
    Leave,
    /// Sign-extend EAX into RAX.
    Cdqe,
    /// Unconditional relative jump.
    Jmp,
    /// Conditional relative jump.
    Jcc(Condition),
    /// Return.
    Ret,
    /// Direct relative call.
    Call,
    /// Repeated byte copy.
    RepMovsb,
    /// Repeated qword copy.
    RepMovsq,
    /// Byte swap.
    Bswap,
    /// Repeated byte fill.
    RepStosb,
    /// Repeated qword fill.
    RepStosq,
    /// Conditional move.
    Cmov(Condition),
    /// Conditional byte set.
    Setcc(Condition),
    /// SSE/SSE2 operation.
    Sse(SseOp),
}

/// An addressable memory operand.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryOperand {
    /// Base register number, if any.
    pub base: Option<u8>,
    /// Scaled index register number, if any.
    pub index: Option<u8>,
    /// Index scale: one, two, four, or eight.
    pub scale: u8,
    /// Signed displacement.
    pub disp: i64,
    /// Whether the addressing uses RIP-relative displacement.
    pub rip_relative: bool,
    /// Operand width.
    pub width: Width,
}

/// Decoded operand.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operand {
    /// No operand.
    None,
    /// General-purpose register.
    Reg {
        /// Register number, zero through fifteen.
        index: u8,
        /// Operand width.
        width: Width,
    },
    /// Immediate value.
    Imm {
        /// Bit pattern of the immediate.
        value: u64,
        /// Encoded width.
        width: Width,
    },
    /// 128-bit SIMD register.
    Xmm {
        /// Register index zero through fifteen.
        index: u8,
    },
    /// Memory operand.
    Mem(MemoryOperand),
}

/// Fully decoded instruction.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Instruction {
    /// Virtual address of the instruction.
    pub offset: u64,
    /// Encoded length in bytes.
    pub length: u8,
    /// Operation.
    pub mnemonic: Mnemonic,
    /// Primary operand width.
    pub width: Width,
    /// First operand.
    pub dst: Operand,
    /// Second operand.
    pub src: Operand,
    /// Third operand, used by three-operand multiply.
    pub aux: Operand,
    /// Relative branch target, if applicable.
    pub target: Option<u64>,
}

#[inline]
const fn decode_error(offset: u64, reason: DecodeReason) -> CoreError {
    CoreError::Decode(DecodeError { offset, reason })
}

#[inline]
const fn as_i64(value: u64) -> i64 {
    i64::from_ne_bytes(value.to_ne_bytes())
}

#[inline]
const fn sign_extend(value: u64, bits: u32) -> u64 {
    if bits >= 64 {
        value
    } else {
        let shift = 64_u32.saturating_sub(bits);
        let shifted = as_i64(value.wrapping_shl(shift));
        u64::from_ne_bytes(shifted.wrapping_shr(shift).to_ne_bytes())
    }
}

#[inline]
fn need(code: &[u8], index: usize, amount: usize, offset: u64) -> Result<()> {
    let end = index
        .checked_add(amount)
        .ok_or_else(|| decode_error(offset, DecodeReason::Truncated))?;
    if end > code.len() || end > MAX_X86_INSTRUCTION_BYTES {
        return Err(decode_error(offset, DecodeReason::Truncated));
    }
    Ok(())
}

#[inline]
fn read_u8(code: &[u8], index: &mut usize, offset: u64) -> Result<u8> {
    need(code, *index, 1, offset)?;
    let value = code
        .get(*index)
        .copied()
        .ok_or_else(|| decode_error(offset, DecodeReason::Truncated))?;
    *index = index.saturating_add(1);
    Ok(value)
}

#[inline]
fn read_unsigned(code: &[u8], index: &mut usize, bytes: usize, offset: u64) -> Result<u64> {
    if bytes == 0 || bytes > 8 {
        return Err(decode_error(offset, DecodeReason::UnsupportedForm));
    }
    need(code, *index, bytes, offset)?;
    let mut value = 0_u64;
    let mut consumed = 0_usize;
    while consumed < bytes {
        let position = index
            .checked_add(consumed)
            .ok_or_else(|| decode_error(offset, DecodeReason::Truncated))?;
        let byte = code
            .get(position)
            .copied()
            .ok_or_else(|| decode_error(offset, DecodeReason::Truncated))?;
        let shift = u32::try_from(consumed.wrapping_mul(8))
            .map_err(|_| decode_error(offset, DecodeReason::UnsupportedForm))?;
        value |= u64::from(byte) << shift;
        consumed = consumed.saturating_add(1);
    }
    *index = index.saturating_add(bytes);
    Ok(value)
}

#[inline]
fn read_signed(code: &[u8], index: &mut usize, bytes: usize, offset: u64) -> Result<i64> {
    let value = read_unsigned(code, index, bytes, offset)?;
    Ok(as_i64(sign_extend(
        value,
        u32::try_from(bytes.wrapping_mul(8))
            .map_err(|_| decode_error(offset, DecodeReason::UnsupportedForm))?,
    )))
}

#[inline]
const fn register_number(low: u8, extension: u8) -> u8 {
    low | extension
}

#[inline]
const fn rex_r(rex: u8) -> u8 {
    (rex & 0x04) << 1
}

#[inline]
const fn rex_x(rex: u8) -> u8 {
    (rex & 0x02) << 2
}

#[inline]
const fn rex_b(rex: u8) -> u8 {
    (rex & 0x01) << 3
}

#[inline]
fn check_high_byte(index: u8, rex_present: bool, offset: u64) -> Result<()> {
    if (4..=7).contains(&index) && !rex_present {
        return Err(decode_error(offset, DecodeReason::HighByteRegister));
    }
    Ok(())
}

#[inline]
fn check_register_operand(
    modrm: &ModRmResult,
    width: Width,
    rex_present: bool,
    offset: u64,
) -> Result<()> {
    if width == Width::W8 {
        check_high_byte(modrm.reg, rex_present, offset)?;
    }
    Ok(())
}

struct ModRmResult {
    reg: u8,
    rm: Operand,
}

#[allow(clippy::too_many_arguments)]
fn decode_modrm(
    code: &[u8],
    index: &mut usize,
    rex: u8,
    rex_present: bool,
    _reg_width: Width,
    rm_width: Width,
    offset: u64,
) -> Result<ModRmResult> {
    let modrm = read_u8(code, index, offset)?;
    let mod_bits = modrm >> 6;
    let reg_low = (modrm >> 3) & 0x07;
    let rm_low = modrm & 0x07;
    let reg = register_number(reg_low, rex_r(rex));

    if mod_bits == 3 {
        let rm_index = register_number(rm_low, rex_b(rex));
        if rm_width == Width::W8 {
            check_high_byte(rm_index, rex_present, offset)?;
        }
        return Ok(ModRmResult {
            reg,
            rm: Operand::Reg {
                index: rm_index,
                width: rm_width,
            },
        });
    }

    let mut base: Option<u8> = None;
    let mut index_register: Option<u8> = None;
    let mut scale = 1_u8;
    let mut disp = 0_i64;
    let mut rip_relative = false;

    if rm_low == 4 {
        let sib = read_u8(code, index, offset)?;
        scale = 1_u8
            .checked_shl(u32::from(sib >> 6))
            .ok_or_else(|| decode_error(offset, DecodeReason::UnsupportedAddressing))?;
        let index_low = (sib >> 3) & 0x07;
        let base_low = sib & 0x07;
        if index_low != 4 || (rex & 0x02) != 0 {
            index_register = Some(register_number(index_low, rex_x(rex)));
        }
        if base_low == 5 && mod_bits == 0 {
            return Err(decode_error(offset, DecodeReason::AbsoluteMemory));
        }
        base = Some(register_number(base_low, rex_b(rex)));
    } else if rm_low == 5 && mod_bits == 0 {
        rip_relative = true;
    } else {
        base = Some(register_number(rm_low, rex_b(rex)));
    }

    if mod_bits == 1 {
        disp = read_signed(code, index, 1, offset)?;
    } else if mod_bits == 2 || rip_relative {
        disp = read_signed(code, index, 4, offset)?;
    }

    Ok(ModRmResult {
        reg,
        rm: Operand::Mem(MemoryOperand {
            base,
            index: index_register,
            scale,
            disp,
            rip_relative,
            width: rm_width,
        }),
    })
}

fn no_operands(
    offset: u64,
    index: usize,
    length_offset: u64,
    mnemonic: Mnemonic,
    width: Width,
) -> Result<Instruction> {
    let _ = length_offset;
    let length = u8::try_from(index).map_err(|_| decode_error(offset, DecodeReason::TooLong))?;
    Ok(Instruction {
        offset,
        length,
        mnemonic,
        width,
        dst: Operand::None,
        src: Operand::None,
        aux: Operand::None,
        target: None,
    })
}

#[allow(clippy::too_many_lines)]
fn decode_vex(code: &[u8], offset: u64) -> Result<Instruction> {
    let mut index = 0_usize;
    let first = read_u8(code, &mut index, offset)?;
    let (map, pp, length, vvvv, rex) = if first == 0xc5 {
        let byte = read_u8(code, &mut index, offset)?;
        let r = (byte >> 7) & 1;
        (
            1_u8,
            byte & 0x03,
            (byte >> 2) & 1,
            (!((byte >> 3) & 0x0f)) & 0x0f,
            u8::from(r == 0) << 2,
        )
    } else {
        let byte1 = read_u8(code, &mut index, offset)?;
        let byte2 = read_u8(code, &mut index, offset)?;
        let r = (byte1 >> 7) & 1;
        let x = (byte1 >> 6) & 1;
        let b = (byte1 >> 5) & 1;
        let w = (byte2 >> 7) & 1;
        let rex = (u8::from(r == 0) << 2) | (u8::from(x == 0) << 1) | u8::from(b == 0) | (w << 3);
        (
            byte1 & 0x1f,
            byte2 & 0x03,
            (byte2 >> 2) & 1,
            (!((byte2 >> 3) & 0x0f)) & 0x0f,
            rex,
        )
    };
    if map != 1 || length != 0 {
        return Err(decode_error(offset, DecodeReason::UnsupportedEncoding));
    }
    let opcode = read_u8(code, &mut index, offset)?;
    if pp == 0x00 && opcode == 0x77 {
        return no_operands(offset, index, offset, Mnemonic::Nop, Width::W64);
    }
    if pp == 0x01 && opcode == 0x73 {
        let modrm = decode_modrm(code, &mut index, rex, true, Width::W64, Width::W64, offset)?;
        let Operand::Reg {
            index: register, ..
        } = modrm.rm
        else {
            return Err(decode_error(offset, DecodeReason::UnsupportedForm));
        };
        let shift = read_u8(code, &mut index, offset)?;
        let operation = match modrm.reg {
            3 => SseOp::Psrldq { shift },
            7 => SseOp::Pslldq { shift },
            _ => return Err(decode_error(offset, DecodeReason::UnsupportedOpcode)),
        };
        let length =
            u8::try_from(index).map_err(|_| decode_error(offset, DecodeReason::TooLong))?;
        return Ok(Instruction {
            offset,
            length,
            mnemonic: Mnemonic::Sse(operation),
            width: Width::W64,
            dst: Operand::Xmm { index: register },
            src: Operand::Imm {
                value: u64::from(shift),
                width: Width::W8,
            },
            aux: Operand::None,
            target: None,
        });
    }
    if pp == 0x01 && (opcode == 0x6e || opcode == 0x7e) {
        let width = if (rex & 0x08) != 0 {
            Width::W64
        } else {
            Width::W32
        };
        let modrm = decode_modrm(code, &mut index, rex, true, width, width, offset)?;
        let register = Operand::Xmm { index: modrm.reg };
        let (operation, dst, src) = if opcode == 0x7e {
            (SseOp::MovqToGpr, modrm.rm, register)
        } else {
            (SseOp::MovqFromGpr, register, modrm.rm)
        };
        let length =
            u8::try_from(index).map_err(|_| decode_error(offset, DecodeReason::TooLong))?;
        return Ok(Instruction {
            offset,
            length,
            mnemonic: Mnemonic::Sse(operation),
            width,
            dst,
            src,
            aux: Operand::None,
            target: None,
        });
    }
    let operation = match (pp, opcode) {
        (0x01, 0xef) => SseOp::Pxor,
        (0x01, 0xdb) => SseOp::Pand,
        (0x01, 0xeb) => SseOp::Por,
        (0x01, 0xd4) => SseOp::Paddq,
        (0x01, 0xfb) => SseOp::Psubq,
        (0x01, 0xfe) => SseOp::Paddd,
        (0x01, 0xfa) => SseOp::Psubd,
        (0x01, 0xf4) => SseOp::Pmuludq,
        (0x01, 0x6c) => SseOp::Punpcklqdq,
        (0x01, 0x6d) => SseOp::Punpckhqdq,
        (0x02, 0x6f) => SseOp::MovdquLoad,
        (0x02, 0x7f) => SseOp::MovdquStore,
        (0x01, 0x6f) => SseOp::MovdqaLoad,
        (0x01, 0x7f) => SseOp::MovdqaStore,
        _ => return Err(decode_error(offset, DecodeReason::UnsupportedOpcode)),
    };
    let modrm = decode_modrm(code, &mut index, rex, true, Width::W64, Width::W64, offset)?;
    let rm = match modrm.rm {
        Operand::Reg {
            index: register, ..
        } => Operand::Xmm { index: register },
        memory => memory,
    };
    let register = Operand::Xmm { index: modrm.reg };
    let (dst, src, aux) = match operation {
        SseOp::MovdquStore | SseOp::MovdqaStore => (rm, register, Operand::None),
        SseOp::MovdquLoad | SseOp::MovdqaLoad => (register, rm, Operand::None),
        _ => (register, Operand::Xmm { index: vvvv }, rm),
    };
    let length = u8::try_from(index).map_err(|_| decode_error(offset, DecodeReason::TooLong))?;
    Ok(Instruction {
        offset,
        length,
        mnemonic: Mnemonic::Sse(operation),
        width: Width::W64,
        dst,
        src,
        aux,
        target: None,
    })
}

fn decode_inner(code: &[u8], offset: u64) -> Result<Instruction> {
    if matches!(code.first().copied(), Some(0xc4 | 0xc5)) {
        return decode_vex(code, offset);
    }
    let mut index = 0_usize;
    let mut operand_override = false;
    let mut rex = 0_u8;
    let mut rex_present = false;
    let mut rep_prefix: Option<u8> = None;

    loop {
        let byte = code
            .get(index)
            .copied()
            .ok_or_else(|| decode_error(offset, DecodeReason::Truncated))?;
        match byte {
            0x40..=0x4f => {
                rex = byte;
                rex_present = true;
                index = index.saturating_add(1);
            }
            0x66 => {
                operand_override = true;
                index = index.saturating_add(1);
            }
            0x67 | 0xf0 | 0x64 | 0x65 => {
                return Err(decode_error(offset, DecodeReason::UnsupportedPrefix));
            }
            // In 64-bit mode CS/DS/ES/SS overrides do not change addressing;
            // accept and ignore them so compiler-emitted `cs nop` padding lifts.
            0x2e | 0x36 | 0x3e | 0x26 => {
                index = index.saturating_add(1);
            }
            0xf2 | 0xf3 => {
                rep_prefix = Some(byte);
                index = index.saturating_add(1);
            }
            _ => break,
        }
        if index >= MAX_X86_INSTRUCTION_BYTES {
            return Err(decode_error(offset, DecodeReason::TooLong));
        }
    }

    let operand_width = if (rex & 0x08) != 0 {
        Width::W64
    } else if operand_override {
        Width::W16
    } else {
        Width::W32
    };

    let opcode = read_u8(code, &mut index, offset)?;

    if rep_prefix == Some(0xf3) {
        let repeated = match opcode {
            0xa4 => Some((Mnemonic::RepMovsb, Width::W8)),
            0xa5 => Some((Mnemonic::RepMovsq, Width::W64)),
            0xaa => Some((Mnemonic::RepStosb, Width::W8)),
            0xab => Some((Mnemonic::RepStosq, Width::W64)),
            _ => None,
        };
        if let Some((mnemonic, width)) = repeated {
            return no_operands(offset, index, offset, mnemonic, width);
        }
    }

    if opcode == 0x0f {
        let start = index;
        if rep_prefix == Some(0xf3) {
            if let (Some(second), Some(third)) = (
                code.get(index).copied(),
                code.get(index.saturating_add(1)).copied(),
            ) {
                if second == 0x1e && third == 0xfa && (rex & 0x08) == 0 {
                    index = index.saturating_add(2);
                    return no_operands(offset, index, offset, Mnemonic::Endbr, Width::W64);
                }
            }
            if let Some(instruction) = decode_sse(code, &mut index, offset, rex, rex_present, 0xf3)?
            {
                return Ok(instruction);
            }
            return Err(decode_error(offset, DecodeReason::UnsupportedPrefix));
        }
        if operand_override {
            if let Some(instruction) = decode_sse(code, &mut index, offset, rex, rex_present, 0x66)?
            {
                return Ok(instruction);
            }
            index = start;
        }
    }

    if rep_prefix.is_some() {
        if opcode == 0x0f {
            let second = read_u8(code, &mut index, offset)?;
            if second == 0x1e {
                let third = read_u8(code, &mut index, offset)?;
                if third == 0xfa && (rex & 0x08) == 0 {
                    return no_operands(offset, index, offset, Mnemonic::Endbr, Width::W64);
                }
            }
        }
        return Err(decode_error(offset, DecodeReason::UnsupportedPrefix));
    }

    match opcode {
        0xe8 => {
            let displacement = read_signed(code, &mut index, 4, offset)?;
            let length =
                u8::try_from(index).map_err(|_| decode_error(offset, DecodeReason::TooLong))?;
            let target = offset
                .wrapping_add(u64::from(length))
                .wrapping_add(u64::from_ne_bytes(displacement.to_ne_bytes()));
            Ok(Instruction {
                offset,
                length,
                mnemonic: Mnemonic::Call,
                width: Width::W64,
                dst: Operand::None,
                src: Operand::None,
                aux: Operand::None,
                target: Some(target),
            })
        }
        0x90 => {
            if (rex & 0x01) != 0 {
                return Err(decode_error(offset, DecodeReason::UnsupportedOpcode));
            }
            no_operands(offset, index, offset, Mnemonic::Nop, operand_width)
        }
        0x0f => decode_two_byte(code, &mut index, offset, rex, rex_present, operand_width),
        0x63 => {
            if (rex & 0x08) == 0 {
                return Err(decode_error(offset, DecodeReason::UnsupportedForm));
            }
            let modrm = decode_modrm(
                code,
                &mut index,
                rex,
                rex_present,
                Width::W64,
                Width::W32,
                offset,
            )?;
            check_register_operand(&modrm, Width::W64, rex_present, offset)?;
            let length =
                u8::try_from(index).map_err(|_| decode_error(offset, DecodeReason::TooLong))?;
            Ok(Instruction {
                offset,
                length,
                mnemonic: Mnemonic::Movsxd,
                width: Width::W64,
                dst: Operand::Reg {
                    index: modrm.reg,
                    width: Width::W64,
                },
                src: modrm.rm,
                aux: Operand::None,
                target: None,
            })
        }
        0xb8..=0xbf => {
            let register = register_number(opcode & 0x07, rex_b(rex));
            let (value, immediate_width) = match operand_width {
                Width::W64 => (read_unsigned(code, &mut index, 8, offset)?, Width::W64),
                Width::W16 => (read_unsigned(code, &mut index, 2, offset)?, Width::W16),
                _ => (read_unsigned(code, &mut index, 4, offset)?, Width::W32),
            };
            let length =
                u8::try_from(index).map_err(|_| decode_error(offset, DecodeReason::TooLong))?;
            Ok(Instruction {
                offset,
                length,
                mnemonic: Mnemonic::Mov,
                width: operand_width,
                dst: Operand::Reg {
                    index: register,
                    width: operand_width,
                },
                src: Operand::Imm {
                    value,
                    width: immediate_width,
                },
                aux: Operand::None,
                target: None,
            })
        }
        0xb0..=0xb7 => {
            let register = register_number(opcode & 0x07, rex_b(rex));
            let value = read_unsigned(code, &mut index, 1, offset)?;
            let length =
                u8::try_from(index).map_err(|_| decode_error(offset, DecodeReason::TooLong))?;
            Ok(Instruction {
                offset,
                length,
                mnemonic: Mnemonic::Mov,
                width: Width::W8,
                dst: Operand::Reg {
                    index: register,
                    width: Width::W8,
                },
                src: Operand::Imm {
                    value,
                    width: Width::W8,
                },
                aux: Operand::None,
                target: None,
            })
        }
        0x50..=0x57 => {
            let register = register_number(opcode & 0x07, rex_b(rex));
            let length =
                u8::try_from(index).map_err(|_| decode_error(offset, DecodeReason::TooLong))?;
            Ok(Instruction {
                offset,
                length,
                mnemonic: Mnemonic::Push,
                width: Width::W64,
                dst: Operand::Reg {
                    index: register,
                    width: Width::W64,
                },
                src: Operand::None,
                aux: Operand::None,
                target: None,
            })
        }
        0x58..=0x5f => {
            let register = register_number(opcode & 0x07, rex_b(rex));
            let length =
                u8::try_from(index).map_err(|_| decode_error(offset, DecodeReason::TooLong))?;
            Ok(Instruction {
                offset,
                length,
                mnemonic: Mnemonic::Pop,
                width: Width::W64,
                dst: Operand::Reg {
                    index: register,
                    width: Width::W64,
                },
                src: Operand::None,
                aux: Operand::None,
                target: None,
            })
        }
        0xc3 => no_operands(offset, index, offset, Mnemonic::Ret, Width::W64),
        0xc9 => no_operands(offset, index, offset, Mnemonic::Leave, Width::W64),
        0x98 => {
            if (rex & 0x08) == 0 {
                return Err(decode_error(offset, DecodeReason::UnsupportedForm));
            }
            no_operands(offset, index, offset, Mnemonic::Cdqe, Width::W64)
        }
        0xeb => {
            let displacement = read_signed(code, &mut index, 1, offset)?;
            let length =
                u8::try_from(index).map_err(|_| decode_error(offset, DecodeReason::TooLong))?;
            let target = offset
                .wrapping_add(u64::from(length))
                .wrapping_add(u64::from_ne_bytes(displacement.to_ne_bytes()));
            Ok(Instruction {
                offset,
                length,
                mnemonic: Mnemonic::Jmp,
                width: Width::W64,
                dst: Operand::None,
                src: Operand::None,
                aux: Operand::None,
                target: Some(target),
            })
        }
        0xe9 => {
            let displacement = read_signed(code, &mut index, 4, offset)?;
            let length =
                u8::try_from(index).map_err(|_| decode_error(offset, DecodeReason::TooLong))?;
            let target = offset
                .wrapping_add(u64::from(length))
                .wrapping_add(u64::from_ne_bytes(displacement.to_ne_bytes()));
            Ok(Instruction {
                offset,
                length,
                mnemonic: Mnemonic::Jmp,
                width: Width::W64,
                dst: Operand::None,
                src: Operand::None,
                aux: Operand::None,
                target: Some(target),
            })
        }
        0x70..=0x7f => {
            let condition = Condition::from_nibble(opcode & 0x0f)
                .ok_or_else(|| decode_error(offset, DecodeReason::UnsupportedOpcode))?;
            let displacement = read_signed(code, &mut index, 1, offset)?;
            let length =
                u8::try_from(index).map_err(|_| decode_error(offset, DecodeReason::TooLong))?;
            let target = offset
                .wrapping_add(u64::from(length))
                .wrapping_add(u64::from_ne_bytes(displacement.to_ne_bytes()));
            Ok(Instruction {
                offset,
                length,
                mnemonic: Mnemonic::Jcc(condition),
                width: Width::W64,
                dst: Operand::None,
                src: Operand::None,
                aux: Operand::None,
                target: Some(target),
            })
        }
        0x88..=0x8b => {
            let width = if opcode == 0x88 || opcode == 0x8a {
                Width::W8
            } else {
                operand_width
            };
            let modrm = decode_modrm(code, &mut index, rex, rex_present, width, width, offset)?;
            check_register_operand(&modrm, width, rex_present, offset)?;
            let register = Operand::Reg {
                index: modrm.reg,
                width,
            };
            let (dst, src) = if opcode == 0x88 || opcode == 0x89 {
                (modrm.rm, register)
            } else {
                (register, modrm.rm)
            };
            let length =
                u8::try_from(index).map_err(|_| decode_error(offset, DecodeReason::TooLong))?;
            Ok(Instruction {
                offset,
                length,
                mnemonic: Mnemonic::Mov,
                width,
                dst,
                src,
                aux: Operand::None,
                target: None,
            })
        }
        0x8d => {
            let modrm = decode_modrm(
                code,
                &mut index,
                rex,
                rex_present,
                operand_width,
                Width::W32,
                offset,
            )?;
            if matches!(modrm.rm, Operand::Reg { .. }) {
                return Err(decode_error(offset, DecodeReason::UnsupportedForm));
            }
            check_register_operand(&modrm, operand_width, rex_present, offset)?;
            let length =
                u8::try_from(index).map_err(|_| decode_error(offset, DecodeReason::TooLong))?;
            Ok(Instruction {
                offset,
                length,
                mnemonic: Mnemonic::Lea,
                width: operand_width,
                dst: Operand::Reg {
                    index: modrm.reg,
                    width: operand_width,
                },
                src: modrm.rm,
                aux: Operand::None,
                target: None,
            })
        }
        0x80 | 0x81 | 0x83 => {
            let width = if opcode == 0x80 {
                Width::W8
            } else {
                operand_width
            };
            let modrm = decode_modrm(code, &mut index, rex, rex_present, width, width, offset)?;
            let operation = modrm.reg & 0x07;
            let immediate_bytes = match opcode {
                0x80 | 0x83 => 1,
                _ => match width {
                    Width::W16 => 2,
                    Width::W32 | Width::W64 => 4,
                    Width::W8 => 1,
                },
            };
            let raw = read_unsigned(code, &mut index, immediate_bytes, offset)?;
            let value = if opcode == 0x80 {
                raw & 0xff
            } else if opcode == 0x83 {
                sign_extend(raw & 0xff, 8)
            } else if width == Width::W64 {
                sign_extend(raw, 32)
            } else {
                raw & width.mask()
            };
            let mnemonic = match operation {
                0 => Mnemonic::Add,
                1 => Mnemonic::Or,
                4 => Mnemonic::And,
                5 => Mnemonic::Sub,
                6 => Mnemonic::Xor,
                7 => Mnemonic::Cmp,
                _ => return Err(decode_error(offset, DecodeReason::UnsupportedOpcode)),
            };
            let length =
                u8::try_from(index).map_err(|_| decode_error(offset, DecodeReason::TooLong))?;
            Ok(Instruction {
                offset,
                length,
                mnemonic,
                width,
                dst: modrm.rm,
                src: Operand::Imm {
                    value,
                    width: if immediate_bytes == 1 {
                        Width::W8
                    } else if immediate_bytes == 2 {
                        Width::W16
                    } else {
                        Width::W32
                    },
                },
                aux: Operand::None,
                target: None,
            })
        }
        0xc6 | 0xc7 => {
            let width = if opcode == 0xc6 {
                Width::W8
            } else {
                operand_width
            };
            let modrm = decode_modrm(code, &mut index, rex, rex_present, width, width, offset)?;
            if (modrm.reg & 0x07) != 0 {
                return Err(decode_error(offset, DecodeReason::UnsupportedOpcode));
            }
            let bytes = match width {
                Width::W8 => 1,
                Width::W16 => 2,
                Width::W32 | Width::W64 => 4,
            };
            let raw = read_unsigned(code, &mut index, bytes, offset)?;
            let value = if width == Width::W64 {
                sign_extend(raw, 32)
            } else {
                raw & width.mask()
            };
            let length =
                u8::try_from(index).map_err(|_| decode_error(offset, DecodeReason::TooLong))?;
            Ok(Instruction {
                offset,
                length,
                mnemonic: Mnemonic::Mov,
                width,
                dst: modrm.rm,
                src: Operand::Imm {
                    value,
                    width: if bytes == 1 {
                        Width::W8
                    } else if bytes == 2 {
                        Width::W16
                    } else {
                        Width::W32
                    },
                },
                aux: Operand::None,
                target: None,
            })
        }
        0x00 | 0x01 | 0x02 | 0x03 | 0x08 | 0x09 | 0x0a | 0x0b | 0x20 | 0x21 | 0x22 | 0x23
        | 0x28 | 0x29 | 0x2a | 0x2b | 0x30 | 0x31 | 0x32 | 0x33 | 0x38 | 0x39 | 0x3a | 0x3b => {
            let width = if (opcode & 1) == 0 {
                Width::W8
            } else {
                operand_width
            };
            let modrm = decode_modrm(code, &mut index, rex, rex_present, width, width, offset)?;
            check_register_operand(&modrm, width, rex_present, offset)?;
            let register = Operand::Reg {
                index: modrm.reg,
                width,
            };
            let mnemonic = match opcode >> 3 {
                0 => Mnemonic::Add,
                1 => Mnemonic::Or,
                4 => Mnemonic::And,
                5 => Mnemonic::Sub,
                6 => Mnemonic::Xor,
                7 => Mnemonic::Cmp,
                _ => return Err(decode_error(offset, DecodeReason::UnsupportedOpcode)),
            };
            let (dst, src) = if (opcode & 2) == 0 {
                (modrm.rm, register)
            } else {
                (register, modrm.rm)
            };
            let length =
                u8::try_from(index).map_err(|_| decode_error(offset, DecodeReason::TooLong))?;
            Ok(Instruction {
                offset,
                length,
                mnemonic,
                width,
                dst,
                src,
                aux: Operand::None,
                target: None,
            })
        }
        0x84 | 0x85 => {
            let width = if opcode == 0x84 {
                Width::W8
            } else {
                operand_width
            };
            let modrm = decode_modrm(code, &mut index, rex, rex_present, width, width, offset)?;
            check_register_operand(&modrm, width, rex_present, offset)?;
            let length =
                u8::try_from(index).map_err(|_| decode_error(offset, DecodeReason::TooLong))?;
            Ok(Instruction {
                offset,
                length,
                mnemonic: Mnemonic::Test,
                width,
                dst: modrm.rm,
                src: Operand::Reg {
                    index: modrm.reg,
                    width,
                },
                aux: Operand::None,
                target: None,
            })
        }
        0x04 | 0x05 | 0x0c | 0x0d | 0x24 | 0x25 | 0x2c | 0x2d | 0x34 | 0x35 | 0x3c | 0x3d
        | 0xa8 | 0xa9 => {
            let width = if (opcode & 1) == 0 {
                Width::W8
            } else {
                operand_width
            };
            let bytes = match width {
                Width::W8 => 1,
                Width::W16 => 2,
                Width::W32 | Width::W64 => 4,
            };
            let raw = read_unsigned(code, &mut index, bytes, offset)?;
            let value = if width == Width::W64 {
                sign_extend(raw, 32)
            } else {
                raw & width.mask()
            };
            let mnemonic = match opcode >> 3 {
                0 => Mnemonic::Add,
                1 => Mnemonic::Or,
                4 => Mnemonic::And,
                5 => Mnemonic::Sub,
                6 => Mnemonic::Xor,
                7 => Mnemonic::Cmp,
                21 => Mnemonic::Test,
                _ => return Err(decode_error(offset, DecodeReason::UnsupportedOpcode)),
            };
            let length =
                u8::try_from(index).map_err(|_| decode_error(offset, DecodeReason::TooLong))?;
            Ok(Instruction {
                offset,
                length,
                mnemonic,
                width,
                dst: Operand::Reg { index: 0, width },
                src: Operand::Imm {
                    value,
                    width: if bytes == 1 {
                        Width::W8
                    } else if bytes == 2 {
                        Width::W16
                    } else {
                        Width::W32
                    },
                },
                aux: Operand::None,
                target: None,
            })
        }
        0xc0 | 0xc1 | 0xd0 | 0xd1 | 0xd2 | 0xd3 => {
            let width = if (opcode & 1) == 0 {
                Width::W8
            } else {
                operand_width
            };
            let modrm = decode_modrm(code, &mut index, rex, rex_present, width, width, offset)?;
            let operation = modrm.reg & 0x07;
            let mnemonic = match operation {
                0 => Mnemonic::Rol,
                1 => Mnemonic::Ror,
                4 => Mnemonic::Shl,
                5 => Mnemonic::Shr,
                7 => Mnemonic::Sar,
                _ => return Err(decode_error(offset, DecodeReason::UnsupportedOpcode)),
            };
            let count = match opcode {
                0xc0 | 0xc1 => read_unsigned(code, &mut index, 1, offset)? & 0xff,
                0xd0 | 0xd1 => 1,
                _ => 0,
            };
            let src = match opcode {
                0xd2 | 0xd3 => Operand::Reg {
                    index: 1,
                    width: Width::W8,
                },
                _ => Operand::Imm {
                    value: count,
                    width: Width::W8,
                },
            };
            let length =
                u8::try_from(index).map_err(|_| decode_error(offset, DecodeReason::TooLong))?;
            Ok(Instruction {
                offset,
                length,
                mnemonic,
                width,
                dst: modrm.rm,
                src,
                aux: Operand::None,
                target: None,
            })
        }
        0x69 | 0x6b => {
            let width = operand_width;
            let modrm = decode_modrm(code, &mut index, rex, rex_present, width, width, offset)?;
            check_register_operand(&modrm, width, rex_present, offset)?;
            let imm_bytes = if opcode == 0x6b {
                1
            } else if width == Width::W16 {
                2
            } else {
                4
            };
            let raw = read_unsigned(code, &mut index, imm_bytes, offset)?;
            let value = if opcode == 0x6b {
                sign_extend(raw & 0xff, 8)
            } else if width == Width::W64 {
                sign_extend(raw, 32)
            } else {
                raw & width.mask()
            };
            let length =
                u8::try_from(index).map_err(|_| decode_error(offset, DecodeReason::TooLong))?;
            Ok(Instruction {
                offset,
                length,
                mnemonic: Mnemonic::Imul,
                width,
                dst: Operand::Reg {
                    index: modrm.reg,
                    width,
                },
                src: modrm.rm,
                aux: Operand::Imm {
                    value,
                    width: if imm_bytes == 1 {
                        Width::W8
                    } else if imm_bytes == 2 {
                        Width::W16
                    } else {
                        Width::W32
                    },
                },
                target: None,
            })
        }
        0xf6 | 0xf7 => {
            let width = if opcode == 0xf6 {
                Width::W8
            } else {
                operand_width
            };
            let modrm = decode_modrm(code, &mut index, rex, rex_present, width, width, offset)?;
            let operation = modrm.reg & 0x07;
            let (mnemonic, src) = match operation {
                0 => {
                    let bytes = match width {
                        Width::W8 => 1,
                        Width::W16 => 2,
                        Width::W32 | Width::W64 => 4,
                    };
                    let raw = read_unsigned(code, &mut index, bytes, offset)?;
                    let value = if width == Width::W64 {
                        sign_extend(raw, 32)
                    } else {
                        raw & width.mask()
                    };
                    (
                        Mnemonic::Test,
                        Operand::Imm {
                            value,
                            width: if bytes == 1 {
                                Width::W8
                            } else if bytes == 2 {
                                Width::W16
                            } else {
                                Width::W32
                            },
                        },
                    )
                }
                2 => (Mnemonic::Not, Operand::None),
                3 => (Mnemonic::Neg, Operand::None),
                _ => return Err(decode_error(offset, DecodeReason::UnsupportedOpcode)),
            };
            let length =
                u8::try_from(index).map_err(|_| decode_error(offset, DecodeReason::TooLong))?;
            Ok(Instruction {
                offset,
                length,
                mnemonic,
                width,
                dst: modrm.rm,
                src,
                aux: Operand::None,
                target: None,
            })
        }
        0xfe | 0xff => {
            let width = if opcode == 0xfe {
                Width::W8
            } else {
                operand_width
            };
            let modrm = decode_modrm(code, &mut index, rex, rex_present, width, width, offset)?;
            let operation = modrm.reg & 0x07;
            let mnemonic = match operation {
                0 => Mnemonic::Inc,
                1 => Mnemonic::Dec,
                6 if opcode == 0xff => Mnemonic::Push,
                _ => return Err(decode_error(offset, DecodeReason::UnsupportedOpcode)),
            };
            let length =
                u8::try_from(index).map_err(|_| decode_error(offset, DecodeReason::TooLong))?;
            Ok(Instruction {
                offset,
                length,
                mnemonic,
                width: if mnemonic == Mnemonic::Push {
                    Width::W64
                } else {
                    width
                },
                dst: modrm.rm,
                src: Operand::None,
                aux: Operand::None,
                target: None,
            })
        }
        _ => Err(decode_error(offset, DecodeReason::UnsupportedOpcode)),
    }
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn decode_sse(
    code: &[u8],
    index: &mut usize,
    offset: u64,
    rex: u8,
    rex_present: bool,
    prefix: u8,
) -> Result<Option<Instruction>> {
    let start = *index;
    let opcode = read_u8(code, index, offset)?;
    if prefix == 0xf3 && opcode == 0x7e {
        let modrm = decode_modrm(
            code,
            index,
            rex,
            rex_present,
            Width::W64,
            Width::W64,
            offset,
        )?;
        let rm = match modrm.rm {
            Operand::Reg {
                index: register, ..
            } => Operand::Xmm { index: register },
            memory => memory,
        };
        let length =
            u8::try_from(*index).map_err(|_| decode_error(offset, DecodeReason::TooLong))?;
        return Ok(Some(Instruction {
            offset,
            length,
            mnemonic: Mnemonic::Sse(SseOp::MovqLoad),
            width: Width::W64,
            dst: Operand::Xmm { index: modrm.reg },
            src: rm,
            aux: Operand::None,
            target: None,
        }));
    }
    if prefix == 0x66 && opcode == 0xd6 {
        let modrm = decode_modrm(
            code,
            index,
            rex,
            rex_present,
            Width::W64,
            Width::W64,
            offset,
        )?;
        let rm = match modrm.rm {
            Operand::Reg {
                index: register, ..
            } => Operand::Xmm { index: register },
            memory => memory,
        };
        let length =
            u8::try_from(*index).map_err(|_| decode_error(offset, DecodeReason::TooLong))?;
        return Ok(Some(Instruction {
            offset,
            length,
            mnemonic: Mnemonic::Sse(SseOp::MovqStore),
            width: Width::W64,
            dst: rm,
            src: Operand::Xmm { index: modrm.reg },
            aux: Operand::None,
            target: None,
        }));
    }
    if prefix == 0x66 && opcode == 0x73 {
        let modrm = decode_modrm(
            code,
            index,
            rex,
            rex_present,
            Width::W64,
            Width::W64,
            offset,
        )?;
        let Operand::Reg {
            index: register, ..
        } = modrm.rm
        else {
            *index = start;
            return Ok(None);
        };
        let shift = read_u8(code, index, offset)?;
        let operation = match modrm.reg {
            3 => SseOp::Psrldq { shift },
            7 => SseOp::Pslldq { shift },
            _ => {
                *index = start;
                return Ok(None);
            }
        };
        let length =
            u8::try_from(*index).map_err(|_| decode_error(offset, DecodeReason::TooLong))?;
        return Ok(Some(Instruction {
            offset,
            length,
            mnemonic: Mnemonic::Sse(operation),
            width: Width::W64,
            dst: Operand::Xmm { index: register },
            src: Operand::Imm {
                value: u64::from(shift),
                width: Width::W8,
            },
            aux: Operand::None,
            target: None,
        }));
    }
    if prefix == 0x66 && (opcode == 0x7e || opcode == 0x6e) {
        let width = if (rex & 0x08) != 0 {
            Width::W64
        } else {
            Width::W32
        };
        let modrm = decode_modrm(code, index, rex, rex_present, width, width, offset)?;
        let register = Operand::Xmm { index: modrm.reg };
        let (operation, dst, src) = if opcode == 0x7e {
            (SseOp::MovqToGpr, modrm.rm, register)
        } else {
            (SseOp::MovqFromGpr, register, modrm.rm)
        };
        let length =
            u8::try_from(*index).map_err(|_| decode_error(offset, DecodeReason::TooLong))?;
        return Ok(Some(Instruction {
            offset,
            length,
            mnemonic: Mnemonic::Sse(operation),
            width,
            dst,
            src,
            aux: Operand::None,
            target: None,
        }));
    }
    let (operation, load) = match (prefix, opcode) {
        (0xf3, 0x6f) => (SseOp::MovdquLoad, true),
        (0xf3, 0x7f) => (SseOp::MovdquStore, false),
        (0x66, 0x6f) => (SseOp::MovdqaLoad, true),
        (0x66, 0x7f) => (SseOp::MovdqaStore, false),
        (0x66, 0xef) => (SseOp::Pxor, true),
        (0x66, 0xdb) => (SseOp::Pand, true),
        (0x66, 0xeb) => (SseOp::Por, true),
        (0x66, 0xd4) => (SseOp::Paddq, true),
        (0x66, 0xfb) => (SseOp::Psubq, true),
        (0x66, 0xfe) => (SseOp::Paddd, true),
        (0x66, 0xfa) => (SseOp::Psubd, true),
        (0x66, 0xf4) => (SseOp::Pmuludq, true),
        (0x66, 0x6c) => (SseOp::Punpcklqdq, true),
        (0x66, 0x6d) => (SseOp::Punpckhqdq, true),
        _ => {
            *index = start;
            return Ok(None);
        }
    };
    let modrm = decode_modrm(
        code,
        index,
        rex,
        rex_present,
        Width::W64,
        Width::W64,
        offset,
    )?;
    let rm = match modrm.rm {
        Operand::Reg {
            index: register, ..
        } => Operand::Xmm { index: register },
        memory => memory,
    };
    let register = Operand::Xmm { index: modrm.reg };
    let (dst, src) = if load { (register, rm) } else { (rm, register) };
    let length = u8::try_from(*index).map_err(|_| decode_error(offset, DecodeReason::TooLong))?;
    Ok(Some(Instruction {
        offset,
        length,
        mnemonic: Mnemonic::Sse(operation),
        width: Width::W64,
        dst,
        src,
        aux: Operand::None,
        target: None,
    }))
}

fn decode_two_byte(
    code: &[u8],
    index: &mut usize,
    offset: u64,
    rex: u8,
    rex_present: bool,
    operand_width: Width,
) -> Result<Instruction> {
    let opcode = read_u8(code, index, offset)?;
    match opcode {
        0x1f => {
            let modrm = decode_modrm(
                code,
                index,
                rex,
                rex_present,
                Width::W32,
                Width::W32,
                offset,
            )?;
            let _ = modrm;
            let length =
                u8::try_from(*index).map_err(|_| decode_error(offset, DecodeReason::TooLong))?;
            Ok(Instruction {
                offset,
                length,
                mnemonic: Mnemonic::Nop,
                width: Width::W32,
                dst: Operand::None,
                src: Operand::None,
                aux: Operand::None,
                target: None,
            })
        }
        0xc8..=0xcf => {
            // BSWAP has no defined 16-bit form. Real CPUs disagree on what
            // `66 0F C8+rd` does, so fail closed instead of inventing a value.
            if operand_width == Width::W16 {
                return Err(decode_error(offset, DecodeReason::UnsupportedForm));
            }
            let register = register_number(opcode & 0x07, rex_b(rex));
            let width = if (rex & 0x08) != 0 {
                Width::W64
            } else {
                Width::W32
            };
            let length =
                u8::try_from(*index).map_err(|_| decode_error(offset, DecodeReason::TooLong))?;
            Ok(Instruction {
                offset,
                length,
                mnemonic: Mnemonic::Bswap,
                width,
                dst: Operand::Reg {
                    index: register,
                    width,
                },
                src: Operand::None,
                aux: Operand::None,
                target: None,
            })
        }
        0x80..=0x8f => {
            let condition = Condition::from_nibble(opcode & 0x0f)
                .ok_or_else(|| decode_error(offset, DecodeReason::UnsupportedOpcode))?;
            let displacement = read_signed(code, index, 4, offset)?;
            let length =
                u8::try_from(*index).map_err(|_| decode_error(offset, DecodeReason::TooLong))?;
            let target = offset
                .wrapping_add(u64::from(length))
                .wrapping_add(u64::from_ne_bytes(displacement.to_ne_bytes()));
            Ok(Instruction {
                offset,
                length,
                mnemonic: Mnemonic::Jcc(condition),
                width: Width::W64,
                dst: Operand::None,
                src: Operand::None,
                aux: Operand::None,
                target: Some(target),
            })
        }
        0x40..=0x4f => {
            let condition = Condition::from_nibble(opcode & 0x0f)
                .ok_or_else(|| decode_error(offset, DecodeReason::UnsupportedOpcode))?;
            let modrm = decode_modrm(
                code,
                index,
                rex,
                rex_present,
                operand_width,
                operand_width,
                offset,
            )?;
            check_register_operand(&modrm, operand_width, rex_present, offset)?;
            let length =
                u8::try_from(*index).map_err(|_| decode_error(offset, DecodeReason::TooLong))?;
            Ok(Instruction {
                offset,
                length,
                mnemonic: Mnemonic::Cmov(condition),
                width: operand_width,
                dst: Operand::Reg {
                    index: modrm.reg,
                    width: operand_width,
                },
                src: modrm.rm,
                aux: Operand::None,
                target: None,
            })
        }
        0x90..=0x9f => {
            let condition = Condition::from_nibble(opcode & 0x0f)
                .ok_or_else(|| decode_error(offset, DecodeReason::UnsupportedOpcode))?;
            let modrm = decode_modrm(code, index, rex, rex_present, Width::W8, Width::W8, offset)?;
            let length =
                u8::try_from(*index).map_err(|_| decode_error(offset, DecodeReason::TooLong))?;
            Ok(Instruction {
                offset,
                length,
                mnemonic: Mnemonic::Setcc(condition),
                width: Width::W8,
                dst: modrm.rm,
                src: Operand::None,
                aux: Operand::None,
                target: None,
            })
        }
        0xaf => {
            let modrm = decode_modrm(
                code,
                index,
                rex,
                rex_present,
                operand_width,
                operand_width,
                offset,
            )?;
            check_register_operand(&modrm, operand_width, rex_present, offset)?;
            let length =
                u8::try_from(*index).map_err(|_| decode_error(offset, DecodeReason::TooLong))?;
            Ok(Instruction {
                offset,
                length,
                mnemonic: Mnemonic::Imul,
                width: operand_width,
                dst: Operand::Reg {
                    index: modrm.reg,
                    width: operand_width,
                },
                src: modrm.rm,
                aux: Operand::None,
                target: None,
            })
        }
        0xb6 | 0xb7 | 0xbe | 0xbf => {
            let source_width = if opcode == 0xb6 || opcode == 0xbe {
                Width::W8
            } else {
                Width::W16
            };
            let mnemonic = if opcode == 0xb6 || opcode == 0xb7 {
                Mnemonic::Movzx
            } else {
                Mnemonic::Movsx
            };
            let modrm = decode_modrm(
                code,
                index,
                rex,
                rex_present,
                operand_width,
                source_width,
                offset,
            )?;
            let length =
                u8::try_from(*index).map_err(|_| decode_error(offset, DecodeReason::TooLong))?;
            Ok(Instruction {
                offset,
                length,
                mnemonic,
                width: operand_width,
                dst: Operand::Reg {
                    index: modrm.reg,
                    width: operand_width,
                },
                src: modrm.rm,
                aux: Operand::None,
                target: None,
            })
        }
        0x05 | 0x0b | 0x31 | 0x30 | 0x32 | 0x33 | 0x34 | 0x35 | 0xa2 | 0xae => {
            Err(decode_error(offset, DecodeReason::UnsupportedOpcode))
        }
        _ => Err(decode_error(offset, DecodeReason::UnsupportedOpcode)),
    }
}

/// Decodes one instruction at the start of `code`.
///
/// # Errors
///
/// Returns a typed decode error for truncation, unsupported prefixes, opcodes,
/// addressing forms, high-byte registers, or instruction length violations.
#[inline]
pub fn decode(code: &[u8], address: u64) -> Result<Instruction> {
    let instruction = decode_inner(code, address)?;
    if instruction.length == 0 || usize::from(instruction.length) > MAX_X86_INSTRUCTION_BYTES {
        return Err(decode_error(address, DecodeReason::TooLong));
    }
    Ok(instruction)
}

#[cfg(test)]
mod tests {
    use super::{Condition, Mnemonic, Operand, SseOp, decode};
    use crate::ir::Width;

    fn decode_at(bytes: &[u8], address: u64) -> super::Instruction {
        match decode(bytes, address) {
            Ok(instruction) => instruction,
            Err(error) => panic!("decode failed: {error}"),
        }
    }

    fn rejected(bytes: &[u8]) -> bool {
        decode(bytes, 0x1000).is_err()
    }

    #[test]
    fn decodes_reference_check_function() {
        let bytes = [
            0x48, 0x39, 0xf7, 0x76, 0x15, 0x48, 0x8d, 0x0c, 0x7f, 0x48, 0x01, 0xf1, 0x48, 0xb8,
            0x78, 0x56, 0x34, 0x12, 0x5a, 0x5a, 0xa5, 0xa5, 0x48, 0x31, 0xc8, 0xc3,
        ];
        let first = decode_at(&bytes, 0x1000);
        assert_eq!(first.mnemonic, Mnemonic::Cmp);
        assert_eq!(first.width, Width::W64);
        assert_eq!(first.length, 3);
        match first.dst {
            Operand::Reg { index, .. } => assert_eq!(index, 7),
            _ => assert_eq!(first.length, first.length),
        }
        let second = decode_at(&bytes[3..], 0x1003);
        assert_eq!(second.mnemonic, Mnemonic::Jcc(Condition::BelowOrEqual));
        assert_eq!(second.length, 2);
        assert_eq!(second.target, Some(0x101a));
        let lea = decode_at(&bytes[5..], 0x1005);
        assert_eq!(lea.mnemonic, Mnemonic::Lea);
        assert_eq!(lea.length, 4);
        let movabs = decode_at(&bytes[12..], 0x100c);
        assert_eq!(movabs.mnemonic, Mnemonic::Mov);
        assert_eq!(movabs.length, 10);
    }

    #[test]
    fn decodes_endbr64_and_nops() {
        let endbr = decode_at(&[0xf3, 0x0f, 0x1e, 0xfa], 0);
        assert_eq!(endbr.mnemonic, Mnemonic::Endbr);
        assert_eq!(endbr.length, 4);
        let nop = decode_at(&[0x0f, 0x1f, 0x44, 0x00, 0x00], 0);
        assert_eq!(nop.mnemonic, Mnemonic::Nop);
        assert_eq!(nop.length, 5);
        let one = decode_at(&[0x90], 0);
        assert_eq!(one.mnemonic, Mnemonic::Nop);
    }

    #[test]
    fn decodes_bswap_widths() {
        let instruction = decode_at(&[0x0f, 0xc8], 0x1000);
        assert_eq!(instruction.mnemonic, Mnemonic::Bswap);
        assert_eq!(instruction.width, Width::W32);
        let instruction = decode_at(&[0x48, 0x0f, 0xc8], 0x1000);
        assert_eq!(instruction.mnemonic, Mnemonic::Bswap);
        assert_eq!(instruction.width, Width::W64);
        let instruction = decode_at(&[0x66, 0x48, 0x0f, 0xc8], 0x1000);
        assert_eq!(instruction.mnemonic, Mnemonic::Bswap);
        assert_eq!(instruction.width, Width::W64);
    }

    #[test]
    fn rejects_undefined_16_bit_bswap() {
        assert!(rejected(&[0x66, 0x0f, 0xc8]));
        assert!(rejected(&[0x66, 0x0f, 0xcf]));
    }

    #[test]
    fn decodes_repeated_string_forms() {
        assert_eq!(
            decode_at(&[0xf3, 0xa4], 0x1000).mnemonic,
            Mnemonic::RepMovsb
        );
        assert_eq!(
            decode_at(&[0xf3, 0xa5], 0x1000).mnemonic,
            Mnemonic::RepMovsq
        );
        assert_eq!(
            decode_at(&[0xf3, 0xaa], 0x1000).mnemonic,
            Mnemonic::RepStosb
        );
        assert_eq!(
            decode_at(&[0xf3, 0xab], 0x1000).mnemonic,
            Mnemonic::RepStosq
        );
    }

    #[test]
    fn decodes_common_sse2_forms() {
        let instruction = decode_at(&[0x66, 0x0f, 0xef, 0xc0], 0x1000);
        assert_eq!(instruction.mnemonic, Mnemonic::Sse(SseOp::Pxor));
        assert_eq!(instruction.dst, Operand::Xmm { index: 0 });
        assert_eq!(instruction.src, Operand::Xmm { index: 0 });

        let instruction = decode_at(&[0xf3, 0x0f, 0x6f, 0x00], 0x1000);
        assert_eq!(instruction.mnemonic, Mnemonic::Sse(SseOp::MovdquLoad));
        assert_eq!(instruction.dst, Operand::Xmm { index: 0 });
        assert!(matches!(instruction.src, Operand::Mem(_)));

        let instruction = decode_at(&[0xf3, 0x0f, 0x7f, 0x08], 0x1000);
        assert_eq!(instruction.mnemonic, Mnemonic::Sse(SseOp::MovdquStore));
        assert_eq!(instruction.src, Operand::Xmm { index: 1 });
        assert!(matches!(instruction.dst, Operand::Mem(_)));

        let instruction = decode_at(&[0x66, 0x0f, 0xd4, 0xc1], 0x1000);
        assert_eq!(instruction.mnemonic, Mnemonic::Sse(SseOp::Paddq));
        assert_eq!(instruction.dst, Operand::Xmm { index: 0 });
        assert_eq!(instruction.src, Operand::Xmm { index: 1 });

        let instruction = decode_at(&[0x66, 0x0f, 0x73, 0xd9, 0x08], 0x1000);
        assert_eq!(
            instruction.mnemonic,
            Mnemonic::Sse(SseOp::Psrldq { shift: 8 })
        );

        let instruction = decode_at(&[0x66, 0x48, 0x0f, 0x7e, 0xc0], 0x1000);
        assert_eq!(instruction.mnemonic, Mnemonic::Sse(SseOp::MovqToGpr));
        assert_eq!(instruction.width, Width::W64);
    }

    #[test]
    fn decodes_vex_128_bit_forms_and_rejects_256_bit() {
        let instruction = decode_at(&[0xc5, 0xf1, 0xef, 0xc2], 0x1000);
        assert_eq!(instruction.mnemonic, Mnemonic::Sse(SseOp::Pxor));
        assert_eq!(instruction.dst, Operand::Xmm { index: 0 });
        assert_eq!(instruction.src, Operand::Xmm { index: 1 });
        assert_eq!(instruction.aux, Operand::Xmm { index: 2 });

        let instruction = decode_at(&[0xc5, 0xfa, 0x6f, 0x00], 0x1000);
        assert_eq!(instruction.mnemonic, Mnemonic::Sse(SseOp::MovdquLoad));
        assert_eq!(instruction.dst, Operand::Xmm { index: 0 });
        assert!(matches!(instruction.src, Operand::Mem(_)));

        let instruction = decode_at(&[0xc5, 0xfa, 0x7f, 0x00], 0x1000);
        assert_eq!(instruction.mnemonic, Mnemonic::Sse(SseOp::MovdquStore));
        assert_eq!(instruction.src, Operand::Xmm { index: 0 });

        assert!(decode(&[0xc5, 0xfd, 0xef, 0xc0], 0x1000).is_err());
        assert_eq!(
            decode_at(&[0xc5, 0xf8, 0x77], 0x1000).mnemonic,
            Mnemonic::Nop
        );

        let instruction = decode_at(&[0xc5, 0xf9, 0x73, 0xd8, 0x08], 0x1000);
        assert_eq!(
            instruction.mnemonic,
            Mnemonic::Sse(SseOp::Psrldq { shift: 8 })
        );

        let instruction = decode_at(&[0xc4, 0xe1, 0xf9, 0x7e, 0xc0], 0x1000);
        assert_eq!(instruction.mnemonic, Mnemonic::Sse(SseOp::MovqToGpr));
        assert_eq!(instruction.width, Width::W64);

        let instruction = decode_at(&[0xc4, 0xe1, 0xf9, 0x6e, 0xc0], 0x1000);
        assert_eq!(instruction.mnemonic, Mnemonic::Sse(SseOp::MovqFromGpr));
        assert_eq!(instruction.width, Width::W64);
    }

    #[test]
    fn decodes_direct_calls_and_rejects_indirect_calls() {
        let call = decode_at(&[0xe8, 0, 0, 0, 0], 0x1000);
        assert_eq!(call.mnemonic, Mnemonic::Call);
        assert_eq!(call.target, Some(0x1005));
        assert!(decode(&[0xff, 0x15, 0, 0, 0, 0], 0).is_err());
        let rip = decode(&[0x48, 0x8b, 0x05, 0, 0, 0, 0], 0);
        assert!(rip.is_ok());
        if let Ok(instruction) = rip {
            assert!(matches!(instruction.src, Operand::Mem(_)));
        }
    }

    #[test]
    fn rejects_truncation_and_high_bytes() {
        assert!(decode(&[0x48, 0x8b], 0).is_err());
        assert!(decode(&[0x88, 0xe0], 0).is_err());
        assert!(decode(&[0x48, 0x88, 0xe0], 0).is_ok());
    }

    #[test]
    fn decoder_never_accepts_overlong_instruction() {
        let bytes = [
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x90,
        ];
        assert!(decode(&bytes, 0).is_err());
    }
    #[test]
    fn decodes_all_move_forms() {
        for bytes in [
            &[0x48, 0xb8, 0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0][..],
            &[0xb8, 0x78, 0x56, 0x34, 0x12][..],
            &[0x66, 0xb8, 0x34, 0x12][..],
            &[0xb0, 0x7f][..],
            &[0x48, 0x89, 0xf8][..],
            &[0x48, 0x8b, 0xc7][..],
            &[0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff][..],
            &[0xc6, 0x00, 0x01][..],
            &[0x48, 0x89, 0x44, 0x24, 0x08][..],
        ] {
            let instruction = decode_at(bytes, 0x1000);
            assert_eq!(instruction.mnemonic, Mnemonic::Mov);
            assert_eq!(usize::from(instruction.length), bytes.len());
        }
        assert_eq!(
            decode_at(&[0x48, 0x0f, 0xb6, 0xc7], 0).mnemonic,
            Mnemonic::Movzx
        );
        assert_eq!(
            decode_at(&[0x48, 0x0f, 0xbe, 0xc7], 0).mnemonic,
            Mnemonic::Movsx
        );
        assert_eq!(decode_at(&[0x48, 0x63, 0xc7], 0).mnemonic, Mnemonic::Movsxd);
    }

    #[test]
    fn decodes_all_arithmetic_forms() {
        let instructions = [
            (&[0x48, 0x01, 0xf8][..], Mnemonic::Add),
            (&[0x48, 0x03, 0xc7][..], Mnemonic::Add),
            (&[0x48, 0x83, 0xc0, 0x05][..], Mnemonic::Add),
            (&[0x48, 0x81, 0xe8, 0x05, 0, 0, 0][..], Mnemonic::Sub),
            (&[0x48, 0x31, 0xc0][..], Mnemonic::Xor),
            (&[0x48, 0x21, 0xf8][..], Mnemonic::And),
            (&[0x48, 0x09, 0xf8][..], Mnemonic::Or),
            (&[0x48, 0x39, 0xf8][..], Mnemonic::Cmp),
            (&[0x48, 0x85, 0xc0][..], Mnemonic::Test),
            (&[0x48, 0x05, 0x05, 0, 0, 0][..], Mnemonic::Add),
            (&[0x48, 0xff, 0xc0][..], Mnemonic::Inc),
            (&[0x48, 0xff, 0xc8][..], Mnemonic::Dec),
            (&[0xfe, 0xc0][..], Mnemonic::Inc),
            (&[0xff, 0xc0][..], Mnemonic::Inc),
            (&[0x48, 0xf7, 0xd8][..], Mnemonic::Neg),
            (&[0x48, 0xf7, 0xd0][..], Mnemonic::Not),
            (&[0x48, 0x0f, 0xaf, 0xc7][..], Mnemonic::Imul),
            (&[0x48, 0x6b, 0xc7, 0x05][..], Mnemonic::Imul),
            (&[0x48, 0x69, 0xc7, 0x05, 0, 0, 0][..], Mnemonic::Imul),
            (&[0x48, 0xc1, 0xe0, 0x05][..], Mnemonic::Shl),
            (&[0x48, 0xd1, 0xe8][..], Mnemonic::Shr),
            (&[0x48, 0xd3, 0xf8][..], Mnemonic::Sar),
            (&[0x48, 0xc1, 0xc0, 0x05][..], Mnemonic::Rol),
            (&[0x48, 0xc1, 0xc8, 0x05][..], Mnemonic::Ror),
            (&[0xd0, 0xc0][..], Mnemonic::Rol),
        ];
        for (bytes, mnemonic) in instructions {
            let instruction = decode_at(bytes, 0x1000);
            assert_eq!(instruction.mnemonic, mnemonic);
            assert_eq!(usize::from(instruction.length), bytes.len());
        }
    }

    #[test]
    fn decodes_control_flow_and_misc_forms() {
        assert_eq!(decode_at(&[0x50], 0).mnemonic, Mnemonic::Push);
        assert_eq!(decode_at(&[0x5f], 0).mnemonic, Mnemonic::Pop);
        assert_eq!(decode_at(&[0xc9], 0).mnemonic, Mnemonic::Leave);
        assert_eq!(decode_at(&[0x48, 0x98], 0).mnemonic, Mnemonic::Cdqe);
        assert_eq!(decode_at(&[0xeb, 0], 0).mnemonic, Mnemonic::Jmp);
        assert_eq!(decode_at(&[0xe9, 0, 0, 0, 0], 0).mnemonic, Mnemonic::Jmp);
        assert_eq!(
            decode_at(&[0x74, 0], 0).mnemonic,
            Mnemonic::Jcc(Condition::Equal)
        );
        assert_eq!(
            decode_at(&[0x0f, 0x84, 0, 0, 0, 0], 0).mnemonic,
            Mnemonic::Jcc(Condition::Equal)
        );
        assert_eq!(
            decode_at(&[0x48, 0x0f, 0x4f, 0xc6], 0).mnemonic,
            Mnemonic::Cmov(Condition::Greater)
        );
        assert_eq!(
            decode_at(&[0x0f, 0x9f, 0xc0], 0).mnemonic,
            Mnemonic::Setcc(Condition::Greater)
        );
        assert_eq!(
            decode_at(&[0x48, 0x8d, 0x44, 0x24, 0x08], 0).mnemonic,
            Mnemonic::Lea
        );
        assert_eq!(
            decode_at(&[0xf3, 0x0f, 0x1e, 0xfa], 0).mnemonic,
            Mnemonic::Endbr
        );
    }

    #[test]
    fn rejects_unsupported_and_malformed_encodings() {
        for bytes in [
            &[0x48, 0x8b][..],
            &[0xff, 0xd0][..],
            &[0xff, 0xe0][..],
            &[0x67, 0x48, 0x8b, 0x00][..],
            &[0xf0, 0x48, 0x8b, 0x00][..],
            &[0x88, 0xe0][..],
            &[0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0][..],
            &[0x62, 0xf1, 0x7c, 0x48, 0x58, 0xc0][..],
            &[0x0f, 0x0b][..],
            &[0x0f, 0x05][..],
            &[0xc7, 0xc8, 0, 0, 0, 0][..],
            &[0x48, 0x81, 0xd0, 0, 0, 0, 0][..],
            &[0x48, 0xf7, 0xf0][..],
        ] {
            assert!(rejected(bytes), "accepted {bytes:02x?}");
        }
    }

    #[test]
    fn ignores_cs_ds_es_ss_overrides_in_long_mode() {
        let instruction = decode_at(&[0x2e, 0x48, 0x8b, 0x00], 0x1000);
        assert_eq!(instruction.mnemonic, Mnemonic::Mov);
        assert_eq!(instruction.length, 4);
        assert_eq!(decode_at(&[0x36, 0x90], 0).mnemonic, Mnemonic::Nop);
        assert!(rejected(&[0x64, 0x48, 0x8b, 0x00]));
        assert!(rejected(&[0x65, 0x48, 0x8b, 0x00]));
    }

    #[test]
    fn accepts_rip_relative_at_decode_layer() {
        let instruction = decode_at(&[0x48, 0x8b, 0x05, 0, 0, 0, 0], 0x1000);
        match instruction.src {
            Operand::Mem(memory) => assert!(memory.rip_relative),
            _ => panic!("expected RIP-relative memory"),
        }
    }

    #[test]
    fn decodes_memory_widths_and_scales() {
        let instruction = decode_at(&[0x48, 0x8b, 0x44, 0x8f, 0x10], 0x1000);
        match instruction.src {
            Operand::Mem(memory) => {
                assert_eq!(memory.scale, 4);
                assert_eq!(memory.disp, 0x10);
                assert_eq!(memory.index, Some(1));
            }
            _ => panic!("expected memory operand"),
        }
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::{read_signed, read_unsigned, sign_extend};

    #[kani::proof]
    #[kani::unwind(10)]
    fn read_unsigned_is_bounded() {
        let bytes: [u8; 8] = kani::any();
        let start: usize = kani::any();
        let count: usize = kani::any();
        kani::assume(start < 8);
        kani::assume(count >= 1 && count <= 8 - start);
        let mut index = start;
        let _ = read_unsigned(&bytes, &mut index, count, 0);
    }

    #[kani::proof]
    #[kani::unwind(10)]
    fn read_signed_is_bounded() {
        let bytes: [u8; 8] = kani::any();
        let start: usize = kani::any();
        let count: usize = kani::any();
        kani::assume(start < 8);
        kani::assume(count >= 1 && count <= 8 - start);
        let mut index = start;
        let _ = read_signed(&bytes, &mut index, count, 0);
    }

    #[kani::proof]
    fn sign_extend_is_total() {
        let value: u64 = kani::any();
        let bits: u32 = kani::any();
        kani::assume(bits <= 64);
        let _ = sign_extend(value, bits);
    }
}
