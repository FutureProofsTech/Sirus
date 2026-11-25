//! Lifts the supported x86-64 subset into Sirus IR and a validated CFG.
//!
//! Policy: decode only reachable instructions, reject overlapping or malformed
//! control flow, never guess a semantic, and reset flag knowledge at every basic
//! block boundary so cross-block flag liveness fails closed.

use crate::decode::{Condition, Instruction, MemoryOperand, Mnemonic, Operand, SseOp, decode};
use crate::error::{CoreError, DecodeError, DecodeReason, Result};
use crate::ir::{
    Block, BoundedVec, ByteBuf, IrOp, LiftedFunction, MAX_BLOCKS, MAX_DATA_BYTES,
    MAX_FUNCTION_BYTES, MAX_IR_OPS, MAX_STACK_ARGS, Terminator, Width,
};
use crate::shared::format::{
    REG_CF, REG_OF, REG_ONE, REG_RAX, REG_RBP, REG_RSP, REG_SF, REG_TMP0, REG_TMP1, REG_TMP2,
    REG_TMP3, REG_XMM_BASE, REG_ZERO, REG_ZF,
};

const FLAG_ZF: u8 = 1;
const FLAG_CF: u8 = 2;
const FLAG_SF: u8 = 4;
const FLAG_OF: u8 = 8;
const FLAG_ALL: u8 = FLAG_ZF | FLAG_CF | FLAG_SF | FLAG_OF;
const MAX_QUEUE: usize = 1024;
const INSTRUCTION_LIMIT: usize = MAX_FUNCTION_BYTES;
const MAX_DATA_REFS: usize = 64;
const RIP_WINDOW: usize = 256;

/// Resolves read-only bytes from the input image for RIP-relative operands.
pub trait BinaryData {
    /// Returns `len` bytes at virtual address `va`, or `None` when the address
    /// is not readable read-only data.
    fn read_readonly(&self, va: u64, len: usize) -> Option<&[u8]>;
}

struct EmptyData;

impl BinaryData for EmptyData {
    #[inline]
    fn read_readonly(&self, _va: u64, _len: usize) -> Option<&[u8]> {
        None
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct DataRef {
    va: u64,
    offset: usize,
    len: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FlagKind {
    Add,
    Sub,
    Bitwise,
    Test,
    Inc,
    Dec,
}

struct Lifter<'a> {
    code_len: usize,
    base_va: u64,
    leaders: BoundedVec<u32, MAX_BLOCKS>,
    blocks: BoundedVec<Block, MAX_BLOCKS>,
    ops: BoundedVec<IrOp, MAX_IR_OPS>,
    error_offset: u64,
    reader: &'a dyn BinaryData,
    data: ByteBuf<MAX_DATA_BYTES>,
    data_refs: BoundedVec<DataRef, MAX_DATA_REFS>,
    data_base: usize,
    current_va: u64,
    current_len: u8,
    max_stack_args: u8,
}

impl<'a> Lifter<'a> {
    fn new(code_len: usize, base_va: u64, reader: &'a dyn BinaryData, data_base: usize) -> Self {
        Self {
            code_len,
            base_va,
            leaders: BoundedVec::new(),
            blocks: BoundedVec::new(),
            ops: BoundedVec::new(),
            error_offset: base_va,
            reader,
            data: ByteBuf::new(),
            data_refs: BoundedVec::new(),
            data_base,
            current_va: base_va,
            current_len: 0,
            max_stack_args: 0,
        }
    }

    #[inline]
    fn emit(&mut self, operation: IrOp) -> Result<()> {
        self.ops.push(operation)
    }

    #[inline]
    fn mov(&mut self, dst: u8, src: u8) -> Result<()> {
        self.emit(IrOp::Mov { dst, src })
    }

    #[inline]
    fn mov_imm(&mut self, dst: u8, value: u64) -> Result<()> {
        self.emit(IrOp::MovImm { dst, value })
    }

    #[inline]
    fn add(&mut self, dst: u8, src: u8) -> Result<()> {
        self.emit(IrOp::Add { dst, src })
    }

    #[inline]
    fn sub(&mut self, dst: u8, src: u8) -> Result<()> {
        self.emit(IrOp::Sub { dst, src })
    }

    #[inline]
    fn and(&mut self, dst: u8, src: u8) -> Result<()> {
        self.emit(IrOp::And { dst, src })
    }

    #[inline]
    fn or(&mut self, dst: u8, src: u8) -> Result<()> {
        self.emit(IrOp::Or { dst, src })
    }

    #[inline]
    fn xor(&mut self, dst: u8, src: u8) -> Result<()> {
        self.emit(IrOp::Xor { dst, src })
    }

    #[inline]
    fn add_imm(&mut self, dst: u8, value: u64) -> Result<()> {
        self.emit(IrOp::AddImm { dst, value })
    }

    #[inline]
    fn sub_imm(&mut self, dst: u8, value: u64) -> Result<()> {
        self.emit(IrOp::SubImm { dst, value })
    }

    #[inline]
    fn and_imm(&mut self, dst: u8, value: u64) -> Result<()> {
        self.emit(IrOp::AndImm { dst, value })
    }

    #[inline]
    fn xor_imm(&mut self, dst: u8, value: u64) -> Result<()> {
        self.emit(IrOp::XorImm { dst, value })
    }

    #[inline]
    fn shl_imm(&mut self, dst: u8, value: u64) -> Result<()> {
        self.emit(IrOp::ShlImm { dst, value })
    }

    #[inline]
    fn shr_u_imm(&mut self, dst: u8, value: u64) -> Result<()> {
        self.emit(IrOp::ShrUImm { dst, value })
    }

    #[inline]
    fn shr_s_imm(&mut self, dst: u8, value: u64) -> Result<()> {
        self.emit(IrOp::ShrSImm { dst, value })
    }

    #[inline]
    fn cmp_eq(&mut self, dst: u8, lhs: u8, rhs: u8) -> Result<()> {
        self.emit(IrOp::CmpEq { dst, lhs, rhs })
    }

    #[inline]
    fn cmp_lt_u(&mut self, dst: u8, lhs: u8, rhs: u8) -> Result<()> {
        self.emit(IrOp::CmpLtU { dst, lhs, rhs })
    }

    #[inline]
    fn apply_mask(&mut self, register: u8, width: Width) -> Result<()> {
        if width == Width::W64 {
            Ok(())
        } else {
            self.and_imm(register, width.mask())
        }
    }

    fn sign_extend(&mut self, register: u8, bits: u32) -> Result<()> {
        if bits >= 64 {
            return Ok(());
        }
        let shift = 64_u32.saturating_sub(bits);
        self.shl_imm(register, u64::from(shift))?;
        self.shr_s_imm(register, u64::from(shift))
    }

    fn resolve_rip_data(&mut self, va: u64, width: usize) -> Result<usize> {
        for reference in &self.data_refs {
            let end = reference
                .va
                .checked_add(u64::try_from(reference.len).unwrap_or(u64::MAX))
                .ok_or(CoreError::ArithmeticOverflow)?;
            let requested_end = va
                .checked_add(u64::try_from(width).unwrap_or(u64::MAX))
                .ok_or(CoreError::ArithmeticOverflow)?;
            if va >= reference.va && requested_end <= end {
                let delta = usize::try_from(va.saturating_sub(reference.va))
                    .map_err(|_| CoreError::ArithmeticOverflow)?;
                return reference
                    .offset
                    .checked_add(delta)
                    .ok_or(CoreError::ArithmeticOverflow);
            }
        }
        let start = va & !0x0f;
        let lead =
            usize::try_from(va.saturating_sub(start)).map_err(|_| CoreError::ArithmeticOverflow)?;
        let needed = lead
            .checked_add(width)
            .ok_or(CoreError::ArithmeticOverflow)?;
        let mut selected = None;
        for length in [RIP_WINDOW, 128, 64, 32, 16, 8] {
            if length < needed {
                continue;
            }
            if let Some(bytes) = self.reader.read_readonly(start, length) {
                selected = Some(bytes);
                break;
            }
        }
        let Some(bytes) = selected else {
            return Err(CoreError::Decode(DecodeError {
                offset: self.error_offset,
                reason: DecodeReason::RipRelativeMemory,
            }));
        };
        if bytes.len() < needed {
            return Err(CoreError::Decode(DecodeError {
                offset: self.error_offset,
                reason: DecodeReason::RipRelativeMemory,
            }));
        }
        let offset = self.data.len();
        self.data.extend_from_slice(bytes)?;
        self.data_refs.push(DataRef {
            va: start,
            offset,
            len: bytes.len(),
        })?;
        offset
            .checked_add(lead)
            .ok_or(CoreError::ArithmeticOverflow)
    }

    fn note_stack_access(&mut self, memory: &MemoryOperand) -> Result<()> {
        if memory.rip_relative {
            return Ok(());
        }
        let Some(base) = memory.base else {
            return Ok(());
        };
        let (threshold, bias) = if base == REG_RBP {
            (16_i64, 16_i64)
        } else if base == REG_RSP {
            (8_i64, 8_i64)
        } else {
            return Ok(());
        };
        if memory.disp < threshold {
            return Ok(());
        }
        let relative = usize::try_from(memory.disp.saturating_sub(bias))
            .map_err(|_| CoreError::ArithmeticOverflow)?;
        let count = relative / 8 + 1;
        if count > MAX_STACK_ARGS {
            return Err(CoreError::Decode(DecodeError {
                offset: self.error_offset,
                reason: DecodeReason::UnsupportedForm,
            }));
        }
        self.max_stack_args = self
            .max_stack_args
            .max(u8::try_from(count).map_err(|_| CoreError::ArithmeticOverflow)?);
        Ok(())
    }

    fn compute_address(&mut self, memory: &MemoryOperand, load_width: Option<u8>) -> Result<()> {
        self.note_stack_access(memory)?;
        if memory.rip_relative {
            if memory.base.is_some() || memory.index.is_some() {
                return Err(CoreError::Decode(DecodeError {
                    offset: self.error_offset,
                    reason: DecodeReason::UnsupportedAddressing,
                }));
            }
            let next = self
                .current_va
                .checked_add(u64::from(self.current_len))
                .ok_or(CoreError::ArithmeticOverflow)?;
            let target = next
                .checked_add_signed(memory.disp)
                .ok_or(CoreError::Decode(DecodeError {
                    offset: self.error_offset,
                    reason: DecodeReason::RipRelativeMemory,
                }))?;
            let width = usize::from(load_width.unwrap_or(8).max(1));
            let offset = self.resolve_rip_data(target, width)?;
            let address = self
                .data_base
                .checked_add(offset)
                .ok_or(CoreError::ArithmeticOverflow)?;
            self.mov_imm(
                REG_TMP3,
                u64::try_from(address).map_err(|_| CoreError::ArithmeticOverflow)?,
            )?;
            return Ok(());
        }
        let Some(base) = memory.base else {
            return Err(CoreError::Decode(DecodeError {
                offset: self.error_offset,
                reason: DecodeReason::AbsoluteMemory,
            }));
        };
        self.mov(REG_TMP3, base)?;
        if let Some(index) = memory.index {
            self.mov(REG_TMP2, index)?;
            match memory.scale {
                1 => {}
                2 => self.shl_imm(REG_TMP2, 1)?,
                4 => self.shl_imm(REG_TMP2, 2)?,
                8 => self.shl_imm(REG_TMP2, 3)?,
                _ => {
                    return Err(CoreError::Decode(DecodeError {
                        offset: self.error_offset,
                        reason: DecodeReason::UnsupportedAddressing,
                    }));
                }
            }
            self.add(REG_TMP3, REG_TMP2)?;
        }
        if memory.disp != 0 {
            self.add_imm(REG_TMP3, u64::from_ne_bytes(memory.disp.to_ne_bytes()))?;
        }
        Ok(())
    }

    fn read_operand_into(&mut self, operand: Operand, width: Width, target: u8) -> Result<()> {
        match operand {
            Operand::Reg { index, .. } => {
                self.mov(target, index)?;
                self.apply_mask(target, width)
            }
            Operand::Imm { value, .. } => self.mov_imm(target, value & width.mask()),
            Operand::Mem(memory) => {
                self.compute_address(&memory, Some(width.bytes()))?;
                self.emit(IrOp::Load {
                    dst: target,
                    addr: REG_TMP3,
                    width,
                })
            }
            _ => Err(CoreError::Decode(DecodeError {
                offset: self.error_offset,
                reason: DecodeReason::UnsupportedForm,
            })),
        }
    }

    fn write_register(&mut self, dst: u8, width: Width, value: u8) -> Result<()> {
        if width == Width::W64 {
            if dst != value {
                self.mov(dst, value)?;
            }
            return Ok(());
        }
        if width == Width::W32 {
            self.apply_mask(value, Width::W32)?;
            if dst != value {
                self.mov(dst, value)?;
            }
            return Ok(());
        }
        self.apply_mask(value, width)?;
        let scratch = if REG_TMP3 != value && REG_TMP3 != dst {
            REG_TMP3
        } else if REG_TMP2 != value && REG_TMP2 != dst {
            REG_TMP2
        } else {
            REG_TMP1
        };
        self.mov(scratch, dst)?;
        self.and_imm(scratch, !width.mask())?;
        self.or(scratch, value)?;
        self.mov(dst, scratch)
    }

    fn write_operand(&mut self, operand: Operand, width: Width, value: u8) -> Result<()> {
        match operand {
            Operand::Reg { index, .. } => self.write_register(index, width, value),
            Operand::Mem(memory) => {
                if memory.rip_relative {
                    return Err(CoreError::Decode(DecodeError {
                        offset: self.error_offset,
                        reason: DecodeReason::RipRelativeMemory,
                    }));
                }
                if value != REG_TMP0 {
                    self.mov(REG_TMP0, value)?;
                }
                self.compute_address(&memory, None)?;
                self.emit(IrOp::Store {
                    addr: REG_TMP3,
                    src: REG_TMP0,
                    width,
                })
            }
            _ => Err(CoreError::Decode(DecodeError {
                offset: self.error_offset,
                reason: DecodeReason::UnsupportedForm,
            })),
        }
    }

    fn set_flags(
        &mut self,
        kind: FlagKind,
        width: Width,
        left: u8,
        right: u8,
        result: u8,
    ) -> Result<()> {
        self.cmp_eq(REG_ZF, result, REG_ZERO)?;
        self.mov(REG_SF, result)?;
        self.shr_u_imm(REG_SF, u64::from(width.sign_bit()))?;
        self.and_imm(REG_SF, 1)?;

        match kind {
            FlagKind::Add => {
                self.cmp_lt_u(REG_CF, result, left)?;
            }
            FlagKind::Sub => {
                self.cmp_lt_u(REG_CF, left, right)?;
            }
            FlagKind::Inc | FlagKind::Dec => {}
            FlagKind::Bitwise | FlagKind::Test => {
                self.mov_imm(REG_CF, 0)?;
            }
        }

        match kind {
            FlagKind::Bitwise | FlagKind::Test => {
                self.mov_imm(REG_OF, 0)?;
            }
            FlagKind::Add | FlagKind::Inc => {
                self.mov(REG_TMP3, left)?;
                self.xor(REG_TMP3, right)?;
                self.emit(IrOp::Not { dst: REG_TMP3 })?;
                self.mov(REG_TMP1, left)?;
                self.xor(REG_TMP1, result)?;
                self.and(REG_TMP3, REG_TMP1)?;
                self.shr_u_imm(REG_TMP3, u64::from(width.sign_bit()))?;
                self.and_imm(REG_TMP3, 1)?;
                self.mov(REG_OF, REG_TMP3)?;
            }
            FlagKind::Sub | FlagKind::Dec => {
                self.mov(REG_TMP3, left)?;
                self.xor(REG_TMP3, right)?;
                self.mov(REG_TMP1, left)?;
                self.xor(REG_TMP1, result)?;
                self.and(REG_TMP3, REG_TMP1)?;
                self.shr_u_imm(REG_TMP3, u64::from(width.sign_bit()))?;
                self.and_imm(REG_TMP3, 1)?;
                self.mov(REG_OF, REG_TMP3)?;
            }
        }
        Ok(())
    }

    const fn required_flags(condition: Condition) -> Option<u8> {
        match condition {
            Condition::Overflow | Condition::NoOverflow => Some(FLAG_OF),
            Condition::Below | Condition::AboveOrEqual => Some(FLAG_CF),
            Condition::Equal | Condition::NotEqual => Some(FLAG_ZF),
            Condition::BelowOrEqual | Condition::Above => Some(FLAG_CF | FLAG_ZF),
            Condition::Sign | Condition::NoSign => Some(FLAG_SF),
            Condition::Less | Condition::GreaterOrEqual => Some(FLAG_SF | FLAG_OF),
            Condition::LessOrEqual | Condition::Greater => Some(FLAG_SF | FLAG_OF | FLAG_ZF),
            Condition::Parity | Condition::NoParity => None,
        }
    }

    fn compute_condition(&mut self, condition: Condition, known: u8, offset: u64) -> Result<u8> {
        let required =
            Self::required_flags(condition).ok_or(CoreError::UnsupportedCondition { offset })?;
        if known & required != required {
            return Err(CoreError::UnknownFlags { offset });
        }
        match condition {
            Condition::Overflow => self.mov(REG_TMP0, REG_OF)?,
            Condition::NoOverflow => {
                self.mov(REG_TMP0, REG_OF)?;
                self.xor_imm(REG_TMP0, 1)?;
            }
            Condition::Below => self.mov(REG_TMP0, REG_CF)?,
            Condition::AboveOrEqual => {
                self.mov(REG_TMP0, REG_CF)?;
                self.xor_imm(REG_TMP0, 1)?;
            }
            Condition::Equal => self.mov(REG_TMP0, REG_ZF)?,
            Condition::NotEqual => {
                self.mov(REG_TMP0, REG_ZF)?;
                self.xor_imm(REG_TMP0, 1)?;
            }
            Condition::BelowOrEqual => {
                self.mov(REG_TMP0, REG_CF)?;
                self.or(REG_TMP0, REG_ZF)?;
            }
            Condition::Above => {
                self.mov(REG_TMP0, REG_CF)?;
                self.or(REG_TMP0, REG_ZF)?;
                self.xor_imm(REG_TMP0, 1)?;
            }
            Condition::Sign => self.mov(REG_TMP0, REG_SF)?,
            Condition::NoSign => {
                self.mov(REG_TMP0, REG_SF)?;
                self.xor_imm(REG_TMP0, 1)?;
            }
            Condition::Less => {
                self.mov(REG_TMP0, REG_SF)?;
                self.xor(REG_TMP0, REG_OF)?;
            }
            Condition::GreaterOrEqual => {
                self.mov(REG_TMP0, REG_SF)?;
                self.xor(REG_TMP0, REG_OF)?;
                self.xor_imm(REG_TMP0, 1)?;
            }
            Condition::LessOrEqual => {
                self.mov(REG_TMP0, REG_SF)?;
                self.xor(REG_TMP0, REG_OF)?;
                self.or(REG_TMP0, REG_ZF)?;
            }
            Condition::Greater => {
                self.mov(REG_TMP0, REG_SF)?;
                self.xor(REG_TMP0, REG_OF)?;
                self.or(REG_TMP0, REG_ZF)?;
                self.xor_imm(REG_TMP0, 1)?;
            }
            Condition::Parity | Condition::NoParity => {
                return Err(CoreError::UnsupportedCondition { offset });
            }
        }
        Ok(REG_TMP0)
    }

    fn lower_alu(&mut self, instruction: &Instruction, operation: Mnemonic) -> Result<()> {
        let width = instruction.width;
        self.read_operand_into(instruction.dst, width, REG_TMP0)?;
        self.read_operand_into(instruction.src, width, REG_TMP1)?;
        self.mov(REG_TMP2, REG_TMP0)?;
        let kind = match operation {
            Mnemonic::Add => {
                self.add(REG_TMP2, REG_TMP1)?;
                FlagKind::Add
            }
            Mnemonic::Sub => {
                self.sub(REG_TMP2, REG_TMP1)?;
                FlagKind::Sub
            }
            Mnemonic::And => {
                self.and(REG_TMP2, REG_TMP1)?;
                FlagKind::Bitwise
            }
            Mnemonic::Or => {
                self.or(REG_TMP2, REG_TMP1)?;
                FlagKind::Bitwise
            }
            Mnemonic::Xor => {
                self.xor(REG_TMP2, REG_TMP1)?;
                FlagKind::Bitwise
            }
            _ => {
                return Err(CoreError::Decode(DecodeError {
                    offset: instruction.offset,
                    reason: DecodeReason::UnsupportedForm,
                }));
            }
        };
        self.apply_mask(REG_TMP2, width)?;
        self.set_flags(kind, width, REG_TMP0, REG_TMP1, REG_TMP2)?;
        self.write_operand(instruction.dst, width, REG_TMP2)
    }

    const fn xmm_low(index: u8) -> u8 {
        REG_XMM_BASE.saturating_add(index.saturating_mul(2))
    }

    const fn xmm_high(index: u8) -> u8 {
        Self::xmm_low(index).saturating_add(1)
    }

    fn read_sse_scratch(&mut self, operand: Operand) -> Result<()> {
        match operand {
            Operand::Xmm { index } => {
                self.mov(REG_TMP0, Self::xmm_low(index))?;
                self.mov(REG_TMP1, Self::xmm_high(index))
            }
            Operand::Mem(memory) => {
                self.compute_address(&memory, Some(16))?;
                self.emit(IrOp::Load {
                    dst: REG_TMP0,
                    addr: REG_TMP3,
                    width: Width::W64,
                })?;
                self.add_imm(REG_TMP3, 8)?;
                self.emit(IrOp::Load {
                    dst: REG_TMP1,
                    addr: REG_TMP3,
                    width: Width::W64,
                })
            }
            _ => Err(CoreError::Decode(DecodeError {
                offset: self.error_offset,
                reason: DecodeReason::UnsupportedForm,
            })),
        }
    }

    fn write_sse_value(&mut self, operand: Operand, index: u8) -> Result<()> {
        match operand {
            Operand::Xmm { index: target } => {
                self.mov(Self::xmm_low(target), Self::xmm_low(index))?;
                self.mov(Self::xmm_high(target), Self::xmm_high(index))
            }
            Operand::Mem(memory) => {
                if memory.rip_relative {
                    return Err(CoreError::Decode(DecodeError {
                        offset: self.error_offset,
                        reason: DecodeReason::RipRelativeMemory,
                    }));
                }
                self.compute_address(&memory, None)?;
                self.emit(IrOp::Store {
                    addr: REG_TMP3,
                    src: Self::xmm_low(index),
                    width: Width::W64,
                })?;
                self.add_imm(REG_TMP3, 8)?;
                self.emit(IrOp::Store {
                    addr: REG_TMP3,
                    src: Self::xmm_high(index),
                    width: Width::W64,
                })
            }
            _ => Err(CoreError::Decode(DecodeError {
                offset: self.error_offset,
                reason: DecodeReason::UnsupportedForm,
            })),
        }
    }

    fn lower_sse_lane32(&mut self, index: u8, subtract: bool) -> Result<()> {
        let halves = [Self::xmm_low(index), Self::xmm_high(index)];
        let sources = [REG_TMP0, REG_TMP1];
        for (half, source) in halves.into_iter().zip(sources) {
            self.mov(REG_TMP2, half)?;
            self.and_imm(REG_TMP2, 0xffff_ffff)?;
            self.mov(REG_TMP3, source)?;
            self.and_imm(REG_TMP3, 0xffff_ffff)?;
            if subtract {
                self.sub(REG_TMP2, REG_TMP3)?;
            } else {
                self.add(REG_TMP2, REG_TMP3)?;
            }
            self.and_imm(REG_TMP2, 0xffff_ffff)?;
            self.mov(REG_TMP3, half)?;
            self.shr_u_imm(REG_TMP3, 32)?;
            self.and_imm(REG_TMP3, 0xffff_ffff)?;
            self.shr_u_imm(source, 32)?;
            self.and_imm(source, 0xffff_ffff)?;
            if subtract {
                self.sub(REG_TMP3, source)?;
            } else {
                self.add(REG_TMP3, source)?;
            }
            self.and_imm(REG_TMP3, 0xffff_ffff)?;
            self.shl_imm(REG_TMP3, 32)?;
            self.or(REG_TMP2, REG_TMP3)?;
            self.mov(half, REG_TMP2)?;
        }
        Ok(())
    }

    fn lower_sse_pmuludq(&mut self, index: u8) -> Result<()> {
        let halves = [Self::xmm_low(index), Self::xmm_high(index)];
        let sources = [REG_TMP0, REG_TMP1];
        for (half, source) in halves.into_iter().zip(sources) {
            self.mov(REG_TMP2, half)?;
            self.and_imm(REG_TMP2, 0xffff_ffff)?;
            self.mov(REG_TMP3, source)?;
            self.and_imm(REG_TMP3, 0xffff_ffff)?;
            self.emit(IrOp::Mul {
                dst: REG_TMP2,
                src: REG_TMP3,
            })?;
            self.mov(half, REG_TMP2)?;
        }
        Ok(())
    }

    fn lower_sse_punpck(&mut self, index: u8, high: bool) -> Result<()> {
        let low = Self::xmm_low(index);
        let top = Self::xmm_high(index);
        if high {
            self.mov(REG_TMP2, top)?;
            self.mov(low, REG_TMP2)?;
            self.mov(top, REG_TMP1)
        } else {
            self.mov(top, REG_TMP0)
        }
    }

    fn lower_sse_movq_load(&mut self, instruction: &Instruction) -> Result<()> {
        let Operand::Xmm { index } = instruction.dst else {
            return Err(CoreError::Decode(DecodeError {
                offset: self.error_offset,
                reason: DecodeReason::UnsupportedForm,
            }));
        };
        let low = Self::xmm_low(index);
        let top = Self::xmm_high(index);
        match instruction.src {
            Operand::Xmm { index: source } => {
                self.mov(low, Self::xmm_low(source))?;
                self.mov_imm(top, 0)
            }
            Operand::Mem(memory) => {
                self.compute_address(&memory, Some(8))?;
                self.emit(IrOp::Load {
                    dst: low,
                    addr: REG_TMP3,
                    width: Width::W64,
                })?;
                self.mov_imm(top, 0)
            }
            _ => Err(CoreError::Decode(DecodeError {
                offset: self.error_offset,
                reason: DecodeReason::UnsupportedForm,
            })),
        }
    }

    fn lower_sse_movq_store(&mut self, instruction: &Instruction) -> Result<()> {
        let Operand::Xmm { index } = instruction.src else {
            return Err(CoreError::Decode(DecodeError {
                offset: self.error_offset,
                reason: DecodeReason::UnsupportedForm,
            }));
        };
        let low = Self::xmm_low(index);
        match instruction.dst {
            Operand::Xmm { index: target } => {
                self.mov(Self::xmm_low(target), low)?;
                self.mov_imm(Self::xmm_high(target), 0)
            }
            Operand::Mem(memory) => {
                if memory.rip_relative {
                    return Err(CoreError::Decode(DecodeError {
                        offset: self.error_offset,
                        reason: DecodeReason::RipRelativeMemory,
                    }));
                }
                self.compute_address(&memory, None)?;
                self.emit(IrOp::Store {
                    addr: REG_TMP3,
                    src: low,
                    width: Width::W64,
                })
            }
            _ => Err(CoreError::Decode(DecodeError {
                offset: self.error_offset,
                reason: DecodeReason::UnsupportedForm,
            })),
        }
    }

    fn lower_sse_shift(&mut self, index: u8, shift: u8, left: bool) -> Result<()> {
        let low = Self::xmm_low(index);
        let high = Self::xmm_high(index);
        if shift >= 16 {
            self.mov_imm(low, 0)?;
            self.mov_imm(high, 0)?;
            return Ok(());
        }
        if shift == 0 {
            return Ok(());
        }
        let bits = u64::from(shift).saturating_mul(8);
        if left {
            if shift < 8 {
                self.mov(REG_TMP0, high)?;
                self.shl_imm(REG_TMP0, bits)?;
                self.mov(REG_TMP1, low)?;
                self.shr_u_imm(REG_TMP1, 64_u64.saturating_sub(bits))?;
                self.or(REG_TMP0, REG_TMP1)?;
                self.shl_imm(low, bits)?;
            } else {
                self.mov(REG_TMP0, low)?;
                self.shl_imm(
                    REG_TMP0,
                    u64::from(shift.saturating_sub(8)).saturating_mul(8),
                )?;
                self.mov_imm(low, 0)?;
            }
            self.mov(high, REG_TMP0)
        } else if shift < 8 {
            self.mov(REG_TMP0, low)?;
            self.shr_u_imm(REG_TMP0, bits)?;
            self.mov(REG_TMP1, high)?;
            self.shl_imm(REG_TMP1, 64_u64.saturating_sub(bits))?;
            self.or(REG_TMP0, REG_TMP1)?;
            self.shr_u_imm(high, bits)?;
            self.mov(low, REG_TMP0)
        } else {
            self.mov(REG_TMP0, high)?;
            self.shr_u_imm(
                REG_TMP0,
                u64::from(shift.saturating_sub(8)).saturating_mul(8),
            )?;
            self.mov(low, REG_TMP0)?;
            self.mov_imm(high, 0)
        }
    }

    fn lower_sse_movq_to_gpr(&mut self, instruction: &Instruction) -> Result<()> {
        let Operand::Xmm { index } = instruction.src else {
            return Err(CoreError::Decode(DecodeError {
                offset: self.error_offset,
                reason: DecodeReason::UnsupportedForm,
            }));
        };
        self.mov(REG_TMP0, Self::xmm_low(index))?;
        match instruction.dst {
            Operand::Reg { index: dst, .. } => {
                self.write_register(dst, instruction.width, REG_TMP0)
            }
            Operand::Mem(_) => self.write_operand(instruction.dst, instruction.width, REG_TMP0),
            _ => Err(CoreError::Decode(DecodeError {
                offset: self.error_offset,
                reason: DecodeReason::UnsupportedForm,
            })),
        }
    }

    fn lower_sse_movq_from_gpr(&mut self, instruction: &Instruction) -> Result<()> {
        let Operand::Xmm { index } = instruction.dst else {
            return Err(CoreError::Decode(DecodeError {
                offset: self.error_offset,
                reason: DecodeReason::UnsupportedForm,
            }));
        };
        self.read_operand_into(instruction.src, instruction.width, REG_TMP0)?;
        self.mov(Self::xmm_low(index), REG_TMP0)?;
        self.mov_imm(Self::xmm_high(index), 0)
    }

    fn lower_sse(
        &mut self,
        instruction: &Instruction,
        operation: SseOp,
    ) -> Result<Option<Terminator>> {
        match operation {
            SseOp::MovdquLoad | SseOp::MovdqaLoad => {
                let Operand::Xmm { index } = instruction.dst else {
                    return Err(CoreError::Decode(DecodeError {
                        offset: self.error_offset,
                        reason: DecodeReason::UnsupportedForm,
                    }));
                };
                match instruction.src {
                    Operand::Xmm { index: source } => {
                        self.mov(Self::xmm_low(index), Self::xmm_low(source))?;
                        self.mov(Self::xmm_high(index), Self::xmm_high(source))?;
                    }
                    Operand::Mem(memory) => {
                        self.compute_address(&memory, Some(16))?;
                        self.emit(IrOp::Load {
                            dst: Self::xmm_low(index),
                            addr: REG_TMP3,
                            width: Width::W64,
                        })?;
                        self.add_imm(REG_TMP3, 8)?;
                        self.emit(IrOp::Load {
                            dst: Self::xmm_high(index),
                            addr: REG_TMP3,
                            width: Width::W64,
                        })?;
                    }
                    _ => {
                        return Err(CoreError::Decode(DecodeError {
                            offset: self.error_offset,
                            reason: DecodeReason::UnsupportedForm,
                        }));
                    }
                }
            }
            SseOp::MovdquStore | SseOp::MovdqaStore => {
                let Operand::Xmm { index } = instruction.src else {
                    return Err(CoreError::Decode(DecodeError {
                        offset: self.error_offset,
                        reason: DecodeReason::UnsupportedForm,
                    }));
                };
                self.write_sse_value(instruction.dst, index)?;
            }
            SseOp::Pxor | SseOp::Pand | SseOp::Por | SseOp::Paddq | SseOp::Psubq => {
                let Operand::Xmm { index } = instruction.dst else {
                    return Err(CoreError::Decode(DecodeError {
                        offset: self.error_offset,
                        reason: DecodeReason::UnsupportedForm,
                    }));
                };
                self.read_sse_scratch(instruction.src)?;
                let low = Self::xmm_low(index);
                let high = Self::xmm_high(index);
                match operation {
                    SseOp::Pxor => {
                        self.xor(low, REG_TMP0)?;
                        self.xor(high, REG_TMP1)?;
                    }
                    SseOp::Pand => {
                        self.and(low, REG_TMP0)?;
                        self.and(high, REG_TMP1)?;
                    }
                    SseOp::Por => {
                        self.or(low, REG_TMP0)?;
                        self.or(high, REG_TMP1)?;
                    }
                    SseOp::Paddq => {
                        self.add(low, REG_TMP0)?;
                        self.add(high, REG_TMP1)?;
                    }
                    SseOp::Psubq => {
                        self.sub(low, REG_TMP0)?;
                        self.sub(high, REG_TMP1)?;
                    }
                    SseOp::MovdquLoad
                    | SseOp::MovdquStore
                    | SseOp::MovdqaLoad
                    | SseOp::MovdqaStore
                    | SseOp::Psrldq { .. }
                    | SseOp::Pslldq { .. }
                    | SseOp::MovqToGpr
                    | SseOp::MovqFromGpr
                    | SseOp::Paddd
                    | SseOp::Psubd
                    | SseOp::Pmuludq
                    | SseOp::Punpcklqdq
                    | SseOp::Punpckhqdq
                    | SseOp::MovqLoad
                    | SseOp::MovqStore => {
                        return Err(CoreError::Decode(DecodeError {
                            offset: self.error_offset,
                            reason: DecodeReason::UnsupportedForm,
                        }));
                    }
                }
            }
            SseOp::Paddd | SseOp::Psubd => {
                let Operand::Xmm { index } = instruction.dst else {
                    return Err(CoreError::Decode(DecodeError {
                        offset: self.error_offset,
                        reason: DecodeReason::UnsupportedForm,
                    }));
                };
                self.read_sse_scratch(instruction.src)?;
                self.lower_sse_lane32(index, matches!(operation, SseOp::Psubd))?;
            }
            SseOp::Pmuludq => {
                let Operand::Xmm { index } = instruction.dst else {
                    return Err(CoreError::Decode(DecodeError {
                        offset: self.error_offset,
                        reason: DecodeReason::UnsupportedForm,
                    }));
                };
                self.read_sse_scratch(instruction.src)?;
                self.lower_sse_pmuludq(index)?;
            }
            SseOp::Punpcklqdq | SseOp::Punpckhqdq => {
                let Operand::Xmm { index } = instruction.dst else {
                    return Err(CoreError::Decode(DecodeError {
                        offset: self.error_offset,
                        reason: DecodeReason::UnsupportedForm,
                    }));
                };
                self.read_sse_scratch(instruction.src)?;
                self.lower_sse_punpck(index, matches!(operation, SseOp::Punpckhqdq))?;
            }
            SseOp::MovqLoad => self.lower_sse_movq_load(instruction)?,
            SseOp::MovqStore => self.lower_sse_movq_store(instruction)?,
            SseOp::Psrldq { shift } => {
                let Operand::Xmm { index } = instruction.dst else {
                    return Err(CoreError::Decode(DecodeError {
                        offset: self.error_offset,
                        reason: DecodeReason::UnsupportedForm,
                    }));
                };
                self.lower_sse_shift(index, shift, false)?;
            }
            SseOp::Pslldq { shift } => {
                let Operand::Xmm { index } = instruction.dst else {
                    return Err(CoreError::Decode(DecodeError {
                        offset: self.error_offset,
                        reason: DecodeReason::UnsupportedForm,
                    }));
                };
                self.lower_sse_shift(index, shift, true)?;
            }
            SseOp::MovqToGpr => self.lower_sse_movq_to_gpr(instruction)?,
            SseOp::MovqFromGpr => self.lower_sse_movq_from_gpr(instruction)?,
        }
        Ok(None)
    }

    fn lower_instruction(
        &mut self,
        instruction: &Instruction,
        known: &mut u8,
    ) -> Result<Option<Terminator>> {
        self.error_offset = instruction.offset;
        match instruction.mnemonic {
            Mnemonic::Nop | Mnemonic::Endbr => Ok(None),
            Mnemonic::Sse(operation) => self.lower_sse(instruction, operation),
            Mnemonic::Mov => {
                let width = instruction.width;
                self.read_operand_into(instruction.src, width, REG_TMP0)?;
                self.write_operand(instruction.dst, width, REG_TMP0)?;
                Ok(None)
            }
            Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd => {
                let source_width =
                    operand_width(instruction.src).ok_or(CoreError::Decode(DecodeError {
                        offset: instruction.offset,
                        reason: DecodeReason::UnsupportedForm,
                    }))?;
                self.read_operand_into(instruction.src, source_width, REG_TMP0)?;
                if instruction.mnemonic != Mnemonic::Movzx {
                    self.sign_extend(REG_TMP0, source_width.bits())?;
                }
                match instruction.dst {
                    Operand::Reg { index, .. } => {
                        self.write_register(index, instruction.width, REG_TMP0)?;
                        Ok(None)
                    }
                    _ => Err(CoreError::Decode(DecodeError {
                        offset: instruction.offset,
                        reason: DecodeReason::UnsupportedForm,
                    })),
                }
            }
            Mnemonic::Lea => {
                let Operand::Mem(memory) = instruction.src else {
                    return Err(CoreError::Decode(DecodeError {
                        offset: instruction.offset,
                        reason: DecodeReason::UnsupportedForm,
                    }));
                };
                self.compute_address(&memory, None)?;
                match instruction.dst {
                    Operand::Reg { index, .. } => {
                        self.write_register(index, instruction.width, REG_TMP3)?;
                        Ok(None)
                    }
                    _ => Err(CoreError::Decode(DecodeError {
                        offset: instruction.offset,
                        reason: DecodeReason::UnsupportedForm,
                    })),
                }
            }
            Mnemonic::Add | Mnemonic::Sub | Mnemonic::And | Mnemonic::Or | Mnemonic::Xor => {
                self.lower_alu(instruction, instruction.mnemonic)?;
                *known |= FLAG_ALL;
                Ok(None)
            }
            Mnemonic::Cmp => {
                self.read_operand_into(instruction.dst, instruction.width, REG_TMP0)?;
                self.read_operand_into(instruction.src, instruction.width, REG_TMP1)?;
                self.mov(REG_TMP2, REG_TMP0)?;
                self.sub(REG_TMP2, REG_TMP1)?;
                self.apply_mask(REG_TMP2, instruction.width)?;
                self.set_flags(
                    FlagKind::Sub,
                    instruction.width,
                    REG_TMP0,
                    REG_TMP1,
                    REG_TMP2,
                )?;
                *known |= FLAG_ALL;
                Ok(None)
            }
            Mnemonic::Test => {
                self.read_operand_into(instruction.dst, instruction.width, REG_TMP0)?;
                self.read_operand_into(instruction.src, instruction.width, REG_TMP1)?;
                self.mov(REG_TMP2, REG_TMP0)?;
                self.and(REG_TMP2, REG_TMP1)?;
                self.apply_mask(REG_TMP2, instruction.width)?;
                self.set_flags(
                    FlagKind::Test,
                    instruction.width,
                    REG_TMP0,
                    REG_TMP1,
                    REG_TMP2,
                )?;
                *known |= FLAG_ALL;
                Ok(None)
            }
            Mnemonic::Inc | Mnemonic::Dec => {
                let width = instruction.width;
                self.read_operand_into(instruction.dst, width, REG_TMP0)?;
                self.mov(REG_TMP1, REG_ONE)?;
                self.apply_mask(REG_TMP1, width)?;
                self.mov(REG_TMP2, REG_TMP0)?;
                if instruction.mnemonic == Mnemonic::Inc {
                    self.add(REG_TMP2, REG_TMP1)?;
                } else {
                    self.sub(REG_TMP2, REG_TMP1)?;
                }
                self.apply_mask(REG_TMP2, width)?;
                if instruction.mnemonic == Mnemonic::Inc {
                    self.set_flags(FlagKind::Inc, width, REG_TMP0, REG_TMP1, REG_TMP2)?;
                } else {
                    self.set_flags(FlagKind::Dec, width, REG_TMP0, REG_TMP1, REG_TMP2)?;
                }
                self.write_operand(instruction.dst, width, REG_TMP2)?;
                *known = (*known & FLAG_CF) | FLAG_ZF | FLAG_SF | FLAG_OF;
                Ok(None)
            }
            Mnemonic::Neg => {
                let width = instruction.width;
                self.read_operand_into(instruction.dst, width, REG_TMP0)?;
                self.mov(REG_TMP2, REG_ZERO)?;
                self.sub(REG_TMP2, REG_TMP0)?;
                self.apply_mask(REG_TMP2, width)?;
                self.set_flags(FlagKind::Sub, width, REG_ZERO, REG_TMP0, REG_TMP2)?;
                self.write_operand(instruction.dst, width, REG_TMP2)?;
                *known |= FLAG_ALL;
                Ok(None)
            }
            Mnemonic::Not => {
                self.read_operand_into(instruction.dst, instruction.width, REG_TMP0)?;
                self.emit(IrOp::Not { dst: REG_TMP0 })?;
                self.write_operand(instruction.dst, instruction.width, REG_TMP0)?;
                Ok(None)
            }
            Mnemonic::Imul => {
                let width = instruction.width;
                let has_immediate = matches!(instruction.aux, Operand::Imm { .. });
                if has_immediate {
                    self.read_operand_into(instruction.src, width, REG_TMP0)?;
                    self.read_operand_into(instruction.aux, width, REG_TMP1)?;
                } else {
                    self.read_operand_into(instruction.dst, width, REG_TMP0)?;
                    self.read_operand_into(instruction.src, width, REG_TMP1)?;
                }
                self.mov(REG_TMP2, REG_TMP0)?;
                self.emit(IrOp::Mul {
                    dst: REG_TMP2,
                    src: REG_TMP1,
                })?;
                self.apply_mask(REG_TMP2, width)?;
                self.write_operand(instruction.dst, width, REG_TMP2)?;
                *known = 0;
                Ok(None)
            }
            Mnemonic::Shl | Mnemonic::Shr | Mnemonic::Sar | Mnemonic::Rol | Mnemonic::Ror => {
                let width = instruction.width;
                self.read_operand_into(instruction.dst, width, REG_TMP0)?;
                self.mov(REG_TMP2, REG_TMP0)?;
                if let Operand::Imm { value, .. } = instruction.src {
                    match instruction.mnemonic {
                        Mnemonic::Shl => self.shl_imm(REG_TMP2, value)?,
                        Mnemonic::Shr => self.shr_u_imm(REG_TMP2, value)?,
                        Mnemonic::Sar => self.emit(IrOp::ShrSImm {
                            dst: REG_TMP2,
                            value,
                        })?,
                        Mnemonic::Rol => self.emit(IrOp::RotLImm {
                            dst: REG_TMP2,
                            value,
                        })?,
                        _ => self.emit(IrOp::RotRImm {
                            dst: REG_TMP2,
                            value,
                        })?,
                    }
                } else {
                    self.read_operand_into(instruction.src, Width::W8, REG_TMP1)?;
                    match instruction.mnemonic {
                        Mnemonic::Shl => self.emit(IrOp::Shl {
                            dst: REG_TMP2,
                            src: REG_TMP1,
                        })?,
                        Mnemonic::Shr => self.emit(IrOp::ShrU {
                            dst: REG_TMP2,
                            src: REG_TMP1,
                        })?,
                        Mnemonic::Sar => self.emit(IrOp::ShrS {
                            dst: REG_TMP2,
                            src: REG_TMP1,
                        })?,
                        Mnemonic::Rol => self.emit(IrOp::RotL {
                            dst: REG_TMP2,
                            src: REG_TMP1,
                        })?,
                        _ => self.emit(IrOp::RotR {
                            dst: REG_TMP2,
                            src: REG_TMP1,
                        })?,
                    }
                }
                self.apply_mask(REG_TMP2, width)?;
                self.write_operand(instruction.dst, width, REG_TMP2)?;
                *known = 0;
                Ok(None)
            }
            Mnemonic::Push => {
                self.read_operand_into(instruction.dst, Width::W64, REG_TMP0)?;
                self.sub_imm(REG_RSP, 8)?;
                self.emit(IrOp::Store {
                    addr: REG_RSP,
                    src: REG_TMP0,
                    width: Width::W64,
                })?;
                Ok(None)
            }
            Mnemonic::Pop => {
                let Operand::Reg { index, .. } = instruction.dst else {
                    return Err(CoreError::Decode(DecodeError {
                        offset: instruction.offset,
                        reason: DecodeReason::UnsupportedForm,
                    }));
                };
                self.emit(IrOp::Load {
                    dst: REG_TMP0,
                    addr: REG_RSP,
                    width: Width::W64,
                })?;
                self.add_imm(REG_RSP, 8)?;
                self.write_register(index, Width::W64, REG_TMP0)?;
                Ok(None)
            }
            Mnemonic::Leave => {
                self.mov(REG_RSP, REG_RBP)?;
                self.emit(IrOp::Load {
                    dst: REG_RBP,
                    addr: REG_RSP,
                    width: Width::W64,
                })?;
                self.add_imm(REG_RSP, 8)?;
                Ok(None)
            }
            Mnemonic::Cdqe => {
                self.read_operand_into(
                    Operand::Reg {
                        index: REG_RAX,
                        width: Width::W32,
                    },
                    Width::W32,
                    REG_TMP0,
                )?;
                self.sign_extend(REG_TMP0, 32)?;
                self.write_register(REG_RAX, Width::W64, REG_TMP0)?;
                Ok(None)
            }
            Mnemonic::Cmov(condition) => {
                let Operand::Reg { index, .. } = instruction.dst else {
                    return Err(CoreError::Decode(DecodeError {
                        offset: instruction.offset,
                        reason: DecodeReason::UnsupportedForm,
                    }));
                };
                let condition_register =
                    self.compute_condition(condition, *known, instruction.offset)?;
                self.read_operand_into(instruction.src, instruction.width, REG_TMP1)?;
                self.mov(REG_TMP2, index)?;
                self.emit(IrOp::Select {
                    dst: REG_TMP2,
                    cond: condition_register,
                    when_true: REG_TMP1,
                    when_false: REG_TMP2,
                })?;
                self.mov(index, REG_TMP2)?;
                Ok(None)
            }
            Mnemonic::Setcc(condition) => {
                let Operand::Reg { index, .. } = instruction.dst else {
                    return Err(CoreError::Decode(DecodeError {
                        offset: instruction.offset,
                        reason: DecodeReason::UnsupportedForm,
                    }));
                };
                let condition_register =
                    self.compute_condition(condition, *known, instruction.offset)?;
                self.mov(REG_TMP1, index)?;
                self.and_imm(REG_TMP1, !0xff)?;
                self.or(REG_TMP1, condition_register)?;
                self.mov(index, REG_TMP1)?;
                Ok(None)
            }
            Mnemonic::Jmp => {
                let Some(target) = instruction.target else {
                    return Err(CoreError::InvalidBranchTarget {
                        offset: instruction.offset,
                        target: instruction.offset,
                    });
                };
                let target_index = self.branch_target(target, instruction.offset)?;
                Ok(Some(Terminator::Jump {
                    target: target_index,
                }))
            }
            Mnemonic::Jcc(condition) => {
                let condition_register =
                    self.compute_condition(condition, *known, instruction.offset)?;
                let Some(target) = instruction.target else {
                    return Err(CoreError::InvalidBranchTarget {
                        offset: instruction.offset,
                        target: instruction.offset,
                    });
                };
                let true_index = self.branch_target(target, instruction.offset)?;
                let fallthrough = self
                    .base_va
                    .checked_add(
                        instruction
                            .offset
                            .checked_sub(self.base_va)
                            .ok_or(CoreError::ArithmeticOverflow)?
                            .checked_add(u64::from(instruction.length))
                            .ok_or(CoreError::ArithmeticOverflow)?,
                    )
                    .ok_or(CoreError::ArithmeticOverflow)?;
                let false_index = self.branch_target(fallthrough, instruction.offset)?;
                Ok(Some(Terminator::Branch {
                    cond: condition_register,
                    when_true: true_index,
                    when_false: false_index,
                }))
            }
            Mnemonic::Ret => Ok(Some(Terminator::Return { value: REG_RAX })),
        }
    }

    fn branch_target(&self, target: u64, offset: u64) -> Result<u16> {
        let relative = target
            .checked_sub(self.base_va)
            .ok_or(CoreError::InvalidBranchTarget { offset, target })?;
        let relative = usize::try_from(relative)
            .map_err(|_| CoreError::InvalidBranchTarget { offset, target })?;
        if relative >= self.code_len {
            return Err(CoreError::InvalidBranchTarget { offset, target });
        }
        let wanted = u32::try_from(relative)
            .map_err(|_| CoreError::InvalidBranchTarget { offset, target })?;
        let mut index = 0_usize;
        while index < self.leaders.len() {
            if self.leaders.get(index) == Some(&wanted) {
                return u16::try_from(index)
                    .map_err(|_| CoreError::InvalidBlock { block: u16::MAX });
            }
            index = index.saturating_add(1);
        }
        Err(CoreError::InvalidBranchTarget { offset, target })
    }

    fn add_leader(&mut self, relative: usize) -> Result<()> {
        if relative >= self.code_len {
            return Err(CoreError::InvalidFunctionSize {
                size: u64::try_from(relative).unwrap_or(u64::MAX),
            });
        }
        let value = u32::try_from(relative).map_err(|_| CoreError::ArithmeticOverflow)?;
        if !self.leaders.contains(&value) {
            self.leaders
                .insert_sorted_by(value, |left, right| left < right)?;
        }
        Ok(())
    }

    fn relative_target(&self, target: u64, offset: u64) -> Result<usize> {
        let relative = target
            .checked_sub(self.base_va)
            .ok_or(CoreError::InvalidBranchTarget { offset, target })?;
        let relative = usize::try_from(relative)
            .map_err(|_| CoreError::InvalidBranchTarget { offset, target })?;
        if relative >= self.code_len {
            return Err(CoreError::InvalidBranchTarget { offset, target });
        }
        Ok(relative)
    }

    fn discover(&mut self, code: &[u8]) -> Result<()> {
        let mut owners = [u16::MAX; MAX_FUNCTION_BYTES];
        let mut queue = BoundedVec::<u32, MAX_QUEUE>::new();
        self.add_leader(0)?;
        queue.push(0)?;
        let mut decoded_count = 0_usize;
        while let Some(start_value) = queue.pop() {
            let start = usize::try_from(start_value).map_err(|_| CoreError::ArithmeticOverflow)?;
            let mut cursor = start;
            loop {
                if cursor >= self.code_len {
                    return Err(CoreError::MissingTerminator {
                        offset: self
                            .base_va
                            .wrapping_add(u64::try_from(cursor).unwrap_or(u64::MAX)),
                    });
                }
                if cursor != start {
                    let current =
                        u32::try_from(cursor).map_err(|_| CoreError::ArithmeticOverflow)?;
                    if self.leaders.contains(&current) {
                        break;
                    }
                }
                if let Some(owner) = owners.get(cursor).copied() {
                    if owner != u16::MAX {
                        if usize::from(owner) == cursor {
                            break;
                        }
                        return Err(CoreError::OverlappingInstruction {
                            offset: self
                                .base_va
                                .wrapping_add(u64::try_from(cursor).unwrap_or(u64::MAX)),
                        });
                    }
                } else {
                    return Err(CoreError::ArithmeticOverflow);
                }
                let slice = code.get(cursor..).ok_or(CoreError::MalformedBinary)?;
                let instruction = decode(
                    slice,
                    self.base_va
                        .wrapping_add(u64::try_from(cursor).unwrap_or(u64::MAX)),
                )?;
                self.current_va = instruction.offset;
                self.current_len = instruction.length;
                let length = usize::from(instruction.length);
                let end = cursor
                    .checked_add(length)
                    .ok_or(CoreError::ArithmeticOverflow)?;
                if end > self.code_len {
                    return Err(CoreError::Decode(DecodeError {
                        offset: instruction.offset,
                        reason: DecodeReason::Truncated,
                    }));
                }
                let mut mark = cursor;
                while mark < end {
                    let owner = owners.get_mut(mark).ok_or(CoreError::ArithmeticOverflow)?;
                    if *owner != u16::MAX && usize::from(*owner) != cursor {
                        return Err(CoreError::OverlappingInstruction {
                            offset: self
                                .base_va
                                .wrapping_add(u64::try_from(mark).unwrap_or(u64::MAX)),
                        });
                    }
                    *owner = u16::try_from(cursor).map_err(|_| CoreError::ArithmeticOverflow)?;
                    mark = mark.saturating_add(1);
                }
                decoded_count = decoded_count.saturating_add(1);
                if decoded_count > INSTRUCTION_LIMIT {
                    return Err(CoreError::CapacityExceeded);
                }
                match instruction.mnemonic {
                    Mnemonic::Jcc(_) => {
                        let target = instruction.target.ok_or(CoreError::InvalidBranchTarget {
                            offset: instruction.offset,
                            target: instruction.offset,
                        })?;
                        let target_relative = self.relative_target(target, instruction.offset)?;
                        if end >= self.code_len {
                            return Err(CoreError::InvalidBranchTarget {
                                offset: instruction.offset,
                                target: self
                                    .base_va
                                    .wrapping_add(u64::try_from(end).unwrap_or(u64::MAX)),
                            });
                        }
                        self.add_leader(target_relative)?;
                        self.add_leader(end)?;
                        queue.push(
                            u32::try_from(target_relative)
                                .map_err(|_| CoreError::ArithmeticOverflow)?,
                        )?;
                        queue
                            .push(u32::try_from(end).map_err(|_| CoreError::ArithmeticOverflow)?)?;
                        break;
                    }
                    Mnemonic::Jmp => {
                        let target = instruction.target.ok_or(CoreError::InvalidBranchTarget {
                            offset: instruction.offset,
                            target: instruction.offset,
                        })?;
                        let target_relative = self.relative_target(target, instruction.offset)?;
                        self.add_leader(target_relative)?;
                        queue.push(
                            u32::try_from(target_relative)
                                .map_err(|_| CoreError::ArithmeticOverflow)?,
                        )?;
                        break;
                    }
                    Mnemonic::Ret => break,
                    _ => {
                        cursor = end;
                    }
                }
            }
        }
        self.leaders.sort_unstable_by(|left, right| left < right);
        self.leaders.dedup();
        let mut index = 0_usize;
        while index < self.leaders.len() {
            let Some(value) = self.leaders.get(index).copied() else {
                return Err(CoreError::ArithmeticOverflow);
            };
            let relative = usize::try_from(value).map_err(|_| CoreError::ArithmeticOverflow)?;
            let Some(owner) = owners.get(relative).copied() else {
                return Err(CoreError::ArithmeticOverflow);
            };
            if owner == u16::MAX || usize::from(owner) != relative {
                return Err(CoreError::InvalidBranchTarget {
                    offset: self
                        .base_va
                        .wrapping_add(u64::try_from(relative).unwrap_or(u64::MAX)),
                    target: self
                        .base_va
                        .wrapping_add(u64::try_from(relative).unwrap_or(u64::MAX)),
                });
            }
            index = index.saturating_add(1);
        }
        Ok(())
    }

    fn build(&mut self, code: &[u8]) -> Result<()> {
        let count = self.leaders.len();
        let mut block_index = 0_usize;
        while block_index < count {
            let start_value = self
                .leaders
                .get(block_index)
                .copied()
                .ok_or(CoreError::ArithmeticOverflow)?;
            let start = usize::try_from(start_value).map_err(|_| CoreError::ArithmeticOverflow)?;
            let limit = match self.leaders.get(block_index.saturating_add(1)).copied() {
                Some(next) => usize::try_from(next).map_err(|_| CoreError::ArithmeticOverflow)?,
                None => self.code_len,
            };
            let ops_start = self.ops.len();
            if block_index == 0 {
                self.mov_imm(REG_ZERO, 0)?;
                self.mov_imm(REG_ONE, 1)?;
                self.mov_imm(REG_ZF, 0)?;
                self.mov_imm(REG_CF, 0)?;
                self.mov_imm(REG_SF, 0)?;
                self.mov_imm(REG_OF, 0)?;
            }
            let mut flags_known = 0_u8;
            let mut cursor = start;
            let terminator = loop {
                if cursor == limit {
                    if block_index.saturating_add(1) < count {
                        let target = u16::try_from(block_index.saturating_add(1))
                            .map_err(|_| CoreError::InvalidBlock { block: u16::MAX })?;
                        break Terminator::Jump { target };
                    }
                    return Err(CoreError::MissingTerminator {
                        offset: self
                            .base_va
                            .wrapping_add(u64::try_from(cursor).unwrap_or(u64::MAX)),
                    });
                }
                if cursor > limit {
                    return Err(CoreError::OverlappingInstruction {
                        offset: self
                            .base_va
                            .wrapping_add(u64::try_from(cursor).unwrap_or(u64::MAX)),
                    });
                }
                let slice = code.get(cursor..).ok_or(CoreError::MalformedBinary)?;
                let instruction = decode(
                    slice,
                    self.base_va
                        .wrapping_add(u64::try_from(cursor).unwrap_or(u64::MAX)),
                )?;
                self.current_va = instruction.offset;
                self.current_len = instruction.length;
                let length = usize::from(instruction.length);
                let end = cursor
                    .checked_add(length)
                    .ok_or(CoreError::ArithmeticOverflow)?;
                if end > limit {
                    return Err(CoreError::OverlappingInstruction {
                        offset: instruction.offset,
                    });
                }
                match self.lower_instruction(&instruction, &mut flags_known)? {
                    Some(terminator) => break terminator,
                    None => cursor = end,
                }
            };
            let ops_len = self.ops.len().saturating_sub(ops_start);
            let ops_start = u16::try_from(ops_start)
                .map_err(|_| CoreError::InvalidBlock { block: u16::MAX })?;
            let ops_len =
                u16::try_from(ops_len).map_err(|_| CoreError::InvalidBlock { block: u16::MAX })?;
            self.blocks.push(Block {
                start_va: self
                    .base_va
                    .wrapping_add(u64::try_from(start).unwrap_or(u64::MAX)),
                ops_start,
                ops_len,
                terminator,
            })?;
            block_index = block_index.saturating_add(1);
        }
        Ok(())
    }
}

#[inline]
const fn operand_width(operand: Operand) -> Option<Width> {
    match operand {
        Operand::Reg { width, .. }
        | Operand::Imm { width, .. }
        | Operand::Mem(MemoryOperand { width, .. }) => Some(width),
        _ => None,
    }
}

/// Lifts one bounded native function without embedded read-only data.
///
/// Returns a fully validated CFG. Any unsupported, ambiguous, overlapping, or
/// out-of-range instruction rejects the whole function.
///
/// # Errors
///
/// Returns a typed error for empty or oversized functions, malformed or
/// unsupported instructions, overlapping decode paths, invalid branch targets,
/// unknown flags, and fixed-capacity exhaustion.
#[inline]
pub fn lift_function(code: &[u8], base_va: u64) -> Result<LiftedFunction> {
    lift_function_with_data(code, base_va, &EmptyData, 0)
}

/// Lifts one bounded native function and resolves read-only RIP-relative data.
///
/// `data_base` is the program-wide private-memory offset assigned to this
/// function's embedded data. The caller must lay out functions in the same
/// order when concatenating their data.
///
/// # Errors
///
/// Returns a typed error for empty or oversized functions, malformed or
/// unsupported instructions, overlapping decode paths, invalid branch targets,
/// unknown flags, unreadable RIP-relative data, and fixed-capacity exhaustion.
#[inline]
pub fn lift_function_with_data(
    code: &[u8],
    base_va: u64,
    reader: &dyn BinaryData,
    data_base: usize,
) -> Result<LiftedFunction> {
    if code.is_empty() || code.len() > MAX_FUNCTION_BYTES {
        return Err(CoreError::InvalidFunctionSize {
            size: u64::try_from(code.len()).unwrap_or(u64::MAX),
        });
    }
    let mut lifter = Lifter::new(code.len(), base_va, reader, data_base);
    lifter.discover(code)?;
    lifter.build(code)?;
    if lifter.blocks.is_empty() {
        return Err(CoreError::InvalidFunctionSize { size: 0 });
    }
    Ok(LiftedFunction {
        entry_block: 0,
        blocks: lifter.blocks,
        ops: lifter.ops,
        byte_len: u64::try_from(code.len()).unwrap_or(u64::MAX),
        data: lifter.data,
        data_base: lifter.data_base,
        stack_args: lifter.max_stack_args,
    })
}

#[cfg(test)]
mod tests {
    use super::{BinaryData, EmptyData, FlagKind, Lifter, lift_function, lift_function_with_data};
    use crate::error::CoreError;
    use crate::ir::Terminator;
    use crate::shared::format::{REG_RAX, REG_RDI, REG_RSI};

    #[test]
    fn lifts_straight_line_add() {
        let code = [0x48, 0x89, 0xf8, 0x48, 0x01, 0xf0, 0xc3];
        let function = lift_function(&code, 0x1000);
        assert!(function.is_ok());
        if let Ok(function) = function {
            assert_eq!(function.entry_block, 0);
            assert_eq!(function.blocks.len(), 1);
            let block = function.blocks.get(0);
            assert!(block.is_some());
            if let Some(block) = block {
                assert_eq!(block.terminator, Terminator::Return { value: REG_RAX });
                assert!(block.ops_len > 0);
            }
        }
        let _ = (
            REG_RDI,
            REG_RSI,
            FlagKind::Add,
            Lifter::new(1, 0, &EmptyData, 0),
        );
    }

    #[test]
    fn lifts_conditional_branch() {
        let code = [
            0x48, 0x39, 0xf7, 0x76, 0x05, 0x48, 0x89, 0xf8, 0xc3, 0x48, 0x89, 0xf0, 0xc3,
        ];
        let function = lift_function(&code, 0);
        assert!(function.is_ok());
        if let Ok(function) = function {
            assert_eq!(function.blocks.len(), 3);
            let entry = function.blocks.get(0);
            assert!(matches!(
                entry.map(|block| block.terminator),
                Some(Terminator::Branch { .. })
            ));
        }
    }

    #[test]
    fn short_opcode_corpus_is_total() {
        let mut first = 0_u16;
        while first <= 0xff {
            let mut second = 0_u16;
            while second <= 0xff {
                let code = [
                    u8::try_from(first).unwrap_or(0),
                    u8::try_from(second).unwrap_or(0),
                    0xc3,
                ];
                let _ = lift_function(&code, 0x1000);
                let two_byte = [
                    0x0f,
                    u8::try_from(first).unwrap_or(0),
                    u8::try_from(second).unwrap_or(0),
                    0xc3,
                ];
                let _ = lift_function(&two_byte, 0x1000);
                second = second.saturating_add(1);
            }
            first = first.saturating_add(1);
        }
    }

    #[test]
    fn rejects_call_inside_protected_range() {
        let code = [0x48, 0x89, 0xf8, 0xe8, 0, 0, 0, 0, 0xc3];
        let result = lift_function(&code, 0);
        assert!(result.is_err());
        if let Err(error) = result {
            assert!(matches!(error, CoreError::Decode(_)));
        }
    }

    #[test]
    fn rejects_riprelative_memory() {
        let code = [0x48, 0x8b, 0x05, 0, 0, 0, 0, 0xc3];
        let result = lift_function(&code, 0);
        assert!(result.is_err());
        if let Err(error) = result {
            assert!(matches!(error, CoreError::Decode(_)));
        }
    }

    #[test]
    fn rejects_empty_function() {
        assert!(lift_function(&[], 0).is_err());
    }
    struct TestData<'a> {
        base: u64,
        bytes: &'a [u8],
    }

    impl BinaryData for TestData<'_> {
        fn read_readonly(&self, va: u64, len: usize) -> Option<&[u8]> {
            if va != self.base || len > self.bytes.len() {
                return None;
            }
            self.bytes.get(..len)
        }
    }

    #[test]
    fn lifts_sse2_register_and_memory_forms() {
        let code = [0x66, 0x0f, 0xef, 0xc0, 0x66, 0x0f, 0xd4, 0xc0, 0xc3];
        let function = lift_function(&code, 0x1000).expect("sse lift");
        assert!(
            function
                .ops
                .as_slice()
                .iter()
                .any(|operation| { matches!(operation, crate::ir::IrOp::Xor { dst: 64, .. }) })
        );
        assert!(
            function
                .ops
                .as_slice()
                .iter()
                .any(|operation| { matches!(operation, crate::ir::IrOp::Add { dst: 64, .. }) })
        );
        assert!(
            function
                .ops
                .as_slice()
                .iter()
                .any(|operation| { matches!(operation, crate::ir::IrOp::Xor { dst: 65, .. }) })
        );
    }

    #[test]
    fn lifts_rip_relative_read_only_load() {
        let bytes = [
            0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let reader = TestData {
            base: 0x2000,
            bytes: &bytes,
        };
        let code = [0x48, 0x8b, 0x05, 0xf9, 0x0f, 0x00, 0x00, 0xc3];
        let function = lift_function_with_data(&code, 0x1000, &reader, 0).expect("rip load");
        assert_eq!(function.data.len(), 16);
        assert_eq!(
            function.data.as_slice().get(..8),
            Some(bytes.get(..8).unwrap_or(&[]))
        );
        assert!(
            function
                .ops
                .as_slice()
                .iter()
                .any(|operation| { matches!(operation, crate::ir::IrOp::MovImm { value: 0, .. }) })
        );
        assert!(
            function
                .ops
                .as_slice()
                .iter()
                .any(|operation| matches!(operation, crate::ir::IrOp::Load { .. }))
        );
    }

    #[test]
    fn lifts_rip_relative_lea_and_rejects_store() {
        let bytes = [0xaa_u8; 16];
        let reader = TestData {
            base: 0x3000,
            bytes: &bytes,
        };
        let lea = [0x48, 0x8d, 0x05, 0xf9, 0x1f, 0x00, 0x00, 0xc3];
        let function = lift_function_with_data(&lea, 0x1000, &reader, 16).expect("rip lea");
        assert_eq!(function.data.len(), 16);
        assert!(
            function.ops.as_slice().iter().any(|operation| {
                matches!(operation, crate::ir::IrOp::MovImm { value: 16, .. })
            })
        );
        let store = [0x48, 0x89, 0x05, 0xf9, 0x1f, 0x00, 0x00, 0xc3];
        assert!(lift_function_with_data(&store, 0x1000, &reader, 0).is_err());
    }

    #[test]
    fn lifts_stack_frame_and_leave() {
        let code = [
            0x55, 0x48, 0x89, 0xe5, 0x57, 0x48, 0x89, 0xf8, 0x5f, 0xc9, 0xc3,
        ];
        let function = lift_function(&code, 0x2000).expect("lift");
        assert_eq!(function.entry_block, 0);
        assert_eq!(function.blocks.len(), 1);
        if let Some(block) = function.blocks.get(0) {
            assert_eq!(block.terminator, Terminator::Return { value: REG_RAX });
        }
    }

    #[test]
    fn lifts_inc_dec_neg_not() {
        let code = [
            0x48, 0xff, 0xc0, 0x48, 0xff, 0xc8, 0x48, 0xf7, 0xd8, 0x48, 0xf7, 0xd0, 0xc3,
        ];
        assert!(lift_function(&code, 0x3000).is_ok());
    }

    #[test]
    fn lifts_setcc_and_cmov() {
        let code = [
            0x48, 0x39, 0xf7, 0x0f, 0x9f, 0xc0, 0x48, 0x0f, 0x4f, 0xc6, 0xc3,
        ];
        assert!(lift_function(&code, 0x4000).is_ok());
    }

    #[test]
    fn lifts_every_non_parity_condition() {
        for opcode in 0x70_u8..=0x7f {
            let code = [0x48, 0x39, 0xf7, opcode, 0x00, 0xc3];
            let result = lift_function(&code, 0x5000);
            if opcode == 0x7a || opcode == 0x7b {
                assert!(result.is_err(), "parity must fail closed");
            } else {
                assert!(result.is_ok(), "condition {opcode:#x} failed");
            }
        }
    }

    #[test]
    fn rejects_conditions_after_unsupported_flag_setter() {
        let code = [0x48, 0xc1, 0xe0, 0x01, 0x74, 0x00, 0xc3];
        assert!(lift_function(&code, 0x6000).is_err());
    }

    #[test]
    fn lifts_memory_operands_and_address_forms() {
        let code = [
            0x48, 0x83, 0xec, 0x10, 0x48, 0x89, 0x3c, 0x24, 0x48, 0x8b, 0x04, 0x24, 0x48, 0x83,
            0xc4, 0x10, 0xc3,
        ];
        assert!(lift_function(&code, 0x7000).is_ok());
        let lea = [0x48, 0x8d, 0x44, 0x24, 0x08, 0xc3];
        assert!(lift_function(&lea, 0x7100).is_ok());
    }

    #[test]
    fn rejects_missing_terminator_and_out_of_range_branch() {
        assert!(lift_function(&[0x48, 0x89, 0xf8], 0x8000).is_err());
        assert!(lift_function(&[0xeb, 0x7f], 0x9000).is_err());
    }

    #[test]
    fn rejects_unsupported_flag_use_at_block_start() {
        let code = [0x74, 0x00, 0xc3];
        assert!(lift_function(&code, 0xa000).is_err());
    }
    #[test]
    fn arbitrary_opcode_corpus_never_panics() {
        let mut state = 0x1234_5678_9abc_def0_u64;
        let mut first = 0_u16;
        while first < 256 {
            let mut tail = [0_u8; 16];
            let mut index = 0_usize;
            while index < tail.len() {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                if let Some(slot) = tail.get_mut(index) {
                    *slot = u8::try_from(state & 0xff).unwrap_or(0);
                }
                index = index.saturating_add(1);
            }
            let mut code = [0_u8; 17];
            if let Some(slot) = code.first_mut() {
                *slot = u8::try_from(first & 0xff).unwrap_or(0);
            }
            let mut copy = 0_usize;
            while copy < tail.len() {
                if let (Some(target), Some(source)) = (code.get_mut(copy + 1), tail.get(copy)) {
                    *target = *source;
                }
                copy = copy.saturating_add(1);
            }
            drop(lift_function(&code, 0xb000));
            first = first.saturating_add(1);
        }
    }
}
