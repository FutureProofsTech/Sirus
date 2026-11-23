//! Lowers IR to randomized, alias-encoded virtual ISA bytes.
//!
//! Each IR statement is rebuilt as an expression, expanded with bounded MBA,
//! constant-blinded, compiled into three-address operations over dead scratch
//! registers, and then encoded with per-build opcode aliases, operand orders,
//! register maps, and immediate endianness.

use crate::error::{CoreError, Result};
use crate::ir::{ByteBuf, IrOp, Terminator, Width};
use crate::mba::{BuildRng, ExprArena, ExprOp, expand};
use crate::shared::derive::Tables;
use crate::shared::format::{
    ALIASES_PER_SEMANTIC, MAX_OPERANDS, REG_ONE, REG_TEMP_BASE, ROLE_IMM, ROLE_REG, SEM_ADD_RR,
    SEM_AND_RR, SEM_CMPEQ_RR, SEM_CMPLES_RR, SEM_CMPLEU_RR, SEM_CMPLTS_RR, SEM_CMPLTU_RR, SEM_JCC,
    SEM_JMP, SEM_LOAD8, SEM_LOAD16, SEM_LOAD32, SEM_LOAD64, SEM_MOV_RI, SEM_MOV_RR, SEM_MUL_RR,
    SEM_NEG_R, SEM_NOT_R, SEM_OR_RR, SEM_RET, SEM_ROTL_RR, SEM_ROTR_RR, SEM_SAR_RR,
    SEM_SELECT_RRRR, SEM_SHL_RR, SEM_SHR_RR, SEM_STORE8, SEM_STORE16, SEM_STORE32, SEM_STORE64,
    SEM_SUB_RR, SEM_TRAP, SEM_XOR_RR, format,
};

/// Maximum plaintext size of one encoded block body.
pub const MAX_BLOCK_BODY: usize = 32_768;

const TEMP_COUNT: usize = 36;

#[derive(Clone, Copy, Debug)]
struct CompiledValue {
    register: u8,
    owned: bool,
}

struct BlockEncoder<'a> {
    tables: &'a Tables,
    rng: &'a mut BuildRng,
    states: &'a [u64],
    depth: u8,
    budget: u16,
    arena: ExprArena,
    temps: [bool; TEMP_COUNT],
    body: ByteBuf<MAX_BLOCK_BODY>,
}

impl<'a> BlockEncoder<'a> {
    fn new(
        tables: &'a Tables,
        rng: &'a mut BuildRng,
        states: &'a [u64],
        depth: u8,
        budget: u16,
    ) -> Self {
        Self {
            tables,
            rng,
            states,
            depth,
            budget,
            arena: ExprArena::new(),
            temps: [false; TEMP_COUNT],
            body: ByteBuf::new(),
        }
    }

    #[inline]
    fn alloc_temp(&mut self) -> Result<u8> {
        let mut index = 0_usize;
        while index < TEMP_COUNT {
            let used = self.temps.get(index).copied().unwrap_or(true);
            if !used {
                if let Some(slot) = self.temps.get_mut(index) {
                    *slot = true;
                }
                let offset =
                    u8::try_from(index).map_err(|_| CoreError::InvalidRegister { register: 0 })?;
                return Ok(REG_TEMP_BASE.saturating_add(offset));
            }
            index = index.saturating_add(1);
        }
        Err(CoreError::CapacityExceeded)
    }

    #[inline]
    fn free_temp(&mut self, register: u8) {
        let base = REG_TEMP_BASE;
        let offset = register.saturating_sub(base);
        if register >= base && usize::from(offset) < TEMP_COUNT {
            if let Some(slot) = self.temps.get_mut(usize::from(offset)) {
                *slot = false;
            }
        }
    }

    fn emit(&mut self, semantic: u8, operands: [u64; MAX_OPERANDS]) -> Result<()> {
        let alias_choice = self.rng.below(ALIASES_PER_SEMANTIC);
        let alias = self
            .tables
            .alias_for(semantic, alias_choice)
            .ok_or(CoreError::InvalidPlan)?;
        let layout = format(semantic).ok_or(CoreError::InvalidPlan)?;
        self.body.push(alias.opcode)?;
        let mut position = 0_usize;
        while position < usize::from(layout.len) {
            let role = alias
                .order
                .get(position)
                .copied()
                .ok_or(CoreError::InvalidPlan)?;
            let role_index = usize::from(role);
            if role_index >= usize::from(layout.len) {
                return Err(CoreError::InvalidPlan);
            }
            let kind = layout
                .roles
                .get(role_index)
                .copied()
                .ok_or(CoreError::InvalidPlan)?;
            let value = operands
                .get(role_index)
                .copied()
                .ok_or(CoreError::InvalidPlan)?;
            match kind {
                ROLE_REG => {
                    let logical = u8::try_from(value)
                        .map_err(|_| CoreError::InvalidRegister { register: 0 })?;
                    let encoded = self
                        .tables
                        .encode_register(alias.reg_map, logical)
                        .ok_or(CoreError::InvalidRegister { register: logical })?;
                    self.body.push(encoded)?;
                }
                ROLE_IMM => {
                    let bytes = if alias.big_endian {
                        value.to_be_bytes()
                    } else {
                        value.to_le_bytes()
                    };
                    for byte in bytes {
                        self.body.push(byte)?;
                    }
                }
                _ => return Err(CoreError::InvalidPlan),
            }
            position = position.saturating_add(1);
        }
        Ok(())
    }

    fn compile_expr(&mut self, id: u32) -> Result<CompiledValue> {
        let node = self.arena.node(id).ok_or(CoreError::InvalidPlan)?;
        match node.op {
            ExprOp::Reg => {
                let register = u8::try_from(node.imm)
                    .map_err(|_| CoreError::InvalidRegister { register: 0 })?;
                Ok(CompiledValue {
                    register,
                    owned: false,
                })
            }
            ExprOp::Const => {
                let target = self.alloc_temp()?;
                let first = self.rng.next_u64();
                let second = first ^ node.imm;
                self.emit(SEM_MOV_RI, [u64::from(target), first, 0, 0])?;
                let scratch = self.alloc_temp()?;
                self.emit(SEM_MOV_RI, [u64::from(scratch), second, 0, 0])?;
                self.emit(SEM_XOR_RR, [u64::from(target), u64::from(scratch), 0, 0])?;
                self.free_temp(scratch);
                Ok(CompiledValue {
                    register: target,
                    owned: true,
                })
            }
            ExprOp::Not | ExprOp::Neg => {
                let value = self.compile_expr(node.a)?;
                let target = self.alloc_temp()?;
                self.emit(
                    SEM_MOV_RR,
                    [u64::from(target), u64::from(value.register), 0, 0],
                )?;
                let operation = if node.op == ExprOp::Not {
                    SEM_NOT_R
                } else {
                    SEM_NEG_R
                };
                self.emit(operation, [u64::from(target), 0, 0, 0])?;
                if value.owned {
                    self.free_temp(value.register);
                }
                Ok(CompiledValue {
                    register: target,
                    owned: true,
                })
            }
            ExprOp::CmpEq | ExprOp::CmpLtU | ExprOp::CmpLtS | ExprOp::CmpLeU | ExprOp::CmpLeS => {
                let left = self.compile_expr(node.a)?;
                let right = self.compile_expr(node.b)?;
                let target = self.alloc_temp()?;
                let operation = match node.op {
                    ExprOp::CmpEq => SEM_CMPEQ_RR,
                    ExprOp::CmpLtU => SEM_CMPLTU_RR,
                    ExprOp::CmpLtS => SEM_CMPLTS_RR,
                    ExprOp::CmpLeU => SEM_CMPLEU_RR,
                    _ => SEM_CMPLES_RR,
                };
                self.emit(
                    operation,
                    [
                        u64::from(target),
                        u64::from(left.register),
                        u64::from(right.register),
                        0,
                    ],
                )?;
                if left.owned {
                    self.free_temp(left.register);
                }
                if right.owned {
                    self.free_temp(right.register);
                }
                Ok(CompiledValue {
                    register: target,
                    owned: true,
                })
            }
            ExprOp::Select => {
                let condition = self.compile_expr(node.a)?;
                let when_true = self.compile_expr(node.b)?;
                let when_false = self.compile_expr(node.c)?;
                let target = self.alloc_temp()?;
                self.emit(
                    SEM_SELECT_RRRR,
                    [
                        u64::from(target),
                        u64::from(condition.register),
                        u64::from(when_true.register),
                        u64::from(when_false.register),
                    ],
                )?;
                if condition.owned {
                    self.free_temp(condition.register);
                }
                if when_true.owned {
                    self.free_temp(when_true.register);
                }
                if when_false.owned {
                    self.free_temp(when_false.register);
                }
                Ok(CompiledValue {
                    register: target,
                    owned: true,
                })
            }
            _ => {
                let left = self.compile_expr(node.a)?;
                let right = self.compile_expr(node.b)?;
                let target = self.alloc_temp()?;
                self.emit(
                    SEM_MOV_RR,
                    [u64::from(target), u64::from(left.register), 0, 0],
                )?;
                let operation = match node.op {
                    ExprOp::Add => SEM_ADD_RR,
                    ExprOp::Sub => SEM_SUB_RR,
                    ExprOp::Mul => SEM_MUL_RR,
                    ExprOp::And => SEM_AND_RR,
                    ExprOp::Or => SEM_OR_RR,
                    ExprOp::Xor => SEM_XOR_RR,
                    ExprOp::Shl => SEM_SHL_RR,
                    ExprOp::ShrU => SEM_SHR_RR,
                    ExprOp::ShrS => SEM_SAR_RR,
                    ExprOp::RotL => SEM_ROTL_RR,
                    ExprOp::RotR => SEM_ROTR_RR,
                    _ => return Err(CoreError::InvalidPlan),
                };
                self.emit(
                    operation,
                    [u64::from(target), u64::from(right.register), 0, 0],
                )?;
                if left.owned {
                    self.free_temp(left.register);
                }
                if right.owned {
                    self.free_temp(right.register);
                }
                Ok(CompiledValue {
                    register: target,
                    owned: true,
                })
            }
        }
    }

    fn apply_expression(&mut self, dst: u8, root: u32) -> Result<()> {
        let expanded = expand(&mut self.arena, root, self.rng, self.depth, self.budget);
        let compiled = self.compile_expr(expanded)?;
        if compiled.register != dst {
            self.emit(
                SEM_MOV_RR,
                [u64::from(dst), u64::from(compiled.register), 0, 0],
            )?;
        }
        if compiled.owned {
            self.free_temp(compiled.register);
        }
        Ok(())
    }

    fn encode_ir(&mut self, operation: &IrOp) -> Result<()> {
        self.arena.reset();
        match *operation {
            IrOp::Nop => Ok(()),
            IrOp::Mov { dst, src } => {
                if dst == src {
                    return Ok(());
                }
                self.emit(SEM_MOV_RR, [u64::from(dst), u64::from(src), 0, 0])
            }
            IrOp::MovImm { dst, value } => {
                let root = self.arena.constant(value)?;
                self.apply_expression(dst, root)
            }
            IrOp::Add { dst, src } => {
                let left = self.arena.reg(dst)?;
                let right = self.arena.reg(src)?;
                let root = self.arena.binary(ExprOp::Add, left, right)?;
                self.apply_expression(dst, root)
            }
            IrOp::AddImm { dst, value } => {
                let left = self.arena.reg(dst)?;
                let right = self.arena.constant(value)?;
                let root = self.arena.binary(ExprOp::Add, left, right)?;
                self.apply_expression(dst, root)
            }
            IrOp::Sub { dst, src } => {
                let left = self.arena.reg(dst)?;
                let right = self.arena.reg(src)?;
                let root = self.arena.binary(ExprOp::Sub, left, right)?;
                self.apply_expression(dst, root)
            }
            IrOp::SubImm { dst, value } => {
                let left = self.arena.reg(dst)?;
                let right = self.arena.constant(value)?;
                let root = self.arena.binary(ExprOp::Sub, left, right)?;
                self.apply_expression(dst, root)
            }
            IrOp::Mul { dst, src } => {
                let left = self.arena.reg(dst)?;
                let right = self.arena.reg(src)?;
                let root = self.arena.binary(ExprOp::Mul, left, right)?;
                self.apply_expression(dst, root)
            }
            IrOp::And { dst, src } => {
                let left = self.arena.reg(dst)?;
                let right = self.arena.reg(src)?;
                let root = self.arena.binary(ExprOp::And, left, right)?;
                self.apply_expression(dst, root)
            }
            IrOp::AndImm { dst, value } => {
                let left = self.arena.reg(dst)?;
                let right = self.arena.constant(value)?;
                let root = self.arena.binary(ExprOp::And, left, right)?;
                self.apply_expression(dst, root)
            }
            IrOp::Or { dst, src } => {
                let left = self.arena.reg(dst)?;
                let right = self.arena.reg(src)?;
                let root = self.arena.binary(ExprOp::Or, left, right)?;
                self.apply_expression(dst, root)
            }
            IrOp::OrImm { dst, value } => {
                let left = self.arena.reg(dst)?;
                let right = self.arena.constant(value)?;
                let root = self.arena.binary(ExprOp::Or, left, right)?;
                self.apply_expression(dst, root)
            }
            IrOp::Xor { dst, src } => {
                let left = self.arena.reg(dst)?;
                let right = self.arena.reg(src)?;
                let root = self.arena.binary(ExprOp::Xor, left, right)?;
                self.apply_expression(dst, root)
            }
            IrOp::XorImm { dst, value } => {
                let left = self.arena.reg(dst)?;
                let right = self.arena.constant(value)?;
                let root = self.arena.binary(ExprOp::Xor, left, right)?;
                self.apply_expression(dst, root)
            }
            IrOp::Not { dst } => {
                let value = self.arena.reg(dst)?;
                let root = self.arena.unary(ExprOp::Not, value)?;
                self.apply_expression(dst, root)
            }
            IrOp::Neg { dst } => {
                let value = self.arena.reg(dst)?;
                let root = self.arena.unary(ExprOp::Neg, value)?;
                self.apply_expression(dst, root)
            }
            IrOp::Shl { dst, src } => {
                let left = self.arena.reg(dst)?;
                let right = self.arena.reg(src)?;
                let root = self.arena.binary(ExprOp::Shl, left, right)?;
                self.apply_expression(dst, root)
            }
            IrOp::ShlImm { dst, value } => {
                let left = self.arena.reg(dst)?;
                let right = self.arena.constant(value)?;
                let root = self.arena.binary(ExprOp::Shl, left, right)?;
                self.apply_expression(dst, root)
            }
            IrOp::ShrU { dst, src } => {
                let left = self.arena.reg(dst)?;
                let right = self.arena.reg(src)?;
                let root = self.arena.binary(ExprOp::ShrU, left, right)?;
                self.apply_expression(dst, root)
            }
            IrOp::ShrUImm { dst, value } => {
                let left = self.arena.reg(dst)?;
                let right = self.arena.constant(value)?;
                let root = self.arena.binary(ExprOp::ShrU, left, right)?;
                self.apply_expression(dst, root)
            }
            IrOp::ShrS { dst, src } => {
                let left = self.arena.reg(dst)?;
                let right = self.arena.reg(src)?;
                let root = self.arena.binary(ExprOp::ShrS, left, right)?;
                self.apply_expression(dst, root)
            }
            IrOp::ShrSImm { dst, value } => {
                let left = self.arena.reg(dst)?;
                let right = self.arena.constant(value)?;
                let root = self.arena.binary(ExprOp::ShrS, left, right)?;
                self.apply_expression(dst, root)
            }
            IrOp::RotL { dst, src } => {
                let left = self.arena.reg(dst)?;
                let right = self.arena.reg(src)?;
                let root = self.arena.binary(ExprOp::RotL, left, right)?;
                self.apply_expression(dst, root)
            }
            IrOp::RotLImm { dst, value } => {
                let left = self.arena.reg(dst)?;
                let right = self.arena.constant(value)?;
                let root = self.arena.binary(ExprOp::RotL, left, right)?;
                self.apply_expression(dst, root)
            }
            IrOp::RotR { dst, src } => {
                let left = self.arena.reg(dst)?;
                let right = self.arena.reg(src)?;
                let root = self.arena.binary(ExprOp::RotR, left, right)?;
                self.apply_expression(dst, root)
            }
            IrOp::RotRImm { dst, value } => {
                let left = self.arena.reg(dst)?;
                let right = self.arena.constant(value)?;
                let root = self.arena.binary(ExprOp::RotR, left, right)?;
                self.apply_expression(dst, root)
            }
            IrOp::CmpEq { dst, lhs, rhs } => {
                let left = self.arena.reg(lhs)?;
                let right = self.arena.reg(rhs)?;
                let root = self.arena.binary(ExprOp::CmpEq, left, right)?;
                self.apply_expression(dst, root)
            }
            IrOp::CmpLtU { dst, lhs, rhs } => {
                let left = self.arena.reg(lhs)?;
                let right = self.arena.reg(rhs)?;
                let root = self.arena.binary(ExprOp::CmpLtU, left, right)?;
                self.apply_expression(dst, root)
            }
            IrOp::CmpLtS { dst, lhs, rhs } => {
                let left = self.arena.reg(lhs)?;
                let right = self.arena.reg(rhs)?;
                let root = self.arena.binary(ExprOp::CmpLtS, left, right)?;
                self.apply_expression(dst, root)
            }
            IrOp::CmpLeU { dst, lhs, rhs } => {
                let left = self.arena.reg(lhs)?;
                let right = self.arena.reg(rhs)?;
                let root = self.arena.binary(ExprOp::CmpLeU, left, right)?;
                self.apply_expression(dst, root)
            }
            IrOp::CmpLeS { dst, lhs, rhs } => {
                let left = self.arena.reg(lhs)?;
                let right = self.arena.reg(rhs)?;
                let root = self.arena.binary(ExprOp::CmpLeS, left, right)?;
                self.apply_expression(dst, root)
            }
            IrOp::Select {
                dst,
                cond,
                when_true,
                when_false,
            } => {
                let condition = self.arena.reg(cond)?;
                let true_value = self.arena.reg(when_true)?;
                let false_value = self.arena.reg(when_false)?;
                let root =
                    self.arena
                        .ternary(ExprOp::Select, condition, true_value, false_value)?;
                self.apply_expression(dst, root)
            }
            IrOp::Load { dst, addr, width } => {
                let semantic = match width {
                    Width::W8 => SEM_LOAD8,
                    Width::W16 => SEM_LOAD16,
                    Width::W32 => SEM_LOAD32,
                    Width::W64 => SEM_LOAD64,
                };
                self.emit(semantic, [u64::from(dst), u64::from(addr), 0, 0])
            }
            IrOp::Store { addr, src, width } => {
                let semantic = match width {
                    Width::W8 => SEM_STORE8,
                    Width::W16 => SEM_STORE16,
                    Width::W32 => SEM_STORE32,
                    Width::W64 => SEM_STORE64,
                };
                self.emit(semantic, [u64::from(addr), u64::from(src), 0, 0])
            }
        }
    }

    fn target_state(&self, block: u16) -> Result<u64> {
        self.states
            .get(usize::from(block))
            .copied()
            .ok_or(CoreError::InvalidBlock { block })
    }

    fn encode_terminator(&mut self, terminator: Terminator) -> Result<()> {
        match terminator {
            Terminator::Jump { target } => {
                let state = self.target_state(target)?;
                self.emit(SEM_JMP, [state, u64::from(REG_ONE), 0, 0])
            }
            Terminator::Branch {
                cond,
                when_true,
                when_false,
            } => {
                let true_state = self.target_state(when_true)?;
                let false_state = self.target_state(when_false)?;
                self.emit(
                    SEM_JCC,
                    [u64::from(cond), true_state, false_state, u64::from(REG_ONE)],
                )
            }
            Terminator::Return { value } => self.emit(SEM_RET, [u64::from(value), 0, 0, 0]),
            Terminator::Trap => self.emit(SEM_TRAP, [0_u64; MAX_OPERANDS]),
        }
    }

    fn finish(mut self, ops: &[IrOp], terminator: Terminator) -> Result<ByteBuf<MAX_BLOCK_BODY>> {
        for operation in ops {
            self.encode_ir(operation)?;
        }
        self.encode_terminator(terminator)?;
        Ok(self.body)
    }
}

/// Encodes one flattened block body.
#[inline]
pub(crate) fn encode_block(
    ops: &[IrOp],
    terminator: Terminator,
    states: &[u64],
    tables: &Tables,
    rng: &mut BuildRng,
    mba_depth: u8,
    mba_budget: u16,
) -> Result<ByteBuf<MAX_BLOCK_BODY>> {
    let encoder = BlockEncoder::new(tables, rng, states, mba_depth, mba_budget);
    encoder.finish(ops, terminator)
}

#[cfg(test)]
mod tests {
    use super::{MAX_BLOCK_BODY, encode_block};
    use crate::ir::{ByteBuf, IrOp, Terminator};
    use crate::mba::BuildRng;
    use crate::shared::derive::Tables;
    use crate::shared::format::{REG_ONE, REG_RAX, SEM_MOV_RI, SEM_RET, format};

    fn seed() -> [u8; 32] {
        [0x5a_u8; 32]
    }

    #[test]
    fn encodes_a_return_block() {
        let tables = Tables::derive(&seed());
        let mut rng = BuildRng::new(&seed(), 1);
        let states = [0x1111_2222_3333_4444_u64];
        let ops = [IrOp::MovImm {
            dst: REG_RAX,
            value: 7,
        }];
        let body = encode_block(
            &ops,
            Terminator::Return { value: REG_RAX },
            &states,
            &tables,
            &mut rng,
            0,
            0,
        );
        assert!(body.is_ok());
        if let Ok(body) = body {
            assert!(!body.is_empty());
            assert!(body.len() <= MAX_BLOCK_BODY);
            let first = body.get(0).unwrap_or(0xff);
            assert!(tables.semantic_for_opcode(first).is_some());
            let _ = (format(SEM_MOV_RI), format(SEM_RET), REG_ONE);
            let _ = ByteBuf::<1>::new();
        }
    }

    #[test]
    fn survives_high_mba_configuration() {
        let tables = Tables::derive(&seed());
        let mut rng = BuildRng::new(&seed(), 2);
        let states = [1_u64];
        let ops = [
            IrOp::MovImm {
                dst: REG_RAX,
                value: 0xdead_beef,
            },
            IrOp::Add {
                dst: REG_RAX,
                src: REG_RAX,
            },
            IrOp::Xor {
                dst: REG_RAX,
                src: REG_RAX,
            },
        ];
        let body = encode_block(
            &ops,
            Terminator::Return { value: REG_RAX },
            &states,
            &tables,
            &mut rng,
            4,
            512,
        );
        assert!(body.is_ok());
    }

    #[test]
    fn rejects_invalid_target_state() {
        let tables = Tables::derive(&seed());
        let mut rng = BuildRng::new(&seed(), 3);
        let states = [1_u64];
        let result = encode_block(
            &[],
            Terminator::Jump { target: 3 },
            &states,
            &tables,
            &mut rng,
            0,
            0,
        );
        assert!(result.is_err());
    }
}
