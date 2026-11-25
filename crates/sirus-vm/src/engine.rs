//! Reference Sirus virtual machine.
//!
//! This module is included verbatim in generated injected runtimes. It is
//! `no_std`, allocation-free, contains no `unsafe`, and treats every byte of
//! input as hostile. Malformed payloads halt deterministically; they never
//! trigger an out-of-bounds access, panic, or unbounded execution.

use crate::shared::cipher::{
    BodyCipher, MANIFEST_COUNT_BYTES, MANIFEST_ENTRY_BYTES, MAX_PAYLOAD_BLOCKS,
    decode_manifest_u32, decode_manifest_u64, effective_key, manifest_byte, manifest_size,
    payload_hash,
};
use crate::shared::derive::{DecodeTables, Seed, Tables};
use crate::shared::format::{
    MAX_OPERANDS, REG_R8, REG_R9, REG_RAX, REG_RCX, REG_RDI, REG_RDX, REG_RSI, REG_RSP, ROLE_IMM,
    ROLE_REG, SEM_ADD_RI, SEM_ADD_RR, SEM_AND_RI, SEM_AND_RR, SEM_BSWAP, SEM_CALL, SEM_CMPEQ_RR,
    SEM_CMPLES_RR, SEM_CMPLEU_RR, SEM_CMPLTS_RR, SEM_CMPLTU_RR, SEM_JCC, SEM_JMP, SEM_LOAD8,
    SEM_LOAD16, SEM_LOAD32, SEM_LOAD64, SEM_MOV_RI, SEM_MOV_RR, SEM_MUL_RR, SEM_NEG_R, SEM_NOP,
    SEM_NOT_R, SEM_OR_RI, SEM_OR_RR, SEM_REP_MOVS, SEM_REP_STOS, SEM_RET, SEM_ROTL_RI, SEM_ROTL_RR,
    SEM_ROTR_RI, SEM_ROTR_RR, SEM_SAR_RI, SEM_SAR_RR, SEM_SELECT_RRRR, SEM_SHL_RI, SEM_SHL_RR,
    SEM_SHR_RI, SEM_SHR_RR, SEM_STORE8, SEM_STORE16, SEM_STORE32, SEM_STORE64, SEM_SUB_RI,
    SEM_SUB_RR, SEM_TRAP, SEM_XOR_RI, SEM_XOR_RR, VM_DATA_LIMIT, VM_MEMORY_SIZE, VM_REGISTERS,
    VM_STACK_ARG_BASE, VM_STACK_ARG_SLOTS, format,
};

/// Deterministic VM outcome.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// The virtual program executed `RET` and produced a value.
    Returned,
    /// The payload or an encoded instruction failed validation.
    BadPayload,
    /// The deterministic instruction budget was exhausted.
    FuelExhausted,
    /// The virtual program executed `TRAP`.
    Trap,
    /// The fixed oblivious pass budget was exhausted before the frontier
    /// converged.
    LoopBound,
}

/// Result of one protected invocation.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Run {
    /// Value left in virtual `RAX`, or zero on failure.
    pub value: u64,
    /// Why execution stopped.
    pub status: Status,
    /// Number of charged steps, including dispatcher scans.
    pub steps: u64,
}

/// Everything the generated entry thunk passes to the engine.
#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub struct VmInput<'a> {
    /// Complete encrypted payload.
    pub payload: &'a [u8],
    /// Read-only data installed into private memory at startup.
    pub data: &'a [u8],
    /// Per-build plan seed.
    pub seed: &'a Seed,
    /// Integrity hash expected by the build.
    pub expected_hash: u64,
    /// First half of the split base key.
    pub base_a: u64,
    /// Second half of the split base key.
    pub base_b: u64,
    /// Blinded state pairs, one per generated entry thunk.
    pub entry_states: &'a [[u64; 2]],
    /// Maximum charged steps for this invocation.
    pub fuel: u64,
}

impl<'a> VmInput<'a> {
    /// Constructs the complete runtime input in one checked shape.
    #[inline]
    #[must_use]
    pub const fn new(
        payload: &'a [u8],
        seed: &'a Seed,
        expected_hash: u64,
        base_a: u64,
        base_b: u64,
        entry_states: &'a [[u64; 2]],
        fuel: u64,
    ) -> Self {
        Self::with_data(
            payload,
            &[],
            seed,
            expected_hash,
            base_a,
            base_b,
            entry_states,
            fuel,
        )
    }

    /// Constructs the runtime input with read-only data for RIP-relative operands.
    #[inline]
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "runtime input is a flat fixed-shape descriptor"
    )]
    pub const fn with_data(
        payload: &'a [u8],
        data: &'a [u8],
        seed: &'a Seed,
        expected_hash: u64,
        base_a: u64,
        base_b: u64,
        entry_states: &'a [[u64; 2]],
        fuel: u64,
    ) -> Self {
        Self {
            payload,
            data,
            seed,
            expected_hash,
            base_a,
            base_b,
            entry_states,
            fuel,
        }
    }
}

/// Control-flow result of one semantic operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flow {
    /// Continue in the current block.
    Continue,
    /// Transfer to another flattened block.
    Jump(u64),
    /// Return to the host.
    Return(u64),
    /// Halt through an explicit trap.
    Trap,
    /// Direct guest call.
    Call {
        /// Callee entry state.
        callee: u64,
        /// State to resume after the callee returns.
        return_state: u64,
    },
    /// Conditional transfer used only by oblivious execution.
    Branch {
        /// Raw branch condition.
        condition: u64,
        /// Target when the condition is non-zero.
        when_true: u64,
        /// Target when the condition is zero.
        when_false: u64,
    },
}

/// Decoded instruction operands in canonical role order.
#[derive(Clone, Copy, Debug)]
struct Decoded {
    semantic: u8,
    values: [u64; MAX_OPERANDS],
}

/// Reads and decrypts a block body one byte at a time.
struct BodyReader<'a> {
    payload: &'a [u8],
    tables: &'a DecodeTables,
    cipher: BodyCipher,
    position: usize,
    end: usize,
    previous: u8,
}

impl<'a> BodyReader<'a> {
    #[inline]
    const fn new(
        payload: &'a [u8],
        tables: &'a DecodeTables,
        cipher: BodyCipher,
        start: usize,
        end: usize,
    ) -> Self {
        Self {
            payload,
            tables,
            cipher,
            position: start,
            end,
            previous: 0,
        }
    }

    #[inline]
    fn next_plain(&mut self) -> Option<u8> {
        if self.position >= self.end {
            return None;
        }
        let raw = self.payload.get(self.position).copied()?;
        let plain = self.cipher.apply(self.position, self.previous, raw);
        self.previous = plain;
        self.position = self.position.checked_add(1)?;
        Some(plain)
    }

    #[inline]
    fn read_immediate(&mut self, big_endian: bool) -> Option<u64> {
        let mut bytes = [0_u8; 8];
        let mut index = 0_usize;
        while index < 8 {
            let byte = self.next_plain()?;
            if let Some(slot) = bytes.get_mut(index) {
                *slot = byte;
            }
            index += 1;
        }
        Some(decode_manifest_u64(&bytes, big_endian))
    }

    #[inline]
    fn read_instruction(&mut self) -> Option<Decoded> {
        let opcode = self.next_plain()?;
        let semantic = self.tables.semantic_for_opcode(opcode)?;
        let alias_index = self.tables.alias_index_for_opcode(opcode)?;
        let alias = self.tables.alias_for(semantic, alias_index)?;
        let layout = format(semantic)?;
        let mut values = [0_u64; MAX_OPERANDS];
        let mut position = 0_usize;
        while position < usize::from(layout.len) {
            let role = alias.order.get(position).copied()?;
            let role_index = usize::from(role);
            if role_index >= usize::from(layout.len) {
                return None;
            }
            let kind = layout.roles.get(role_index).copied()?;
            let value = match kind {
                ROLE_REG => {
                    let encoded = self.next_plain()?;
                    u64::from(self.tables.decode_register(alias.reg_map, encoded)?)
                }
                ROLE_IMM => self.read_immediate(alias.big_endian)?,
                _ => return None,
            };
            if let Some(slot) = values.get_mut(role_index) {
                *slot = value;
            }
            position = position.checked_add(1)?;
        }
        Some(Decoded { semantic, values })
    }
}

#[inline]
fn reg_value(
    registers: &[u64; VM_REGISTERS],
    masks: Option<&[u64; VM_REGISTERS]>,
    values: &[u64; MAX_OPERANDS],
    operand: usize,
) -> Option<u64> {
    let raw = values.get(operand).copied()?;
    let slot = usize::try_from(raw).ok()?;
    let stored = registers.get(slot).copied()?;
    match masks {
        Some(masks) => Some(stored ^ masks.get(slot).copied()?),
        None => Some(stored),
    }
}

#[inline]
fn set_reg_value(
    registers: &mut [u64; VM_REGISTERS],
    masks: Option<&[u64; VM_REGISTERS]>,
    values: &[u64; MAX_OPERANDS],
    operand: usize,
    value: u64,
) -> Option<()> {
    let raw = values.get(operand).copied()?;
    let slot = usize::try_from(raw).ok()?;
    let encoded = match masks {
        Some(masks) => value ^ masks.get(slot).copied()?,
        None => value,
    };
    let target = registers.get_mut(slot)?;
    *target = encoded;
    Some(())
}

#[inline]
fn set_reg_value_active(
    registers: &mut [u64; VM_REGISTERS],
    masks: Option<&[u64; VM_REGISTERS]>,
    values: &[u64; MAX_OPERANDS],
    operand: usize,
    value: u64,
    active: Option<u64>,
) -> Option<()> {
    let selected = match active {
        Some(enable) => {
            let current = reg_value(registers, masks, values, operand)?;
            let enable = 0_u64.wrapping_sub(u64::from(enable != 0));
            (value & enable) | (current & !enable)
        }
        None => value,
    };
    set_reg_value(registers, masks, values, operand, selected)
}

#[inline]
fn immediate(values: &[u64; MAX_OPERANDS], operand: usize) -> Option<u64> {
    values.get(operand).copied()
}

#[inline]
const fn as_i64(value: u64) -> i64 {
    i64::from_ne_bytes(value.to_ne_bytes())
}

#[inline]
const fn as_u64(value: i64) -> u64 {
    u64::from_ne_bytes(value.to_ne_bytes())
}

#[inline]
fn shift_amount(value: u64) -> u32 {
    u32::try_from(value & 63).unwrap_or(0)
}

#[inline]
#[cfg(any(test, kani))]
fn load_memory(memory: &[u8], address: u64, width: usize) -> Option<u64> {
    load_memory_with_key(memory, address, width, None)
}

fn load_memory_with_key(
    memory: &[u8],
    address: u64,
    width: usize,
    memory_key: Option<u64>,
) -> Option<u64> {
    let start = usize::try_from(address).ok()?;
    let end = start.checked_add(width)?;
    if end > memory.len() || width > 8 {
        return None;
    }
    let mut value = 0_u64;
    let mut index = 0_usize;
    while index < width {
        let byte = memory.get(start.checked_add(index)?).copied()?;
        let plain = memory_key.map_or(byte, |key| {
            byte ^ memory_mask(key, start.checked_add(index).unwrap_or(0))
        });
        let shift = u32::try_from(index.wrapping_mul(8)).ok()?;
        value |= u64::from(plain) << shift;
        index = index.checked_add(1)?;
    }
    Some(value)
}

#[inline]
#[cfg(any(test, kani))]
fn store_memory(memory: &mut [u8], address: u64, width: usize, value: u64) -> Option<()> {
    store_memory_with_key(memory, address, width, value, None)
}

fn store_memory_with_key(
    memory: &mut [u8],
    address: u64,
    width: usize,
    value: u64,
    memory_key: Option<u64>,
) -> Option<()> {
    let start = usize::try_from(address).ok()?;
    let end = start.checked_add(width)?;
    if end > memory.len() || width > 8 {
        return None;
    }
    let mut index = 0_usize;
    while index < width {
        let shift = u32::try_from(index.wrapping_mul(8)).ok()?;
        let byte = u8::try_from((value >> shift) & 0xff).ok()?;
        let position = start.checked_add(index)?;
        let stored = memory_key.map_or(byte, |key| byte ^ memory_mask(key, position));
        let target = memory.get_mut(position)?;
        *target = stored;
        index = index.checked_add(1)?;
    }
    Some(())
}

#[cfg(target_os = "windows")]
const STACK_ARG_OFFSET: usize = 0x28;
#[cfg(not(target_os = "windows"))]
const STACK_ARG_OFFSET: usize = 8;

#[inline]
fn install_stack_arguments(memory: &mut [u8], memory_key: u64, args: [u64; 6]) -> bool {
    let base = usize::try_from(VM_STACK_ARG_BASE).unwrap_or(usize::MAX);
    let mut slot = 0_usize;
    while slot < VM_STACK_ARG_SLOTS.saturating_add(1) {
        let value = if slot == 0 {
            0_u64
        } else {
            args.get(slot.saturating_sub(1)).copied().unwrap_or(0)
        };
        let bytes = value.to_le_bytes();
        let offset = if slot == 0 {
            base
        } else {
            let Some(offset) = base
                .checked_add(STACK_ARG_OFFSET)
                .and_then(|start| start.checked_add(slot.saturating_sub(1).saturating_mul(8)))
            else {
                return false;
            };
            offset
        };
        let mut index = 0_usize;
        while index < 8 {
            let Some(byte) = bytes.get(index).copied() else {
                return false;
            };
            let Some(slot_byte) = memory.get_mut(offset.saturating_add(index)) else {
                return false;
            };
            *slot_byte = byte ^ memory_mask(memory_key, offset.saturating_add(index));
            index = index.saturating_add(1);
        }
        slot = slot.saturating_add(1);
    }
    true
}

fn install_data(memory: &mut [u8], memory_key: u64, data: &[u8]) -> bool {
    if data.len() > VM_DATA_LIMIT || data.len() > memory.len() {
        return false;
    }
    let mut index = 0_usize;
    while index < data.len() {
        let Some(byte) = data.get(index).copied() else {
            return false;
        };
        let Some(slot) = memory.get_mut(index) else {
            return false;
        };
        *slot = byte ^ memory_mask(memory_key, index);
        index = index.saturating_add(1);
    }
    true
}

fn memory_mask(key: u64, address: usize) -> u8 {
    let mut value = key
        ^ u64::try_from(address)
            .unwrap_or(u64::MAX)
            .wrapping_mul(0x9e37_79b9_7f4a_7c15);
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    u8::try_from(value & 0xff).unwrap_or(0)
}

/// Executes a single decoded operation. Returns `None` for any semantic or
/// operand violation.
#[allow(clippy::too_many_lines)]
#[cfg(test)]
fn execute_semantic(
    decoded: &Decoded,
    registers: &mut [u64; VM_REGISTERS],
    memory: &mut [u8],
) -> Option<Flow> {
    execute_semantic_inner(decoded, registers, None, memory, None, None)
}

#[allow(
    clippy::too_many_lines,
    clippy::inline_always,
    reason = "semantic dispatch is the per-instruction hot path; avoid a call per opcode"
)]
#[inline(always)]
fn execute_semantic_inner(
    decoded: &Decoded,
    registers: &mut [u64; VM_REGISTERS],
    masks: Option<&[u64; VM_REGISTERS]>,
    memory: &mut [u8],
    memory_key: Option<u64>,
    active: Option<u64>,
) -> Option<Flow> {
    let values = &decoded.values;
    let write_binary =
        |registers: &mut [u64; VM_REGISTERS], operation: fn(u64, u64) -> u64| -> Option<()> {
            let left = reg_value(registers, masks, values, 0)?;
            let right = reg_value(registers, masks, values, 1)?;
            set_reg_value_active(registers, masks, values, 0, operation(left, right), active)
        };
    let write_binary_imm =
        |registers: &mut [u64; VM_REGISTERS], operation: fn(u64, u64) -> u64| -> Option<()> {
            let left = reg_value(registers, masks, values, 0)?;
            let right = immediate(values, 1)?;
            set_reg_value_active(registers, masks, values, 0, operation(left, right), active)
        };
    let write_unary =
        |registers: &mut [u64; VM_REGISTERS], operation: fn(u64) -> u64| -> Option<()> {
            let value = reg_value(registers, masks, values, 0)?;
            set_reg_value_active(registers, masks, values, 0, operation(value), active)
        };

    match decoded.semantic {
        SEM_NOP => Some(Flow::Continue),
        SEM_MOV_RR => {
            let source = reg_value(registers, masks, values, 1)?;
            set_reg_value_active(registers, masks, values, 0, source, active)?;
            Some(Flow::Continue)
        }
        SEM_MOV_RI => {
            let source = immediate(values, 1)?;
            set_reg_value_active(registers, masks, values, 0, source, active)?;
            Some(Flow::Continue)
        }
        SEM_ADD_RR => {
            write_binary(registers, u64::wrapping_add)?;
            Some(Flow::Continue)
        }
        SEM_ADD_RI => {
            write_binary_imm(registers, u64::wrapping_add)?;
            Some(Flow::Continue)
        }
        SEM_SUB_RR => {
            write_binary(registers, u64::wrapping_sub)?;
            Some(Flow::Continue)
        }
        SEM_SUB_RI => {
            write_binary_imm(registers, u64::wrapping_sub)?;
            Some(Flow::Continue)
        }
        SEM_MUL_RR => {
            write_binary(registers, u64::wrapping_mul)?;
            Some(Flow::Continue)
        }
        SEM_AND_RR => {
            write_binary(registers, |left, right| left & right)?;
            Some(Flow::Continue)
        }
        SEM_AND_RI => {
            write_binary_imm(registers, |left, right| left & right)?;
            Some(Flow::Continue)
        }
        SEM_OR_RR => {
            write_binary(registers, |left, right| left | right)?;
            Some(Flow::Continue)
        }
        SEM_OR_RI => {
            write_binary_imm(registers, |left, right| left | right)?;
            Some(Flow::Continue)
        }
        SEM_XOR_RR => {
            write_binary(registers, |left, right| left ^ right)?;
            Some(Flow::Continue)
        }
        SEM_XOR_RI => {
            write_binary_imm(registers, |left, right| left ^ right)?;
            Some(Flow::Continue)
        }
        SEM_NOT_R => {
            write_unary(registers, |value| !value)?;
            Some(Flow::Continue)
        }
        SEM_NEG_R => {
            write_unary(registers, u64::wrapping_neg)?;
            Some(Flow::Continue)
        }
        SEM_SHL_RR => {
            write_binary(registers, |left, right| {
                left.wrapping_shl(shift_amount(right))
            })?;
            Some(Flow::Continue)
        }
        SEM_SHL_RI => {
            write_binary_imm(registers, |left, right| {
                left.wrapping_shl(shift_amount(right))
            })?;
            Some(Flow::Continue)
        }
        SEM_SHR_RR => {
            write_binary(registers, |left, right| {
                left.wrapping_shr(shift_amount(right))
            })?;
            Some(Flow::Continue)
        }
        SEM_SHR_RI => {
            write_binary_imm(registers, |left, right| {
                left.wrapping_shr(shift_amount(right))
            })?;
            Some(Flow::Continue)
        }
        SEM_SAR_RR => {
            write_binary(registers, |left, right| {
                as_u64(as_i64(left).wrapping_shr(shift_amount(right)))
            })?;
            Some(Flow::Continue)
        }
        SEM_SAR_RI => {
            write_binary_imm(registers, |left, right| {
                as_u64(as_i64(left).wrapping_shr(shift_amount(right)))
            })?;
            Some(Flow::Continue)
        }
        SEM_ROTL_RR => {
            write_binary(registers, |left, right| {
                left.rotate_left(shift_amount(right))
            })?;
            Some(Flow::Continue)
        }
        SEM_ROTL_RI => {
            write_binary_imm(registers, |left, right| {
                left.rotate_left(shift_amount(right))
            })?;
            Some(Flow::Continue)
        }
        SEM_ROTR_RR => {
            write_binary(registers, |left, right| {
                left.rotate_right(shift_amount(right))
            })?;
            Some(Flow::Continue)
        }
        SEM_ROTR_RI => {
            write_binary_imm(registers, |left, right| {
                left.rotate_right(shift_amount(right))
            })?;
            Some(Flow::Continue)
        }
        SEM_CMPEQ_RR | SEM_CMPLTU_RR | SEM_CMPLTS_RR | SEM_CMPLEU_RR | SEM_CMPLES_RR => {
            let left = reg_value(registers, masks, values, 1)?;
            let right = reg_value(registers, masks, values, 2)?;
            let result = match decoded.semantic {
                SEM_CMPEQ_RR => left == right,
                SEM_CMPLTU_RR => left < right,
                SEM_CMPLTS_RR => as_i64(left) < as_i64(right),
                SEM_CMPLEU_RR => left <= right,
                _ => as_i64(left) <= as_i64(right),
            };
            set_reg_value_active(registers, masks, values, 0, u64::from(result), active)?;
            Some(Flow::Continue)
        }
        SEM_SELECT_RRRR => {
            let condition = reg_value(registers, masks, values, 1)?;
            let when_true = reg_value(registers, masks, values, 2)?;
            let when_false = reg_value(registers, masks, values, 3)?;
            let mask = 0_u64.wrapping_sub(u64::from(condition != 0));
            let selected = (when_true & mask) | (when_false & !mask);
            set_reg_value_active(registers, masks, values, 0, selected, active)?;
            Some(Flow::Continue)
        }
        SEM_LOAD8 | SEM_LOAD16 | SEM_LOAD32 | SEM_LOAD64 => {
            let width = match decoded.semantic {
                SEM_LOAD8 => 1,
                SEM_LOAD16 => 2,
                SEM_LOAD32 => 4,
                _ => 8,
            };
            let address = reg_value(registers, masks, values, 1)?;
            let effective = if active == Some(0) { 0 } else { address };
            let loaded = if active.is_some() {
                load_memory_oblivious(memory, effective, width, memory_key)?
            } else {
                load_memory_with_key(memory, effective, width, memory_key)?
            };
            set_reg_value_active(registers, masks, values, 0, loaded, active)?;
            Some(Flow::Continue)
        }
        SEM_STORE8 | SEM_STORE16 | SEM_STORE32 | SEM_STORE64 => {
            let width = match decoded.semantic {
                SEM_STORE8 => 1,
                SEM_STORE16 => 2,
                SEM_STORE32 => 4,
                _ => 8,
            };
            let address = reg_value(registers, masks, values, 0)?;
            let value = reg_value(registers, masks, values, 1)?;
            let effective = if active == Some(0) { 0 } else { address };
            if active.is_some() {
                store_memory_oblivious(memory, effective, width, value, memory_key, active)?;
            } else {
                store_memory_with_key(memory, effective, width, value, memory_key)?;
            }
            Some(Flow::Continue)
        }
        SEM_JMP => {
            let target = immediate(values, 0)?;
            let mix = reg_value(registers, masks, values, 1)?;
            Some(Flow::Jump(target.wrapping_add(mix).wrapping_sub(mix)))
        }
        SEM_JCC => {
            let condition = reg_value(registers, masks, values, 0)?;
            let true_target = immediate(values, 1)?;
            let false_target = immediate(values, 2)?;
            let mix = reg_value(registers, masks, values, 3)?;
            let true_target = true_target.wrapping_add(mix).wrapping_sub(mix);
            let false_target = false_target.wrapping_add(mix).wrapping_sub(mix);
            if active.is_some() {
                Some(Flow::Branch {
                    condition,
                    when_true: true_target,
                    when_false: false_target,
                })
            } else {
                let mask = 0_u64.wrapping_sub(u64::from(condition != 0));
                Some(Flow::Jump((true_target & mask) | (false_target & !mask)))
            }
        }
        SEM_RET => {
            let value = reg_value(registers, masks, values, 0)?;
            Some(Flow::Return(value))
        }
        SEM_CALL => {
            let callee = immediate(values, 0)?;
            let return_state = immediate(values, 1)?;
            Some(Flow::Call {
                callee,
                return_state,
            })
        }
        SEM_BSWAP => {
            let value = reg_value(registers, masks, values, 0)?;
            let code = immediate(values, 1)?;
            let swapped = match code {
                0 => u64::from(u32::try_from(value & 0xffff_ffff).ok()?.swap_bytes()),
                1 => value.swap_bytes(),
                _ => return None,
            };
            set_reg_value_active(registers, masks, values, 0, swapped, active)?;
            Some(Flow::Continue)
        }
        SEM_REP_MOVS | SEM_REP_STOS => {
            if active.is_some() {
                return None;
            }
            let width_code = immediate(values, 0)?;
            execute_rep(
                registers,
                masks,
                memory,
                memory_key,
                width_code,
                decoded.semantic == SEM_REP_MOVS,
            )?;
            Some(Flow::Continue)
        }
        SEM_TRAP => Some(Flow::Trap),
        _ => None,
    }
}

fn execute_rep(
    registers: &mut [u64; VM_REGISTERS],
    masks: Option<&[u64; VM_REGISTERS]>,
    memory: &mut [u8],
    memory_key: Option<u64>,
    width_code: u64,
    copy: bool,
) -> Option<()> {
    let width = match width_code {
        0 => 1_usize,
        1 => 8_usize,
        _ => return None,
    };
    let count = get_reg_value_raw(registers, masks, REG_RCX)?;
    let maximum = u64::try_from(VM_MEMORY_SIZE / width).ok()?;
    if count > maximum {
        return None;
    }
    let mut source = get_reg_value_raw(registers, masks, REG_RSI)?;
    let mut destination = get_reg_value_raw(registers, masks, REG_RDI)?;
    let fill = get_reg_value_raw(registers, masks, REG_RAX)?;
    let mut index = 0_u64;
    while index < count {
        let value = if copy {
            load_memory_with_key(memory, source, width, memory_key)?
        } else {
            fill
        };
        store_memory_with_key(memory, destination, width, value, memory_key)?;
        if copy {
            source = source.checked_add(u64::try_from(width).ok()?)?;
        }
        destination = destination.checked_add(u64::try_from(width).ok()?)?;
        index = index.saturating_add(1);
    }
    set_reg_value_raw(registers, masks, REG_RSI, source)?;
    set_reg_value_raw(registers, masks, REG_RDI, destination)?;
    set_reg_value_raw(registers, masks, REG_RCX, 0)?;
    Some(())
}

fn load_memory_oblivious(
    memory: &[u8],
    address: u64,
    width: usize,
    memory_key: Option<u64>,
) -> Option<u64> {
    if width == 0 || width > 8 {
        return None;
    }
    let length = u64::try_from(memory.len()).ok()?;
    let mut valid = u64::MAX;
    let mut value = 0_u64;
    let mut index = 0_usize;
    while index < width {
        let target = address.wrapping_add(u64::try_from(index).ok()?);
        let mut selected = 0_u8;
        let mut position = 0_usize;
        while position < memory.len() {
            let byte = memory.get(position).copied()?;
            let plain = memory_key.map_or(byte, |key| byte ^ memory_mask(key, position));
            let same = u64::from(u64::try_from(position).unwrap_or(u64::MAX) == target);
            let mask = 0_u8.wrapping_sub(u8::try_from(same).unwrap_or(0));
            selected |= plain & mask;
            position = position.saturating_add(1);
        }
        valid &= u64::from(target < length);
        let shift = u32::try_from(index.wrapping_mul(8)).ok()?;
        value |= u64::from(selected) << shift;
        index = index.saturating_add(1);
    }
    if valid == 0 {
        return None;
    }
    Some(value)
}

fn store_memory_oblivious(
    memory: &mut [u8],
    address: u64,
    width: usize,
    value: u64,
    memory_key: Option<u64>,
    active: Option<u64>,
) -> Option<()> {
    let write = active != Some(0);
    if width == 0 || width > 8 {
        return None;
    }
    let length = u64::try_from(memory.len()).ok()?;
    let mut valid = u64::MAX;
    let mut index = 0_usize;
    while index < width {
        let target = address.wrapping_add(u64::try_from(index).ok()?);
        let shift = u32::try_from(index.wrapping_mul(8)).ok()?;
        let new_byte = u8::try_from((value >> shift) & 0xff).ok()?;
        let mut position = 0_usize;
        while position < memory.len() {
            let old = memory.get(position).copied()?;
            let plain = memory_key.map_or(old, |key| old ^ memory_mask(key, position));
            let same = u64::from(u64::try_from(position).unwrap_or(u64::MAX) == target);
            let mask = 0_u8.wrapping_sub(u8::try_from(same).unwrap_or(0));
            let chosen = if write {
                (new_byte & mask) | (plain & !mask)
            } else {
                plain
            };
            let stored = memory_key.map_or(chosen, |key| chosen ^ memory_mask(key, position));
            if let Some(slot) = memory.get_mut(position) {
                *slot = stored;
            }
            position = position.saturating_add(1);
        }
        valid &= u64::from(target < length);
        index = index.saturating_add(1);
    }
    if valid == 0 {
        return None;
    }
    Some(())
}

#[inline]
const fn halt(status: Status, steps: u64) -> Run {
    Run {
        value: 0,
        status,
        steps,
    }
}

#[inline]
fn read_manifest_u64_at(payload: &[u8], key: u64, start: usize, big_endian: bool) -> Option<u64> {
    let mut bytes = [0_u8; 8];
    let mut index = 0_usize;
    while index < 8 {
        let position = start.checked_add(index)?;
        let raw = payload.get(position).copied()?;
        let plain = manifest_byte(key, position, raw);
        if let Some(slot) = bytes.get_mut(index) {
            *slot = plain;
        }
        index = index.checked_add(1)?;
    }
    Some(decode_manifest_u64(&bytes, big_endian))
}

#[inline]
fn read_manifest_u32_at(payload: &[u8], key: u64, start: usize, big_endian: bool) -> Option<u32> {
    let mut bytes = [0_u8; 4];
    let mut index = 0_usize;
    while index < 4 {
        let position = start.checked_add(index)?;
        let raw = payload.get(position).copied()?;
        let plain = manifest_byte(key, position, raw);
        if let Some(slot) = bytes.get_mut(index) {
            *slot = plain;
        }
        index = index.checked_add(1)?;
    }
    Some(decode_manifest_u32(&bytes, big_endian))
}

fn load_manifest(
    payload: &[u8],
    key: u64,
    big_endian: bool,
    tags: &mut [u64; MAX_PAYLOAD_BLOCKS],
    offsets: &mut [u32; MAX_PAYLOAD_BLOCKS],
    lengths: &mut [u32; MAX_PAYLOAD_BLOCKS],
) -> Option<(usize, usize)> {
    let count_value = read_manifest_u64_at(payload, key, 0, big_endian)?;
    let count = usize::try_from(count_value).ok()?;
    if count == 0 || count > MAX_PAYLOAD_BLOCKS {
        return None;
    }
    let manifest_len = manifest_size(count)?;
    if manifest_len > payload.len() {
        return None;
    }
    let mut index = 0_usize;
    while index < count {
        let entry_relative = index.checked_mul(MANIFEST_ENTRY_BYTES)?;
        let entry_start = MANIFEST_COUNT_BYTES.checked_add(entry_relative)?;
        let tag = read_manifest_u64_at(payload, key, entry_start, big_endian)?;
        let offset_start = entry_start.checked_add(8)?;
        let length_start = offset_start.checked_add(4)?;
        let offset = read_manifest_u32_at(payload, key, offset_start, big_endian)?;
        let length = read_manifest_u32_at(payload, key, length_start, big_endian)?;
        let offset = usize::try_from(offset).ok()?;
        let length = usize::try_from(length).ok()?;
        let end = offset.checked_add(length)?;
        if offset < manifest_len || length == 0 || end > payload.len() {
            return None;
        }
        *tags.get_mut(index)? = tag;
        *offsets.get_mut(index)? = u32::try_from(offset).ok()?;
        *lengths.get_mut(index)? = u32::try_from(length).ok()?;
        index = index.saturating_add(1);
    }
    Some((count, manifest_len))
}

/// Executes a protected function with tables derived from the plan seed.
#[inline]
#[must_use]
pub fn execute(input: VmInput<'_>, entry_index: usize, args: [u64; 6]) -> Run {
    let tables = Tables::derive(input.seed).decode_tables();
    execute_with_tables(input, entry_index, args, &tables)
}

/// Executes a protected function with a data-independent instruction stream,
/// deriving the decode tables from the plan seed.
#[inline]
#[must_use]
pub fn execute_oblivious(
    input: VmInput<'_>,
    entry_index: usize,
    args: [u64; 6],
    passes: usize,
) -> Run {
    let tables = Tables::derive(input.seed).decode_tables();
    execute_oblivious_with_tables(input, entry_index, args, &tables, passes)
}

/// Executes a protected function using a precomputed decode table.
#[inline]
#[must_use]
pub fn execute_with_tables(
    input: VmInput<'_>,
    entry_index: usize,
    args: [u64; 6],
    tables: &DecodeTables,
) -> Run {
    execute_with_tables_and_stack(input, entry_index, args, [0_u64; 6], tables)
}

fn execute_with_tables_and_stack(
    input: VmInput<'_>,
    entry_index: usize,
    args: [u64; 6],
    stack_args: [u64; 6],
    tables: &DecodeTables,
) -> Run {
    let mut steps = 0_u64;
    let mut fuel = input.fuel;
    let actual_hash = payload_hash(input.seed, input.payload);
    let key = effective_key(input.base_a, input.base_b, actual_hash, input.expected_hash);
    let Some(entry) = input.entry_states.get(entry_index) else {
        return halt(Status::BadPayload, steps);
    };
    let [entry_a, entry_b] = *entry;
    let mut state = entry_a ^ entry_b;
    let fill_key = key ^ 0x9e37_79b9_7f4a_7c15;
    let masks: [u64; VM_REGISTERS] = core::array::from_fn(|index| {
        fill_key
            .rotate_left(u32::try_from(index.wrapping_mul(7) & 63).unwrap_or(0))
            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
            .rotate_left(u32::try_from(index & 63).unwrap_or(0))
    });
    let mut registers: [u64; VM_REGISTERS] = core::array::from_fn(|index| {
        fill_key.rotate_left(u32::try_from(index & 63).unwrap_or(0))
            ^ masks.get(index).copied().unwrap_or(0)
    });
    let memory_key = key.rotate_left(23) ^ 0xa5a5_5a5a_9696_6969;
    let [
        argument0,
        argument1,
        argument2,
        argument3,
        argument4,
        argument5,
    ] = args;
    let _ = set_reg_value_raw(&mut registers, Some(&masks), REG_RDI, argument0);
    let _ = set_reg_value_raw(&mut registers, Some(&masks), REG_RSI, argument1);
    let _ = set_reg_value_raw(&mut registers, Some(&masks), REG_RDX, argument2);
    let _ = set_reg_value_raw(&mut registers, Some(&masks), REG_RCX, argument3);
    let _ = set_reg_value_raw(&mut registers, Some(&masks), REG_R8, argument4);
    let _ = set_reg_value_raw(&mut registers, Some(&masks), REG_R9, argument5);
    let _ = set_reg_value_raw(&mut registers, Some(&masks), REG_RSP, VM_STACK_ARG_BASE);
    let _ = set_reg_value_raw(&mut registers, Some(&masks), REG_RAX, 0);
    let fill_byte = u8::try_from(fill_key & 0xff).unwrap_or(0);
    let mut memory: [u8; VM_MEMORY_SIZE] = core::array::from_fn(|index| {
        (u8::try_from(index & 0xff).unwrap_or(0) ^ fill_byte) ^ memory_mask(memory_key, index)
    });
    if !install_data(&mut memory, memory_key, input.data) {
        return halt(Status::BadPayload, steps);
    }
    if !install_stack_arguments(&mut memory, memory_key, stack_args) {
        return halt(Status::BadPayload, steps);
    }

    let mut tags = [0_u64; MAX_PAYLOAD_BLOCKS];
    let mut offsets = [0_u32; MAX_PAYLOAD_BLOCKS];
    let mut lengths = [0_u32; MAX_PAYLOAD_BLOCKS];
    let Some((count, _manifest_len)) = load_manifest(
        input.payload,
        key,
        tables.manifest_big_endian,
        &mut tags,
        &mut offsets,
        &mut lengths,
    ) else {
        return halt(Status::BadPayload, steps);
    };
    let scan_cost = u64::try_from(count).unwrap_or(u64::MAX);
    if fuel < scan_cost {
        return halt(Status::FuelExhausted, steps);
    }
    fuel = fuel.saturating_sub(scan_cost);
    steps = steps.saturating_add(scan_cost);

    let mut call_stack = [0_u64; MAX_CALL_DEPTH];
    let mut call_depth = 0_usize;
    'dispatch: loop {
        let mut found: Option<(usize, usize)> = None;
        let mut entry_index_scan = 0_usize;
        while entry_index_scan < count {
            if tags.get(entry_index_scan).copied() == Some(state) {
                let Some(offset) = offsets.get(entry_index_scan).copied() else {
                    return halt(Status::BadPayload, steps);
                };
                let Some(length) = lengths.get(entry_index_scan).copied() else {
                    return halt(Status::BadPayload, steps);
                };
                found = Some((
                    usize::try_from(offset).unwrap_or(usize::MAX),
                    usize::try_from(length).unwrap_or(usize::MAX),
                ));
                break;
            }
            entry_index_scan = entry_index_scan.saturating_add(1);
        }
        let Some((body_start, body_length)) = found else {
            return halt(Status::BadPayload, steps);
        };
        let Some(body_end) = body_start.checked_add(body_length) else {
            return halt(Status::BadPayload, steps);
        };

        let mut reader = BodyReader::new(
            input.payload,
            tables,
            BodyCipher::new(key, state, body_start),
            body_start,
            body_end,
        );
        loop {
            if fuel == 0 {
                return halt(Status::FuelExhausted, steps);
            }
            fuel = fuel.saturating_sub(1);
            steps = steps.saturating_add(1);
            let Some(decoded) = reader.read_instruction() else {
                return halt(Status::BadPayload, steps);
            };
            let Some(flow) = execute_semantic_inner(
                &decoded,
                &mut registers,
                Some(&masks),
                &mut memory,
                Some(memory_key),
                None,
            ) else {
                return halt(Status::BadPayload, steps);
            };
            match flow {
                Flow::Continue => {
                    if reader.position >= reader.end {
                        return halt(Status::BadPayload, steps);
                    }
                }
                Flow::Jump(target) => {
                    state = target;
                    continue 'dispatch;
                }
                Flow::Branch {
                    condition,
                    when_true,
                    when_false,
                } => {
                    let mask = 0_u64.wrapping_sub(u64::from(condition != 0));
                    state = (when_true & mask) | (when_false & !mask);
                    continue 'dispatch;
                }
                Flow::Call {
                    callee,
                    return_state,
                } => {
                    if call_depth >= MAX_CALL_DEPTH {
                        return halt(Status::Trap, steps);
                    }
                    let Some(slot) = call_stack.get_mut(call_depth) else {
                        return halt(Status::Trap, steps);
                    };
                    *slot = return_state;
                    call_depth = call_depth.saturating_add(1);
                    state = callee;
                    continue 'dispatch;
                }
                Flow::Return(value) => {
                    if call_depth > 0 {
                        call_depth = call_depth.saturating_sub(1);
                        let Some(return_state) = call_stack.get(call_depth).copied() else {
                            return halt(Status::Trap, steps);
                        };
                        let _ = set_reg_value_raw(&mut registers, Some(&masks), REG_RAX, value);
                        state = return_state;
                        continue 'dispatch;
                    }
                    return Run {
                        value,
                        status: Status::Returned,
                        steps,
                    };
                }
                Flow::Trap => return halt(Status::Trap, steps),
            }
        }
    }
}

/// Dispatches to normal or oblivious execution using build-time constants.
#[inline]
#[must_use]
pub fn execute_entry(
    input: VmInput<'_>,
    entry_index: usize,
    args: [u64; 6],
    tables: &DecodeTables,
    constant_time: bool,
    passes: usize,
) -> Run {
    if constant_time {
        execute_oblivious_with_tables(input, entry_index, args, tables, passes)
    } else {
        execute_with_tables(input, entry_index, args, tables)
    }
}

/// Dispatches to normal or oblivious execution with stack arguments.
#[inline]
#[must_use]
pub fn execute_entry_with_stack(
    input: VmInput<'_>,
    entry_index: usize,
    args: [u64; 6],
    stack_args: [u64; 6],
    tables: &DecodeTables,
    constant_time: bool,
    passes: usize,
) -> Run {
    if constant_time {
        execute_oblivious_with_tables_and_stack(
            input,
            entry_index,
            args,
            stack_args,
            tables,
            passes,
        )
    } else {
        execute_with_tables_and_stack(input, entry_index, args, stack_args, tables)
    }
}

/// Maximum nested guest-call depth.
pub const MAX_CALL_DEPTH: usize = 16;

/// Default fixed pass budget for oblivious execution.
pub const DEFAULT_OBLIVIOUS_PASSES: usize = 256;

/// Executes a protected function with a data-independent instruction stream.
///
/// Every manifest block is decoded and executed on every pass. A frontier mask
/// carries the active path, and all register writes are predicated with a
/// bitwise select. The pass count is fixed by the caller, so branch and loop
/// decisions do not change the executed instruction count or memory addresses.
#[inline]
#[allow(
    clippy::too_many_lines,
    reason = "oblivious runner keeps one linear frontier transaction"
)]
#[must_use]
pub fn execute_oblivious_with_tables(
    input: VmInput<'_>,
    entry_index: usize,
    args: [u64; 6],
    tables: &DecodeTables,
    passes: usize,
) -> Run {
    execute_oblivious_with_tables_and_stack(input, entry_index, args, [0_u64; 6], tables, passes)
}

fn execute_oblivious_with_tables_and_stack(
    input: VmInput<'_>,
    entry_index: usize,
    args: [u64; 6],
    stack_args: [u64; 6],
    tables: &DecodeTables,
    passes: usize,
) -> Run {
    let mut steps = 0_u64;
    let mut fuel = input.fuel;
    let actual_hash = payload_hash(input.seed, input.payload);
    let key = effective_key(input.base_a, input.base_b, actual_hash, input.expected_hash);
    let Some(entry) = input.entry_states.get(entry_index) else {
        return halt(Status::BadPayload, steps);
    };
    let [entry_a, entry_b] = *entry;
    let entry_state = entry_a ^ entry_b;
    let fill_key = key ^ 0x9e37_79b9_7f4a_7c15;
    let masks: [u64; VM_REGISTERS] = core::array::from_fn(|index| {
        fill_key
            .rotate_left(u32::try_from(index.wrapping_mul(7) & 63).unwrap_or(0))
            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
            .rotate_left(u32::try_from(index & 63).unwrap_or(0))
    });
    let mut registers: [u64; VM_REGISTERS] = core::array::from_fn(|index| {
        fill_key.rotate_left(u32::try_from(index & 63).unwrap_or(0))
            ^ masks.get(index).copied().unwrap_or(0)
    });
    let memory_key = key.rotate_left(23) ^ 0xa5a5_5a5a_9696_6969;
    let [
        argument0,
        argument1,
        argument2,
        argument3,
        argument4,
        argument5,
    ] = args;
    let _ = set_reg_value_raw(&mut registers, Some(&masks), REG_RDI, argument0);
    let _ = set_reg_value_raw(&mut registers, Some(&masks), REG_RSI, argument1);
    let _ = set_reg_value_raw(&mut registers, Some(&masks), REG_RDX, argument2);
    let _ = set_reg_value_raw(&mut registers, Some(&masks), REG_RCX, argument3);
    let _ = set_reg_value_raw(&mut registers, Some(&masks), REG_R8, argument4);
    let _ = set_reg_value_raw(&mut registers, Some(&masks), REG_R9, argument5);
    let _ = set_reg_value_raw(&mut registers, Some(&masks), REG_RSP, VM_STACK_ARG_BASE);
    let _ = set_reg_value_raw(&mut registers, Some(&masks), REG_RAX, 0);
    let fill_byte = u8::try_from(fill_key & 0xff).unwrap_or(0);
    let mut memory: [u8; VM_MEMORY_SIZE] = core::array::from_fn(|index| {
        (u8::try_from(index & 0xff).unwrap_or(0) ^ fill_byte) ^ memory_mask(memory_key, index)
    });
    if !install_data(&mut memory, memory_key, input.data) {
        return halt(Status::BadPayload, steps);
    }
    if !install_stack_arguments(&mut memory, memory_key, stack_args) {
        return halt(Status::BadPayload, steps);
    }

    let Some(count_value) = read_manifest_u64_at(input.payload, key, 0, tables.manifest_big_endian)
    else {
        return halt(Status::BadPayload, steps);
    };
    let Ok(count) = usize::try_from(count_value) else {
        return halt(Status::BadPayload, steps);
    };
    if count == 0 || count > MAX_PAYLOAD_BLOCKS {
        return halt(Status::BadPayload, steps);
    }
    let Some(manifest_len) = manifest_size(count) else {
        return halt(Status::BadPayload, steps);
    };
    if manifest_len > input.payload.len() {
        return halt(Status::BadPayload, steps);
    }
    let scan_cost = u64::try_from(count).unwrap_or(u64::MAX);
    if fuel < scan_cost {
        return halt(Status::FuelExhausted, steps);
    }
    fuel = fuel.saturating_sub(scan_cost);
    steps = steps.saturating_add(scan_cost);

    let mut tags = [0_u64; MAX_PAYLOAD_BLOCKS];
    let mut offsets = [0_usize; MAX_PAYLOAD_BLOCKS];
    let mut lengths = [0_usize; MAX_PAYLOAD_BLOCKS];
    let mut index = 0_usize;
    while index < count {
        let Some(entry_relative) = index.checked_mul(MANIFEST_ENTRY_BYTES) else {
            return halt(Status::BadPayload, steps);
        };
        let Some(entry_start) = MANIFEST_COUNT_BYTES.checked_add(entry_relative) else {
            return halt(Status::BadPayload, steps);
        };
        let Some(offset_start) = entry_start.checked_add(8) else {
            return halt(Status::BadPayload, steps);
        };
        let Some(length_start) = offset_start.checked_add(4) else {
            return halt(Status::BadPayload, steps);
        };
        let Some(tag) =
            read_manifest_u64_at(input.payload, key, entry_start, tables.manifest_big_endian)
        else {
            return halt(Status::BadPayload, steps);
        };
        let Some(offset) =
            read_manifest_u32_at(input.payload, key, offset_start, tables.manifest_big_endian)
        else {
            return halt(Status::BadPayload, steps);
        };
        let Some(length) =
            read_manifest_u32_at(input.payload, key, length_start, tables.manifest_big_endian)
        else {
            return halt(Status::BadPayload, steps);
        };
        let Ok(offset) = usize::try_from(offset) else {
            return halt(Status::BadPayload, steps);
        };
        let Ok(length) = usize::try_from(length) else {
            return halt(Status::BadPayload, steps);
        };
        if offset < manifest_len || length == 0 {
            return halt(Status::BadPayload, steps);
        }
        let Some(end) = offset.checked_add(length) else {
            return halt(Status::BadPayload, steps);
        };
        if end > input.payload.len() {
            return halt(Status::BadPayload, steps);
        }
        if let Some(slot) = tags.get_mut(index) {
            *slot = tag;
        }
        if let Some(slot) = offsets.get_mut(index) {
            *slot = offset;
        }
        if let Some(slot) = lengths.get_mut(index) {
            *slot = length;
        }
        index = index.saturating_add(1);
    }

    let mut entry_block = None;
    let mut scan = 0_usize;
    while scan < count {
        if tags.get(scan).copied() == Some(entry_state) {
            entry_block = Some(scan);
        }
        scan = scan.saturating_add(1);
    }
    let Some(entry_block) = entry_block else {
        return halt(Status::BadPayload, steps);
    };
    let mut current = [0_u64; MAX_PAYLOAD_BLOCKS];
    if let Some(slot) = current.get_mut(entry_block) {
        *slot = u64::MAX;
    }
    let mut result = 0_u64;
    let mut returned = 0_u64;
    let mut trapped = 0_u64;
    let mut pass = 0_usize;
    while pass < passes {
        let mut next = [0_u64; MAX_PAYLOAD_BLOCKS];
        let mut block_index = 0_usize;
        while block_index < count {
            let apply = current.get(block_index).copied().unwrap_or(0);
            trace_event("block", pass, block_index, apply, 0, 0);
            let Some(tag) = tags.get(block_index).copied() else {
                return halt(Status::BadPayload, steps);
            };
            let Some(offset) = offsets.get(block_index).copied() else {
                return halt(Status::BadPayload, steps);
            };
            let Some(length) = lengths.get(block_index).copied() else {
                return halt(Status::BadPayload, steps);
            };
            if fuel == 0 {
                return halt(Status::FuelExhausted, steps);
            }
            fuel = fuel.saturating_sub(1);
            steps = steps.saturating_add(1);
            let Some(end) = offset.checked_add(length) else {
                return halt(Status::BadPayload, steps);
            };
            let mut reader = BodyReader::new(
                input.payload,
                tables,
                BodyCipher::new(key, tag, offset),
                offset,
                end,
            );
            loop {
                if fuel == 0 {
                    return halt(Status::FuelExhausted, steps);
                }
                fuel = fuel.saturating_sub(1);
                steps = steps.saturating_add(1);
                let Some(decoded) = reader.read_instruction() else {
                    return halt(Status::BadPayload, steps);
                };
                trace_event("op", pass, block_index, apply, decoded.semantic, 0);
                let Some(flow) = execute_semantic_inner(
                    &decoded,
                    &mut registers,
                    Some(&masks),
                    &mut memory,
                    Some(memory_key),
                    Some(apply),
                ) else {
                    trace_event("sem-fail", pass, block_index, apply, decoded.semantic, 0);
                    return halt(Status::BadPayload, steps);
                };
                match flow {
                    Flow::Continue => {
                        if reader.position >= reader.end {
                            return halt(Status::BadPayload, steps);
                        }
                    }
                    Flow::Jump(target) => {
                        let Some(()) = enqueue_target(target, apply, &tags, count, &mut next)
                        else {
                            return halt(Status::BadPayload, steps);
                        };
                        break;
                    }
                    Flow::Branch {
                        condition,
                        when_true,
                        when_false,
                    } => {
                        let mask = 0_u64.wrapping_sub(u64::from(condition != 0));
                        let Some(()) =
                            enqueue_target(when_true, apply & mask, &tags, count, &mut next)
                        else {
                            return halt(Status::BadPayload, steps);
                        };
                        let Some(()) =
                            enqueue_target(when_false, apply & !mask, &tags, count, &mut next)
                        else {
                            return halt(Status::BadPayload, steps);
                        };
                        break;
                    }
                    Flow::Call { .. } => {
                        return halt(Status::BadPayload, steps);
                    }
                    Flow::Return(value) => {
                        trace_event("return", pass, block_index, apply, 0, value);
                        result |= apply & value;
                        returned |= apply;
                        break;
                    }
                    Flow::Trap => {
                        trapped |= apply;
                        break;
                    }
                }
            }
            block_index = block_index.saturating_add(1);
        }
        current = next;
        pass = pass.saturating_add(1);
    }

    let mut active = 0_u64;
    let mut position = 0_usize;
    while position < count {
        active |= current.get(position).copied().unwrap_or(0);
        position = position.saturating_add(1);
    }
    if returned != 0 {
        Run {
            value: result,
            status: Status::Returned,
            steps,
        }
    } else if trapped != 0 {
        halt(Status::Trap, steps)
    } else if active != 0 {
        halt(Status::LoopBound, steps)
    } else {
        halt(Status::BadPayload, steps)
    }
}

#[cfg(feature = "trace")]
#[allow(
    clippy::print_stderr,
    reason = "the trace feature is an explicit diagnostic build; it writes to stderr by design"
)]
fn trace_event(phase: &str, pass: usize, block: usize, apply: u64, semantic: u8, value: u64) {
    std::eprintln!(
        "CT {phase} pass={pass} block={block} apply={apply:#x} sem={semantic} value={value:#x}"
    );
}

#[cfg(not(feature = "trace"))]
const fn trace_event(
    _phase: &str,
    _pass: usize,
    _block: usize,
    _apply: u64,
    _semantic: u8,
    _value: u64,
) {
}

fn enqueue_target(
    target: u64,
    mask: u64,
    tags: &[u64; MAX_PAYLOAD_BLOCKS],
    count: usize,
    next: &mut [u64; MAX_PAYLOAD_BLOCKS],
) -> Option<()> {
    let mut index = 0_usize;
    let mut found = None;
    while index < count {
        if tags.get(index).copied() == Some(target) {
            found = Some(index);
        }
        index = index.saturating_add(1);
    }
    let index = found?;
    let slot = next.get_mut(index)?;
    *slot |= mask;
    Some(())
}

#[inline]
fn get_reg_value_raw(
    registers: &[u64; VM_REGISTERS],
    masks: Option<&[u64; VM_REGISTERS]>,
    slot: u8,
) -> Option<u64> {
    let index = usize::from(slot);
    let stored = registers.get(index).copied()?;
    match masks {
        Some(masks) => Some(stored ^ masks.get(index).copied()?),
        None => Some(stored),
    }
}

fn set_reg_value_raw(
    registers: &mut [u64; VM_REGISTERS],
    masks: Option<&[u64; VM_REGISTERS]>,
    slot: u8,
    value: u64,
) -> Option<()> {
    let target = usize::from(slot);
    let mask = match masks {
        Some(masks) => masks.get(target).copied()?,
        None => 0,
    };
    let slot = registers.get_mut(target)?;
    *slot = value ^ mask;
    Some(())
}

#[cfg(test)]
mod tests {
    use super::{
        Decoded, Flow, as_i64, as_u64, execute_semantic, load_memory, load_memory_with_key,
        reg_value, set_reg_value, set_reg_value_active, shift_amount, store_memory,
        store_memory_with_key,
    };
    use crate::shared::format::{
        MAX_OPERANDS, REG_RAX, REG_RBX, REG_RCX, REG_RDX, REG_RSP, SEM_ADD_RI, SEM_ADD_RR,
        SEM_AND_RI, SEM_AND_RR, SEM_CMPEQ_RR, SEM_CMPLES_RR, SEM_CMPLEU_RR, SEM_CMPLTS_RR, SEM_JCC,
        SEM_JMP, SEM_LOAD8, SEM_LOAD16, SEM_LOAD32, SEM_LOAD64, SEM_MOV_RI, SEM_MOV_RR, SEM_MUL_RR,
        SEM_NEG_R, SEM_NOP, SEM_NOT_R, SEM_OR_RI, SEM_OR_RR, SEM_RET, SEM_ROTL_RI, SEM_ROTL_RR,
        SEM_ROTR_RI, SEM_ROTR_RR, SEM_SAR_RI, SEM_SAR_RR, SEM_SELECT_RRRR, SEM_SHL_RI, SEM_SHL_RR,
        SEM_SHR_RI, SEM_SHR_RR, SEM_STORE8, SEM_STORE16, SEM_STORE32, SEM_STORE64, SEM_SUB_RI,
        SEM_SUB_RR, SEM_XOR_RI, SEM_XOR_RR, VM_MEMORY_SIZE, VM_REGISTERS,
    };

    fn registers() -> [u64; VM_REGISTERS] {
        [0_u64; VM_REGISTERS]
    }

    fn memory() -> [u8; VM_MEMORY_SIZE] {
        [0_u8; VM_MEMORY_SIZE]
    }

    fn decoded(semantic: u8, values: [u64; MAX_OPERANDS]) -> Decoded {
        Decoded { semantic, values }
    }

    fn set(registers: &mut [u64; VM_REGISTERS], slot: u8, value: u64) {
        if let Some(target) = registers.get_mut(usize::from(slot)) {
            *target = value;
        }
    }

    fn get(registers: &[u64; VM_REGISTERS], slot: u8) -> u64 {
        registers.get(usize::from(slot)).copied().unwrap_or(0)
    }

    #[test]
    fn active_register_writes_are_predicated() {
        let mut regs = registers();
        let values = [u64::from(REG_RAX), 0, 0, 0];
        set(&mut regs, REG_RAX, 7);
        set_reg_value_active(&mut regs, None, &values, 0, 9, Some(0)).expect("inactive");
        assert_eq!(get(&regs, REG_RAX), 7);
        set_reg_value_active(&mut regs, None, &values, 0, 9, Some(1)).expect("active");
        assert_eq!(get(&regs, REG_RAX), 9);
    }

    #[test]
    fn arithmetic_and_bitwise_semantics() {
        let mut regs = registers();
        let mut mem = memory();
        set(&mut regs, REG_RAX, 10);
        set(&mut regs, REG_RCX, 3);
        assert_eq!(
            execute_semantic(
                &decoded(SEM_ADD_RR, [u64::from(REG_RAX), u64::from(REG_RCX), 0, 0]),
                &mut regs,
                &mut mem
            ),
            Some(Flow::Continue)
        );
        assert_eq!(get(&regs, REG_RAX), 13);
        assert_eq!(
            execute_semantic(
                &decoded(SEM_MUL_RR, [u64::from(REG_RAX), u64::from(REG_RCX), 0, 0]),
                &mut regs,
                &mut mem
            ),
            Some(Flow::Continue)
        );
        assert_eq!(get(&regs, REG_RAX), 39);
        assert_eq!(
            execute_semantic(
                &decoded(SEM_SUB_RR, [u64::from(REG_RAX), u64::from(REG_RCX), 0, 0]),
                &mut regs,
                &mut mem
            ),
            Some(Flow::Continue)
        );
        assert_eq!(get(&regs, REG_RAX), 36);
        assert_eq!(
            execute_semantic(
                &decoded(SEM_XOR_RR, [u64::from(REG_RAX), u64::from(REG_RCX), 0, 0]),
                &mut regs,
                &mut mem
            ),
            Some(Flow::Continue)
        );
        assert_eq!(get(&regs, REG_RAX), 39);
        assert_eq!(
            execute_semantic(
                &decoded(SEM_AND_RR, [u64::from(REG_RAX), u64::from(REG_RCX), 0, 0]),
                &mut regs,
                &mut mem
            ),
            Some(Flow::Continue)
        );
        assert_eq!(get(&regs, REG_RAX), 3);
        assert_eq!(
            execute_semantic(
                &decoded(SEM_OR_RR, [u64::from(REG_RAX), u64::from(REG_RCX), 0, 0]),
                &mut regs,
                &mut mem
            ),
            Some(Flow::Continue)
        );
        assert_eq!(get(&regs, REG_RAX), 3);
    }

    #[test]
    fn remaining_semantic_families_are_covered() {
        let mut regs = registers();
        let mut mem = memory();
        let rax = u64::from(REG_RAX);
        let rcx = u64::from(REG_RCX);
        set(&mut regs, REG_RAX, 0x55);
        set(&mut regs, REG_RCX, 4);
        for instruction in [
            decoded(SEM_NOP, [0; 4]),
            decoded(SEM_SUB_RI, [rax, 5, 0, 0]),
            decoded(SEM_AND_RI, [rax, 0x0f, 0, 0]),
            decoded(SEM_OR_RI, [rax, 0x80, 0, 0]),
            decoded(SEM_XOR_RI, [rax, 0x11, 0, 0]),
            decoded(SEM_SHL_RR, [rax, rcx, 0, 0]),
            decoded(SEM_SHR_RR, [rax, rcx, 0, 0]),
            decoded(SEM_SAR_RR, [rax, rcx, 0, 0]),
            decoded(SEM_ROTL_RR, [rax, rcx, 0, 0]),
            decoded(SEM_ROTR_RR, [rax, rcx, 0, 0]),
            decoded(SEM_CMPLEU_RR, [rax, rcx, 0, 0]),
            decoded(SEM_CMPLES_RR, [rax, rcx, 0, 0]),
        ] {
            assert_eq!(
                execute_semantic(&instruction, &mut regs, &mut mem),
                Some(Flow::Continue)
            );
        }
        for instruction in [
            decoded(SEM_STORE8, [0, rax, 0, 0]),
            decoded(SEM_STORE16, [0, rax, 0, 0]),
            decoded(SEM_STORE32, [0, rax, 0, 0]),
            decoded(SEM_STORE64, [0, rax, 0, 0]),
        ] {
            assert_eq!(
                execute_semantic(&instruction, &mut regs, &mut mem),
                Some(Flow::Continue)
            );
        }
        let values = [rax, rax, 0, 0];
        for semantic in [SEM_LOAD8, SEM_LOAD16, SEM_LOAD32, SEM_LOAD64] {
            assert_eq!(
                execute_semantic(&decoded(semantic, values), &mut regs, &mut mem),
                Some(Flow::Continue)
            );
        }
        assert_eq!(
            execute_semantic(&decoded(255, [0; 4]), &mut regs, &mut mem),
            None
        );
    }

    #[test]
    fn immediate_and_unary_semantics() {
        let mut regs = registers();
        let mut mem = memory();
        let mut instruction = decoded(SEM_MOV_RI, [u64::from(REG_RAX), 123, 0, 0]);
        assert_eq!(
            execute_semantic(&instruction, &mut regs, &mut mem),
            Some(Flow::Continue)
        );
        assert_eq!(get(&regs, REG_RAX), 123);
        instruction = decoded(SEM_ADD_RI, [u64::from(REG_RAX), 7, 0, 0]);
        assert_eq!(
            execute_semantic(&instruction, &mut regs, &mut mem),
            Some(Flow::Continue)
        );
        assert_eq!(get(&regs, REG_RAX), 130);
        instruction = decoded(SEM_NOT_R, [u64::from(REG_RAX), 0, 0, 0]);
        assert_eq!(
            execute_semantic(&instruction, &mut regs, &mut mem),
            Some(Flow::Continue)
        );
        assert_eq!(get(&regs, REG_RAX), !130_u64);
        instruction = decoded(SEM_NEG_R, [u64::from(REG_RAX), 0, 0, 0]);
        assert_eq!(
            execute_semantic(&instruction, &mut regs, &mut mem),
            Some(Flow::Continue)
        );
        assert_eq!(get(&regs, REG_RAX), 131);
    }

    #[test]
    fn shifts_and_rotations_mask_counts() {
        assert_eq!(shift_amount(64), 0);
        assert_eq!(shift_amount(65), 1);
        assert_eq!(as_i64(0xffff_ffff_ffff_ffff) >> 1, -1);
        assert_eq!(as_u64(-1), u64::MAX);
        let mut regs = registers();
        let mut mem = memory();
        set(&mut regs, REG_RAX, 1);
        let mut instruction = decoded(SEM_SHL_RI, [u64::from(REG_RAX), 65, 0, 0]);
        assert_eq!(
            execute_semantic(&instruction, &mut regs, &mut mem),
            Some(Flow::Continue)
        );
        assert_eq!(get(&regs, REG_RAX), 2);
        instruction = decoded(SEM_SHR_RI, [u64::from(REG_RAX), 1, 0, 0]);
        assert_eq!(
            execute_semantic(&instruction, &mut regs, &mut mem),
            Some(Flow::Continue)
        );
        assert_eq!(get(&regs, REG_RAX), 1);
        instruction = decoded(SEM_SAR_RI, [u64::from(REG_RAX), 0, 0, 0]);
        assert_eq!(
            execute_semantic(&instruction, &mut regs, &mut mem),
            Some(Flow::Continue)
        );
        set(&mut regs, REG_RAX, 0x80);
        instruction = decoded(SEM_ROTL_RI, [u64::from(REG_RAX), 1, 0, 0]);
        assert_eq!(
            execute_semantic(&instruction, &mut regs, &mut mem),
            Some(Flow::Continue)
        );
        assert_eq!(get(&regs, REG_RAX), 0x100);
        instruction = decoded(SEM_ROTR_RI, [u64::from(REG_RAX), 8, 0, 0]);
        assert_eq!(
            execute_semantic(&instruction, &mut regs, &mut mem),
            Some(Flow::Continue)
        );
        assert_eq!(get(&regs, REG_RAX), 1);
    }

    #[test]
    fn comparisons_and_select_are_boolean() {
        let mut regs = registers();
        let mut mem = memory();
        set(&mut regs, REG_RAX, 42);
        set(&mut regs, REG_RCX, 42);
        set(&mut regs, REG_RDX, 7);
        let mut instruction = decoded(
            SEM_CMPEQ_RR,
            [
                u64::from(REG_RBX),
                u64::from(REG_RAX),
                u64::from(REG_RCX),
                0,
            ],
        );
        assert_eq!(
            execute_semantic(&instruction, &mut regs, &mut mem),
            Some(Flow::Continue)
        );
        assert_eq!(get(&regs, REG_RBX), 1);
        instruction = decoded(
            SEM_SELECT_RRRR,
            [
                u64::from(REG_RBX),
                u64::from(REG_RBX),
                u64::from(REG_RAX),
                u64::from(REG_RDX),
            ],
        );
        assert_eq!(
            execute_semantic(&instruction, &mut regs, &mut mem),
            Some(Flow::Continue)
        );
        assert_eq!(get(&regs, REG_RBX), 42);
        instruction = decoded(
            SEM_CMPLTS_RR,
            [
                u64::from(REG_RBX),
                u64::from(REG_RAX),
                u64::from(REG_RDX),
                0,
            ],
        );
        assert_eq!(
            execute_semantic(&instruction, &mut regs, &mut mem),
            Some(Flow::Continue)
        );
        assert_eq!(get(&regs, REG_RBX), 0);
        instruction = decoded(
            SEM_CMPLES_RR,
            [
                u64::from(REG_RBX),
                u64::from(REG_RDX),
                u64::from(REG_RAX),
                0,
            ],
        );
        assert_eq!(
            execute_semantic(&instruction, &mut regs, &mut mem),
            Some(Flow::Continue)
        );
        assert_eq!(get(&regs, REG_RBX), 1);
    }

    #[test]
    fn memory_is_little_endian_and_bounds_checked() {
        let mut memory = memory();
        assert_eq!(
            store_memory(&mut memory, 100, 8, 0x0102_0304_0506_0708),
            Some(())
        );
        assert_eq!(load_memory(&memory, 100, 8), Some(0x0102_0304_0506_0708));
        assert_eq!(load_memory(&memory, 100, 4), Some(0x0506_0708));
        assert_eq!(load_memory(&memory, 100, 1), Some(0x08));
        assert_eq!(
            load_memory(
                &memory,
                u64::try_from(VM_MEMORY_SIZE).unwrap_or(u64::MAX),
                1
            ),
            None
        );
        assert_eq!(
            store_memory(
                &mut memory,
                u64::try_from(VM_MEMORY_SIZE).unwrap_or(u64::MAX) - 1,
                8,
                0
            ),
            None
        );
    }

    #[test]
    fn load_store_semantics_validate_addresses() {
        let mut regs = registers();
        let mut mem = memory();
        set(&mut regs, REG_RSP, 100);
        set(&mut regs, REG_RAX, 0x1122_3344_5566_7788);
        let mut instruction = decoded(SEM_STORE64, [u64::from(REG_RSP), u64::from(REG_RAX), 0, 0]);
        assert_eq!(
            execute_semantic(&instruction, &mut regs, &mut mem),
            Some(Flow::Continue)
        );
        instruction = decoded(SEM_LOAD64, [u64::from(REG_RCX), u64::from(REG_RSP), 0, 0]);
        assert_eq!(
            execute_semantic(&instruction, &mut regs, &mut mem),
            Some(Flow::Continue)
        );
        assert_eq!(get(&regs, REG_RCX), 0x1122_3344_5566_7788);
        instruction = decoded(SEM_LOAD64, [u64::from(REG_RCX), u64::from(REG_RSP), 0, 0]);
        set(&mut regs, REG_RSP, u64::MAX);
        assert_eq!(execute_semantic(&instruction, &mut regs, &mut mem), None);
    }

    #[test]
    fn state_transitions_and_returns() {
        let mut regs = registers();
        let mut mem = memory();
        set(&mut regs, REG_RAX, 0xabcd);
        let jumps = decoded(SEM_JMP, [0x1234_5678, u64::from(REG_RAX), 0, 0]);
        assert_eq!(
            execute_semantic(&jumps, &mut regs, &mut mem),
            Some(Flow::Jump(0x1234_5678))
        );
        let conditional = decoded(SEM_JCC, [u64::from(REG_RBX), 100, 200, u64::from(REG_RAX)]);
        set(&mut regs, REG_RBX, 1);
        assert_eq!(
            execute_semantic(&conditional, &mut regs, &mut mem),
            Some(Flow::Jump(100))
        );
        set(&mut regs, REG_RBX, 0);
        assert_eq!(
            execute_semantic(&conditional, &mut regs, &mut mem),
            Some(Flow::Jump(200))
        );
        let returns = decoded(SEM_RET, [u64::from(REG_RAX), 0, 0, 0]);
        assert_eq!(
            execute_semantic(&returns, &mut regs, &mut mem),
            Some(Flow::Return(0xabcd))
        );
    }

    #[test]
    fn invalid_register_operands_fail_closed() {
        let mut regs = registers();
        let mut mem = memory();
        let instruction = decoded(
            SEM_MOV_RR,
            [
                u64::from(u8::try_from(MAX_OPERANDS).unwrap_or(u8::MAX)) + 100,
                0,
                0,
                0,
            ],
        );
        assert_eq!(execute_semantic(&instruction, &mut regs, &mut mem), None);
    }

    #[test]
    fn masked_register_and_memory_state_hide_plaintext_and_round_trip() {
        let masks = [0x9e37_79b9_7f4a_7c15_u64; VM_REGISTERS];
        let mut register_file = [0_u64; VM_REGISTERS];
        let values = [3_u64, 0, 0, 0];
        set_reg_value(&mut register_file, Some(&masks), &values, 0, 0xdead_beef)
            .expect("set masked register");
        assert_ne!(register_file.get(3).copied(), Some(0xdead_beef));
        assert_eq!(
            reg_value(&register_file, Some(&masks), &values, 0),
            Some(0xdead_beef)
        );

        let key = 0x0123_4567_89ab_cdef_u64;
        let mut memory = [0_u8; 16];
        store_memory_with_key(&mut memory, 2, 8, 0xfeed_face_cafe_beef, Some(key))
            .expect("masked store");
        assert_ne!(
            memory.get(2..10),
            Some(0xfeed_face_cafe_beef_u64.to_le_bytes().as_slice())
        );
        assert_eq!(
            load_memory_with_key(&memory, 2, 8, Some(key)),
            Some(0xfeed_face_cafe_beef)
        );
    }
}

#[cfg(kani)]
mod proofs {
    use super::{
        load_memory, load_memory_with_key, reg_value, set_reg_value, store_memory,
        store_memory_with_key,
    };
    use crate::shared::format::VM_REGISTERS;

    #[kani::proof]
    #[kani::unwind(10)]
    fn load_memory_is_bounded() {
        let memory: [u8; 64] = kani::any();
        let address: u64 = kani::any();
        let width: usize = kani::any();
        kani::assume(width >= 1 && width <= 8);
        let _ = load_memory(&memory, address, width);
    }

    #[kani::proof]
    fn masked_register_round_trip() {
        let mask: u64 = kani::any();
        let value: u64 = kani::any();
        let mut registers = [0_u64; VM_REGISTERS];
        let masks = [mask; VM_REGISTERS];
        let values = [7_u64, 0, 0, 0];
        let _ = set_reg_value(&mut registers, Some(&masks), &values, 0, value);
        assert_eq!(reg_value(&registers, Some(&masks), &values, 0), Some(value));
    }

    #[kani::proof]
    fn masked_memory_round_trip() {
        let key = 0x1234_5678_9abc_def0_u64;
        let value: u64 = kani::any();
        let address = 8_u64;
        let width = 8_usize;
        let mut memory = [0_u8; 64];
        assert!(store_memory_with_key(&mut memory, address, width, value, Some(key)).is_some());
        assert_eq!(
            load_memory_with_key(&memory, address, width, Some(key)),
            Some(value)
        );
    }

    #[kani::proof]
    #[kani::unwind(10)]
    fn store_memory_is_bounded() {
        let mut memory: [u8; 64] = kani::any();
        let address: u64 = kani::any();
        let width: usize = kani::any();
        let value: u64 = kani::any();
        kani::assume(width >= 1 && width <= 8);
        let _ = store_memory(&mut memory, address, width, value);
    }
}
