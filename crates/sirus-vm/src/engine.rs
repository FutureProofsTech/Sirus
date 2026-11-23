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
use crate::shared::derive::{Seed, Tables};
use crate::shared::format::{
    MAX_OPERANDS, REG_R8, REG_R9, REG_RAX, REG_RCX, REG_RDI, REG_RDX, REG_RSI, REG_RSP, ROLE_IMM,
    ROLE_REG, SEM_ADD_RI, SEM_ADD_RR, SEM_AND_RI, SEM_AND_RR, SEM_CMPEQ_RR, SEM_CMPLES_RR,
    SEM_CMPLEU_RR, SEM_CMPLTS_RR, SEM_CMPLTU_RR, SEM_JCC, SEM_JMP, SEM_LOAD8, SEM_LOAD16,
    SEM_LOAD32, SEM_LOAD64, SEM_MOV_RI, SEM_MOV_RR, SEM_MUL_RR, SEM_NEG_R, SEM_NOP, SEM_NOT_R,
    SEM_OR_RI, SEM_OR_RR, SEM_RET, SEM_ROTL_RI, SEM_ROTL_RR, SEM_ROTR_RI, SEM_ROTR_RR, SEM_SAR_RI,
    SEM_SAR_RR, SEM_SELECT_RRRR, SEM_SHL_RI, SEM_SHL_RR, SEM_SHR_RI, SEM_SHR_RR, SEM_STORE8,
    SEM_STORE16, SEM_STORE32, SEM_STORE64, SEM_SUB_RI, SEM_SUB_RR, SEM_TRAP, SEM_XOR_RI,
    SEM_XOR_RR, VM_MEMORY_SIZE, VM_REGISTERS, VM_STACK_TOP, format,
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
        Self {
            payload,
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
    tables: &'a Tables,
    cipher: BodyCipher,
    position: usize,
    end: usize,
    previous: u8,
}

impl<'a> BodyReader<'a> {
    #[inline]
    const fn new(
        payload: &'a [u8],
        tables: &'a Tables,
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
    values: &[u64; MAX_OPERANDS],
    operand: usize,
) -> Option<u64> {
    let raw = values.get(operand).copied()?;
    let slot = usize::try_from(raw).ok()?;
    registers.get(slot).copied()
}

#[inline]
fn set_reg_value(
    registers: &mut [u64; VM_REGISTERS],
    values: &[u64; MAX_OPERANDS],
    operand: usize,
    value: u64,
) -> Option<()> {
    let raw = values.get(operand).copied()?;
    let slot = usize::try_from(raw).ok()?;
    let target = registers.get_mut(slot)?;
    *target = value;
    Some(())
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
fn load_memory(memory: &[u8; VM_MEMORY_SIZE], address: u64, width: usize) -> Option<u64> {
    let start = usize::try_from(address).ok()?;
    let end = start.checked_add(width)?;
    if end > VM_MEMORY_SIZE || width > 8 {
        return None;
    }
    let mut value = 0_u64;
    let mut index = 0_usize;
    while index < width {
        let byte = memory.get(start.checked_add(index)?).copied()?;
        let shift = u32::try_from(index.wrapping_mul(8)).ok()?;
        value |= u64::from(byte) << shift;
        index = index.checked_add(1)?;
    }
    Some(value)
}

#[inline]
fn store_memory(
    memory: &mut [u8; VM_MEMORY_SIZE],
    address: u64,
    width: usize,
    value: u64,
) -> Option<()> {
    let start = usize::try_from(address).ok()?;
    let end = start.checked_add(width)?;
    if end > VM_MEMORY_SIZE || width > 8 {
        return None;
    }
    let mut index = 0_usize;
    while index < width {
        let shift = u32::try_from(index.wrapping_mul(8)).ok()?;
        let byte = u8::try_from((value >> shift) & 0xff).ok()?;
        let target = memory.get_mut(start.checked_add(index)?)?;
        *target = byte;
        index = index.checked_add(1)?;
    }
    Some(())
}

/// Executes a single decoded operation. Returns `None` for any semantic or
/// operand violation.
#[allow(clippy::too_many_lines)]
fn execute_semantic(
    decoded: &Decoded,
    registers: &mut [u64; VM_REGISTERS],
    memory: &mut [u8; VM_MEMORY_SIZE],
) -> Option<Flow> {
    let values = &decoded.values;
    let write_binary =
        |registers: &mut [u64; VM_REGISTERS], operation: fn(u64, u64) -> u64| -> Option<()> {
            let left = reg_value(registers, values, 0)?;
            let right = reg_value(registers, values, 1)?;
            set_reg_value(registers, values, 0, operation(left, right))
        };
    let write_binary_imm =
        |registers: &mut [u64; VM_REGISTERS], operation: fn(u64, u64) -> u64| -> Option<()> {
            let left = reg_value(registers, values, 0)?;
            let right = immediate(values, 1)?;
            set_reg_value(registers, values, 0, operation(left, right))
        };
    let write_unary =
        |registers: &mut [u64; VM_REGISTERS], operation: fn(u64) -> u64| -> Option<()> {
            let value = reg_value(registers, values, 0)?;
            set_reg_value(registers, values, 0, operation(value))
        };

    match decoded.semantic {
        SEM_NOP => Some(Flow::Continue),
        SEM_MOV_RR => {
            let source = reg_value(registers, values, 1)?;
            set_reg_value(registers, values, 0, source)?;
            Some(Flow::Continue)
        }
        SEM_MOV_RI => {
            let source = immediate(values, 1)?;
            set_reg_value(registers, values, 0, source)?;
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
            let left = reg_value(registers, values, 1)?;
            let right = reg_value(registers, values, 2)?;
            let result = match decoded.semantic {
                SEM_CMPEQ_RR => left == right,
                SEM_CMPLTU_RR => left < right,
                SEM_CMPLTS_RR => as_i64(left) < as_i64(right),
                SEM_CMPLEU_RR => left <= right,
                _ => as_i64(left) <= as_i64(right),
            };
            set_reg_value(registers, values, 0, u64::from(result))?;
            Some(Flow::Continue)
        }
        SEM_SELECT_RRRR => {
            let condition = reg_value(registers, values, 1)?;
            let selected = if condition != 0 {
                reg_value(registers, values, 2)?
            } else {
                reg_value(registers, values, 3)?
            };
            set_reg_value(registers, values, 0, selected)?;
            Some(Flow::Continue)
        }
        SEM_LOAD8 | SEM_LOAD16 | SEM_LOAD32 | SEM_LOAD64 => {
            let width = match decoded.semantic {
                SEM_LOAD8 => 1,
                SEM_LOAD16 => 2,
                SEM_LOAD32 => 4,
                _ => 8,
            };
            let address = reg_value(registers, values, 1)?;
            let loaded = load_memory(memory, address, width)?;
            set_reg_value(registers, values, 0, loaded)?;
            Some(Flow::Continue)
        }
        SEM_STORE8 | SEM_STORE16 | SEM_STORE32 | SEM_STORE64 => {
            let width = match decoded.semantic {
                SEM_STORE8 => 1,
                SEM_STORE16 => 2,
                SEM_STORE32 => 4,
                _ => 8,
            };
            let address = reg_value(registers, values, 0)?;
            let value = reg_value(registers, values, 1)?;
            store_memory(memory, address, width, value)?;
            Some(Flow::Continue)
        }
        SEM_JMP => {
            let target = immediate(values, 0)?;
            let mix = reg_value(registers, values, 1)?;
            Some(Flow::Jump(target.wrapping_add(mix).wrapping_sub(mix)))
        }
        SEM_JCC => {
            let condition = reg_value(registers, values, 0)?;
            let true_target = immediate(values, 1)?;
            let false_target = immediate(values, 2)?;
            let target = if condition != 0 {
                true_target
            } else {
                false_target
            };
            let mix = reg_value(registers, values, 3)?;
            Some(Flow::Jump(target.wrapping_add(mix).wrapping_sub(mix)))
        }
        SEM_RET => {
            let value = reg_value(registers, values, 0)?;
            Some(Flow::Return(value))
        }
        SEM_TRAP => Some(Flow::Trap),
        _ => None,
    }
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

/// Executes a protected function.
#[inline]
#[must_use]
pub fn execute(input: VmInput<'_>, entry_index: usize, args: [u64; 6]) -> Run {
    let mut steps = 0_u64;
    let mut fuel = input.fuel;
    let tables = Tables::derive(input.seed);
    let actual_hash = payload_hash(input.seed, input.payload);
    let key = effective_key(input.base_a, input.base_b, actual_hash, input.expected_hash);
    let Some(entry) = input.entry_states.get(entry_index) else {
        return halt(Status::BadPayload, steps);
    };
    let [entry_a, entry_b] = *entry;
    let mut state = entry_a ^ entry_b;
    let fill_key = key ^ 0x9e37_79b9_7f4a_7c15;
    let mut registers: [u64; VM_REGISTERS] =
        core::array::from_fn(|index| fill_key.rotate_left(u32::try_from(index & 63).unwrap_or(0)));
    let [
        argument0,
        argument1,
        argument2,
        argument3,
        argument4,
        argument5,
    ] = args;
    let _ = set_reg_value_raw(&mut registers, REG_RDI, argument0);
    let _ = set_reg_value_raw(&mut registers, REG_RSI, argument1);
    let _ = set_reg_value_raw(&mut registers, REG_RDX, argument2);
    let _ = set_reg_value_raw(&mut registers, REG_RCX, argument3);
    let _ = set_reg_value_raw(&mut registers, REG_R8, argument4);
    let _ = set_reg_value_raw(&mut registers, REG_R9, argument5);
    let _ = set_reg_value_raw(&mut registers, REG_RSP, VM_STACK_TOP);
    let _ = set_reg_value_raw(&mut registers, REG_RAX, 0);
    let fill_byte = u8::try_from(fill_key & 0xff).unwrap_or(0);
    let mut memory: [u8; VM_MEMORY_SIZE] =
        core::array::from_fn(|index| u8::try_from(index & 0xff).unwrap_or(0) ^ fill_byte);

    'dispatch: loop {
        let Some(count_value) =
            read_manifest_u64_at(input.payload, key, 0, tables.manifest_big_endian)
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

        let mut found: Option<(usize, usize)> = None;
        let mut entry_index_scan = 0_usize;
        while entry_index_scan < count {
            let Some(entry_relative) = entry_index_scan.checked_mul(MANIFEST_ENTRY_BYTES) else {
                return halt(Status::BadPayload, steps);
            };
            let Some(entry_start) = MANIFEST_COUNT_BYTES.checked_add(entry_relative) else {
                return halt(Status::BadPayload, steps);
            };
            let Some(tag) =
                read_manifest_u64_at(input.payload, key, entry_start, tables.manifest_big_endian)
            else {
                return halt(Status::BadPayload, steps);
            };
            if tag == state {
                let Some(offset_start) = entry_start.checked_add(8) else {
                    return halt(Status::BadPayload, steps);
                };
                let Some(length_start) = offset_start.checked_add(4) else {
                    return halt(Status::BadPayload, steps);
                };
                let Some(offset) = read_manifest_u32_at(
                    input.payload,
                    key,
                    offset_start,
                    tables.manifest_big_endian,
                ) else {
                    return halt(Status::BadPayload, steps);
                };
                let Some(length) = read_manifest_u32_at(
                    input.payload,
                    key,
                    length_start,
                    tables.manifest_big_endian,
                ) else {
                    return halt(Status::BadPayload, steps);
                };
                let Ok(offset) = usize::try_from(offset) else {
                    return halt(Status::BadPayload, steps);
                };
                let Ok(length) = usize::try_from(length) else {
                    return halt(Status::BadPayload, steps);
                };
                found = Some((offset, length));
                break;
            }
            entry_index_scan = entry_index_scan.saturating_add(1);
        }
        let Some((body_start, body_length)) = found else {
            return halt(Status::BadPayload, steps);
        };
        if body_start < manifest_len || body_length == 0 {
            return halt(Status::BadPayload, steps);
        }
        let Some(body_end) = body_start.checked_add(body_length) else {
            return halt(Status::BadPayload, steps);
        };
        if body_end > input.payload.len() {
            return halt(Status::BadPayload, steps);
        }

        let mut reader = BodyReader::new(
            input.payload,
            &tables,
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
            let Some(flow) = execute_semantic(&decoded, &mut registers, &mut memory) else {
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
                Flow::Return(value) => {
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

#[inline]
fn set_reg_value_raw(registers: &mut [u64; VM_REGISTERS], slot: u8, value: u64) -> Option<()> {
    let target = registers.get_mut(usize::from(slot))?;
    *target = value;
    Some(())
}

#[cfg(test)]
mod tests {
    use super::{
        Decoded, Flow, as_i64, as_u64, execute_semantic, load_memory, shift_amount, store_memory,
    };
    use crate::shared::format::{
        MAX_OPERANDS, REG_RAX, REG_RBX, REG_RCX, REG_RDX, REG_RSP, SEM_ADD_RI, SEM_ADD_RR,
        SEM_AND_RR, SEM_CMPEQ_RR, SEM_CMPLES_RR, SEM_CMPLTS_RR, SEM_JCC, SEM_JMP, SEM_LOAD64,
        SEM_MOV_RI, SEM_MOV_RR, SEM_MUL_RR, SEM_NEG_R, SEM_NOT_R, SEM_OR_RR, SEM_RET, SEM_ROTL_RI,
        SEM_ROTR_RI, SEM_SAR_RI, SEM_SELECT_RRRR, SEM_SHL_RI, SEM_SHR_RI, SEM_STORE64, SEM_SUB_RR,
        SEM_XOR_RR, VM_MEMORY_SIZE, VM_REGISTERS,
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
}
