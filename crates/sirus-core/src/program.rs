//! Whole-program flattening, decoy synthesis, manifest construction, and final
//! encrypted payload production.

use crate::encode::{encode_block, encode_block_with_nonlinear};
use crate::error::{CoreError, Result};
use crate::ir::{
    BoundedVec, ByteBuf, IrOp, LiftedFunction, MAX_BLOCKS, MAX_FUNCTIONS, MAX_PAYLOAD, Terminator,
};
use crate::mba::BuildRng;
use crate::shared::cipher::{
    BodyCipher, MANIFEST_COUNT_BYTES, MANIFEST_ENTRY_BYTES, MAX_PAYLOAD_BLOCKS, base_key,
    encode_manifest_u32, encode_manifest_u64, manifest_byte, manifest_size, payload_hash,
};
use crate::shared::derive::{Seed, Tables};
use crate::shared::format::{
    DEFAULT_FUEL, REG_RAX, REG_TMP0, REG_TMP1, REG_TMP2, REG_TMP3, REG_ZERO,
};

const DOMAIN_STATE: u64 = 0x7374_6174_655f_6964;
const DOMAIN_ENCODE: u64 = 0x656e_636f_6465_5f62;
const DOMAIN_MANIFEST: u64 = 0x6d61_6e69_6665_7374;

/// Tunables for one protection build.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompileOptions {
    /// Maximum MBA rewrite depth.
    pub mba_depth: u8,
    /// Maximum number of expression nodes created per statement.
    pub mba_budget: u16,
    /// Number of opaque guard/decoy pairs per function.
    pub decoys: u8,
    /// Reject data-dependent branches and memory accesses and disable decoys.
    pub constant_time: bool,
    /// Instruction budget for one runtime invocation.
    pub fuel: u64,
}

impl CompileOptions {
    /// Creates default production settings.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            mba_depth: 3,
            mba_budget: 512,
            decoys: 2,
            constant_time: false,
            fuel: DEFAULT_FUEL,
        }
    }

    const fn validate(self) -> Result<()> {
        if self.mba_depth > 8 || self.mba_budget > 4096 || self.decoys > 8 || self.fuel == 0 {
            return Err(CoreError::InvalidPlan);
        }
        Ok(())
    }
}

impl Default for CompileOptions {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// Summary of a compiled program.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgramStats {
    /// Number of protected functions.
    pub functions: usize,
    /// Number of original flattened blocks.
    pub original_blocks: usize,
    /// Number of synthetic guard/decoy blocks.
    pub decoy_blocks: usize,
    /// Number of manifest entries.
    pub manifest_entries: usize,
    /// Final encrypted payload size.
    pub payload_bytes: usize,
    /// Plaintext body bytes before encryption and manifest framing.
    pub body_bytes: usize,
}

/// Fully compiled encrypted payload and runtime constants.
#[derive(Clone, Debug)]
pub struct CompiledProgram {
    payload: ByteBuf<MAX_PAYLOAD>,
    seed: Seed,
    entry_states: BoundedVec<[u64; 2], MAX_FUNCTIONS>,
    expected_hash: u64,
    base_a: u64,
    base_b: u64,
    fuel: u64,
    stats: ProgramStats,
}

impl CompiledProgram {
    /// Returns the encrypted payload.
    #[inline]
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        self.payload.as_slice()
    }

    /// Returns the build seed.
    #[inline]
    #[must_use]
    pub const fn seed(&self) -> &Seed {
        &self.seed
    }

    /// Returns the blinded entry state pairs, in input-function order.
    #[inline]
    #[must_use]
    pub fn entry_states(&self) -> &[[u64; 2]] {
        self.entry_states.as_slice()
    }

    /// Returns the integrity hash expected by the runtime.
    #[inline]
    #[must_use]
    pub const fn expected_hash(&self) -> u64 {
        self.expected_hash
    }

    /// Returns the first half of the split base key.
    #[inline]
    #[must_use]
    pub const fn base_a(&self) -> u64 {
        self.base_a
    }

    /// Returns the second half of the split base key.
    #[inline]
    #[must_use]
    pub const fn base_b(&self) -> u64 {
        self.base_b
    }

    /// Returns the fuel budget.
    #[inline]
    #[must_use]
    pub const fn fuel(&self) -> u64 {
        self.fuel
    }

    /// Returns compilation statistics.
    #[inline]
    #[must_use]
    pub const fn stats(&self) -> ProgramStats {
        self.stats
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct ManifestEntry {
    state: u64,
    offset: u32,
    length: u32,
}

fn allocate_state(rng: &mut BuildRng, used: &mut BoundedVec<u64, MAX_BLOCKS>) -> Result<u64> {
    let mut attempts = 0_usize;
    while attempts < 128 {
        let candidate = rng.next_u64();
        if candidate != 0 && !used.contains(&candidate) {
            used.push(candidate)?;
            return Ok(candidate);
        }
        attempts = attempts.saturating_add(1);
    }
    Err(CoreError::InvalidState)
}

fn shuffle_u16(values: &mut BoundedVec<u16, MAX_BLOCKS>, rng: &mut BuildRng) {
    let mut index = values.len();
    while index > 1 {
        index = index.saturating_sub(1);
        let target = rng.below(index.saturating_add(1));
        if target != index {
            let first = values.get(index).copied().unwrap_or(0);
            let second = values.get(target).copied().unwrap_or(0);
            if let Some(slot) = values.get_mut(index) {
                *slot = second;
            }
            if let Some(slot) = values.get_mut(target) {
                *slot = first;
            }
        }
    }
}

fn push_guarded_state(
    payload: &mut ByteBuf<MAX_PAYLOAD>,
    key: u64,
    index: usize,
    value: u64,
    big_endian: bool,
) -> Result<()> {
    let bytes = encode_manifest_u64(value, big_endian);
    let mut offset = 0_usize;
    while offset < 8 {
        let position = index
            .checked_add(offset)
            .ok_or(CoreError::ArithmeticOverflow)?;
        let byte = bytes
            .get(offset)
            .copied()
            .ok_or(CoreError::ArithmeticOverflow)?;
        payload.push(manifest_byte(key, position, byte))?;
        offset = offset.saturating_add(1);
    }
    Ok(())
}

fn push_guarded_u32(
    buffer: &mut [u8; 16],
    index: usize,
    value: u32,
    big_endian: bool,
) -> Result<()> {
    let bytes = encode_manifest_u32(value, big_endian);
    let mut offset = 0_usize;
    while offset < 4 {
        let position = index
            .checked_add(offset)
            .ok_or(CoreError::ArithmeticOverflow)?;
        let byte = bytes
            .get(offset)
            .copied()
            .ok_or(CoreError::ArithmeticOverflow)?;
        let target = buffer
            .get_mut(position)
            .ok_or(CoreError::ArithmeticOverflow)?;
        *target = byte;
        offset = offset.saturating_add(1);
    }
    Ok(())
}

fn finalize(
    seed: &Seed,
    fuel: u64,
    tables: &Tables,
    bodies: &ByteBuf<MAX_PAYLOAD>,
    entries: &BoundedVec<ManifestEntry, MAX_BLOCKS>,
    entry_states: BoundedVec<[u64; 2], MAX_FUNCTIONS>,
    stats: ProgramStats,
) -> Result<CompiledProgram> {
    let count = entries.len();
    if count == 0 || count > MAX_PAYLOAD_BLOCKS {
        return Err(CoreError::InvalidState);
    }
    let manifest_len = manifest_size(count).ok_or(CoreError::PayloadTooLarge)?;
    let key = base_key(seed);
    let mut payload = ByteBuf::<MAX_PAYLOAD>::new();
    push_guarded_state(
        &mut payload,
        key,
        0,
        u64::try_from(count).map_err(|_| CoreError::ArithmeticOverflow)?,
        tables.manifest_big_endian,
    )?;

    let mut manifest_rng = BuildRng::new(seed, DOMAIN_MANIFEST);
    let mut ordered = BoundedVec::<u16, MAX_BLOCKS>::new();
    let mut index = 0_usize;
    while index < count {
        ordered.push(u16::try_from(index).map_err(|_| CoreError::ArithmeticOverflow)?)?;
        index = index.saturating_add(1);
    }
    shuffle_u16(&mut ordered, &mut manifest_rng);

    let mut manifest_position = 0_usize;
    while manifest_position < count {
        let entry_index = ordered
            .get(manifest_position)
            .copied()
            .ok_or(CoreError::ArithmeticOverflow)?;
        let entry = entries
            .get(usize::from(entry_index))
            .copied()
            .ok_or(CoreError::ArithmeticOverflow)?;
        let mut field = [0_u8; 16];
        let state_bytes = encode_manifest_u64(entry.state, tables.manifest_big_endian);
        let mut state_offset = 0_usize;
        while state_offset < 8 {
            let byte = state_bytes
                .get(state_offset)
                .copied()
                .ok_or(CoreError::ArithmeticOverflow)?;
            let target = field
                .get_mut(state_offset)
                .ok_or(CoreError::ArithmeticOverflow)?;
            *target = byte;
            state_offset = state_offset.saturating_add(1);
        }
        let absolute_offset = usize::try_from(entry.offset)
            .ok()
            .and_then(|relative| relative.checked_add(manifest_len))
            .and_then(|absolute| u32::try_from(absolute).ok())
            .ok_or(CoreError::PayloadTooLarge)?;
        push_guarded_u32(&mut field, 8, absolute_offset, tables.manifest_big_endian)?;
        push_guarded_u32(&mut field, 12, entry.length, tables.manifest_big_endian)?;
        let start = MANIFEST_COUNT_BYTES
            .checked_add(
                manifest_position
                    .checked_mul(MANIFEST_ENTRY_BYTES)
                    .ok_or(CoreError::ArithmeticOverflow)?,
            )
            .ok_or(CoreError::ArithmeticOverflow)?;
        let mut byte_offset = 0_usize;
        while byte_offset < MANIFEST_ENTRY_BYTES {
            let position = start
                .checked_add(byte_offset)
                .ok_or(CoreError::ArithmeticOverflow)?;
            let byte = field
                .get(byte_offset)
                .copied()
                .ok_or(CoreError::ArithmeticOverflow)?;
            payload.push(manifest_byte(key, position, byte))?;
            byte_offset = byte_offset.saturating_add(1);
        }
        manifest_position = manifest_position.saturating_add(1);
    }

    if payload.len() != manifest_len {
        return Err(CoreError::InvalidState);
    }

    let mut entry_index = 0_usize;
    while entry_index < count {
        let entry = entries
            .get(entry_index)
            .copied()
            .ok_or(CoreError::ArithmeticOverflow)?;
        let body_start = manifest_len
            .checked_add(usize::try_from(entry.offset).map_err(|_| CoreError::ArithmeticOverflow)?)
            .ok_or(CoreError::ArithmeticOverflow)?;
        if payload.len() != body_start {
            return Err(CoreError::InvalidState);
        }
        let body_end = body_start
            .checked_add(usize::try_from(entry.length).map_err(|_| CoreError::ArithmeticOverflow)?)
            .ok_or(CoreError::ArithmeticOverflow)?;
        let mut absolute = body_start;
        let mut previous = 0_u8;
        let mut cipher = BodyCipher::new(key, entry.state, body_start);
        while absolute < body_end {
            let body_offset = absolute
                .checked_sub(manifest_len)
                .ok_or(CoreError::ArithmeticOverflow)?;
            let plain = bodies
                .get(body_offset)
                .ok_or(CoreError::ArithmeticOverflow)?;
            payload.push(cipher.apply(absolute, previous, plain))?;
            previous = plain;
            absolute = absolute.saturating_add(1);
        }
        entry_index = entry_index.saturating_add(1);
    }

    let expected_hash = payload_hash(seed, payload.as_slice());
    let base = base_key(seed);
    let base_a = manifest_rng.next_u64();
    let base_b = base_a ^ base;
    let final_stats = ProgramStats {
        payload_bytes: payload.len(),
        ..stats
    };
    Ok(CompiledProgram {
        payload,
        seed: *seed,
        entry_states,
        expected_hash,
        base_a,
        base_b,
        fuel,
        stats: final_stats,
    })
}

fn validate_constant_time(functions: &[LiftedFunction]) -> Result<()> {
    let mut function_index = 0_usize;
    while function_index < functions.len() {
        let Some(function) = functions.get(function_index) else {
            return Err(CoreError::InvalidFunctionSize { size: 0 });
        };
        let mut block_index = 0_usize;
        while block_index < function.blocks.len() {
            let Some(block) = function.blocks.get(block_index) else {
                return Err(CoreError::InvalidBlock { block: u16::MAX });
            };
            if matches!(block.terminator, Terminator::Branch { .. }) {
                return Err(CoreError::ConstantTimeUnsupported);
            }
            let Some(ops) = function.block_ops(block) else {
                return Err(CoreError::InvalidBlock { block: u16::MAX });
            };
            for op in ops {
                if matches!(op, IrOp::Load { .. } | IrOp::Store { .. }) {
                    return Err(CoreError::ConstantTimeUnsupported);
                }
            }
            block_index = block_index.saturating_add(1);
        }
        function_index = function_index.saturating_add(1);
    }
    Ok(())
}

/// Compiles one or more lifted functions into a shared encrypted VM payload.
///
/// All functions share one ISA plan, one cipher stream, one integrity binding,
/// and one runtime. Each function receives a blinded entry state in input order.
///
/// # Errors
///
/// Returns a typed error for invalid options, empty or oversized function sets,
/// invalid CFG targets, MBA or encoder capacity exhaustion, and payload overflow.
#[inline]
pub fn compile(
    functions: &[LiftedFunction],
    seed: Seed,
    options: CompileOptions,
) -> Result<CompiledProgram> {
    options.validate()?;
    if options.constant_time {
        validate_constant_time(functions)?;
    }
    let decoy_setting = if options.constant_time {
        0
    } else {
        options.decoys
    };
    if functions.is_empty() || functions.len() > MAX_FUNCTIONS {
        return Err(CoreError::InvalidFunctionSize {
            size: u64::try_from(functions.len()).unwrap_or(u64::MAX),
        });
    }
    let tables = Tables::derive(&seed);
    let mut state_rng = BuildRng::new(&seed, DOMAIN_STATE);
    let mut used_states = BoundedVec::<u64, MAX_BLOCKS>::new();
    let mut states = [[0_u64; MAX_BLOCKS]; MAX_FUNCTIONS];
    let mut counts = [0_usize; MAX_FUNCTIONS];
    let mut total_original = 0_usize;

    let mut function_index = 0_usize;
    while function_index < functions.len() {
        let Some(function) = functions.get(function_index) else {
            return Err(CoreError::InvalidFunctionSize { size: 0 });
        };
        let block_count = function.blocks.len();
        if block_count == 0 || usize::from(function.entry_block) >= block_count {
            return Err(CoreError::InvalidBlock {
                block: function.entry_block,
            });
        }
        total_original = total_original
            .checked_add(block_count)
            .ok_or(CoreError::ArithmeticOverflow)?;
        if total_original > MAX_BLOCKS {
            return Err(CoreError::CapacityExceeded);
        }
        let mut block_index = 0_usize;
        while block_index < block_count {
            let state = allocate_state(&mut state_rng, &mut used_states)?;
            if let Some(row) = states.get_mut(function_index) {
                if let Some(slot) = row.get_mut(block_index) {
                    *slot = state;
                }
            }
            block_index = block_index.saturating_add(1);
        }
        if let Some(count) = counts.get_mut(function_index) {
            *count = block_count;
        }
        function_index = function_index.saturating_add(1);
    }

    let mut remaining_pairs = MAX_BLOCKS.saturating_sub(total_original) / 2;
    let mut decoy_count = 0_usize;

    function_index = 0;
    while function_index < functions.len() {
        let Some(function) = functions.get(function_index) else {
            return Err(CoreError::InvalidFunctionSize { size: 0 });
        };
        let original = function.blocks.len();
        let mut candidates = BoundedVec::<u16, MAX_BLOCKS>::new();
        let mut block_index = 0_usize;
        while block_index < original {
            let Some(block) = function.blocks.get(block_index) else {
                return Err(CoreError::InvalidBlock {
                    block: u16::try_from(block_index)
                        .map_err(|_| CoreError::InvalidBlock { block: u16::MAX })?,
                });
            };
            if matches!(block.terminator, Terminator::Jump { .. }) {
                candidates.push(
                    u16::try_from(block_index)
                        .map_err(|_| CoreError::InvalidBlock { block: u16::MAX })?,
                )?;
            }
            block_index = block_index.saturating_add(1);
        }
        shuffle_u16(&mut candidates, &mut state_rng);
        let planned = usize::from(decoy_setting)
            .min(candidates.len())
            .min(remaining_pairs);
        remaining_pairs = remaining_pairs.saturating_sub(planned);
        decoy_count = decoy_count.saturating_add(planned.saturating_mul(2));
        let base_count = counts
            .get(function_index)
            .copied()
            .ok_or(CoreError::ArithmeticOverflow)?;
        let mut decoy_index = 0_usize;
        while decoy_index < planned {
            let guard_index = base_count
                .checked_add(decoy_index.saturating_mul(2))
                .ok_or(CoreError::ArithmeticOverflow)?;
            let Some(function_row) = states.get_mut(function_index) else {
                return Err(CoreError::ArithmeticOverflow);
            };
            let guard_state = allocate_state(&mut state_rng, &mut used_states)?;
            let decoy_state = allocate_state(&mut state_rng, &mut used_states)?;
            if let Some(slot) = function_row.get_mut(guard_index) {
                *slot = guard_state;
            }
            if let Some(slot) = function_row.get_mut(guard_index.saturating_add(1)) {
                *slot = decoy_state;
            }
            decoy_index = decoy_index.saturating_add(1);
        }
        if let Some(count) = counts.get_mut(function_index) {
            *count = base_count
                .checked_add(planned.saturating_mul(2))
                .ok_or(CoreError::ArithmeticOverflow)?;
        }
        function_index = function_index.saturating_add(1);
    }

    let mut encode_rng = BuildRng::new(&seed, DOMAIN_ENCODE);
    let mut bodies = ByteBuf::<MAX_PAYLOAD>::new();
    let mut entries = BoundedVec::<ManifestEntry, MAX_BLOCKS>::new();
    let mut body_bytes = 0_usize;

    function_index = 0;
    while function_index < functions.len() {
        let Some(function) = functions.get(function_index) else {
            return Err(CoreError::InvalidFunctionSize { size: 0 });
        };
        let original = function.blocks.len();
        let total = counts
            .get(function_index)
            .copied()
            .ok_or(CoreError::ArithmeticOverflow)?;
        let state_slice = states
            .get(function_index)
            .and_then(|row| row.get(..total))
            .ok_or(CoreError::ArithmeticOverflow)?;
        let mut guard_for = [u16::MAX; MAX_BLOCKS];
        let mut candidates = BoundedVec::<u16, MAX_BLOCKS>::new();
        let mut nonlinear_target = None;
        let mut block_index = 0_usize;
        while block_index < original {
            let Some(block) = function.blocks.get(block_index) else {
                return Err(CoreError::InvalidBlock {
                    block: u16::try_from(block_index)
                        .map_err(|_| CoreError::InvalidBlock { block: u16::MAX })?,
                });
            };
            if matches!(block.terminator, Terminator::Jump { .. }) {
                candidates.push(
                    u16::try_from(block_index)
                        .map_err(|_| CoreError::InvalidBlock { block: u16::MAX })?,
                )?;
            }
            if nonlinear_target.is_none()
                && function.block_ops(block).is_some_and(|ops| !ops.is_empty())
            {
                nonlinear_target = Some(block_index);
            }
            block_index = block_index.saturating_add(1);
        }
        shuffle_u16(&mut candidates, &mut encode_rng);
        let decoys = usize::from(decoy_setting)
            .min(candidates.len())
            .min((total.saturating_sub(original)) / 2);
        let mut decoy_index = 0_usize;
        while decoy_index < decoys {
            let candidate = candidates.get(decoy_index).copied().unwrap_or(0);
            let guard = original
                .checked_add(decoy_index.saturating_mul(2))
                .ok_or(CoreError::ArithmeticOverflow)?;
            if let Some(slot) = guard_for.get_mut(usize::from(candidate)) {
                *slot = u16::try_from(guard)
                    .map_err(|_| CoreError::InvalidBlock { block: u16::MAX })?;
            }
            decoy_index = decoy_index.saturating_add(1);
        }

        block_index = 0;
        while block_index < original {
            let Some(block) = function.blocks.get(block_index) else {
                return Err(CoreError::InvalidBlock {
                    block: u16::try_from(block_index)
                        .map_err(|_| CoreError::InvalidBlock { block: u16::MAX })?,
                });
            };
            let Some(ops) = function.block_ops(block) else {
                return Err(CoreError::InvalidBlock {
                    block: u16::try_from(block_index)
                        .map_err(|_| CoreError::InvalidBlock { block: u16::MAX })?,
                });
            };
            let guard = guard_for.get(block_index).copied().unwrap_or(u16::MAX);
            let terminator = if guard == u16::MAX {
                block.terminator
            } else {
                Terminator::Jump { target: guard }
            };
            let body = if nonlinear_target == Some(block_index) {
                encode_block_with_nonlinear(
                    ops,
                    terminator,
                    state_slice,
                    &tables,
                    &mut encode_rng,
                    options.mba_depth,
                    options.mba_budget,
                )?
            } else {
                encode_block(
                    ops,
                    terminator,
                    state_slice,
                    &tables,
                    &mut encode_rng,
                    options.mba_depth,
                    options.mba_budget,
                )?
            };
            let offset = u32::try_from(bodies.len()).map_err(|_| CoreError::PayloadTooLarge)?;
            let length = u32::try_from(body.len()).map_err(|_| CoreError::PayloadTooLarge)?;
            bodies.extend_from_slice(body.as_slice())?;
            body_bytes = body_bytes.saturating_add(body.len());
            let state = state_slice
                .get(block_index)
                .copied()
                .ok_or(CoreError::InvalidState)?;
            entries.push(ManifestEntry {
                state,
                offset,
                length,
            })?;
            block_index = block_index.saturating_add(1);
        }

        decoy_index = 0;
        while decoy_index < decoys {
            let candidate = candidates.get(decoy_index).copied().unwrap_or(0);
            let Some(block) = function.blocks.get(usize::from(candidate)) else {
                return Err(CoreError::InvalidBlock { block: candidate });
            };
            let Terminator::Jump { target } = block.terminator else {
                return Err(CoreError::InvalidBlock { block: candidate });
            };
            let guard_index = original
                .checked_add(decoy_index.saturating_mul(2))
                .ok_or(CoreError::ArithmeticOverflow)?;
            let decoy_index_value = guard_index.saturating_add(1);
            let guard_state = state_slice
                .get(guard_index)
                .copied()
                .ok_or(CoreError::InvalidState)?;
            let decoy_state = state_slice
                .get(decoy_index_value)
                .copied()
                .ok_or(CoreError::InvalidState)?;

            let mut guard_ops = BoundedVec::<IrOp, 16>::new();
            guard_ops.push(IrOp::Mov {
                dst: REG_TMP0,
                src: REG_RAX,
            })?;
            guard_ops.push(IrOp::AndImm {
                dst: REG_TMP0,
                value: 1,
            })?;
            guard_ops.push(IrOp::Mov {
                dst: REG_TMP1,
                src: REG_TMP0,
            })?;
            guard_ops.push(IrOp::SubImm {
                dst: REG_TMP1,
                value: 1,
            })?;
            guard_ops.push(IrOp::Mul {
                dst: REG_TMP0,
                src: REG_TMP1,
            })?;
            guard_ops.push(IrOp::CmpEq {
                dst: REG_TMP0,
                lhs: REG_TMP0,
                rhs: REG_ZERO,
            })?;
            let guard_body = encode_block(
                guard_ops.as_slice(),
                Terminator::Branch {
                    cond: REG_TMP0,
                    when_true: target,
                    when_false: u16::try_from(decoy_index_value)
                        .map_err(|_| CoreError::InvalidBlock { block: u16::MAX })?,
                },
                state_slice,
                &tables,
                &mut encode_rng,
                options.mba_depth,
                options.mba_budget,
            )?;
            let guard_offset =
                u32::try_from(bodies.len()).map_err(|_| CoreError::PayloadTooLarge)?;
            let guard_length =
                u32::try_from(guard_body.len()).map_err(|_| CoreError::PayloadTooLarge)?;
            bodies.extend_from_slice(guard_body.as_slice())?;
            body_bytes = body_bytes.saturating_add(guard_body.len());
            entries.push(ManifestEntry {
                state: guard_state,
                offset: guard_offset,
                length: guard_length,
            })?;

            let c1 = encode_rng.next_u64();
            let c2 = encode_rng.next_u64();
            let c3 = encode_rng.next_u64();
            let mut decoy_ops = BoundedVec::<IrOp, 8>::new();
            decoy_ops.push(IrOp::MovImm {
                dst: REG_TMP2,
                value: c1,
            })?;
            decoy_ops.push(IrOp::MovImm {
                dst: REG_TMP3,
                value: c2,
            })?;
            decoy_ops.push(IrOp::Xor {
                dst: REG_TMP2,
                src: REG_TMP3,
            })?;
            decoy_ops.push(IrOp::AddImm {
                dst: REG_TMP2,
                value: c3,
            })?;
            decoy_ops.push(IrOp::Mul {
                dst: REG_TMP2,
                src: REG_TMP2,
            })?;
            let decoy_body = encode_block(
                decoy_ops.as_slice(),
                Terminator::Jump { target },
                state_slice,
                &tables,
                &mut encode_rng,
                options.mba_depth,
                options.mba_budget,
            )?;
            let decoy_offset =
                u32::try_from(bodies.len()).map_err(|_| CoreError::PayloadTooLarge)?;
            let decoy_length =
                u32::try_from(decoy_body.len()).map_err(|_| CoreError::PayloadTooLarge)?;
            bodies.extend_from_slice(decoy_body.as_slice())?;
            body_bytes = body_bytes.saturating_add(decoy_body.len());
            entries.push(ManifestEntry {
                state: decoy_state,
                offset: decoy_offset,
                length: decoy_length,
            })?;
            decoy_index = decoy_index.saturating_add(1);
        }
        function_index = function_index.saturating_add(1);
    }

    let mut entry_states = BoundedVec::<[u64; 2], MAX_FUNCTIONS>::new();
    function_index = 0;
    while function_index < functions.len() {
        let Some(function) = functions.get(function_index) else {
            return Err(CoreError::InvalidFunctionSize { size: 0 });
        };
        let entry_index = usize::from(function.entry_block);
        let entry_state = states
            .get(function_index)
            .and_then(|row| row.get(entry_index))
            .copied()
            .ok_or(CoreError::InvalidState)?;
        let mask = state_rng.next_u64();
        entry_states.push([entry_state ^ mask, mask])?;
        function_index = function_index.saturating_add(1);
    }

    let summary_stats = ProgramStats {
        functions: functions.len(),
        original_blocks: total_original,
        decoy_blocks: decoy_count,
        manifest_entries: entries.len(),
        payload_bytes: 0,
        body_bytes,
    };

    finalize(
        &seed,
        options.fuel,
        &tables,
        &bodies,
        &entries,
        entry_states,
        summary_stats,
    )
}

#[cfg(test)]
mod tests {
    use super::{CompileOptions, ProgramStats, compile};
    use crate::ir::BoundedVec;
    use crate::lifter::lift_function;
    use crate::shared::format::DEFAULT_FUEL;

    fn options() -> CompileOptions {
        let mut options = CompileOptions::new();
        options.decoys = 1;
        options
    }

    #[test]
    fn compiles_a_simple_function_deterministically() {
        let code = [0x48, 0x89, 0xf8, 0x48, 0x01, 0xf0, 0xc3];
        let function = lift_function(&code, 0x1000).expect("lift");
        let functions = [function];
        let first = compile(&functions, [3_u8; 32], options());
        let second = compile(&functions, [3_u8; 32], options());
        assert!(first.is_ok());
        assert!(second.is_ok());
        if let (Ok(first), Ok(second)) = (first, second) {
            assert_eq!(first.payload(), second.payload());
            assert_eq!(first.entry_states(), second.entry_states());
            assert_eq!(first.expected_hash(), second.expected_hash());
            assert_eq!(first.entry_states().len(), 1);
            assert!(first.stats().payload_bytes > 0);
            assert_eq!(first.stats().functions, 1);
        }
    }

    #[test]
    fn constant_time_accepts_branchless_and_rejects_branch_or_memory() {
        let straight = [0x48, 0x89, 0xf8, 0x48, 0x01, 0xf0, 0xc3];
        let function = lift_function(&straight, 0x1000).expect("lift straight");
        let mut options = CompileOptions::new();
        options.constant_time = true;
        options.decoys = 2;
        let program = compile(&[function], [0x33_u8; 32], options).expect("constant time");
        assert_eq!(program.stats().decoy_blocks, 0);

        let branch = [
            0x48, 0x39, 0xf7, 0x76, 0x07, 0x48, 0x89, 0xf8, 0x48, 0x01, 0xf0, 0xc3, 0x48, 0x89,
            0xf8, 0x48, 0x29, 0xf0, 0xc3,
        ];
        let function = lift_function(&branch, 0x2000).expect("lift branch");
        let mut options = CompileOptions::new();
        options.constant_time = true;
        assert!(matches!(
            compile(&[function], [0x44_u8; 32], options),
            Err(crate::error::CoreError::ConstantTimeUnsupported)
        ));

        let memory = [0x48, 0x8b, 0x07, 0xc3];
        let function = lift_function(&memory, 0x3000).expect("lift memory");
        let mut options = CompileOptions::new();
        options.constant_time = true;
        assert!(matches!(
            compile(&[function], [0x55_u8; 32], options),
            Err(crate::error::CoreError::ConstantTimeUnsupported)
        ));
    }

    #[test]
    fn different_seeds_change_payload_and_entry_state() {
        let code = [0x48, 0x89, 0xf8, 0x48, 0x01, 0xf0, 0xc3];
        let function = lift_function(&code, 0x1000).expect("lift");
        let functions = [function];
        let first = compile(&functions, [1_u8; 32], options()).expect("first");
        let second = compile(&functions, [2_u8; 32], options()).expect("second");
        assert_ne!(first.payload(), second.payload());
        assert_ne!(first.entry_states(), second.entry_states());
    }

    #[test]
    fn rejects_invalid_options_and_empty_input() {
        let code = [0xc3];
        let function = lift_function(&code, 0).expect("lift");
        let mut bad = CompileOptions::new();
        bad.mba_depth = 9;
        assert!(compile(&[function], [0_u8; 32], bad).is_err());
        let empty: [crate::ir::LiftedFunction; 0] = [];
        assert!(compile(&empty, [0_u8; 32], CompileOptions::new()).is_err());
        let _ = BoundedVec::<u8, 1>::new();
    }
    #[test]
    fn exposes_all_compiled_constants() {
        let code = [0x48, 0x89, 0xf8, 0xc3];
        let function = lift_function(&code, 0x1000).expect("lift");
        let program = compile(&[function], [0x5a_u8; 32], options()).expect("compile");
        assert_ne!(program.payload().len(), 0);
        assert_eq!(program.seed(), &[0x5a_u8; 32]);
        assert_eq!(program.entry_states().len(), 1);
        assert_eq!(program.expected_hash(), program.expected_hash());
        assert!(program.base_a() ^ program.base_b() != 0);
        assert_eq!(program.fuel(), options().fuel);
        assert_eq!(program.stats().functions, 1);
        assert!(program.stats().payload_bytes >= program.payload().len());
    }

    #[test]
    fn decoys_can_be_disabled_and_shared_by_many_functions() {
        let code = [0x48, 0x89, 0xf8, 0xc3];
        let function = lift_function(&code, 0x1000).expect("lift");
        let mut no_decoys = options();
        no_decoys.decoys = 0;
        let program =
            compile(&[function.clone(), function], [6_u8; 32], no_decoys).expect("compile");
        assert_eq!(program.entry_states().len(), 2);
        assert_eq!(program.stats().decoy_blocks, 0);
        assert_eq!(program.stats().functions, 2);
        let mut with_decoys = CompileOptions::new();
        with_decoys.decoys = 2;
        let function = lift_function(&code, 0x1000).expect("lift");
        let program = compile(&[function], [7_u8; 32], with_decoys).expect("compile");
        assert_eq!(program.stats().decoy_blocks, 0);
    }

    #[test]
    fn rejects_invalid_entry_blocks_and_too_many_functions() {
        let code = [0xc3];
        let mut function = lift_function(&code, 0).expect("lift");
        function.entry_block = 99;
        assert!(compile(&[function], [0_u8; 32], CompileOptions::new()).is_err());
        let code = [0xc3];
        let function = lift_function(&code, 0).expect("lift");
        let functions = [
            function.clone(),
            function.clone(),
            function.clone(),
            function.clone(),
            function.clone(),
            function.clone(),
            function.clone(),
            function.clone(),
            function,
        ];
        assert!(compile(&functions, [0_u8; 32], CompileOptions::new()).is_err());
    }

    #[test]
    fn options_defaults_and_validation() {
        let options = CompileOptions::default();
        assert_eq!(options, CompileOptions::new());
        assert_eq!(options.mba_depth, 3);
        assert_eq!(options.mba_budget, 512);
        assert_eq!(options.decoys, 2);
        assert_eq!(options.fuel, DEFAULT_FUEL);
        let _ = ProgramStats {
            functions: 0,
            original_blocks: 0,
            decoy_blocks: 0,
            manifest_entries: 0,
            payload_bytes: 0,
            body_bytes: 0,
        };
    }
}
