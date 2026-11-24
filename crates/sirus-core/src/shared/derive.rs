//! Deterministic derivation of per-build ISA tables from a 256-bit seed.
//!
//! The tables are never serialized into the runtime. Both the build-time
//! encoder and the injected VM call this module with the same seed. Alias
//! operand layouts are derived once per invocation into a fixed table, then
//! indexed per instruction; this avoids per-instruction SipHash/shuffle work.

use crate::shared::format::{
    ALIASES_PER_SEMANTIC, MAX_OPERANDS, SEMANTIC_COUNT, SEMANTIC_IDS, VM_REGISTERS, format,
};
use crate::shared::sip::SipHasher24;

/// 256-bit plan seed.
pub type Seed = [u8; 32];

/// Total number of opcode aliases.
pub const ALIAS_COUNT: usize = SEMANTIC_COUNT * ALIASES_PER_SEMANTIC;

/// Marker used for unassigned table entries.
pub const INVALID_ENTRY: u8 = 0xff;

/// Description of one opcode alias.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AliasSpec {
    /// The opcode byte assigned to this alias.
    pub opcode: u8,
    /// Operand roles in the order they appear on the wire.
    pub order: [u8; MAX_OPERANDS],
    /// Which of the two register encoding maps this alias uses.
    pub reg_map: u8,
    /// Whether 64-bit operands in this alias are big-endian.
    pub big_endian: bool,
}

/// Serialized bytes for one alias: opcode, four order bytes, register map,
/// endian flag, reserved.
pub const ALIAS_SERIALIZED_BYTES: usize = 8;

/// Encrypted runtime decode-table image length.
pub const RUNTIME_TABLE_BYTES: usize =
    256 + 256 + 2 * 256 + ALIAS_COUNT * ALIAS_SERIALIZED_BYTES + 1;

/// Runtime decode tables. This is the subset the VM needs during execution;
/// build-only encoding maps and the seed are deliberately absent.
#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub struct DecodeTables {
    semantic_of_opcode: [u8; 256],
    alias_of_opcode: [u8; 256],
    reg_decode: [[u8; 256]; 2],
    aliases: [AliasSpec; ALIAS_COUNT],
    /// Whether manifest integers use big-endian byte order.
    pub manifest_big_endian: bool,
}

impl DecodeTables {
    /// Decrypts and validates one per-build decode-table image.
    #[must_use]
    #[inline]
    pub fn from_encrypted(bytes: &[u8], key: u64) -> Option<Self> {
        let mut semantic_of_opcode = [INVALID_ENTRY; 256];
        let mut alias_of_opcode = [INVALID_ENTRY; 256];
        let mut reg_decode = [[INVALID_ENTRY; 256]; 2];
        let mut aliases = [AliasSpec::default(); ALIAS_COUNT];
        let mut index = 0_usize;
        while index < 256 {
            if let Some(slot) = semantic_of_opcode.get_mut(index) {
                *slot = table_plain(bytes, key, index)?;
            }
            index = index.saturating_add(1);
        }
        index = 0;
        while index < 256 {
            if let Some(slot) = alias_of_opcode.get_mut(index) {
                *slot = table_plain(bytes, key, 256 + index)?;
            }
            index = index.saturating_add(1);
        }
        let mut variant = 0_usize;
        while variant < 2 {
            index = 0;
            while index < 256 {
                if let Some(slot) = reg_decode
                    .get_mut(variant)
                    .and_then(|table| table.get_mut(index))
                {
                    *slot = table_plain(bytes, key, 512 + variant * 256 + index)?;
                }
                index = index.saturating_add(1);
            }
            variant = variant.saturating_add(1);
        }
        index = 0;
        while index < ALIAS_COUNT {
            let start = 1024 + index * ALIAS_SERIALIZED_BYTES;
            let mut order = [0_u8; MAX_OPERANDS];
            if let Some(slot) = aliases.get_mut(index) {
                let mut field = 0_usize;
                let opcode = table_plain(bytes, key, start)?;
                while field < MAX_OPERANDS {
                    if let Some(value) = order.get_mut(field) {
                        *value = table_plain(bytes, key, start + 1 + field)?;
                    }
                    field = field.saturating_add(1);
                }
                let reg_map = table_plain(bytes, key, start + 5)?;
                let big_endian = table_plain(bytes, key, start + 6)? != 0;
                *slot = AliasSpec {
                    opcode,
                    order,
                    reg_map,
                    big_endian,
                };
            }
            index = index.saturating_add(1);
        }
        let manifest_big_endian = table_plain(bytes, key, RUNTIME_TABLE_BYTES - 1)? != 0;
        Some(Self {
            semantic_of_opcode,
            alias_of_opcode,
            reg_decode,
            aliases,
            manifest_big_endian,
        })
    }

    /// Returns one alias for a semantic and alias index.
    #[inline]
    #[must_use]
    pub fn alias_for(&self, semantic: u8, choice: usize) -> Option<AliasSpec> {
        let alias_index = choice % ALIASES_PER_SEMANTIC;
        let flat_index = usize::from(semantic)
            .checked_mul(ALIASES_PER_SEMANTIC)?
            .checked_add(alias_index)?;
        self.aliases.get(flat_index).copied()
    }

    /// Decodes a wire register byte for an alias map.
    #[inline]
    #[must_use]
    pub fn decode_register(&self, variant: u8, encoded: u8) -> Option<u8> {
        let variant_index = usize::from(variant & 1);
        self.reg_decode
            .get(variant_index)
            .and_then(|table| table.get(usize::from(encoded)))
            .copied()
            .filter(|value| *value < slot_u8(VM_REGISTERS))
    }

    /// Returns the semantic for an encoded opcode.
    #[inline]
    #[must_use]
    pub fn semantic_for_opcode(&self, opcode: u8) -> Option<u8> {
        self.semantic_of_opcode
            .get(usize::from(opcode))
            .copied()
            .filter(|value| usize::from(*value) < SEMANTIC_COUNT)
    }

    /// Returns the alias index for an encoded opcode.
    #[inline]
    #[must_use]
    pub fn alias_index_for_opcode(&self, opcode: u8) -> Option<usize> {
        self.alias_of_opcode
            .get(usize::from(opcode))
            .copied()
            .filter(|value| usize::from(*value) < ALIASES_PER_SEMANTIC)
            .map(usize::from)
    }
}

impl Tables {
    /// Extracts the runtime-only decode view for a VM invocation.
    #[inline]
    #[must_use]
    pub const fn decode_tables(&self) -> DecodeTables {
        DecodeTables {
            semantic_of_opcode: self.semantic_of_opcode,
            alias_of_opcode: self.alias_of_opcode,
            reg_decode: self.reg_decode,
            aliases: self.aliases,
            manifest_big_endian: self.manifest_big_endian,
        }
    }

    /// Serializes and encrypts the runtime decode table for the generated VM.
    #[must_use]
    #[inline]
    pub fn encode_runtime_table(&self, key: u64) -> [u8; RUNTIME_TABLE_BYTES] {
        let mut bytes = [0_u8; RUNTIME_TABLE_BYTES];
        let mut index = 0_usize;
        while index < 256 {
            table_put(
                &mut bytes,
                index,
                self.semantic_of_opcode.get(index).copied().unwrap_or(0),
            );
            index = index.saturating_add(1);
        }
        index = 0;
        while index < 256 {
            table_put(
                &mut bytes,
                256 + index,
                self.alias_of_opcode.get(index).copied().unwrap_or(0),
            );
            index = index.saturating_add(1);
        }
        let mut variant = 0_usize;
        while variant < 2 {
            index = 0;
            while index < 256 {
                table_put(
                    &mut bytes,
                    512 + variant * 256 + index,
                    self.reg_decode
                        .get(variant)
                        .and_then(|table| table.get(index))
                        .copied()
                        .unwrap_or(INVALID_ENTRY),
                );
                index = index.saturating_add(1);
            }
            variant = variant.saturating_add(1);
        }
        index = 0;
        while index < ALIAS_COUNT {
            let start = 1024 + index * ALIAS_SERIALIZED_BYTES;
            let spec = self.aliases.get(index).copied().unwrap_or_default();
            table_put(&mut bytes, start, spec.opcode);
            let mut field = 0_usize;
            while field < MAX_OPERANDS {
                table_put(
                    &mut bytes,
                    start + 1 + field,
                    spec.order.get(field).copied().unwrap_or(0),
                );
                field = field.saturating_add(1);
            }
            table_put(&mut bytes, start + 5, spec.reg_map);
            table_put(&mut bytes, start + 6, u8::from(spec.big_endian));
            index = index.saturating_add(1);
        }
        table_put(
            &mut bytes,
            RUNTIME_TABLE_BYTES - 1,
            u8::from(self.manifest_big_endian),
        );
        index = 0;
        while index < RUNTIME_TABLE_BYTES {
            if let Some(byte) = bytes.get(index).copied() {
                table_put(&mut bytes, index, byte ^ table_mask(key, index));
            }
            index = index.saturating_add(1);
        }
        bytes
    }

    /// Returns the per-build key used to encrypt the runtime decode table.
    #[inline]
    #[must_use]
    pub fn runtime_table_key(&self) -> u64 {
        table_key(&self.seed)
    }
}

/// Derives the per-build runtime-table encryption key from the plan seed.
#[inline]
#[must_use]
pub fn table_key(seed: &Seed) -> u64 {
    SipHasher24::hash_u64(
        load_u64(seed, 0) ^ 0x7461_626c_655f_6b65,
        load_u64(seed, 8).rotate_left(37),
        0x7374_6174_655f_6964,
    )
}

fn table_mask(key: u64, index: usize) -> u8 {
    let mut value = key
        ^ u64::try_from(index)
            .unwrap_or(u64::MAX)
            .wrapping_mul(0x9e37_79b9_7f4a_7c15);
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    u8::try_from(value & 0xff).unwrap_or(0)
}

fn table_plain(bytes: &[u8], key: u64, index: usize) -> Option<u8> {
    bytes
        .get(index)
        .copied()
        .map(|byte| byte ^ table_mask(key, index))
}

fn table_put(bytes: &mut [u8; RUNTIME_TABLE_BYTES], index: usize, value: u8) {
    if let Some(slot) = bytes.get_mut(index) {
        *slot = value;
    }
}

/// Full derived tables needed by both encoder and runtime.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tables {
    seed: Seed,
    opcodes: [u8; 256],
    aliases: [AliasSpec; ALIAS_COUNT],
    semantic_of_opcode: [u8; 256],
    alias_of_opcode: [u8; 256],
    reg_decode: [[u8; 256]; 2],
    reg_encode: [[u8; VM_REGISTERS]; 2],
    /// Whether manifest integers use big-endian byte order.
    pub manifest_big_endian: bool,
}

#[derive(Clone, Debug)]
struct Expander {
    state: u64,
}

impl Expander {
    #[inline]
    fn new(seed: &Seed) -> Self {
        Self {
            state: load_u64(seed, 0) ^ load_u64(seed, 8).rotate_left(17) ^ 0x6a09_e667_f3bc_c908,
        }
    }

    #[inline]
    const fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    #[inline]
    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        let modulus = u64::try_from(bound).unwrap_or(u64::MAX);
        usize::try_from(self.next_u64() % modulus).unwrap_or(0)
    }
}

/// Small deterministic stream for deriving one alias independently.
#[derive(Clone, Debug)]
struct AliasRng {
    state: u64,
}

impl AliasRng {
    #[inline]
    fn new(seed: &Seed, flat_index: usize) -> Self {
        let index = u64::try_from(flat_index).unwrap_or(u64::MAX);
        let k0 = load_u64(seed, 16) ^ 0x616c_6961_735f_7274;
        let k1 = load_u64(seed, 24).rotate_left(29);
        let state = SipHasher24::hash_u64(k0, k1, index);
        Self { state: state | 1 }
    }

    #[inline]
    const fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    #[inline]
    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        let modulus = u64::try_from(bound).unwrap_or(u64::MAX);
        usize::try_from(self.next_u64() % modulus).unwrap_or(0)
    }
}

#[inline]
fn load_u64(bytes: &[u8], offset: usize) -> u64 {
    bytes
        .get(offset..offset.wrapping_add(8))
        .and_then(|slice| <[u8; 8]>::try_from(slice).ok())
        .map_or(0, u64::from_le_bytes)
}

#[inline]
fn slot_u8(value: usize) -> u8 {
    u8::try_from(value).unwrap_or(0)
}

fn shuffle(bytes: &mut [u8; 256], rng: &mut Expander) {
    let mut index = 255_usize;
    while index > 0 {
        let target = rng.below(index.saturating_add(1));
        if target != index {
            let first = bytes.get(index).copied().unwrap_or(0);
            let second = bytes.get(target).copied().unwrap_or(0);
            if let Some(slot) = bytes.get_mut(index) {
                *slot = second;
            }
            if let Some(slot) = bytes.get_mut(target) {
                *slot = first;
            }
        }
        index = index.saturating_sub(1);
    }
}

fn shuffle_order(order: &mut [u8; MAX_OPERANDS], count: usize, rng: &mut AliasRng) {
    if count <= 1 {
        return;
    }
    let mut index = count.saturating_sub(1);
    while index > 0 {
        let target = rng.below(index.saturating_add(1));
        if target != index {
            let first = order.get(index).copied().unwrap_or(0);
            let second = order.get(target).copied().unwrap_or(0);
            if let Some(slot) = order.get_mut(index) {
                *slot = second;
            }
            if let Some(slot) = order.get_mut(target) {
                *slot = first;
            }
        }
        index = index.saturating_sub(1);
    }
}

fn derive_alias_spec(
    seed: &Seed,
    semantic: u8,
    alias_index: usize,
    opcodes: &[u8; 256],
) -> Option<AliasSpec> {
    let layout = format(semantic)?;
    let semantic_index = usize::from(semantic);
    let flat_index = semantic_index
        .checked_mul(ALIASES_PER_SEMANTIC)?
        .checked_add(alias_index)?;
    let opcode = opcodes.get(flat_index).copied()?;
    let mut rng = AliasRng::new(seed, flat_index);
    let mut order = [0_u8, 1, 2, 3];
    shuffle_order(&mut order, usize::from(layout.len), &mut rng);
    let reg_map = u8::from(rng.next_u64() & 1 == 1);
    let big_endian = rng.next_u64() & 1 == 1;
    Some(AliasSpec {
        opcode,
        order,
        reg_map,
        big_endian,
    })
}

impl Tables {
    /// Derives every per-build table.
    #[inline]
    #[must_use]
    pub fn derive(seed: &Seed) -> Self {
        let seed_byte = seed.first().copied().unwrap_or(0);
        let mut opcodes: [u8; 256] =
            core::array::from_fn(|index| u8::try_from(index).unwrap_or(0) ^ seed_byte);
        let mut opcode_rng = Expander::new(seed);
        shuffle(&mut opcodes, &mut opcode_rng);

        let mut aliases = [AliasSpec::default(); ALIAS_COUNT];
        let mut semantic_of_opcode: [u8; 256] =
            core::array::from_fn(|index| 0xc0 | u8::try_from(index & 0x3f).unwrap_or(0));
        let mut alias_of_opcode: [u8; 256] =
            core::array::from_fn(|index| 0xc0 | u8::try_from(index & 0x3f).unwrap_or(0));
        for semantic in SEMANTIC_IDS {
            let mut alias_index = 0_usize;
            while alias_index < ALIASES_PER_SEMANTIC {
                if let Some(spec) = derive_alias_spec(seed, semantic, alias_index, &opcodes) {
                    let flat_index = usize::from(semantic)
                        .saturating_mul(ALIASES_PER_SEMANTIC)
                        .saturating_add(alias_index);
                    if let Some(slot) = aliases.get_mut(flat_index) {
                        *slot = spec;
                    }
                    if let Some(slot) = semantic_of_opcode.get_mut(usize::from(spec.opcode)) {
                        *slot = semantic;
                    }
                    if let Some(slot) = alias_of_opcode.get_mut(usize::from(spec.opcode)) {
                        *slot = slot_u8(alias_index);
                    }
                }
                alias_index = alias_index.saturating_add(1);
            }
        }

        let mut first_pool: [u8; 256] = core::array::from_fn(|index| {
            u8::try_from(index).unwrap_or(0) ^ seed.get(1).copied().unwrap_or(0)
        });
        let mut second_pool: [u8; 256] = core::array::from_fn(|index| {
            u8::try_from(index).unwrap_or(0) ^ seed.get(2).copied().unwrap_or(0)
        });
        let mut register_rng = Expander::new(&{
            let mut register_seed = *seed;
            if let Some(slot) = register_seed.get_mut(0) {
                *slot ^= 0xa7;
            }
            register_seed
        });
        shuffle(&mut first_pool, &mut register_rng);
        shuffle(&mut second_pool, &mut register_rng);

        let reg_encode: [[u8; VM_REGISTERS]; 2] = core::array::from_fn(|variant| {
            let pool = if variant == 0 {
                &first_pool
            } else {
                &second_pool
            };
            core::array::from_fn(|slot| pool.get(slot).copied().unwrap_or(INVALID_ENTRY))
        });
        let mut reg_decode: [[u8; 256]; 2] = [[INVALID_ENTRY; 256]; 2];
        let mut variant = 0_usize;
        while variant < 2 {
            let mut slot = 0_usize;
            while slot < VM_REGISTERS {
                let encoded = reg_encode
                    .get(variant)
                    .and_then(|table| table.get(slot))
                    .copied()
                    .unwrap_or(INVALID_ENTRY);
                if let Some(target) = reg_decode
                    .get_mut(variant)
                    .and_then(|table| table.get_mut(usize::from(encoded)))
                {
                    *target = slot_u8(slot);
                }
                slot = slot.saturating_add(1);
            }
            variant = variant.saturating_add(1);
        }

        Self {
            seed: *seed,
            opcodes,
            aliases,
            semantic_of_opcode,
            alias_of_opcode,
            reg_decode,
            reg_encode,
            manifest_big_endian: opcode_rng.next_u64() & 1 == 1,
        }
    }

    /// Returns one alias for a semantic, selected by the caller's random source.
    #[inline]
    #[must_use]
    pub fn alias_for(&self, semantic: u8, choice: usize) -> Option<AliasSpec> {
        let alias_index = choice % ALIASES_PER_SEMANTIC;
        let flat_index = usize::from(semantic)
            .checked_mul(ALIASES_PER_SEMANTIC)?
            .checked_add(alias_index)?;
        self.aliases.get(flat_index).copied()
    }

    /// Encodes a logical register for an alias map.
    #[inline]
    #[must_use]
    pub fn encode_register(&self, variant: u8, register: u8) -> Option<u8> {
        let variant_index = usize::from(variant & 1);
        self.reg_encode
            .get(variant_index)
            .and_then(|table| table.get(usize::from(register)))
            .copied()
    }

    /// Decodes a wire register byte for an alias map.
    #[inline]
    #[must_use]
    pub fn decode_register(&self, variant: u8, encoded: u8) -> Option<u8> {
        let variant_index = usize::from(variant & 1);
        self.reg_decode
            .get(variant_index)
            .and_then(|table| table.get(usize::from(encoded)))
            .copied()
            .filter(|value| *value < slot_u8(VM_REGISTERS))
    }

    /// Returns the semantic for an encoded opcode.
    #[inline]
    #[must_use]
    pub fn semantic_for_opcode(&self, opcode: u8) -> Option<u8> {
        self.semantic_of_opcode
            .get(usize::from(opcode))
            .copied()
            .filter(|value| usize::from(*value) < SEMANTIC_COUNT)
    }

    /// Returns the alias index for an encoded opcode.
    #[inline]
    #[must_use]
    pub fn alias_index_for_opcode(&self, opcode: u8) -> Option<usize> {
        self.alias_of_opcode
            .get(usize::from(opcode))
            .copied()
            .filter(|value| usize::from(*value) < ALIASES_PER_SEMANTIC)
            .map(usize::from)
    }
}

#[cfg(test)]
mod tests {
    use super::{Tables, derive_alias_spec};
    use crate::shared::format::{
        ALIASES_PER_SEMANTIC, SEMANTIC_COUNT, SEMANTIC_IDS, VM_REGISTERS, format,
    };

    fn seed(value: u8) -> [u8; 32] {
        let mut seed = [0_u8; 32];
        let mut index = 0_usize;
        while index < 32 {
            if let Some(slot) = seed.get_mut(index) {
                *slot = value.wrapping_add(u8::try_from(index).unwrap_or(0));
            }
            index += 1;
        }
        seed
    }

    #[test]
    fn derivation_is_deterministic() {
        let first = Tables::derive(&seed(7));
        let second = Tables::derive(&seed(7));
        assert_eq!(first, second);
    }

    #[test]
    fn different_seeds_differ() {
        let first = Tables::derive(&seed(1));
        let second = Tables::derive(&seed(2));
        assert_ne!(first.alias_for(0, 0), second.alias_for(0, 0));
        assert_ne!(first.encode_register(0, 0), second.encode_register(0, 0));
    }

    #[test]
    fn encrypted_decode_table_round_trips_and_rejects_truncation() {
        let tables = Tables::derive(&seed(0x5a));
        let key = tables.runtime_table_key();
        let bytes = tables.encode_runtime_table(key);
        assert_ne!(bytes, tables.encode_runtime_table(key ^ 1));
        let decoded = super::DecodeTables::from_encrypted(&bytes, key).expect("decode table");
        for semantic in SEMANTIC_IDS {
            for alias in 0..ALIASES_PER_SEMANTIC {
                assert_eq!(
                    tables.alias_for(semantic, alias),
                    decoded.alias_for(semantic, alias)
                );
            }
        }
        for index in 0..=255_u8 {
            assert_eq!(
                tables.semantic_for_opcode(index),
                decoded.semantic_for_opcode(index)
            );
            if let Some(alias) = tables.alias_for(0, 0) {
                assert_eq!(
                    tables.decode_register(alias.reg_map, index),
                    decoded.decode_register(alias.reg_map, index)
                );
            }
        }
        assert_eq!(tables.manifest_big_endian, decoded.manifest_big_endian);
        assert!(super::DecodeTables::from_encrypted(&bytes[..bytes.len() - 1], key).is_none());
    }

    #[test]
    fn arbitrary_decode_tables_do_not_panic_on_lookup() {
        let mut bytes = [0_u8; super::RUNTIME_TABLE_BYTES];
        let mut state = 0x1234_5678_9abc_def0_u64;
        let mut round = 0_usize;
        while round < 32 {
            let mut index = 0_usize;
            while index < bytes.len() {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                if let Some(slot) = bytes.get_mut(index) {
                    *slot = u8::try_from(state & 0xff).unwrap_or(0);
                }
                index = index.saturating_add(1);
            }
            if let Some(tables) = super::DecodeTables::from_encrypted(&bytes, state) {
                for opcode in 0..=255_u8 {
                    let _ = tables.semantic_for_opcode(opcode);
                    let _ = tables.alias_index_for_opcode(opcode);
                    for variant in 0..2_u8 {
                        let _ = tables.decode_register(variant, opcode);
                    }
                }
                for semantic in 0..=255_u8 {
                    for alias in 0..4 {
                        let _ = tables.alias_for(semantic, alias);
                    }
                }
            }
            round = round.saturating_add(1);
        }
    }

    #[test]
    fn zero_bounds_yield_zero_without_advancing() {
        let seed = seed(3);
        let mut expander = super::Expander::new(&seed);
        assert_eq!(expander.below(0), 0);
        let mut alias = super::AliasRng::new(&seed, 0);
        assert_eq!(alias.below(0), 0);
    }

    #[test]
    fn every_semantic_has_four_unique_opcodes() {
        let tables = Tables::derive(&seed(9));
        let expected = SEMANTIC_COUNT * ALIASES_PER_SEMANTIC;
        let mut count = 0_usize;
        for semantic in SEMANTIC_IDS {
            for alias in 0..ALIASES_PER_SEMANTIC {
                let spec = tables
                    .alias_for(semantic, alias)
                    .expect("alias for semantic");
                assert_eq!(tables.semantic_for_opcode(spec.opcode), Some(semantic));
                assert_eq!(tables.alias_index_for_opcode(spec.opcode), Some(alias));
                count += 1;
            }
        }
        assert_eq!(count, expected);
        assert!(count <= 256);
    }

    #[test]
    fn every_opcode_is_globally_unique() {
        let tables = Tables::derive(&seed(11));
        let mut seen = [false; 256];
        for semantic in SEMANTIC_IDS {
            for alias in 0..ALIASES_PER_SEMANTIC {
                let spec = tables.alias_for(semantic, alias).expect("alias");
                let slot = seen
                    .get_mut(usize::from(spec.opcode))
                    .expect("opcode index");
                assert!(!*slot, "duplicate opcode {}", spec.opcode);
                *slot = true;
            }
        }
    }

    #[test]
    fn register_maps_invert() {
        let tables = Tables::derive(&seed(13));
        for variant in 0_u8..2 {
            for logical in 0..u8::try_from(VM_REGISTERS).unwrap_or(0) {
                let encoded = tables.encode_register(variant, logical).expect("encode");
                assert_eq!(tables.decode_register(variant, encoded), Some(logical));
            }
        }
    }

    #[test]
    fn operand_orders_are_permutations_of_valid_roles() {
        let tables = Tables::derive(&seed(17));
        for semantic in SEMANTIC_IDS {
            let layout = format(semantic).expect("format");
            for alias in 0..ALIASES_PER_SEMANTIC {
                let spec = tables.alias_for(semantic, alias).expect("alias");
                let count = usize::from(layout.len);
                let mut seen = [false; 4];
                for position in 0..count {
                    let role = usize::from(spec.order.get(position).copied().unwrap_or(0));
                    assert!(role < count);
                    assert!(!seen.get(role).copied().unwrap_or(true));
                    if let Some(slot) = seen.get_mut(role) {
                        *slot = true;
                    }
                }
            }
        }
    }

    #[test]
    fn invalid_lookups_return_none() {
        let tables = Tables::derive(&seed(21));
        assert_eq!(tables.alias_for(u8::MAX, 0), None);
        assert_eq!(tables.encode_register(0, u8::MAX), None);
        let mut invalid_register = false;
        let mut encoded = 0_u16;
        while encoded <= 255 {
            if tables
                .decode_register(0, u8::try_from(encoded).unwrap_or(0))
                .is_none()
            {
                invalid_register = true;
                break;
            }
            encoded += 1;
        }
        assert!(invalid_register);
        let mut invalid_opcode = false;
        let mut opcode = 0_u16;
        while opcode <= 255 {
            if tables
                .semantic_for_opcode(u8::try_from(opcode).unwrap_or(0))
                .is_none()
            {
                invalid_opcode = true;
                break;
            }
            opcode += 1;
        }
        assert!(invalid_opcode);
    }

    #[test]
    fn alias_derivation_is_stable_across_calls() {
        let tables = Tables::derive(&seed(19));
        let first = tables.alias_for(3, 2);
        let second = tables.alias_for(3, 2);
        assert_eq!(first, second);
        assert_eq!(first, derive_alias_spec(&seed(19), 3, 2, &tables.opcodes));
    }
}
