//! Deterministic derivation of per-build ISA tables from a 256-bit seed.
//!
//! The tables are never serialized into the runtime. Both the build-time
//! encoder and the injected VM call this module with the same seed.

use crate::shared::format::{
    ALIASES_PER_SEMANTIC, INVALID_OPCODE, MAX_OPERANDS, SEMANTIC_COUNT, SEMANTIC_IDS, VM_REGISTERS,
    format,
};
use crate::shared::sip::SipHasher24;

/// 256-bit plan seed.
pub type Seed = [u8; 32];

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

/// Full derived tables needed by both encoder and runtime.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tables {
    /// Aliases for every semantic operation.
    pub aliases: [[AliasSpec; ALIASES_PER_SEMANTIC]; SEMANTIC_COUNT],
    /// Opcode byte to semantic, or `INVALID_OPCODE`.
    pub semantic_of_opcode: [u8; 256],
    /// Opcode byte to alias index, or `INVALID_OPCODE`.
    pub alias_of_opcode: [u8; 256],
    /// Encoded register byte to logical register, or `INVALID_OPCODE`.
    pub reg_decode: [[u8; 256]; 2],
    /// Logical register to encoded register byte.
    pub reg_encode: [[u8; VM_REGISTERS]; 2],
    /// Whether manifest integers use big-endian byte order.
    pub manifest_big_endian: bool,
}

/// Small deterministic expander built from `SipHash`. It is not a general
/// cryptographic random generator; build entropy comes from `ChaCha20` and the
/// operating system. This expander only converts one secret seed into
/// reproducible structural tables.
#[derive(Clone, Debug)]
struct Expander {
    k0: u64,
    k1: u64,
    counter: u64,
}

impl Expander {
    #[inline]
    fn new(seed: &Seed) -> Self {
        Self {
            k0: load_u64(seed, 0),
            k1: load_u64(seed, 8),
            counter: 0,
        }
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        let value = SipHasher24::hash_u64(self.k0, self.k1, self.counter);
        self.counter = self.counter.wrapping_add(1);
        value
    }

    #[inline]
    fn next_bool(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }

    #[inline]
    fn below(&mut self, bound: usize) -> usize {
        let modulus = u64::try_from(bound).unwrap_or(1);
        if modulus == 0 {
            return 0;
        }
        let value = self.next_u64() % modulus;
        usize::try_from(value).unwrap_or(0)
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
fn low_u8(value: u64) -> u8 {
    u8::try_from(value & 0xff).unwrap_or(0)
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

fn shuffle_order(order: &mut [u8; MAX_OPERANDS], count: usize, rng: &mut Expander) {
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

impl Tables {
    /// Derives every per-build table. Returns `None` if a compiled-in semantic
    /// format is malformed, which would indicate source corruption.
    #[inline]
    #[must_use]
    pub fn derive(seed: &Seed) -> Option<Self> {
        let mut rng = Expander::new(seed);
        let mut opcodes = [0_u8; 256];
        let mut index = 0_usize;
        while index < 256 {
            if let Some(slot) = opcodes.get_mut(index) {
                *slot = slot_u8(index);
            }
            index = index.saturating_add(1);
        }
        shuffle(&mut opcodes, &mut rng);

        let mut aliases = [[AliasSpec::default(); ALIASES_PER_SEMANTIC]; SEMANTIC_COUNT];
        let mut semantic_of_opcode = [INVALID_OPCODE; 256];
        let mut alias_of_opcode = [INVALID_OPCODE; 256];
        let mut cursor = 0_usize;

        for semantic in SEMANTIC_IDS {
            let layout = format(semantic)?;
            for alias_index in 0..ALIASES_PER_SEMANTIC {
                let opcode = opcodes.get(cursor).copied().unwrap_or(INVALID_OPCODE);
                cursor = cursor.saturating_add(1);
                let mut order = [0_u8, 1, 2, 3];
                shuffle_order(&mut order, usize::from(layout.len), &mut rng);
                let spec = AliasSpec {
                    opcode,
                    order,
                    reg_map: u8::from(rng.next_bool()),
                    big_endian: rng.next_bool(),
                };
                if let Some(semantic_slot) = aliases.get_mut(usize::from(semantic)) {
                    if let Some(alias_slot) = semantic_slot.get_mut(alias_index) {
                        *alias_slot = spec;
                    }
                }
                if let Some(slot) = semantic_of_opcode.get_mut(usize::from(opcode)) {
                    *slot = semantic;
                }
                if let Some(slot) = alias_of_opcode.get_mut(usize::from(opcode)) {
                    *slot = slot_u8(alias_index);
                }
            }
        }

        let mut reg_decode = [[INVALID_OPCODE; 256]; 2];
        let mut reg_encode = [[0_u8; VM_REGISTERS]; 2];
        let mut variant = 0_usize;
        while variant < 2 {
            let mut encodings = [0_u8; 256];
            let mut init = 0_usize;
            while init < 256 {
                if let Some(slot) = encodings.get_mut(init) {
                    *slot = slot_u8(init);
                }
                init = init.saturating_add(1);
            }
            shuffle(&mut encodings, &mut rng);
            let mut register = 0_usize;
            while register < VM_REGISTERS {
                let encoded = encodings.get(register).copied().unwrap_or(INVALID_OPCODE);
                if let Some(encode_slot) = reg_encode.get_mut(variant) {
                    if let Some(value) = encode_slot.get_mut(register) {
                        *value = encoded;
                    }
                }
                if let Some(decode_table) = reg_decode.get_mut(variant) {
                    if let Some(value) = decode_table.get_mut(usize::from(encoded)) {
                        *value = slot_u8(register);
                    }
                }
                register = register.saturating_add(1);
            }
            variant = variant.saturating_add(1);
        }

        Some(Self {
            aliases,
            semantic_of_opcode,
            alias_of_opcode,
            reg_decode,
            reg_encode,
            manifest_big_endian: rng.next_bool(),
        })
    }

    /// Returns one alias for a semantic, selected by the caller's random source.
    #[inline]
    #[must_use]
    pub fn alias_for(&self, semantic: u8, choice: usize) -> Option<AliasSpec> {
        let alias_index = choice % ALIASES_PER_SEMANTIC;
        self.aliases
            .get(usize::from(semantic))
            .and_then(|aliases| aliases.get(alias_index))
            .copied()
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
            .filter(|value| *value != INVALID_OPCODE)
    }

    /// Returns the alias index for an encoded opcode.
    #[inline]
    #[must_use]
    pub fn alias_index_for_opcode(&self, opcode: u8) -> Option<usize> {
        self.alias_of_opcode
            .get(usize::from(opcode))
            .copied()
            .filter(|value| *value != INVALID_OPCODE)
            .map(usize::from)
    }
}

/// Returns the low byte of a value without an unchecked cast.
#[inline]
#[must_use]
pub fn low_byte(value: u64) -> u8 {
    low_u8(value)
}

#[cfg(test)]
mod tests {
    use super::{Tables, low_byte};
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
        assert!(first.is_some());
        assert_eq!(first, second);
    }

    #[test]
    fn different_seeds_differ() {
        let first = Tables::derive(&seed(1)).expect("seed 1");
        let second = Tables::derive(&seed(2)).expect("seed 2");
        assert_ne!(first.aliases, second.aliases);
        assert_ne!(first.reg_encode, second.reg_encode);
    }

    #[test]
    fn every_semantic_has_four_unique_opcodes() {
        let tables = Tables::derive(&seed(9)).expect("tables");
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
    fn opcodes_are_globally_unique() {
        let tables = Tables::derive(&seed(11)).expect("tables");
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
        let tables = Tables::derive(&seed(13)).expect("tables");
        for variant in 0_u8..2 {
            for logical in 0..u8::try_from(VM_REGISTERS).unwrap_or(0) {
                let encoded = tables.encode_register(variant, logical).expect("encode");
                assert_eq!(tables.decode_register(variant, encoded), Some(logical));
            }
        }
    }

    #[test]
    fn operand_orders_are_permutations_of_valid_roles() {
        let tables = Tables::derive(&seed(17)).expect("tables");
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
    fn low_byte_never_casts() {
        assert_eq!(low_byte(0x1234), 0x34);
        assert_eq!(low_byte(u64::MAX), 0xff);
    }
}
