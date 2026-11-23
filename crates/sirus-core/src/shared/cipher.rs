//! Payload manifest encryption, rolling body cipher, and integrity binding.
//!
//! The manifest is position-addressed so the dispatcher can find a state
//! without decrypting the whole payload. Block bodies use a rolling chain that
//! depends on the previous decoded byte, the absolute payload offset, and the
//! block state.

use crate::shared::derive::Seed;
use crate::shared::format::DEFAULT_FUEL;
use crate::shared::sip::SipHasher24;

/// Number of bytes in the encrypted block-count field.
pub const MANIFEST_COUNT_BYTES: usize = 8;

/// Number of bytes in one encrypted manifest entry.
pub const MANIFEST_ENTRY_BYTES: usize = 16;

/// Maximum number of blocks accepted by the runtime.
pub const MAX_PAYLOAD_BLOCKS: usize = 256;

/// Domain separation constant for the manifest stream.
const MANIFEST_DOMAIN: u64 = 0x6d61_6e69_6665_7374;

/// Domain separation constant for payload integrity.
const INTEGRITY_DOMAIN: u64 = 0x7369_7275_7369_6e74;

/// Domain separation constant for body initialization.
const BODY_DOMAIN: u64 = 0x626f_6479_7374_7265;

/// Returns the exact manifest size for a block count, or `None` on overflow or
/// an out-of-range count.
#[inline]
#[must_use]
pub fn manifest_size(count: usize) -> Option<usize> {
    if count > MAX_PAYLOAD_BLOCKS {
        return None;
    }
    count
        .checked_mul(MANIFEST_ENTRY_BYTES)?
        .checked_add(MANIFEST_COUNT_BYTES)
}

/// Computes the integrity binding hash over the encrypted payload. The key is
/// derived from the second half of the plan seed.
#[inline]
#[must_use]
pub fn payload_hash(seed: &Seed, payload: &[u8]) -> u64 {
    let k0 = read_u64(seed, 16) ^ INTEGRITY_DOMAIN;
    let k1 = read_u64(seed, 24).rotate_left(23);
    SipHasher24::hash(k0, k1, payload)
}

/// Derives the intended base key from the first half of the seed.
#[inline]
#[must_use]
pub fn base_key(seed: &Seed) -> u64 {
    read_u64(seed, 0)
        .rotate_left(7)
        .wrapping_add(read_u64(seed, 8))
        .wrapping_add(BODY_DOMAIN)
}

/// Mixes integrity status into the effective key without a conditional branch.
/// An intact payload yields `base_a ^ base_b`; any mutation alters the key.
#[inline]
#[must_use]
pub fn effective_key(base_a: u64, base_b: u64, actual_hash: u64, expected_hash: u64) -> u64 {
    base_a ^ base_b ^ actual_hash ^ expected_hash
}

/// Position-addressed manifest keystream byte.
#[inline]
#[must_use]
pub fn manifest_mask(key: u64, index: usize) -> u8 {
    let index = u64::try_from(index).unwrap_or(u64::MAX);
    let hash = SipHasher24::hash_u64(key, key.rotate_left(32) ^ MANIFEST_DOMAIN, index);
    u8::try_from(hash & 0xff).unwrap_or(0)
}

/// XORs one manifest byte. Symmetric for encryption and decryption.
#[inline]
#[must_use]
pub fn manifest_byte(key: u64, index: usize, byte: u8) -> u8 {
    byte ^ manifest_mask(key, index)
}

/// Decodes a manifest integer according to the build's chosen byte order.
#[inline]
#[must_use]
pub fn decode_manifest_u32(bytes: &[u8; 4], big_endian: bool) -> u32 {
    if big_endian {
        u32::from_be_bytes(*bytes)
    } else {
        u32::from_le_bytes(*bytes)
    }
}

/// Encodes a manifest integer according to the build's chosen byte order.
#[inline]
#[must_use]
pub fn encode_manifest_u32(value: u32, big_endian: bool) -> [u8; 4] {
    if big_endian {
        value.to_be_bytes()
    } else {
        value.to_le_bytes()
    }
}

/// Decodes a manifest integer according to the build's chosen byte order.
#[inline]
#[must_use]
pub fn decode_manifest_u64(bytes: &[u8; 8], big_endian: bool) -> u64 {
    if big_endian {
        u64::from_be_bytes(*bytes)
    } else {
        u64::from_le_bytes(*bytes)
    }
}

/// Encodes a manifest integer according to the build's chosen byte order.
#[inline]
#[must_use]
pub fn encode_manifest_u64(value: u64, big_endian: bool) -> [u8; 8] {
    if big_endian {
        value.to_be_bytes()
    } else {
        value.to_le_bytes()
    }
}

/// Rolling cipher state for one block body.
#[derive(Clone, Copy, Debug)]
pub struct BodyCipher {
    state: u64,
}

impl BodyCipher {
    /// Initializes a body cipher from the global key, block state, and absolute
    /// body offset.
    #[inline]
    #[must_use]
    pub fn new(global_key: u64, block_state: u64, body_offset: usize) -> Self {
        let offset = u64::try_from(body_offset).unwrap_or(u64::MAX);
        let state = global_key
            ^ block_state.rotate_left(17)
            ^ offset
            ^ BODY_DOMAIN;
        Self { state }
    }

    /// XORs one byte at an absolute payload offset. `previous_plain` is the
    /// previous decoded byte of the same body, or zero at the start.
    #[inline]
    pub fn apply(&mut self, absolute_offset: usize, previous_plain: u8, byte: u8) -> u8 {
        let index = u64::try_from(absolute_offset).unwrap_or(u64::MAX);
        let hash = SipHasher24::hash_u64(
            self.state,
            self.state.rotate_left(29) ^ u64::from(previous_plain),
            index,
        );
        let mask = u8::try_from(hash & 0xff).unwrap_or(0);
        self.state = self
            .state
            .rotate_left(11)
            .wrapping_add(hash)
            .wrapping_add(index)
            ^ u64::from(previous_plain);
        byte ^ mask
    }

    /// Returns the current chaining state for diagnostics and tests.
    #[inline]
    #[must_use]
    pub const fn state(&self) -> u64 {
        self.state
    }
}

/// Reads a little-endian integer from a seed without indexing.
#[inline]
fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    bytes
        .get(offset..offset.wrapping_add(8))
        .and_then(|slice| <[u8; 8]>::try_from(slice).ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0)
}

/// Returns the default fuel so generated sources can reference one constant.
#[inline]
#[must_use]
pub const fn default_fuel() -> u64 {
    DEFAULT_FUEL
}

#[cfg(test)]
mod tests {
    use super::{
        base_key, decode_manifest_u64, effective_key, encode_manifest_u64, manifest_byte,
        manifest_size, payload_hash, BodyCipher, MANIFEST_ENTRY_BYTES, MAX_PAYLOAD_BLOCKS,
    };

    fn seed(value: u8) -> [u8; 32] {
        [value; 32]
    }

    #[test]
    fn manifest_size_is_checked() {
        assert_eq!(manifest_size(0), Some(8));
        assert_eq!(
            manifest_size(3),
            Some(8 + 3 * MANIFEST_ENTRY_BYTES)
        );
        assert_eq!(manifest_size(MAX_PAYLOAD_BLOCKS + 1), None);
    }

    #[test]
    fn manifest_cipher_is_symmetric() {
        let key = 0x1234_5678_9abc_def0;
        let plain = [0x10_u8, 0x20, 0x30, 0x40];
        let mut cipher = [0_u8; 4];
        for (index, byte) in plain.iter().enumerate() {
            if let Some(slot) = cipher.get_mut(index) {
                *slot = manifest_byte(key, index, *byte);
            }
        }
        assert_ne!(cipher, plain);
        for (index, byte) in cipher.iter().enumerate() {
            assert_eq!(manifest_byte(key, index, *byte), plain[index]);
        }
    }

    #[test]
    fn manifest_endian_round_trips() {
        let value = 0x0102_0304_0506_0708_u64;
        for big in [false, true] {
            let bytes = encode_manifest_u64(value, big);
            assert_eq!(decode_manifest_u64(&bytes, big), value);
        }
    }

    #[test]
    fn body_cipher_round_trips_and_chains() {
        let plain = [7_u8, 8, 9, 10, 11, 12, 13, 14];
        let mut encrypted = [0_u8; 8];
        let mut previous = 0_u8;
        let mut encryptor = BodyCipher::new(99, 0xaaaa_bbbb, 64);
        for (index, byte) in plain.iter().enumerate() {
            let absolute = 64 + index;
            let cipher = encryptor.apply(absolute, previous, *byte);
            assert_ne!(cipher, *byte);
            if let Some(slot) = encrypted.get_mut(index) {
                *slot = cipher;
            }
            previous = *byte;
        }
        let mut decryptor = BodyCipher::new(99, 0xaaaa_bbbb, 64);
        let mut decrypted = [0_u8; 8];
        let mut previous = 0_u8;
        for (index, byte) in encrypted.iter().enumerate() {
            let absolute = 64 + index;
            let plain_byte = decryptor.apply(absolute, previous, *byte);
            if let Some(slot) = decrypted.get_mut(index) {
                *slot = plain_byte;
            }
            previous = plain_byte;
        }
        assert_eq!(plain, decrypted);
        assert_ne!(encryptor.state(), 0);
        assert!(
            BodyCipher::new(99, 0xaaaa_bbbb, 64).apply(64, 0, 1)
                != BodyCipher::new(99, 0xaaaa_bbbb, 65).apply(65, 0, 1)
        );
    }

    #[test]
    fn integrity_mismatch_changes_effective_key() {
        let seed = seed(42);
        let payload = b"encrypted payload";
        let actual = payload_hash(&seed, payload);
        let expected = actual;
        let base = base_key(&seed);
        assert_eq!(effective_key(base, 0, actual, expected), base);
        assert_ne!(
            effective_key(base, 0, actual ^ 1, expected),
            base
        );
        assert_ne!(payload_hash(&seed, b"other"), actual);
    }
}
