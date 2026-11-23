//! Entropy, seed parsing, deterministic junk, and hexadecimal helpers.

use core::fmt::Write as _;
use std::collections::hash_map::RandomState;
use std::fs::File;
use std::hash::{BuildHasher, Hasher};
use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

use sirus_core::shared::chacha::ChaCha20;
use sirus_core::shared::derive::Seed;

use crate::error::{ProtectError, Result};

/// Obtains 256 bits of build entropy.
///
/// Linux uses `/dev/urandom`. Other platforms fall back to `RandomState`, wall
/// time, process id, and argument-derived mixing. The fallback is documented as
/// non-cryptographic; production Linux builds always use the OS source.
pub fn seed() -> Result<Seed> {
    let mut seed = [0_u8; 32];
    match File::open("/dev/urandom").and_then(|mut file| file.read_exact(&mut seed)) {
        Ok(()) => return Ok(seed),
        Err(_) => {}
    }
    let random_state = RandomState::new();
    let mut hasher = random_state.build_hasher();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    hasher.write_u128(now.as_nanos());
    hasher.write_u32(std::process::id());
    for argument in std::env::args_os() {
        hasher.write(argument.to_string_lossy().as_bytes());
    }
    let first = hasher.finish();
    hasher.write_u64(first);
    let second = hasher.finish();
    hasher.write_u64(second);
    let third = hasher.finish();
    hasher.write_u64(third);
    let fourth = hasher.finish();
    let words = [first, second, third, fourth];
    for (index, word) in words.iter().enumerate() {
        let bytes = word.to_le_bytes();
        let base = index.saturating_mul(8);
        for (offset, byte) in bytes.iter().enumerate() {
            if let Some(slot) = seed.get_mut(base.saturating_add(offset)) {
                *slot = *byte;
            }
        }
    }
    Ok(seed)
}

/// Parses a 64-character hexadecimal seed.
pub fn parse_seed(text: &str) -> Result<Seed> {
    if text.len() != 64 {
        return Err(ProtectError::usage("seed must be exactly 64 hex characters"));
    }
    let mut seed = [0_u8; 32];
    let mut index = 0_usize;
    while index < 32 {
        let high_index = index.saturating_mul(2);
        let low_index = high_index.saturating_add(1);
        let Some(high_char) = text.chars().nth(high_index) else {
            return Err(ProtectError::usage("seed is truncated"));
        };
        let Some(low_char) = text.chars().nth(low_index) else {
            return Err(ProtectError::usage("seed is truncated"));
        };
        let Some(high) = high_char.to_digit(16) else {
            return Err(ProtectError::usage("seed contains a non-hex character"));
        };
        let Some(low) = low_char.to_digit(16) else {
            return Err(ProtectError::usage("seed contains a non-hex character"));
        };
        let high = u8::try_from(high).map_err(|_| ProtectError::internal("hex high nibble"))?;
        let low = u8::try_from(low).map_err(|_| ProtectError::internal("hex low nibble"))?;
        if let Some(slot) = seed.get_mut(index) {
            *slot = (high << 4) | low;
        }
        index = index.saturating_add(1);
    }
    Ok(seed)
}

/// Formats a seed as lowercase hexadecimal.
pub fn format_seed(seed: &Seed) -> String {
    let mut output = String::with_capacity(64);
    for byte in seed {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

/// Builds a short unique identifier from the seed, payload hash, and size.
pub fn build_id(seed: &Seed, payload_hash: u64, payload_len: usize) -> String {
    let mut first = [0_u8; 8];
    let mut second = [0_u8; 8];
    for (index, byte) in seed.iter().take(8).enumerate() {
        if let Some(slot) = first.get_mut(index) {
            *slot = *byte;
        }
    }
    let first_word = u64::from_le_bytes(first).rotate_left(17) ^ payload_hash;
    let second_word = payload_hash
        .rotate_left(31)
        .wrapping_add(u64::try_from(payload_len).unwrap_or(u64::MAX))
        ^ u64::from_le_bytes(seed.get(8..16).and_then(|slice| <[u8; 8]>::try_from(slice).ok()).unwrap_or(second));
    for (index, byte) in second_word.to_le_bytes().iter().enumerate() {
        if let Some(slot) = second.get_mut(index) {
            *slot = *byte;
        }
    }
    let mut output = String::with_capacity(16);
    for word in [first_word, second_word] {
        let _ = write!(output, "{word:016x}");
    }
    output
}

/// Generates deterministic random bytes for scrubbing.
pub fn junk(seed: &Seed, domain: u64, length: usize) -> Vec<u8> {
    let mut nonce = [0_u8; 12];
    let bytes = domain.to_le_bytes();
    for (index, byte) in bytes.iter().enumerate().take(8) {
        if let Some(slot) = nonce.get_mut(index) {
            *slot = *byte;
        }
    }
    let mut stream = ChaCha20::new(*seed, nonce);
    let mut output = vec![0_u8; length];
    stream.fill(&mut output);
    output
}

/// Reads a hexadecimal byte pattern such as `48 8b 05` or `488b05`.
pub fn parse_hex_bytes(text: &str) -> Result<Vec<u8>> {
    let mut digits = String::with_capacity(text.len());
    for character in text.chars() {
        if character.is_ascii_hexdigit() {
            digits.push(character);
        } else if character.is_whitespace() || character == '_' || character == ':' {
            continue;
        } else {
            return Err(ProtectError::usage("invalid hex byte pattern"));
        }
    }
    if digits.is_empty() || digits.len() % 2 != 0 {
        return Err(ProtectError::usage(
            "hex byte pattern must contain complete bytes",
        ));
    }
    let mut output = Vec::with_capacity(digits.len() / 2);
    let chars: Vec<char> = digits.chars().collect();
    let mut index = 0_usize;
    while index < chars.len() {
        let Some(high_char) = chars.get(index) else {
            break;
        };
        let Some(low_char) = chars.get(index.saturating_add(1)) else {
            break;
        };
        let Some(high) = high_char.to_digit(16) else {
            return Err(ProtectError::usage("invalid hex byte pattern"));
        };
        let Some(low) = low_char.to_digit(16) else {
            return Err(ProtectError::usage("invalid hex byte pattern"));
        };
        let high = u8::try_from(high).map_err(|_| ProtectError::internal("hex nibble"))?;
        let low = u8::try_from(low).map_err(|_| ProtectError::internal("hex nibble"))?;
        output.push((high << 4) | low);
        index = index.saturating_add(2);
    }
    Ok(output)
}
