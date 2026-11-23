//! `ChaCha20` stream cipher (RFC 8439), used to expand operating-system entropy
//! into build keys and randomized padding. This is the only primitive in the
//! project intended to carry cryptographic entropy.

use core::cmp::min;

/// Loads four little-endian bytes without a panicking index operation.
#[inline]
fn load_u32(bytes: &[u8], offset: usize) -> u32 {
    bytes
        .get(offset..offset.wrapping_add(4))
        .and_then(|slice| <[u8; 4]>::try_from(slice).ok())
        .map_or(0, u32::from_le_bytes)
}

macro_rules! quarter_round {
    ($a:ident, $b:ident, $c:ident, $d:ident) => {
        $a = $a.wrapping_add($b);
        $d ^= $a;
        $d = $d.rotate_left(16);
        $c = $c.wrapping_add($d);
        $b ^= $c;
        $b = $b.rotate_left(12);
        $a = $a.wrapping_add($b);
        $d ^= $a;
        $d = $d.rotate_left(8);
        $c = $c.wrapping_add($d);
        $b ^= $c;
        $b = $b.rotate_left(7);
    };
}

/// `ChaCha20` generator with a 256-bit key and 96-bit nonce.
#[derive(Clone, Debug)]
pub struct ChaCha20 {
    key: [u32; 8],
    nonce: [u32; 3],
    counter: u32,
    block: [u8; 64],
    block_index: usize,
}

impl ChaCha20 {
    /// Creates a stream. The counter starts at zero.
    #[inline]
    #[must_use]
    pub fn new(key: [u8; 32], nonce: [u8; 12]) -> Self {
        let mut words = [0_u32; 8];
        let mut index = 0_usize;
        while index < 8 {
            if let Some(word) = words.get_mut(index) {
                *word = load_u32(&key, index.wrapping_mul(4));
            }
            index += 1;
        }
        let mut nonce_words = [0_u32; 3];
        let mut nonce_index = 0_usize;
        while nonce_index < 3 {
            if let Some(word) = nonce_words.get_mut(nonce_index) {
                *word = load_u32(&nonce, nonce_index.wrapping_mul(4));
            }
            nonce_index += 1;
        }
        Self {
            key: words,
            nonce: nonce_words,
            counter: 0,
            block: [0_u8; 64],
            block_index: 64,
        }
    }

    /// Creates a stream with an explicit counter.
    #[inline]
    #[must_use]
    pub const fn with_counter(mut self, counter: u32) -> Self {
        self.counter = counter;
        self.block_index = 64;
        self
    }

    #[inline]
    fn generate_block(&mut self) {
        let mut x0 = 0x6170_7865_u32;
        let mut x1 = 0x3320_646e_u32;
        let mut x2 = 0x7962_2d32_u32;
        let mut x3 = 0x6b20_6574_u32;
        let [k0, k1, k2, k3, k4, k5, k6, k7] = self.key;
        let [n0, n1, n2] = self.nonce;
        let mut x4 = k0;
        let mut x5 = k1;
        let mut x6 = k2;
        let mut x7 = k3;
        let mut x8 = k4;
        let mut x9 = k5;
        let mut x10 = k6;
        let mut x11 = k7;
        let mut x12 = self.counter;
        let mut x13 = n0;
        let mut x14 = n1;
        let mut x15 = n2;

        let mut round = 0_u8;
        while round < 10 {
            quarter_round!(x0, x4, x8, x12);
            quarter_round!(x1, x5, x9, x13);
            quarter_round!(x2, x6, x10, x14);
            quarter_round!(x3, x7, x11, x15);
            quarter_round!(x0, x5, x10, x15);
            quarter_round!(x1, x6, x11, x12);
            quarter_round!(x2, x7, x8, x13);
            quarter_round!(x3, x4, x9, x14);
            round += 1;
        }

        x0 = x0.wrapping_add(0x6170_7865);
        x1 = x1.wrapping_add(0x3320_646e);
        x2 = x2.wrapping_add(0x7962_2d32);
        x3 = x3.wrapping_add(0x6b20_6574);
        x4 = x4.wrapping_add(k0);
        x5 = x5.wrapping_add(k1);
        x6 = x6.wrapping_add(k2);
        x7 = x7.wrapping_add(k3);
        x8 = x8.wrapping_add(k4);
        x9 = x9.wrapping_add(k5);
        x10 = x10.wrapping_add(k6);
        x11 = x11.wrapping_add(k7);
        x12 = x12.wrapping_add(self.counter);
        x13 = x13.wrapping_add(n0);
        x14 = x14.wrapping_add(n1);
        x15 = x15.wrapping_add(n2);

        let words = [
            x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15,
        ];
        for (index, word) in words.iter().enumerate() {
            let offset = index.wrapping_mul(4);
            if let Some(chunk) = self.block.get_mut(offset..offset.wrapping_add(4)) {
                chunk.copy_from_slice(&word.to_le_bytes());
            }
        }
        self.counter = self.counter.wrapping_add(1);
        self.block_index = 0;
    }

    /// Fills the destination with keystream bytes.
    #[inline]
    pub fn fill(&mut self, destination: &mut [u8]) {
        let mut written = 0_usize;
        while written < destination.len() {
            if self.block_index >= 64 {
                self.generate_block();
            }
            let available = 64_usize.saturating_sub(self.block_index);
            let wanted = destination.len().saturating_sub(written);
            let amount = min(available, wanted);
            let source = self
                .block
                .get(self.block_index..self.block_index.saturating_add(amount));
            let target = destination.get_mut(written..written.saturating_add(amount));
            if let (Some(source), Some(target)) = (source, target) {
                target.copy_from_slice(source);
            }
            written = written.saturating_add(amount);
            self.block_index = self.block_index.saturating_add(amount);
        }
    }

    /// Applies the keystream to a buffer in place. Encryption and decryption are
    /// the same operation.
    #[inline]
    pub fn apply_keystream(&mut self, buffer: &mut [u8]) {
        let mut offset = 0_usize;
        while offset < buffer.len() {
            if self.block_index >= 64 {
                self.generate_block();
            }
            let available = 64_usize.saturating_sub(self.block_index);
            let wanted = buffer.len().saturating_sub(offset);
            let amount = min(available, wanted);
            let mut inner = 0_usize;
            while inner < amount {
                let source_index = self.block_index.saturating_add(inner);
                let target_index = offset.saturating_add(inner);
                if let (Some(source), Some(target)) =
                    (self.block.get(source_index), buffer.get_mut(target_index))
                {
                    *target ^= *source;
                }
                inner = inner.saturating_add(1);
            }
            offset = offset.saturating_add(amount);
            self.block_index = self.block_index.saturating_add(amount);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ChaCha20;

    #[test]
    fn rfc8439_block_vector() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut stream = ChaCha20::new(key, nonce).with_counter(1);
        let mut block = [0_u8; 64];
        stream.fill(&mut block);
        let expected = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20,
            0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a,
            0xc3, 0xd4, 0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2,
            0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
            0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
        ];
        assert_eq!(block, expected);
    }

    #[test]
    fn keystream_is_self_inverse() {
        let key = [42_u8; 32];
        let nonce = [7_u8; 12];
        let mut first = ChaCha20::new(key, nonce);
        let mut second = ChaCha20::new(key, nonce);
        let mut plaintext = *b"Sirus must survive an adversarial review.";
        let original = plaintext;
        first.apply_keystream(&mut plaintext);
        assert_ne!(plaintext, original);
        second.apply_keystream(&mut plaintext);
        assert_eq!(plaintext, original);
    }

    #[test]
    fn fill_handles_unaligned_boundaries() {
        let mut stream = ChaCha20::new([1_u8; 32], [2_u8; 12]);
        let mut first = [0_u8; 7];
        let mut second = [0_u8; 70];
        stream.fill(&mut first);
        stream.fill(&mut second);
        let mut reference = ChaCha20::new([1_u8; 32], [2_u8; 12]);
        let mut combined = [0_u8; 77];
        reference.fill(&mut combined);
        assert_eq!(first.as_slice(), combined.get(..7).unwrap_or(&[]));
        assert_eq!(second.as_slice(), combined.get(7..).unwrap_or(&[]));
    }
}
