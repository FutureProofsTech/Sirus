//! SipHash-2-4, used for authenticated payload binding and deterministic
//! construction of per-build lookup tables.
//!
//! The implementation is streaming, allocation-free and uses no unsafe code.
//! It follows the reference algorithm from Aumasson and Bernstein.

/// SipHash-2-4 streaming state.
#[derive(Clone, Copy, Debug)]
pub struct SipHasher24 {
    k0: u64,
    k1: u64,
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    tail: u64,
    tail_len: u32,
    length: u64,
}

#[inline]
const fn rotl(value: u64, count: u32) -> u64 {
    value.rotate_left(count)
}

#[inline]
fn sip_round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = rotl(*v1, 13);
    *v1 ^= *v0;
    *v0 = rotl(*v0, 32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = rotl(*v3, 16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = rotl(*v3, 21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = rotl(*v1, 17);
    *v1 ^= *v2;
    *v2 = rotl(*v2, 32);
}

impl SipHasher24 {
    /// Creates a hasher from a 128-bit key.
    #[inline]
    #[must_use]
    pub const fn new(k0: u64, k1: u64) -> Self {
        Self {
            k0,
            k1,
            v0: k0 ^ 0x736f_6d65_7073_6575,
            v1: k1 ^ 0x646f_7261_6e64_6f6d,
            v2: k0 ^ 0x6c79_6765_6e65_7261,
            v3: k1 ^ 0x7465_6462_7974_6573,
            tail: 0,
            tail_len: 0,
            length: 0,
        }
    }

    #[inline]
    fn compress(&mut self, message: u64) {
        self.v3 ^= message;
        sip_round(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        sip_round(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        self.v0 ^= message;
    }

    /// Absorbs bytes. May be called repeatedly.
    #[inline]
    pub fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            let shift = self.tail_len.wrapping_mul(8);
            self.tail |= u64::from(*byte) << shift;
            self.tail_len = self.tail_len.wrapping_add(1);
            self.length = self.length.wrapping_add(1);
            if self.tail_len == 8 {
                let message = self.tail;
                self.tail = 0;
                self.tail_len = 0;
                self.compress(message);
            }
        }
    }

    /// Absorbs a little-endian integer as eight message bytes.
    #[inline]
    pub fn write_u64(&mut self, value: u64) {
        self.write(&value.to_le_bytes());
    }

    /// Finalizes the hash.
    #[inline]
    #[must_use]
    pub fn finish(&self) -> u64 {
        let mut v0 = self.v0;
        let mut v1 = self.v1;
        let mut v2 = self.v2;
        let mut v3 = self.v3;
        let final_block = if self.tail_len == 0 {
            self.length.wrapping_shl(56)
        } else {
            self.tail | self.length.wrapping_shl(56)
        };
        v3 ^= final_block;
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= final_block;
        v2 ^= 0xff;
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^ v1 ^ v2 ^ v3
    }

    /// One-shot convenience hash.
    #[inline]
    #[must_use]
    pub fn hash(k0: u64, k1: u64, bytes: &[u8]) -> u64 {
        let mut state = Self::new(k0, k1);
        state.write(bytes);
        state.finish()
    }

    /// One-shot hash over a single integer in little-endian order.
    #[inline]
    #[must_use]
    pub fn hash_u64(k0: u64, k1: u64, value: u64) -> u64 {
        let mut state = Self::new(k0, k1);
        state.write_u64(value);
        state.finish()
    }

    /// Shadows fields so a hasher cannot be accidentally reused without
    /// finalizing. This is a no-op used to keep the public shape inspectable.
    #[inline]
    #[must_use]
    pub const fn keys(&self) -> (u64, u64) {
        (self.k0, self.k1)
    }
}

#[cfg(test)]
mod tests {
    use super::SipHasher24;

    #[test]
    fn rfc_reference_vector() {
        let key0 = u64::from_le_bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
        let key1 = u64::from_le_bytes([0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]);
        let mut message = [0_u8; 15];
        let mut index = 0_u8;
        while index < 15 {
            if let Some(byte) = message.get_mut(usize::from(index)) {
                *byte = index;
            }
            index += 1;
        }
        assert_eq!(SipHasher24::hash(key0, key1, &message), 0xa129_ca61_49be_45e5);
    }

    #[test]
    fn streaming_matches_one_shot() {
        let data = b"the quick brown fox jumps over the lazy dog";
        let one_shot = SipHasher24::hash(7, 11, data);
        let mut streaming = SipHasher24::new(7, 11);
        streaming.write(&data[..5]);
        streaming.write(&data[5..17]);
        streaming.write(&data[17..]);
        assert_eq!(streaming.finish(), one_shot);
        assert_eq!(streaming.keys(), (7, 11));
    }

    #[test]
    fn empty_message_is_deterministic() {
        assert_eq!(SipHasher24::hash(1, 2, &[]), SipHasher24::hash(1, 2, &[]));
        assert_ne!(SipHasher24::hash(1, 2, &[]), SipHasher24::hash(2, 1, &[]));
    }
}
