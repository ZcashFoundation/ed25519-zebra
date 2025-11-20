//! Simple 256 bits unsigned integer operations.
//! We use this instead of crates such as `bigint` for best performance.

use curve25519_dalek::Scalar;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct U256(pub(crate) [u64; 4]);

impl From<Scalar> for U256 {
    fn from(s: Scalar) -> Self {
        U256(scalar_to_limbs(&s))
    }
}

impl From<&Scalar> for U256 {
    fn from(s: &Scalar) -> Self {
        U256(scalar_to_limbs(s))
    }
}

impl From<U256> for Scalar {
    fn from(u: U256) -> Self {
        limbs_to_scalar(&u.0)
    }
}

/// Ed25519 group order L = 2^252 + 27742317777372353535851937790883648493
/// Represented as 4 limbs of u64 (little-endian)
pub(crate) const L: [u64; 4] = [
    0x5812631a5cf5d3ed,
    0x14def9dea2f79cd6,
    0x0000000000000000,
    0x1000000000000000,
];

/// Convert limbs back to Scalar (handling sign for two's complement)
fn limbs_to_scalar(limbs: &[u64; 4]) -> Scalar {
    let mut bytes = [0u8; 32];

    // Check if negative (MSB set)
    let is_negative = (limbs[3] >> 63) != 0;

    if is_negative {
        // For negative numbers, we need to negate and then compute L - value
        // Two's complement: flip bits and add 1
        let mut negated = [!limbs[0], !limbs[1], !limbs[2], !limbs[3]];
        // Add 1
        let mut carry = true;
        for i in 0..4 {
            let (sum, c) = negated[i].overflowing_add(if carry { 1 } else { 0 });
            negated[i] = sum;
            carry = c;
        }

        // Convert to bytes
        for (i, &limb) in negated.iter().enumerate() {
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
        }
        let positive = Scalar::from_bytes_mod_order(bytes);

        -positive
        // // Return L - positive (modular negation)
        // let ell = Scalar::from_bytes_mod_order([
        //     0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
        //     0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        //     0x00, 0x00, 0x00, 0x10,
        // ]);
        // ell - positive
    } else {
        // Positive number, just convert directly
        for (i, &limb) in limbs.iter().enumerate() {
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
        }
        Scalar::from_bytes_mod_order(bytes)
    }
}

/// Convert a Scalar to 4 limbs of u64 (little-endian)
#[inline]
fn scalar_to_limbs(s: &Scalar) -> [u64; 4] {
    let bytes = s.as_bytes();
    [
        u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]),
        u64::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]),
        u64::from_le_bytes([
            bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ]),
        u64::from_le_bytes([
            bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
        ]),
    ]
}

impl U256 {
    /// Compute bit length.
    /// Takes into account the sign bit
    pub(crate) fn bit_length(&self) -> u32 {
        // Check sign (MSB of highest limb)
        let is_negative = (self.0[3] >> 63) != 0;

        // Find the highest non-zero limb
        for i in (0..4).rev() {
            let word = if is_negative {
                self.0[i] ^ 0xFFFFFFFFFFFFFFFF // Flip bits if negative
            } else {
                self.0[i]
            };

            if word != 0 {
                // Found non-zero limb, compute bit length
                return (i as u32 + 1) * 64 - word.leading_zeros();
            }
        }

        1 // All zero
    }

    /// Add with left shift: a += b << s (with carry)
    pub(crate) fn add_lshift_4(&mut self, b: &Self, s: u32) {
        if s >= 256 {
            return; // Shift is too large, result is zero
        }

        let limb_shift = (s / 64) as usize;
        let bit_shift = s % 64;

        if bit_shift == 0 {
            // Simple case: whole limb shifts
            let mut carry = false;
            for i in 0..4 {
                if i < limb_shift {
                    continue;
                }
                let src_idx = i - limb_shift;
                if src_idx >= 4 {
                    break;
                }
                let (sum, c1) = self.0[i].overflowing_add(b.0[src_idx]);
                let (sum, c2) = sum.overflowing_add(if carry { 1 } else { 0 });
                self.0[i] = sum;
                carry = c1 || c2;
            }
        } else {
            // Bit-level shift
            let mut carry = false;
            let mut prev = 0u64;

            for i in 0..4 {
                let src_idx = (i as usize).wrapping_sub(limb_shift);
                let shifted_val = if src_idx < 4 {
                    (b.0[src_idx] << bit_shift) | prev
                } else {
                    prev
                };

                let (sum, c1) = self.0[i].overflowing_add(shifted_val);
                let (sum, c2) = sum.overflowing_add(if carry { 1 } else { 0 });
                self.0[i] = sum;
                carry = c1 || c2;

                if src_idx < 4 {
                    prev = b.0[src_idx] >> (64 - bit_shift);
                } else {
                    prev = 0;
                }
            }
        }
    }

    /// Subtract with left shift: a -= b << s (with borrow)
    pub(crate) fn sub_lshift_4(&mut self, b: &Self, s: u32) {
        if s >= 256 {
            return;
        }

        let limb_shift = (s / 64) as usize;
        let bit_shift = s % 64;

        if bit_shift == 0 {
            let mut borrow = false;
            for i in 0..4 {
                if i < limb_shift {
                    continue;
                }
                let src_idx = i - limb_shift;
                if src_idx >= 4 {
                    break;
                }
                let (diff, b1) = self.0[i].overflowing_sub(b.0[src_idx]);
                let (diff, b2) = diff.overflowing_sub(if borrow { 1 } else { 0 });
                self.0[i] = diff;
                borrow = b1 || b2;
            }
        } else {
            let mut borrow = false;
            let mut prev = 0u64;

            for i in 0..4 {
                let src_idx = (i as usize).wrapping_sub(limb_shift);
                let shifted_val = if src_idx < 4 {
                    (b.0[src_idx] << bit_shift) | prev
                } else {
                    prev
                };

                let (diff, b1) = self.0[i].overflowing_sub(shifted_val);
                let (diff, b2) = diff.overflowing_sub(if borrow { 1 } else { 0 });
                self.0[i] = diff;
                borrow = b1 || b2;

                if src_idx < 4 {
                    prev = b.0[src_idx] >> (64 - bit_shift);
                } else {
                    prev = 0;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_bit_length_4() {
        // Test positive numbers
        assert_eq!(U256([1, 0, 0, 0]).bit_length(), 1);
        assert_eq!(U256([0xff, 0, 0, 0]).bit_length(), 8);
        assert_eq!(U256([0, 1, 0, 0]).bit_length(), 65);
        assert_eq!(U256([0, 0, 1, 0]).bit_length(), 129);

        // Test L
        assert_eq!(U256(L).bit_length(), 253);
    }

    #[test]
    fn test_scalar_conversion() {
        let original = Scalar::from(42u64);
        let limbs: U256 = original.into();
        let recovered = limbs.into();
        assert_eq!(original, recovered);
    }
}
