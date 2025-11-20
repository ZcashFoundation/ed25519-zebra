//! Implementation of the TCHES 2025 paper
//!
//! This module implements Algorithm 4 (hEEA_approx_q) from the paper, which generates
//! half-size scalars for faster EdDSA verification.
//!
//! For verification sB = R + hA, we find rho, tau such that rho = tau*h (mod ell)

use curve25519_dalek::scalar::Scalar;

use crate::u256::{L, U256};

/// Implement curve25519_hEEA_vartime algorithm
/// Returns (rho, tau) such that rho ≡ tau * v (mod L)
pub(crate) fn curve25519_heea_vartime(v: &U256) -> (U256, [u64; 2]) {
    let mut r0 = U256(L);
    let mut r1 = *v;
    let mut t0 = [0u64; 2];
    let mut t1 = [1u64, 0u64];

    let mut bl_r0 = 253u32; // bit_length(L) = 253
    let mut bl_r1 = r1.bit_length();

    // Main loop - continue until r1 is approximately half-size (~127 bits)
    loop {
        // Stop when r1 is small enough (half-size)
        if bl_r1 <= 127 {
            return (r1, t1);
        }

        // Compute shift amount
        let s = bl_r0 - bl_r1;

        // Perform the shift-and-add/sub operation
        let mut r = r0;
        let mut t = t0;

        // Check if signs are the same (MSB of highest limb)
        let sign_r0 = (r0.0[3] >> 63) != 0;
        let sign_r1 = (r1.0[3] >> 63) != 0;

        if sign_r0 == sign_r1 {
            // Same sign: subtract
            r.sub_lshift_4(&r1, s);
            // sub_lshift_4(&mut r, &r1, s);
            // For t (only 2 limbs)
            let t_shifted = if s == 0 {
                t1
            } else if s < 64 {
                [t1[0] << s, (t1[1] << s) | (t1[0] >> (64 - s))]
            } else if s < 128 {
                [0, t1[0] << (s - 64)]
            } else {
                [0, 0]
            };
            let (d0, b1) = t[0].overflowing_sub(t_shifted[0]);
            let (d1, _b2) = t[1].overflowing_sub(t_shifted[1]);
            let (d1, _b3) = d1.overflowing_sub(if b1 { 1 } else { 0 });
            t = [d0, d1];
        } else {
            // Different sign: add
            r.add_lshift_4(&r1, s);
            // For t (only 2 limbs)
            let t_shifted = if s == 0 {
                t1
            } else if s < 64 {
                [t1[0] << s, (t1[1] << s) | (t1[0] >> (64 - s))]
            } else if s < 128 {
                [0, t1[0] << (s - 64)]
            } else {
                [0, 0]
            };
            let (sum0, c1) = t[0].overflowing_add(t_shifted[0]);
            let (sum1, _c2) = t[1].overflowing_add(t_shifted[1]);
            let (sum1, _c3) = sum1.overflowing_add(if c1 { 1 } else { 0 });
            t = [sum0, sum1];
        }

        let bl_r = r.bit_length();

        if bl_r > bl_r1 {
            // r grew, so keep it in r0
            r0 = r;
            t0 = t;
            bl_r0 = bl_r;
        } else {
            // r shrunk, swap
            r0 = r1;
            r1 = r;
            t0 = t1;
            t1 = t;
            bl_r0 = bl_r1;
            bl_r1 = bl_r;
        }
    }
}

/// Convert 2 limbs to Scalar (for tau)
fn limbs2_to_scalar(limbs: &[u64; 2]) -> Scalar {
    let mut bytes = [0u8; 32];

    let is_negative = (limbs[1] >> 63) != 0;

    if is_negative {
        let mut negated = [!limbs[0], !limbs[1]];
        let mut carry = true;
        for i in 0..2 {
            let (sum, c) = negated[i].overflowing_add(if carry { 1 } else { 0 });
            negated[i] = sum;
            carry = c;
        }

        for (i, &limb) in negated.iter().enumerate() {
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
        }
        let positive = Scalar::from_bytes_mod_order(bytes);

        let ell = Scalar::from_bytes_mod_order([
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ]);
        ell - positive
    } else {
        for (i, &limb) in limbs.iter().enumerate() {
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
        }
        Scalar::from_bytes_mod_order(bytes)
    }
}

/// Generate half-size scalars (rho, tau) for a given hash value h
///
/// This function takes the hash value h from the signature verification equation
/// and produces two half-size scalars rho and tau such that rho = tau*h (mod ell).
///
/// And a flag indicating if rho is negative in its signed representation.
pub fn generate_half_size_scalars(h: &Scalar) -> (Scalar, Scalar, bool) {
    // Convert h to limbs
    let v_limbs = h.into();

    // Run the algorithm
    let (rho_limbs, tau_limbs) = curve25519_heea_vartime(&v_limbs);

    // Convert back to Scalars
    let rho = rho_limbs.into();
    let tau = limbs2_to_scalar(&tau_limbs);

    (rho, tau, rho_limbs.0[3] != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::digest::Update;
    use rand::RngCore;

    #[test]
    fn test_generate_half_size_scalars() {
        use rand::thread_rng;
        use sha2::{Digest, Sha512};

        let mut rng = thread_rng();

        // Test with multiple random scalars
        for _ in 0..1000 {
            // Generate a random scalar by hashing random bytes
            let mut random_bytes = [0u8; 64];
            for byte in &mut random_bytes {
                *byte = (rng.next_u32() & 0xff) as u8;
            }
            let h = Scalar::from_hash(Sha512::new().chain(&random_bytes));

            // Convert h to limbs to see the actual output
            let h_limbs = h.into();
            let (rho_limbs, tau_limbs) = curve25519_heea_vartime(&h_limbs);

            // Check the magnitude of rho and tau in their signed representation
            let rho_magnitude_bits = rho_limbs.bit_length();

            // For tau (2 limbs), compute bit length manually
            let tau_is_negative = (tau_limbs[1] >> 63) != 0;
            let tau_magnitude_bits = if tau_is_negative {
                // For negative, compute bit length of absolute value
                let mut negated = [!tau_limbs[0], !tau_limbs[1]];
                let mut carry = true;
                for i in 0..2 {
                    let (sum, c) = negated[i].overflowing_add(if carry { 1 } else { 0 });
                    negated[i] = sum;
                    carry = c;
                }
                // Compute bit length of negated value
                if negated[1] != 0 {
                    128 - negated[1].leading_zeros()
                } else if negated[0] != 0 {
                    64 - negated[0].leading_zeros()
                } else {
                    1
                }
            } else {
                if tau_limbs[1] != 0 {
                    128 - tau_limbs[1].leading_zeros()
                } else if tau_limbs[0] != 0 {
                    64 - tau_limbs[0].leading_zeros()
                } else {
                    1
                }
            };

            // Now convert to Scalars and verify the equation
            let (rho, tau, _) = generate_half_size_scalars(&h);

            // Verify that rho = tau * h (mod ell)
            let computed_rho = tau * h;
            assert_eq!(rho, computed_rho, "rho should equal tau * h");

            // Check that they are non-zero
            assert_ne!(rho, Scalar::ZERO, "rho should be non-zero");
            assert_ne!(tau, Scalar::ZERO, "tau should be non-zero");

            // Both magnitudes should be approximately half-size (~127 bits)
            assert!(
                rho_magnitude_bits <= 128,
                "rho magnitude should be approximately half-size, got {} bits",
                rho_magnitude_bits
            );
            assert!(
                tau_magnitude_bits <= 128,
                "tau magnitude should be approximately half-size, got {} bits",
                tau_magnitude_bits
            );
        }
    }
}
