//! Performs batch Ed25519 signature verification.
//!
//! Batch verification asks whether *all* signatures in some set are valid,
//! rather than asking whether *each* of them is valid. This allows sharing
//! computations among all signature verifications, performing less work overall
//! at the cost of higher latency (the entire batch must complete), complexity of
//! caller code (which must assemble a batch of signatures across work-items),
//! and loss of the ability to easily pinpoint failing signatures.
//!
//! In addition to these general tradeoffs, design flaws in Ed25519 specifically
//! mean that batched verification may not agree with individual verification.
//! Some signatures may verify as part of a batch but not on their own.
//! This problem is fixed by [ZIP215], a precise specification for edge cases
//! in Ed25519 signature validation that ensures that batch verification agrees
//! with individual verification in all cases.
//!
//! This crate implements ZIP215, so batch verification always agrees with
//! individual verification, but this is not guaranteed by other implementations.
//! **Be extremely careful when using Ed25519 in a consensus-critical context
//! like a blockchain.**
//!
//! This batch verification implementation is adaptive in the sense that it
//! detects multiple signatures created with the same verification key and
//! automatically coalesces terms in the final verification equation. In the
//! limiting case where all signatures in the batch are made with the same
//! verification key, coalesced batch verification runs twice as fast as ordinary
//! batch verification.
//!
//! ![benchmark](https://www.zfnd.org/images/coalesced-batch-graph.png)
//!
//! This optimization doesn't help much with Zcash, where public keys are random,
//! but could be useful in proof-of-stake systems where signatures come from a
//! set of validators (provided that system uses the ZIP215 rules).
//!
//! # Example
//! ```
//! # use ed25519_zebra::*;
//! let mut batch = batch::Verifier::new();
//! for _ in 0..32 {
//!     let sk = SigningKey::new(rand::thread_rng());
//!     let vk_bytes = VerificationKeyBytes::from(&sk);
//!     let msg = b"BatchVerifyTest";
//!     let sig = sk.sign(&msg[..]);
//!     batch.queue((vk_bytes, sig, &msg[..]));
//! }
//! assert!(batch.verify(rand::thread_rng()).is_ok());
//! ```
//!
//! [ZIP215]: https://zips.z.cash/zip-0215

use alloc::vec::Vec;
use core::convert::TryFrom;

use curve25519_dalek::{
    digest::Update,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::{IsIdentity, VartimeMultiscalarMul},
};
use hashbrown::HashMap;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha512;

use crate::{Error, VerificationKey, VerificationKeyBytes};
use ed25519::Signature;

// Shim to generate a u128 without importing `rand`.
fn gen_u128<R: RngCore + CryptoRng>(mut rng: R) -> u128 {
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes[..]);
    u128::from_le_bytes(bytes)
}

/// A batch verification item.
///
/// This struct exists to allow batch processing to be decoupled from the
/// lifetime of the message. This is useful when using the batch verification API
/// in an async context.
#[derive(Clone, Debug)]
pub struct Item {
    vk_bytes: VerificationKeyBytes,
    sig: Signature,
    k: Scalar,
}

impl<'msg, M: AsRef<[u8]> + ?Sized> From<(VerificationKeyBytes, Signature, &'msg M)> for Item {
    fn from(tup: (VerificationKeyBytes, Signature, &'msg M)) -> Self {
        let (vk_bytes, sig, msg) = tup;
        // Compute k now to avoid dependency on the msg lifetime.
        let k = Scalar::from_hash(
            Sha512::default()
                .chain(&sig.r_bytes()[..])
                .chain(&vk_bytes.0[..])
                .chain(msg),
        );
        Self { vk_bytes, sig, k }
    }
}

impl Item {
    /// Perform non-batched verification of this `Item`.
    ///
    /// This is useful (in combination with `Item::clone`) for implementing fallback
    /// logic when batch verification fails. In contrast to
    /// [`VerificationKey::verify`](crate::VerificationKey::verify), which requires
    /// borrowing the message data, the `Item` type is unlinked from the lifetime of
    /// the message.
    pub fn verify_single(self) -> Result<(), Error> {
        VerificationKey::try_from(self.vk_bytes)
            .and_then(|vk| vk.verify_prehashed(&self.sig, self.k))
    }
}

/// A batch verification context.
#[derive(Default)]
pub struct Verifier {
    /// Signature data queued for verification.
    signatures: HashMap<VerificationKeyBytes, Vec<(Scalar, Signature)>>,
    /// Caching this count avoids a hash traversal to figure out
    /// how much to preallocate.
    batch_size: usize,
}

impl Verifier {
    /// Construct a new batch verifier.
    pub fn new() -> Verifier {
        Verifier::default()
    }

    /// Queue a (key, signature, message) tuple for verification.
    pub fn queue<I: Into<Item>>(&mut self, item: I) {
        let Item { vk_bytes, sig, k } = item.into();

        self.signatures
            .entry(vk_bytes)
            // The common case is 1 signature per public key.
            // We could also consider using a smallvec here.
            .or_insert_with(|| Vec::with_capacity(1))
            .push((k, sig));
        self.batch_size += 1;
    }

    /// Perform batch verification using the new hEEA-based randomization method
    /// from "Accelerating EdDSA Signature Verification with Faster Scalar Size Halving" (TCHES 2025).
    ///
    /// This method uses half-size scalars for improved performance with larger batch sizes.
    ///
    /// Note: According to the paper (Section 4.2), for a single signer (same public key for all
    /// signatures), the computational cost without optimization is the same as the classical method.
    /// The optimization would be to skip hEEA calls and use equation (1) directly. For now, we use
    /// the general approach which works correctly for both cases.
    #[allow(non_snake_case)]
    pub fn verify_heea<R: RngCore + CryptoRng>(self, mut rng: R) -> Result<(), Error> {
        // Step 1: Pick random U < ℓ and compute U' such that UU' ≡ 1 mod ℓ
        let mut U_bytes = [0u8; 32];
        rng.fill_bytes(&mut U_bytes);
        let U = Scalar::from_bytes_mod_order(U_bytes);

        // Compute U_inv = U^-1 mod ℓ
        let U_inv = U.invert();

        // Prepare accumulators
        let mut sum_tau_s = Scalar::ZERO;
        let mut R_coeffs = Vec::with_capacity(self.batch_size);
        let mut Rs = Vec::with_capacity(self.batch_size);

        // For A coefficients, we coalesce by (pubkey, sign) to reduce MSM size
        // Map from (vk_bytes, sign) to accumulated ρ coefficient
        use hashbrown::HashMap;
        let mut A_coeff_map: HashMap<(VerificationKeyBytes, bool), Scalar> = HashMap::new();
        let mut max_duplicity = 0usize;

        // Step 2-3: For each signature, compute half-size scalars and accumulate
        for (vk_bytes, sigs) in self.signatures.iter() {
            // Track duplicity for this public key
            let duplicity = sigs.len();
            if duplicity > max_duplicity {
                max_duplicity = duplicity;
            }

            for (k, sig) in sigs.iter() {
                // v_i = h_i * U' mod ℓ
                let v = k * U_inv;

                // Generate half-size scalars: ρ_i ≡ τ_i * v_i mod ℓ
                // This means: ρ_i ≡ τ_i * h_i * U' mod ℓ
                // Or equivalently: τ_i * h_i ≡ U * ρ_i mod ℓ
                let (rho_i, tau_i, flip_h) = crate::heea::generate_half_size_scalars(&v);

                // Extract s and R from signature
                let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(*sig.s_bytes()))
                    .ok_or(Error::InvalidSignature)?;
                let R = CompressedEdwardsY(*sig.r_bytes())
                    .decompress()
                    .ok_or(Error::InvalidSignature)?;

                // Accumulate τ_i * s_i
                sum_tau_s += tau_i * s;

                // Store τ_i and R_i for Σ(τ_i * R_i)
                R_coeffs.push(tau_i);
                Rs.push(R);

                // Coalesce ρ_i by (pubkey, sign)
                // A and -A are treated as different bases
                let key = (*vk_bytes, flip_h);
                *A_coeff_map.entry(key).or_insert(Scalar::ZERO) += rho_i;
            }
        }

        // Convert the coalesced map into vectors for MSM
        let mut A_coeffs = Vec::with_capacity(A_coeff_map.len());
        let mut As = Vec::with_capacity(A_coeff_map.len());

        for ((vk_bytes, flip_h), rho_sum) in A_coeff_map.iter() {
            let A = CompressedEdwardsY(vk_bytes.0)
                .decompress()
                .ok_or(Error::InvalidSignature)?;
            let A_base = if *flip_h { -A } else { A };
            A_coeffs.push(*rho_sum);
            As.push(A_base);
        }

        // Step 4: Compute R_sum = Σ(τ_i * R_i) and A_sum = Σ(ρ_i * A_i)
        // For A_sum, the coalesced scalars can be up to 128 + log2(max_duplicity) bits
        use curve25519_dalek::traits::VartimeMultiscalarMul;
        let R_sum = EdwardsPoint::vartime_multiscalar_mul(R_coeffs.iter(), Rs.iter(), Some(128));

        // Calculate scalar_bits for A_sum based on max_duplicity
        // Each ρ_i is ~128 bits, and we sum up to max_duplicity of them
        // So the result can be up to 128 + log2(max_duplicity) bits
        let extra_bits = if max_duplicity > 1 {
            (max_duplicity as f64).log2().ceil() as u32
        } else {
            0
        };
        let a_scalar_bits = 128 + extra_bits;

        let A_sum = EdwardsPoint::vartime_multiscalar_mul(
            A_coeffs.iter(),
            As.iter(),
            Some(a_scalar_bits as usize),
        );

        // Step 5: Call hEEA_approx_q with U to get final ρ and τ
        // such that ρ ≡ τ * U mod ℓ
        let (rho_final, tau_final, flip_final) = crate::heea::generate_half_size_scalars(&U);

        // Step 6: Final verification equation
        // From step 4: sum_tau_s * B = R_sum + U * A_sum
        // Multiply by τ_final: τ_final * sum_tau_s * B = τ_final * R_sum + τ_final * U * A_sum
        // Since ρ_final ≡ τ_final * U mod ℓ:
        //   τ_final * sum_tau_s * B = τ_final * R_sum + ρ_final * A_sum
        //
        // Rearranging: τ_final * R_sum + ρ_final * A_sum - τ_final * sum_tau_s * B = 0
        //
        // We verify: [8] * (τ_final * R_sum + ρ_final * A_sum - τ_final * sum_tau_s * B) = 0

        let ts_final = tau_final * sum_tau_s;
        let A_final = if flip_final { -A_sum } else { A_sum };

        // vartime_triple_scalar_mul_basepoint computes: a*A + b*B + c*BASEPOINT
        // We want: tau_final * R_sum + rho_final * A_final - ts_final * BASEPOINT = 0
        let result = EdwardsPoint::vartime_triple_scalar_mul_basepoint(
            &rho_final,
            &A_final,
            &tau_final,
            &R_sum,
            &(-ts_final),
        );

        if result.mul_by_cofactor().is_identity() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    /// Perform batch verification, returning `Ok(())` if all signatures were
    /// valid and `Err` otherwise.
    #[allow(non_snake_case)]
    pub fn verify<R: RngCore + CryptoRng>(self, mut rng: R) -> Result<(), Error> {
        // The batch verification equation is
        //
        // 8*[-sum(z_i * s_i)]B + 8*sum([z_i]R_i) + 8*sum([z_i * k_i]A_i) = 0.
        //
        // where for each signature i,
        // - A_i is the verification key;
        // - R_i is the signature's R value;
        // - s_i is the signature's s value;
        // - k_i is the hash of the message and other data;
        // - z_i is a random 128-bit Scalar.
        //
        // Normally n signatures would require a multiscalar multiplication of
        // size 2*n + 1, together with 2*n point decompressions (to obtain A_i
        // and R_i). However, because we store batch entries in a HashMap
        // indexed by the verification key, we can "coalesce" all z_i * k_i
        // terms for each distinct verification key into a single coefficient.
        //
        // For n signatures from m verification keys, this approach instead
        // requires a multiscalar multiplication of size n + m + 1 together with
        // n + m point decompressions. When m = n, so all signatures are from
        // distinct verification keys, this is as efficient as the usual method.
        // However, when m = 1 and all signatures are from a single verification
        // key, this is nearly twice as fast.

        let m = self.signatures.keys().count();

        let mut A_coeffs = Vec::with_capacity(m);
        let mut As = Vec::with_capacity(m);
        let mut R_coeffs = Vec::with_capacity(self.batch_size);
        let mut Rs = Vec::with_capacity(self.batch_size);
        let mut B_coeff = Scalar::ZERO;

        for (vk_bytes, sigs) in self.signatures.iter() {
            let A = CompressedEdwardsY(vk_bytes.0)
                .decompress()
                .ok_or(Error::InvalidSignature)?;

            let mut A_coeff = Scalar::ZERO;

            for (k, sig) in sigs.iter() {
                let R = CompressedEdwardsY(*sig.r_bytes())
                    .decompress()
                    .ok_or(Error::InvalidSignature)?;
                let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(*sig.s_bytes()))
                    .ok_or(Error::InvalidSignature)?;
                let z = Scalar::from(gen_u128(&mut rng));
                B_coeff -= z * s;
                Rs.push(R);
                R_coeffs.push(z);
                A_coeff += z * k;
            }

            As.push(A);
            A_coeffs.push(A_coeff);
        }

        use core::iter::once;
        use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as B;
        let check = EdwardsPoint::vartime_multiscalar_mul(
            once(&B_coeff).chain(A_coeffs.iter()).chain(R_coeffs.iter()),
            once(&B).chain(As.iter()).chain(Rs.iter()),
            None,
        );

        if check.mul_by_cofactor().is_identity() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}
