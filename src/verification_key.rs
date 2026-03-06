use core::convert::{TryFrom, TryInto};
use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::{HEEADecomposition, IsIdentity},
};
use sha2::{digest::Update, Sha512};
use zeroize::DefaultIsZeroes;

use ed25519::{signature::Verifier, Signature};

#[cfg(feature = "pkcs8")]
use pkcs8::der::asn1::BitStringRef;
#[cfg(feature = "pkcs8")]
use pkcs8::spki::{
    AlgorithmIdentifierRef, DecodePublicKey, EncodePublicKey, SubjectPublicKeyInfoRef,
};
#[cfg(feature = "pkcs8")]
use pkcs8::{Document, ObjectIdentifier};

use crate::Error;

/// The length of an ed25519 `VerificationKey`, in bytes.
pub const VERIFICATION_KEY_LENGTH: usize = 32;

/// A refinement type for `[u8; 32]` indicating that the bytes represent an
/// encoding of an Ed25519 verification key.
///
/// This is useful for representing an encoded verification key, while the
/// [`VerificationKey`] type in this library caches other decoded state used in
/// signature verification.
///
/// A `VerificationKeyBytes` can be used to verify a single signature using the
/// following idiom:
/// ```
/// use core::convert::TryFrom;
/// # use rand::thread_rng;
/// # use ed25519_zebra::*;
/// # let msg = b"Zcash";
/// # let sk = SigningKey::new(thread_rng());
/// # let sig = sk.sign(msg);
/// # let vk_bytes = VerificationKeyBytes::from(&sk);
/// VerificationKey::try_from(vk_bytes)
///     .and_then(|vk| vk.verify(&sig, msg));
/// ```
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VerificationKeyBytes(pub(crate) [u8; VERIFICATION_KEY_LENGTH]);

impl core::fmt::Debug for VerificationKeyBytes {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        fmt.debug_tuple("VerificationKeyBytes")
            .field(&self.0)
            .finish()
    }
}

impl AsRef<[u8]> for VerificationKeyBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl TryFrom<&[u8]> for VerificationKeyBytes {
    type Error = Error;
    fn try_from(slice: &[u8]) -> Result<VerificationKeyBytes, Self::Error> {
        if slice.len() == 32 {
            let mut bytes = [0u8; 32];
            bytes[..].copy_from_slice(slice);
            Ok(bytes.into())
        } else {
            Err(Error::InvalidSliceLength)
        }
    }
}

impl From<[u8; 32]> for VerificationKeyBytes {
    fn from(bytes: [u8; 32]) -> VerificationKeyBytes {
        VerificationKeyBytes(bytes)
    }
}

impl From<VerificationKeyBytes> for [u8; 32] {
    fn from(refined: VerificationKeyBytes) -> [u8; 32] {
        refined.0
    }
}

#[cfg(feature = "pkcs8")]
impl<'a> TryFrom<SubjectPublicKeyInfoRef<'a>> for VerificationKeyBytes {
    type Error = Error;

    fn try_from(spki: SubjectPublicKeyInfoRef) -> Result<VerificationKeyBytes, Error> {
        Ok(VerificationKeyBytes::try_from(spki.subject_public_key.as_bytes().unwrap()).unwrap())
    }
}

/// A valid Ed25519 verification key.
///
/// This is also called a public key by other implementations.
///
/// This type holds decompressed state used in signature verification; if the
/// verification key may not be used immediately, it is probably better to use
/// [`VerificationKeyBytes`], which is a refinement type for `[u8; 32]`.
///
/// ## Zcash-specific consensus properties
///
/// Ed25519 checks are described in [§5.4.5][ps] of the Zcash protocol specification and in
/// [ZIP 215].  The verification criteria for an (encoded) verification key `A_bytes` are:
///
/// * `A_bytes` MUST be an encoding of a point `A` on the twisted Edwards form of
///   Curve25519, and non-canonical encodings MUST be accepted;
///
/// [ps]: https://zips.z.cash/protocol/protocol.pdf#concreteed25519
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "VerificationKeyBytes"))]
#[cfg_attr(feature = "serde", serde(into = "VerificationKeyBytes"))]
#[allow(non_snake_case)]
pub struct VerificationKey {
    pub(crate) A_bytes: VerificationKeyBytes,
    pub(crate) minus_A: EdwardsPoint,
}

impl From<VerificationKey> for VerificationKeyBytes {
    fn from(vk: VerificationKey) -> VerificationKeyBytes {
        vk.A_bytes
    }
}

impl AsRef<[u8]> for VerificationKey {
    fn as_ref(&self) -> &[u8] {
        &self.A_bytes.0[..]
    }
}

impl Default for VerificationKey {
    fn default() -> VerificationKey {
        let identity: EdwardsPoint = Default::default();
        let identity_bytes = identity.compress().to_bytes();

        VerificationKey {
            A_bytes: VerificationKeyBytes::from(identity_bytes),
            minus_A: -identity,
        }
    }
}

impl DefaultIsZeroes for VerificationKey {}

impl From<VerificationKey> for [u8; 32] {
    fn from(vk: VerificationKey) -> [u8; 32] {
        vk.A_bytes.0
    }
}

impl TryFrom<VerificationKeyBytes> for VerificationKey {
    type Error = Error;
    #[allow(non_snake_case)]
    fn try_from(bytes: VerificationKeyBytes) -> Result<Self, Self::Error> {
        // * `A_bytes` and `R_bytes` MUST be encodings of points `A` and `R` respectively on the
        //   twisted Edwards form of Curve25519, and non-canonical encodings MUST be accepted;
        let A = CompressedEdwardsY(bytes.0)
            .decompress()
            .ok_or(Error::MalformedPublicKey)?;

        Ok(VerificationKey {
            A_bytes: bytes,
            minus_A: -A,
        })
    }
}

impl TryFrom<&[u8]> for VerificationKey {
    type Error = Error;
    fn try_from(slice: &[u8]) -> Result<VerificationKey, Error> {
        VerificationKeyBytes::try_from(slice).and_then(|vkb| vkb.try_into())
    }
}

impl TryFrom<[u8; 32]> for VerificationKey {
    type Error = Error;
    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        VerificationKeyBytes::from(bytes).try_into()
    }
}

#[cfg(feature = "pkcs8")]
impl EncodePublicKey for VerificationKey {
    /// Serialize [`VerificationKey`] to an ASN.1 DER-encoded document.
    fn to_public_key_der(&self) -> pkcs8::spki::Result<Document> {
        let alg_info = AlgorithmIdentifierRef {
            oid: ObjectIdentifier::new_unwrap("1.3.101.112"), // RFC 8410
            parameters: None,
        };
        SubjectPublicKeyInfoRef {
            algorithm: alg_info,
            subject_public_key: BitStringRef::from_bytes(&self.A_bytes.0[..])?,
        }
        .try_into()
    }
}

#[cfg(feature = "pkcs8")]
impl DecodePublicKey for VerificationKey {
    /// Deserialize [`VerificationKey`] from ASN.1 DER bytes (32 bytes).
    fn from_public_key_der(bytes: &[u8]) -> Result<Self, pkcs8::spki::Error> {
        let spki = SubjectPublicKeyInfoRef::try_from(bytes).unwrap();
        let pk_bytes = spki.subject_public_key.as_bytes().unwrap();
        Ok(Self::try_from(pk_bytes).unwrap())
    }
}

impl Verifier<Signature> for VerificationKey {
    /// Verify a [`Signature`] object against a given [`VerificationKey`].
    fn verify(
        &self,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), ed25519::signature::Error> {
        self.verify(signature, message)
            .map_err(|_| ed25519::signature::Error::new())
    }
}

impl VerificationKey {
    /// Verify a purported `signature` on the given `msg`.
    ///
    /// ## Zcash-specific consensus properties
    ///
    /// Ed25519 checks are described in [§5.4.5][ps] of the Zcash protocol specification and in
    /// [ZIP215].  The verification criteria for an (encoded) signature `(R_bytes, s_bytes)` with
    /// (encoded) verification key `A_bytes` are:
    ///
    /// * `A_bytes` and `R_bytes` MUST be encodings of points `A` and `R` respectively on the
    ///   twisted Edwards form of Curve25519, and non-canonical encodings MUST be accepted;
    ///
    /// * `s_bytes` MUST represent an integer `s` less than `l`, the order of the prime-order
    ///   subgroup of Curve25519;
    ///
    /// * the verification equation `[8][s]B = [8]R + [8][k]A` MUST be satisfied;
    ///
    /// * the alternate verification equation `[s]B = R + [k]A`, allowed by RFC 8032, MUST NOT be
    ///   used.
    ///
    /// [ps]: https://zips.z.cash/protocol/protocol.pdf#concreteed25519
    /// [ZIP215]: https://zips.z.cash/zip-0215
    pub fn verify(&self, signature: &Signature, msg: &[u8]) -> Result<(), Error> {
        let k = Scalar::from_hash(
            Sha512::default()
                .chain(&signature.r_bytes()[..])
                .chain(&self.A_bytes.0[..])
                .chain(msg),
        );
        self.verify_prehashed(signature, k)
    }

    /// Verify a signature using the heea half-size scalar optimization.
    ///
    /// This implements the algorithm from "Accelerating EdDSA Signature Verification
    /// with Faster Scalar Size Halving" (TCHES 2025).
    ///
    /// The standard verification equation sB = R + hA is transformed to:
    /// τsB = τR + ρA where ρ ≡ τh (mod ℓ)
    ///
    /// Both ρ and τ are approximately half the size of h.
    ///
    /// We then decompose τs into two 128-bit scalars:
    /// τs = τs_hi * 2^128 + τs_lo
    ///
    /// The verification equation becomes:
    /// τs_lo B + τs_hi (2^128 B) = τR + ρA
    /// which can be done via 4-variable MSM with half-size scalars.
    #[allow(non_snake_case)]
    pub fn verify_heea(&self, signature: &Signature, msg: &[u8]) -> Result<(), Error> {
        // Compute the hash scalar h (called k in the standard implementation)
        let h = Scalar::from_hash(
            Sha512::default()
                .chain(&signature.r_bytes()[..])
                .chain(&self.A_bytes.0[..])
                .chain(msg),
        );

        // Generate half-size scalars ρ and τ such that ρ ≡ τh (mod ℓ)
        // in order to have rho and tau approximately half the size of h
        // it is possible that we compute ρ ≡ -τh (mod ℓ)
        // this is indicated by `flip_h` flag being true,
        // in which case we will need to negate A later
        // let (rho, tau, flip_h) = crate::heea::generate_half_size_scalars(&h);
        let (rho, tau, flip_h) = h.heea_decompose();

        // Extract s from the signature
        let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(*signature.s_bytes()))
            .ok_or(Error::InvalidSignature)?;

        // Decode R from the signature
        let neg_R = -CompressedEdwardsY(*signature.r_bytes())
            .decompress()
            .ok_or(Error::InvalidSignature)?;

        // Standard verification checks: sB = R + hA
        // Transformed verification: -τsB + τR + ρA == 0
        //
        // We verify:
        //  [8] τs B + [8] τ (-R) + [8] ρ (-A) == 0

        // Compute τs
        let ts = tau * s;
        let A = if flip_h { -self.minus_A } else { self.minus_A };
        // Compute the multi-scalar multiplication
        let result = EdwardsPoint::vartime_triple_scalar_mul_basepoint(&tau, &neg_R, &rho, &A, &ts);

        // Check if [8] τs B + [8] τ (-R) + [8] ρ (-A) == 0
        if result.mul_by_cofactor().is_identity() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    /// Verify a signature with a prehashed `k` value. Note that this is not the
    /// same as "prehashing" in RFC8032.
    #[allow(non_snake_case)]
    pub(crate) fn verify_prehashed(&self, signature: &Signature, k: Scalar) -> Result<(), Error> {
        // `s_bytes` MUST represent an integer less than the prime `l`.
        let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(*signature.s_bytes()))
            .ok_or(Error::InvalidSignature)?;
        // `R_bytes` MUST be an encoding of a point on the twisted Edwards form of Curve25519.
        let R = CompressedEdwardsY(*signature.r_bytes())
            .decompress()
            .ok_or(Error::InvalidSignature)?;
        // We checked the encoding of A_bytes when constructing `self`.

        //       [8][s]B = [8]R + [8][k]A
        // <=>   [8]R = [8][s]B - [8][k]A
        // <=>   0 = [8](R - ([s]B - [k]A))
        // <=>   0 = [8](R - R')  where R' = [s]B - [k]A
        let R_prime = EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &self.minus_A, &s);

        if (R - R_prime).mul_by_cofactor().is_identity() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}
