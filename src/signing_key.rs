#[cfg(feature = "pkcs8")]
const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112"); // RFC 8410
#[cfg(feature = "pkcs8")]
const ALGORITHM_ID: AlgorithmIdentifierRef = AlgorithmIdentifierRef {
    oid: OID,
    parameters: None,
};

use crate::Error;
#[cfg(all(feature = "pem", feature = "pkcs8"))]
use alloc::string::String;
use core::convert::TryFrom;
#[cfg(feature = "pkcs8")]
use core::convert::TryInto;
use curve25519_dalek::{constants, digest::Update, scalar::Scalar};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use ed25519::{signature::Signer, Signature};

#[cfg(feature = "pkcs8")]
use ed25519::KeypairBytes;
#[cfg(feature = "pem")]
use ed25519::PublicKeyBytes;

#[cfg(all(feature = "pem", feature = "pkcs8"))]
use der::pem::LineEnding;
#[cfg(feature = "pkcs8")]
use pkcs8::der::SecretDocument;
#[cfg(feature = "pkcs8")]
use pkcs8::{
    spki::AlgorithmIdentifierRef, DecodePrivateKey, DecodePublicKey, Document, EncodePrivateKey,
    EncodePublicKey, ObjectIdentifier, PrivateKeyInfo,
};
#[cfg(all(feature = "pem", feature = "pkcs8"))]
use zeroize::Zeroizing;

#[cfg(all(feature = "pem", feature = "pkcs8"))]
use pkcs8::der::pem::PemLabel;

use crate::{VerificationKey, VerificationKeyBytes};

/// The length of a ed25519 `SecretKey`, in bytes.
pub const SECRET_KEY_LENGTH: usize = 32;

/// ed25519 secret key as defined in [RFC8032 § 5.1.5]:
///
/// > The private key is 32 octets (256 bits, corresponding to b) of
/// > cryptographically secure random data.
///
/// [RFC8032 § 5.1.5]: https://www.rfc-editor.org/rfc/rfc8032#section-5.1.5
pub type SecretKey = [u8; SECRET_KEY_LENGTH];

/// An Ed25519 signing key.
///
/// This is also called a secret key by other implementations.
#[derive(Copy, Clone, Zeroize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(from = "SerdeHelper"))]
#[cfg_attr(feature = "serde", serde(into = "SerdeHelper"))]
pub struct SigningKey {
    seed: SecretKey,
    s: Scalar,
    prefix: [u8; 32],
    vk: VerificationKey,
}

impl core::fmt::Debug for SigningKey {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        fmt.debug_struct("SigningKey")
            .field("vk", &self.vk)
            .finish()
    }
}

impl<'a> From<&'a SigningKey> for VerificationKey {
    fn from(sk: &'a SigningKey) -> VerificationKey {
        sk.vk
    }
}

impl<'a> From<&'a SigningKey> for VerificationKeyBytes {
    fn from(sk: &'a SigningKey) -> VerificationKeyBytes {
        sk.vk.into()
    }
}

impl AsRef<[u8]> for SigningKey {
    fn as_ref(&self) -> &[u8] {
        &self.seed[..]
    }
}

impl From<SigningKey> for SecretKey {
    fn from(sk: SigningKey) -> SecretKey {
        sk.seed
    }
}

impl TryFrom<&[u8]> for SigningKey {
    type Error = Error;
    fn try_from(slice: &[u8]) -> Result<SigningKey, Self::Error> {
        if slice.len() == 32 {
            let mut bytes = [0u8; 32];
            bytes[..].copy_from_slice(slice);
            Ok(bytes.into())
        } else {
            Err(Self::Error::InvalidSliceLength)
        }
    }
}

impl From<SecretKey> for SigningKey {
    #[allow(non_snake_case)]
    fn from(seed: [u8; 32]) -> SigningKey {
        // Expand the seed to a 64-byte array with SHA512.
        let h = Sha512::digest(&seed[..]);

        // Convert the low half to a scalar with Ed25519 "clamping"
        let s = {
            let mut scalar_bytes = [0u8; 32];
            scalar_bytes[..].copy_from_slice(&h[0..32]);
            scalar_bytes[0] &= 248;
            scalar_bytes[31] &= 127;
            scalar_bytes[31] |= 64;
            Scalar::from_bytes_mod_order(scalar_bytes)
        };

        // Extract and cache the high half.
        let prefix = {
            let mut prefix = [0u8; 32];
            prefix[..].copy_from_slice(&h[32..64]);
            prefix
        };

        // Compute the public key as A = [s]B.
        let A = &s * constants::ED25519_BASEPOINT_TABLE;

        SigningKey {
            seed,
            s,
            prefix,
            vk: VerificationKey {
                minus_A: -A,
                A_bytes: VerificationKeyBytes(A.compress().to_bytes()),
            },
        }
    }
}

impl ConstantTimeEq for SigningKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.seed.ct_eq(&other.seed)
    }
}

impl PartialEq for SigningKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for SigningKey {}

#[cfg(feature = "pkcs8")]
impl<'a> TryFrom<PrivateKeyInfo<'a>> for SigningKey {
    type Error = Error;
    fn try_from(pki: PrivateKeyInfo) -> Result<Self, Self::Error> {
        if pki.algorithm == ALGORITHM_ID {
            SigningKey::try_from(pki.private_key)
        } else {
            Err(Self::Error::MalformedSecretKey)
        }
    }
}

#[cfg(feature = "pkcs8")]
impl EncodePublicKey for SigningKey {
    /// Serialize the public key for a [`SigningKey`] to an ASN.1 DER-encoded document.
    fn to_public_key_der(&self) -> pkcs8::spki::Result<Document> {
        self.vk.to_public_key_der()
    }
}

impl Signer<Signature> for SigningKey {
    /// Generate a [`Signature`] using a given [`SigningKey`].
    fn try_sign(&self, message: &[u8]) -> Result<Signature, ed25519::signature::Error> {
        Ok(self.sign(message))
    }
}

#[cfg(feature = "pkcs8")]
impl TryFrom<KeypairBytes> for SigningKey {
    type Error = pkcs8::Error;

    fn try_from(pkcs8_key: KeypairBytes) -> pkcs8::Result<Self> {
        SigningKey::try_from(&pkcs8_key)
    }
}

#[cfg(feature = "pkcs8")]
impl TryFrom<&KeypairBytes> for SigningKey {
    type Error = pkcs8::Error;

    fn try_from(pkcs8_key: &KeypairBytes) -> pkcs8::Result<Self> {
        let signing_key = SigningKey::from_der(&pkcs8_key.secret_key);

        // Validate the public key in the PKCS#8 document if present
        if let Some(public_bytes) = &pkcs8_key.public_key {
            let expected_verifying_key =
                VerificationKey::from_public_key_der(public_bytes.as_ref())
                    .map_err(|_| pkcs8::Error::KeyMalformed)?;

            if VerificationKey::try_from(&signing_key.unwrap())
                .unwrap()
                .A_bytes
                != expected_verifying_key.into()
            {
                return Err(pkcs8::Error::KeyMalformed);
            }
        }

        signing_key
    }
}

#[cfg(feature = "pem")]
impl From<SigningKey> for KeypairBytes {
    fn from(signing_key: SigningKey) -> KeypairBytes {
        KeypairBytes::from(&signing_key)
    }
}

#[cfg(feature = "pem")]
impl From<&SigningKey> for KeypairBytes {
    fn from(signing_key: &SigningKey) -> KeypairBytes {
        KeypairBytes {
            secret_key: signing_key.s.to_bytes(),
            public_key: Some(PublicKeyBytes(signing_key.vk.try_into().unwrap())),
        }
    }
}

#[cfg(feature = "pkcs8")]
impl EncodePrivateKey for SigningKey {
    /// Serialize [`SigningKey`] to an ASN.1 DER-encoded secret document. Note that this
    /// will generate a v2 (RFC 5958) DER encoding with a public key.
    fn to_pkcs8_der(&self) -> pkcs8::Result<SecretDocument> {
        // In RFC 8410, the octet string containing the private key is encapsulated by
        // another octet string. Just add octet string bytes to the key when building
        // the document.
        let mut final_key = [0u8; 34];
        final_key[..2].copy_from_slice(&[0x04, 0x20]);
        final_key[2..].copy_from_slice(&self.seed);
        SecretDocument::try_from(PrivateKeyInfo {
            algorithm: ALGORITHM_ID,
            private_key: &final_key,
            public_key: Some(self.vk.A_bytes.0.as_slice()),
        })
    }
}

#[cfg(feature = "pkcs8")]
impl DecodePrivateKey for SigningKey {
    /// Create a [`SigningKey`] from an ASN.1 DER-encoded bytes. The bytes may include an
    /// accompanying public key, as defined in RFC 5958 (v1 and v2), but the call will
    /// fail if the public key doesn't match the private key's true accompanying public
    /// key.
    fn from_pkcs8_der(bytes: &[u8]) -> pkcs8::Result<Self> {
        let keypair = KeypairBytes::from_pkcs8_der(bytes).unwrap();
        let sk = SigningKey::try_from(keypair.secret_key).unwrap();
        match keypair.public_key {
            Some(vk2) => {
                if sk.vk.A_bytes.0 == vk2.to_bytes() {
                    Ok(sk)
                } else {
                    Err(pkcs8::Error::KeyMalformed)
                }
            }
            None => Ok(sk),
        }
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
struct SerdeHelper([u8; 32]);

impl From<SerdeHelper> for SigningKey {
    fn from(helper: SerdeHelper) -> SigningKey {
        helper.0.into()
    }
}

impl From<SigningKey> for SerdeHelper {
    fn from(sk: SigningKey) -> Self {
        Self(sk.into())
    }
}

impl SigningKey {
    /// Construct a [`SigningKey`] from a [`SecretKey`]
    ///
    #[inline]
    pub fn from_bytes(secret_key: &SecretKey) -> Self {
        (*secret_key).into()
    }

    /// Convert this [`SigningKey`] into a [`SecretKey`]
    #[inline]
    pub fn to_bytes(&self) -> SecretKey {
        (*self).into()
    }

    /// Convert this [`SigningKey`] into a [`SecretKey`] reference
    #[inline]
    pub fn as_bytes(&self) -> &SecretKey {
        &self.seed
    }

    /// Generate a new signing key.
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> SigningKey {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes[..]);
        bytes.into()
    }

    /// Get the [`VerificationKey`] for this [`SigningKey`].
    pub fn verification_key(&self) -> VerificationKey {
        self.into()
    }

    /// Create a signature on `msg` using this key.
    #[allow(non_snake_case)]
    pub fn sign(&self, msg: &[u8]) -> Signature {
        let r = Scalar::from_hash(Sha512::default().chain(&self.prefix[..]).chain(msg));

        let R_bytes = (&r * constants::ED25519_BASEPOINT_TABLE)
            .compress()
            .to_bytes();

        let k = Scalar::from_hash(
            Sha512::default()
                .chain(&R_bytes[..])
                .chain(&self.vk.A_bytes.0[..])
                .chain(msg),
        );

        let s_bytes = (r + k * self.s).to_bytes();

        Signature::from_components(R_bytes, s_bytes)
    }

    /// Parse [`SigningKey`] from ASN.1 DER bytes.
    #[cfg(feature = "pkcs8")]
    pub fn from_der(bytes: &[u8]) -> pkcs8::Result<Self> {
        bytes
            .try_into()
            .map_err(|_| pkcs8::Error::ParametersMalformed)
    }

    /// Serialize [`SigningKey`] to an ASN.1 DER-encoded secret document. Note that this
    /// will generate a v1 (RFC 5958) DER encoding without a public key.
    #[cfg(feature = "pkcs8")]
    pub fn to_pkcs8_der_v1(&self) -> pkcs8::Result<SecretDocument> {
        // In RFC 8410, the octet string containing the private key is encapsulated by
        // another octet string. Just add octet string bytes to the key when building
        // the document.
        let mut final_key = [0u8; 34];
        final_key[..2].copy_from_slice(&[0x04, 0x20]);
        final_key[2..].copy_from_slice(&self.seed);
        SecretDocument::try_from(PrivateKeyInfo::new(ALGORITHM_ID, &final_key))
    }

    /// Serialize [`SigningKey`] as a PEM-encoded PKCS#8 string. Note that this
    /// will generate a v1 (RFC 5958) PEM encoding without a public key.
    #[cfg(all(feature = "pem", feature = "pkcs8"))]
    pub fn to_pkcs8_pem_v1(
        &self,
        line_ending: LineEnding,
    ) -> Result<Zeroizing<String>, pkcs8::Error> {
        let doc = self.to_pkcs8_der_v1()?;
        Ok(doc.to_pem(PrivateKeyInfo::PEM_LABEL, line_ending)?)
    }
}
