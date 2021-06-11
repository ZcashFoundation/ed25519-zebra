const OID: ObjectIdentifier = ObjectIdentifier::new("1.3.101.112");  // RFC 8410
const ALGORITHM_ID: AlgorithmIdentifier = AlgorithmIdentifier {
        oid: OID,
        parameters: None,
    };

use core::convert::{TryFrom, TryInto,};
use curve25519_dalek::{constants, digest::Update, scalar::Scalar};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

#[cfg(feature = "pem")]
use pkcs8::FromPrivateKey;
#[cfg(any(feature = "pem", feature = "std"))]
use pkcs8::{AlgorithmIdentifier, ObjectIdentifier, PrivateKeyDocument, PrivateKeyInfo, ToPrivateKey};

use crate::{Error, Signature, VerificationKey, VerificationKeyBytes};

#[cfg(feature = "pem")]
use {crate::pem, alloc::string::String, core::str::FromStr};

/// An Ed25519 signing key.
///
/// This is also called a secret key by other implementations.
#[derive(Copy, Clone, Zeroize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(from = "SerdeHelper"))]
#[cfg_attr(feature = "serde", serde(into = "SerdeHelper"))]
pub struct SigningKey {
    seed: [u8; 32],
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

impl From<SigningKey> for [u8; 32] {
    fn from(sk: SigningKey) -> [u8; 32] {
        sk.seed
    }
}

impl TryFrom<&[u8]> for SigningKey {
    type Error = Error;
    fn try_from(slice: &[u8]) -> Result<SigningKey, Error> {
        if slice.len() == 32 {
            let mut bytes = [0u8; 32];
            bytes[..].copy_from_slice(slice);
            Ok(bytes.into())
        } else {
            Err(Error::InvalidSliceLength)
        }
    }
}

impl From<[u8; 32]> for SigningKey {
    #[allow(non_snake_case)]
    fn from(seed: [u8; 32]) -> SigningKey {
        // Expand the seed to a 64-byte array with SHA512.
        let h = Sha512::digest(&seed[..]);

        // Convert the low half to a scalar with Ed25519 "clamping"
        let s = {
            let mut scalar_bytes = [0u8; 32];
            scalar_bytes[..].copy_from_slice(&h.as_slice()[0..32]);
            scalar_bytes[0] &= 248;
            scalar_bytes[31] &= 127;
            scalar_bytes[31] |= 64;
            Scalar::from_bits(scalar_bytes)
        };

        // Extract and cache the high half.
        let prefix = {
            let mut prefix = [0u8; 32];
            prefix[..].copy_from_slice(&h.as_slice()[32..64]);
            prefix
        };

        // Compute the public key as A = [s]B.
        let A = &s * &constants::ED25519_BASEPOINT_TABLE;

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

impl<'a> TryFrom<PrivateKeyInfo<'a>> for SigningKey {
    type Error = Error;
    fn try_from(pki: PrivateKeyInfo) -> Result<Self, Error> {
        if pki.algorithm == ALGORITHM_ID {
            SigningKey::try_from(pki.private_key)
        } else {
            Err(Error::MalformedSecretKey)
        }
    }
}

impl ToPrivateKey for SigningKey {
    fn to_pkcs8_der(&self) -> pkcs8::Result<PrivateKeyDocument> {
        // In RFC 8410, the octet string containing the private key is encapsulated by
        // another octet string. Just add octet string bytes to the key.
        let mut final_key = [0u8; 34];
        final_key[..2].copy_from_slice(&[0x04, 0x20]);
        final_key[2..].copy_from_slice(&self.seed);

        Ok(PrivateKeyInfo::new(ALGORITHM_ID, &final_key).into())
    }
}

#[cfg(feature = "pem")]
impl FromPrivateKey for SigningKey {
    fn from_pkcs8_private_key_info(pki: PrivateKeyInfo<'_>) -> pkcs8::Result<Self> {
        // Split off the extra octet string bytes.
        match &pki.private_key {
            [0x04, 0x20, private_key @ ..] => SigningKey::try_from(private_key).map_err(|_| pkcs8::Error::Crypto),
            _ => Err(der::Tag::OctetString.value_error().into())
        }
    }
}

#[cfg(feature = "pem")]
impl From<PrivateKeyDocument> for SigningKey {
    fn from(doc: PrivateKeyDocument) -> SigningKey {
        let pki = doc.unwrap();
        pki.private_key.try_into().expect("Ed25519 private key wasn't 32 bytes")
    }
}

#[cfg(feature = "pem")]
impl From<SigningKey> for PublicKeyDocument {
    fn from(sk: SigningKey) -> Result<PublicKeyDocument, Error> {
        let pki = PrivateKeyInfo::try_from(sk.seed).unwrap();
        PublicKeyDocument::try_from(pki)
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
    /// Generate a new signing key.
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> SigningKey {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes[..]);
        bytes.into()
    }

    /// Create a signature on `msg` using this key.
    #[allow(non_snake_case)]
    pub fn sign(&self, msg: &[u8]) -> Signature {
        let r = Scalar::from_hash(Sha512::default().chain(&self.prefix[..]).chain(msg));

        let R_bytes = (&r * &constants::ED25519_BASEPOINT_TABLE)
            .compress()
            .to_bytes();

        let k = Scalar::from_hash(
            Sha512::default()
                .chain(&R_bytes[..])
                .chain(&self.vk.A_bytes.0[..])
                .chain(msg),
        );

        let s_bytes = (r + k * self.s).to_bytes();

        Signature { R_bytes, s_bytes }
    }

    /// Parse [`SigningKey`] from ASN.1 DER
    pub fn from_der(bytes: &[u8]) -> pkcs8::Result<Self> {
        bytes.try_into().map_err(|_| pkcs8::Error::Crypto)
    }

    #[cfg(feature = "pem")]
    pub fn from_pem(s: &str) -> pkcs8::Result<Self> {
        let der_bytes = pem::decode(s, pem::PUBLIC_KEY_BOUNDARY)?;
        Self::from_der(&*der_bytes)
    }

    /// Serialize [`SigningKey`] as PEM-encoded PKCS#8 string.
    #[cfg(feature = "pem")]
    pub fn to_pem(&self) -> String {
        pem::encode(&self.0, pem::PUBLIC_KEY_BOUNDARY)
    }
}
