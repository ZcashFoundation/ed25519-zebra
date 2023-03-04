const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");  // RFC 8410
const ALGORITHM_ID: AlgorithmIdentifierRef = AlgorithmIdentifierRef {
    oid: OID,
    parameters: None,
};

use core::convert::{TryFrom, TryInto,};
use crate::Error;
use curve25519_dalek::{constants, digest::Update, scalar::Scalar};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

pub use ed25519::{
    signature::{Signer, Verifier},
    ComponentBytes, Error as Ed25519Error, KeypairBytes, PublicKeyBytes, Signature,
};

use pkcs8::{der::SecretDocument};
#[cfg(any(feature = "pem", feature = "std"))]
use pkcs8::{DecodePrivateKey, Document, EncodePrivateKey, EncodePublicKey, ObjectIdentifier, PrivateKeyInfo, spki::AlgorithmIdentifierRef};

use crate::{VerificationKey, VerificationKeyBytes};

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
    fn try_from(pki: PrivateKeyInfo) -> Result<Self, Self::Error> {
        if pki.algorithm == ALGORITHM_ID {
            SigningKey::try_from(pki.private_key)
        } else {
            Err(Self::Error::MalformedSecretKey)
        }
    }
}

impl EncodePublicKey for SigningKey {
    fn to_public_key_der(&self) -> pkcs8::spki::Result<Document> {
        self.vk.to_public_key_der()
    }
}
impl Signer<Signature> for SigningKey {
    fn try_sign(&self, message: &[u8]) -> Result<Signature, ed25519::signature::Error> {
        Ok(self.sign(message))
    }
}

// #[cfg(feature = "pkcs8")]
impl TryFrom<KeypairBytes> for SigningKey {
    type Error = pkcs8::Error;

    fn try_from(pkcs8_key: KeypairBytes) -> pkcs8::Result<Self> {
        SigningKey::try_from(&pkcs8_key)
    }
}

// #[cfg(feature = "pkcs8")]
impl TryFrom<&KeypairBytes> for SigningKey {
    type Error = pkcs8::Error;

    fn try_from(pkcs8_key: &KeypairBytes) -> pkcs8::Result<Self> {
        let signing_key = SigningKey::from_der(&pkcs8_key.secret_key);

        // Validate the public key in the PKCS#8 document if present
        if let Some(public_bytes) = &pkcs8_key.public_key {
            let expected_verifying_key = VerificationKeyBytes::from_der(public_bytes.as_ref())
                .map_err(|_| pkcs8::Error::KeyMalformed)?;

            if VerificationKey::try_from(&signing_key.unwrap()).unwrap().A_bytes != expected_verifying_key {
                return Err(pkcs8::Error::KeyMalformed);
            }
        }

        signing_key
    }
}

// #[cfg(feature = "pkcs8")]
impl From<SigningKey> for KeypairBytes {
    fn from(signing_key: SigningKey) -> KeypairBytes {
        KeypairBytes::from(&signing_key)
    }
}

// #[cfg(feature = "pkcs8")]
impl From<&SigningKey> for KeypairBytes {
    fn from(signing_key: &SigningKey) -> KeypairBytes {
        KeypairBytes {
            secret_key: signing_key.s.to_bytes(),
            public_key: Some(PublicKeyBytes(signing_key.vk.try_into().unwrap())),
        }
    }
}

impl EncodePrivateKey for SigningKey {
    fn to_pkcs8_der(&self) -> pkcs8::Result<SecretDocument> {
        // In RFC 8410, the octet string containing the private key is encapsulated by
        // another octet string. Just add octet string bytes to the key.
        let mut final_key = [0u8; 34];
        final_key[..2].copy_from_slice(&[0x04, 0x20]);
        final_key[2..].copy_from_slice(&self.seed);

        SecretDocument::try_from(PrivateKeyInfo::new(ALGORITHM_ID, &final_key))
    }
}

impl DecodePrivateKey for SigningKey {
    fn from_pkcs8_der(bytes: &[u8]) -> pkcs8::Result<Self> {
        // Split off the extra octet string bytes.
        let keypair = KeypairBytes::from_pkcs8_der(bytes).unwrap();
        Ok(SigningKey::try_from(keypair.secret_key).unwrap())
    }
}

#[cfg(feature = "pem")]
impl From<SecretDocument> for SigningKey {
    fn from(doc: SecretDocument) -> SigningKey {
        let pki = doc.unwrap();
        pki.private_key.try_into().expect("Ed25519 private key wasn't 32 bytes")
    }
}

#[cfg(feature = "pem")]
impl From<SigningKey> for Document {
    fn from(sk: SigningKey) -> Result<Document, Error> {
        let pki = PrivateKeyInfo::try_from(sk.seed).unwrap();
        Document::try_from(pki)
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

        Signature::from_components(R_bytes.into(), s_bytes.into())
    }

    /// Parse [`SigningKey`] from ASN.1 DER
    pub fn from_der(bytes: &[u8]) -> pkcs8::Result<Self> {
        bytes.try_into().map_err(|_| pkcs8::Error::ParametersMalformed)
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
