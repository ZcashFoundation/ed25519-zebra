#[cfg(feature = "pem")]
use der::pem::LineEnding;
#[cfg(any(feature = "pem", feature = "pkcs8"))]
use ed25519_zebra::*;
#[cfg(any(feature = "pem", feature = "pkcs8"))]
use hex;
#[cfg(feature = "pkcs8")]
pub use pkcs8::{
    spki::AlgorithmIdentifierRef, EncodePrivateKey, EncodePublicKey, ObjectIdentifier,
    PrivateKeyInfo,
};
#[cfg(any(feature = "pem", feature = "pkcs8"))]
use std::convert::TryFrom;

/// Ed25519 PKCS#8 v1 private key encoded as ASN.1 DER.
#[cfg(feature = "pkcs8")]
const PKCS8_V1_DER: &[u8] = include_bytes!("examples/pkcs8-v1.der");

/// Ed25519 PKCS#8 v1 private key encoded as PEM.
#[cfg(feature = "pem")]
const PKCS8_V1_PEM: &str = include_str!("examples/pkcs8-v1.pem");

/// Ed25519 PKCS#8 v2 private key + public key encoded as ASN.1 DER.
#[cfg(feature = "pkcs8")]
const PKCS8_V2_DER: &[u8] = include_bytes!("examples/pkcs8-v2.der");

/// Ed25519 PKCS#8 v1 private key encoded as PEM.
#[cfg(feature = "pem")]
const PKCS8_V2_PEM: &str = include_str!("examples/pkcs8-v2.pem");

/// Ed25519 SubjectPublicKeyInfo encoded as ASN.1 DER.
#[cfg(feature = "pkcs8")]
const PUBLIC_KEY_DER: &[u8] = include_bytes!("examples/pubkey.der");

/// Ed25519 SubjectPublicKeyInfo encoded as PEM.
#[cfg(feature = "pem")]
const PUBLIC_KEY_PEM: &str = include_str!("examples/pubkey.pem");

#[test]
#[cfg(feature = "pkcs8")]
fn encode_signing_key_to_der() {
    let sk_bytes_string = "D4EE72DBF913584AD5B6D8F1F769F8AD3AFE7C28CBF1D4FBE097A88F44755842";
    let mut sk_array = [0u8; 32];
    hex::decode_to_slice(sk_bytes_string, &mut sk_array as &mut [u8]).ok();

    let sk = SigningKey::from(sk_array);
    let vk = sk.to_public_key_der().unwrap();
    assert_eq!(sk.to_pkcs8_der_v1().unwrap().as_bytes(), PKCS8_V1_DER);
    assert_eq!(sk.to_pkcs8_der().unwrap().as_bytes(), PKCS8_V2_DER);
    assert_eq!(vk.as_bytes(), PUBLIC_KEY_DER);
}

#[test]
#[cfg(feature = "pem")]
fn encode_signing_key_to_pem() {
    let sk_bytes_string = "D4EE72DBF913584AD5B6D8F1F769F8AD3AFE7C28CBF1D4FBE097A88F44755842";
    let mut sk_array = [0u8; 32];
    hex::decode_to_slice(sk_bytes_string, &mut sk_array as &mut [u8]).ok();

    let sk = SigningKey::from(sk_array);
    let vk = sk.to_public_key_pem(LineEnding::default()).unwrap();
    assert_eq!(
        sk.to_pkcs8_pem_v1(LineEnding::default())
            .unwrap()
            .as_bytes(),
        PKCS8_V1_PEM.as_bytes()
    );
    assert_eq!(
        sk.to_pkcs8_pem(LineEnding::default()).unwrap().as_bytes(),
        PKCS8_V2_PEM.as_bytes()
    );
    assert_eq!(vk, PUBLIC_KEY_PEM);
}

#[test]
#[cfg(feature = "pkcs8")]
fn encode_verification_key_to_der() {
    let vk_bytes_string = "19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1";
    let mut vk_array = [0u8; 32];
    hex::decode_to_slice(vk_bytes_string, &mut vk_array as &mut [u8]).ok();

    let vk = VerificationKey::try_from(vk_array).unwrap();
    let pkd = vk.to_public_key_der().unwrap();
    assert_eq!(pkd.as_ref(), PUBLIC_KEY_DER);
}

#[test]
#[cfg(feature = "pem")]
fn encode_verification_key_to_pem() {
    let vk_bytes_string = "19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1";
    let mut vk_array = [0u8; 32];
    hex::decode_to_slice(vk_bytes_string, &mut vk_array as &mut [u8]).ok();

    let vk = VerificationKey::try_from(vk_array).unwrap();
    let pem = vk.to_public_key_pem(LineEnding::default()).unwrap();
    assert_eq!(pem, PUBLIC_KEY_PEM);
}
