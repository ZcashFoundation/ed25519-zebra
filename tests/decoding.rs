#[cfg(any(feature = "pem", feature = "pkcs8"))]
use ed25519_zebra::*;

#[cfg(any(feature = "pem", feature = "pkcs8"))]
use hex;

#[cfg(feature = "pkcs8")]
use pkcs8::{DecodePrivateKey, DecodePublicKey};

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

/// Ed25519 PKCS#8 v2 private key + mismatched public key encoded as ASN.1 DER.
#[cfg(feature = "pkcs8")]
const PKCS8_V2_DER_BAD: &[u8] = include_bytes!("examples/pkcs8-v2-bad-ver-key.der");

/// Ed25519 PKCS#8 v2 private key + mismatched public key encoded as PEM.
#[cfg(feature = "pem")]
const PKCS8_V2_PEM_BAD: &str = include_str!("examples/pkcs8-v2-bad-ver-key.pem");

/// Ed25519 SubjectPublicKeyInfo encoded as ASN.1 DER.
#[cfg(feature = "pkcs8")]
const PUBLIC_KEY_DER: &[u8] = include_bytes!("examples/pubkey.der");

/// Ed25519 SubjectPublicKeyInfo encoded as PEM.
#[cfg(feature = "pem")]
const PUBLIC_KEY_PEM: &str = include_str!("examples/pubkey.pem");

#[test]
#[cfg(feature = "pkcs8")]
fn decode_der_to_signing_key() {
    // Test against a v1 DER key.
    let sk1 = SigningKey::from_pkcs8_der(PKCS8_V1_DER).unwrap();
    let sk_bytes_string_1 = "D4EE72DBF913584AD5B6D8F1F769F8AD3AFE7C28CBF1D4FBE097A88F44755842";
    assert_eq!(hex::decode(sk_bytes_string_1).unwrap(), sk1.as_ref());

    // Test against a v2 DER key.
    let sk2 = SigningKey::from_pkcs8_der(PKCS8_V2_DER).unwrap();
    let sk_bytes_string_2 = "D4EE72DBF913584AD5B6D8F1F769F8AD3AFE7C28CBF1D4FBE097A88F44755842";
    assert_eq!(hex::decode(sk_bytes_string_2).unwrap(), sk2.as_ref());

    // Test against a v2 DER key with a mismatched public key.
    assert!(SigningKey::from_pkcs8_der(PKCS8_V2_DER_BAD).is_err());
}

#[test]
#[cfg(feature = "pem")]
fn decode_doc_to_signing_key() {
    // Test against a v1 PEM key.
    let sk1 = SigningKey::from_pkcs8_pem(PKCS8_V1_PEM).unwrap();
    let sk_bytes_string_1 = "D4EE72DBF913584AD5B6D8F1F769F8AD3AFE7C28CBF1D4FBE097A88F44755842";
    assert_eq!(hex::decode(sk_bytes_string_1).unwrap(), sk1.as_ref());

    // Test against a valid v2 PEM key.
    let sk2 = SigningKey::from_pkcs8_pem(PKCS8_V2_PEM).unwrap();
    let sk_bytes_string_2 = "D4EE72DBF913584AD5B6D8F1F769F8AD3AFE7C28CBF1D4FBE097A88F44755842";
    assert_eq!(hex::decode(sk_bytes_string_2).unwrap(), sk2.as_ref());

    // Test against a v2 DER key with a mismatched public key.
    assert!(SigningKey::from_pkcs8_pem(PKCS8_V2_PEM_BAD).is_err());
}

#[test]
#[cfg(feature = "pkcs8")]
fn decode_der_to_verification_key() {
    let vk = VerificationKey::from_public_key_der(PUBLIC_KEY_DER).unwrap();
    let vk_bytes_string = "19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1";
    assert_eq!(hex::decode(vk_bytes_string).unwrap(), vk.as_ref());
}

#[test]
#[cfg(feature = "pem")]
fn decode_doc_to_verification_key() {
    let vk = VerificationKey::from_public_key_pem(PUBLIC_KEY_PEM).unwrap();
    let vk_bytes_string = "19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1";
    assert_eq!(hex::decode(vk_bytes_string).unwrap(), vk.as_ref());
}
