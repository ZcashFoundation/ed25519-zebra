#![cfg(feature = "pkcs8")]
//! Tests for the PKCS#8/DER (and PEM) conversion paths.
//!
//! These cover the roundtrips through each public conversion path, and that
//! malformed input produces errors instead of panics.

use std::convert::TryFrom;

use ed25519::{KeypairBytes, PublicKeyBytes};
use ed25519_zebra::{SigningKey, VerificationKey, VerificationKeyBytes};
use pkcs8::{
    DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, PrivateKeyInfoRef,
};

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from([seed; 32])
}

#[test]
fn pkcs8_der_v2_roundtrip() {
    let sk = signing_key(42);
    let doc = sk.to_pkcs8_der().unwrap();
    let decoded = SigningKey::from_pkcs8_der(doc.as_bytes()).unwrap();
    assert_eq!(sk, decoded);
}

#[test]
fn pkcs8_der_v1_roundtrip() {
    let sk = signing_key(42);
    let doc = sk.to_pkcs8_der_v1().unwrap();
    let decoded = SigningKey::from_pkcs8_der(doc.as_bytes()).unwrap();
    assert_eq!(sk, decoded);
}

#[test]
fn private_key_info_ref_decodes_nested_octet_string() {
    let sk = signing_key(42);
    let doc = sk.to_pkcs8_der().unwrap();
    let pki = PrivateKeyInfoRef::try_from(doc.as_bytes()).unwrap();
    let decoded = SigningKey::try_from(pki).unwrap();
    assert_eq!(sk, decoded);
}

#[test]
fn keypair_bytes_decode_preserves_key() {
    let sk = signing_key(42);
    let doc = sk.to_pkcs8_der().unwrap();
    let keypair = KeypairBytes::from_pkcs8_der(doc.as_bytes()).unwrap();
    assert_eq!(keypair.secret_key, [42u8; 32]);
    let decoded = SigningKey::try_from(&keypair).unwrap();
    assert_eq!(sk, decoded);
}

#[cfg(feature = "pem")]
#[test]
fn keypair_bytes_roundtrip_preserves_seed() {
    let sk = signing_key(42);
    let keypair = KeypairBytes::from(&sk);
    assert_eq!(keypair.secret_key, [42u8; 32]);
    let decoded = SigningKey::try_from(&keypair).unwrap();
    assert_eq!(sk, decoded);
}

#[test]
fn keypair_bytes_rejects_mismatched_public_key() {
    let keypair = KeypairBytes {
        secret_key: [42u8; 32],
        public_key: Some(PublicKeyBytes(
            VerificationKeyBytes::from(VerificationKey::from(&signing_key(7))).into(),
        )),
    };
    assert!(SigningKey::try_from(&keypair).is_err());
}

#[test]
fn public_key_der_roundtrip() {
    let vk = VerificationKey::from(&signing_key(42));
    let doc = vk.to_public_key_der().unwrap();
    let decoded = VerificationKey::from_public_key_der(doc.as_bytes()).unwrap();
    assert_eq!(vk, decoded);
}

#[test]
fn malformed_private_key_der_returns_err() {
    assert!(SigningKey::from_pkcs8_der(&[0xde, 0xad, 0xbe, 0xef]).is_err());
}

#[test]
fn malformed_public_key_der_returns_err() {
    assert!(VerificationKey::from_public_key_der(&[0xde, 0xad, 0xbe, 0xef]).is_err());
}

#[cfg(feature = "pem")]
#[test]
fn pkcs8_pem_roundtrip() {
    use pkcs8::der::pem::LineEnding;

    let sk = signing_key(42);
    let pem = sk.to_pkcs8_pem(LineEnding::LF).unwrap();
    let decoded = SigningKey::from_pkcs8_pem(&pem).unwrap();
    assert_eq!(sk, decoded);
}
