use hex;
use std::convert::TryFrom;
use pkcs8::{ToPrivateKey, ToPublicKey};

use ed25519_zebra::*;

#[test]
fn encode_signing_key_to_der() {
    let sk_bytes_string = "D4EE72DBF913584AD5B6D8F1F769F8AD3AFE7C28CBF1D4FBE097A88F44755842";
    let mut sk_array = [0u8; 32];
    hex::decode_to_slice(sk_bytes_string, &mut sk_array as &mut [u8]).ok();

    let sk = SigningKey::try_from(sk_array).unwrap();
    let pkd = sk.to_pkcs8_der();
    let sk_bytes_der_string = "302e020100300506032b657004220420d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842";

    assert_eq!(
        pkd.as_ref(),
        hex::decode(sk_bytes_der_string).unwrap()
    );
}

#[test]
fn encode_signing_key_to_pem() {
    let sk_bytes_string = "D4EE72DBF913584AD5B6D8F1F769F8AD3AFE7C28CBF1D4FBE097A88F44755842";
    let mut sk_array = [0u8; 32];
    hex::decode_to_slice(sk_bytes_string, &mut sk_array as &mut [u8]).ok();

    let sk = SigningKey::try_from(sk_array).unwrap();
    let pkd = sk.to_pkcs8_der();
    let pki = pkd.private_key_info();
    let pem_bytes_string = "2d2d2d2d2d424547494e2050524956415445204b45592d2d2d2d2d0a4d43344341514177425159444b32567742434945494e5475637476354531684b31626259386664702b4b30362f6e776f792f48552b2b435871493945645668430a2d2d2d2d2d454e442050524956415445204b45592d2d2d2d2d";

    assert_eq!(
        &*pki.to_pem().as_bytes(),
        hex::decode(pem_bytes_string).unwrap()
    );
}

#[test]
fn encode_signing_key_to_pki() {
    let sk_bytes_string = "D4EE72DBF913584AD5B6D8F1F769F8AD3AFE7C28CBF1D4FBE097A88F44755842";
    let mut sk_array = [0u8; 32];
    hex::decode_to_slice(sk_bytes_string, &mut sk_array as &mut [u8]).ok();

    let sk = SigningKey::try_from(sk_array).unwrap();
    let pkd = sk.to_pkcs8_der();
    let pki = pkd.private_key_info();

    let (octetstring_prefix, private_key) = pki.private_key.split_at(2);
    assert_eq!(pki.algorithm.oid, "1.3.101.112".parse().unwrap());
    assert_eq!(pki.algorithm.parameters, None);

    assert_eq!(hex::encode(octetstring_prefix), "0420");
    assert_eq!(
        private_key,
        sk_array
    );
}

#[test]
fn encode_verification_key_to_der() {
    let vk_bytes_string = "4d29167f3f1912a6f7adfa293a051a15c05ec67b8f17267b1c5550dce853bd0d";
    let mut vk_array = [0u8; 32];
    hex::decode_to_slice(vk_bytes_string, &mut vk_array as &mut [u8]).ok();

    let vk = VerificationKey::try_from(vk_array).unwrap();
    let pkd = vk.to_public_key_der();
    let der_bytes_string = "302a300506032b65700321004d29167f3f1912a6f7adfa293a051a15c05ec67b8f17267b1c5550dce853bd0d";

    assert_eq!(hex::decode(der_bytes_string).unwrap(), pkd.as_ref());
}

#[test]
fn encode_verification_key_to_pem() {
    let vk_bytes_string = "4d29167f3f1912a6f7adfa293a051a15c05ec67b8f17267b1c5550dce853bd0d";
    let mut vk_array = [0u8; 32];
    hex::decode_to_slice(vk_bytes_string, &mut vk_array as &mut [u8]).ok();

    let vk = VerificationKey::try_from(vk_array).unwrap();
    let pem = vk.to_public_key_der().to_pem();
    let pem_bytes_string = "2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d436f77425159444b3256774179454154536b57667a385a4571623372666f704f67556146634265786e755046795a3748465651334f68547651303d0a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d";

    assert_eq!(pem.as_bytes(), hex::decode(pem_bytes_string).unwrap());
}

#[test]
fn encode_verification_key_to_pki() {
    let vk_bytes_string = "4d29167f3f1912a6f7adfa293a051a15c05ec67b8f17267b1c5550dce853bd0d";
    let mut vk_array = [0u8; 32];
    hex::decode_to_slice(vk_bytes_string, &mut vk_array as &mut [u8]).ok();

    let vk = VerificationKey::try_from(vk_array).unwrap();
    let pkd = vk.to_public_key_der();
    let spki = pkd.spki();

    assert_eq!(spki.algorithm.oid, "1.3.101.112".parse().unwrap());
    assert_eq!(spki.algorithm.parameters, None);

    assert_eq!(
        spki.subject_public_key,
        vk_array
    );
}
