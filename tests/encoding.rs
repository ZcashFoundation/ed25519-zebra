use hex;
use std::convert::TryFrom;
use pkcs8::{ToPrivateKey, ToPublicKey};

use ed25519_zebra::*;

#[test]
fn encode_signing_key_to_der() {
    let sk_bytes_string = "17ED9C73E9DB649EC189A612831C5FC570238207C1AA9DFBD2C53E3FF5E5EA85";
    let mut sk_array = [0u8; 32];
    hex::decode_to_slice(sk_bytes_string, &mut sk_array as &mut [u8]).ok();

    let sk = SigningKey::try_from(sk_array).unwrap();
    let pkd = sk.to_pkcs8_der();
    let sk_bytes_der_string = "302c020100300506032b6570042017ed9c73e9db649ec189a612831c5fc570238207c1aa9dfbd2c53e3ff5e5ea85";

    assert_eq!(
        pkd.as_ref(),
        hex::decode(sk_bytes_der_string).unwrap()
    );
}

#[test]
fn encode_signing_key_to_pem() {
    let sk_bytes_string = "17ED9C73E9DB649EC189A612831C5FC570238207C1AA9DFBD2C53E3FF5E5EA85";
    let mut sk_array = [0u8; 32];
    hex::decode_to_slice(sk_bytes_string, &mut sk_array as &mut [u8]).ok();

    let sk = SigningKey::try_from(sk_array).unwrap();
    let pkd = sk.to_pkcs8_der();
    let pki = pkd.private_key_info();
    let pem_bytes_string = "2d2d2d2d2d424547494e2050524956415445204b45592d2d2d2d2d0a4d43774341514177425159444b32567742434158375a787a3664746b6e73474a70684b4448462f4663434f43423847716e6676537854342f3965587168513d3d0a2d2d2d2d2d454e442050524956415445204b45592d2d2d2d2d";

    assert_eq!(
        &*pki.to_pem().as_bytes(),
        hex::decode(pem_bytes_string).unwrap()
    );
}

#[test]
fn encode_signing_key_to_pki() {
    let sk_bytes_string = "17ED9C73E9DB649EC189A612831C5FC570238207C1AA9DFBD2C53E3FF5E5EA85";
    let mut sk_array = [0u8; 32];
    hex::decode_to_slice(sk_bytes_string, &mut sk_array as &mut [u8]).ok();

    let sk = SigningKey::try_from(sk_array).unwrap();
    let pkd = sk.to_pkcs8_der();
    let pki = pkd.private_key_info();

    assert_eq!(pki.algorithm.oid, "1.3.101.112".parse().unwrap());
    assert_eq!(pki.algorithm.parameters, None);

    assert_eq!(
        pki.private_key,
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
