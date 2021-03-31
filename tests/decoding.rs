use hex;
use pkcs8::{FromPrivateKey, FromPublicKey, ToPrivateKey, ToPublicKey};
use std::convert::TryFrom;
use ed25519_zebra::*;

#[test]
fn decode_der_to_signing_key() {
    let der_bytes_string = "302c020100300506032b6570042017ed9c73e9db649ec189a612831c5fc570238207c1aa9dfbd2c53e3ff5e5ea85";
    let mut der_bytes = [0u8; 46];
    hex::decode_to_slice(der_bytes_string, &mut der_bytes as &mut [u8]).ok();
    let sk = SigningKey::from_pkcs8_der(der_bytes.as_ref()).unwrap();

    let sk_bytes_string = "17ED9C73E9DB649EC189A612831C5FC570238207C1AA9DFBD2C53E3FF5E5EA85";
    assert_eq!(hex::decode(sk_bytes_string).unwrap(), sk.as_ref());
}

#[test]
fn decode_doc_to_signing_key() {
    let sk_bytes_string = "17ED9C73E9DB649EC189A612831C5FC570238207C1AA9DFBD2C53E3FF5E5EA85";
    let mut sk_array = [0u8; 32];
    hex::decode_to_slice(sk_bytes_string, &mut sk_array as &mut [u8]).ok();

    let sk1 = SigningKey::try_from(sk_array).unwrap();
    let pkd = sk1.to_pkcs8_der();

    let sk2 = SigningKey::from_pkcs8_doc(&pkd).unwrap();
    assert_eq!(sk_array, sk2.as_ref());
}

#[test]
fn decode_pem_to_signing_key() {
    let pem_bytes_string = "2d2d2d2d2d424547494e2050524956415445204b45592d2d2d2d2d0a4d43774341514177425159444b32567742434158375a787a3664746b6e73474a70684b4448462f4663434f43423847716e6676537854342f3965587168513d3d0a2d2d2d2d2d454e442050524956415445204b45592d2d2d2d2d";
    let mut pem_bytes = [0u8; 118];
    hex::decode_to_slice(pem_bytes_string, &mut pem_bytes as &mut [u8]).ok();
    let sk = SigningKey::from_pkcs8_pem(String::from_utf8_lossy(pem_bytes.as_ref()).as_ref()).unwrap();

    let sk_bytes_string = "17ED9C73E9DB649EC189A612831C5FC570238207C1AA9DFBD2C53E3FF5E5EA85";
    assert_eq!(hex::decode(sk_bytes_string).unwrap(), sk.as_ref());
}

#[test]
fn decode_der_to_verification_key() {
    let der_bytes_string = "302a300506032b65700321004d29167f3f1912a6f7adfa293a051a15c05ec67b8f17267b1c5550dce853bd0d";
    let mut der_bytes = [0u8; 44];
    hex::decode_to_slice(der_bytes_string, &mut der_bytes as &mut [u8]).ok();
    let vk = VerificationKey::from_public_key_der(der_bytes.as_ref()).unwrap();

    let vk_bytes_string = "4d29167f3f1912a6f7adfa293a051a15c05ec67b8f17267b1c5550dce853bd0d";
    assert_eq!(hex::decode(vk_bytes_string).unwrap(), vk.as_ref());
}

#[test]
fn decode_doc_to_verification_key() {
    let vk_bytes_string = "4d29167f3f1912a6f7adfa293a051a15c05ec67b8f17267b1c5550dce853bd0d";
    let mut vk_array = [0u8; 32];
    hex::decode_to_slice(vk_bytes_string, &mut vk_array as &mut [u8]).ok();

    let vk1 = VerificationKey::try_from(vk_array).unwrap();
    let pkd = vk1.to_public_key_der();

    let vk2 = VerificationKey::from_public_key_doc(&pkd).unwrap();
    assert_eq!(vk_array, vk2.as_ref());
}

#[test]
fn decode_pem_to_verification_key() {
    let pem_bytes_string = "2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d436f77425159444b3256774179454154536b57667a385a4571623372666f704f67556146634265786e755046795a3748465651334f68547651303d0a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d";
    let mut pem_bytes = [0u8; 112];
    hex::decode_to_slice(pem_bytes_string, &mut pem_bytes as &mut [u8]).ok();
    let vk = VerificationKey::from_public_key_pem(String::from_utf8_lossy(pem_bytes.as_ref()).as_ref()).unwrap();

    let vk_bytes_string = "4d29167f3f1912a6f7adfa293a051a15c05ec67b8f17267b1c5550dce853bd0d";
    assert_eq!(hex::decode(vk_bytes_string).unwrap(), vk.as_ref());
}
