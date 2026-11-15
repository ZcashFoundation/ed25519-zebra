use core::convert::TryFrom;

use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519::{signature::Verifier, Signature};
use ed25519_zebra::VerificationKey;
use serde_json::Value;

fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(public_key) = VerificationKey::try_from(public_key) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(signature) else {
        return false;
    };

    public_key.verify(&signature, message).is_ok()
}

fn has_noncanonical_zero_x_encoding(bytes: &[u8]) -> bool {
    let Ok(encoded) = <[u8; 32]>::try_from(bytes) else {
        return false;
    };
    if encoded[31] & 0x80 == 0 {
        return false;
    }

    let mut cleared_sign_bit = encoded;
    cleared_sign_bit[31] &= 0x7f;
    let Some(with_sign_bit) = CompressedEdwardsY(encoded).decompress() else {
        return false;
    };
    let Some(without_sign_bit) = CompressedEdwardsY(cleared_sign_bit).decompress() else {
        return false;
    };

    with_sign_bit == without_sign_bit && with_sign_bit.compress().to_bytes() != encoded
}

fn is_zip215_encoding_exception(test: &Value, public_key: &[u8], signature: &[u8]) -> bool {
    let is_invalid_encoding = test["result"] == "invalid"
        && signature.len() == 64
        && test["flags"]
            .as_array()
            .unwrap()
            .iter()
            .any(|flag| flag == "InvalidEncoding");
    if !is_invalid_encoding {
        return false;
    }

    let noncanonical_public_key = has_noncanonical_zero_x_encoding(public_key);
    let noncanonical_r = has_noncanonical_zero_x_encoding(&signature[..32]);

    noncanonical_public_key || noncanonical_r
}

#[test]
fn wycheproof_ed25519() {
    let vectors: Value = serde_json::from_str(include_str!("vectors/ed25519_test.json")).unwrap();
    let groups = vectors["testGroups"].as_array().unwrap();
    let mut cases = 0;
    let mut skipped = 0;

    for (group_index, group) in groups.iter().enumerate() {
        assert_eq!(group["publicKey"]["curve"], "edwards25519");
        let public_key = hex::decode(group["publicKey"]["pk"].as_str().unwrap()).unwrap();

        for test in group["tests"].as_array().unwrap() {
            let message = hex::decode(test["msg"].as_str().unwrap()).unwrap();
            let signature = hex::decode(test["sig"].as_str().unwrap()).unwrap();
            if is_zip215_encoding_exception(test, &public_key, &signature) {
                // ZIP 215 requires accepting non-canonical point encodings (see `VerificationKey::verify` docs).
                skipped += 1;
                continue;
            }

            let actual = verify(&public_key, &message, &signature);
            let tc_id = test["tcId"].as_u64().unwrap();

            match test["result"].as_str().unwrap() {
                "valid" => assert!(
                    actual,
                    "valid signature rejected in group {}, test {}",
                    group_index, tc_id
                ),
                "invalid" => assert!(
                    !actual,
                    "invalid signature accepted in group {}, test {}",
                    group_index, tc_id
                ),
                "acceptable" => {}
                result => panic!(
                    "unknown result {} in group {}, test {}",
                    result, group_index, tc_id
                ),
            }

            cases += 1;
        }
    }

    assert_eq!(
        cases + skipped,
        vectors["numberOfTests"].as_u64().unwrap() as usize
    );
}
