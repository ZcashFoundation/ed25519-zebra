#![cfg(feature = "alloc")]

use rand::thread_rng;

use ed25519_zebra::*;

#[test]
fn batch_verify() {
    let mut batch = batch::Verifier::new();
    for _ in 0..32 {
        let sk = SigningKey::new(thread_rng());
        let pk_bytes = VerificationKeyBytes::from(&sk);
        let msg = b"BatchVerifyTest";
        let sig = sk.sign(&msg[..]);
        batch.queue((pk_bytes, sig, msg));
    }
    assert!(batch.verify(thread_rng()).is_ok());
}

#[test]
fn batch_verify_with_one_bad_sig() {
    let bad_index = 10;
    let mut batch = batch::Verifier::new();
    let mut items = Vec::new();
    for i in 0..32 {
        let sk = SigningKey::new(thread_rng());
        let pk_bytes = VerificationKeyBytes::from(&sk);
        let msg = b"BatchVerifyTest";
        let sig = if i != bad_index {
            sk.sign(&msg[..])
        } else {
            sk.sign(b"badmsg")
        };
        let item: batch::Item = (pk_bytes, sig, msg).into();
        items.push(item.clone());
        batch.queue(item);
    }
    assert!(batch.verify(thread_rng()).is_err());
    for (i, item) in items.drain(..).enumerate() {
        if i != bad_index {
            assert!(item.verify_single().is_ok());
        } else {
            assert!(item.verify_single().is_err());
        }
    }
}

#[test]
fn batch_verify_heea() {
    let mut batch = batch::Verifier::new();
    for _ in 0..4 {
        let sk = SigningKey::new(thread_rng());
        let pk_bytes = VerificationKeyBytes::from(&sk);
        let msg = b"BatchVerifyTest_HEEA";
        let sig = sk.sign(&msg[..]);
        batch.queue((pk_bytes, sig, msg));
    }
    assert!(batch.verify_heea(thread_rng()).is_ok());
}

#[test]
fn batch_verify_heea_with_one_bad_sig() {
    let bad_index = 10;
    let mut batch = batch::Verifier::new();
    let mut items = Vec::new();
    for i in 0..32 {
        let sk = SigningKey::new(thread_rng());
        let pk_bytes = VerificationKeyBytes::from(&sk);
        let msg = b"BatchVerifyTest_HEEA";
        let sig = if i != bad_index {
            sk.sign(&msg[..])
        } else {
            sk.sign(b"badmsg")
        };
        let item: batch::Item = (pk_bytes, sig, msg).into();
        items.push(item.clone());
        batch.queue(item);
    }
    assert!(batch.verify_heea(thread_rng()).is_err());
    for (i, item) in items.drain(..).enumerate() {
        if i != bad_index {
            assert!(item.verify_single().is_ok());
        } else {
            assert!(item.verify_single().is_err());
        }
    }
}

// #[test]
// fn batch_verify_heea_different_batch_sizes() {
//     // Test various batch sizes to ensure the algorithm works correctly
//     for batch_size in [1, 2, 4, 8, 16, 32, 64].iter() {
//         let mut batch = batch::Verifier::new();
//         for _ in 0..*batch_size {
//             let sk = SigningKey::new(thread_rng());
//             let pk_bytes = VerificationKeyBytes::from(&sk);
//             let msg = b"BatchVerifyTest_HEEA_Size";
//             let sig = sk.sign(&msg[..]);
//             batch.queue((pk_bytes, sig, msg));
//         }
//         assert!(
//             batch.verify_heea(thread_rng()).is_ok(),
//             "Batch verification with hEEA failed for batch size {}",
//             batch_size
//         );
//     }
// }
