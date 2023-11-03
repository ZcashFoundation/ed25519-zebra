use core::convert::TryFrom;

use rand::thread_rng;

use ed25519_zebra::{Signature, SigningKey, VerificationKey, VerificationKeyBytes};

#[test]
fn parsing() {
    let sk = SigningKey::new(thread_rng());
    let pk = VerificationKey::from(&sk);
    let pkb = VerificationKeyBytes::from(&sk);
    let sig = sk.sign(b"test");

    let sk_array: [u8; 32] = sk.into();
    let pk_array: [u8; 32] = pk.into();
    let pkb_array: [u8; 32] = pkb.into();
    let sig_array: [u8; 64] = sig.into();

    let sk2 = SigningKey::try_from(sk_array).unwrap();
    let pk2 = VerificationKey::try_from(pk_array).unwrap();
    let pkb2 = VerificationKeyBytes::try_from(pkb_array).unwrap();
    let sig2 = Signature::try_from(sig_array).unwrap();

    assert_eq!(sk, sk2);
    assert_eq!(pk, pk2);
    assert_eq!(pkb, pkb2);
    assert_eq!(sig, sig2);

    let sk3: SigningKey = bincode::deserialize(sk.as_ref()).unwrap();
    let pk3: VerificationKey = bincode::deserialize(pk.as_ref()).unwrap();
    let pkb3: VerificationKeyBytes = bincode::deserialize(pkb.as_ref()).unwrap();

    assert_eq!(sk, sk3);
    assert_eq!(pk, pk3);
    assert_eq!(pkb, pkb3);
}

#[test]
fn sign_and_verify() {
    let sk = SigningKey::new(thread_rng());
    let pk = VerificationKey::from(&sk);

    let msg = b"ed25519-zebra test message";

    let sig = sk.sign(&msg[..]);

    assert_eq!(pk.verify(&sig, &msg[..]), Ok(()))
}
