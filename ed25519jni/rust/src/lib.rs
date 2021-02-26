use ed25519_zebra::{Signature, SigningKey, VerificationKey, VerificationKeyBytes,};
use jni::{objects::JClass, sys::{jboolean, jbyteArray}, JNIEnv,};
use std::{convert::TryFrom, panic, ptr,};

mod utils;

use crate::utils::exception::unwrap_exc_or;

#[no_mangle]
pub extern "system" fn Java_org_zfnd_ed25519_Ed25519Interface_checkVerificationKeyBytes(
    env: JNIEnv<'_>,
    _: JClass<'_>,
    vk_bytes: jbyteArray,
) -> jboolean {
    let mut vkb = [0u8; 32];
    vkb.copy_from_slice(&env.convert_byte_array(vk_bytes).unwrap());

    let vkb_result = VerificationKeyBytes::try_from(VerificationKeyBytes::from(vkb));
    vkb_result.is_ok() as _
}

#[no_mangle]
pub extern "system" fn Java_org_zfnd_ed25519_Ed25519Interface_getVerificationKeyBytes(
    env: JNIEnv<'_>,
    _: JClass<'_>,
    sk_seed_bytes: jbyteArray,
) -> jbyteArray {
    let res = panic::catch_unwind(|| {
        let mut seed_data = [0u8; 32];
        seed_data.copy_from_slice(&env.convert_byte_array(sk_seed_bytes).unwrap());
        let sk = SigningKey::from(seed_data);
        let pkb = VerificationKeyBytes::from(&sk);
        let pkb_array: [u8; 32] = pkb.into();

        Ok(env.byte_array_from_slice(&pkb_array).unwrap())
    });
    unwrap_exc_or(&env, res, ptr::null_mut())
}

#[no_mangle]
pub extern "system" fn Java_org_zfnd_ed25519_Ed25519Interface_sign(
    env: JNIEnv<'_>,
    _: JClass<'_>,
    sk_seed_bytes: jbyteArray,
    msg: jbyteArray,
) -> jbyteArray {
    let res = panic::catch_unwind(|| {
        let mut seed_data = [0u8; 32];
        seed_data.copy_from_slice(&env.convert_byte_array(sk_seed_bytes).unwrap());
        let sk = SigningKey::from(seed_data);

        let msg = {
            let mut data = vec![];
            data.extend_from_slice(&env.convert_byte_array(msg).unwrap());
            data
        };

        let signature = {
            let mut data = [0u8; 64];
            data.copy_from_slice(&<[u8; 64]>::from(sk.sign(&msg)));
            data
        };

        Ok(env.byte_array_from_slice(&signature).unwrap())
    });
    unwrap_exc_or(&env, res, ptr::null_mut())
}

#[no_mangle]
pub extern "system" fn Java_org_zfnd_ed25519_Ed25519Interface_verify(
    env: JNIEnv<'_>,
    _: JClass<'_>,
    vk_bytes: jbyteArray,
    signature: jbyteArray,
    msg: jbyteArray,
) -> jboolean {
    let mut vk_data = [0u8; 32];
    vk_data.copy_from_slice(&env.convert_byte_array(vk_bytes).unwrap());

    let mut sigdata = [0u8; 64];
    sigdata.copy_from_slice(&env.convert_byte_array(signature).unwrap());
    let signature = Signature::from(sigdata);

    let msg = {
        let mut data = vec![];
        data.extend_from_slice(&env.convert_byte_array(msg).unwrap());
        data
    };

    let vkb = VerificationKeyBytes::try_from(VerificationKeyBytes::from(vk_data)).unwrap();
    let vk = VerificationKey::try_from(vkb).unwrap();
    let resbool = vk.verify(&signature, &msg).is_ok();
    resbool as _
}
