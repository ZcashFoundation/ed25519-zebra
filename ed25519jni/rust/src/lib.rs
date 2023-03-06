use ed25519::Signature;
use ed25519_zebra::{SigningKey, VerificationKey, VerificationKeyBytes,};
use jni::{objects::{JClass, JString}, sys::{jboolean, jbyteArray, jstring}, JNIEnv,};
use pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey,};
use pkcs8::der::pem::LineEnding;
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

// SigningKeySeed bytes -> DER bytes
#[no_mangle]
pub extern "system" fn Java_org_zfnd_ed25519_Ed25519Interface_getSigningKeySeedEncoded(
    env: JNIEnv<'_>,
    _: JClass<'_>,
    sks_bytes: jbyteArray,
) -> jbyteArray {
    let res = panic::catch_unwind(|| {
        let mut sks = [0u8; 32];
        sks.copy_from_slice(&env.convert_byte_array(sks_bytes).unwrap());
        let sk = SigningKey::from(sks);

        Ok(env.byte_array_from_slice(sk.to_pkcs8_der_v1().unwrap().as_bytes()).unwrap())
    });
    unwrap_exc_or(&env, res, ptr::null_mut())
}

// SigningKeySeed bytes -> PEM string
#[no_mangle]
pub extern "system" fn Java_org_zfnd_ed25519_Ed25519Interface_getSigningKeySeedPEM(
    env: JNIEnv<'_>,
    _: JClass<'_>,
    sks_bytes: jbyteArray,
) -> jstring {
    let res = panic::catch_unwind(|| {
        let mut sks = [0u8; 32];
        sks.copy_from_slice(&env.convert_byte_array(sks_bytes).unwrap());
        let sk = SigningKey::from(sks);

        let output = env.new_string(&*sk.to_pkcs8_pem_v1(LineEnding::default()).unwrap()).expect("Couldn't create SKS PEM string!");
        Ok(output.into_inner())
    });
    unwrap_exc_or(&env, res, ptr::null_mut())
}

// DER bytes -> SigningKeySeed bytes
#[no_mangle]
pub extern "system" fn Java_org_zfnd_ed25519_Ed25519Interface_generatePrivate(
    env: JNIEnv<'_>,
    _: JClass<'_>,
    der_bytes: jbyteArray,
) -> jbyteArray {
    let res = panic::catch_unwind(|| {
        let mut der_data = [0u8; 48];
        der_data.copy_from_slice(&env.convert_byte_array(der_bytes).unwrap());
        let sk = SigningKey::from_pkcs8_der(der_data.as_ref()).unwrap();

        Ok(env.byte_array_from_slice(&sk.as_ref()).unwrap())
    });
    unwrap_exc_or(&env, res, ptr::null_mut())
}

// PEM string -> SigningKeySeed bytes
#[no_mangle]
pub extern "system" fn Java_org_zfnd_ed25519_Ed25519Interface_generatePrivatePEM(
    env: JNIEnv<'_>,
    _: JClass<'_>,
    pem_java_string: JString<'_>,
) -> jbyteArray {
    let res = panic::catch_unwind(|| {
        let pem_string: String = env.get_string(pem_java_string).expect("Couldn't get PEM Java string!").into();
        let sk = SigningKey::from_pkcs8_pem(&pem_string).unwrap();

        Ok(env.byte_array_from_slice(&sk.as_ref()).unwrap())
    });
    unwrap_exc_or(&env, res, ptr::null_mut())
}

// VerificationKeyBytes bytes -> DER bytes
#[no_mangle]
pub extern "system" fn Java_org_zfnd_ed25519_Ed25519Interface_getVerificationKeyBytesEncoded(
    env: JNIEnv<'_>,
    _: JClass<'_>,
    vk_bytes: jbyteArray,
) -> jbyteArray {
    let res = panic::catch_unwind(|| {
        let mut vk_data = [0u8; 32];
        vk_data.copy_from_slice(&env.convert_byte_array(vk_bytes).unwrap());

        let vkb = VerificationKeyBytes::try_from(vk_data).unwrap();
        let vk = VerificationKey::try_from(vkb).unwrap();
        Ok(env.byte_array_from_slice(vk.to_public_key_der().unwrap().as_ref()).unwrap())
    });
    unwrap_exc_or(&env, res, ptr::null_mut())
}

// VerificationKeyBytes bytes -> PEM string
#[no_mangle]
pub extern "system" fn Java_org_zfnd_ed25519_Ed25519Interface_getVerificationKeyBytesPEM(
    env: JNIEnv<'_>,
    _: JClass<'_>,
    vk_bytes: jbyteArray,
) -> jstring {
    let res = panic::catch_unwind(|| {
        let mut vkb = [0u8; 32];
        vkb.copy_from_slice(&env.convert_byte_array(vk_bytes).unwrap());
        let vk = VerificationKey::try_from(VerificationKeyBytes::from(vkb)).unwrap();

        let output = env.new_string(vk.to_public_key_pem(LineEnding::default()).unwrap()).expect("Couldn't create VKB PEM string!");
        Ok(output.into_inner())
    });
    unwrap_exc_or(&env, res, ptr::null_mut())
}

// DER bytes -> VerificationKeyBytes bytes
#[no_mangle]
pub extern "system" fn Java_org_zfnd_ed25519_Ed25519Interface_generatePublic(
    env: JNIEnv<'_>,
    _: JClass<'_>,
    der_bytes: jbyteArray,
) -> jbyteArray {
    let res = panic::catch_unwind(|| {
        let mut der_data = [0u8; 44];
        der_data.copy_from_slice(&env.convert_byte_array(der_bytes).unwrap());
        let vk = VerificationKey::from_public_key_der(der_data.as_ref()).unwrap();

        Ok(env.byte_array_from_slice(&vk.as_ref()).unwrap())
    });
    unwrap_exc_or(&env, res, ptr::null_mut())
}

// PEM string -> VerificationKeyBytes bytes
#[no_mangle]
pub extern "system" fn Java_org_zfnd_ed25519_Ed25519Interface_generatePublicPEM(
    env: JNIEnv<'_>,
    _: JClass<'_>,
    pem_java_string: JString<'_>,
) -> jbyteArray {
    let res = panic::catch_unwind(|| {
        let pem_string: String = env.get_string(pem_java_string).expect("Couldn't get VKB PEM Java string!").into();
        let vk = VerificationKey::from_public_key_pem(&pem_string).unwrap();

        Ok(env.byte_array_from_slice(&vk.as_ref()).unwrap())
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

    let vkb = VerificationKeyBytes::try_from(vk_data).unwrap();
    let vk = VerificationKey::try_from(vkb).unwrap();
    let resbool = vk.verify(&signature, &msg).is_ok();
    resbool as _
}
