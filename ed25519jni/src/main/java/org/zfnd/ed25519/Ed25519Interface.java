package org.zfnd.ed25519;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.scijava.nativelib.NativeLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Ed25519Interface {
  public static final int SEED_LEN = 32;

  private static final Logger logger;
  private static final boolean enabled;

  static {
    logger = LoggerFactory.getLogger(Ed25519Interface.class);
    boolean isEnabled = true;

    try {
      NativeLoader.loadLibrary("ed25519jni");
    } catch (java.io.IOException | UnsatisfiedLinkError e) {
      logger.error("Could not find ed25519jni - Interface is not enabled - ", e);
      isEnabled = false;
    }
    enabled = isEnabled;
  }

  // Helper method to determine whether the Ed25519 Rust backend is loaded and
  // available.
  //
  // @return whether the Ed25519 Rust backend is enabled
  public static boolean isEnabled() {
    return enabled;
  }

  // Generate a new Ed25519 signing key seed and check the results for validity. This
  // code is valid but not canonical. If the Rust code ever adds restrictions on which
  // values are allowed, this code will have to stay in sync.
  //
  // @param rng An initialized, secure RNG
  // @return sks 32 byte signing key seed
  private static byte[] genSigningKeySeedFromJava(SecureRandom rng) {
    byte[] seedBytes = new byte[SEED_LEN];
    rng.nextBytes(seedBytes);
    BigInteger sb = new BigInteger(seedBytes);
    while(sb == BigInteger.ZERO) {
      rng.nextBytes(seedBytes);
      sb = new BigInteger(seedBytes);
    }

    return seedBytes;
  }

  // Public frontend to use when generating a signing key seed.
  //
  // @return sksb Java object containing an EdDSA signing key seed
  // @throws RuntimeException if ???
  public static SigningKeySeed genSigningKeySeed(SecureRandom rng) {
    return new SigningKeySeed(genSigningKeySeedFromJava(rng));
  }

  // Check if verification key bytes for a verification key are valid.
  //
  // @return true if valid, false if not
  // @param vk_bytes 32 byte verification key bytes to verify
  // @throws RuntimeException if ???
  public static native boolean checkVerificationKeyBytes(byte[] vk_bytes);

  // Get verification key bytes from a signing key seed.
  //
  // @return vkb 32 byte verification key
  // @param sk_seed_bytes 32 byte signing key seed
  // @throws RuntimeException if ???
  private static native byte[] getVerificationKeyBytes(byte[] sk_seed_bytes);

  // Get verification key bytes from a signing key seed.
  //
  // @return vkb VerificationKeyBytes object
  // @param sk_seed_bytes SigningKeySeed object
  // @throws RuntimeException if ???
  public static VerificationKeyBytes getVerificationKeyBytes(SigningKeySeed sksb) {
    return new VerificationKeyBytes(getVerificationKeyBytes(sksb.getSigningKeySeed()));
  }

  // Creates a signature on msg using the given signing key.
  //
  // @return sig 64 byte signature
  // @param sk_seed_bytes 32 byte signing key seed
  // @param msg Message of arbitrary length to be signed
  // @throws RuntimeException if ???
  private static native byte[] sign(byte[] sk_seed_bytes, byte[] msg);

  // Creates a signature on msg using the given signing key.
  //
  // @return sig 64 byte signature
  // @param sk_seed_bytes 32 byte signing key seed
  // @param msg Message of arbitrary length to be signed
  // @throws RuntimeException if ???
  public static byte[] sign(SigningKeySeed sksb, byte[] msg) {
    return sign(sksb.getSigningKeySeed(), msg);
  }

  /// Verifies a purported `signature` on the given `msg`.
  //
  // @return true if verified, false if not
  // @param vk_bytes 32 byte verification key bytes
  // @param sig 64 byte signature to be verified
  // @param msg Message of arbitrary length to be signed
  // @throws RuntimeException if ???
  private static native boolean verify(byte[] vk_bytes, byte[] sig, byte[] msg);

  /// Verifies a purported `signature` on the given `msg`.
  //
  // @return true if verified, false if not
  // @param vk_bytes 32 byte verification key bytes
  // @param sig 64 byte signature to be verified
  // @param msg Message of arbitrary length to be signed
  // @throws RuntimeException if ???
  public static boolean verify(VerificationKeyBytes vkb, byte[] sig, byte[] msg) {
    return verify(vkb.getVerificationKeyBytes(), sig, msg);
  }
}
