package org.zfnd.ed25519;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.scijava.nativelib.NativeLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Interface class offering Java users access to certain ed25519-zebra functionality.
 * Uses include but are not necessarily limited to:
 *  - Generating a signing key seed (essentially a private key).
 *  - Obtaining a DER-encoded (v1, per RFC 5958) signing key seed byte array.
 *  - Obtaining a PEM-encoded (v1, per RFC 5958) signing key seed string.
 *  - Getting verification key bytes (basically a public key) from a signing key seed.
 *  - Obtaining a DER-encoded (v1, per RFC 5958) verification key byte structure.
 *  - Obtaining a PEM-encoded (v1, per RFC 5958) verification key string.
 *  - Signing data with a signing key seed.
 *  - Verifying a signature with verification key bytes.
 */
public class Ed25519Interface {
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

  /**
   * Default constuctor.
   */
  public Ed25519Interface() {  }

  /**
   * Helper method to determine whether the Ed25519 Rust backend is loaded and
   * available.
   *
   * @return whether the Ed25519 Rust backend is enabled
   */
  public static boolean isEnabled() {
    return enabled;
  }

  /**
   * Generate a new Ed25519 signing key seed and check the results for validity. This
   * code is valid but not canonical. If the Rust code ever adds restrictions on which
   * values are allowed, this code will have to stay in sync.
   *
   * @param rng An initialized, secure RNG
   * @return the signing key seed bytes (32 bytes)
   */
  private static byte[] genSigningKeySeedFromJava(SecureRandom rng) {
    byte[] seedBytes = new byte[SigningKeySeed.BYTE_LENGTH];

    do {
      rng.nextBytes(seedBytes);
    } while(!SigningKeySeed.bytesAreValid(seedBytes));

    return seedBytes;
  }

  /**
   * Public frontend to use when generating a signing key seed.
   *
   * @param rng source of entropy for key material
   * @return instance of SigningKeySeed containing an EdDSA signing key seed
   */
  public static SigningKeySeed genSigningKeySeed(SecureRandom rng) {
    return new SigningKeySeed(genSigningKeySeedFromJava(rng));
  }

  /**
   * Get the encoded DER (RFC 8410) bytes for signing key seed bytes.
   *
   * @param sks the signing key seed bytes
   * @return the encoded DER bytes
   */
  public static native byte[] getSigningKeySeedEncoded(byte[] sks);

  /**
   * Get the encoded DER (RFC 8410) bytes for signing key seed bytes.
   *
   * @param sks the signing key seed
   * @return the encoded DER bytes
   */
  public static byte[] getSigningKeySeedEncoded(SigningKeySeed sks) {
    return getSigningKeySeedEncoded(sks.getSigningKeySeedCopy());
  }

  /**
   * Get the encoded PEM (RFC 8410) string for signing key seed bytes.
   *
   * @param sks the signing key seed bytes
   * @return the encoded PEM string
   */
  public static native String getSigningKeySeedPEM(byte[] sks);

  /**
   * Get the encoded PEM (RFC 8410) string for signing key seed bytes.
   *
   * @param sks the signing key seed
   * @return the encoded PEM string
   */
  public static String getSigningKeySeedPEM(SigningKeySeed sks) {
    return getSigningKeySeedPEM(sks.getSigningKeySeedCopy());
  }

  /**
   * Generate a SigningKeySeed object from DER (RFC 8410) bytes.
   *
   * @param derBytes the encoded DER bytes (48 bytes)
   * @return a new SigningKeySeed object
   */
  public static native byte[] generatePrivate(byte[] derBytes);

  /**
   * Generate a SigningKeySeed object from a PEM (RFC 8410) string.
   *
   * @param pemString the encoded PEM string
   * @return a new SigningKeySeed object
   */
  public static native byte[] generatePrivatePEM(String pemString);

  /**
   * Check if verification key bytes for a verification key are valid.
   *
   * @param vk_bytes 32 byte verification key bytes to verify
   * @return true if valid, false if not
   */
  public static native boolean checkVerificationKeyBytes(byte[] vk_bytes);

  /**
   * Get verification key bytes from a signing key seed.
   *
   * @param sk_seed_bytes 32 byte signing key seed
   * @return 32 byte verification key
   * @throws RuntimeException on error in libed25519
   */
  private static native byte[] getVerificationKeyBytes(byte[] sk_seed_bytes);

  /**
   * Get verification key bytes from a signing key seed.
   *
   * @param seed signing key seed
   * @return verification key bytes
   */
  public static VerificationKeyBytes getVerificationKeyBytes(SigningKeySeed seed) {
    return new VerificationKeyBytes(getVerificationKeyBytes(seed.getSigningKeySeed()));
  }

  /**
   * Get the encoded DER (RFC 8410) bytes for verification key bytes.
   *
   * @param vkb the verification key byte array
   * @return the encoded DER bytes (44 bytes)
   */
  public static native byte[] getVerificationKeyBytesEncoded(byte[] vkb);

  /**
   * Get the encoded DER (RFC 8410) bytes for verification key bytes.
   *
   * @param vkb the verification key bytes
   * @return the encoded DER bytes (44 bytes)
   */
  public static byte[] getVerificationKeyBytesEncoded(VerificationKeyBytes vkb) {
    return getVerificationKeyBytesEncoded(vkb.getVerificationKeyBytes());
  }

  /**
   * Get the encoded PEM (RFC 8410) bytes for verification key bytes.
   *
   * @param vkb the verification key bytes
   * @return the encoded PEM bytes
   */
  public static native String getVerificationKeyBytesPEM(byte[] vkb);

  /**
   * Get the encoded PEM (RFC 8410) bytes for verification key bytes.
   *
   * @param vkb the verification key bytes
   * @return the encoded PEM string
   */
  public static String getVerificationKeyBytesPEM(VerificationKeyBytes vkb) {
    return getVerificationKeyBytesPEM(vkb.getVerificationKeyBytes());
  }

  /**
   * Generate a VerificationKeyBytes object from DER (RFC 8410) bytes.
   *
   * @param derBytes the encoded DER bytes (44 bytes)
   * @return a new VerificationKeyBytes object
   */
  public static native byte[] generatePublic(byte[] derBytes);

  /**
   * Generate a VerificationKeyBytes object from PEM (RFC 8410) bytes.
   *
   * @param pemString the encoded PEM string
   * @return a new VerificationKeyBytes object
   */
  public static native byte[] generatePublicPEM(String pemString);

  /**
   * Creates a signature on msg using the given signing key.
   *
   * @param sk_seed_bytes 32 byte signing key seed
   * @param msg Message of arbitrary length to be signed
   * @return signature data
   * @throws RuntimeException on error in libed25519
   */
  private static native byte[] sign(byte[] sk_seed_bytes, byte[] msg);

  /**
   * Creates a signature on message using the given signing key.
   *
   * @param seed signing key seed
   * @param message Message of arbitrary length to be signed
   * @return signature data
   * @throws RuntimeException on error in libed25519
   */
  public static Signature sign(SigningKeySeed seed, byte[] message) {
    return new Signature(sign(seed.getSigningKeySeed(), message));
  }

  /**
   * Verifies a purported `signature` on the given `msg`.
   *
   * @param vk_bytes 32 byte verification key bytes
   * @param sig 64 byte signature to be verified
   * @param msg Message of arbitrary length to be signed
   * @return true if verified, false if not
   * @throws RuntimeException on error in libed25519
   */
  private static native boolean verify(byte[] vk_bytes, byte[] sig, byte[] msg);

  /**
   * Verifies a purported `signature` on the given `message` with `verificationKey`.
   *
   * @param verificationKey verification key bytes
   * @param signature 64 byte signature to be verified
   * @param message message of arbitrary length to be signed
   * @return true if verified, false if not
   * @throws RuntimeException on error in libed25519
   */
  public static boolean verify(VerificationKeyBytes verificationKey, Signature signature, byte[] message) {
    return verify(verificationKey.getVerificationKeyBytes(), signature.getSignatureBytes(), message);
  }
}
