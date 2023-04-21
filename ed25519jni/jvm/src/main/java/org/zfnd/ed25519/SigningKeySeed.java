package org.zfnd.ed25519;

import java.util.Arrays;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Java wrapper class for signing key seeds that performs some sanity checking.
 */
public class SigningKeySeed {
    /**
     * Length of signing key seeds.
     **/
    public static final int BYTE_LENGTH = 32;
    private static final Logger logger = LoggerFactory.getLogger(SigningKeySeed.class);

    private byte[] seed;

    // Determining if bytes are valid is pretty trivial. Rust code not needed.
    static boolean bytesAreValid(final byte[] seedBytes) {
        if(seedBytes.length == BYTE_LENGTH) {
            for (int b = 0; b < BYTE_LENGTH; b++) {
                if (seedBytes[b] != 0) {
                    return true;
                }
            }
        }

        return false;
    }

    SigningKeySeed(final byte[] seed) {
        // package protected constructor
        // assumes valid values from us or underlying library and that the caller will not mutate them
        this.seed = seed;
    }

    /**
     * Get a copy of the actual signing key seed bytes.
     *
     * @return a byte array copy of the wrapped bytes
     */
    public byte[] getSigningKeySeedCopy() {
        return seed.clone();
    }

    byte[] getSigningKeySeed() {
        return seed;
    }

    /**
     * Generate a SigningKeySeed object from DER (RFC 8410) bytes.
     *
     * @param derBytes the encoded DER bytes
     * @return a new SigningKeySeed object
     */
    public static SigningKeySeed generatePrivate(byte[] derBytes) {
        return SigningKeySeed.fromBytesOrThrow(Ed25519Interface.generatePrivate(derBytes));
    }

    /**
     * Generate a SigningKeySeed object from PEM (RFC 5958) bytes.
     *
     * @param pemString the encoded PEM string
     * @return a new SigningKeySeed object
     */
    public static SigningKeySeed generatePrivatePEM(String pemString) {
        return SigningKeySeed.fromBytesOrThrow(Ed25519Interface.generatePrivatePEM(pemString));
    }

    /**
     * Get the encoded DER (RFC 8410) bytes for signing key seed bytes.
     *
     * @return the encoded DER bytes
     */
    public byte[] getEncoded() {
        return Ed25519Interface.getSigningKeySeedEncoded(this);
    }

    /**
     * Get the encoded PEM (RFC 5958) bytes for signing key seed bytes.
     *
     * @return the encoded PEM bytes
     */
    public String getPEM() {
        return Ed25519Interface.getSigningKeySeedPEM(this);
    }

    /**
     * Get the signing key algorithm name.
     *
     * @return the signing key algorithm name
     */
    public static String getAlgorithm() {
        return "EdDSA";
    }

    /**
     * Get the signing key format.
     *
     * @return the signing key algorithm format
     */
    public static String getFormat() {
        return "PKCS#8";
    }

    /**
     * Optionally convert bytes into a signing key seed wrapper.
     *
     * @param bytes untrusted, unvalidated bytes that may be a valid signing key seed
     * @return optionally a signing key seed wrapper, if bytes are valid
     */
    public static Optional<SigningKeySeed> fromBytes(final byte[] bytes) {
        // input is mutable and from untrusted source, so take a copy
        final byte[] cloneBytes = bytes.clone();

        if (bytesAreValid(cloneBytes)) {
            return Optional.of(new SigningKeySeed(cloneBytes));
        }
        else {
            return Optional.empty();
        }
    }

    /**
     * Convert bytes into a signing key seed wrapper.
     *
     * @param bytes bytes that are expected be a valid signing key seed
     * @return a signing key seed wrapper, if bytes are valid
     * @throws IllegalArgumentException if bytes are invalid
     */
    public static SigningKeySeed fromBytesOrThrow(final byte[] bytes) {
        return fromBytes(bytes)
            .orElseThrow(() -> new IllegalArgumentException("Expected " + BYTE_LENGTH + " bytes where not all are zero!"));
    }
}
