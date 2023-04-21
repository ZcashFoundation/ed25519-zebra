package org.zfnd.ed25519;

import java.util.Arrays;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Java wrapper class for verification key bytes that performs some sanity checking.
 */
public class VerificationKeyBytes {
    /**
     * Length of verification keys.
     **/
    public static final int BYTE_LENGTH = 32;
    private static final Logger logger = LoggerFactory.getLogger(VerificationKeyBytes.class);

    private byte[] vkb;

    // Determining if bytes are valid is complicated. Call into Rust.
    static boolean bytesAreValid(final byte[] verificationKeyBytes) {
        return (verificationKeyBytes.length == BYTE_LENGTH) && Ed25519Interface.checkVerificationKeyBytes(verificationKeyBytes);
    }

    VerificationKeyBytes(final byte[] verificationKeyBytes) {
        // package protected constructor
        // assumes valid values from us or underlying library and that the caller will not mutate them
        this.vkb = verificationKeyBytes;
    }

    /**
     * Get a copy of the actual verification key bytes.
     *
     * @return a byte array with a copy of the wrapped bytes
     */
    public byte[] getVerificationKeyBytesCopy() {
        return vkb.clone();
    }

    byte[] getVerificationKeyBytes() {
        return vkb;
    }

    /**
     * Generate a VerificationKeyBytes object from DER (RFC 8410) bytes.
     *
     * @param derBytes the encoded DER bytes
     * @return a new VerificationKeyBytes object
     */
    public static VerificationKeyBytes generatePublic(byte[] derBytes) {
        return VerificationKeyBytes.fromBytesOrThrow(Ed25519Interface.generatePublic(derBytes));
    }

    /**
     * Generate a VerificationKeyBytes object from PEM (RFC 8410) bytes.
     *
     * @param pemString the encoded PEM string
     * @return a new VerificationKeyBytes object
     */
    public static VerificationKeyBytes generatePublicPEM(String pemString) {
        return VerificationKeyBytes.fromBytesOrThrow(Ed25519Interface.generatePublicPEM(pemString));
    }

    /**
     * Get the encoded DER (RFC 8410) bytes for verification key bytes.
     *
     * @return the encoded DER bytes
     */
    public byte[] getEncoded() {
        return Ed25519Interface.getVerificationKeyBytesEncoded(this);
    }

    /**
     * Get the encoded PEM (RFC 8410) bytes for verification key bytes.
     *
     * @return the encoded PEM bytes
     */
    public String getPEM() {
        return Ed25519Interface.getVerificationKeyBytesPEM(this);
    }

    /**
     * Optionally convert bytes into a verification key wrapper.
     *
     * @param bytes untrusted, unvalidated bytes that may be an encoding of a verification key
     * @return optionally a verification key wrapper, if bytes are valid
     */
    public static Optional<VerificationKeyBytes> fromBytes(final byte[] bytes) {
        // input is mutable and from untrusted source, so take a copy
        final byte[] cloneBytes = bytes.clone();

        if (bytesAreValid(cloneBytes)) {
            return Optional.of(new VerificationKeyBytes(cloneBytes));
        }
        else {
            return Optional.empty();
        }
    }

    /**
     * Convert bytes into a verification key wrapper.
     *
     * @param bytes bytes that are expected be an encoding of a verification key
     * @return a verification key wrapper, if bytes are valid
     * @throws IllegalArgumentException if bytes are invalid
     */
    public static VerificationKeyBytes fromBytesOrThrow(final byte[] bytes) {
        return fromBytes(bytes)
            .orElseThrow(() -> new IllegalArgumentException("Expected " + BYTE_LENGTH + " bytes that encode a verification key!"));
    }

    /**
     * Get the verification key algorithm name.
     *
     * @return the verification key algorithm name
     */
    public static String getAlgorithm() {
        return "EdDSA";
    }

    /**
     * Get the verification key algorithm format.
     *
     * @return the verification key algorithm format
     */
    public static String getFormat() {
        return "X.509";
    }

    @Override
    public boolean equals(final Object other) {
        if (other == this) {
            return true;
        } else if (other instanceof VerificationKeyBytes) {
            final VerificationKeyBytes that = (VerificationKeyBytes) other;
            return Arrays.equals(that.vkb, this.vkb);
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {
        return 23 * Arrays.hashCode(this.vkb);
    }
}
