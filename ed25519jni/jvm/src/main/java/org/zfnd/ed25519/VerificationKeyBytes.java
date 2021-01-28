package org.zfnd.ed25519;

import java.util.Arrays;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// Java wrapper class for verification key bytes that performs some sanity checking.
public class VerificationKeyBytes {
    private static final int BYTES_LENGTH = 32;
    private static final Logger logger = LoggerFactory.getLogger(VerificationKeyBytes.class);
    private byte[] vkb = new byte[BYTES_LENGTH];

    // Determining if bytes are valid is complicated. Call into Rust.
    private static boolean bytesAreValid(final byte[] verificationKeyBytes) {
        if(verificationKeyBytes.length == BYTES_LENGTH) {
            return Ed25519Interface.checkVerificationKeyBytes(verificationKeyBytes);
        }
        else {
            return false;
        }
    }

    public VerificationKeyBytes(final byte[] verificationKeyBytes) {
        if(bytesAreValid(verificationKeyBytes)) {
            vkb = Arrays.copyOf(verificationKeyBytes, BYTES_LENGTH);
        }
        else {
            throw new IllegalArgumentException("Attempted to create invalid "
                + "verification key bytes (input not valid)");
        }
    }

    public byte[] getVerificationKeyBytes() {
        return vkb;
    }

    public static Optional<VerificationKeyBytes> fromBytes(final byte[] verificationKeyBytes) {
        Optional<VerificationKeyBytes> vkb = Optional.empty();

        try {
            vkb = Optional.of(new VerificationKeyBytes(verificationKeyBytes));
        }
        catch (IllegalArgumentException e) {
            logger.error("Attempted to create invalid verification key bytes - Illegal "
                    + "argument exception has been caught and ignored");
        }
        finally {
            return vkb;
        }
    }

    public static VerificationKeyBytes fromBytesOrThrow(final byte[] verificationKeyBytes) {
        // The constructor already throws, so this method can YOLO the creation.
        return new VerificationKeyBytes(verificationKeyBytes);
    }
}
