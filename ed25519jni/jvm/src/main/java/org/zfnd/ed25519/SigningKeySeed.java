package org.zfnd.ed25519;

import java.util.Arrays;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// Java wrapper class for signing key seeds that performs some sanity checking.
public class SigningKeySeed {
    public static final int SEED_LENGTH = 32;
    private static final Logger logger = LoggerFactory.getLogger(SigningKeySeed.class);
    private byte[] seed = new byte[SEED_LENGTH];

    // Determining if bytes are valid is pretty trivial. Rust code not needed.
    private static boolean bytesAreValid(final byte[] seedBytes) {
        boolean valid = false;
        if(seedBytes.length == SEED_LENGTH) {
            for (int b = 0; b < SEED_LENGTH; b++) {
                if (seedBytes[b] != 0) {
                    valid = true;
                    break;
                }
            }
        }

        return valid;
    }

    public SigningKeySeed(final byte[] seedBytes) {
        if(bytesAreValid(seedBytes)) {
            seed = Arrays.copyOf(seedBytes, SEED_LENGTH);
        }
        else {
            throw new IllegalArgumentException("Attempted to create invalid signing "
                + "key seed - Bytes were invalid");
        }
    }

    public byte[] getSigningKeySeed() {
        return seed;
    }

    public static Optional<SigningKeySeed> fromBytes(final byte[] seedBytes) {
        Optional<SigningKeySeed> sks = Optional.empty();

        try {
            sks = Optional.of(new SigningKeySeed(seedBytes));
        }
        catch (IllegalArgumentException e) {
            logger.error("Attempted to create invalid signing key seed - Illegal "
                + "argument exception has been caught and ignored");
        }
        finally {
            return sks;
        }
    }

    public static SigningKeySeed fromBytesOrThrow(final byte[] seedBytes) {
        // The constructor already throws, so this method can YOLO the creation.
        return new SigningKeySeed(seedBytes);
    }
}
