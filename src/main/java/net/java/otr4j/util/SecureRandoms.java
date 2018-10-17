package net.java.otr4j.util;

import javax.annotation.Nonnull;
import java.security.SecureRandom;

/**
 * Utility class for SecureRandom.
 */
public final class SecureRandoms {

    private SecureRandoms() {
        // No need to instantiate utility class.
    }

    /**
     * Fill provided byte-array with random data from provided {@link SecureRandom} instance. This is a convenience
     * function that can be used in-line for field or variable instantiation.
     *
     * @param random a SecureRandom instance
     * @param dest   The destination byte-array to be fully filled with random
     *               data.
     * @return Returns 'dest' filled with random data.
     */
    @Nonnull
    public static byte[] randomBytes(@Nonnull final SecureRandom random, @Nonnull final byte[] dest) {
        random.nextBytes(dest);
        return dest;
    }
}
