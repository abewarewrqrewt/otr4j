package net.java.otr4j.util;

import javax.annotation.Nonnull;

/**
 * Utility methods for byte arrays.
 */
public final class ByteArrays {

    private ByteArrays() {
        // No need to instantiate utility class.
    }

    /**
     * Check to verify length is exactly specified length.
     *
     * @param length Expected length.
     * @param bytes  Array to verify length of.
     * @return Returns same byte array iff it matches length requirement.
     * @throws IllegalArgumentException Thrown in case the length requirement is not met.
     */
    @Nonnull
    public static byte[] requireLengthExactly(final int length, @Nonnull final byte[] bytes) {
        if (bytes.length != length) {
            throw new IllegalArgumentException("Illegal array length");
        }
        return bytes;
    }

    /**
     * Test if all bytes are zero for provided byte-array.
     *
     * @param data The byte-array to verify.
     * @return Returns true if all bytes are zero, or false otherwise.
     */
    public static boolean allZeroBytes(@Nonnull final byte[] data) {
        for (final byte b : data) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }
}
