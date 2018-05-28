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
     * Check to verify length is zero or exactly as specified.
     *
     * @param length Expected length, in case not zero-length.
     * @param bytes  Array to verify length of.
     * @return Returns same byte array iff it matches length requirements. (zero, or as specified)
     * @throws IllegalArgumentException In case bytes do not match requirements.
     */
    // FIXME add unit tests
    @Nonnull
    public static byte[] requireZeroOrLengthExactly(final int length, @Nonnull final byte[] bytes) {
        if (bytes.length != 0 && bytes.length != length) {
            throw new IllegalArgumentException("Illegal array length");
        }
        return bytes;
    }
}
