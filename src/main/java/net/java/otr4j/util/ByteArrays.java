package net.java.otr4j.util;

import javax.annotation.Nonnull;

import static java.util.Arrays.fill;

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
     * Clear zeroes all bytes in the array.
     *
     * @param array the byte array to be cleared.
     */
    // FIXME deprecate and use BC Arrays.clear method.
    public static void clear(@Nonnull final byte[] array) {
        fill(array, (byte) 0x00);
    }
}
