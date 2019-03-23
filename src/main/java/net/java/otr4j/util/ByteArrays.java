/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.util;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.io.ByteArrayOutputStream;
import java.util.Locale;

import static java.util.Objects.requireNonNull;
import static org.bouncycastle.util.Arrays.constantTimeAreEqual;

/**
 * Utility methods for byte arrays.
 */
// FIXME adopt CanIgnoreReturnValue.
// FIXME adopt CheckReturnValue from Error-Prone.
public final class ByteArrays {

    /**
     * Index for hexadecimal symbols.
     */
    private static final char[] HEX_ENCODER = {'0', '1', '2', '3', '4', '5',
        '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

    /**
     * Index for decoding hexadecimal values.
     */
    private static final String HEX_DECODER = "0123456789ABCDEF";

    private ByteArrays() {
        // No need to instantiate utility class.
    }

    /**
     * Check to verify length is exactly specified length.
     *
     * @param length Expected length.
     * @param bytes  Array to verify length of.
     * @return Returns same byte-array iff it matches length requirement.
     * @throws IllegalArgumentException Thrown in case the length requirement is not met.
     */
    @Nonnull
    public static byte[] requireLengthExactly(final int length, @Nonnull final byte[] bytes) {
        if (bytes.length != length) {
            throw new IllegalArgumentException("Illegal array length: " + bytes.length);
        }
        return bytes;
    }

    /**
     * Check to verify length is at least specified minimum length.
     *
     * @param minLength The minimum length (inclusive)
     * @param bytes     The source bytes to verify.
     * @return Returns same byte-array iff it matches length requirements.
     */
    @Nonnull
    public static byte[] requireLengthAtLeast(final int minLength, @Nonnull final byte[] bytes) {
        if (bytes.length < minLength) {
            throw new IllegalArgumentException("Illegal array length: " + bytes.length);
        }
        return bytes;
    }

    /**
     * Test if all bytes are zero for provided byte-array.
     *
     * @param data The byte-array to verify.
     * @return Returns true if all bytes are zero, or false otherwise.
     */
    @CheckReturnValue
    public static boolean allZeroBytes(@Nonnull final byte[] data) {
        for (final byte b : data) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * Test equality of two byte arrays using constant-time method. Throws an IllegalArgumentException in case both
     * arrays are same instance. Inputs cannot be null and must be equal length.
     *
     * @param data1 The first byte array.
     * @param data2 The second byte array.
     * @return Returns true iff both byte arrays have same contents (and same length).
     */
    @CheckReturnValue
    public static boolean constantTimeEquals(@Nonnull final byte[] data1, @Nonnull final byte[] data2) {
        if (requireNonNull(data1) == requireNonNull(data2)) {
            throw new IllegalArgumentException("BUG: Same instance is compared.");
        }
        return constantTimeEqualsOrSame(data1, data2);
    }

    /**
     * Test equality of two byte arrays using constant-time method. Inputs cannot be null and must be equal length.
     *
     * @param data1 The first byte array.
     * @param data2 The second byte array.
     * @return Returns true iff both byte arrays have same contents (and same length).
     */
    @CheckReturnValue
    public static boolean constantTimeEqualsOrSame(@Nonnull final byte[] data1, @Nonnull final byte[] data2) {
        requireNonNull(data1);
        requireNonNull(data2);
        assert !allZeroBytes(data1) : "Expected non-zero bytes for data1. This may indicate that a critical bug is present, or it may be a false warning.";
        assert !allZeroBytes(data2) : "Expected non-zero bytes for data1. This may indicate that a critical bug is present, or it may be a false warning.";
        return constantTimeAreEqual(data1, data2);
    }

    /**
     * Convert byte-array value to hexadecimal string representation.
     *
     * @param in value as byte-array
     * @return Returns hexadecimal string representation.
     */
    @Nonnull
    public static String toHexString(@Nonnull final byte[] in) {
        final StringBuilder out = new StringBuilder(in.length * 2);
        for (final byte b : in) {
            out.append(HEX_ENCODER[(b >>> 4) & 0x0F]);
            out.append(HEX_ENCODER[b & 0x0F]);
        }
        return out.toString();
    }

    /**
     * Convert hexadecimal string to byte-array.
     *
     * @param v A hexadecimal value in string representation. (Restriction: v should contain an even number of
     *          hexadecimal characters.)
     * @return Returns byte-array with byte-representation for input.
     */
    @Nonnull
    public static byte[] fromHexString(@Nonnull final String v) {
        final String value = v.toUpperCase(Locale.US);
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int index = 0; index < value.length(); index += 2) {
            final int high = HEX_DECODER.indexOf(value.charAt(index));
            final int low = HEX_DECODER.indexOf(value.charAt(index + 1));
            out.write((high << 4) + low);
        }
        return out.toByteArray();
    }
}
