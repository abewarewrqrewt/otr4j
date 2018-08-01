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
public final class ByteArrays {

    /**
     * Index for hexadecimal symbols.
     */
    private static final char HEX_ENCODER[] = {'0', '1', '2', '3', '4', '5',
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
     * @return Returns same byte array iff it matches length requirement.
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
     * arrays are same instance. Inputs cannot be null.
     *
     * @param data1 The first byte array.
     * @param data2 The second byte array.
     * @return Returns true iff both byte arrays have same contents (and same length).
     */
    // TODO constantTimeEquals is applied in all reasonable cases. We need to ensure 'equals' methods are also considerate of same instances. Do we really want to accept same instances everywhere?
    @CheckReturnValue
    public static boolean constantTimeEquals(@Nonnull final byte[] data1, @Nonnull final byte[] data2) {
        if (requireNonNull(data1) == requireNonNull(data2)) {
            throw new IllegalArgumentException("BUG: Same instance is compared.");
        }
        return constantTimeAreEqual(data1, data2);
    }

    @Nonnull
    public static String toHexString(@Nonnull final byte in[]) {
        final StringBuilder out = new StringBuilder(in.length * 2);
        for (final byte b : in) {
            out.append(HEX_ENCODER[(b >>> 4) & 0x0F]);
            out.append(HEX_ENCODER[b & 0x0F]);
        }
        return out.toString();
    }

    @Nonnull
    public static byte[] fromHexString(@Nonnull String value) {
        value = value.toUpperCase(Locale.US);
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int index = 0; index < value.length(); index += 2) {
            final int high = HEX_DECODER.indexOf(value.charAt(index));
            final int low = HEX_DECODER.indexOf(value.charAt(index + 1));
            out.write((high << 4) + low);
        }
        return out.toByteArray();
    }
}
