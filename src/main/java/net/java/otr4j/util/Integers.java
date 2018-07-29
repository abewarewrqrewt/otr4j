package net.java.otr4j.util;

import javax.annotation.Nonnull;
import java.math.BigInteger;

/**
 * Utility methods for integers.
 */
public final class Integers {

    private Integers() {
        // No need to instantiate utility class.
    }

    /**
     * Require an integer value to be at least specified value (inclusive). If not, throw an exception.
     *
     * @param minInclusive Minimum acceptable value.
     * @param value        Value to check.
     * @return Returns same value as provided iff it passes minimum bound check.
     * @throws IllegalArgumentException Throws IllegalArgumentException in case value does not pass check.
     */
    public static int requireAtLeast(final int minInclusive, final int value) {
        if (value < minInclusive) {
            throw new IllegalArgumentException("value is expected to be at minimum " + minInclusive + ", but was " + value);
        }
        return value;
    }

    /**
     * Parse unsigned integer textual value-representation. All 32 bits are used, the resulting integer may have a
     * negative value.
     *
     * @param text Textual representation of integer value.
     * @param radix Radix for parsing.
     * @return Returns integer value between 0 and 0xffffffff. (That is, all 32 bits are used. So might be negative.)
     */
    public static int parseUnsignedInt(@Nonnull final String text, final int radix) {
        return new BigInteger(text, radix).intValue();
    }
}
