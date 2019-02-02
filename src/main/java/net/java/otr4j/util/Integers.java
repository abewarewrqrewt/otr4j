/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

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
     * Require an integer value to be different than the forbidden value.
     *
     * @param forbidden the forbidden value
     * @param value     the value to be verified
     * @return Returns value iff not equal to the forbidden value.
     */
    // FIXME write unit tests
    public static int requireNotEquals(final int forbidden, final int value) {
        if (value == forbidden) {
            throw new IllegalArgumentException("value must not be: " + forbidden);
        }
        return value;
    }

    /**
     * Verify that value is in specified range.
     *
     * @param minInclusive the minimum value (inclusive)
     * @param maxInclusive the maximum value (inclusive)
     * @param value        the value to verify
     * @return Returns {@code value} in case in range.
     * @throws IllegalArgumentException In case of illegal value.
     */
    public static int requireInRange(final int minInclusive, final int maxInclusive, final int value) {
        if (value < minInclusive || value > maxInclusive) {
            throw new IllegalArgumentException("Illegal value: " + value);
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
