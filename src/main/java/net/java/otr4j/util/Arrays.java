package net.java.otr4j.util;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;

/**
 * Array utilities.
 */
public final class Arrays {

    private Arrays() {
        // No need to instantiate utility class.
    }

    /**
     * Check given data array for 'null' values. In case some index is still null, return true.
     *
     * @param data The array of data.
     * @return Returns true iff some entries are missing (contain null), false otherwise.
     */
    @CheckReturnValue
    public static boolean containsEmpty(@Nonnull final Object[] data) {
        for (final Object entry : data) {
            if (entry == null) {
                return true;
            }
        }
        return false;
    }
}
