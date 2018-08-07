package net.java.otr4j.util;

import javax.annotation.Nonnull;

/**
 * String utilities.
 */
public final class Strings {

    private Strings() {
        // No need to instantiate utility class.
    }

    /**
     * Join multiple String parts into a single concatenated String.
     *
     * @param parts separated string parts
     * @return Joint string.
     */
    // FIXME write unit tests
    public static String join(@Nonnull final String[] parts) {
        final StringBuilder builder = new StringBuilder();
        for (final String part : parts) {
            builder.append(part);
        }
        return builder.toString();
    }
}
