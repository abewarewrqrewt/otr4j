package net.java.otr4j.util;

import javax.annotation.Nonnull;
import java.util.Map;

/**
 * Utilities for Map.
 */
public final class Maps {

    private Maps() {
        // No need to instantiate utility class.
    }

    @Nonnull
    public static <K, V> Map<K, V> requireMinEntries(final int minimum, @Nonnull final Map<K, V> map) {
        final int size = map.size();
        if (size < minimum) {
            throw new IllegalArgumentException("Expected at minimum " + minimum + " entries. Got only " + size + " entries.");
        }
        return map;
    }
}
