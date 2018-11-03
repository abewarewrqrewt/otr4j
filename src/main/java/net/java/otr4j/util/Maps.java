/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

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

    /**
     * Test for requirement of min number of entries in the provided map.
     *
     * @param minimum the minimum number
     * @param map     the map to be verified
     * @param <K>     the type of keys
     * @param <V>     the type of values
     * @return Returns the same map iff it meets specified requirements.
     * @throws IllegalArgumentException In case provided map does not meet minimum requirements.
     */
    @Nonnull
    public static <K, V> Map<K, V> requireMinEntries(final int minimum, @Nonnull final Map<K, V> map) {
        final int size = map.size();
        if (size < minimum) {
            throw new IllegalArgumentException("Expected at minimum " + minimum + " entries. Got only " + size + " entries.");
        }
        return map;
    }
}
