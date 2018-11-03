/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.util;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;

import static java.util.Objects.requireNonNull;

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

    /**
     * Contains search for an element of type E in an array E[]. This is a naive search and is meant to be used only for
     * small arrays where this cannot become a performance issue. The function is there for convenience over the typical
     * approach of sorting-then-binary-searching.
     *
     * 'e' is expected to be non-null. To search for null, try {@link #containsEmpty(Object[])}.
     *
     * @param e    The (non-null) element to search for.
     * @param data The data array to look in.
     * @param <E>  The type of data.
     * @return Returns true iff e is found, or false otherwise.
     */
    @CheckReturnValue
    public static <E> boolean contains(@Nonnull final E e, @Nonnull final E[] data) {
        requireNonNull(e);
        for (final E i : data) {
            if (e.equals(i)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Contains search for an int in an int-array. This is a naive search and is meant to be used only for small arrays
     * where this cannot become a performance issue. The function is there for convenience over the typical approach of
     * sorting-then-binary-searching.
     *
     * @param e    The int value to search for.
     * @param data The data array to look in.
     * @return Returns true iff e is found, or false otherwise.
     */
    @CheckReturnValue
    public static boolean contains(final int e, @Nonnull final int[] data) {
        for (final int v : data) {
            if (e == v) {
                return true;
            }
        }
        return false;
    }
}
