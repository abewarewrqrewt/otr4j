/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.util;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Utilities for Iterables.
 */
public final class Iterables {

    private Iterables() {
        // No need to instantiate utility class.
    }

    /**
     * Find instance by its type and return instance safely casted to its specific (sub)type.
     * <p>
     * The method expects to actually find an instance. In case no instance is found in the Iterable, an
     * {@link IllegalArgumentException} is thrown.
     *
     * @param iterable  The iterable to be searched.
     * @param fieldType The element type to find.
     * @param <T>       The type of elements contained in the iterable.
     * @param <S>       The type of element to find, expected to be a subtype of T.
     * @return Returns found element.
     * @throws IllegalArgumentException In case instance cannot be found.
     */
    @Nonnull
    public static <T, S extends T> S findByType(@Nonnull final Iterable<T> iterable, @Nonnull final Class<S> fieldType) {
        for (final T field : iterable) {
            if (fieldType.isInstance(field)) {
                return fieldType.cast(field);
            }
        }
        throw new IllegalArgumentException("Cannot find instance of specified class.");
    }

    /**
     * Find instance by its type and return instance safely casted to its specific (sub)type. Otherwise return default.
     *
     * @param iterable     The iterable to be searched.
     * @param fieldType    The element type to find.
     * @param <T>          The type of elements contained in the iterable.
     * @param <S>          The type of element to find, expected to be a subtype of T.
     * @param defaultValue The default value in case no element was found.
     * @return Returns found element or default. (Only returns null if default value is null.)
     */
    @Nullable
    public static <T, S extends T> S findByType(@Nonnull final Iterable<T> iterable, @Nonnull final Class<S> fieldType,
            @Nullable final S defaultValue) {
        for (final T field : iterable) {
            if (fieldType.isInstance(field)) {
                return fieldType.cast(field);
            }
        }
        return defaultValue;
    }
}
