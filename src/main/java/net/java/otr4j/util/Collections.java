package net.java.otr4j.util;

import javax.annotation.Nonnull;
import java.util.Collection;

import static java.util.Objects.requireNonNull;

/**
 * Utilities for Collections.
 */
public final class Collections {

    private Collections() {
        // No need to instantiate utility class.
    }

    /**
     * Require certain illegal values to not be present in the provided collection. If present, throw an
     * IllegalArgumentException.
     *
     * @param blacklist  The "blacklist" of illegal values.
     * @param collection The collection to verify.
     * @param <S>        The base type of elements in the blacklist.
     * @param <T>        The type of collection to be verified. (Preserves type upon returning.)
     * @return Returns same collection as provided iff no illegal values are present.
     * @throws IllegalArgumentException In case illegal values are present.
     */
    @Nonnull
    public static <S, T extends Collection<S>> T requireNoIllegalValues(@Nonnull final Collection<S> blacklist,
            @Nonnull final T collection) {
        requireNonNull(collection);
        for (final S illegal : blacklist) {
            if (collection.contains(illegal)) {
                throw new IllegalArgumentException("Blacklisted value encountered: " + illegal);
            }
        }
        return collection;
    }

    /**
     * Require a minimum number of elements to be present in the provided collection.
     *
     * @param minimum    The expected minimum number of elements.
     * @param collection The collection to be verified.
     * @param <T>        The type of collection to be verified. (Preserves type upon returning.)
     * @return Returns same collection as provided iff minimum bound is satisfied.
     * @throws IllegalArgumentException In case minimum bound is not satisfied.
     */
    @Nonnull
    public static <T extends Collection<?>> T requireMinElements(final int minimum, @Nonnull final T collection) {
        final int size = collection.size();
        if (size < minimum) {
            throw new IllegalArgumentException("Only " + size + " entries found. Expected " + minimum + " at minimum.");
        }
        return collection;
    }

    /**
     * Require specified elements to be present in provided collection.
     *
     * @param elements   The elements that are expected to be present.
     * @param collection The collection to be verified.
     * @param <E>        The base type of the elements.
     * @param <T>        The type of the collection to be verified.
     * @return Returns same collection as provided iff all expected elements are present.
     * @throws IllegalArgumentException In case expected elements are not present.
     */
    @Nonnull
    public static <E, T extends Collection<? super E>> T requireElements(@Nonnull final Collection<E> elements,
            @Nonnull final T collection) {
        if (!collection.containsAll(elements)) {
            throw new IllegalArgumentException("Expected elements certain elements to be present, but these are missing.");
        }
        return collection;
    }
}
