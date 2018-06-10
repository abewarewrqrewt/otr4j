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

    @Nonnull
    public static <S, T extends Collection<S>> T requireNoIllegalValues(@Nonnull final T collection, @Nonnull final Collection<S> blacklist) {
        requireNonNull(collection);
        for (final S illegal : blacklist) {
            if (collection.contains(illegal)) {
                throw new IllegalArgumentException("Blacklisted value encountered: " + illegal);
            }
        }
        return collection;
    }

    @Nonnull
    public static <T extends Collection<?>> T requireMinElements(final int minimum, @Nonnull final T collection) {
        final int size = collection.size();
        if (size < minimum) {
            throw new IllegalArgumentException("Only " + size + " entries found. Expected " + minimum + " at minimum.");
        }
        return collection;
    }
}
