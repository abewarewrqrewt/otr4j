package net.java.otr4j.util;

import javax.annotation.Nonnull;
import java.util.Collection;

public final class Collections {

    private Collections() {
        // No need to instantiate utility class.
    }

    @SafeVarargs
    @Nonnull
    public static <S, T extends Collection<S>> T requireNoIllegalValues(@Nonnull final T collection, final S... illegals) {
        for (final S illegal : illegals) {
            if (collection.contains(illegal)) {
                throw new IllegalArgumentException("Illegal OTR version encountered: " + illegal);
            }
        }
        return collection;
    }
}
