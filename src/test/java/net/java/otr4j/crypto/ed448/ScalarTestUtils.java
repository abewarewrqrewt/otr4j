package net.java.otr4j.crypto.ed448;

import javax.annotation.Nonnull;
import java.math.BigInteger;

public final class ScalarTestUtils {

    private ScalarTestUtils() {
        // No need to instantiate utility class.
    }

    @Nonnull
    public static Scalar fromBigInteger(@Nonnull final BigInteger value) {
        return Scalar.fromBigInteger(value);
    }
}
