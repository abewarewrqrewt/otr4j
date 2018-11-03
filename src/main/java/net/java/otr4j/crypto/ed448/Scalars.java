/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.crypto.ed448;

/**
 * Utility class for {@link Scalar}.
 */
public final class Scalars {

    /**
     * Scalar value representing zero.
     */
    private static final byte[] ZERO = new byte[] {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    /**
     * Scalar value representing one.
     */
    private static final byte[] ONE = new byte[] {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    private Scalars() {
        // No need to instantiate utility.
    }

    /**
     * Scalar with value zero.
     *
     * @return Returns new scalar representing 0.
     */
    public static Scalar zero() {
        return new Scalar(ZERO.clone());
    }

    /**
     * Scalar with value one.
     *
     * @return Returns new scalar representing 1.
     */
    public static Scalar one() {
        return new Scalar(ONE.clone());
    }
}
