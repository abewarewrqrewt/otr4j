/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.crypto.ed448;

import javax.annotation.Nonnull;

import static net.java.otr4j.crypto.ed448.Scalar.SCALAR_LENGTH_BYTES;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;

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

    /**
     * Pruning of private key source data.
     * <p>
     * The procedure is described in RFC 8032, section 5.2.5. "Key Generation", step 2.
     * <pre>
     * 2.  Prune the buffer: The two least significant bits of the first
     *     octet are cleared, all eight bits the last octet are cleared, and
     *     the highest bit of the second to last octet is set.
     * </pre>
     *
     * @param privateKeySourceData Public key source data.
     * @throws IllegalArgumentException In case of invalid length of source data.
     */
    public static void prune(@Nonnull final byte[] privateKeySourceData) {
        requireLengthExactly(SCALAR_LENGTH_BYTES, privateKeySourceData);
        privateKeySourceData[0] &= 0b11111100;
        privateKeySourceData[SCALAR_LENGTH_BYTES - 1] = 0;
        privateKeySourceData[SCALAR_LENGTH_BYTES - 2] |= 0b10000000;
    }
}
