/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.crypto.ed448;

import javax.annotation.Nonnull;
import java.security.SecureRandom;

import static net.java.otr4j.crypto.ed448.Scalar.SCALAR_LENGTH_BYTES;
import static net.java.otr4j.crypto.ed448.Scalar.decodeScalar;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;
import static net.java.otr4j.util.SecureRandoms.randomBytes;

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
     * Generate a new random value in Z_q.
     *
     * @param random SecureRandom instance
     * @return Returns a newly generated random value.
     */
    // FIXME move this method out, this method does not rely on internals.
    public static Scalar generateRandomValueInZq(@Nonnull final SecureRandom random) {
        // FIXME OTRv4 now documents that you should always hash the random value, so we should make it part of this.
        return decodeScalar(randomBytes(random, new byte[SCALAR_LENGTH_BYTES]));
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
    static void prune(@Nonnull final byte[] privateKeySourceData) {
        requireLengthExactly(SCALAR_LENGTH_BYTES, privateKeySourceData);
        privateKeySourceData[0] &= 0b11111100;
        privateKeySourceData[SCALAR_LENGTH_BYTES - 1] = 0;
        privateKeySourceData[SCALAR_LENGTH_BYTES - 2] |= 0b10000000;
    }
}
