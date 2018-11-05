/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.crypto.ed448;

import nl.dannyvanheumen.joldilocks.Points;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.security.SecureRandom;

import static net.java.otr4j.crypto.ed448.Scalar.decodeScalar;
import static net.java.otr4j.util.ByteArrays.constantTimeEqualsOrSame;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;
import static net.java.otr4j.util.SecureRandoms.randomBytes;
import static org.bouncycastle.math.ec.rfc8032.Ed448.PUBLIC_KEY_SIZE;

/**
 * Class that provides access to Ed448 constants.
 */
public final class Ed448 {

    /**
     * Identity (or neutral element) of the curve.
     */
    private static final Point IDENTITY = new Point(new byte[] {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});

    /**
     * Base Point of the curve.
     */
    private static final Point G = new Point(new byte[] {20, -6, 48, -14, 91, 121, 8, -104, -83, -56, -41, 78, 44, 19, -67, -3, -60, 57, 124, -26, 28, -1, -45, 58, -41, -62, -96, 5, 30, -100, 120, -121, 64, -104, -93, 108, 115, 115, -22, 75, 98, -57, -55, 86, 55, 32, 118, -120, 36, -68, -74, 110, 113, 70, 63, 105, 0});

    /**
     * Prime order.
     */
    private static final Scalar Q = new Scalar(new byte[] {-13, 68, 88, -85, -110, -62, 120, 35, 85, -113, -59, -115, 114, -62, 108, 33, -112, 54, -42, -82, 73, -37, 78, -60, -23, 35, -54, 124, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 63, 0});

    private Ed448() {
        // No need to instantiate utility class.
    }

    /**
     * Access base point of Ed448-Goldilocks curve.
     *
     * @return Returns base point.
     */
    @Nonnull
    public static Point basePoint() {
        return G;
    }

    /**
     * Access prime order of Ed448-Goldilocks curve.
     *
     * @return Returns prime order.
     */
    @Nonnull
    public static Scalar primeOrder() {
        return Q;
    }

    /**
     * Access identity point of Ed448-Goldilocks curve.
     *
     * @return Identity
     */
    @Nonnull
    public static Point identity() {
        return IDENTITY;
    }

    /**
     * Perform scalar multiplication by Ed448 base point.
     *
     * @param scalar the scalar value
     * @return Returns the point resulting from the multiplication.
     */
    @Nonnull
    public static Point multiplyByBase(@Nonnull final Scalar scalar) {
        return new Point(nl.dannyvanheumen.joldilocks.Ed448.multiplyByBase(scalar.toBigInteger()).encode());
    }

    /**
     * Require point to be valid.
     *
     * @param point the point to validate
     * @return Returns the same point iff it is valid.
     */
    @Nonnull
    public static Point requireValidPoint(@Nonnull final Point point) {
        if (checkIdentity(point)) {
            throw new IllegalArgumentException("Point is illegal: point is identity.");
        }
        // FIXME make full implementation of point validation.
        return point;
    }

    /**
     * Method for testing if a point is the identity point.
     *
     * @param point point
     * @return Returns true if p is identity, or false otherwise.
     */
    @CheckReturnValue
    public static boolean checkIdentity(@Nonnull final Point point) {
        requireLengthExactly(PUBLIC_KEY_SIZE, point.encoded);
        return constantTimeEqualsOrSame(IDENTITY.encoded, point.encoded);
    }

    /**
     * Verify that given point is contained in the curve.
     *
     * @param p The point to verify.
     * @return Returns true if it is contained in the curve.
     */
    // TODO: According to otrv4 spec, we can verify point is on the curve with: Given point X = (x,y), check X != Identity & x in range [0, q-1] & y in range [0, q-1] & q * X = Identity.
    // (https://github.com/otrv4/otrv4/blob/master/otrv4.md#verifying-that-a-point-is-on-the-curve)
    @CheckReturnValue
    public static boolean containsPoint(@Nonnull final Point p) {
        try {
            // FIXME does it even make sense to call 'contains'? I suspect that 'Points.decode' already does a point validity check, but maybe not identity check.
            return nl.dannyvanheumen.joldilocks.Ed448.contains(Points.decode(p.encoded));
        } catch (final Points.InvalidDataException e) {
            return false;
        }
    }

    /**
     * Generate a new random value in Z_q.
     *
     * @param random SecureRandom instance
     * @return Returns a newly generated random value.
     */
    public static Scalar generateRandomValueInZq(@Nonnull final SecureRandom random) {
        return decodeScalar(randomBytes(random, new byte[57]));
    }
}
