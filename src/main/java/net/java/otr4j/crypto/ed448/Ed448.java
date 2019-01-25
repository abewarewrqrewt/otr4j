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
import java.math.BigInteger;

import static java.math.BigInteger.ZERO;
import static net.java.otr4j.util.ByteArrays.constantTimeEquals;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;
import static org.bouncycastle.math.ec.rfc8032.Ed448.PUBLIC_KEY_SIZE;

/**
 * Class that provides access to Ed448 constants.
 */
public final class Ed448 {

    /**
     * Identity (or neutral element) of the curve.
     */
    private static final byte[] IDENTITY = new byte[] {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    /**
     * Prime p of the Ed448-Goldilocks curve. (Used as modulus.)
     */
    private static final BigInteger MODULUS = new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16);

    /**
     * Base Point of the curve.
     */
    private static final byte[] G = new byte[] {20, -6, 48, -14, 91, 121, 8, -104, -83, -56, -41, 78, 44, 19, -67, -3, -60, 57, 124, -26, 28, -1, -45, 58, -41, -62, -96, 5, 30, -100, 120, -121, 64, -104, -93, 108, 115, 115, -22, 75, 98, -57, -55, 86, 55, 32, 118, -120, 36, -68, -74, 110, 113, 70, 63, 105, 0};

    /**
     * Prime order.
     */
    private static final byte[] Q = new byte[] {-13, 68, 88, -85, -110, -62, 120, 35, 85, -113, -59, -115, 114, -62, 108, 33, -112, 54, -42, -82, 73, -37, 78, -60, -23, 35, -54, 124, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 63, 0};

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
        return new Point(G.clone());
    }

    /**
     * Access prime order of Ed448-Goldilocks curve.
     *
     * @return Returns prime order.
     */
    @Nonnull
    public static Scalar primeOrder() {
        return new Scalar(Q.clone());
    }

    /**
     * Access identity point of Ed448-Goldilocks curve.
     *
     * @return Identity
     */
    @Nonnull
    public static Point identity() {
        return new Point(IDENTITY.clone());
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
        if (!containsPoint(point)) {
            throw new IllegalArgumentException("Point is illegal: point is identity.");
        }
        return point;
    }

    /**
     * Verify that given point is contained in the curve.
     *
     * @param point The point to verify.
     * @return Returns true if it is contained in the curve.
     */
    @CheckReturnValue
    public static boolean containsPoint(@Nonnull final Point point) {
        if (checkIdentity(point)) {
            return false;
        }
        try {
            final nl.dannyvanheumen.joldilocks.Point p = Points.decode(point.getEncoded());
            if (p.x().compareTo(ZERO) < 0 || p.x().compareTo(MODULUS) >= 0) {
                return false;
            }
            if (p.y().compareTo(ZERO) < 0 || p.y().compareTo(MODULUS) >= 0) {
                return false;
            }
        } catch (final Points.InvalidDataException e) {
            return false;
        }
        return checkIdentity(point.multiply(primeOrder()));
    }

    /**
     * Method for testing if a point is the identity point.
     *
     * @param point point
     * @return Returns true if p is identity, or false otherwise.
     */
    @CheckReturnValue
    public static boolean checkIdentity(@Nonnull final Point point) {
        requireLengthExactly(PUBLIC_KEY_SIZE, point.getEncoded());
        return constantTimeEquals(IDENTITY, point.getEncoded());
    }
}
