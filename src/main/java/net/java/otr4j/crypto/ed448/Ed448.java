package net.java.otr4j.crypto.ed448;

import nl.dannyvanheumen.joldilocks.Points;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;

import static java.math.BigInteger.ONE;
import static java.math.BigInteger.ZERO;
import static net.java.otr4j.crypto.ed448.Scalar.fromBigInteger;

/**
 * Class that provides access to Ed448 constants.
 */
public final class Ed448 {

    /**
     * Identity (or neutral element) of the curve.
     */
    private static final Point IDENTITY = Point.createPoint(ZERO, ONE);

    /**
     * Base Point of the curve.
     */
    private static final Point G = new Point(nl.dannyvanheumen.joldilocks.Ed448.basePoint());

    /**
     * Cofactor of the curve.
     */
    private static final Scalar C = fromBigInteger(nl.dannyvanheumen.joldilocks.Ed448.cofactor());

    /**
     * Prime order of the curve.
     */
    private static final Scalar Q = fromBigInteger(nl.dannyvanheumen.joldilocks.Ed448.primeOrder());

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
     * Access cofactor of Ed448-Goldilocks curve.
     *
     * @return Returns cofactor.
     */
    @Nonnull
    public static Scalar cofactor() {
        return C;
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
        return new Point(nl.dannyvanheumen.joldilocks.Ed448.multiplyByBase(scalar.value));
    }

    /**
     * Method for testing if a point is the identity point.
     *
     * @param point point
     * @return Returns true if p is identity, or false otherwise.
     */
    // FIXME write unit tests for checkIdentity
    @CheckReturnValue
    public static boolean checkIdentity(@Nonnull final Point point) {
        return Points.checkIdentity(point.p);
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
        return nl.dannyvanheumen.joldilocks.Ed448.contains(p.p);
    }
}
