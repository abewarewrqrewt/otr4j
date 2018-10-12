package net.java.otr4j.crypto.ed448;

import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.math.BigInteger;

/**
 * Class that provides access to Ed448 constants.
 */
public final class Ed448 {

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
        return nl.dannyvanheumen.joldilocks.Ed448.basePoint();
    }

    /**
     * Access prime order of Ed448-Goldilocks curve.
     *
     * @return Returns prime order.
     */
    @Nonnull
    public static BigInteger primeOrder() {
        return nl.dannyvanheumen.joldilocks.Ed448.primeOrder();
    }

    /**
     * Perform scalar multiplication by Ed448 base point.
     *
     * @param scalar the scalar value
     * @return Returns the point resulting from the multiplication.
     */
    @Nonnull
    public static Point multiplyByBase(@Nonnull final BigInteger scalar) {
        return nl.dannyvanheumen.joldilocks.Ed448.multiplyByBase(scalar);
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
        return nl.dannyvanheumen.joldilocks.Ed448.contains(p);
    }
}
