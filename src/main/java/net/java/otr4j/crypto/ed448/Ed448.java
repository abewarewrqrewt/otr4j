package net.java.otr4j.crypto.ed448;

import nl.dannyvanheumen.joldilocks.Points;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.math.BigInteger;
import java.security.SecureRandom;

import static java.math.BigInteger.ONE;
import static java.math.BigInteger.ZERO;
import static net.java.otr4j.util.SecureRandoms.random;

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
     * Scalar value representing one.
     */
    private static final Scalar COFACTOR = new Scalar(new byte[] {4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});

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
     * Access cofactor of Ed448-Goldilocks curve.
     *
     * @return Returns cofactor.
     */
    @Nonnull
    static Scalar cofactor() {
        return COFACTOR;
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
        return new Point(nl.dannyvanheumen.joldilocks.Ed448.multiplyByBase(scalar.toBigInteger()));
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

    /**
     * Generate a new random value in Z_q.
     *
     * @param random SecureRandom instance
     * @return Returns a newly generated random value.
     */
    // FIXME SMP: not sure what this is exactly. Need to see how to reliably generate these values.
    // FIXME how to reliable generate random value "in q"? (Is this correct for scalars? 0 <= x < q (... or [0,q-1])? (We probably need to generate `a larger value mod q`, but do we need to care about uniform distributed of mod q random value?)
    public static Scalar generateRandomValueInZq(@Nonnull final SecureRandom random) {
        final BigInteger q = nl.dannyvanheumen.joldilocks.Ed448.primeOrder();
        final byte[] data = random(random, new byte[57]);
        final BigInteger value = new BigInteger(1, data).mod(q);
        assert ZERO.compareTo(value) <= 0 && q.compareTo(value) > 0
                : "Generated scalar value should always be less to be valid, i.e. greater or equal to zero and smaller than prime order.";
        return Scalar.fromBigInteger(value);
    }
}
