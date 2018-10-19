package net.java.otr4j.crypto.ed448;

import nl.dannyvanheumen.joldilocks.Points;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.security.SecureRandom;

import static java.math.BigInteger.ONE;
import static java.math.BigInteger.ZERO;
import static net.java.otr4j.crypto.ed448.Point.createPoint;
import static net.java.otr4j.crypto.ed448.Point.decodePoint;
import static net.java.otr4j.crypto.ed448.Point.mustDecodePoint;
import static net.java.otr4j.util.SecureRandoms.randomBytes;

/**
 * Class that provides access to Ed448 constants.
 */
public final class Ed448 {

    /**
     * Identity (or neutral element) of the curve.
     */
    private static final Point IDENTITY = createPoint(ZERO, ONE);

    /**
     * Base Point of the curve.
     */
    // FIXME replace with constant expression for base point G
    private static final Point G = mustDecodePoint(nl.dannyvanheumen.joldilocks.Ed448.basePoint().encode());

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
        try {
            return decodePoint(nl.dannyvanheumen.joldilocks.Ed448.multiplyByBase(scalar.toBigInteger()).encode());
        } catch (final ValidationException e) {
            throw new IllegalStateException("Illegal point data. Failed to decode.", e);
        }
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
        try {
            return Points.checkIdentity(Points.decode(point.encoded));
        } catch (final Points.InvalidDataException e) {
            throw new IllegalStateException("Illegal point data. Failed to decode.", e);
        }
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
    // FIXME how to reliable generate random value "in q"? (Is this correct for scalars? 0 <= x < q (... or [0,q-1])? (We probably need to generate `a larger value mod q`, but do we need to care about uniform distributed of mod q random value?)
    public static Scalar generateRandomValueInZq(@Nonnull final SecureRandom random) {
        return Scalar.decodeScalar(randomBytes(random, new byte[57]));
    }
}
