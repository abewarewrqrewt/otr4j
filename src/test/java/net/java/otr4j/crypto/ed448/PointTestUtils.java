package net.java.otr4j.crypto.ed448;

import nl.dannyvanheumen.joldilocks.Points;

import javax.annotation.Nonnull;
import java.math.BigInteger;

public final class PointTestUtils {

    /**
     * Construct a new point based on scalar values for x and y coordinates.
     *
     * @param x the x-coordinate
     * @param y the y-coordinate
     * @return Returns newly created point.
     */
    @Nonnull
    public static Point createPoint(@Nonnull final BigInteger x, @Nonnull final BigInteger y) {
        return new Point(Points.createPoint(x, y).encode());
    }
}
