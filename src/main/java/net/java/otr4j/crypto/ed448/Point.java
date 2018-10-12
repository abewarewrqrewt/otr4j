package net.java.otr4j.crypto.ed448;

import nl.dannyvanheumen.joldilocks.Points;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Objects;

import static java.util.Objects.requireNonNull;

/**
 * Point wrapper classed used to abstract away from the actual cryptographic implementation.
 */
// FIXME write unit tests for Point wrapper
public final class Point {

    // FIXME investigate reducing access once more is clear about the logic in the ed448 wrapper package.
    final nl.dannyvanheumen.joldilocks.Point p;

    Point(@Nonnull final nl.dannyvanheumen.joldilocks.Point p) {
        this.p = requireNonNull(p);
    }

    /**
     * Decode a point encoded as byte-array according to RFC 8032.
     *
     * @param encodedPoint the point encoded as an array of bytes
     * @return Returns the point.
     * @throws ValidationException In case of an illegal point representation.
     */
    @Nonnull
    public static Point decodePoint(@Nonnull final byte[] encodedPoint) throws ValidationException {
        try {
            return new Point(Points.decode(encodedPoint));
        } catch (final Points.InvalidDataException e) {
            throw new ValidationException("Failed to read encoded point. Illegal point encountered.", e);
        }
    }

    /**
     * Construct a new point based on scalar values for x and y coordinates.
     *
     * @param x the x-coordinate
     * @param y the y-coordinate
     * @return Returns newly created point.
     */
    // FIXME consider if this method is really needed. Should we use utility method for this purpose?
    @Nonnull
    public static Point createPoint(@Nonnull final BigInteger x, @Nonnull final BigInteger y) {
        return new Point(Points.createPoint(x, y));
    }

    @Override
    public boolean equals(final Object o) {
        // FIXME should we make exception to detect same-instance comparison?
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final Point point1 = (Point) o;
        // FIXME needs constant-time comparison?
        return Objects.equals(p, point1.p);
    }

    @Override
    public int hashCode() {
        return Objects.hash(p);
    }

    /**
     * Negate the point.
     *
     * @return Returns the negated point.
     */
    @Nonnull
    public Point negate() {
        return new Point(this.p.negate());
    }

    /**
     * Multiply point with provided scalar value.
     *
     * @param scalar the scalar value
     * @return Returns new point resulting from multiplication.
     */
    @Nonnull
    public Point multiply(@Nonnull final Scalar scalar) {
        return new Point(this.p.multiply(scalar.value));
    }

    /**
     * Add provided point to this point.
     *
     * @param point the point to add
     * @return Returns the result of adding the two points together.
     */
    @Nonnull
    public Point add(@Nonnull final Point point) {
        return new Point(this.p.add(point.p));
    }

    /**
     * Encode the point according to RFC 8032 byte encoding.
     *
     * @return Returns the byte-array representing the point.
     */
    @Nonnull
    public byte[] encode() {
        return this.p.encode();
    }

    /**
     * Encode the point according to the RFC 8032 byte encoding to provided output stream.
     *
     * @param out the destination output stream
     * @throws IOException In case of failure in the output stream during encoding.
     */
    @Nonnull
    public void encodeTo(@Nonnull final OutputStream out) throws IOException {
        this.p.encodeTo(out);
    }
}
