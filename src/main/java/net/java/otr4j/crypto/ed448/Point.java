/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.crypto.ed448;

import nl.dannyvanheumen.joldilocks.Points;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Arrays;

import static net.java.otr4j.util.ByteArrays.constantTimeEquals;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;
import static org.bouncycastle.math.ec.rfc8032.Ed448.PUBLIC_KEY_SIZE;
import static org.bouncycastle.util.Arrays.clear;

/**
 * Point wrapper classed used to abstract away from the actual cryptographic implementation.
 */
public final class Point implements AutoCloseable {

    private final byte[] encoded;

    private boolean cleared = false;

    Point(@Nonnull final byte[] encoded) {
        this.encoded = requireLengthExactly(PUBLIC_KEY_SIZE, encoded);
    }

    @SuppressWarnings("PMD.MethodReturnsInternalArray")
    @Nonnull
    byte[] getEncoded() {
        requireNotCleared();
        return this.encoded;
    }

    @Override
    public void close() {
        clear(this.encoded);
        this.cleared = true;
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
            return new Point(Points.decode(encodedPoint).encode());
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
        return new Point(Points.createPoint(x, y).encode());
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final Point other = (Point) o;
        return constantTimeEquals(this.encoded, other.encoded);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(this.encoded);
    }

    /**
     * Negate the point.
     *
     * @return Returns the negated point.
     */
    @Nonnull
    public Point negate() {
        requireNotCleared();
        try {
            return new Point(Points.decode(this.encoded).negate().encode());
        } catch (final Points.InvalidDataException e) {
            throw new IllegalStateException("BUG: Point instance encountered with illegal point data.", e);
        }
    }

    /**
     * Multiply point with provided scalar value.
     *
     * @param scalar the scalar value
     * @return Returns new point resulting from multiplication.
     */
    @Nonnull
    public Point multiply(@Nonnull final Scalar scalar) {
        requireNotCleared();
        try {
            return new Point(Points.decode(this.encoded).multiply(scalar.toBigInteger()).encode());
        } catch (final Points.InvalidDataException e) {
            throw new IllegalStateException("BUG: Point instance encountered with illegal point data.", e);
        }
    }

    /**
     * Add provided point to this point.
     *
     * @param point the point to add
     * @return Returns the result of adding the two points together.
     */
    @Nonnull
    public Point add(@Nonnull final Point point) {
        this.requireNotCleared();
        point.requireNotCleared();
        try {
            return new Point(Points.decode(this.encoded).add(Points.decode(point.encoded)).encode());
        } catch (final Points.InvalidDataException e) {
            throw new IllegalStateException("BUG: Point instance encountered with illegal point data.", e);
        }
    }

    /**
     * Encode the point according to RFC 8032 byte encoding.
     *
     * @return Returns the byte-array representing the point.
     */
    @Nonnull
    public byte[] encode() {
        requireNotCleared();
        return this.encoded.clone();
    }

    /**
     * Encode the point according to the RFC 8032 byte encoding to provided output stream.
     *
     * @param out the destination output stream
     * @throws IOException In case of failure in the output stream during encoding.
     */
    public void encodeTo(@Nonnull final OutputStream out) throws IOException {
        requireNotCleared();
        out.write(this.encoded, 0, PUBLIC_KEY_SIZE);
    }

    private void requireNotCleared() {
        if (this.cleared) {
            throw new IllegalStateException("Point data was already cleared.");
        }
    }
}
