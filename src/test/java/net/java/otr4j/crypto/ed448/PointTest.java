/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.crypto.ed448;

import nl.dannyvanheumen.joldilocks.Points;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import static java.math.BigInteger.valueOf;
import static net.java.otr4j.crypto.ed448.Ed448.basePoint;
import static net.java.otr4j.crypto.ed448.Ed448.identity;
import static net.java.otr4j.crypto.ed448.Point.decodePoint;
import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.internal.util.reflection.Whitebox.getInternalState;

@SuppressWarnings("ConstantConditions")
public final class PointTest {

    private static final byte[] BASE_POINT_ENCODED = new byte[] {20, -6, 48, -14, 91, 121, 8, -104, -83, -56, -41, 78, 44, 19, -67, -3, -60, 57, 124, -26, 28, -1, -45, 58, -41, -62, -96, 5, 30, -100, 120, -121, 64, -104, -93, 108, 115, 115, -22, 75, 98, -57, -55, 86, 55, 32, 118, -120, 36, -68, -74, 110, 113, 70, 63, 105, 0};

    private static final byte[] ILLEGAL_POINT_ENCODED = new byte[] {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff};

    private static final Scalar TWO = Scalar.fromBigInteger(valueOf(2L));

    @Test(expected = NullPointerException.class)
    public void testConstructNullPoint() {
        new Point(null);
    }

    @Test
    public void testConstructValidPoint() {
        final Point p = new Point(BASE_POINT_ENCODED.clone());
        assertArrayEquals(BASE_POINT_ENCODED.clone(), p.getEncoded());
    }

    @Test(expected = NullPointerException.class)
    public void testMultiplicationNullPoint() {
        final Point p = new Point(BASE_POINT_ENCODED.clone());
        p.multiply(null);
    }

    @Test
    public void testMultiplication() throws Points.InvalidDataException {
        final nl.dannyvanheumen.joldilocks.Point joldilocksPoint = Points.decode(BASE_POINT_ENCODED.clone());
        final nl.dannyvanheumen.joldilocks.Point joldilocksExpected = joldilocksPoint.multiply(valueOf(2L));
        final Point p = new Point(BASE_POINT_ENCODED.clone());
        final Point p2 = p.multiply(TWO);
        assertArrayEquals(joldilocksExpected.encode(), p2.encode());
    }

    @Test(expected = NullPointerException.class)
    public void testAdditionNullPoint() {
        final Point p = new Point(BASE_POINT_ENCODED.clone());
        p.add(null);
    }

    @Test
    public void testAddition() throws Points.InvalidDataException {
        final nl.dannyvanheumen.joldilocks.Point joldilocksPoint = Points.decode(BASE_POINT_ENCODED.clone());
        final nl.dannyvanheumen.joldilocks.Point joldilocksExpected = joldilocksPoint.multiply(valueOf(2L));
        final Point p = new Point(BASE_POINT_ENCODED.clone());
        final Point p2 = p.add(p);
        assertArrayEquals(joldilocksExpected.encode(), p2.encode());
    }

    @Test(expected = NullPointerException.class)
    public void testDecodeNullPoint() throws ValidationException {
        decodePoint(null);
    }

    @Test
    public void testDecodePoint() throws ValidationException {
        final byte[] expected = basePoint().encode();
        assertArrayEquals(expected, decodePoint(BASE_POINT_ENCODED.clone()).encode());
    }

    @Test
    public void testDoubleNegatePoint() throws ValidationException {
        final Point p = decodePoint(BASE_POINT_ENCODED.clone());
        assertEquals(p, p.negate().negate());
        assertArrayEquals(p.getEncoded(), p.negate().negate().getEncoded());
        assertArrayEquals(p.encode(), p.negate().negate().encode());
    }

    @Test
    public void testEncodeTo() throws ValidationException, IOException {
        final Point p = decodePoint(BASE_POINT_ENCODED.clone());
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            p.encodeTo(out);
            assertArrayEquals(BASE_POINT_ENCODED, out.toByteArray());
        }
    }

    @Test
    public void testNegatePoint() throws ValidationException, Points.InvalidDataException {
        final Point p = decodePoint(BASE_POINT_ENCODED.clone());
        final nl.dannyvanheumen.joldilocks.Point expected = Points.decode(BASE_POINT_ENCODED.clone()).negate();
        assertArrayEquals(expected.encode(), p.negate().encode());
    }

    @Test(expected = ValidationException.class)
    public void testPointDecodeZeroBytes() throws ValidationException {
        decodePoint(ILLEGAL_POINT_ENCODED.clone());
    }

    @Test(expected = IllegalStateException.class)
    public void testMultiplyIllegalPoint() {
        new Point(ILLEGAL_POINT_ENCODED.clone()).multiply(TWO);
    }

    @Test(expected = IllegalStateException.class)
    public void testAddIllegalPoint() {
        new Point(ILLEGAL_POINT_ENCODED.clone()).add(new Point(BASE_POINT_ENCODED.clone()));
    }

    @Test(expected = IllegalStateException.class)
    public void testNegateIllegalPoint() {
        new Point(ILLEGAL_POINT_ENCODED.clone()).negate();
    }

    @Test
    public void testClose() {
        final Point p = new Point(BASE_POINT_ENCODED.clone());
        p.close();
        assertTrue(allZeroBytes((byte[]) getInternalState(p, "encoded")));
    }

    @Test(expected = IllegalStateException.class)
    public void testEncodeClosedPoint() {
        final Point p = new Point(BASE_POINT_ENCODED.clone());
        p.close();
        p.encode();
    }

    @Test(expected = IllegalStateException.class)
    public void testEncodeToClosedPoint() throws IOException {
        final Point p = new Point(BASE_POINT_ENCODED.clone());
        p.close();
        p.encodeTo(System.err);
    }

    @Test(expected = IllegalStateException.class)
    public void testNegateClosedPoint() {
        final Point p = new Point(BASE_POINT_ENCODED.clone());
        p.close();
        p.negate();
    }

    @Test(expected = IllegalStateException.class)
    public void testClosedAddPoint() {
        final Point p = new Point(BASE_POINT_ENCODED.clone());
        p.close();
        p.add(new Point(BASE_POINT_ENCODED.clone()));
    }

    @Test(expected = IllegalStateException.class)
    public void testAddClosedPoint() {
        final Point p = new Point(BASE_POINT_ENCODED.clone());
        p.close();
        new Point(BASE_POINT_ENCODED.clone()).add(p);
    }

    @Test(expected = IllegalStateException.class)
    public void testClosedMultiplyPoint() {
        final Point p = new Point(BASE_POINT_ENCODED.clone());
        p.close();
        p.multiply(TWO);
    }

    @Test
    public void testAddNegativeCounterPoint() {
        final Point p = new Point(BASE_POINT_ENCODED.clone());
        assertArrayEquals(p.getEncoded(), p.add(p).add(p.negate()).encode());
    }

    @Test
    public void testAddIdentityPoint() {
        final Point p = new Point(BASE_POINT_ENCODED.clone());
        assertArrayEquals(p.getEncoded(), p.add(identity()).encode());
    }

    @Test
    public void testMultiplyIdentityPoint() {
        final Point p = new Point(BASE_POINT_ENCODED.clone());
        assertArrayEquals(p.getEncoded(), p.multiply(Scalar.fromBigInteger(valueOf(1L))).encode());
    }
}