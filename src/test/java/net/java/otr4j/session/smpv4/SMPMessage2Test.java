package net.java.otr4j.session.smpv4;

import net.java.otr4j.io.OtrOutputStream;
import nl.dannyvanheumen.joldilocks.Point;
import org.junit.Test;

import java.math.BigInteger;

import static java.math.BigInteger.valueOf;
import static nl.dannyvanheumen.joldilocks.Ed448.basePoint;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

@SuppressWarnings("ConstantConditions")
public final class SMPMessage2Test {

    @Test
    public void testConstructSMPMessage2() {
        final Point g2b = basePoint().multiply(valueOf(2L));
        final BigInteger c2 = valueOf(2L);
        final BigInteger d2 = valueOf(3L);
        final Point g3b = basePoint().multiply(valueOf(3L));
        final BigInteger c3 = valueOf(4L);
        final BigInteger d3 = valueOf(5L);
        final Point pb = basePoint().multiply(valueOf(4L));
        final Point qb = basePoint().multiply(valueOf(5L));
        final BigInteger cp = valueOf(6L);
        final BigInteger d5 = valueOf(7L);
        final BigInteger d6 = valueOf(8L);
        final SMPMessage2 message = new SMPMessage2(g2b, c2, d2, g3b, c3, d3, pb, qb, cp, d5, d6);
        assertEquals(g2b, message.g2b);
        assertEquals(c2, message.c2);
        assertEquals(d2, message.d2);
        assertEquals(g3b, message.g3b);
        assertEquals(c3, message.c3);
        assertEquals(d3, message.d3);
        assertEquals(pb, message.pb);
        assertEquals(qb, message.qb);
        assertEquals(cp, message.cp);
        assertEquals(d5, message.d5);
        assertEquals(d6, message.d6);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructSMPMessage2NullG2B() {
        final BigInteger c2 = valueOf(2L);
        final BigInteger d2 = valueOf(3L);
        final Point g3b = basePoint().multiply(valueOf(3L));
        final BigInteger c3 = valueOf(4L);
        final BigInteger d3 = valueOf(5L);
        final Point pb = basePoint().multiply(valueOf(4L));
        final Point qb = basePoint().multiply(valueOf(5L));
        final BigInteger cp = valueOf(6L);
        final BigInteger d5 = valueOf(7L);
        final BigInteger d6 = valueOf(8L);
        new SMPMessage2(null, c2, d2, g3b, c3, d3, pb, qb, cp, d5, d6);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructSMPMessage2NullC2() {
        final Point g2b = basePoint().multiply(valueOf(2L));
        final BigInteger d2 = valueOf(3L);
        final Point g3b = basePoint().multiply(valueOf(3L));
        final BigInteger c3 = valueOf(4L);
        final BigInteger d3 = valueOf(5L);
        final Point pb = basePoint().multiply(valueOf(4L));
        final Point qb = basePoint().multiply(valueOf(5L));
        final BigInteger cp = valueOf(6L);
        final BigInteger d5 = valueOf(7L);
        final BigInteger d6 = valueOf(8L);
        new SMPMessage2(g2b, null, d2, g3b, c3, d3, pb, qb, cp, d5, d6);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructSMPMessage2NullD2() {
        final Point g2b = basePoint().multiply(valueOf(2L));
        final BigInteger c2 = valueOf(2L);
        final Point g3b = basePoint().multiply(valueOf(3L));
        final BigInteger c3 = valueOf(4L);
        final BigInteger d3 = valueOf(5L);
        final Point pb = basePoint().multiply(valueOf(4L));
        final Point qb = basePoint().multiply(valueOf(5L));
        final BigInteger cp = valueOf(6L);
        final BigInteger d5 = valueOf(7L);
        final BigInteger d6 = valueOf(8L);
        new SMPMessage2(g2b, c2, null, g3b, c3, d3, pb, qb, cp, d5, d6);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructSMPMessage2NullG3B() {
        final Point g2b = basePoint().multiply(valueOf(2L));
        final BigInteger c2 = valueOf(2L);
        final BigInteger d2 = valueOf(3L);
        final BigInteger c3 = valueOf(4L);
        final BigInteger d3 = valueOf(5L);
        final Point pb = basePoint().multiply(valueOf(4L));
        final Point qb = basePoint().multiply(valueOf(5L));
        final BigInteger cp = valueOf(6L);
        final BigInteger d5 = valueOf(7L);
        final BigInteger d6 = valueOf(8L);
        new SMPMessage2(g2b, c2, d2, null, c3, d3, pb, qb, cp, d5, d6);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructSMPMessage2NullC3() {
        final Point g2b = basePoint().multiply(valueOf(2L));
        final BigInteger c2 = valueOf(2L);
        final BigInteger d2 = valueOf(3L);
        final Point g3b = basePoint().multiply(valueOf(3L));
        final BigInteger d3 = valueOf(5L);
        final Point pb = basePoint().multiply(valueOf(4L));
        final Point qb = basePoint().multiply(valueOf(5L));
        final BigInteger cp = valueOf(6L);
        final BigInteger d5 = valueOf(7L);
        final BigInteger d6 = valueOf(8L);
        new SMPMessage2(g2b, c2, d2, g3b, null, d3, pb, qb, cp, d5, d6);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructSMPMessage2NullD3() {
        final Point g2b = basePoint().multiply(valueOf(2L));
        final BigInteger c2 = valueOf(2L);
        final BigInteger d2 = valueOf(3L);
        final Point g3b = basePoint().multiply(valueOf(3L));
        final BigInteger c3 = valueOf(4L);
        final Point pb = basePoint().multiply(valueOf(4L));
        final Point qb = basePoint().multiply(valueOf(5L));
        final BigInteger cp = valueOf(6L);
        final BigInteger d5 = valueOf(7L);
        final BigInteger d6 = valueOf(8L);
        new SMPMessage2(g2b, c2, d2, g3b, c3, null, pb, qb, cp, d5, d6);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructSMPMessage2NullPB() {
        final Point g2b = basePoint().multiply(valueOf(2L));
        final BigInteger c2 = valueOf(2L);
        final BigInteger d2 = valueOf(3L);
        final Point g3b = basePoint().multiply(valueOf(3L));
        final BigInteger c3 = valueOf(4L);
        final BigInteger d3 = valueOf(5L);
        final Point qb = basePoint().multiply(valueOf(5L));
        final BigInteger cp = valueOf(6L);
        final BigInteger d5 = valueOf(7L);
        final BigInteger d6 = valueOf(8L);
        new SMPMessage2(g2b, c2, d2, g3b, c3, d3, null, qb, cp, d5, d6);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructSMPMessage2NullQB() {
        final Point g2b = basePoint().multiply(valueOf(2L));
        final BigInteger c2 = valueOf(2L);
        final BigInteger d2 = valueOf(3L);
        final Point g3b = basePoint().multiply(valueOf(3L));
        final BigInteger c3 = valueOf(4L);
        final BigInteger d3 = valueOf(5L);
        final Point pb = basePoint().multiply(valueOf(4L));
        final BigInteger cp = valueOf(6L);
        final BigInteger d5 = valueOf(7L);
        final BigInteger d6 = valueOf(8L);
        new SMPMessage2(g2b, c2, d2, g3b, c3, d3, pb, null, cp, d5, d6);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructSMPMessage2NullCP() {
        final Point g2b = basePoint().multiply(valueOf(2L));
        final BigInteger c2 = valueOf(2L);
        final BigInteger d2 = valueOf(3L);
        final Point g3b = basePoint().multiply(valueOf(3L));
        final BigInteger c3 = valueOf(4L);
        final BigInteger d3 = valueOf(5L);
        final Point pb = basePoint().multiply(valueOf(4L));
        final Point qb = basePoint().multiply(valueOf(5L));
        final BigInteger d5 = valueOf(7L);
        final BigInteger d6 = valueOf(8L);
        new SMPMessage2(g2b, c2, d2, g3b, c3, d3, pb, qb, null, d5, d6);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructSMPMessage2NullD5() {
        final Point g2b = basePoint().multiply(valueOf(2L));
        final BigInteger c2 = valueOf(2L);
        final BigInteger d2 = valueOf(3L);
        final Point g3b = basePoint().multiply(valueOf(3L));
        final BigInteger c3 = valueOf(4L);
        final BigInteger d3 = valueOf(5L);
        final Point pb = basePoint().multiply(valueOf(4L));
        final Point qb = basePoint().multiply(valueOf(5L));
        final BigInteger cp = valueOf(6L);
        final BigInteger d6 = valueOf(8L);
        new SMPMessage2(g2b, c2, d2, g3b, c3, d3, pb, qb, cp, null, d6);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructSMPMessage2NullD6() {
        final Point g2b = basePoint().multiply(valueOf(2L));
        final BigInteger c2 = valueOf(2L);
        final BigInteger d2 = valueOf(3L);
        final Point g3b = basePoint().multiply(valueOf(3L));
        final BigInteger c3 = valueOf(4L);
        final BigInteger d3 = valueOf(5L);
        final Point pb = basePoint().multiply(valueOf(4L));
        final Point qb = basePoint().multiply(valueOf(5L));
        final BigInteger cp = valueOf(6L);
        final BigInteger d5 = valueOf(7L);
        new SMPMessage2(g2b, c2, d2, g3b, c3, d3, pb, qb, cp, d5, null);
    }

    @Test
    public void testVerifyEncoding() {
        final byte[] expected = new byte[] {0, 0, 0, 57, -19, -122, -109, -22, -51, -5, -22, -38, 107, -96, -51, -47, -66, -78, -68, -69, -104, 48, 42, 58, -125, 101, 101, 13, -72, -60, -40, -118, 114, 109, -29, -73, -41, 77, -120, 53, -96, -41, 110, 3, -80, -62, -122, 80, 32, -42, 89, -77, -115, 4, -41, 74, 99, -23, 5, -82, -128, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 57, -4, -42, -114, 88, 19, -84, 34, -72, -81, 45, -48, -2, 104, -102, -6, -65, -16, 103, 103, -37, 27, 51, 58, -69, 88, 29, 78, -20, -126, 60, -28, -4, -71, -61, 86, 35, -107, -115, 74, -102, 68, -90, 58, -44, 122, -38, -53, 6, -9, 92, 18, -43, -37, -88, 5, -32, -128, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 57, 57, 24, -27, 109, -8, 54, -30, 50, 91, 79, 13, 93, 40, 68, -44, -75, 114, -108, -54, -95, 126, -7, -40, -64, -63, 91, -118, 123, 34, -61, 13, -55, 69, -40, 87, 4, 47, -64, -73, -100, -105, 27, 2, -34, -91, 51, 75, 22, 39, -27, -51, -84, -28, 119, -112, -44, 0, 0, 0, 0, 57, -21, 53, -12, 114, 20, 115, -76, 67, 84, 34, 31, -120, 18, 85, 64, 88, 60, -77, -46, 89, -18, -92, -41, 39, 113, 1, -104, -74, -9, 81, 101, -40, -50, -113, -79, 58, -126, -95, 12, 38, -34, 10, 88, -3, -28, -100, 16, -71, -45, -19, 23, 37, 26, 117, -3, -83, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        final Point g2b = basePoint().multiply(valueOf(2L));
        final BigInteger c2 = valueOf(2L);
        final BigInteger d2 = valueOf(3L);
        final Point g3b = basePoint().multiply(valueOf(3L));
        final BigInteger c3 = valueOf(4L);
        final BigInteger d3 = valueOf(5L);
        final Point pb = basePoint().multiply(valueOf(4L));
        final Point qb = basePoint().multiply(valueOf(5L));
        final BigInteger cp = valueOf(6L);
        final BigInteger d5 = valueOf(7L);
        final BigInteger d6 = valueOf(8L);
        final SMPMessage2 message = new SMPMessage2(g2b, c2, d2, g3b, c3, d3, pb, qb, cp, d5, d6);
        final OtrOutputStream out = new OtrOutputStream();
        message.writeTo(out);
        assertArrayEquals(expected, out.toByteArray());
    }
}