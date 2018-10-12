package net.java.otr4j.session.smpv4;

import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.io.OtrOutputStream;
import org.junit.Test;

import java.math.BigInteger;

import static java.math.BigInteger.valueOf;
import static net.java.otr4j.crypto.ed448.Ed448.basePoint;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

@SuppressWarnings("ConstantConditions")
public final class SMPMessage3Test {

    @Test
    public void testConstructSMPMessage3() {
        final Point pa = basePoint().multiply(valueOf(2L));
        final Point qa = basePoint().multiply(valueOf(3L));
        final BigInteger cp = valueOf(1L);
        final BigInteger d5 = valueOf(2L);
        final BigInteger d6 = valueOf(3L);
        final Point ra = basePoint().multiply(valueOf(4L));
        final BigInteger cr = valueOf(4L);
        final BigInteger d7 = valueOf(5L);
        final SMPMessage3 message = new SMPMessage3(pa, qa, cp, d5, d6, ra, cr, d7);
        assertEquals(pa, message.pa);
        assertEquals(qa, message.qa);
        assertEquals(cp, message.cp);
        assertEquals(d5, message.d5);
        assertEquals(d6, message.d6);
        assertEquals(ra, message.ra);
        assertEquals(cr, message.cr);
        assertEquals(d7, message.d7);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructSMPMessage3NullPA() {
        final Point qa = basePoint().multiply(valueOf(3L));
        final BigInteger cp = valueOf(1L);
        final BigInteger d5 = valueOf(2L);
        final BigInteger d6 = valueOf(3L);
        final Point ra = basePoint().multiply(valueOf(4L));
        final BigInteger cr = valueOf(4L);
        final BigInteger d7 = valueOf(5L);
        new SMPMessage3(null, qa, cp, d5, d6, ra, cr, d7);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructSMPMessage3NullPQA() {
        final Point pa = basePoint().multiply(valueOf(2L));
        final BigInteger cp = valueOf(1L);
        final BigInteger d5 = valueOf(2L);
        final BigInteger d6 = valueOf(3L);
        final Point ra = basePoint().multiply(valueOf(4L));
        final BigInteger cr = valueOf(4L);
        final BigInteger d7 = valueOf(5L);
        new SMPMessage3(pa, null, cp, d5, d6, ra, cr, d7);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructSMPMessage3NullCP() {
        final Point pa = basePoint().multiply(valueOf(2L));
        final Point qa = basePoint().multiply(valueOf(3L));
        final BigInteger d5 = valueOf(2L);
        final BigInteger d6 = valueOf(3L);
        final Point ra = basePoint().multiply(valueOf(4L));
        final BigInteger cr = valueOf(4L);
        final BigInteger d7 = valueOf(5L);
        new SMPMessage3(pa, qa, null, d5, d6, ra, cr, d7);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructSMPMessage3NullD5() {
        final Point pa = basePoint().multiply(valueOf(2L));
        final Point qa = basePoint().multiply(valueOf(3L));
        final BigInteger cp = valueOf(1L);
        final BigInteger d6 = valueOf(3L);
        final Point ra = basePoint().multiply(valueOf(4L));
        final BigInteger cr = valueOf(4L);
        final BigInteger d7 = valueOf(5L);
        new SMPMessage3(pa, qa, cp, null, d6, ra, cr, d7);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructSMPMessage3NullD6() {
        final Point pa = basePoint().multiply(valueOf(2L));
        final Point qa = basePoint().multiply(valueOf(3L));
        final BigInteger cp = valueOf(1L);
        final BigInteger d5 = valueOf(2L);
        final Point ra = basePoint().multiply(valueOf(4L));
        final BigInteger cr = valueOf(4L);
        final BigInteger d7 = valueOf(5L);
        new SMPMessage3(pa, qa, cp, d5, null, ra, cr, d7);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructSMPMessage3NullRA() {
        final Point pa = basePoint().multiply(valueOf(2L));
        final Point qa = basePoint().multiply(valueOf(3L));
        final BigInteger cp = valueOf(1L);
        final BigInteger d5 = valueOf(2L);
        final BigInteger d6 = valueOf(3L);
        final BigInteger cr = valueOf(4L);
        final BigInteger d7 = valueOf(5L);
        new SMPMessage3(pa, qa, cp, d5, d6, null, cr, d7);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructSMPMessage3NullCR() {
        final Point pa = basePoint().multiply(valueOf(2L));
        final Point qa = basePoint().multiply(valueOf(3L));
        final BigInteger cp = valueOf(1L);
        final BigInteger d5 = valueOf(2L);
        final BigInteger d6 = valueOf(3L);
        final Point ra = basePoint().multiply(valueOf(4L));
        final BigInteger d7 = valueOf(5L);
        new SMPMessage3(pa, qa, cp, d5, d6, ra, null, d7);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructSMPMessage3NullD7() {
        final Point pa = basePoint().multiply(valueOf(2L));
        final Point qa = basePoint().multiply(valueOf(3L));
        final BigInteger cp = valueOf(1L);
        final BigInteger d5 = valueOf(2L);
        final BigInteger d6 = valueOf(3L);
        final Point ra = basePoint().multiply(valueOf(4L));
        final BigInteger cr = valueOf(4L);
        new SMPMessage3(pa, qa, cp, d5, d6, ra, cr, null);
    }

    @Test
    public void testVerifyEncoding() {
        final byte[] expected = new byte[] {-19, -122, -109, -22, -51, -5, -22, -38, 107, -96, -51, -47, -66, -78, -68, -69, -104, 48, 42, 58, -125, 101, 101, 13, -72, -60, -40, -118, 114, 109, -29, -73, -41, 77, -120, 53, -96, -41, 110, 3, -80, -62, -122, 80, 32, -42, 89, -77, -115, 4, -41, 74, 99, -23, 5, -82, -128, -4, -42, -114, 88, 19, -84, 34, -72, -81, 45, -48, -2, 104, -102, -6, -65, -16, 103, 103, -37, 27, 51, 58, -69, 88, 29, 78, -20, -126, 60, -28, -4, -71, -61, 86, 35, -107, -115, 74, -102, 68, -90, 58, -44, 122, -38, -53, 6, -9, 92, 18, -43, -37, -88, 5, -32, -128, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 57, 24, -27, 109, -8, 54, -30, 50, 91, 79, 13, 93, 40, 68, -44, -75, 114, -108, -54, -95, 126, -7, -40, -64, -63, 91, -118, 123, 34, -61, 13, -55, 69, -40, 87, 4, 47, -64, -73, -100, -105, 27, 2, -34, -91, 51, 75, 22, 39, -27, -51, -84, -28, 119, -112, -44, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        final Point pa = basePoint().multiply(valueOf(2L));
        final Point qa = basePoint().multiply(valueOf(3L));
        final BigInteger cp = valueOf(1L);
        final BigInteger d5 = valueOf(2L);
        final BigInteger d6 = valueOf(3L);
        final Point ra = basePoint().multiply(valueOf(4L));
        final BigInteger cr = valueOf(4L);
        final BigInteger d7 = valueOf(5L);
        final SMPMessage3 message = new SMPMessage3(pa, qa, cp, d5, d6, ra, cr, d7);
        final OtrOutputStream out = new OtrOutputStream();
        message.writeTo(out);
        assertArrayEquals(expected, out.toByteArray());
    }
}