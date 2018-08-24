package net.java.otr4j.session.smpv4;

import net.java.otr4j.io.OtrOutputStream;
import nl.dannyvanheumen.joldilocks.Point;
import org.junit.Test;

import java.math.BigInteger;

import static java.math.BigInteger.valueOf;
import static nl.dannyvanheumen.joldilocks.Ed448.basePoint;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public final class SMPMessage4Test {

    @Test
    public void testConstructSMPMessage4() {
        final Point rb = basePoint().multiply(valueOf(2L));
        final BigInteger cr = valueOf(1L);
        final BigInteger d7 = valueOf(2L);
        final SMPMessage4 message = new SMPMessage4(rb, cr, d7);
        assertEquals(rb, message.rb);
        assertEquals(cr, message.cr);
        assertEquals(d7, message.d7);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructSMPMessage4NullRB() {
        final BigInteger cr = valueOf(1L);
        final BigInteger d7 = valueOf(2L);
        new SMPMessage4(null, cr, d7);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructSMPMessage4NullCR() {
        final Point rb = basePoint().multiply(valueOf(2L));
        final BigInteger d7 = valueOf(2L);
        new SMPMessage4(rb, null, d7);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructSMPMessage4NullD7() {
        final Point rb = basePoint().multiply(valueOf(2L));
        final BigInteger cr = valueOf(1L);
        new SMPMessage4(rb, cr, null);
    }

    @Test
    public void testVerifyEncoding() {
        final byte[] expected = new byte[] {-19, -122, -109, -22, -51, -5, -22, -38, 107, -96, -51, -47, -66, -78, -68, -69, -104, 48, 42, 58, -125, 101, 101, 13, -72, -60, -40, -118, 114, 109, -29, -73, -41, 77, -120, 53, -96, -41, 110, 3, -80, -62, -122, 80, 32, -42, 89, -77, -115, 4, -41, 74, 99, -23, 5, -82, -128, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        final Point rb = basePoint().multiply(valueOf(2L));
        final BigInteger cr = valueOf(1L);
        final BigInteger d7 = valueOf(2L);
        final SMPMessage4 message = new SMPMessage4(rb, cr, d7);
        final OtrOutputStream out = new OtrOutputStream();
        message.writeTo(out);
        assertArrayEquals(expected, out.toByteArray());
    }
}