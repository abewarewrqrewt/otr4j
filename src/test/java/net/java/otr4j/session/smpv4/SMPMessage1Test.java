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
public final class SMPMessage1Test {

    @Test
    public void testConstructSMPMessage1() {
        final String question = "This is my question";
        final Point g2a = basePoint().multiply(valueOf(2L));
        final BigInteger c2 = valueOf(1L);
        final BigInteger d2 = valueOf(2L);
        final Point g3a = basePoint().multiply(valueOf(3L));
        final BigInteger c3 = valueOf(3L);
        final BigInteger d3 = valueOf(4L);
        final SMPMessage1 message = new SMPMessage1(question, g2a, c2, d2, g3a, c3, d3);
        assertEquals(question, message.question);
        assertEquals(g2a, message.g2a);
        assertEquals(c2, message.c2);
        assertEquals(d2, message.d2);
        assertEquals(g3a, message.g3a);
        assertEquals(c3, message.c3);
        assertEquals(d3, message.d3);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructSMPMessage1NullQuestion() {
        final Point g2a = basePoint().multiply(valueOf(2L));
        final BigInteger c2 = valueOf(1L);
        final BigInteger d2 = valueOf(2L);
        final Point g3a = basePoint().multiply(valueOf(3L));
        final BigInteger c3 = valueOf(3L);
        final BigInteger d3 = valueOf(4L);
        new SMPMessage1(null, g2a, c2, d2, g3a, c3, d3);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructSMPMessage1NullG2A() {
        final String question = "This is my question";
        final BigInteger c2 = valueOf(1L);
        final BigInteger d2 = valueOf(2L);
        final Point g3a = basePoint().multiply(valueOf(3L));
        final BigInteger c3 = valueOf(3L);
        final BigInteger d3 = valueOf(4L);
        new SMPMessage1(question, null, c2, d2, g3a, c3, d3);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructSMPMessage1NullC2() {
        final String question = "This is my question";
        final Point g2a = basePoint().multiply(valueOf(2L));
        final BigInteger d2 = valueOf(2L);
        final Point g3a = basePoint().multiply(valueOf(3L));
        final BigInteger c3 = valueOf(3L);
        final BigInteger d3 = valueOf(4L);
        new SMPMessage1(question, g2a, null, d2, g3a, c3, d3);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructSMPMessage1NullD2() {
        final String question = "This is my question";
        final Point g2a = basePoint().multiply(valueOf(2L));
        final BigInteger c2 = valueOf(1L);
        final Point g3a = basePoint().multiply(valueOf(3L));
        final BigInteger c3 = valueOf(3L);
        final BigInteger d3 = valueOf(4L);
        new SMPMessage1(question, g2a, c2, null, g3a, c3, d3);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructSMPMessage1NullG3A() {
        final String question = "This is my question";
        final Point g2a = basePoint().multiply(valueOf(2L));
        final BigInteger c2 = valueOf(1L);
        final BigInteger d2 = valueOf(2L);
        final BigInteger c3 = valueOf(3L);
        final BigInteger d3 = valueOf(4L);
        new SMPMessage1(question, g2a, c2, d2, null, c3, d3);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructSMPMessage1NullC3() {
        final String question = "This is my question";
        final Point g2a = basePoint().multiply(valueOf(2L));
        final BigInteger c2 = valueOf(1L);
        final BigInteger d2 = valueOf(2L);
        final Point g3a = basePoint().multiply(valueOf(3L));
        final BigInteger d3 = valueOf(4L);
        new SMPMessage1(question, g2a, c2, d2, g3a, null, d3);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructSMPMessage1NullD3() {
        final String question = "This is my question";
        final Point g2a = basePoint().multiply(valueOf(2L));
        final BigInteger c2 = valueOf(1L);
        final BigInteger d2 = valueOf(2L);
        final Point g3a = basePoint().multiply(valueOf(3L));
        final BigInteger c3 = valueOf(3L);
        new SMPMessage1(question, g2a, c2, d2, g3a, c3, null);
    }

    @Test
    public void testVerifyEncoding() {
        final byte[] expected = new byte[] {0, 0, 0, 19, 84, 104, 105, 115, 32, 105, 115, 32, 109, 121, 32, 113, 117, 101, 115, 116, 105, 111, 110, 0, 0, 0, 57, -19, -122, -109, -22, -51, -5, -22, -38, 107, -96, -51, -47, -66, -78, -68, -69, -104, 48, 42, 58, -125, 101, 101, 13, -72, -60, -40, -118, 114, 109, -29, -73, -41, 77, -120, 53, -96, -41, 110, 3, -80, -62, -122, 80, 32, -42, 89, -77, -115, 4, -41, 74, 99, -23, 5, -82, -128, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 57, -4, -42, -114, 88, 19, -84, 34, -72, -81, 45, -48, -2, 104, -102, -6, -65, -16, 103, 103, -37, 27, 51, 58, -69, 88, 29, 78, -20, -126, 60, -28, -4, -71, -61, 86, 35, -107, -115, 74, -102, 68, -90, 58, -44, 122, -38, -53, 6, -9, 92, 18, -43, -37, -88, 5, -32, -128, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        final String question = "This is my question";
        final Point g2a = basePoint().multiply(valueOf(2L));
        final BigInteger c2 = valueOf(1L);
        final BigInteger d2 = valueOf(2L);
        final Point g3a = basePoint().multiply(valueOf(3L));
        final BigInteger c3 = valueOf(3L);
        final BigInteger d3 = valueOf(4L);
        final SMPMessage1 message = new SMPMessage1(question, g2a, c2, d2, g3a, c3, d3);
        final OtrOutputStream out = new OtrOutputStream();
        message.writeTo(out);
        assertArrayEquals(expected, out.toByteArray());
    }
}