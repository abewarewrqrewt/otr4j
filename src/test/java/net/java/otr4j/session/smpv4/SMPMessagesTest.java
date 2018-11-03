/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.smpv4;

import net.java.otr4j.api.TLV;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.io.OtrOutputStream;
import org.junit.Test;

import java.net.ProtocolException;

import static java.math.BigInteger.ONE;
import static java.math.BigInteger.valueOf;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.copyOf;
import static net.java.otr4j.crypto.ed448.Ed448.basePoint;
import static net.java.otr4j.crypto.ed448.Point.createPoint;
import static net.java.otr4j.crypto.ed448.Scalar.fromBigInteger;
import static net.java.otr4j.session.smpv4.SMPMessage.SMP1;
import static net.java.otr4j.session.smpv4.SMPMessage.SMP2;
import static net.java.otr4j.session.smpv4.SMPMessage.SMP3;
import static net.java.otr4j.session.smpv4.SMPMessage.SMP4;
import static net.java.otr4j.session.smpv4.SMPMessage.SMP_ABORT;
import static net.java.otr4j.session.smpv4.SMPMessages.parse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

@SuppressWarnings( {"ConstantConditions", "CatchMayIgnoreException"})
public final class SMPMessagesTest {

    private static final Point ILLEGAL_POINT = createPoint(ONE, ONE);

    @Test(expected = NullPointerException.class)
    public void testParseNull() throws OtrCryptoException, ProtocolException {
        parse(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testUnsupportedTLV() throws OtrCryptoException, ProtocolException {
        parse(new TLV(0xff, new byte[0]));
    }

    @Test
    public void testParseTLVSMP1() throws OtrCryptoException, ProtocolException {
        final String question = "This is my question";
        final Point g2a = basePoint().multiply(fromBigInteger(valueOf(2L)));
        final Point g3a = basePoint().multiply(fromBigInteger(valueOf(3L)));
        final byte[] input = new OtrOutputStream().writeData(question.getBytes(UTF_8)).writePoint(g2a)
                .writeScalar(fromBigInteger(valueOf(2L))).writeScalar(fromBigInteger(valueOf(3L))).writePoint(g3a)
                .writeScalar(fromBigInteger(valueOf(4L))).writeScalar(fromBigInteger(valueOf(5L))).toByteArray();
        final SMPMessage1 result = (SMPMessage1) parse(new TLV(SMP1, input));
        assertEquals(question, result.question);
        assertEquals(g2a, result.g2a);
        assertEquals(fromBigInteger(valueOf(2L)), result.c2);
        assertEquals(fromBigInteger(valueOf(3L)), result.d2);
        assertEquals(g3a, result.g3a);
        assertEquals(fromBigInteger(valueOf(4L)), result.c3);
        assertEquals(fromBigInteger(valueOf(5L)), result.d3);
    }

    @Test(expected = ProtocolException.class)
    public void testParseTLVSMP1CorruptedQuestion() throws OtrCryptoException, ProtocolException {
        final Point g2a = basePoint().multiply(fromBigInteger(valueOf(2L)));
        final Point g3a = basePoint().multiply(fromBigInteger(valueOf(3L)));
        final byte[] input = new OtrOutputStream().writeByte(0xff).writeByte(0xff).writeByte(0xff).writeByte(0xff)
                .writePoint(g2a).writeScalar(fromBigInteger(valueOf(2L))).writeScalar(fromBigInteger(valueOf(3L)))
                .writePoint(g3a).writeScalar(fromBigInteger(valueOf(4L))).writeScalar(fromBigInteger(valueOf(5L)))
                .toByteArray();
        parse(new TLV(SMP1, input));
    }

    @Test
    public void testParseTLVSMP1TooMuchData() throws OtrCryptoException, ProtocolException {
        final String question = "This is my question";
        final Point g2a = basePoint().multiply(fromBigInteger(valueOf(2L)));
        final Point g3a = basePoint().multiply(fromBigInteger(valueOf(3L)));
        final byte[] input = new OtrOutputStream().writeData(question.getBytes(UTF_8)).writePoint(g2a)
                .writeScalar(fromBigInteger(valueOf(2L))).writeScalar(fromBigInteger(valueOf(3L))).writePoint(g3a)
                .writeScalar(fromBigInteger(valueOf(4L))).writeScalar(fromBigInteger(valueOf(5L))).toByteArray();
        final SMPMessage1 result = (SMPMessage1) parse(new TLV(SMP1, copyOf(input, input.length + 1)));
        assertEquals(question, result.question);
        assertEquals(g2a, result.g2a);
        assertEquals(fromBigInteger(valueOf(2L)), result.c2);
        assertEquals(fromBigInteger(valueOf(3L)), result.d2);
        assertEquals(g3a, result.g3a);
        assertEquals(fromBigInteger(valueOf(4L)), result.c3);
        assertEquals(fromBigInteger(valueOf(5L)), result.d3);
    }

    @Test(expected = OtrCryptoException.class)
    public void testParseTLVSMP1BadPointG2A() throws ProtocolException, OtrCryptoException {
        final String question = "This is my question";
        final Point g3a = basePoint().multiply(fromBigInteger(valueOf(3L)));
        final byte[] input = new OtrOutputStream().writeData(question.getBytes(UTF_8)).writePoint(ILLEGAL_POINT)
                .writeScalar(fromBigInteger(valueOf(2L))).writeScalar(fromBigInteger(valueOf(3L))).writePoint(g3a)
                .writeScalar(fromBigInteger(valueOf(4L))).writeScalar(fromBigInteger(valueOf(5L))).toByteArray();
        parse(new TLV(SMP1, input));
    }

    @Test(expected = OtrCryptoException.class)
    public void testParseTLVSMP1BadPointG3A() throws ProtocolException, OtrCryptoException {
        final String question = "This is my question";
        final Point g2a = basePoint().multiply(fromBigInteger(valueOf(2L)));
        final byte[] input = new OtrOutputStream().writeData(question.getBytes(UTF_8)).writePoint(g2a)
                .writeScalar(fromBigInteger(valueOf(2L))).writeScalar(fromBigInteger(valueOf(3L)))
                .writePoint(ILLEGAL_POINT).writeScalar(fromBigInteger(valueOf(4L)))
                .writeScalar(fromBigInteger(valueOf(5L))).toByteArray();
        parse(new TLV(SMP1, input));
    }

    @Test
    public void testParseIncompleteTLVSMP1() throws OtrCryptoException, ProtocolException {
        final String question = "This is my question";
        final Point g2a = basePoint().multiply(fromBigInteger(valueOf(2L)));
        final Point g3a = basePoint().multiply(fromBigInteger(valueOf(3L)));
        final byte[] data = new OtrOutputStream().writeData(question.getBytes(UTF_8)).writePoint(g2a)
                .writeScalar(fromBigInteger(valueOf(2L))).writeScalar(fromBigInteger(valueOf(3L)))
                .writePoint(g3a).writeScalar(fromBigInteger(valueOf(4L))).writeScalar(fromBigInteger(valueOf(5L)))
                .toByteArray();
        for (int i = 0; i < data.length; i++) {
            try {
                parse(new TLV(SMP1, copyOf(data, i)));
                fail("Did not expect to successfully parse an incomplete message. Something is probably wrong here.");
            } catch (final ProtocolException ignored) {
                // No need to worry, this was expected to happen.
            }
        }
        assertNotNull(parse(new TLV(SMP1, data)));
    }

    @Test
    public void testParseTLVSMP2() throws OtrCryptoException, ProtocolException {
        final Point g2b = basePoint().multiply(fromBigInteger(valueOf(2L)));
        final Point g3b = basePoint().multiply(fromBigInteger(valueOf(3L)));
        final Point pb = basePoint().multiply(fromBigInteger(valueOf(4L)));
        final Point qb = basePoint().multiply(fromBigInteger(valueOf(5L)));
        final byte[] input = new OtrOutputStream().writePoint(g2b).writeScalar(fromBigInteger(valueOf(1L)))
                .writeScalar(fromBigInteger(valueOf(2L))).writePoint(g3b).writeScalar(fromBigInteger(valueOf(3L)))
                .writeScalar(fromBigInteger(valueOf(4L))).writePoint(pb).writePoint(qb)
                .writeScalar(fromBigInteger(valueOf(5L))).writeScalar(fromBigInteger(valueOf(6L)))
                .writeScalar(fromBigInteger(valueOf(7L))).toByteArray();
        final SMPMessage2 result = (SMPMessage2) parse(new TLV(SMP2, input));
        assertEquals(g2b, result.g2b);
        assertEquals(fromBigInteger(valueOf(1L)), result.c2);
        assertEquals(fromBigInteger(valueOf(2L)), result.d2);
        assertEquals(g3b, result.g3b);
        assertEquals(fromBigInteger(valueOf(3L)), result.c3);
        assertEquals(fromBigInteger(valueOf(4L)), result.d3);
        assertEquals(pb, result.pb);
        assertEquals(qb, result.qb);
        assertEquals(fromBigInteger(valueOf(5L)), result.cp);
        assertEquals(fromBigInteger(valueOf(6L)), result.d5);
        assertEquals(fromBigInteger(valueOf(7L)), result.d6);
    }

    @Test
    public void testParseTLVSMP2TooMuchData() throws OtrCryptoException, ProtocolException {
        final Point g2b = basePoint().multiply(fromBigInteger(valueOf(2L)));
        final Point g3b = basePoint().multiply(fromBigInteger(valueOf(3L)));
        final Point pb = basePoint().multiply(fromBigInteger(valueOf(4L)));
        final Point qb = basePoint().multiply(fromBigInteger(valueOf(5L)));
        final byte[] input = new OtrOutputStream().writePoint(g2b).writeScalar(fromBigInteger(valueOf(1L)))
                .writeScalar(fromBigInteger(valueOf(2L))).writePoint(g3b).writeScalar(fromBigInteger(valueOf(3L)))
                .writeScalar(fromBigInteger(valueOf(4L))).writePoint(pb).writePoint(qb)
                .writeScalar(fromBigInteger(valueOf(5L))).writeScalar(fromBigInteger(valueOf(6L)))
                .writeScalar(fromBigInteger(valueOf(7L))).toByteArray();
        final SMPMessage2 result = (SMPMessage2) parse(new TLV(SMP2, copyOf(input, input.length + 2)));
        assertEquals(g2b, result.g2b);
        assertEquals(fromBigInteger(valueOf(1L)), result.c2);
        assertEquals(fromBigInteger(valueOf(2L)), result.d2);
        assertEquals(g3b, result.g3b);
        assertEquals(fromBigInteger(valueOf(3L)), result.c3);
        assertEquals(fromBigInteger(valueOf(4L)), result.d3);
        assertEquals(pb, result.pb);
        assertEquals(qb, result.qb);
        assertEquals(fromBigInteger(valueOf(5L)), result.cp);
        assertEquals(fromBigInteger(valueOf(6L)), result.d5);
        assertEquals(fromBigInteger(valueOf(7L)), result.d6);
    }

    @Test(expected = OtrCryptoException.class)
    public void testParseTLVSMP2BadPointG2B() throws OtrCryptoException, ProtocolException {
        final Point g3b = basePoint().multiply(fromBigInteger(valueOf(3L)));
        final Point pb = basePoint().multiply(fromBigInteger(valueOf(4L)));
        final Point qb = basePoint().multiply(fromBigInteger(valueOf(5L)));
        final byte[] input = new OtrOutputStream().writePoint(ILLEGAL_POINT).writeScalar(fromBigInteger(valueOf(1L)))
                .writeScalar(fromBigInteger(valueOf(2L))).writePoint(g3b).writeScalar(fromBigInteger(valueOf(3L)))
                .writeScalar(fromBigInteger(valueOf(4L))).writePoint(pb).writePoint(qb)
                .writeScalar(fromBigInteger(valueOf(5L))).writeScalar(fromBigInteger(valueOf(6L)))
                .writeScalar(fromBigInteger(valueOf(7L))).toByteArray();
        parse(new TLV(SMP2, copyOf(input, input.length + 2)));
    }

    @Test(expected = OtrCryptoException.class)
    public void testParseTLVSMP2BadPointG3B() throws OtrCryptoException, ProtocolException {
        final Point g2b = basePoint().multiply(fromBigInteger(valueOf(2L)));
        final Point pb = basePoint().multiply(fromBigInteger(valueOf(4L)));
        final Point qb = basePoint().multiply(fromBigInteger(valueOf(5L)));
        final byte[] input = new OtrOutputStream().writePoint(g2b).writeScalar(fromBigInteger(valueOf(1L)))
                .writeScalar(fromBigInteger(valueOf(2L))).writePoint(ILLEGAL_POINT)
                .writeScalar(fromBigInteger(valueOf(3L))).writeScalar(fromBigInteger(valueOf(4L))).writePoint(pb)
                .writePoint(qb).writeScalar(fromBigInteger(valueOf(5L))).writeScalar(fromBigInteger(valueOf(6L)))
                .writeScalar(fromBigInteger(valueOf(7L))).toByteArray();
        parse(new TLV(SMP2, copyOf(input, input.length + 2)));
    }

    @Test(expected = OtrCryptoException.class)
    public void testParseTLVSMP2BadPointPB() throws OtrCryptoException, ProtocolException {
        final Point g2b = basePoint().multiply(fromBigInteger(valueOf(2L)));
        final Point g3b = basePoint().multiply(fromBigInteger(valueOf(3L)));
        final Point qb = basePoint().multiply(fromBigInteger(valueOf(5L)));
        final byte[] input = new OtrOutputStream().writePoint(g2b).writeScalar(fromBigInteger(valueOf(1L)))
                .writeScalar(fromBigInteger(valueOf(2L))).writePoint(g3b).writeScalar(fromBigInteger(valueOf(3L)))
                .writeScalar(fromBigInteger(valueOf(4L))).writePoint(ILLEGAL_POINT).writePoint(qb)
                .writeScalar(fromBigInteger(valueOf(5L))).writeScalar(fromBigInteger(valueOf(6L)))
                .writeScalar(fromBigInteger(valueOf(7L))).toByteArray();
        parse(new TLV(SMP2, copyOf(input, input.length + 2)));
    }

    @Test(expected = OtrCryptoException.class)
    public void testParseTLVSMP2BadPointQB() throws OtrCryptoException, ProtocolException {
        final Point g2b = basePoint().multiply(fromBigInteger(valueOf(2L)));
        final Point g3b = basePoint().multiply(fromBigInteger(valueOf(3L)));
        final Point pb = basePoint().multiply(fromBigInteger(valueOf(4L)));
        final byte[] input = new OtrOutputStream().writePoint(g2b).writeScalar(fromBigInteger(valueOf(1L)))
                .writeScalar(fromBigInteger(valueOf(2L))).writePoint(g3b).writeScalar(fromBigInteger(valueOf(3L)))
                .writeScalar(fromBigInteger(valueOf(4L))).writePoint(pb).writePoint(ILLEGAL_POINT)
                .writeScalar(fromBigInteger(valueOf(5L))).writeScalar(fromBigInteger(valueOf(6L)))
                .writeScalar(fromBigInteger(valueOf(7L))).toByteArray();
        parse(new TLV(SMP2, copyOf(input, input.length + 2)));
    }

    @Test
    public void testParseTLVSMP2IncompleteMessage() throws OtrCryptoException, ProtocolException {
        final Point g2b = basePoint().multiply(fromBigInteger(valueOf(2L)));
        final Point g3b = basePoint().multiply(fromBigInteger(valueOf(3L)));
        final Point pb = basePoint().multiply(fromBigInteger(valueOf(4L)));
        final Point qb = basePoint().multiply(fromBigInteger(valueOf(5L)));
        final byte[] data = new OtrOutputStream().writePoint(g2b).writeScalar(fromBigInteger(valueOf(1L)))
                .writeScalar(fromBigInteger(valueOf(2L))).writePoint(g3b).writeScalar(fromBigInteger(valueOf(3L)))
                .writeScalar(fromBigInteger(valueOf(4L))).writePoint(pb).writePoint(qb)
                .writeScalar(fromBigInteger(valueOf(5L))).writeScalar(fromBigInteger(valueOf(6L)))
                .writeScalar(fromBigInteger(valueOf(7L))).toByteArray();
        for (int i = 0; i < data.length; i++) {
            try {
                parse(new TLV(SMP2, copyOf(data, i)));
                fail("Did not expect to successfully parse an incomplete message. Something is probably wrong here.");
            } catch (final ProtocolException ignored) {
                // No need to worry, this was expected to happen.
            }
        }
        assertNotNull(parse(new TLV(SMP2, data)));
    }

    @Test
    public void testParseTLVSMP3() throws OtrCryptoException, ProtocolException {
        final Point pa = basePoint().multiply(fromBigInteger(valueOf(2L)));
        final Point qa = basePoint().multiply(fromBigInteger(valueOf(3L)));
        final Point ra = basePoint().multiply(fromBigInteger(valueOf(4L)));
        final byte[] input = new OtrOutputStream().writePoint(pa).writePoint(qa).writeScalar(fromBigInteger(valueOf(1L)))
                .writeScalar(fromBigInteger(valueOf(2L))).writeScalar(fromBigInteger(valueOf(3L))).writePoint(ra)
                .writeScalar(fromBigInteger(valueOf(4L))).writeScalar(fromBigInteger(valueOf(5L))).toByteArray();
        final SMPMessage3 result = (SMPMessage3) parse(new TLV(SMP3, input));
        assertEquals(pa, result.pa);
        assertEquals(qa, result.qa);
        assertEquals(fromBigInteger(valueOf(1L)), result.cp);
        assertEquals(fromBigInteger(valueOf(2L)), result.d5);
        assertEquals(fromBigInteger(valueOf(3L)), result.d6);
        assertEquals(ra, result.ra);
        assertEquals(fromBigInteger(valueOf(4L)), result.cr);
        assertEquals(fromBigInteger(valueOf(5L)), result.d7);
    }

    @Test
    public void testParseTLVSMP3TooMuchData() throws OtrCryptoException, ProtocolException {
        final Point pa = basePoint().multiply(fromBigInteger(valueOf(2L)));
        final Point qa = basePoint().multiply(fromBigInteger(valueOf(3L)));
        final Point ra = basePoint().multiply(fromBigInteger(valueOf(4L)));
        final byte[] input = new OtrOutputStream().writePoint(pa).writePoint(qa).writeScalar(fromBigInteger(valueOf(1L)))
                .writeScalar(fromBigInteger(valueOf(2L))).writeScalar(fromBigInteger(valueOf(3L))).writePoint(ra)
                .writeScalar(fromBigInteger(valueOf(4L))).writeScalar(fromBigInteger(valueOf(5L))).toByteArray();
        final SMPMessage3 result = (SMPMessage3) parse(new TLV(SMP3, copyOf(input, input.length + 3)));
        assertEquals(pa, result.pa);
        assertEquals(qa, result.qa);
        assertEquals(fromBigInteger(valueOf(1L)), result.cp);
        assertEquals(fromBigInteger(valueOf(2L)), result.d5);
        assertEquals(fromBigInteger(valueOf(3L)), result.d6);
        assertEquals(ra, result.ra);
        assertEquals(fromBigInteger(valueOf(4L)), result.cr);
        assertEquals(fromBigInteger(valueOf(5L)), result.d7);
    }

    @Test(expected = OtrCryptoException.class)
    public void testParseTLVSMP3BadPointPA() throws OtrCryptoException, ProtocolException {
        final Point qa = basePoint().multiply(fromBigInteger(valueOf(3L)));
        final Point ra = basePoint().multiply(fromBigInteger(valueOf(4L)));
        final byte[] input = new OtrOutputStream().writePoint(ILLEGAL_POINT).writePoint(qa)
                .writeScalar(fromBigInteger(valueOf(1L))).writeScalar(fromBigInteger(valueOf(2L)))
                .writeScalar(fromBigInteger(valueOf(3L))).writePoint(ra).writeScalar(fromBigInteger(valueOf(4L)))
                .writeScalar(fromBigInteger(valueOf(5L))).toByteArray();
        parse(new TLV(SMP3, input));
    }

    @Test(expected = OtrCryptoException.class)
    public void testParseTLVSMP3BadPointQA() throws OtrCryptoException, ProtocolException {
        final Point pa = basePoint().multiply(fromBigInteger(valueOf(2L)));
        final Point ra = basePoint().multiply(fromBigInteger(valueOf(4L)));
        final byte[] input = new OtrOutputStream().writePoint(pa).writePoint(ILLEGAL_POINT)
                .writeScalar(fromBigInteger(valueOf(1L))).writeScalar(fromBigInteger(valueOf(2L)))
                .writeScalar(fromBigInteger(valueOf(3L))).writePoint(ra).writeScalar(fromBigInteger(valueOf(4L)))
                .writeScalar(fromBigInteger(valueOf(5L))).toByteArray();
        parse(new TLV(SMP3, input));
    }

    @Test(expected = OtrCryptoException.class)
    public void testParseTLVSMP3BadPointRA() throws OtrCryptoException, ProtocolException {
        final Point pa = basePoint().multiply(fromBigInteger(valueOf(2L)));
        final Point qa = basePoint().multiply(fromBigInteger(valueOf(3L)));
        final byte[] input = new OtrOutputStream().writePoint(pa).writePoint(qa).writeScalar(fromBigInteger(valueOf(1L)))
                .writeScalar(fromBigInteger(valueOf(2L))).writeScalar(fromBigInteger(valueOf(3L)))
                .writePoint(ILLEGAL_POINT).writeScalar(fromBigInteger(valueOf(4L)))
                .writeScalar(fromBigInteger(valueOf(5L))).toByteArray();
        parse(new TLV(SMP3, input));
    }

    @Test
    public void testParseTLVSMP3IncompleteMessage() throws OtrCryptoException, ProtocolException {
        final Point pa = basePoint().multiply(fromBigInteger(valueOf(2L)));
        final Point qa = basePoint().multiply(fromBigInteger(valueOf(3L)));
        final Point ra = basePoint().multiply(fromBigInteger(valueOf(4L)));
        final byte[] data = new OtrOutputStream().writePoint(pa).writePoint(qa).writeScalar(fromBigInteger(valueOf(1L)))
                .writeScalar(fromBigInteger(valueOf(2L))).writeScalar(fromBigInteger(valueOf(3L))).writePoint(ra)
                .writeScalar(fromBigInteger(valueOf(4L))).writeScalar(fromBigInteger(valueOf(5L))).toByteArray();
        for (int i = 0; i < data.length; i++) {
            try {
                parse(new TLV(SMP3, copyOf(data, i)));
                fail("Did not expect to successfully parse an incomplete message. Something is probably wrong here.");
            } catch (final ProtocolException ignored) {
                // No need to worry, this was expected to happen.
            }
        }
        assertNotNull(parse(new TLV(SMP3, data)));
    }

    @Test
    public void testParseTLVSMP4() throws OtrCryptoException, ProtocolException {
        final Point rb = basePoint().multiply(fromBigInteger(valueOf(2L)));
        final byte[] input = new OtrOutputStream().writePoint(rb).writeScalar(fromBigInteger(valueOf(1L)))
                .writeScalar(fromBigInteger(valueOf(2L))).toByteArray();
        final SMPMessage4 result = (SMPMessage4) parse(new TLV(SMP4, input));
        assertEquals(rb, result.rb);
        assertEquals(fromBigInteger(valueOf(1L)), result.cr);
        assertEquals(fromBigInteger(valueOf(2L)), result.d7);
    }

    @Test
    public void testParseTLVSMP4TooMuchData() throws OtrCryptoException, ProtocolException {
        final Point rb = basePoint().multiply(fromBigInteger(valueOf(2L)));
        final byte[] input = new OtrOutputStream().writePoint(rb).writeScalar(fromBigInteger(valueOf(1L)))
                .writeScalar(fromBigInteger(valueOf(2L))).toByteArray();
        final SMPMessage4 result = (SMPMessage4) parse(new TLV(SMP4, copyOf(input, input.length + 3)));
        assertEquals(rb, result.rb);
        assertEquals(fromBigInteger(valueOf(1L)), result.cr);
        assertEquals(fromBigInteger(valueOf(2L)), result.d7);
    }

    @Test(expected = OtrCryptoException.class)
    public void testParseTLVSMP4BadPointRB() throws OtrCryptoException, ProtocolException {
        final Point rb = ILLEGAL_POINT;
        final byte[] input = new OtrOutputStream().writePoint(rb).writeScalar(fromBigInteger(valueOf(1L)))
                .writeScalar(fromBigInteger(valueOf(2L))).toByteArray();
        final SMPMessage4 result = (SMPMessage4) parse(new TLV(SMP4, input));
        assertEquals(rb, result.rb);
        assertEquals(fromBigInteger(valueOf(1L)), result.cr);
        assertEquals(fromBigInteger(valueOf(2L)), result.d7);
    }

    @Test
    public void testParseTLVSMP4IncompleteMessage() throws OtrCryptoException, ProtocolException {
        final Point rb = basePoint().multiply(fromBigInteger(valueOf(2L)));
        final byte[] data = new OtrOutputStream().writePoint(rb).writeScalar(fromBigInteger(valueOf(1L)))
                .writeScalar(fromBigInteger(valueOf(2L))).toByteArray();
        for (int i = 0; i < data.length; i++) {
            try {
                parse(new TLV(SMP4, copyOf(data, i)));
                fail("Did not expect to successfully parse an incomplete message. Something is probably wrong here.");
            } catch (final ProtocolException ignored) {
                // No need to worry, this was expected to happen.
            }
        }
        assertNotNull(parse(new TLV(SMP4, data)));
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testParseTLVSMPAbortMessage() throws OtrCryptoException, ProtocolException {
        parse(new TLV(SMP_ABORT, new byte[0]));
    }
}