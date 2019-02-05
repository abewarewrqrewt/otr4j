/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.smpv4;

import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.crypto.ed448.Scalar;
import net.java.otr4j.crypto.ed448.Scalars;
import net.java.otr4j.crypto.ed448.ValidationException;
import org.junit.Test;

import javax.annotation.Nonnull;
import java.math.BigInteger;
import java.security.SecureRandom;

import static java.math.BigInteger.valueOf;
import static net.java.otr4j.crypto.ed448.Point.decodePoint;
import static net.java.otr4j.crypto.ed448.PointTestUtils.createPoint;
import static net.java.otr4j.crypto.ed448.Scalar.decodeScalar;
import static net.java.otr4j.crypto.ed448.ScalarTestUtils.fromBigInteger;
import static net.java.otr4j.session.api.SMPStatus.INPROGRESS;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@SuppressWarnings("ConstantConditions")
public final class StateExpect4Test {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Point pb = mustDecodePoint(new byte[] {95, 51, -114, -29, 111, -95, -88, -67, -64, -59, -49, 2, 33, -124, 7, -91, 76, -8, -25, -2, -7, 112, 127, 63, 63, -86, -42, 45, -99, 32, 32, -87, -43, 95, -100, 24, -81, -128, -73, 9, 32, 17, 83, -48, -121, -39, 6, -29, -127, 94, -79, 110, -61, 39, -8, -44, -128});
    private static final Point qb = mustDecodePoint(new byte[] {-92, -10, 84, -92, 3, -64, 8, 106, -9, -72, 16, 25, -63, -85, 32, -5, -79, -20, 123, 127, -104, -19, -45, 51, -104, 41, -33, -16, -29, 93, 68, 93, -123, 9, -31, -83, -66, 48, -52, 45, 43, 48, 25, 99, -107, -113, -30, -70, -47, -56, 37, -102, -65, 29, 50, 37, -128});
    private static final Point pa = mustDecodePoint(new byte[] {-101, 21, 13, 39, -73, -66, -16, 64, 11, -99, -81, 6, 79, 100, 5, 69, 64, -51, -27, -116, -117, -97, 46, -41, -105, -1, -19, -15, -54, 79, 126, 1, 22, -75, -15, 24, -105, 42, 123, 123, -111, -27, -7, -94, -122, 20, 100, -12, -25, 4, -70, -38, 114, -19, 115, -64, -128});
    private static final Point qa = mustDecodePoint(new byte[] {65, 37, -115, -60, -79, -97, -85, -93, 44, -40, 8, 83, 35, -87, 7, 65, 87, 102, 122, -94, -102, -83, -38, 31, -123, 60, -42, -113, -14, 58, 123, 126, -55, -30, 36, -112, -4, 49, -16, 52, -66, 60, -36, -11, -47, -26, -30, -121, 61, 80, -63, -21, -44, -9, -108, 95, -128});
    private static final Point ra = mustDecodePoint(new byte[] {-95, -71, -9, 20, -86, 74, -58, -122, -68, 74, -111, -44, 14, 43, 108, -72, 111, -82, 63, 44, -16, 87, -88, -48, -108, 53, 8, -1, 57, 52, -94, -86, -50, -76, -17, -120, -77, -107, -48, -101, 91, -102, 27, 80, -28, -5, -46, -110, 55, 116, -59, 60, 109, 7, 119, -85, -128});
    private static final Point rb = mustDecodePoint(new byte[] {-75, 127, 84, -118, 89, 97, 59, 85, 63, -41, 7, 56, 8, -35, 117, -75, 67, 55, 33, -103, -101, 3, -63, -77, -37, 103, -64, 86, 8, 56, -123, -19, -52, 108, -88, 40, 32, -74, -109, -63, 93, 114, 10, -74, 114, 76, -10, -95, -36, -55, 42, 91, -86, 28, -81, 21, 0});
    private static final Scalar cp = decodeScalar(new byte[] {-102, -3, -37, 86, 57, -107, -57, 19, 118, 117, -81, 76, -6, -33, 12, 103, 58, 109, -5, 120, 43, -65, -121, -10, -80, 127, 101, 65, -84, -12, 99, -95, -32, -96, -76, -89, -43, 95, -45, -82, 36, 69, 107, 54, -4, -60, 43, 41, -17, -113, 31, -21, 119, 104, 88, 41, 0});
    private static final Scalar d5 = decodeScalar(new byte[] {92, -33, 26, 108, 7, 58, 50, 77, 102, -39, 109, 47, -1, -9, 35, -58, -7, 110, -50, 125, -89, -128, 21, -42, -96, 98, 78, -31, 6, 99, -124, -67, -87, -26, -44, -43, -102, -72, 60, 112, -67, -24, 95, 120, 105, 126, 12, 83, -114, -102, 71, -123, -65, 4, 59, 4, 0});
    private static final Scalar d6 = decodeScalar(new byte[] {-109, -50, 3, -124, 29, 122, 15, -31, 40, 41, 102, -20, 30, 73, 14, 79, 81, -96, -12, -59, -101, -97, -119, -102, 73, 8, -86, 109, 64, -128, 22, -99, 11, 109, -127, 65, 66, -62, -90, 88, -108, 102, -94, -52, 18, -69, -95, 124, 121, 124, 59, 30, 39, 101, 35, 7, 0});
    private static final Scalar cr = decodeScalar(new byte[] {-38, -118, 6, 30, 83, -74, -99, 15, -122, 103, 59, 81, -2, 64, 87, 127, 109, 32, 96, -45, 64, 52, 87, 98, -96, -47, -10, 27, -107, 93, 11, 33, -19, -46, -29, 108, -46, -124, 73, 15, 49, 92, 55, -52, 0, 92, 32, 7, -48, -77, -43, -60, -38, -120, 98, 0, 0});
    private static final Scalar d7 = decodeScalar(new byte[] {4, -122, 117, -105, 10, 14, -8, 87, -60, 105, -99, -31, -59, 98, -128, 58, -12, 104, 57, -110, -112, 59, 21, 46, 127, -104, 58, 112, -102, 95, 52, -72, 48, 79, 95, -122, -104, 15, -46, -89, 80, -6, 73, 62, 83, 79, 100, 99, 84, -109, 7, -53, 105, 123, 54, 56, 0});
    private static final Scalar a3 = decodeScalar(new byte[] {3, -43, 43, -72, 28, 126, 101, -89, -37, 80, -56, 114, -51, 10, 59, 67, 116, -91, -125, -16, -11, -98, -107, -48, 59, 110, -7, -22, 41, -75, 102, -122, 82, 83, -113, -74, -63, -59, 80, -121, -83, 18, -25, -63, -46, -54, -90, 23, -60, -32, -40, 85, -90, 122, 92, 52, 0});
    private static final Point g3b = mustDecodePoint(new byte[] {-17, -118, 59, 116, -59, 126, -118, -18, -97, 26, 126, -112, 95, 89, -69, 120, 89, -19, -70, -52, -39, 36, 110, 116, -41, -85, 71, -47, 110, -35, 88, -12, 39, 74, -52, -13, -39, -80, -12, 43, -113, 75, 119, -110, 29, 108, 46, 94, 20, 101, -94, -4, 75, -49, 20, 62, 0});

    @Test(expected = NullPointerException.class)
    public void testConstructNullSecureRandom() {
        new StateExpect4(null, a3, g3b, pa, pb, qa, qb);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructNulla3() {
        new StateExpect4(RANDOM, null, g3b, pa, pb, qa, qb);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructNullg3b() {
        new StateExpect4(RANDOM, a3, null, pa, pb, qa, qb);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructNullpa() {
        new StateExpect4(RANDOM, a3, g3b, null, pb, qa, qb);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructNullpb() {
        new StateExpect4(RANDOM, a3, g3b, pa, null, qa, qb);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructNullqa() {
        new StateExpect4(RANDOM, a3, g3b, pa, pb, null, qb);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructNullqb() {
        new StateExpect4(RANDOM, a3, g3b, pa, pb, qa, null);
    }

    @Test
    public void testConstruct() {
        final StateExpect4 state = new StateExpect4(RANDOM, a3, g3b, pa, pb, qa, qb);
        assertEquals(INPROGRESS, state.getStatus());
    }

    @Test(expected = NullPointerException.class)
    public void testInitiateNullContext() throws SMPAbortException {
        final StateExpect4 state = new StateExpect4(RANDOM, a3, g3b, pa, pb, qa, qb);
        state.initiate(null, "test", fromBigInteger(valueOf(1L)));
    }

    @Test(expected = SMPAbortException.class)
    public void testInitiateAbortStateExpect1() throws SMPAbortException {
        final StateExpect4 state = new StateExpect4(RANDOM, a3, g3b, pa, pb, qa, qb);
        final SMPContext context = mock(SMPContext.class);
        try {
            state.initiate(context, "test", fromBigInteger(valueOf(1L)));
            fail("Expected SMP initiation to fail.");
        } catch (final SMPAbortException e) {
            verify(context).setState(any(StateExpect1.class));
            throw e;
        }
    }

    @Test
    public void testRespondWithSecret() {
        final StateExpect4 state = new StateExpect4(RANDOM, a3, g3b, pa, pb, qa, qb);
        assertNull(state.respondWithSecret(null, null, null));
    }

    @Test(expected = NullPointerException.class)
    public void testProcessNullContext() throws SMPAbortException {
        final StateExpect4 state = new StateExpect4(RANDOM, a3, g3b, pa, pb, qa, qb);
        final SMPMessage4 message = new SMPMessage4(rb, cr, d7);
        state.process(null, message);
    }

    @Test(expected = NullPointerException.class)
    public void testProcessNullMessage() throws SMPAbortException {
        final StateExpect4 state = new StateExpect4(RANDOM, a3, g3b, pa, pb, qa, qb);
        final SMPContext context = mock(SMPContext.class);
        state.process(context, null);
    }

    @Test
    public void testProcessCorrectMessage() throws SMPAbortException {
        final StateExpect4 state = new StateExpect4(RANDOM, a3, g3b, pa, pb, qa, qb);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage4 message = new SMPMessage4(rb, cr, d7);
        assertNull(state.process(context, message));
        // TODO investigate if following verification statement works. There seem to be some unexpected results.
        verify(context).setState(any(StateExpect1.class));
    }

    @Test
    public void testProcessBadMessageBadpb() throws SMPAbortException {
        final StateExpect4 state = new StateExpect4(RANDOM, a3, g3b, pa, pb.negate(), qa, qb);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage4 message = new SMPMessage4(rb, cr, d7);
        assertNull(state.process(context, message));
        // TODO investigate if following verification statement works. There seem to be some unexpected results.
        verify(context).setState(any(StateExpect1.class));
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessBadMessageBadrb() throws SMPAbortException {
        final StateExpect4 state = new StateExpect4(RANDOM, a3, g3b, pa, pb, qa, qb);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage4 message = new SMPMessage4(rb.negate(), cr, d7);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessBadMessageIllegalcr() throws SMPAbortException {
        final StateExpect4 state = new StateExpect4(RANDOM, a3, g3b, pa, pb, qa, qb);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage4 message = new SMPMessage4(rb, Scalars.one(), d7);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessBadMessageIllegald7() throws SMPAbortException {
        final StateExpect4 state = new StateExpect4(RANDOM, a3, g3b, pa, pb, qa, qb);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage4 message = new SMPMessage4(rb, cr, Scalars.one());
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessBadMessageIllegalrb() throws SMPAbortException {
        final StateExpect4 state = new StateExpect4(RANDOM, a3, g3b, pa, pb, qa, qb);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage4 message = new SMPMessage4(createPoint(BigInteger.ONE, BigInteger.ONE), cr, Scalars.one());
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessBadMessageBada3() throws SMPAbortException {
        final StateExpect4 state = new StateExpect4(RANDOM, Scalars.one(), g3b, pa, pb, qa, qb);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage4 message = new SMPMessage4(rb, cr, Scalars.one());
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessBadMessageBadg3b() throws SMPAbortException {
        final StateExpect4 state = new StateExpect4(RANDOM, a3, g3b.negate(), pa, pb, qa, qb);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage4 message = new SMPMessage4(rb, cr, Scalars.one());
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessBadMessageBadpa() throws SMPAbortException {
        final StateExpect4 state = new StateExpect4(RANDOM, a3, g3b, pa.negate(), pb, qa, qb);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage4 message = new SMPMessage4(rb, cr, Scalars.one());
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessBadMessageBadqa() throws SMPAbortException {
        final StateExpect4 state = new StateExpect4(RANDOM, a3, g3b, pa, pb, qa.negate(), qb);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage4 message = new SMPMessage4(rb, cr, Scalars.one());
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessBadMessageBadqb() throws SMPAbortException {
        final StateExpect4 state = new StateExpect4(RANDOM, a3, g3b, pa, pb, qa, qb.negate());
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage4 message = new SMPMessage4(rb, cr, Scalars.one());
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessWrongMessage() throws SMPAbortException {
        final StateExpect4 state = new StateExpect4(RANDOM, a3, g3b, pa, pb, qa, qb.negate());
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(pa, qa, cp, d5, d6, ra, cr, d7);
        state.process(context, message);
    }

    private static Point mustDecodePoint(@Nonnull final byte[] encoded) {
        try {
            return decodePoint(encoded);
        } catch (final ValidationException e) {
            throw new IllegalArgumentException("Illegal point.", e);
        }
    }
}