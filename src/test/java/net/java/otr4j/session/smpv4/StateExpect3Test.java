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
import org.bouncycastle.crypto.prng.FixedSecureRandom;
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
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@SuppressWarnings("ConstantConditions")
public final class StateExpect3Test {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Point pb = mustDecodePoint(new byte[] {95, 51, -114, -29, 111, -95, -88, -67, -64, -59, -49, 2, 33, -124, 7, -91, 76, -8, -25, -2, -7, 112, 127, 63, 63, -86, -42, 45, -99, 32, 32, -87, -43, 95, -100, 24, -81, -128, -73, 9, 32, 17, 83, -48, -121, -39, 6, -29, -127, 94, -79, 110, -61, 39, -8, -44, -128});
    private static final Point qb = mustDecodePoint(new byte[] {-92, -10, 84, -92, 3, -64, 8, 106, -9, -72, 16, 25, -63, -85, 32, -5, -79, -20, 123, 127, -104, -19, -45, 51, -104, 41, -33, -16, -29, 93, 68, 93, -123, 9, -31, -83, -66, 48, -52, 45, 43, 48, 25, 99, -107, -113, -30, -70, -47, -56, 37, -102, -65, 29, 50, 37, -128});
    private static final Point g3a = mustDecodePoint(new byte[] {30, 7, -88, -11, -74, -46, -28, -39, 1, -123, 15, 76, -75, -102, -102, -33, -8, 47, 7, 57, -87, -101, -48, -17, 27, 8, 95, -96, -112, 7, 56, -8, 65, 121, -87, 32, 103, -68, -81, 68, -7, 92, 71, -123, -122, 81, -103, 119, 39, 71, 56, -90, -121, -124, -98, -66, -128});
    private static final Point g2 = mustDecodePoint(new byte[] {100, -5, -57, 82, 98, 62, -96, 63, -17, 7, 19, -65, 70, 36, 35, 5, 19, -41, 34, 106, 1, -8, 47, -87, 7, 126, 72, -8, -58, 73, -63, -11, -36, 20, -58, 2, 11, 50, 119, -72, -121, -91, -120, 98, 6, -63, -116, 28, -56, -96, -78, 70, 48, 62, 71, 38, 0});
    private static final Point g3 = mustDecodePoint(new byte[] {114, -66, -113, -123, -100, 119, 59, -34, -68, 26, 112, -27, -112, 17, -63, -40, 117, 104, -75, -94, -26, 79, 44, 106, 52, 27, 104, 71, 61, -97, -15, 86, -122, 57, 15, -41, 8, 62, 83, -14, -98, 81, 91, 67, -95, 107, -100, 19, -69, 95, -96, 87, 60, -21, 68, -96, 0});
    private static final Point pa = mustDecodePoint(new byte[] {-101, 21, 13, 39, -73, -66, -16, 64, 11, -99, -81, 6, 79, 100, 5, 69, 64, -51, -27, -116, -117, -97, 46, -41, -105, -1, -19, -15, -54, 79, 126, 1, 22, -75, -15, 24, -105, 42, 123, 123, -111, -27, -7, -94, -122, 20, 100, -12, -25, 4, -70, -38, 114, -19, 115, -64, -128});
    private static final Point qa = mustDecodePoint(new byte[] {65, 37, -115, -60, -79, -97, -85, -93, 44, -40, 8, 83, 35, -87, 7, 65, 87, 102, 122, -94, -102, -83, -38, 31, -123, 60, -42, -113, -14, 58, 123, 126, -55, -30, 36, -112, -4, 49, -16, 52, -66, 60, -36, -11, -47, -26, -30, -121, 61, 80, -63, -21, -44, -9, -108, 95, -128});
    private static final Point ra = mustDecodePoint(new byte[] {-95, -71, -9, 20, -86, 74, -58, -122, -68, 74, -111, -44, 14, 43, 108, -72, 111, -82, 63, 44, -16, 87, -88, -48, -108, 53, 8, -1, 57, 52, -94, -86, -50, -76, -17, -120, -77, -107, -48, -101, 91, -102, 27, 80, -28, -5, -46, -110, 55, 116, -59, 60, 109, 7, 119, -85, -128});
    private static final Point rb = mustDecodePoint(new byte[] {-75, 127, 84, -118, 89, 97, 59, 85, 63, -41, 7, 56, 8, -35, 117, -75, 67, 55, 33, -103, -101, 3, -63, -77, -37, 103, -64, 86, 8, 56, -123, -19, -52, 108, -88, 40, 32, -74, -109, -63, 93, 114, 10, -74, 114, 76, -10, -95, -36, -55, 42, 91, -86, 28, -81, 21, 0});
    private static final Scalar b3 = decodeScalar(new byte[] {-98, -6, 18, -7, -36, -29, -9, -87, 117, 45, -44, 35, -76, -101, -7, -3, 4, 61, -20, -113, 96, -6, 70, 86, -70, 117, -122, 8, 18, -57, 42, 98, 109, -46, -86, -45, 25, -128, -56, 71, -61, -76, -76, 98, 15, -114, -102, -10, -107, 32, 41, -39, -16, 113, 53, 5, 0});
    private static final Scalar cp = decodeScalar(new byte[] {-102, -3, -37, 86, 57, -107, -57, 19, 118, 117, -81, 76, -6, -33, 12, 103, 58, 109, -5, 120, 43, -65, -121, -10, -80, 127, 101, 65, -84, -12, 99, -95, -32, -96, -76, -89, -43, 95, -45, -82, 36, 69, 107, 54, -4, -60, 43, 41, -17, -113, 31, -21, 119, 104, 88, 41, 0});
    private static final Scalar d5 = decodeScalar(new byte[] {92, -33, 26, 108, 7, 58, 50, 77, 102, -39, 109, 47, -1, -9, 35, -58, -7, 110, -50, 125, -89, -128, 21, -42, -96, 98, 78, -31, 6, 99, -124, -67, -87, -26, -44, -43, -102, -72, 60, 112, -67, -24, 95, 120, 105, 126, 12, 83, -114, -102, 71, -123, -65, 4, 59, 4, 0});
    private static final Scalar d6 = decodeScalar(new byte[] {-109, -50, 3, -124, 29, 122, 15, -31, 40, 41, 102, -20, 30, 73, 14, 79, 81, -96, -12, -59, -101, -97, -119, -102, 73, 8, -86, 109, 64, -128, 22, -99, 11, 109, -127, 65, 66, -62, -90, 88, -108, 102, -94, -52, 18, -69, -95, 124, 121, 124, 59, 30, 39, 101, 35, 7, 0});
    private static final Scalar cr = decodeScalar(new byte[] {79, -116, -35, -90, 106, -46, 13, -128, -17, -127, 88, 115, 43, -17, -80, -75, -84, -7, 60, 103, -42, -90, -47, -120, -114, 65, 104, 21, -43, 15, -82, -36, 97, -128, -57, 20, -124, 95, -94, -116, -35, 23, -85, 122, 10, 80, -125, 12, 90, 97, -55, -112, -56, -43, -56, 22, 0});
    private static final Scalar d7 = decodeScalar(new byte[] {-99, -101, -1, 46, -127, -120, 93, -79, -61, -46, 107, 40, 71, -53, 74, 2, 21, -27, -46, 117, -117, 82, 32, 127, 20, 41, 38, 33, -1, 29, -96, 38, -1, 79, 121, -39, 3, -49, -96, -96, 32, -60, 78, -126, -80, -85, 39, -39, -16, -41, 11, 22, 92, -113, 57, 0, 0});

    @Test
    public void testConstruct() {
        final StateExpect3 state = new StateExpect3(RANDOM, pb, qb, b3, g3a, g2, g3);
        assertEquals(INPROGRESS, state.getStatus());
    }

    @Test(expected = NullPointerException.class)
    public void testConstructNullSecureRandom() {
        new StateExpect3(null, pb, qb, b3, g3a, g2, g3);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructNullpb() {
        new StateExpect3(RANDOM, null, qb, b3, g3a, g2, g3);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructNullqb() {
        new StateExpect3(RANDOM, pb, null, b3, g3a, g2, g3);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructNullb3() {
        new StateExpect3(RANDOM, pb, qb, null, g3a, g2, g3);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructNullg3a() {
        new StateExpect3(RANDOM, pb, qb, b3, null, g2, g3);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructNullg2() {
        new StateExpect3(RANDOM, pb, qb, b3, g3a, null, g3);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructNullg3() {
        new StateExpect3(RANDOM, pb, qb, b3, g3a, g2, null);
    }

    @Test(expected = NullPointerException.class)
    public void testInitiateNullContext() throws SMPAbortException {
        final StateExpect3 state = new StateExpect3(RANDOM, pb, qb, b3, g3a, g2, g3);
        state.initiate(null, "test", fromBigInteger(valueOf(1L)));
    }

    @Test(expected = SMPAbortException.class)
    public void testInitiateAbortStateExpect1() throws SMPAbortException {
        final StateExpect3 state = new StateExpect3(RANDOM, pb, qb, b3, g3a, g2, g3);
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
        final StateExpect3 state = new StateExpect3(RANDOM, pb, qb, b3, g3a, g2, g3);
        assertNull(state.respondWithSecret(null, null, null));
    }

    @Test(expected = NullPointerException.class)
    public void testProcessNullContext() throws SMPAbortException {
        final StateExpect3 state = new StateExpect3(RANDOM, pb, qb, b3, g3a, g2, g3);
        final SMPMessage3 message = new SMPMessage3(pa, qa, cp, d5, d6, ra, cr, d7);
        state.process(null, message);
    }

    @Test(expected = NullPointerException.class)
    public void testProcessNullMessage() throws SMPAbortException {
        final StateExpect3 state = new StateExpect3(RANDOM, pb, qb, b3, g3a, g2, g3);
        final SMPContext context = mock(SMPContext.class);
        state.process(context, null);
    }

    @Test
    public void testProcessMessageSMPSucceeded() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {-40, 85, 67, 42, 62, -26, -43, 26, -79, -128, 38, 13, -8, 79, -92, -109, -31, 66, -26, -12, 100, 56, -97, 118, -36, 68, 19, 68, 118, -70, 69, -66, 86, 104, 39, 27, -37, -43, -52, 73, -56, 98, -40, 46, 91, 1, 29, -49, 6, -100, -80, -9, -41, -4, -89, -103, 104};
        final Scalar expectedCr = decodeScalar(new byte[] {-38, -118, 6, 30, 83, -74, -99, 15, -122, 103, 59, 81, -2, 64, 87, 127, 109, 32, 96, -45, 64, 52, 87, 98, -96, -47, -10, 27, -107, 93, 11, 33, -19, -46, -29, 108, -46, -124, 73, 15, 49, 92, 55, -52, 0, 92, 32, 7, -48, -77, -43, -60, -38, -120, 98, 0, 0});
        final Scalar expectedD7 = decodeScalar(new byte[] {4, -122, 117, -105, 10, 14, -8, 87, -60, 105, -99, -31, -59, 98, -128, 58, -12, 104, 57, -110, -112, 59, 21, 46, 127, -104, 58, 112, -102, 95, 52, -72, 48, 79, 95, -122, -104, 15, -46, -89, 80, -6, 73, 62, 83, 79, 100, 99, 84, -109, 7, -53, 105, 123, 54, 56, 0});
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb, qb, b3, g3a, g2, g3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(pa, qa, cp, d5, d6, ra, cr, d7);
        final SMPMessage4 response = state.process(context, message);
        assertEquals(rb, response.rb);
        assertEquals(expectedCr, response.cr);
        assertEquals(expectedD7, response.d7);
        verify(context).setState(any(StateExpect4.class));
    }

    @Test
    public void testProcessMessageSMPFailed() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {-40, 85, 67, 42, 62, -26, -43, 26, -79, -128, 38, 13, -8, 79, -92, -109, -31, 66, -26, -12, 100, 56, -97, 118, -36, 68, 19, 68, 118, -70, 69, -66, 86, 104, 39, 27, -37, -43, -52, 73, -56, 98, -40, 46, 91, 1, 29, -49, 6, -100, -80, -9, -41, -4, -89, -103, 104};
        final Scalar expectedCr = decodeScalar(new byte[] {-38, -118, 6, 30, 83, -74, -99, 15, -122, 103, 59, 81, -2, 64, 87, 127, 109, 32, 96, -45, 64, 52, 87, 98, -96, -47, -10, 27, -107, 93, 11, 33, -19, -46, -29, 108, -46, -124, 73, 15, 49, 92, 55, -52, 0, 92, 32, 7, -48, -77, -43, -60, -38, -120, 98, 0, 0});
        final Scalar expectedD7 = decodeScalar(new byte[] {4, -122, 117, -105, 10, 14, -8, 87, -60, 105, -99, -31, -59, 98, -128, 58, -12, 104, 57, -110, -112, 59, 21, 46, 127, -104, 58, 112, -102, 95, 52, -72, 48, 79, 95, -122, -104, 15, -46, -89, 80, -6, 73, 62, 83, 79, 100, 99, 84, -109, 7, -53, 105, 123, 54, 56, 0});
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb.negate(), qb, b3, g3a, g2, g3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(pa, qa, cp, d5, d6, ra, cr, d7);
        final SMPMessage4 response = state.process(context, message);
        assertEquals(rb, response.rb);
        assertEquals(expectedCr, response.cr);
        assertEquals(expectedD7, response.d7);
        // TODO investigate if following verification statement works. There seem to be some unexpected results.
        verify(context).setState(any(StateExpect1.class));
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadqb() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {-40, 85, 67, 42, 62, -26, -43, 26, -79, -128, 38, 13, -8, 79, -92, -109, -31, 66, -26, -12, 100, 56, -97, 118, -36, 68, 19, 68, 118, -70, 69, -66, 86, 104, 39, 27, -37, -43, -52, 73, -56, 98, -40, 46, 91, 1, 29, -49, 6, -100, -80, -9, -41, -4, -89, -103, 104};
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb, qb.negate(), b3, g3a, g2, g3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(pa, qa, cp, d5, d6, ra, cr, d7);
        state.process(context, message);
    }

    @Test
    public void testProcessMessageBadb3() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {-40, 85, 67, 42, 62, -26, -43, 26, -79, -128, 38, 13, -8, 79, -92, -109, -31, 66, -26, -12, 100, 56, -97, 118, -36, 68, 19, 68, 118, -70, 69, -66, 86, 104, 39, 27, -37, -43, -52, 73, -56, 98, -40, 46, 91, 1, 29, -49, 6, -100, -80, -9, -41, -4, -89, -103, 104};
        final Scalar expectedCr = decodeScalar(new byte[] {-38, -118, 6, 30, 83, -74, -99, 15, -122, 103, 59, 81, -2, 64, 87, 127, 109, 32, 96, -45, 64, 52, 87, 98, -96, -47, -10, 27, -107, 93, 11, 33, -19, -46, -29, 108, -46, -124, 73, 15, 49, 92, 55, -52, 0, 92, 32, 7, -48, -77, -43, -60, -38, -120, 98, 0, 0});
        final Scalar expectedD7 = decodeScalar(new byte[] {4, -122, 117, -105, 10, 14, -8, 87, -60, 105, -99, -31, -59, 98, -128, 58, -12, 104, 57, -110, -112, 59, 21, 46, 127, -104, 58, 112, -102, 95, 52, -72, 48, 79, 95, -122, -104, 15, -46, -89, 80, -6, 73, 62, 83, 79, 100, 99, 84, -109, 7, -53, 105, 123, 54, 56, 0});
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb, qb, Scalars.one(), g3a, g2, g3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(pa, qa, cp, d5, d6, ra, cr, d7);
        final SMPMessage4 response = state.process(context, message);
        assertNotEquals(rb, response.rb);
        assertEquals(expectedCr, response.cr);
        assertNotEquals(expectedD7, response.d7);
        // TODO investigate if following verification statement works. There seem to be some unexpected results.
        verify(context).setState(any(StateExpect1.class));
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadg3a() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {-40, 85, 67, 42, 62, -26, -43, 26, -79, -128, 38, 13, -8, 79, -92, -109, -31, 66, -26, -12, 100, 56, -97, 118, -36, 68, 19, 68, 118, -70, 69, -66, 86, 104, 39, 27, -37, -43, -52, 73, -56, 98, -40, 46, 91, 1, 29, -49, 6, -100, -80, -9, -41, -4, -89, -103, 104};
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb, qb, b3, g3a.negate(), g2, g3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(pa, qa, cp, d5, d6, ra, cr, d7);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadg2() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {-40, 85, 67, 42, 62, -26, -43, 26, -79, -128, 38, 13, -8, 79, -92, -109, -31, 66, -26, -12, 100, 56, -97, 118, -36, 68, 19, 68, 118, -70, 69, -66, 86, 104, 39, 27, -37, -43, -52, 73, -56, 98, -40, 46, 91, 1, 29, -49, 6, -100, -80, -9, -41, -4, -89, -103, 104};
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb, qb, b3, g3a, g2.negate(), g3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(pa, qa, cp, d5, d6, ra, cr, d7);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadg3() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {-40, 85, 67, 42, 62, -26, -43, 26, -79, -128, 38, 13, -8, 79, -92, -109, -31, 66, -26, -12, 100, 56, -97, 118, -36, 68, 19, 68, 118, -70, 69, -66, 86, 104, 39, 27, -37, -43, -52, 73, -56, 98, -40, 46, 91, 1, 29, -49, 6, -100, -80, -9, -41, -4, -89, -103, 104};
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb, qb, b3, g3a, g2, g3.negate());
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(pa, qa, cp, d5, d6, ra, cr, d7);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadpa() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {-40, 85, 67, 42, 62, -26, -43, 26, -79, -128, 38, 13, -8, 79, -92, -109, -31, 66, -26, -12, 100, 56, -97, 118, -36, 68, 19, 68, 118, -70, 69, -66, 86, 104, 39, 27, -37, -43, -52, 73, -56, 98, -40, 46, 91, 1, 29, -49, 6, -100, -80, -9, -41, -4, -89, -103, 104};
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb, qb, b3, g3a, g2, g3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(pa.negate(), qa, cp, d5, d6, ra, cr, d7);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadqa() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {-40, 85, 67, 42, 62, -26, -43, 26, -79, -128, 38, 13, -8, 79, -92, -109, -31, 66, -26, -12, 100, 56, -97, 118, -36, 68, 19, 68, 118, -70, 69, -66, 86, 104, 39, 27, -37, -43, -52, 73, -56, 98, -40, 46, 91, 1, 29, -49, 6, -100, -80, -9, -41, -4, -89, -103, 104};
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb, qb, b3, g3a, g2, g3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(pa, qa.negate(), cp, d5, d6, ra, cr, d7);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadcp() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {-40, 85, 67, 42, 62, -26, -43, 26, -79, -128, 38, 13, -8, 79, -92, -109, -31, 66, -26, -12, 100, 56, -97, 118, -36, 68, 19, 68, 118, -70, 69, -66, 86, 104, 39, 27, -37, -43, -52, 73, -56, 98, -40, 46, 91, 1, 29, -49, 6, -100, -80, -9, -41, -4, -89, -103, 104};
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb, qb, b3, g3a, g2, g3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(pa, qa, Scalars.one(), d5, d6, ra, cr, d7);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadd5() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {-40, 85, 67, 42, 62, -26, -43, 26, -79, -128, 38, 13, -8, 79, -92, -109, -31, 66, -26, -12, 100, 56, -97, 118, -36, 68, 19, 68, 118, -70, 69, -66, 86, 104, 39, 27, -37, -43, -52, 73, -56, 98, -40, 46, 91, 1, 29, -49, 6, -100, -80, -9, -41, -4, -89, -103, 104};
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb, qb, b3, g3a, g2, g3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(pa, qa, cp, Scalars.one(), d6, ra, cr, d7);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadd6() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {-40, 85, 67, 42, 62, -26, -43, 26, -79, -128, 38, 13, -8, 79, -92, -109, -31, 66, -26, -12, 100, 56, -97, 118, -36, 68, 19, 68, 118, -70, 69, -66, 86, 104, 39, 27, -37, -43, -52, 73, -56, 98, -40, 46, 91, 1, 29, -49, 6, -100, -80, -9, -41, -4, -89, -103, 104};
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb, qb, b3, g3a, g2, g3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(pa, qa, cp, d5, Scalars.one(), ra, cr, d7);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadra() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {-40, 85, 67, 42, 62, -26, -43, 26, -79, -128, 38, 13, -8, 79, -92, -109, -31, 66, -26, -12, 100, 56, -97, 118, -36, 68, 19, 68, 118, -70, 69, -66, 86, 104, 39, 27, -37, -43, -52, 73, -56, 98, -40, 46, 91, 1, 29, -49, 6, -100, -80, -9, -41, -4, -89, -103, 104};
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb, qb, b3, g3a, g2, g3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(pa, qa, cp, d5, d6, ra.negate(), cr, d7);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadcr() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {-40, 85, 67, 42, 62, -26, -43, 26, -79, -128, 38, 13, -8, 79, -92, -109, -31, 66, -26, -12, 100, 56, -97, 118, -36, 68, 19, 68, 118, -70, 69, -66, 86, 104, 39, 27, -37, -43, -52, 73, -56, 98, -40, 46, 91, 1, 29, -49, 6, -100, -80, -9, -41, -4, -89, -103, 104};
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb, qb, b3, g3a, g2, g3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(pa, qa, cp, d5, d6, ra, Scalars.one(), d7);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadd7() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {-40, 85, 67, 42, 62, -26, -43, 26, -79, -128, 38, 13, -8, 79, -92, -109, -31, 66, -26, -12, 100, 56, -97, 118, -36, 68, 19, 68, 118, -70, 69, -66, 86, 104, 39, 27, -37, -43, -52, 73, -56, 98, -40, 46, 91, 1, 29, -49, 6, -100, -80, -9, -41, -4, -89, -103, 104};
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb, qb, b3, g3a, g2, g3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(pa, qa, cp, d5, d6, ra, cr, Scalars.one());
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageIllegalpa() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {-40, 85, 67, 42, 62, -26, -43, 26, -79, -128, 38, 13, -8, 79, -92, -109, -31, 66, -26, -12, 100, 56, -97, 118, -36, 68, 19, 68, 118, -70, 69, -66, 86, 104, 39, 27, -37, -43, -52, 73, -56, 98, -40, 46, 91, 1, 29, -49, 6, -100, -80, -9, -41, -4, -89, -103, 104};
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb, qb, b3, g3a, g2, g3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(createPoint(BigInteger.ONE, BigInteger.ONE), qa, cp, d5, d6, ra, cr,
                Scalars.one());
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageIllegalqa() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {-40, 85, 67, 42, 62, -26, -43, 26, -79, -128, 38, 13, -8, 79, -92, -109, -31, 66, -26, -12, 100, 56, -97, 118, -36, 68, 19, 68, 118, -70, 69, -66, 86, 104, 39, 27, -37, -43, -52, 73, -56, 98, -40, 46, 91, 1, 29, -49, 6, -100, -80, -9, -41, -4, -89, -103, 104};
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb, qb, b3, g3a, g2, g3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(pa, createPoint(BigInteger.ONE, BigInteger.ONE), cp, d5, d6, ra, cr,
                Scalars.one());
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageIllegalra() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {-40, 85, 67, 42, 62, -26, -43, 26, -79, -128, 38, 13, -8, 79, -92, -109, -31, 66, -26, -12, 100, 56, -97, 118, -36, 68, 19, 68, 118, -70, 69, -66, 86, 104, 39, 27, -37, -43, -52, 73, -56, 98, -40, 46, 91, 1, 29, -49, 6, -100, -80, -9, -41, -4, -89, -103, 104};
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb, qb, b3, g3a, g2, g3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(pa, qa, cp, d5, d6, createPoint(BigInteger.ONE, BigInteger.ONE), cr,
                Scalars.one());
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadMessage() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {-40, 85, 67, 42, 62, -26, -43, 26, -79, -128, 38, 13, -8, 79, -92, -109, -31, 66, -26, -12, 100, 56, -97, 118, -36, 68, 19, 68, 118, -70, 69, -66, 86, 104, 39, 27, -37, -43, -52, 73, -56, 98, -40, 46, 91, 1, 29, -49, 6, -100, -80, -9, -41, -4, -89, -103, 104};
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb, qb, b3, g3a, g2, g3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage4 message = new SMPMessage4(rb, cr, d7);
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