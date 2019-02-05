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
public final class StateExpect2Test {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Scalar secret = decodeScalar(new byte[]{20, 92, 91, -92, 30, 124, 119, 30, 105, -90, -78, -108, -62, 50, -102, -55, -32, -77, -114, 60, 16, 42, 111, -15, -10, 69, -77, -107, 127, -10, 26, -90, 12, 49, 71, 31, -96, -124, 19, 33, 69, 45, 56, -30, -76, -39, -21, -47, 19, 63, -57, 111, -60, 51, -75, 14, 0});
    private static final Point g2b = mustDecodePoint(new byte[]{-30, 95, 30, -93, -64, 52, -54, -25, 107, -80, -90, 121, -55, -113, 49, -87, -109, 109, -92, 66, -17, -109, 38, 97, 90, -116, 68, -116, -88, -37, -13, -87, 53, 46, -38, -85, -23, -110, 1, 74, 121, 63, 106, -66, 113, 28, -7, -45, -2, 14, -91, -6, 117, 82, -110, -26, 0});
    private static final Point g3b = mustDecodePoint(new byte[]{-17, -118, 59, 116, -59, 126, -118, -18, -97, 26, 126, -112, 95, 89, -69, 120, 89, -19, -70, -52, -39, 36, 110, 116, -41, -85, 71, -47, 110, -35, 88, -12, 39, 74, -52, -13, -39, -80, -12, 43, -113, 75, 119, -110, 29, 108, 46, 94, 20, 101, -94, -4, 75, -49, 20, 62, 0});
    private static final Point pb = mustDecodePoint(new byte[]{95, 51, -114, -29, 111, -95, -88, -67, -64, -59, -49, 2, 33, -124, 7, -91, 76, -8, -25, -2, -7, 112, 127, 63, 63, -86, -42, 45, -99, 32, 32, -87, -43, 95, -100, 24, -81, -128, -73, 9, 32, 17, 83, -48, -121, -39, 6, -29, -127, 94, -79, 110, -61, 39, -8, -44, -128});
    private static final Point qb = mustDecodePoint(new byte[]{-92, -10, 84, -92, 3, -64, 8, 106, -9, -72, 16, 25, -63, -85, 32, -5, -79, -20, 123, 127, -104, -19, -45, 51, -104, 41, -33, -16, -29, 93, 68, 93, -123, 9, -31, -83, -66, 48, -52, 45, 43, 48, 25, 99, -107, -113, -30, -70, -47, -56, 37, -102, -65, 29, 50, 37, -128});
    private static final Point pa = mustDecodePoint(new byte[]{-101, 21, 13, 39, -73, -66, -16, 64, 11, -99, -81, 6, 79, 100, 5, 69, 64, -51, -27, -116, -117, -97, 46, -41, -105, -1, -19, -15, -54, 79, 126, 1, 22, -75, -15, 24, -105, 42, 123, 123, -111, -27, -7, -94, -122, 20, 100, -12, -25, 4, -70, -38, 114, -19, 115, -64, -128});
    private static final Point qa = mustDecodePoint(new byte[]{65, 37, -115, -60, -79, -97, -85, -93, 44, -40, 8, 83, 35, -87, 7, 65, 87, 102, 122, -94, -102, -83, -38, 31, -123, 60, -42, -113, -14, 58, 123, 126, -55, -30, 36, -112, -4, 49, -16, 52, -66, 60, -36, -11, -47, -26, -30, -121, 61, 80, -63, -21, -44, -9, -108, 95, -128});
    private static final Point ra = mustDecodePoint(new byte[]{-95, -71, -9, 20, -86, 74, -58, -122, -68, 74, -111, -44, 14, 43, 108, -72, 111, -82, 63, 44, -16, 87, -88, -48, -108, 53, 8, -1, 57, 52, -94, -86, -50, -76, -17, -120, -77, -107, -48, -101, 91, -102, 27, 80, -28, -5, -46, -110, 55, 116, -59, 60, 109, 7, 119, -85, -128});
    private static final Scalar a2 = decodeScalar(new byte[]{-25, 106, 19, -40, -99, 112, 45, 70, -82, 103, 47, 103, 68, -45, -113, -85, -78, -113, -21, 62, -28, -13, -94, 90, -9, -70, 35, -52, 6, -71, -40, 73, -45, 73, -21, -121, -10, 31, -31, 106, 70, -67, 92, -35, -86, 34, -84, -49, -57, -18, -57, 96, 12, -20, 15, 33, 0});
    private static final Scalar a3 = decodeScalar(new byte[]{3, -43, 43, -72, 28, 126, 101, -89, -37, 80, -56, 114, -51, 10, 59, 67, 116, -91, -125, -16, -11, -98, -107, -48, 59, 110, -7, -22, 41, -75, 102, -122, 82, 83, -113, -74, -63, -59, 80, -121, -83, 18, -25, -63, -46, -54, -90, 23, -60, -32, -40, 85, -90, 122, 92, 52, 0});
    private static final Scalar c2 = decodeScalar(new byte[]{-77, 66, 65, -103, -64, -14, 40, -56, -39, 54, 82, 58, 47, 24, -65, -85, -15, -19, 103, -7, -102, 94, -32, -66, -106, -128, 18, -112, 52, 102, -64, -29, 122, -43, 22, 31, 124, -58, 99, -5, 38, 92, -9, -128, 30, -84, -76, -95, 22, -114, -2, -88, -90, -101, 69, 53, 0});
    private static final Scalar d2 = decodeScalar(new byte[]{-78, -92, 106, 27, 18, -117, -66, 59, 62, -97, 17, -34, 107, -119, 35, 96, 31, -79, 76, 116, 77, -9, -81, -38, -86, -99, -28, -98, -61, 13, 29, -32, -92, 44, -51, 88, 59, -123, -58, -74, 25, 2, 49, 126, -58, 100, -79, -27, 102, -12, -10, 63, 65, 5, -30, 19, 0});
    private static final Scalar c3 = decodeScalar(new byte[]{91, 55, 111, -62, -50, -84, 43, 21, -58, 1, -77, -119, -97, 9, 67, 65, 8, -6, 2, -67, -89, 113, -38, -82, -19, 98, -7, -33, -7, 105, 23, 117, 55, 29, -91, -18, -114, 116, 37, -104, -116, -113, -82, 51, 9, 106, -90, -43, 89, -16, 100, 55, -55, 120, 6, 32, 0});
    private static final Scalar d3 = decodeScalar(new byte[]{30, -10, 99, 65, -59, 11, 45, 8, -43, -115, -65, -98, -22, 96, -26, -38, 33, 116, -87, 98, 67, -42, 70, -93, -90, -68, 23, 95, 116, -126, -56, -34, -88, 76, -2, 125, -17, -111, -2, -128, 98, 126, -104, -96, -67, -79, -3, -35, 122, 111, 58, 32, 68, 77, 79, 40, 0});
    private static final Scalar cp = decodeScalar(new byte[]{-56, 102, 78, -80, -93, -35, 4, 65, 59, 65, -98, -98, -58, -40, 22, -71, 16, -100, -13, 4, -8, 34, 10, -110, 94, -62, 55, -5, -41, 61, -33, 112, 7, 33, -111, -32, 38, 67, 89, -5, -83, 76, 85, -97, -59, -50, -38, -47, -80, -106, 58, 34, -32, 44, -1, 22, 0});
    private static final Scalar d5 = decodeScalar(new byte[]{-44, 86, -56, -45, 9, -5, -57, -51, 13, -26, 99, 94, -10, -18, 0, 24, 88, -90, 43, -122, 27, 50, 66, 104, 20, 26, 35, 3, -53, -97, -31, 32, 57, -88, -4, -48, 77, 29, 65, -113, -83, 82, -125, 92, 11, -67, -126, -121, -31, 19, 118, -106, 20, 56, -60, 28, 0});
    private static final Scalar d6 = decodeScalar(new byte[]{84, 58, -91, 0, 85, -72, 70, -112, -35, 127, -81, -3, -21, 100, 59, -21, -2, 36, -13, 28, -104, -4, -14, 101, 23, -15, 67, 86, -22, 59, -34, 29, 16, -118, 25, 55, -17, 78, -38, 53, -63, 34, 32, -10, 20, 90, -85, 58, 101, 42, -9, 108, -100, 100, 127, 19, 0});
    private static final Scalar cr = decodeScalar(new byte[]{79, -116, -35, -90, 106, -46, 13, -128, -17, -127, 88, 115, 43, -17, -80, -75, -84, -7, 60, 103, -42, -90, -47, -120, -114, 65, 104, 21, -43, 15, -82, -36, 97, -128, -57, 20, -124, 95, -94, -116, -35, 23, -85, 122, 10, 80, -125, 12, 90, 97, -55, -112, -56, -43, -56, 22, 0});
    private static final Scalar d7 = decodeScalar(new byte[]{-99, -101, -1, 46, -127, -120, 93, -79, -61, -46, 107, 40, 71, -53, 74, 2, 21, -27, -46, 117, -117, 82, 32, 127, 20, 41, 38, 33, -1, 29, -96, 38, -1, 79, 121, -39, 3, -49, -96, -96, 32, -60, 78, -126, -80, -85, 39, -39, -16, -41, 11, 22, 92, -113, 57, 0, 0});

    @Test
    public void testConstruct() {
        final StateExpect2 state = new StateExpect2(RANDOM, secret, a2, a3);
        assertEquals(INPROGRESS, state.getStatus());
    }

    @Test(expected = NullPointerException.class)
    public void testConstructNullSecureRandom() {
        new StateExpect2(null, secret, a2, a3);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructNullSecret() {
        new StateExpect2(RANDOM, null, a2, a3);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructNulla2() {
        new StateExpect2(RANDOM, secret, null, a3);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructNulla3() {
        new StateExpect2(RANDOM, secret, a2, null);
    }

    @Test(expected = NullPointerException.class)
    public void testInitiateNullContext() throws SMPAbortException {
        final StateExpect2 state = new StateExpect2(RANDOM, secret, a2, a3);
        state.initiate(null, "test", fromBigInteger(valueOf(1L)));
    }

    @Test(expected = SMPAbortException.class)
    public void testInitiateAbortStateExpect1() throws SMPAbortException {
        final StateExpect2 state = new StateExpect2(RANDOM, secret, a2, a3);
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
        final StateExpect2 state = new StateExpect2(RANDOM, secret, a2, a3);
        assertNull(state.respondWithSecret(null, null, null));
    }

    @Test(expected = NullPointerException.class)
    public void testProcessNullContext() throws SMPAbortException {
        final StateExpect2 state = new StateExpect2(RANDOM, secret, a2, a3);
        final SMPMessage2 message = new SMPMessage2(g2b, c2, d2, g3b, c3, d3, pb, qb, cp, d5, d6);
        state.process(null, message);
    }

    @Test(expected = NullPointerException.class)
    public void testProcessNullMessage() throws SMPAbortException {
        final StateExpect2 state = new StateExpect2(RANDOM, secret, a2, a3);
        final SMPContext context = mock(SMPContext.class);
        state.process(context, null);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessWrongMessage() throws SMPAbortException {
        final StateExpect2 state = new StateExpect2(RANDOM, secret, a2, a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(pa, qa, cp, d5, d6, ra, cr, d7);
        state.process(context, message);
    }

    @Test
    public void testProcessSMPSucceeded() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {36, -29, -6, 118, 86, 75, -116, 119, -38, 53, -54, 102, 37, 123, -9, -6, -26, 90, 79, -98, -38, -27, -21, 106, -58, -91, 1, -110, 28, -115, -42, -20, -77, 118, -29, -81, 101, 55, 118, 96, 56, -103, 45, 82, 22, 78, 41, -51, -63, 35, 55, 68, 10, 37, -72, -44, 96, -37, -79, 124, 100, 58, -11, -67, -48, -90, 54, 29, -92, -53, 79, -60, 2, -101, -3, 49, 86, -22, -25, 29, 61, -78, -115, 40, 46, -67, -110, 57, 99, 37, 75, -123, -76, -69, 104, 89, 53, 117, -1, -122, -123, -43, -84, 16, -33, -73, -27, -70, -109, 92, 120, -53, -29, 20, -49, -101, 84, 21, -86, -76, 10, 59, 41, -73, 77, -27, -115, -1, 65, -23, -34, 81, -10, 84, -69, -122, 108, 74, -94, 71, 94, -71, -110, -32, -97, -110, -42, 77, -128, 43, -74, 9, 30, 107, 11, -56, -39, -100, 53, 73, 20, 102, 120, -85, 106, -49, 57, 92, 2, -54, 75, 101, -111, 5, 99, 109, -86, 39, 32, -94, 70, 9, -32, 44, 84, 12, -29, -22, 29, 20, -83, -118, 5, 127, -113, 17, 74, 17, -12, -84, -39, 49, -20, -76, -26, -94, 69, -110, -55, 54, -48, 55, -115, 27, -74, 68, 50, -32, -40, -6, 4, 99, -81, 43, 94, -122, 7, -44};
        final Scalar expectedCp = decodeScalar(new byte[] {-102, -3, -37, 86, 57, -107, -57, 19, 118, 117, -81, 76, -6, -33, 12, 103, 58, 109, -5, 120, 43, -65, -121, -10, -80, 127, 101, 65, -84, -12, 99, -95, -32, -96, -76, -89, -43, 95, -45, -82, 36, 69, 107, 54, -4, -60, 43, 41, -17, -113, 31, -21, 119, 104, 88, 41, 0});
        final Scalar expectedD5 = decodeScalar(new byte[] {92, -33, 26, 108, 7, 58, 50, 77, 102, -39, 109, 47, -1, -9, 35, -58, -7, 110, -50, 125, -89, -128, 21, -42, -96, 98, 78, -31, 6, 99, -124, -67, -87, -26, -44, -43, -102, -72, 60, 112, -67, -24, 95, 120, 105, 126, 12, 83, -114, -102, 71, -123, -65, 4, 59, 4, 0});
        final Scalar expectedD6 = decodeScalar(new byte[] {-109, -50, 3, -124, 29, 122, 15, -31, 40, 41, 102, -20, 30, 73, 14, 79, 81, -96, -12, -59, -101, -97, -119, -102, 73, 8, -86, 109, 64, -128, 22, -99, 11, 109, -127, 65, 66, -62, -90, 88, -108, 102, -94, -52, 18, -69, -95, 124, 121, 124, 59, 30, 39, 101, 35, 7, 0});
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret, a2, a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(g2b, c2, d2, g3b, c3, d3, pb, qb, cp, d5, d6);
        final SMPMessage3 response = state.process(context, message);
        assertEquals(pa, response.pa);
        assertEquals(qa, response.qa);
        assertEquals(expectedCp, response.cp);
        assertEquals(expectedD5, response.d5);
        assertEquals(expectedD6, response.d6);
        assertEquals(ra, response.ra);
        assertEquals(cr, response.cr);
        assertEquals(d7, response.d7);
        // TODO investigate if following verification statement works. There seem to be some unexpected results.
        verify(context).setState(any(StateExpect1.class));
    }

    @Test
    public void testProcessMessageBadSecret() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {36, -29, -6, 118, 86, 75, -116, 119, -38, 53, -54, 102, 37, 123, -9, -6, -26, 90, 79, -98, -38, -27, -21, 106, -58, -91, 1, -110, 28, -115, -42, -20, -77, 118, -29, -81, 101, 55, 118, 96, 56, -103, 45, 82, 22, 78, 41, -51, -63, 35, 55, 68, 10, 37, -72, -44, 96, -37, -79, 124, 100, 58, -11, -67, -48, -90, 54, 29, -92, -53, 79, -60, 2, -101, -3, 49, 86, -22, -25, 29, 61, -78, -115, 40, 46, -67, -110, 57, 99, 37, 75, -123, -76, -69, 104, 89, 53, 117, -1, -122, -123, -43, -84, 16, -33, -73, -27, -70, -109, 92, 120, -53, -29, 20, -49, -101, 84, 21, -86, -76, 10, 59, 41, -73, 77, -27, -115, -1, 65, -23, -34, 81, -10, 84, -69, -122, 108, 74, -94, 71, 94, -71, -110, -32, -97, -110, -42, 77, -128, 43, -74, 9, 30, 107, 11, -56, -39, -100, 53, 73, 20, 102, 120, -85, 106, -49, 57, 92, 2, -54, 75, 101, -111, 5, 99, 109, -86, 39, 32, -94, 70, 9, -32, 44, 84, 12, -29, -22, 29, 20, -83, -118, 5, 127, -113, 17, 74, 17, -12, -84, -39, 49, -20, -76, -26, -94, 69, -110, -55, 54, -48, 55, -115, 27, -74, 68, 50, -32, -40, -6, 4, 99, -81, 43, 94, -122, 7, -44};
        final Scalar expectedCp = decodeScalar(new byte[] {-102, -3, -37, 86, 57, -107, -57, 19, 118, 117, -81, 76, -6, -33, 12, 103, 58, 109, -5, 120, 43, -65, -121, -10, -80, 127, 101, 65, -84, -12, 99, -95, -32, -96, -76, -89, -43, 95, -45, -82, 36, 69, 107, 54, -4, -60, 43, 41, -17, -113, 31, -21, 119, 104, 88, 41, 0});
        final Scalar expectedD5 = decodeScalar(new byte[] {92, -33, 26, 108, 7, 58, 50, 77, 102, -39, 109, 47, -1, -9, 35, -58, -7, 110, -50, 125, -89, -128, 21, -42, -96, 98, 78, -31, 6, 99, -124, -67, -87, -26, -44, -43, -102, -72, 60, 112, -67, -24, 95, 120, 105, 126, 12, 83, -114, -102, 71, -123, -65, 4, 59, 4, 0});
        final Scalar expectedD6 = decodeScalar(new byte[] {-109, -50, 3, -124, 29, 122, 15, -31, 40, 41, 102, -20, 30, 73, 14, 79, 81, -96, -12, -59, -101, -97, -119, -102, 73, 8, -86, 109, 64, -128, 22, -99, 11, 109, -127, 65, 66, -62, -90, 88, -108, 102, -94, -52, 18, -69, -95, 124, 121, 124, 59, 30, 39, 101, 35, 7, 0});
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret.negate(), a2, a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(g2b, c2, d2, g3b, c3, d3, pb, qb, cp, d5, d6);
        final SMPMessage3 response = state.process(context, message);
        assertEquals(pa, response.pa);
        assertNotEquals(qa, response.qa);
        assertEquals(expectedCp, response.cp);
        assertEquals(expectedD5, response.d5);
        assertNotEquals(expectedD6, response.d6);
        assertNotEquals(ra, response.ra);
        assertNotEquals(cr, response.cr);
        assertNotEquals(d7, response.d7);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBada2() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {36, -29, -6, 118, 86, 75, -116, 119, -38, 53, -54, 102, 37, 123, -9, -6, -26, 90, 79, -98, -38, -27, -21, 106, -58, -91, 1, -110, 28, -115, -42, -20, -77, 118, -29, -81, 101, 55, 118, 96, 56, -103, 45, 82, 22, 78, 41, -51, -63, 35, 55, 68, 10, 37, -72, -44, 96, -37, -79, 124, 100, 58, -11, -67, -48, -90, 54, 29, -92, -53, 79, -60, 2, -101, -3, 49, 86, -22, -25, 29, 61, -78, -115, 40, 46, -67, -110, 57, 99, 37, 75, -123, -76, -69, 104, 89, 53, 117, -1, -122, -123, -43, -84, 16, -33, -73, -27, -70, -109, 92, 120, -53, -29, 20, -49, -101, 84, 21, -86, -76, 10, 59, 41, -73, 77, -27, -115, -1, 65, -23, -34, 81, -10, 84, -69, -122, 108, 74, -94, 71, 94, -71, -110, -32, -97, -110, -42, 77, -128, 43, -74, 9, 30, 107, 11, -56, -39, -100, 53, 73, 20, 102, 120, -85, 106, -49, 57, 92, 2, -54, 75, 101, -111, 5, 99, 109, -86, 39, 32, -94, 70, 9, -32, 44, 84, 12, -29, -22, 29, 20, -83, -118, 5, 127, -113, 17, 74, 17, -12, -84, -39, 49, -20, -76, -26, -94, 69, -110, -55, 54, -48, 55, -115, 27, -74, 68, 50, -32, -40, -6, 4, 99, -81, 43, 94, -122, 7, -44};
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret, Scalars.one(), a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(g2b, c2, d2, g3b, c3, d3, pb, qb, cp, d5, d6);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBada3() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {36, -29, -6, 118, 86, 75, -116, 119, -38, 53, -54, 102, 37, 123, -9, -6, -26, 90, 79, -98, -38, -27, -21, 106, -58, -91, 1, -110, 28, -115, -42, -20, -77, 118, -29, -81, 101, 55, 118, 96, 56, -103, 45, 82, 22, 78, 41, -51, -63, 35, 55, 68, 10, 37, -72, -44, 96, -37, -79, 124, 100, 58, -11, -67, -48, -90, 54, 29, -92, -53, 79, -60, 2, -101, -3, 49, 86, -22, -25, 29, 61, -78, -115, 40, 46, -67, -110, 57, 99, 37, 75, -123, -76, -69, 104, 89, 53, 117, -1, -122, -123, -43, -84, 16, -33, -73, -27, -70, -109, 92, 120, -53, -29, 20, -49, -101, 84, 21, -86, -76, 10, 59, 41, -73, 77, -27, -115, -1, 65, -23, -34, 81, -10, 84, -69, -122, 108, 74, -94, 71, 94, -71, -110, -32, -97, -110, -42, 77, -128, 43, -74, 9, 30, 107, 11, -56, -39, -100, 53, 73, 20, 102, 120, -85, 106, -49, 57, 92, 2, -54, 75, 101, -111, 5, 99, 109, -86, 39, 32, -94, 70, 9, -32, 44, 84, 12, -29, -22, 29, 20, -83, -118, 5, 127, -113, 17, 74, 17, -12, -84, -39, 49, -20, -76, -26, -94, 69, -110, -55, 54, -48, 55, -115, 27, -74, 68, 50, -32, -40, -6, 4, 99, -81, 43, 94, -122, 7, -44};
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret, a2, Scalars.one());
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(g2b, c2, d2, g3b, c3, d3, pb, qb, cp, d5, d6);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageIllegalg2b() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {36, -29, -6, 118, 86, 75, -116, 119, -38, 53, -54, 102, 37, 123, -9, -6, -26, 90, 79, -98, -38, -27, -21, 106, -58, -91, 1, -110, 28, -115, -42, -20, -77, 118, -29, -81, 101, 55, 118, 96, 56, -103, 45, 82, 22, 78, 41, -51, -63, 35, 55, 68, 10, 37, -72, -44, 96, -37, -79, 124, 100, 58, -11, -67, -48, -90, 54, 29, -92, -53, 79, -60, 2, -101, -3, 49, 86, -22, -25, 29, 61, -78, -115, 40, 46, -67, -110, 57, 99, 37, 75, -123, -76, -69, 104, 89, 53, 117, -1, -122, -123, -43, -84, 16, -33, -73, -27, -70, -109, 92, 120, -53, -29, 20, -49, -101, 84, 21, -86, -76, 10, 59, 41, -73, 77, -27, -115, -1, 65, -23, -34, 81, -10, 84, -69, -122, 108, 74, -94, 71, 94, -71, -110, -32, -97, -110, -42, 77, -128, 43, -74, 9, 30, 107, 11, -56, -39, -100, 53, 73, 20, 102, 120, -85, 106, -49, 57, 92, 2, -54, 75, 101, -111, 5, 99, 109, -86, 39, 32, -94, 70, 9, -32, 44, 84, 12, -29, -22, 29, 20, -83, -118, 5, 127, -113, 17, 74, 17, -12, -84, -39, 49, -20, -76, -26, -94, 69, -110, -55, 54, -48, 55, -115, 27, -74, 68, 50, -32, -40, -6, 4, 99, -81, 43, 94, -122, 7, -44};
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret, a2, a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(createPoint(BigInteger.ONE, BigInteger.ONE), c2, d2, g3b, c3, d3, pb, qb, cp, d5, d6);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadg2b() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {36, -29, -6, 118, 86, 75, -116, 119, -38, 53, -54, 102, 37, 123, -9, -6, -26, 90, 79, -98, -38, -27, -21, 106, -58, -91, 1, -110, 28, -115, -42, -20, -77, 118, -29, -81, 101, 55, 118, 96, 56, -103, 45, 82, 22, 78, 41, -51, -63, 35, 55, 68, 10, 37, -72, -44, 96, -37, -79, 124, 100, 58, -11, -67, -48, -90, 54, 29, -92, -53, 79, -60, 2, -101, -3, 49, 86, -22, -25, 29, 61, -78, -115, 40, 46, -67, -110, 57, 99, 37, 75, -123, -76, -69, 104, 89, 53, 117, -1, -122, -123, -43, -84, 16, -33, -73, -27, -70, -109, 92, 120, -53, -29, 20, -49, -101, 84, 21, -86, -76, 10, 59, 41, -73, 77, -27, -115, -1, 65, -23, -34, 81, -10, 84, -69, -122, 108, 74, -94, 71, 94, -71, -110, -32, -97, -110, -42, 77, -128, 43, -74, 9, 30, 107, 11, -56, -39, -100, 53, 73, 20, 102, 120, -85, 106, -49, 57, 92, 2, -54, 75, 101, -111, 5, 99, 109, -86, 39, 32, -94, 70, 9, -32, 44, 84, 12, -29, -22, 29, 20, -83, -118, 5, 127, -113, 17, 74, 17, -12, -84, -39, 49, -20, -76, -26, -94, 69, -110, -55, 54, -48, 55, -115, 27, -74, 68, 50, -32, -40, -6, 4, 99, -81, 43, 94, -122, 7, -44};
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret, a2, a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(g2b.negate(), c2, d2, g3b, c3, d3, pb, qb, cp, d5, d6);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageIllegalg3b() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {36, -29, -6, 118, 86, 75, -116, 119, -38, 53, -54, 102, 37, 123, -9, -6, -26, 90, 79, -98, -38, -27, -21, 106, -58, -91, 1, -110, 28, -115, -42, -20, -77, 118, -29, -81, 101, 55, 118, 96, 56, -103, 45, 82, 22, 78, 41, -51, -63, 35, 55, 68, 10, 37, -72, -44, 96, -37, -79, 124, 100, 58, -11, -67, -48, -90, 54, 29, -92, -53, 79, -60, 2, -101, -3, 49, 86, -22, -25, 29, 61, -78, -115, 40, 46, -67, -110, 57, 99, 37, 75, -123, -76, -69, 104, 89, 53, 117, -1, -122, -123, -43, -84, 16, -33, -73, -27, -70, -109, 92, 120, -53, -29, 20, -49, -101, 84, 21, -86, -76, 10, 59, 41, -73, 77, -27, -115, -1, 65, -23, -34, 81, -10, 84, -69, -122, 108, 74, -94, 71, 94, -71, -110, -32, -97, -110, -42, 77, -128, 43, -74, 9, 30, 107, 11, -56, -39, -100, 53, 73, 20, 102, 120, -85, 106, -49, 57, 92, 2, -54, 75, 101, -111, 5, 99, 109, -86, 39, 32, -94, 70, 9, -32, 44, 84, 12, -29, -22, 29, 20, -83, -118, 5, 127, -113, 17, 74, 17, -12, -84, -39, 49, -20, -76, -26, -94, 69, -110, -55, 54, -48, 55, -115, 27, -74, 68, 50, -32, -40, -6, 4, 99, -81, 43, 94, -122, 7, -44};
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret, a2, a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(g2b, c2, d2, createPoint(BigInteger.ONE, BigInteger.ONE), c3, d3, pb, qb, cp, d5, d6);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadg3b() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {36, -29, -6, 118, 86, 75, -116, 119, -38, 53, -54, 102, 37, 123, -9, -6, -26, 90, 79, -98, -38, -27, -21, 106, -58, -91, 1, -110, 28, -115, -42, -20, -77, 118, -29, -81, 101, 55, 118, 96, 56, -103, 45, 82, 22, 78, 41, -51, -63, 35, 55, 68, 10, 37, -72, -44, 96, -37, -79, 124, 100, 58, -11, -67, -48, -90, 54, 29, -92, -53, 79, -60, 2, -101, -3, 49, 86, -22, -25, 29, 61, -78, -115, 40, 46, -67, -110, 57, 99, 37, 75, -123, -76, -69, 104, 89, 53, 117, -1, -122, -123, -43, -84, 16, -33, -73, -27, -70, -109, 92, 120, -53, -29, 20, -49, -101, 84, 21, -86, -76, 10, 59, 41, -73, 77, -27, -115, -1, 65, -23, -34, 81, -10, 84, -69, -122, 108, 74, -94, 71, 94, -71, -110, -32, -97, -110, -42, 77, -128, 43, -74, 9, 30, 107, 11, -56, -39, -100, 53, 73, 20, 102, 120, -85, 106, -49, 57, 92, 2, -54, 75, 101, -111, 5, 99, 109, -86, 39, 32, -94, 70, 9, -32, 44, 84, 12, -29, -22, 29, 20, -83, -118, 5, 127, -113, 17, 74, 17, -12, -84, -39, 49, -20, -76, -26, -94, 69, -110, -55, 54, -48, 55, -115, 27, -74, 68, 50, -32, -40, -6, 4, 99, -81, 43, 94, -122, 7, -44};
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret, a2, a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(g2b, c2, d2, g3b.negate(), c3, d3, pb, qb, cp, d5, d6);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageIllegalpb() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {36, -29, -6, 118, 86, 75, -116, 119, -38, 53, -54, 102, 37, 123, -9, -6, -26, 90, 79, -98, -38, -27, -21, 106, -58, -91, 1, -110, 28, -115, -42, -20, -77, 118, -29, -81, 101, 55, 118, 96, 56, -103, 45, 82, 22, 78, 41, -51, -63, 35, 55, 68, 10, 37, -72, -44, 96, -37, -79, 124, 100, 58, -11, -67, -48, -90, 54, 29, -92, -53, 79, -60, 2, -101, -3, 49, 86, -22, -25, 29, 61, -78, -115, 40, 46, -67, -110, 57, 99, 37, 75, -123, -76, -69, 104, 89, 53, 117, -1, -122, -123, -43, -84, 16, -33, -73, -27, -70, -109, 92, 120, -53, -29, 20, -49, -101, 84, 21, -86, -76, 10, 59, 41, -73, 77, -27, -115, -1, 65, -23, -34, 81, -10, 84, -69, -122, 108, 74, -94, 71, 94, -71, -110, -32, -97, -110, -42, 77, -128, 43, -74, 9, 30, 107, 11, -56, -39, -100, 53, 73, 20, 102, 120, -85, 106, -49, 57, 92, 2, -54, 75, 101, -111, 5, 99, 109, -86, 39, 32, -94, 70, 9, -32, 44, 84, 12, -29, -22, 29, 20, -83, -118, 5, 127, -113, 17, 74, 17, -12, -84, -39, 49, -20, -76, -26, -94, 69, -110, -55, 54, -48, 55, -115, 27, -74, 68, 50, -32, -40, -6, 4, 99, -81, 43, 94, -122, 7, -44};
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret, a2, a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(g2b, c2, d2, g3b, c3, d3, createPoint(BigInteger.ONE, BigInteger.ONE), qb, cp, d5, d6);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadpb() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {36, -29, -6, 118, 86, 75, -116, 119, -38, 53, -54, 102, 37, 123, -9, -6, -26, 90, 79, -98, -38, -27, -21, 106, -58, -91, 1, -110, 28, -115, -42, -20, -77, 118, -29, -81, 101, 55, 118, 96, 56, -103, 45, 82, 22, 78, 41, -51, -63, 35, 55, 68, 10, 37, -72, -44, 96, -37, -79, 124, 100, 58, -11, -67, -48, -90, 54, 29, -92, -53, 79, -60, 2, -101, -3, 49, 86, -22, -25, 29, 61, -78, -115, 40, 46, -67, -110, 57, 99, 37, 75, -123, -76, -69, 104, 89, 53, 117, -1, -122, -123, -43, -84, 16, -33, -73, -27, -70, -109, 92, 120, -53, -29, 20, -49, -101, 84, 21, -86, -76, 10, 59, 41, -73, 77, -27, -115, -1, 65, -23, -34, 81, -10, 84, -69, -122, 108, 74, -94, 71, 94, -71, -110, -32, -97, -110, -42, 77, -128, 43, -74, 9, 30, 107, 11, -56, -39, -100, 53, 73, 20, 102, 120, -85, 106, -49, 57, 92, 2, -54, 75, 101, -111, 5, 99, 109, -86, 39, 32, -94, 70, 9, -32, 44, 84, 12, -29, -22, 29, 20, -83, -118, 5, 127, -113, 17, 74, 17, -12, -84, -39, 49, -20, -76, -26, -94, 69, -110, -55, 54, -48, 55, -115, 27, -74, 68, 50, -32, -40, -6, 4, 99, -81, 43, 94, -122, 7, -44};
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret, a2, a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(g2b, c2, d2, g3b, c3, d3, pb.negate(), qb, cp, d5, d6);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageIllegalqb() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {36, -29, -6, 118, 86, 75, -116, 119, -38, 53, -54, 102, 37, 123, -9, -6, -26, 90, 79, -98, -38, -27, -21, 106, -58, -91, 1, -110, 28, -115, -42, -20, -77, 118, -29, -81, 101, 55, 118, 96, 56, -103, 45, 82, 22, 78, 41, -51, -63, 35, 55, 68, 10, 37, -72, -44, 96, -37, -79, 124, 100, 58, -11, -67, -48, -90, 54, 29, -92, -53, 79, -60, 2, -101, -3, 49, 86, -22, -25, 29, 61, -78, -115, 40, 46, -67, -110, 57, 99, 37, 75, -123, -76, -69, 104, 89, 53, 117, -1, -122, -123, -43, -84, 16, -33, -73, -27, -70, -109, 92, 120, -53, -29, 20, -49, -101, 84, 21, -86, -76, 10, 59, 41, -73, 77, -27, -115, -1, 65, -23, -34, 81, -10, 84, -69, -122, 108, 74, -94, 71, 94, -71, -110, -32, -97, -110, -42, 77, -128, 43, -74, 9, 30, 107, 11, -56, -39, -100, 53, 73, 20, 102, 120, -85, 106, -49, 57, 92, 2, -54, 75, 101, -111, 5, 99, 109, -86, 39, 32, -94, 70, 9, -32, 44, 84, 12, -29, -22, 29, 20, -83, -118, 5, 127, -113, 17, 74, 17, -12, -84, -39, 49, -20, -76, -26, -94, 69, -110, -55, 54, -48, 55, -115, 27, -74, 68, 50, -32, -40, -6, 4, 99, -81, 43, 94, -122, 7, -44};
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret, a2, a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(g2b, c2, d2, g3b, c3, d3, pb, createPoint(BigInteger.ONE, BigInteger.ONE), cp, d5, d6);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadqb() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {36, -29, -6, 118, 86, 75, -116, 119, -38, 53, -54, 102, 37, 123, -9, -6, -26, 90, 79, -98, -38, -27, -21, 106, -58, -91, 1, -110, 28, -115, -42, -20, -77, 118, -29, -81, 101, 55, 118, 96, 56, -103, 45, 82, 22, 78, 41, -51, -63, 35, 55, 68, 10, 37, -72, -44, 96, -37, -79, 124, 100, 58, -11, -67, -48, -90, 54, 29, -92, -53, 79, -60, 2, -101, -3, 49, 86, -22, -25, 29, 61, -78, -115, 40, 46, -67, -110, 57, 99, 37, 75, -123, -76, -69, 104, 89, 53, 117, -1, -122, -123, -43, -84, 16, -33, -73, -27, -70, -109, 92, 120, -53, -29, 20, -49, -101, 84, 21, -86, -76, 10, 59, 41, -73, 77, -27, -115, -1, 65, -23, -34, 81, -10, 84, -69, -122, 108, 74, -94, 71, 94, -71, -110, -32, -97, -110, -42, 77, -128, 43, -74, 9, 30, 107, 11, -56, -39, -100, 53, 73, 20, 102, 120, -85, 106, -49, 57, 92, 2, -54, 75, 101, -111, 5, 99, 109, -86, 39, 32, -94, 70, 9, -32, 44, 84, 12, -29, -22, 29, 20, -83, -118, 5, 127, -113, 17, 74, 17, -12, -84, -39, 49, -20, -76, -26, -94, 69, -110, -55, 54, -48, 55, -115, 27, -74, 68, 50, -32, -40, -6, 4, 99, -81, 43, 94, -122, 7, -44};
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret, a2, a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(g2b, c2, d2, g3b, c3, d3, pb, qb.negate(), cp, d5, d6);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadc2() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {36, -29, -6, 118, 86, 75, -116, 119, -38, 53, -54, 102, 37, 123, -9, -6, -26, 90, 79, -98, -38, -27, -21, 106, -58, -91, 1, -110, 28, -115, -42, -20, -77, 118, -29, -81, 101, 55, 118, 96, 56, -103, 45, 82, 22, 78, 41, -51, -63, 35, 55, 68, 10, 37, -72, -44, 96, -37, -79, 124, 100, 58, -11, -67, -48, -90, 54, 29, -92, -53, 79, -60, 2, -101, -3, 49, 86, -22, -25, 29, 61, -78, -115, 40, 46, -67, -110, 57, 99, 37, 75, -123, -76, -69, 104, 89, 53, 117, -1, -122, -123, -43, -84, 16, -33, -73, -27, -70, -109, 92, 120, -53, -29, 20, -49, -101, 84, 21, -86, -76, 10, 59, 41, -73, 77, -27, -115, -1, 65, -23, -34, 81, -10, 84, -69, -122, 108, 74, -94, 71, 94, -71, -110, -32, -97, -110, -42, 77, -128, 43, -74, 9, 30, 107, 11, -56, -39, -100, 53, 73, 20, 102, 120, -85, 106, -49, 57, 92, 2, -54, 75, 101, -111, 5, 99, 109, -86, 39, 32, -94, 70, 9, -32, 44, 84, 12, -29, -22, 29, 20, -83, -118, 5, 127, -113, 17, 74, 17, -12, -84, -39, 49, -20, -76, -26, -94, 69, -110, -55, 54, -48, 55, -115, 27, -74, 68, 50, -32, -40, -6, 4, 99, -81, 43, 94, -122, 7, -44};
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret, a2, a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(g2b, Scalars.one(), d2, g3b, c3, d3, pb, qb, cp, d5, d6);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadd2() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {36, -29, -6, 118, 86, 75, -116, 119, -38, 53, -54, 102, 37, 123, -9, -6, -26, 90, 79, -98, -38, -27, -21, 106, -58, -91, 1, -110, 28, -115, -42, -20, -77, 118, -29, -81, 101, 55, 118, 96, 56, -103, 45, 82, 22, 78, 41, -51, -63, 35, 55, 68, 10, 37, -72, -44, 96, -37, -79, 124, 100, 58, -11, -67, -48, -90, 54, 29, -92, -53, 79, -60, 2, -101, -3, 49, 86, -22, -25, 29, 61, -78, -115, 40, 46, -67, -110, 57, 99, 37, 75, -123, -76, -69, 104, 89, 53, 117, -1, -122, -123, -43, -84, 16, -33, -73, -27, -70, -109, 92, 120, -53, -29, 20, -49, -101, 84, 21, -86, -76, 10, 59, 41, -73, 77, -27, -115, -1, 65, -23, -34, 81, -10, 84, -69, -122, 108, 74, -94, 71, 94, -71, -110, -32, -97, -110, -42, 77, -128, 43, -74, 9, 30, 107, 11, -56, -39, -100, 53, 73, 20, 102, 120, -85, 106, -49, 57, 92, 2, -54, 75, 101, -111, 5, 99, 109, -86, 39, 32, -94, 70, 9, -32, 44, 84, 12, -29, -22, 29, 20, -83, -118, 5, 127, -113, 17, 74, 17, -12, -84, -39, 49, -20, -76, -26, -94, 69, -110, -55, 54, -48, 55, -115, 27, -74, 68, 50, -32, -40, -6, 4, 99, -81, 43, 94, -122, 7, -44};
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret, a2, a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(g2b, c2, Scalars.one(), g3b, c3, d3, pb, qb, cp, d5, d6);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadc3() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {36, -29, -6, 118, 86, 75, -116, 119, -38, 53, -54, 102, 37, 123, -9, -6, -26, 90, 79, -98, -38, -27, -21, 106, -58, -91, 1, -110, 28, -115, -42, -20, -77, 118, -29, -81, 101, 55, 118, 96, 56, -103, 45, 82, 22, 78, 41, -51, -63, 35, 55, 68, 10, 37, -72, -44, 96, -37, -79, 124, 100, 58, -11, -67, -48, -90, 54, 29, -92, -53, 79, -60, 2, -101, -3, 49, 86, -22, -25, 29, 61, -78, -115, 40, 46, -67, -110, 57, 99, 37, 75, -123, -76, -69, 104, 89, 53, 117, -1, -122, -123, -43, -84, 16, -33, -73, -27, -70, -109, 92, 120, -53, -29, 20, -49, -101, 84, 21, -86, -76, 10, 59, 41, -73, 77, -27, -115, -1, 65, -23, -34, 81, -10, 84, -69, -122, 108, 74, -94, 71, 94, -71, -110, -32, -97, -110, -42, 77, -128, 43, -74, 9, 30, 107, 11, -56, -39, -100, 53, 73, 20, 102, 120, -85, 106, -49, 57, 92, 2, -54, 75, 101, -111, 5, 99, 109, -86, 39, 32, -94, 70, 9, -32, 44, 84, 12, -29, -22, 29, 20, -83, -118, 5, 127, -113, 17, 74, 17, -12, -84, -39, 49, -20, -76, -26, -94, 69, -110, -55, 54, -48, 55, -115, 27, -74, 68, 50, -32, -40, -6, 4, 99, -81, 43, 94, -122, 7, -44};
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret, a2, a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(g2b, c2, d2, g3b, Scalars.one(), d3, pb, qb, cp, d5, d6);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadd3() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {36, -29, -6, 118, 86, 75, -116, 119, -38, 53, -54, 102, 37, 123, -9, -6, -26, 90, 79, -98, -38, -27, -21, 106, -58, -91, 1, -110, 28, -115, -42, -20, -77, 118, -29, -81, 101, 55, 118, 96, 56, -103, 45, 82, 22, 78, 41, -51, -63, 35, 55, 68, 10, 37, -72, -44, 96, -37, -79, 124, 100, 58, -11, -67, -48, -90, 54, 29, -92, -53, 79, -60, 2, -101, -3, 49, 86, -22, -25, 29, 61, -78, -115, 40, 46, -67, -110, 57, 99, 37, 75, -123, -76, -69, 104, 89, 53, 117, -1, -122, -123, -43, -84, 16, -33, -73, -27, -70, -109, 92, 120, -53, -29, 20, -49, -101, 84, 21, -86, -76, 10, 59, 41, -73, 77, -27, -115, -1, 65, -23, -34, 81, -10, 84, -69, -122, 108, 74, -94, 71, 94, -71, -110, -32, -97, -110, -42, 77, -128, 43, -74, 9, 30, 107, 11, -56, -39, -100, 53, 73, 20, 102, 120, -85, 106, -49, 57, 92, 2, -54, 75, 101, -111, 5, 99, 109, -86, 39, 32, -94, 70, 9, -32, 44, 84, 12, -29, -22, 29, 20, -83, -118, 5, 127, -113, 17, 74, 17, -12, -84, -39, 49, -20, -76, -26, -94, 69, -110, -55, 54, -48, 55, -115, 27, -74, 68, 50, -32, -40, -6, 4, 99, -81, 43, 94, -122, 7, -44};
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret, a2, a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(g2b, c2, d2, g3b, c3, Scalars.one(), pb, qb, cp, d5, d6);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadcp() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {36, -29, -6, 118, 86, 75, -116, 119, -38, 53, -54, 102, 37, 123, -9, -6, -26, 90, 79, -98, -38, -27, -21, 106, -58, -91, 1, -110, 28, -115, -42, -20, -77, 118, -29, -81, 101, 55, 118, 96, 56, -103, 45, 82, 22, 78, 41, -51, -63, 35, 55, 68, 10, 37, -72, -44, 96, -37, -79, 124, 100, 58, -11, -67, -48, -90, 54, 29, -92, -53, 79, -60, 2, -101, -3, 49, 86, -22, -25, 29, 61, -78, -115, 40, 46, -67, -110, 57, 99, 37, 75, -123, -76, -69, 104, 89, 53, 117, -1, -122, -123, -43, -84, 16, -33, -73, -27, -70, -109, 92, 120, -53, -29, 20, -49, -101, 84, 21, -86, -76, 10, 59, 41, -73, 77, -27, -115, -1, 65, -23, -34, 81, -10, 84, -69, -122, 108, 74, -94, 71, 94, -71, -110, -32, -97, -110, -42, 77, -128, 43, -74, 9, 30, 107, 11, -56, -39, -100, 53, 73, 20, 102, 120, -85, 106, -49, 57, 92, 2, -54, 75, 101, -111, 5, 99, 109, -86, 39, 32, -94, 70, 9, -32, 44, 84, 12, -29, -22, 29, 20, -83, -118, 5, 127, -113, 17, 74, 17, -12, -84, -39, 49, -20, -76, -26, -94, 69, -110, -55, 54, -48, 55, -115, 27, -74, 68, 50, -32, -40, -6, 4, 99, -81, 43, 94, -122, 7, -44};
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret, a2, a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(g2b, c2, d2, g3b, c3, d3, pb, qb, Scalars.one(), d5, d6);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadd5() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {36, -29, -6, 118, 86, 75, -116, 119, -38, 53, -54, 102, 37, 123, -9, -6, -26, 90, 79, -98, -38, -27, -21, 106, -58, -91, 1, -110, 28, -115, -42, -20, -77, 118, -29, -81, 101, 55, 118, 96, 56, -103, 45, 82, 22, 78, 41, -51, -63, 35, 55, 68, 10, 37, -72, -44, 96, -37, -79, 124, 100, 58, -11, -67, -48, -90, 54, 29, -92, -53, 79, -60, 2, -101, -3, 49, 86, -22, -25, 29, 61, -78, -115, 40, 46, -67, -110, 57, 99, 37, 75, -123, -76, -69, 104, 89, 53, 117, -1, -122, -123, -43, -84, 16, -33, -73, -27, -70, -109, 92, 120, -53, -29, 20, -49, -101, 84, 21, -86, -76, 10, 59, 41, -73, 77, -27, -115, -1, 65, -23, -34, 81, -10, 84, -69, -122, 108, 74, -94, 71, 94, -71, -110, -32, -97, -110, -42, 77, -128, 43, -74, 9, 30, 107, 11, -56, -39, -100, 53, 73, 20, 102, 120, -85, 106, -49, 57, 92, 2, -54, 75, 101, -111, 5, 99, 109, -86, 39, 32, -94, 70, 9, -32, 44, 84, 12, -29, -22, 29, 20, -83, -118, 5, 127, -113, 17, 74, 17, -12, -84, -39, 49, -20, -76, -26, -94, 69, -110, -55, 54, -48, 55, -115, 27, -74, 68, 50, -32, -40, -6, 4, 99, -81, 43, 94, -122, 7, -44};
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret, a2, a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(g2b, c2, d2, g3b, c3, d3, pb, qb, cp, Scalars.one(), d6);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadd6() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[] {36, -29, -6, 118, 86, 75, -116, 119, -38, 53, -54, 102, 37, 123, -9, -6, -26, 90, 79, -98, -38, -27, -21, 106, -58, -91, 1, -110, 28, -115, -42, -20, -77, 118, -29, -81, 101, 55, 118, 96, 56, -103, 45, 82, 22, 78, 41, -51, -63, 35, 55, 68, 10, 37, -72, -44, 96, -37, -79, 124, 100, 58, -11, -67, -48, -90, 54, 29, -92, -53, 79, -60, 2, -101, -3, 49, 86, -22, -25, 29, 61, -78, -115, 40, 46, -67, -110, 57, 99, 37, 75, -123, -76, -69, 104, 89, 53, 117, -1, -122, -123, -43, -84, 16, -33, -73, -27, -70, -109, 92, 120, -53, -29, 20, -49, -101, 84, 21, -86, -76, 10, 59, 41, -73, 77, -27, -115, -1, 65, -23, -34, 81, -10, 84, -69, -122, 108, 74, -94, 71, 94, -71, -110, -32, -97, -110, -42, 77, -128, 43, -74, 9, 30, 107, 11, -56, -39, -100, 53, 73, 20, 102, 120, -85, 106, -49, 57, 92, 2, -54, 75, 101, -111, 5, 99, 109, -86, 39, 32, -94, 70, 9, -32, 44, 84, 12, -29, -22, 29, 20, -83, -118, 5, 127, -113, 17, 74, 17, -12, -84, -39, 49, -20, -76, -26, -94, 69, -110, -55, 54, -48, 55, -115, 27, -74, 68, 50, -32, -40, -6, 4, 99, -81, 43, 94, -122, 7, -44};
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret, a2, a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(g2b, c2, d2, g3b, c3, d3, pb, qb, cp, d5, Scalars.one());
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