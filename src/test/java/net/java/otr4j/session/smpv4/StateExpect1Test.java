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
import org.bouncycastle.util.test.FixedSecureRandom;
import org.junit.Test;

import javax.annotation.Nonnull;
import java.math.BigInteger;
import java.security.SecureRandom;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.crypto.OtrCryptoEngine4.generateRandomValueInZq;
import static net.java.otr4j.crypto.ed448.Ed448.basePoint;
import static net.java.otr4j.crypto.ed448.Point.decodePoint;
import static net.java.otr4j.crypto.ed448.PointTestUtils.createPoint;
import static net.java.otr4j.crypto.ed448.Scalar.decodeScalar;
import static net.java.otr4j.session.api.SMPStatus.UNDECIDED;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.mock;

@SuppressWarnings("ConstantConditions")
public final class StateExpect1Test {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Scalar secret = decodeScalar(new byte[] {20, 92, 91, -92, 30, 124, 119, 30, 105, -90, -78, -108, -62, 50, -102, -55, -32, -77, -114, 60, 16, 42, 111, -15, -10, 69, -77, -107, 127, -10, 26, -90, 12, 49, 71, 31, -96, -124, 19, 33, 69, 45, 56, -30, -76, -39, -21, -47, 19, 63, -57, 111, -60, 51, -75, 14, 0});
    private static final Point g2a = mustDecodePoint(new byte[] {-105, -57, 56, -70, 81, -81, -67, -75, -9, -72, -109, 125, -16, -16, -82, 97, -82, -14, 83, -109, -8, 72, -100, -51, 90, 123, -43, -106, 85, 103, -15, -58, -43, 124, 91, 106, -17, 63, -92, 52, 71, 48, 35, -99, -103, 126, -48, -95, -80, 120, -46, -6, -43, 60, -2, -75, -128});
    private static final Point g3a = mustDecodePoint(new byte[] {30, 7, -88, -11, -74, -46, -28, -39, 1, -123, 15, 76, -75, -102, -102, -33, -8, 47, 7, 57, -87, -101, -48, -17, 27, 8, 95, -96, -112, 7, 56, -8, 65, 121, -87, 32, 103, -68, -81, 68, -7, 92, 71, -123, -122, 81, -103, 119, 39, 71, 56, -90, -121, -124, -98, -66, -128});
    private static final Scalar c2_a = decodeScalar(new byte[] {-73, 85, 3, 114, 28, -82, -72, -34, -63, 124, -127, -121, 5, 84, 96, -47, -90, -105, -3, -42, 72, -77, -54, 85, -9, 6, -70, -86, -55, -82, -126, -48, -16, -47, -12, 50, -96, -51, 112, 41, 126, 41, 14, -91, 56, 82, 68, 10, 106, 22, 71, 47, -59, 112, -124, 18, 0});
    private static final Scalar d2_a = decodeScalar(new byte[] {49, 78, 26, -126, -36, -126, 35, 43, 15, 61, -27, -118, 18, -76, -2, -37, -61, 28, -24, -8, -108, -19, -33, -89, 8, 119, -90, 25, 63, 4, 21, 16, -38, 75, 101, -12, 36, -66, 23, -87, -126, -3, -97, 41, 40, 9, 36, -79, 33, 90, 75, 16, -32, 52, 31, 29, 0});
    private static final Scalar c3_a = decodeScalar(new byte[] {70, 6, -35, 50, 32, 21, -11, 122, 30, -106, -90, -95, 26, -12, 88, -87, -38, 114, 115, -73, 75, 14, -68, 127, 43, -121, -117, 19, -61, -11, 80, -5, 80, 30, -122, -46, 97, 127, 77, 18, -7, -37, 53, 119, -39, 107, -110, -30, -127, 98, -41, -100, 86, 75, -110, 54, 0});
    private static final Scalar d3_a = decodeScalar(new byte[] {38, 92, -102, 60, 13, 53, 108, -44, 127, 98, 50, 4, 123, -68, 87, -8, -69, 118, 20, 55, 34, -7, 67, 101, -62, 7, -26, -10, -117, -105, -22, 120, -23, -46, -95, -54, -111, 92, 4, -90, 55, -64, 23, -89, 100, 0, 114, 60, -13, 58, 25, -57, -88, 83, -62, 48, 0});

    @Test
    public void testConstruct() {
        final StateExpect1 state = new StateExpect1(RANDOM, UNDECIDED);
        assertEquals(UNDECIDED, state.getStatus());
    }

    @Test(expected = NullPointerException.class)
    public void testConstructNullRandom() {
        new StateExpect1(null, UNDECIDED);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructNullStatus() {
        new StateExpect1(RANDOM, null);
    }

    @Test(expected = NullPointerException.class)
    public void testInitiateNullContext() {
        final StateExpect1 state = new StateExpect1(RANDOM, UNDECIDED);
        state.initiate(null, "Hello", secret);
    }

    @Test(expected = NullPointerException.class)
    public void testInitiateNullQuestion() {
        final StateExpect1 state = new StateExpect1(RANDOM, UNDECIDED);
        final SMPContext context = mock(SMPContext.class);
        state.initiate(context, null, secret);
    }

    @Test(expected = NullPointerException.class)
    public void testInitiateNullSecret() {
        final StateExpect1 state = new StateExpect1(RANDOM, UNDECIDED);
        final SMPContext context = mock(SMPContext.class);
        state.initiate(context, "Hello", null);
    }

    @Test
    public void testInitiate() throws ValidationException {
        final byte[] fakeRandomData = new byte[] {114, -67, 114, -53, -38, -115, 117, -30, 99, 105, 35, -107, -43, -10, -66, 115, 52, 66, -45, 50, 66, -56, -37, 2, -16, 10, -115, -126, 77, -109, -110, 36, 6, 118, -110, -94, -90, -58, 1, 65, -61, -6, 5, 104, 14, 113, 65, 39, -23, 12, 21, 42, -96, -9, -120, -85, 22, -22, 20, -66, -90, -107, 105, -94, 61, 12, 115, 114, -89, -100, -68, -124, 3, -73, -36, -25, 0, -39, -120, 74, -21, -80, -28, 78, 8, 82, -116, -47, 121, -128, 86, -110, 85, -63, -85, 41, 40, -69, -57, 57, 58, 47, 31, 105, 46, -75, 23, -125, -103, 50, -8, -83, -34, -52, 65, -67, 94, 93, -49, -1, -110, -78, 121, -104, 6, -43, 68, 107, 7, -108, -8, 17, -22, -14, -55, -19, -83, -57, -112, 77, -33, 55, -114, -90, -58, -52, 37, -125, 105, -80, -73, -12, 126, 69, 123, -83, -43, 34, 39, -124, -101, 25, 69, -61, 86, 35, 114, -79, -40, 86, 30, 106, 81, 58, 59, 27, 27, 80, -70, -114, -20, -32, -125, -107, -121, -107, 122, 42, -50, 71, -56, 9, 84, -82, 48, 122, 59, 81, -27, -85, -74, 58, -21, -13, 73, -46, -49, -30, 3, 107, -79, -105, 65, 34, 4, -18, 1, 86, 85, 83, -64, 88, -118, 30, -1, -93, -29, -62};
        final Point expectedG2a = decodePoint(new byte[] {32, -8, 55, 39, -11, -92, -117, -97, 74, -128, 12, 11, 6, 10, -68, 111, -17, -13, 39, -99, -43, 31, -64, -48, 76, -120, -65, -94, -128, -27, -101, 6, 17, -70, -38, 106, 15, 37, 21, -101, -121, -80, -63, -8, -94, -78, 42, -120, 94, 60, -91, -52, 71, 66, -20, 62, 0});
        final Scalar expectedC2 = decodeScalar(new byte[] {-79, 24, -50, 77, 95, -1, -110, 12, 101, 55, 22, -105, -126, 109, 65, 26, 18, 112, -72, 101, -43, -58, -94, -87, 23, -59, 26, 52, -29, 37, 122, 102, -125, -12, -98, 51, 27, -87, 36, 4, 5, 70, -30, -114, -67, 101, -122, -46, 24, -17, -89, -86, 113, 20, 108, 4, 0});
        final Scalar expectedD2 = decodeScalar(new byte[] {-42, 2, 19, 77, 9, 48, -55, 56, 74, 122, -96, -13, -116, -112, -7, 64, 88, 82, -96, 108, -112, -71, -26, 124, -110, 60, -108, 51, -47, 60, -59, -94, 15, -15, 38, -126, 105, 45, 115, -38, -127, 3, 77, -19, 84, 103, 117, -68, 26, 61, -106, -113, -77, 36, 21, 35, 0});
        final Point expectedG3a = decodePoint(new byte[] {37, -121, 56, -65, 54, 95, 66, -79, -117, -55, -25, 43, -17, 69, 123, -75, -50, -124, 54, 32, 60, -84, 121, -68, 30, -88, -35, 8, -66, 63, -23, 66, -65, -120, 81, -3, -110, -48, 55, -74, -93, 106, -38, 69, -64, -101, 32, -62, 3, -90, 91, -109, -55, 79, 70, 43, 0});
        final Scalar expectedC3 = decodeScalar(new byte[] {20, 114, 1, 123, 12, -2, 17, 20, -112, 101, -120, 23, -94, -77, 106, -28, -2, 24, -104, -91, -10, 38, 67, 51, 102, -53, -16, -80, 14, -72, 52, -6, -15, 100, -28, -116, -28, 58, -91, 125, 6, -124, 8, 112, 38, 20, 81, -81, 42, 10, 47, -126, -91, -75, 112, 48, 0});
        final Scalar expectedD3 = decodeScalar(new byte[] {69, 123, 68, -106, 41, -46, 5, 72, -59, 45, 17, -70, -126, -111, -80, -22, -26, -42, 122, -39, 110, -41, -17, 68, 99, 121, -32, -124, 107, -61, -44, 42, -58, -65, -100, 75, -93, 111, 89, -55, -68, -26, -18, 80, -126, 102, -13, -125, -44, 8, 25, 22, -102, 79, 20, 52, 0});
        final StateExpect1 state = new StateExpect1(new FixedSecureRandom(fakeRandomData), UNDECIDED);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage1 message = state.initiate(context, "Hello", secret);
        assertNotNull(message);
        assertEquals("Hello", message.question);
        assertEquals(expectedG2a, message.g2a);
        assertEquals(expectedC2, message.c2);
        assertEquals(expectedD2, message.d2);
        assertEquals(expectedG3a, message.g3a);
        assertEquals(expectedC3, message.c3);
        assertEquals(expectedD3, message.d3);
    }

    @Test
    public void testRespondWithSecret() throws SMPAbortException, ValidationException {
        final byte[] fakeRandomData = new byte[] {-7, -24, 35, -23, 9, -56, 25, -120, 9, -8, -82, 105, 109, 17, -57, 122, -20, -80, 82, -117, 25, 30, -13, 112, -34, -58, -17, -8, 88, -123, 14, -30, -25, -23, 74, 0, 96, -102, -10, -62, -93, -84, -10, -95, -36, 120, -73, -42, -80, -20, -12, -19, 124, 43, -69, -59, 19, 100, -70, -108, -4, 110, -21, -13, -2, 2, 39, -33, -121, -65, 3, 9, -52, 39, 126, 48, 52, 20, 107, 106, -80, 96, 33, 112, -26, 11, 14, -16, -59, -37, 32, 98, -59, -66, -71, -54, -5, 106, 10, 44, 16, -34, -64, 119, 41, -42, -36, 104, -123, 49, -53, -18, 124, 87, 0, 31, 0, -49, 39, -100, -123, 9, -67, -81, 42, -84, 56, 34, 103, 35, -33, 77, 63, -84, 22, -11, -89, 65, -69, -67, 121, 122, -105, -110, -85, -28, -84, 27, -127, -35, -90, -48, 89, -54, -58, -84, -71, 97, 83, -21, -50, -94, -44, 73, -18, -106, -7, 92, -57, -75, 51, -35, -42, -2, 21, -22, 3, -71, 116, 29, -120, -103, -63, 82, -57, 5, -15, -42, 57, 29, 62, -31, 41, 92, -48, 2, 61, 72, 48, -75, -58, -38, 18, 59, 5, -61, -91, -35, -69, 33, -34, -118, -28, -104, -125, 97, 47, 45, 21, -106, -72, 96, -15, 0, -84, -80, -28, 121, -74, -9, -81, -48, -28, -52, 64, 86, -21, 27, -127, 111, -96, -96, -11, -118, 41, 57, 81, -54, 6, 78, 38, 78, -8, 114, -65, -114, 94, 21, 57, -11, -23, -121, 58, 85, 54, 121, -99, 47, 114, 35, -101, 116, 90, 6, -4, -76, 15, -12, -14, 37, -99, -40, -41, 15, 112, 40, 76, -125, -75, -94, 36, -61, 84, 72, 96, 41, -119, -53, -98, -79, 47, -52, 66, -98, 67, 78, 46, 52, -1, -12, -91, -122, 101, 114, -48, 74, -73, -44, -56, -9, -94, -112, -73, -23, -100, -20, -39, 3, 79, 11, 92, -57, -52, 83, -44, -109, 75, -92, -18, 75, -126, -36, -3, -45, -35, 28, -4, -14, -88, 65, 121, -119, 52, 15, -121, -63, -105, -25, 81, 13, 119, 119, -127, 41, 82, -85, -23, -75, 104, 59, -82, 22, 36, 76, 92, 54, 45, -70, 30, 20, -91, -90, 22, 101, -128, -125, -85, 38, -45, -5, 64, -74, -82, 5, 41, -102, -121, 38, 63};
        final Point expectedG2b = decodePoint(new byte[]{65, 58, -110, 57, 28, 28, -46, 89, 27, -15, -67, 3, 34, 50, 85, 104, 56, 26, 34, 105, -68, -106, -20, -63, -51, -90, -108, 97, 24, 59, 66, -13, 93, 36, -46, 89, 46, -37, 66, 43, -128, -19, 2, 123, 23, 25, -12, 3, 75, -21, 117, -127, 57, -101, 44, -55, -128});
        final Scalar expectedC2 = decodeScalar(new byte[]{71, 107, -29, 100, 126, 89, -4, 44, -40, 26, 25, -13, 77, -5, -72, 109, -99, -5, 15, 73, 95, -12, -112, -11, 18, -109, 34, -123, -28, 60, -35, 4, -24, -12, -111, 4, -66, -8, -104, 122, -96, 96, 88, -23, 2, -64, 60, -123, 90, 59, -96, -82, -104, -23, 111, 49, 0});
        final Scalar expectedD2 = decodeScalar(new byte[]{-33, -128, -11, -103, -35, -54, 10, -54, -62, -100, -34, -17, -38, -74, 59, 18, 18, -86, 46, -112, -79, -14, 72, -14, 11, 18, -1, 123, -61, 79, 45, 13, 72, -3, 83, -66, -79, 5, 50, 75, -109, -125, 83, 124, -90, -106, -93, -46, -62, 4, 89, -5, -54, 17, -102, 24, 0});
        final Point expectedG3b = decodePoint(new byte[]{27, -86, 76, -40, 64, -120, -17, -69, -126, -30, 13, -41, -19, -68, -53, 78, -92, -66, -23, -63, -115, -37, -59, -98, 105, 70, 28, -60, -16, 71, 35, 94, -55, -4, -57, -6, -4, -61, 16, -53, 108, -70, 23, 60, -98, 115, -123, 13, 69, -2, -2, 48, 64, 53, -45, -55, 0});
        final Scalar expectedC3 = decodeScalar(new byte[]{120, 10, 45, 47, -122, 49, 64, 116, -88, 71, -82, 17, -9, -113, 73, 15, 16, 92, -125, 12, 69, -125, 113, -5, 42, 34, 36, -84, 34, 50, -111, 62, -41, 75, -68, 105, 99, 41, 26, -120, -109, 51, 59, -127, 125, -127, -31, -79, 70, -47, -106, -11, 54, 122, 92, 2, 0});
        final Scalar expectedD3 = decodeScalar(new byte[]{57, -16, 49, 39, -122, -60, 69, 65, -61, -115, -79, 22, 116, -109, 10, 111, 88, 8, 12, -75, -50, -98, 72, 90, 81, 63, 21, 54, -13, 93, -61, 4, -106, 119, 16, -59, -66, -106, 90, 64, -115, -29, -26, -98, -49, -116, -30, 41, -97, 24, 63, 47, 36, 114, -34, 40, 0});
        final Point expectedPb = decodePoint(new byte[]{-12, -54, 15, -7, -78, -117, -79, -62, 60, 20, -5, 32, -44, -36, -48, -84, -117, -117, -125, 123, -42, 56, -117, -15, 112, 27, -87, 70, -108, -12, -81, 47, 66, 47, -23, -53, -47, 17, 10, -36, -57, 24, -81, 55, 65, 1, -59, -105, 73, 13, -3, 109, -18, -58, 46, -13, 0});
        final Point expectedQb = decodePoint(new byte[]{-41, -69, -9, 21, -51, -50, 119, -63, 88, -43, 31, 77, -58, 103, -115, 14, 1, -47, 33, 83, -104, -27, -20, -125, -87, -128, 65, -20, -83, 110, -40, 23, -124, -30, 78, -45, 124, -100, 103, -85, -122, 101, -78, -56, -77, -120, 98, -118, -9, -126, 52, 35, -32, -88, 90, -115, -128});
        final Scalar expectedCp = decodeScalar(new byte[]{-90, -6, 90, -55, -100, 39, 19, -3, -106, 82, 32, 36, -121, -36, -37, 8, -56, -38, 93, -65, 107, 67, -114, -90, -68, -3, -102, 90, -41, -98, -43, 127, -39, -86, -39, 40, -6, 73, -78, -107, 42, -66, 55, 48, 19, 14, 13, -87, 21, -8, 49, 24, 75, -45, 36, 32, 0});
        final Scalar expectedD5 = decodeScalar(new byte[]{73, -120, 60, -27, -97, 21, 54, -60, -22, 46, -42, -25, 63, -125, -17, -115, -115, -95, -68, -113, -117, 96, -127, 111, 54, 118, -97, -104, 1, 71, 52, 92, -122, 39, 54, 68, 23, 45, -30, -79, 46, -62, 12, -126, -13, -42, 68, 9, -84, 108, 94, -76, 91, 66, -62, 53, 0});
        final Scalar expectedD6 = decodeScalar(new byte[]{59, -107, 49, 66, 99, 4, 76, -8, -14, 84, -32, 122, 1, 51, -36, 67, -63, -13, 13, -13, 94, 80, 68, -66, 71, -112, -79, -69, 24, 33, 100, 14, -37, -63, 77, -91, 12, -57, -109, -25, -73, 99, 79, -123, 40, 119, 13, 43, -27, 35, -31, 123, -122, -12, -24, 62, 0});
        final StateExpect1 state = new StateExpect1(new FixedSecureRandom(fakeRandomData), UNDECIDED);
        final Context context = new Context();
        state.process(context, new SMPMessage1("Hello", g2a, c2_a, d2_a, g3a, c3_a, d3_a));
        final SMPMessage2 message = context.state.respondWithSecret(context, "Hello", secret);
        assertNotNull(message);
        assertEquals(expectedG2b, message.g2b);
        assertEquals(expectedC2, message.c2);
        assertEquals(expectedD2, message.d2);
        assertEquals(expectedG3b, message.g3b);
        assertEquals(expectedC3, message.c3);
        assertEquals(expectedD3, message.d3);
        assertEquals(expectedPb, message.pb);
        assertEquals(expectedQb, message.qb);
        assertEquals(expectedCp, message.cp);
        assertEquals(expectedD5, message.d5);
        assertEquals(expectedD6, message.d6);
    }

    @Test
    public void testRespondWithSecretNoMessageReceived() {
        final StateExpect1 state = new StateExpect1(RANDOM, UNDECIDED);
        final SMPContext context = mock(SMPContext.class);
        assertNull(state.respondWithSecret(context, "Hello", secret));
    }

    @Test
    public void testRespondWithSecretWrongQuestion() throws SMPAbortException {
        final StateExpect1 state = new StateExpect1(RANDOM, UNDECIDED);
        final Context context = new Context();
        state.process(context, new SMPMessage1("Hello", g2a, c2_a, d2_a, g3a, c3_a, d3_a));
        assertNull(context.state.respondWithSecret(context, "Bye", secret));
    }

    @Test(expected = NullPointerException.class)
    public void testProcessNullContext() throws SMPAbortException {
        final StateExpect1 state = new StateExpect1(RANDOM, UNDECIDED);
        assertNull(state.process(null, new SMPMessage1("Hello", g2a, c2_a, d2_a, g3a, c3_a, d3_a)));
    }

    @Test(expected = NullPointerException.class)
    public void testProcessNullMessage() throws SMPAbortException {
        final StateExpect1 state = new StateExpect1(RANDOM, UNDECIDED);
        final Context context = new Context();
        assertNull(state.process(context, null));
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessSMPMessage4() throws SMPAbortException {
        final StateExpect1 state = new StateExpect1(RANDOM, UNDECIDED);
        final Context context = new Context();
        final SMPMessage4 message = new SMPMessage4(basePoint(), generateRandomValueInZq(RANDOM),
                generateRandomValueInZq(RANDOM));
        state.process(context, message);
    }

    @Test
    public void testProcess() throws SMPAbortException {
        final StateExpect1 state = new StateExpect1(RANDOM, UNDECIDED);
        final Context context = new Context();
        final SMPMessage1 message = new SMPMessage1("Hello", g2a, c2_a, d2_a, g3a, c3_a, d3_a);
        assertNull(state.process(context, message));
        assertEquals("Hello", context.question);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessIllegalg2a() throws SMPAbortException {
        final StateExpect1 state = new StateExpect1(RANDOM, UNDECIDED);
        final Context context = new Context();
        final SMPMessage1 message = new SMPMessage1("Hello", createPoint(BigInteger.ONE, BigInteger.ONE), c2_a, d2_a, g3a, c3_a, d3_a);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessBadg2a() throws SMPAbortException {
        final StateExpect1 state = new StateExpect1(RANDOM, UNDECIDED);
        final Context context = new Context();
        final SMPMessage1 message = new SMPMessage1("Hello", g2a.negate(), c2_a, d2_a, g3a, c3_a, d3_a);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessIllegalg3a() throws SMPAbortException {
        final StateExpect1 state = new StateExpect1(RANDOM, UNDECIDED);
        final Context context = new Context();
        final SMPMessage1 message = new SMPMessage1("Hello", g2a, c2_a, d2_a, createPoint(BigInteger.ONE, BigInteger.ONE), c3_a, d3_a);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessBadg3a() throws SMPAbortException {
        final StateExpect1 state = new StateExpect1(RANDOM, UNDECIDED);
        final Context context = new Context();
        final SMPMessage1 message = new SMPMessage1("Hello", g2a, c2_a, d2_a, g3a.negate(), c3_a, d3_a);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessIllegalc2() throws SMPAbortException {
        final StateExpect1 state = new StateExpect1(RANDOM, UNDECIDED);
        final Context context = new Context();
        final SMPMessage1 message = new SMPMessage1("Hello", g2a, Scalars.one(), d2_a, g3a, c3_a, d3_a);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessIllegald2() throws SMPAbortException {
        final StateExpect1 state = new StateExpect1(RANDOM, UNDECIDED);
        final Context context = new Context();
        final SMPMessage1 message = new SMPMessage1("Hello", g2a, c2_a, Scalars.one(), g3a, c3_a, d3_a);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessIllegalc3() throws SMPAbortException {
        final StateExpect1 state = new StateExpect1(RANDOM, UNDECIDED);
        final Context context = new Context();
        final SMPMessage1 message = new SMPMessage1("Hello", g2a, c2_a, d2_a, g3a, Scalars.one(), d3_a);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessIllegald3() throws SMPAbortException {
        final StateExpect1 state = new StateExpect1(RANDOM, UNDECIDED);
        final Context context = new Context();
        final SMPMessage1 message = new SMPMessage1("Hello", g2a, c2_a, d2_a, g3a, c3_a, Scalars.one());
        state.process(context, message);
    }

    private static Point mustDecodePoint(@Nonnull final byte[] encoded) {
        try {
            return decodePoint(encoded);
        } catch (final ValidationException e) {
            throw new IllegalArgumentException("Illegal point.", e);
        }
    }

    private static final class Context implements SMPContext {
        private SMPState state;
        private String question;

        @Override
        public void setState(@Nonnull final SMPState newState) {
            this.state = requireNonNull(newState);
        }

        @Override
        public void requestSecret(@Nonnull final String question) {
            this.question = requireNonNull(question);
        }
    }
}