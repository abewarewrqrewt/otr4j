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
import static net.java.otr4j.crypto.ed448.Point.decodePoint;
import static net.java.otr4j.crypto.ed448.PointTestUtils.createPoint;
import static net.java.otr4j.crypto.ed448.Scalar.decodeScalar;
import static net.java.otr4j.crypto.ed448.ScalarTestUtils.fromBigInteger;
import static net.java.otr4j.session.api.SMPStatus.UNDECIDED;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.mock;

@SuppressWarnings("ConstantConditions")
public final class StateExpect1Test {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Scalar secret = fromBigInteger(new BigInteger("156646870446509697993543906405546302203937595276099597245169544217380323950616830748419230701118835593301852473925689151030104403160214", 10));
    private static final Point g2a = createPoint(
            new BigInteger("556126760061111951763657713165359364949137409429907558250190706803191942221006997715534159064635956115146859509850685483783825658051062", 10),
            new BigInteger("402300785987933532722239956410658839879984334939846965731832817389739507515141868374683434686898800718793116044193956150363860355205672", 10));
    private static final Point g3a = createPoint(
            new BigInteger("518174644249461528695945953725187603845615868738496167939067703005335185228858161198005082414857631829817255298083903928767327400128404", 10),
            new BigInteger("411593944040901258928967352546948763853118126911749716436241852339527571133863427871032238507886034736469451532393155247111763030574468", 10));
    private static final Scalar c2_a = fromBigInteger(new BigInteger("56215524322547104127699096785674005241383967134488713674233477434334447753644548760497263024362137158154026484631381429216317310018096", 10));
    private static final Scalar d2_a = fromBigInteger(new BigInteger("49816908830739953057536629170097286773000082402282036191373078454544319859212531223793126796299628553378507448554557863323847000516506", 10));
    private static final Scalar c3_a = fromBigInteger(new BigInteger("133604216714654954479797674994885870941073982273867141172149471004408885607045458728198265688676286621800854863935821594357563292700948", 10));
    private static final Scalar d3_a = fromBigInteger(new BigInteger("175749258705876639276476226769967272420621636867036494467329856230066809134918277210694227277683436810214089278213679819342030799621732", 10));

    private static final Point rb = createPoint(
            new BigInteger("207262232174680451060776976413201759833926533152870268659156413710415430620278577554952401659472618835066253611213476907998866291547848", 10),
            new BigInteger("243919295076423503288241325716951068924347181567637759634078287663516781375902876181296806140094995694034332370011945034139749942390997", 10));
    private static final Scalar cr = fromBigInteger(new BigInteger("56552690208569846484767066019279120176962659824535518690139189690745687293876835490924077826911617221281921640170307321984832871226348", 10));
    private static final Scalar d7 = fromBigInteger(new BigInteger("145952570674148673490476737637065914811240433627086277391960523808477106159276648430230314099961485884566992342590501652557852798653734", 10));

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
        final byte[] fakeRandomData = new byte[] {-62, -76, -12, -64, -81, 14, 123, 99, -67, -96, -27, -52, 40, 120, -89, 14, -48, 116, 127, -13, -39, 36, 44, 55, 100, -82, 58, 6, -125, 42, 56, 67, 122, -31, -126, -14, -45, -124, 97, 87, 51, -37, -64, -113, -10, -32, -15, -43, -103, 81, -64, 43, 43, 104, -62, 32, -47, 0, -23, 50, 2, 65, 73, -25, 78, -45, -101, -32, -123, -4, -108, -31, 57, -82, 125, -125, -100, -52, -2, -24, 31, 12, -18, 104, 123, -78, 73, -54, 81, -44, -39, -47, 82, -23, 107, -6, -19, -18, 107, -6, -121, 5, 95, 93, 105, 1, -46, -45, 46, 113, -52, -55, 69, -10, -36, 88, -55, 121, -89, -120, 126, -49, 79, -3, -97, 96, 70, 115, 47, -5, -120, 33, -126, 110, -98, 12, -125, 34, -91, 44, -105, 122, -27, 12, 66, -3, 54, -61, -103, 35, -11, -55, 31, 42, -122, -61, 15, -96, -56, -46, 48, 85, -31, 124, -26, -115, 62, 87, 68, -15, -35, -34, -63, -67, -106, 117, -94, 3, -73, -11, -50, -87, -9, 75, 56, -76, 14, -15, -70, 69, 47, 56, 29, -105, -52, 2, 127, 20, -7, 18, 108, 78, 35, 122, -88, 5, 109, -76, 79, -100, 125, -7, 49, -17, -107, 125, -21, 85, 34, 88, -126, -70, -5, -7, -108, 95, -18, -4};
        final Point expectedG2a = decodePoint(new byte[] {77, 12, 8, -14, -91, -114, 25, 26, -58, -4, 40, -11, -54, -82, -94, 4, 21, -113, -14, -1, 33, 93, 25, 68, -79, -15, -15, 55, -104, 17, -56, 103, -93, 74, 49, 106, -56, 61, -15, -7, 76, -110, -92, -26, -40, -57, 103, -58, 122, -48, -3, 89, 38, 68, 1, -65, -128});
        final Scalar expectedC2 = decodeScalar(new byte[] {-116, 105, 57, 36, 123, 7, 6, -99, 101, -11, 79, 71, 25, 110, -46, 4, 106, -58, 119, 71, 80, 121, 45, 25, 38, -76, -35, -14, -87, 79, -31, -94, 2, -53, -80, -120, 43, 111, 58, -5, 40, 45, -88, 47, 84, -47, -89, -97, -53, -117, 1, -112, 64, -112, 94, 42, 0});
        final Scalar expectedD2 = decodeScalar(new byte[] {-115, -30, 103, 20, 114, -15, -17, 127, -108, -49, -128, 120, 72, -4, 90, -73, -11, 4, -100, -62, -111, 83, -19, -11, -111, 46, -112, -128, -87, -81, -52, 64, -58, 63, -115, 4, 54, -53, -75, 74, 8, -24, -103, 94, 44, -25, 18, 94, 1, 63, -23, 76, 120, 116, -123, 38, 0});
        final Point expectedG3a = decodePoint(new byte[] {-50, -99, -13, -99, 56, 98, -31, -84, -79, 37, 22, -28, -52, -28, -110, 52, 96, -114, -92, 0, -48, 40, 113, 113, 123, -35, 113, -14, -13, 86, 107, 58, -97, 106, -46, 0, -10, 85, 63, -18, -66, -114, -50, -49, -44, 89, -22, 91, -19, 43, -59, -2, 85, 111, 54, 61, 0});
        final Scalar expectedC3 = decodeScalar(new byte[] {-36, 98, -114, 1, 127, 116, -118, -16, 5, 66, 75, -109, 58, -103, -112, -77, 86, -44, -115, 21, 58, 110, -10, 18, 121, -7, -68, -109, -61, -105, -121, 77, 30, 3, 126, -52, 60, -85, 29, -88, 85, -109, -76, 94, 19, -76, -35, -101, 15, -84, -79, -53, 1, 24, -22, 47, 0});
        final Scalar expectedD3 = decodeScalar(new byte[] {123, 56, 60, -72, -58, -79, 115, -87, 105, 40, 104, -30, -76, 60, -82, 85, -27, -69, 23, 2, -82, 15, 117, 56, 124, -70, 75, -115, 1, 19, -21, 115, -93, 90, -53, -48, -22, -50, 13, 46, -67, -114, 81, -97, 75, 43, 16, -101, 27, -75, 10, 64, 45, -28, -116, 40, 0});
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
        final Scalar expectedC2 = decodeScalar(new byte[]{71, 111, -117, -103, -28, 22, -69, -44, -125, 8, 86, 12, -128, 14, -50, -4, 53, 16, -21, 44, -95, 108, -36, -81, -43, -115, 75, -48, 21, 3, 12, -21, 113, -13, 75, 19, -65, -8, -104, 122, -96, 96, 88, -23, 2, -64, 60, -123, 90, 59, -96, -82, -104, -23, 111, 49, 0});
        final Scalar expectedD2 = decodeScalar(new byte[]{64, -45, 95, 86, 59, -33, -57, 29, -22, 11, -50, 78, -15, 27, 56, 80, -29, 42, -8, -42, -55, -96, 95, -26, 5, 95, -21, 14, 19, 92, -111, -20, 110, 77, -95, -16, 121, -113, -52, -8, 63, 24, -2, 56, -7, 35, -68, 119, -49, -72, 23, -105, 89, -70, -27, 10, 0});
        final Point expectedG3b = decodePoint(new byte[]{27, -86, 76, -40, 64, -120, -17, -69, -126, -30, 13, -41, -19, -68, -53, 78, -92, -66, -23, -63, -115, -37, -59, -98, 105, 70, 28, -60, -16, 71, 35, 94, -55, -4, -57, -6, -4, -61, 16, -53, 108, -70, 23, 60, -98, 115, -123, 13, 69, -2, -2, 48, 64, 53, -45, -55, 0});
        final Scalar expectedC3 = decodeScalar(new byte[]{120, -114, -126, -45, -64, 53, 109, -104, 59, -55, 23, 98, -113, 18, -26, -81, -117, 53, -102, -67, -89, 6, 56, 18, 61, -21, 113, -64, -69, 104, 78, -56, 84, -122, -28, 30, 101, 41, 26, -120, -109, 51, 59, -127, 125, -127, -31, -79, 70, -47, -106, -11, 54, 122, 92, 2, 0});
        final Scalar expectedD3 = decodeScalar(new byte[]{-109, 127, 123, 100, -88, 107, 45, 124, 71, -50, 86, -93, -73, 6, 101, 74, 80, 18, 59, 102, -98, 31, -37, -110, 6, 117, -56, -8, -4, 56, 32, 65, 57, 87, 39, -95, -105, -128, 47, 74, 61, -32, 89, -65, 70, 79, 71, -64, -128, -115, 106, 81, -75, 22, 18, 23, 0});
        final Point expectedPb = decodePoint(new byte[]{82, -64, -87, -24, -85, 67, 14, -83, 13, -107, 101, -122, -68, 57, -97, -80, -32, -73, -86, 81, -9, -58, 79, -68, -123, 121, -55, 127, -40, -119, 44, 96, 71, 116, -52, -86, -1, 98, -37, 102, -21, 101, 31, -23, 4, -96, 86, -71, 38, -12, -1, 13, -111, -33, 17, -2, 0});
        final Point expectedQb = decodePoint(new byte[]{-10, 125, -23, -11, 23, -5, 4, 126, -41, 106, 96, -101, -52, -75, -64, -41, -43, 72, -38, -28, -83, -21, -79, -34, 55, -3, 28, 113, -103, 37, -46, -32, -28, -42, 103, 18, 1, -23, -71, -86, -40, -109, 9, 18, -49, 98, -59, 93, 105, 62, -117, 20, -76, 2, 44, 13, 0});
        final Scalar expectedCp = decodeScalar(new byte[]{-77, -27, -128, -37, -99, -25, 82, -41, 104, 43, 5, -110, -18, 36, -86, 24, 33, 77, -80, 108, -3, 88, -19, 108, -102, -71, 72, -52, -128, 67, -33, 68, -120, 47, 26, -59, 30, 37, -97, 102, -37, -89, -9, -11, 62, 98, 122, 51, -125, 28, 42, -24, 52, 43, -49, 12, 0});
        final Scalar expectedD5 = decodeScalar(new byte[]{-122, -53, -34, 0, 53, 24, 89, -55, 19, -77, -51, 33, -19, 57, 0, -90, -79, -28, -27, 45, -102, 74, -111, -113, -15, -101, -15, 86, -31, -7, -45, -111, 126, -109, -11, -12, -65, -73, -24, -115, 54, 120, 25, -84, -34, -57, 74, -86, -117, 17, -115, 125, -24, 43, -91, 9, 0});
        final Scalar expectedD6 = decodeScalar(new byte[]{-92, -3, -127, 19, -48, 56, 109, 43, 23, -125, -18, -88, -119, -121, 77, -37, -12, 32, 115, 55, 29, -116, 99, 19, 13, -47, -48, -74, -43, -120, -115, -90, -61, -86, 33, 40, -124, 51, 32, 28, 120, 74, 107, 39, -57, -24, 103, -86, 118, -29, 72, -74, -100, -98, 43, 31, 0});
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
        final SMPMessage4 message = new SMPMessage4(rb, cr, d7);
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