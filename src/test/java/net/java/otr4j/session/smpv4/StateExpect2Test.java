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
    private static final Scalar secret = fromBigInteger(new BigInteger("156646870446509697993543906405546302203937595276099597245169544217380323950616830748419230701118835593301852473925689151030104403160214", 10));
    private static final Point g2b = createPoint(
            new BigInteger("535510067367745935609486739796535297303106274342962289544648627870003598673009393052188837292200285737567938860665953091291609090188544", 10),
            new BigInteger("125280783069596720941658452716628999375827610701463890489482485540230585647574140509361516626953912722673932519726268057161630015231532", 10));
    private static final Point g3b = createPoint(
            new BigInteger("25460154400798033061057906375464023188226226982418482149467593583623510947345044595566809932111935577651183265131423524693421017471242", 10),
            new BigInteger("553052674467468451498390089236097910339465676043764019155003492986686446924070189167293939278539676908850471424077516167161370570930870", 10));
    private static final Point pb = createPoint(
            new BigInteger("150971551590059119684514014051782205053977785666422029127804430526951029198846199892957327905468410035748726553951282154034774550008486", 10),
            new BigInteger("22380432526449194175787570945218836926017979984737449943120906860192566288203629458502199108124043807619691145917657476124547825617627", 10));
    private static final Point qb = createPoint(
            new BigInteger("423430412264875129675225626571000691034761078275754236126134904918998073249689389127999342833148835049651469030268345753112431699348696", 10),
            new BigInteger("27371249592200388578572706841215291643260958466414201154940100359190642782246779086087976919600673242377448605891352376861486556308423", 10));
    private static final Point pa = createPoint(
            new BigInteger("465943338087689210004311262653217262867584260336764995023461214036125904185851440432009245692764184419275942574209323203357723240467548", 10),
            new BigInteger("171512624718754523296213069499915004048105351732065305821916994076620475525139204045825568923885234090579511388053138214933231286738769", 10));
    private static final Point qa = createPoint(
            new BigInteger("166233517570629524836327531569104738143692654989309180176792709961188220191331070218340399706383261483114723213643495221558313447723211", 10),
            new BigInteger("518917581830034185786914774664355117879178739934839678626989026565322227675465996556006358187381023415692754242138646331342140362437821", 10));
    private static final Point ra = createPoint(
            new BigInteger("314477180835505334456514522697211639823564271172558398781788373480025093584267496798280363802109367409945899677297245744207604995798215", 10),
            new BigInteger("314029684065464803946366772814894787049170212355244776063157390940002824357662292553115470960421307470791608461875703125153400706900709", 10));
    private static final Scalar r4 = fromBigInteger(new BigInteger("4848823671279697407137727930542462362850237819434391365386462331719995539129866443292840169805814262621847420649345769965317287348", 10));
    private static final Scalar r5 = fromBigInteger(new BigInteger("6093723104156361563235633010766054571606619914455883426503126819249759028984281412972947332166622716165667676992220970018247617818", 10));
    private static final Scalar r6 = fromBigInteger(new BigInteger("4898355827584876372361803991328154525279690424308456604711524616971929965834305690790568318779002259332597465317036597829614224197", 10));
    private static final Scalar r7 = fromBigInteger(new BigInteger("10327876212163104498832270384706478291329857475634355830265712208763978612460575175501454261843646764359066094297572626480874373321", 10));
    private static final Scalar a2 = fromBigInteger(new BigInteger("673848653576269490820269595107132458021950184923936107336090953739462122027562298199756197615735822162566149329088995049443871609", 10));
    private static final Scalar a3 = fromBigInteger(new BigInteger("10992407629513027537721921961288862111472222592979105676178912973948354718168450900717698573770450980134969731918121327601220662649", 10));
    private static final Scalar c2 = fromBigInteger(new BigInteger("111022924696436872341199729470810106169691412099562751065315157956932607321704386418842646614967543212975232690938096962929374138840360", 10));
    private static final Scalar d2 = fromBigInteger(new BigInteger("101345345229065684334282374371023601758415295857263117254747849658520035320960346748846057135976056655742957171515534523417214373693098", 10));
    private static final Scalar c3 = fromBigInteger(new BigInteger("62617459100015197706706660769267850673374894996485466090690871115733599023295580435733677134748019493119048062634692839095351921724769", 10));
    private static final Scalar d3 = fromBigInteger(new BigInteger("137562898370533368188949012935464486921412442457491703380251471222259286769274568095679144010941490174773593749015593431117048642147968", 10));
    private static final Scalar cp = fromBigInteger(new BigInteger("28045188189773086196199811649212088777481441211542237396012741618349225156254977936298093632091077961453305961030130988861845216328283", 10));
    private static final Scalar d5 = fromBigInteger(new BigInteger("149784617958500236288042084698627372846752050231135475713620548703969334046909579101335416023239157022443926007634155769652596827828560", 10));
    private static final Scalar d6 = fromBigInteger(new BigInteger("94724577901200260682137525745100301807843255453810112147553827587265819853644379707894360868997126906680725252985586449377226774745039", 10));
    private static final Scalar cr = fromBigInteger(new BigInteger("48212869955179756863375262751674186371416622227372458498814862703043948906876869678112891347756106998961858786630233240056114069543171", 10));
    private static final Scalar d7 = fromBigInteger(new BigInteger("92942743748171249034039202643159748376089330632273362315367772348633802592365130463925174120166078027659350437796406524022645144750795", 10));

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
    public void testProcessSMPSucceeded() throws SMPAbortException, ValidationException {
        final byte[] fakeRandomData = new byte[] {-38, -81, -119, -77, 114, 89, 29, -111, -47, -22, -69, 22, 42, 51, 23, 63, -79, -106, 73, -16, 67, 47, 76, -30, 10, 16, -66, 9, -36, -100, -47, -10, -53, -38, -128, 112, 111, -94, 39, -29, 104, -122, -40, -39, 86, -5, 39, -34, -125, 71, 26, 101, -103, 64, 68, -76, 86, -83, 4, -66, 56, -23, -25, -55, -115, 37, 42, -1, 94, -60, -92, 21, -96, -60, 98, 93, 74, -113, 31, 82, 118, -63, 96, -72, 103, -116, 93, 69, -121, 116, -27, -64, -64, -122, -97, -120, 75, -50, -93, -127, -71, 94, 125, 24, -119, 22, 22, 94, 124, -120, -98, 119, -63, 27, -46, -82, 46, -53, 94, -98, 69, -51, 126, 92, 77, -75, -10, -20, 73, -42, -80, 13, -108, -42, 115, -83, 9, -120, 73, -124, -4, -99, 70, -73, -22, -90, 47, -48, -114, 49, 117, -15, -7, -111, -88, 17, -4, -31, -52, -1, 1, -117, 96, 106, 10, 47, 70, -9, -45, -49, 78, -39, 114, 52, 111, -51, 21, 82, 56, 50, 96, 26, 77, -21, 108, -58, -90, -3, -115, -118, -95, 90, 104, 91, 67, -82, -59, 64, -13, -38, 66, 101, -32, -37, 86, -58, 20, -38, 62, 80, 17, 69, -119, 103, -58, -97, -20, 70, 70, -48, -122, 99, 69, 38, -120, 20, 74, -90};
        final Point expectedPa = decodePoint(new byte[] {-36, 110, 74, -99, -81, 65, -45, 93, 86, 31, 51, -12, -13, -104, -7, -88, -15, 118, -21, 87, 26, 45, 26, -18, -108, -108, 44, 123, -50, -45, -63, -46, -96, 126, -22, -44, -67, 40, -83, 61, -71, -120, 104, 84, 100, -78, -57, 115, 116, -65, 6, 54, 24, 46, 83, 72, 0});
        final Point expectedQa = decodePoint(new byte[] {57, -15, -11, -46, -48, 124, -87, -9, 91, 123, 92, -101, -127, 16, 97, -26, 14, 127, -19, -83, -50, 34, 117, 42, 4, -66, 13, -106, 123, 7, -71, 126, 49, -99, 108, -27, -41, 33, 28, 19, -40, 29, -42, -20, -54, 80, -47, 21, 25, -41, 123, -81, -62, 37, 28, -57, -128});
        final Scalar expectedCp = decodeScalar(new byte[] {-52, -50, 43, 69, 45, -85, 73, -29, 94, 113, -29, 7, -10, 99, -7, -44, 74, -8, 103, -112, -127, -53, 115, -115, -37, 47, -67, -71, 68, 33, -112, -53, -30, -56, -110, 124, 71, -112, 79, -59, -26, -25, 73, -121, 99, 75, -18, -26, -125, -53, 52, 89, -36, -38, 107, 10, 0});
        final Scalar expectedD5 = decodeScalar(new byte[] {106, 98, 28, 18, 14, -14, 65, -40, -30, 41, 111, 76, 30, -21, 32, 17, -6, -112, 98, -97, -23, -94, -9, -125, 14, -21, 8, -24, -119, 54, -97, 8, 34, 10, -62, 100, -29, -68, 98, -118, -59, 101, 0, 77, 107, -57, 87, 4, -88, 79, 82, 107, 41, -128, -105, 20, 0});
        final Scalar expectedD6 = decodeScalar(new byte[] {41, 59, 99, -26, 44, -75, -13, -26, 41, -20, -114, 76, 70, -25, -62, -17, -21, -104, -119, -4, 24, -105, -64, 103, -9, 0, -5, 68, 80, 13, -120, -80, 120, 89, -16, -3, 99, 109, -62, 4, -38, 66, 121, -88, 68, -117, -88, -64, 110, 73, -71, -26, 77, 28, 108, 27, 0});
        final Point expectedRa = decodePoint(new byte[] {-48, -126, 123, -84, -82, -18, -30, 69, 102, 121, 21, -5, 108, -93, -48, 106, 100, -59, -113, -83, 33, -106, 11, -89, 18, -20, 76, 50, 51, -117, 9, 44, -17, -100, -104, -67, -12, 73, 74, -47, -5, 31, -58, 44, -48, 125, 72, 68, 13, -17, -88, -27, -12, -104, 69, 38, 0});
        final Scalar expectedCr = decodeScalar(new byte[] {40, 36, 100, 73, 48, -36, 38, 106, -56, -72, 34, -54, -17, -4, -14, -103, 29, 35, 32, 84, -6, 40, 12, -10, -29, 40, -78, -21, 46, -30, -4, -73, 8, -73, 110, -67, 46, -73, -83, -7, -101, -124, -84, 11, -33, -83, 92, -57, 26, 47, -35, -70, 6, -79, -107, 46, 0});
        final Scalar expectedD7 = decodeScalar(new byte[] {-2, 126, 85, -20, 115, 122, 23, 50, 27, 124, 75, -67, 72, 126, 56, -103, 40, 37, -74, -80, 76, -29, 36, 88, 55, -117, 90, -103, 41, -48, 96, -30, 29, -110, 37, -33, 25, 70, -6, 61, 51, -36, -115, 46, -103, 46, -89, 99, -46, 80, -28, -113, -64, 111, -30, 50, 0});
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret, a2, a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(g2b, c2, d2, g3b, c3, d3, pb, qb, cp, d5, d6);
        final SMPMessage3 response = state.process(context, message);
        assertEquals(expectedPa, response.pa);
        assertEquals(expectedQa, response.qa);
        assertEquals(expectedCp, response.cp);
        assertEquals(expectedD5, response.d5);
        assertEquals(expectedD6, response.d6);
        assertEquals(expectedRa, response.ra);
        assertEquals(expectedCr, response.cr);
        assertEquals(expectedD7, response.d7);
        // TODO investigate if following verification statement works. There seem to be some unexpected results.
        verify(context).setState(any(StateExpect1.class));
    }

    @Test
    public void testProcessMessageBadSecret() throws SMPAbortException, ValidationException {
        final byte[] fakeRandomData = new byte[] {-38, -81, -119, -77, 114, 89, 29, -111, -47, -22, -69, 22, 42, 51, 23, 63, -79, -106, 73, -16, 67, 47, 76, -30, 10, 16, -66, 9, -36, -100, -47, -10, -53, -38, -128, 112, 111, -94, 39, -29, 104, -122, -40, -39, 86, -5, 39, -34, -125, 71, 26, 101, -103, 64, 68, -76, 86, -83, 4, -66, 56, -23, -25, -55, -115, 37, 42, -1, 94, -60, -92, 21, -96, -60, 98, 93, 74, -113, 31, 82, 118, -63, 96, -72, 103, -116, 93, 69, -121, 116, -27, -64, -64, -122, -97, -120, 75, -50, -93, -127, -71, 94, 125, 24, -119, 22, 22, 94, 124, -120, -98, 119, -63, 27, -46, -82, 46, -53, 94, -98, 69, -51, 126, 92, 77, -75, -10, -20, 73, -42, -80, 13, -108, -42, 115, -83, 9, -120, 73, -124, -4, -99, 70, -73, -22, -90, 47, -48, -114, 49, 117, -15, -7, -111, -88, 17, -4, -31, -52, -1, 1, -117, 96, 106, 10, 47, 70, -9, -45, -49, 78, -39, 114, 52, 111, -51, 21, 82, 56, 50, 96, 26, 77, -21, 108, -58, -90, -3, -115, -118, -95, 90, 104, 91, 67, -82, -59, 64, -13, -38, 66, 101, -32, -37, 86, -58, 20, -38, 62, 80, 17, 69, -119, 103, -58, -97, -20, 70, 70, -48, -122, 99, 69, 38, -120, 20, 74, -90};
        final Point expectedPa = decodePoint(new byte[] {-36, 110, 74, -99, -81, 65, -45, 93, 86, 31, 51, -12, -13, -104, -7, -88, -15, 118, -21, 87, 26, 45, 26, -18, -108, -108, 44, 123, -50, -45, -63, -46, -96, 126, -22, -44, -67, 40, -83, 61, -71, -120, 104, 84, 100, -78, -57, 115, 116, -65, 6, 54, 24, 46, 83, 72, 0});
        final Point expectedQa = decodePoint(new byte[] {57, -15, -11, -46, -48, 124, -87, -9, 91, 123, 92, -101, -127, 16, 97, -26, 14, 127, -19, -83, -50, 34, 117, 42, 4, -66, 13, -106, 123, 7, -71, 126, 49, -99, 108, -27, -41, 33, 28, 19, -40, 29, -42, -20, -54, 80, -47, 21, 25, -41, 123, -81, -62, 37, 28, -57, -128});
        final Scalar expectedCp = decodeScalar(new byte[] {-52, -50, 43, 69, 45, -85, 73, -29, 94, 113, -29, 7, -10, 99, -7, -44, 74, -8, 103, -112, -127, -53, 115, -115, -37, 47, -67, -71, 68, 33, -112, -53, -30, -56, -110, 124, 71, -112, 79, -59, -26, -25, 73, -121, 99, 75, -18, -26, -125, -53, 52, 89, -36, -38, 107, 10, 0});
        final Scalar expectedD5 = decodeScalar(new byte[] {106, 98, 28, 18, 14, -14, 65, -40, -30, 41, 111, 76, 30, -21, 32, 17, -6, -112, 98, -97, -23, -94, -9, -125, 14, -21, 8, -24, -119, 54, -97, 8, 34, 10, -62, 100, -29, -68, 98, -118, -59, 101, 0, 77, 107, -57, 87, 4, -88, 79, 82, 107, 41, -128, -105, 20, 0});
        final Scalar expectedD6 = decodeScalar(new byte[] {41, 59, 99, -26, 44, -75, -13, -26, 41, -20, -114, 76, 70, -25, -62, -17, -21, -104, -119, -4, 24, -105, -64, 103, -9, 0, -5, 68, 80, 13, -120, -80, 120, 89, -16, -3, 99, 109, -62, 4, -38, 66, 121, -88, 68, -117, -88, -64, 110, 73, -71, -26, 77, 28, 108, 27, 0});
        final Point expectedRa = decodePoint(new byte[] {-48, -126, 123, -84, -82, -18, -30, 69, 102, 121, 21, -5, 108, -93, -48, 106, 100, -59, -113, -83, 33, -106, 11, -89, 18, -20, 76, 50, 51, -117, 9, 44, -17, -100, -104, -67, -12, 73, 74, -47, -5, 31, -58, 44, -48, 125, 72, 68, 13, -17, -88, -27, -12, -104, 69, 38, 0});
        final Scalar expectedCr = decodeScalar(new byte[] {40, 36, 100, 73, 48, -36, 38, 106, -56, -72, 34, -54, -17, -4, -14, -103, 29, 35, 32, 84, -6, 40, 12, -10, -29, 40, -78, -21, 46, -30, -4, -73, 8, -73, 110, -67, 46, -73, -83, -7, -101, -124, -84, 11, -33, -83, 92, -57, 26, 47, -35, -70, 6, -79, -107, 46, 0});
        final Scalar expectedD7 = decodeScalar(new byte[] {-2, 126, 85, -20, 115, 122, 23, 50, 27, 124, 75, -67, 72, 126, 56, -103, 40, 37, -74, -80, 76, -29, 36, 88, 55, -117, 90, -103, 41, -48, 96, -30, 29, -110, 37, -33, 25, 70, -6, 61, 51, -36, -115, 46, -103, 46, -89, 99, -46, 80, -28, -113, -64, 111, -30, 50, 0});
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret.negate(), a2, a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(g2b, c2, d2, g3b, c3, d3, pb, qb, cp, d5, d6);
        final SMPMessage3 response = state.process(context, message);
        assertEquals(expectedPa, response.pa);
        assertNotEquals(expectedQa, response.qa);
        assertEquals(expectedCp, response.cp);
        assertEquals(expectedD5, response.d5);
        assertNotEquals(expectedD6, response.d6);
        assertNotEquals(expectedRa, response.ra);
        assertNotEquals(expectedCr, response.cr);
        assertNotEquals(expectedD7, response.d7);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBada2() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[4 * 57];
        r4.encodeTo(fakeRandomData, 0);
        r5.encodeTo(fakeRandomData, 57);
        r6.encodeTo(fakeRandomData, 114);
        r7.encodeTo(fakeRandomData, 171);
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret, Scalars.one(), a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(g2b, c2, d2, g3b, c3, d3, pb, qb, cp, d5, d6);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBada3() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[4 * 57];
        r4.encodeTo(fakeRandomData, 0);
        r5.encodeTo(fakeRandomData, 57);
        r6.encodeTo(fakeRandomData, 114);
        r7.encodeTo(fakeRandomData, 171);
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret, a2, Scalars.one());
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(g2b, c2, d2, g3b, c3, d3, pb, qb, cp, d5, d6);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageIllegalg2b() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[4 * 57];
        r4.encodeTo(fakeRandomData, 0);
        r5.encodeTo(fakeRandomData, 57);
        r6.encodeTo(fakeRandomData, 114);
        r7.encodeTo(fakeRandomData, 171);
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret, a2, a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(createPoint(BigInteger.ONE, BigInteger.ONE), c2, d2, g3b, c3, d3, pb, qb, cp, d5, d6);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadg2b() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[4 * 57];
        r4.encodeTo(fakeRandomData, 0);
        r5.encodeTo(fakeRandomData, 57);
        r6.encodeTo(fakeRandomData, 114);
        r7.encodeTo(fakeRandomData, 171);
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret, a2, a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(g2b.negate(), c2, d2, g3b, c3, d3, pb, qb, cp, d5, d6);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageIllegalg3b() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[4 * 57];
        r4.encodeTo(fakeRandomData, 0);
        r5.encodeTo(fakeRandomData, 57);
        r6.encodeTo(fakeRandomData, 114);
        r7.encodeTo(fakeRandomData, 171);
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret, a2, a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(g2b, c2, d2, createPoint(BigInteger.ONE, BigInteger.ONE), c3, d3, pb, qb, cp, d5, d6);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadg3b() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[4 * 57];
        r4.encodeTo(fakeRandomData, 0);
        r5.encodeTo(fakeRandomData, 57);
        r6.encodeTo(fakeRandomData, 114);
        r7.encodeTo(fakeRandomData, 171);
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret, a2, a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(g2b, c2, d2, g3b.negate(), c3, d3, pb, qb, cp, d5, d6);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageIllegalpb() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[4 * 57];
        r4.encodeTo(fakeRandomData, 0);
        r5.encodeTo(fakeRandomData, 57);
        r6.encodeTo(fakeRandomData, 114);
        r7.encodeTo(fakeRandomData, 171);
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret, a2, a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(g2b, c2, d2, g3b, c3, d3, createPoint(BigInteger.ONE, BigInteger.ONE), qb, cp, d5, d6);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadpb() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[4 * 57];
        r4.encodeTo(fakeRandomData, 0);
        r5.encodeTo(fakeRandomData, 57);
        r6.encodeTo(fakeRandomData, 114);
        r7.encodeTo(fakeRandomData, 171);
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret, a2, a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(g2b, c2, d2, g3b, c3, d3, pb.negate(), qb, cp, d5, d6);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageIllegalqb() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[4 * 57];
        r4.encodeTo(fakeRandomData, 0);
        r5.encodeTo(fakeRandomData, 57);
        r6.encodeTo(fakeRandomData, 114);
        r7.encodeTo(fakeRandomData, 171);
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret, a2, a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(g2b, c2, d2, g3b, c3, d3, pb, createPoint(BigInteger.ONE, BigInteger.ONE), cp, d5, d6);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadqb() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[4 * 57];
        r4.encodeTo(fakeRandomData, 0);
        r5.encodeTo(fakeRandomData, 57);
        r6.encodeTo(fakeRandomData, 114);
        r7.encodeTo(fakeRandomData, 171);
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret, a2, a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(g2b, c2, d2, g3b, c3, d3, pb, qb.negate(), cp, d5, d6);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadc2() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[4 * 57];
        r4.encodeTo(fakeRandomData, 0);
        r5.encodeTo(fakeRandomData, 57);
        r6.encodeTo(fakeRandomData, 114);
        r7.encodeTo(fakeRandomData, 171);
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret, a2, a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(g2b, Scalars.one(), d2, g3b, c3, d3, pb, qb, cp, d5, d6);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadd2() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[4 * 57];
        r4.encodeTo(fakeRandomData, 0);
        r5.encodeTo(fakeRandomData, 57);
        r6.encodeTo(fakeRandomData, 114);
        r7.encodeTo(fakeRandomData, 171);
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret, a2, a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(g2b, c2, Scalars.one(), g3b, c3, d3, pb, qb, cp, d5, d6);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadc3() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[4 * 57];
        r4.encodeTo(fakeRandomData, 0);
        r5.encodeTo(fakeRandomData, 57);
        r6.encodeTo(fakeRandomData, 114);
        r7.encodeTo(fakeRandomData, 171);
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret, a2, a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(g2b, c2, d2, g3b, Scalars.one(), d3, pb, qb, cp, d5, d6);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadd3() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[4 * 57];
        r4.encodeTo(fakeRandomData, 0);
        r5.encodeTo(fakeRandomData, 57);
        r6.encodeTo(fakeRandomData, 114);
        r7.encodeTo(fakeRandomData, 171);
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret, a2, a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(g2b, c2, d2, g3b, c3, Scalars.one(), pb, qb, cp, d5, d6);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadcp() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[4 * 57];
        r4.encodeTo(fakeRandomData, 0);
        r5.encodeTo(fakeRandomData, 57);
        r6.encodeTo(fakeRandomData, 114);
        r7.encodeTo(fakeRandomData, 171);
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret, a2, a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(g2b, c2, d2, g3b, c3, d3, pb, qb, Scalars.one(), d5, d6);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadd5() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[4 * 57];
        r4.encodeTo(fakeRandomData, 0);
        r5.encodeTo(fakeRandomData, 57);
        r6.encodeTo(fakeRandomData, 114);
        r7.encodeTo(fakeRandomData, 171);
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret, a2, a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(g2b, c2, d2, g3b, c3, d3, pb, qb, cp, Scalars.one(), d6);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadd6() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[4 * 57];
        r4.encodeTo(fakeRandomData, 0);
        r5.encodeTo(fakeRandomData, 57);
        r6.encodeTo(fakeRandomData, 114);
        r7.encodeTo(fakeRandomData, 171);
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret, a2, a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(g2b, c2, d2, g3b, c3, d3, pb, qb, cp, d5, Scalars.one());
        state.process(context, message);
    }
}