package net.java.otr4j.session.smpv4;

import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.crypto.ed448.Scalar;
import org.bouncycastle.crypto.prng.FixedSecureRandom;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import static java.math.BigInteger.valueOf;
import static net.java.otr4j.crypto.ed448.Point.createPoint;
import static net.java.otr4j.crypto.ed448.Scalar.ONE;
import static net.java.otr4j.crypto.ed448.Scalar.fromBigInteger;
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
    private static final Point pb = createPoint(
            new BigInteger("150971551590059119684514014051782205053977785666422029127804430526951029198846199892957327905468410035748726553951282154034774550008486", 10),
            new BigInteger("22380432526449194175787570945218836926017979984737449943120906860192566288203629458502199108124043807619691145917657476124547825617627", 10));
    private static final Point qb = createPoint(
            new BigInteger("423430412264875129675225626571000691034761078275754236126134904918998073249689389127999342833148835049651469030268345753112431699348696", 10),
            new BigInteger("27371249592200388578572706841215291643260958466414201154940100359190642782246779086087976919600673242377448605891352376861486556308423", 10));
    private static final Point g3a = createPoint(
            new BigInteger("518174644249461528695945953725187603845615868738496167939067703005335185228858161198005082414857631829817255298083903928767327400128404", 10),
            new BigInteger("411593944040901258928967352546948763853118126911749716436241852339527571133863427871032238507886034736469451532393155247111763030574468", 10));
    private static final Point g2 = createPoint(
            new BigInteger("461040231870912278223335051003007589124444431620652617813251747737875255390128010129415238249086909415909114003045585587473495359933842", 10),
            new BigInteger("378179442616209022897918842999078744137085816218860340532337222199856750749813374446200431224005985387770293772337897615452902812899754", 10));
    private static final Point g3 = createPoint(
            new BigInteger("64712806652336856881234519237674951336100608683154962969591387101780248238545172716068676332096324991830846385623416736375164371616205", 10),
            new BigInteger("210386130815266405388184355964395704043399087077006199960064048841865230842670391032599659513617832767135871367377513619788370536757084", 10));
    private static final Point pa = createPoint(
            new BigInteger("465943338087689210004311262653217262867584260336764995023461214036125904185851440432009245692764184419275942574209323203357723240467548", 10),
            new BigInteger("171512624718754523296213069499915004048105351732065305821916994076620475525139204045825568923885234090579511388053138214933231286738769", 10));
    private static final Point qa = createPoint(
            new BigInteger("166233517570629524836327531569104738143692654989309180176792709961188220191331070218340399706383261483114723213643495221558313447723211", 10),
            new BigInteger("518917581830034185786914774664355117879178739934839678626989026565322227675465996556006358187381023415692754242138646331342140362437821", 10));
    private static final Point ra = createPoint(
            new BigInteger("314477180835505334456514522697211639823564271172558398781788373480025093584267496798280363802109367409945899677297245744207604995798215", 10),
            new BigInteger("314029684065464803946366772814894787049170212355244776063157390940002824357662292553115470960421307470791608461875703125153400706900709", 10));
    private static final Point rb = createPoint(
            new BigInteger("207262232174680451060776976413201759833926533152870268659156413710415430620278577554952401659472618835066253611213476907998866291547848", 10),
            new BigInteger("243919295076423503288241325716951068924347181567637759634078287663516781375902876181296806140094995694034332370011945034139749942390997", 10));
    private static final Scalar b3 = fromBigInteger(new BigInteger("6620572565451325478577935676729801683996665547132615779785633946993382844827938072605777950304437030465346847174123905281902647976", 10));
    private static final Scalar cp = fromBigInteger(new BigInteger("77816735911757946719447405301929329577374213233553378783621970734989972850028859935350835911100334011448998047272156287285184162475910", 10));
    private static final Scalar d5 = fromBigInteger(new BigInteger("168402301387910408888564889044656243554121209615331400658802104743919568546071693427503525480092417336791762973045156197916739168241313", 10));
    private static final Scalar d6 = fromBigInteger(new BigInteger("164091252447905741784359447423080363209407831152698892830742713829575334091018414587457181999291987776278550423061209800388520373919397", 10));
    private static final Scalar cr = fromBigInteger(new BigInteger("48212869955179756863375262751674186371416622227372458498814862703043948906876869678112891347756106998961858786630233240056114069543171", 10));
    private static final Scalar responseCr = fromBigInteger(new BigInteger("56552690208569846484767066019279120176962659824535518690139189690745687293876835490924077826911617221281921640170307321984832871226348", 10));
    private static final Scalar d7 = fromBigInteger(new BigInteger("92942743748171249034039202643159748376089330632273362315367772348633802592365130463925174120166078027659350437796406524022645144750795", 10));
    private static final Scalar responseD7 = fromBigInteger(new BigInteger("145952570674148673490476737637065914811240433627086277391960523808477106159276648430230314099961485884566992342590501652557852798653734", 10));
    private static final Scalar r7 = fromBigInteger(new BigInteger("7600950275105416617264243473722295903011889056977042647701408849843465351892940325962184631905666782846636443769119291050099400852", 10));

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
        // FIXME investigate why this isn't 56 bytes per scalar! (I believe this is a mistake)
        final byte[] fakeRandomData = new byte[54];
        r7.encodeTo(fakeRandomData, 0);
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb, qb, b3, g3a, g2, g3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(pa, qa, cp, d5, d6, ra, cr, d7);
        final SMPMessage4 response = state.process(context, message);
        assertEquals(rb, response.rb);
        assertEquals(responseCr, response.cr);
        assertEquals(responseD7, response.d7);
        verify(context).setState(any(StateExpect4.class));
    }

    @Test
    public void testProcessMessageSMPFailed() throws SMPAbortException {
        // FIXME investigate why this isn't 56 bytes per scalar! (I believe this is a mistake)
        final byte[] fakeRandomData = new byte[54];
        r7.encodeTo(fakeRandomData, 0);
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb.negate(), qb, b3, g3a, g2, g3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(pa, qa, cp, d5, d6, ra, cr, d7);
        final SMPMessage4 response = state.process(context, message);
        assertEquals(rb, response.rb);
        assertEquals(responseCr, response.cr);
        assertEquals(responseD7, response.d7);
        // TODO investigate if following verification statement works. There seem to be some unexpected results.
        verify(context).setState(any(StateExpect1.class));
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadqb() throws SMPAbortException {
        // FIXME investigate why this isn't 56 bytes per scalar! (I believe this is a mistake)
        final byte[] fakeRandomData = new byte[54];
        r7.encodeTo(fakeRandomData, 0);
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb, qb.negate(), b3, g3a, g2, g3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(pa, qa, cp, d5, d6, ra, cr, d7);
        state.process(context, message);
    }

    @Test
    public void testProcessMessageBadb3() throws SMPAbortException {
        // FIXME investigate why this isn't 56 bytes per scalar! (I believe this is a mistake)
        final byte[] fakeRandomData = new byte[54];
        r7.encodeTo(fakeRandomData, 0);
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb, qb, ONE, g3a, g2, g3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(pa, qa, cp, d5, d6, ra, cr, d7);
        final SMPMessage4 response = state.process(context, message);
        assertNotEquals(rb, response.rb);
        assertEquals(responseCr, response.cr);
        assertNotEquals(responseD7, response.d7);
        // TODO investigate if following verification statement works. There seem to be some unexpected results.
        verify(context).setState(any(StateExpect1.class));
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadg3a() throws SMPAbortException {
        // FIXME investigate why this isn't 56 bytes per scalar! (I believe this is a mistake)
        final byte[] fakeRandomData = new byte[54];
        r7.encodeTo(fakeRandomData, 0);
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb, qb, b3, g3a.negate(), g2, g3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(pa, qa, cp, d5, d6, ra, cr, d7);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadg2() throws SMPAbortException {
        // FIXME investigate why this isn't 56 bytes per scalar! (I believe this is a mistake)
        final byte[] fakeRandomData = new byte[54];
        r7.encodeTo(fakeRandomData, 0);
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb, qb, b3, g3a, g2.negate(), g3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(pa, qa, cp, d5, d6, ra, cr, d7);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadg3() throws SMPAbortException {
        // FIXME investigate why this isn't 56 bytes per scalar! (I believe this is a mistake)
        final byte[] fakeRandomData = new byte[54];
        r7.encodeTo(fakeRandomData, 0);
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb, qb, b3, g3a, g2, g3.negate());
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(pa, qa, cp, d5, d6, ra, cr, d7);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadpa() throws SMPAbortException {
        // FIXME investigate why this isn't 56 bytes per scalar! (I believe this is a mistake)
        final byte[] fakeRandomData = new byte[54];
        r7.encodeTo(fakeRandomData, 0);
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb, qb, b3, g3a, g2, g3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(pa.negate(), qa, cp, d5, d6, ra, cr, d7);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadqa() throws SMPAbortException {
        // FIXME investigate why this isn't 56 bytes per scalar! (I believe this is a mistake)
        final byte[] fakeRandomData = new byte[54];
        r7.encodeTo(fakeRandomData, 0);
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb, qb, b3, g3a, g2, g3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(pa, qa.negate(), cp, d5, d6, ra, cr, d7);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadcp() throws SMPAbortException {
        // FIXME investigate why this isn't 56 bytes per scalar! (I believe this is a mistake)
        final byte[] fakeRandomData = new byte[54];
        r7.encodeTo(fakeRandomData, 0);
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb, qb, b3, g3a, g2, g3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(pa, qa, ONE, d5, d6, ra, cr, d7);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadd5() throws SMPAbortException {
        // FIXME investigate why this isn't 56 bytes per scalar! (I believe this is a mistake)
        final byte[] fakeRandomData = new byte[54];
        r7.encodeTo(fakeRandomData, 0);
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb, qb, b3, g3a, g2, g3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(pa, qa, cp, ONE, d6, ra, cr, d7);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadd6() throws SMPAbortException {
        // FIXME investigate why this isn't 56 bytes per scalar! (I believe this is a mistake)
        final byte[] fakeRandomData = new byte[54];
        r7.encodeTo(fakeRandomData, 0);
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb, qb, b3, g3a, g2, g3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(pa, qa, cp, d5, ONE, ra, cr, d7);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadra() throws SMPAbortException {
        // FIXME investigate why this isn't 56 bytes per scalar! (I believe this is a mistake)
        final byte[] fakeRandomData = new byte[54];
        r7.encodeTo(fakeRandomData, 0);
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb, qb, b3, g3a, g2, g3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(pa, qa, cp, d5, d6, ra.negate(), cr, d7);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadcr() throws SMPAbortException {
        // FIXME investigate why this isn't 56 bytes per scalar! (I believe this is a mistake)
        final byte[] fakeRandomData = new byte[54];
        r7.encodeTo(fakeRandomData, 0);
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb, qb, b3, g3a, g2, g3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(pa, qa, cp, d5, d6, ra, ONE, d7);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadd7() throws SMPAbortException {
        // FIXME investigate why this isn't 56 bytes per scalar! (I believe this is a mistake)
        final byte[] fakeRandomData = new byte[54];
        r7.encodeTo(fakeRandomData, 0);
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb, qb, b3, g3a, g2, g3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(pa, qa, cp, d5, d6, ra, cr, ONE);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageIllegalpa() throws SMPAbortException {
        // FIXME investigate why this isn't 56 bytes per scalar! (I believe this is a mistake)
        final byte[] fakeRandomData = new byte[54];
        r7.encodeTo(fakeRandomData, 0);
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb, qb, b3, g3a, g2, g3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(createPoint(BigInteger.ONE, BigInteger.ONE), qa, cp, d5, d6, ra, cr, ONE);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageIllegalqa() throws SMPAbortException {
        // FIXME investigate why this isn't 56 bytes per scalar! (I believe this is a mistake)
        final byte[] fakeRandomData = new byte[54];
        r7.encodeTo(fakeRandomData, 0);
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb, qb, b3, g3a, g2, g3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(pa, createPoint(BigInteger.ONE, BigInteger.ONE), cp, d5, d6, ra, cr, ONE);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageIllegalra() throws SMPAbortException {
        // FIXME investigate why this isn't 56 bytes per scalar! (I believe this is a mistake)
        final byte[] fakeRandomData = new byte[54];
        r7.encodeTo(fakeRandomData, 0);
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb, qb, b3, g3a, g2, g3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(pa, qa, cp, d5, d6, createPoint(BigInteger.ONE, BigInteger.ONE), cr, ONE);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessMessageBadMessage() throws SMPAbortException {
        // FIXME investigate why this isn't 56 bytes per scalar! (I believe this is a mistake)
        final byte[] fakeRandomData = new byte[54];
        r7.encodeTo(fakeRandomData, 0);
        final StateExpect3 state = new StateExpect3(new FixedSecureRandom(fakeRandomData), pb, qb, b3, g3a, g2, g3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage4 message = new SMPMessage4(rb, cr, d7);
        state.process(context, message);
    }
}