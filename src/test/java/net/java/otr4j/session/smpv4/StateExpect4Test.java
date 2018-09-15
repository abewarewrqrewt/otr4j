package net.java.otr4j.session.smpv4;

import nl.dannyvanheumen.joldilocks.Point;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import static java.math.BigInteger.ONE;
import static java.math.BigInteger.valueOf;
import static net.java.otr4j.session.api.SMPStatus.INPROGRESS;
import static nl.dannyvanheumen.joldilocks.Points.createPoint;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@SuppressWarnings("ConstantConditions")
public final class StateExpect4Test {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final BigInteger a3 = new BigInteger("10992407629513027537721921961288862111472222592979105676178912973948354718168450900717698573770450980134969731918121327601220662649", 10);
    private static final Point g3b = createPoint(
            new BigInteger("25460154400798033061057906375464023188226226982418482149467593583623510947345044595566809932111935577651183265131423524693421017471242", 10),
            new BigInteger("553052674467468451498390089236097910339465676043764019155003492986686446924070189167293939278539676908850471424077516167161370570930870", 10));
    private static final Point pa = createPoint(
            new BigInteger("465943338087689210004311262653217262867584260336764995023461214036125904185851440432009245692764184419275942574209323203357723240467548", 10),
            new BigInteger("171512624718754523296213069499915004048105351732065305821916994076620475525139204045825568923885234090579511388053138214933231286738769", 10));
    private static final Point pb = createPoint(
            new BigInteger("150971551590059119684514014051782205053977785666422029127804430526951029198846199892957327905468410035748726553951282154034774550008486", 10),
            new BigInteger("22380432526449194175787570945218836926017979984737449943120906860192566288203629458502199108124043807619691145917657476124547825617627", 10));
    private static final Point qa = createPoint(
            new BigInteger("166233517570629524836327531569104738143692654989309180176792709961188220191331070218340399706383261483114723213643495221558313447723211", 10),
            new BigInteger("518917581830034185786914774664355117879178739934839678626989026565322227675465996556006358187381023415692754242138646331342140362437821", 10));
    private static final Point qb = createPoint(
            new BigInteger("423430412264875129675225626571000691034761078275754236126134904918998073249689389127999342833148835049651469030268345753112431699348696", 10),
            new BigInteger("27371249592200388578572706841215291643260958466414201154940100359190642782246779086087976919600673242377448605891352376861486556308423", 10));
    private static final Point rb = createPoint(
            new BigInteger("207262232174680451060776976413201759833926533152870268659156413710415430620278577554952401659472618835066253611213476907998866291547848", 10),
            new BigInteger("243919295076423503288241325716951068924347181567637759634078287663516781375902876181296806140094995694034332370011945034139749942390997", 10));
    private static final BigInteger cr = new BigInteger("56552690208569846484767066019279120176962659824535518690139189690745687293876835490924077826911617221281921640170307321984832871226348", 10);
    private static final BigInteger d7 = new BigInteger("145952570674148673490476737637065914811240433627086277391960523808477106159276648430230314099961485884566992342590501652557852798653734", 10);
    private static final Point ra = createPoint(
            new BigInteger("314477180835505334456514522697211639823564271172558398781788373480025093584267496798280363802109367409945899677297245744207604995798215", 10),
            new BigInteger("314029684065464803946366772814894787049170212355244776063157390940002824357662292553115470960421307470791608461875703125153400706900709", 10));
    private static final BigInteger cp = new BigInteger("77816735911757946719447405301929329577374213233553378783621970734989972850028859935350835911100334011448998047272156287285184162475910", 10);
    private static final BigInteger d5 = new BigInteger("168402301387910408888564889044656243554121209615331400658802104743919568546071693427503525480092417336791762973045156197916739168241313", 10);
    private static final BigInteger d6 = new BigInteger("164091252447905741784359447423080363209407831152698892830742713829575334091018414587457181999291987776278550423061209800388520373919397", 10);

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
        state.initiate(null, "test", valueOf(1L));
    }

    @Test(expected = SMPAbortException.class)
    public void testInitiateAbortStateExpect1() throws SMPAbortException {
        final StateExpect4 state = new StateExpect4(RANDOM, a3, g3b, pa, pb, qa, qb);
        final SMPContext context = mock(SMPContext.class);
        try {
            state.initiate(context, "test", valueOf(1L));
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
        final SMPMessage4 message = new SMPMessage4(rb, ONE, d7);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessBadMessageIllegald7() throws SMPAbortException {
        final StateExpect4 state = new StateExpect4(RANDOM, a3, g3b, pa, pb, qa, qb);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage4 message = new SMPMessage4(rb, cr, ONE);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessBadMessageIllegalrb() throws SMPAbortException {
        final StateExpect4 state = new StateExpect4(RANDOM, a3, g3b, pa, pb, qa, qb);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage4 message = new SMPMessage4(createPoint(ONE, ONE), cr, ONE);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessBadMessageBada3() throws SMPAbortException {
        final StateExpect4 state = new StateExpect4(RANDOM, ONE, g3b, pa, pb, qa, qb);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage4 message = new SMPMessage4(rb, cr, ONE);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessBadMessageBadg3b() throws SMPAbortException {
        final StateExpect4 state = new StateExpect4(RANDOM, a3, g3b.negate(), pa, pb, qa, qb);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage4 message = new SMPMessage4(rb, cr, ONE);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessBadMessageBadpa() throws SMPAbortException {
        final StateExpect4 state = new StateExpect4(RANDOM, a3, g3b, pa.negate(), pb, qa, qb);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage4 message = new SMPMessage4(rb, cr, ONE);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessBadMessageBadqa() throws SMPAbortException {
        final StateExpect4 state = new StateExpect4(RANDOM, a3, g3b, pa, pb, qa.negate(), qb);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage4 message = new SMPMessage4(rb, cr, ONE);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessBadMessageBadqb() throws SMPAbortException {
        final StateExpect4 state = new StateExpect4(RANDOM, a3, g3b, pa, pb, qa, qb.negate());
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage4 message = new SMPMessage4(rb, cr, ONE);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessWrongMessage() throws SMPAbortException {
        final StateExpect4 state = new StateExpect4(RANDOM, a3, g3b, pa, pb, qa, qb.negate());
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage3 message = new SMPMessage3(pa, qa, cp, d5, d6, ra, cr, d7);
        state.process(context, message);
    }
}