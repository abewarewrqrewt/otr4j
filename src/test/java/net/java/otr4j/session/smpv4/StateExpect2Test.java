package net.java.otr4j.session.smpv4;

import nl.dannyvanheumen.joldilocks.Point;
import org.bouncycastle.crypto.prng.FixedSecureRandom;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import static java.math.BigInteger.valueOf;
import static net.java.otr4j.session.api.SMPStatus.INPROGRESS;
import static nl.dannyvanheumen.joldilocks.Points.createPoint;
import static nl.dannyvanheumen.joldilocks.Scalars.encodeLittleEndianTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@SuppressWarnings("ConstantConditions")
public final class StateExpect2Test {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final BigInteger secret = new BigInteger("156646870446509697993543906405546302203937595276099597245169544217380323950616830748419230701118835593301852473925689151030104403160214", 10);
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
    private static final BigInteger r4 = new BigInteger("4848823671279697407137727930542462362850237819434391365386462331719995539129866443292840169805814262621847420649345769965317287348", 10);
    private static final BigInteger r5 = new BigInteger("6093723104156361563235633010766054571606619914455883426503126819249759028984281412972947332166622716165667676992220970018247617818", 10);
    private static final BigInteger r6 = new BigInteger("4898355827584876372361803991328154525279690424308456604711524616971929965834305690790568318779002259332597465317036597829614224197", 10);
    private static final BigInteger r7 = new BigInteger("10327876212163104498832270384706478291329857475634355830265712208763978612460575175501454261843646764359066094297572626480874373321", 10);
    private static final BigInteger a2 = new BigInteger("673848653576269490820269595107132458021950184923936107336090953739462122027562298199756197615735822162566149329088995049443871609", 10);
    private static final BigInteger a3 = new BigInteger("10992407629513027537721921961288862111472222592979105676178912973948354718168450900717698573770450980134969731918121327601220662649", 10);
    private static final BigInteger b3 = new BigInteger("6620572565451325478577935676729801683996665547132615779785633946993382844827938072605777950304437030465346847174123905281902647976", 10);
    private static final BigInteger c2 = new BigInteger("111022924696436872341199729470810106169691412099562751065315157956932607321704386418842646614967543212975232690938096962929374138840360", 10);
    private static final BigInteger d2 = new BigInteger("101345345229065684334282374371023601758415295857263117254747849658520035320960346748846057135976056655742957171515534523417214373693098", 10);
    private static final BigInteger c3 = new BigInteger("62617459100015197706706660769267850673374894996485466090690871115733599023295580435733677134748019493119048062634692839095351921724769", 10);
    private static final BigInteger d3 = new BigInteger("137562898370533368188949012935464486921412442457491703380251471222259286769274568095679144010941490174773593749015593431117048642147968", 10);
    private static final BigInteger cp = new BigInteger("28045188189773086196199811649212088777481441211542237396012741618349225156254977936298093632091077961453305961030130988861845216328283", 10);
    private static final BigInteger responseCp = new BigInteger("77816735911757946719447405301929329577374213233553378783621970734989972850028859935350835911100334011448998047272156287285184162475910", 10);
    private static final BigInteger d5 = new BigInteger("149784617958500236288042084698627372846752050231135475713620548703969334046909579101335416023239157022443926007634155769652596827828560", 10);
    private static final BigInteger responseD5 = new BigInteger("168402301387910408888564889044656243554121209615331400658802104743919568546071693427503525480092417336791762973045156197916739168241313", 10);
    private static final BigInteger d6 = new BigInteger("94724577901200260682137525745100301807843255453810112147553827587265819853644379707894360868997126906680725252985586449377226774745039", 10);
    private static final BigInteger responseD6 = new BigInteger("164091252447905741784359447423080363209407831152698892830742713829575334091018414587457181999291987776278550423061209800388520373919397", 10);
    private static final BigInteger cr = new BigInteger("48212869955179756863375262751674186371416622227372458498814862703043948906876869678112891347756106998961858786630233240056114069543171", 10);
    private static final BigInteger responseCr = new BigInteger("56552690208569846484767066019279120176962659824535518690139189690745687293876835490924077826911617221281921640170307321984832871226348", 10);
    private static final BigInteger d7 = new BigInteger("92942743748171249034039202643159748376089330632273362315367772348633802592365130463925174120166078027659350437796406524022645144750795", 10);
    private static final BigInteger responseD7 = new BigInteger("145952570674148673490476737637065914811240433627086277391960523808477106159276648430230314099961485884566992342590501652557852798653734", 10);

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
        state.initiate(null, "test", valueOf(1L));
    }

    @Test(expected = SMPAbortException.class)
    public void testInitiateAbortStateExpect1() throws SMPAbortException {
        final StateExpect2 state = new StateExpect2(RANDOM, secret, a2, a3);
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
        final byte[] fakeRandomData = new byte[4*54];
        encodeLittleEndianTo(fakeRandomData, 0, r4);
        encodeLittleEndianTo(fakeRandomData, 54, r5);
        encodeLittleEndianTo(fakeRandomData, 108, r6);
        encodeLittleEndianTo(fakeRandomData, 162, r7);
        final StateExpect2 state = new StateExpect2(new FixedSecureRandom(fakeRandomData), secret, a2, a3);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage2 message = new SMPMessage2(g2b, c2, d2, g3b, c3, d3, pb, qb, cp, d5, d6);
        final SMPMessage3 response = state.process(context, message);
        assertEquals(pa, response.pa);
        assertEquals(qa, response.qa);
        assertEquals(responseCp, response.cp);
        assertEquals(responseD5, response.d5);
        assertEquals(responseD6, response.d6);
        assertEquals(ra, response.ra);
        assertEquals(cr, response.cr);
        assertEquals(d7, response.d7);
        // TODO investigate if following verification statement works. There seem to be some unexpected results.
        verify(context).setState(any(StateExpect1.class));
    }

    // TODO continue with exception cases.
}