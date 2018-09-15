package net.java.otr4j.session.smpv4;

import nl.dannyvanheumen.joldilocks.Point;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.junit.Test;

import javax.annotation.Nonnull;
import java.math.BigInteger;
import java.security.SecureRandom;

import static java.math.BigInteger.ONE;
import static java.util.Objects.requireNonNull;
import static net.java.otr4j.session.api.SMPStatus.UNDECIDED;
import static nl.dannyvanheumen.joldilocks.Points.createPoint;
import static nl.dannyvanheumen.joldilocks.Scalars.encodeLittleEndianTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.mock;

@SuppressWarnings("ConstantConditions")
public final class StateExpect1Test {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final BigInteger secret = new BigInteger("156646870446509697993543906405546302203937595276099597245169544217380323950616830748419230701118835593301852473925689151030104403160214", 10);
    private static final Point g2a = createPoint(
            new BigInteger("556126760061111951763657713165359364949137409429907558250190706803191942221006997715534159064635956115146859509850685483783825658051062", 10),
            new BigInteger("402300785987933532722239956410658839879984334939846965731832817389739507515141868374683434686898800718793116044193956150363860355205672", 10));
    private static final Point g3a = createPoint(
            new BigInteger("518174644249461528695945953725187603845615868738496167939067703005335185228858161198005082414857631829817255298083903928767327400128404", 10),
            new BigInteger("411593944040901258928967352546948763853118126911749716436241852339527571133863427871032238507886034736469451532393155247111763030574468", 10));
    private static final BigInteger r2_a = new BigInteger("5825641231146188239205319860011438373615054019046086214582588373646960014991824724274851505231897375859907031974285152936173935712", 10);
    private static final BigInteger r3_a = new BigInteger("4186508033601174568794549048106489527716204617773319472160761153597914032032303947719871227301780125998936489846843471162675733215", 10);
    private static final BigInteger a2 = new BigInteger("673848653576269490820269595107132458021950184923936107336090953739462122027562298199756197615735822162566149329088995049443871609", 10);
    private static final BigInteger a3 = new BigInteger("10992407629513027537721921961288862111472222592979105676178912973948354718168450900717698573770450980134969731918121327601220662649", 10);
    private static final BigInteger c2_a = new BigInteger("56215524322547104127699096785674005241383967134488713674233477434334447753644548760497263024362137158154026484631381429216317310018096", 10);
    private static final BigInteger d2_a = new BigInteger("49816908830739953057536629170097286773000082402282036191373078454544319859212531223793126796299628553378507448554557863323847000516506", 10);
    private static final BigInteger c3_a = new BigInteger("133604216714654954479797674994885870941073982273867141172149471004408885607045458728198265688676286621800854863935821594357563292700948", 10);
    private static final BigInteger d3_a = new BigInteger("175749258705876639276476226769967272420621636867036494467329856230066809134918277210694227277683436810214089278213679819342030799621732", 10);

    private static final Point g2b = createPoint(
            new BigInteger("535510067367745935609486739796535297303106274342962289544648627870003598673009393052188837292200285737567938860665953091291609090188544", 10),
            new BigInteger("125280783069596720941658452716628999375827610701463890489482485540230585647574140509361516626953912722673932519726268057161630015231532", 10));
    private static final Point g3b = createPoint(
            new BigInteger("25460154400798033061057906375464023188226226982418482149467593583623510947345044595566809932111935577651183265131423524693421017471242", 10),
            new BigInteger("553052674467468451498390089236097910339465676043764019155003492986686446924070189167293939278539676908850471424077516167161370570930870", 10));
    private static final BigInteger b2 = new BigInteger("1515970709239640259971195367335149754581870548973690603822729175199184252492557966154679926683355329851527565965720681900917167675", 10);
    private static final BigInteger b3 = new BigInteger("6620572565451325478577935676729801683996665547132615779785633946993382844827938072605777950304437030465346847174123905281902647976", 10);
    private static final BigInteger c2_b = new BigInteger("111022924696436872341199729470810106169691412099562751065315157956932607321704386418842646614967543212975232690938096962929374138840360", 10);
    private static final BigInteger d2_b = new BigInteger("101345345229065684334282374371023601758415295857263117254747849658520035320960346748846057135976056655742957171515534523417214373693098", 10);
    private static final BigInteger c3_b = new BigInteger("62617459100015197706706660769267850673374894996485466090690871115733599023295580435733677134748019493119048062634692839095351921724769", 10);
    private static final BigInteger d3_b = new BigInteger("137562898370533368188949012935464486921412442457491703380251471222259286769274568095679144010941490174773593749015593431117048642147968", 10);
    private static final BigInteger r2_b = new BigInteger("10127852481549419750720718959133855379477088891304727781381237911576442201855075921659952274536184981085991254963573870727931630336", 10);
    private static final BigInteger r3_b = new BigInteger("8434508993637230856366065434315301434931736478290436065344111653023727018808065280949205722917628781366452171643409682774825457914", 10);
    private static final BigInteger r4 = new BigInteger("9635925776782861461871237860165663587468420417278307770423293914354237244597140607452133235706278254500013691471352229570602226015", 10);
    private static final BigInteger r5 = new BigInteger("10686081247772896546423084565129447586171663178748220102084138462931982178528329790130810515450163356992039253021890589767099032626", 10);
    private static final BigInteger r6 = new BigInteger("6863131127926975886154030295855926762097878615731435970462889775596834098326008935484867889680939562020517399609966372549208960018", 10);
    private static final Point pb = createPoint(
            new BigInteger("150971551590059119684514014051782205053977785666422029127804430526951029198846199892957327905468410035748726553951282154034774550008486", 10),
            new BigInteger("22380432526449194175787570945218836926017979984737449943120906860192566288203629458502199108124043807619691145917657476124547825617627", 10));
    private static final Point qb = createPoint(
            new BigInteger("423430412264875129675225626571000691034761078275754236126134904918998073249689389127999342833148835049651469030268345753112431699348696", 10),
            new BigInteger("27371249592200388578572706841215291643260958466414201154940100359190642782246779086087976919600673242377448605891352376861486556308423", 10));
    private static final BigInteger cp = new BigInteger("28045188189773086196199811649212088777481441211542237396012741618349225156254977936298093632091077961453305961030130988861845216328283", 10);
    private static final BigInteger d5 = new BigInteger("149784617958500236288042084698627372846752050231135475713620548703969334046909579101335416023239157022443926007634155769652596827828560", 10);
    private static final BigInteger d6 = new BigInteger("94724577901200260682137525745100301807843255453810112147553827587265819853644379707894360868997126906680725252985586449377226774745039", 10);

    private static final Point rb = createPoint(
            new BigInteger("207262232174680451060776976413201759833926533152870268659156413710415430620278577554952401659472618835066253611213476907998866291547848", 10),
            new BigInteger("243919295076423503288241325716951068924347181567637759634078287663516781375902876181296806140094995694034332370011945034139749942390997", 10));
    private static final BigInteger cr = new BigInteger("56552690208569846484767066019279120176962659824535518690139189690745687293876835490924077826911617221281921640170307321984832871226348", 10);
    private static final BigInteger d7 = new BigInteger("145952570674148673490476737637065914811240433627086277391960523808477106159276648430230314099961485884566992342590501652557852798653734", 10);

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
    public void testInitiate() {
        final byte[] fakeRandomData = new byte[4 * 54];
        encodeLittleEndianTo(fakeRandomData, 0, a2);
        encodeLittleEndianTo(fakeRandomData, 54, a3);
        encodeLittleEndianTo(fakeRandomData, 108, r2_a);
        encodeLittleEndianTo(fakeRandomData, 162, r3_a);
        final StateExpect1 state = new StateExpect1(new FixedSecureRandom(fakeRandomData), UNDECIDED);
        final SMPContext context = mock(SMPContext.class);
        final SMPMessage1 message = state.initiate(context, "Hello", secret);
        assertNotNull(message);
        assertEquals("Hello", message.question);
        assertEquals(g2a, message.g2a);
        assertEquals(c2_a, message.c2);
        assertEquals(d2_a, message.d2);
        assertEquals(g3a, message.g3a);
        assertEquals(c3_a, message.c3);
        assertEquals(d3_a, message.d3);
    }

    @Test
    public void testRespondWithSecret() throws SMPAbortException {
        final byte[] fakeRandomData = new byte[7 * 54];
        encodeLittleEndianTo(fakeRandomData, 0, b2);
        encodeLittleEndianTo(fakeRandomData, 54, b3);
        encodeLittleEndianTo(fakeRandomData, 108, r2_b);
        encodeLittleEndianTo(fakeRandomData, 162, r3_b);
        encodeLittleEndianTo(fakeRandomData, 216, r4);
        encodeLittleEndianTo(fakeRandomData, 270, r5);
        encodeLittleEndianTo(fakeRandomData, 324, r6);
        final StateExpect1 state = new StateExpect1(new FixedSecureRandom(fakeRandomData), UNDECIDED);
        final Context context = new Context();
        state.process(context, new SMPMessage1("Hello", g2a, c2_a, d2_a, g3a, c3_a, d3_a));
        final SMPMessage2 message = context.state.respondWithSecret(context, "Hello", secret);
        assertNotNull(message);
        assertEquals(g2b, message.g2b);
        assertEquals(c2_b, message.c2);
        assertEquals(d2_b, message.d2);
        assertEquals(g3b, message.g3b);
        assertEquals(c3_b, message.c3);
        assertEquals(d3_b, message.d3);
        assertEquals(pb, message.pb);
        assertEquals(qb, message.qb);
        assertEquals(cp, message.cp);
        assertEquals(d5, message.d5);
        assertEquals(d6, message.d6);
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
        final SMPMessage1 message = new SMPMessage1("Hello", createPoint(ONE, ONE), c2_a, d2_a, g3a, c3_a, d3_a);
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
        final SMPMessage1 message = new SMPMessage1("Hello", g2a, c2_a, d2_a, createPoint(ONE, ONE), c3_a, d3_a);
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
        final SMPMessage1 message = new SMPMessage1("Hello", g2a, ONE, d2_a, g3a, c3_a, d3_a);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessIllegald2() throws SMPAbortException {
        final StateExpect1 state = new StateExpect1(RANDOM, UNDECIDED);
        final Context context = new Context();
        final SMPMessage1 message = new SMPMessage1("Hello", g2a, c2_a, ONE, g3a, c3_a, d3_a);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessIllegalc3() throws SMPAbortException {
        final StateExpect1 state = new StateExpect1(RANDOM, UNDECIDED);
        final Context context = new Context();
        final SMPMessage1 message = new SMPMessage1("Hello", g2a, c2_a, d2_a, g3a, ONE, d3_a);
        state.process(context, message);
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessIllegald3() throws SMPAbortException {
        final StateExpect1 state = new StateExpect1(RANDOM, UNDECIDED);
        final Context context = new Context();
        final SMPMessage1 message = new SMPMessage1("Hello", g2a, c2_a, d2_a, g3a, c3_a, ONE);
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