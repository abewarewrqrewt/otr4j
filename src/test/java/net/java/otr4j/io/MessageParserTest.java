package net.java.otr4j.io;

import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.messages.AbstractEncodedMessage;
import net.java.otr4j.io.messages.Fragment;
import net.java.otr4j.io.messages.Message;
import net.java.otr4j.io.messages.PlainTextMessage;
import net.java.otr4j.io.messages.QueryMessage;
import org.junit.Test;

import java.net.ProtocolException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import static net.java.otr4j.io.MessageParser.encodeVersionString;
import static net.java.otr4j.io.MessageParser.parse;
import static net.java.otr4j.io.MessageParser.parseVersionString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@SuppressWarnings("ConstantConditions")
public final class MessageParserTest {

    @Test
    public void testNoFailureOnPlainMessage() throws ProtocolException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        final Message msg = parse("Hello world");
        assertTrue(msg instanceof PlainTextMessage);
        final PlainTextMessage plainMsg = (PlainTextMessage) msg;
        assertEquals("", plainMsg.getTag());
        assertTrue(plainMsg.getVersions().isEmpty());
        assertEquals("Hello world", plainMsg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV1() throws ProtocolException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        PlainTextMessage msg = (PlainTextMessage) parse(" \t  \t\t\t\t \t \t \t   \t \t  \t ");
        assertTrue(msg.getVersions().isEmpty());
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV2() throws ProtocolException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        PlainTextMessage msg = (PlainTextMessage) parse(" \t  \t\t\t\t \t \t \t    \t\t  \t ");
        assertEquals(1, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Session.OTRv.TWO));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV3() throws ProtocolException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        PlainTextMessage msg = (PlainTextMessage) parse(" \t  \t\t\t\t \t \t \t    \t\t  \t\t");
        assertEquals(1, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Session.OTRv.THREE));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV4() throws ProtocolException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        PlainTextMessage msg = (PlainTextMessage) parse(" \t  \t\t\t\t \t \t \t    \t\t \t  ");
        assertEquals(1, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Session.OTRv.FOUR));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV2V3V4() throws ProtocolException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        PlainTextMessage msg = (PlainTextMessage) parse(" \t  \t\t\t\t \t \t \t    \t\t  \t   \t\t  \t\t  \t\t \t  ");
        assertEquals(3, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Session.OTRv.TWO));
        assertTrue(msg.getVersions().contains(Session.OTRv.THREE));
        assertTrue(msg.getVersions().contains(Session.OTRv.FOUR));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV2AndV3() throws ProtocolException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        PlainTextMessage msg = (PlainTextMessage) parse(" \t  \t\t\t\t \t \t \t    \t\t  \t   \t\t  \t\t");
        assertEquals(2, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Session.OTRv.TWO));
        assertTrue(msg.getVersions().contains(Session.OTRv.THREE));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV1V2V4() throws ProtocolException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        PlainTextMessage msg = (PlainTextMessage) parse(" \t  \t\t\t\t \t \t \t   \t \t  \t   \t\t  \t   \t\t \t  ");
        assertEquals(2, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Session.OTRv.TWO));
        assertTrue(msg.getVersions().contains(Session.OTRv.FOUR));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV1AndV2() throws ProtocolException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        PlainTextMessage msg = (PlainTextMessage) parse(" \t  \t\t\t\t \t \t \t   \t \t  \t   \t\t  \t ");
        assertEquals(1, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Session.OTRv.TWO));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV1V3V4() throws ProtocolException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        PlainTextMessage msg = (PlainTextMessage) parse(" \t  \t\t\t\t \t \t \t   \t \t  \t   \t\t  \t\t  \t\t \t  ");
        assertEquals(2, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Session.OTRv.THREE));
        assertTrue(msg.getVersions().contains(Session.OTRv.FOUR));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV1AndV3() throws ProtocolException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        PlainTextMessage msg = (PlainTextMessage) parse(" \t  \t\t\t\t \t \t \t   \t \t  \t   \t\t  \t\t");
        assertEquals(1, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Session.OTRv.THREE));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV1V2V3V4() throws ProtocolException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        PlainTextMessage msg = (PlainTextMessage) parse(" \t  \t\t\t\t \t \t \t   \t \t  \t   \t\t  \t   \t\t  \t\t  \t\t \t  ");
        assertEquals(3, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Session.OTRv.TWO));
        assertTrue(msg.getVersions().contains(Session.OTRv.THREE));
        assertTrue(msg.getVersions().contains(Session.OTRv.FOUR));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectWhitespaceErasure() throws ProtocolException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        PlainTextMessage msg = (PlainTextMessage) parse("Hello \t  \t\t\t\t \t \t \t   \t \t  \t   \t\t  \t\t world!");
        assertEquals(1, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Session.OTRv.THREE));
        assertEquals("Hello world!", msg.getCleanText());
    }

    @Test
    public void testCorrectDeduplicationOfVersionsWhileParsingQueryMessage() throws ProtocolException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        final QueryMessage msg = (QueryMessage) parse("?OTRv2222222?");
        assertEquals(1, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Session.OTRv.TWO));
    }

    @Test
    public void testEnsureEmptyVersionStringIsCorrectlyParsed() throws ProtocolException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        final QueryMessage msg = (QueryMessage) parse("?OTRv?");
        assertTrue(msg.getVersions().isEmpty());
    }

    @Test
    public void testEnsureOTRv1VersionStringIsIgnored() throws ProtocolException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        final QueryMessage msg = (QueryMessage) parse("?OTR?");
        assertTrue(msg.getVersions().isEmpty());
    }

    @Test
    public void testEnsureFakeOTRHeadersCorrectlyIgnored1() throws ProtocolException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        final PlainTextMessage msg = (PlainTextMessage) parse("?");
        assertTrue(msg.getVersions().isEmpty());
    }

    @Test
    public void testEnsureFakeOTRHeadersCorrectlyIgnored2() throws ProtocolException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        final PlainTextMessage msg = (PlainTextMessage) parse("?O");
        assertTrue(msg.getVersions().isEmpty());
    }

    @Test
    public void testEnsureFakeOTRHeadersCorrectlyIgnored3() throws ProtocolException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        final PlainTextMessage msg = (PlainTextMessage) parse("?OTRa");
        assertTrue(msg.getVersions().isEmpty());
        assertEquals("?OTRa", msg.getCleanText());
    }

    @Test
    public void testEnsureFakeOTRHeadersCorrectlyIgnored4() throws ProtocolException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        final PlainTextMessage msg = (PlainTextMessage) parse("?OTR ");
        assertTrue(msg.getVersions().isEmpty());
        assertEquals("?OTR ", msg.getCleanText());
    }

    @Test
    public void testIncompleteMessageMissingEnding() throws ProtocolException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        final String message = "?OTR:BADBASE64CODEMISSINGDOT";
        final PlainTextMessage msg = (PlainTextMessage) parse(message);
        assertTrue(msg.getVersions().isEmpty());
        assertEquals(message, msg.getCleanText());
    }

    @Test
    public void testOTRQueryMessageV1NotOTREncoded() throws ProtocolException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        assertTrue(parse("?OTR? some other content ...") instanceof QueryMessage);
    }

    @Test
    public void testCorrectOTREncodingDetection() throws ProtocolException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        assertTrue(parse("?OTR:AAMDJ+MVmSfjFZcAAAAAAQAAAAIAAADA1g5IjD1ZGLDVQEyCgCyn9hbrL3KAbGDdzE2ZkMyTKl7XfkSxh8YJnudstiB74i4BzT0W2haClg6dMary/jo9sMudwmUdlnKpIGEKXWdvJKT+hQ26h9nzMgEditLB8vjPEWAJ6gBXvZrY6ZQrx3gb4v0UaSMOMiR5sB7Eaulb2Yc6RmRnnlxgUUC2alosg4WIeFN951PLjScajVba6dqlDi+q1H5tPvI5SWMN7PCBWIJ41+WvF+5IAZzQZYgNaVLbAAAAAAAAAAEAAAAHwNiIi5Ms+4PsY/L2ipkTtquknfx6HodLvk3RAAAAAA==.") instanceof AbstractEncodedMessage);
    }

    @Test
    public void testOTRv2FragmentNotOTREncoded() throws ProtocolException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        assertTrue(parse("?OTR,1,3,?OTR:AAMDJ+MVmSfjFZcAAAAAAQAAAAIAAADA1g5IjD1ZGLDVQEyCgCyn9hbrL3KAbGDdzE2ZkMyTKl7XfkSxh8YJnudstiB74i4BzT0W2haClg6dMary/jo9sMudwmUdlnKpIGEKXWdvJKT+hQ26h9nzMgEditLB8v,") instanceof Fragment);
    }

    @Test
    public void testOTRv3FragmentNotOTREncoded() throws ProtocolException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        assertTrue(parse("?OTR|5a73a599|27e31597,00001,00003,?OTR:AAMDJ+MVmSfjFZcAAAAAAQAAAAIAAADA1g5IjD1ZGLDVQEyCgCyn9hbrL3KAbGDdzE2ZkMyTKl7XfkSxh8YJnudstiB74i4BzT0W2haClg6dMary/jo9sMudwmUdlnKpIGEKXWdvJKT+hQ26h9nzMgEditLB8v,") instanceof Fragment);
    }

    @Test(expected = ProtocolException.class)
    public void testToMessageWrongProtocolVersion() throws Exception {
        parse("?OTR:AAUDdAYBciqzcLcAAAAAAQAAAAIAAADAh7NAcXJNpXa8qw89tvx4eoxhR3iaTx4omdj34HRpgMXDGIR7Kp4trQ+L5k8INcse58RJWHQPYW+dgKMkwrpCNJIgaqjzaiJC5+QPylSchrAB78MNZiCLXW7YU3dSic1Pm0dpa57wwiFp7sfSm00GEcE7M1bRe7Pr1zgb8KP/5PJUeI7IVmYTDj5ONWUsyoocD40RQ+Bu+I7GLgb7WICGZ6mpof3UGEFFmJLB5lDfunhCqb0d3MRP0G6k/8YJzjIlAAAAAAAAAAEAAAAF8VtymMJceqLiPIYPjRTLmlr5gQPirDY87QAAAAA=.");
    }

    @Test(expected = NullPointerException.class)
    public void testEncodeVersionsStringNull() {
        encodeVersionString(null);
    }

    @Test
    public void testEncodeVersionsStringEmptyVersionsSet() {
        assertEquals("", encodeVersionString(Collections.<Integer>emptySet()));
    }

    @Test
    public void testEncodeVersionsStringSingletonSet() {
        assertEquals("4", encodeVersionString(Collections.singleton(4)));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testEncodeVersionsStringDoubleDigitVersion() {
        encodeVersionString(Collections.singleton(10));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testEncodeVersionsStringNegativeVersion() {
        encodeVersionString(Collections.singleton(-3));
    }

    @Test
    public void testEncodeVersionsStringMultipleVersions() {
        assertEquals("3456", encodeVersionString(Arrays.asList(3, 4, 5, 6)));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testEncodeVersionsStringMultipleVersionsSomeIllegal() {
        encodeVersionString(Arrays.asList(3, 4, -5, 6));
    }

    @Test(expected = NullPointerException.class)
    public void testParseVersionsStringNull() {
        parseVersionString(null);
    }

    @Test
    public void testParseVersionsStringSingleton() {
        assertEquals(Collections.singleton(1), parseVersionString("1"));
    }

    @Test
    public void testParseVersionsStringMultiple() {
        final HashSet<Integer> expected = new HashSet<>();
        expected.add(1);
        expected.add(3);
        expected.add(4);
        expected.add(5);
        assertEquals(expected, parseVersionString("1345"));
    }

    @Test
    public void testParseVersionsStringDuplicates() {
        final HashSet<Integer> expected = new HashSet<>();
        expected.add(3);
        expected.add(1);
        assertEquals(expected, parseVersionString("131113"));
    }
}
