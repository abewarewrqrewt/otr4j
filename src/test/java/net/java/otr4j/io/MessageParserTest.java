/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.io;

import net.java.otr4j.api.Session;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;

import java.net.ProtocolException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import static java.util.Arrays.copyOfRange;
import static net.java.otr4j.io.MessageParser.encodeVersionString;
import static net.java.otr4j.io.MessageParser.parseMessage;
import static net.java.otr4j.io.MessageParser.parseVersionString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

@SuppressWarnings("ConstantConditions")
public final class MessageParserTest {

    @Test
    public void testNoFailureOnPlainMessage() throws ProtocolException {
        final Message msg = parseMessage("Hello world");
        assertTrue(msg instanceof PlainTextMessage);
        final PlainTextMessage plainMsg = (PlainTextMessage) msg;
        assertTrue(plainMsg.getVersions().isEmpty());
        assertEquals("Hello world", plainMsg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV1() throws ProtocolException {
        PlainTextMessage msg = (PlainTextMessage) parseMessage(" \t  \t\t\t\t \t \t \t   \t \t  \t ");
        assertTrue(msg.getVersions().isEmpty());
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV2() throws ProtocolException {
        PlainTextMessage msg = (PlainTextMessage) parseMessage(" \t  \t\t\t\t \t \t \t    \t\t  \t ");
        assertEquals(1, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Session.Version.TWO));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV3() throws ProtocolException {
        PlainTextMessage msg = (PlainTextMessage) parseMessage(" \t  \t\t\t\t \t \t \t    \t\t  \t\t");
        assertEquals(1, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Session.Version.THREE));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV4() throws ProtocolException {
        PlainTextMessage msg = (PlainTextMessage) parseMessage(" \t  \t\t\t\t \t \t \t    \t\t \t  ");
        assertEquals(1, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Session.Version.FOUR));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV2V3V4() throws ProtocolException {
        PlainTextMessage msg = (PlainTextMessage) parseMessage(" \t  \t\t\t\t \t \t \t    \t\t  \t   \t\t  \t\t  \t\t \t  ");
        assertEquals(3, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Session.Version.TWO));
        assertTrue(msg.getVersions().contains(Session.Version.THREE));
        assertTrue(msg.getVersions().contains(Session.Version.FOUR));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV2AndV3() throws ProtocolException {
        PlainTextMessage msg = (PlainTextMessage) parseMessage(" \t  \t\t\t\t \t \t \t    \t\t  \t   \t\t  \t\t");
        assertEquals(2, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Session.Version.TWO));
        assertTrue(msg.getVersions().contains(Session.Version.THREE));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV1V2V4() throws ProtocolException {
        PlainTextMessage msg = (PlainTextMessage) parseMessage(" \t  \t\t\t\t \t \t \t   \t \t  \t   \t\t  \t   \t\t \t  ");
        assertEquals(2, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Session.Version.TWO));
        assertTrue(msg.getVersions().contains(Session.Version.FOUR));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV1AndV2() throws ProtocolException {
        PlainTextMessage msg = (PlainTextMessage) parseMessage(" \t  \t\t\t\t \t \t \t   \t \t  \t   \t\t  \t ");
        assertEquals(1, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Session.Version.TWO));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV1V3V4() throws ProtocolException {
        PlainTextMessage msg = (PlainTextMessage) parseMessage(" \t  \t\t\t\t \t \t \t   \t \t  \t   \t\t  \t\t  \t\t \t  ");
        assertEquals(2, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Session.Version.THREE));
        assertTrue(msg.getVersions().contains(Session.Version.FOUR));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV1AndV3() throws ProtocolException {
        PlainTextMessage msg = (PlainTextMessage) parseMessage(" \t  \t\t\t\t \t \t \t   \t \t  \t   \t\t  \t\t");
        assertEquals(1, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Session.Version.THREE));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV1V2V3V4() throws ProtocolException {
        PlainTextMessage msg = (PlainTextMessage) parseMessage(" \t  \t\t\t\t \t \t \t   \t \t  \t   \t\t  \t   \t\t  \t\t  \t\t \t  ");
        assertEquals(3, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Session.Version.TWO));
        assertTrue(msg.getVersions().contains(Session.Version.THREE));
        assertTrue(msg.getVersions().contains(Session.Version.FOUR));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectWhitespaceErasure() throws ProtocolException {
        PlainTextMessage msg = (PlainTextMessage) parseMessage("Hello \t  \t\t\t\t \t \t \t   \t \t  \t   \t\t  \t\t world!");
        assertEquals(1, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Session.Version.THREE));
        assertEquals("Hello world!", msg.getCleanText());
    }

    @Test
    public void testCorrectDeduplicationOfVersionsWhileParsingQueryMessage() throws ProtocolException {
        final QueryMessage msg = (QueryMessage) parseMessage("?OTRv2222222?");
        assertEquals(1, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Session.Version.TWO));
    }

    @Test
    public void testEnsureEmptyVersionStringIsCorrectlyParsed() throws ProtocolException {
        final QueryMessage msg = (QueryMessage) parseMessage("?OTRv?");
        assertTrue(msg.getVersions().isEmpty());
    }

    @Test
    public void testParseOTRError() throws ProtocolException {
        final ErrorMessage msg = (ErrorMessage) parseMessage("?OTR Error:Hello world of errors!");
        assertEquals("Hello world of errors!", msg.error);
    }

    @Test
    public void testEnsureOTRv1VersionStringIsIgnored() throws ProtocolException {
        final QueryMessage msg = (QueryMessage) parseMessage("?OTR?");
        assertTrue(msg.getVersions().isEmpty());
    }

    @Test
    public void testEnsureFakeOTRHeadersCorrectlyIgnored1() throws ProtocolException {
        final PlainTextMessage msg = (PlainTextMessage) parseMessage("?");
        assertTrue(msg.getVersions().isEmpty());
    }

    @Test
    public void testEnsureFakeOTRHeadersCorrectlyIgnored2() throws ProtocolException {
        final PlainTextMessage msg = (PlainTextMessage) parseMessage("?O");
        assertTrue(msg.getVersions().isEmpty());
    }

    @Test
    public void testEnsureFakeOTRHeadersCorrectlyIgnored3() throws ProtocolException {
        final PlainTextMessage msg = (PlainTextMessage) parseMessage("?OTRa");
        assertTrue(msg.getVersions().isEmpty());
        assertEquals("?OTRa", msg.getCleanText());
    }

    @Test
    public void testEnsureFakeOTRHeadersCorrectlyIgnored4() throws ProtocolException {
        final PlainTextMessage msg = (PlainTextMessage) parseMessage("?OTR ");
        assertTrue(msg.getVersions().isEmpty());
        assertEquals("?OTR ", msg.getCleanText());
    }

    @Test
    public void testIncompleteMessageMissingEnding() throws ProtocolException {
        final String message = "?OTR:BADBASE64CODEMISSINGDOT";
        final PlainTextMessage msg = (PlainTextMessage) parseMessage(message);
        assertTrue(msg.getVersions().isEmpty());
        assertEquals(message, msg.getCleanText());
    }

    @Test
    public void testOTRQueryMessageV1NotOTREncoded() throws ProtocolException {
        assertTrue(parseMessage("?OTR? some other content ...") instanceof QueryMessage);
    }

    @Test
    public void testCorrectOTREncodingDetection() throws ProtocolException {
        assertTrue(parseMessage("?OTR:AAMDJ+MVmSfjFZcAAAAAAQAAAAIAAADA1g5IjD1ZGLDVQEyCgCyn9hbrL3KAbGDdzE2ZkMyTKl7XfkSxh8YJnudstiB74i4BzT0W2haClg6dMary/jo9sMudwmUdlnKpIGEKXWdvJKT+hQ26h9nzMgEditLB8vjPEWAJ6gBXvZrY6ZQrx3gb4v0UaSMOMiR5sB7Eaulb2Yc6RmRnnlxgUUC2alosg4WIeFN951PLjScajVba6dqlDi+q1H5tPvI5SWMN7PCBWIJ41+WvF+5IAZzQZYgNaVLbAAAAAAAAAAEAAAAHwNiIi5Ms+4PsY/L2ipkTtquknfx6HodLvk3RAAAAAA==.") instanceof EncodedMessage);
    }

    @Test
    public void testOTRv2FragmentNotOTREncoded() throws ProtocolException {
        assertTrue(parseMessage("?OTR,1,3,?OTR:AAMDJ+MVmSfjFZcAAAAAAQAAAAIAAADA1g5IjD1ZGLDVQEyCgCyn9hbrL3KAbGDdzE2ZkMyTKl7XfkSxh8YJnudstiB74i4BzT0W2haClg6dMary/jo9sMudwmUdlnKpIGEKXWdvJKT+hQ26h9nzMgEditLB8v,") instanceof Fragment);
    }

    @Test
    public void testOTRv3FragmentNotOTREncoded() throws ProtocolException {
        assertTrue(parseMessage("?OTR|5a73a599|27e31597,00001,00003,?OTR:AAMDJ+MVmSfjFZcAAAAAAQAAAAIAAADA1g5IjD1ZGLDVQEyCgCyn9hbrL3KAbGDdzE2ZkMyTKl7XfkSxh8YJnudstiB74i4BzT0W2haClg6dMary/jo9sMudwmUdlnKpIGEKXWdvJKT+hQ26h9nzMgEditLB8v,") instanceof Fragment);
    }

    @Test(expected = ProtocolException.class)
    public void testToMessageWrongProtocolVersion() throws Exception {
        parseMessage("?OTR:AAUDdAYBciqzcLcAAAAAAQAAAAIAAADAh7NAcXJNpXa8qw89tvx4eoxhR3iaTx4omdj34HRpgMXDGIR7Kp4trQ+L5k8INcse58RJWHQPYW+dgKMkwrpCNJIgaqjzaiJC5+QPylSchrAB78MNZiCLXW7YU3dSic1Pm0dpa57wwiFp7sfSm00GEcE7M1bRe7Pr1zgb8KP/5PJUeI7IVmYTDj5ONWUsyoocD40RQ+Bu+I7GLgb7WICGZ6mpof3UGEFFmJLB5lDfunhCqb0d3MRP0G6k/8YJzjIlAAAAAAAAAAEAAAAF8VtymMJceqLiPIYPjRTLmlr5gQPirDY87QAAAAA=.");
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

    @Test(expected = ProtocolException.class)
    public void testParseMessageWithUnsupportedVersion() throws ProtocolException {
        parseMessage("?OTR:" + Base64.toBase64String(new byte[] {0x00, 0x01}) + ".");
    }

    @Test(expected = ProtocolException.class)
    public void testParseMessageEmpty() throws ProtocolException {
        parseMessage("?OTR:.");
    }

    @Test
    public void testParsePartialHeaders() throws ProtocolException {
        final byte[] header = new byte[] {0x00, 0x04, (byte) 0xff, 0x1, 0x2, 0x3, 0x4, 0x4, 0x3, 0x2, 0x1};
        for (int i = 0; i < header.length - 1; i++) {
            try {
                parseMessage("?OTR:" + Base64.toBase64String(copyOfRange(header, 0, i)) + ".");
                fail("Expected parsing to fail with ProtocolException but this did not happen.");
            } catch (final ProtocolException expected) {
                // expected failure, no need to respond
            }
        }
        assertNotNull(parseMessage("?OTR:" + Base64.toBase64String(header) + "."));
    }

    @Test
    public void testParseCorrectOTRv4Header() throws ProtocolException {
        final EncodedMessage encoded = (EncodedMessage) parseMessage("?OTR:" + Base64.toBase64String(
                new byte[] {0x00, 0x04, (byte) 0xff, 0x1, 0x2, 0x3, 0x4, 0x4, 0x3, 0x2, 0x1}) + ".");
        assertEquals(4, encoded.version);
        assertEquals((byte) 0xff, encoded.type);
        assertEquals(0x01020304, encoded.senderTag.getValue());
        assertEquals(0x04030201, encoded.receiverTag.getValue());
    }

    @Test
    public void testParseCorrectOTRv3Header() throws ProtocolException {
        final EncodedMessage encoded = (EncodedMessage) parseMessage("?OTR:" + Base64.toBase64String(
                new byte[] {0x00, 0x03, (byte) 0xff, 0x1, 0x2, 0x3, 0x4, 0x4, 0x3, 0x2, 0x1}) + ".");
        assertEquals(3, encoded.version);
        assertEquals((byte) 0xff, encoded.type);
        assertEquals(0x01020304, encoded.senderTag.getValue());
        assertEquals(0x04030201, encoded.receiverTag.getValue());
    }

    @Test
    public void testParseCorrectOTRv2Header() throws ProtocolException {
        final EncodedMessage encoded = (EncodedMessage) parseMessage("?OTR:" + Base64.toBase64String(
                new byte[] {0x00, 0x02, (byte) 0xff, 0x1, 0x2, 0x3, 0x4, 0x4, 0x3, 0x2, 0x1}) + ".");
        assertEquals(2, encoded.version);
        assertEquals((byte) 0xff, encoded.type);
        assertEquals(0, encoded.senderTag.getValue());
        assertEquals(0, encoded.receiverTag.getValue());
        // Ensure that what would be the instance tags in OTRv3+ are considered part of the content payload in OTRv2.
        assertEquals(0x01020304, encoded.payload.readInt());
        assertEquals(0x04030201, encoded.payload.readInt());
    }
}
