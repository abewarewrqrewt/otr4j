package net.java.otr4j.io;

import net.java.otr4j.api.Session;
import net.java.otr4j.api.Session.OTRv;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.messages.Message;
import net.java.otr4j.io.messages.PlainTextMessage;
import net.java.otr4j.io.messages.QueryMessage;
import org.junit.Test;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import static java.nio.charset.StandardCharsets.UTF_8;
import static net.java.otr4j.io.SerializationUtils.encodeVersionString;
import static net.java.otr4j.io.SerializationUtils.parseVersionString;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@SuppressWarnings("ConstantConditions")
public class SerializationUtilsTest {

	@Test
	public void testOTRQueryMessageV1NotOTREncoded() {
		assertFalse(SerializationUtils.otrEncoded("?OTR? some other content ..."));
	}
	
	@Test
	public void testOTRQueryMessageV2NotOTREncoded() {
		assertFalse(SerializationUtils.otrEncoded("?OTRv2? some other content ..."));
	}
	
	@Test
	public void testOTRQueryMessageV23NotOTREncoded() {
		assertFalse(SerializationUtils.otrEncoded("?OTRv23? some other content ..."));
	}
	
	@Test
	public void testCorrectOTREncodingDetection() {
		assertTrue(SerializationUtils.otrEncoded("?OTR:AAMDJ+MVmSfjFZcAAAAAAQAAAAIAAADA1g5IjD1ZGLDVQEyCgCyn9hbrL3KAbGDdzE2ZkMyTKl7XfkSxh8YJnudstiB74i4BzT0W2haClg6dMary/jo9sMudwmUdlnKpIGEKXWdvJKT+hQ26h9nzMgEditLB8vjPEWAJ6gBXvZrY6ZQrx3gb4v0UaSMOMiR5sB7Eaulb2Yc6RmRnnlxgUUC2alosg4WIeFN951PLjScajVba6dqlDi+q1H5tPvI5SWMN7PCBWIJ41+WvF+5IAZzQZYgNaVLbAAAAAAAAAAEAAAAHwNiIi5Ms+4PsY/L2ipkTtquknfx6HodLvk3RAAAAAA==."));
	}

	@Test
	public void testOTRv2FragmentNotOTREncoded() {
		assertFalse(SerializationUtils.otrEncoded("?OTR,1,3,?OTR:AAMDJ+MVmSfjFZcAAAAAAQAAAAIAAADA1g5IjD1ZGLDVQEyCgCyn9hbrL3KAbGDdzE2ZkMyTKl7XfkSxh8YJnudstiB74i4BzT0W2haClg6dMary/jo9sMudwmUdlnKpIGEKXWdvJKT+hQ26h9nzMgEditLB8v,"));
	}

	@Test
	public void testOTRv3FragmentNotOTREncoded() {
		assertFalse(SerializationUtils.otrEncoded("?OTR|5a73a599|27e31597,00001,00003,?OTR:AAMDJ+MVmSfjFZcAAAAAAQAAAAIAAADA1g5IjD1ZGLDVQEyCgCyn9hbrL3KAbGDdzE2ZkMyTKl7XfkSxh8YJnudstiB74i4BzT0W2haClg6dMary/jo9sMudwmUdlnKpIGEKXWdvJKT+hQ26h9nzMgEditLB8v,"));
	}

	@Test(expected = IOException.class)
	public void testToMessageWrongProtocolVersion() throws Exception {

		SerializationUtils
				.toMessage("?OTR:AAUDdAYBciqzcLcAAAAAAQAAAAIAAADAh7NAcXJNpXa8qw89tvx4eoxhR3iaTx4omdj34HRpgMXDGIR7Kp4trQ+L5k8INcse58RJWHQPYW+dgKMkwrpCNJIgaqjzaiJC5+QPylSchrAB78MNZiCLXW7YU3dSic1Pm0dpa57wwiFp7sfSm00GEcE7M1bRe7Pr1zgb8KP/5PJUeI7IVmYTDj5ONWUsyoocD40RQ+Bu+I7GLgb7WICGZ6mpof3UGEFFmJLB5lDfunhCqb0d3MRP0G6k/8YJzjIlAAAAAAAAAAEAAAAF8VtymMJceqLiPIYPjRTLmlr5gQPirDY87QAAAAA=.");
	}


    @Test
    public void testPlaintextMessageNoNullMangling() {
        final String data = "This is a test with \0 null \0 values.";
        final PlainTextMessage m = new PlainTextMessage("?OTRv23?",
                new HashSet<>(Arrays.asList(OTRv.TWO, OTRv.THREE)), data);
        assertTrue(SerializationUtils.toString(m).startsWith("This is a test with \0 null \0 values."));
    }

    @Test
    public void testBytesConversionNullMangling() {
        assertArrayEquals("This is a test with ? null ? values.".getBytes(UTF_8),
                SerializationUtils.convertTextToBytes("This is a test with \0 null \0 values."));
    }

    @Test
    public void testNoFailureOnPlainMessage() throws IOException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        final Message msg = SerializationUtils.toMessage("Hello world");
        assertTrue(msg instanceof PlainTextMessage);
        final PlainTextMessage plainMsg = (PlainTextMessage) msg;
        assertEquals("", plainMsg.getTag());
        assertTrue(plainMsg.getVersions().isEmpty());
        assertEquals("Hello world", plainMsg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV1() throws IOException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        PlainTextMessage msg = (PlainTextMessage) SerializationUtils.toMessage(" \t  \t\t\t\t \t \t \t   \t \t  \t ");
        assertTrue(msg.getVersions().isEmpty());
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV2() throws IOException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        PlainTextMessage msg = (PlainTextMessage) SerializationUtils.toMessage(" \t  \t\t\t\t \t \t \t    \t\t  \t ");
        assertEquals(1, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Session.OTRv.TWO));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV3() throws IOException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        PlainTextMessage msg = (PlainTextMessage) SerializationUtils.toMessage(" \t  \t\t\t\t \t \t \t    \t\t  \t\t");
        assertEquals(1, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Session.OTRv.THREE));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV4() throws IOException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        PlainTextMessage msg = (PlainTextMessage) SerializationUtils.toMessage(" \t  \t\t\t\t \t \t \t    \t\t \t  ");
        assertEquals(1, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Session.OTRv.FOUR));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV2V3V4() throws IOException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        PlainTextMessage msg = (PlainTextMessage) SerializationUtils.toMessage(" \t  \t\t\t\t \t \t \t    \t\t  \t   \t\t  \t\t  \t\t \t  ");
        assertEquals(3, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Session.OTRv.TWO));
        assertTrue(msg.getVersions().contains(Session.OTRv.THREE));
        assertTrue(msg.getVersions().contains(Session.OTRv.FOUR));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV2AndV3() throws IOException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        PlainTextMessage msg = (PlainTextMessage) SerializationUtils.toMessage(" \t  \t\t\t\t \t \t \t    \t\t  \t   \t\t  \t\t");
        assertEquals(2, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Session.OTRv.TWO));
        assertTrue(msg.getVersions().contains(Session.OTRv.THREE));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV1V2V4() throws IOException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        PlainTextMessage msg = (PlainTextMessage) SerializationUtils.toMessage(" \t  \t\t\t\t \t \t \t   \t \t  \t   \t\t  \t   \t\t \t  ");
        assertEquals(2, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Session.OTRv.TWO));
        assertTrue(msg.getVersions().contains(Session.OTRv.FOUR));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV1AndV2() throws IOException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        PlainTextMessage msg = (PlainTextMessage) SerializationUtils.toMessage(" \t  \t\t\t\t \t \t \t   \t \t  \t   \t\t  \t ");
        assertEquals(1, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Session.OTRv.TWO));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV1V3V4() throws IOException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        PlainTextMessage msg = (PlainTextMessage) SerializationUtils.toMessage(" \t  \t\t\t\t \t \t \t   \t \t  \t   \t\t  \t\t  \t\t \t  ");
        assertEquals(2, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Session.OTRv.THREE));
        assertTrue(msg.getVersions().contains(Session.OTRv.FOUR));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV1AndV3() throws IOException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        PlainTextMessage msg = (PlainTextMessage) SerializationUtils.toMessage(" \t  \t\t\t\t \t \t \t   \t \t  \t   \t\t  \t\t");
        assertEquals(1, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Session.OTRv.THREE));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV1V2V3V4() throws IOException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        PlainTextMessage msg = (PlainTextMessage) SerializationUtils.toMessage(" \t  \t\t\t\t \t \t \t   \t \t  \t   \t\t  \t   \t\t  \t\t  \t\t \t  ");
        assertEquals(3, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Session.OTRv.TWO));
        assertTrue(msg.getVersions().contains(Session.OTRv.THREE));
        assertTrue(msg.getVersions().contains(Session.OTRv.FOUR));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectWhitespaceErasure() throws IOException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        PlainTextMessage msg = (PlainTextMessage) SerializationUtils.toMessage("Hello \t  \t\t\t\t \t \t \t   \t \t  \t   \t\t  \t\t world!");
        assertEquals(1, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Session.OTRv.THREE));
        assertEquals("Hello world!", msg.getCleanText());
    }

    @Test
    public void testQueryHeaderEmpty() {
        // Verify that we do not send the "bizarre claim" (as documented by otr spec) of willingness to speak otr but we accept not a single version.
        final QueryMessage msg = new QueryMessage("", Collections.<Integer>emptySet());
        assertEquals("", SerializationUtils.toString(msg));
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testCorrectQueryHeaderV1() {
        final QueryMessage msg = new QueryMessage("?OTR?", Collections.singleton(1));
        assertEquals("", SerializationUtils.toString(msg));
    }

    @Test
    public void testCorrectQueryHeaderV2() {
        final QueryMessage msg = new QueryMessage("?OTRv2?", Collections.singleton(Session.OTRv.TWO));
        assertEquals("?OTRv2?", SerializationUtils.toString(msg));
    }

    @Test
    public void testCorrectQueryHeaderV3() {
        final QueryMessage msg = new QueryMessage("?OTRv3?", Collections.singleton(Session.OTRv.THREE));
        assertEquals("?OTRv3?", SerializationUtils.toString(msg));
    }

    @Test
    public void testCorrectQueryHeaderV2AndV3() {
        final QueryMessage msg = new QueryMessage("?OTRv23?", new HashSet<>(Arrays.asList(Session.OTRv.TWO, Session.OTRv.THREE)));
        assertEquals("?OTRv23?", SerializationUtils.toString(msg));
    }

    @Test
    public void testCorrectDeduplicationOfVersionsWhileParsingQueryMessage() throws IOException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        final QueryMessage msg = (QueryMessage) SerializationUtils.toMessage("?OTRv2222222?");
        assertEquals(1, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Session.OTRv.TWO));
    }

    @Test
    public void testEnsureEmptyVersionStringIsCorrectlyParsed() throws IOException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        final QueryMessage msg = (QueryMessage) SerializationUtils.toMessage("?OTRv?");
        assertTrue(msg.getVersions().isEmpty());
    }

    @Test
    public void testEnsureOTRv1VersionStringIsIgnored() throws IOException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        final QueryMessage msg = (QueryMessage) SerializationUtils.toMessage("?OTR?");
        assertTrue(msg.getVersions().isEmpty());
    }

    @Test
    public void testEnsureFakeOTRHeadersCorrectlyIgnored1() throws IOException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        final QueryMessage msg = (QueryMessage) SerializationUtils.toMessage("?");
        assertTrue(msg.getVersions().isEmpty());
    }

    @Test
    public void testEnsureFakeOTRHeadersCorrectlyIgnored2() throws IOException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        final QueryMessage msg = (QueryMessage) SerializationUtils.toMessage("?O");
        assertTrue(msg.getVersions().isEmpty());
    }

    @Test
    public void testEnsureFakeOTRHeadersCorrectlyIgnored3() throws IOException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        final PlainTextMessage msg = (PlainTextMessage) SerializationUtils.toMessage("?OTRa");
        assertTrue(msg.getVersions().isEmpty());
        assertEquals("?OTRa", msg.getCleanText());
    }

    @Test
    public void testEnsureFakeOTRHeadersCorrectlyIgnored4() throws IOException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        final PlainTextMessage msg = (PlainTextMessage) SerializationUtils.toMessage("?OTR ");
        assertTrue(msg.getVersions().isEmpty());
        assertEquals("?OTR ", msg.getCleanText());
    }

    @Test
    public void testIncompleteMessageMissingEnding() throws IOException, OtrCryptoException, OtrInputStream.UnsupportedLengthException {
        final String message = "?OTR:BADBASE64CODEMISSINGDOT";
        final PlainTextMessage msg = (PlainTextMessage) SerializationUtils.toMessage(message);
        assertTrue(msg.getVersions().isEmpty());
        assertEquals(message, msg.getCleanText());
    }

    @Test
    public void testWhitespaceTagsNoVersions() {
        final PlainTextMessage m = new PlainTextMessage("", Collections.<Integer>emptySet(), "Hello");
        assertEquals("Hello", SerializationUtils.toString(m));
    }

    @Test
    public void testWhitespaceTagsAllVersions() {
        final HashSet<Integer> versions = new HashSet<>();
        versions.add(OTRv.TWO);
        versions.add(OTRv.THREE);
        versions.add(OTRv.FOUR);
        final PlainTextMessage m = new PlainTextMessage("", versions, "Hello");
        assertEquals("Hello \t  \t\t\t\t \t \t \t    \t\t  \t   \t\t  \t\t  \t\t \t  ", SerializationUtils.toString(m));
    }

    @Test
    public void testWhitespaceTagsVersion2Only() {
        final PlainTextMessage m = new PlainTextMessage("", Collections.singleton(OTRv.TWO), "Hello");
        assertEquals("Hello \t  \t\t\t\t \t \t \t    \t\t  \t ", SerializationUtils.toString(m));
    }

    @Test
    public void testWhitespaceTagsVersion3Only() {
        final PlainTextMessage m = new PlainTextMessage("", Collections.singleton(OTRv.THREE), "Hello");
        assertEquals("Hello \t  \t\t\t\t \t \t \t    \t\t  \t\t", SerializationUtils.toString(m));
    }

    @Test
    public void testWhitespaceTagsVersion4Only() {
        final PlainTextMessage m = new PlainTextMessage("", Collections.singleton(OTRv.FOUR), "Hello");
        assertEquals("Hello \t  \t\t\t\t \t \t \t    \t\t \t  ", SerializationUtils.toString(m));
    }

    @Test(expected = NullPointerException.class)
    public void testExtractContentsNull() throws IOException {
	    SerializationUtils.extractContents(null);
    }

    @Test
    public void testExtractContentsEmptyByteArray() throws IOException {
	    SerializationUtils.extractContents(new byte[0]);
    }

    @Test
    public void testExtractContentsMessageOnly() throws IOException {
        final SerializationUtils.Content content = SerializationUtils.extractContents("Hello world!".getBytes(UTF_8));
        assertNotNull(content);
        assertEquals("Hello world!", content.message);
        assertTrue(content.tlvs.isEmpty());
    }

    @Test
    public void testExtractContentsMessageAndDisconnect() throws IOException {
        final byte[] textBytes = "Hello world!".getBytes(UTF_8);
        final byte[] messageBytes = new byte[textBytes.length + 5];
        System.arraycopy(textBytes, 0, messageBytes, 0, textBytes.length);
        messageBytes[textBytes.length+2] = 1;
        final SerializationUtils.Content content = SerializationUtils.extractContents(messageBytes);
        assertNotNull(content);
        assertNotNull(content.message);
        assertEquals("Hello world!", content.message);
        assertNotNull(content.tlvs);
        assertEquals(1, content.tlvs.size());
        assertEquals(1, content.tlvs.get(0).getType());
        assertArrayEquals(new byte[0], content.tlvs.get(0).getValue());
    }

    @Test
    public void testExtractContentsMessageAndPaddingValue() throws IOException {
        final byte[] textBytes = "Hello world!".getBytes(UTF_8);
        final byte[] messageBytes = new byte[textBytes.length + 7];
        System.arraycopy(textBytes, 0, messageBytes, 0, textBytes.length);
        messageBytes[textBytes.length + 2] = 0;
        messageBytes[textBytes.length + 4] = 2;
        messageBytes[textBytes.length + 5] = 'a';
        messageBytes[textBytes.length + 6] = 'b';
        final SerializationUtils.Content content = SerializationUtils.extractContents(messageBytes);
        assertNotNull(content);
        assertNotNull(content.message);
        assertEquals("Hello world!", content.message);
        assertNotNull(content.tlvs);
        assertEquals(1, content.tlvs.size());
        assertEquals(0, content.tlvs.get(0).getType());
        assertArrayEquals(new byte[]{'a', 'b'}, content.tlvs.get(0).getValue());
    }

    @Test
    public void testExtractContentsMessageAndDisconnectAndPaddingValue() throws IOException {
        final byte[] textBytes = "Hello world!".getBytes(UTF_8);
        final byte[] messageBytes = new byte[textBytes.length + 11];
        System.arraycopy(textBytes, 0, messageBytes, 0, textBytes.length);
        messageBytes[textBytes.length + 2] = 0;
        messageBytes[textBytes.length + 4] = 2;
        messageBytes[textBytes.length + 5] = 'a';
        messageBytes[textBytes.length + 6] = 'b';
        messageBytes[textBytes.length + 8] = 1;
        final SerializationUtils.Content content = SerializationUtils.extractContents(messageBytes);
        assertNotNull(content);
        assertNotNull(content.message);
        assertEquals("Hello world!", content.message);
        assertNotNull(content.tlvs);
        assertEquals(2, content.tlvs.size());
        assertEquals(0, content.tlvs.get(0).getType());
        assertArrayEquals(new byte[]{'a', 'b'}, content.tlvs.get(0).getValue());
        assertEquals(1, content.tlvs.get(1).getType());
        assertArrayEquals(new byte[0], content.tlvs.get(1).getValue());
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
