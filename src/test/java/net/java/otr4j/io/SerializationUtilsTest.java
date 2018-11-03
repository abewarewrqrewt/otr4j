/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.io;

import net.java.otr4j.api.Session.OTRv;
import org.junit.Test;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@SuppressWarnings("ConstantConditions")
public class SerializationUtilsTest {

    @Test
    public void testPlaintextMessageNoNullMangling() {
        final String data = "This is a test with \0 null \0 values.";
        final PlainTextMessage m = new PlainTextMessage("?OTRv23?",
                new HashSet<>(Arrays.asList(OTRv.TWO, OTRv.THREE)), data);
        assertTrue(SerializationUtils.toString(m).startsWith("This is a test with \0 null \0 values."));
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
        final QueryMessage msg = new QueryMessage("?OTRv2?", Collections.singleton(OTRv.TWO));
        assertEquals("?OTRv2?", SerializationUtils.toString(msg));
    }

    @Test
    public void testCorrectQueryHeaderV3() {
        final QueryMessage msg = new QueryMessage("?OTRv3?", Collections.singleton(OTRv.THREE));
        assertEquals("?OTRv3?", SerializationUtils.toString(msg));
    }

    @Test
    public void testCorrectQueryHeaderV2AndV3() {
        final QueryMessage msg = new QueryMessage("?OTRv23?", new HashSet<>(Arrays.asList(OTRv.TWO, OTRv.THREE)));
        assertEquals("?OTRv23?", SerializationUtils.toString(msg));
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
        final PlainTextMessage m = new PlainTextMessage(versions, "Hello");
        assertEquals("Hello \t  \t\t\t\t \t \t \t    \t\t  \t   \t\t  \t\t  \t\t \t  ", SerializationUtils.toString(m));
    }

    @Test
    public void testWhitespaceTagsVersion2Only() {
        final PlainTextMessage m = new PlainTextMessage(Collections.singleton(OTRv.TWO), "Hello");
        assertEquals("Hello \t  \t\t\t\t \t \t \t    \t\t  \t ", SerializationUtils.toString(m));
    }

    @Test
    public void testWhitespaceTagsVersion3Only() {
        final PlainTextMessage m = new PlainTextMessage(Collections.singleton(OTRv.THREE), "Hello");
        assertEquals("Hello \t  \t\t\t\t \t \t \t    \t\t  \t\t", SerializationUtils.toString(m));
    }

    @Test
    public void testWhitespaceTagsVersion4Only() {
        final PlainTextMessage m = new PlainTextMessage(Collections.singleton(OTRv.FOUR), "Hello");
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
}
