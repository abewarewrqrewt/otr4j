/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.io;

import net.java.otr4j.io.EncryptedMessage.Content;
import org.junit.Test;

import java.io.IOException;

import static java.nio.charset.StandardCharsets.UTF_8;
import static net.java.otr4j.io.EncryptedMessage.extractContents;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@SuppressWarnings("ConstantConditions")
public final class EncryptedMessageTest {

    @Test(expected = NullPointerException.class)
    public void testExtractContentsNull() throws IOException {
        extractContents(null);
    }

    @Test
    public void testExtractContentsEmptyByteArray() throws IOException {
        extractContents(new byte[0]);
    }

    @Test
    public void testExtractContentsMessageOnly() throws IOException {
        final Content content = extractContents("Hello world!".getBytes(UTF_8));
        assertNotNull(content);
        assertEquals("Hello world!", content.message);
        assertTrue(content.tlvs.isEmpty());
    }

    @Test
    public void testExtractContentsMessageAndDisconnect() throws IOException {
        final byte[] textBytes = "Hello world!".getBytes(UTF_8);
        final byte[] messageBytes = new byte[textBytes.length + 5];
        System.arraycopy(textBytes, 0, messageBytes, 0, textBytes.length);
        messageBytes[textBytes.length + 2] = 1;
        final Content content = extractContents(messageBytes);
        assertNotNull(content);
        assertNotNull(content.message);
        assertEquals("Hello world!", content.message);
        assertNotNull(content.tlvs);
        assertEquals(1, content.tlvs.size());
        assertEquals(1, content.tlvs.get(0).type);
        assertArrayEquals(new byte[0], content.tlvs.get(0).value);
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
        final Content content = extractContents(messageBytes);
        assertNotNull(content);
        assertNotNull(content.message);
        assertEquals("Hello world!", content.message);
        assertNotNull(content.tlvs);
        assertEquals(1, content.tlvs.size());
        assertEquals(0, content.tlvs.get(0).type);
        assertArrayEquals(new byte[] {'a', 'b'}, content.tlvs.get(0).value);
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
        final Content content = extractContents(messageBytes);
        assertNotNull(content);
        assertNotNull(content.message);
        assertEquals("Hello world!", content.message);
        assertNotNull(content.tlvs);
        assertEquals(2, content.tlvs.size());
        assertEquals(0, content.tlvs.get(0).type);
        assertArrayEquals(new byte[] {'a', 'b'}, content.tlvs.get(0).value);
        assertEquals(1, content.tlvs.get(1).type);
        assertArrayEquals(new byte[0], content.tlvs.get(1).value);
    }
}