/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.messages;

import org.junit.Test;

import static net.java.otr4j.messages.MysteriousT4.generatePhi;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

@SuppressWarnings("ConstantConditions")
public class MysteriousT4Test {

    @Test(expected = NullPointerException.class)
    public void testGeneratePhiNullQueryTag() {
        generatePhi(0, 0, null, "myContactID", "theirContactID");
    }

    @Test(expected = NullPointerException.class)
    public void testGeneratePhiNullSenderContact() {
        generatePhi(0, 0, "?OTRv4?", null, "theirContactID");
    }

    @Test(expected = NullPointerException.class)
    public void testGeneratePhiNullReceiverContact() {
        generatePhi(0, 0, "?OTRv4?", "myContactID", null);
    }

    @Test
    public void testGeneratePhiExtremeSenderInstanceTagValues() {
        assertArrayEquals(new byte[]{127, -1, -1, -1, 0, 0, 0, 0, 0, 0, 0, 7, 63, 79, 84, 82, 118, 52, 63, 0, 0, 0, 11, 109, 121, 67, 111, 110, 116, 97, 99, 116, 73, 68, 0, 0, 0, 14, 116, 104, 101, 105, 114, 67, 111, 110, 116, 97, 99, 116, 73, 68},
            generatePhi(Integer.MAX_VALUE, 0, "?OTRv4?", "myContactID", "theirContactID"));
        assertArrayEquals(new byte[]{-128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 63, 79, 84, 82, 118, 52, 63, 0, 0, 0, 11, 109, 121, 67, 111, 110, 116, 97, 99, 116, 73, 68, 0, 0, 0, 14, 116, 104, 101, 105, 114, 67, 111, 110, 116, 97, 99, 116, 73, 68},
            generatePhi(Integer.MIN_VALUE, 0, "?OTRv4?", "myContactID", "theirContactID"));
        assertArrayEquals(new byte[]{-1, -1, -1, -1, 0, 0, 0, 0, 0, 0, 0, 7, 63, 79, 84, 82, 118, 52, 63, 0, 0, 0, 11, 109, 121, 67, 111, 110, 116, 97, 99, 116, 73, 68, 0, 0, 0, 14, 116, 104, 101, 105, 114, 67, 111, 110, 116, 97, 99, 116, 73, 68},
            generatePhi(0xffffffff, 0, "?OTRv4?", "myContactID", "theirContactID"));
    }

    @Test
    public void testGeneratePhiExtremeReceiverInstanceTagValues() {
        assertArrayEquals(new byte[]{0, 0, 0, 0, 127, -1, -1, -1, 0, 0, 0, 7, 63, 79, 84, 82, 118, 52, 63, 0, 0, 0, 11, 109, 121, 67, 111, 110, 116, 97, 99, 116, 73, 68, 0, 0, 0, 14, 116, 104, 101, 105, 114, 67, 111, 110, 116, 97, 99, 116, 73, 68},
            generatePhi(0, Integer.MAX_VALUE, "?OTRv4?", "myContactID", "theirContactID"));
        assertArrayEquals(new byte[]{0, 0, 0, 0, -128, 0, 0, 0, 0, 0, 0, 7, 63, 79, 84, 82, 118, 52, 63, 0, 0, 0, 11, 109, 121, 67, 111, 110, 116, 97, 99, 116, 73, 68, 0, 0, 0, 14, 116, 104, 101, 105, 114, 67, 111, 110, 116, 97, 99, 116, 73, 68},
            generatePhi(0, Integer.MIN_VALUE, "?OTRv4?", "myContactID", "theirContactID"));
        assertArrayEquals(new byte[]{0, 0, 0, 0, -1, -1, -1, -1, 0, 0, 0, 7, 63, 79, 84, 82, 118, 52, 63, 0, 0, 0, 11, 109, 121, 67, 111, 110, 116, 97, 99, 116, 73, 68, 0, 0, 0, 14, 116, 104, 101, 105, 114, 67, 111, 110, 116, 97, 99, 116, 73, 68},
            generatePhi(0, 0xffffffff, "?OTRv4?", "myContactID", "theirContactID"));
    }

    @Test
    public void testGeneratePhiEmptyQueryTagIsAccepted() {
        assertArrayEquals(new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, 109, 121, 67, 111, 110, 116, 97, 99, 116, 73, 68, 0, 0, 0, 14, 116, 104, 101, 105, 114, 67, 111, 110, 116, 97, 99, 116, 73, 68},
            generatePhi(0, 0, "", "myContactID", "theirContactID"));
    }

    @Test
    public void testGeneratePhiUnicodeCharactersAreReflectedByLengthOfResult() {
        final byte[] plainChars = generatePhi(0, 0, "?OTRv4?", "myContactID", "theirContactID");
        final byte[] unicodeCharsReceiver = generatePhi(0, 0, "?OTRv4?", "myContactID", "th\ud801\udc01irContactID");
        assertTrue(plainChars.length < unicodeCharsReceiver.length);
        final byte[] unicodeCharsSender = generatePhi(0, 0, "?OTRv4?", "m\u24e8ContactID", "theirContactID");
        assertTrue(plainChars.length < unicodeCharsSender.length);
    }
}
