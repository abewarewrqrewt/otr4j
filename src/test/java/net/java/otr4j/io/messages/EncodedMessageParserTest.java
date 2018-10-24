package net.java.otr4j.io.messages;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.OtrInputStream;
import net.java.otr4j.io.OtrInputStream.UnsupportedLengthException;
import net.java.otr4j.io.OtrOutputStream;
import org.junit.Test;

import javax.crypto.interfaces.DHPublicKey;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.ProtocolException;
import java.security.KeyPair;
import java.security.SecureRandom;

import static java.util.Arrays.copyOf;
import static net.java.otr4j.api.InstanceTag.ZERO_TAG;
import static net.java.otr4j.api.Session.OTRv.ONE;
import static net.java.otr4j.io.messages.EncodedMessageParser.parse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

// TODO Need to add tests for parsing various type of encoded messages.
// FIXME rewrite EncodedMessageParser tests!
@SuppressWarnings("ConstantConditions")
public class EncodedMessageParserTest {

    private static final SecureRandom RANDOM = new SecureRandom();

//    @Test(expected = NullPointerException.class)
//    public void testParsingNullInputStream() throws IOException, OtrCryptoException, UnsupportedLengthException {
//        parse(3, 0x35, ZERO_TAG, ZERO_TAG, null);
//    }
//
//    @Test(expected = ProtocolException.class)
//    public void testParsingEmptyInputStream() throws IOException, OtrCryptoException, UnsupportedLengthException {
//        parse(3, 0x35, ZERO_TAG, ZERO_TAG, new OtrInputStream(new byte[0]));
//    }
//
//    @Test(expected = ProtocolException.class)
//    public void testParsingIncompleteInputStream() throws IOException, OtrCryptoException, UnsupportedLengthException {
//        parse(3, 0x35, ZERO_TAG, ZERO_TAG, new OtrInputStream(new byte[] {0x00, 0x03}));
//    }
//
//    @Test(expected = ProtocolException.class)
//    public void testParsingIllegalSenderInstanceTag() throws IOException, OtrCryptoException, UnsupportedLengthException {
//        parse(3, 0x35, ZERO_TAG, ZERO_TAG, new OtrInputStream(new byte[] {0x00, 0x04, 0x35, 0x00, 0x00, 0x00, (byte) 0xff}));
//    }
//
//    @Test(expected = ProtocolException.class)
//    public void testParsingIllegalReceiverInstanceTag() throws IOException, OtrCryptoException, UnsupportedLengthException {
//        parse(3, 0x35, ZERO_TAG, ZERO_TAG, new OtrInputStream(new byte[] {0x00, 0x04, 0x35, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, (byte) 0xff}));
//    }
//
//    @Test
//    public void testConstructAndParseDHKeyMessage() throws IOException, OtrCryptoException, UnsupportedLengthException {
//        final KeyPair keypair = OtrCryptoEngine.generateDHKeyPair(RANDOM);
//        // Prepare output message to parse.
//        final DHKeyMessage m = new DHKeyMessage(Session.OTRv.THREE, (DHPublicKey) keypair.getPublic(),
//                new InstanceTag(12345), new InstanceTag(9876543));
//        final ByteArrayOutputStream output = new ByteArrayOutputStream();
//        final OtrOutputStream otrOutput = new OtrOutputStream(output);
//        m.writeTo(otrOutput);
//        // Parse produced message bytes.
//        final OtrInputStream otrInput = new OtrInputStream(output.toByteArray());
//        final AbstractEncodedMessage parsedM = parse(otrInput);
//        assertEquals(m, parsedM);
//    }
//
//    @Test(expected = ProtocolException.class)
//    public void testConstructAndParseDHKeyMessageIllegalProtocolVersion() throws IOException, OtrCryptoException, UnsupportedLengthException {
//        // Prepare output message to parse.
//        final byte[] input = new byte[]{0, 4, 10, 0, 0, 48, 57, 0, -106, -76, 63, 0, 0, 0, -64, -19, -99, -91, 46, -16, -7, -38, -102, -67, 120, 24, 53, 98, -43, 15, 41, 28, -61, -122, 34, 91, -70, 4, 35, -87, 99, -122, 40, 33, -78, -10, 125, 103, 87, -77, 61, -5, -123, -24, 122, -2, -16, -128, 75, 108, 80, -53, -40, -11, 71, 27, 105, 122, 77, 45, 116, 12, -107, -54, -110, -91, -105, -16, 68, -44, -24, -127, 121, 53, -108, -24, -85, -10, 31, 13, -63, -91, 17, -113, -17, -21, -72, 29, -93, -85, -98, 82, 76, -57, -36, -41, 81, 56, -76, 25, -78, -124, 4, -46, -73, 11, -71, 84, -15, -66, -26, 43, -87, 82, 54, -96, -110, 27, 29, 35, -94, 53, 107, 118, 100, 25, 122, 124, -128, 10, -1, 82, -36, 125, 32, 29, -122, 121, 112, -31, -20, 116, 111, -87, 22, -100, -125, -34, -105, -41, 14, -67, 33, 7, 53, -108, 127, -35, 84, 86, -90, -4, -22, 93, -60, 35, 38, 48, 77, 80, 51, -93, 122, -67, 20, 97, -37, 45, -8, -96, 73, 77, -122, 83, -116, 27, 2, 14, -10, -40, -54, -81, 97, 125, -101, -39, -126};
//        // Parse produced message bytes.
//        final OtrInputStream otrInput = new OtrInputStream(input);
//        parse(otrInput);
//    }
//
//    @Test
//    public void testConstructAndParsePartialDHKeyMessage() throws UnsupportedLengthException {
//        final KeyPair keypair = OtrCryptoEngine.generateDHKeyPair(RANDOM);
//        // Prepare output message to parse.
//        final DHKeyMessage m = new DHKeyMessage(Session.OTRv.THREE, (DHPublicKey) keypair.getPublic(),
//                new InstanceTag(12345), new InstanceTag(9876543));
//        final ByteArrayOutputStream output = new ByteArrayOutputStream();
//        final OtrOutputStream otrOutput = new OtrOutputStream(output);
//        m.writeTo(otrOutput);
//        final byte[] message = output.toByteArray();
//        for (int i = 0; i < message.length; i++) {
//            // Try every possible partial message by starting with 0 length message up to the full-length message and
//            // try every substring in between.
//            final byte[] partial = copyOf(message, i);
//            try {
//                parse(new OtrInputStream(partial));
//                fail("Expected exception due to parsing an incomplete message.");
//            } catch (final ProtocolException | OtrCryptoException expected) {
//                // Expected behavior for partial messages being parsed.
//            }
//        }
//    }
}
