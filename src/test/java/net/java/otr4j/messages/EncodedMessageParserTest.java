package net.java.otr4j.messages;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.EncodedMessage;
import net.java.otr4j.io.MessageParser;
import net.java.otr4j.io.OtrInputStream;
import net.java.otr4j.io.OtrInputStream.UnsupportedLengthException;
import net.java.otr4j.io.OtrOutputStream;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;

import javax.crypto.interfaces.DHPublicKey;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.ProtocolException;
import java.security.KeyPair;
import java.security.SecureRandom;

import static java.util.Arrays.copyOf;
import static java.util.Arrays.copyOfRange;
import static net.java.otr4j.api.InstanceTag.ZERO_TAG;
import static net.java.otr4j.messages.EncodedMessageParser.parse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

// TODO Need to add tests for parsing various type of encoded messages.
@SuppressWarnings("ConstantConditions")
public class EncodedMessageParserTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Test(expected = NullPointerException.class)
    public void testParsingNullSenderTag() throws IOException, OtrCryptoException, UnsupportedLengthException, ValidationException {
        parse(4, 0x35, null, ZERO_TAG, new OtrInputStream(new byte[0]));
    }

    @Test(expected = NullPointerException.class)
    public void testParsingNullReceiverTag() throws IOException, OtrCryptoException, UnsupportedLengthException, ValidationException {
        parse(4, 0x35, ZERO_TAG, null, new OtrInputStream(new byte[0]));
    }

    @Test(expected = NullPointerException.class)
    public void testParsingNullInputStream() throws IOException, OtrCryptoException, UnsupportedLengthException, ValidationException {
        parse(4, 0x35, ZERO_TAG, ZERO_TAG, null);
    }

    @Test(expected = ProtocolException.class)
    public void testParsingEmptyInputStream() throws IOException, OtrCryptoException, UnsupportedLengthException, ValidationException {
        parse(4, 0x35, ZERO_TAG, ZERO_TAG, new OtrInputStream(new byte[0]));
    }

    @Test(expected = ProtocolException.class)
    public void testParsingIncompleteInputStream() throws IOException, OtrCryptoException, UnsupportedLengthException, ValidationException {
        parse(3, 0x35, ZERO_TAG, ZERO_TAG, new OtrInputStream(new byte[] {0x10, 0x20}));
    }

    @Test(expected = ProtocolException.class)
    public void testParsingUnsupportedMessageType() throws IOException, OtrCryptoException, UnsupportedLengthException, ValidationException {
        parse(3, 0xff, ZERO_TAG, ZERO_TAG, new OtrInputStream(new byte[0]));
    }

    @Test(expected = IllegalStateException.class)
    public void testParsingUnsupportedVersion0() throws IOException, OtrCryptoException, UnsupportedLengthException, ValidationException {
        parse(0, DataMessage.MESSAGE_DATA, ZERO_TAG, ZERO_TAG, new OtrInputStream(new byte[0]));
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testParsingUnsupportedFutureVersion() throws IOException, OtrCryptoException, UnsupportedLengthException, ValidationException {
        parse(99, DataMessage.MESSAGE_DATA, ZERO_TAG, ZERO_TAG, new OtrInputStream(new byte[0]));
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testParsingUnsupportedOTRv1() throws IOException, OtrCryptoException, UnsupportedLengthException, ValidationException {
        parse(1, DataMessage.MESSAGE_DATA, ZERO_TAG, ZERO_TAG, new OtrInputStream(new byte[0]));
    }

    @Test
    public void testConstructAndParseDHKeyMessage() throws IOException, OtrCryptoException, UnsupportedLengthException, ValidationException {
        final KeyPair keypair = OtrCryptoEngine.generateDHKeyPair(RANDOM);
        // Prepare output message to parse.
        final DHKeyMessage m = new DHKeyMessage(Session.OTRv.THREE, (DHPublicKey) keypair.getPublic(),
                new InstanceTag(12345), new InstanceTag(9876543));
        final ByteArrayOutputStream output = new ByteArrayOutputStream();
        final OtrOutputStream otrOutput = new OtrOutputStream(output);
        m.writeTo(otrOutput);
        // Parse produced message bytes.
        final EncodedMessage message = (EncodedMessage) MessageParser.parse("?OTR:"
                + Base64.toBase64String(output.toByteArray()) + ".");
        final AbstractEncodedMessage parsedM = parse(message.getVersion(), message.getType(),
                message.getSenderInstanceTag(), message.getReceiverInstanceTag(), message.getPayload());
        assertEquals(m, parsedM);
    }

    @Test(expected = ProtocolException.class)
    public void testConstructAndParseDHKeyMessageIllegalProtocolVersion() throws IOException, OtrCryptoException, UnsupportedLengthException, ValidationException {
        final String input = "?OTR:AAQKAAAwOQCWtD8AAADA7Z2lLvD52pq9eBg1YtUPKRzDhiJbugQjqWOGKCGy9n1nV7M9+4Xoev7wgEtsUMvY9UcbaXpNLXQMlcqSpZfwRNTogXk1lOir9h8NwaURj+/ruB2jq55STMfc11E4tBmyhATStwu5VPG+5iupUjagkhsdI6I1a3ZkGXp8gAr/Utx9IB2GeXDh7HRvqRacg96X1w69IQc1lH/dVFam/OpdxCMmME1QM6N6vRRh2y34oElNhlOMGwIO9tjKr2F9m9mC.";
        // Parse produced message bytes.
        final EncodedMessage message = (EncodedMessage) MessageParser.parse(input);
        parse(message.getVersion(), message.getType(), message.getSenderInstanceTag(), message.getReceiverInstanceTag(),
                message.getPayload());
    }

    @Test
    public void testConstructAndParsePartialDHKeyMessage() throws UnsupportedLengthException, ProtocolException, OtrCryptoException, ValidationException {
        final KeyPair keypair = OtrCryptoEngine.generateDHKeyPair(RANDOM);
        // Prepare output message to parse.
        final DHKeyMessage m = new DHKeyMessage(Session.OTRv.THREE, (DHPublicKey) keypair.getPublic(),
                new InstanceTag(12345), new InstanceTag(9876543));
        final OtrOutputStream output = new OtrOutputStream();
        m.writeTo(output);
        final byte[] fullMessage = output.toByteArray();
        final byte[] payload = copyOfRange(fullMessage, 11, fullMessage.length);
        for (int i = 0; i < payload.length; i++) {
            // Try every possible partial message by starting with 0 length message up to the full-length message and
            // try every substring in between.
            final byte[] partial = copyOf(payload, i);
            try {
                parse(Session.OTRv.THREE, DHKeyMessage.MESSAGE_DHKEY, new InstanceTag(12345),
                        new InstanceTag(9876543), new OtrInputStream(partial));
                fail("Expected exception due to parsing an incomplete message.");
            } catch (final ProtocolException | OtrCryptoException expected) {
                // Expected behavior for partial messages being parsed.
            }
        }
        final AbstractEncodedMessage dhKeyMessage = parse(Session.OTRv.THREE, DHKeyMessage.MESSAGE_DHKEY,
                new InstanceTag(12345), new InstanceTag(9876543), new OtrInputStream(payload));
        assertTrue(dhKeyMessage instanceof DHKeyMessage);
    }
}
