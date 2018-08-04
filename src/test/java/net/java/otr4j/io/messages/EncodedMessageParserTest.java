package net.java.otr4j.io.messages;

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
import static net.java.otr4j.io.messages.EncodedMessageParser.parse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

// TODO Need to add tests for parsing various type of encoded messages.
@SuppressWarnings("ConstantConditions")
public class EncodedMessageParserTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Test(expected = NullPointerException.class)
    public void testParsingNullInputStream() throws IOException, OtrCryptoException, UnsupportedLengthException {
        parse(null);
    }

    @Test(expected = ProtocolException.class)
    public void testParsingEmptyInputStream() throws IOException, OtrCryptoException, UnsupportedLengthException {
        parse(new OtrInputStream(new byte[0]));
    }

    @Test(expected = ProtocolException.class)
    public void testParsingIncompleteInputStream() throws IOException, OtrCryptoException, UnsupportedLengthException {
        parse(new OtrInputStream(new byte[] { 0x00, 0x03 }));
    }

    @Test
    public void testConstructAndParseDHKeyMessage() throws IOException, OtrCryptoException, UnsupportedLengthException {
        final KeyPair keypair = OtrCryptoEngine.generateDHKeyPair(RANDOM);
        // Prepare output message to parse.
        final DHKeyMessage m = new DHKeyMessage(Session.OTRv.THREE, (DHPublicKey) keypair.getPublic(), 12345, 9876543);
        final ByteArrayOutputStream output = new ByteArrayOutputStream();
        final OtrOutputStream otrOutput = new OtrOutputStream(output);
        m.writeTo(otrOutput);
        // Parse produced message bytes.
        final OtrInputStream otrInput = new OtrInputStream(output.toByteArray());
        final AbstractEncodedMessage parsedM = parse(otrInput);
        assertEquals(m, parsedM);
    }

    @Test(expected = ProtocolException.class)
    public void testConstructAndParseDHKeyMessageIllegalProtocolVersion() throws IOException, OtrCryptoException, UnsupportedLengthException {
        final KeyPair keypair = OtrCryptoEngine.generateDHKeyPair(RANDOM);
        // Prepare output message to parse.
        final DHKeyMessage m = new DHKeyMessage(Session.OTRv.FOUR, (DHPublicKey) keypair.getPublic(), 12345, 9876543);
        final ByteArrayOutputStream output = new ByteArrayOutputStream();
        final OtrOutputStream otrOutput = new OtrOutputStream(output);
        m.writeTo(otrOutput);
        // Parse produced message bytes.
        final OtrInputStream otrInput = new OtrInputStream(output.toByteArray());
        parse(otrInput);
    }

    @Test
    public void testConstructAndParsePartialDHKeyMessage() throws UnsupportedLengthException {
        final KeyPair keypair = OtrCryptoEngine.generateDHKeyPair(RANDOM);
        // Prepare output message to parse.
        final DHKeyMessage m = new DHKeyMessage(Session.OTRv.THREE, (DHPublicKey) keypair.getPublic(), 12345, 9876543);
        final ByteArrayOutputStream output = new ByteArrayOutputStream();
        final OtrOutputStream otrOutput = new OtrOutputStream(output);
        m.writeTo(otrOutput);
        final byte[] message = output.toByteArray();
        for (int i = 0; i < message.length; i++) {
            // Try every possible partial message by starting with 0 length message up to the full-length message and
            // try every substring in between.
            final byte[] partial = copyOf(message, i);
            try {
                parse(new OtrInputStream(partial));
                fail("Expected exception due to parsing an incomplete message.");
            } catch (final ProtocolException | OtrCryptoException expected) {
                // Expected behavior for partial messages being parsed.
            }
        }
    }
}
