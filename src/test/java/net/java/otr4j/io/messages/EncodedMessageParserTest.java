package net.java.otr4j.io.messages;

import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.OtrInputStream;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.ProtocolException;

import static org.junit.Assert.assertNotNull;

// TODO Need to add tests for parsing various type of encoded messages, instead of only testing exception cases.
public class EncodedMessageParserTest {

    @Test
    public void testInstanceAvailable() {
        assertNotNull(EncodedMessageParser.instance());
    }

    @Test(expected = NullPointerException.class)
    public void testParsingNullInputStream() throws IOException, OtrCryptoException {
        EncodedMessageParser.instance().read(null);
    }

    @Test(expected = ProtocolException.class)
    public void testParsingEmptyInputStream() throws IOException, OtrCryptoException {
        EncodedMessageParser.instance().read(new OtrInputStream(new ByteArrayInputStream(new byte[0])));
    }

    @Test(expected = ProtocolException.class)
    public void testParsingIncompleteInputStream() throws IOException, OtrCryptoException {
        EncodedMessageParser.instance().read(new OtrInputStream(new ByteArrayInputStream(new byte[] { 0x00, 0x03 })));
    }
}
