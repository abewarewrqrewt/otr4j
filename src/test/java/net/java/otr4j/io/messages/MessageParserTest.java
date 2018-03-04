package net.java.otr4j.io.messages;

import org.junit.Test;

import static org.junit.Assert.*;

public class MessageParserTest {

    @Test
    public void testInstanceAvailable() {
        assertNotNull(MessageParser.instance());
    }
}
