package net.java.otr4j.io.messages;

import net.java.otr4j.api.Session;
import org.junit.Test;

import static net.java.otr4j.api.InstanceTag.SMALLEST_VALUE;

public final class RevealSignatureMessageTest {

    @Test
    public void testProtocolVersionValid() {
        new RevealSignatureMessage(Session.OTRv.THREE, new byte[0], new byte[0], new byte[0], SMALLEST_VALUE, SMALLEST_VALUE);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testProtocolVersionIllegalValue() {
        new RevealSignatureMessage(Session.OTRv.FOUR, new byte[0], new byte[0], new byte[0], SMALLEST_VALUE, SMALLEST_VALUE);
    }
}
