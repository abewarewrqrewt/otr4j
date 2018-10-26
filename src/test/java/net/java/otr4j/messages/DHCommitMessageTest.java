package net.java.otr4j.messages;

import net.java.otr4j.api.Session.OTRv;
import org.junit.Test;

import static net.java.otr4j.api.InstanceTag.SMALLEST_TAG;

public final class DHCommitMessageTest {

    @Test
    public void testDHCommitMessageProtocolVersionValid() {
        new DHCommitMessage(OTRv.THREE, new byte[0], new byte[0], SMALLEST_TAG, SMALLEST_TAG);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDHCommitMessageProtocolVersionIllegalVersion() {
        new DHCommitMessage(OTRv.FOUR, new byte[0], new byte[0], SMALLEST_TAG, SMALLEST_TAG);
    }
}
