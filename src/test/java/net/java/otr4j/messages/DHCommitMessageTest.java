/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.messages;

import net.java.otr4j.api.Session;
import net.java.otr4j.api.Session.Version;
import org.junit.Test;

import static net.java.otr4j.api.InstanceTag.SMALLEST_TAG;

public final class DHCommitMessageTest {

    @Test
    public void testDHCommitMessageProtocolVersionValid() {
        new DHCommitMessage(Session.Version.THREE, new byte[0], new byte[0], SMALLEST_TAG, SMALLEST_TAG);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDHCommitMessageProtocolVersionIllegalVersion() {
        new DHCommitMessage(Version.FOUR, new byte[0], new byte[0], SMALLEST_TAG, SMALLEST_TAG);
    }
}
