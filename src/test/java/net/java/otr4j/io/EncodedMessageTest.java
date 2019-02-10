/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.io;

import net.java.otr4j.api.Session;
import org.junit.Test;

import static net.java.otr4j.api.InstanceTag.ZERO_TAG;

@SuppressWarnings("ConstantConditions")
public final class EncodedMessageTest {

    @Test(expected = NullPointerException.class)
    public void testParsingNullSenderTag() {
        new EncodedMessage(Session.Version.FOUR, 0x35, null, ZERO_TAG, new OtrInputStream(new byte[0]));
    }

    @Test(expected = NullPointerException.class)
    public void testParsingNullReceiverTag() {
        new EncodedMessage(Session.Version.FOUR, 0x35, ZERO_TAG, null, new OtrInputStream(new byte[0]));
    }

    @Test(expected = NullPointerException.class)
    public void testParsingNullInputStream() {
        new EncodedMessage(Session.Version.FOUR, 0x35, ZERO_TAG, ZERO_TAG, null);
    }
}