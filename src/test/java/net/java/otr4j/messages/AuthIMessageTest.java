/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.messages;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.Session.Version;
import net.java.otr4j.crypto.OtrCryptoEngine4.Sigma;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.io.OtrOutputStream;
import org.junit.Test;

import java.security.SecureRandom;

import static net.java.otr4j.api.InstanceTag.SMALLEST_TAG;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringSign;
import static net.java.otr4j.messages.AuthIMessage.MESSAGE_AUTH_I;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;

@SuppressWarnings("ConstantConditions")
public final class AuthIMessageTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final byte[] M = new byte[] {'H', 'e', 'l', 'l', 'o'};
    private static final InstanceTag INSTANCE_TAG = InstanceTag.random(RANDOM);
    private static final Sigma SIG;

    static {
        final EdDSAKeyPair longTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final Point pk2 = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final Point pk3 = ECDHKeyPair.generate(RANDOM).getPublicKey();
        SIG = ringSign(RANDOM, longTermKeyPair, longTermKeyPair.getPublicKey(), pk2, pk3, M);
    }

    @Test
    public void testConstruction() {
        final AuthIMessage m = new AuthIMessage(4, INSTANCE_TAG, INSTANCE_TAG, SIG);
        assertEquals(Version.FOUR, m.protocolVersion);
        assertEquals(INSTANCE_TAG, m.senderInstanceTag);
        assertEquals(INSTANCE_TAG, m.receiverInstanceTag);
        assertEquals(MESSAGE_AUTH_I, m.getType());
        assertSame(SIG, m.sigma);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructionIllegalVersion() {
        new AuthIMessage(Version.THREE, INSTANCE_TAG, INSTANCE_TAG, SIG);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullRingSignature() {
        new AuthIMessage(Version.FOUR, INSTANCE_TAG, INSTANCE_TAG, null);
    }

    @Test
    public void testWriteTo() {
        final byte[] expected = new OtrOutputStream().writeShort(4).writeByte(MESSAGE_AUTH_I).writeInt(256)
                .writeInt(256).write(SIG).toByteArray();
        final AuthIMessage m = new AuthIMessage(4, SMALLEST_TAG, SMALLEST_TAG, SIG);
        OtrOutputStream out = new OtrOutputStream();
        m.writeTo(out);
        assertArrayEquals(expected, out.toByteArray());
    }
}