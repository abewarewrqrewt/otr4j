package net.java.otr4j.io.messages;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.OtrCryptoEngine;
import org.junit.Test;

import javax.crypto.interfaces.DHPublicKey;
import java.security.SecureRandom;

public final class DHKeyMessageTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final DHPublicKey publicKey = (DHPublicKey) OtrCryptoEngine.generateDHKeyPair(RANDOM).getPublic();

    @Test
    public void testDHKeyMessageProtocolVersionValid() {
        new DHKeyMessage(Session.OTRv.THREE, publicKey, InstanceTag.SMALLEST_VALUE, InstanceTag.SMALLEST_VALUE);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDHKeyMessageProtocolVersionIllegalValue() {
        new DHKeyMessage(Session.OTRv.FOUR, publicKey, InstanceTag.SMALLEST_VALUE, InstanceTag.SMALLEST_VALUE);
    }
}
