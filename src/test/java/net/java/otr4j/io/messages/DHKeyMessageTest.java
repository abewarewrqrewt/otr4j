package net.java.otr4j.io.messages;

import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.OtrCryptoEngine;
import org.junit.Test;

import javax.crypto.interfaces.DHPublicKey;
import java.security.SecureRandom;

import static net.java.otr4j.api.InstanceTag.SMALLEST_TAG;

public final class DHKeyMessageTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final DHPublicKey publicKey = (DHPublicKey) OtrCryptoEngine.generateDHKeyPair(RANDOM).getPublic();

    @Test
    public void testDHKeyMessageProtocolVersionValid() {
        new DHKeyMessage(Session.OTRv.THREE, publicKey, SMALLEST_TAG, SMALLEST_TAG);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDHKeyMessageProtocolVersionIllegalValue() {
        new DHKeyMessage(Session.OTRv.FOUR, publicKey, SMALLEST_TAG, SMALLEST_TAG);
    }
}
