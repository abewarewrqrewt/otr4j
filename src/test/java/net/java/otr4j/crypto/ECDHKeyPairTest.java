package net.java.otr4j.crypto;

import org.junit.Test;

import java.security.SecureRandom;

import static net.java.otr4j.crypto.ECDHKeyPair.generate;
import static org.junit.Assert.*;

@SuppressWarnings("ConstantConditions")
public class ECDHKeyPairTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Test(expected = NullPointerException.class)
    public void testGenerateNull() {
        generate(null);
    }

    @Test
    public void testGenerateKeyPair() {
        final ECDHKeyPair keypair = generate(RANDOM);
        assertNotNull(keypair);
        assertNotNull(keypair.getPublicKey());
    }
}
