package net.java.otr4j.crypto;

import org.junit.Test;

import java.security.SecureRandom;

import static net.java.otr4j.crypto.ECDHKeyPairs.verifyECDHPublicKey;

public class ECDHKeyPairsTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Test(expected = NullPointerException.class)
    public void testVerifyECDHPublicKeyNullPoint() throws OtrCryptoException {
        verifyECDHPublicKey(null);
    }

    @Test
    public void testVerifyECDHPublicKey() throws OtrCryptoException {
        final ECDHKeyPair keypair = ECDHKeyPair.generate(RANDOM);
        verifyECDHPublicKey(keypair.getPublicKey());
    }
}
